"""Shared local operations. Source facts, judgments, and goals are separate records."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

from .collector import collect
from .rubric import DIMENSIONS, PROFILES, RUBRIC_VERSION, rubric


class ConflictError(ValueError):
    """The caller must refresh before changing local state."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def now():
    return datetime.now(UTC).isoformat()


def _id(prefix):
    return prefix + uuid.uuid4().hex


def _gap(score, target, axis):
    """Distance from a capability minimum or burden ceiling; missing stays unknown."""
    if score is None or target is None:
        return None
    return max(target - score if axis == "capability" else score - target, 0)


def _goal_alignment(assessment, review, goals, goal_rubric_version):
    """Suggest a direction from saved judgments, without assigning or changing them."""
    targets = (goals or {}).get("targets", {})
    ratings = (review or {}).get("ratings", {})
    missing = [
        dimension
        for dimension in DIMENSIONS
        if any(
            targets.get(dimension, {}).get(key) is None for key in ("capability_min", "burden_max")
        )
    ]
    compatible = (
        assessment["rubric_version"] == RUBRIC_VERSION
        and (review is None or review["rubric_version"] == RUBRIC_VERSION)
        and (goals is None or goal_rubric_version == RUBRIC_VERSION)
    )
    unknown = any(
        ratings.get(dimension, {}).get(axis) is None
        for dimension in DIMENSIONS
        for axis in ("capability", "burden")
    )
    status = "ready"
    if goals is None:
        status = "no_goals"
    elif not compatible or missing:
        status = "not_comparable"
    elif unknown:
        status = "needs_review"
    anchors = rubric()["dimensions"]
    proofs = {
        "security": "Demonstrate that the selected boundary rejects an unauthorized case while preserving authorized use and relevant failure handling.",
        "testing": "Show that the smallest relevant check detects the intended defect and preserves required behavior; review its recurring upkeep before broadening the suite.",
        "documentation": "Have a reader complete one needed task from the guidance and verify that its paths, examples and required steps match the captured implementation.",
        "maintainability": "Trace one representative change through its edit sites and verify the required outputs, errors and safeguards; identify the upkeep it avoids or adds.",
        "delivery": "Show source-linked evidence for one required build or release boundary, including its applicable failure and recovery path, without assuming a green run proves delivery.",
        "operability": "Demonstrate one needed detection or recovery scenario and verify that an operator can follow the relevant evidence and recovery steps.",
        "extensibility": "Prove one needed variation through the simplest adequate supported seam, including compatibility and failure behavior; a plugin framework is not required by the score.",
    }
    dimensions = {}
    for dimension in DIMENSIONS:
        rating, target = ratings.get(dimension, {}), targets.get(dimension, {})
        capability = _gap(rating.get("capability"), target.get("capability_min"), "capability")
        burden = _gap(rating.get("burden"), target.get("burden_max"), "burden")
        next_capability = None
        verification = "Cite captured evidence for both capability and upkeep, including relevant failure paths; reassess after an authorized change."
        if goals is not None and not compatible:
            capability = burden = None
            action = "inspect"
            next_step = "Confirm goals and the captured review against a matching current rubric before choosing an engineering change; their rubric identities are not comparable."
        elif dimension in missing:
            action = "set_target"
            next_step = "Explicitly choose this dimension's capability minimum and burden ceiling; no target is inferred."
        elif capability is None or burden is None:
            action = "inspect"
            next_step = "Review the unknown axis against captured evidence before choosing a change; a missing score does not mean zero or a need for more machinery."
            if capability:
                next_step += " The saved review shows a capability deficit; inspect the cost of one bounded protection before strengthening."
            if burden:
                next_step += " The saved review shows excess upkeep; investigate a smaller implementation while preserving important protections and clarifying the unknown capability."
        elif capability:
            action = "rebalance" if burden else "strengthen"
            next_capability = min(rating["capability"] + 1, target["capability_min"])
            anchor = anchors[dimension]["capability"][next_capability]
            next_step = f"Take one bounded step toward: {anchor} Preserve required behavior and safeguards; keep upkeep within burden ceiling {target['burden_max']}."
            if burden:
                next_step += " Remove or reuse existing upkeep while closing that gap; if no bounded change fits both goals, surface the tradeoff before expanding scope."
            verification = proofs[dimension]
        elif burden:
            action = "simplify"
            next_step = "Remove one evidenced source of upkeep while preserving the selected capability minimum, required behavior and safeguards; do not weaken a contract merely to lower burden."
        else:
            action = "maintain"
            next_step = "Preserve the demonstrated fit. Capability above the selected minimum needs no reduction, and meeting a goal alone does not justify adding machinery."
        dimensions[dimension] = {
            "current": {axis: rating.get(axis) for axis in ("capability", "burden")},
            "target": {axis: target.get(axis) for axis in ("capability_min", "burden_max")},
            "capability_gap": capability,
            "burden_gap": burden,
            "next_capability": next_capability,
            "action": action,
            "next_step": next_step,
            "verification": verification,
            "evidence_ids": list(rating.get("evidence_ids", [])),
            "confidence": rating.get("confidence"),
            "burden_basis": rating.get(
                "burden_basis", "source_estimate" if rating.get("burden") is not None else "unknown"
            ),
            "burden_confidence": rating.get("burden_confidence"),
        }
    return {
        "status": status,
        "goal_revision": goals["revision"] if goals else 0,
        "review_id": review["id"] if review else None,
        "missing_targets": missing,
        "dimensions": dimensions,
    }


def _validate(value, schema):
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(e.path))
    if errors:
        # Never echo potentially sensitive submitted values in validation errors.
        path = ".".join(str(p) for p in errors[0].path) or "document"
        raise ValueError(f"Invalid {path}: does not satisfy the {errors[0].validator} constraint")


def _object(properties, required=None):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties) if required is None else required,
        "additionalProperties": False,
    }


SCORE = {"type": "integer", "minimum": 0, "maximum": 5}
TEXT = {"type": "string", "minLength": 1, "maxLength": 12000}
IDS = {"type": "array", "items": {"type": "string", "maxLength": 200}, "maxItems": 200}
TARGET_SCHEMA = _object(
    {dim: _object({"capability_min": SCORE, "burden_max": SCORE}) for dim in DIMENSIONS}
)
RATING_SCHEMA = _object(
    {
        "capability": {"anyOf": [SCORE, {"type": "null"}]},
        "burden": {"anyOf": [SCORE, {"type": "null"}]},
        "confidence": {"enum": ["low", "medium", "high"]},
        "rationale": TEXT,
        "evidence_ids": IDS,
        "recommendations": {"type": "array", "items": TEXT, "maxItems": 20},
        "burden_basis": {"enum": ["source_estimate", "observed", "unknown"]},
        "burden_confidence": {"enum": ["low", "medium", "high"]},
    },
    required=["capability", "burden", "confidence", "rationale", "evidence_ids", "recommendations"],
)
REVIEW_SCHEMA = _object(
    {
        "assessment_id": {"type": "string", "maxLength": 100},
        "source_digest": {"type": "string", "maxLength": 100},
        "rubric_version": {"const": RUBRIC_VERSION},
        "ratings": _object({dim: RATING_SCHEMA for dim in DIMENSIONS}),
        "findings": {
            "type": "array",
            "maxItems": 100,
            "items": _object(
                {
                    "severity": {"enum": ["critical", "high", "medium", "low"]},
                    "title": TEXT,
                    "evidence_ids": IDS,
                }
            ),
        },
    }
)


class AssessmentService:
    def __init__(self, state_dir, allowed_roots=None):
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.allowed_roots = (
            tuple(Path(p).expanduser().resolve(strict=True) for p in allowed_roots)
            if allowed_roots is not None
            else None
        )
        if self.allowed_roots is not None:
            if not self.allowed_roots:
                raise ValueError("At least one allowed root is required")
            for root in self.allowed_roots:
                self._root(root)
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path = self.state_dir / "project-assess.sqlite3"
        if self.db_path.is_symlink():
            raise ValueError("State database must not be a symlink")
        with self._db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, root TEXT UNIQUE NOT NULL, name TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS assessments (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
                    project_id TEXT NOT NULL REFERENCES projects(id), data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reviews (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
                    assessment_id TEXT NOT NULL REFERENCES assessments(id), data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS goals (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL REFERENCES projects(id),
                    revision INTEGER NOT NULL, data TEXT NOT NULL, UNIQUE(project_id, revision));
                CREATE TABLE IF NOT EXISTS requests (
                    id TEXT PRIMARY KEY, operation TEXT NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL);
                """
            )
            version = db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
            if version and version[0] != "1":
                raise ValueError("Unsupported assessment state schema version")
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('schema_version', '1')")
            for (root,) in db.execute("SELECT root FROM projects"):
                if self.state_dir.is_relative_to(Path(root)):
                    raise ValueError("State directory must be outside assessed projects")
        os.chmod(self.db_path, 0o600)

    @contextmanager
    def _db(self, write=False):
        db = sqlite3.connect(self.db_path, timeout=10)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _root(self, root):
        path = Path(root).expanduser().resolve(strict=True)
        if not path.is_dir():
            raise ValueError("Project root must be a directory")
        if self.state_dir.is_relative_to(path):
            raise ValueError("State directory must be outside assessed projects")
        if self.allowed_roots is not None and not any(
            path.is_relative_to(allowed) for allowed in self.allowed_roots
        ):
            raise PermissionError("Project is outside configured allowed roots")
        return path

    def _project(self, db, project_id):
        row = db.execute("SELECT id, root, name FROM projects WHERE id=?", (project_id,)).fetchone()
        if not row:
            raise ValueError("Unknown project")
        self._root(row[1])
        return {"id": row[0], "root": row[1], "name": row[2]}

    def list_projects(self):
        with self._db() as db:
            result = []
            for (project_id,) in db.execute("SELECT id FROM projects ORDER BY name,id"):
                try:
                    project = self._project(db, project_id)
                except (OSError, PermissionError, ValueError):
                    continue
                latest = self._latest(db, project_id)
                goals = self._goals(db, project_id)
                project.update(
                    latest_assessment_id=latest["id"] if latest else None,
                    goal_revision=goals["revision"] if goals else 0,
                )
                result.append(project)
            return result

    @staticmethod
    def rubric():
        return rubric()

    def scan(self, root, reports=None):
        root = self._root(root)
        # Report paths have the same authorization boundary as source reads.
        report_paths = []
        for report in reports or []:
            path = Path(report).expanduser().resolve(strict=True)
            if self.allowed_roots is not None and not any(
                path.is_relative_to(allowed) for allowed in self.allowed_roots
            ):
                raise PermissionError("Report is outside configured allowed roots")
            report_paths.append(path)
        snapshot = collect(root, reports=report_paths)
        project_id = "p_" + hashlib.sha256(str(root).encode()).hexdigest()[:24]
        snapshot.update(id=_id("a_"), project_id=project_id, created_at=now())
        with self._db(write=True) as db:
            db.execute(
                "INSERT OR IGNORE INTO projects VALUES (?,?,?)", (project_id, str(root), root.name)
            )
            db.execute(
                "INSERT INTO assessments(id,project_id,data) VALUES (?,?,?)",
                (snapshot["id"], project_id, canonical(snapshot)),
            )
        return snapshot

    def _assessment(self, db, assessment_id, *, missing_ok=False):
        row = db.execute("SELECT data FROM assessments WHERE id=?", (assessment_id,)).fetchone()
        if not row:
            if missing_ok:
                return None
            raise ValueError("Unknown assessment")
        assessment = json.loads(row[0])
        self._authorize_assessment(db, assessment)
        return assessment

    def _authorize_assessment(self, db, assessment):
        self._project(db, assessment["project_id"])
        if self.allowed_roots is not None:
            for evidence in assessment["evidence"]:
                if evidence["kind"] in {"junit", "cobertura", "test-value", "ruff"}:
                    path = Path(evidence["path"]).resolve()
                    if not any(path.is_relative_to(root) for root in self.allowed_roots):
                        raise PermissionError("Captured report is outside configured allowed roots")

    @staticmethod
    def _latest(db, project_id):
        row = db.execute(
            "SELECT data FROM assessments WHERE project_id=? ORDER BY seq DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def _review(db, assessment_id):
        row = db.execute(
            "SELECT data FROM reviews WHERE assessment_id=? ORDER BY seq DESC LIMIT 1",
            (assessment_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def _goals(db, project_id):
        row = db.execute(
            "SELECT data FROM goals WHERE project_id=? ORDER BY revision DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def evidence(self, assessment_id, evidence_id=None):
        with self._db() as db:
            items = self._assessment(db, assessment_id)["evidence"]
        if evidence_id is None:
            return items
        for item in items:
            if item["id"] == evidence_id:
                return item
        raise ValueError("Unknown evidence ID in this assessment")

    def _alignment(self, db, assessment):
        goals = self._goals(db, assessment["project_id"])
        baseline_id = (goals or {}).get("baseline_assessment_id")
        baseline = None
        if baseline_id == assessment["id"]:
            baseline = assessment
        elif baseline_id:
            baseline = self._assessment(db, baseline_id, missing_ok=True)
        return _goal_alignment(
            assessment,
            self._review(db, assessment["id"]),
            goals,
            baseline["rubric_version"] if baseline else None,
        )

    def evolve(self, assessment_id):
        """Align a captured judgment with selected goals; make no state or source changes."""
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
            return {
                "assessment_id": assessment_id,
                "project_id": assessment["project_id"],
                "source": assessment["source"],
                "goal_alignment": self._alignment(db, assessment),
            }

    def doctor(self, assessment_id):
        """Project captured simplify candidates without executing or changing source."""
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
            alignment = self._alignment(db, assessment)
        groups = {lens: [] for lens in ("reuse", "quality", "efficiency")}
        entries = assessment["evidence"]
        source_ids = {entry["path"]: entry["id"] for entry in entries}
        static = next((entry for entry in entries if entry["kind"] == "static-analysis"), None)
        analysis = static["stats"] if static else None
        gaps = list(assessment["gaps"])
        guidance = {
            "duplicate_function": (
                "Compare callers and side effects; share one implementation only when their contracts match.",
                "Verify the affected callers retain their distinct outputs, errors and required boundaries.",
            ),
            "dependency_cycle": (
                "Break one unnecessary dependency or move the shared concern to a suitable dependency-leaf module.",
                "Check the affected imports and public entrypoints, including any deferred import behavior.",
            ),
            "complex_function": (
                "Separate one coherent branch-heavy concern when that clarifies behavior; preserve required safeguards.",
                "Verify representative outcomes and the relevant failure or recovery paths.",
            ),
            "loop_io": (
                "Check which work is invariant before hoisting, caching or batching the smallest repeated operation.",
                "Verify ordering, freshness, failure handling and the relevant operation count.",
            ),
        }
        status = "not_collected"
        if analysis is None:
            gaps.append(
                "Static analysis was not collected for this snapshot; rescan to capture candidates."
            )
        elif analysis.get("schema_version") != 1:
            status = "unsupported"
            gaps.append(
                "Captured static-analysis schema is unsupported; use a compatible analyzer and rescan."
            )
        else:
            status = analysis["status"]
            gaps.extend(analysis["gaps"])
            for candidate in analysis["candidates"][:100]:
                lens = candidate["lens"]
                if lens not in groups or candidate["kind"] not in guidance:
                    gaps.append(
                        "A captured candidate kind or lens is unsupported by this doctor version."
                    )
                    status = "partial"
                    continue
                smallest_fix, verification = guidance[candidate["kind"]]
                groups[lens].append(
                    {
                        **candidate,
                        "evidence_ids": sorted(
                            {static["id"]}
                            | {
                                source_ids[location["path"]]
                                for location in candidate["locations"]
                                if location["path"] in source_ids
                            }
                        ),
                        "source_identity": "captured_snapshot",
                        "smallest_fix": smallest_fix,
                        "verification": verification,
                    }
                )
        inventory = None
        test_static = next(
            (entry for entry in entries if entry["kind"] == "test-value-static-analysis"), None
        )
        if test_static:
            stats = test_static["stats"]
            inventory = {
                "evidence_id": test_static["id"],
                "schema": stats["schema"],
                "counts": stats["counts"],
                "caveat": "Static test leads do not establish redundant behavior, real case counts or execution cost; inspect the full inventory and its gaps.",
            }
            if status in {"not_collected", "unsupported"}:
                status = "partial"
            if stats["schema"] != "test-value-static.v1":
                gaps.append(
                    "Captured test-value static schema is unsupported by this doctor version."
                )
                status = "partial"
            else:
                definitions = {row["id"]: row for row in stats["definitions"]}
                gaps.extend(
                    "Test static analysis: " + gap.get("reason", "unknown gap")
                    for gap in stats["gaps"]
                )
                if stats["gaps"] or not all(stats["bounded"].values()):
                    status = "partial"
                for candidate in stats["candidates"]:
                    # Body-only hashes omit bindings; avoid duplicating the
                    # stricter AST clone leads with weaker merge suggestions.
                    if candidate["kind"] not in {"test-static-lead", "javascript-matrix-lead"}:
                        continue
                    if sum(len(rows) for rows in groups.values()) >= 100:
                        gaps.append(
                            "Doctor candidate limit reached; inspect the remaining captured evidence directly."
                        )
                        status = "partial"
                        break
                    definition = definitions.get(candidate["id"])
                    if not definition or definition["path"] not in source_ids:
                        gaps.append(
                            "Some test-static candidate locations were not captured; inspect the inventory or rescan a narrower scope."
                        )
                        status = "partial"
                        continue
                    span = definition["span"]
                    metrics = (
                        {
                            "parameterization": definition["parameterization"],
                            "assertions": definition["assertions"],
                            "setup_leads": len(definition["setupLeads"]),
                        }
                        if candidate["kind"] == "test-static-lead"
                        else {"matrix": candidate["matrix"], "confidence": "low"}
                    )
                    groups["quality"].append(
                        {
                            "kind": candidate["kind"],
                            "lens": "quality",
                            "id": candidate["id"],
                            "locations": [
                                {
                                    "path": definition["path"],
                                    "line": span["line"],
                                    "end_line": span["endLine"],
                                }
                            ],
                            "metrics": metrics,
                            "evidence_ids": [test_static["id"], source_ids[definition["path"]]],
                            "source_identity": "captured_snapshot",
                            "binding_ambiguous": True,
                            "smallest_fix": "Trace distinct test outcomes and fixture bindings; simplify only repeated setup or cases whose required behavior remains protected.",
                            "verification": "Check the selected test cases and their closest behavior proofs after an authorized change; lexical counts alone do not justify pruning.",
                        }
                    )
        for entry in entries:
            if entry["kind"] != "ruff":
                continue
            if status in {"not_collected", "unsupported"}:
                status = "partial"
            gaps.extend(entry["stats"]["gaps"])
            gaps.append(
                "Supplied Ruff diagnostics have unverified source identity; inspect applicability before changing code."
            )
            for diagnostic in entry["stats"]["diagnostics"]:
                if sum(len(rows) for rows in groups.values()) >= 100:
                    gaps.append(
                        "Doctor candidate limit reached; inspect the remaining captured evidence directly."
                    )
                    break
                lens = "efficiency" if diagnostic["code"].startswith("PERF") else "quality"
                groups[lens].append(
                    {
                        "kind": "ruff_diagnostic",
                        "lens": lens,
                        "locations": [
                            {key: diagnostic[key] for key in ("path", "line", "end_line")}
                        ],
                        "code": diagnostic["code"],
                        "message": diagnostic["message"],
                        "fix_applicability": diagnostic["fix_applicability"],
                        "evidence_ids": [entry["id"]],
                        "source_identity": "unverified",
                        "smallest_fix": "Inspect the diagnostic against the intended behavior and apply only the smallest authorized correction.",
                        "verification": "Recheck the diagnostic and the affected behavior; a suggested fix is not proof of safety.",
                    }
                )
        if status == "complete" and not assessment.get("complete", False):
            status = "partial"
        return {
            "schema_version": 1,
            "assessment_id": assessment_id,
            "project_id": assessment["project_id"],
            "source": assessment["source"],
            "rubric_version": assessment["rubric_version"],
            "status": status,
            "method": "captured_static_analysis",
            "groups": groups,
            "goal_alignment": alignment,
            "test_value_static": inventory,
            "gaps": sorted(set(gaps)),
            "verification": "Trace actual callers and choose relevant behavior checks before an authorized edit; rescan afterward to assess the change.",
            "caveat": "Static candidates and supplied diagnostics require review. Empty groups are not a clean bill of health; this operation assigns no grades and applies no fixes.",
        }

    def review_template(self, assessment_id):
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
        return {
            "assessment_id": assessment_id,
            "source_digest": assessment["source"]["manifest_digest"],
            "rubric_version": assessment["rubric_version"],
            "ratings": {
                dimension: {
                    "capability": None,
                    "burden": None,
                    "burden_basis": "unknown",
                    "burden_confidence": "low",
                    "confidence": "low",
                    "rationale": "Not assessed; inspect the captured evidence and rubric.",
                    "evidence_ids": [],
                    "recommendations": [],
                }
                for dimension in DIMENSIONS
            },
            "findings": [],
        }

    @staticmethod
    def _replay(db, request_id, operation, payload):
        if request_id is None:
            return None
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
            raise ValueError("request_id must be a nonempty string of at most 128 characters")
        row = db.execute(
            "SELECT operation,payload,result FROM requests WHERE id=?", (request_id,)
        ).fetchone()
        if row:
            if row[:2] != (operation, canonical(payload)):
                raise ConflictError("Request ID was already used for a different operation")
            return json.loads(row[2])
        return None

    @staticmethod
    def _record_request(db, request_id, operation, payload, result):
        if request_id is not None:
            db.execute(
                "INSERT INTO requests VALUES (?,?,?,?)",
                (request_id, operation, canonical(payload), canonical(result)),
            )

    def submit_review(self, assessment_id, review, request_id=None):
        _validate(review, REVIEW_SCHEMA)
        with self._db(write=True) as db:
            assessment = self._assessment(db, assessment_id)
            if (
                review["assessment_id"] != assessment_id
                or review["source_digest"] != assessment["source"]["manifest_digest"]
                or review["rubric_version"] != assessment["rubric_version"]
            ):
                raise ConflictError("Review identity does not match the captured assessment")
            replay = self._replay(db, request_id, "review", review)
            if replay:
                return replay
            if self._latest(db, assessment["project_id"])["id"] != assessment_id:
                raise ConflictError("Assessment is stale; review the latest snapshot")
            evidence_ids = {item["id"] for item in assessment["evidence"]}
            for rating in review["ratings"].values():
                if not set(rating["evidence_ids"]) <= evidence_ids:
                    raise ValueError("Review cites evidence outside its captured snapshot")
                if (
                    any(rating[key] is not None for key in ("capability", "burden"))
                    and not rating["evidence_ids"]
                ):
                    raise ValueError("Scored ratings require evidence citations")
            for finding in review["findings"]:
                if not finding["evidence_ids"] or not set(finding["evidence_ids"]) <= evidence_ids:
                    raise ValueError("Findings require evidence from this snapshot")
            result = {
                **review,
                "schema_version": 1,
                "id": _id("r_"),
                "created_at": now(),
                "provenance": "agent_judgment",
            }
            # Missing methodology never means measured toil. Keep older clients
            # valid while qualifying estimates separately from capability.
            result["ratings"] = json.loads(canonical(review["ratings"]))
            for rating in result["ratings"].values():
                if rating["burden"] is None:
                    rating["burden_basis"] = "unknown"
                    rating["burden_confidence"] = "low"
                else:
                    if rating.get("burden_basis", "unknown") == "unknown":
                        rating["burden_basis"] = "source_estimate"
                    rating.setdefault("burden_confidence", "low")
            db.execute(
                "INSERT INTO reviews(id,assessment_id,data) VALUES (?,?,?)",
                (result["id"], assessment_id, canonical(result)),
            )
            self._record_request(db, request_id, "review", review, result)
        return result

    def set_targets(
        self, project_id, targets=None, expected_revision=None, profile=None, request_id=None
    ):
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected_revision must be a nonnegative integer")
        if profile is not None:
            if profile not in PROFILES:
                raise ValueError("Unknown target profile")
            if targets is None:
                targets = PROFILES[profile]["targets"]
        based_on_profile = profile
        if profile is not None and targets != PROFILES[profile]["targets"]:
            profile = None
        if isinstance(targets, dict):
            missing = [dimension for dimension in DIMENSIONS if dimension not in targets]
            if missing:
                raise ValueError(
                    "Targets missing dimensions: "
                    + ", ".join(missing)
                    + ". Set their targets or choose a current profile."
                )
        _validate(targets, TARGET_SCHEMA)
        payload = {
            "project_id": project_id,
            "targets": targets,
            "expected_revision": expected_revision,
            "profile": profile,
            "based_on_profile": based_on_profile,
        }
        with self._db(write=True) as db:
            self._project(db, project_id)
            replay = self._replay(db, request_id, "targets", payload)
            if replay:
                return replay
            current = self._goals(db, project_id)
            revision = current["revision"] if current else 0
            if expected_revision != revision:
                raise ConflictError("Goals changed; reload before saving")
            baseline = self._latest(db, project_id)
            review = self._review(db, baseline["id"]) if baseline else None
            result = {
                "schema_version": 1,
                "project_id": project_id,
                "revision": revision + 1,
                "created_at": now(),
                "targets": targets,
                "profile": profile,
                "based_on_profile": based_on_profile,
                "baseline_assessment_id": baseline["id"] if baseline else None,
                "baseline_review_id": review["id"] if review else None,
                "event": "goal_changed",
                "engineering_progress_steps": 0,
            }
            db.execute(
                "INSERT INTO goals(project_id,revision,data) VALUES (?,?,?)",
                (project_id, result["revision"], canonical(result)),
            )
            self._record_request(db, request_id, "targets", payload, result)
        return result

    def _progress(self, db, project_id):
        self._project(db, project_id)
        goals = self._goals(db, project_id)
        latest = self._latest(db, project_id)
        result = {
            "project_id": project_id,
            "goal_revision": goals["revision"] if goals else 0,
            "assessment_id": latest["id"] if latest else None,
            "event": "no_goals" if goals is None else "goal_baseline",
            "comparable": False,
            "dimensions": {},
            "remaining_steps": None,
            "steps_closer": None,
            "engineering_progress_steps": None,
        }
        if goals is None or latest is None:
            return result
        missing_targets = [
            dimension for dimension in DIMENSIONS if dimension not in goals["targets"]
        ]
        result["missing_targets"] = missing_targets
        self._authorize_assessment(db, latest)
        baseline = self._assessment(db, goals["baseline_assessment_id"])
        current_review = self._review(db, latest["id"])
        first_row = db.execute(
            "SELECT data FROM reviews WHERE assessment_id=? ORDER BY seq LIMIT 1", (latest["id"],)
        ).fetchone()
        first_review = json.loads(first_row[0]) if first_row else None
        baseline_review = None
        if goals["baseline_review_id"]:
            row = db.execute(
                "SELECT data FROM reviews WHERE id=?", (goals["baseline_review_id"],)
            ).fetchone()
            baseline_review = json.loads(row[0]) if row else None
        comparable = (
            all(baseline[key] == latest[key] for key in ("rubric_version", "scope_digest"))
            and baseline.get("complete", False)
            and latest.get("complete", False)
            and not missing_targets
        )
        same_source = baseline["source"]["manifest_digest"] == latest["source"]["manifest_digest"]
        same_review = (current_review or {}).get("id") == goals["baseline_review_id"]
        event = "source_change"
        if not comparable:
            event = "not_comparable"
        elif baseline["id"] == latest["id"] and same_review:
            event = "goal_baseline"
        elif same_source or (current_review or {}).get("id") != (first_review or {}).get("id"):
            event = "evidence_update"
        result.update(
            comparable=comparable,
            baseline_assessment_id=baseline["id"],
            event=event,
            provisional=any(
                r["confidence"] == "low"
                or (
                    r["burden"] is not None
                    and (
                        r.get("burden_basis", "source_estimate") != "observed"
                        or r.get("burden_confidence", "low") == "low"
                    )
                )
                for r in (current_review or {}).get("ratings", {}).values()
            ),
        )
        total_remaining = 0
        total_closer = 0
        engineering_closer = 0
        for dimension in DIMENSIONS:
            target = goals["targets"].get(dimension, {})
            current = (current_review or {}).get("ratings", {}).get(dimension, {})
            initial = (first_review or {}).get("ratings", {}).get(dimension, {})
            old = (baseline_review or {}).get("ratings", {}).get(dimension, {})
            values = {}
            for axis, target_key in (("capability", "capability_min"), ("burden", "burden_max")):
                score, old_score = current.get(axis), old.get(axis)
                gap = _gap(score, target.get(target_key), axis)
                old_gap = _gap(old_score, target.get(target_key), axis)
                closer = (
                    old_gap - gap
                    if comparable and gap is not None and old_gap is not None
                    else None
                )
                first_gap = _gap(initial.get(axis), target.get(target_key), axis)
                engineering_delta = (
                    old_gap - first_gap
                    if comparable and first_gap is not None and old_gap is not None
                    else None
                )
                engineering_closer = (
                    None
                    if engineering_delta is None or engineering_closer is None
                    else engineering_closer + engineering_delta
                )
                values[axis + "_gap"] = gap
                values["baseline_" + axis + "_gap"] = old_gap
                values[axis + "_steps"] = closer
                total_remaining = (
                    None if gap is None or total_remaining is None else total_remaining + gap
                )
                total_closer = (
                    None if closer is None or total_closer is None else total_closer + closer
                )
            result["dimensions"][dimension] = values
        result["remaining_steps"] = total_remaining
        result["steps_closer"] = total_closer
        result["engineering_progress_steps"] = (
            engineering_closer if comparable and not same_source else 0 if comparable else None
        )
        return result

    def progress(self, project_id):
        with self._db() as db:
            return self._progress(db, project_id)

    def get_report(self, assessment_id):
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
            return {
                "assessment": assessment,
                "review": self._review(db, assessment_id),
                "goals": self._goals(db, assessment["project_id"]),
                "progress": self._progress(db, assessment["project_id"]),
            }

    def get_badge(self, assessment_id, dimension="summary", *, format="svg"):
        """Export only public badge fields from the requested authorized snapshot and review."""
        from .badges import badge, badge_data

        if format not in {"svg", "json"}:
            raise ValueError("Badge format must be svg or json")
        with self._db() as db:
            report = {
                "assessment": self._assessment(db, assessment_id),
                "review": self._review(db, assessment_id),
            }
        return badge(report, dimension) if format == "svg" else badge_data(report, dimension)

    def history(self, project_id, *, summary=False):
        with self._db() as db:
            self._project(db, project_id)
            assessments = [
                json.loads(row[0])
                for row in db.execute(
                    "SELECT data FROM assessments WHERE project_id=? ORDER BY seq", (project_id,)
                )
            ]
            for assessment in assessments:
                self._authorize_assessment(db, assessment)
            reviews = [
                json.loads(row[0])
                for row in db.execute(
                    "SELECT r.data FROM reviews r JOIN assessments a ON r.assessment_id=a.id "
                    "WHERE a.project_id=? ORDER BY r.seq",
                    (project_id,),
                )
            ]
            goals = [
                json.loads(row[0])
                for row in db.execute(
                    "SELECT data FROM goals WHERE project_id=? ORDER BY revision", (project_id,)
                )
            ]
            if summary:
                # Authorize every snapshot before exposing even its metadata.
                # CLI/MCP callers retain full history for evidence review.
                return {
                    "assessments": [{k: a[k] for k in ("id", "created_at")} for a in assessments],
                    "reviews": [
                        {k: r[k] for k in ("id", "assessment_id", "created_at")} for r in reviews
                    ],
                    "goals": [{k: g[k] for k in ("revision", "created_at")} for g in goals],
                }
            return {"assessments": assessments, "reviews": reviews, "goals": goals}


def markdown_report(report):
    assessment = report["assessment"]
    lines = [
        f"# Project assessment: {Path(assessment['source']['root']).name}",
        "",
        f"Snapshot: `{assessment['id']}`; rubric: {assessment['rubric_version']}",
        "",
        "Capability and burden are evidence-backed judgments; missing evidence is unknown.",
        "",
        "| Dimension | Capability | Burden and evidence | Capability confidence |",
        "|---|---:|---:|---|",
    ]
    ratings = (report["review"] or {}).get("ratings", {})
    for dimension in DIMENSIONS:
        rating = ratings.get(dimension, {})
        burden = rating.get("burden")
        burden_text = "unknown"
        if burden is not None:
            basis = (
                "observed" if rating.get("burden_basis") == "observed" else "estimated from source"
            )
            burden_text = f"{burden} ({basis}; {rating.get('burden_confidence', 'low')} confidence)"
        lines.append(
            f"| {dimension} | {rating.get('capability') if rating.get('capability') is not None else 'unknown'} | {burden_text} | {rating.get('confidence', 'unknown')} |"
        )
    facts = assessment["facts"]
    inventory = facts.get("inventory", {})
    lines += [
        "",
        "## Collected facts",
        "",
        f"Manifest files: {inventory.get('manifest_files', 'unknown')}; recognized text files: "
        f"{inventory.get('recognized_files', 'unknown')}; source files: "
        f"{inventory.get('source_files', 'unknown')}; test files: "
        f"{inventory.get('test_files', 'unknown')}; documentation files: "
        f"{inventory.get('documentation_files', 'unknown')}.",
    ]
    architecture = facts.get("maintainability")
    documentation = facts.get("documentation", {}).get("doc_value")
    if documentation:
        lines += [
            "",
            f"Documentation evidence: {documentation['words']} words; "
            f"{documentation['exact_duplicate_groups']} exact duplicate groups; "
            f"{documentation['local_link_leads']} local-link leads. These are bounded source "
            "observations, not burden scores, semantic equivalence or deletion decisions. "
            f"Inspect evidence {documentation['evidence_id']} for locations, scope and gaps.",
        ]
    if architecture:
        lines += [
            "",
            f"Architecture review hints: {architecture['forwarding_functions']} forwarding functions; "
            f"{architecture['abstract_classes']} abstract/interface classes. These are syntactic "
            "inspection candidates, not burden scores; justified boundaries can produce the same patterns.",
        ]
    analysis = facts.get("static_analysis")
    if analysis:
        coverage = analysis["coverage"]
        lines += [
            "",
            f"Static analysis: {analysis['status']}; Python files parsed "
            f"{coverage['parsed_files']}/{coverage['python_files']}; "
            f"other source files {coverage['other_source_files']}; "
            f"{analysis['summary']['candidate_count']} candidate leads. "
            "These are inspection leads, not defects or ratings. "
            f"Evidence: {analysis['evidence_id']}.",
        ]
    lines += ["", "## Evidence gaps", ""]
    lines += ["- " + gap for gap in assessment["gaps"]] or ["- No collector gaps recorded."]
    for dimension, rating in ratings.items():
        lines += ["", f"## {dimension.capitalize()}", "", rating["rationale"]]
        lines += ["- " + r for r in rating["recommendations"]]
        lines += ["", "Evidence: " + ", ".join(rating["evidence_ids"])]
    lines += ["", "## Findings", ""]
    for finding in assessment["findings"] + (report["review"] or {}).get("findings", []):
        lines.append(
            f"- {finding.get('severity', 'unknown')}: {finding.get('title', finding.get('message', 'Finding'))}"
        )
    lines += [
        "",
        "## Goals and progress",
        "",
        "```json",
        json.dumps({"goals": report["goals"], "progress": report["progress"]}, indent=2),
        "```",
        "",
    ]
    return "\n".join(lines)
