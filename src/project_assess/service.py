"""Shared local operations. Source facts, judgments, and goals are separate records."""

from __future__ import annotations

import hashlib
import html
import json
import os
import sqlite3
import time
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


def _ecosystem_fit(assessment):
    """Read bounded ecosystem evidence from this snapshot, never the current worktree."""
    summary = assessment["facts"].get("ecosystem_fit")
    if summary is None:
        return {
            "status": "not_collected",
            "gaps": ["Ecosystem fit was not collected for this snapshot; rescan to capture it."],
        }
    evidence = next(
        (
            entry
            for entry in assessment["evidence"]
            if entry["id"] == summary.get("evidence_id") and entry["kind"] == "ecosystem-analysis"
        ),
        None,
    )
    if evidence is None or summary.get("schema_version") != 1:
        return {
            **summary,
            "status": "unsupported",
            "gaps": [
                *summary.get("gaps", []),
                "Captured ecosystem evidence is missing or unsupported; rescan with a compatible collector.",
            ],
        }
    stats = evidence["stats"]
    if stats.get("schema_version") != 1:
        return {
            **summary,
            "status": "unsupported",
            "gaps": [
                *summary.get("gaps", []),
                "Captured ecosystem-analysis schema is unsupported; use a compatible collector.",
            ],
        }
    return {
        **summary,
        "dependencies": stats["dependencies"],
        "signals": stats["signals"],
        "caveat": stats["caveat"],
    }


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
        "testing": "Demonstrate effective protection of the important outcomes and failures in scope, with source-linked execution evidence for the selected rubric level; distinguish missing tests from missing execution evidence and account for recurring upkeep.",
        "documentation": "Verify the needed reader workflows against the captured implementation, including setup, common changes and applicable recovery; identify workflows that remain unexamined.",
        "maintainability": "Trace representative valuable changes through their edit sites and verify required outputs, errors and safeguards; identify the upkeep the proposed design avoids or adds across the affected system.",
        "delivery": "Show source-linked evidence for the required build and release boundaries in scope, including applicable failure and recovery paths, without assuming a green run proves delivery.",
        "operability": "Demonstrate the needed detection and recovery scenarios in scope and verify that operators can use the evidence and recovery steps; retain explicit gaps for unverified scenarios.",
        "extensibility": "Demonstrate the actual variations and supported authors in scope through adequate seams, including compatibility and failure behavior; a plugin framework is not required by the score.",
    }
    dimensions = {}
    for dimension in DIMENSIONS:
        rating, target = ratings.get(dimension, {}), targets.get(dimension, {})
        capability = _gap(rating.get("capability"), target.get("capability_min"), "capability")
        burden = _gap(rating.get("burden"), target.get("burden_max"), "burden")
        next_capability = None
        target_capability = target.get("capability_min")
        target_anchor = (
            anchors[dimension]["capability"][target_capability]
            if compatible and target_capability is not None
            else None
        )
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
                next_step += " The saved review shows a capability deficit; establish the missing cost evidence while planning the full capability target."
            if burden:
                next_step += " The saved review shows excess upkeep; investigate a smaller implementation while preserving important protections and clarifying the unknown capability."
        elif capability:
            action = "rebalance" if burden else "strengthen"
            next_capability = min(rating["capability"] + 1, target["capability_min"])
            next_step = f"Plan for the full capability minimum {target_capability}: {target_anchor} Preserve required behavior and safeguards; keep upkeep within burden ceiling {target['burden_max']}. Choose a first implementation slice after identifying the required system changes and acceptance evidence."
            if burden:
                next_step += " Reduce demonstrated upkeep while closing that gap; surface any tradeoff that prevents meeting both targets."
            verification = proofs[dimension]
        elif burden:
            action = "simplify"
            next_step = "Plan to reduce the demonstrated upkeep to the selected ceiling while preserving the full capability minimum, required behavior and safeguards; do not weaken a contract merely to lower burden."
        else:
            action = "maintain"
            next_step = "Preserve the demonstrated fit. Capability above the selected minimum needs no reduction, and meeting a goal alone does not justify adding machinery."
        dimensions[dimension] = {
            "current": {axis: rating.get(axis) for axis in ("capability", "burden")},
            "target": {axis: target.get(axis) for axis in ("capability_min", "burden_max")},
            "capability_gap": capability,
            "burden_gap": burden,
            "next_capability": next_capability,
            "target_capability": target_capability,
            "target_anchor": target_anchor,
            "action": action,
            "next_step": next_step,
            "verification": verification,
            "evidence_ids": list(rating.get("evidence_ids", [])),
            "rationale": rating.get("rationale"),
            "recommendations": list(rating.get("recommendations", [])),
            "confidence": rating.get("confidence"),
            "burden_basis": rating.get(
                "burden_basis", "source_estimate" if rating.get("burden") is not None else "unknown"
            ),
            "burden_confidence": rating.get("burden_confidence"),
        }
    plan = (review or {}).get("plan")
    planning_status = "ready"
    if not compatible:
        planning_status = "not_comparable"
    elif review is None:
        planning_status = "no_review"
    elif plan is None:
        planning_status = "missing_plan"
    elif goals is None or missing:
        planning_status = "scenario_unconfirmed"
    elif (plan.get("assumed_targets") is not None and plan["assumed_targets"] != targets) or (
        plan.get("goal_revision") is not None and plan["goal_revision"] != goals["revision"]
    ):
        planning_status = "targets_changed"
    elif plan.get("assumed_targets") is None and plan.get("goal_revision") is None:
        planning_status = "scenario_unconfirmed"
    findings = []
    for finding in assessment.get("findings", []) + (review or {}).get("findings", []):
        if finding not in findings:
            findings.append(finding)
    return {
        "status": status,
        "goal_revision": goals["revision"] if goals else 0,
        "review_id": review["id"] if review else None,
        "missing_targets": missing,
        "dimensions": dimensions,
        "coverage": (review or {}).get("coverage"),
        "plan": plan,
        "planning_status": planning_status,
        "findings": findings,
        "urgent_findings": [item for item in findings if item["severity"] in {"critical", "high"}],
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
COVERAGE_SCHEMA = _object(
    {
        "schema_version": {"const": 1},
        "scope": {"enum": ["whole_project", "focused"]},
        "examined": {
            "type": "array",
            "maxItems": 100,
            "items": _object({"area": TEXT, "evidence_ids": IDS}),
        },
        "unexamined": {
            "type": "array",
            "maxItems": 100,
            "items": _object({"area": TEXT, "reason": TEXT}),
        },
        "limitations": {"type": "array", "items": TEXT, "maxItems": 100},
        "validation": {
            "type": "array",
            "maxItems": 100,
            "items": _object(
                {
                    "check": TEXT,
                    "status": {"enum": ["passed", "failed", "not_run", "unavailable"]},
                    "evidence_ids": IDS,
                }
            ),
        },
    }
)
INITIATIVE_ID = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$"}
PLAN_SCHEMA = _object(
    {
        "schema_version": {"const": 1},
        "diagnosis": TEXT,
        "target_state": TEXT,
        "goal_revision": {"anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]},
        "assumed_targets": {"anyOf": [TARGET_SCHEMA, {"type": "null"}]},
        "initiatives": {
            "type": "array",
            "maxItems": 100,
            "items": _object(
                {
                    "id": INITIATIVE_ID,
                    "title": TEXT,
                    "priority": {"enum": ["critical", "high", "medium", "low"]},
                    "root_cause": TEXT,
                    "scope": TEXT,
                    "dimension_impacts": {
                        **_object({dimension: TEXT for dimension in DIMENSIONS}, required=[]),
                        "minProperties": 1,
                    },
                    "evidence_ids": IDS,
                    "acceptance": {"type": "array", "items": TEXT, "minItems": 1, "maxItems": 30},
                    "burden_effect": TEXT,
                    "depends_on": {"type": "array", "items": INITIATIVE_ID, "maxItems": 100},
                    "first_slice": TEXT,
                }
            ),
        },
    },
    required=["schema_version", "diagnosis", "target_state", "initiatives"],
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
        "coverage": COVERAGE_SCHEMA,
        "plan": PLAN_SCHEMA,
        "review_context": _object(
            {
                "tool_code_digest": {"type": ["string", "null"], "maxLength": 100},
                "loaded_instructions": {
                    "type": "array",
                    "maxItems": 30,
                    "items": _object(
                        {
                            "path": {"type": "string", "maxLength": 4096},
                            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                            "read_status": {"enum": ["complete", "partial"]},
                        }
                    ),
                },
            },
            required=[],
        ),
    },
    required=["assessment_id", "source_digest", "rubric_version", "ratings", "findings"],
)


def _validate_planning(review, evidence_ids):
    """Bind optional authored planning to captured evidence, without judging its quality."""
    coverage = review.get("coverage", {})
    for area in coverage.get("examined", []):
        if not area["evidence_ids"] or not set(area["evidence_ids"]) <= evidence_ids:
            raise ValueError("Examined coverage areas must cite captured evidence")
    for check in coverage.get("validation", []):
        if not set(check["evidence_ids"]) <= evidence_ids or (
            check["status"] in {"passed", "failed"} and not check["evidence_ids"]
        ):
            raise ValueError("Completed validation checks must cite captured evidence")
    initiatives = review.get("plan", {}).get("initiatives", [])
    dependencies = {item["id"]: item["depends_on"] for item in initiatives}
    if len(dependencies) != len(initiatives):
        raise ValueError("Plan initiative IDs must be unique")
    for item in initiatives:
        if not item["evidence_ids"] or not set(item["evidence_ids"]) <= evidence_ids:
            raise ValueError("Plan initiatives must cite captured evidence")
        if not set(item["depends_on"]) <= dependencies.keys():
            raise ValueError("Plan dependencies must reference existing initiative IDs")
    visiting, visited = set(), set()

    def visit(initiative_id):
        if initiative_id in visiting:
            raise ValueError("Plan dependencies must not contain cycles")
        if initiative_id not in visited:
            visiting.add(initiative_id)
            for dependency in dependencies[initiative_id]:
                visit(dependency)
            visiting.remove(initiative_id)
            visited.add(initiative_id)

    for initiative_id in dependencies:
        visit(initiative_id)


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
        started = time.monotonic()
        snapshot = collect(root, reports=report_paths)
        snapshot["collection"] = {"seconds": round(time.monotonic() - started, 4)}
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
                if evidence["kind"] in {"junit", "cobertura", "test-value", "ruff", "sarif"}:
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

    def overview(self, assessment_id):
        """Read a compact handoff; detailed captured data remains queryable by view."""
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
            review = self._review(db, assessment_id)
            alignment = self._alignment(db, assessment)
        facts = assessment["facts"]
        findings = [*assessment["findings"], *(review or {}).get("findings", [])]
        urgent = [row for row in findings if row.get("severity") in {"critical", "high"}]
        coverage = (review or {}).get("coverage", {})
        return {
            "assessment_id": assessment_id,
            "project_id": assessment["project_id"],
            "created_at": assessment["created_at"],
            "source": assessment["source"],
            "scope_digest": assessment["scope_digest"],
            "rubric_version": assessment["rubric_version"],
            "complete": assessment["complete"],
            "gap_count": len(assessment["gaps"]),
            "inventory": facts.get("inventory", {}),
            "static_analysis": {
                key: value
                for key, value in facts.get("static_analysis", {}).items()
                if key
                in {
                    "analyzer",
                    "status",
                    "coverage",
                    "summary",
                    "candidate_counts",
                    "limits",
                    "evidence_id",
                }
            },
            "javascript_analysis": facts.get("javascript_analysis", {}),
            "evidence_kinds": {
                kind: sum(entry["kind"] == kind for entry in assessment["evidence"])
                for kind in sorted({entry["kind"] for entry in assessment["evidence"]})
            },
            "review_id": (review or {}).get("id"),
            "review_coverage": {
                "scope": coverage.get("scope", "unknown"),
                "examined_count": len(coverage.get("examined", [])),
                "unexamined_count": len(coverage.get("unexamined", [])),
                "limitation_count": len(coverage.get("limitations", [])),
            },
            "urgent_findings": [
                {key: row.get(key) for key in ("severity", "title", "evidence_ids")}
                for row in urgent[:20]
            ],
            "urgent_findings_omitted": max(0, len(urgent) - 20),
            "planning_status": {
                "status": alignment.get("planning_status"),
                "gap_status": alignment["status"],
                "review_id": alignment["review_id"],
                "goal_revision": alignment["goal_revision"],
                "missing_targets": alignment["missing_targets"],
            },
            "tool_provenance": assessment.get("tool_provenance", facts.get("tool_provenance")),
            "reported_findings": {
                severity: sum(row.get("severity") == severity for row in findings)
                for severity in ("critical", "high", "medium", "low", "info")
            },
            "ratings": {
                dimension: {
                    key: row.get(key)
                    for key in (
                        "capability",
                        "burden",
                        "confidence",
                        "burden_basis",
                        "burden_confidence",
                    )
                }
                for dimension, row in (review or {}).get("ratings", {}).items()
            },
            "next_step": "Use query_evidence views for bounded index, candidates, snippets, graph, hotspots, coverage and provenance. Read collection gaps before judging scope.",
        }

    def query_evidence(
        self,
        assessment_id,
        *,
        view="index",
        kind=None,
        path=None,
        role=None,
        candidate_kind=None,
        line=None,
        offset=0,
        limit=20,
        max_chars=24000,
    ):
        """Filter and page immutable captured evidence without reading the current source."""
        from .static_analysis import source_role

        views = {
            "index",
            "details",
            "candidates",
            "snippets",
            "graph",
            "hotspots",
            "coverage",
            "provenance",
        }
        if view not in views:
            raise ValueError("Unknown evidence query view")
        if any(
            value is not None and (not isinstance(value, str) or len(value) > 256)
            for value in (kind, path, role, candidate_kind)
        ):
            raise ValueError("Evidence filters must be strings of at most 256 characters")
        if any(type(value) is not int for value in (offset, limit, max_chars)) or not (
            offset >= 0 and 1 <= limit <= 100 and 2000 <= max_chars <= 100000
        ):
            raise ValueError("Require offset >= 0, limit 1..100 and max_chars 2000..100000")
        if line is not None and (type(line) is not int or line < 1):
            raise ValueError("line must be a positive integer")
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
        entries = assessment["evidence"]
        source = {entry["path"]: entry for entry in entries}
        captured_roles = {
            module["path"]: module["role"]
            for entry in entries
            for module in entry.get("stats", {}).get("modules", [])
        }

        def entry_role(entry):
            stats = entry.get("stats", {})
            if entry.get("role") or stats.get("role"):
                return entry.get("role") or stats["role"]
            if stats.get("is_test"):
                return "test"
            if entry["path"] in captured_roles:
                return captured_roles[entry["path"]]
            if entry["kind"] in {"python", "javascript"}:
                return source_role(entry["path"])["role"]
            return entry["kind"]

        candidate_rows = []
        for entry in entries if candidate_kind is not None or view == "candidates" else []:
            stats = entry.get("stats", {})
            definitions = {row["id"]: row for row in stats.get("definitions", []) if "id" in row}
            candidates = list(stats.get("candidate_index", stats.get("candidates", [])))
            if entry["kind"] in {"ruff", "sarif"}:
                candidates.extend(
                    {
                        **diagnostic,
                        "kind": entry["kind"] + "_diagnostic",
                        "locations": [
                            {key: diagnostic[key] for key in ("path", "line", "end_line")}
                        ],
                        "source_identity": "unverified",
                    }
                    for diagnostic in stats.get("diagnostics", [])
                )
            if entry["kind"] == "ecosystem-analysis":
                candidates.extend(
                    {
                        "kind": "ecosystem_fit_review",
                        "locations": [{"path": signal["path"], "line": signal["line"]}],
                        "metrics": {"signal_kind": signal["kind"]},
                        "source_identity": "captured_snapshot",
                    }
                    for signal in stats.get("signals", [])
                )
            for row in candidates:
                if not isinstance(row, dict):
                    continue
                locations = row.get("locations", [])
                if not locations and row.get("id"):
                    definition = definitions.get(row["id"])
                    if definition:
                        locations = [
                            {
                                "path": definition["path"],
                                "line": definition["span"]["line"],
                                "end_line": definition["span"]["endLine"],
                            }
                        ]
                candidate_rows.append(
                    {
                        **row,
                        "locations": locations,
                        "evidence_id": entry["id"],
                        "evidence_kind": entry["kind"],
                    }
                )
        matching_candidates = [
            row
            for row in candidate_rows
            if candidate_kind is None or row.get("kind") == candidate_kind
        ]
        candidate_paths = {
            location["path"] for row in matching_candidates for location in row.get("locations", [])
        }
        by_evidence = {}
        candidate_ranges = {}
        for row in matching_candidates:
            by_evidence.setdefault(row["evidence_id"], []).append(row)
            for location in row.get("locations", []):
                candidate_ranges.setdefault(location["path"], []).append(location)
        rows = []
        for entry in entries:
            if kind is not None and entry["kind"] != kind:
                continue
            stats = entry.get("stats", {})
            common = {"evidence_id": entry["id"], "evidence_kind": entry["kind"]}
            if view in {"index", "details"}:
                if (
                    candidate_kind
                    and entry["path"] not in candidate_paths
                    and entry["id"] not in by_evidence
                ):
                    continue
                rows.append(
                    {
                        **(
                            {key: entry[key] for key in ("id", "path", "digest", "kind", "lines")}
                            if view == "index"
                            else entry
                        ),
                        "role": entry_role(entry),
                        "sections": sorted(stats),
                        **common,
                    }
                )
            elif view == "candidates":
                rows.extend(by_evidence.get(entry["id"], []))
            elif view == "snippets":
                windows = entry.get("source_windows", stats.get("source_windows", []))
                if isinstance(windows, list):
                    rows.extend(
                        {
                            **window,
                            "path": window.get("path", entry["path"]),
                            "digest": entry["digest"],
                            **common,
                        }
                        for window in windows
                    )
                rows.extend(
                    {**common, **snippet, "analysis_evidence_id": entry["id"]}
                    for candidate in stats.get("candidates", [])
                    for snippet in candidate.get("snippets", [])
                    if not candidate_kind or candidate.get("kind") == candidate_kind
                )
            elif view == "graph":
                rows.extend(
                    {**edge, "path": edge["source"], "record_type": "edge", **common}
                    for edge in stats.get("topology", {}).get("edges", [])
                )
                rows.extend(
                    {**module, "record_type": "module", **common}
                    for module in stats.get("modules", [])
                )
            elif view == "hotspots":
                rows.extend({**row, **common} for row in stats.get("hotspots", []))
            elif view == "coverage" and "coverage" in stats:
                rows.append(
                    {
                        "coverage": stats["coverage"],
                        "status": stats.get("status"),
                        "limits": stats.get("limits", {}),
                        "candidate_counts": stats.get("candidate_counts", {}),
                        **common,
                    }
                )
        if view == "coverage" and kind is None:
            rows.extend({"record_type": "collection_gap", "gap": gap} for gap in assessment["gaps"])
        if view == "provenance":
            rows = [
                {
                    "source": assessment["source"],
                    "scope_digest": assessment["scope_digest"],
                    "rubric_version": assessment["rubric_version"],
                    "tool_provenance": assessment.get(
                        "tool_provenance", assessment["facts"].get("tool_provenance")
                    ),
                    "collection_gap_count": len(assessment["gaps"]),
                }
            ]
        filtered = []
        seen_snippets = set()
        for row in rows:
            paths = (
                [row["path"]]
                if "path" in row
                else [location["path"] for location in row.get("locations", [])]
            )
            if path and not any(path in location for location in paths):
                continue
            roles = (
                {row["role"]}
                if "role" in row
                else {entry_role(source[location]) for location in paths if location in source}
            )
            if role and role not in roles:
                continue
            if line is not None and not any(
                location.get("line", line + 1)
                <= line
                <= location.get("end_line", location.get("line", 0))
                and (not path or path in location.get("path", ""))
                for location in ([row] if "line" in row else row.get("locations", []))
            ):
                continue
            if (
                candidate_kind
                and view not in {"candidates", "index", "details"}
                and not any(location in candidate_paths for location in paths)
            ):
                continue
            if view == "snippets":
                if candidate_kind and not any(
                    location["path"] == row.get("path")
                    and location.get("line", 0) <= row.get("end_line", 0)
                    and location.get("end_line", location.get("line", 0)) >= row.get("line", 0)
                    for location in candidate_ranges.get(row.get("path"), [])
                ):
                    continue
                identity = (
                    row.get("path"),
                    row.get("line"),
                    row.get("end_line"),
                    row.get("digest"),
                    row.get("excerpt"),
                )
                if identity in seen_snippets:
                    continue
                seen_snippets.add(identity)
            filtered.append(row)
        result = {
            "schema_version": 1,
            "assessment_id": assessment_id,
            "source": assessment["source"],
            "scope_digest": assessment["scope_digest"],
            "view": view,
            "collection_complete": assessment["complete"],
            "collection_gap_count": len(assessment["gaps"]),
            "matched": len(filtered),
            "offset": offset,
            "returned": 0,
            "next_offset": None,
            "max_chars": max_chars,
            "items": [],
            "oversized_rows": 0,
            "analysis_scope": [
                {
                    "evidence_id": entry["id"],
                    "status": entry["stats"].get("status"),
                    "candidate_counts": entry["stats"].get("candidate_counts", {}),
                    "topology_complete": entry["stats"].get("topology", {}).get("complete"),
                }
                for entry in entries
                if entry["kind"] in {"static-analysis", "javascript-analysis"}
            ],
        }
        if view == "snippets" and not filtered:
            result["gap"] = (
                "No matching source window was captured; the range is unknown. Rescan with a compatible collector or inspect source separately and verify its digest."
            )
        if view in {"graph", "hotspots"} and not any(
            ("topology" if view == "graph" else "hotspots") in entry.get("stats", {})
            for entry in entries
        ):
            result["gap"] = (
                "This view was not collected for the saved snapshot; rescan with a compatible collector."
            )
        for row in filtered[offset : offset + limit]:
            result["items"].append(row)
            if len(json.dumps(result, indent=2)) + 100 > max_chars:
                result["items"].pop()
                if result["items"]:
                    break
                result["items"].append(
                    {
                        "evidence_id": row.get("evidence_id"),
                        "path": row.get("path"),
                        "omitted": "Row exceeds output budget; use a narrower view or raise max_chars.",
                    }
                )
                result["oversized_rows"] += 1
                break
        result["returned"] = len(result["items"])
        end = offset + result["returned"]
        result["next_offset"] = end if end < len(filtered) else None
        if len(json.dumps(result, indent=2)) > max_chars:
            raise ValueError("Output budget is too small for snapshot identity; raise max_chars")
        return result

    def source_context(self, assessment_id, evidence_id, line=1, end_line=None, max_chars=8000):
        """Read only captured source whose current complete bytes match the saved digest."""
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
        entry = next((row for row in assessment["evidence"] if row["id"] == evidence_id), None)
        if entry is None:
            raise ValueError("Unknown evidence ID in this assessment")
        from .source_context import read_context

        return {
            "assessment_id": assessment_id,
            "source": assessment["source"],
            **read_context(
                Path(assessment["source"]["root"]),
                entry,
                line=line,
                end_line=end_line,
                max_chars=max_chars,
            ),
        }

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

    def doctor(self, assessment_id, *, limit=100):
        """Project captured simplify candidates without executing or changing source."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Doctor limit must be an integer from 1 to 100")
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
            alignment = self._alignment(db, assessment)
        groups = {lens: [] for lens in ("reuse", "quality", "efficiency")}
        families = {
            name: []
            for name in (
                "python_ast",
                "javascript_ast",
                "tests",
                "ruff",
                "ecosystem",
                "dead_code",
                "sarif",
            )
        }
        entries = assessment["evidence"]
        source_ids = {entry["path"]: entry["id"] for entry in entries}
        analyses = [
            entry
            for entry in entries
            if entry["kind"] in {"static-analysis", "javascript-analysis"}
        ]
        analysis = analyses[0]["stats"] if analyses else None
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
        guidance.update(
            {
                "near_duplicate_function": (
                    "Compare the differing literals, callees and interfaces before sharing behavior.",
                    "Preserve each caller's distinct outputs, errors and side effects.",
                ),
                "duplicate_block": (
                    "Compare bindings and control flow around the repeated block before extracting one shared concern.",
                    "Check the enclosing functions' outcomes, errors and early exits.",
                ),
                "unreachable_statement": (
                    "Inspect the stated control-flow proof and remove only statements that cannot execute in this context.",
                    "Verify the enclosing branch and its important success and failure outcomes.",
                ),
                "unused_symbol": (
                    "Trace local references, public exports, decorators and reflection before changing the symbol.",
                    "Check supported callers and entrypoints; absence of static references alone does not justify deletion.",
                ),
                "unreferenced_module": (
                    "Check package discovery, entrypoints, configuration and dynamic loading before treating the module as unused.",
                    "Verify supported imports and the installed package layout before an authorized removal.",
                ),
                "shadowed_module": (
                    "Verify which module Python resolves in supported source and installed layouts before removing a predecessor.",
                    "Check public imports and packaging; a source-layout collision alone does not establish deletion safety.",
                ),
            }
        )
        status = "not_collected"
        if not analyses:
            gaps.append(
                "Static analysis was not collected for this snapshot; rescan to capture candidates."
            )
        for static in analyses:
            analysis = static["stats"]
            if analysis.get("schema_version") != 1:
                status = "unsupported" if status == "not_collected" else "partial"
                gaps.append(
                    "Captured static-analysis schema is unsupported; use a compatible analyzer and rescan."
                )
                continue
            if status == "not_collected":
                status = analysis["status"]
            elif status != "complete" or analysis["status"] != "complete":
                status = "partial"
            gaps.extend(analysis["gaps"])
            rich = analysis["candidates"]
            index = analysis.get("candidate_index", rich)
            rich_ids = {row.get("id") for row in rich if row.get("id")}
            ordered = (
                [*rich, *(row for row in index if row.get("id") not in rich_ids)]
                if rich_ids
                else index
            )
            for candidate in ordered:
                lens = candidate["lens"]
                if lens not in groups or candidate["kind"] not in guidance:
                    gaps.append(
                        "A captured candidate kind or lens is unsupported by this doctor version."
                    )
                    status = "partial"
                    continue
                smallest_fix, verification = guidance[candidate["kind"]]
                family = (
                    "dead_code"
                    if candidate["kind"]
                    in {
                        "unreachable_statement",
                        "unused_symbol",
                        "unreferenced_module",
                        "shadowed_module",
                    }
                    else "javascript_ast"
                    if static["kind"] == "javascript-analysis"
                    else "python_ast"
                )
                families[family].append(
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
        analysis = analyses[0]["stats"] if analyses else None
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
                    families["tests"].append(
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
            if entry["kind"] not in {"ruff", "sarif"}:
                continue
            if status in {"not_collected", "unsupported"}:
                status = "partial"
            gaps.extend(entry["stats"]["gaps"])
            report_kind = entry["kind"]
            gaps.append(
                f"Supplied {report_kind.upper()} diagnostics have unverified source identity; inspect applicability before changing code."
            )
            for diagnostic in entry["stats"]["diagnostics"]:
                lens = (
                    "efficiency"
                    if report_kind == "ruff" and diagnostic["code"].startswith("PERF")
                    else "quality"
                )
                families[report_kind].append(
                    {
                        "kind": report_kind + "_diagnostic",
                        "lens": lens,
                        "locations": [
                            {key: diagnostic[key] for key in ("path", "line", "end_line")}
                        ],
                        "code": diagnostic["code"],
                        "message": diagnostic["message"],
                        **(
                            {"fix_applicability": diagnostic["fix_applicability"]}
                            if report_kind == "ruff"
                            else {
                                "tool": diagnostic["tool"],
                                "producer_level": diagnostic["producer_level"],
                            }
                        ),
                        "evidence_ids": [entry["id"]],
                        "source_identity": "unverified",
                        "smallest_fix": "Inspect the diagnostic against the intended behavior and apply only the smallest authorized correction.",
                        "verification": "Recheck the diagnostic and the affected behavior; a suggested fix is not proof of safety.",
                    }
                )
        ecosystem = _ecosystem_fit(assessment)
        if ecosystem["status"] in {"complete", "partial"}:
            signals = sorted(
                ecosystem["signals"], key=lambda signal: signal.get("scope") != "source"
            )
            for signal in signals:
                if signal["path"] not in source_ids or not signal.get("line"):
                    continue
                families["ecosystem"].append(
                    {
                        "kind": "ecosystem_fit_review",
                        "lens": "reuse",
                        "locations": [{"path": signal["path"], "line": signal["line"]}],
                        "metrics": {
                            "signal_kind": signal["kind"],
                            "scope": signal.get("scope", "unknown"),
                        },
                        "evidence_ids": sorted(
                            {ecosystem["evidence_id"], source_ids[signal["path"]]}
                        ),
                        "source_identity": "captured_snapshot",
                        "smallest_fix": "Trace whether the syntax signal is active and inspect its required behavior. Compare an existing maintained ecosystem option with the current primitives; retain the current approach when it fits better.",
                        "verification": "Compare required semantics, errors, security, compatibility and dependency upkeep before choosing a bounded change; a syntax signal does not justify migration.",
                    }
                )
        # A large family cannot hide a smaller, independently useful family.
        counts = {
            family: {"captured": len(rows), "returned": 0, "omitted": len(rows)}
            for family, rows in families.items()
        }
        returned = 0
        for index in range(limit):
            for family, rows in families.items():
                if index >= len(rows) or returned >= limit:
                    continue
                candidate = rows[index]
                candidate["family"] = family
                candidate["candidate_confidence"] = {
                    "level": candidate.get("confidence", "low"),
                    "basis": "supplied_unverified_diagnostic"
                    if family in {"ruff", "sarif"}
                    else "captured_syntax",
                    "defect_established": False,
                    "change_safety": "requires_review",
                }
                groups[candidate["lens"]].append(candidate)
                counts[family]["returned"] += 1
                counts[family]["omitted"] -= 1
                returned += 1
        captured = sum(len(rows) for rows in families.values())
        if captured > returned:
            gaps.append(
                "Doctor candidate limit reached; query captured evidence for remaining candidates."
            )
            status = "partial"
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
            "analysis_scope": {
                "coverage": (analysis or {}).get("coverage", {}),
                "candidate_counts": (analysis or {}).get("candidate_counts", {}),
                "summary": (analysis or {}).get("summary", {}),
                "analyses": [
                    {
                        "evidence_id": entry["id"],
                        "kind": entry["kind"],
                        "coverage": entry["stats"].get("coverage", {}),
                        "candidate_counts": entry["stats"].get("candidate_counts", {}),
                    }
                    for entry in analyses
                ],
            },
            "selection": {
                "method": "round_robin_families",
                "limit": limit,
                "captured": captured,
                "returned": returned,
                "omitted": captured - returned,
                "families": counts,
            },
            "goal_alignment": alignment,
            "test_value_static": inventory,
            "ecosystem_fit": ecosystem,
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
            "coverage": {
                "schema_version": 1,
                "scope": "whole_project",
                "examined": [],
                "unexamined": [
                    {
                        "area": "Project-wide review",
                        "reason": "Not yet reviewed; replace this placeholder with actual examined and unexamined areas.",
                    }
                ],
                "limitations": [],
                "validation": [],
            },
            "review_context": {
                "tool_code_digest": assessment.get("tool_provenance", {}).get("code_digest"),
                "loaded_instructions": [],
            },
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
            _validate_planning(review, evidence_ids)
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
                "goal_alignment": self._alignment(db, assessment),
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


def _markdown_text(value):
    text = html.escape(str(value), quote=False).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "[", "]", "|"):
        text = text.replace(character, "\\" + character)
    return text


def _planning_markdown(alignment):
    lines = ["", "## Review coverage", ""]
    coverage = alignment.get("coverage")
    if coverage:
        lines.append("Scope: " + _markdown_text(coverage["scope"]) + ".")
        for area in coverage["examined"]:
            lines.append(
                "- Examined: "
                + _markdown_text(area["area"])
                + "; evidence: "
                + _markdown_text(", ".join(area["evidence_ids"]))
            )
        for area in coverage["unexamined"]:
            lines.append(
                "- Unexamined: "
                + _markdown_text(area["area"])
                + ": "
                + _markdown_text(area["reason"])
            )
        lines.extend("- Limitation: " + _markdown_text(value) for value in coverage["limitations"])
        for check in coverage["validation"]:
            lines.append(
                "- Validation: "
                + _markdown_text(check["check"])
                + ": "
                + _markdown_text(check["status"])
                + "; evidence: "
                + _markdown_text(", ".join(check["evidence_ids"]))
            )
    else:
        lines.append("Review coverage was not recorded.")
    lines += [
        "",
        "## Improvement plan",
        "",
        "Planning status: " + _markdown_text(alignment.get("planning_status", "unknown")) + ".",
    ]
    plan = alignment.get("plan")
    if not plan:
        return lines + [
            "",
            "No authored roadmap was recorded; numeric goals do not supply a diagnosis.",
        ]
    lines += [
        "",
        "Diagnosis: " + _markdown_text(plan["diagnosis"]),
        "",
        "Target state: " + _markdown_text(plan["target_state"]),
    ]
    for item in plan["initiatives"]:
        lines += ["", "### " + _markdown_text(item["title"]), ""]
        for label, value in (
            ("Priority", item["priority"]),
            ("Root cause", item["root_cause"]),
            ("Full scope", item["scope"]),
            ("Burden effect", item["burden_effect"]),
            ("Dependencies", ", ".join(item["depends_on"]) or "None"),
            ("Evidence", ", ".join(item["evidence_ids"])),
        ):
            lines.append(label + ": " + _markdown_text(value))
        lines += ["", "Dimension impacts:", ""]
        lines.extend(
            "- " + _markdown_text(key) + ": " + _markdown_text(value)
            for key, value in item["dimension_impacts"].items()
        )
        lines += [
            "",
            "Acceptance:",
            "",
            *["- " + _markdown_text(value) for value in item["acceptance"]],
        ]
        lines += ["", "First implementation slice: " + _markdown_text(item["first_slice"])]
    return lines


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
    ecosystem = _ecosystem_fit(assessment)
    lines += ["", "## Ecosystem fit", "", f"Collection: {ecosystem['status']}."]
    if ecosystem["status"] in {"complete", "partial"}:
        lines += [
            "",
            f"Captured dependency declarations: {ecosystem['dependency_count']}; "
            f"syntax signals: {ecosystem['signal_count']}. "
            "These are review leads, not a fit rating or a migration recommendation. "
            f"Evidence: {_markdown_text(ecosystem['evidence_id'])}.",
            "",
            _markdown_text(ecosystem["caveat"]),
            "",
            "Dependency inventory:",
        ]
        for dependency in ecosystem["dependencies"]:
            location = dependency["path"]
            if dependency.get("line"):
                location += f":{dependency['line']}"
            lines.append(
                f"- {_markdown_text(dependency['name'])} "
                f"({_markdown_text(dependency['group'])}) — {_markdown_text(location)}"
            )
        if not ecosystem["dependencies"]:
            lines.append("- No declarations captured; runtime dependencies may still exist.")
        lines += ["", "Syntax signals to inspect:"]
        for signal in ecosystem["signals"]:
            location = signal["path"]
            if signal.get("line"):
                location += f":{signal['line']}"
            lines.append(f"- {_markdown_text(signal['kind'])} — {_markdown_text(location)}")
        if not ecosystem["signals"]:
            lines.append("- No supported signals captured; this does not establish fit.")
        lines += [
            "",
            "Collection limits: " + _markdown_text(json.dumps(ecosystem["limits"], sort_keys=True)),
        ]
    lines += ["", *["- " + _markdown_text(gap) for gap in ecosystem.get("gaps", [])]]
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
    lines += _planning_markdown(report.get("goal_alignment", {}))
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
