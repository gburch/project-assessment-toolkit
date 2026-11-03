"""Shared local operations. Source facts, judgments, and goals are separate records."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator

from .collector import collect
from .comparison import compare_assessments
from .confidence import (
    MAX_FINDING_EXCERPT,
    burden_support_assessment,
    confidence_assessment,
    validate_finding_support,
)
from .control_inventory import DIMENSIONS as CONTROL_DIMENSIONS
from .dimension_inputs import dimension_inputs
from .documentation import maintenance_candidates
from .project_context import (
    PROJECT_CONTEXT_SCHEMA,
    project_context_assessment,
    project_context_rubric,
    project_context_template,
    validate_project_context,
)
from .prompting import (
    PROMPTING_SCHEMA,
    prompting_profile,
    prompting_rubric,
    prompting_template,
    validate_prompting,
)
from .report_identity import _draft_digest, _normalized_ratings, canonical
from .report_markdown import _ecosystem_fit, _review_coverage
from .report_markdown import markdown_report as markdown_report
from .review_context import build_challenge_evidence_index, get_system_map
from .review_plan import VERSION as REVIEW_PLAN_VERSION
from .review_plan import build_review_plan
from .rubric import DIMENSIONS, PROFILES, RUBRIC_VERSION, rubric


class ConflictError(ValueError):
    """The caller must refresh before changing local state."""


def now():
    return datetime.now(UTC).isoformat()


# Backfilled snapshots sort by commit time; worktree scans by capture time.
_AS_OF = "COALESCE(json_extract(data,'$.source.origin.as_of'),json_extract(data,'$.created_at'))"
_BACKFILLED = "json_extract(data,'$.source.origin.kind')='git-commit'"
HINDSIGHT_NOTE = (
    "Judged in hindsight from committed source; knowledge from after this commit may shape "
    "these ratings."
)


def _backfilled(assessment):
    return (assessment.get("source", {}).get("origin") or {}).get("kind") == "git-commit"


def _as_of(assessment):
    return (assessment.get("source", {}).get("origin") or {}).get("as_of") or assessment.get(
        "created_at"
    )


def _id(prefix):
    return prefix + uuid.uuid4().hex


def _gap(score, target, axis):
    """Distance from a capability minimum or burden ceiling; missing stays unknown."""
    if score is None or target is None:
        return None
    return max(target - score if axis == "capability" else score - target, 0)


def _coverage_summary(coverage):
    """Keep coverage totals visible without copying per-file evidence into summaries."""
    if not isinstance(coverage, dict) or not isinstance(coverage.get("batches"), list):
        return coverage

    def detail_table(value, field, path):
        if not isinstance(value, dict) or not isinstance(value.get(field), list):
            return value
        return {
            **{key: item for key, item in value.items() if key != field},
            field + "_retained_in_evidence": len(value[field]),
            "details_available": True,
            "details_path": path,
        }

    batches = []
    for index, batch in enumerate(coverage["batches"]):
        if not isinstance(batch, dict):
            batches.append(batch)
            continue
        projected = dict(batch)
        sections = batch.get("model_sections", {})
        methods = sections.get("methods", {}) if isinstance(sections, dict) else {}
        if isinstance(methods, dict) and "file_coverage" in methods:
            projected["model_sections"] = {
                **sections,
                "methods": {
                    **methods,
                    "file_coverage": detail_table(
                        methods["file_coverage"],
                        "rows",
                        f"stats.coverage.batches[{index}].model_sections.methods.file_coverage.rows",
                    ),
                },
            }
        if "ast_compatibility" in batch:
            projected["ast_compatibility"] = detail_table(
                batch["ast_compatibility"],
                "files",
                f"stats.coverage.batches[{index}].ast_compatibility.files",
            )
        batches.append(projected)
    return {**coverage, "batches": batches}


def _prompting_summary(profile):
    """Keep brief handoffs bounded; authored rationale and citations stay in the report."""
    return {
        **{key: profile[key] for key in ("status", "level", "level_label", "confidence")},
        "variability": {"status": profile["variability"]["status"]},
        "intent": {key: profile["intent"][key] for key in ("min", "max", "basis", "provisional")},
        "fit": {key: profile["fit"][key] for key in ("status", "direction", "provisional")},
        "collection": {
            key: profile["collection"].get(key) for key in ("status", "evidence_id", "summary")
        },
        "details_view": "report",
    }


def _assessment_method(review, *, compact=False):
    """Label recorded review provenance; never infer freshness or independence."""
    method = (review or {}).get("methodology", {})
    origins = method.get("dimensions", {})
    labels = {
        "reassessed": "Freshly reassessed",
        "carried_forward": "Carried forward",
        "unreviewed": "Unreviewed",
        "unestablished": "Freshness unestablished",
    }
    dimensions = {
        dimension: {
            "origin": origins.get(dimension, "unestablished"),
            "label": labels[origins.get(dimension, "unestablished")],
        }
        for dimension in DIMENSIONS
    }
    challenge = (review or {}).get("challenge", {"status": "unrecorded"})
    traces = (review or {}).get("change_traces", [])
    needs_trace = (
        method.get("mode") == "fresh"
        and (review or {}).get("coverage", {}).get("scope") == "whole_project"
    )
    completed = (
        bool(method) and challenge["status"] == "completed" and (not needs_trace or bool(traces))
    )
    gaps = []
    if not method:
        gaps.append("Freshness was not recorded; existing scores have not been reclassified.")
    if challenge["status"] != "completed":
        gaps.append("No completed independent challenge is recorded; this review is provisional.")
    if needs_trace and not traces:
        gaps.append("No representative change trace is recorded; this review is provisional.")
    result = {
        "schema_version": 1,
        "status": method.get("mode", "unestablished"),
        "completion": "completed" if completed else "provisional" if method else "unestablished",
        "reviewer_id": method.get("reviewer_id"),
        "based_on_review_id": method.get("based_on_review_id"),
        "dimensions": dimensions,
        "counts": {
            origin: sum(row["origin"] == origin for row in dimensions.values()) for origin in labels
        },
        "trace_count": len(traces),
        "challenge": challenge,
        "gaps": gaps,
        "caveat": "Freshness and reviewer independence are declarations bound to captured evidence, not authenticated approval. Accepted challenge responses do not mean engineering changes are complete.",
    }
    if compact:
        items = challenge.get("items", [])
        result["challenge"] = {
            "status": challenge["status"],
            "reviewer_id": challenge.get("reviewer_id"),
            "independence": challenge.get("independence"),
            "item_count": len(items),
            "response_counts": {
                decision: sum(item["response"]["decision"] == decision for item in items)
                for decision in ("accepted", "rejected", "deferred")
            },
        }
    else:
        result["change_traces"] = traces
    return result


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
        "performance": "Establish user-relevant workload and resource needs before adding assurance. Existing or occasional source-linked measurements can support the selected level; a benchmark suite or blocking CI gate is not required. Retain capacity gaps, inspect threshold margin and variance, and weigh rerun and baseline-maintenance cost before recommending more machinery or a goal tradeoff.",
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
            next_step = f"Plan for the full capability minimum {target_capability}: {target_anchor} Preserve required behavior and safeguards; keep upkeep within burden ceiling {target['burden_max']}. Weigh user value and required system changes against added upkeep before choosing an implementation slice and acceptance evidence. If assurance would be disproportionate, explain the remaining gap and an owner-reviewed goal tradeoff rather than adding machinery solely for the score."
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
        "review_coverage": _review_coverage(review),
        "assessment_method": _assessment_method(review),
        "confidence_assessment": confidence_assessment(assessment, review),
        "dimension_inputs": dimension_inputs(assessment),
        "system_map": get_system_map(assessment),
        "project_context": project_context_assessment(assessment, review, goals),
        "prompting": prompting_profile(assessment, review),
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


def _confidence_summary(confidence):
    """Keep confidence labels/readiness, with detailed omission context in review-plan."""
    result = json.loads(canonical(confidence))
    for row in result.get("dimensions", {}).values():
        coverage = row.get("coverage", {})
        row["coverage"] = {
            "status": coverage.get("status"),
            "omission_counts": coverage.get("omission_counts", {}),
            "analysis_limit_count": len(coverage.get("analysis_limits", [])),
            "syntax_gap_count": len(coverage.get("syntax_gaps", [])),
            "details_view": "review-plan",
        }
        readiness = row.get("burden", {}).get("support", {}).get("readiness", {})
        steps = readiness.get("next_steps", [])
        readiness["next_steps"] = steps[:1]
        readiness["omitted_next_steps"] = max(0, len(steps) - 1)
        readiness.pop("caveat", None)
    return result


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
        "burden_support": _object(
            {
                "claim": TEXT,
                "scope": {"enum": ["project", "workflow"]},
                "scope_description": TEXT,
                "observation_ids": IDS,
                "change_trace_ids": {
                    "type": "array",
                    "maxItems": 100,
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$"},
                },
                "representativeness": TEXT,
                "counterevidence": TEXT,
                "freshness": TEXT,
                "limitations": {"type": "array", "items": TEXT, "maxItems": 20},
                "corroboration_ids": IDS,
                "counterevidence_ids": IDS,
            },
            required=[
                "claim",
                "scope",
                "scope_description",
                "observation_ids",
                "change_trace_ids",
                "representativeness",
                "counterevidence",
                "freshness",
                "limitations",
            ],
        ),
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
        "dimension_reviews": _object(
            {
                dimension: _object(
                    {
                        "status": {"enum": ["reviewed", "partial", "unreviewed"]},
                        "rationale": TEXT,
                        "evidence_ids": IDS,
                    }
                )
                for dimension in DIMENSIONS
            }
        ),
    },
    required=["schema_version", "scope", "examined", "unexamined", "limitations", "validation"],
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
METHODOLOGY_SCHEMA = _object(
    {
        "schema_version": {"const": 1},
        "mode": {"enum": ["fresh", "refresh"]},
        "reviewer_id": {"type": "string", "minLength": 1, "maxLength": 200},
        "based_on_review_id": {"type": ["string", "null"], "maxLength": 100},
        "dimensions": _object(
            {dim: {"enum": ["reassessed", "carried_forward", "unreviewed"]} for dim in DIMENSIONS}
        ),
        "confidence_standard": {"const": "source-estimate-v1"},
    },
    required=["schema_version", "mode", "reviewer_id", "based_on_review_id", "dimensions"],
)
CHANGE_TRACE_SCHEMA = _object(
    {
        "id": INITIATIVE_ID,
        "title": TEXT,
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": _object(
                {
                    "owner": TEXT,
                    "change": TEXT,
                    "evidence_ids": IDS,
                    "activity": {"enum": ["edit", "verification", "inspection", "unknown"]},
                },
                required=["owner", "change", "evidence_ids"],
            ),
        },
        "cost": TEXT,
        "invariant": TEXT,
        "counterevidence": TEXT,
        "gaps": {"type": "array", "items": TEXT, "maxItems": 20},
    }
)
CHALLENGE_SCHEMA = _object(
    {
        "schema_version": {"const": 1},
        "status": {"enum": ["completed", "unavailable"]},
        "reviewer_id": {"type": "string", "minLength": 1, "maxLength": 200},
        "independence": {"const": "declared"},
        "draft_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "summary": TEXT,
        "evidence_ids": IDS,
        "gaps": {"type": "array", "items": TEXT, "maxItems": 20},
        "burden_dimensions": {
            "type": "array",
            "uniqueItems": True,
            "maxItems": len(DIMENSIONS),
            "items": {"enum": list(DIMENSIONS)},
        },
        "items": {
            "type": "array",
            "maxItems": 30,
            "items": _object(
                {
                    "id": INITIATIVE_ID,
                    "concern": TEXT,
                    "evidence_ids": IDS,
                    "response": _object(
                        {
                            "decision": {"enum": ["accepted", "rejected", "deferred"]},
                            "rationale": TEXT,
                            "evidence_ids": IDS,
                        }
                    ),
                }
            ),
        },
    },
    required=["schema_version", "status", "summary", "gaps"],
)
FINDING_SUPPORT_SCHEMA = _object(
    {
        "confidence": {"enum": ["low", "medium", "high"]},
        "scope": {"enum": ["source", "inference"]},
        "rationale": TEXT,
        "citations": {
            "type": "array",
            "minItems": 1,
            "maxItems": 4,
            "items": _object(
                {
                    "evidence_id": {"type": "string", "maxLength": 200},
                    "line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                    "excerpt": {"type": "string", "minLength": 1, "maxLength": MAX_FINDING_EXCERPT},
                }
            ),
        },
        "counterevidence": TEXT,
        "limitations": {"type": "array", "items": TEXT, "maxItems": 20},
    }
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
                    "support": FINDING_SUPPORT_SCHEMA,
                },
                required=["severity", "title", "evidence_ids"],
            ),
        },
        "coverage": COVERAGE_SCHEMA,
        "plan": PLAN_SCHEMA,
        "project_context": PROJECT_CONTEXT_SCHEMA,
        "prompting": PROMPTING_SCHEMA,
        "methodology": METHODOLOGY_SCHEMA,
        "change_traces": {"type": "array", "maxItems": 10, "items": CHANGE_TRACE_SCHEMA},
        "challenge": CHALLENGE_SCHEMA,
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
    if "project_context" in review:
        validate_project_context(review["project_context"], evidence_ids, review.get("plan"))
    for dimension, row in coverage.get("dimension_reviews", {}).items():
        if not set(row["evidence_ids"]) <= evidence_ids or (
            row["status"] in {"reviewed", "partial"} and not row["evidence_ids"]
        ):
            raise ValueError("Reviewed dimensions must cite captured evidence")
        if (
            coverage["scope"] == "whole_project"
            and row["status"] == "unreviewed"
            and any(
                review["ratings"][dimension][axis] is not None for axis in ("capability", "burden")
            )
        ):
            raise ValueError("Unreviewed whole-project dimensions cannot carry numeric ratings")
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
        schema = {
            "metadata": (
                ("key", "value"),
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            ),
            "projects": (
                ("id", "root", "name"),
                "CREATE TABLE projects (id TEXT PRIMARY KEY, root TEXT UNIQUE NOT NULL, name TEXT NOT NULL)",
            ),
            "assessments": (
                ("seq", "id", "project_id", "data"),
                "CREATE TABLE assessments (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, project_id TEXT NOT NULL REFERENCES projects(id), data TEXT NOT NULL)",
            ),
            "reviews": (
                ("seq", "id", "assessment_id", "data"),
                "CREATE TABLE reviews (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, assessment_id TEXT NOT NULL REFERENCES assessments(id), data TEXT NOT NULL)",
            ),
            "goals": (
                ("seq", "project_id", "revision", "data"),
                "CREATE TABLE goals (seq INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL REFERENCES projects(id), revision INTEGER NOT NULL, data TEXT NOT NULL, UNIQUE(project_id, revision))",
            ),
            "requests": (
                ("id", "operation", "payload", "result"),
                "CREATE TABLE requests (id TEXT PRIMARY KEY, operation TEXT NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL)",
            ),
        }
        # Serialize first creation with other constructors. Individual statements
        # retain this transaction; executescript would implicitly commit it.
        with self._db(write=True) as db:
            objects = set(
                db.execute("SELECT name,type FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'")
            )
            if objects:
                if ("metadata", "table") not in objects:
                    raise ValueError("Unversioned or incomplete assessment state schema")
                try:
                    version = db.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()
                except sqlite3.DatabaseError:
                    raise ValueError("Incomplete assessment state schema") from None
                if version is None:
                    raise ValueError("Unversioned assessment state schema")
                if version[0] != "1":
                    raise ValueError("Unsupported assessment state schema version")
                for name, (columns, _) in schema.items():
                    actual = tuple(row[1] for row in db.execute(f"PRAGMA table_info({name})"))
                    if (name, "table") not in objects or actual != columns:
                        raise ValueError("Incomplete or incompatible assessment state schema")
                for (root,) in db.execute("SELECT root FROM projects"):
                    if self.state_dir.is_relative_to(Path(root)):
                        raise ValueError("State directory must be outside assessed projects")
            else:
                for _, statement in schema.values():
                    db.execute(statement)
                db.execute("INSERT INTO metadata VALUES ('schema_version', '1')")
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
        if self.state_dir.is_relative_to(path) or path.is_relative_to(self.state_dir):
            raise ValueError("Assessed projects and the state directory must be outside each other")
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
        return {
            **rubric(),
            "project_context": project_context_rubric(),
            "prompting": prompting_rubric(),
        }

    def scan(self, root, reports=None, *, analysis_profile="standard", analyzers=None):
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
        snapshot = collect(
            root, reports=report_paths, analysis_profile=analysis_profile, analyzers=analyzers
        )
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

    def backfill(
        self,
        root,
        *,
        months=None,
        tags=None,
        revisions=None,
        analysis_profile="standard",
        analyzers=None,
    ):
        """Save facts-only snapshots of earlier commits read from local Git objects.

        Nothing is checked out or written in the project. Each commit's blobs are
        verified and extracted beneath state, then collected like a worktree scan.
        Ratings stay unknown until a review, which is then labelled as hindsight.
        """
        from .analyzer_registry import validate_analyzers
        from .budgets import get_budget
        from .git_backfill import CAVEAT, VERSION, replace_snapshot, select_commits

        root = self._root(root)
        get_budget(analysis_profile)
        analyzers = validate_analyzers(analyzers)
        plan = select_commits(root, months=months, tags=tags, revisions=revisions)
        project_id = "p_" + hashlib.sha256(str(root).encode()).hexdigest()[:24]
        with self._db(write=True) as db:
            db.execute(
                "INSERT OR IGNORE INTO projects VALUES (?,?,?)", (project_id, str(root), root.name)
            )
        results = []
        for commit in plan["commits"]:
            row = {key: commit[key] for key in ("revision", "committed_at", "selected_by")}
            with self._db() as db:
                existing = db.execute(
                    f"SELECT id FROM assessments WHERE project_id=? AND {_BACKFILLED} AND "
                    "json_extract(data,'$.source.revision')=? AND "
                    "json_extract(data,'$.facts.collection.analysis_profile')=? "
                    "ORDER BY seq DESC LIMIT 1",
                    (project_id, commit["revision"], analysis_profile),
                ).fetchone()
            if existing:
                results.append({**row, "status": "existing", "assessment_id": existing[0]})
                continue
            started = time.monotonic()
            try:
                directory, extraction = replace_snapshot(self.state_dir, project_id, commit, root)
                snapshot = collect(
                    directory,
                    analysis_profile=analysis_profile,
                    analyzers=analyzers,
                    git_snapshot={
                        "revision": commit["revision"],
                        "paths": extraction["paths"],
                        "repository": root,
                    },
                )
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                gap = str(error) if isinstance(error, ValueError) else "Git objects were unreadable"
                results.append({**row, "status": "unavailable", "gaps": [gap]})
                continue
            snapshot["collection"] = {"seconds": round(time.monotonic() - started, 4)}
            snapshot["source"] = {
                **snapshot["source"],
                "root": str(root),
                "origin": {
                    "kind": "git-commit",
                    "version": VERSION,
                    "tree": commit["tree"],
                    "committed_at": commit["committed_at"],
                    "as_of": commit["as_of"],
                    "selected_by": commit["selected_by"],
                    "extraction": extraction["coverage"],
                    "caveat": CAVEAT,
                },
            }
            snapshot["gaps"] = sorted({*snapshot["gaps"], *extraction["gaps"], CAVEAT})
            snapshot.update(id=_id("a_"), project_id=project_id, created_at=now())
            with self._db(write=True) as db:
                db.execute(
                    "INSERT INTO assessments(id,project_id,data) VALUES (?,?,?)",
                    (snapshot["id"], project_id, canonical(snapshot)),
                )
            results.append(
                {
                    **row,
                    "status": "captured",
                    "assessment_id": snapshot["id"],
                    "complete": snapshot["complete"],
                    "gaps": extraction["gaps"],
                }
            )
        return {
            "project_id": project_id,
            "selection": plan["selection"],
            "snapshots": results,
            "gaps": plan["gaps"],
            "caveat": CAVEAT,
        }

    def _source_root(self, assessment):
        """Backfills read their private extracted tree; scans read the project."""
        if _backfilled(assessment):
            from .git_backfill import snapshot_directory

            return snapshot_directory(
                self.state_dir, assessment["project_id"], assessment["source"]["revision"]
            )
        return Path(assessment["source"]["root"])

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
                if evidence["kind"] in {
                    "junit",
                    "cobertura",
                    "test-value",
                    "observation",
                    "burden-context",
                    "ruff",
                    "sarif",
                }:
                    path = Path(evidence["path"]).resolve()
                    if not any(path.is_relative_to(root) for root in self.allowed_roots):
                        raise PermissionError("Captured report is outside configured allowed roots")

    @staticmethod
    def _latest(db, project_id):
        """The newest worktree scan; backfilled history never displaces it."""
        row = db.execute(
            f"SELECT data FROM assessments WHERE project_id=? "
            f"ORDER BY COALESCE({_BACKFILLED},0), {_AS_OF} DESC, seq DESC LIMIT 1",
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

    def _timeline(self, db, assessment, limit=12):
        """Recent snapshots up to this one by source time, oldest first, with their
        latest saved ratings. Backfilled commits sort by commit date.

        Preserve transition identity; incompatible rubrics never share a scale.
        """
        (seq,) = db.execute(
            "SELECT seq FROM assessments WHERE id=?", (assessment["id"],)
        ).fetchone()
        as_of = _as_of(assessment)
        rows = db.execute(
            f"SELECT data FROM assessments WHERE project_id=? AND "
            f"({_AS_OF}<? OR ({_AS_OF}=? AND seq<=?)) ORDER BY {_AS_OF} DESC, seq DESC LIMIT ?",
            (assessment["project_id"], as_of, as_of, seq, limit),
        ).fetchall()
        goal_baselines = {
            goal["baseline_assessment_id"]: goal
            for (data,) in db.execute(
                "SELECT data FROM goals WHERE project_id=? ORDER BY revision",
                (assessment["project_id"],),
            )
            if (goal := json.loads(data)).get("baseline_assessment_id")
        }
        timeline, previous, previous_review = [], None, None
        for (data,) in reversed(rows):
            snapshot = json.loads(data)
            try:
                self._authorize_assessment(db, snapshot)
            except PermissionError:
                previous, previous_review = None, None
                continue
            review = self._review(db, snapshot["id"])
            reviewed = review is not None and (
                snapshot.get("rubric_version") == assessment.get("rubric_version")
            )
            first_row = db.execute(
                "SELECT data FROM reviews WHERE assessment_id=? ORDER BY seq LIMIT 1",
                (snapshot["id"],),
            ).fetchone()
            first_review = json.loads(first_row[0]) if first_row else None
            comparison = (
                compare_assessments(previous, snapshot, previous_review, review, first_review)
                if previous is not None
                else {"comparable": False, "event": "initial"}
            )
            goal = goal_baselines.get(snapshot["id"])
            if goal and goal.get("baseline_review_id") == (review or {}).get("id"):
                comparison = {**comparison, "event": "goal_baseline"}
            ratings = review.get("ratings", {}) if reviewed else {}
            timeline.append(
                {
                    "assessment_id": snapshot["id"],
                    "created_at": snapshot.get("created_at"),
                    "as_of": _as_of(snapshot),
                    "origin": "git-commit" if _backfilled(snapshot) else "scan",
                    "revision": snapshot.get("source", {}).get("revision"),
                    "review_id": (review or {}).get("id"),
                    "rubric_version": snapshot.get("rubric_version"),
                    "scope_digest": snapshot.get("scope_digest"),
                    "manifest_digest": snapshot.get("source", {}).get("manifest_digest"),
                    "complete": snapshot.get("complete") is True,
                    "goal_revision": goal["revision"] if goal else None,
                    "comparison": comparison,
                    "reviewed": reviewed,
                    "hindsight": reviewed and "hindsight" in review,
                    "ratings": {
                        dimension: {
                            axis: ratings.get(dimension, {}).get(axis)
                            for axis in ("capability", "burden")
                        }
                        for dimension in DIMENSIONS
                    },
                }
            )
            previous, previous_review = snapshot, review
        return timeline

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
        return {
            "assessment_id": assessment_id,
            "project_id": assessment["project_id"],
            "created_at": assessment["created_at"],
            "source": assessment["source"],
            "scope_digest": assessment["scope_digest"],
            "rubric_version": assessment["rubric_version"],
            "complete": assessment["complete"],
            "project_context": alignment["project_context"],
            "prompting": _prompting_summary(alignment["prompting"]),
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
            "source_analysis": facts.get("source_analysis", {}),
            "optional_analysis": {
                name: {**provider, "coverage": _coverage_summary(provider["coverage"])}
                if isinstance(provider, dict) and "coverage" in provider
                else provider
                for name, provider in facts.get("optional_analysis", {}).items()
            },
            "collection_scope": {
                key: value
                for key, value in facts.get("collection", {}).items()
                if key not in {"skipped_inputs", "unsearched_directories", "unprocessed_reports"}
            },
            "evidence_kinds": {
                kind: sum(entry["kind"] == kind for entry in assessment["evidence"])
                for kind in sorted({entry["kind"] for entry in assessment["evidence"]})
            },
            "review_id": (review or {}).get("id"),
            "review_coverage": alignment["review_coverage"],
            "assessment_method": _assessment_method(review, compact=True),
            "confidence_assessment": _confidence_summary(confidence_assessment(assessment, review)),
            "dimension_inputs": alignment["dimension_inputs"],
            "review_plan": {
                "version": REVIEW_PLAN_VERSION,
                "view": "review-plan",
                "next_step": "Inspect the per-dimension source tasks and counterevidence questions; revisit low-confidence dimensions before final review.",
            },
            "system_map": alignment["system_map"],
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
            "next_step": (
                "Captured facts have no authored review yet. For an assessment request, inspect "
                "system_map, dimension_inputs, the rubric and representative source workflows; "
                "establish current scope/readiness and stated or provisional intended purpose, "
                "then author cited ratings, coverage and a proportionately ranked plan using "
                "review_template. Preserve explicit numeric targets. "
                "For a whole-project review, complete the independent challenge or record its "
                "unavailability, then submit_review and read the saved report. Give the user "
                "the verdict, scores, important findings, improvement plan and limits inline, "
                "with artifact links as supporting evidence. Explicit scan-only requests may "
                "stop at capture scope and unscored facts."
                if review is None
                else "An authored review is saved. Read the full report for its diagnosis, "
                "current scope/readiness, intended purpose, cited ratings, findings, coverage "
                "and ranked plan; use evolve for goal alignment and "
                "history/progress only where comparable. Present a substantive inline report "
                "with evidence and limits, respecting the requested scope. Artifact links "
                "support the report rather than replacing it."
            ),
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
        dimension=None,
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
            "dataflow",
            "hotspots",
            "coverage",
            "provenance",
            "areas",
            "area-dependencies",
            "controls",
            "burden",
            "prompting",
            "review-plan",
        }
        if view not in views:
            raise ValueError("Unknown evidence query view")
        allowed_dimensions = CONTROL_DIMENSIONS if view == "controls" else DIMENSIONS
        if dimension is not None and (
            view not in {"controls", "burden", "review-plan"} or dimension not in allowed_dimensions
        ):
            raise ValueError(
                "Dimension filters require a supported controls, burden or review-plan dimension"
            )
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
        navigation_view = view in {"areas", "area-dependencies"}
        if view == "review-plan" and any(
            value is not None for value in (kind, candidate_kind, line)
        ):
            raise ValueError("Review plans support dimension, path and role filters")
        if navigation_view and any(value is not None for value in (kind, candidate_kind, line)):
            raise ValueError(
                "Area directory views support path and role filters, not kind, candidate_kind or line"
            )
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
            review = self._review(db, assessment_id) if view == "review-plan" else None
        entries = assessment["evidence"]
        source = {entry["path"]: entry for entry in entries}
        documentation_projections = {
            entry["id"]: maintenance_candidates(entry, source)
            for entry in entries
            if entry["kind"] == "documentation-analysis"
            and (view == "candidates" or candidate_kind is not None and view != "controls")
            and kind in {None, "documentation-analysis"}
        }
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
            if entry["kind"] in {"python", "javascript", "source"}:
                return source_role(entry["path"])["role"]
            return entry["kind"]

        candidate_rows = []
        for entry in (
            entries
            if (candidate_kind is not None and view not in {"controls", "prompting"})
            or view == "candidates"
            else []
        ):
            stats = entry.get("stats", {})
            definitions = {row["id"]: row for row in stats.get("definitions", []) if "id" in row}
            candidates = list(stats.get("candidate_index", stats.get("candidates", [])))
            if entry["id"] in documentation_projections:
                candidates.extend(documentation_projections[entry["id"]]["candidates"])
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
        for entry in entries if not navigation_view and view != "review-plan" else []:
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
            elif view == "controls" and entry["kind"] == "control-analysis":
                rows.extend(
                    {**row, "kind": "file", "record_type": "control_file", **common}
                    for row in stats.get("files", [])
                )
                rows.extend(
                    {**row, "record_type": "control_signal", **common}
                    for row in stats.get("signals", [])
                )
            elif view == "burden" and entry["kind"] == "burden-analysis":
                rows.extend({**row, **common} for row in stats.get("leads", []))
                rows.extend(
                    {
                        **timing,
                        **common,
                        "kind": "burden_timing",
                        "dimensions": ["testing", "delivery"],
                        "reported_evidence_id": timing.get("evidence_id"),
                    }
                    for timing in stats.get("timings", [])
                )
            elif view == "burden" and entry["kind"] == "burden-context":
                rows.extend(
                    {
                        **claim,
                        **common,
                        "kind": "attributed_change_experience",
                        "attribution": stats.get("attribution"),
                        "reported_at": stats.get("reported_at"),
                        "period": stats.get("period"),
                        "scope": stats.get("scope"),
                        "sourceIdentity": stats.get("sourceIdentity"),
                        "limitations": stats.get("limitations", []),
                    }
                    for claim in stats.get("claims", [])
                )
            elif view == "candidates":
                rows.extend(by_evidence.get(entry["id"], []))
            elif view == "prompting" and entry["kind"] == "prompting-analysis":
                rows.extend(
                    {**row, "record_type": "prompting_signal", **common}
                    for row in stats.get("signals", [])
                )
                rows.extend(
                    {**row, "kind": "file", "record_type": "prompting_file", **common}
                    for row in stats.get("coverage", {}).get("files", [])
                )
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
                    {**edge, "path": edge["source"], "record_type": "inferred_edge", **common}
                    for edge in stats.get("topology", {}).get("inferred_edges", [])
                )
                rows.extend(
                    {**module, "record_type": "module", **common}
                    for module in stats.get("modules", [])
                )
            elif view == "dataflow":
                flow = stats.get("dataflow_analysis", {})
                rows.extend(
                    {**row, "record_type": "value_flow", "locations": row["steps"], **common}
                    for row in flow.get("paths", [])
                )
                rows.extend(
                    {**row, "record_type": "dataflow_skipped_method", **common}
                    for batch in flow.get("batches", [])
                    for row in batch.get("skipped_methods", {}).get("rows", [])
                )
                rows.extend(
                    {**row, "record_type": "dataflow_endpoint", "language": batch["language"],
                     "selection_policy": batch["selection"]["policy"],
                     "plan_digest": batch["selection"]["plan_digest"], **common}
                    for batch in flow.get("batches", [])
                    for row in batch.get("selection", {}).get("endpoints", [])
                )
            elif view == "hotspots":
                rows.extend({**row, **common} for row in stats.get("hotspots", []))
            elif view == "coverage" and entry["kind"] == "documentation-analysis":
                rows.append(
                    {
                        "coverage": stats.get("scope", {}),
                        "drift_scope": stats.get("driftEvidence", {}).get("scope", {}),
                        "gaps": stats.get("gaps", []),
                        **common,
                    }
                )
            elif view == "coverage" and "coverage" in stats:
                rows.append(
                    {
                        "coverage": {
                            key: value for key, value in stats["coverage"].items() if key != "files"
                        }
                        if entry["kind"] == "prompting-analysis"
                        else _coverage_summary(stats["coverage"]),
                        "status": stats.get("status"),
                        "limits": stats.get("limits", {}),
                        "candidate_counts": stats.get("candidate_counts", {}),
                        **common,
                    }
                )
        navigation = None
        review_plan = None
        if view == "review-plan":
            review_plan = build_review_plan(assessment, review, dimension=dimension)
            for dim, packet in review_plan["dimensions"].items():
                rows.append(
                    {
                        "record_type": "dimension_review_scope",
                        "dimension": dim,
                        **{
                            key: value
                            for key, value in packet.items()
                            if key not in {"source_tasks", "connections"}
                        },
                    }
                )
                rows.extend(
                    {"record_type": "source_task", "dimension": dim, **task}
                    for task in packet["source_tasks"]
                )
                rows.extend(
                    {
                        "record_type": "captured_connection",
                        "dimension": dim,
                        **edge,
                        "locations": [{"path": edge["source"]}, {"path": edge["target"]}],
                    }
                    for edge in packet["connections"]
                )
        if navigation_view:
            navigation = get_system_map(assessment, compact=False)
            if view == "areas":
                rows = [
                    {**area, "record_type": "area", "role": "production"}
                    for area in navigation["areas"]
                ]
            else:
                rows = [
                    {
                        **dependency,
                        "record_type": "area_dependency",
                        "role": "production",
                        "locations": [
                            {"path": dependency["source_area"]},
                            {"path": dependency["target_area"]},
                        ],
                    }
                    for dependency in navigation["cross_area_dependencies"]
                ]
        if view == "coverage" and kind is None:
            if assessment["facts"].get("collection", {}).get("analysis_profile") == "deep":
                providers = dimension_inputs(assessment)["providers"]
                for provider, check in (
                    ("dead_code", "dead_code"),
                    ("documentation", "documentation_drift"),
                ):
                    rows.append(
                        {
                            "record_type": "required_deep_check",
                            "check": check,
                            **providers[provider],
                        }
                    )
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
            if view in {"controls", "burden", "prompting"}:
                if dimension is not None and dimension not in row.get("dimensions", []):
                    continue
                if candidate_kind is not None and row.get("kind") != candidate_kind:
                    continue
            paths = (
                [row["path"]]
                if "path" in row
                else [location["path"] for location in row.get("locations", [])]
            )
            if view == "burden" and row.get("kind") == "attributed_change_experience":
                paths = list(
                    dict.fromkeys(
                        row.get("scope", {}).get("paths", [])
                        + [
                            p
                            for example in row.get("examples", [])
                            for p in example.get("paths", [])
                        ]
                    )
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
                and view
                not in {"candidates", "index", "details", "controls", "burden", "prompting"}
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
                    **(
                        {
                            "dataflow_status": entry["stats"]
                            .get("dataflow_analysis", {})
                            .get("status", "not_collected"),
                            "phases": entry["stats"].get("coverage", {}).get("phases", {}),
                            "query_coverage": [
                                {"language": batch["language"], "status": batch["status"],
                                 "queries": batch.get("queries", {}),
                                 "selection_policy": batch.get("selection", {}).get("policy"),
                                 "plan_digest": batch.get("selection", {}).get("plan_digest"),
                                 "checkpoint_recovered": batch.get("checkpoint_recovered", False)}
                                for batch in entry["stats"].get("dataflow_analysis", {}).get("batches", [])
                            ],
                        }
                        if view == "dataflow"
                        else {}
                    ),
                }
                for entry in entries
                if entry["kind"] != "prompting-analysis"
                or view in {"prompting", "coverage", "review-plan"}
                or kind == "prompting-analysis"
                if entry["kind"]
                in {
                    "static-analysis",
                    "javascript-analysis",
                    "source-analysis",
                    "analyzer-analysis",
                    "control-analysis",
                    "burden-analysis",
                    "prompting-analysis",
                }
            ],
        }
        if view == "dataflow":
            result["caveat"] = (
                "Modeled value influence under Joern's default semantics and call targets, "
                "not validated provenance, feasible execution or safe deletion. External calls, "
                "callbacks and execution boundaries can produce spurious paths; verify source "
                "and library contracts. Empty results leave missing flows unknown."
            )
        if view == "prompting":
            result["caveat"] = (
                "Captured naming and syntax hints are not observed model execution, AI authorship, "
                "a prompt reliance level or measured output variability. Inspect actual product "
                "and host-agent workflows, authority and evaluation evidence before judging fit."
            )
        if documentation_projections and view == "candidates":
            result["documentation_scope"] = {
                "collection_status": dimension_inputs(assessment)["providers"]["documentation"][
                    "collection_status"
                ],
                "details_view": "coverage",
                "projections": [
                    {
                        "evidence_id": identity,
                        "status": projection["status"],
                        "omitted": projection["omitted"],
                    }
                    for identity, projection in documentation_projections.items()
                ],
            }
        if view == "controls":
            result["caveat"] = (
                "Coverage rows describe the supported syntax rules; signals describe mechanisms, "
                "risk candidates or naming hints, not effective controls, defects or absence proof."
                if any(entry["kind"] == "control-analysis" for entry in entries)
                else "Control inventory was not collected in this snapshot."
            )
        if review_plan is not None:
            result["review_plan_scope"] = {
                key: review_plan[key] for key in ("version", "limits", "caveat")
            }
        if view == "burden":
            result["burden_scope"] = [
                {
                    "evidence_id": entry["id"],
                    **{
                        key: entry["stats"].get(key)
                        for key in ("status", "coverage", "limits", "caveat")
                    },
                    "gaps": entry["stats"].get("gaps", [])[:5],
                    "omitted_gaps": max(0, len(entry["stats"].get("gaps", [])) - 5),
                    "dimensions": {
                        d: {
                            key: value
                            for key, value in summary.items()
                            if key in {"lead_count", "retained_leads", "cost_status"}
                        }
                        for d, summary in entry["stats"].get("dimensions", {}).items()
                    },
                    "timing_records": len(entry["stats"].get("timings", [])),
                    "timing_view": "Paginated burden_timing rows retain declared semantics; they are not whole-gate wall time by default.",
                }
                for entry in entries
                if entry["kind"] == "burden-analysis"
            ]
            result["caveat"] = (
                "Source mechanisms and attributed experience are distinct. Static leads do not "
                "establish actual waits, recurrence or burden scores. Inspect declared scope, "
                "timing semantics, counterevidence and confidence support."
            )
        if navigation is not None:
            result["navigation_scope"] = {
                "status": navigation["status"],
                "production_files": navigation["production_files"],
                "production_areas": navigation["area_count"],
                "cross_area_dependencies": len(navigation["cross_area_dependencies"]),
                "excluded_files_by_role": navigation["excluded_files_by_role"],
                "excluded_nonproduction_or_uncaptured_import_edges": navigation[
                    "excluded_nonproduction_or_uncaptured_import_edges"
                ],
                "citations_per_group": navigation["limits"]["citations_per_group"],
                "caveat": navigation["caveat"],
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
        if "documentation_scope" in result and len(json.dumps(result, indent=2)) + 300 > max_chars:
            # Reserve room for a candidate or its explicit oversized-row marker.
            # Full collection/projection detail remains in coverage and Doctor.
            result["documentation_scope"] = {"details_view": "coverage"}
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
        if navigation is not None:
            result["remaining"] = max(0, len(filtered) - end)
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
                self._source_root(assessment),
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
                "source_text",
                "documentation",
            )
        }
        entries = assessment["evidence"]
        source_ids = {entry["path"]: entry["id"] for entry in entries}
        analyses = [
            entry
            for entry in entries
            if entry["kind"]
            in {"static-analysis", "javascript-analysis", "source-analysis", "analyzer-analysis"}
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
                    "Inspect reachability and binding/compiler effects before removal, including async-generator shape and hoisted declarations.",
                    "Preserve public contracts, generator/coroutine classification, cleanup and important outcomes; unreachable does not mean safe to delete.",
                ),
                "redundant_condition": (
                    "Inspect the redundant guard while preserving its reachable body and any condition-evaluation effects.",
                    "Verify the body still executes with the same outputs, side effects and public contracts.",
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
                "duplicate_source_file": (
                    "Inspect exact text matches against supported callers and deliberate boundary or generated scaffolding before sharing source.",
                    "Preserve each file's language, packaging and public behavior; text equality does not establish semantic interchangeability.",
                ),
                "duplicate_source_block": (
                    "Compare bindings and enclosing responsibilities around the matching text before proposing a shared concern.",
                    "Preserve language-specific outputs, errors, authority and side effects; source-text analysis does not parse semantics.",
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
                    "analyzer:" + str(analysis.get("analyzer", {}).get("name", "unknown"))[:100]
                    if static["kind"] == "analyzer-analysis"
                    else "source_text"
                    if static["kind"] == "source-analysis"
                    else "dead_code"
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
                families.setdefault(family, []).append(
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
                            "assertions": {
                                "countBasis": "legacy_bare_ast_assert",
                                "attribution": "legacy_scope_unspecified",
                                "unittestStyleCallCount": None,
                                "unittestStyleMethods": None,
                                "unittestStyleCallBasis": "not_collected",
                                "otherCheckStyles": "unknown",
                                **definition["assertions"],
                            },
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
        documentation_scope = dimension_inputs(assessment)["providers"]["documentation"]
        documentation_projections = []
        sources = {entry["path"]: entry for entry in entries}
        for entry in entries:
            if entry["kind"] != "documentation-analysis":
                continue
            projection = maintenance_candidates(entry, sources)
            documentation_projections.append(
                {
                    "evidence_id": entry["id"],
                    **{key: value for key, value in projection.items() if key != "candidates"},
                }
            )
            gaps.extend(projection["gaps"])
            if (
                projection["status"] != "complete"
                or documentation_scope["collection_status"] != "collected"
            ):
                status = "partial"
            for candidate in projection["candidates"]:
                families["documentation"].append(
                    {
                        **candidate,
                        "evidence_ids": sorted({entry["id"], *candidate["source_evidence_ids"]}),
                        "smallest_fix": "Trace the guidance, source, declared commands and actual callers; correct only a demonstrated mismatch or share genuinely repeated guidance.",
                        "verification": "Check affected workflows and source-of-truth ownership. Literal paths, overlap and undeclared scripts do not establish stale guidance or safe deletion.",
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
                    else "captured_text"
                    if family in {"source_text", "documentation"}
                    else "captured_source_producer"
                    if family.startswith("analyzer:")
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
                "documentation": {**documentation_scope, "projections": documentation_projections},
                "coverage": _coverage_summary((analysis or {}).get("coverage", {})),
                "candidate_counts": (analysis or {}).get("candidate_counts", {}),
                "summary": (analysis or {}).get("summary", {}),
                "analyses": [
                    {
                        "evidence_id": entry["id"],
                        "kind": entry["kind"],
                        "coverage": _coverage_summary(entry["stats"].get("coverage", {})),
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
            "prompting": alignment["prompting"],
            "burden_analysis": assessment["facts"].get("burden_analysis", {}),
            "gaps": sorted(set(gaps)),
            "verification": "Trace actual callers and choose relevant behavior checks before an authorized edit; rescan afterward to assess the change.",
            "caveat": "Static candidates and supplied diagnostics require review. Empty groups are not a clean bill of health; this operation assigns no grades and applies no fixes.",
        }

    def review_template(self, assessment_id, mode=None):
        if mode not in {None, "fresh", "refresh"}:
            raise ValueError("Review mode must be fresh or refresh")
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
        result = {
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
            "project_context": project_context_template(),
            "prompting": prompting_template(),
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
                "dimension_reviews": {
                    dimension: {
                        "status": "unreviewed",
                        "rationale": "Not reviewed; inspect the captured evidence for this dimension.",
                        "evidence_ids": [],
                    }
                    for dimension in DIMENSIONS
                },
            },
            "review_context": {
                "tool_code_digest": assessment.get("tool_provenance", {}).get("code_digest"),
                "loaded_instructions": [],
            },
        }
        if mode is not None:
            result["methodology"] = {
                "schema_version": 1,
                "mode": mode,
                "reviewer_id": "unassigned",
                "based_on_review_id": None,
                "dimensions": {dimension: "unreviewed" for dimension in DIMENSIONS},
                "confidence_standard": "source-estimate-v1",
            }
            result["change_traces"] = []
        return result

    def _validate_review_document(self, db, assessment, review, *, final=True):
        _validate(review, REVIEW_SCHEMA)
        if (
            review["assessment_id"] != assessment["id"]
            or review["source_digest"] != assessment["source"]["manifest_digest"]
            or review["rubric_version"] != assessment["rubric_version"]
        ):
            raise ConflictError("Review identity does not match the captured assessment")
        evidence_ids = {item["id"] for item in assessment["evidence"]}
        if "prompting" in review:
            validate_prompting(review["prompting"], assessment["evidence"])

        def cites(ids):
            if not ids or not set(ids) <= evidence_ids:
                raise ValueError("Authored review claims require evidence from this snapshot")

        for rating in review["ratings"].values():
            if not set(rating["evidence_ids"]) <= evidence_ids:
                raise ValueError("Review cites evidence outside its captured snapshot")
            if any(rating[key] is not None for key in ("capability", "burden")):
                cites(rating["evidence_ids"])
        for finding in review["findings"]:
            cites(finding["evidence_ids"])
        support_verification = validate_finding_support(
            assessment, review, root=self._source_root(assessment)
        )
        _validate_planning(review, evidence_ids)
        method = review.get("methodology")
        if method:
            if (
                not method["reviewer_id"].strip()
                or method["reviewer_id"] != method["reviewer_id"].strip()
            ):
                raise ValueError(
                    "Reviewer identity must be nonempty without surrounding whitespace"
                )
            origins = method["dimensions"]
            carried = [dim for dim, origin in origins.items() if origin == "carried_forward"]
            if method["mode"] == "fresh" and carried:
                raise ValueError("A fresh review cannot carry forward judgments")
            prior_id = method["based_on_review_id"]
            if method["mode"] == "refresh" and not prior_id:
                raise ValueError("A refresh must identify its prior review")
            prior = prior_assessment = None
            if prior_id:
                row = db.execute("SELECT data FROM reviews WHERE id=?", (prior_id,)).fetchone()
                if row is None:
                    raise ValueError("Unknown prior review")
                prior = json.loads(row[0])
                prior_assessment = self._assessment(db, prior["assessment_id"])
                same_snapshot = (
                    prior_assessment["rubric_version"] == assessment["rubric_version"]
                    and prior_assessment["scope_digest"] == assessment["scope_digest"]
                    and all(
                        prior_assessment["source"][key] == assessment["source"][key]
                        for key in ("revision", "manifest_digest")
                    )
                )
                if prior_assessment["project_id"] != assessment["project_id"] and not same_snapshot:
                    raise ValueError("Prior review belongs to a different project and snapshot")
                if carried and not same_snapshot:
                    raise ConflictError("Changed source, scope or rubric requires reassessment")
            if carried:
                previous = _normalized_ratings(prior["ratings"])
                current = _normalized_ratings(review["ratings"])
                keys = ("capability", "burden", "confidence", "burden_basis", "burden_confidence")
                for dimension in carried:
                    if any(
                        current[dimension].get(key) != previous[dimension].get(key) for key in keys
                    ):
                        raise ValueError(
                            "Carried-forward judgments must preserve prior axes and confidence"
                        )
            for dimension, origin in origins.items():
                if origin == "unreviewed" and any(
                    review["ratings"][dimension][key] is not None
                    for key in ("capability", "burden")
                ):
                    raise ValueError("Unreviewed dimensions must retain unknown scores")
        traces = review.get("change_traces", [])
        if len({trace["id"] for trace in traces}) != len(traces):
            raise ValueError("Change trace IDs must be unique")
        for trace in traces:
            for step in trace["steps"]:
                cites(step["evidence_ids"])
        for rating in review["ratings"].values():
            burden_support = rating.get("burden_support")
            if burden_support:
                if burden_support["observation_ids"]:
                    cites(burden_support["observation_ids"])
                for field in ("corroboration_ids", "counterevidence_ids"):
                    if burden_support.get(field):
                        cites(burden_support[field])
                if not set(burden_support["change_trace_ids"]) <= {t["id"] for t in traces}:
                    raise ValueError("Burden support cites unknown change traces")
        challenge = review.get("challenge")
        if challenge and final:
            if challenge["status"] == "completed":
                required = {"reviewer_id", "independence", "draft_digest", "items", "evidence_ids"}
                if not required <= challenge.keys():
                    raise ValueError(
                        "Completed challenge is missing its reviewer, binding or evidence"
                    )
                if (
                    not method
                    or method["reviewer_id"].casefold() == "unassigned"
                    or not challenge["reviewer_id"].strip()
                    or challenge["reviewer_id"] != challenge["reviewer_id"].strip()
                    or challenge["reviewer_id"].casefold()
                    in {"unassigned", method["reviewer_id"].casefold()}
                ):
                    raise ValueError("Challenge requires distinct declared reviewer identities")
                if challenge["draft_digest"] != _draft_digest(assessment, review):
                    raise ConflictError(
                        "Challenge is stale; challenge the current draft and snapshot"
                    )
                cites(challenge["evidence_ids"])
                if len({item["id"] for item in challenge["items"]}) != len(challenge["items"]):
                    raise ValueError("Challenge item IDs must be unique")
                for item in challenge["items"]:
                    cites(item["evidence_ids"])
                    cites(item["response"]["evidence_ids"])
            elif set(challenge) - {"schema_version", "status", "summary", "gaps"}:
                raise ValueError(
                    "Unavailable challenge must state its limitation without a completion receipt"
                )
        scored = any(
            rating[axis] is not None
            for rating in review["ratings"].values()
            for axis in ("capability", "burden")
        )
        if (
            final
            and method
            and method["mode"] == "fresh"
            and scored
            and review.get("coverage", {}).get("scope") == "whole_project"
        ):
            if not traces or challenge is None:
                raise ValueError(
                    "Fresh whole-project scores require a change trace and challenge or explicit unavailability"
                )
        if final:
            for dimension, rating in review["ratings"].items():
                medium_estimate = (
                    rating.get("burden_basis") == "source_estimate"
                    and rating.get("burden_confidence") == "medium"
                    and (
                        (method or {}).get("confidence_standard") == "source-estimate-v1"
                        or any(
                            key in (rating.get("burden_support") or {})
                            for key in ("corroboration_ids", "counterevidence_ids")
                        )
                    )
                )
                if rating.get("burden_confidence") == "high" or medium_estimate:
                    support = burden_support_assessment(assessment, review, dimension)
                    if support["status"] != "structured_support_present_for_declared_scope":
                        raise ValueError(
                            ("Medium source-estimate" if medium_estimate else "High burden")
                            + " confidence lacks support for "
                            + dimension
                            + ": "
                            + "; ".join(support["gaps"])
                        )
        return support_verification

    def challenge_template(self, assessment_id, review):
        """Prepare a bounded, score-free handoff; the caller runs a separate reviewer."""
        with self._db() as db:
            assessment = self._assessment(db, assessment_id)
            if (
                not _backfilled(assessment)
                and self._latest(db, assessment["project_id"])["id"] != assessment_id
            ):
                raise ConflictError("Assessment is stale; challenge the latest snapshot")
            self._validate_review_document(db, assessment, review, final=False)
            goals = self._goals(db, assessment["project_id"])
        selected_evidence = build_challenge_evidence_index(
            assessment, review.get("change_traces", [])
        )
        return {
            "schema_version": 1,
            "assessment_id": assessment_id,
            "source": assessment["source"],
            "scope_digest": assessment["scope_digest"],
            "rubric_version": assessment["rubric_version"],
            "draft_digest": _draft_digest(assessment, review),
            "context": {
                "complete": assessment["complete"],
                "collection_gaps": assessment["gaps"][:50],
                "omitted_collection_gaps": max(0, len(assessment["gaps"]) - 50),
                "inventory": assessment["facts"].get("inventory", {}),
                "system_map": get_system_map(assessment),
                "dimension_inputs": dimension_inputs(assessment),
                "evidence_index": selected_evidence["items"],
                "evidence_selection": selected_evidence["selection"],
                "omitted_evidence": selected_evidence["selection"]["omitted"],
            },
            "change_traces": review.get("change_traces", []),
            "burden_review": {
                dimension: {
                    key: support[key]
                    for key in (
                        "scope",
                        "scope_description",
                        "claim",
                        "observation_ids",
                        "change_trace_ids",
                        "representativeness",
                        "counterevidence",
                        "freshness",
                        "limitations",
                        "corroboration_ids",
                        "counterevidence_ids",
                    )
                    if key in support
                }
                for dimension, rating in review["ratings"].items()
                if (support := rating.get("burden_support"))
            },
            "rubric": self.rubric(),
            "project_intent": (review.get("project_context") or {}).get("intended"),
            "prompting_intent": (review.get("prompting") or {}).get("intent"),
            "targets": (goals or {}).get("targets"),
            "instructions": [
                "Use current user-stated purpose as a constraint. Documented or inferred intent remains a provisional claim to challenge. Independently establish realized scope/readiness before seeing proposed current milestones or ranked priorities; do not assume commercial or platform scope is better.",
                "Form your independent judgment first. Then inspect burden_review scopes and query their observation_ids from this snapshot; challenge recurrence, actual cost, applicability and contrary paths. These references contain no proposed scores. Do not declare burden_dimensions unless you reviewed that dimension's support.",
                "Use a separate reviewer. Form an independent judgment from current captured evidence before seeing proposed grades, rationales, findings or plans.",
                "Challenge missing debt, favorable counterevidence, source freshness, change traces and the proportionality of improvements. Query evidence and inspect source context where needed.",
                "Return cited concerns, inspected evidence IDs, reviewer identity and limitations. The author records an accepted, rejected or deferred response with rationale and citations for every concern.",
                "Independence is declared, not authenticated. Any draft score, rationale, plan, trace or source change requires a follow-up challenge bound to the new digest.",
            ],
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
            # Backfilled history is reviewable at any time, always as hindsight.
            if (
                not _backfilled(assessment)
                and self._latest(db, assessment["project_id"])["id"] != assessment_id
            ):
                raise ConflictError("Assessment is stale; review the latest snapshot")
            support_verification = self._validate_review_document(db, assessment, review)
            result = {
                **review,
                "schema_version": 1,
                "id": _id("r_"),
                "created_at": now(),
                "provenance": "agent_judgment",
            }
            result["ratings"] = _normalized_ratings(review["ratings"])
            if _backfilled(assessment):
                result["hindsight"] = {
                    "source_as_of": assessment["source"]["origin"]["as_of"],
                    "judged_at": result["created_at"],
                    "note": HINDSIGHT_NOTE,
                }
            if support_verification["findings"]:
                result["support_verification"] = support_verification
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
        comparison = compare_assessments(
            baseline, latest, baseline_review, current_review, first_review
        )
        if missing_targets:
            comparison = {"comparable": False, "event": "not_comparable"}
        comparable = comparison["comparable"]
        same_source = baseline["source"].get("manifest_digest") == latest["source"].get(
            "manifest_digest"
        )
        result.update(
            **comparison,
            baseline_assessment_id=baseline["id"],
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
            alignment = self._alignment(db, assessment)
            report = {
                "assessment": assessment,
                "review": self._review(db, assessment_id),
                "goals": self._goals(db, assessment["project_id"]),
                "progress": self._progress(db, assessment["project_id"]),
                "goal_alignment": alignment,
                "review_coverage": alignment["review_coverage"],
                "assessment_method": alignment["assessment_method"],
                "confidence_assessment": alignment["confidence_assessment"],
                "system_map": alignment["system_map"],
                "project_context": alignment["project_context"],
                "prompting": alignment["prompting"],
                "timeline": self._timeline(db, assessment),
            }
        from .badges import badge_assets
        from .report_export import dimension_map_data

        report["badges"] = badge_assets(report)
        report["dimension_map"] = dimension_map_data(report)
        return report

    def export_report(self, assessment_id):
        """Create a private offline report and badge bundle under configured state."""
        from .report_export import export_report

        report = self.get_report(assessment_id)
        with self._db() as db:
            roots = [row[0] for row in db.execute("SELECT root FROM projects")]
        return export_report(report, self.state_dir, forbidden_roots=roots)

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
                    "assessments": [
                        {
                            "id": a["id"],
                            "created_at": a["created_at"],
                            "as_of": _as_of(a),
                            "origin": "git-commit" if _backfilled(a) else "scan",
                        }
                        for a in assessments
                    ],
                    "reviews": [
                        {k: r[k] for k in ("id", "assessment_id", "created_at")} for r in reviews
                    ],
                    "goals": [{k: g[k] for k in ("revision", "created_at")} for g in goals],
                }
            return {"assessments": assessments, "reviews": reviews, "goals": goals}
