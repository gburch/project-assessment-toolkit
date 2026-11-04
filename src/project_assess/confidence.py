"""Source-span receipts and explicit limits on authored confidence.

Matching a citation establishes its source identity and text, not the truth of
the interpretation, effectiveness at runtime, or a whole-project score.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .report_identity import _draft_digest
from .rubric import DIMENSIONS
from .source_context import read_context

SOURCE_KINDS = frozenset(
    {"python", "javascript", "source", "documentation", "manifest", "configuration"}
)
REPORT_KINDS = frozenset(
    {"junit", "coverage", "cobertura", "test-value", "observation", "burden-context"}
)
MAX_FINDING_EXCERPT = 4000


def _nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def _observed_cost(entry):
    """Recognize explicit supplied change-cost semantics, never testcase sums."""
    stats = entry.get("stats", {})
    if entry.get("kind") != "observation" or stats.get("type") != "change_cost":
        return False
    if stats.get("sourceIdentity", {}).get("overall") != "matched":
        return False
    names = {"wall_elapsed", "blocked_wait", "active_effort", "change_elapsed"}
    units = {"s", "sec", "seconds", "ms", "minutes", "min", "hours", "h"}
    return any(
        result.get("name") in names
        and result.get("unit") in units
        and type(result.get("value")) in {int, float}
        and math.isfinite(result["value"])
        and result["value"] >= 0
        and result.get("status") == "observed"
        for result in stats.get("results", [])
    )


def _context_claims(entry, dimension):
    """Return attributed dimension-specific experience, retaining supplied status."""
    stats = entry.get("stats", {})
    if entry.get("kind") != "burden-context":
        return []
    attribution = stats.get("attribution", {})
    period = stats.get("period", {})
    if not (
        _nonblank(attribution.get("role"))
        and _nonblank(attribution.get("label"))
        and (period.get("start") or period.get("end"))
    ):
        return []
    # Joint claims such as "slow tests OR security rework on most changes" do
    # not establish that frequency or cost independently for either dimension.
    return [
        claim
        for claim in stats.get("claims", [])
        if set(claim.get("dimensions", [])) == {dimension}
        and _nonblank(claim.get("statement"))
        and claim.get("workflow_stage", "unknown") != "unknown"
        and claim.get("duration", {}).get("semantics") not in {"summed_test_elapsed", "cpu"}
        and (not claim.get("duration") or claim.get("completion") == "complete")
    ]


def _burden_recurrence(contexts, costs):
    if any(
        claim.get("frequency") in {"some_changes", "most_changes", "all_changes"}
        for _, claim in contexts
    ):
        return "reported_recurring"
    instants = set()
    for entry in costs:
        timestamp = entry.get("stats", {}).get("observed_at")
        if not isinstance(timestamp, str):
            continue
        try:
            instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if instant.utcoffset() is not None:
                instants.add(instant.astimezone(UTC))
        except (TypeError, ValueError):
            continue
    return "multiple_dated_observations" if len(instants) > 1 else "not_established"


def _burden_observation_paths(entry, claim=None):
    stats = entry.get("stats", {})
    if claim is None:
        return set(stats.get("scenario", {}).get("scope", []))
    return set(stats.get("scope", {}).get("paths", [])) | {
        path for example in claim.get("examples", []) for path in example.get("paths", [])
    }


def _partial_elapsed(entry, dimension):
    stats = entry.get("stats", {})
    if entry.get("kind") == "burden-context":
        return any(
            set(claim.get("dimensions", [])) == {dimension}
            and claim.get("completion") == "partial"
            and claim.get("duration", {}).get("semantics")
            in {"wall_elapsed", "blocked_wait", "active_effort"}
            for claim in stats.get("claims", [])
        )
    return (
        entry.get("kind") == "observation"
        and stats.get("type") == "change_cost"
        and any(
            result.get("name")
            in {"wall_elapsed_lower_bound", "blocked_wait_lower_bound", "active_effort_lower_bound"}
            and result.get("status") == "observed"
            and type(result.get("value")) in {int, float}
            and math.isfinite(result["value"])
            and result["value"] >= 0
            and result.get("unit") in {"s", "sec", "seconds", "ms", "minutes", "min", "hours", "h"}
            for result in stats.get("results", [])
        )
    )


def _burden_challenge_matches(assessment, review, dimension):
    challenge = review.get("challenge", {})
    author = review.get("methodology", {}).get("reviewer_id", "")
    challenger = challenge.get("reviewer_id", "")
    if not (
        challenge.get("status") == "completed"
        and dimension in challenge.get("burden_dimensions", [])
        and _nonblank(author)
        and _nonblank(challenger)
        and author.casefold() not in {"unassigned", challenger.casefold()}
        and challenger.casefold() != "unassigned"
    ):
        return False
    try:
        return challenge.get("draft_digest") == _draft_digest(assessment, review)
    except (KeyError, TypeError, ValueError):
        return False


def burden_evidence_inventory(assessment, review, dimension):
    """Expose available corroboration and next steps without assigning confidence."""
    rating = review.get("ratings", {}).get(dimension, {})
    support = rating.get("burden_support") or {}
    entries = {entry["id"]: entry for entry in assessment.get("evidence", [])}
    cited = [entries[eid] for eid in rating.get("evidence_ids", []) if eid in entries]
    source_ids = {entry["id"] for entry in cited if entry.get("kind") in SOURCE_KINDS}
    contexts = [(entry, claim) for entry in cited for claim in _context_claims(entry, dimension)]
    costs = [entry for entry in cited if _observed_cost(entry)]
    partial_elapsed_ids = {entry["id"] for entry in cited if _partial_elapsed(entry, dimension)}
    experience_ids = {entry["id"] for entry, _ in contexts}
    cost_ids = {entry["id"] for entry in costs}
    explicit = bool(support.get("change_trace_ids"))
    traces = [
        trace
        for trace in review.get("change_traces", [])
        if trace.get("id") in support.get("change_trace_ids", [])
        or not explicit
        and any(source_ids.intersection(step.get("evidence_ids", [])) for step in trace["steps"])
    ]
    activities = Counter(dict.fromkeys(("edit", "verification", "inspection", "unknown"), 0))
    trace_sources = set()
    for trace in traces:
        for step in trace["steps"]:
            activity = step.get("activity", "unknown")
            activities[activity if activity in activities else "unknown"] += 1
            trace_sources.update(
                eid
                for eid in step.get("evidence_ids", [])
                if entries.get(eid, {}).get("kind") in SOURCE_KINDS
            )
    trace_paths = {entries[eid].get("path") for eid in trace_sources}
    relevant_contexts = [
        (entry, claim)
        for entry, claim in contexts
        if not _burden_observation_paths(entry, claim)
        or trace_paths.intersection(_burden_observation_paths(entry, claim))
    ]
    relevant_costs = [
        entry for entry in costs if trace_paths.intersection(_burden_observation_paths(entry))
    ]
    applicable_ids = {entry["id"] for entry, _ in relevant_contexts} | {
        entry["id"] for entry in relevant_costs
    }
    limited = {
        entry["id"]
        for entry in cited
        if entry.get("kind") in REPORT_KINDS
        and (
            entry["id"] not in applicable_ids
            or entry.get("stats", {}).get("sourceIdentity", {}).get("overall") != "matched"
        )
    }
    recurrence = _burden_recurrence(relevant_contexts, relevant_costs)
    challenged = _burden_challenge_matches(assessment, review, dimension)
    next_steps = []
    if not source_ids:
        next_steps.append("Cite current captured source implementing the costly mechanism.")
    if not trace_sources:
        next_steps.append(
            "Trace a representative change through its required completion path and current source."
        )
    if activities["unknown"]:
        next_steps.append(
            "Label edits, verification and inspection separately; checkpoints are not mandatory edits, and verification waits can be costly."
        )
    if not contexts and not costs:
        next_steps.append(
            "Corroborate scope with attributed dimension-specific experience or existing matched cost reports; keep source estimates labeled."
        )
    if limited:
        next_steps.append(
            "Reconcile report scope, dates, source identity and timing/completion semantics."
        )
    if partial_elapsed_ids:
        next_steps.append(
            "Retain partial elapsed as an already-incurred lower bound, not total gate time or a person's blocked wait."
        )
    if recurrence == "not_established":
        next_steps.append(
            "For project recurrence, use representative dated costs or explicit dimension-specific frequency; isolated costs stay workflow-scoped."
        )
    if not challenged:
        next_steps.append(
            "Have a distinct reviewer challenge this dimension's scope, cost and contrary evidence against the exact draft."
        )
    return {
        "source_evidence_ids": sorted(source_ids),
        "experience_evidence_ids": sorted(experience_ids),
        "matched_cost_evidence_ids": sorted(cost_ids),
        "partial_elapsed_evidence_ids": sorted(partial_elapsed_ids),
        "limited_report_evidence_ids": sorted(limited),
        "trace_ids": [trace["id"] for trace in traces],
        "trace_selection": "explicit" if explicit else "shared_source_citations",
        "trace_activities": dict(activities),
        "source_trace_evidence_ids": sorted(trace_sources),
        "recurrence": recurrence,
        "challenge": "bound_dimension_review" if challenged else "not_established",
        "next_steps": next_steps,
        "caveat": "Evidence inventory, not a confidence rating or verified cost.",
    }


CHALLENGE_GAP_FIELD = "challenge"
_CAPTURED_EVIDENCE_ID = re.compile(r"e-[0-9a-f]{8,64}")


def evidence_label(value):
    """Name a captured ID; other submitted text may be sensitive and is never echoed."""
    return value if _CAPTURED_EVIDENCE_ID.fullmatch(value) else "an ID outside this snapshot"


def _trace_label(review, trace):
    return f"change_traces[{review.get('change_traces', []).index(trace)}]"


def _add_gap(result, field, message, failures=()):
    """Record a gap with the field and evidence or trace IDs needed to correct it."""
    failures = list(failures)
    result["gaps"].append(message + (f" [{'; '.join(failures)}]" if failures else ""))
    result["gap_details"].append({"field": field, "message": message, "failures": failures})


def burden_support_assessment(assessment, review, dimension):
    """Check explicit support prerequisites, not the truth of a burden judgment.

    No score or confidence is assigned here. A successful result records a
    bounded, challenge-covered support declaration. Authorship, experience,
    representativeness and semantic correctness remain review judgments.
    """
    review = review or {}
    rating = review.get("ratings", {}).get(dimension, {})
    support = rating.get("burden_support") or {}
    result = {
        "status": "not_requested",
        "scope": support.get("scope"),
        "claim": support.get("claim"),
        "gaps": [],
        "gap_details": [],
        "evidence_ids": list(support.get("observation_ids", [])),
        "readiness": burden_evidence_inventory(assessment, review, dimension),
    }
    if (
        rating.get("burden_confidence") == "medium"
        and rating.get("burden_basis") == "source_estimate"
        and (
            review.get("methodology", {}).get("confidence_standard") == "source-estimate-v1"
            or any(key in support for key in ("corroboration_ids", "counterevidence_ids"))
        )
    ):
        return _source_estimate_support(assessment, review, dimension, result)
    if rating.get("burden_confidence") != "high":
        return result
    result["status"] = "withheld"
    if rating.get("burden") is None or rating.get("burden_basis") != "observed":
        _add_gap(
            result, "burden", "High burden confidence requires a scored, observed burden claim."
        )
    if not support:
        _add_gap(
            result,
            "burden_support",
            "No explicit burden support is recorded for the high-confidence claim.",
        )
        return result
    for key in ("claim", "scope_description", "representativeness", "counterevidence", "freshness"):
        if not _nonblank(support.get(key)):
            _add_gap(
                result, f"burden_support.{key}", f"Burden support must explicitly record {key}."
            )
    scope = support.get("scope")
    coverage = review.get("coverage", {})
    status = coverage.get("dimension_reviews", {}).get(dimension, {}).get("status")
    if scope == "project":
        if coverage.get("scope") != "whole_project" or status != "reviewed":
            _add_gap(
                result,
                "coverage.scope",
                "Project-scoped burden confidence requires reviewed whole-project scope.",
            )
        if not assessment.get("complete", False):
            _add_gap(
                result,
                "collection",
                "Partial collection does not establish project-scoped burden support.",
            )
    elif scope == "workflow":
        if status not in {"reviewed", "partial"}:
            _add_gap(
                result,
                f"coverage.dimension_reviews.{dimension}.status",
                "Workflow-scoped burden confidence requires an explicitly reviewed scope.",
            )
    else:
        _add_gap(
            result, "burden_support.scope", "Burden support must declare project or workflow scope."
        )

    entries = {entry["id"]: entry for entry in assessment.get("evidence", [])}
    cited = set(rating.get("evidence_ids", []))
    observation_ids = support.get("observation_ids", [])
    observations = [entries[eid] for eid in observation_ids if eid in entries and eid in cited]
    if not observation_ids or len(observations) != len(observation_ids):
        _add_gap(
            result,
            "burden_support.observation_ids",
            "Burden observations must be cited evidence from this captured assessment.",
            [
                f"{evidence_label(eid)}: "
                + ("not in rating evidence_ids" if eid in entries else "not in this snapshot")
                for eid in observation_ids
                if eid not in entries or eid not in cited
            ],
        )
    contexts = [
        (entry, claim) for entry in observations for claim in _context_claims(entry, dimension)
    ]
    costs = [entry for entry in observations if _observed_cost(entry)]
    if not contexts and not costs:
        _add_gap(
            result,
            "burden_support.observation_ids",
            "No applicable dimension-specific attributed experience with a stated period or "
            "source-matched explicit change-cost observation is cited; joint claims, JUnit "
            "sums and source identity alone do not establish the cost.",
            [
                f"{entry['id']}: {entry.get('kind')} has no applicable claim"
                for entry in observations
            ],
        )
    traces = {trace["id"]: trace for trace in review.get("change_traces", [])}
    trace_ids = support.get("change_trace_ids", [])
    selected = [traces[tid] for tid in trace_ids if tid in traces]
    if not trace_ids or len(selected) != len(trace_ids):
        _add_gap(
            result,
            "burden_support.change_trace_ids",
            "Burden support requires referenced representative change traces.",
            [
                f"change_trace_ids[{index}]: unknown change trace"
                for index, tid in enumerate(trace_ids)
                if tid not in traces
            ],
        )
    source_ids = {
        eid
        for trace in selected
        for step in trace.get("steps", [])
        for eid in step.get("evidence_ids", [])
        if eid in entries and entries[eid].get("kind") in SOURCE_KINDS
    }
    if not source_ids:
        _add_gap(
            result,
            "change_traces.steps.evidence_ids",
            "Change traces must corroborate the hurdle with captured current source.",
            [f"{_trace_label(review, trace)}: no captured source step" for trace in selected],
        )
    source_paths = {entries[eid].get("path") for eid in source_ids}
    relevant_contexts = [
        (entry, claim)
        for entry, claim in contexts
        if not _burden_observation_paths(entry, claim)
        or source_paths.intersection(_burden_observation_paths(entry, claim))
    ]
    relevant_costs = [
        entry for entry in costs if source_paths.intersection(_burden_observation_paths(entry))
    ]
    if len(relevant_contexts) != len(contexts) or len(relevant_costs) != len(costs):
        _add_gap(
            result,
            "burden_support.observation_ids",
            "Each observation scope must be corroborated by a current source change trace; "
            "reconcile the scope before claiming high confidence.",
            [
                f"{identity}: scope not matched by a change trace"
                for identity in sorted(
                    {pair[0]["id"] for pair in contexts if pair not in relevant_contexts}
                    | {entry["id"] for entry in costs if entry not in relevant_costs}
                )
            ],
        )
    if (
        scope == "project"
        and _burden_recurrence(relevant_contexts, relevant_costs) == "not_established"
    ):
        _add_gap(
            result,
            "burden_support.observation_ids",
            "Project-scoped burden needs recurring dimension-specific experience or multiple distinct dated cost observations; one isolated workflow cost does not establish project recurrence.",
        )

    method = review.get("methodology", {})
    challenge = review.get("challenge", {})
    author = method.get("reviewer_id", "")
    challenger = challenge.get("reviewer_id", "")
    if not (
        challenge.get("status") == "completed"
        and dimension in challenge.get("burden_dimensions", [])
        and _nonblank(author)
        and _nonblank(challenger)
        and author.casefold() not in {"unassigned", challenger.casefold()}
        and challenger.casefold() != "unassigned"
    ):
        _add_gap(
            result,
            CHALLENGE_GAP_FIELD,
            "A distinct declared reviewer must challenge this dimension's burden support.",
        )
    else:
        # Reuse the canonical draft binding; a completed label alone
        # cannot turn an old or unrelated challenge into current support.
        if challenge.get("draft_digest") != _draft_digest(assessment, review):
            _add_gap(
                result,
                CHALLENGE_GAP_FIELD,
                "The burden challenge is not bound to this current draft and snapshot.",
            )
    if not result["gaps"]:
        result["status"] = "structured_support_present_for_declared_scope"
    return result


def _source_estimate_support(assessment, review, dimension, result):
    """Check declared structural support; never turn estimates into observed cost."""
    from .review_plan import dimension_coverage

    result.update(status="withheld", standard="source-estimate-v1")
    rating = review["ratings"][dimension]
    support = rating.get("burden_support") or {}
    if rating.get("burden") is None:
        _add_gap(
            result, "burden", "Medium source confidence requires a scored structural estimate."
        )
    for key in ("claim", "scope_description", "representativeness", "counterevidence", "freshness"):
        if not _nonblank(support.get(key)):
            _add_gap(
                result,
                f"burden_support.{key}",
                f"Source-estimate support must explicitly record {key}.",
            )
    coverage = review.get("coverage", {})
    dimension_review = coverage.get("dimension_reviews", {}).get(dimension, {})
    scope = support.get("scope")
    if scope == "project":
        if coverage.get("scope") != "whole_project" or dimension_review.get("status") != "reviewed":
            _add_gap(
                result,
                f"coverage.dimension_reviews.{dimension}.status",
                "Project estimates require representative reviewed dimension coverage.",
            )
        for blocker in dimension_coverage(assessment, dimension)["collection_blockers"]:
            _add_gap(result, "collection", blocker)
    elif scope == "workflow":
        if dimension_review.get("status") not in {"reviewed", "partial"}:
            _add_gap(
                result,
                f"coverage.dimension_reviews.{dimension}.status",
                "Workflow estimates require an explicitly reviewed source scope.",
            )
    else:
        _add_gap(
            result,
            "burden_support.scope",
            "Source-estimate support must declare project or workflow scope.",
        )
    entries = {entry["id"]: entry for entry in assessment.get("evidence", [])}
    cited = set(rating.get("evidence_ids", []))
    examined = set(dimension_review.get("evidence_ids", []))
    for field in ("corroboration_ids", "counterevidence_ids"):
        ids = support.get(field, [])
        failing = []
        for eid in ids:
            problems = [
                problem
                for problem, present in (
                    (f"not in ratings.{dimension}.evidence_ids", eid in cited),
                    (
                        f"not in coverage.dimension_reviews.{dimension}.evidence_ids",
                        eid in examined,
                    ),
                    (
                        f"kind {entries.get(eid, {}).get('kind', 'unknown')} is not current source",
                        entries.get(eid, {}).get("kind") in SOURCE_KINDS,
                    ),
                )
                if not present
            ]
            if problems:
                failing.append(f"{evidence_label(eid)}: {', '.join(problems)}")
        if not ids or failing:
            _add_gap(
                result,
                f"burden_support.{field}",
                f"{field} must cite current source inspected for this dimension.",
                failing,
            )
    traces = {trace["id"]: trace for trace in review.get("change_traces", [])}
    ids = support.get("change_trace_ids", [])
    selected = [traces[identity] for identity in ids if identity in traces]
    if not ids or len(selected) != len(ids):
        _add_gap(
            result,
            "burden_support.change_trace_ids",
            "Source estimates require a referenced representative change or upkeep trace.",
            [
                f"change_trace_ids[{index}]: unknown change trace"
                for index, identity in enumerate(ids)
                if identity not in traces
            ],
        )
    for trace in selected:
        if not _nonblank(trace.get("cost")) or not _nonblank(trace.get("counterevidence")):
            _add_gap(
                result,
                "change_traces.cost",
                "Each estimate trace must explain upkeep and a contrary or simpler path.",
                [f"{_trace_label(review, trace)}: cost or counterevidence is blank"],
            )
        if any(step.get("activity", "unknown") == "unknown" for step in trace.get("steps", [])):
            _add_gap(
                result,
                "change_traces.steps.activity",
                "Estimate traces must distinguish edits, verification and inspection.",
                [f"{_trace_label(review, trace)}: a step has unknown activity"],
            )
        if not any(
            eid in cited and eid in examined and entries.get(eid, {}).get("kind") in SOURCE_KINDS
            for step in trace.get("steps", [])
            for eid in step.get("evidence_ids", [])
        ):
            _add_gap(
                result,
                "change_traces.steps.evidence_ids",
                "Each estimate trace must intersect inspected current dimension source.",
                [f"{_trace_label(review, trace)}: no step cites inspected dimension source"],
            )
        trace_ids = {eid for step in trace.get("steps", []) for eid in step.get("evidence_ids", [])}
        if not trace_ids.intersection(support.get("corroboration_ids", [])):
            _add_gap(
                result,
                "burden_support.corroboration_ids",
                "Each estimate trace must include source corroborating this dimension's upkeep mechanism.",
                [f"{_trace_label(review, trace)}: shares no evidence ID with corroboration_ids"],
            )
    if not _burden_challenge_matches(assessment, review, dimension):
        _add_gap(
            result,
            CHALLENGE_GAP_FIELD,
            "A distinct reviewer must challenge the estimate against this exact draft.",
        )
    if not result["gaps"]:
        result["status"] = "structured_support_present_for_declared_scope"
    result["caveat"] = (
        "Structural estimate support, not measured duration, recurrence, runtime effectiveness or automatically earned confidence. Corroboration and contrary-source relevance remain review judgments."
    )
    return result


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _excerpt_digest(excerpt):
    return hashlib.sha256(excerpt.encode()).hexdigest()


def validate_finding_support(assessment, review, *, root=None):
    """Validate bounded authored citations and return server-owned receipts."""
    entries = {entry["id"]: entry for entry in assessment["evidence"]}
    findings = review.get("findings", [])
    total = sum(len(finding.get("support", {}).get("citations", [])) for finding in findings)
    if total > 32:
        raise ValueError("Finding support is limited to 32 citations per review")
    receipts, cache = [], {}
    for index, finding in enumerate(findings):
        support = finding.get("support")
        if support is None:
            continue
        citations = []
        for citation in support["citations"]:
            entry = entries.get(citation["evidence_id"])
            if entry is None or entry["id"] not in finding["evidence_ids"]:
                raise ValueError("Finding citations must belong to the finding's snapshot evidence")
            if entry["kind"] not in SOURCE_KINDS:
                raise ValueError("Finding citations require original captured source evidence")
            if citation["end_line"] - citation["line"] >= 80:
                raise ValueError("A finding citation may span at most 80 lines")
            context = read_context(
                Path(root or assessment["source"]["root"]),
                entry,
                line=citation["line"],
                end_line=citation["end_line"],
                max_chars=MAX_FINDING_EXCERPT,
                _line_cache=cache,
            )
            if (
                context["truncated"]
                or context["end_line"] != citation["end_line"]
                or context["excerpt"] != citation["excerpt"]
            ):
                raise ValueError(
                    "Finding citation must exactly match the complete redacted source span"
                )
            citations.append(
                {
                    "evidence_id": entry["id"],
                    "digest": entry["digest"],
                    "line": citation["line"],
                    "end_line": citation["end_line"],
                    "excerpt_sha256": _excerpt_digest(citation["excerpt"]),
                }
            )
        receipts.append(
            {"index": index, "finding_digest": _digest(finding), "citations": citations}
        )
    return {
        "schema_version": 1,
        "source_digest": assessment["source"]["manifest_digest"],
        "method": "snapshot_matched_source_spans",
        "findings": receipts,
    }


def _receipt_matches(assessment, finding, index, verification):
    if (
        verification.get("schema_version") != 1
        or verification.get("method") != "snapshot_matched_source_spans"
        or verification.get("source_digest") != assessment["source"]["manifest_digest"]
    ):
        return False
    receipt = next(
        (row for row in verification.get("findings", []) if row.get("index") == index), {}
    )
    if receipt.get("finding_digest") != _digest(finding):
        return False
    entries = {entry["id"]: entry for entry in assessment["evidence"]}
    expected = []
    for citation in finding.get("support", {}).get("citations", []):
        entry = entries.get(citation["evidence_id"])
        if entry is None or entry["kind"] not in SOURCE_KINDS:
            return False
        expected.append(
            {
                "evidence_id": entry["id"],
                "digest": entry["digest"],
                "line": citation["line"],
                "end_line": citation["end_line"],
                "excerpt_sha256": _excerpt_digest(citation["excerpt"]),
            }
        )
    return bool(expected) and receipt.get("citations") == expected


def confidence_assessment(assessment, review):
    """Project support and blockers without changing authored grades/confidence."""
    review = review or {}
    verification = review.get("support_verification", {})
    findings = []
    for index, finding in enumerate(review.get("findings", [])):
        support = finding.get("support", {})
        verified = _receipt_matches(assessment, finding, index, verification) if support else False
        findings.append(
            {
                "index": index,
                "title": finding["title"],
                "declared_confidence": support.get("confidence"),
                "scope": support.get("scope", "unestablished"),
                "grounding": "verified_source_spans" if verified else "unestablished",
                "citation_count": len(support.get("citations", [])),
                "limitations": list(support.get("limitations", [])),
            }
        )
    entries = {entry["id"]: entry for entry in assessment["evidence"]}
    coverage = review.get("coverage", {})
    dimensions = {}
    for dimension in DIMENSIONS:
        rating = review.get("ratings", {}).get(dimension, {})
        status = coverage.get("dimension_reviews", {}).get(dimension, {}).get("status")
        cited = [entries[eid] for eid in rating.get("evidence_ids", []) if eid in entries]
        reports = [entry for entry in cited if entry["kind"] in REPORT_KINDS]
        bound_reports = [
            entry
            for entry in reports
            if entry["kind"] in {"test-value", "observation"}
            and entry.get("stats", {}).get("sourceIdentity", {}).get("overall") == "matched"
        ]
        common = []
        if status != "reviewed":
            common.append(
                "Dimension breadth is "
                + (status or "unestablished")
                + "; inspect representative workflows and record remaining scope."
            )
        from .review_plan import dimension_coverage

        collection_scope = dimension_coverage(assessment, dimension)
        common.extend(collection_scope["collection_blockers"])
        capability = list(common)
        score = rating.get("capability")
        if score is None:
            capability.append("Capability remains unknown.")
        needs_validation = score is not None and (
            score >= 4 or dimension == "performance" and score >= 3
        )
        if needs_validation and not bound_reports:
            capability.append(
                "The selected anchor needs current validation or change/workload observations; "
                "no source-matched execution report is cited. Source configuration alone does not establish it."
            )
        elif needs_validation:
            capability.append(
                "Source-matched supplied reports are cited, but matching identity alone does not "
                "establish the selected anchor's scenario relevance, execution effectiveness or "
                "representative workload/change observations; inspect and record that scope."
            )
        burden = list(common)
        basis = rating.get(
            "burden_basis", "source_estimate" if rating.get("burden") is not None else "unknown"
        )
        if rating.get("burden") is None:
            burden.append("Burden remains unknown.")
        elif basis == "source_estimate":
            burden.append(
                "Upkeep is estimated from source; corroborate representative change costs, maintainer observations or measured feedback before treating it as observed."
            )
        elif basis == "observed" and not reports:
            burden.append(
                "Observed burden is declared, but no observation/report artifact is cited; source files alone do not verify measured or experienced upkeep."
            )
        elif basis == "observed" and any(entry["kind"] == "burden-context" for entry in reports):
            burden.append(
                "Attributed maintainer experience is cited; distinguish reported experience "
                "from independently measured timing, and inspect scope, recurrence, freshness "
                "and current change traces. Source matching does not authenticate experience."
            )
        elif basis == "observed" and not bound_reports:
            burden.append(
                "Cited supplied reports lack established matching source identity; observed upkeep is unverified."
            )
        elif basis == "observed":
            burden.append(
                "Matching source identity does not establish observed upkeep: inspect the report's "
                "actual change-cost, maintainer or feedback measurements and their relevance."
            )
        burden_support = burden_support_assessment(assessment, review, dimension)
        if burden_support["status"] == "structured_support_present_for_declared_scope":
            burden = (
                list(common)
                + [
                    "Support covers the declared workflow only; it does not establish project-wide burden confidence."
                ]
                if burden_support.get("scope") == "workflow"
                else []
            )
            if burden_support.get("standard") == "source-estimate-v1":
                burden.append(
                    "The supported structural estimate does not establish measured time, frequency or runtime effectiveness."
                )
        elif burden_support["status"] == "withheld":
            burden.extend(burden_support["gaps"])
        dimensions[dimension] = {
            "capability": {
                "declared_confidence": rating.get("confidence"),
                "grounding": "authored_judgment",
                "blockers": capability,
            },
            "burden": {
                "declared_confidence": rating.get("burden_confidence"),
                "basis": basis,
                "grounding": "authored_judgment",
                "blockers": burden,
                "support": burden_support,
            },
            "cited_report_count": len(reports),
            "source_matched_report_count": len(bound_reports),
            "coverage": collection_scope,
        }
    return {
        "schema_version": 1,
        "findings": findings,
        "dimensions": dimensions,
        "summary": {
            "findings": len(findings),
            "verified_source_findings": sum(
                row["grounding"] == "verified_source_spans" for row in findings
            ),
            "declared_high_source_findings": sum(
                row["grounding"] == "verified_source_spans"
                and row["scope"] == "source"
                and row["declared_confidence"] == "high"
                for row in findings
            ),
        },
        "caveat": "Finding confidence and dimension confidence are authored judgments. Verified source spans establish matching captured bytes and quoted ranges, not semantic correctness, reachability, runtime effectiveness or project-wide confidence. Structured burden support records prerequisites for the declared scope, not authenticated experience, verified timing or a certified score. A completed challenge does not upgrade either axis. Activities are declarations; shared source citations do not prove trace relevance. Distinct observation dates do not establish representative recurrence.",
    }
