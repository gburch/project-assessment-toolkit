"""Source-span receipts and explicit limits on authored confidence.

Matching a citation establishes its source identity and text, not the truth of
the interpretation, effectiveness at runtime, or a whole-project score.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

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
        "evidence_ids": list(support.get("observation_ids", [])),
    }
    if rating.get("burden_confidence") != "high":
        return result
    result["status"] = "withheld"
    gaps = result["gaps"]
    if rating.get("burden") is None or rating.get("burden_basis") != "observed":
        gaps.append("High burden confidence requires a scored, observed burden claim.")
    if not support:
        gaps.append("No explicit burden support is recorded for the high-confidence claim.")
        return result
    for key in ("claim", "scope_description", "representativeness", "counterevidence", "freshness"):
        if not _nonblank(support.get(key)):
            gaps.append(f"Burden support must explicitly record {key}.")
    scope = support.get("scope")
    coverage = review.get("coverage", {})
    status = coverage.get("dimension_reviews", {}).get(dimension, {}).get("status")
    if scope == "project":
        if coverage.get("scope") != "whole_project" or status != "reviewed":
            gaps.append("Project-scoped burden confidence requires reviewed whole-project scope.")
        if not assessment.get("complete", False):
            gaps.append("Partial collection does not establish project-scoped burden support.")
    elif scope == "workflow":
        if status not in {"reviewed", "partial"}:
            gaps.append("Workflow-scoped burden confidence requires an explicitly reviewed scope.")
    else:
        gaps.append("Burden support must declare project or workflow scope.")

    entries = {entry["id"]: entry for entry in assessment.get("evidence", [])}
    cited = set(rating.get("evidence_ids", []))
    observation_ids = support.get("observation_ids", [])
    observations = [entries[eid] for eid in observation_ids if eid in entries and eid in cited]
    if not observation_ids or len(observations) != len(observation_ids):
        gaps.append("Burden observations must be cited evidence from this captured assessment.")
    contexts = [
        (entry, claim) for entry in observations for claim in _context_claims(entry, dimension)
    ]
    costs = [entry for entry in observations if _observed_cost(entry)]
    if not contexts and not costs:
        gaps.append(
            "No applicable dimension-specific attributed experience with a stated period or "
            "source-matched explicit change-cost observation is cited; joint claims, JUnit "
            "sums and source identity alone do not establish the cost."
        )
    if (
        scope == "project"
        and contexts
        and not costs
        and all(claim.get("frequency", "unknown") == "unknown" for _, claim in contexts)
    ):
        gaps.append("Project-scoped experienced burden needs an explicit change-frequency basis.")

    traces = {trace["id"]: trace for trace in review.get("change_traces", [])}
    trace_ids = support.get("change_trace_ids", [])
    selected = [traces[tid] for tid in trace_ids if tid in traces]
    if not trace_ids or len(selected) != len(trace_ids):
        gaps.append("Burden support requires referenced representative change traces.")
    source_ids = {
        eid
        for trace in selected
        for step in trace.get("steps", [])
        for eid in step.get("evidence_ids", [])
        if eid in entries and entries[eid].get("kind") in SOURCE_KINDS
    }
    if not source_ids:
        gaps.append("Change traces must corroborate the hurdle with captured current source.")
    source_paths = {entries[eid].get("path") for eid in source_ids}
    context_paths = {
        path
        for entry, claim in contexts
        for path in (
            entry.get("stats", {}).get("scope", {}).get("paths", [])
            + [path for example in claim.get("examples", []) for path in example.get("paths", [])]
        )
    }
    cost_paths = {
        path
        for entry in costs
        for path in entry.get("stats", {}).get("scenario", {}).get("scope", [])
    }
    if (context_paths or cost_paths) and not source_paths.intersection(context_paths | cost_paths):
        gaps.append(
            "Observation scope is not corroborated by a current source change trace; "
            "reconcile the scope before claiming high confidence."
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
        gaps.append("A distinct declared reviewer must challenge this dimension's burden support.")
    else:
        # Reuse the service's canonical draft binding; a completed label alone
        # cannot turn an old or unrelated challenge into current support.
        from .service import _draft_digest

        if challenge.get("draft_digest") != _draft_digest(assessment, review):
            gaps.append("The burden challenge is not bound to this current draft and snapshot.")
    if not gaps:
        result["status"] = "structured_support_present_for_declared_scope"
    return result


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _excerpt_digest(excerpt):
    return hashlib.sha256(excerpt.encode()).hexdigest()


def validate_finding_support(assessment, review):
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
                Path(assessment["source"]["root"]),
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
        if not assessment.get("complete", False):
            common.append(
                "Collection is partial; establish whether its omissions affect this dimension."
            )
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
            burden = []
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
        "caveat": "Finding confidence and dimension confidence are authored judgments. Verified source spans establish matching captured bytes and quoted ranges, not semantic correctness, reachability, runtime effectiveness or project-wide confidence. Structured burden support records prerequisites for the declared scope, not authenticated experience, verified timing or a certified score. A completed challenge does not upgrade either axis.",
    }
