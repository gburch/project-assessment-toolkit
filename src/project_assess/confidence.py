"""Source-span receipts and explicit limits on authored confidence.

Matching a citation establishes its source identity and text, not the truth of
the interpretation, effectiveness at runtime, or a whole-project score.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .rubric import DIMENSIONS
from .source_context import read_context

SOURCE_KINDS = frozenset(
    {"python", "javascript", "source", "documentation", "manifest", "configuration"}
)
REPORT_KINDS = frozenset({"junit", "coverage", "cobertura", "test-value", "observation"})
MAX_FINDING_EXCERPT = 4000


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
        elif basis == "observed" and not bound_reports:
            burden.append(
                "Cited supplied reports lack established matching source identity; observed upkeep is unverified."
            )
        elif basis == "observed":
            burden.append(
                "Matching source identity does not establish observed upkeep: inspect the report's "
                "actual change-cost, maintainer or feedback measurements and their relevance."
            )
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
        "caveat": "Finding confidence and dimension confidence are authored judgments. Verified source spans establish matching captured bytes and quoted ranges, not semantic correctness, reachability, runtime effectiveness or project-wide confidence. A completed challenge does not upgrade either axis.",
    }
