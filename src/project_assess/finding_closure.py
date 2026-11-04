"""Finite, source-bound finding decisions; none of these operations award scores."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy

from jsonschema import Draft202012Validator

from .report_identity import canonical, normalize_report_path

VERSION = 1
_SOURCE_KINDS = {"python", "javascript", "source", "documentation", "manifest", "configuration"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_TEXT = {"type": "string", "minLength": 1, "maxLength": 2000}
_IDS = {
    "type": "array",
    "minItems": 1,
    "maxItems": 100,
    "uniqueItems": True,
    "items": {"type": "string", "minLength": 1, "maxLength": 200},
}
EVENT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "finding_id": {"type": "string", "pattern": "^f_[0-9a-f]{32}$"},
        "assessment_id": {"type": "string", "minLength": 1, "maxLength": 100},
        "source_digest": _DIGEST,
        "status": {"enum": ["open", "implemented", "verified", "accepted"]},
        "actor": {"type": "string", "minLength": 1, "maxLength": 200},
        "rationale": _TEXT,
        "evidence_ids": _IDS,
        "scope": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "digest": _DIGEST,
                },
                "required": ["path", "digest"],
            },
        },
        "verification": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "basis": {"enum": ["source_review", "execution_report"]},
                "acceptance": _TEXT,
                "limitations": {"type": "array", "minItems": 1, "maxItems": 20, "items": _TEXT},
            },
            "required": ["basis", "acceptance", "limitations"],
        },
    },
    "required": [
        "finding_id",
        "assessment_id",
        "source_digest",
        "status",
        "actor",
        "rationale",
        "evidence_ids",
        "scope",
    ],
}
CAVEAT = (
    "Finding state records a supplied decision and finite verification scope, not a whole-project "
    "grade. Source review is reviewer verification; source-matched execution reports remain "
    "supplied claims, not authenticated executions. Absence from a scan never closes a finding."
)


def _sources(assessment):
    result = {}
    for item in assessment.get("evidence", []):
        if item.get("kind") not in _SOURCE_KINDS:
            continue
        try:
            path = normalize_report_path(item["path"])
        except (KeyError, ValueError):
            continue
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest", "")):
            continue
        if path in result and result[path] != item["digest"]:
            raise ValueError("Conflicting captured source identities")
        result[path] = item["digest"]
    return result


def finding_reference(assessment, review=None, index=0):
    """Address a saved finding without guessing that similar titles are the same issue."""
    if type(index) is not int or index < 0:
        raise ValueError("Finding index must be a nonnegative integer")
    if review is not None and (
        not review.get("id")
        or review.get("assessment_id") != assessment["id"]
        or review.get("source_digest") != assessment["source"]["manifest_digest"]
    ):
        raise ValueError("Origin review must be saved and bound to the origin assessment")
    findings = (review or assessment).get("findings", [])
    if index >= len(findings):
        raise ValueError("Unknown origin finding")
    finding = findings[index]
    source = _sources(assessment)
    ids = set(finding.get("evidence_ids", []))
    files = {
        row["path"]: source[row["path"]]
        for row in assessment.get("evidence", [])
        if row["id"] in ids and row.get("path") in source
    }
    # Exact source citations sometimes carry the source evidence only in support.
    support_ids = {
        row.get("evidence_id") for row in finding.get("support", {}).get("citations", [])
    }
    files.update(
        {
            row["path"]: source[row["path"]]
            for row in assessment.get("evidence", [])
            if row["id"] in support_ids and row.get("path") in source
        }
    )
    origin = {
        "assessment_id": assessment["id"],
        "review_id": review["id"] if review else None,
        "index": index,
    }
    return {
        "finding_id": "f_" + hashlib.sha256(canonical(origin).encode()).hexdigest()[:32],
        "origin": origin,
        "finding": deepcopy(finding),
        "source_files": [
            {"path": path, "digest": digest} for path, digest in sorted(files.items())
        ],
    }


def _scope_matches(scope, assessment):
    captured = _sources(assessment)
    return all(captured.get(row["path"]) == row["digest"] for row in scope)


def _passed_execution(entries, scope):
    needed = {row["path"]: row["digest"] for row in scope}
    for entry in entries:
        if entry.get("kind") != "observation":
            continue
        stats = entry.get("stats", {})
        identity = stats.get("sourceIdentity", {})
        files = {
            row["path"]: row["digest"]
            for row in identity.get("files", [])
            if row.get("status") == "matched"
        }
        results = stats.get("results", [])
        if (
            identity.get("overall") == "matched"
            and results
            and all(row.get("status") == "passed" for row in results)
            and all(
                files.get(path) == digest and digest is not None for path, digest in needed.items()
            )
        ):
            return True
    return False


def validate_event(payload, origin_assessment, origin_review, current_assessment, previous=None):
    """Validate source binding, not the semantic truth of the supplied acceptance review.

    The caller authorizes both snapshots, enforces latest-source admission and CAS,
    and stores the returned event atomically. No project files are read here.
    """
    try:
        encoded = canonical(payload)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid finding event") from exc
    if len(encoded.encode()) > 128 * 1024 or not Draft202012Validator(EVENT_SCHEMA).is_valid(
        payload
    ):
        raise ValueError("Invalid or unbounded finding event")
    if any(not payload[key].strip() for key in ("actor", "rationale")):
        raise ValueError("Finding event requires an actor and rationale")
    # The stable reference includes the origin index; the service supplies the origin review.
    matches = [
        finding_reference(origin_assessment, origin_review, index)
        for index in range(len((origin_review or origin_assessment).get("findings", [])))
    ]
    reference = next((row for row in matches if row["finding_id"] == payload["finding_id"]), None)
    if reference is None:
        raise ValueError("Unknown origin finding")
    if (
        origin_assessment.get("project_id") != current_assessment.get("project_id")
        or payload["assessment_id"] != current_assessment["id"]
        or payload["source_digest"] != current_assessment["source"]["manifest_digest"]
    ):
        raise ValueError("Finding event must bind the current project assessment and source")
    if previous and previous.get("finding_id") != payload["finding_id"]:
        raise ValueError("Previous event belongs to another finding")
    scope = payload["scope"]
    paths = [normalize_report_path(row["path"]) for row in scope]
    if len(paths) != len(set(paths)):
        raise ValueError("Finding scope must contain unique paths")
    if not _scope_matches(scope, current_assessment):
        raise ValueError("Finding scope must match captured current file identities")
    origin_files = {row["path"]: row["digest"] for row in reference["source_files"]}
    if not origin_files or not set(origin_files) <= set(paths):
        raise ValueError("Finding scope must cover the cited origin source files")
    entries = {row["id"]: row for row in current_assessment.get("evidence", [])}
    if not set(payload["evidence_ids"]) <= set(entries):
        raise ValueError("Finding event cites evidence outside the current assessment")
    cited = [entries[key] for key in payload["evidence_ids"]]
    original_sources = _sources(origin_assessment)
    changed = any(row["digest"] != original_sources.get(row["path"]) for row in scope)
    if payload["status"] in {"implemented", "verified"} and not changed:
        raise ValueError("Remediation needs changed relevant source, not a review-only update")
    verification = payload.get("verification")
    if payload["status"] == "verified":
        if not verification:
            raise ValueError("Verified findings need explicit acceptance and verification basis")
        cited_paths = {row.get("path") for row in cited if row.get("kind") in _SOURCE_KINDS}
        if not any(row["path"] in cited_paths for row in scope if row["digest"] is not None):
            raise ValueError("Verification requires a current source citation")
        if verification["basis"] == "execution_report" and not _passed_execution(cited, scope):
            raise ValueError(
                "Execution verification needs a passed, source-matched scoped observation"
            )
    elif verification is not None:
        raise ValueError("Verification details require verified status")
    result = json.loads(encoded)
    result["schema_version"] = VERSION
    result["verification_label"] = (
        "reviewer_verified"
        if verification and verification["basis"] == "source_review"
        else "supplied_execution_report"
        if verification
        else "not_verified"
    )
    return result


def project_finding(reference, events, current_assessment):
    """Keep decisions visible and invalidate only their declared relevant source scope."""
    applicable = [row for row in events if row.get("finding_id") == reference["finding_id"]]
    latest = applicable[-1] if applicable else None
    state = latest["status"] if latest else "open"
    scope = latest["scope"] if latest else reference["source_files"]
    if (
        latest
        and state in {"implemented", "verified", "accepted"}
        and not _scope_matches(scope, current_assessment)
    ):
        state = "needs_recheck"
    return {
        **deepcopy(reference),
        "status": state,
        "recorded_status": latest["status"] if latest else "open",
        "last_event_id": latest.get("id") if latest else None,
        "verification": deepcopy(latest.get("verification")) if latest else None,
        "verification_label": latest.get("verification_label", "not_verified")
        if latest
        else "not_verified",
        "rationale": latest.get("rationale") if latest else None,
        "scope": deepcopy(scope),
        "event_count": len(applicable),
        "caveat": CAVEAT,
    }
