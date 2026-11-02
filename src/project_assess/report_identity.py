"""Pure review bindings, inert report paths and declared-source matching."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath


def normalize_report_path(value):
    if not isinstance(value, str):
        raise ValueError("Report paths must be normalized project-relative paths")
    path = PurePosixPath(value)
    if (
        not value
        or len(value) > 4096
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {".", ".."} for part in value.split("/"))
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("Report paths must be normalized project-relative paths")
    return value


def match_source_identity(source, manifest, revision, redact=lambda value: value):
    """Match declared identities only; this neither reads files nor verifies a claim."""
    files = source["files"]
    captured = {row["path"]: row["digest"] for row in manifest}
    statuses = [
        "unverified"
        if row["path"] not in captured
        else "matched"
        if row["digest"] == captured[row["path"]]
        else "mismatch"
        for row in files
    ]
    declared_revision = source["revision"]
    revision_status = (
        "unverified"
        if declared_revision is None or revision is None
        else "matched"
        if declared_revision == revision
        else "mismatch"
    )
    overall = (
        "mismatch"
        if "mismatch" in statuses or revision_status == "mismatch"
        else "matched"
        if files
        and all(status == "matched" for status in statuses)
        and revision_status == "matched"
        else "unverified"
    )
    return {
        "overall": overall,
        "revision": revision_status,
        "declared_revision": declared_revision,
        "captured_revision": revision,
        "files": [
            {"path": redact(row["path"]), "digest": row["digest"], "status": status}
            for row, status in zip(files, statuses, strict=True)
        ],
        "scope": "Only declared file identities and revision, not the complete project or runtime environment",
    }, {
        "declared_files": len(files),
        "source_matched_files": statuses.count("matched"),
        "source_unverified_files": statuses.count("unverified"),
        "source_mismatched_files": statuses.count("mismatch"),
    }


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _normalized_ratings(ratings):
    """Use the same burden defaults for storage and challenge identity."""
    result = json.loads(canonical(ratings))
    for rating in result.values():
        if rating["burden"] is None:
            rating["burden_basis"] = "unknown"
            rating["burden_confidence"] = "low"
        else:
            if rating.get("burden_basis", "unknown") == "unknown":
                rating["burden_basis"] = "source_estimate"
            rating.setdefault("burden_confidence", "low")
    return result


def _draft_digest(assessment, review):
    draft = {
        key: value
        for key, value in review.items()
        if key
        not in {
            "challenge",
            "id",
            "created_at",
            "provenance",
            "schema_version",
            "support_verification",
        }
    }
    draft["ratings"] = _normalized_ratings(draft["ratings"])
    bound = {
        "assessment_id": assessment["id"],
        "source": assessment["source"],
        "scope_digest": assessment["scope_digest"],
        "rubric_version": assessment["rubric_version"],
        "draft": draft,
    }
    return hashlib.sha256(canonical(bound).encode()).hexdigest()
