"""Pure, offline badge projections of one captured assessment and its saved review."""

from __future__ import annotations

import re
from datetime import datetime
from html import escape

from .rubric import DIMENSIONS


def _allowed(value, pattern):
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.isoformat() if parsed.tzinfo is not None else None


def _score(value):
    return value if type(value) is int and 0 <= value <= 5 else None


def _choice(value, choices):
    return value if isinstance(value, str) and value in choices else "unknown"


def _rating(rating):
    burden = _score(rating.get("burden"))
    basis = rating.get("burden_basis", "source_estimate" if burden is not None else "unknown")
    return {
        "capability": _score(rating.get("capability")),
        "burden": burden,
        "confidence": _choice(rating.get("confidence"), {"low", "medium", "high"}),
        "burden_basis": _choice(basis, {"observed", "source_estimate"})
        if burden is not None
        else "unknown",
        "burden_confidence": _choice(rating.get("burden_confidence"), {"low", "medium", "high"})
        if burden is not None
        else "unknown",
    }


def _combined(values):
    unique = set(values)
    return next(iter(unique)) if len(unique) == 1 else "mixed"


def badge_data(report, dimension="summary"):
    """Return Shields endpoint data with only allowlisted PAT provenance.

    ``known`` means both saved rating axes are numeric, not that a project is
    healthy. Finding counts include records in both the snapshot and its review.
    """
    if dimension not in ("summary", *DIMENSIONS):
        raise ValueError("Unknown badge dimension")
    assessment, review = report["assessment"], report.get("review")
    source = assessment.get("source", {})
    if review is not None and any(
        expected is None or review.get(key) != expected
        for key, expected in (
            ("assessment_id", assessment.get("id")),
            ("source_digest", source.get("manifest_digest")),
            ("rubric_version", assessment.get("rubric_version")),
        )
    ):
        raise ValueError("Review does not match the selected assessment")
    ratings = {
        name: _rating((review or {}).get("ratings", {}).get(name, {})) for name in DIMENSIONS
    }
    known = sum(
        rating["capability"] is not None and rating["burden"] is not None
        for rating in ratings.values()
    )
    findings = assessment.get("findings", []) + (review or {}).get("findings", [])
    counts = {
        level: sum(row.get("severity") == level for row in findings)
        for level in ("critical", "high")
    }
    revision = _allowed(source.get("revision"), r"[0-9a-fA-F]{7,64}")
    complete = assessment.get("complete") is True
    provenance = {
        "assessment_id": _allowed(assessment.get("id"), r"a_[0-9a-f]{1,64}"),
        "review_id": _allowed((review or {}).get("id"), r"r_[0-9a-f]{1,64}"),
        "assessed_at": _timestamp(assessment.get("created_at")),
        "reviewed_at": _timestamp((review or {}).get("created_at")),
        "revision": revision.lower()[:12] if revision else None,
        "source_digest": _allowed(source.get("manifest_digest"), r"sha256:[0-9a-f]{64}"),
        "rubric_version": _allowed(
            assessment.get("rubric_version"), r"[0-9]{1,8}(?:\.[0-9]{1,8}){0,3}"
        ),
        "dimension": dimension,
        "review_status": "unreviewed" if review is None else "reviewed",
        "known_dimensions": known,
        "total_dimensions": len(DIMENSIONS),
        "complete": complete,
        "gap_count": len(assessment.get("gaps", [])),
        "findings": counts,
    }
    reported = f"{counts['critical']} critical / {counts['high']} high"
    if dimension == "summary":
        label = "PAT"
        status = "unreviewed" if review is None else f"{known}/{len(DIMENSIONS)} known"
        message = f"{status} | reported: {reported}"
        provenance.update(
            {
                key: _combined(rating[key] for rating in ratings.values())
                for key in ("confidence", "burden_basis", "burden_confidence")
            }
        )
    else:
        label = "PAT " + dimension.capitalize()
        rating = ratings[dimension]
        capability, burden = (
            "?" if rating[axis] is None else rating[axis] for axis in ("capability", "burden")
        )
        message = f"C{capability}/5 B{burden}/5"
        if review is None:
            message += " | unreviewed"
        if counts["critical"] or counts["high"]:
            message += " | reported: " + reported
        provenance.update(rating)
    if not complete:
        message += " | partial scan"
    return {
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": "9a6700" if counts["critical"] or counts["high"] else "616e7c",
        "pat": provenance,
    }


def badge(report, dimension="summary"):
    """Render a deterministic standalone SVG without filesystem or network access."""
    data = badge_data(report, dimension)
    meta = data["pat"]
    title = data["label"] + ": " + data["message"]
    description = (
        f"Captured snapshot {meta['assessment_id'] or 'unknown'} at {meta['assessed_at'] or 'unknown'}; "
        f"review {meta['review_id'] or 'unknown'} at {meta['reviewed_at'] or 'unknown'}; "
        f"source revision {meta['revision'] or 'unknown'}; source digest {meta['source_digest'] or 'unknown'}; "
        f"rubric {meta['rubric_version'] or 'unknown'}. "
        f"Capability confidence: {meta['confidence']}; burden basis: {meta['burden_basis']}; "
        f"burden confidence: {meta['burden_confidence']}. "
        f"Both rating axes known for {meta['known_dimensions']}/{meta['total_dimensions']} dimensions. "
        f"Collection complete: {str(meta['complete']).lower()}; collection gaps: {meta['gap_count']}. "
        "Finding counts are reported records, not proof of absent risks or a security certification. "
        "Static snapshot; current repository or deployed behavior may differ."
    )
    left = 14 + len(data["label"]) * 7
    message, footers = data["message"], []
    right = 14 + len(message) * 7
    if left + right > 288 and " | " in message:
        message, *footers = message.split(" | ")
        right = 14 + len(message) * 7
    width = max([left + right, *(14 + len(part) * 7 for part in footers)])
    height = 24 + 18 * len(footers)
    identity = "pat-badge-" + dimension
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="{identity}-title {identity}-desc">'
        f'<title id="{identity}-title">{escape(title)}</title>'
        f'<desc id="{identity}-desc">{escape(description)}</desc>'
        f'<rect width="{width}" height="{height}" rx="3" fill="#4b5563"/>'
        f'<path d="M{left} 0h{width - left}v24H{left}z" fill="#{data["color"]}"/>'
        '<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans Mono,monospace" font-size="11">'
        f'<text x="{left / 2:g}" y="16">{escape(data["label"])}</text>'
        f'<text x="{left + (width - left) / 2:g}" y="16">{escape(message)}</text>'
        + "".join(
            f'<text x="{width / 2:g}" y="{37 + row * 18}">{escape(part)}</text>'
            for row, part in enumerate(footers)
        )
        + "</g></svg>"
    )
