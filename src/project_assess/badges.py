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
        "Higher capability means more demonstrated support; lower burden means less upkeep. "
        "Axis colors distinguish capability and burden, not rating quality. "
        "Static snapshot; current repository or deployed behavior may differ."
    )

    def text(x, y, value, *, color="#cbd5e1", size=10, weight=400, anchor="start"):
        return (
            f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{escape(str(value))}</text>'
        )

    counts = meta["findings"]
    has_findings = bool(counts["critical"] or counts["high"])
    footers = []
    if has_findings:
        warning = f"Reported: {counts['critical']} critical / {counts['high']} high"
        footers.extend(
            [warning]
            if len(warning) <= 29
            else [f"Reported: {counts['critical']} critical", f"{counts['high']} high"]
        )
    if meta["review_status"] == "unreviewed" and dimension != "summary":
        footers.append("Unreviewed")
    if not meta["complete"]:
        footers.append("Partial scan")
    card_height = 52 + 18 * len(footers)
    height = card_height + 8  # Keep wrapped cards apart in GitHub's inline image layout.
    visible = [
        text(
            12,
            20,
            "Assessment" if dimension == "summary" else dimension.capitalize(),
            color="#f1f5f9",
            size=12,
            weight=600,
        ),
        text(188, 19, "PAT", color="#94a3b8", size=9, weight=600, anchor="end"),
    ]
    if dimension == "summary":
        if meta["review_status"] == "unreviewed":
            visible.append(text(12, 44, "Unreviewed", color="#f1f5f9", size=12, weight=600))
        else:
            visible.extend(
                [
                    text(
                        12,
                        45,
                        f"{meta['known_dimensions']}/{meta['total_dimensions']}",
                        color="#f1f5f9",
                        size=14,
                        weight=700,
                    ),
                    text(42, 44, "known"),
                ]
            )
        visible.append(
            text(
                188,
                44,
                "Reported findings" if has_findings else "0 critical / 0 high",
                color="#fbbf24" if has_findings else "#94a3b8",
                anchor="end",
            )
        )
    else:
        for label, key, x, color in (
            ("Capability", "capability", 12, "#67e8f9"),
            ("Burden", "burden", 112, "#fbbf24"),
        ):
            score = "?" if meta[key] is None else meta[key]
            visible.extend(
                [
                    text(x, 43, label, color=color),
                    text(
                        91 if key == "capability" else 188,
                        45,
                        f"{score}/5",
                        color=color,
                        size=14,
                        weight=700,
                        anchor="end",
                    ),
                ]
            )
        visible.append('<path d="M100 31v16" stroke="#334155"/>')
    if footers:
        visible.append('<path d="M12 52h176" stroke="#334155"/>')
        visible.extend(
            text(100, 65 + row * 18, value, color="#fbbf24", anchor="middle")
            for row, value in enumerate(footers)
        )
    identity = "pat-badge-" + dimension
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="{height}" '
        f'viewBox="0 0 200 {height}" role="img" aria-labelledby="{identity}-title {identity}-desc">'
        f'<title id="{identity}-title">{escape(title)}</title>'
        f'<desc id="{identity}-desc">{escape(description)}</desc>'
        f'<rect x="0.5" y="0.5" width="199" height="{card_height - 1}" rx="8" fill="#111b2b" stroke="#334155"/>'
        '<g font-family="system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif">'
        + "".join(visible)
        + "</g></svg>"
    )
