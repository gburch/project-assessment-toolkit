"""Pure, offline badge projections of one captured assessment and its saved review."""

from __future__ import annotations

import re
from datetime import datetime
from html import escape

from .rubric import DIMENSIONS

NAVY, SLATE, AMBER, RUST, LINE, TRACK = (
    "#13223B",
    "#5B6478",
    "#F2AE12",
    "#B4471F",
    "#E2DCCB",
    "#F0EDE4",
)
# The PAT mark: an amber P holding a spirit-level vial, drawn in a 32px box.
MARK = (
    '<g transform="{transform}"><path d="M4 6a4 4 0 0 1 4-4h12a10 10 0 0 1 0 20h-6v6a4 4 0 0 1-8 0z" '
    'fill="#F2AE12"/><rect x="6" y="7.5" width="21" height="9" rx="4.5" fill="#F6EFD2" '
    'stroke="#13223B" stroke-width="2"/><path d="M11.5 8.5v7M21.5 8.5v7" stroke="#13223B" '
    'stroke-width="1.6"/><ellipse cx="16.5" cy="12" rx="2.6" ry="2.1" fill="#D9B300"/></g>'
)


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
        label = "PAT " + (
            "Performance & Scalability" if dimension == "performance" else dimension.capitalize()
        )
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


def badge_assets(report):
    """Render the complete fixed-name badge set for one report snapshot.

    Callers choose where to export these assets. The renderer performs no writes,
    and asset names come only from the shared dimension list, never project text.
    """
    return {f"{dimension}.svg": badge(report, dimension) for dimension in ("summary", *DIMENSIONS)}


def badge(report, dimension="summary"):
    """Render a deterministic standalone SVG without filesystem or network access."""
    data = badge_data(report, dimension)
    meta = data["pat"]
    ratings = (report.get("review") or {}).get("ratings", {})
    dots = [
        _score(ratings.get(name, {}).get("capability")) is not None
        and _score(ratings.get(name, {}).get("burden")) is not None
        for name in DIMENSIONS
    ]
    title = data["label"] + ": " + data["message"]
    description = (
        f"Captured snapshot {meta['assessment_id'] or 'unknown'} at {meta['assessed_at'] or 'unknown'}; "
        f"review {meta['review_id'] or 'unknown'} at {meta['reviewed_at'] or 'unknown'}; "
        f"source revision {meta['revision'] or 'unknown'}; source digest {meta['source_digest'] or 'unknown'}; "
        f"rubric {meta['rubric_version'] or 'unknown'}. "
        f"Capability confidence: {meta['confidence']}; burden basis: {meta['burden_basis']}; "
        f"declared burden confidence: {meta['burden_confidence']} (inspect the report for scope and support). "
        f"Both rating axes known for {meta['known_dimensions']}/{meta['total_dimensions']} dimensions. "
        f"Collection complete: {str(meta['complete']).lower()}; collection gaps: {meta['gap_count']}. "
        "Finding counts are reported records, not proof of absent risks or a security certification. "
        "Higher capability means more demonstrated support; lower burden means less upkeep. "
        "Both tracks place the better end on the right. "
        "Static snapshot; current repository or deployed behavior may differ."
    )

    def text(x, y, value, *, color=SLATE, size=10, weight=400, anchor="start"):
        return (
            f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" '
            f'font-weight="{weight}" text-anchor="{anchor}">{escape(str(value))}</text>'
        )

    counts = meta["findings"]
    footers = []
    if counts["critical"] or counts["high"]:
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
    stamp = (meta["assessed_at"] or "Date unknown")[:10]
    if dimension == "summary":
        visible = [
            MARK.format(transform="translate(10 10)"),
            text(50, 24, "PAT", color=NAVY, size=12, weight=700),
            text(50, 40, stamp),
        ]
        if meta["review_status"] == "unreviewed":
            visible.append(
                text(188, 24, "Unreviewed", color=NAVY, size=12, weight=700, anchor="end")
            )
        else:
            visible.append(
                text(
                    188,
                    24,
                    f"{meta['known_dimensions']}/{meta['total_dimensions']} known",
                    color=NAVY,
                    size=12,
                    weight=700,
                    anchor="end",
                )
            )
            # One dot per dimension: filled when both axes are rated, never a grade.
            visible.extend(
                f'<circle cx="{132 + 8 * index}" cy="37" r="3" fill="{AMBER if known else "#FFFFFF"}" '
                f'stroke="{NAVY if known else SLATE}"/>'
                for index, known in enumerate(dots)
            )
    else:
        visible = [
            text(12, 20, data["label"].removeprefix("PAT "), color=NAVY, size=12, weight=700),
            MARK.format(transform="translate(172 6) scale(0.5)"),
        ]
        for label, key, left in (("Capability", "capability", 12), ("Burden", "burden", 108)):
            value = meta[key]
            visible.extend(
                [
                    text(left, 37, label),
                    text(
                        left + 80,
                        37,
                        f"{'?' if value is None else value}/5",
                        color=NAVY,
                        size=11,
                        weight=700,
                        anchor="end",
                    ),
                    f'<rect x="{left}" y="42" width="80" height="5" rx="2.5" fill="{TRACK}"/>',
                ]
            )
            if value is not None:
                # Right is better on both tracks: burden runs heavy to light.
                position = value if key == "capability" else 5 - value
                visible.append(
                    f'<circle cx="{left + 3 + 74 * position / 5:g}" cy="44.5" r="3.5" '
                    f'fill="{AMBER}" stroke="{NAVY}"/>'
                )
    if footers:
        visible.append(f'<path d="M12 52h176" stroke="{LINE}"/>')
        visible.extend(
            text(
                100,
                65 + row * 18,
                value,
                color=SLATE if value in ("Partial scan", "Unreviewed") else RUST,
                size=10,
                weight=600,
                anchor="middle",
            )
            for row, value in enumerate(footers)
        )
    identity = "pat-badge-" + dimension
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="{height}" '
        f'viewBox="0 0 200 {height}" role="img" aria-labelledby="{identity}-title {identity}-desc">'
        f'<title id="{identity}-title">{escape(title)}</title>'
        f'<desc id="{identity}-desc">{escape(description)}</desc>'
        f'<rect x="0.5" y="0.5" width="199" height="{card_height - 1}" rx="10" fill="#FFFFFF" stroke="{LINE}"/>'
        '<g font-family="system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif">'
        + "".join(visible)
        + "</g></svg>"
    )
