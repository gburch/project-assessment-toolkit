"""Hard size limits for views an agent reads whole; omitted detail stays queryable."""

from __future__ import annotations

import json

BRIEF_CHARS = 80_000
DOCTOR_CHARS = 64_000
CHALLENGE_CHARS = 96_000
_METADATA_CHARS = 400


def _size(value):
    return len(json.dumps(value, indent=2, allow_nan=False))


def _parent(document, path):
    """Copy the dictionaries along ``path`` so the caller's document stays unchanged."""
    parent, *names = document, *path.split(".")
    for name in names[:-1]:
        child = parent.get(name)
        parent[name] = child = dict(child) if isinstance(child, dict) else {}
        parent = child
    return parent, names[-1]


def fit_budget(document, limit, references):
    """Replace named sections with read references, in order, until ``document`` fits.

    ``references`` maps a dotted section path to the command that reads its detail,
    least useful first. Removing a large section can free more room than was needed,
    so the most useful omitted sections then return where they fit. Exceeding the
    limit with every section removed is a defect.
    """
    result = dict(document)
    room = limit - _METADATA_CHARS
    removed = []
    for path, command in references.items():
        if _size(result) <= room:
            break
        parent, name = _parent(result, path)
        if name in parent:
            removed.append((path, parent[name]))
            parent[name] = {
                "omitted_for_budget": True,
                "chars": _size(parent[name]),
                "read_with": command,
            }
    if _size(result) > room:
        raise ValueError(f"View exceeds its {limit}-character budget after omitting detail")
    omitted = []
    for path, original in reversed(removed):
        parent, name = _parent(result, path)
        marker = parent[name]
        parent[name] = original
        if _size(result) > room:
            parent[name] = marker
            omitted.append(path)
    return {**result, "output_budget": {"limit_chars": limit, "omitted_sections": omitted[::-1]}}
