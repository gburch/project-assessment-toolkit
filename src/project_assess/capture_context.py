"""Candidate-centered context from bytes already captured, with one shared budget."""

from __future__ import annotations

import json
from collections import deque

CONTEXT_LINES = 3
MAX_WINDOW_LINES = 32
MAX_LINE_CHARS = 400


def attach_source_windows(analyses, sources, evidence, redact, byte_limit):
    entries = {entry["path"]: entry for entry in evidence if entry["path"] in sources}
    redacted, retained, used, omitted = {}, {}, 0, 0
    queues = deque(iter(analysis.get("candidates", [])) for analysis in analyses)
    for analysis in analyses:
        # Rich rows may alias the compact index; adding context must not expand
        # every indexed row or serialize the same window a third time.
        analysis["candidate_index"] = [
            {key: value for key, value in row.items() if key != "snippets"}
            for row in analysis.get("candidate_index", [])
        ]
    while queues:
        queue = queues.popleft()
        candidate = next(queue, None)
        if candidate is None:
            continue
        queues.append(queue)
        for location in candidate.get("locations", []):
            path, line = location["path"], location["line"]
            if path not in entries:
                omitted += 1
                continue
            if path not in redacted:
                # Redact the whole captured text first, preserving multiline
                # private-key context that may start outside the excerpt.
                redacted[path] = redact(sources[path]).splitlines()
            lines = redacted[path]
            start = max(1, line - CONTEXT_LINES)
            end = min(
                len(lines), location["end_line"] + CONTEXT_LINES, start + MAX_WINDOW_LINES - 1
            )
            if line > len(lines) or end < start:
                omitted += 1
                continue
            selected = lines[start - 1 : end]
            window = {
                "path": path,
                "line": start,
                "end_line": end,
                "candidate_line": line,
                "digest": entries[path]["digest"],
                "evidence_id": entries[path]["id"],
                "source_identity": "captured_snapshot",
                "excerpt": "\n".join(value[:MAX_LINE_CHARS] for value in selected),
                "truncated": end < location["end_line"]
                or any(len(value) > MAX_LINE_CHARS for value in selected),
            }
            key = (path, start, end)
            cost = len(json.dumps(window, sort_keys=True).encode())
            # Count both persisted copies: per-source window and rich snippet.
            cost *= 1 if key in retained else 2
            if used + cost > byte_limit:
                omitted += 1
                continue
            used += cost
            if key not in retained:
                retained[key] = window
                entries[path]["stats"].setdefault("source_windows", []).append(window)
            candidate.setdefault("snippets", []).append(window)
    for analysis in analyses:
        analysis["source_context"] = {
            "budget_bytes": byte_limit,
            "retained_bytes": used,
            "windows": len(retained),
            "omitted_locations": omitted,
            "partial": bool(omitted),
            "context_lines": CONTEXT_LINES,
            "max_window_lines": MAX_WINDOW_LINES,
            "max_line_characters": MAX_LINE_CHARS,
            "caveat": "Captured redacted excerpts, not full source; omitted or clipped ranges require further inspection.",
        }
        if omitted:
            analysis["gaps"].append(
                f"Captured source-window budget/scope omitted {omitted} candidate location(s)"
            )
