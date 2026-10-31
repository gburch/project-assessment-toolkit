"""Bounded source ranges whose bytes still match the immutable snapshot."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from .collector import (
    MAX_FILE_BYTES,
    MAX_SOURCE_FILE_BYTES,
    _bytes_digest,
    _open_directory,
    _read_at,
    _redact,
)


def read_context(root, entry, line=1, end_line=None, max_chars=8000):
    """Read captured source only; reject stale bytes and all symlink traversal."""
    if type(line) is not int or line < 1:
        raise ValueError("line must be a positive integer")
    if end_line is not None and (type(end_line) is not int or end_line < line):
        raise ValueError("end_line must be at or after line")
    if type(max_chars) is not int or not 256 <= max_chars <= 16000:
        raise ValueError("max_chars must be between 256 and 16000")
    path = PurePosixPath(entry["path"])
    if entry["kind"] not in {
        "python",
        "javascript",
        "source",
        "documentation",
        "manifest",
        "configuration",
    }:
        raise ValueError("Source context requires a captured source evidence ID")
    if path.is_absolute() or not path.parts or any(part in {"..", "."} for part in path.parts):
        raise ValueError("Source path is not a captured relative path")
    descriptors = []
    try:
        descriptors.append(_open_directory(Path(root)))
        for part in path.parts[:-1]:
            descriptors.append(
                os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1])
            )
        bound = (
            MAX_SOURCE_FILE_BYTES
            if entry["kind"] in {"python", "javascript", "source"}
            else MAX_FILE_BYTES
        )
        payload, _ = _read_at(descriptors[-1], path.name, bound)
    except (OSError, ValueError):
        raise ValueError(
            "Captured source is inaccessible; rescan before requesting live context"
        ) from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    if _bytes_digest(payload) != entry["digest"]:
        raise ValueError("Source bytes changed since capture; rescan to inspect the new source")
    # Preserve multiline credential state even when its opening marker lies
    # above the requested range.
    lines = _redact(payload.decode("utf-8")).splitlines()
    if line > len(lines):
        raise ValueError("Requested line is outside captured source")
    requested_end = end_line if end_line is not None else line + 39
    last = min(requested_end, line + 199, len(lines))
    selected, used, clipped = [], 0, False
    for value in lines[line - 1 : last]:
        available = max_chars - used - bool(selected)
        if available < 0 or (available == 0 and value):
            break
        selected.append(value[:available])
        used += len(selected[-1]) + (len(selected) > 1)
        if len(value) > available:
            clipped = True
            break
    actual_end = line + len(selected) - 1
    truncated = requested_end > actual_end or clipped
    return {
        "evidence_id": entry["id"],
        "path": entry["path"],
        "digest": entry["digest"],
        "source_identity": "snapshot_matched_live_bytes",
        "line": line,
        "end_line": actual_end,
        "next_line": actual_end
        if clipped
        else actual_end + 1
        if actual_end < min(requested_end, len(lines))
        else None,
        "line_truncated": clipped,
        "total_lines": len(lines),
        "excerpt": "\n".join(selected),
        "truncated": truncated,
        "caveat": "Matching source bytes do not prove reachability, runtime behavior or safe removal.",
    }
