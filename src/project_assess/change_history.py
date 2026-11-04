"""Bounded local Git co-change metadata; no messages, authors, blobs or target code."""

from __future__ import annotations

import os
import re
import selectors
import subprocess
import time
from collections import Counter
from datetime import datetime
from pathlib import PurePosixPath

from .static_analysis import source_role

VERSION = "2"
MAX_COMMITS = 30
MAX_OUTPUT_BYTES = 512 * 1024
MAX_PATHS_PER_COMMIT = 128
MAX_COCHANGES = 2000
MAX_DELETION_COMMITS = 200
MAX_DELETED_DOCUMENTS = 50
_DOCUMENT_SUFFIXES = {".md", ".mdx", ".mdc", ".rst", ".adoc", ".txt"}
_OBJECT_ID = re.compile(r"[0-9a-f]{40,64}")
_CAVEAT = (
    "Bounded local first-parent commit metadata, not required edit sites, effort, runtime cost "
    "or representative change frequency. Commit dates are not workflow execution times. "
    "Only currently captured paths are retained; removed/excluded paths and other branches remain unknown."
)


def _read_git(prefix, environment, args, deadline, limit):
    process = subprocess.Popen(
        [*prefix, "--no-pager", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={**environment, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"},
    )
    payload = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError("Git history time limit reached")
                chunk = os.read(process.stdout.fileno(), min(65536, limit - len(payload) + 1))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > limit:
                    raise ValueError("Git history output byte limit reached")
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if process.returncode != 0:
            raise ValueError("Local Git history is unavailable")
        return bytes(payload)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def _parse_history(payload):
    """Null framing prevents filenames from masquerading as commit headers."""
    if payload and not payload.endswith(b"\0"):
        raise ValueError("Git history output is incomplete")
    tokens, rows, position = payload.split(b"\0"), [], 0
    while position < len(tokens) - 1:
        if tokens[position] != b"" or position + 4 >= len(tokens):
            raise ValueError("Unsupported Git history framing")
        revision = tokens[position + 1].decode("ascii")
        date = tokens[position + 2].decode("ascii")
        parents = tokens[position + 3].decode("ascii").split()
        if (
            not _OBJECT_ID.fullmatch(revision)
            or any(not _OBJECT_ID.fullmatch(parent) for parent in parents)
            or tokens[position + 4] != b""
        ):
            raise ValueError("Unsupported Git history identity")
        if datetime.fromisoformat(date.replace("Z", "+00:00")).utcoffset() is None:
            raise ValueError("Git commit date lacks timezone")
        position += 5
        paths = []
        first_path = True
        while position < len(tokens) - 1 and tokens[position] != b"":
            raw = tokens[position]
            if first_path:
                if not raw.startswith(b"\n"):
                    raise ValueError("Unsupported Git history path framing")
                raw = raw[1:]
                first_path = False
            paths.append(os.fsdecode(raw))
            position += 1
        rows.append(
            {
                "revision": revision,
                "committed_at": date,
                "parent_count": len(parents),
                "paths": paths,
            }
        )
    return rows


def _deleted_documents(prefix, environment, current, tip, deadline, gaps):
    """Record paths only; deleted content is never read or retained."""
    try:
        payload = _read_git(
            prefix,
            environment,
            [
                "log",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--no-show-signature",
                "--no-notes",
                "--find-renames",
                "--diff-filter=D",
                "--first-parent",
                "--diff-merges=first-parent",
                "-z",
                "--format=%x00%H%x00%cI%x00%P%x00",
                "--name-only",
                f"--max-count={MAX_DELETION_COMMITS}",
                tip,
                "--",
            ],
            deadline,
            MAX_OUTPUT_BYTES,
        )
        rows = _parse_history(payload)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        gaps.append("Deleted-document history could not be read within its bounds")
        return [], 0
    found = {}
    for row in rows:
        for path in row["paths"]:
            role = source_role(path)
            if (
                PurePosixPath(path).suffix.lower() in _DOCUMENT_SUFFIXES
                and path not in current
                and not role["vendor_hint"]
                and not role["generated_hint"]
            ):
                found.setdefault(
                    path,
                    {
                        "path": path,
                        "deleted_at": row["committed_at"],
                        "revision": row["revision"],
                    },
                )
    ordered = sorted(
        found.values(), key=lambda item: (item["deleted_at"], item["path"]), reverse=True
    )
    if len(ordered) > MAX_DELETED_DOCUMENTS:
        gaps.append("Deleted-document retention is partial")
    return ordered[:MAX_DELETED_DOCUMENTS], max(0, len(ordered) - MAX_DELETED_DOCUMENTS)


def collect_change_history(
    prefix,
    environment,
    captured_paths,
    revision,
    *,
    max_commits=MAX_COMMITS,
    timeout_seconds=5,
    tip="HEAD",
):
    """Use the collector's trusted Git prefix/environment without loading project config.

    ``tip`` is HEAD for worktree scans, or the captured revision for Git backfills.
    """
    if type(max_commits) is not int or not 1 <= max_commits <= MAX_COMMITS:
        raise ValueError("Invalid change history commit limit")
    if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 5:
        raise ValueError("Invalid change history time limit")
    result = {
        "schema_version": 1,
        "version": VERSION,
        "status": "unavailable",
        "source_revision": revision,
        "head_observed": None,
        "commits": [],
        "cochanges": [],
        "deleted_documents": [],
        "coverage": {
            "selection": "local_first_parent_HEAD",
            "commit_limit": max_commits,
            "commits_observed": 0,
            "commits_retained": 0,
            "shallow": None,
            "uncaptured_path_occurrences": 0,
            "retention_path_omissions": 0,
            "cochange_pairs_omitted": 0,
            "boundary_commits_omitted": 0,
            "max_paths_per_commit": MAX_PATHS_PER_COMMIT,
            "max_cochanges": MAX_COCHANGES,
            "output_byte_limit": MAX_OUTPUT_BYTES,
        },
        "gaps": [],
        "caveat": _CAVEAT,
    }
    if tip not in {"HEAD", revision}:
        raise ValueError("Change history starts at HEAD or the captured revision")
    if tip != "HEAD":
        result["coverage"]["selection"] = "local_first_parent_revision"
    if not isinstance(revision, str) or not _OBJECT_ID.fullmatch(revision):
        result["gaps"].append("No captured Git revision; historical co-change remains unknown")
        return result
    deadline = time.monotonic() + timeout_seconds
    try:
        shallow = _read_git(
            prefix, environment, ["rev-parse", "--is-shallow-repository"], deadline, 16
        ).strip()
        if shallow not in {b"true", b"false"}:
            raise ValueError("Local Git shallow status is unknown")
        result["coverage"]["shallow"] = shallow == b"true"
        payload = _read_git(
            prefix,
            environment,
            [
                "log",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--no-show-signature",
                "--no-notes",
                "--no-renames",
                "--first-parent",
                "--diff-merges=first-parent",
                "-z",
                "--format=%x00%H%x00%cI%x00%P%x00",
                "--name-only",
                f"--max-count={max_commits + 1}",
                tip,
                "--",
            ],
            deadline,
            MAX_OUTPUT_BYTES,
        )
        rows = _parse_history(payload)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        result["gaps"].append(
            str(error)
            if isinstance(error, ValueError)
            else "Local Git history could not be read within its bounds"
        )
        return result
    coverage = result["coverage"]
    coverage["commits_observed"] = len(rows)
    result["head_observed"] = rows[0]["revision"] if rows else None
    if result["head_observed"] != revision:
        result["gaps"].append("Git history HEAD does not match the captured source revision")
        return result
    known = set(captured_paths)
    pairs = Counter()
    for row in rows[:max_commits]:
        if coverage["shallow"] and row["parent_count"] == 0:
            # Git presents a shallow frontier as a root whose whole tree was
            # added. That is not an observed co-change and must not be counted.
            coverage["boundary_commits_omitted"] += 1
            result["commits"].append(
                {
                    "revision": row["revision"],
                    "committed_at": row["committed_at"],
                    "paths": [],
                    "boundary_omitted": True,
                    "uncaptured_paths": 0,
                    "omitted_paths": 0,
                }
            )
            continue
        eligible = sorted(set(row["paths"]).intersection(known))
        uncaptured = len(row["paths"]) - len(eligible)
        omitted = max(0, len(eligible) - MAX_PATHS_PER_COMMIT)
        coverage["uncaptured_path_occurrences"] += uncaptured
        coverage["retention_path_omissions"] += omitted
        paths = eligible[:MAX_PATHS_PER_COMMIT]
        result["commits"].append(
            {
                "revision": row["revision"],
                "committed_at": row["committed_at"],
                "paths": paths,
                "boundary_omitted": False,
                "uncaptured_paths": uncaptured,
                "omitted_paths": omitted,
            }
        )
        for index, left in enumerate(paths):
            for right in paths[index + 1 :]:
                pair = (left, right)
                if pair in pairs or len(pairs) < MAX_COCHANGES:
                    pairs[pair] += 1
                else:
                    coverage["cochange_pairs_omitted"] += 1
    coverage["commits_retained"] = len(result["commits"])
    if len(rows) > max_commits:
        result["gaps"].append("Git history commit limit reached; older changes remain unknown")
    if coverage["shallow"]:
        result["gaps"].append("Git history is shallow; earlier changes remain unavailable")
    if coverage["boundary_commits_omitted"]:
        result["gaps"].append(
            "Shallow frontier root diffs are omitted; their apparent whole-tree additions are not co-change evidence"
        )
    if coverage["uncaptured_path_occurrences"]:
        result["gaps"].append(
            "History includes uncaptured or removed paths; only current captured names are retained"
        )
    if coverage["retention_path_omissions"] or coverage["cochange_pairs_omitted"]:
        result["gaps"].append("Git history path or pair retention is partial")
    result["cochanges"] = [
        {"paths": list(pair), "commits": count}
        for pair, count in sorted(pairs.items(), key=lambda item: (-item[1], item[0]))
    ]
    result["deleted_documents"], omitted = _deleted_documents(
        prefix, environment, known, tip, deadline, result["gaps"]
    )
    coverage["deleted_documents_omitted"] = omitted
    result["status"] = "partial" if result["gaps"] else "complete"
    return result
