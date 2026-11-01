"""Read earlier commits from local Git objects into private PAT state.

Only object reads are used: ``rev-parse``, ``log``, ``for-each-ref``, ``ls-tree``
and raw ``cat-file --batch``. Nothing is checked out, no filter, textconv or hook
runs, and the assessed repository is never written. Blob bytes are verified
against their object IDs before they are written beneath PAT's state directory.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

from .change_history import _read_git
from .collector import (
    _SECRET_DIRS,
    _SKIP_DIRS,
    MAX_FILES,
    MAX_GIT_OUTPUT_BYTES,
    MAX_SOURCE_FILE_BYTES,
    _git_configuration,
    _secret_name,
)

VERSION = "1"
MAX_SNAPSHOTS = 12
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_SELECTION_OUTPUT_BYTES = 64 * 1024
SELECTION_SECONDS = 10
EXTRACTION_SECONDS = 60
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# A revision name, never an option, pathspec or ``<rev>:<path>`` object lookup.
_REVISION = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/@{}~^+-]{0,199}")
_TREE_ENTRY = re.compile(rb"(\d{6}) (blob|tree|commit) ([0-9a-f]{40,64}) +(-|\d+)\t(.+)", re.S)
CAVEAT = (
    "Facts from committed Git objects only. Untracked files, supplied reports, runtime state "
    "and the reviewer knowledge of that time are unknown; ratings stay unknown until reviewed."
)


def _environment(root):
    prefix, environment = _git_configuration(Path(root))
    return prefix, {**environment, "GIT_NO_REPLACE_OBJECTS": "1"}


def _git_text(prefix, environment, args, deadline, limit=MAX_SELECTION_OUTPUT_BYTES):
    return _read_git(prefix, environment, args, deadline, limit).decode("utf-8", "replace")


def _as_of(committed_at):
    moment = datetime.fromisoformat(committed_at.replace("Z", "+00:00"))
    if moment.utcoffset() is None:
        raise ValueError("Git commit date lacks timezone")
    return moment.astimezone(UTC).isoformat()


def _commit(prefix, environment, name, deadline):
    """Resolve one name to a commit with its tree and committer date."""
    try:
        revision = _git_text(
            prefix, environment, ["rev-parse", "--verify", "--quiet", name + "^{commit}"], deadline
        ).strip()
    except ValueError:
        return None
    if not _OBJECT_ID.fullmatch(revision):
        return None
    fields = _git_text(
        prefix,
        environment,
        [
            "log",
            "-1",
            "--no-walk",
            "--no-color",
            "--no-show-signature",
            "--no-notes",
            "--format=%H%x00%T%x00%cI",
            revision,
            "--",
        ],
        deadline,
    ).strip()
    observed, tree, committed_at = (fields.split("\0") + ["", ""])[:3]
    if observed != revision or not _OBJECT_ID.fullmatch(tree):
        raise ValueError("Unsupported Git commit identity")
    return {
        "revision": revision,
        "tree": tree,
        "committed_at": committed_at,
        "as_of": _as_of(committed_at),
    }


def _month_starts(months, today):
    year, month = today.year, today.month
    for _ in range(months):
        yield datetime(year, month, 1, tzinfo=UTC)
        year, month = (year - 1, 12) if month == 1 else (year, month - 1)


def select_commits(root, *, months=None, tags=None, revisions=None, today=None):
    """Choose up to MAX_SNAPSHOTS commits, oldest first.

    ``months`` takes the last first-parent commit before each of the latest month
    starts (month-end states); ``tags`` the newest release tags; ``revisions`` an
    explicit list of commit names.
    """
    chosen = [value is not None for value in (months, tags, revisions)]
    if sum(chosen) != 1:
        raise ValueError("Choose exactly one of months, tags or revisions")
    for value in (months, tags):
        if value is not None and (type(value) is not int or not 1 <= value <= MAX_SNAPSHOTS):
            raise ValueError(f"Backfill counts must be integers from 1 to {MAX_SNAPSHOTS}")
    if revisions is not None:
        if (
            not isinstance(revisions, list)
            or not 1 <= len(revisions) <= MAX_SNAPSHOTS
            or any(not isinstance(name, str) or not _REVISION.fullmatch(name) for name in revisions)
        ):
            raise ValueError(
                f"Revisions must be 1 to {MAX_SNAPSHOTS} plain commit names, tags or IDs"
            )
    prefix, environment = _environment(root)
    deadline = time.monotonic() + SELECTION_SECONDS
    gaps, found = [], {}

    def keep(commit, label):
        found.setdefault(commit["revision"], {**commit, "selected_by": []})["selected_by"].append(
            label
        )

    shallow = _git_text(prefix, environment, ["rev-parse", "--is-shallow-repository"], deadline)
    if shallow.strip() == "true":
        gaps.append("Git history is shallow; commits beyond its frontier are unavailable")
    if months is not None:
        mode = "monthly"
        for start in _month_starts(months, today or datetime.now(UTC)):
            # The last commit before a month starts is the previous month's end state.
            label = "month-end " + (start - timedelta(days=1)).strftime("%Y-%m")
            revision = _git_text(
                prefix,
                environment,
                [
                    "rev-list",
                    "-1",
                    "--first-parent",
                    "--before=" + start.isoformat(),
                    "HEAD",
                    "--",
                ],
                deadline,
            ).strip()
            commit = _commit(prefix, environment, revision, deadline) if revision else None
            if commit is None:
                gaps.append(f"No first-parent commit before {start.date().isoformat()}")
                continue
            keep(commit, label)
    elif tags is not None:
        mode = "tags"
        listing = _git_text(
            prefix,
            environment,
            [
                "for-each-ref",
                f"--count={tags}",
                "--sort=-creatordate",
                "--format=%(refname:strip=2)%00%(objectname)",
                "refs/tags/",
            ],
            deadline,
        )
        lines = [line for line in listing.split("\n") if line]
        if not lines:
            gaps.append("No release tags were found")
        for line in lines:
            name, _, objectname = line.partition("\0")
            commit = (
                _commit(prefix, environment, objectname, deadline)
                if _OBJECT_ID.fullmatch(objectname)
                else None
            )
            if commit is None:
                gaps.append("A tag does not name a commit and was skipped")
                continue
            keep(commit, "tag " + "".join(c for c in name if c.isprintable())[:120])
    else:
        mode = "revisions"
        for name in revisions:
            commit = _commit(prefix, environment, name, deadline)
            if commit is None:
                gaps.append("Unknown or non-commit revision: " + name)
                continue
            keep(commit, "revision " + name)
    commits = sorted(found.values(), key=lambda row: (row["as_of"], row["revision"]))
    return {
        "version": VERSION,
        "selection": {
            "mode": mode,
            "months": months,
            "tags": tags,
            "revisions": revisions,
            "limit": MAX_SNAPSHOTS,
        },
        "commits": commits,
        "gaps": gaps,
    }


def _excluded_directory(parts):
    for index, part in enumerate(parts[:-1]):
        if part in _SKIP_DIRS or part.lower() in _SECRET_DIRS:
            return PurePosixPath(*parts[: index + 1])
    return None


def _safe_parts(path):
    parts = tuple(path.split("/"))
    if (
        not path
        or any(part in {"", ".", ".."} or part.casefold() == ".git" for part in parts)
        or any(ord(char) < 32 or char == "\x7f" for char in path)
    ):
        return None
    return parts


def _verified(oid, payload):
    algorithm = hashlib.sha1 if len(oid) == 40 else hashlib.sha256
    return algorithm(b"blob %d\0" % len(payload) + payload).hexdigest() == oid


def _read_blobs(prefix, environment, wanted, deadline, write):
    """Stream raw blob bytes; ``cat-file`` without --filters runs no drivers."""
    process = subprocess.Popen(
        [*prefix, "--no-pager", "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    timer = threading.Timer(max(0.01, deadline - time.monotonic()), process.kill)
    timer.start()

    def feed():
        try:
            for oid, _ in wanted:
                process.stdin.write(oid.encode() + b"\n")
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    try:
        for oid, path in wanted:
            header = process.stdout.readline(256).split()
            if len(header) != 3 or header[0].decode() != oid or header[1] != b"blob":
                raise ValueError("Git object read failed or exceeded its time limit")
            size = int(header[2])
            payload = process.stdout.read(size)
            if len(payload) != size or process.stdout.read(1) != b"\n":
                raise ValueError("Git object read failed or exceeded its time limit")
            if not _verified(oid, payload):
                raise ValueError("Git object bytes do not match their object ID")
            write(path, payload)
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        writer.join(1)
        process.stdout.close()


def extract_commit(root, commit, destination):
    """Write a commit's eligible blobs to a new private directory.

    Returns the committed path set (for collector selection) and extraction
    coverage. Excluded directories are recreated empty so collection reports
    them exactly as a worktree scan would; their files are never copied.
    """
    destination = Path(destination)
    prefix, environment = _environment(root)
    deadline = time.monotonic() + EXTRACTION_SECONDS
    listing = _read_git(
        prefix,
        environment,
        ["ls-tree", "-r", "-z", "-l", "--full-tree", commit["revision"]],
        deadline,
        MAX_GIT_OUTPUT_BYTES,
    )
    if listing and not listing.endswith(b"\0"):
        raise ValueError("Git tree listing is incomplete")
    counts = dict.fromkeys(
        (
            "submodules",
            "symlinks",
            "unsafe_paths",
            "path_collisions",
            "credential_files",
            "excluded_directory_files",
            "oversize_blobs",
            "byte_limit_blobs",
            "file_limit_blobs",
        ),
        0,
    )
    selected, wanted, excluded_directories, claimed = set(), [], set(), set()
    total = 0
    for raw in listing.split(b"\0")[:-1]:
        match = _TREE_ENTRY.fullmatch(raw)
        if not match:
            raise ValueError("Unsupported Git tree listing")
        mode, kind, oid, size, raw_path = match.groups()
        path = os.fsdecode(raw_path)
        parts = _safe_parts(path)
        if parts is None:
            counts["unsafe_paths"] += 1
            continue
        if kind == b"commit":
            counts["submodules"] += 1
            continue
        if kind != b"blob":
            raise ValueError("Unsupported Git tree listing")
        selected.add(path)
        if mode == b"120000":
            counts["symlinks"] += 1
            continue
        directory = _excluded_directory(parts)
        if directory is not None:
            excluded_directories.add(directory)
            counts["excluded_directory_files"] += 1
            continue
        if _secret_name(parts[-1]):
            counts["credential_files"] += 1
            continue
        key = unicodedata.normalize("NFC", path).casefold()
        if key in claimed:
            counts["path_collisions"] += 1
            continue
        size = int(size)
        if size > MAX_SOURCE_FILE_BYTES:
            counts["oversize_blobs"] += 1
            continue
        if len(wanted) >= MAX_FILES:
            counts["file_limit_blobs"] += 1
            continue
        if total + size > MAX_SNAPSHOT_BYTES:
            counts["byte_limit_blobs"] += 1
            continue
        claimed.add(key)
        total += size
        wanted.append((oid.decode(), path))
    destination.mkdir(mode=0o700)
    for directory in sorted(excluded_directories):
        try:
            (destination / directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            counts["path_collisions"] += 1
    written = []

    def write(path, payload):
        target = destination / path
        try:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except OSError:
            counts["path_collisions"] += 1
            return
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        written.append(len(payload))

    _read_blobs(prefix, environment, wanted, deadline, write)
    gaps = []
    messages = {
        "submodules": "submodule commit(s) were not followed",
        "symlinks": "symlink(s) were not materialized",
        "unsafe_paths": "unsafe committed path(s) were not written",
        "path_collisions": "path(s) collide on this filesystem and were not written",
        "credential_files": "credential-named file(s) were not copied",
        "oversize_blobs": f"blob(s) over {MAX_SOURCE_FILE_BYTES} bytes were not extracted",
        "byte_limit_blobs": "blob(s) exceeded the backfill byte limit and were not extracted",
        "file_limit_blobs": "blob(s) exceeded the backfill file limit and were not extracted",
    }
    for key, text in messages.items():
        if counts[key]:
            gaps.append(f"Git backfill: {counts[key]} {text}")
    return {
        "paths": selected,
        "coverage": {
            "tree": commit["tree"],
            "tree_entries": len(selected) + counts["submodules"] + counts["unsafe_paths"],
            "extracted_files": len(written),
            "extracted_bytes": sum(written),
            "omitted": counts,
            "limits": {
                "max_files": MAX_FILES,
                "max_blob_bytes": MAX_SOURCE_FILE_BYTES,
                "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
                "max_listing_bytes": MAX_GIT_OUTPUT_BYTES,
                "seconds": EXTRACTION_SECONDS,
            },
        },
        "gaps": gaps,
    }


def snapshot_directory(state_dir, project_id, revision):
    return Path(state_dir) / "git-snapshots" / project_id / revision


def replace_snapshot(state_dir, project_id, commit, root):
    """Extract into a fresh private directory, then move it into place."""
    final = snapshot_directory(state_dir, project_id, commit["revision"])
    parent = final.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.resolve().is_relative_to(Path(state_dir).resolve()):
        raise ValueError("Git snapshot directory must stay inside PAT state")
    staging = Path(tempfile.mkdtemp(prefix=".extract-", dir=parent))
    try:
        extraction = extract_commit(root, commit, staging / "tree")
        if final.exists() or final.is_symlink():
            if final.is_symlink():
                final.unlink()
            else:
                shutil.rmtree(final)
        os.replace(staging / "tree", final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return final, extraction
