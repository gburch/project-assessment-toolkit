#!/usr/bin/env python3
"""Collect bounded, read-only evidence about documentation value.

The report is deliberately advisory. It identifies navigation and maintenance
leads; it does not decide whether a document is redundant or safe to delete.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .markdown import AUTOLINK_RE as AUTOLINK_RE
from .markdown import INLINE_LINK_RE as INLINE_LINK_RE
from .markdown import REFERENCE_LINK_RE as REFERENCE_LINK_RE
from .markdown import (
    UNSUPPORTED_LINK_RE,
    headings,
    local_links,
    without_fences,
    words,
)
from .sections import analyze_sections

SCHEMA = "doc-value-audit.v1"
TEXT_EXTENSIONS = {".md", ".mdx", ".rst", ".adoc", ".txt", ".yaml", ".yml", ".json"}
EXTENSIONLESS_DOC_NAMES = {"README", "LICENSE", "NOTICE", "COPYING"}
SKIP_PARTS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".ruff_cache",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    "coverage",
    "htmlcov",
    "vendor",
}
MAX_READ_BYTES = 2_000_000
MAX_BINARY_HASH_BYTES = 256_000_000
MAX_DELTA_PATHS = 4_000
MAX_GIT_OUTPUT_BYTES = 4_000_000
MAX_CALLER_FILES = 500
MAX_CALLER_BYTES = 1_000_000
DOC_DIR_NAMES = {
    "doc",
    "docs",
    "documentation",
    "guide",
    "guides",
    "handbook",
    "runbook",
    "runbooks",
    "spec",
    "specs",
    "proposal",
    "proposals",
    "handoff",
    "handoffs",
    "evidence",
    "artifact",
    "artifacts",
    "record",
    "records",
    "report",
    "reports",
    "design",
    "designs",
    ".agents",
    ".codex",
    ".github",
}
ARTIFACT_DIR_NAMES = (DOC_DIR_NAMES - {".agents", ".codex", ".github"}) | {
    "asset",
    "assets",
    "image",
    "images",
    "media",
    "attachment",
    "attachments",
    "fixture",
    "fixtures",
}
CALLER_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".h",
    ".java",
    ".js",
    ".jsx",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
    ".zsh",
}
CONFIG_EXTENSIONS = {".json", ".toml", ".yaml", ".yml", ".ini", ".cfg"}
SENSITIVE_PATH_PARTS = {
    ".aws",
    ".gnupg",
    ".keys",
    ".secrets",
    "credentials",
    "passwords",
    "private",
    "secrets",
    "tokens",
}


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_sha256(path: Path, limit: int = MAX_BINARY_HASH_BYTES) -> tuple[str | None, bool]:
    """Hash a file without loading large artifacts into memory."""
    digest = hashlib.sha256()
    read = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                read += len(chunk)
                if read > limit:
                    return None, True
                digest.update(chunk)
    except OSError:
        return None, False
    return "sha256:" + digest.hexdigest(), False


def _git_configuration(root: Path) -> tuple[list[str], dict[str, str]]:
    """Return a non-invasive Git command prefix and minimal environment.

    Assessments must not activate repository hooks, clean filters, fsmonitor,
    system/global configuration, or lazy fetching.  In particular, this tool
    deliberately does not run ``status`` or ``diff``: those commands can ask
    repository extensions to execute arbitrary assessed-project code.
    """
    # Reuse the collector's non-executing Git configuration at this boundary.
    from ..collector import _git_configuration as collector_git_configuration

    return collector_git_configuration(root)


def git(root: Path, *args: str) -> tuple[str, int]:
    prefix, environment = _git_configuration(root)
    try:
        p = subprocess.run(
            [*prefix, *args],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
            timeout=5,
        )
        if len(p.stdout.encode("utf-8")) > MAX_GIT_OUTPUT_BYTES:
            return "", 125
        return p.stdout, p.returncode
    except (OSError, subprocess.TimeoutExpired):
        return "", 127


def git_bytes(root: Path, *args: str) -> tuple[bytes, int]:
    prefix, environment = _git_configuration(root)
    try:
        process = subprocess.run(
            [*prefix, *args],
            capture_output=True,
            check=False,
            env=environment,
            timeout=5,
        )
        if len(process.stdout) > MAX_GIT_OUTPUT_BYTES:
            return b"", 125
        return process.stdout, process.returncode
    except (OSError, subprocess.TimeoutExpired):
        return b"", 127


def git_identity(root: Path) -> dict[str, Any]:
    head, rc = git(root, "rev-parse", "HEAD")
    return {
        "isRepository": rc == 0,
        "head": head.strip() if rc == 0 else None,
        # Deliberately unknown: status/diff are unsafe in an assessed repo.
        "trackedDirty": None,
        "statusRead": False,
        "dirtyStatus": "unknown",
        "metadataOnly": True,
    }


def under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def skip(path: Path, root: Path) -> bool:
    return any(part in SKIP_PARTS for part in path.relative_to(root).parts)


def safe_path(path: Path, root: Path) -> Path | None:
    """Resolve symlinks before any file read and reject escapes."""
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        return None
    return resolved if under_root(resolved, root) else None


def doc_bearing_directory(path: Path, root: Path) -> bool:
    return any(part.lower() in DOC_DIR_NAMES for part in path.relative_to(root).parts[:-1])


def artifact_directory(path: Path, root: Path) -> bool:
    return any(part.lower() in ARTIFACT_DIR_NAMES for part in path.relative_to(root).parts[:-1])


def excluded(path: Path, root: Path, patterns: list[str]) -> bool:
    if not patterns:
        return False
    rel = path.relative_to(root).as_posix()
    return any(
        fnmatch.fnmatch(rel, pattern)
        or any(fnmatch.fnmatch(part, pattern) for part in path.relative_to(root).parts)
        for pattern in patterns
    )


def selected_path(path: Path, root: Path, selectors: list[str]) -> bool:
    if not selectors:
        return True
    resolved = path.resolve(strict=False)
    for selector in selectors:
        selected = safe_path(root / selector, root)
        if selected and (resolved == selected or under_root(resolved, selected)):
            return True
    return False


def is_candidate(path: Path, root: Path, *, allow_structured: bool = False) -> bool:
    resolved = safe_path(path, root)
    if resolved is None or not resolved.is_file() or skip(resolved, root):
        return False
    suffix = resolved.suffix.lower()
    if suffix not in TEXT_EXTENSIONS and resolved.name.upper() not in EXTENSIONLESS_DOC_NAMES:
        return False
    # Structured files are documentation candidates only in a generic
    # documentation-bearing directory or an explicitly selected artifact tree.
    return not (
        suffix in {".json", ".yaml", ".yml"}
        and not (allow_structured or doc_bearing_directory(resolved, root))
    )


def filesystem_paths(
    scan_root: Path,
    *,
    root: Path | None = None,
    allow_structured: bool = False,
    exclude: list[str] | None = None,
) -> Iterable[Path]:
    workspace_root = root or scan_root
    for directory, subdirs, files in os.walk(scan_root, followlinks=False):
        directory_path = Path(directory)
        subdirs[:] = [name for name in subdirs if name not in SKIP_PARTS]
        for name in files:
            path = directory_path / name
            if excluded(path, workspace_root, exclude or []):
                continue
            if is_candidate(path, workspace_root, allow_structured=allow_structured):
                resolved = safe_path(path, workspace_root)
                if resolved:
                    yield resolved


def tracked_paths(
    root: Path, explicit: list[str], exclude: list[str]
) -> tuple[list[Path], list[str], str]:
    gaps: list[str] = []
    paths: list[Path] = []
    if explicit:
        for item in explicit:
            lexical = root / item
            if excluded(lexical, root, exclude):
                continue
            p = safe_path(lexical, root)
            if p is None:
                if lexical.exists() or lexical.is_symlink():
                    gaps.append(f"symlink-escape-or-unresolvable:{item}")
            elif p.is_file() and is_candidate(p, root, allow_structured=True):
                paths.append(p)
            elif p.is_dir():
                paths.extend(filesystem_paths(p, root=root, allow_structured=True, exclude=exclude))
            else:
                gaps.append(f"path-not-found-or-outside-root:{item}")
        return sorted(set(paths)), gaps, "explicit"
    listing, rc = git(root, "ls-files", "-z")
    if rc == 0:
        for name in listing.split("\0"):
            if not name:
                continue
            lexical = root / name
            if excluded(lexical, root, exclude):
                continue
            p = safe_path(lexical, root)
            if p is None:
                if lexical.exists() or lexical.is_symlink():
                    gaps.append(f"symlink-escape-or-unresolvable:{name}")
            elif p.exists() and is_candidate(p, root) and not excluded(p, root, exclude):
                paths.append(p)
        return sorted(set(paths)), gaps, "git-tracked"
    gaps.append("git-inventory-unavailable; use --path for an explicit filesystem inventory")
    paths.extend(filesystem_paths(root, exclude=exclude))
    return sorted(set(paths)), gaps, "filesystem-fallback"


def artifact_paths(
    root: Path, explicit: list[str], exclude: list[str], mode: str
) -> tuple[list[Path], list[str]]:
    """Find bounded artifact/config paths without parsing their contents."""
    paths: list[Path] = []
    gaps: list[str] = []

    def consider(lexical: Path, *, explicit_selection: bool = False) -> None:
        if excluded(lexical, root, exclude):
            return
        path = safe_path(lexical, root)
        if path is None:
            if lexical.exists() or lexical.is_symlink():
                gaps.append(f"symlink-escape-or-unresolvable:{lexical.relative_to(root)}")
            return
        if not path.is_file() or (skip(path, root) and not artifact_directory(path, root)):
            return
        if (
            explicit_selection
            or artifact_directory(path, root)
            or path.suffix.lower() in CONFIG_EXTENSIONS
        ):
            paths.append(path)

    if explicit:
        for item in explicit:
            lexical = root / item
            path = safe_path(lexical, root)
            if path is None:
                if lexical.exists() or lexical.is_symlink():
                    gaps.append(f"symlink-escape-or-unresolvable:{item}")
            elif path.is_file():
                consider(path, explicit_selection=True)
            elif path.is_dir():
                for directory, subdirs, files in os.walk(path, followlinks=False):
                    subdirs[:] = [name for name in subdirs if name not in SKIP_PARTS]
                    for name in files:
                        consider(Path(directory) / name, explicit_selection=True)
        return sorted(set(paths)), gaps

    if mode == "git-tracked":
        listing, rc = git(root, "ls-files", "-z")
        if rc == 0:
            for name in listing.split("\0"):
                if name:
                    consider(root / name)
            return sorted(set(paths)), gaps
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = [name for name in subdirs if name not in SKIP_PARTS]
        for name in files:
            consider(Path(directory) / name)
    return sorted(set(paths)), gaps


def artifact_record(path: Path, root: Path) -> dict[str, Any] | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    digest, truncated = file_sha256(path)
    suffix = path.suffix.lower()
    role_name = (
        "config"
        if suffix in CONFIG_EXTENSIONS and not artifact_directory(path, root)
        else "artifact"
    )
    if any(
        part.lower() in {"evidence", "receipt", "receipts", "benchmark", "benchmarks", "proof"}
        for part in path.relative_to(root).parts[:-1]
    ):
        role_name = "raw_evidence"
    if path.name.upper() in {"LICENSE", "NOTICE", "COPYING"}:
        role_name = "required_record"
    record: dict[str, Any] = {
        "path": path.relative_to(root).as_posix(),
        "extension": suffix,
        "bytes": size,
        "sha256": digest,
        "role": role_name,
        "words": None,
        "tokensApprox": None,
        "parse": "omitted-binary-or-config",
    }
    if truncated:
        record["hashStatus"] = f"omitted-over-{MAX_BINARY_HASH_BYTES}-bytes"
    elif digest is None:
        record["hashStatus"] = "unreadable"
    return record


def caller_files(
    root: Path, selectors: list[str], exclude: list[str]
) -> tuple[list[Path], list[str]]:
    paths: list[Path] = []
    gaps: list[str] = []
    blocked_names = ("secret", "credential", "password", "passwd", "token", "private", "apikey")

    def add(path: Path) -> None:
        if (
            excluded(path, root, exclude)
            or not path.is_file()
            or path.suffix.lower() not in CALLER_EXTENSIONS
        ):
            return
        rel_parts = path.relative_to(root).parts
        if any(part.startswith(".") for part in rel_parts) or any(
            word in path.name.lower() for word in blocked_names
        ):
            return
        resolved = safe_path(path, root)
        if resolved:
            paths.append(resolved)

    for selector in selectors:
        lexical = root / selector
        path = safe_path(lexical, root)
        if path is None:
            gaps.append(f"caller-path-unavailable:{selector}")
        elif path.is_file():
            add(path)
        elif path.is_dir():
            for directory, subdirs, files in os.walk(path, followlinks=False):
                subdirs[:] = [name for name in subdirs if name not in SKIP_PARTS]
                for name in files:
                    add(Path(directory) / name)
    if len(paths) > MAX_CALLER_FILES:
        gaps.append(f"caller-file-limit:{len(paths)}>{MAX_CALLER_FILES}")
        paths = paths[:MAX_CALLER_FILES]
    return sorted(set(paths)), gaps


def caller_references(
    root: Path, selectors: list[str], exclude: list[str], targets: set[str]
) -> tuple[dict[str, dict[str, list[str]]], list[str]]:
    paths, gaps = caller_files(root, selectors, exclude)
    exact_refs: dict[str, list[str]] = defaultdict(list)
    basename_refs: dict[str, list[str]] = defaultdict(list)
    for path in paths:
        try:
            if path.stat().st_size > MAX_CALLER_BYTES:
                gaps.append(f"caller-size-limit:{path.relative_to(root)}")
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            gaps.append(f"caller-unreadable:{path.relative_to(root)}")
            continue
        rel = path.relative_to(root).as_posix()
        for target in targets:
            if target in text:
                exact_refs[target].append(rel)
            elif Path(target).name in text:
                basename_refs[target].append(rel)
    refs: dict[str, dict[str, list[str]]] = {}
    for target in targets:
        exact = exact_refs.get(target, [])[:50]
        basename = basename_refs.get(target, [])[:50]
        if exact or basename:
            refs[target] = {"exactPath": exact, "basenameLead": basename}
    return refs, gaps


def role(path: Path, text: str, root: Path) -> tuple[str, list[str]]:
    rel = path.relative_to(root).as_posix().lower()
    name = path.name.lower()
    hints: list[str] = []
    if path.suffix in {".json", ".yaml", ".yml"} and not doc_bearing_directory(path, root):
        # This branch is only reached for explicitly selected config files;
        # they remain visible in the receipt without inflating doc counts.
        return "config", ["structured file outside a documentation-bearing directory"]
    if any(x in rel for x in ("evidence", "receipt", "artifact", "snapshot", "proof")):
        hints.append("path-or-format resembles evidence/artifact")
        return "raw_evidence", hints
    if any(x in rel for x in ("generated", "build/", "dist/", "coverage", "cache/")):
        hints.append("path resembles generated output")
        return "generated", hints
    if any(
        x in rel for x in ("handoff", "archive", "history", "changelog", "report", "audit", "plan")
    ):
        hints.append("path resembles historical or review record")
        return "history", hints
    if any(x in name for x in ("license", "security", "privacy", "contract", "policy")):
        hints.append("name resembles required policy/record")
        return "required_record", hints
    if name in {"agents.md", "readme.md", "skill.md"} or any(
        x in rel for x in ("guide", "runbook", "architecture", "development", ".agents/skills/")
    ):
        hints.append("name/path resembles navigational guidance")
        return "guidance", hints
    if re.search(r"(?im)^#{1,3}\s+(?:how|usage|run|install|development|commands?)\b", text):
        hints.append("headings resemble operational guidance")
        return "guidance", hints
    return "unknown", hints


def resolve_link(source: Path, target: str, root: Path) -> tuple[Path | None, str | None]:
    parsed = urlsplit(unquote(target))
    if parsed.scheme or parsed.netloc:
        return None, "external"
    fragment = parsed.fragment or None
    raw = parsed.path
    path = (source.parent / raw).resolve() if raw else source.resolve()
    if not under_root(path, root):
        return None, "outside-root"
    if not path.exists():
        return path, "missing-target"
    if fragment and (
        path.suffix.lower() in {".md", ".mdx", ".rst", ".adoc"}
        or path.name.upper() in EXTENSIONLESS_DOC_NAMES
    ):
        try:
            if path.stat().st_size > MAX_READ_BYTES:
                return path, "anchor-unreadable-size"
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return path, "anchor-unreadable"
        anchors, unsupported = headings(text)
        if fragment.lower() not in anchors:
            if unsupported:
                return path, "uncertain-anchor"
            return path, "missing-anchor"
    return path, None


def bounded_near_duplicates(
    records: list[dict[str, Any]], max_pairs: int
) -> tuple[list[dict[str, Any]], int, bool, int]:
    pairs = 0
    truncated = False
    result: list[dict[str, Any]] = []
    token_sets = [set(record["normalized"][:12000].split()) for record in records]
    prefix_truncated = sum(len(record["normalized"]) > 12000 for record in records)
    for i, left in enumerate(records):
        if pairs >= max_pairs:
            break
        if left.get("bytes", 0) > 500_000:
            continue
        for j, right in enumerate(records[i + 1 :], i + 1):
            if pairs >= max_pairs:
                truncated = True
                break
            if left.get("extension") != right.get("extension"):
                continue
            size = max(left["bytes"], right["bytes"], 1)
            if min(left["bytes"], right["bytes"]) / size < 0.65:
                continue
            pairs += 1
            left_tokens = token_sets[i]
            right_tokens = token_sets[j]
            union = left_tokens | right_tokens
            ratio = len(left_tokens & right_tokens) / len(union) if union else 1.0
            if ratio >= 0.82 and left["sha256"] != right["sha256"]:
                result.append(
                    {
                        "left": left["path"],
                        "right": right["path"],
                        "similarity": round(ratio, 3),
                        "basis": "bounded normalized token-set Jaccard",
                    }
                )
    return result, pairs, truncated, prefix_truncated


def sensitive_path(path: Path, root: Path) -> bool:
    parts = [part.lower() for part in path.relative_to(root).parts]
    return any(
        part in SENSITIVE_PATH_PARTS
        or any(token in part for token in ("credential", "password", "secret", "token"))
        for part in parts
    )


def delta_shape(path: Path, root: Path) -> bool:
    """Whether a path can contribute to the bounded documentation delta."""
    if skip(path, root) or sensitive_path(path, root):
        return False
    suffix = path.suffix.lower()
    return (
        suffix in TEXT_EXTENSIONS
        or path.name.upper() in EXTENSIONLESS_DOC_NAMES
        or suffix in CONFIG_EXTENSIONS
        or artifact_directory(path, root)
    )


def delta_paths(
    root: Path,
    selectors: list[str],
    exclude: list[str],
) -> tuple[set[str], bool, list[str], set[str]]:
    """Bound current filesystem enumeration to selected doc-value candidates."""
    scan_roots: list[Path] = []
    gaps: list[str] = []
    unavailable: set[str] = set()
    if selectors:
        for selector in selectors:
            selected = safe_path(root / selector, root)
            if selected is None:
                gaps.append(f"delta-selector-unavailable:{selector}")
            elif selected.is_dir() or selected.is_file():
                scan_roots.append(selected)
    else:
        scan_roots = [root]
    found: set[str] = set()
    complete = True
    for scan_root in sorted(set(scan_roots)):
        if scan_root.is_file():
            candidates = [scan_root]
            subdir_iter: Iterable[tuple[str, list[str], list[str]]] = []
        else:
            candidates = []
            subdir_iter = os.walk(scan_root, followlinks=False)
        for directory, subdirs, files in subdir_iter:
            directory_path = Path(directory)
            subdirs[:] = [
                name
                for name in subdirs
                if name not in SKIP_PARTS
                and name.lower() not in SENSITIVE_PATH_PARTS
                and not any(token in name.lower() for token in ("credential", "secret", "token"))
            ]
            candidates.extend(directory_path / name for name in files)
            for lexical in candidates:
                path = safe_path(lexical, root)
                if path is None:
                    if lexical.exists() or lexical.is_symlink():
                        rel = lexical.relative_to(root).as_posix()
                        gaps.append(f"delta-path-unavailable:{rel}")
                        unavailable.add(rel)
                    continue
                rel = path.relative_to(root).as_posix()
                if (
                    rel in found
                    or excluded(path, root, exclude)
                    or not selected_path(path, root, selectors)
                    or not path.is_file()
                    or not delta_shape(path, root)
                ):
                    continue
                found.add(rel)
                if len(found) >= MAX_DELTA_PATHS:
                    complete = False
                    gaps.append(f"delta-current-path-limit:{MAX_DELTA_PATHS}")
                    return found, complete, sorted(set(gaps)), unavailable
            candidates = []
        if scan_root.is_file():
            for lexical in candidates:
                path = safe_path(lexical, root)
                if path and path.is_file() and delta_shape(path, root):
                    rel = path.relative_to(root).as_posix()
                    if not excluded(path, root, exclude) and selected_path(path, root, selectors):
                        found.add(rel)
    return found, complete, sorted(set(gaps)), unavailable


def diff_delta(
    root: Path,
    base: str,
    current: set[str],
    exclude: list[str],
    selectors: list[str],
) -> dict[str, Any]:
    resolved, resolved_rc = git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
    if resolved_rc != 0:
        return {"base": base, "available": False, "gap": "git-base-unavailable"}

    # Do not use ``git status`` or ``git diff`` here.  Both may invoke a
    # repository clean filter or fsmonitor.  Compare immutable baseline blobs
    # with bounded raw filesystem bytes instead.  A rename is intentionally
    # represented as D+A because this comparison has no rename heuristic.
    base_listing, base_rc = git(root, "ls-tree", "-r", "-z", "--name-only", resolved.strip())
    if base_rc != 0:
        return {"base": base, "available": False, "gap": "git-tree-failed"}
    raw_base_paths = {name for name in base_listing.split("\0") if name}
    base_paths = {
        name
        for name in raw_base_paths
        if delta_shape(root / name, root)
        and not excluded(root / name, root, exclude)
        and selected_path(root / name, root, selectors)
    }
    gaps: list[str] = []
    if len(base_paths) > MAX_DELTA_PATHS:
        gaps.append(f"delta-base-path-limit:{MAX_DELTA_PATHS}")
        base_paths = set(sorted(base_paths)[:MAX_DELTA_PATHS])
        base_complete = False
    else:
        base_complete = True
    index_listing, index_rc = git(root, "ls-files", "-z", "--cached")
    indexed_paths = {name for name in index_listing.split("\0") if name} if index_rc == 0 else set()
    current_paths, current_complete, current_gaps, unavailable = delta_paths(
        root, selectors, exclude
    )
    gaps.extend(current_gaps)
    candidate_paths = sorted(base_paths | current_paths)
    changed: list[dict[str, Any]] = []
    for path in candidate_paths:
        if path in unavailable:
            continue
        lexical = root / path
        if excluded(lexical, root, exclude) or not selected_path(lexical, root, selectors):
            continue
        in_base = path in base_paths
        in_current = path in current_paths
        if in_base and not in_current and current_complete:
            row: dict[str, Any] = {"status": "D", "path": path}
        elif in_current and not in_base and base_complete:
            row = {"status": "A", "path": path}
            if index_rc == 0:
                row["untracked"] = path not in indexed_paths
            else:
                row["untrackedStatus"] = "unknown"
        elif in_base and in_current:
            before = baseline_payload(root, resolved.strip(), path)
            current_path = safe_path(root / path, root)
            current_sha: str | None = None
            current_hash_limited = False
            if current_path and current_path.is_file():
                current_sha, current_hash_limited = file_sha256(current_path)
            if before.get("sha256") is None or current_sha is None:
                changed_content = before.get("bytes") != (
                    current_path.stat().st_size if current_path and current_path.exists() else None
                )
                if not changed_content:
                    # Equal sizes with an unavailable digest are not proof of
                    # equality.  Keep the row and make the uncertainty visible.
                    changed_content = True
            else:
                changed_content = before.get("sha256") != current_sha
            if not changed_content:
                continue
            row = {"status": "M", "path": path}
            if before.get("sha256") is None or current_hash_limited:
                row["comparison"] = "size-or-hash-limited"
        else:
            continue
        if row["status"] in {"A", "M"} and path in current:
            row["documentation"] = True
        changed.append(row)
    deleted = [x["path"] for x in changed if x["status"] == "D"]
    return {
        "base": base,
        "baseResolved": resolved.strip() if resolved_rc == 0 else None,
        "available": resolved_rc == 0,
        "changed": changed,
        "deleted": deleted,
        "gaps": sorted(set(gaps)),
    }


def payload_stats(data: bytes, path: str, root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"present": True, "bytes": len(data), "sha256": sha256(data)}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        result.update({"kind": "binary", "words": None, "tokensApprox": None})
        return result
    candidate = root / path
    shape_is_text = (
        candidate.suffix.lower() in TEXT_EXTENSIONS
        and (
            candidate.suffix.lower() not in CONFIG_EXTENSIONS
            or doc_bearing_directory(candidate, root)
        )
        or candidate.name.upper() in EXTENSIONLESS_DOC_NAMES
    )
    if shape_is_text:
        result.update(
            {
                "kind": "text",
                "words": len(words(text)),
                "tokensApprox": max(1, round(len(text) / 4)),
            }
        )
    else:
        result.update({"kind": "config", "words": None, "tokensApprox": None})
    return result


def baseline_payload(root: Path, base: str, path: str) -> dict[str, Any]:
    object_name, rc = git(root, "rev-parse", f"{base}:{path}")
    if rc != 0 or not object_name.strip():
        return {"present": False}
    size_text, size_rc = git(root, "cat-file", "-s", object_name.strip())
    if size_rc != 0 or not size_text.strip().isdigit():
        return {"present": "unknown", "reason": "baseline-size-unavailable"}
    size = int(size_text.strip())
    if size > MAX_READ_BYTES:
        return {
            "present": True,
            "bytes": size,
            "sha256": None,
            "kind": "unknown",
            "reason": f"baseline-size-limit:{MAX_READ_BYTES}",
        }
    blob, blob_rc = git_bytes(root, "cat-file", "blob", object_name.strip())
    return (
        payload_stats(blob, path, root)
        if blob_rc == 0
        else {
            "present": "unknown",
            "bytes": size,
            "reason": "baseline-read-failed",
        }
    )


def untracked_paths(root: Path, selectors: list[str], exclude: list[str]) -> set[str]:
    """Find filesystem paths absent from the Git index without ``status``."""
    listing, rc = git(root, "ls-files", "-z", "--cached")
    if rc != 0:
        return set()
    tracked = {name for name in listing.split("\0") if name}
    found: set[str] = set()
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = [name for name in subdirs if name not in SKIP_PARTS]
        for name in files:
            path = safe_path(Path(directory) / name, root)
            if path is None:
                continue
            rel = path.relative_to(root).as_posix()
            if (
                rel in tracked
                or excluded(path, root, exclude)
                or not selected_path(path, root, selectors)
            ):
                continue
            found.add(rel)
    return found


def changed_document_rows(
    root: Path,
    delta: dict[str, Any],
    current_payloads: dict[str, dict[str, Any]],
    selectors: list[str],
    exclude: list[str],
) -> list[dict[str, Any]]:
    if not delta.get("available"):
        return []
    rows: list[dict[str, Any]] = []
    for change in delta.get("changed", []):
        path = change["path"]
        is_doc = (
            path.lower().endswith(tuple(TEXT_EXTENSIONS))
            or Path(path).name.upper() in EXTENSIONLESS_DOC_NAMES
            or any(part.lower() in ARTIFACT_DIR_NAMES for part in Path(path).parts[:-1])
        )
        if (
            not is_doc
            or excluded(root / path, root, exclude)
            or not selected_path(root / path, root, selectors)
        ):
            continue
        before_path = change.get("previousPath", path)
        before = baseline_payload(root, delta["base"], before_path)
        after = current_payloads.get(path)
        if after is None:
            current_path = safe_path(root / path, root)
            after = (
                {"present": "unknown", "reason": "outside-or-limited-current-inventory"}
                if current_path and current_path.exists()
                else {"present": False}
            )
        row: dict[str, Any] = {
            "status": change["status"],
            "path": path,
            "before": before,
            "after": after,
        }
        if "previousPath" in change:
            row["previousPath"] = change["previousPath"]
        if change.get("untracked"):
            row["untracked"] = True
        rows.append(row)
    return rows


def validate_output(root: Path, requested: Path) -> Path:
    """Validate destination before inventory or any write occurs."""
    if not root.exists() or not root.is_dir():
        raise ValueError(f"root does not exist or is not a directory: {root}")
    destination = requested.expanduser().resolve(strict=False)
    if destination.exists() and destination.is_dir():
        destination = (destination / "doc-value.json").resolve(strict=False)
    if under_root(destination, root):
        raise ValueError("--output must resolve outside --root")
    return destination


def summary_lines(report: dict[str, Any], top: int) -> list[str]:
    inventory = report["inventory"]
    lines = [
        "doc-value summary: "
        f"text={inventory['count']} files, artifacts={inventory['artifactCount']}, "
        f"configs={inventory['configCount']}, "
        f"words={inventory['words']}, links={len(report['links'])}, "
        f"exact-duplicate-groups={len(report['exactDuplicates'])}, gaps={len(report['gaps'])}"
    ]
    rows = []
    for record in inventory["files"]:
        issue_count = sum(
            1 for link in report["links"] if link["source"] == record["path"] and "issue" in link
        )
        rows.append((record["bytes"], issue_count, record))
    rows.extend((record["bytes"], 0, record) for record in inventory["binaryArtifacts"])

    def render(title: str, selected: list[tuple[int, int, dict[str, Any]]]) -> None:
        lines.append(title)
        for _, issue_count, record in selected[:top]:
            detail = f"{record['bytes']} bytes; words={record.get('words')}; role={record['role']}"
            if issue_count:
                detail += f"; link-issues={issue_count}"
            lines.append(f"- {record['path']} ({detail})")

    render("largest by bytes:", sorted(rows, key=lambda item: item[0], reverse=True))
    render(
        "largest by words:",
        sorted(rows, key=lambda item: item[2].get("words") or -1, reverse=True),
    )
    render("reference issue leads:", sorted(rows, key=lambda item: item[1], reverse=True))
    sections = report.get("sectionAnalysis", {})
    if sections.get("enabled"):
        lines.append("section leads (lexical only; human review required):")
        leads = list(sections.get("passageLeads", [])) + list(sections.get("containmentLeads", []))
        seen_leads: set[tuple[Any, ...]] = set()
        shown = 0
        for lead in leads:
            left = lead.get("left", lead.get("shorter", {}))
            right = lead.get("right", lead.get("longer", {}))
            signature = (
                lead.get("kind"),
                left.get("path"),
                tuple(left.get("headingPath", [])),
                right.get("path"),
                tuple(right.get("headingPath", [])),
            )
            if signature in seen_leads:
                continue
            seen_leads.add(signature)
            similarity = f" similarity={lead['similarity']}" if "similarity" in lead else ""
            lines.append(
                f"- {lead.get('kind', 'lead')}{similarity}: "
                f"{left.get('path')}:{left.get('lineStart')}-{left.get('lineEnd')} "
                f"vs {right.get('path')}:{right.get('lineStart')}-{right.get('lineEnd')}"
            )
            shown += 1
            if shown >= top:
                break
        if not leads:
            lines.append("- no bounded lexical section leads")
    return lines


def audit(args: argparse.Namespace) -> dict[str, Any]:
    root = args.root.resolve()
    paths, gaps, inventory_mode = tracked_paths(root, args.path, args.exclude)
    if args.base:
        for rel in untracked_paths(root, args.path, args.exclude):
            path = safe_path(root / rel, root)
            if (
                path
                and path.is_file()
                and is_candidate(path, root, allow_structured=bool(args.path))
            ):
                paths.append(path)
        paths = sorted(set(paths))
    text_limit_applied = False
    if args.max_files and len(paths) > args.max_files:
        gaps.append(f"file-limit:{len(paths)}>{args.max_files}")
        paths = paths[: args.max_files]
        text_limit_applied = True
    records: list[dict[str, Any]] = []
    texts: dict[str, str] = {}
    by_hash: dict[str, list[str]] = defaultdict(list)
    link_rows: list[dict[str, Any]] = []
    backlinks: Counter[str] = Counter()
    for path in paths:
        rel = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
            if size > MAX_READ_BYTES:
                gaps.append(f"size-limit:{rel}:{size}>{MAX_READ_BYTES}")
                continue
            data = path.read_bytes()
        except OSError as exc:
            gaps.append(f"unreadable:{rel}:{exc.__class__.__name__}")
            continue
        if len(data) > MAX_READ_BYTES:
            gaps.append(f"size-limit:{rel}:{len(data)}>{MAX_READ_BYTES}")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            gaps.append(f"non-utf8:{rel}")
            continue
        texts[rel] = text
        digest = sha256(data)
        inferred, hints = role(path, text, root)
        record: dict[str, Any] = {
            "path": rel,
            "extension": path.suffix.lower(),
            "bytes": len(data),
            "words": len(words(text)),
            "tokensApprox": max(1, round(len(text) / 4)),
            "sha256": digest,
            "role": inferred,
            "roleHints": hints,
            "normalized": " ".join(words(text)),
        }
        records.append(record)
        by_hash[digest].append(rel)
    artifact_paths_found, artifact_gaps = artifact_paths(
        root, args.path, args.exclude, inventory_mode
    )
    gaps.extend(artifact_gaps)
    artifact_records: list[dict[str, Any]] = []
    known = {record["path"] for record in records}
    for path in artifact_paths_found:
        rel = path.relative_to(root).as_posix()
        if rel in known:
            continue
        artifact_item = artifact_record(path, root)
        if artifact_item:
            artifact_records.append(artifact_item)
    known.update(record["path"] for record in artifact_records)
    # Working-tree additions are not returned by git ls-files; retain their
    # artifact identity in a base comparison without parsing binary content.
    if args.base:
        for rel in untracked_paths(root, args.path, args.exclude):
            path = safe_path(root / rel, root)
            if (
                path
                and path.is_file()
                and path.relative_to(root).as_posix() not in known
                and (artifact_directory(path, root) or path.suffix.lower() in CONFIG_EXTENSIONS)
            ):
                artifact_item = artifact_record(path, root)
                if artifact_item:
                    artifact_records.append(artifact_item)
                    known.add(artifact_item["path"])
    known_text = set(texts)
    for rel, text in texts.items():
        for target in local_links(text):
            target_path, issue = resolve_link(root / rel, target, root)
            row = {
                "source": rel,
                "target": target,
                "kind": "local" if issue != "external" else "external",
            }
            if target_path and under_root(target_path, root):
                row["candidateResolved"] = target_path.relative_to(root).as_posix()
            if issue:
                row["issue"] = issue
                if issue == "external":
                    gaps.append(f"unverified-external-link:{rel}:{target}")
                elif issue.startswith("uncertain-anchor") or issue.startswith("anchor-unreadable"):
                    gaps.append(f"uncertain-anchor:{rel}:{target}:{issue}")
            elif target_path:
                target_rel = target_path.relative_to(root).as_posix()
                row["resolved"] = target_rel
                backlinks[target_rel] += 1
            else:
                gaps.append(f"unmeasured-link:{rel}:{target}")
            link_rows.append(row)
        if UNSUPPORTED_LINK_RE.search(without_fences(text)):
            gaps.append(f"unsupported-markdown-link-markup:{rel}")
    # A small literal-reference pass finds inbound callers when a path is not
    # linked using Markdown syntax (for example a command or handoff mentions it).
    literal_refs: dict[str, list[str]] = {}
    for target in known_text:
        refs = [source for source, text in texts.items() if source != target and target in text]
        if refs:
            literal_refs[target] = refs[:50]
    for record in records:
        record.pop("normalized", None)
        record["backlinks"] = backlinks.get(record["path"], 0)
        record["literalReferences"] = len(literal_refs.get(record["path"], []))
    duplicates = [paths for paths in by_hash.values() if len(paths) > 1]
    near, compared_pairs, pair_budget_exhausted, prefix_truncated = bounded_near_duplicates(
        [{**r, "normalized": " ".join(words(texts[r["path"]]))} for r in records], args.max_pairs
    )
    section_report: dict[str, Any] = (
        analyze_sections(
            texts,
            max_pairs=args.section_max_pairs,
            window_words=args.section_window_words,
            window_step=args.section_window_step,
            exact_run_words=args.section_exact_run_words,
        )
        if args.sections
        else {"enabled": False}
    )
    if args.sections:
        gaps.extend(section_report.get("gaps", []))
        if section_report.get("windows", {}).get("truncated"):
            gaps.append("section-window-limit-reached")
        if section_report.get("progress", {}).get("pairBudgetExhausted"):
            gaps.append(f"section-pair-budget-exhausted:{args.section_max_pairs}")
    caller_refs: dict[str, dict[str, list[str]]] = {}
    if args.callers:
        caller_refs, caller_gaps = caller_references(root, args.callers, args.exclude, known_text)
        gaps.extend(caller_gaps)
    else:
        gaps.append("literal-reference-scan-inventory-only; source/code callers are not scanned")
    if pair_budget_exhausted:
        gaps.append(f"similarity-pair-budget-exhausted:{args.max_pairs}")
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "generatedAt": datetime.now(UTC).isoformat(),
        "root": str(root),
        "identity": git_identity(root),
        "inputs": {
            "paths": args.path,
            "excludes": args.exclude,
            "callers": args.callers,
            "selectionHash": sha256(
                json.dumps(
                    {"paths": args.path, "excludes": args.exclude, "callers": args.callers},
                    sort_keys=True,
                ).encode()
            ),
        },
        "policy": {
            "readOnly": True,
            "inventoryScope": (
                "text documentation plus path-selected artifacts and configs; "
                "artifact content is not parsed"
            ),
            "textMetrics": "words and token estimates apply only to decoded documentation text",
            "wordCount": "regex word-like tokens",
            "tokensApprox": "UTF-8 characters / 4; planning estimate only",
            "similarity": "token-set Jaccard over first 12000 normalized characters; lead only",
            "maxReadBytes": MAX_READ_BYTES,
            "maxBinaryHashBytes": MAX_BINARY_HASH_BYTES,
            "maxFiles": "parsed text inventory cap; artifact/config metadata is separate",
            "callerScope": (
                "optional selected source extensions; hidden/secret-looking paths are skipped; "
                "exact and basename matches are separate leads"
            ),
            "maxPairs": args.max_pairs,
        },
        "inventory": {
            "mode": inventory_mode,
            "files": records,
            "binaryArtifacts": artifact_records,
            "textLimit": {"maxFiles": args.max_files, "applied": text_limit_applied},
            "count": len(records),
            "byKind": {
                "text": len(records),
                "binaryArtifacts": sum(
                    r["role"] in {"artifact", "raw_evidence"} for r in artifact_records
                ),
                "config": sum(r["role"] == "config" for r in artifact_records),
                "requiredRecords": sum(
                    r["role"] == "required_record" for r in records + artifact_records
                ),
            },
            "artifactCount": sum(
                r["role"] in {"artifact", "raw_evidence"} for r in artifact_records
            ),
            "configCount": sum(r["role"] == "config" for r in artifact_records),
            "words": sum(x["words"] for x in records),
            "textBytes": sum(x["bytes"] for x in records),
            "artifactBytes": sum(
                x["bytes"] for x in artifact_records if x["role"] in {"artifact", "raw_evidence"}
            ),
            "totalBytes": sum(x["bytes"] for x in records + artifact_records),
            "tokensApprox": sum(x["tokensApprox"] for x in records),
        },
        "exactDuplicates": duplicates,
        "nearDuplicates": near,
        "similarityEvidence": {
            "comparedPairs": compared_pairs,
            "maxPairs": args.max_pairs,
            "pairBudgetExhausted": pair_budget_exhausted,
            "prefixCharacters": 12000,
            "prefixTruncatedFiles": prefix_truncated,
        },
        "links": link_rows,
        "literalReferences": literal_refs,
        "callerReferences": caller_refs,
        "sectionAnalysis": section_report,
        "gaps": gaps,
    }
    if args.base:
        report["delta"] = diff_delta(root, args.base, known, args.exclude, args.path)
        report["gaps"].extend(report["delta"].get("gaps", []))
        if report["delta"].get("available"):
            current_payloads: dict[str, dict[str, Any]] = {}
            for record in records:
                current_payloads[record["path"]] = {
                    key: record.get(key)
                    for key in (
                        "present",
                        "bytes",
                        "sha256",
                        "words",
                        "tokensApprox",
                        "role",
                        "parse",
                    )
                    if key in record
                }
                current_payloads[record["path"]]["present"] = True
                current_payloads[record["path"]]["kind"] = "text"
            for artifact_item in artifact_records:
                current_payloads[artifact_item["path"]] = {
                    key: artifact_item.get(key)
                    for key in (
                        "present",
                        "bytes",
                        "sha256",
                        "words",
                        "tokensApprox",
                        "role",
                        "parse",
                    )
                    if key in artifact_item
                }
                current_payloads[artifact_item["path"]]["present"] = True
                current_payloads[artifact_item["path"]]["kind"] = (
                    "config" if artifact_item.get("role") == "config" else "binary"
                )
            report["delta"]["changedDocuments"] = changed_document_rows(
                root, report["delta"], current_payloads, args.path, args.exclude
            )
            deleted = report["delta"].get("deleted", [])
            if args.callers and deleted:
                deleted_refs, deleted_caller_gaps = caller_references(
                    root, args.callers, args.exclude, known_text | set(deleted)
                )
                report["callerReferences"].update(deleted_refs)
                report["gaps"].extend(deleted_caller_gaps)
            report["delta"]["deletedInboundReferences"] = {
                p: {
                    "exactPathMentions": [s for s, text in texts.items() if p in text and s != p][
                        :50
                    ],
                    "markdownCandidates": [
                        row["source"] for row in link_rows if row.get("candidateResolved") == p
                    ][:50],
                    "basenameMentions": [
                        s for s, text in texts.items() if Path(p).name in text and s != p
                    ][:50],
                    "scope": (
                        "document references are inventory-only; optional bounded caller scan "
                        "is reported separately"
                    ),
                }
                for p in deleted
            }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", nargs="?", default="audit", choices=["audit"])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--path", action="append", default=[], help="explicit file or directory; repeatable"
    )
    parser.add_argument(
        "--exclude", action="append", default=[], help="path glob to omit; repeatable"
    )
    parser.add_argument(
        "--callers", action="append", default=[], help="bounded source/code caller path; repeatable"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="JSON receipt path outside the repository"
    )
    parser.add_argument("--base", help="git base/ref for a working-tree documentation delta")
    parser.add_argument(
        "--max-files",
        type=int,
        default=2000,
        help="cap parsed text files; artifact/config metadata remains separate",
    )
    parser.add_argument("--max-pairs", type=int, default=5000)
    parser.add_argument(
        "--sections", action="store_true", help="index heading sections and lexical passage leads"
    )
    parser.add_argument(
        "--section-max-pairs", type=int, default=2000, help="section comparison pair budget"
    )
    parser.add_argument(
        "--section-window-words", type=int, default=160, help="section passage window size"
    )
    parser.add_argument(
        "--section-window-step", type=int, default=80, help="section passage window step"
    )
    parser.add_argument(
        "--section-exact-run-words",
        type=int,
        default=20,
        help="minimum exact shared token run to report",
    )
    parser.add_argument("--summary", action="store_true", help="print concise review leads")
    parser.add_argument("--top", type=int, default=10, help="number of summary leads")
    args = parser.parse_args(argv)
    if (
        args.max_files < 1
        or args.max_pairs < 0
        or args.top < 0
        or args.section_max_pairs < 0
        or args.section_window_words < 1
        or args.section_window_step < 1
        or args.section_exact_run_words < 1
    ):
        parser.error(
            "--max-files must be positive; pair budgets non-negative; top, window size, "
            "window step, and exact-run length must be positive"
        )
    try:
        root = args.root.expanduser().resolve(strict=False)
        output = validate_output(root, args.output)
    except ValueError as exc:
        parser.error(str(exc))
    args.root = root
    report = audit(args)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    inv = report["inventory"]
    if args.summary:
        for line in summary_lines(report, args.top):
            print(line)
    else:
        print(
            f"doc-value: {inv['count']} files, {inv['words']} words, {len(report['links'])} links, "
            f"{len(report['exactDuplicates'])} exact duplicate groups, "
            f"{len(report['nearDuplicates'])} near-duplicate leads"
        )
    if report["gaps"]:
        print(f"doc-value: {len(report['gaps'])} evidence gap(s); see {output}")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
