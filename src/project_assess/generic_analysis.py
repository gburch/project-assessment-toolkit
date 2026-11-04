"""Language-neutral source inventory and exact-text reuse leads from captured bytes.

This is deliberately not a lexer, parser, type checker or reachability analyzer.
Native syntax analyzers and supplied reports can add richer evidence separately.
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter, defaultdict, deque
from pathlib import PurePosixPath

from .static_analysis import _retained_candidates, candidate_coverage, source_role

VERSION = "3"
MAX_CANDIDATES = 100
MAX_INDEX = 20_000
BLOCK_LINES = 12
BLOCK_STRIDE = 1
MIN_BLOCK_CHARACTERS = 200
MAX_LOCATIONS = 20
MAX_COVERAGE_AREAS = 256
_ROLE_ORDER = {"production": 0, "unknown": 1, "test": 2, "tooling": 3}
_LANGUAGES = {
    ".py": "python",
    ".pyi": "python-stub",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".swift": "swift",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c-family",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".m": "objective-c",
    ".mm": "objective-cpp",
    ".scala": "scala",
    ".sc": "scala",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".lua": "lua",
    ".pl": "perl",
    ".r": "r",
    ".vue": "vue",
    ".svelte": "svelte",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
}
_CAVEAT = (
    "Exact-text reuse leads, not semantic equivalence, complexity, reachability or scores. "
    "Shared scaffolding, licenses, generated content and deliberate boundary duplication may match. "
    "Inspect callers and requirements before merging code. Syntax/type support is reported separately."
)


def source_language(path: str) -> str | None:
    return _LANGUAGES.get(PurePosixPath(path).suffix.lower())


def source_area(path: str) -> str:
    """Use one stable path heuristic for navigation and bounded sampling."""
    directories = PurePosixPath(path).parts[:-1]
    start = next((i + 1 for i, part in enumerate(directories) if part in {"src", "lib"}), 0)
    return "/".join(directories[: start + min(2, len(directories) - start)]) or "(root)"


def source_text_facts(path: str, text: str) -> dict:
    lines = text.splitlines()
    return {
        "language": source_language(path),
        "lines": len(lines),
        "nonblank_lines": sum(bool(line.strip()) for line in lines),
        "bytes": len(text.encode()),
        "syntax_analysis": "not_available",
        **source_role(path),
    }


def _fingerprint(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _merged_blocks(groups, file_hashes):
    """Combine overlapping identical windows so one copied region is one lead."""
    rows = []
    for digest, locations in groups.items():
        if len(locations) < 2:
            continue
        paths = {row["path"] for row in locations}
        if len(paths) > 1 and len({file_hashes[path] for path in paths}) == 1:
            continue  # Whole-file equality already describes this copied region.
        ordered = sorted(locations, key=lambda row: (row["path"], row["line"]))
        rows.append((tuple(row["path"] for row in ordered), digest, ordered))
    merged, previous = [], {}
    for paths, digest, locations in sorted(
        rows, key=lambda row: (row[0], tuple(loc["line"] for loc in row[2]))
    ):
        prior = previous.get(paths)
        if (
            prior is not None
            and all(
                old["_nonblank_start"] <= current["_nonblank_start"] <= old["_nonblank_end"]
                for old, current in zip(prior[1], locations, strict=True)
            )
            and len(
                {
                    current["_nonblank_start"] - old["_nonblank_start"]
                    for old, current in zip(prior[1], locations, strict=True)
                }
            )
            == 1
        ):
            for old, current in zip(prior[1], locations, strict=True):
                old["end_line"] = max(old["end_line"], current["end_line"])
                old["_nonblank_end"] = max(old["_nonblank_end"], current["_nonblank_end"])
            prior[0].append(digest)
        else:
            prior = ([digest], [dict(row) for row in locations])
            previous[paths] = prior
            merged.append(prior)
    return {
        _fingerprint("|".join(digests)): [
            {key: row[key] for key in ("path", "line", "end_line")} for row in locations
        ]
        for digests, locations in merged
    }


def _block_allocations(modules, max_blocks):
    """Give files area-balanced breadth before weighted deeper comparisons."""
    grouped = defaultdict(lambda: defaultdict(deque))
    demands, allocated = {}, Counter()
    for row in sorted(modules, key=lambda row: row["path"]):
        path = row["path"]
        demands[path] = row["block_windows"]
        if demands[path]:
            grouped[row["role"]][row["area"]].append(path)
    order = []
    # One window per eligible file precedes deeper work on any file. This
    # ordering also drives the first actual comparison pass under a deadline.
    for role in sorted(grouped, key=lambda value: (_ROLE_ORDER.get(value, 4), value)):
        areas = {area: deque(paths) for area, paths in grouped[role].items()}
        while areas:
            for area in sorted(areas):
                path = areas[area].popleft()
                order.append(path)
                if len(order) <= max_blocks:
                    allocated[path] = 1
                if not areas[area]:
                    del areas[area]
    remaining = max(0, max_blocks - sum(allocated.values()))
    pending, area_order = {}, {}
    for role, areas in grouped.items():
        pending[role] = {
            area: deque(path for path in paths if allocated[path] < demands[path])
            for area, paths in areas.items()
        }
        pending[role] = {area: paths for area, paths in pending[role].items() if paths}
        area_order[role] = deque(sorted(pending[role]))
    roles = ["production", "production", "unknown", "test", "tooling"]
    roles += sorted(set(pending) - set(roles))
    while remaining and any(area_order.values()):
        for role in roles:
            if not remaining or not area_order.get(role):
                continue
            area = area_order[role].popleft()
            paths = pending[role][area]
            path = paths.popleft()
            allocated[path] += 1
            remaining -= 1
            if allocated[path] < demands[path]:
                paths.append(path)
            if paths:
                area_order[role].append(area)
    return order, allocated


def _window_indices(total, count):
    """Nested samples retain their first windows as the allocation grows."""
    if count >= total:
        return range(total)
    selected = [0]
    if count > 1:
        selected.append(total - 1)
    intervals = deque([(1, total - 2)])
    while intervals and len(selected) < count:
        start, end = intervals.popleft()
        if start > end:
            continue
        middle = (start + end) // 2
        selected.append(middle)
        intervals.extend(((start, middle - 1), (middle + 1, end)))
    return sorted(selected[:count])


def summarize_source_text(sources: dict[str, str], *, max_blocks=40_000, deadline=None):
    """Summarize captured text only; retain one shared bound for block comparisons."""
    if type(max_blocks) is not int or not 0 <= max_blocks <= 1_000_000:
        raise ValueError("max_blocks must be an integer between 0 and 1000000")
    modules, candidates, gaps = [], [], []
    files, blocks, file_hashes = defaultdict(list), defaultdict(list), {}
    block_count, timed_out = 0, False
    for path, text in sorted(sources.items()):
        facts = source_text_facts(path, text)
        modules.append(
            {
                "path": path,
                **facts,
                "area": source_area(path),
                "block_windows": max(0, facts["nonblank_lines"] - BLOCK_LINES + 1),
                "blocks_examined": 0,
            }
        )
        file_hashes[path] = _fingerprint(text)
        # Whole-file equality is inexpensive and retains literal/whitespace differences.
        if facts["nonblank_lines"] >= BLOCK_LINES and len(text) >= MIN_BLOCK_CHARACTERS:
            files[file_hashes[path]].append({"path": path, "line": 1, "end_line": facts["lines"]})
    by_path = {row["path"]: row for row in modules}
    order, allocations = _block_allocations(modules, max_blocks)
    block_limited = sum(row["block_windows"] for row in modules) > max_blocks

    def examine(path, indices):
        nonlocal block_count, timed_out
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            return
        text = sources[path]
        meaningful = [
            (number, line) for number, line in enumerate(text.splitlines(), 1) if line.strip()
        ]
        for index in indices:
            if deadline is not None and block_count % 256 == 0 and time.monotonic() >= deadline:
                timed_out = True
                break
            block_count += 1
            by_path[path]["blocks_examined"] += 1
            window = meaningful[index : index + BLOCK_LINES]
            # Avoid obvious all-comment/license fragments without pretending to parse comments.
            code_lines = sum(
                not line.lstrip().startswith(("//", "#", "/*", "*", "*/", "<!--"))
                for _, line in window
            )
            value = "\n".join(line for _, line in window)
            if code_lines < 4 or len(value) < MIN_BLOCK_CHARACTERS:
                continue
            blocks[_fingerprint(value)].append(
                {
                    "path": path,
                    "line": window[0][0],
                    "end_line": window[-1][0],
                    "_nonblank_start": index,
                    "_nonblank_end": index + BLOCK_LINES - 1,
                }
            )

    # Compare one real window in every allocated file before deeper work.
    # Whole-file equality above remains full-scope even when this phase expires.
    for path in order:
        if allocations[path]:
            examine(path, (0,))
            if timed_out:
                break
    if not timed_out:
        for path in order:
            if allocations[path] > 1:
                indices = _window_indices(by_path[path]["block_windows"], allocations[path])
                examine(path, (index for index in indices if index))
                if timed_out:
                    break
    areas = {}
    for row in modules:
        row["blocks_omitted"] = row["block_windows"] - row["blocks_examined"]
        key = (row["role"], row["area"])
        area = areas.setdefault(
            key,
            {
                "path": row["area"],
                "role": row["role"],
                "files": 0,
                "examined_files": 0,
                "eligible_files": 0,
                "blocks_examined": 0,
                "blocks_omitted": 0,
            },
        )
        area["files"] += 1
        area["eligible_files"] += row["block_windows"] > 0
        area["examined_files"] += row["blocks_examined"] > 0
        area["blocks_examined"] += row["blocks_examined"]
        area["blocks_omitted"] += row["blocks_omitted"]
    roles = {row["path"]: row["role"] for row in modules}
    languages = {row["path"]: row["language"] for row in modules}
    blocks = _merged_blocks(blocks, file_hashes)
    for kind, groups in (("duplicate_source_file", files), ("duplicate_source_block", blocks)):
        for digest, locations in sorted(groups.items()):
            if len(locations) < 2:
                continue
            candidate_roles = sorted({roles[row["path"]] for row in locations})
            candidates.append(
                {
                    "id": "text-" + _fingerprint(kind + digest)[:24],
                    "kind": kind,
                    "lens": "reuse",
                    "confidence": "medium",
                    "role": candidate_roles[0] if len(candidate_roles) == 1 else "unknown",
                    "roles": candidate_roles,
                    "locations": locations[:MAX_LOCATIONS],
                    "metrics": {
                        "matching_locations": len(locations),
                        "omitted_locations": max(0, len(locations) - MAX_LOCATIONS),
                        "languages": sorted(
                            {languages[row["path"]] for row in locations if languages[row["path"]]}
                        ),
                        "normalization": "exact whole text"
                        if kind.endswith("file")
                        else "exact nonblank lines; indentation and literal text retained",
                        "fingerprint": digest,
                    },
                    "caveat": _CAVEAT,
                }
            )
    retained = _retained_candidates(candidates, MAX_CANDIDATES)
    indexed = _retained_candidates(candidates, MAX_INDEX)
    if block_limited:
        gaps.append(
            "Generic source block-comparison limit reached; remaining block reuse is unknown"
        )
    if timed_out:
        gaps.append("Generic source deadline reached; remaining block reuse is unknown")
    if len(candidates) > MAX_CANDIDATES:
        gaps.append("Generic rich candidate sample is bounded; use the compact index")
    if len(candidates) > MAX_INDEX:
        gaps.append("Generic candidate index limit reached; remaining leads are omitted")
    generic_languages = sorted(
        {
            row["language"]
            for row in modules
            if row["language"] not in {"python", "javascript", "typescript"}
        }
    )
    if generic_languages:
        gaps.append(
            "Language-neutral text evidence does not establish syntax, types or unused-code semantics for: "
            + ", ".join(generic_languages)
        )
    return {
        "schema_version": 1,
        "analyzer": {"name": "project-assess-source-text", "version": VERSION},
        "status": "partial"
        if block_limited or timed_out or len(candidates) > MAX_CANDIDATES
        else "complete",
        "coverage": {
            "source_files": len(modules),
            "languages": dict(
                sorted(Counter(row["language"] or "unknown" for row in modules).items())
            ),
            "blocks_examined": block_count,
            "blocks_omitted": sum(row["blocks_omitted"] for row in modules),
            "eligible_block_files": sum(row["block_windows"] > 0 for row in modules),
            "block_files_examined": sum(row["blocks_examined"] > 0 for row in modules),
            "block_files_omitted": sum(
                row["block_windows"] > 0 and not row["blocks_examined"] for row in modules
            ),
            "block_analysis_complete": not (block_limited or timed_out),
            "area_count": len(areas),
            "areas": list(areas.values())[:MAX_COVERAGE_AREAS],
            "omitted_areas": max(0, len(areas) - MAX_COVERAGE_AREAS),
            "sampling": "one_window_per_file_by_role_and_area_then_weighted_area_refill; nested_spread_within_file",
        },
        "candidate_coverage": candidate_coverage(
            candidates,
            indexed,
            {
                "duplicate_source_file": {
                    "complete": True,
                    "eligible_units": len(modules),
                    "analyzed_units": len(modules),
                    "partial_units": 0,
                    "basis": "whole captured source texts hashed before bounded block work",
                },
                "duplicate_source_block": {
                    "complete": not (block_limited or timed_out),
                    "eligible_units": sum(row["block_windows"] for row in modules),
                    "analyzed_units": block_count,
                    "partial_units": sum(row["blocks_omitted"] for row in modules),
                    "basis": "exact nonblank block windows; omitted windows remain unknown",
                },
            },
        ),
        "modules": sorted(modules, key=lambda row: row["path"]),
        "candidates": retained,
        "candidate_index": indexed,
        "candidate_counts": {
            "total": len(candidates),
            "retained": len(retained),
            "indexed": len(indexed),
            "omitted_from_index": len(candidates) - len(indexed),
            "by_kind": dict(sorted(Counter(row["kind"] for row in candidates).items())),
            "by_role": dict(sorted(Counter(row["role"] for row in candidates).items())),
        },
        "summary": {"candidate_count": len(candidates), "source_files": len(modules)},
        "limits": {
            "blocks": max_blocks,
            "block_lines": BLOCK_LINES,
            "block_stride": BLOCK_STRIDE,
            "minimum_characters": MIN_BLOCK_CHARACTERS,
            "locations_per_candidate": MAX_LOCATIONS,
            "candidates": MAX_CANDIDATES,
            "candidate_index": MAX_INDEX,
            "coverage_areas": MAX_COVERAGE_AREAS,
        },
        "gaps": gaps,
        "caveat": _CAVEAT,
    }
