"""Language-neutral source inventory and exact-text reuse leads from captured bytes.

This is deliberately not a lexer, parser, type checker or reachability analyzer.
Native syntax analyzers and supplied reports can add richer evidence separately.
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter, defaultdict
from pathlib import PurePosixPath

from .static_analysis import _retained_candidates, source_role

VERSION = "1"
MAX_CANDIDATES = 100
MAX_INDEX = 20_000
BLOCK_LINES = 12
BLOCK_STRIDE = 1
MIN_BLOCK_CHARACTERS = 200
MAX_LOCATIONS = 20
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
        if prior is not None and all(
            old["line"] <= current["line"] <= old["end_line"]
            for old, current in zip(prior[1], locations, strict=True)
        ):
            for old, current in zip(prior[1], locations, strict=True):
                old["end_line"] = max(old["end_line"], current["end_line"])
            prior[0].append(digest)
        else:
            prior = ([digest], [dict(row) for row in locations])
            previous[paths] = prior
            merged.append(prior)
    return {_fingerprint("|".join(digests)): locations for digests, locations in merged}


def summarize_source_text(sources: dict[str, str], *, max_blocks=40_000, deadline=None):
    """Summarize captured text only; retain one shared bound for block comparisons."""
    if type(max_blocks) is not int or not 0 <= max_blocks <= 1_000_000:
        raise ValueError("max_blocks must be an integer between 0 and 1000000")
    modules, candidates, gaps = [], [], []
    files, blocks, file_hashes = defaultdict(list), defaultdict(list), {}
    block_count, block_limited, timed_out = 0, False, False

    def priority(item):
        path = item[0]
        role = source_role(path)["role"]
        native = source_language(path) in {"python", "javascript", "typescript"}
        return ({"production": 0, "unknown": 1, "test": 2, "tooling": 3}.get(role, 4), native, path)

    for path, text in sorted(sources.items(), key=priority):
        facts = source_text_facts(path, text)
        modules.append({"path": path, **facts})
        file_hashes[path] = _fingerprint(text)
        # Whole-file equality is inexpensive and retains literal/whitespace differences.
        if facts["nonblank_lines"] >= BLOCK_LINES and len(text) >= MIN_BLOCK_CHARACTERS:
            files[file_hashes[path]].append({"path": path, "line": 1, "end_line": facts["lines"]})
        if timed_out or block_limited:
            continue
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            continue
        meaningful = [
            (number, line) for number, line in enumerate(text.splitlines(), 1) if line.strip()
        ]
        for index in range(0, max(0, len(meaningful) - BLOCK_LINES + 1), BLOCK_STRIDE):
            if block_count >= max_blocks:
                block_limited = True
                break
            if deadline is not None and block_count % 256 == 0 and time.monotonic() >= deadline:
                timed_out = True
                break
            block_count += 1
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
                {"path": path, "line": window[0][0], "end_line": window[-1][0]}
            )
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
            "block_analysis_complete": not (block_limited or timed_out),
        },
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
        },
        "gaps": gaps,
        "caveat": _CAVEAT,
    }
