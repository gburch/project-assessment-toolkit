"""Run installed Vulture on bounded captured text, without scavenge or configuration."""

from __future__ import annotations

import ast
import hashlib
import importlib
import json
import math
import re
import time
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
from itertools import islice
from pathlib import PurePosixPath

from .static_analysis import _retained_candidates, source_role

VERSION = "1"
MAX_CANDIDATES = 100
MAX_INDEX = 20_000
MAX_INPUT_RECORDS = 20_000
_PROFILES = {
    "standard": {
        "files": 1000,
        "bytes": 32 * 1024 * 1024,
        "bytes_per_file": 2 * 1024 * 1024,
        "nodes": 500_000,
        "nodes_per_file": 100_000,
        "seconds": 120,
    },
    "deep": {
        "files": 4000,
        "bytes": 128 * 1024 * 1024,
        "bytes_per_file": 8 * 1024 * 1024,
        "nodes": 2_000_000,
        "nodes_per_file": 250_000,
        "seconds": 300,
    },
}
_CAVEAT = (
    "Vulture confidence is a producer heuristic, not PAT confidence, severity, "
    "proof of disuse or permission to remove code. Dynamic callers, public exports, "
    "decorators, registries and external consumers remain open-world. "
    "Unused arguments/import bindings can preserve signatures or import side effects. "
    "Even unreachable yields can intentionally preserve generator or async-generator shape."
)
_WHITELIST_GAP = (
    "Only Vulture.scan was used. Project configuration, project whitelist files and "
    "Vulture's bundled whitelists were not loaded; implicit framework uses can be reported. "
    "Source noqa comments are honored by the producer, not verified by PAT."
)
_clock = time.monotonic


def vulture_info():
    try:
        installed = version("vulture")
    except PackageNotFoundError:
        installed = None
    release = re.fullmatch(r"2\.(\d+)(?:\.\d+)?", installed or "")
    supported = release is not None and int(release[1]) >= 14
    return {
        "name": "vulture",
        "version": installed,
        "available": supported,
        "adapter_version": VERSION,
        "optional": True,
        "languages": ["python"],
        "extra": "vulture",
        "license": "MIT",
        "supported_versions": ">=2.14,<3",
        "selection": "explicit",
        "execution": "installed Python API on captured text",
    }


def _path(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\x00" in value
        or "\\" in value
    ):
        raise ValueError("Analyzer sources require captured relative paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError("Analyzer sources require captured relative paths")
    return path.as_posix()


def _snapshot(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("Analyzer snapshot identity must be an object")
    return {
        key: item
        for key, item in value.items()
        if key
        in {
            "assessment_id",
            "revision",
            "manifest_digest",
            "source_digest",
            "scope_digest",
            "worktree_manifest_digest",
        }
        and (item is None or isinstance(item, str) and len(item) <= 256)
    }


def analyze_vulture(
    sources,
    *,
    snapshot=None,
    config=None,
    redact=None,
    analysis_profile="standard",
    deadline=None,
):
    """Bound work and check a cooperative deadline before each file/finalization.

    The deadline cannot interrupt an individual bounded AST/API operation. No
    source file, project config, executable whitelist or plugin is loaded.
    """
    if not isinstance(analysis_profile, str) or analysis_profile not in _PROFILES:
        raise ValueError("Unknown analysis profile")
    if config is None:
        config = {}
    if not isinstance(config, dict) or config.keys() - {"min_confidence"}:
        raise ValueError("Vulture configuration only supports min_confidence data")
    minimum = config.get("min_confidence", 60)
    if type(minimum) is not int or not 0 <= minimum <= 100:
        raise ValueError("Vulture min_confidence must be an integer from 0 to 100")
    if deadline is not None and (type(deadline) not in {int, float} or not math.isfinite(deadline)):
        raise ValueError("Analyzer deadline must be a finite monotonic time")
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_INPUT_RECORDS:
        raise ValueError("Analyzer sources must be captured source records")
    selected, seen = [], set()
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("text"), str):
            raise ValueError("Analyzer sources require captured text and identity")
        path = _path(source.get("path"))
        if path in seen:
            raise ValueError("Analyzer source paths must be unique")
        seen.add(path)
        for field in ("evidence_id", "digest"):
            if (
                not isinstance(source.get(field), str)
                or not source[field]
                or len(source[field]) > 256
            ):
                raise ValueError("Analyzer sources require captured evidence IDs and digests")
        if PurePosixPath(path).suffix == ".py":
            row = {**source, "path": path, **source_role(path)}
            if source.get("role") in {"production", "test", "tooling", "generated", "unknown"}:
                row["role"] = source["role"]
            selected.append(row)
    # Preserve declared source/test roles while prioritizing product review work.
    selected.sort(
        key=lambda row: (
            {"production": 0, "unknown": 1, "test": 2, "tooling": 3}.get(row["role"], 4),
            row["path"],
        )
    )
    limits = {
        **_PROFILES[analysis_profile],
        "candidates": MAX_CANDIDATES,
        "candidate_index": MAX_INDEX,
        "input_records": MAX_INPUT_RECORDS,
        "deadline_mode": "cooperative; individual bounded API calls are not preempted",
    }
    start = _clock()
    stop = (
        min(start + limits["seconds"], deadline)
        if deadline is not None
        else start + limits["seconds"]
    )
    identity = vulture_info()
    modules, scanned, gaps, omission_counts = [], {}, {_WHITELIST_GAP}, Counter()
    result = {
        "schema_version": 1,
        "analyzer": identity,
        "available": identity["available"],
        "status": "unavailable",
        "configuration": {
            "min_confidence": minimum,
            "analysis_profile": analysis_profile,
            "project_config_loaded": False,
            "whitelist_files_loaded": False,
            "bundled_whitelists_loaded": False,
            "source_noqa": "producer_honored",
        },
        "provenance": {
            "snapshot": _snapshot(snapshot),
            "source_identity": "captured_snapshot",
            "execution": "Vulture.scan(captured_text), then get_unused_code; no scavenge",
            "shared_deadline": deadline is not None,
        },
        "coverage": {
            "captured_source_files": len(sources),
            "python_files": len(selected),
            "analyzed_files": 0,
            "omitted_files": len(selected),
            "input_bytes": 0,
            "nodes_analyzed": 0,
        },
        "summary": {"candidate_count": 0, "producer_findings": None},
        "modules": modules,
        "candidates": [],
        "candidate_index": [],
        "candidate_counts": {
            "total": 0,
            "retained": 0,
            "indexed": 0,
            "omitted_from_index": 0,
            "by_kind": {},
            "by_role": {},
        },
        "limits": limits,
        "gaps": [],
        "caveat": _CAVEAT,
    }
    if not identity["available"]:
        result["gaps"] = sorted(
            gaps
            | {
                "Optional Vulture analyzer unavailable; install the vulture extra in the assessor environment. No project dependencies were installed."
            }
        )
        return result
    if not selected:
        result["status"] = "unsupported"
        result["gaps"] = sorted(gaps | {"No captured Python source was supplied to Vulture"})
        return result
    try:
        tool = importlib.import_module("vulture")

        class QuietVulture(tool.Vulture):
            def _log(self, *args, **kwargs):
                # Vulture can log raw syntax-error source. Never emit that text.
                if kwargs.get("force"):
                    self.input_error = True

        engine = QuietVulture(verbose=False)
    except (ImportError, AttributeError, TypeError, ValueError):
        result["available"] = False
        result["gaps"] = sorted(gaps | {"Installed Vulture API is unavailable or incompatible"})
        return result
    partial, yielded_lines = False, {}
    for source in selected:
        path, text = source["path"], source["text"]
        reason = None
        if _clock() >= stop:
            reason = "cooperative_deadline"
        elif len(scanned) >= limits["files"]:
            reason = "file_limit"
        elif len(text) > limits["bytes_per_file"]:
            reason = "file_byte_limit"
        if reason:
            omission_counts[reason] += 1
            partial = True
            continue
        raw = text.encode("utf-8", errors="replace")
        if (
            len(raw) > limits["bytes_per_file"]
            or result["coverage"]["input_bytes"] + len(raw) > limits["bytes"]
        ):
            omission_counts["input_byte_limit"] += 1
            partial = True
            continue
        if "sha256:" + hashlib.sha256(raw).hexdigest() != source["digest"]:
            omission_counts["source_digest_mismatch"] += 1
            partial = True
            continue
        try:
            tree = ast.parse(text, filename=path, type_comments=True)
            nodes = list(islice(ast.walk(tree), limits["nodes_per_file"] + 1))
        except (SyntaxError, ValueError, RecursionError):
            omission_counts["parse_error"] += 1
            partial = True
            continue
        if (
            len(nodes) > limits["nodes_per_file"]
            or result["coverage"]["nodes_analyzed"] + len(nodes) > limits["nodes"]
        ):
            omission_counts["ast_node_limit"] += 1
            partial = True
            continue
        if _clock() >= stop:
            omission_counts["cooperative_deadline"] += 1
            partial = True
            continue
        # Synthetic absolute labels prevent filename heuristics from resolving
        # paths inside the assessed project. Vulture.scan reads only `text`.
        virtual = "/__pat_captured_sources__/" + path
        try:
            engine.input_error = False
            engine.scan(text, filename=virtual)
            if engine.input_error:
                raise ValueError("Producer rejected captured input")
        except (SyntaxError, ValueError, RecursionError, AttributeError):
            omission_counts["producer_error"] += 1
            partial = True
            continue
        scanned[virtual] = source
        yielded_lines[path] = {
            node.lineno for node in nodes if isinstance(node, (ast.Yield, ast.YieldFrom))
        }
        result["coverage"]["input_bytes"] += len(raw)
        result["coverage"]["nodes_analyzed"] += len(nodes)
        modules.append(
            {
                "path": path,
                "role": source["role"],
                "role_basis": source["role_basis"],
                "source_evidence_id": source["evidence_id"],
                "digest": source["digest"],
                "lines": len(text.splitlines()),
                "bytes": len(raw),
                "nodes_analyzed": len(nodes),
            }
        )
    candidates = []
    if _clock() >= stop:
        omission_counts["cooperative_deadline_before_finalization"] += 1
        partial = True
    else:
        try:
            items = engine.get_unused_code(min_confidence=minimum)
            result["summary"]["producer_findings"] = len(items)
        except (AttributeError, TypeError, ValueError, RecursionError):
            items = []
            omission_counts["producer_finalization_error"] += 1
            partial = True
        clean = redact or (lambda text: text)
        if len(items) > MAX_INDEX:
            omission_counts["producer_candidate_work_limit"] += len(items) - MAX_INDEX
            partial = True
        for item in items[:MAX_INDEX]:
            if _clock() >= stop:
                omission_counts["cooperative_deadline_during_normalization"] += 1
                partial = True
                break
            source = scanned.get(str(item.filename))
            if source is None:
                continue
            location = {
                "path": source["path"],
                "line": item.first_lineno,
                "end_line": item.last_lineno,
            }
            if (
                type(item.first_lineno) is not int
                or type(item.last_lineno) is not int
                or not 1 <= item.first_lineno <= item.last_lineno
            ):
                omission_counts["invalid_producer_location"] += 1
                partial = True
                continue
            kind = "unreachable_statement" if item.typ == "unreachable_code" else "unused_symbol"
            metrics = {
                "producer_kind": item.typ,
                "code_type": item.typ,
                "symbol": clean(str(item.name))[:256],
                "message": clean(str(item.message))[:500],
                "producer_confidence": item.confidence,
                "producer_confidence_scale": "0..100 heuristic, separate from PAT confidence",
                "source_digest": source["digest"],
            }
            marker = kind == "unreachable_statement" and any(
                item.first_lineno <= line <= item.last_lineno
                for line in yielded_lines[source["path"]]
            )
            if marker:
                metrics["retention_hint"] = "unreachable_yield_can_preserve_generator_shape"
            candidate = {
                "kind": kind,
                "lens": "quality",
                "locations": [location],
                "metrics": metrics,
                "confidence": "low",
                "role": source["role"],
                "roles": [source["role"]],
                "source_evidence_ids": [source["evidence_id"]],
                "source_identity": "captured_snapshot",
                "caveat": _CAVEAT,
                "counterevidence": [
                    "Inspect exports, actual callers and dynamic dispatch before removal."
                ],
            }
            if marker:
                candidate["counterevidence"].append(
                    "This reported range contains a yield; removing it can change generator/async-generator shape even when the branch cannot execute."
                )
            candidate["id"] = (
                "v-"
                + hashlib.sha256(
                    json.dumps([kind, location, metrics], sort_keys=True).encode()
                ).hexdigest()[:24]
            )
            candidates.append(candidate)
    if len(candidates) > MAX_CANDIDATES:
        gaps.add("Vulture rich candidate sample is bounded; inspect the compact index and coverage")
        partial = True
    if len(candidates) > MAX_INDEX:
        gaps.add("Vulture candidate index limit reached")
        partial = True
    if omission_counts:
        gaps.add(
            "Some captured Python source or producer output was omitted; no absence-of-use conclusion covers omitted code"
        )
    retained, indexed = (
        _retained_candidates(candidates, MAX_CANDIDATES),
        _retained_candidates(candidates, MAX_INDEX),
    )
    result.update(
        status="partial" if partial else "complete",
        candidates=retained,
        candidate_index=indexed,
        gaps=sorted(gaps),
    )
    result["summary"]["candidate_count"] = len(candidates)
    result["coverage"].update(
        analyzed_files=len(scanned),
        omitted_files=len(selected) - len(scanned),
        omissions=dict(sorted(omission_counts.items())),
    )
    result["candidate_counts"] = {
        "total": len(candidates),
        "retained": len(retained),
        "indexed": len(indexed),
        "omitted_from_index": len(candidates) - len(indexed),
        "by_kind": dict(sorted(Counter(row["kind"] for row in candidates).items())),
        "by_role": dict(sorted(Counter(row["role"] for row in candidates).items())),
    }
    return result
