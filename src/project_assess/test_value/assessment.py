"""Turn test-value reports into bounded, non-identifying assessment evidence.

The reports are supplied claims and observations.  This adapter deliberately
does not read paths named by a report, execute a runner, or infer assertion
equivalence from shared coverage.
"""

from __future__ import annotations

import math
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMAS = frozenset(
    {"test-value-audit.v3", "test-value-evidence-compare.v1", "test-value-evidence.v1"}
)
MAX_DEPTH = 64
MAX_ITEMS = 250_000
MAX_SUMMARY_ITEMS = 32


def _shape(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    """Reject pathological JSON shapes before any fields are inspected."""
    count = [0] if count is None else count
    if depth > MAX_DEPTH:
        raise ValueError("test-value report JSON depth limit exceeded")
    count[0] += 1
    if count[0] > MAX_ITEMS:
        raise ValueError("test-value report JSON item limit exceeded")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 1024:
                raise ValueError("test-value report JSON key is invalid")
            _shape(child, depth + 1, count)
    elif isinstance(value, list):
        for child in value:
            _shape(child, depth + 1, count)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("test-value report contains nonfinite JSON value")
    elif isinstance(value, (str, int, float, bool)) or value is None:
        return
    else:
        raise ValueError("test-value report JSON value is invalid")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return value


def _status(reported: Any, actual: Any) -> str:
    if reported is None or actual is None:
        return "unknown"
    return "matched" if reported == actual else "mismatch"


def _root_status(raw: Mapping[str, Any], root: Path) -> str:
    value = raw.get("root")
    if value is None:
        value = _mapping(raw.get("project")).get("root")
    if not isinstance(value, str) or not value:
        return "unknown"
    # Do not resolve or inspect report-referenced paths.  Normalization is only
    # string comparison against the already-authorized assessment root.
    try:
        reported = os.path.normcase(os.path.abspath(value))
        expected = os.path.normcase(os.path.abspath(str(root)))
    except (OSError, ValueError):
        return "unknown"
    return _status(reported, expected)


def _revision(raw: Mapping[str, Any]) -> Any:
    source = _mapping(raw.get("currentSource"))
    if source.get("revision") is not None:
        return source.get("revision")
    project = _mapping(raw.get("project"))
    return project.get("revision")


def _source_hashes(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    hashes = raw.get("sourceHashes")
    if isinstance(hashes, Mapping):
        return hashes
    project = _mapping(raw.get("project"))
    hashes = project.get("sourceHashes")
    if isinstance(hashes, Mapping):
        return hashes
    # Comparison reports retain source identity per imported artifact rather
    # than repeating one top-level map.  Merge only the already-captured
    # metadata; no paths named here are opened.
    merged: dict[str, Any] = {}
    for item in _items(raw.get("inputs")):
        for source in _items(_mapping(item).get("sources")):
            source = _mapping(source)
            if source.get("path") is not None and source.get("hash") is not None:
                merged[source["path"]] = source["hash"]
        provenance = _mapping(item).get("provenance")
        after = _mapping(provenance).get("sourceHashesAfter")
        if isinstance(after, Mapping):
            merged.update(after)
    return merged


def _relative_source(path: Any, report_root: Any, root: Path) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    path = path.replace("\\", "/")
    if ".." in path.split("/"):
        return None
    if os.path.isabs(path):
        if not isinstance(report_root, str) or not report_root:
            return None
        prefix = os.path.normcase(os.path.abspath(report_root)).rstrip(os.sep) + os.sep
        normalized = os.path.normcase(os.path.abspath(path))
        if not normalized.startswith(prefix):
            return None
        path = normalized[len(prefix) :]
    while path.startswith("./"):
        path = path[2:]
    if not path or path == ".":
        return None
    return path


def _source_status(raw: Mapping[str, Any], root: Path, manifest: Mapping[str, str]) -> str:
    hashes = _source_hashes(raw)
    if not hashes:
        return "unknown"
    report_root = raw.get("root") or _mapping(raw.get("project")).get("root")
    statuses = []
    for path, digest in list(hashes.items())[:MAX_ITEMS]:
        relative = _relative_source(path, report_root, root)
        if relative is None or not isinstance(digest, str) or relative not in manifest:
            statuses.append("unknown")
        else:
            statuses.append("matched" if manifest[relative] == digest else "mismatch")
    if "mismatch" in statuses:
        return "mismatch"
    if statuses and all(status == "matched" for status in statuses):
        return "matched"
    return "unknown"


def _phase_summary(rows: Sequence[Any]) -> dict[str, dict[str, int | float]]:
    result: dict[str, dict[str, int | float]] = {}
    for row in rows:
        phases = _mapping(_mapping(row).get("phases"))
        for phase in ("setup", "call", "teardown", "unassigned"):
            value = _mapping(phases.get(phase))
            if not value:
                continue
            bucket = result.setdefault(phase, {"count": 0, "seconds": 0.0})
            bucket["count"] += 1
            duration = value.get("durationSeconds", value.get("seconds"))
            if (
                isinstance(duration, (int, float))
                and not isinstance(duration, bool)
                and duration >= 0
            ):
                bucket["seconds"] += duration
    return result


def _outcomes(rows: Sequence[Any]) -> dict[str, int]:
    counts = Counter()
    for row in rows:
        outcome = _mapping(row).get("outcome")
        if isinstance(outcome, str) and outcome in {
            "passed",
            "failed",
            "skipped",
            "xfailed",
            "xpassed",
        }:
            counts[outcome] += 1
        else:
            counts["unknown"] += 1
    return dict(sorted(counts.items()))


def _attribution(rows: Sequence[Any], features: Sequence[Any]) -> dict[str, int]:
    counts = Counter()
    for row in rows:
        attribution = _mapping(row).get("attribution")
        counts[
            attribution if attribution in {"case", "file", "suite", "unknown"} else "unknown"
        ] += 1
    for feature in features:
        attribution = _mapping(feature).get("attribution")
        counts[
            attribution if attribution in {"case", "file", "suite", "unknown"} else "unknown"
        ] += 0
    return dict(sorted(counts.items()))


def _gaps(raw: Mapping[str, Any]) -> list[str]:
    values = raw.get("gaps", [])
    reasons: list[str] = []
    for value in values if isinstance(values, list) else []:
        if isinstance(value, str):
            reason = value
        else:
            reason = _mapping(value).get("reason")
        if isinstance(reason, str) and reason and reason not in reasons:
            reasons.append(reason[:200])
    return reasons[:MAX_SUMMARY_ITEMS]


def _safe_tool(raw: Mapping[str, Any]) -> dict[str, Any]:
    tool = _mapping(raw.get("tool"))
    if not tool:
        tool = _mapping(raw.get("analyzer"))
    result: dict[str, Any] = {}
    for key in ("collectorHash", "normalizerHash", "moduleHash", "python"):
        value = tool.get(key)
        if isinstance(value, str) and len(value) <= 200:
            result[key] = value
    versions = raw.get("toolVersions")
    if isinstance(versions, Mapping):
        result["versions"] = {
            str(key): str(value)[:100]
            for key, value in list(versions.items())[:MAX_SUMMARY_ITEMS]
            if isinstance(key, str) and isinstance(value, (str, int, float))
        }
    return result


def _provenance(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Keep operational provenance while omitting commands and raw paths."""
    source = _mapping(raw.get("provenance"))
    if not source:
        source = _mapping(raw.get("collection"))
    result: dict[str, Any] = {}
    for key in (
        "exitCode",
        "durationSeconds",
        "sourceStable",
        "testStable",
        "configStable",
        "finished",
        "outcome",
    ):
        value = source.get(key)
        if (
            isinstance(value, (str, int, float, bool))
            and not isinstance(value, float)
            or (isinstance(value, float) and math.isfinite(value) and value >= 0)
        ):
            result[key] = value
    invocation = _mapping(raw.get("invocation"))
    if isinstance(invocation.get("outcome"), str):
        result["invocationOutcome"] = invocation["outcome"][:40]
    return result


def summarize(
    raw: Mapping[str, Any],
    root: Path,
    manifest: Sequence[Mapping[str, Any]] | Mapping[str, str],
    revision: str | None,
) -> dict[str, Any]:
    """Return a compact safe summary of one supported test-value report."""
    if not isinstance(raw, Mapping):
        raise ValueError("test-value report must contain an object")
    _shape(raw)
    schema = raw.get("schema")
    if schema not in SUPPORTED_SCHEMAS:
        raise ValueError("unsupported test-value report schema")
    required_shapes = {
        "test-value-audit.v3": {"tests": list, "gaps": list},
        "test-value-evidence.v1": {"project": Mapping, "tests": list, "gaps": list},
        "test-value-evidence-compare.v1": {"inputs": list, "tests": list, "gaps": list},
    }[schema]
    for key, expected in required_shapes.items():
        if key not in raw or not isinstance(raw[key], expected):
            raise ValueError("malformed test-value report shape")
    if isinstance(manifest, Mapping):
        captured = {str(key): str(value) for key, value in manifest.items()}
    else:
        captured = {
            str(item.get("path")): str(item.get("digest"))
            for item in manifest
            if isinstance(item, Mapping)
            and isinstance(item.get("path"), str)
            and isinstance(item.get("digest"), str)
        }
    rows = _items(raw.get("tests"))
    if schema == "test-value-evidence-compare.v1":
        rows = _items(raw.get("tests"))
    features = _items(raw.get("coverageFeatures"))
    outcomes = _outcomes(rows)
    source_status = _source_status(raw, root, captured)
    revision_status = _status(_revision(raw), revision)
    root_status = _root_status(raw, root)
    identity_status = (
        "mismatch"
        if "mismatch" in {source_status, revision_status, root_status}
        else "matched"
        if {source_status, revision_status, root_status} == {"matched"}
        else "unknown"
    )
    groups = _items(raw.get("identicalFootprints"))
    overlap = _items(raw.get("crossLayerOverlap"))
    candidates = _items(raw.get("rankedCandidates"))
    policy = _mapping(raw.get("policy"))
    artifacts = _items(raw.get("artifacts"))
    claims = {
        "healthyCollection": raw.get("healthyCollection")
        if isinstance(raw.get("healthyCollection"), bool)
        else None,
        "confidentOverlap": raw.get("confidentOverlap")
        if isinstance(raw.get("confidentOverlap"), bool)
        else None,
        "source": "supplied",
        "assessmentComplete": False,
        "rating": None,
    }
    return {
        "schema": schema,
        "counts": {
            "tests": len(rows),
            "coverageFeatures": len(features) if "coverageFeatures" in raw else None,
            "identicalFootprints": len(groups) if "identicalFootprints" in raw else None,
            "crossLayerOverlap": len(overlap) if "crossLayerOverlap" in raw else None,
            "rankedCandidates": len(candidates) if "rankedCandidates" in raw else None,
            "artifacts": len(artifacts) if "artifacts" in raw else None,
        },
        "outcomes": outcomes,
        "phases": _phase_summary(rows),
        "attribution": _attribution(rows, features),
        "sourceIdentity": {
            "root": root_status,
            "revision": revision_status,
            "sourceHashes": source_status,
            "overall": identity_status,
        },
        "policy": {
            "softTargetPercent": _number(policy.get("softTargetPercent")),
            "criticalSources": len(_items(policy.get("criticalSources"))),
            "protectedTests": len(_items(policy.get("protectedTests"))),
        },
        "tool": _safe_tool(raw),
        "provenance": _provenance(raw),
        "artifacts": {
            "count": len(artifacts),
            "hashed": sum(isinstance(_mapping(item).get("hash"), str) for item in artifacts),
        },
        "gaps": {"count": len(_gaps(raw)), "reasons": _gaps(raw)},
        "claims": claims,
        "note": "Supplied test-value claims and overlap are review evidence, not assertion equivalence or deletion proof.",
    }
