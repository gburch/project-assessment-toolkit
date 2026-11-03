"""Bind trusted Joern flow results to the captured source, without assigning scores."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import PurePosixPath

MAX_PATHS = 20_000
MAX_STEPS = 64
_MAX_COUNT = 2**53
_CAVEAT = (
    "Modeled value-flow paths under Joern's default semantics, not runtime traces, "
    "validated vulnerabilities or permission to delete code. Unknown external behavior, "
    "dynamic dispatch, skipped methods and bounded queries can leave flows unresolved. "
    "An empty result does not establish absence of a flow."
)
_SCOPE = "method_parameters_to_returns_and_selected_operation_arguments"


def _count(value):
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        raise ValueError("Invalid dataflow counter")
    return value


def _section(value, maximum, *, lower_bound=False):
    if not isinstance(value, dict) or value.get("status") not in {"complete", "partial"}:
        raise ValueError("Invalid dataflow section")
    rows = value.get("rows")
    if not isinstance(rows, list) or len(rows) > maximum:
        raise ValueError("Invalid bounded dataflow rows")
    count, omitted = _count(value.get("count")), _count(value.get("omitted"))
    if count != len(rows) + omitted:
        raise ValueError("Inconsistent dataflow row counts")
    result = {"status": value["status"], "count": count, "omitted": omitted, "rows": []}
    if lower_bound:
        if type(value.get("count_is_lower_bound")) is not bool:
            raise ValueError("Invalid dataflow lower-bound declaration")
        result["count_is_lower_bound"] = value["count_is_lower_bound"]
    return result


def normalize_dataflow(raw, *, stage, sources, clean):
    """Return ``(source-bound result, gaps)``; reject malformed aggregate claims.

    Individual paths with unbound locations are omitted and explicitly counted.
    Only whitelisted fields are retained; producer diagnostics and graph IDs never
    enter the report. Counts describe the modeled/query scope, not project quality.
    """
    status = raw.get("dataflow")
    if status not in {"not_run", "complete", "partial", "error"}:
        raise ValueError("Unqualified dataflow status")
    value = raw.get("dataflow_analysis")
    result = {
        "schema_version": 1,
        "status": status,
        "scope": _SCOPE,
        "semantics": "joern_default",
        "paths": {"status": status, "count": None, "omitted": None, "rows": []},
        "caveat": _CAVEAT,
    }
    if status == "not_run":
        if value is not None and value != {"status": "not_run"}:
            raise ValueError("Unexpected dataflow evidence for an unrun phase")
        return result, set()
    if not isinstance(value, dict) or value.get("status") != status:
        raise ValueError("Inconsistent dataflow phase status")
    if status == "error":
        # An unsuccessful phase has no usable path evidence. Do not relay raw
        # diagnostics, or reinterpret an empty result as a successful check.
        return result, {"Joern dataflow did not complete; missing flows remain unknown"}
    if (
        value.get("semantics", "joern_default") != "joern_default"
        or value.get("scope", _SCOPE) != _SCOPE
    ):
        raise ValueError("Unqualified dataflow semantics or scope")
    keys = (
        "max_definitions",
        "maximum_definitions_observed",
        "max_call_depth",
        "methods_total",
        "methods_analyzed",
        "methods_skipped",
    )
    result.update((key, _count(value.get(key))) for key in keys)
    if "source_parameter_count" in value:
        result["source_parameter_count"] = _count(value["source_parameter_count"])
    if result["max_definitions"] != 50_000 or result["max_call_depth"] != 8:
        raise ValueError("Unqualified dataflow analysis limits")
    if result["methods_total"] != result["methods_analyzed"] + result["methods_skipped"]:
        raise ValueError("Inconsistent dataflow method counts")
    if (
        result["methods_skipped"] == 0
        and result["maximum_definitions_observed"] > result["max_definitions"]
    ):
        raise ValueError("Unreported dataflow method omissions")
    queries = value.get("queries")
    if not isinstance(queries, dict):
        raise ValueError("Missing dataflow query coverage")
    query_keys = ("sinks_total", "sinks_queried", "sinks_omitted", "paths_truncated", "step_limit")
    result["queries"] = {key: _count(queries.get(key)) for key in query_keys}
    if result["queries"]["step_limit"] != MAX_STEPS:
        raise ValueError("Unqualified dataflow path limit")
    if queries["sinks_total"] != queries["sinks_queried"] + queries["sinks_omitted"]:
        raise ValueError("Inconsistent dataflow sink counts")

    def located(row):
        if not isinstance(row, dict) or row.get("identity_truncated"):
            raise ValueError("Unlocated dataflow node")
        path = row.get("path")
        if (
            not isinstance(path, str)
            or not 1 <= len(path) <= 4096
            or "\\" in path
            or "\x00" in path
        ):
            raise ValueError("Invalid dataflow source path")
        path = PurePosixPath(path)
        if path.is_absolute():
            path = path.relative_to(PurePosixPath(stage.as_posix()))
        if not path.parts or ".." in path.parts or path.as_posix() not in sources:
            raise ValueError("Dataflow node is outside captured source")
        path = path.as_posix()
        source = sources[path]
        at = row.get("line")
        if type(at) is not int or not 1 <= at <= len(source["lines"]):
            raise ValueError("Dataflow node has no captured source line")
        result = {
            "path": path,
            "line": at,
            "source_evidence_id": source["evidence_id"],
            "digest": source["digest"],
        }
        for key, maximum in (("name", 256), ("method", 4096), ("node_type", 64)):
            text = row.get(key)
            if not isinstance(text, str) or not 1 <= len(text) <= maximum or "\x00" in text:
                raise ValueError("Invalid dataflow node identity")
            result[key] = clean(text.replace(stage.as_posix() + "/", ""))[:maximum]
        return result

    result["skipped_methods"] = _section(value.get("skipped_methods"), MAX_PATHS)
    result["paths"] = _section(value.get("paths"), MAX_PATHS, lower_bound=True)
    if result["skipped_methods"]["count"] != result["methods_skipped"]:
        raise ValueError("Inconsistent skipped dataflow methods")
    omissions = Counter()
    skipped = result["skipped_methods"]
    for row in value["skipped_methods"]["rows"]:
        try:
            node = located({**row, "name": "<method>", "node_type": "METHOD"})
            definitions = _count(row.get("definitions"))
            if (
                not result["max_definitions"]
                < definitions
                <= result["maximum_definitions_observed"]
            ):
                raise ValueError("Invalid skipped method definition count")
            reason = row.get("reason")
            if reason != "definition_limit":
                raise ValueError("Unqualified skipped method reason")
            skipped["rows"].append({**node, "definitions": definitions, "reason": reason})
        except (ValueError, TypeError, KeyError):
            omissions["unlocated_skipped_method"] += 1
            skipped["omitted"] += 1
    paths, seen = result["paths"], set()
    for row in value["paths"]["rows"]:
        try:
            if not isinstance(row, dict) or row.get("kind") not in {
                "parameter_to_return",
                "parameter_to_operation",
            }:
                raise ValueError("Unqualified dataflow path kind")
            steps = row.get("steps")
            if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
                raise ValueError("Invalid dataflow path length")
            start, end = located(row.get("source")), located(row.get("sink"))
            steps = [located(node) for node in steps]
            if steps[0] != start or steps[-1] != end:
                raise ValueError("Inconsistent dataflow path endpoints")
            interprocedural = len({(node["path"], node["method"]) for node in steps}) > 1
            if (
                type(row.get("interprocedural")) is not bool
                or row["interprocedural"] != interprocedural
            ):
                raise ValueError("Inconsistent dataflow procedure scope")
            path = {
                "kind": row["kind"],
                "basis": "joern_default_semantics_with_modeled_callees",
                "confidence": "low",
                "source_identity": "captured_snapshot",
                "source": start,
                "sink": end,
                "steps": steps,
                "interprocedural": interprocedural,
            }
            identity = json.dumps(path, sort_keys=True, separators=(",", ":")).encode()
            path["id"] = "jf-" + hashlib.sha256(identity).hexdigest()[:24]
            if path["id"] in seen:
                omissions["duplicate_path"] += 1
                paths["omitted"] += 1
                continue
            seen.add(path["id"])
            paths["rows"].append(path)
        except (ValueError, TypeError, KeyError):
            omissions["unbound_or_inconsistent_path"] += 1
            paths["omitted"] += 1
    paths["rows"].sort(key=lambda row: (row["source"]["path"], row["source"]["line"], row["id"]))
    skipped["rows"].sort(key=lambda row: (row["path"], row["line"], row["method"]))
    gaps = set()
    if omissions:
        result["normalization_omissions"] = dict(sorted(omissions.items()))
        gaps.add(
            "Joern dataflow rows could not all be bound to distinct captured-source paths; omitted evidence remains unknown"
        )
    for section in (paths, skipped):
        if section["omitted"] or omissions:
            section["status"] = "partial"
    if result["methods_skipped"]:
        gaps.add("Joern dataflow skipped methods above its recorded definition limit")
    if queries["sinks_omitted"] or queries["paths_truncated"] or paths["count_is_lower_bound"]:
        gaps.add("Joern dataflow queries were bounded; missing paths remain unknown")
    if paths["omitted"] or skipped["omitted"]:
        gaps.add(
            "Joern dataflow detail was omitted; inspect its counts and source-linked retained paths"
        )
    if status == "partial" or paths["status"] != "complete" or skipped["status"] != "complete":
        gaps.add("Joern dataflow evidence is partial within its declared scope")
    if gaps:
        result["status"] = "partial"
    return result, gaps
