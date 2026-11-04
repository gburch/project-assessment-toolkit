"""Bind trusted Joern flow results to the captured source, without assigning scores."""

from __future__ import annotations

import hashlib
import json
import re
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
_CATEGORIES = ("named_effect_hint", "lifecycle_name_hint", "source_supported_cross_file", "breadth")
_KINDS = {"parameter_to_return", "parameter_to_operation"}
_TRACE_COUNTERS = (
    "sinks_eligible",
    "sinks_selected",
    "sinks_not_selected",
    "sinks_pending",
    "sinks_skipped",
    "engine_queries",
    "sinks_proven_empty",
)


class _EndpointMismatch(ValueError):
    pass


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


def _selection(value, queries, located):
    """Validate the complete ordered selected plan and its completed prefix."""
    if (
        not isinstance(value, dict)
        or set(value)
        not in (
            {"policy", "limit", "plan_digest", "endpoints"},
            {
                "policy",
                "limit",
                "plan_digest",
                "endpoints",
                "completed_endpoint_ids",
                "timed_out_endpoint_ids",
            },
        )
        or value["policy"] != "priority_file_method_round_robin_v1"
        or type(value["limit"]) is not int
        or value["limit"] != 2048
        or not isinstance(value["endpoints"], list)
        or len(value["endpoints"]) != queries["sinks_selected"]
        or len(value["endpoints"]) > value["limit"]
    ):
        raise ValueError("Invalid dataflow selection plan")
    explicit = "completed_endpoint_ids" in value
    completed = value.get("completed_endpoint_ids", [])
    timed_out = value.get("timed_out_endpoint_ids", [])
    if explicit and (
        not isinstance(completed, list)
        or not isinstance(timed_out, list)
        or any(not isinstance(item, str) for item in [*completed, *timed_out])
        or len(set(completed)) != len(completed)
        or len(set(timed_out)) != len(timed_out)
        or set(completed).intersection(timed_out)
        or len(completed) != queries["sinks_queried"]
        or len(timed_out) != queries.get("sinks_timed_out", 0)
    ):
        raise ValueError("Invalid completed/timeout endpoint identities")
    rows, ids = [], set()
    for index, row in enumerate(value["endpoints"]):
        if (
            not isinstance(row, dict)
            or set(row) != {"id", "category", "kind", "path", "line", "location_basis"}
            or not isinstance(row["id"], str)
            or re.fullmatch(r"[0-9a-f]{64}", row["id"]) is None
            or row["id"] in ids
            or row["category"] not in _CATEGORIES
            or row["kind"] not in _KINDS
            or row["location_basis"] not in {"node_line", "method_line"}
        ):
            raise ValueError("Invalid selected endpoint identity")
        location = located(
            {**row, "name": "<endpoint>", "method": "<plan>", "node_type": "PLANNED_ENDPOINT"}
        )
        ids.add(row["id"])
        rows.append(
            {
                **{key: location[key] for key in ("path", "line", "source_evidence_id", "digest")},
                **{key: row[key] for key in ("id", "category", "kind", "location_basis")},
                "status": (
                    "completed"
                    if row["id"] in completed
                    else "timed_out"
                    if row["id"] in timed_out
                    else "pending"
                )
                if explicit
                else "completed"
                if index < queries["sinks_queried"]
                else "pending",
            }
        )
    if explicit and not (set(completed) | set(timed_out)) <= ids:
        raise ValueError("Completed/timeout endpoints lie outside the selected plan")
    digest = hashlib.sha256("\n".join(row["id"] for row in rows).encode()).hexdigest()
    if value["plan_digest"] != digest:
        raise ValueError("Dataflow selection digest mismatch")
    categories = queries.get("by_category")
    if not isinstance(categories, dict) or set(categories) != set(_CATEGORIES):
        raise ValueError("Missing dataflow category coverage")
    safe_categories = {}
    for category in _CATEGORIES:
        counts = categories[category]
        if not isinstance(counts, dict) or set(counts) != {"candidates", "selected", "queried"}:
            raise ValueError("Invalid dataflow category counters")
        counts = {key: _count(number) for key, number in counts.items()}
        selected = sum(row["category"] == category for row in rows)
        completed_count = sum(
            row["category"] == category and row["status"] == "completed" for row in rows
        )
        if (
            not counts["candidates"]
            >= counts["selected"]
            == selected
            >= counts["queried"]
            == completed_count
        ):
            raise ValueError("Inconsistent dataflow category coverage")
        safe_categories[category] = counts
    if any(
        sum(counts[key] for counts in safe_categories.values()) != queries[field]
        for key, field in (
            ("candidates", "sinks_eligible"),
            ("selected", "sinks_selected"),
            ("queried", "sinks_queried"),
        )
    ):
        raise ValueError("Inconsistent total category coverage")
    return {
        "policy": value["policy"],
        "limit": value["limit"],
        "plan_digest": digest,
        "endpoints": rows,
        **(
            {"completed_endpoint_ids": completed, "timed_out_endpoint_ids": timed_out}
            if explicit
            else {}
        ),
    }, safe_categories


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
    traced = raw.get("query_version") == "8" or "selection" in value
    if traced:
        result["queries"].update((key, _count(queries.get(key))) for key in _TRACE_COUNTERS)
        if "sinks_timed_out" in queries:
            result["queries"]["sinks_timed_out"] = _count(queries["sinks_timed_out"])
            if queries["sinks_timed_out"] > queries["sinks_pending"]:
                raise ValueError("Timeout endpoints must remain unresolved")
        q = result["queries"]
        if (
            q["sinks_total"] != q["sinks_eligible"] + q["sinks_skipped"]
            or q["sinks_eligible"] != q["sinks_selected"] + q["sinks_not_selected"]
            or q["sinks_selected"] != q["sinks_queried"] + q["sinks_pending"]
            or q["sinks_queried"] != q["engine_queries"] + q["sinks_proven_empty"]
        ):
            raise ValueError("Inconsistent selected dataflow query counters")
        if "source_parameter_count" not in result:
            raise ValueError("Missing captured parameter count")

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

    completed_endpoints = {}
    if traced:
        result["selection"], result["queries"]["by_category"] = _selection(
            value.get("selection"),
            {**result["queries"], "by_category": queries.get("by_category")},
            located,
        )
        completed_endpoints = {
            row["id"]: row
            for row in result["selection"]["endpoints"]
            if row["status"] == "completed"
        }

    result["skipped_methods"] = _section(value.get("skipped_methods"), MAX_PATHS)
    result["paths"] = _section(value.get("paths"), MAX_PATHS, lower_bound=True)
    if traced and result["paths"]["count"] and not result["queries"]["engine_queries"]:
        raise ValueError("Proven-empty queries cannot produce path witnesses")
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
            if traced:
                endpoint = completed_endpoints.get(row.get("endpoint_id"))
                if (
                    endpoint is None
                    or endpoint["kind"] != row["kind"]
                    or (endpoint["path"], endpoint["line"]) != (end["path"], end["line"])
                    or endpoint["location_basis"] != "node_line"
                    or start["node_type"] != "METHOD_PARAMETER_IN"
                ):
                    raise _EndpointMismatch("Path is not bound to a completed endpoint")
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
            if traced:
                path["endpoint_id"] = row["endpoint_id"]
            if path["id"] in seen:
                omissions["duplicate_path"] += 1
                paths["omitted"] += 1
                continue
            seen.add(path["id"])
            paths["rows"].append(path)
        except _EndpointMismatch:
            raise
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
    if queries.get("sinks_timed_out"):
        gaps.add(
            "Individual Joern endpoint queries exceeded their wall allowance; these endpoints remain unknown, never proven empty"
        )
    if queries["sinks_omitted"] or queries["paths_truncated"] or paths["count_is_lower_bound"]:
        gaps.add("Joern dataflow queries were bounded; missing paths remain unknown")
    if traced and (
        queries["sinks_omitted"] or queries["paths_truncated"] or result["methods_skipped"]
    ):
        if status != "partial" or not paths["count_is_lower_bound"]:
            raise ValueError("Incomplete tracing must declare partial lower-bound paths")
    if paths["omitted"] or skipped["omitted"]:
        gaps.add(
            "Joern dataflow detail was omitted; inspect its counts and source-linked retained paths"
        )
    if status == "partial" or paths["status"] != "complete" or skipped["status"] != "complete":
        gaps.add("Joern dataflow evidence is partial within its declared scope")
    if gaps:
        result["status"] = "partial"
    return result, gaps
