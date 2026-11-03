"""Qualify Deep dataflow using the real contained Joern adapter on synthetic source.

Set PAT_JOERN_HOME and PAT_JOERN_JAVA_HOME to the qualified external tools, then run:
uv run --locked python scripts/test-joern-dataflow.py --output /tmp/pat-dataflow-proof

The fixtures are parsed, never imported, built or executed. This optional check is
separate from offline pytest; elapsed times are observations, not acceptance gates.
"""

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from pathlib import Path

from project_assess import joern_analysis as adapter

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/joern_dataflow"
LANGUAGES = ("python", "typescript", "java")


def digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def sources_for(language):
    return [
        {
            "path": "src/" + path.name.removesuffix(".txt"),
            "text": path.read_text(),
            "digest": digest(path.read_bytes()),
            "evidence_id": "e-fixture-" + path.name,
            "role": "production",
        }
        for path in sorted((FIXTURES / language).iterdir())
        if path.is_file()
    ]


def run_case(name, sources, output, profile="deep"):
    started = time.monotonic()
    result = adapter.analyze_joern(
        sources,
        snapshot={
            "root": str(output),
            "revision": "synthetic-dataflow-fixtures",
            "manifest_digest": digest(json.dumps(sources, sort_keys=True).encode()),
        },
        analysis_profile=profile,
    )
    (output / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
    return result, round(time.monotonic() - started, 3)


def fixture_checks(result):
    flow = result.get("dataflow_analysis", {})
    paths = flow.get("paths", [])

    def method(node, name):
        # Frontends qualify method names differently; fixture names are distinct.
        return name in node.get("method", "")

    cross_file = [
        row
        for row in paths
        if row["source"]["name"] == "payload"
        and method(row["source"], "entry")
        and len({step["path"] for step in row["steps"]}) > 1
        and row["interprocedural"]
    ]
    overwrite_paths = [
        row
        for row in paths
        if row["kind"] == "parameter_to_return" and method(row["sink"], "overwritten")
    ]
    entry_names = {row["source"]["name"] for row in overwrite_paths}
    candidates = result.get("candidate_index", [])
    checks = {
        "deep_dataflow_completed": flow.get("status") == "complete",
        "all_fixture_files_modeled": result.get("coverage", {}).get("modeled_files")
        == result.get("coverage", {}).get("eligible_files"),
        "cross_file_parameter_flow": bool(cross_file),
        "operation_flow": any(row["kind"] == "parameter_to_operation" for row in paths),
        "cross_file_caller_to_operation": any(
            row["kind"] == "parameter_to_operation"
            and row["source"]["name"] in {"operation_payload", "operationPayload"}
            and method(row["sink"], "relay")
            and len({step["path"] for step in row["steps"]}) > 1
            and row["interprocedural"]
            for row in paths
        ),
        "unrelated_parameter_not_operation_input": not any(
            row["kind"] == "parameter_to_operation"
            and row["source"]["name"] in {"unrelated_payload", "unrelatedPayload"}
            for row in paths
        ),
        "replacement_reaches_return": "replacement" in entry_names,
        "overwritten_source_does_not_reach_return": "obsolete" not in entry_names
        and "replacement" in entry_names,
        "callback_parameter_not_cleanup": not any(
            row.get("metrics", {}).get("symbol") in {"unused_context", "unusedContext"}
            for row in candidates
        ),
        "binding_leads_preserve_initializer_warning": all(
            "initializer" in row.get("caveat", "").lower()
            for row in candidates
            if row.get("metrics", {}).get("symbol") == "unused"
        ),
        "flow_steps_have_source_identity": bool(paths)
        and all(
            step.get("source_evidence_id") and step.get("digest", "").startswith("sha256:")
            for row in paths
            for step in row["steps"]
        ),
    }
    return checks


def synthetic_source(name, text):
    return {
        "path": "src/" + name + ".py",
        "text": text,
        "digest": digest(text.encode()),
        "evidence_id": "e-" + name,
        "role": "production",
    }


def bounded_query_probes(output):
    """Query over 64 independent endpoints and overflow one sink's path detail."""
    receipts = []
    # Separate reads keep this an endpoint check rather than a 64-step test:
    # Joern can chain repeated reads of the same parameter through prior calls.
    text = "".join(
        f"def cohort_{index}(payload_{index}):\n    print(payload_{index})\n\n"
        for index in range(70)
    )
    sources = [synthetic_source("cohort", text)]
    (output / "cohort-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    result, seconds = run_case("cohort", sources, output)
    flow = result.get("dataflow_analysis", {})
    batches = flow.get("batches", [])
    queries = batches[0].get("queries", {}) if len(batches) == 1 else {}
    retained_endpoints = {
        (row["sink"]["line"], row["source"]["name"])
        for row in flow.get("paths", [])
        if row["kind"] == "parameter_to_operation"
        and row["source"]["name"].startswith("payload_")
        and "cohort" in row["sink"]["method"]
    }
    receipts.append({
        "case": "cohort", "seconds": seconds,
        "checks": {
            "dataflow_complete": flow.get("status") == "complete",
            "more_than_sixty_four_sinks": queries.get("sinks_total", 0) > 64,
            "all_sinks_queried": queries.get("sinks_queried") == queries.get("sinks_total")
            and queries.get("sinks_omitted") == 0,
            "under_cap_scope_preserved": queries.get("sinks_selected") == queries.get("sinks_eligible")
            and queries.get("sinks_not_selected") == 0,
            "all_seventy_operation_endpoints_retained": retained_endpoints
            == {(2 + 3 * index, f"payload_{index}") for index in range(70)},
            "no_path_detail_truncation": queries.get("paths_truncated") == 0,
        },
    })
    print(json.dumps(receipts[-1]), flush=True)

    names = [f"value_{index}" for index in range(70)]
    text = "from fanin_service import emit\n\n" + "".join(
        f"def caller_{index}({name}, unrelated_{index}):\n    emit({name})\n\n"
        for index, name in enumerate(names)
    )
    sources = [
        synthetic_source("fanin", text),
        synthetic_source("fanin_service", 'def emit(value):\n    print(value)\n    return "handled"\n'),
    ]
    (output / "fanin-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    result, seconds = run_case("fanin", sources, output)
    flow = result.get("dataflow_analysis", {})
    batches = flow.get("batches", [])
    batch = batches[0] if len(batches) == 1 else {}
    paths = [
        row for row in flow.get("paths", [])
        if row["kind"] == "parameter_to_operation" and "emit" in row["sink"]["method"]
    ]
    receipts.append({
        "case": "fanin", "seconds": seconds,
        "checks": {
            "overfull_sink_is_partial": flow.get("status") == "partial",
            "sink_truncation_reported": batch.get("queries", {}).get("paths_truncated", 0) > 0,
            "path_count_is_lower_bound": batch.get("paths", {}).get("count_is_lower_bound") is True,
            "sixty_four_paths_retained_for_single_sink": len(paths) == 64
            and len({(row["sink"]["path"], row["sink"]["line"]) for row in paths}) == 1,
            "only_reaching_value_parameters_retained": bool(paths)
            and all(row["source"]["name"] in {*names, "value"} for row in paths),
            "cross_file_caller_paths_retained": any(
                row["source"]["name"] in names and row["interprocedural"]
                and len({step["path"] for step in row["steps"]}) > 1 for row in paths
            ),
        },
    })
    print(json.dumps(receipts[-1]), flush=True)
    return receipts


def over_limit_probe(output):
    """Observe the unchanged 50k definition skip while a normal method retains flow."""
    text = (
        "def over_limit(payload):\n"
        + "".join(f"    value_{index} = payload\n" for index in range(17000))
        + "    return value_16999\n\n"
        + "def normal(retained):\n    return retained\n"
    )
    sources = [synthetic_source("over_limit", text)]
    (output / "over-limit-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    result, seconds = run_case("over-limit", sources, output)
    combined = result.get("dataflow_analysis", {})
    batches = combined.get("batches", [])
    flow = batches[0] if len(batches) == 1 else {}
    skipped = flow.get("skipped_methods", {}).get("rows", [])
    paths = combined.get("paths", [])
    checks = {
        "method_exceeds_unchanged_definition_limit": flow.get("maximum_definitions_observed", 0) > 50000,
        "over_limit_skip_has_source_bound_receipt": any(
            "over_limit" in row["method"] and row["definitions"] > 50000
            and row["reason"] == "definition_limit" and row.get("source_evidence_id")
            for row in skipped
        ),
        "skipped_flow_remains_partial": combined.get("status") == "partial"
        and flow.get("methods_skipped", 0) > 0,
        "normal_method_still_has_parameter_flow": any(
            row["kind"] == "parameter_to_return" and row["source"]["name"] == "retained"
            and ".normal" in row["source"]["method"] and ".normal" in row["sink"]["method"]
            for row in paths
        ),
        "skipped_method_has_no_claimed_paths": not any(
            ".over_limit" in row["source"]["method"] or ".over_limit" in row["sink"]["method"]
            for row in paths
        ),
        "all_phases_completed": bool(batches) and all(
            batch.get("phase_progress", {}).get("status") == "complete" for batch in result["coverage"]["batches"]
        ),
    }
    return {"case": "over-limit", "seconds": seconds, "checks": checks}


def recovery_probe(output):
    """Fail a private trusted query after its checkpoint; never alter production code."""
    production_path = adapter.QUERY_PATH
    production = production_path.read_bytes()
    marker = b"// PAT_DATAFLOW_CHECKPOINT_COMPLETE"
    if production.count(marker) != 1:
        raise ValueError("Expected one trusted dataflow checkpoint marker")
    fault_path = output / "recovery-fault.sc"
    fault = production.replace(marker, b'throw new OutOfMemoryError("synthetic recovery probe")', 1)
    fault_path.write_bytes(fault)
    fault_path.chmod(0o400)
    try:
        adapter.QUERY_PATH = fault_path
        result, seconds = run_case("recovery-fault", sources_for("python"), output)
    finally:
        adapter.QUERY_PATH = production_path
    batches = result.get("coverage", {}).get("batches", [])
    flow = result.get("dataflow_analysis", {})
    checks = {
        "query_process_failed": bool(batches)
        and all(batch.get("process_status") != "complete" for batch in batches),
        "immutable_base_checkpoint_recovered": bool(batches)
        and all(batch.get("base_checkpoint_recovered") for batch in batches),
        "all_source_files_modeled_after_recovery": result.get("coverage", {}).get("modeled_files")
        == len(sources_for("python")),
        "base_methods_retained": (result.get("summary", {}).get("methods") or 0) > 0,
        "base_calls_retained": (result.get("summary", {}).get("calls") or 0) > 0,
        "failed_dataflow_remains_unknown": flow.get("status") == "error"
        and flow.get("paths") == [],
        "production_query_unchanged": production_path.read_bytes() == production,
    }
    return {
        "case": "recovery-fault",
        "seconds": seconds,
        "production_query_sha256": hashlib.sha256(production).hexdigest(),
        "fault_query_sha256": hashlib.sha256(fault).hexdigest(),
        "injection": "Trusted private query throws after checkpoint, before dataflow; final output is overwritten and process fails.",
        "checks": checks,
    }


def count_mismatch_probe(output):
    """A swallowed worker failure must not establish an overlay or usable paths."""
    production_path = adapter.QUERY_PATH
    production = production_path.read_bytes()
    expected = b"val expected = definitionCounts(method.id)"
    caught = b'errors.value += Obj("section" -> "dataflow_analysis", "error" -> error.getClass.getName)'
    if production.count(expected) != 1 or production.count(caught) != 1:
        raise ValueError("Expected one trusted definition guard and dataflow catch")
    fault = production.replace(expected, expected + b" + 1L", 1).replace(
        caught,
        caught + b'\n        result("metadata")("overlays") = Arr.from(cpg.metaData.overlays.toVector.distinct.sorted)',
        1,
    )
    fault_path = output / "count-mismatch.sc"
    fault_path.write_bytes(fault)
    fault_path.chmod(0o400)
    implementation = {
        Path(adapter.__file__).with_name(name): digest(Path(adapter.__file__).with_name(name).read_bytes())
        for name in ("joern_analysis.py", "joern_dataflow.py", "joern_bindings.py")
    }
    original_run, producer = adapter._run, []

    def run(argv, **kwargs):
        status = original_run(argv, **kwargs)
        if path := kwargs.get("output"):
            if path.is_file():
                raw = json.loads(path.read_text())
                producer.append({
                    "process_status": status, "dataflow": raw.get("dataflow"),
                    "flow_status": raw.get("dataflow_analysis", {}).get("status"),
                    "overlays_after_failure": raw.get("metadata", {}).get("overlays", []),
                    "errors": raw.get("errors", []),
                })
        return status

    try:
        adapter.QUERY_PATH, adapter._run = fault_path, run
        result, seconds = run_case("count-mismatch", sources_for("python"), output)
    finally:
        adapter.QUERY_PATH, adapter._run = production_path, original_run
    (output / "count-mismatch-producer.json").write_text(json.dumps(producer, indent=2) + "\n")
    flow = result.get("dataflow_analysis", {})
    checks = {
        "producer_rejected_count_mismatch": bool(producer) and all(
            row["dataflow"] == row["flow_status"] == "error" for row in producer
        ),
        "overlay_not_falsely_established": bool(producer) and all(
            "dataflowOss" not in row["overlays_after_failure"] for row in producer
        ),
        "no_usable_flow_paths": flow.get("paths") == [],
        "worker_failure_remains_unknown": flow.get("status") in {"error", "partial"}
        and result.get("status") != "complete",
        "base_methods_retained": (result.get("summary", {}).get("methods") or 0) > 0,
        "production_query_unchanged": production_path.read_bytes() == production,
        "implementation_unchanged": all(digest(path.read_bytes()) == value for path, value in implementation.items()),
    }
    return {
        "case": "count-mismatch", "seconds": seconds, "checks": checks,
        "production_query_sha256": hashlib.sha256(production).hexdigest(),
        "fault_query_sha256": hashlib.sha256(fault).hexdigest(),
        "implementation_hashes": {str(path): value for path, value in implementation.items()},
        "injection": "Trusted private worker expects the native definition count plus one; capture actual graph overlays in the error handler before adapter recovery.",
    }


def empty_shortcut_probe(output):
    """Compare the exact-empty shortcut with Engine execution on the same source."""
    production_path = adapter.QUERY_PATH
    production = production_path.read_bytes()
    overlay = b'phase("dataflow_overlay_completed")'
    decision = b"val empty = provenEmptyStarter(sink)"
    if production.count(overlay) != 1 or production.count(decision) != 1:
        raise ValueError("Expected one qualified overlay and initial-starter decision")
    audit = b'''
        def probeHasIncoming(node: CfgNode): Boolean = node.inE("REACHING_DEF").exists {
          edge => edge.src match {
            case parent: CfgNode => !parent.isInstanceOf[Method]
            case _ => false
          }
        }
        val excludedProbe = Seq(
          "METHOD_PARAMETER_IN" -> cpg.method.parameter.toVector.map(node => node: CfgNode),
          "CALL" -> cpg.call.toVector.map(node => node: CfgNode),
          "METHOD_REF" -> cpg.methodRef.toVector.map(node => node: CfgNode)
        ).map { case (kind, nodes) =>
          val zero = nodes.filterNot(probeHasIncoming)
          kind -> Obj("zero_ddg_nodes" -> zero.size,
            "all_refused" -> Bool(zero.forall(node => !provenEmptyStarter(node))))
        }
        result("starter_probe") = Obj.from(excludedProbe)
'''
    sources = [synthetic_source("empty_starters", (
        "def identity(value):\n    return value\n\n"
        "def call_argument(value):\n    print(identity(value))\n\n"
        'def literal_only():\n    print("fixed")\n    return "fixed"\n\n'
        "def empty_call():\n    return unknown()\n\n"
        "def callback(value):\n    return lambda: value\n\n"
        "def callback_argument(value):\n    print(lambda: value)\n"
    ))]
    (output / "empty-shortcut-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    results, proofs, times = {}, {}, {}
    original_run = adapter._run
    for mode in ("enabled", "disabled"):
        query = production.replace(overlay, overlay + audit, 1)
        if mode == "disabled":
            query = query.replace(decision, b"val empty = false", 1)
        path = output / ("empty-shortcut-" + mode + ".sc")
        path.write_bytes(query)
        path.chmod(0o400)

        def run(argv, *, probe_mode=mode, **kwargs):
            status = original_run(argv, **kwargs)
            if producer := kwargs.get("output"):
                if producer.is_file():
                    proofs[probe_mode] = json.loads(producer.read_text()).get("starter_probe", {})
            return status

        try:
            adapter.QUERY_PATH, adapter._run = path, run
            results[mode], times[mode] = run_case("empty-shortcut-" + mode, sources, output)
        finally:
            adapter.QUERY_PATH, adapter._run = production_path, original_run
    (output / "empty-shortcut-starter-proof.json").write_text(json.dumps(proofs, indent=2) + "\n")
    enabled, disabled = (results[mode]["dataflow_analysis"] for mode in ("enabled", "disabled"))

    def core_paths(flow):
        return {json.dumps({key: value for key, value in row.items() if key != "endpoint_id"}, sort_keys=True)
                for row in flow["paths"]}

    checks = {
        "complete_flow_on_both_paths": enabled["status"] == disabled["status"] == "complete",
        "nonempty_semantic_paths_and_ids_preserved": bool(enabled["paths"])
        and core_paths(enabled) == core_paths(disabled),
        "parameter_call_argument_flow_preserved": any(
            row["kind"] == "parameter_to_operation" and row["sink"]["node_type"] == "CALL"
            and "call_argument" in row["sink"]["method"] for row in enabled["paths"]
        ),
        "special_zero_ddg_starters_never_bypassed": all(
            proofs.get(mode, {}).get(kind, {}).get("zero_ddg_nodes", 0) > 0
            and proofs[mode][kind]["all_refused"]
            for mode in ("enabled", "disabled") for kind in ("METHOD_PARAMETER_IN", "CALL", "METHOD_REF")
        ),
        "ordinary_empty_shortcut_exercised": sum(batch["queries"]["sinks_proven_empty"]
                                                 for batch in enabled["batches"]) > 0,
        "disabled_shortcut_uses_engine": all(batch["queries"]["sinks_proven_empty"] == 0
                                            for batch in disabled["batches"]),
        "production_query_unchanged": production_path.read_bytes() == production,
    }
    return {"case": "empty-shortcut", "seconds": times, "checks": checks,
            "production_query_sha256": hashlib.sha256(production).hexdigest()}


def selection_breadth_probe(output):
    """Exercise the production cap with competing files, methods and priorities."""
    sources, fat_ranges = [], {}
    large_files = (
        ("src/selection_a.py", "production"), ("src/selection_b.py", "production"),
        ("tests/test_selection.py", "test"), ("tools/selection.py", "tooling"),
    )
    for path, role in large_files:
        text = ""
        if path == "src/selection_a.py":
            text = (
                "from selection_service import relay\n\n"
                "def effect_priority(payload):\n    send(payload)\n\n"
                "def close(payload):\n    return payload\n\n"
                "def cross_file(payload):\n    return relay(payload)\n\n"
            )
        text += "".join(f"def method_{index}(payload):\n    return payload\n\n" for index in range(600))
        if path == "src/selection_a.py":
            first = len(text.splitlines()) + 1
            text += "def noisy(" + ", ".join(f"value_{index}" for index in range(100)) + "):\n"
            text += "".join(f"    print(value_{index})\n" for index in range(100))
            fat_ranges[path] = (first, len(text.splitlines()))
        row = synthetic_source(path.replace("/", "_"), text)
        row.update(path=path, role=role)
        sources.append(row)
    service = synthetic_source("selection_service", "def relay(value):\n    return value\n")
    sources.append(service)
    (output / "selection-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    first, first_seconds = run_case("selection-first", sources, output)
    repeated, repeated_seconds = run_case("selection-repeated", sources, output)
    first_flow, second_flow = (result.get("dataflow_analysis", {}) for result in (first, repeated))
    batch = first_flow["batches"][0] if first_flow.get("batches") else {}
    again = second_flow["batches"][0] if second_flow.get("batches") else {}
    queries = batch.get("queries", {})
    selection = batch.get("selection", {})
    endpoints = selection.get("endpoints", [])
    roles = {row["path"]: row["role"] for row in sources}
    breadth = Counter(row["path"] for row in endpoints if row["category"] == "breadth")
    counts = [breadth[path] for path, _ in large_files]
    categories = {row["category"] for row in endpoints}
    all_categories = {"named_effect_hint", "lifecycle_name_hint", "source_supported_cross_file", "breadth"}
    checks = {
        "scope_exceeds_production_cap": queries.get("sinks_eligible", 0) > 2048,
        "cap_and_not_selected_are_explicit": queries.get("sinks_selected") == len(endpoints) == 2048
        and queries.get("sinks_not_selected") == queries.get("sinks_eligible", 0) - 2048,
        "selected_work_completed": queries.get("sinks_pending") == 0
        and queries.get("sinks_queried") == queries.get("sinks_selected"),
        "all_priority_categories_receive_a_turn": categories == all_categories
        and {row["category"] for row in endpoints[:4]} == all_categories,
        "files_and_roles_receive_breadth": set(roles) <= {row["path"] for row in endpoints}
        and {roles[row["path"]] for row in endpoints} == {"production", "test", "tooling"},
        "breadth_files_rotate_fairly": min(counts) > 0 and max(counts) - min(counts) <= 1,
        "one_large_method_does_not_consume_file_quota": all(
            sum(row["path"] == path and start <= row["line"] <= end for row in endpoints
                if row["category"] == "breadth") <= 1
            for path, (start, end) in fat_ranges.items()
        ),
        "fresh_workspace_plan_is_deterministic": bool(endpoints)
        and selection == again.get("selection"),
        "unselected_scope_remains_partial": first_flow.get("status") == second_flow.get("status") == "partial"
        and batch.get("paths", {}).get("count_is_lower_bound") is True,
    }
    return {"case": "selection-breadth", "seconds": {"first": first_seconds, "repeated": repeated_seconds},
            "checks": checks}


def flow_checkpoint_probe(output):
    """Exit a private query after its first saved witness, before remaining work."""
    production_path = adapter.QUERY_PATH
    production = production_path.read_bytes()
    marker = b"if (rows.count > 0) firstWitnessSaved = true"
    if production.count(marker) != 1:
        raise ValueError("Expected one successful first-witness checkpoint hook")
    fault = production.replace(
        marker, marker + b"\n          if (rows.count > 0 && sinksQueried < selected.size) System.exit(23)", 1
    )
    query = output / "flow-checkpoint-exit.sc"
    query.write_bytes(fault)
    query.chmod(0o400)
    original_run = adapter._run

    def run(argv, **kwargs):
        status = original_run(argv, **kwargs)
        if path := kwargs.get("output"):
            for suffix, name in ((".base.json", "flow-checkpoint-base.json"),
                                 (".flow.json", "flow-checkpoint-producer.json")):
                companion = Path(str(path) + suffix)
                if companion.is_file():
                    (output / name).write_bytes(companion.read_bytes())
        return status

    try:
        adapter.QUERY_PATH, adapter._run = query, run
        result, seconds = run_case("flow-checkpoint", sources_for("python"), output)
    finally:
        adapter.QUERY_PATH, adapter._run = production_path, original_run
    batches = result.get("coverage", {}).get("batches", [])
    flow = result.get("dataflow_analysis", {})
    checkpoint = output / "flow-checkpoint-producer.json"
    base = output / "flow-checkpoint-base.json"
    value = json.loads(checkpoint.read_text()) if checkpoint.is_file() else {}
    checks = {
        "owned_failure_after_saved_witness": bool(batches)
        and all(batch["process_status"] != "complete" for batch in batches),
        "base_and_flow_checkpoint_recovered": bool(batches) and all(
            batch["base_checkpoint_recovered"] and batch["flow_checkpoint_recovered"] for batch in batches
        ),
        "completed_paths_retained_as_partial": bool(flow.get("paths")) and flow.get("status") == "partial",
        "remaining_selected_work_stays_pending": any(
            batch.get("queries", {}).get("sinks_pending", 0) > 0 for batch in flow.get("batches", [])
        ),
        "checkpoint_bound_to_exact_base": base.is_file()
        and value.get("base_sha256") == hashlib.sha256(base.read_bytes()).hexdigest(),
        "no_worker_failure_invented": bool(batches) and all(
            not batch["producer_diagnostics"]["engine_failed"] for batch in batches
        ),
        "metrics_are_labeled_as_base": bool(batches)
        and all(batch["model_metrics_scope"] == "base_before_dataflow" for batch in batches),
        "production_query_unchanged": production_path.read_bytes() == production,
    }
    return {"case": "flow-checkpoint", "seconds": seconds, "checks": checks,
            "production_query_sha256": hashlib.sha256(production).hexdigest(),
            "fault_query_sha256": hashlib.sha256(fault).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New directory outside checkout")
    parser.add_argument("--language", choices=LANGUAGES, action="append")
    parser.add_argument(
        "--skip-large", action="store_true", help="Omit the large Python method probe"
    )
    parser.add_argument(
        "--over-limit-probe", action="store_true",
        help="Also qualify a method above the unchanged 50,000-definition limit",
    )
    parser.add_argument(
        "--recovery-probe",
        action="store_true",
        help="Also inject a trusted query failure to qualify immutable checkpoint recovery",
    )
    parser.add_argument(
        "--count-mismatch-probe", action="store_true",
        help="Also force a private worker definition mismatch and verify fail-closed output",
    )
    parser.add_argument(
        "--empty-shortcut-probe", action="store_true",
        help="Also compare shortcut-on/off paths and inspect excluded zero-DDG starter types",
    )
    parser.add_argument(
        "--selection-breadth-probe", action="store_true",
        help="Also qualify production-cap selection fairness and fresh-workspace plan stability",
    )
    parser.add_argument(
        "--flow-checkpoint-probe", action="store_true",
        help="Also exit a private query after its first saved witness and qualify partial recovery",
    )
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.is_relative_to(ROOT):
        parser.error("Output must be outside the checkout")
    home, java, _, _, _ = adapter._tools()
    if home.is_relative_to(ROOT) or java.is_relative_to(ROOT):
        parser.error("Operator tools must be outside the checkout")
    if adapter._sandbox()[0] is None:
        parser.error("Qualified OS containment is unavailable")
    os.umask(0o077)
    output.mkdir(parents=True, exist_ok=False)
    original_fixtures = {
        str(path): digest(path.read_bytes()) for path in FIXTURES.rglob("*") if path.is_file()
    }
    implementation = {
        str(Path(adapter.__file__).with_name(name)): digest(
            Path(adapter.__file__).with_name(name).read_bytes()
        )
        for name in ("joern_analysis.py", "joern_dataflow.py", "joern_bindings.py")
    }
    query = adapter.QUERY_PATH.read_bytes()
    receipts = []
    for language in args.language or LANGUAGES:
        result, seconds = run_case(language, sources_for(language), output)
        checks = fixture_checks(result)
        receipts.append({"case": language, "seconds": seconds, "checks": checks})
        print(json.dumps(receipts[-1]), flush=True)

    standard, seconds = run_case("standard", sources_for("python"), output, "standard")
    receipts.append(
        {
            "case": "standard",
            "seconds": seconds,
            "checks": {
                "dataflow_not_run": standard.get("dataflow_analysis", {}).get("status") == "not_run"
            },
        }
    )
    receipts.extend(bounded_query_probes(output))
    if not args.skip_large:
        # Distinct reaching definitions exceed the old 4,000-definition ceiling.
        # The text is input to static analysis only, never executed.
        text = (
            "def large(payload):\n"
            + "".join(f"    value_{index} = payload\n" for index in range(4200))
            + "    return value_4199\n"
        )
        sources = [
            {
                "path": "src/large.py",
                "text": text,
                "digest": digest(text.encode()),
                "evidence_id": "e-large",
                "role": "production",
            }
        ]
        result, seconds = run_case("large", sources, output)
        combined = result.get("dataflow_analysis", {})
        batches = combined.get("batches", [])
        flow = batches[0] if len(batches) == 1 else {}
        checks = {
            "method_exceeds_former_threshold": flow.get("maximum_definitions_observed", 0) > 4000,
            "large_method_not_skipped": flow.get("methods_skipped") == 0,
            "large_method_flow_found": any(
                row["source"]["name"] == "payload" and row["kind"] == "parameter_to_return"
                for row in combined.get("paths", [])
            ),
        }
        receipts.append({"case": "large", "seconds": seconds, "checks": checks})
        print(json.dumps(receipts[-1]), flush=True)
    if args.over_limit_probe:
        receipts.append(over_limit_probe(output))
        print(json.dumps(receipts[-1]), flush=True)
    if args.recovery_probe:
        receipts.append(recovery_probe(output))
        print(json.dumps(receipts[-1]), flush=True)
    if args.count_mismatch_probe:
        receipts.append(count_mismatch_probe(output))
        print(json.dumps(receipts[-1]), flush=True)
    if args.empty_shortcut_probe:
        receipts.append(empty_shortcut_probe(output))
        print(json.dumps(receipts[-1]), flush=True)
    if args.selection_breadth_probe:
        receipts.append(selection_breadth_probe(output))
        print(json.dumps(receipts[-1]), flush=True)
    if args.flow_checkpoint_probe:
        receipts.append(flow_checkpoint_probe(output))
        print(json.dumps(receipts[-1]), flush=True)
    unchanged = all(
        Path(path).is_file() and digest(Path(path).read_bytes()) == value
        for path, value in original_fixtures.items()
    )
    receipt = {
        "status": "passed"
        if unchanged and all(all(case["checks"].values()) for case in receipts)
        else "failed",
        "query_sha256": hashlib.sha256(query).hexdigest(),
        "query_unchanged": query == adapter.QUERY_PATH.read_bytes(),
        "implementation_hashes": implementation,
        "implementation_unchanged": all(
            digest(Path(path).read_bytes()) == value for path, value in implementation.items()
        ),
        "fixture_hashes": original_fixtures,
        "fixtures_unchanged": unchanged,
        "target_code_executed": False,
        "cases": receipts,
        "scope": "Synthetic supported-language dataflow cases; no proof of whole-project completeness or safe deletion.",
    }
    if not receipt["query_unchanged"] or not receipt["implementation_unchanged"]:
        receipt["status"] = "failed"
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    if receipt["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
