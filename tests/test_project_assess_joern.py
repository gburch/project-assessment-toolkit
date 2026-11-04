"""Contained optional-provider boundaries and declaration normalization, without Java."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from project_assess import joern_analysis as analysis

FLOW_CATEGORIES = (
    "named_effect_hint", "lifecycle_name_hint", "source_supported_cross_file", "breadth",
)
TEST_RUN_TOKEN = "a" * 32


def flow_selection(endpoints):
    return {
        "policy": "priority_file_method_round_robin_v1",
        "limit": 2048,
        "plan_digest": hashlib.sha256("\n".join(row["id"] for row in endpoints).encode()).hexdigest(),
        "endpoints": endpoints,
    }


def flow_endpoint(path, line, category, kind="parameter_to_operation", identity="first"):
    return {
        "id": hashlib.sha256(f"{path}:{line}:{kind}:{identity}".encode()).hexdigest(),
        "category": category, "kind": kind, "path": path, "line": line,
        "location_basis": "node_line",
    }


def source(path="src/app.py", text="def _call(context):\n    unused = value()\n    return run()\n"):
    return {
        "path": path,
        "text": text,
        "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
        "evidence_id": "e-" + path,
        "role": "production",
    }


def raw_result(path):
    method = {
        "path": path,
        "line": 1,
        "name": "call",
        "full_name": "call",
        "is_external": False,
        "is_abstract": False,
        "is_constructor": False,
        "has_body": True,
    }
    binding = {
        "path": path,
        "line": 1,
        "symbol": "context",
        "binding_kind": "parameter",
        "method_name": "call",
        "method_full_name": "call",
        "is_abstract": False,
        "is_constructor": False,
        "has_body": True,
        "read_count": 0,
        "reference_count": 0,
        "cleanup_status": "review_candidate",
        "capture_status": "not_captured",
        "signature_status": "private_direct_only",
        "basis": "identifier_REF_reads_with_capture_and_function_escape_checks",
    }

    def section(rows):
        return {"status": "complete", "count": len(rows), "omitted": 0, "rows": rows}

    return {
        "schema_version": 1,
        "query_version": "9",
        "run_token": TEST_RUN_TOKEN,
        "dataflow": "not_run",
        "errors": [],
        "gaps": [],
        "metadata": {
            "languages": ["PYTHONSRC"],
            "overlays": ["base", "controlflow"],
            "max_heap_bytes": 2 * 1024**3,
            "active_processors": 2,
            "java_version": "21.0.13",
        },
        "metrics": {
            "nodes": 24,
            "edges": 30,
            "methods": 2,
            "calls": 3,
            "edge_counts": {"CFG": 8, "REF": 6, "CALL": 1, "CDG": 0},
        },
        "source_files": section([{"path": path}]),
        "methods": {
            **section([method]),
            "external_models": 17,
            "unlocated_models": 2,
            "sampling": "max_min_per_file_then_round_robin",
            "source_files": 1,
            "retained_files": 1,
            "omitted_files": 0,
            "row_byte_limit": 6 * 1024**2 - 256 * 1024 - 4096,
            "byte_omissions": 0,
            "file_coverage": {
                "status": "complete",
                "count": 1,
                "omitted": 0,
                "limit": 1,
                "byte_limit": 256 * 1024,
                "rows": [{"path": path, "count": 1, "retained": 1, "identity_truncated": False}],
            },
        },
        "calls": section(
            [
                {
                    "path": path,
                    "line": 3,
                    "caller_name": "call",
                    "caller_full_name": "call",
                    "target_path": path,
                    "target_name": "call",
                    "target_full_name": "call",
                    "resolution": "internal",
                    "dependency_status": "source_supported",
                    "dependency_basis": "captured_named_call",
                }
            ]
        ),
        "module_edges": {
            **section([{"source": path, "target": path, "count": 7}]),
            "count_is_lower_bound": False,
            "occurrences": 7,
            "omitted_occurrences": 0,
        },
        "inferred_module_edges": {**section([]), "count_is_lower_bound": False},
        "unread_bindings": {
            **section(
                [
                    binding,
                    {
                        **binding,
                        "line": 2,
                        "symbol": "unused",
                        "binding_kind": "local",
                        "signature_status": "not_applicable",
                    },
                ]
            ),
            "suppressed": {"captured_binding": 3},
            "captured_declarations": 3,
        },
    }


@pytest.fixture
def qualified(tmp_path, monkeypatch):
    monkeypatch.setattr(analysis.uuid, "uuid4", lambda: analysis.uuid.UUID(hex=TEST_RUN_TOKEN))
    home, java = tmp_path / "tools", tmp_path / "jdk"
    home.mkdir()
    java.mkdir()
    query = home / "query.sc"
    query.write_text("// trusted synthetic query\n")
    paths = {name: home / name for name in (*analysis._FRONTENDS, "repl", "astgen", "swift_astgen")}
    paths["query"] = query
    hashes = {"query": analysis._hash_file(query)}
    monkeypatch.setattr(analysis, "_tools", lambda: (home, java, paths, "21.0.13", hashes))
    monkeypatch.setattr(analysis, "_sandbox", lambda: ("macos-sandbox-exec", "/synthetic/sandbox"))
    root = tmp_path / "original"
    root.mkdir()
    return {"root": str(root), "revision": "synthetic", "manifest_digest": "sha256:snapshot"}


def fake_run(argv, *, cwd, output=None, **kwargs):
    if not output and "ASTGEN_BIN" in kwargs.get("env", {}):
        (kwargs["workspace"] / "ast-compatibility.json").write_text(
            json.dumps({"schema_version": 1, "files": []})
        )
    if output:
        path = next((cwd / "source").rglob("*.*")).relative_to(cwd / "source").as_posix()
        raw = raw_result(path)
        raw["run_token"] = next(
            (value.removeprefix("runToken=") for value in argv if value.startswith("runToken=")),
            "0" * 32,
        )
        if "profile=deep" in argv:
            raw["dataflow"] = "complete"
            raw["metadata"]["overlays"].append("dataflowOss")
            raw["dataflow_analysis"] = {
                "status": "complete",
                "max_definitions": 50_000,
                "maximum_definitions_observed": 0,
                "max_call_depth": 8,
                "methods_total": 0,
                "methods_analyzed": 0,
                "methods_skipped": 0,
                "source_parameter_count": 0,
                "skipped_methods": {"status": "complete", "count": 0, "omitted": 0, "rows": []},
                "paths": {
                    "status": "complete",
                    "count": 0,
                    "omitted": 0,
                    "count_is_lower_bound": False,
                    "rows": [],
                },
                "queries": {
                    "sinks_total": 0,
                    "sinks_queried": 0,
                    "sinks_omitted": 0,
                    "paths_truncated": 0,
                    "step_limit": 64,
                    "sinks_eligible": 0,
                    "sinks_selected": 0,
                    "sinks_not_selected": 0,
                    "sinks_pending": 0,
                    "sinks_skipped": 0,
                    "engine_queries": 0,
                    "sinks_proven_empty": 0,
                    "by_category": {
                        name: {"candidates": 0, "selected": 0, "queried": 0}
                        for name in FLOW_CATEGORIES
                    },
                },
                "selection": flow_selection([]),
            }
            raw["methods"]["row_byte_limit"] = 48 * 1024**2 - 2 * 1024**2 - 4096
            raw["methods"]["file_coverage"]["byte_limit"] = 2 * 1024**2
        output.write_text(json.dumps(raw))
    return "complete"


def partial_flow_result(raw, path="src/app.py"):
    """One completed operation path and one selected return still pending."""
    start = {"path": path, "line": 1, "name": "context", "method": "call",
             "node_type": "METHOD_PARAMETER_IN"}
    end = {"path": path, "line": 3, "name": "context", "method": "call",
           "node_type": "IDENTIFIER"}
    endpoints = [
        flow_endpoint(path, 3, "named_effect_hint"),
        flow_endpoint(path, 4, "breadth", "parameter_to_return", "pending"),
    ]
    raw["dataflow"] = "partial"
    flow = raw["dataflow_analysis"]
    flow.update(status="partial", methods_total=1, methods_analyzed=1,
                source_parameter_count=1, selection=flow_selection(endpoints))
    flow["queries"].update(
        sinks_total=2, sinks_eligible=2, sinks_selected=2, sinks_not_selected=0,
        sinks_pending=1, sinks_skipped=0, sinks_queried=1, sinks_omitted=1,
        engine_queries=1, sinks_proven_empty=0,
        by_category={
            "named_effect_hint": {"candidates": 1, "selected": 1, "queried": 1},
            "lifecycle_name_hint": {"candidates": 0, "selected": 0, "queried": 0},
            "source_supported_cross_file": {"candidates": 0, "selected": 0, "queried": 0},
            "breadth": {"candidates": 1, "selected": 1, "queried": 0},
        },
    )
    flow["paths"].update(
        status="partial", count=1, omitted=0, count_is_lower_bound=True,
        rows=[{"kind": "parameter_to_operation", "endpoint_id": endpoints[0]["id"],
               "source": start, "sink": end,
               "steps": [start, end], "interprocedural": False}],
    )
    return raw


def completed_flow_result(raw, path="src/app.py"):
    raw = partial_flow_result(raw, path)
    raw["dataflow"] = "complete"
    flow = raw["dataflow_analysis"]
    flow["status"] = "complete"
    flow["selection"] = flow_selection(flow["selection"]["endpoints"][:1])
    flow["queries"].update(sinks_total=1, sinks_eligible=1, sinks_selected=1,
                           sinks_pending=0, sinks_omitted=0)
    flow["queries"]["by_category"]["breadth"] = {"candidates": 0, "selected": 0, "queried": 0}
    flow["paths"].update(status="complete", count_is_lower_bound=False)
    return raw


def progress_checkpoint_files(output):
    """Write bound base/progress companions from a synthetic successful query."""
    raw = partial_flow_result(json.loads(output.read_text()))
    base = json.loads(json.dumps(raw))
    base.update(checkpoint="base_before_dataflow", dataflow="error")
    base["metadata"]["overlays"].remove("dataflowOss")
    base["dataflow_analysis"] = {"status": "error"}
    base["errors"] = [{"section": "dataflow_analysis", "error": "InterruptedDataflow"}]
    base_path = Path(str(output) + ".base.json")
    base_path.write_text(json.dumps(base))
    flow_path = Path(str(output) + ".flow.json")
    envelope = {
        "schema_version": 1, "query_version": "9", "checkpoint": "dataflow_progress",
        "run_token": raw["run_token"],
        "base_sha256": hashlib.sha256(base_path.read_bytes()).hexdigest(),
        "overlays": sorted(raw["metadata"]["overlays"]), "truncated_values": 0,
        "dataflow_analysis": raw["dataflow_analysis"],
    }
    flow_path.write_text(json.dumps(envelope))
    output.unlink()
    return base_path, flow_path, envelope


def flow_progress_result(flow, base_sha256, stage):
    counters = ("sinks_total", "sinks_eligible", "sinks_selected", "sinks_not_selected",
                "sinks_skipped", "sinks_queried", "sinks_pending", "engine_queries", "sinks_proven_empty")
    return {
        "schema_version": 1, "query_version": "9", "run_token": TEST_RUN_TOKEN,
        "base_sha256": base_sha256, "plan_digest": flow["selection"]["plan_digest"],
        "stage": stage, "source_parameter_count": flow["source_parameter_count"],
        **{key: flow["queries"][key] for key in counters},
        "engine_queries_started": flow["queries"]["engine_queries"],
        "by_category": flow["queries"]["by_category"],
        "elapsed_seconds": 10, "flow_elapsed_seconds": 5, "maximum_endpoint_seconds": 1,
        "flow_budget_seconds": 1200, "budget_origin": "query_body_start",
        "current_endpoint_started_seconds": None,
    }


def phase_result(*events):
    return {
        "schema_version": 1,
        "query_version": "9",
        "phases": [
            {"phase": phase, "elapsed_seconds": elapsed} for phase, elapsed in events
        ],
    }


def test_missing_operator_tools_does_not_start_or_install_anything(monkeypatch):
    monkeypatch.delenv("PAT_JOERN_HOME", raising=False)
    monkeypatch.delenv("PAT_JOERN_JAVA_HOME", raising=False)
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: pytest.fail("metadata started a process")
    )
    assert not analysis.joern_info()["available"]
    result = analysis.analyze_joern([source()])
    assert result["status"] == "unavailable" and result["summary"]["methods"] is None
    assert result["candidate_index"] == []


def test_qualified_metadata_and_fixed_profiles_do_not_launch_java(qualified, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("metadata launched Java"))
    info = analysis.joern_info()
    assert info["available"] and info["version"] == "4.0.669"
    assert info["adapter_version"] == "12"
    assert info["query_version"] == "9" and info["dataflow"] == "deep_profile"
    assert qualified["root"] not in json.dumps(info)
    deep = analysis.joern_limits("deep")
    assert deep["seconds"] == 3600 and deep["heap_gib"] == 8
    deep["seconds"] = 0
    assert analysis.joern_limits("deep")["seconds"] == 3600
    assert info["javascript_transport"]["type_maps"] == "not_run"
    assert (
        info["javascript_transport"]["sha256"]
        == hashlib.sha256(analysis._ASTGEN_TRANSPORT.encode()).hexdigest()
    )


@pytest.mark.parametrize("profile,seconds,heap", [("standard", 120, 2), ("deep", 3600, 8)])
@pytest.mark.parametrize(
    "timeout_override,heap_override,processor_override",
    [(None, None, None), (21600, None, None), (None, 16, None), (None, None, 6),
     (21600, 16, 6), (None, None, 1), (None, None, 32)],
)
def test_host_budget_overrides_are_independent_of_profile_defaults(
    monkeypatch, profile, seconds, heap, timeout_override, heap_override, processor_override
):
    overrides = (
        ("PAT_JOERN_TIMEOUT_SECONDS", timeout_override),
        ("PAT_JOERN_HEAP_GIB", heap_override),
        ("PAT_JOERN_ACTIVE_PROCESSORS", processor_override),
    )
    for variable, _ in overrides:
        monkeypatch.delenv(variable, raising=False)
    baseline = analysis.joern_limits(profile)
    for variable, value in overrides:
        if value is not None:
            monkeypatch.setenv(variable, str(value))
    limits = analysis.joern_limits(profile)
    assert baseline["seconds"] == seconds and baseline["heap_gib"] == heap
    assert baseline["active_processors"] == 2
    assert limits["seconds"] == (timeout_override or seconds)
    assert limits["heap_gib"] == (heap_override or heap)
    assert limits["active_processors"] == (processor_override or 2)
    assert {key: value for key, value in limits.items() if key not in {"seconds", "heap_gib", "active_processors"}} == {
        key: value for key, value in baseline.items() if key not in {"seconds", "heap_gib", "active_processors"}
    }


@pytest.mark.parametrize("variable", ["PAT_JOERN_TIMEOUT_SECONDS", "PAT_JOERN_HEAP_GIB", "PAT_JOERN_ACTIVE_PROCESSORS"])
@pytest.mark.parametrize("value", ["", "0", "-1", "1.5", "nan", "inf", "1e309", " 16", "16 ", "true", "1_000", "16g", "16;echo budget-secret", "$(echo budget-secret)"])
def test_invalid_host_budgets_fail_before_starting_analyzer(monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    monkeypatch.setattr(analysis, "_run", lambda *a, **k: pytest.fail("invalid budget ran Joern"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("invalid budget started a process"))
    with pytest.raises(ValueError, match=variable) as raised:
        analysis.analyze_joern([source()])
    assert "budget-secret" not in str(raised.value)


@pytest.mark.parametrize("variable,value", [("PAT_JOERN_TIMEOUT_SECONDS", "86401"), ("PAT_JOERN_HEAP_GIB", "65"), ("PAT_JOERN_ACTIVE_PROCESSORS", "33")])
def test_host_budget_overrides_remain_bounded(monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    monkeypatch.setattr(analysis, "_run", lambda *a, **k: pytest.fail("invalid budget ran Joern"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("invalid budget started a process"))
    with pytest.raises(ValueError, match=variable):
        analysis.analyze_joern([source()], analysis_profile="deep")


def test_host_budget_controls_process_deadline_heap_processors_and_receipt(qualified, monkeypatch):
    monkeypatch.setenv("PAT_JOERN_TIMEOUT_SECONDS", "21600")
    monkeypatch.setenv("PAT_JOERN_HEAP_GIB", "16")
    monkeypatch.setenv("PAT_JOERN_ACTIVE_PROCESSORS", "6")
    monkeypatch.setattr(analysis, "_clock", lambda: 100.0)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert kwargs["stop"] == 21700.0
        assert "-J-Xmx16g" in argv
        assert "-J-XX:ActiveProcessorCount=6" in argv
        assert kwargs["env"]["JAVA_OPTS"] == "-Xmx16g -XX:ActiveProcessorCount=6 -Xss32m"
        assert kwargs["env"]["_JAVA_OPTIONS"].startswith("-Xmx16g -XX:ActiveProcessorCount=6 ")
        assert not {"PAT_JOERN_TIMEOUT_SECONDS", "PAT_JOERN_HEAP_GIB", "PAT_JOERN_ACTIVE_PROCESSORS"} & kwargs["env"].keys()
        status = fake_run(argv, **kwargs)
        if output := kwargs.get("output"):
            raw = json.loads(output.read_text())
            raw["metadata"]["max_heap_bytes"] = 16 * 1024**3
            raw["metadata"]["active_processors"] = 6
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    assert len(calls) == 2 and result["status"] == "complete"
    assert result["limits"]["seconds"] == 21600 and result["limits"]["heap_gib"] == 16
    assert result["limits"]["active_processors"] == 6
    assert result["provenance"]["operator_overrides"] == {
        "seconds": {
            "environment_variable": "PAT_JOERN_TIMEOUT_SECONDS",
            "value": 21600,
            "profile_default": 3600,
        },
        "heap_gib": {
            "environment_variable": "PAT_JOERN_HEAP_GIB",
            "value": 16,
            "profile_default": 8,
        },
        "active_processors": {
            "environment_variable": "PAT_JOERN_ACTIVE_PROCESSORS",
            "value": 6,
            "profile_default": 2,
        },
    }
    assert result["coverage"]["batches"][0]["model_metadata"]["max_heap_bytes"] == 16 * 1024**3
    assert result["coverage"]["batches"][0]["model_metadata"]["active_processors"] == 6
    assert not result["configuration"]["project_config_loaded"]


@pytest.mark.parametrize("processors,equivalent", [("2", True), ("6", False)])
def test_processor_budget_scope_uses_effective_limit_and_preserves_operator_choice(
    tmp_path, monkeypatch, processors, equivalent
):
    from project_assess.comparison import compare_assessments
    from project_assess.service import AssessmentService

    def unavailable_tools():
        raise OSError("synthetic unavailable tools")

    for variable in ("PAT_JOERN_TIMEOUT_SECONDS", "PAT_JOERN_HEAP_GIB", "PAT_JOERN_ACTIVE_PROCESSORS"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(analysis, "_tools", unavailable_tools)
    monkeypatch.setattr(analysis, "_run", lambda *a, **k: pytest.fail("scope check ran Joern"))
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("raise AssertionError('must not execute')\n")
    service = AssessmentService(tmp_path / "state")
    baseline = service.scan(root, analyzers=["joern"])
    monkeypatch.setenv("PAT_JOERN_ACTIVE_PROCESSORS", processors)
    explicit = service.scan(root, analyzers=["joern"])
    repeated = service.scan(root, analyzers=["joern"])
    assert baseline["source"] == explicit["source"] == repeated["source"]
    assert (baseline["scope_digest"] == explicit["scope_digest"]) is equivalent
    assert explicit["scope_digest"] == repeated["scope_digest"]
    assert compare_assessments(baseline, explicit, None, None, None)["comparable"] is equivalent
    receipt = explicit["facts"]["optional_analysis"]["joern"]
    limits = explicit["facts"]["collection"]["limits"]["dedicated_analyzer_phases"]["joern"]
    assert limits["active_processors"] == receipt["limits"]["active_processors"] == int(processors)
    assert baseline["facts"]["optional_analysis"]["joern"]["provenance"]["operator_overrides"] == {}
    assert receipt["provenance"]["operator_overrides"] == {
        "active_processors": {
            "environment_variable": "PAT_JOERN_ACTIVE_PROCESSORS",
            "value": int(processors),
            "profile_default": 2,
        },
    }


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"x" * 10_000, None),
        (b"x" * 10_001, "javascript_frontend_line_byte_limit"),
        (b"\n" * 49_999, None),
        (b"\n" * 50_000, "javascript_frontend_line_limit"),
        (b"x" * (5 * 1024**2 + 1), "javascript_frontend_file_byte_limit"),
        (b"// EMSCRIPTEN_START_ASM", "javascript_frontend_emscripten"),
    ],
)
def test_javascript_guards_are_explicit_bounded_input_limits(raw, reason):
    assert analysis._javascript_guard(raw) == reason


def test_captured_js_names_are_not_filtered_and_guarded_inputs_keep_coverage_rows(
    qualified, monkeypatch
):
    names = [
        "tests/unit.test.ts",
        ".hidden/example.jsx",
        "src/View.test.tsx",
        "src/types.d.ts",
        "src/module.mts",
        "src/module.cts",
    ]
    inputs = [source(path, "export const kept = 1;\n") for path in names]
    inputs.append(source("src/generated.js", "x" * 10_001))

    def run(argv, *, cwd, output=None, env, **kwargs):
        if output:
            raw = raw_result(names[0])
            for section in ("methods", "calls", "unread_bindings", "module_edges"):
                raw[section].update(rows=[], count=0)
            raw["source_files"].update(rows=[{"path": path} for path in names], count=len(names))
            raw["methods"].update(
                source_files=0,
                retained_files=0,
                omitted_files=0,
                file_coverage={
                    "status": "complete",
                    "count": 0,
                    "omitted": 0,
                    "limit": 0,
                    "byte_limit": 256 * 1024,
                    "rows": [],
                },
            )
            output.write_text(json.dumps(raw))
        else:
            assert "--no-tsTypes" in argv
            script = Path(env["ASTGEN_BIN"])
            assert script.name == "astgen-transport" and script.is_file()
            settings = json.loads(script.with_suffix(".json").read_text())
            assert {row["path"] for row in settings["files"]} == set(names)
            for row in settings["files"]:
                assert not row["alias"].startswith(".") and ".test." not in row["alias"]
                expected = Path(row["path"]).suffix
                if expected in {".mts", ".cts"}:
                    expected = ".ts"
                assert row["alias"].endswith(expected)
                assert (cwd / "transport" / row["alias"]).read_bytes() == (
                    cwd / "source" / row["path"]
                ).read_bytes()
            assert not (cwd / "source/src/generated.js").exists()
            (kwargs["workspace"] / "ast-compatibility.json").write_text(
                json.dumps({"schema_version": 1, "files": []})
            )
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern(inputs, snapshot=qualified)
    assert result["coverage"]["eligible_files"] == 7
    assert result["coverage"]["staged_files"] == result["coverage"]["modeled_files"] == 6
    assert result["coverage"]["omissions"] == {"javascript_frontend_line_byte_limit": 1}
    modules = {row["path"]: row for row in result["modules"]}
    assert set(modules) == {*names, "src/generated.js"}
    assert modules["src/generated.js"]["skip_reason"] == "javascript_frontend_line_byte_limit"
    assert modules["src/generated.js"]["staged"] is False
    assert result["status"] == "partial"


def test_ast_transport_restores_only_headers_and_preserves_original_import_bytes(tmp_path):
    workspace = tmp_path / "workspace with spaces"
    stage = workspace / "javascript/source"
    stage.mkdir(parents=True)
    text = "import { useful } from '../src/library';\nexport const kept = useful();\n"
    record = source(".hidden/view.test.tsx", text)
    original = stage / record["path"]
    original.parent.mkdir()
    original.write_text(text)
    binary = workspace / "synthetic-astgen"
    binary.write_text(
        "#!" + str(Path(sys.executable).resolve()) + "\n"
        "import json,sys\nfrom pathlib import Path\n"
        "args=sys.argv[1:]\n"
        "assert args[-3:]==['--type','ts','--no-tsTypes']\n"
        "root=Path(args[1]);output=Path(args[3]);output.mkdir()\n"
        "for source in root.iterdir():\n"
        " ast={'literal':source.read_text(),'producerPathLiteral':str(source),'padding':'x'*100000}\n"
        " row={'fullName':str(source),'relativeName':source.name,'ast':ast}\n"
        " (output/(source.name+'.json')).write_text(json.dumps(row,separators=(',',':')))\n"
    )
    binary.chmod(0o500)
    launcher = analysis._javascript_transport(
        workspace,
        stage,
        {record["path"]: record},
        {"astgen": binary},
        analysis.joern_limits("standard"),
    )
    output = workspace / "output"
    completed = subprocess.run(
        [str(launcher), "--no-tsTypes", "-t", "ts", "-o", str(output)],
        cwd=stage,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    result = json.loads(next(output.glob("*.json")).read_text())
    assert result["relativeName"] == record["path"] and result["fullName"] == str(original)
    assert result["ast"]["literal"] == text
    assert "/transport/unit00000.tsx" in result["ast"]["producerPathLiteral"]
    assert len(result["ast"]["padding"]) == 100_000
    assert analysis._hash_file(original) == record["digest"]
    rejected = subprocess.run(
        [str(launcher), "--script", str(original)], cwd=stage, capture_output=True, check=False
    )
    assert rejected.returncode != 0


def test_model_proof_and_inferred_edges_are_not_promoted_to_cleanup_or_primary_topology(
    qualified, monkeypatch
):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            for row in raw["unread_bindings"]["rows"]:
                row.pop("capture_status")
            call = raw["calls"]["rows"][0]
            raw["calls"]["rows"] += [
                {**call, "dependency_status": "producer_inferred"},
                {**call, "dependency_status": "rejected"},
                {**call, "dependency_status": "unknown"},
            ]
            raw["calls"]["classifications"] = {"source_supported": 7, "producer_inferred": 11}
            raw["inferred_module_edges"].update(
                rows=[{"source": "src/app.py", "target": "src/app.py", "count": 11}], count=1
            )
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["candidate_index"] == []
    assert result["coverage"]["omissions"] == {
        "unqualified_binding_contract": 2,
        "rejected_call_target": 1,
        "unqualified_call_target": 1,
    }
    assert result["topology"]["edges"] == [
        {
            "source": "src/app.py",
            "target": "src/app.py",
            "source_evidence_id": source()["evidence_id"],
            "source_digest": source()["digest"],
            "target_source_evidence_id": source()["evidence_id"],
            "target_digest": source()["digest"],
            "kind": "source_supported_method_call",
            "count": 7,
        }
    ]
    assert result["topology"]["inferred_edges"][0]["count"] == 11
    calls = result["topology"]["calls"]
    assert len(calls) == 2 and {row["dependency_status"] for row in calls} == {
        "source_supported",
        "producer_inferred",
    }
    assert (
        next(row for row in calls if row["dependency_status"] == "producer_inferred")["resolution"]
        != "internal"
    )
    for row in calls:
        assert (
            row["source_evidence_id"] == row["target_source_evidence_id"] == source()["evidence_id"]
        )
        assert row["digest"] == row["target_digest"] == source()["digest"]
    section = result["coverage"]["batches"][0]["model_sections"]["unread_bindings"]
    assert (
        section["suppressed"] == {"captured_binding": 3} and section["captured_declarations"] == 3
    )
    sections = result["coverage"]["batches"][0]["model_sections"]
    assert sections["methods"]["external_models"] == 17
    assert sections["methods"]["unlocated_models"] == 2
    assert sections["module_edges"]["occurrences"] == 7
    assert sections["module_edges"]["omitted_occurrences"] == 0
    assert sections["inferred_module_edges"]["count"] == 1
    assert sections["calls"]["classifications"] == {"source_supported": 7, "producer_inferred": 11}


def test_captured_ids_keep_redacted_source_endpoints_unambiguous(qualified, monkeypatch):
    from project_assess.collector import _redact_data

    paths = ["src/sk_" + "A" * 24 + ".py", "src/sk_" + "B" * 24 + ".py"]
    captured = [
        {**source(path), "evidence_id": f"e-captured-{index}"} for index, path in enumerate(paths)
    ]

    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result(paths[0])
            raw["source_files"].update(rows=[{"path": path} for path in paths], count=2)
            method = raw["methods"]["rows"][0]
            raw["methods"].update(
                rows=[{**method, "path": path} for path in paths],
                count=2,
                source_files=2,
                retained_files=2,
            )
            raw["methods"]["file_coverage"].update(
                rows=[
                    {"path": path, "count": 1, "retained": 1, "identity_truncated": False}
                    for path in paths
                ],
                count=2,
                limit=2,
            )
            call = raw["calls"]["rows"][0]
            raw["calls"].update(
                rows=[{**call, "target_path": paths[1]}, {**call, "target_path": "outside.py"}],
                count=2,
            )
            raw["module_edges"]["rows"][0]["target"] = paths[1]
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = _redact_data(analysis.analyze_joern(captured, snapshot=qualified))
    by_id = {row["evidence_id"]: row for row in captured}
    modules = result["modules"]
    assert len(modules) == 2 and len({row["path"] for row in modules}) == 1
    assert {row["source_evidence_id"] for row in modules} == set(by_id)
    for row in [*modules, *result["topology"]["methods"], *result["topology"]["calls"]]:
        assert row["digest"] == by_id[row["source_evidence_id"]]["digest"]
    calls = result["topology"]["calls"]
    resolved = next(row for row in calls if row["target_source_evidence_id"] is not None)
    unresolved = next(row for row in calls if row["target_source_evidence_id"] is None)
    assert resolved["target_source_evidence_id"] == captured[1]["evidence_id"]
    assert resolved["target_digest"] == captured[1]["digest"]
    assert unresolved["target_path"] is None and unresolved["target_digest"] is None
    edge = result["topology"]["edges"][0]
    assert edge["source"] == edge["target"]  # Safe labels can coincide; identities do not.
    assert edge["source_evidence_id"] == captured[0]["evidence_id"]
    assert edge["target_source_evidence_id"] == captured[1]["evidence_id"]


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("unread_bindings", "suppressed", {"captured_binding": True}),
        ("unread_bindings", "captured_declarations", -1),
        ("methods", "external_models", True),
        ("calls", "classifications", {"producer_inferred": False}),
        ("module_edges", "count_is_lower_bound", "yes"),
    ],
)
def test_invalid_model_suppression_counts_do_not_become_validated_output(
    qualified, monkeypatch, section, field, value
):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            raw[section][field] = value
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["summary"]["methods"] is None and result["candidate_index"] == []
    assert result["coverage"]["batches"][0]["status"] == "unvalidated_output_or_source"


@pytest.mark.parametrize(
    "config",
    [
        {"script": "project.sc"},
        {"argv": []},
        {"seconds": 21600},
        {"heap_gib": 16},
        {"active_processors": 6},
        {"PAT_JOERN_TIMEOUT_SECONDS": "21600"},
        {"PAT_JOERN_HEAP_GIB": "16"},
        {"PAT_JOERN_ACTIVE_PROCESSORS": "6"},
        False,
    ],
)
def test_caller_cannot_select_scripts_or_commands(config):
    with pytest.raises(ValueError):
        analysis.analyze_joern([], config=config)


@pytest.mark.parametrize("path", ["../escape.py", "/absolute.py", "src\\app.py", ".", ""])
def test_source_paths_cannot_escape_private_staging(path):
    with pytest.raises(ValueError):
        analysis.analyze_joern([source(path)])


def test_staging_is_captured_only_with_clean_environment_and_independent_language_workspaces(
    qualified, monkeypatch
):
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:untrusted.jar")
    monkeypatch.setenv("SCALA_OPTS", "untrusted")
    monkeypatch.setenv("CLASSPATH", "/original/project")
    monkeypatch.setenv("_JAVA_OPTIONS", "-javaagent:untrusted.jar")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        env, cwd = kwargs["env"], kwargs["cwd"]
        assert not {"JAVA_TOOL_OPTIONS", "SCALA_OPTS", "CLASSPATH"} & env.keys()
        assert env["JAVA_OPTS"] == "-Xmx8g -XX:ActiveProcessorCount=2 -Xss32m"
        assert env["_JAVA_OPTIONS"].startswith("-Xmx8g -XX:ActiveProcessorCount=2 -Xss32m ")
        assert "untrusted" not in env["_JAVA_OPTIONS"]
        assert "(deny network*)" in argv[2] and qualified["root"] in argv[2]
        assert not (cwd / "source" / "pyproject.toml").exists()
        assert "dataflow" not in " ".join(argv)
        return fake_run(argv, **kwargs)

    monkeypatch.setattr(analysis, "_run", run)
    sentinel = os.path.join(qualified["root"], "must-not-execute")
    record = source(
        text=f"def call(context):\n    unused = value()\n    return run()\nopen({sentinel!r}, 'w').write('bad')\n"
    )
    result = analysis.analyze_joern(
        [source("src/App.java"), record], snapshot=qualified, analysis_profile="deep"
    )
    assert not os.path.exists(sentinel)
    assert result["coverage"]["staged_files"] == 2 and result["coverage"]["modeled_files"] == 2
    assert len({kwargs["cwd"] for _, kwargs in calls}) == 2
    assert "--delombok-mode" in calls[2][0] and "--fetch-dependencies" not in calls[2][0]
    assert result["topology"]["complete"] is False
    assert all(row["count"] == 7 for row in result["topology"]["edges"])
    assert all(row["confidence"] == "low" for row in result["candidates"])
    assert result["provenance"]["snapshot"]["manifest_digest"] == qualified["manifest_digest"]
    assert "pat-joern-" not in json.dumps(result)
    assert all(not kwargs["cwd"].exists() for _, kwargs in calls)
    assert result["coverage"]["batches"][0]["model_metrics"]["edge_counts"]["REF"] == 6
    assert result["coverage"]["batches"][0]["model_metadata"]["active_processors"] == 2


def test_normal_caveats_do_not_hide_missing_model_files_or_create_partial_status(
    qualified, monkeypatch
):
    monkeypatch.setattr(analysis, "_run", fake_run)
    complete = analysis.analyze_joern([source()], snapshot=qualified)
    assert complete["status"] == "complete"

    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            raw["caveats"] = ["Open-world model, not runtime proof"]
            raw["source_files"]["rows"] = [{"path": "not-captured.py"}]
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    partial = analysis.analyze_joern([source()], snapshot=qualified)
    assert partial["status"] == "partial" and partial["coverage"]["modeled_files"] == 0
    assert partial["summary"]["methods"] is None and partial["summary"]["calls"] is None
    assert partial["coverage"]["batches"][0]["status"] == "partial"
    assert partial["coverage"]["batches"][0]["process_status"] == "complete"
    assert partial["coverage"]["omissions"] == {
        "unlocated_model_file": 1,
        "staged_file_without_model": 1,
    }


def test_effective_runtime_limits_are_verified_not_inferred_from_requested_flags(
    qualified, monkeypatch
):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            raw["metadata"]["max_heap_bytes"] = 16 * 1024**3
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["status"] == "partial" and result["summary"]["methods"] is None
    assert result["candidate_index"] == []


@pytest.mark.parametrize(
    "variable,limit_key,selected,metadata_key,reported",
    [("PAT_JOERN_HEAP_GIB", "heap_gib", 16, "max_heap_bytes", 16 * 1024**3 + 1),
     ("PAT_JOERN_ACTIVE_PROCESSORS", "active_processors", 6, "active_processors", 7)],
)
def test_runtime_metadata_cannot_exceed_operator_selected_limit(
    qualified, monkeypatch, variable, limit_key, selected, metadata_key, reported
):
    monkeypatch.setenv(variable, str(selected))

    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            raw["metadata"][metadata_key] = reported
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["limits"][limit_key] == selected
    assert result["status"] == "partial" and result["summary"]["methods"] is None
    assert result["coverage"]["batches"][0]["status"] == "unvalidated_output_or_source"
    assert result["candidate_index"] == []


def test_query_output_and_workspace_caps_are_polled_without_retaining_logs(tmp_path):
    limits = analysis.joern_limits("standard")
    limits["query_json_bytes"] = 8
    output = tmp_path / "output.json"
    code = "from pathlib import Path;Path('output.json').write_text('x'*100)"
    assert (
        analysis._run(
            [sys.executable, "-c", code],
            workspace=tmp_path,
            cwd=tmp_path,
            env={},
            stop=time.monotonic() + 3,
            limits=limits,
            output=output,
        )
        == "output_limit"
    )
    limits["workspace_bytes"] = 8
    assert (
        analysis._run(
            [sys.executable, "-c", "pass"],
            workspace=tmp_path,
            cwd=tmp_path,
            env={},
            stop=time.monotonic() + 3,
            limits=limits,
        )
        == "workspace_limit"
    )


def test_generated_abstract_constructor_and_truncated_identities_never_become_cleanup_leads(
    qualified, monkeypatch
):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            original = raw["unread_bindings"]["rows"][0]
            raw["unread_bindings"]["rows"] += [
                {**original, "symbol": "<tmp>0"},
                {**original, "is_abstract": True},
                {**original, "has_body": False},
                {**original, "is_constructor": True},
                {**original, "symbol": "not_in_source"},
                {**original, "identity_truncated": True},
            ]
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert {row["metrics"]["symbol"] for row in result["candidates"]} == {"context", "unused"}
    assert result["coverage"]["omissions"] == {
        "abstract_bodyless_or_constructor_binding": 3,
        "generated_or_unvalidated_binding": 2,
        "truncated_model_identity": 1,
    }
    assert result["status"] == "partial"
    assert all("signature" in row["counterevidence"][0] for row in result["candidates"])


def test_digest_mismatch_and_tool_home_inside_original_never_start_a_process(
    qualified, monkeypatch
):
    monkeypatch.setattr(analysis, "_run", lambda *a, **k: pytest.fail("unsafe source/tool was run"))
    bad = {**source(), "digest": "sha256:" + "0" * 64}
    result = analysis.analyze_joern([bad], snapshot=qualified)
    assert result["coverage"]["omissions"] == {"source_digest_mismatch": 1}
    assert result["summary"]["methods"] is None
    snapshot = {**qualified, "root": str(analysis._tools()[0])}
    assert analysis.analyze_joern([source()], snapshot=snapshot)["status"] == "unsupported"


@pytest.mark.parametrize("failure", ["tool_failed", "timeout", "workspace_limit", "log_limit"])
def test_failed_provider_output_is_unknown_and_does_not_leak_diagnostics(
    qualified, monkeypatch, failure
):
    monkeypatch.setattr(analysis, "_run", lambda *a, **k: failure)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["status"] == "partial" and result["summary"]["methods"] is None
    assert result["candidates"] == []
    assert result["coverage"]["batches"][0]["status"] == failure
    assert "missing results remain unknown" in result["gaps"][0]


@pytest.mark.parametrize("profile", ["standard", "deep"])
def test_phase_progress_qualifies_only_profile_complete_ordered_events(tmp_path, profile):
    events = [
        ("import_started", 0),
        ("import_completed", 1.5),
        ("default_overlays_started", 1.5),
        ("default_overlays_completed", 3),
        ("postprocessing_started", 4),
        ("postprocessing_completed", 5),
        ("base_evidence_started", 5),
        ("base_evidence_completed", 7.5),
        ("definition_accounting_started", 8),
        ("definition_accounting_completed", 10),
        ("dataflow_overlay_started", 11),
        ("dataflow_overlay_completed", 20),
        ("dataflow_queries_started", 20),
        ("dataflow_queries_completed", 86_400),
    ]
    durations = {
        "import": 1.5,
        "default_overlays": 1.5,
        "postprocessing": 1,
        "base_evidence": 2.5,
        "definition_accounting": 2,
        "dataflow_overlay": 9,
        "dataflow_queries": 86_380,
    }
    if profile == "standard":
        events = events[:8]
        durations = dict(list(durations.items())[:4])
    payload = phase_result(*events)
    path = tmp_path / "phases.json"
    path.write_text(json.dumps(payload))
    assert analysis._phase_progress(path, profile) == {
        "status": "complete",
        "timing_scope": "query_body_only",
        "last_phase": events[-1][0],
        "events": payload["phases"],
        "durations_seconds": durations,
    }


@pytest.mark.parametrize("profile", ["standard", "deep"])
@pytest.mark.parametrize("event_count", [1, 3])
def test_phase_progress_keeps_incomplete_stage_without_inventing_duration(
    tmp_path, profile, event_count
):
    events = [("import_started", 0), ("import_completed", 2), ("default_overlays_started", 3)]
    payload = phase_result(*events[:event_count])
    path = tmp_path / "phases.json"
    path.write_text(json.dumps(payload))
    assert analysis._phase_progress(path, profile) == {
        "status": "partial",
        "timing_scope": "query_body_only",
        "last_phase": events[event_count - 1][0],
        "events": payload["phases"],
        "durations_seconds": {"import": 2} if event_count == 3 else {},
    }


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param([], id="not-object"),
        pytest.param({**phase_result(("import_started", 0)), "schema_version": True}, id="bool-schema"),
        pytest.param({**phase_result(("import_started", 0)), "schema_version": 1.0}, id="float-schema"),
        pytest.param({**phase_result(("import_started", 0)), "schema_version": 2}, id="future-schema"),
        pytest.param({**phase_result(("import_started", 0)), "query_version": "6"}, id="old-query"),
        pytest.param({**phase_result(("import_started", 0)), "raw_source": "source-secret"}, id="raw-source"),
        pytest.param({**phase_result(("import_started", 0)), "path": "/private/source-secret"}, id="path-key"),
        pytest.param({**phase_result(("import_started", 0)), "phases": None}, id="not-events"),
        pytest.param(phase_result(), id="empty-events"),
        pytest.param({**phase_result(), "phases": ["source-secret"]}, id="not-event-object"),
        pytest.param({**phase_result(), "phases": [{"phase": "import_started"}]}, id="missing-time"),
        pytest.param({**phase_result(), "phases": [{"phase": "import_started", "elapsed_seconds": 0, "path": "source-secret"}]}, id="event-path"),
        pytest.param(phase_result(("source-secret", 0)), id="unknown-phase"),
        pytest.param(phase_result(("import_completed", 0)), id="missing-start"),
        pytest.param(phase_result(("import_started", 0), ("import_started", 1)), id="duplicate-phase"),
        pytest.param(phase_result(("import_started", 0), ("default_overlays_started", 1)), id="skipped-phase"),
        pytest.param(phase_result(("import_started", True)), id="bool-time"),
        pytest.param(phase_result(("import_started", "source-secret")), id="string-time"),
        pytest.param(phase_result(("import_started", None)), id="null-time"),
        pytest.param(phase_result(("import_started", -1)), id="negative-time"),
        pytest.param(phase_result(("import_started", 86_400.1)), id="unbounded-time"),
        pytest.param(phase_result(("import_started", 10**400)), id="huge-integer-time"),
        pytest.param(phase_result(("import_started", 2), ("import_completed", 1)), id="regressing-time"),
        pytest.param(phase_result(("import_started", float("nan"))), id="nan-time"),
        pytest.param(phase_result(("import_started", float("inf"))), id="infinite-time"),
    ],
)
def test_phase_progress_rejects_unqualified_metadata_without_relaying_content(tmp_path, payload):
    path = tmp_path / "phases.json"
    path.write_text(json.dumps(payload))
    assert analysis._phase_progress(path, "deep") == {"status": "invalid"}


def test_standard_phase_progress_rejects_deep_events_and_excess_rows(tmp_path):
    events = [
        (f"{stage}_{state}", 0)
        for stage in (
            "import", "default_overlays", "postprocessing", "base_evidence",
            "definition_accounting", "dataflow_overlay", "dataflow_queries",
        )
        for state in ("started", "completed")
    ]
    path = tmp_path / "phases.json"
    path.write_text(json.dumps(phase_result(*events[:9])))
    assert analysis._phase_progress(path, "standard") == {"status": "invalid"}
    path.write_text(json.dumps(phase_result(*events, ("source-secret", 0))))
    assert analysis._phase_progress(path, "deep") == {"status": "invalid"}


@pytest.mark.parametrize(
    "payload",
    [
        b"source-secret: not JSON",
        b"\xffsource-secret",
        b'{"schema_version":1,"query_version":"9","phases":[],"phases":[{"phase":"import_started","elapsed_seconds":0}]}',
        b'{"schema_version":1,"query_version":"9","phases":[{"phase":"import_started","elapsed_seconds":0,"elapsed_seconds":1}]}',
    ],
)
def test_phase_progress_rejects_invalid_encoding_and_ambiguous_json(tmp_path, payload):
    path = tmp_path / "phases.json"
    path.write_bytes(payload)
    assert analysis._phase_progress(path, "deep") == {"status": "invalid"}


def test_phase_progress_bounds_input_and_refuses_symlinks(tmp_path):
    path = tmp_path / "phases.json"
    assert analysis._phase_progress(path, "deep") == {"status": "unavailable"}
    payload = json.dumps(phase_result(("import_started", 0))).encode()
    path.write_bytes(payload + b" " * (8192 - len(payload)))
    assert analysis._phase_progress(path, "deep")["status"] == "partial"
    path.write_bytes(path.read_bytes() + b" ")
    assert analysis._phase_progress(path, "deep") == {"status": "invalid"}
    target = tmp_path / "source-secret.json"
    target.write_bytes(payload)
    path.unlink()
    path.symlink_to(target)
    assert analysis._phase_progress(path, "deep") == {"status": "invalid"}
    path.unlink()
    path.mkdir()
    assert analysis._phase_progress(path, "deep") == {"status": "invalid"}


@pytest.mark.parametrize("failure", ["tool_failed", "timeout"])
def test_failed_query_retains_qualified_phase_receipt_and_process_timing(
    qualified, monkeypatch, failure
):
    payload = phase_result(
        ("import_started", 0), ("import_completed", 2), ("default_overlays_started", 2.5)
    )

    def run(argv, *, output=None, **kwargs):
        if output:
            output.with_name(output.name + ".phases.json").write_text(json.dumps(payload))
            return failure
        return fake_run(argv, output=output, **kwargs)

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert result["status"] == "partial" and result["summary"]["methods"] is None
    assert batch["status"] == batch["process_status"] == failure
    assert batch["base_checkpoint_recovered"] is False
    assert batch["phase_progress"] == {
        "status": "partial",
        "timing_scope": "query_body_only",
        "last_phase": "default_overlays_started",
        "events": payload["phases"],
        "durations_seconds": {"import": 2},
    }
    assert set(batch["timing"]) == {"parser_seconds", "query_process_seconds"}
    assert all(type(value) is float and value >= 0 for value in batch["timing"].values())


def test_staged_source_mutation_invalidates_model_identity(qualified, monkeypatch):
    def run(argv, **kwargs):
        fake_run(argv, **kwargs)
        if kwargs.get("output"):
            staged = kwargs["cwd"] / "source" / "src/app.py"
            staged.chmod(0o600)
            staged.write_text("changed\n")
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["status"] == "partial" and result["candidate_index"] == []
    assert result["coverage"]["batches"][0]["status"] == "unvalidated_output_or_source"


def test_leader_exit_still_kills_the_remaining_process_group(monkeypatch):
    signals = []

    class ExitedLeader:
        pid = 12345

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    analysis._stop_group(ExitedLeader())
    assert signals == [(12345, signal.SIGTERM), (12345, signal.SIGKILL)]


def test_process_runner_enforces_timeout_and_discards_sensitive_logs(tmp_path, capsys):
    limits = analysis.joern_limits("standard")
    result = analysis._run(
        [sys.executable, "-c", "import time;time.sleep(30)"],
        workspace=tmp_path,
        cwd=tmp_path,
        env={},
        stop=time.monotonic() + 0.1,
        limits=limits,
    )
    assert result == "timeout"
    limits["log_bytes"] = 20
    result = analysis._run(
        [sys.executable, "-c", "print('private-log-' * 1000)"],
        workspace=tmp_path,
        cwd=tmp_path,
        env={},
        stop=time.monotonic() + 3,
        limits=limits,
    )
    assert result == "log_limit"
    assert capsys.readouterr().out == capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "payload",
    [
        '{"schema_version":1,"query_version":"9","schema_version":1}',
        '{"schema_version":true,"query_version":"9","dataflow":"not_run"}',
        '{"schema_version":1,"query_version":"9","dataflow":"run"}',
    ],
)
def test_unqualified_or_ambiguous_query_output_is_rejected(tmp_path, payload):
    output = tmp_path / "out.json"
    output.write_text(payload)
    with pytest.raises(ValueError):
        analysis._read_result(output, 1024)


@pytest.mark.parametrize("read_count", [False, 0.0, None])
def test_unread_binding_read_count_must_be_an_integer_zero(qualified, monkeypatch, read_count):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            raw["unread_bindings"]["rows"] = [
                {**raw["unread_bindings"]["rows"][0], "read_count": read_count}
            ]
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["candidate_index"] == []
    assert result["coverage"]["omissions"]["generated_or_unvalidated_binding"] == 1


def test_unqualified_swift_only_input_is_unsupported_without_execution(qualified, monkeypatch):
    monkeypatch.setattr(analysis, "_run", lambda *a, **k: pytest.fail("Swift must not execute"))
    info = analysis.joern_info()
    assert info["languages"] == ["python", "javascript", "typescript", "java"]
    assert info["unqualified_languages"] == ["swift"]
    result = analysis.analyze_joern([source("src/App.swift")], snapshot=qualified)
    assert result["status"] == "unsupported"
    assert result["summary"]["methods"] is result["summary"]["calls"] is None
    assert result["coverage"]["omissions"] == {"unsupported_language": 1}
    unavailable = {**info, "available": False, "unavailable_reason": "not installed"}
    monkeypatch.setattr(analysis, "joern_info", lambda: unavailable)
    assert analysis.analyze_joern([source("src/App.swift")])["status"] == "unsupported"


def test_mixed_input_retains_qualified_facts_with_an_explicit_unexecuted_swift_gap(
    qualified, monkeypatch
):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return fake_run(argv, **kwargs)

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source(), source("src/App.swift")], snapshot=qualified)
    assert len(calls) == 2
    assert result["status"] == "partial"
    assert result["summary"]["methods"] == 1
    assert result["coverage"]["staged_files"] == result["coverage"]["modeled_files"] == 1
    assert result["coverage"]["omissions"]["unsupported_language"] == 1
    assert result["coverage"]["batches"][1] == {
        "language": "swift",
        "status": "unsupported",
        "process_status": "not_run",
        "staged_files": 0,
        "modeled_files": 0,
        "eligible_files": 1,
    }
    assert all(row["locations"][0]["path"] == "src/app.py" for row in result["candidates"])


def transport_ast(tmp_path, ast):
    workspace = tmp_path / "private workspace"
    stage = workspace / "javascript/source"
    stage.mkdir(parents=True)
    record = source(".hidden/typed.test.ts", "interface IndexedRecord { readonly 0: string; }\n")
    original = stage / record["path"]
    original.parent.mkdir()
    original.write_text(record["text"])
    ast_file = workspace / "producer-ast.json"
    ast_file.write_bytes(
        ast
        if isinstance(ast, bytes)
        else json.dumps(ast, ensure_ascii=False, separators=(",", ":")).encode()
    )
    binary = workspace / "synthetic-astgen"
    binary.write_text(
        "#!" + str(Path(sys.executable).resolve()) + "\n"
        "import json,sys\nfrom pathlib import Path\n"
        f"ast=Path({str(ast_file)!r}).read_bytes()\n"
        "args=sys.argv[1:];root=Path(args[1]);output=Path(args[3]);output.mkdir()\n"
        "assert args[-3:]==['--type','ts','--no-tsTypes']\n"
        "for source in root.iterdir():\n"
        " row={'fullName':str(source),'relativeName':source.name}\n"
        " (output/(source.name+'.json')).write_bytes(json.dumps(row,ensure_ascii=False,separators=(',',':')).encode()[:-1]+b',\"ast\":'+ast+b'}')\n"
    )
    binary.chmod(0o500)
    launcher = analysis._javascript_transport(
        workspace,
        stage,
        {record["path"]: record},
        {"astgen": binary},
        analysis.joern_limits("standard"),
    )
    output = workspace / "output"
    completed = subprocess.run(
        [str(launcher), "--no-tsTypes", "-t", "ts", "-o", str(output)],
        cwd=stage,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    consumer = next(output.glob("*.json"))
    payload = consumer.read_bytes()
    header = payload.split(b',"ast":', 1)
    result = json.loads(header[0] + b"}")
    body = header[1][:-1] if isinstance(ast, bytes) else json.loads(header[1][:-1])
    receipt = analysis._javascript_compatibility(workspace, stage, {record["path"]: record})
    assert result["relativeName"] == record["path"] and result["fullName"] == str(original)
    assert analysis._hash_file(original) == record["digest"]
    return body, receipt, workspace, consumer


def interface_ast(members, **extra):
    return {
        "type": "TSInterfaceDeclaration",
        "id": {"name": "IndexedRecord"},
        "body": {"type": "TSInterfaceBody", "body": members},
        **extra,
    }


def property_ast(value, *, kind="NumericLiteral", computed=False, member="TSPropertySignature"):
    return {
        "type": member,
        "readonly": True,
        "computed": computed,
        "start": 12,
        "end": 34,
        "key": {
            "type": kind,
            "value": value,
            "start": 21,
            "end": 22,
            "loc": {"start": {"line": 2, "column": 11}, "end": {"line": 2, "column": 12}},
            "extra": {"raw": "0x10" if value == 16 else str(value), "rawValue": value},
        },
    }


@pytest.mark.parametrize("padding", [0, 65_499, 131_030])
def test_ast_compatibility_changes_only_safe_interface_property_names(tmp_path, padding):
    from copy import deepcopy

    members = [property_ast(value) for value in (0, 1, 16, 9007199254740991)]
    members += [
        property_ast("named", kind="StringLiteral"),
        property_ast(2, computed=True),
        property_ast(3, member="TSMethodSignature"),
    ]
    runtime = {"type": "ObjectExpression", "properties": [property_ast(0, member="ObjectProperty")]}
    literal = {"type": "NumericLiteral", "value": 0, "start": 80, "end": 81}
    ast = {
        "padding": "x" * padding,
        "string": '{"type":"TSInterfaceDeclaration","body":null}',
        "body": [
            interface_ast(members),
            runtime,
            literal,
            {"type": "CallExpression", "callee": {"name": "kept"}},
        ],
    }
    expected = deepcopy(ast)
    for member, name in zip(
        expected["body"][0]["body"]["body"][:4], ("0", "1", "16", "9007199254740991"), strict=True
    ):
        member["key"]["value"] = name
    result, receipt, _, consumer = transport_ast(tmp_path, ast)
    assert result == expected
    assert receipt["adjusted_files"] == 1 and receipt["numeric_keys"] == 4
    assert (
        receipt["bounded_interfaces"]
        == receipt["unexpected_interfaces"]
        == receipt["unsupported_numeric_keys"]
        == 0
    )
    row = receipt["files"][0]
    assert row["consumer_ast_digest"] == analysis._hash_file(consumer)
    assert row["producer_ast_digest"] != row["consumer_ast_digest"]


def test_ast_compatibility_leaves_unsupported_keys_and_shapes_explicit(tmp_path):
    ast = {
        "body": [
            interface_ast(
                [property_ast(value) for value in (-1, 0.5, 9007199254740992, True, None)]
            ),
            {"type": "TSInterfaceDeclaration", "body": {"type": "TSInterfaceBody", "body": False}},
        ]
    }
    result, receipt, _, _ = transport_ast(tmp_path, ast)
    assert result == ast
    assert receipt["adjusted_files"] == receipt["numeric_keys"] == 0
    assert receipt["unsupported_numeric_keys"] == 5 and receipt["unexpected_interfaces"] == 1


def test_ast_compatibility_bounds_large_interfaces_without_dropping_later_source(tmp_path):
    from copy import deepcopy

    large = interface_ast([property_ast(0)], padding="x" * (2 * 1024**2 + 65_536))
    small = interface_ast([property_ast(1)])
    ast = {"body": [large, small]}
    expected = deepcopy(ast)
    expected["body"][1]["body"]["body"][0]["key"]["value"] = "1"
    result, receipt, _, _ = transport_ast(tmp_path, ast)
    assert result == expected
    assert receipt["bounded_interfaces"] == 1 and receipt["numeric_keys"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "boolean_schema",
        "outside_path",
        "source_digest",
        "boolean_count",
        "bad_ast_digest",
        "duplicate",
    ],
)
def test_ast_compatibility_receipts_reject_unbound_or_malformed_claims(tmp_path, mutation):
    _, _, workspace, _ = transport_ast(tmp_path, {"body": [interface_ast([property_ast(0)])]})
    path = workspace / "ast-compatibility.json"
    value = json.loads(path.read_text())
    if mutation == "boolean_schema":
        value["schema_version"] = True
    elif mutation == "outside_path":
        value["files"][0]["path"] = "../escaped.ts"
    elif mutation == "source_digest":
        value["files"][0]["source_digest"] = "sha256:" + "f" * 64
    elif mutation == "boolean_count":
        value["files"][0]["numeric_keys"] = True
    elif mutation == "bad_ast_digest":
        value["files"][0]["producer_ast_digest"] = "unverified"
    else:
        value["files"] *= 2
    path.write_text(json.dumps(value))
    record = source(".hidden/typed.test.ts", "interface IndexedRecord { readonly 0: string; }\n")
    with pytest.raises(ValueError):
        analysis._javascript_compatibility(
            workspace, workspace / "javascript/source", {record["path"]: record}
        )


def test_ast_compatibility_preserves_utf8_values_across_stream_boundaries(tmp_path):
    from copy import deepcopy

    ast = {"body": [interface_ast([property_ast(0)], description="é😀" * 20_000)]}
    expected = deepcopy(ast)
    expected["body"][0]["body"]["body"][0]["key"]["value"] = "0"
    result, receipt, _, _ = transport_ast(tmp_path, ast)
    assert result == expected and receipt["numeric_keys"] == 1
    assert receipt["unexpected_interfaces"] == 0


@pytest.mark.parametrize("shape", ["deep", "malformed"])
def test_ast_compatibility_preserves_unreadable_nodes_as_explicit_unknowns(tmp_path, shape):
    if shape == "deep":
        annotation = (
            b'{"type":"TSArrayType","elementType":' * 12_000
            + b'{"type":"TSStringKeyword"}'
            + b"}" * 12_000
        )
        ast = (
            b'{"type":"TSInterfaceDeclaration","body":{"type":"TSInterfaceBody","body":'
            b'[{"type":"TSPropertySignature","key":{"type":"NumericLiteral","value":0},"typeAnnotation":'
            + annotation
            + b"}]}}"
        )
    else:
        ast = b'{"type":"TSInterfaceDeclaration","body":'
    result, receipt, _, _ = transport_ast(tmp_path, ast)
    assert result == ast and receipt["unexpected_interfaces"] == 1
    assert receipt["numeric_keys"] == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "boolean_count",
        "bad_sampling",
        "file_totals",
        "outside_path",
        "retained_exceeds_count",
        "bad_byte_limit",
        "boolean_truncation",
        "count_sum",
        "retained_sum",
        "duplicate_path",
    ],
)
def test_method_sampling_metadata_rejects_unbound_or_inconsistent_counts(
    qualified, monkeypatch, mutation
):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            value = raw["methods"]
            row = value["file_coverage"]["rows"][0]
            if mutation == "boolean_count":
                value["source_files"] = True
            elif mutation == "bad_sampling":
                value["sampling"] = "unspecified"
            elif mutation == "file_totals":
                value["omitted_files"] = 1
            elif mutation == "outside_path":
                row["path"] = "../escaped.py"
            elif mutation == "retained_exceeds_count":
                row["retained"] = 2
            elif mutation == "bad_byte_limit":
                value["row_byte_limit"] += 1
            elif mutation == "boolean_truncation":
                row["identity_truncated"] = "false"
            elif mutation == "count_sum":
                value["count"] = 2
            elif mutation == "retained_sum":
                row["retained"] = 0
            else:
                value["file_coverage"]["rows"].append(dict(row))
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    assert result["summary"]["methods"] is None
    assert result["coverage"]["batches"][0]["status"] == "unvalidated_output_or_source"


def test_partial_method_file_metadata_keeps_counts_unknown_without_losing_rows(
    qualified, monkeypatch
):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            raw["source_files"].update(rows=[{"path": "src/app.py"}, {"path": "src/z.py"}], count=2)
            methods = raw["methods"]
            methods["rows"].append({**methods["rows"][0], "path": "src/z.py"})
            methods.update(count=2, source_files=2, retained_files=2)
            methods["file_coverage"].update(status="partial", count=2, limit=2, omitted=1)
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source(), source("src/z.py")], snapshot=qualified)
    modules = {row["path"]: row for row in result["modules"]}
    assert result["summary"]["methods"] == 2 and result["status"] == "partial"
    assert modules["src/app.py"]["method_rows_retained"] == 1
    assert modules["src/app.py"]["method_model_count"] == 1
    assert modules["src/z.py"]["method_rows_retained"] is None
    assert modules["src/z.py"]["method_model_count"] is None
    sections = result["coverage"]["batches"][0]["model_sections"]
    assert sections["methods"]["retained_files"] == 2
    assert sections["methods"]["file_coverage"]["omitted"] == 1


@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff"])
def test_ast_compatibility_preserves_escaped_surrogates_and_unicode_values(tmp_path, surrogate):
    from copy import deepcopy

    ast = {
        "body": [
            interface_ast(
                [property_ast(0)],
                annotation={
                    "type": "TSLiteralType",
                    "literal": {"type": "StringLiteral", "value": surrogate},
                },
                description="é😀",
            )
        ]
    }
    expected = deepcopy(ast)
    expected["body"][0]["body"]["body"][0]["key"]["value"] = "0"
    payload = json.dumps(ast, ensure_ascii=True, separators=(",", ":")).encode()
    result, receipt, _, _ = transport_ast(tmp_path, payload)
    assert json.loads(result) == expected
    assert receipt["numeric_keys"] == 1 and receipt["unexpected_interfaces"] == 0


@pytest.mark.parametrize(
    ("text", "line", "symbol", "kind", "expected"),
    [
        (
            "def _f():\n    value = work()\n    return value\n",
            2,
            "value",
            "local",
            "source_read_or_capture",
        ),
        (
            "def _f():\n    from errors import Failure\n    try: work()\n    except Failure: return\n",
            2,
            "Failure",
            "local",
            "source_read_or_capture",
        ),
        (
            "def _f():\n    reader = work()\n    def read(stream=reader): return stream.read()\n    return read\n",
            2,
            "reader",
            "local",
            "source_read_or_capture",
        ),
        (
            "def install():\n    @server.tool()\n    def read(): return result()\n",
            3,
            "read",
            "local",
            "decorated_function_binding",
        ),
        (
            "def _gate(approval):\n    raise RuntimeError('unavailable')\n",
            1,
            "approval",
            "parameter",
            "raising_stub_signature",
        ),
        (
            "def _f():\n    _receipt = work()\n    return True\n",
            2,
            "_receipt",
            "local",
            "intentional_discard_hint",
        ),
        (
            "def _request(hostname, deadline):\n    return hostname\n",
            1,
            "deadline",
            "parameter",
            "source_unread",
        ),
        (
            "def _f():\n    value = work()\ndef other():\n    value = other_work()\n    return value\n",
            2,
            "value",
            "local",
            "source_unread",
        ),
        (
            "def _f():\n    value = work()\n    def inner(value): return value\n    return inner\n",
            2,
            "value",
            "local",
            "source_unread",
        ),
    ],
)
def test_python_source_countercheck_preserves_reads_and_contracts(
    text, line, symbol, kind, expected
):
    from project_assess.joern_bindings import BindingCountercheck

    check = BindingCountercheck({"src/f.py": {"text": text}}, lambda: False)
    assert check.check("src/f.py", line, symbol, kind) == expected


@pytest.mark.parametrize(
    ("text", "line", "symbol", "kind", "expected"),
    [
        (
            "for (const listener of listeners) listener();",
            1,
            "listener",
            "local",
            "source_read_or_capture",
        ),
        (
            "for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }",
            1,
            "chunk",
            "local",
            "source_read_or_capture",
        ),
        (
            "function view(props: Props) { return <X x={props.value}/>; }",
            1,
            "props",
            "parameter",
            "source_read_or_capture",
        ),
        (
            "function view() { const supplied = value(); return rows.map(row => supplied[row]); }",
            1,
            "supplied",
            "local",
            "source_read_or_capture",
        ),
        (
            "function view() { const value = work(); }\nfunction other() { const value = otherWork(); return value; }",
            1,
            "value",
            "local",
            "source_unread",
        ),
        (
            "function view() { const value = work(); return rows.map(value => value); }",
            1,
            "value",
            "local",
            "source_unread",
        ),
        (
            "function view({ apps, ...props }: Props) { return apps.map(app => props.value); }",
            1,
            "props",
            "local",
            "source_read_or_capture",
        ),
        (
            "for (const [key, entry] of values) consume(entry);",
            1,
            "entry",
            "local",
            "source_read_or_capture",
        ),
        (
            "function view(capability = false) { return rows.map(row => capability && row); }",
            1,
            "capability",
            "local",
            "source_read_or_capture",
        ),
    ],
)
def test_javascript_source_countercheck_uses_binding_scopes(text, line, symbol, kind, expected):
    from project_assess.javascript_analysis import javascript_analyzer_identity
    from project_assess.joern_bindings import BindingCountercheck

    if not javascript_analyzer_identity()["available"]:
        pytest.skip("optional trusted JavaScript parser not installed")
    check = BindingCountercheck({"src/view.tsx": {"text": text}}, lambda: False)
    assert check.check("src/view.tsx", line, symbol, kind) == expected


def test_unavailable_or_bounded_source_qualification_is_unknown(monkeypatch):
    from project_assess import javascript_analysis
    from project_assess.joern_bindings import BindingCountercheck

    monkeypatch.setattr(
        javascript_analysis, "javascript_analyzer_identity", lambda: {"available": False}
    )
    sources = {"view.ts": {"text": "const unused = 1;"}, "broken.py": {"text": "def broken(:"}}
    check = BindingCountercheck(sources, lambda: False)
    assert check.check("view.ts", 1, "unused", "local") == "source_syntax_unavailable_or_bounded"
    assert check.check("broken.py", 1, "unused", "local") == "source_syntax_unavailable_or_bounded"
    expired = BindingCountercheck({"f.py": {"text": "unused = 1"}}, lambda: True)
    assert expired.check("f.py", 1, "unused", "local") == "source_syntax_unavailable_or_bounded"


def test_source_contradiction_suppresses_joern_lead_with_receipt(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        if output:
            raw = raw_result("src/app.py")
            raw["unread_bindings"]["rows"] = [raw["unread_bindings"]["rows"][1]]
            output.write_text(json.dumps(raw))
        return "complete"

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern(
        [source(text="def call(context):\n    unused = value()\n    return unused\n")],
        snapshot=qualified,
    )
    assert result["candidate_index"] == []
    check = result["coverage"]["batches"][0]["model_sections"]["unread_bindings"][
        "source_countercheck"
    ]
    assert check["counts"] == {"source_read_or_capture": 1}
    assert check["change_safety"] == "unverified"


def test_unparsed_source_leads_are_not_retained_as_cleanup(qualified, monkeypatch):
    monkeypatch.setattr(analysis, "_run", fake_run)
    result = analysis.analyze_joern(
        [source(text="def call(context):\n    unused = value(\n")], snapshot=qualified
    )
    assert result["candidate_index"] == []
    assert any("source qualification is incomplete" in gap for gap in result["gaps"])


def test_binding_countercheck_node_and_byte_limits_do_not_create_dead_leads(monkeypatch):
    from project_assess import joern_bindings

    sources = {"f.py": {"text": "def _f(value):\n    return 1\n"}}
    monkeypatch.setattr(joern_bindings, "MAX_NODES", 2)
    assert (
        joern_bindings.BindingCountercheck(sources, lambda: False).check(
            "f.py", 1, "value", "parameter"
        )
        == "source_syntax_unavailable_or_bounded"
    )
    monkeypatch.setattr(joern_bindings, "MAX_BYTES", 2)
    assert (
        joern_bindings.BindingCountercheck(sources, lambda: False).check(
            "f.py", 1, "value", "parameter"
        )
        == "source_syntax_unavailable_or_bounded"
    )


def test_original_public_parameter_contract_cannot_be_overruled_by_producer():
    from project_assess.joern_bindings import BindingCountercheck

    check = BindingCountercheck(
        {"public.py": {"text": "def callback(context):\n    return True\n"}}, lambda: False
    )
    assert (
        check.check("public.py", 1, "context", "parameter") == "public_signature_contract_unknown"
    )


def test_nested_javascript_read_resolution_work_is_bounded(monkeypatch):
    from project_assess import joern_bindings
    from project_assess.javascript_analysis import _parser, _walk, javascript_analyzer_identity

    if not javascript_analyzer_identity()["available"]:
        pytest.skip("optional trusted JavaScript parser not installed")
    depth = 24
    opening = "function _f(deadline) {" + "function _nested(){" * depth
    many_names = ",".join(f"different{i}" for i in range(100))
    text = opening + f"consume({many_names});" + "}" * (depth + 1)
    tree = _parser("f.js").parse(text.encode())
    assert not tree.root_node.has_error
    assert len(list(_walk(tree.root_node, 3001))) < 3000
    monkeypatch.setattr(joern_bindings, "MAX_NODES", 3000)
    check = joern_bindings.BindingCountercheck({"f.js": {"text": text}}, lambda: False)
    assert check.check("f.js", 1, "deadline", "parameter") == "source_syntax_unavailable_or_bounded"

    # Repeated references resolve through the cache instead of rescanning the
    # whole lexical chain, preserving a valid no-read hint within the same bound.
    repeated = opening + "consume(" + ",".join(["same"] * 100) + ");" + "}" * (depth + 1)
    cached = joern_bindings.BindingCountercheck({"f.js": {"text": repeated}}, lambda: False)
    assert cached.check("f.js", 1, "deadline", "parameter") == "source_unread"


def test_deadline_expiring_after_parse_cannot_qualify_unread_binding(monkeypatch):
    from project_assess import joern_bindings

    entered = False
    finish = joern_bindings._Bindings.finish

    def expires_in_resolution(index, expired):
        nonlocal entered
        entered = True
        return finish(index, expired)

    monkeypatch.setattr(joern_bindings._Bindings, "finish", expires_in_resolution)
    check = joern_bindings.BindingCountercheck(
        {"f.py": {"text": "def _f(deadline):\n    return result()\n"}}, lambda: entered
    )
    assert check.check("f.py", 1, "deadline", "parameter") == "source_syntax_unavailable_or_bounded"


def test_mismatched_binding_kind_lookup_does_not_walk_unrelated_declarations():
    from project_assess.joern_bindings import _Bindings

    index = _Bindings()
    for number in range(2000):
        index.declare(0, f"unrelated{number}", number + 2, "local")
    index.declare(0, "read_parameter", 1, "parameter")
    index.reads.append((0, "read_parameter"))
    assert index.finish(lambda: False) is index

    class NoFullWalk(dict):
        def items(self):
            pytest.fail("candidate fallback walked every source declaration")

    index.locations = NoFullWalk(index.locations)
    assert index.check(1, "read_parameter", "local") == "source_read_or_capture"
    assert index.check(1, "unknown", "local") == "source_binding_scope_unknown"


@pytest.mark.parametrize(
    ("member", "expected"),
    [
        ("        def get(self): return value\n", "source_read_or_capture"),
        ("        get = lambda self: value\n", "source_read_or_capture"),
        ("        def get(self, value): return value\n", "source_unread"),
    ],
)
def test_python_method_closures_skip_class_namespace(member, expected):
    from project_assess.joern_bindings import BindingCountercheck

    text = (
        "def _outer(value):\n    class Local:\n        value = 2\n"
        + member
        + "    return Local()\n"
    )
    check = BindingCountercheck({"f.py": {"text": text}}, lambda: False)
    assert check.check("f.py", 1, "value", "parameter") == expected


def test_interrupted_deep_dataflow_recovers_only_qualified_base_checkpoint(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            raw.update(checkpoint="base_before_dataflow", dataflow="error")
            raw["metadata"]["overlays"].remove("dataflowOss")
            raw["dataflow_analysis"] = {"status": "error"}
            raw["errors"] = [{"section": "dataflow_analysis", "error": "InterruptedDataflow"}]
            Path(str(output) + ".base.json").write_text(json.dumps(raw))
            output.unlink()
            return "timeout"
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["process_status"] == "timeout"
    assert batch["base_checkpoint_recovered"] is True
    assert result["coverage"]["modeled_files"] == 1
    assert result["topology"]["methods"] and result["topology"]["calls"]
    assert result["topology"]["edges"][0]["count"] == 7
    assert result["status"] == "partial"
    assert result["coverage"]["phases"]["detail"]["status"] == "complete"
    phase = result["coverage"]["phases"]["dataflow"]
    assert phase["methods_analyzed"] is None
    assert phase["methods_skipped"] is None
    assert phase["sinks_queried"] is None
    assert result["dataflow_analysis"]["batches"][0]["status"] == "error"
    assert result["dataflow_analysis"]["paths"] == []


@pytest.mark.parametrize("failure", ["timeout", "tool_failed", "workspace_limit", "query_output_limit"])
def test_owned_failure_recovers_only_completed_source_bound_flow_prefix(qualified, monkeypatch, failure):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            progress_checkpoint_files(output)
            return failure
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["process_status"] == failure
    assert batch["base_checkpoint_recovered"] is True
    assert batch["flow_checkpoint_recovered"] is True
    assert batch["model_metrics_scope"] == "base_before_dataflow"
    assert batch["producer_diagnostics"] == {
        "terminal_status": failure, "engine_failed": False, "model_pruned": False,
    }
    flow = result["dataflow_analysis"]["batches"][0]
    assert flow["checkpoint_recovered"] is True
    assert flow["status"] == "partial"
    assert flow["queries"]["sinks_selected"] == 2
    assert flow["queries"]["sinks_queried"] == flow["queries"]["sinks_pending"] == 1
    assert flow["queries"]["engine_queries"] == 1 and flow["queries"]["sinks_proven_empty"] == 0
    paths = result["dataflow_analysis"]["paths"]
    assert len(paths) == 1 and paths[0]["source"]["digest"] == captured["digest"]
    assert paths[0]["source"]["source_evidence_id"] == captured["evidence_id"]
    assert paths[0]["endpoint_id"] == flow["selection"]["endpoints"][0]["id"]
    assert result["status"] == "partial" and result["topology"]["methods"]
    assert any("unknown" in gap.lower() for gap in result["gaps"])


@pytest.mark.parametrize("model_pruned", [False, True])
def test_log_limit_withholds_flow_recovery_but_keeps_qualified_base(qualified, monkeypatch, model_pruned):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            progress_checkpoint_files(output)
            return analysis._ProcessStatus("log_limit", model_pruned=model_pruned)
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["base_checkpoint_recovered"] and not batch["flow_checkpoint_recovered"]
    assert batch["flow_checkpoint_status"] == "vetoed_incomplete_diagnostics"
    assert result["topology"]["methods"] and result["coverage"]["modeled_files"] == 1
    assert result["dataflow_analysis"]["paths"] == []
    assert batch["producer_diagnostics"]["engine_failed"] is False


@pytest.mark.parametrize("companion", ["symlink", "oversized", "unreadable"])
def test_invalid_optional_base_cannot_discard_a_valid_final_flow(qualified, monkeypatch, tmp_path, companion):
    if companion == "unreadable":
        def denied(*args):
            raise PermissionError("Synthetic checkpoint read refusal")

        monkeypatch.setattr(analysis, "_checkpoint_digest", denied)

    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = completed_flow_result(json.loads(output.read_text()))
            output.write_text(json.dumps(raw))
            base = Path(str(output) + ".base.json")
            if companion == "symlink":
                outside = tmp_path / "outside-base.json"
                outside.write_text(json.dumps(raw))
                base.symlink_to(outside)
            elif companion == "oversized":
                with base.open("wb") as stream:
                    stream.truncate(kwargs["limits"]["query_json_bytes"] + 1)
            else:
                base.write_text(json.dumps(raw))
                base.chmod(0)
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert not batch["base_checkpoint_recovered"] and not batch["flow_checkpoint_recovered"]
    assert batch["model_metrics_scope"] == "query_final"
    assert result["coverage"]["modeled_files"] == 1
    assert len(result["dataflow_analysis"]["paths"]) == 1
    assert result["dataflow_analysis"]["paths"][0]["source"]["digest"] == captured["digest"]


@pytest.mark.parametrize(
    "stage,pending,expected",
    [("finished", False, "valid"), ("finished", True, "invalid"),
     ("budget_exhausted", False, "invalid"), ("budget_exhausted", True, "valid")],
)
def test_progress_stage_matches_pending_work_without_creating_evidence(tmp_path, stage, pending, expected):
    raw = raw_result("src/app.py")
    raw["dataflow_analysis"] = {
        "queries": {}, "paths": {}, "skipped_methods": {},
    }
    raw = partial_flow_result(raw) if pending else completed_flow_result(raw)
    path = tmp_path / "progress.json"
    path.write_text(json.dumps(flow_progress_result(raw["dataflow_analysis"], "b" * 64, stage)))
    assert analysis._flow_progress(path, TEST_RUN_TOKEN, "b" * 64)["status"] == expected


def test_invalid_progress_does_not_override_independently_qualified_final_paths(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            final = completed_flow_result(json.loads(output.read_text()))
            base_path, _, envelope = progress_checkpoint_files(output)
            output.write_text(json.dumps(final))
            progress = flow_progress_result(final["dataflow_analysis"], envelope["base_sha256"], "budget_exhausted")
            Path(str(output) + ".flow-progress.json").write_text(json.dumps(progress))
            assert hashlib.sha256(base_path.read_bytes()).hexdigest() == progress["base_sha256"]
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    assert result["coverage"]["batches"][0]["flow_progress"] == {"status": "invalid"}
    assert len(result["dataflow_analysis"]["paths"]) == 1
    assert result["dataflow_analysis"]["paths"][0]["source"]["digest"] == captured["digest"]


@pytest.mark.parametrize(
    "mutation",
    ["nonce", "base_hash", "base_changed_after_checkpoint", "query_version", "missing_overlay", "extra_field", "truncated", "duplicate_json_field",
     "symlink", "oversized", "selected_count", "completed_count", "category_count",
     "plan_digest", "duplicate_endpoint", "uppercase_endpoint_id", "endpoint_extra_field", "unselected_path", "pending_path",
     "path_endpoint_kind", "endpoint_source_path", "endpoint_source_line", "incomplete_status"],
)
def test_unqualified_flow_checkpoint_falls_back_to_qualified_base(
    qualified, monkeypatch, tmp_path, mutation
):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if not output:
            return status
        base_path, path, value = progress_checkpoint_files(output)
        flow = value["dataflow_analysis"]
        if mutation == "nonce":
            value["run_token"] = "0" * 32 if value["run_token"] != "0" * 32 else "1" * 32
        elif mutation == "base_hash":
            value["base_sha256"] = "f" * 64
        elif mutation == "base_changed_after_checkpoint":
            base_path.write_text(json.dumps(json.loads(base_path.read_text()), indent=2))
        elif mutation == "query_version":
            value["query_version"] = "7"
        elif mutation == "missing_overlay":
            value["overlays"].remove("dataflowOss")
        elif mutation == "extra_field":
            value["raw_log"] = "UNTRUSTED_CHECKPOINT_SENTINEL"
        elif mutation == "selected_count":
            flow["queries"]["sinks_selected"] = 3
        elif mutation == "completed_count":
            flow["queries"]["sinks_queried"] = 3
        elif mutation == "category_count":
            flow["queries"]["by_category"]["breadth"]["queried"] = 1
        elif mutation == "plan_digest":
            flow["selection"]["plan_digest"] = "f" * 64
        elif mutation == "duplicate_endpoint":
            flow["selection"]["endpoints"][1] = flow["selection"]["endpoints"][0]
            flow["selection"] = flow_selection(flow["selection"]["endpoints"])
        elif mutation == "uppercase_endpoint_id":
            flow["selection"]["endpoints"][0]["id"] = "A" * 64
            flow["selection"] = flow_selection(flow["selection"]["endpoints"])
        elif mutation == "endpoint_extra_field":
            flow["selection"]["endpoints"][0]["raw_code"] = "UNTRUSTED_CHECKPOINT_SENTINEL"
        elif mutation == "unselected_path":
            flow["paths"]["rows"][0]["endpoint_id"] = "f" * 64
        elif mutation == "pending_path":
            flow["paths"]["rows"][0]["endpoint_id"] = flow["selection"]["endpoints"][1]["id"]
        elif mutation == "path_endpoint_kind":
            flow["paths"]["rows"][0]["kind"] = "parameter_to_return"
        elif mutation in {"endpoint_source_path", "endpoint_source_line"}:
            endpoint = flow["selection"]["endpoints"][0]
            endpoint["path" if mutation == "endpoint_source_path" else "line"] = (
                "src/not-captured.py" if mutation == "endpoint_source_path" else 99
            )
            flow["selection"] = flow_selection(flow["selection"]["endpoints"])
        elif mutation == "incomplete_status":
            flow["status"] = "error"
        if mutation == "truncated":
            path.write_text('{"schema_version":1,')
        elif mutation == "duplicate_json_field":
            path.write_text('{"schema_version":1,' + json.dumps(value)[1:])
        elif mutation == "symlink":
            outside = tmp_path / "outside-flow.json"
            outside.write_text(json.dumps(value))
            path.unlink()
            path.symlink_to(outside)
        elif mutation == "oversized":
            with path.open("wb") as stream:
                stream.truncate(32 * 1024**2 + 1)
        else:
            path.write_text(json.dumps(value))
        return "timeout"

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["base_checkpoint_recovered"] is True
    assert not batch["flow_checkpoint_recovered"]
    assert result["coverage"]["modeled_files"] == 1 and result["topology"]["methods"]
    assert result["dataflow_analysis"]["paths"] == []
    assert result["dataflow_analysis"]["status"] != "complete"
    assert "UNTRUSTED_CHECKPOINT_SENTINEL" not in json.dumps(result)


def test_worker_failure_vetoes_an_otherwise_valid_completed_checkpoint(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            progress_checkpoint_files(output)
            return analysis._ProcessStatus("timeout", engine_failed=True)
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["base_checkpoint_recovered"] and not batch["flow_checkpoint_recovered"]
    assert batch["producer_diagnostics"] == {
        "terminal_status": "timeout", "engine_failed": True, "model_pruned": False,
    }
    assert result["dataflow_analysis"]["paths"] == []
    assert result["dataflow_analysis"]["status"] == "error"


@pytest.mark.parametrize("identity", ["run_token", "query_version", "staged_bytes"])
def test_completed_checkpoint_cannot_override_unqualified_base_or_source_identity(
    qualified, monkeypatch, identity
):
    def run(argv, *, cwd, output=None, **kwargs):
        status = fake_run(argv, cwd=cwd, output=output, **kwargs)
        if not output:
            return status
        base_path, flow_path, envelope = progress_checkpoint_files(output)
        if identity == "staged_bytes":
            staged = cwd / "source/src/app.py"
            staged.chmod(0o600)
            staged.write_text("different captured bytes\n")
        else:
            base = json.loads(base_path.read_text())
            if identity == "run_token":
                base["run_token"] = "0" * 32 if base["run_token"] != "0" * 32 else "1" * 32
            else:
                base["query_version"] = "7"
            base_path.write_text(json.dumps(base))
            envelope["base_sha256"] = hashlib.sha256(base_path.read_bytes()).hexdigest()
            flow_path.write_text(json.dumps(envelope))
        return "timeout"

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert not batch["flow_checkpoint_recovered"] and not batch["base_checkpoint_recovered"]
    assert result["coverage"]["modeled_files"] == 0
    assert result["dataflow_analysis"]["paths"] == []


def test_unbound_path_row_does_not_discard_an_independent_qualified_witness(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if not output:
            return status
        _, path, envelope = progress_checkpoint_files(output)
        flow = envelope["dataflow_analysis"]
        flow["queries"].update(sinks_queried=2, sinks_pending=0, sinks_omitted=0, engine_queries=2)
        flow["queries"]["by_category"]["breadth"]["queried"] = 1
        good = json.loads(json.dumps(flow["paths"]["rows"][0]))
        good["kind"] = "parameter_to_return"
        good["endpoint_id"] = flow["selection"]["endpoints"][1]["id"]
        good["sink"].update(line=4, name="return", node_type="RETURN")
        good["steps"][-1] = good["sink"]
        bad = flow["paths"]["rows"][0]
        bad["source"]["path"] = bad["steps"][0]["path"] = "src/not-captured.py"
        flow["paths"].update(count=2, rows=[bad, good])
        path.write_text(json.dumps(envelope))
        return "timeout"

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["flow_checkpoint_recovered"] is True
    flow = result["dataflow_analysis"]["batches"][0]
    assert flow["paths"]["omitted"] == 1 and flow["status"] == "partial"
    paths = result["dataflow_analysis"]["paths"]
    assert len(paths) == 1 and paths[0]["kind"] == "parameter_to_return"
    assert paths[0]["source"]["digest"] == captured["digest"]
    assert "src/not-captured.py" not in json.dumps(result)


def test_sdk_pruning_preserves_valid_witness_but_not_complete_coverage(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = completed_flow_result(json.loads(output.read_text()))
            output.write_text(json.dumps(raw))
            return analysis._ProcessStatus("complete", model_pruned=True)
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["producer_diagnostics"] == {
        "terminal_status": "complete", "engine_failed": False, "model_pruned": True,
    }
    flow = result["dataflow_analysis"]["batches"][0]
    assert flow["status"] == "partial" and flow["paths"]["count_is_lower_bound"] is True
    assert len(result["dataflow_analysis"]["paths"]) == 1
    assert result["dataflow_analysis"]["paths"][0]["source"]["digest"] == captured["digest"]
    assert result["status"] == "partial"
    assert any("prun" in gap.lower() for gap in result["gaps"])


def test_endpoint_identity_does_not_change_existing_normalized_path_identity(qualified, monkeypatch):
    identities = iter(("first-plan", "second-plan"))

    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = completed_flow_result(json.loads(output.read_text()))
            endpoint = raw["dataflow_analysis"]["selection"]["endpoints"][0]
            endpoint["id"] = hashlib.sha256(next(identities).encode()).hexdigest()
            raw["dataflow_analysis"]["selection"] = flow_selection([endpoint])
            raw["dataflow_analysis"]["paths"]["rows"][0]["endpoint_id"] = endpoint["id"]
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    first = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    second = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    before, after = first["dataflow_analysis"]["paths"][0], second["dataflow_analysis"]["paths"][0]
    assert before["endpoint_id"] != after["endpoint_id"]
    assert before["id"] == after["id"]


@pytest.mark.parametrize("python_outcome", ["timeout", "complete"])
def test_language_budget_reserves_javascript_time_and_rolls_forward_unused_time(
    qualified, monkeypatch, python_outcome
):
    clock, calls = [100.0], []
    monkeypatch.setattr(analysis, "_clock", lambda: clock[0])

    def run(argv, *, cwd, output=None, **kwargs):
        language = cwd.name
        calls.append((language, bool(output), clock[0], kwargs["stop"]))
        status = fake_run(argv, cwd=cwd, output=output, **kwargs)
        if output and language == "python":
            if python_outcome == "timeout":
                output.unlink()
                clock[0] = kwargs["stop"]
                return "timeout"
            clock[0] += 4
        else:
            clock[0] += 1
        return status

    monkeypatch.setattr(analysis, "_run", run)
    records = [
        source(),
        source("src/app.js", "function call(context) {\n  const unused = value();\n  return context;\n}\n"),
    ]
    result = analysis.analyze_joern(records, snapshot=qualified, analysis_profile="deep", deadline=140.0)
    python_calls = [row for row in calls if row[0] == "python"]
    javascript_calls = [row for row in calls if row[0] == "javascript"]
    assert len(python_calls) == len(javascript_calls) == 2
    assert python_calls[0][3] < 140.0
    assert all(start < stop <= 140.0 for _, _, start, stop in calls)
    assert javascript_calls[0][2] >= python_calls[-1][2]
    assert javascript_calls[0][3] == 140.0
    batches = {row["language"]: row for row in result["coverage"]["batches"]}
    assert batches["javascript"]["process_status"] == "complete"
    javascript_budget = batches["javascript"]["time_budget"]
    assert javascript_budget["assigned_seconds"] > 0
    assert 0 < javascript_budget["query_body_allowance_seconds"] <= javascript_budget["assigned_seconds"]
    assert javascript_budget["normalization_guard_seconds"] >= 0
    if python_outcome == "complete":
        assert javascript_budget["assigned_seconds"] > batches["python"]["time_budget"]["assigned_seconds"]
    else:
        assert batches["python"]["process_status"] == "timeout"
        assert result["status"] == "partial"
    assert result["limits"]["language_scheduling"]


@pytest.mark.parametrize(
    "counter,value",
    [("sinks_total", 3), ("sinks_eligible", 3), ("sinks_selected", 1),
     ("sinks_not_selected", 1), ("sinks_pending", 0), ("sinks_skipped", 1),
     ("sinks_queried", 0), ("sinks_omitted", 0), ("engine_queries", 0),
     ("sinks_proven_empty", 1), ("sinks_selected", True), ("sinks_pending", -1)],
)
def test_inconsistent_query_accounting_cannot_qualify_flow(qualified, monkeypatch, counter, value):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = partial_flow_result(json.loads(output.read_text()))
            raw["dataflow_analysis"]["queries"][counter] = value
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    assert result["dataflow_analysis"]["paths"] == []
    assert result["dataflow_analysis"]["status"] != "complete"
    assert result["status"] == "partial"


def test_not_selected_endpoints_are_distinct_from_pending_selected_work(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = partial_flow_result(json.loads(output.read_text()))
            flow = raw["dataflow_analysis"]
            endpoints = [flow_endpoint("src/app.py", 3, "named_effect_hint", identity=str(index))
                         for index in range(2048)]
            flow["selection"] = flow_selection(endpoints)
            flow["paths"]["rows"][0]["endpoint_id"] = endpoints[0]["id"]
            flow["queries"].update(
                sinks_total=2049, sinks_eligible=2049, sinks_selected=2048,
                sinks_not_selected=1, sinks_pending=2047, sinks_omitted=2048,
                by_category={name: {"candidates": 2049 if name == "named_effect_hint" else 0,
                                    "selected": 2048 if name == "named_effect_hint" else 0,
                                    "queried": 1 if name == "named_effect_hint" else 0}
                             for name in FLOW_CATEGORIES},
            )
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    flow = result["dataflow_analysis"]["batches"][0]
    assert flow["queries"]["sinks_not_selected"] == 1
    assert flow["queries"]["sinks_pending"] == 2047
    assert flow["queries"]["sinks_queried"] == 1
    assert len(flow["selection"]["endpoints"]) == 2048
    assert flow["status"] == "partial" and flow["paths"]["count_is_lower_bound"] is True
    assert len(result["dataflow_analysis"]["paths"]) == 1


def test_proven_empty_is_completed_without_claiming_an_engine_call(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = partial_flow_result(json.loads(output.read_text()))
            flow = raw["dataflow_analysis"]
            flow["queries"].update(engine_queries=0, sinks_proven_empty=1)
            flow["paths"].update(count=0, rows=[])
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text='def call(context):\n    unused = value()\n    print("fixed")\n    return context\n')
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    flow = result["dataflow_analysis"]["batches"][0]
    assert flow["queries"]["sinks_queried"] == flow["queries"]["sinks_proven_empty"] == 1
    assert flow["queries"]["engine_queries"] == 0
    assert flow["queries"]["sinks_pending"] == 1
    assert flow["status"] == "partial" and result["dataflow_analysis"]["paths"] == []
    assert "unknown" in flow["caveat"].lower()


def test_proven_empty_only_coverage_cannot_supply_a_path_witness(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = completed_flow_result(json.loads(output.read_text()))
            raw["dataflow_analysis"]["queries"].update(engine_queries=0, sinks_proven_empty=1)
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    assert result["dataflow_analysis"]["paths"] == []
    assert result["dataflow_analysis"]["status"] != "complete"
    assert result["status"] == "partial"


@pytest.mark.parametrize("bound", ["deadline", "retention"])
def test_pending_work_or_retention_omissions_cannot_be_reported_as_complete(qualified, monkeypatch, bound):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            if bound == "deadline":
                raw = partial_flow_result(raw)
                raw["dataflow"] = raw["dataflow_analysis"]["status"] = "complete"
                raw["dataflow_analysis"]["paths"].update(status="complete", count_is_lower_bound=False)
            else:
                raw = completed_flow_result(raw)
                raw["dataflow_analysis"]["paths"].update(status="partial", count=2, omitted=1)
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    captured = source(text="def call(context):\n    unused = value()\n    print(context)\n    return context\n")
    result = analysis.analyze_joern([captured], snapshot=qualified, analysis_profile="deep")
    if bound == "deadline":
        assert result["status"] == "partial"
        assert result["dataflow_analysis"]["status"] != "complete"
        assert result["dataflow_analysis"]["paths"] == []
        return
    flow = result["dataflow_analysis"]["batches"][0]
    assert flow["status"] == "partial" and result["status"] == "partial"
    assert len(result["dataflow_analysis"]["paths"]) == 1
    assert flow["queries"]["sinks_pending"] == 0 and flow["paths"]["omitted"] == 1
    assert "unknown" in flow["caveat"].lower()


@pytest.mark.parametrize("unqualified", ["missing_checkpoint", "completed_flow"])
def test_interrupted_process_cannot_promote_an_unqualified_result(
    qualified, monkeypatch, unqualified
):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            if unqualified == "missing_checkpoint":
                raw["dataflow"] = "error"
                raw["dataflow_analysis"] = {"status": "error"}
                raw["metadata"]["overlays"].remove("dataflowOss")
            else:
                raw["checkpoint"] = "base_before_dataflow"
            output.write_text(json.dumps(raw))
            return "timeout"
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["process_status"] == "timeout"
    assert not batch["base_checkpoint_recovered"]
    assert batch["status"] == "unvalidated_output_or_source"
    assert result["coverage"]["modeled_files"] == 0
    assert result["topology"]["methods"] == []
    assert result["summary"]["methods"] is None


@pytest.mark.parametrize("failure", ["tool_failed", "timeout"])
@pytest.mark.parametrize("primary", ["partial", "error", "not_run", "malformed", "missing"])
def test_immutable_base_survives_failed_dataflow_final_output(
    qualified, monkeypatch, failure, primary
):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            base = json.loads(output.read_text())
            base.update(checkpoint="base_before_dataflow", dataflow="error")
            base["metadata"]["overlays"].remove("dataflowOss")
            base["dataflow_analysis"] = {"status": "error"}
            base["errors"] = [{"section": "dataflow_analysis", "error": "InterruptedDataflow"}]
            Path(str(output) + ".base.json").write_text(json.dumps(base))
            if primary == "missing":
                output.unlink()
            elif primary == "malformed":
                output.write_text('{"partially written":')
            else:
                raw["dataflow"] = primary
                if primary == "not_run":
                    raw.pop("dataflow_analysis")
                    raw["metadata"]["overlays"].remove("dataflowOss")
                else:
                    raw["dataflow_analysis"]["status"] = primary
                raw["methods"]["rows"][0]["name"] = "from_incomplete_final"
                output.write_text(json.dumps(raw))
            return failure
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["process_status"] == failure
    assert batch["base_checkpoint_recovered"] is True
    assert result["coverage"]["modeled_files"] == 1
    assert result["topology"]["methods"][0]["name"] == "call"
    assert result["topology"]["edges"][0]["count"] == 7
    assert result["coverage"]["phases"]["detail"]["status"] == "complete"
    assert result["dataflow_analysis"]["paths"] == []
    assert result["coverage"]["phases"]["dataflow"]["methods_analyzed"] is None
    assert result["coverage"]["phases"]["dataflow"]["sinks_queried"] is None
    assert result["status"] == "partial"


def test_symlink_base_checkpoint_cannot_recover_source_facts(qualified, monkeypatch, tmp_path):
    outside = tmp_path / "outside-query.json"

    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            raw.update(checkpoint="base_before_dataflow", dataflow="error")
            raw["metadata"]["overlays"].remove("dataflowOss")
            raw["dataflow_analysis"] = {"status": "error"}
            outside.write_text(json.dumps(raw))
            Path(str(output) + ".base.json").symlink_to(outside)
            output.unlink()
            return "tool_failed"
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    assert not result["coverage"]["batches"][0]["base_checkpoint_recovered"]
    assert result["coverage"]["modeled_files"] == 0
    assert result["topology"]["methods"] == []
    assert result["summary"]["methods"] is None


def test_base_checkpoint_cannot_override_a_captured_source_digest_mismatch(qualified, monkeypatch):
    def run(argv, *, output=None, cwd, **kwargs):
        status = fake_run(argv, output=output, cwd=cwd, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            raw.update(checkpoint="base_before_dataflow", dataflow="error")
            raw["metadata"]["overlays"].remove("dataflowOss")
            raw["dataflow_analysis"] = {"status": "error"}
            Path(str(output) + ".base.json").write_text(json.dumps(raw))
            output.unlink()
            staged = cwd / "source" / "src/app.py"
            staged.chmod(0o600)
            staged.write_text("different captured source\n")
            return "timeout"
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert not batch["base_checkpoint_recovered"]
    assert batch["status"] == "unvalidated_output_or_source"
    assert result["coverage"]["modeled_files"] == 0
    assert result["topology"]["methods"] == []


def test_standard_never_recovers_a_companion_checkpoint(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            raw.update(checkpoint="base_before_dataflow", dataflow="error")
            raw["dataflow_analysis"] = {"status": "error"}
            Path(str(output) + ".base.json").write_text(json.dumps(raw))
            output.unlink()
            return "tool_failed"
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified)
    batch = result["coverage"]["batches"][0]
    assert not batch["base_checkpoint_recovered"]
    assert result["coverage"]["modeled_files"] == 0
    assert result["summary"]["dataflow"] == "not_run"


def test_standard_provider_rejects_unrequested_dataflow(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            raw["dataflow"] = "complete"
            raw["metadata"]["overlays"].append("dataflowOss")
            output.write_text(json.dumps(raw))
        return status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="standard")
    assert result["status"] == "partial"
    assert result["summary"]["dataflow"] == "not_run"
    assert result["coverage"]["batches"][0]["status"] == "unvalidated_output_or_source"
    assert result["coverage"]["modeled_files"] == 0
    assert result["dataflow_analysis"]["paths"] == []


def test_dataflow_service_filters_and_pages_frozen_paths_without_scoring(tmp_path, monkeypatch):
    from project_assess import collector
    from project_assess.service import AssessmentService

    root = tmp_path / "project"
    files = {
        "src/start.py": "def start(value):\n    checked = value\n    return finish(checked)\n",
        "src/finish.py": "def finish(value):\n    first = value\n    return first\n",
        "tests/test_flow.py": "def test_flow(value):\n    return value\nraise AssertionError('must not execute')\n",
    }
    for path, text in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def analyze(name, sources, **options):
        by_path = {row["path"]: row for row in sources}

        def node(path, line):
            record = by_path[path]
            return {
                "path": path,
                "line": line,
                "name": "value",
                "method": path + ":method",
                "node_type": "IDENTIFIER",
                "source_evidence_id": record["evidence_id"],
                "digest": record["digest"],
            }

        paths = []
        if name == "joern":
            for index, locations in enumerate(
                [
                    [("src/start.py", 1), ("src/finish.py", 2)],
                    [("src/start.py", 2), ("src/finish.py", 3)],
                    [("tests/test_flow.py", 1), ("tests/test_flow.py", 2)],
                ]
            ):
                steps = [node(path, at) for path, at in locations]
                paths.append(
                    {
                        "id": f"jf-fixture-{index}",
                        "kind": "parameter_to_return",
                        "source": steps[0],
                        "sink": steps[-1],
                        "steps": steps,
                        "interprocedural": index < 2,
                    }
                )
        return {
            "schema_version": 1,
            "analyzer": {"name": name, "version": "fixture"},
            "available": True,
            "configuration": {},
            "limits": {},
            "status": "complete",
            "coverage": {
                "phases": {"dataflow": {"status": "complete", "retained_paths": len(paths)}}
            },
            "gaps": [],
            "candidates": [],
            "candidate_index": [],
            "modules": [{"path": row["path"], "role": row["role"]} for row in sources],
            "summary": {"candidate_count": 0, "dataflow": "complete", "value_paths": len(paths)},
            "dataflow_analysis": {"status": "complete", "paths": paths, "batches": []},
        }

    monkeypatch.setattr(collector, "run_analyzer", analyze)
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root, analysis_profile="deep")
    query = service.query_evidence(snapshot["id"], view="dataflow", limit=1)
    assert query["matched"] == 3 and query["returned"] == 1 and query["next_offset"] == 1
    second = service.query_evidence(
        snapshot["id"], view="dataflow", limit=1, offset=query["next_offset"]
    )
    assert second["items"][0]["id"] != query["items"][0]["id"]
    target = service.query_evidence(snapshot["id"], view="dataflow", path="src/finish.py", line=3)
    assert target["matched"] == 1 and target["items"][0]["id"] == "jf-fixture-1"
    assert (
        service.query_evidence(snapshot["id"], view="dataflow", role="production")["matched"] == 2
    )
    assert service.query_evidence(snapshot["id"], view="dataflow", role="test")["matched"] == 1
    original = service.query_evidence(snapshot["id"], view="dataflow")
    for path in files:
        (root / path).write_text("changed after capture\n")
    assert service.query_evidence(snapshot["id"], view="dataflow") == original
    report = service.get_report(snapshot["id"])
    assert report["review"] is None and report["goals"] is None
    assert "dataflow_analysis" not in snapshot["facts"]["optional_analysis"]["joern"]


def test_dataflow_service_exposes_pending_endpoint_context_without_value_paths(tmp_path, monkeypatch):
    from project_assess import collector
    from project_assess.service import AssessmentService

    root = tmp_path / "project"
    for path in ("src/pending.py", "tests/test_pending.py"):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("def pending(value):\n    return value\nraise AssertionError('must not execute')\n")
    captured = {}

    def analyze(name, sources, **options):
        captured.update({row["path"]: row for row in sources})
        endpoints = []
        if name == "joern":
            for row in sources:
                endpoints.append({
                    **flow_endpoint(row["path"], 2, "breadth", "parameter_to_return"),
                    "source_evidence_id": row["evidence_id"], "digest": row["digest"], "status": "pending",
                })
        selection = flow_selection(endpoints)
        queries = {"sinks_total": len(endpoints), "sinks_selected": len(endpoints),
                   "sinks_pending": len(endpoints), "sinks_queried": 0}
        return {
            "schema_version": 1, "analyzer": {"name": name, "version": "fixture"},
            "available": True, "configuration": {}, "limits": {}, "status": "partial",
            "coverage": {"phases": {"dataflow": {"status": "partial", "retained_paths": 0}}},
            "gaps": ["Selected endpoints remain pending; missing flows are unknown"],
            "candidates": [], "candidate_index": [],
            "modules": [{"path": row["path"], "role": row["role"]} for row in sources],
            "summary": {"candidate_count": 0, "dataflow": "partial", "value_paths": 0},
            "dataflow_analysis": {
                "status": "partial", "paths": [],
                "batches": [{"language": "python", "status": "partial", "selection": selection,
                             "queries": queries, "checkpoint_recovered": False}] if endpoints else [],
            },
        }

    monkeypatch.setattr(collector, "run_analyzer", analyze)
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root, analysis_profile="deep")
    first = service.query_evidence(snapshot["id"], view="dataflow", limit=1)
    second = service.query_evidence(snapshot["id"], view="dataflow", limit=1, offset=first["next_offset"])
    assert first["matched"] == 2 and first["returned"] == 1 and first["next_offset"] == 1
    assert first["items"][0]["id"] != second["items"][0]["id"]
    row = service.query_evidence(snapshot["id"], view="dataflow", path="tests/test_pending.py", line=2)["items"][0]
    assert row["record_type"] == "dataflow_endpoint" and row["status"] == "pending"
    assert row["source_evidence_id"] == captured[row["path"]]["evidence_id"]
    assert row["digest"] == captured[row["path"]]["digest"]
    assert row["selection_policy"] == "priority_file_method_round_robin_v1"
    assert row["language"] == "python" and len(row["plan_digest"]) == 64
    assert service.query_evidence(snapshot["id"], view="dataflow", role="production")["matched"] == 1
    assert service.query_evidence(snapshot["id"], view="dataflow", role="test")["matched"] == 1
    coverage = next(scope["query_coverage"][0] for scope in first["analysis_scope"] if scope.get("query_coverage"))
    assert coverage["queries"]["sinks_pending"] == coverage["queries"]["sinks_selected"] == 2
    assert coverage["queries"]["sinks_queried"] == 0 and not coverage["checkpoint_recovered"]
    assert "unknown" in first["caveat"].lower()
    assert service.get_report(snapshot["id"])["review"] is None


@pytest.mark.parametrize(
    "marker",
    [
        b"SolveTask failed",
        b"java.lang.StackOverflowError",
        b"java.lang.OutOfMemoryError",
        b"java.util.concurrent.ExecutionException:",
    ],
)
@pytest.mark.parametrize("exit_code", [0, 1])
def test_engine_failures_are_detected_across_log_chunks(tmp_path, capsys, marker, exit_code):
    at = len(marker) // 2
    code = (
        "import os,time\n"
        f"os.write(1, b'RAW_SOURCE_SENTINEL ' + {marker[:at]!r})\n"
        "time.sleep(0.05)\n"
        f"os.write(1, {marker[at:]!r})\n"
        f"raise SystemExit({exit_code})\n"
    )
    status = analysis._run(
        [sys.executable, "-c", code],
        workspace=tmp_path,
        cwd=tmp_path,
        env={},
        stop=time.monotonic() + 3,
        limits=analysis.joern_limits("standard"),
    )
    assert status == "analysis_engine_error"
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize(
    "marker",
    [b"Too many arguments for parameter:", b"Too many new tasks in expansion of unresolved output arguments"],
)
@pytest.mark.parametrize("finish", [True, False])
def test_sdk_pruning_is_recorded_separately_from_worker_failure(tmp_path, marker, finish):
    code = f"import os,time\nos.write(1, {marker!r})\n"
    if not finish:
        code += "time.sleep(10)\n"
    status = analysis._run(
        [sys.executable, "-c", code], workspace=tmp_path, cwd=tmp_path, env={},
        stop=time.monotonic() + 2, limits=analysis.joern_limits("standard"),
    )
    assert status == ("complete" if finish else "timeout")
    assert status.terminal_status == str(status)
    assert status.model_pruned is True
    assert status.engine_failed is False


@pytest.mark.parametrize("owned_failure", ["timeout", "log_limit", "workspace_limit", "query_output_limit"])
def test_engine_failure_marker_veto_survives_later_owned_failure(tmp_path, capsys, owned_failure):
    limits = analysis.joern_limits("standard")
    marker = b"java.lang.OutOfMemoryError"
    output = tmp_path / "result.json" if owned_failure == "query_output_limit" else None
    if owned_failure == "log_limit":
        limits["log_bytes"] = 1
    elif owned_failure == "workspace_limit":
        limits["workspace_bytes"] = 1
    elif output:
        limits["query_json_bytes"] = 1
    code = f"import os,time\nfrom pathlib import Path\nos.write(1, {marker!r})\n"
    if owned_failure in {"workspace_limit", "query_output_limit"}:
        name = "result.json" if output else "excess"
        code += f"time.sleep(0.1)\nPath({name!r}).write_text('excess')\n"
    code += "time.sleep(10)\n"
    status = analysis._run(
        [sys.executable, "-c", code], workspace=tmp_path, cwd=tmp_path, env={},
        stop=time.monotonic() + 2, limits=limits, output=output,
    )
    assert status == "analysis_engine_error"
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_zero_exit_engine_failure_discards_flows_but_preserves_base_facts(qualified, monkeypatch):
    def run(argv, *, output=None, **kwargs):
        status = fake_run(argv, output=output, **kwargs)
        if output:
            raw = json.loads(output.read_text())
            start = {
                "path": "src/app.py",
                "line": 1,
                "name": "context",
                "method": "call",
                "node_type": "METHOD_PARAMETER_IN",
            }
            end = {
                "path": "src/app.py",
                "line": 3,
                "name": "return",
                "method": "call",
                "node_type": "RETURN",
            }
            raw["dataflow_analysis"]["paths"].update(
                count=1,
                rows=[
                    {
                        "kind": "parameter_to_return",
                        "source": start,
                        "sink": end,
                        "steps": [start, end],
                        "interprocedural": False,
                    }
                ],
            )
            output.write_text(json.dumps(raw))
        return "analysis_engine_error" if output else status

    monkeypatch.setattr(analysis, "_run", run)
    result = analysis.analyze_joern([source()], snapshot=qualified, analysis_profile="deep")
    batch = result["coverage"]["batches"][0]
    assert batch["process_status"] == "analysis_engine_error"
    assert batch["base_checkpoint_recovered"] is False
    assert batch["dataflow_worker_failed"] is True
    assert result["coverage"]["modeled_files"] == 1
    assert result["topology"]["methods"] and result["topology"]["calls"]
    assert result["dataflow_analysis"]["paths"] == []
    assert result["coverage"]["phases"]["dataflow"]["methods_analyzed"] is None
