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
        "query_version": "4",
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
                },
            }
            raw["methods"]["row_byte_limit"] = 48 * 1024**2 - 2 * 1024**2 - 4096
            raw["methods"]["file_coverage"]["byte_limit"] = 2 * 1024**2
        output.write_text(json.dumps(raw))
    return "complete"


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
    assert info["adapter_version"] == "6"
    assert info["query_version"] == "4" and info["dataflow"] == "deep_profile"
    assert qualified["root"] not in json.dumps(info)
    deep = analysis.joern_limits("deep")
    assert deep["seconds"] == 7200 and deep["heap_gib"] == 8
    deep["seconds"] = 0
    assert analysis.joern_limits("deep")["seconds"] == 7200
    assert info["javascript_transport"]["type_maps"] == "not_run"
    assert (
        info["javascript_transport"]["sha256"]
        == hashlib.sha256(analysis._ASTGEN_TRANSPORT.encode()).hexdigest()
    )


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


@pytest.mark.parametrize("config", [{"script": "project.sc"}, {"argv": []}, False])
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
        '{"schema_version":1,"query_version":"4","schema_version":1}',
        '{"schema_version":true,"query_version":"4","dataflow":"not_run"}',
        '{"schema_version":1,"query_version":"4","dataflow":"run"}',
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
            output.write_text(json.dumps(raw))
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


@pytest.mark.parametrize(
    "marker",
    [
        b"SolveTask failed",
        b"java.lang.StackOverflowError",
        b"java.lang.OutOfMemoryError",
        b"java.util.concurrent.ExecutionException:",
        b"Too many arguments for parameter:",
        b"Too many new tasks in expansion of unresolved output arguments",
    ],
)
def test_zero_exit_engine_failures_are_detected_across_log_chunks(tmp_path, capsys, marker):
    at = len(marker) // 2
    code = (
        "import os,time\n"
        f"os.write(1, b'RAW_SOURCE_SENTINEL ' + {marker[:at]!r})\n"
        "time.sleep(0.05)\n"
        f"os.write(1, {marker[at:]!r})\n"
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
