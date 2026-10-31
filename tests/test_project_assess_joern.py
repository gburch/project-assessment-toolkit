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


def source(path="src/app.py", text="def call(context):\n    unused = value()\n    return run()\n"):
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
        "query_version": "2",
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
        "methods": {**section([method]), "external_models": 17, "unlocated_models": 2},
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
    if output:
        path = next((cwd / "source").rglob("*.*")).relative_to(cwd / "source").as_posix()
        output.write_text(json.dumps(raw_result(path)))
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
    assert info["query_version"] == "2" and info["dataflow"] == "not_run"
    assert qualified["root"] not in json.dumps(info)
    deep = analysis.joern_limits("deep")
    assert deep["seconds"] == 1800 and deep["heap_gib"] == 8
    deep["seconds"] = 0
    assert analysis.joern_limits("deep")["seconds"] == 1800
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
        assert env["JAVA_OPTS"] == "-Xmx8g -XX:ActiveProcessorCount=2"
        assert env["_JAVA_OPTIONS"].startswith("-Xmx8g -XX:ActiveProcessorCount=2 ")
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
        '{"schema_version":1,"query_version":"2","schema_version":1}',
        '{"schema_version":true,"query_version":"2","dataflow":"not_run"}',
        '{"schema_version":1,"query_version":"2","dataflow":"run"}',
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
