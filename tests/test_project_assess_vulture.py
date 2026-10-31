"""The optional producer sees captured data, never project configuration or code."""

import hashlib
import importlib
import json
from importlib.metadata import PackageNotFoundError

import pytest

from project_assess import analyzer_registry as registry
from project_assess import vulture_analysis as analysis


def source(path, text, evidence_id="e-source", **fields):
    return {
        "path": path,
        "text": text,
        "evidence_id": evidence_id,
        "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
        **fields,
    }


@pytest.fixture
def installed():
    if not analysis.vulture_info()["available"]:
        pytest.skip("Optional vulture extra is not installed")
    return importlib.import_module("vulture")


def test_registry_is_small_static_opt_in_and_metadata_listing_does_not_import_provider(monkeypatch):
    def forbidden_import(name):
        raise AssertionError("Listing metadata must not import an analyzer")

    monkeypatch.setattr(analysis.importlib, "import_module", forbidden_import)
    descriptors = registry.list_analyzers()
    assert len(descriptors) == 1
    assert descriptors[0]["name"] == "vulture" and descriptors[0]["optional"]
    assert descriptors[0]["license"] == "MIT"
    assert registry.validate_analyzers(None) == registry.validate_analyzers([]) == ()
    assert registry.validate_analyzers(["vulture"]) == ("vulture",)
    assert registry.validate_analyzers(("vulture",)) == ("vulture",)
    with pytest.raises(ValueError, match="registered"):
        registry.run_analyzer("project.plugins.custom", [])


@pytest.mark.parametrize(
    "selection",
    [
        "vulture",
        True,
        {"vulture"},
        [True],
        ["vulture", "vulture"],
        ["python_ast"],
        ["swift_command"],
    ],
)
def test_selection_rejects_implicit_plugins_duplicates_and_wrong_types(selection):
    with pytest.raises(ValueError):
        registry.validate_analyzers(selection)


def test_absent_extra_is_explicit_without_any_import_install_or_healthy_result(monkeypatch):
    def missing(_):
        raise PackageNotFoundError("vulture")

    def forbidden(_):
        raise AssertionError("Missing optional dependencies must not be imported or installed")

    monkeypatch.setattr(analysis, "version", missing)
    monkeypatch.setattr(analysis.importlib, "import_module", forbidden)
    result = registry.run_analyzer("vulture", [source("src/app.py", "def unused(): pass\n")])
    assert not result["available"] and result["status"] == "unavailable"
    assert result["coverage"]["analyzed_files"] == 0
    assert result["candidates"] == result["candidate_index"] == []
    assert result["summary"]["producer_findings"] is None
    assert any("assessor environment" in gap for gap in result["gaps"])


def test_real_api_never_scavenges_config_whitelists_imports_or_executes_target(
    installed, monkeypatch, tmp_path, capsys
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Project discovery/configuration/whitelist APIs are forbidden")

    monkeypatch.setattr(installed.Vulture, "scavenge", forbidden)
    monkeypatch.setattr(installed.core, "make_config", forbidden)
    monkeypatch.setattr(installed.core.pkgutil, "get_data", forbidden)
    marker = tmp_path / "executed"
    text = f"import project_plugin\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('executed')\nraise AssertionError('must not execute')\ndef unused(payload):\n    return 1\n"
    snapshot = {"revision": "synthetic-source", "manifest_digest": "sha256:synthetic-manifest"}
    result = registry.run_analyzer("vulture", [source("src/app.py", text)], snapshot=snapshot)

    assert result["available"] and result["status"] == "complete"
    assert result["analyzer"]["version"]
    assert result["provenance"]["snapshot"] == snapshot
    assert result["configuration"]["project_config_loaded"] is False
    assert result["configuration"]["bundled_whitelists_loaded"] is False
    assert result["coverage"]["analyzed_files"] == 1
    assert not marker.exists()
    assert capsys.readouterr().out == ""
    candidate = next(row for row in result["candidates"] if row["metrics"]["symbol"] == "unused")
    assert candidate["kind"] == "unused_symbol" and candidate["metrics"]["code_type"] == "function"
    assert candidate["confidence"] == "low"
    assert candidate["metrics"]["producer_confidence"] == 60
    assert candidate["source_evidence_ids"] == ["e-source"]
    assert "severity" not in candidate


def test_unreachable_async_generator_yield_is_retained_with_counterevidence(installed):
    record = source(
        "tests/test_adapter.py", "async def stopped_source():\n    if False:\n        yield None\n"
    )
    result = registry.run_analyzer("vulture", [record])
    candidate = next(row for row in result["candidates"] if row["kind"] == "unreachable_statement")

    assert candidate["metrics"]["producer_confidence"] == 100
    assert candidate["confidence"] == "low"  # The producer's percent is not PAT confidence.
    assert (
        candidate["metrics"]["retention_hint"] == "unreachable_yield_can_preserve_generator_shape"
    )
    assert any("generator/async-generator" in text for text in candidate["counterevidence"])
    assert "permission to remove" in candidate["caveat"]
    assert record["text"].endswith("yield None\n")


def test_redundant_condition_preserves_reachable_body_and_distinct_unreachable_lead(installed):
    record = source(
        "src/conditions.py",
        "def run():\n    if True:\n        record_event()\nrun()\n"
        "def stopped():\n    return 1\n    ignored_event()\nstopped()\n",
    )
    result = registry.run_analyzer("vulture", [record])
    redundant = next(row for row in result["candidates"] if row["kind"] == "redundant_condition")
    unreachable = next(
        row for row in result["candidates"] if row["kind"] == "unreachable_statement"
    )

    assert redundant["metrics"]["producer_kind"] == "unreachable_code"
    assert redundant["metrics"]["message"] == "redundant if-condition"
    assert redundant["metrics"]["diagnostic_subtype"] == "redundant_condition"
    assert redundant["locations"] == [{"path": record["path"], "line": 2, "end_line": 3}]
    assert redundant["confidence"] == "low"
    assert redundant["source_evidence_ids"] == [record["evidence_id"]]
    assert any("body remains reachable" in text for text in redundant["counterevidence"])
    assert "retention_hint" not in redundant["metrics"]
    assert unreachable["locations"] == [{"path": record["path"], "line": 7, "end_line": 7}]
    assert unreachable["metrics"]["message"] == "unreachable code after 'return'"
    assert len(result["candidates"]) == 2


def test_public_exports_source_noqa_and_cross_file_uses_follow_explicit_producer_scope(installed):
    first = source(
        "src/library.py",
        "__all__ = ['public']\ndef public(): pass\ndef callback(): pass\ndef suppressed():  # noqa: V103\n    pass\ndef candidate(): pass\n",
        "e-library",
    )
    caller = source("src/entry.py", "from library import callback\ncallback()\n", "e-entry")
    result = registry.run_analyzer("vulture", [first, caller])
    names = {row["metrics"]["symbol"] for row in result["candidates"]}

    assert "candidate" in names
    assert "callback" not in names and "public" not in names and "suppressed" not in names
    assert result["configuration"]["source_noqa"] == "producer_honored"
    assert any("bundled whitelists were not loaded" in gap for gap in result["gaps"])
    assert "signatures or import side effects" in result["caveat"]


def test_source_identity_and_native_output_are_deterministic_and_redacted(installed, monkeypatch):
    monkeypatch.setattr(analysis, "_clock", lambda: 10)
    marker = "synthetic_sensitive_name"
    records = [
        source("src/a.py", f"def {marker}(): pass\n", "e-a"),
        source("tests/b.py", "unused_value = 3\n", "e-b"),
    ]

    def clean(value):
        return value.replace(marker, "[redacted]")

    first = registry.run_analyzer("vulture", records, redact=clean, deadline=20)
    second = registry.run_analyzer("vulture", list(reversed(records)), redact=clean, deadline=20)

    assert first == second
    assert marker not in json.dumps(first)
    assert first["modules"][0]["digest"] == records[0]["digest"]
    assert first["candidate_counts"]["total"] == len(first["candidate_index"])
    assert "elapsed" not in json.dumps(first) and "monotonic_time" not in json.dumps(first)


def test_digest_parse_and_node_omissions_never_become_clean_absence_claims(
    installed, monkeypatch, capsys
):
    mismatch = source("src/mismatch.py", "def unused(): pass\n")
    mismatch["digest"] = "sha256:" + "0" * 64
    broken = source("src/broken.py", "def private_syntax_marker(\n")
    monkeypatch.setitem(
        analysis._PROFILES, "standard", {**analysis._PROFILES["standard"], "nodes_per_file": 5}
    )
    large = source("src/large.py", "def sample(x):\n    if x:\n        return x + 1\n")
    result = registry.run_analyzer("vulture", [mismatch, broken, large])

    assert result["status"] == "partial" and result["coverage"]["analyzed_files"] == 0
    assert result["coverage"]["omissions"] == {
        "ast_node_limit": 1,
        "parse_error": 1,
        "source_digest_mismatch": 1,
    }
    assert result["candidates"] == []
    assert "private_syntax_marker" not in json.dumps(result)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_file_input_and_cooperative_deadline_bounds_are_explicit(installed, monkeypatch):
    records = [
        source("tests/test_one.py", "def first(): pass\n", "e-test"),
        source("src/app.py", "def product(): pass\n", "e-product"),
    ]
    monkeypatch.setitem(
        analysis._PROFILES, "standard", {**analysis._PROFILES["standard"], "files": 1}
    )
    result = registry.run_analyzer("vulture", records)
    assert result["status"] == "partial" and result["coverage"]["analyzed_files"] == 1
    assert result["modules"][0]["path"] == "src/app.py"
    assert result["coverage"]["omissions"] == {"file_limit": 1}
    expired = registry.run_analyzer("vulture", records, deadline=0)
    assert expired["status"] == "partial" and expired["coverage"]["analyzed_files"] == 0
    assert expired["summary"]["producer_findings"] is None
    assert expired["limits"]["deadline_mode"].startswith("cooperative")
    monkeypatch.setitem(
        analysis._PROFILES, "standard", {**analysis._PROFILES["standard"], "bytes": 1}
    )
    tiny = registry.run_analyzer("vulture", records)
    assert tiny["coverage"]["omissions"] == {"input_byte_limit": 2}


def test_output_budget_keeps_compact_index_and_producer_count_separate(installed, monkeypatch):
    monkeypatch.setattr(analysis, "MAX_CANDIDATES", 1)
    monkeypatch.setattr(analysis, "MAX_INDEX", 3)
    result = registry.run_analyzer(
        "vulture",
        [source("src/app.py", "\n".join(f"def unused_{index}(): pass" for index in range(6)))],
    )

    assert result["status"] == "partial"
    assert len(result["candidates"]) == 1 and len(result["candidate_index"]) == 3
    assert result["summary"]["producer_findings"] == 6
    assert result["coverage"]["omissions"]["producer_candidate_work_limit"] == 3


@pytest.mark.parametrize(
    "config",
    [
        {"whitelist": "project_whitelist.py"},
        {"command": "external-tool"},
        {"min_confidence": True},
        {"min_confidence": 101},
    ],
)
def test_configuration_is_data_only_and_rejects_executable_whitelists(config):
    with pytest.raises(ValueError):
        registry.run_analyzer("vulture", [], config=config)


@pytest.mark.parametrize(
    "path", ["../escape.py", "/absolute.py", "src/../../escape.py", "src\\windows.py"]
)
def test_only_captured_relative_source_labels_are_accepted(path):
    with pytest.raises(ValueError, match="relative paths"):
        registry.run_analyzer("vulture", [source(path, "")])


def test_non_python_capture_is_explicitly_unsupported(installed):
    result = registry.run_analyzer("vulture", [source("src/Main.swift", "struct Main {}")])
    assert result["status"] == "unsupported" and result["coverage"]["python_files"] == 0
    assert result["candidates"] == []
