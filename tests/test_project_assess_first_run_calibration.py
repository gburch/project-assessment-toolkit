"""First-run evidence calibration fixtures, not claims of calibrated AI judgment."""

import hashlib
from copy import deepcopy

import pytest

from project_assess import collector
from project_assess.review_plan import build_review_plan, dimension_coverage
from project_assess.rubric import DIMENSIONS


def write(root, files):
    root.mkdir(parents=True, exist_ok=True)
    for path, content in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content if isinstance(content, bytes) else content.encode())


def assert_inert_repeatable_plan(root, files):
    hashes = {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in files}
    first = collector.collect(root, analysis_profile="deep")
    before = deepcopy(first)
    plan = build_review_plan(first)
    assert plan == build_review_plan(first)
    assert first == before
    assert set(plan["dimensions"]) == set(DIMENSIONS)
    assert (
        first["source"]["manifest_digest"]
        == collector.collect(root, analysis_profile="deep")["source"]["manifest_digest"]
    )
    assert hashes == {
        path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in files
    }
    entries = {entry["id"]: entry for entry in first["evidence"]}
    for pack in plan["dimensions"].values():
        assert not {"capability", "burden", "confidence", "burden_confidence"}.intersection(pack)
        assert pack["needs_follow_up"]
        for task in pack["source_tasks"]:
            assert task["digest"] == entries[task["evidence_id"]]["digest"]
            assert task["path"] == entries[task["evidence_id"]]["path"]
    return first, plan


def test_first_deep_python_utility_without_git_retains_simple_counterexample(tmp_path):
    files = {
        "utility.py": "raise RuntimeError('assessment must not import me')\ndef summarize(values):\n    return len(values)\n",
        "README.md": "# Usage\nA focused personal utility with no persistent state.\n",
    }
    write(tmp_path, files)
    snapshot, plan = assert_inert_repeatable_plan(tmp_path, files)
    assert snapshot["source"]["revision"] is None
    burden = next(
        entry["stats"] for entry in snapshot["evidence"] if entry["kind"] == "burden-analysis"
    )
    assert not any(row["kind"] == "complex_change_surface" for row in burden["leads"])
    assert {task["path"] for task in plan["dimensions"]["operability"]["source_tasks"]} == set(
        files
    )
    assert (
        "scope" in plan["dimensions"]["operability"]["questions"][0]
        or "failure" in plan["dimensions"]["operability"]["questions"][0]
    )


def test_first_deep_typescript_framework_exposes_extension_and_documented_command_context(tmp_path):
    files = {
        "src/contracts.ts": "export interface Adapter { run(value: string): string; }\n",
        "src/providers/local.ts": "import type {Adapter} from '../contracts';\nexport class LocalAdapter implements Adapter { run(value: string) { return value; } }\n",
        "src/plugin/registry.ts": "import {LocalAdapter} from '../providers/local';\nexport const adapters = new Map([['local', new LocalAdapter()]]);\n",
        "tests/local.test.ts": "import {LocalAdapter} from '../src/providers/local';\ntest('known variant', () => expect(new LocalAdapter().run('x')).toBe('x'));\n",
        "README.md": "# Framework setup\nSee `src/contracts.ts` and `src/providers/local.ts`.\n```sh\nnpm --prefix . run removed\n```\n",
        "package.json": '{"scripts":{"build":"must-not-execute"}}',
    }
    write(tmp_path, files)
    snapshot, plan = assert_inert_repeatable_plan(tmp_path, files)
    extension_paths = {task["path"] for task in plan["dimensions"]["extensibility"]["source_tasks"]}
    assert {
        "src/contracts.ts",
        "src/providers/local.ts",
        "src/plugin/registry.ts",
        "README.md",
        "package.json",
    } <= extension_paths
    doc = next(
        entry["stats"]
        for entry in snapshot["evidence"]
        if entry["kind"] == "documentation-analysis"
    )
    mismatch = next(
        command
        for command in doc["referenceEvidence"]["commands"]
        if command["script"] == "removed"
    )
    assert mismatch["status"] == "not_declared_in_captured_manifest"
    assert mismatch["manifest"] == "package.json"
    documentation = plan["dimensions"]["documentation"]
    assert any(
        "documented_script_mismatch_hint" in task["signal_kinds"]
        for task in documentation["source_tasks"]
    )
    assert not any(task["operation"] == "execute" for task in documentation["source_tasks"])


def test_first_deep_java_swift_sources_remain_reachable_with_semantic_limits(tmp_path):
    files = {
        "src/java/Adapter.java": "public interface Adapter { String run(String value); }\n",
        "src/swift/Adapter.swift": "protocol Adapter { func run(_ value: String) -> String }\n",
        "README.md": "# Adapters\nSupported contracts are `src/java/Adapter.java` and `src/swift/Adapter.swift`.\n",
    }
    write(tmp_path, files)
    snapshot, plan = assert_inert_repeatable_plan(tmp_path, files)
    pack = plan["dimensions"]["extensibility"]
    syntax_paths = {row["path"] for row in pack["coverage"]["syntax_gaps"]}
    assert syntax_paths == {"src/java/Adapter.java", "src/swift/Adapter.swift"}
    assert syntax_paths <= {task["path"] for task in pack["source_tasks"]}
    assert not pack["connections"]
    sources = [entry for entry in snapshot["evidence"] if entry["kind"] == "source"]
    assert len(sources) == 2
    assert all("decision_points" not in entry["stats"] for entry in sources)


def test_first_deep_concentrated_owner_exposes_complexity_and_change_context(tmp_path):
    body = "".join(
        f"        if value == {index}:\n            total += {index}\n" for index in range(45)
    )
    files = {
        "src/app/integration.py": "raise RuntimeError('must not execute')\nfrom pathlib import Path\ndef change(values):\n    total = 0\n    for value in values:\n"
        + body
        + "        total += len(Path('state.json').read_text())\n    return total\n",
        "src/app/service.py": "from .integration import change\ndef handle(values):\n    return change(values)\n",
        "tests/test_service.py": "from app.service import handle\ndef test_change():\n    assert handle([]) == 0\n",
        "docs/architecture.md": "# State ownership\n`src/app/integration.py` owns validation and the shared state change.\n",
    }
    write(tmp_path, files)
    snapshot, plan = assert_inert_repeatable_plan(tmp_path, files)
    burden = next(
        entry["stats"] for entry in snapshot["evidence"] if entry["kind"] == "burden-analysis"
    )
    complex_lead = next(row for row in burden["leads"] if row["kind"] == "complex_change_surface")
    assert complex_lead["metrics"]["decision_points"] >= 45
    assert complex_lead["cost_status"] == "not_established"
    tasks = {task["path"]: task for task in plan["dimensions"]["maintainability"]["source_tasks"]}
    assert "complex_change_surface" in tasks["src/app/integration.py"]["signal_kinds"]
    assert {"src/app/service.py", "tests/test_service.py", "docs/architecture.md"} <= set(tasks)
    assert plan["dimensions"]["maintainability"]["connections"]


def test_first_deep_generated_docs_retain_overlap_without_manual_upkeep_false_positive(tmp_path):
    shared = " ".join(f"shared-guidance-{index}" for index in range(40))
    files = {
        "README.md": f"# Usage\n{shared}\n",
        "docs/generated/copy.md": f"# Usage\n{shared}\n",
        "LICENSE.md": f"# Terms\n{shared}\n",
        "app.py": "raise RuntimeError('must not execute')\n",
    }
    write(tmp_path, files)
    snapshot, plan = assert_inert_repeatable_plan(tmp_path, files)
    doc = next(
        entry["stats"]
        for entry in snapshot["evidence"]
        if entry["kind"] == "documentation-analysis"
    )
    assert doc["exactDuplicates"] == [["README.md", "docs/generated/copy.md"]]
    assert doc["sections"]["passageLeads"]
    assert not any(row["kind"] == "repeated_guidance_passage" for row in doc["maintenanceLeads"])
    burden = next(
        entry["stats"] for entry in snapshot["evidence"] if entry["kind"] == "burden-analysis"
    )
    assert not any(
        row["kind"] in {"duplicate_guidance", "repeated_guidance_passage"}
        for row in burden["leads"]
    )
    assert "README.md" in {
        task["path"] for task in plan["dimensions"]["documentation"]["source_tasks"]
    }


@pytest.mark.parametrize(
    "omitted,content,material",
    [
        ("assets/screenshot.png", b"x" * 300, False),
        ("src/recovery.py", "# recovery state owner\n" * 20, True),
    ],
)
def test_first_deep_distinguishes_omitted_critical_source_from_binary_assets(
    tmp_path, monkeypatch, omitted, content, material
):
    monkeypatch.setattr(collector, "MAX_FILE_BYTES", 128)
    monkeypatch.setattr(collector, "MAX_SOURCE_FILE_BYTES", 128)
    files = {
        "app.py": "raise RuntimeError('must not execute')\n",
        "README.md": "# App\nRead-only evidence fixture.\n",
        omitted: content,
    }
    write(tmp_path, files)
    snapshot, plan = assert_inert_repeatable_plan(tmp_path, files)
    coverage = dimension_coverage(snapshot, "operability")
    assert not snapshot["complete"]
    assert plan["dimensions"]["operability"]["coverage"] == coverage
    assert bool(coverage["collection_blockers"]) is material
    if material:
        assert coverage["status"] == "partial"
        assert coverage["material_omissions"][0]["path"] == omitted
        assert not snapshot["facts"]["collection"]["supported_text_complete"]
    else:
        assert coverage["status"] == "complete"
        assert coverage["asset_only_omissions"][0]["path"] == omitted
        assert snapshot["facts"]["collection"]["supported_text_complete"]
