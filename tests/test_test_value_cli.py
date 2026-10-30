"""Behavioral proofs for the public CLI using one real, reusable pytest project."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import sysconfig
import venv
from pathlib import Path

import pytest
from coverage import CoverageData

SCRIPT = (
    Path(__file__).resolve().parents[1] / ".agents/skills/test-value/scripts/test_value_audit.py"
)


def invoke(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, args)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    base = tmp_path_factory.mktemp("test-value")
    root = base / "project"
    (root / "product").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pytest.ini").write_text("[pytest]\npythonpath = .\n")
    (root / "product/__init__.py").write_text(
        "def calculate(value):\n    if value < 0:\n        return -value\n    return value * 2\n"
    )
    (root / "tests/test_product.py").write_text(
        "import pytest\nfrom product import calculate\n"
        "def test_first():\n    assert calculate(1) == 2\n"
        "def test_repeat():\n    assert calculate(1) == 2\n"
        "def test_other_assertion():\n    assert calculate(2) == 4\n"
        "def test_unique_branch():\n    assert calculate(-3) == 3\n"
        "@pytest.fixture(scope='module')\n"
        "def prepared():\n    return calculate(9)\n"
        "def test_fixture_only(prepared):\n    assert prepared == 18\n"
        "@pytest.mark.parametrize('value', [1,2], ids=['a|b','dot[inner]'])\n"
        "def test_parameters(value):\n    assert calculate(value) == value * 2\n"
    )
    output = base / "collected"
    completed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--",
        "tests/test_product.py",
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    return root, output, json.loads((output / "report.json").read_text())


def test_real_collection_separates_unique_branches_shared_fixtures_and_distinct_assertions(
    sample,
    tmp_path,
):
    root, output, report = sample
    nodes = {row["nodeid"].split("::")[-1]: row for row in report["tests"]}
    ranked = {row["nodeid"].split("::")[-1] for row in report["rankedCandidates"]}
    assert {"test_first", "test_repeat", "test_other_assertion"} <= ranked
    assert nodes["test_first"]["signature"] == nodes["test_other_assertion"]["signature"]
    assert nodes["test_unique_branch"]["uniqueArcs"] > 0
    # Unique ordinary behavior is a review lead, not an automatic keep.  The
    # representative set still retains it when it supplies the marginal line
    # needed by the advisory ordinary-code target.
    assert "test_unique_branch" in ranked
    assert nodes["test_unique_branch"]["sourceSpan"]["sourceLines"] == 2
    assert 0 < nodes["test_unique_branch"]["overlapRatio"] < 1
    assert nodes["test_fixture_only"]["phaseFeatureCounts"]["setup"] > 0
    assert "test_fixture_only" not in ranked
    assert nodes["test_parameters[a|b]"]["outcome"] == "passed"
    assert nodes["test_parameters[dot[inner]]"]["outcome"] == "passed"
    assert report["policy"]["softTargetPercent"] == 70.0
    assert report["executableStatementCoverage"]["ordinary"]["statements"] == 4
    assert report["representativeSet"]["criticalCoveragePreserved"]
    assert report["representativeSet"]["retainedOrdinaryPercentOfExecutable"] >= 70
    # Same footprint, different protection: a real fault passes the first test,
    # but fails the second. The report must not describe either as safe to delete.
    mutant = tmp_path / "mutant"
    shutil.copytree(root, mutant, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    source = mutant / "product/__init__.py"
    source.write_text(source.read_text().replace("value * 2", "2"))
    for target, expected in [("test_first", 0), ("test_other_assertion", 1)]:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"tests/test_product.py::{target}"],
            cwd=mutant,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == expected, completed.stdout + completed.stderr
    assert all(item["recommendation"] == "investigate" for item in report["rankedCandidates"])
    rebuilt = invoke(
        "report",
        "--root",
        root,
        "--source",
        "product/__init__.py",
        "--coverage",
        output / ".coverage",
        "--tests",
        output / "tests.json",
        "--output",
        tmp_path / "report",
    )
    assert rebuilt.returncode == 0, rebuilt.stderr


def test_contextless_and_ambiguous_imports_do_not_claim_redundancy(sample, tmp_path):
    root, output, _ = sample
    original = CoverageData(basename=str(output / ".coverage"))
    original.read()
    contextless = CoverageData(basename=str(tmp_path / ".coverage"))
    contextless.add_arcs({file: original.arcs(file) or [] for file in original.measured_files()})
    contextless.write()
    completed = invoke(
        "report",
        "--root",
        root,
        "--coverage",
        tmp_path / ".coverage",
        "--tests",
        output / "tests.json",
        "--output",
        tmp_path / "no-context",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / "no-context/report.json").read_text())
    assert report["rankedCandidates"] == []
    assert any(gap["reason"] == "per-test-contexts-missing" for gap in report["gaps"])
    case = '<testcase classname="tests.test_product" name="test_first" time="1"/>'
    xml = tmp_path / "duplicate.xml"
    xml.write_text(f"<testsuite>{case}{case}</testsuite>")
    completed = invoke(
        "report",
        "--root",
        root,
        "--coverage",
        output / ".coverage",
        "--junit",
        xml,
        "--output",
        tmp_path / "ambiguous",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / "ambiguous/report.json").read_text())
    assert report["rankedCandidates"] == []
    assert any(gap["reason"] == "ambiguous-timing-identities" for gap in report["gaps"])
    first = next(row for row in report["tests"] if row["nodeid"].endswith("::test_first"))
    assert first["durationSeconds"] is None


def test_collection_uses_the_explicit_project_interpreter(sample, tmp_path):
    root, _, _ = sample
    environment = tmp_path / "project-python"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    interpreter = environment / "bin/python"
    site_packages = Path(
        subprocess.check_output(
            [str(interpreter), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            text=True,
        ).strip()
    )
    (site_packages / "test-dependencies.pth").write_text(sysconfig.get_path("purelib") + "\n")
    output = tmp_path / "project-run"
    completed = invoke(
        "collect",
        "--python",
        interpreter,
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--",
        "tests/test_product.py::test_first",
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    run = json.loads((output / "run.json").read_text())
    assert run["environment"]["python"] == str(interpreter)
    assert json.loads((output / "report.json").read_text())["healthyCollection"]


def test_explicit_critical_source_and_test_are_protected(sample, tmp_path):
    root, output, _ = sample
    inherited = tmp_path / "inherited-policy"
    shutil.copytree(output, inherited)
    manifest_path = inherited / "run.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["policy"] = {
        "softTargetPercent": 55.0,
        "criticalSources": ["product/__init__.py"],
        "protectedTests": ["*::test_first"],
    }
    manifest_path.write_text(json.dumps(manifest))
    completed = invoke(
        "report",
        "--root",
        root,
        "--source",
        "product",
        "--coverage",
        inherited / ".coverage",
        "--tests",
        inherited / "tests.json",
        "--output",
        tmp_path / "critical",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / "critical/report.json").read_text())
    assert report["policy"]["softTargetPercent"] == 55.0
    protected = {row["nodeid"] for row in report["tests"] if row["critical"]}
    assert "tests/test_product.py::test_first" in protected
    assert report["representativeSet"]["criticalCoveragePreserved"]
    assert (
        report["representativeSet"]["criticalFeaturesRetained"]
        == report["representativeSet"]["criticalObservedFeatures"]
    )
    assert not report["representativeSet"]["proposedRemovals"]


def test_representative_selection_prefers_lower_runtime_witness(sample, tmp_path):
    root, output, _ = sample
    retimed = tmp_path / "retimed"
    shutil.copytree(output, retimed)
    tests_path = retimed / "tests.json"
    tests = json.loads(tests_path.read_text())
    for row in tests["tests"]:
        if row["nodeid"].endswith("::test_first"):
            row["phases"]["call"]["seconds"] = 0.001
        elif row["phases"].get("call"):
            row["phases"]["call"]["seconds"] = 100.0
    tests_path.write_text(json.dumps(tests))
    manifest_path = retimed / "run.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifactHashes"]["tests.json"] = (
        "sha256:" + hashlib.sha256(tests_path.read_bytes()).hexdigest()
    )
    manifest_path.write_text(json.dumps(manifest))
    completed = invoke(
        "report",
        "--root",
        root,
        "--source",
        "product",
        "--coverage",
        retimed / ".coverage",
        "--tests",
        tests_path,
        "--output",
        tmp_path / "retimed-report",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / "retimed-report/report.json").read_text())
    selected = report["representativeSet"]["tests"]
    assert "tests/test_product.py::test_first" in selected
    assert "tests/test_product.py::test_repeat" not in selected
    removals = {row["nodeid"]: row for row in report["representativeSet"]["proposedRemovals"]}
    assert "tests/test_product.py::test_first" not in removals
    assert "tests/test_product.py::test_repeat" in removals
    assert removals["tests/test_product.py::test_repeat"]["replacementProtection"]


def test_unmatched_critical_obligations_block_representative_removals(sample, tmp_path):
    root, output, _ = sample
    imported = tmp_path / "unmatched-policy"
    shutil.copytree(output, imported)
    manifest_path = imported / "run.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["policy"] = {
        "softTargetPercent": 70.0,
        "criticalSources": ["product/never-measured.py"],
        "protectedTests": ["*::missing_test"],
    }
    manifest_path.write_text(json.dumps(manifest))
    completed = invoke(
        "report",
        "--root",
        root,
        "--source",
        "product",
        "--coverage",
        imported / ".coverage",
        "--tests",
        imported / "tests.json",
        "--output",
        tmp_path / "unmatched-report",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / "unmatched-report/report.json").read_text())
    reasons = {gap["reason"] for gap in report["gaps"]}
    assert "critical-source-pattern-unmatched" in reasons
    assert "protected-test-pattern-unmatched" in reasons
    representative = report["representativeSet"]
    assert representative["criticalCoverageStatus"] == "unmeasured"
    assert not representative["criticalCoveragePreserved"]
    assert not representative["representativeComplete"]
    assert not representative["proposedRemovals"]
    assert representative["targetMetWithinObserved"]
    assert representative["ordinaryCoverageAtOrAboveSoftTarget"]


def test_greedy_skips_branch_only_rows_when_a_new_line_is_available(tmp_path):
    root = tmp_path / "branch-project"
    (root / "product").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pytest.ini").write_text("[pytest]\npythonpath = .\n")
    (root / "product/__init__.py").write_text(
        "def choose(value):\n"
        "    for _ in range(value): pass\n"
        "    return 1\n\n"
        "def extra_one():\n    return 2\n\n"
        "def extra_two():\n    return 3\n"
    )
    (root / "tests/test_sample.py").write_text(
        "from product import choose, extra_one, extra_two\n\n"
        "def test_seed():\n    assert choose(False) == 1\n\n"
        "def test_branch_only():\n    assert choose(True) == 1\n\n"
        "def test_line_one():\n    assert extra_one() == 2\n\n"
        "def test_line_two():\n    assert extra_two() == 3\n"
    )
    output = tmp_path / "branch-collected"
    completed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--protect-test",
        "*::test_seed",
        "--output",
        output,
        "--",
        "tests/test_sample.py",
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    report = json.loads((output / "report.json").read_text())
    representative = report["representativeSet"]
    assert representative["representativeComplete"]
    assert representative["targetMetWithinObserved"]
    assert "tests/test_sample.py::test_seed" in representative["tests"]
    assert "tests/test_sample.py::test_branch_only" not in representative["tests"]
    assert any(
        row["nodeid"].endswith("::test_branch_only") and row["uniqueArcs"] > 0
        for row in report["tests"]
    )


def test_failed_collection_and_changed_sources_preserve_gaps(sample, tmp_path):
    root, output, _ = sample
    broken = tmp_path / "broken"
    shutil.copytree(root, broken, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    (broken / "tests/test_broken.py").write_text(
        "raise RuntimeError('synthetic collection error')\n"
    )
    completed = invoke(
        "collect",
        "--root",
        broken,
        "--source",
        "product",
        "--output",
        tmp_path / "failed",
        "--",
        "tests",
    )
    assert completed.returncode != 0
    report = json.loads((tmp_path / "failed/report.json").read_text())
    assert report["rankedCandidates"] == []
    assert not report["healthyCollection"]
    assert any(gap["reason"] == "pytest-run-incomplete-or-failed" for gap in report["gaps"])
    tampered = tmp_path / "tampered"
    shutil.copytree(output, tampered)
    tests = json.loads((tampered / "tests.json").read_text())
    tests["tests"][0]["phases"]["call"]["seconds"] = 999
    (tampered / "tests.json").write_text(json.dumps(tests))
    completed = invoke(
        "report",
        "--root",
        root,
        "--coverage",
        tampered / ".coverage",
        "--tests",
        tampered / "tests.json",
        "--output",
        tmp_path / "tampered-report",
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((tmp_path / "tampered-report/report.json").read_text())
    assert report["rankedCandidates"] == []
    assert any(gap["reason"] == "artifact-hash-unbound-or-mismatched" for gap in report["gaps"])
    source = root / "product/__init__.py"
    previous = source.read_text()
    try:
        source.write_text(previous + "# changed after collection\n")
        completed = invoke(
            "report",
            "--root",
            root,
            "--coverage",
            output / ".coverage",
            "--tests",
            output / "tests.json",
            "--output",
            tmp_path / "stale",
        )
        assert completed.returncode == 0, completed.stderr
        report = json.loads((tmp_path / "stale/report.json").read_text())
        assert report["rankedCandidates"] == []
        assert any(gap["reason"] == "source-changed-since-collection" for gap in report["gaps"])
    finally:
        source.write_text(previous)
    test_source = root / "tests/test_product.py"
    previous_test = test_source.read_text()
    try:
        test_source.write_text(previous_test + "\n# changed after collection\n")
        completed = invoke(
            "report",
            "--root",
            root,
            "--coverage",
            output / ".coverage",
            "--tests",
            output / "tests.json",
            "--output",
            tmp_path / "stale-test",
        )
        assert completed.returncode == 0, completed.stderr
        report = json.loads((tmp_path / "stale-test/report.json").read_text())
        assert report["rankedCandidates"] == []
        assert any(
            gap["reason"] == "test-sources-changed-since-collection" for gap in report["gaps"]
        )
    finally:
        test_source.write_text(previous_test)


def test_batched_collection_merges_and_rejects_duplicate_node_identities(sample, tmp_path):
    root, _output, _report = sample
    output = tmp_path / "batched"
    completed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--batch-size",
        "1",
        "--",
        "tests/test_product.py::test_first",
        "tests/test_product.py::test_unique_branch",
        "tests/test_product.py::test_parameters",
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    aggregate = json.loads((output / "report.json").read_text())
    assert aggregate["healthyCollection"]
    assert len(list(output.glob("shard-*/run.json"))) == 3
    assert all("coverage" not in row for row in aggregate["tests"])
    detail = tmp_path / "detail"
    completed = invoke(
        "report",
        "--root",
        root,
        "--coverage",
        output / ".coverage",
        "--tests",
        output / "tests.json",
        "--output",
        detail,
        "--detail",
    )
    assert completed.returncode == 0
    assert "coverage" in json.loads((detail / "report.json").read_text())["tests"][0]

    duplicate = tmp_path / "duplicate"
    completed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        duplicate,
        "--batch-size",
        "1",
        "--",
        "tests/test_product.py::test_first",
        "tests/test_product.py::test_first",
    )
    assert completed.returncode == 2
    merged = json.loads((duplicate / "run.json").read_text())
    assert merged["duplicateNodes"]
    assert any(
        "duplicate node" in error
        for error in json.loads((duplicate / "tests.json").read_text())["collectionErrors"]
    )


def test_resume_rejects_tainted_manifest_and_directory_batches(sample, tmp_path):
    root, _output, _report = sample
    zero = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        tmp_path / "zero-batch",
        "--batch-size",
        "0",
        "--",
        "tests/test_product.py::test_first",
    )
    assert zero.returncode == 2
    assert "--batch-size must be positive" in zero.stderr
    output = tmp_path / "resume"
    completed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--batch-size",
        "1",
        "--",
        "tests/test_product.py::test_first",
        "tests/test_product.py::test_unique_branch",
    )
    assert completed.returncode == 0
    tests_artifact = output / "shard-0000/tests.json"
    tests_artifact.write_text(tests_artifact.read_text() + "\n")
    repaired = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--batch-size",
        "1",
        "--resume",
        "--",
        "tests/test_product.py::test_first",
        "tests/test_product.py::test_unique_branch",
    )
    assert repaired.returncode == 0
    assert list(output.glob("shard-0000.prior-*"))
    reused_run = output / "shard-0000/run.json"
    reused_run_before = reused_run.read_bytes()
    unfinished_run = output / "shard-0001/run.json"
    unfinished = json.loads(unfinished_run.read_text())
    unfinished["exitcode"] = None
    unfinished["finished"] = False
    unfinished_run.write_text(json.dumps(unfinished))
    resumed_unfinished = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--batch-size",
        "1",
        "--resume",
        "--",
        "tests/test_product.py::test_first",
        "tests/test_product.py::test_unique_branch",
    )
    assert resumed_unfinished.returncode == 0
    assert reused_run.read_bytes() == reused_run_before
    prior_unfinished = list(output.glob("shard-0001.prior-*"))
    assert prior_unfinished
    assert any(
        json.loads((prior / "run.json").read_text()).get("exitcode") is None
        and not json.loads((prior / "run.json").read_text()).get("finished")
        for prior in prior_unfinished
    )
    assert json.loads((output / "report.json").read_text())["healthyCollection"]
    manifest = json.loads((output / "manifest.json").read_text())
    manifest["shards"] = [manifest["shards"][0]]
    (output / "manifest.json").write_text(json.dumps(manifest))
    resumed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--batch-size",
        "1",
        "--resume",
        "--",
        "tests/test_product.py::test_first",
        "tests/test_product.py::test_unique_branch",
    )
    assert resumed.returncode == 2
    directory = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        tmp_path / "directory",
        "--batch-size",
        "1",
        "--",
        "tests",
    )
    assert directory.returncode == 2
    assert "requires explicit test files" in directory.stderr


def test_failed_shard_produces_incomplete_global_report(sample, tmp_path):
    root, _output, _report = sample
    output = tmp_path / "failed-shard"
    completed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "product",
        "--output",
        output,
        "--batch-size",
        "1",
        "--",
        "tests/test_product.py::test_first",
        "tests/test_product.py::does_not_exist",
    )
    assert completed.returncode == 2
    assert (output / "report.json").is_file()
    report = json.loads((output / "report.json").read_text())
    assert not report["healthyCollection"]
    assert any(
        gap.get("reason") == "collection-manifest-incomplete-or-failed" for gap in report["gaps"]
    )
