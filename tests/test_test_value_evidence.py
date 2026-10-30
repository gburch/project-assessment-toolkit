"""Behavioral proofs for portable non-pytest evidence import and comparison."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

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


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _normalized(path: Path, source_hash: str, *, layer: str, test_id: str, lines: list[int]):
    return {
        "schema": "test-value-evidence.v1",
        "format": "normalized",
        "layer": layer,
        "framework": "synthetic",
        "provider": "synthetic-provider",
        "invocation": {"isolated": True, "outcome": "passed", "selectedTests": [test_id]},
        "sourceHashes": {"src/shared.ts": source_hash},
        "sources": [{"path": "src/shared.ts", "hash": source_hash, "lines": lines}],
        "tests": [
            {
                "id": test_id,
                "outcome": "passed",
                "durationSeconds": 0.01,
                "features": [
                    {
                        "source": "src/shared.ts",
                        "kind": "line",
                        "coordinate": line,
                        "coordinateSemantics": "original-line",
                    }
                    for line in lines
                ],
            }
        ],
    }


def test_compare_imports_istanbul_and_pytest_without_cross_source_false_matches(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    shared = root / "src/shared.ts"
    other = root / "src/other.ts"
    shared.write_text("export const shared = 1;\nexport const second = 2;\n")
    other.write_text("export const other = 1;\nexport const second = 2;\n")
    shared_hash = _hash(shared)

    unit = tmp_path / "unit.json"
    unit_data = _normalized(unit, shared_hash, layer="unit", test_id="unit", lines=[1, 2])
    unit_data["tests"][0]["behaviorRefs"] = ["behavior:shared"]
    unit.write_text(json.dumps(unit_data))
    automation = tmp_path / "automation.json"
    automation.write_text(
        json.dumps(
            _normalized(
                automation, shared_hash, layer="automation", test_id="automation", lines=[2]
            )
        )
    )
    pytest_report = tmp_path / "pytest-report.json"
    pytest_report.write_text(
        json.dumps(
            {
                "schema": "test-value-audit.v3",
                "healthyCollection": True,
                "collection": {
                    "finished": True,
                    "exitcode": 0,
                    "sourceBefore": {"src/shared.ts": shared_hash},
                    "sourceAfter": {"src/shared.ts": shared_hash},
                },
                "sourceHashes": {"src/shared.ts": shared_hash},
                "tests": [
                    {
                        "nodeid": "tests/test_shared.py::test_shared",
                        "outcome": "passed",
                        "durationSeconds": 0.02,
                        "coverage": {"src/shared.ts": {"lines": [2], "arcs": []}},
                    }
                ],
            }
        )
    )
    output = tmp_path / "comparison"
    completed = invoke(
        "compare",
        "--root",
        root,
        "--output",
        output,
        "--evidence",
        unit,
        "--evidence",
        automation,
        "--pytest-report",
        pytest_report,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    report = json.loads((output / "report.json").read_text())
    assert report["schema"] == "test-value-evidence-compare.v1"
    assert report["confidentOverlap"]
    assert any(overlap["lines"] >= 1 for overlap in report["crossLayerOverlap"])
    assert len(report["tests"]) == 3

    malformed = tmp_path / "malformed-identity.json"
    malformed_data = json.loads(unit.read_text())
    malformed_data["tests"].append({"outcome": "passed"})
    malformed.write_text(json.dumps(malformed_data))
    completed = invoke(
        "compare",
        "--root",
        root,
        "--output",
        tmp_path / "malformed-output",
        "--evidence",
        malformed,
        "--evidence",
        automation,
    )
    assert completed.returncode == 0
    malformed_report = json.loads((tmp_path / "malformed-output/report.json").read_text())
    assert not malformed_report["confidentOverlap"]
    assert any(gap["reason"] == "test-identity-missing" for gap in malformed_report["gaps"])
    assert report["behaviorRelationships"][0]["behaviorRef"] == "behavior:shared"

    different = tmp_path / "different.json"
    different.write_text(
        json.dumps(
            {
                "schema": "test-value-evidence.v1",
                "format": "normalized",
                "layer": "other",
                "framework": "synthetic",
                "provider": "synthetic-provider",
                "invocation": {"isolated": True, "outcome": "passed", "selectedTests": ["other"]},
                "sources": [{"path": "src/other.ts", "hash": _hash(other), "lines": [2]}],
                "tests": [
                    {
                        "id": "other",
                        "outcome": "passed",
                        "features": [
                            {
                                "source": "src/other.ts",
                                "kind": "line",
                                "coordinate": 2,
                                "coordinateSemantics": "original-line",
                            }
                        ],
                    }
                ],
            }
        )
    )
    different_output = tmp_path / "different-output"
    completed = invoke(
        "compare",
        "--root",
        root,
        "--output",
        different_output,
        "--evidence",
        unit,
        "--evidence",
        different,
    )
    assert completed.returncode == 0
    assert json.loads((different_output / "report.json").read_text())["crossLayerOverlap"] == []


def test_compare_preserves_suite_failure_and_source_map_gaps(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    source = root / "src/shared.ts"
    source.write_text("export const shared = 1;\n")
    source_hash = _hash(source)

    istanbul = tmp_path / "coverage.json"
    istanbul.write_text(
        json.dumps(
            {
                "format": "istanbul",
                "layer": "browser",
                "framework": "vitest",
                "provider": "v8",
                "coordinateDomain": "original-source",
                "sourceHashes": {"src/shared.ts": source_hash},
                "coverage": {
                    "bundle.js": {
                        "path": "bundle.js",
                        "hash": source_hash,
                        "inputSourceMap": {
                            "version": 3,
                            "sources": ["src/shared.ts"],
                            "mappings": "AAAA",
                        },
                        "lineMap": {"1": 1},
                        "statementMap": {"0": {"start": {"line": 1}, "end": {"line": 1}}},
                        "s": {"0": 1},
                    }
                },
            }
        )
    )
    failed = tmp_path / "failed.json"
    failed.write_text(
        json.dumps(
            {
                **_normalized(failed, source_hash, layer="failed", test_id="failed", lines=[1]),
                "invocation": {"isolated": True, "outcome": "failed", "selectedTests": ["failed"]},
            }
        )
    )
    lcov = tmp_path / "coverage.info"
    lcov.write_text("TN:\nSF:src/shared.ts\nDA:1,1\nBRDA:1,0,0,1\nBRDA:1,0,1,1\nend_of_record\n")
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuite><testcase name="passed"/><testcase name="skipped">'
        "<skipped/></testcase></testsuite>"
    )
    output = tmp_path / "comparison"
    completed = invoke(
        "compare",
        "--root",
        root,
        "--output",
        output,
        "--evidence",
        istanbul,
        "--evidence",
        failed,
        "--evidence",
        lcov,
        "--evidence",
        junit,
    )
    assert completed.returncode == 0
    report = json.loads((output / "report.json").read_text())
    reasons = {gap["reason"] for gap in report["gaps"]}
    assert "source-map-line-mapping-unavailable" not in reasons
    assert "suite-only-unattributed" in reasons
    assert "source-hash-missing" in reasons
    assert "test-identity-unbound-or-nonisolated" in reasons
    assert not report["confidentOverlap"]
    junit_input = next(item for item in report["inputs"] if item["format"] == "junit")
    assert junit_input["outcomeSummary"] == {"passed": 1, "failed": 0, "skipped": 1}
    lcov_input = next(item for item in report["inputs"] if item["format"] == "lcov")
    assert lcov_input["sources"][0]["branchCount"] == 2


def test_compare_imports_collector_aggregate_without_case_duplication(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    source = root / "src/shared.ts"
    source.write_text("export const shared = 1;\n")
    source_hash = _hash(source)

    def collector(path: Path, ecosystem: str):
        path.write_text(
            json.dumps(
                {
                    "schema": "test-value-evidence.v1",
                    "project": {"sourceHashes": {"src/shared.ts": source_hash}},
                    "runner": {"ecosystem": ecosystem, "versions": {"node": "v22"}},
                    "tests": [{"nodeid": f"{ecosystem}:suite", "outcome": "passed"}],
                    "coverageFeatures": [
                        {
                            "source": {
                                "relativePath": "src/shared.ts",
                                "sourceHash": source_hash,
                                "language": "typescript",
                            },
                            "kind": "statement",
                            "location": {"line": 1},
                            "attribution": "suite",
                        },
                        {
                            "source": {
                                "relativePath": "src/shared.ts",
                                "sourceHash": source_hash,
                                "language": "typescript",
                            },
                            "kind": "branch",
                            "location": {
                                "branch": [
                                    "vitest-istanbul" if ecosystem == "vitest" else "node-lcov",
                                    "1",
                                    "0",
                                    "0",
                                ]
                            },
                            "attribution": "suite",
                        },
                    ],
                    "gaps": [],
                    "provenance": {"exitCode": 0, "artifacts": []},
                }
            )
        )

    vitest = tmp_path / "vitest-evidence.json"
    node = tmp_path / "node-evidence.json"
    collector(vitest, "vitest")
    collector(node, "node-test")
    output = tmp_path / "comparison"
    completed = invoke(
        "compare",
        "--root",
        root,
        "--output",
        output,
        "--evidence",
        vitest,
        "--evidence",
        node,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((output / "report.json").read_text())
    assert any(overlap["lines"] == 1 for overlap in report["crossLayerOverlap"])
    assert all(overlap["branches"] == 0 for overlap in report["crossLayerOverlap"])
    assert report["inputs"][0]["testCount"] == 1
    assert not report["tests"]
    assert not report["confidentOverlap"]

    isolated = tmp_path / "isolated.json"
    isolated.write_text(
        json.dumps(
            {
                "schema": "test-value-evidence.v1",
                "project": {"sourceHashes": {"src/shared.ts": source_hash}},
                "runner": {"ecosystem": "vitest", "versions": {"node": "v22"}},
                "invocation": {
                    "isolated": True,
                    "selectedTests": ["vitest:case"],
                    "outcome": "passed",
                },
                "tests": [
                    {
                        "nodeid": "vitest:case",
                        "outcome": "passed",
                        "coverageFeatures": [
                            {
                                "source": {
                                    "relativePath": "src/shared.ts",
                                    "sourceHash": source_hash,
                                },
                                "kind": "statement",
                                "location": {"line": 1},
                            }
                        ],
                    },
                    {"nodeid": "vitest:skipped", "outcome": "skipped", "coverageFeatures": []},
                ],
                "coverageFeatures": [],
                "gaps": [],
                "provenance": {"exitCode": 0, "artifacts": []},
            }
        )
    )
    isolated_output = tmp_path / "isolated-output"
    completed = invoke(
        "compare",
        "--root",
        root,
        "--output",
        isolated_output,
        "--evidence",
        isolated,
    )
    assert completed.returncode == 0
    isolated_report = json.loads((isolated_output / "report.json").read_text())
    assert [test["id"] for test in isolated_report["tests"]] == ["vitest:case"]
    assert any(gap["reason"] == "skipped-tests-unselected" for gap in isolated_report["gaps"])


def test_compare_imports_real_compact_pytest_report_and_raw_contexts(tmp_path):
    root = tmp_path / "python-project"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pytest.ini").write_text("[pytest]\npythonpath = .\n")
    source = root / "src/value.py"
    source.write_text("def value():\n    return 7\n")
    (root / "src/__init__.py").write_text("")
    (root / "tests/test_value.py").write_text(
        "from src.value import value\n\n\ndef test_value():\n    assert value() == 7\n"
    )
    collected = tmp_path / "pytest-collected"
    completed = invoke(
        "collect",
        "--root",
        root,
        "--source",
        "src",
        "--output",
        collected,
        "--",
        "tests/test_value.py",
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    source_hash = _hash(source)
    evidence = tmp_path / "suite.json"
    evidence.write_text(
        json.dumps(
            {
                "schema": "test-value-evidence.v1",
                "format": "normalized",
                "layer": "python-peer",
                "framework": "synthetic",
                "provider": "synthetic",
                "invocation": {
                    "isolated": True,
                    "outcome": "passed",
                    "selectedTests": ["peer"],
                },
                "sourceHashes": {"src/value.py": source_hash},
                "sources": [{"path": "src/value.py", "hash": source_hash, "lines": [2]}],
                "tests": [
                    {
                        "id": "peer",
                        "outcome": "passed",
                        "features": [
                            {
                                "source": "src/value.py",
                                "kind": "line",
                                "coordinate": 2,
                                "coordinateSemantics": "original-line",
                            }
                        ],
                    }
                ],
            }
        )
    )
    output = tmp_path / "real-compare"
    completed = invoke(
        "compare",
        "--root",
        root,
        "--output",
        output,
        "--evidence",
        evidence,
        "--pytest-report",
        collected / "report.json",
        "--pytest-coverage",
        collected / ".coverage",
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    report = json.loads((output / "report.json").read_text())
    pytest_input = next(item for item in report["inputs"] if item["format"] == "pytest-v3")
    assert pytest_input["testCount"] == 1
    assert any(test["outcome"] == "passed" for test in report["tests"])
    assert any(group["lines"] >= 1 for group in report["crossLayerOverlap"])
    assert report["confidentOverlap"]

    for label, extra_row, reason in [
        (
            "duplicate",
            json.loads((collected / "report.json").read_text())["tests"][0],
            "pytest-test-identities-ambiguous",
        ),
        ("missing", {"outcome": "passed"}, "test-identity-missing"),
    ]:
        altered = json.loads((collected / "report.json").read_text())
        altered["tests"].append(extra_row)
        altered_path = tmp_path / f"{label}-report.json"
        altered_path.write_text(json.dumps(altered))
        result = invoke(
            "compare",
            "--root",
            root,
            "--output",
            tmp_path / f"{label}-output",
            "--evidence",
            evidence,
            "--pytest-report",
            altered_path,
            "--pytest-coverage",
            collected / ".coverage",
        )
        assert result.returncode == 0
        invalid = json.loads((tmp_path / f"{label}-output/report.json").read_text())
        assert not invalid["confidentOverlap"]
        assert not invalid["healthyCollection"]
        assert any(gap["reason"] == reason for gap in invalid["gaps"])

    test_source = root / "tests/test_value.py"
    test_source.write_text(test_source.read_text().replace("value() == 7", "value() == 8"))
    stale = invoke(
        "compare",
        "--root",
        root,
        "--output",
        tmp_path / "stale-tests",
        "--evidence",
        evidence,
        "--pytest-report",
        collected / "report.json",
        "--pytest-coverage",
        collected / ".coverage",
    )
    assert stale.returncode == 0
    stale_report = json.loads((tmp_path / "stale-tests/report.json").read_text())
    assert not stale_report["confidentOverlap"]
    assert any(
        gap["reason"] == "test-sources-changed-since-collection" for gap in stale_report["gaps"]
    )
