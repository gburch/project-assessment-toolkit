"""Real runner proofs for bounded selection and exact invocation identities."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".agents/skills/test-value/scripts/test_value_multilayer.py"
)


@pytest.mark.parametrize("targets", [[], ["tests"]])
def test_nonfile_selection_is_rejected_before_creating_a_run(tmp_path, targets):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    output = tmp_path / "run"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--runner",
            "node-test",
            "--command",
            sys.executable,
            "--source",
            "src",
            "--output",
            str(output),
            "--",
            *targets,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 2
    assert "explicit" in result.stderr
    assert not output.exists()


def test_native_node_binds_exact_file_case_and_preserves_failure_and_aggregate(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("native Node test runner unavailable")
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "package.json").write_text('{"type":"module"}\n')
    product = tmp_path / "src/value.js"
    product.write_text("export function value(n) { return n * 2; }\n")
    (tmp_path / "tests/value.test.mjs").write_text(
        'import { test } from "node:test";\n'
        'import assert from "node:assert/strict";\n'
        'import { value } from "../src/value.js";\n'
        'test("first", () => assert.equal(value(1), 2));\n'
        'test("second", () => assert.equal(value(2), 4));\n'
    )

    def collect(label, name=None):
        output = tmp_path / label
        command = [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--runner",
            "node-test",
            "--command",
            node,
            "--source",
            "src",
            "--coverage",
            "--output",
            str(output),
        ]
        if name:
            command += ["--test-name", name]
        command += ["--", "tests/value.test.mjs"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        return result, json.loads((output / "evidence.json").read_text())

    result, isolated = collect("isolated", "second")
    assert result.returncode == 0, result.stderr
    assert isolated["invocation"]["isolated"]
    selected = next(row for row in isolated["tests"] if row["outcome"] == "passed")
    assert selected["nodeid"] == "node-test:tests/value.test.mjs::second"
    assert selected["coverageFeatures"]
    assert all(
        row["coverageFeatures"] == [] for row in isolated["tests"] if row["outcome"] == "skipped"
    )

    result, aggregate = collect("aggregate")
    assert result.returncode == 0, result.stderr
    assert not aggregate["invocation"]["isolated"]
    assert all(not row["coverageFeatures"] for row in aggregate["tests"])
    assert any(gap["reason"] == "aggregate-coverage-not-per-test" for gap in aggregate["gaps"])

    product.write_text("export function value(n) { return 2; }\n")
    result, failed = collect("failed", "second")
    assert result.returncode != 0
    assert not failed["invocation"]["isolated"]
    failure = next(row for row in failed["tests"] if row["outcome"] == "failed")
    assert failure["phases"]["call"]["outcome"] == "failed"
    assert all(not row["coverageFeatures"] for row in failed["tests"])
