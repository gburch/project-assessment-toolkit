"""Bounded static inventory proofs for Python and JavaScript/TypeScript leads."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

from project_assess.test_value.static import analyze


def test_inventory_keeps_resource_limits_and_explicit_omissions(tmp_path, monkeypatch) -> None:
    from project_assess.test_value import static

    root = tmp_path / "project"
    root.mkdir()
    (root / "large.py").write_text("#" * 512)
    (root / "small.py").write_text("def test_small():\n    assert True\n")
    monkeypatch.setattr(static, "MAX_FILE_BYTES", 128)
    report = analyze(root, ["."])
    assert report["counts"]["files"] == 1
    assert any(gap["reason"] == "size-bound-exceeded" for gap in report["gaps"])
    (root / "small.py").write_text(
        "def test_small():\n" + "    Thing()\n" * 50 + "    assert True\n"
    )
    monkeypatch.setattr(static, "MAX_FILE_BYTES", 10_000)
    monkeypatch.setattr(static, "MAX_REPORT_BYTES", 1600)
    report = analyze(root, ["small.py"])
    output = static.write_report(report, tmp_path / "bounded.json", root)
    assert output.stat().st_size <= 1600
    assert report["omissions"]["definitions"]["omitted"] > 0


def test_inventory_reports_unknowns_ambiguous_bodies_and_low_confidence_matrices(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    (root / "tests").mkdir(parents=True)
    (root / "ui").mkdir()
    (root / "tests/test_cases.py").write_text(
        "import pytest\nfrom one import helper\n\n"
        "@pytest.mark.parametrize('value', [1, 2, 3])\n"
        "def test_literal(value):\n"
        "    for item in range(20):\n"
        "        helper(value)\n"
        "    assert value > 0\n\n"
        "@pytest.mark.parametrize('value', values)\n"
        "def test_dynamic(value):\n"
        "    assert value > 0\n\n"
        "@pytest.mark.parametrize(argnames='value', argvalues=['a', 'b',])\n"
        "def test_keyword(value):\n"
        "    for item in range(5, 50, 2):\n"
        "        Thing(item)\n"
        "    assert value\n\n"
        "def test_same():\n    assert helper(1) == 1\n"
    )
    (root / "tests/test_other.py").write_text(
        "from two import helper\n\ndef test_same():\n    assert helper(1) == 1\n"
    )
    (root / "ui/example.test.ts").write_text(
        "test.each(cases)('dynamic', row => expect(row).toBeTruthy())\n"
        "it.each(['a', 'b',])('literal', row => expect(row).toBeTruthy())\n"
    )
    (root / "tests/broken.py").write_text("def nope(:\n")
    report = analyze(root, ["tests", "ui"])
    by_id = {row["id"]: row for row in report["definitions"]}
    literal = by_id["tests/test_cases.py::test_literal"]
    assert literal["parameterization"] == {
        "literalCases": 3,
        "dynamic": False,
        "decorators": ["pytest.mark.parametrize"],
    }
    assert literal["setupLeads"][0]["kind"] == "loop"
    assert by_id["tests/test_cases.py::test_dynamic"]["parameterization"]["dynamic"]
    keyword = by_id["tests/test_cases.py::test_keyword"]
    assert keyword["parameterization"]["literalCases"] == 2
    assert keyword["parameterization"]["dynamic"] is False
    assert {lead.get("iterations") for lead in keyword["setupLeads"] if lead["kind"] == "loop"} == {
        23
    }
    assert any(lead.get("name") == "Thing" for lead in keyword["setupLeads"])
    group = next(group for group in report["groups"] if len(group["members"]) == 2)
    assert group["bindingAmbiguous"] is True
    assert group["category"] == "test-bodies"
    matrices = [row for row in report["definitions"] if row["kind"] == "js-matrix"]
    assert all(row["confidence"] == "low" for row in matrices)
    assert any(
        row["matrix"]["dynamic"] is False and row["matrix"]["literalCases"] == 2 for row in matrices
    )
    assert any(gap["reason"] == "python-parse-error" for gap in report["gaps"])
    assert all(item["recommendation"] == "investigate" for item in report["candidates"])
    assert any(item["kind"] == "javascript-matrix-lead" for item in report["candidates"])


def test_inventory_cli_rejects_unsafe_scope_and_output_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "tests").mkdir(parents=True)
    (root / "tests/test_one.py").write_text("def test_one():\n    assert True\n")
    command = [
        sys.executable,
        "-m",
        "project_assess.test_value.audit",
        "inventory",
        "--root",
        str(root),
    ]
    unsafe = subprocess.run(
        command + ["--scope", "../", "--output", str(tmp_path / "out.json")],
        capture_output=True,
        text=True,
    )
    assert unsafe.returncode == 2 and "escapes" in unsafe.stderr
    inside = subprocess.run(
        command + ["--scope", "tests", "--output", str(root / "inventory.json")],
        capture_output=True,
        text=True,
    )
    assert inside.returncode == 2 and "outside" in inside.stderr
    output = tmp_path / "inventory.json"
    good = subprocess.run(
        command + ["--scope", "tests", "--output", str(output)], capture_output=True, text=True
    )
    assert good.returncode == 0, good.stderr
    assert json.loads(output.read_text())["schema"] == "test-value-static.v1"


def test_captured_python_tree_matches_text_adapter_without_reparsing(tmp_path, monkeypatch):
    from project_assess.test_value import static

    source = (
        "@pytest.mark.parametrize('value', [1, 2])\n"
        "def test_example(value):\n"
        "    for item in range(12):\n"
        "        Thing(value)\n"
        "    assert value > 0\n"
    )
    path = tmp_path / "tests/test_example.py"
    expected = static._python_file(path, tmp_path, source)
    tree = ast.parse(source)
    before = ast.dump(tree)

    def no_parse(*args, **kwargs):
        raise AssertionError("captured AST must not be parsed again")

    monkeypatch.setattr(static.ast, "parse", no_parse)
    assert static.python_rows(path, tmp_path, tree) == expected
    assert ast.dump(tree) == before
    rows, gaps, _ = expected
    assert not gaps
    assert rows[0]["parameterization"]["literalCases"] == 2
    assert rows[0]["assertions"]["count"] == 1
    assert not path.exists(), "the pure adapter must not need source files on disk"


def test_dynamic_decorator_receivers_never_emit_source_literals(tmp_path):
    from project_assess.test_value import static

    source = (
        '@factory(token="private-static-secret").parametrize("case", [1, 2])\n'
        "def test_factory(case):\n    assert case\n"
        '@registry["private-subscript-secret"].parameterize("case", [3])\n'
        "def test_registry(case):\n    assert case\n"
        '@pytest.mark.parametrize("case", [1, 2, 3])\n'
        "def test_known(case):\n    assert case\n"
        '@parametrize("case", [1])\n'
        "def test_direct(case):\n    assert case\n"
    )
    rows, gaps, _ = static._python_file(tmp_path / "test_cases.py", tmp_path, source)
    assert not gaps
    for row in rows[:2]:
        assert row["parameterization"]["dynamic"]
        assert row["parameterization"]["decorators"] == []
    assert rows[2]["parameterization"] == {
        "literalCases": 3,
        "dynamic": False,
        "decorators": ["pytest.mark.parametrize"],
    }
    assert rows[3]["parameterization"]["decorators"] == ["parametrize"]
    assert "private-static-secret" not in json.dumps(rows)
    assert "private-subscript-secret" not in json.dumps(rows)


def test_project_scan_static_inventory_does_not_expose_dynamic_decorator_tokens(tmp_path):
    from project_assess import collector

    sentinel = tmp_path / "must-not-run"
    root = tmp_path / "source"
    root.mkdir()
    (root / "test_source.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n"
        '@factory(token="private-static-secret").parametrize("case", [1, 2])\n'
        "def test_case(case):\n    assert case\n"
    )
    snapshot = collector.collect(root)
    inventory = next(
        row for row in snapshot["evidence"] if row["kind"] == "test-value-static-analysis"
    )
    definition = inventory["stats"]["definitions"][0]
    assert definition["parameterization"]["dynamic"]
    assert definition["parameterization"]["decorators"] == []
    assert "private-static-secret" not in json.dumps(snapshot)
    assert not sentinel.exists()
