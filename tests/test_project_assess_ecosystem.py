import ast
import json
from copy import deepcopy

import pytest

from project_assess import ecosystem


def test_javascript_groups_retain_declared_names_without_values_or_unsafe_names():
    document = {
        "dependencies": {
            "react": "^19",
            "@scope/widget": "https://user:password@private.example/pkg",
        },
        "devDependencies": {"typescript": "workspace:*"},
        "peerDependencies": {"react": ">=18"},
        "optionalDependencies": {"native-addon": "npm:other@1"},
    }
    original = deepcopy(document)
    inventory = ecosystem.dependency_inventory("ui/package.json", document)

    assert inventory["status"] == "complete"
    assert {(row["name"], row["group"]) for row in inventory["dependencies"]} == {
        ("react", "runtime"),
        ("react", "peer"),
        ("@scope/widget", "runtime"),
        ("typescript", "dev"),
        ("native-addon", "optional"),
    }
    assert document == original
    assert "password" not in json.dumps(inventory) and "https://" not in json.dumps(inventory)
    document["dependencies"]["<img src=x onerror=privateMarker()>"] = "1"
    invalid = ecosystem.dependency_inventory("ui/package.json", document)
    assert invalid["status"] == "partial" and invalid["gaps"]
    assert "privateMarker" not in json.dumps(invalid)


def test_python_uses_standard_requirement_names_across_supported_groups():
    document = {
        "project": {
            "dependencies": ["Some_Package[extra]>=1; python_version >= '3.11'", "some.package<9"],
            "optional-dependencies": {"MCP": ["mcp>=2"], "test_value": ["coverage>=7"]},
        },
        "build-system": {"requires": ["hatchling>=1.27"]},
        "dependency-groups": {
            "lint": ["ruff>=0.12"],
            "tests": ["pytest>=9", {"include-group": "lint"}],
        },
    }
    inventory = ecosystem.dependency_inventory("pyproject.toml", document)

    assert {(row["name"], row["group"]) for row in inventory["dependencies"]} == {
        ("some-package", "runtime"),
        ("mcp", "optional:mcp"),
        ("coverage", "optional:test-value"),
        ("hatchling", "build"),
        ("ruff", "dev:lint"),
        ("pytest", "dev:tests"),
    }
    assert inventory["status"] == "partial"
    assert any("includes" in gap for gap in inventory["gaps"])


def test_requirement_urls_options_and_includes_never_escape_or_trigger_reads():
    text = """# A captured requirements file
Requests>=2 # Comment
Example @ https://user:privatePassword@private.example/pkg.whl
-r /private/secret-requirements.txt
--extra-index-url https://user:privatePassword@private.example/simple
https://private.example/unidentified.whl
"""
    inventory = ecosystem.dependency_inventory("requirements.txt", text)

    assert inventory["dependencies"] == [
        {"name": "example", "group": "runtime"},
        {"name": "requests", "group": "runtime"},
    ]
    assert inventory["status"] == "partial"
    assert any("origins" in gap for gap in inventory["gaps"])
    assert any("includes" in gap for gap in inventory["gaps"])
    for private in ("privatePassword", "private.example", "/private/", "https://"):
        assert private not in json.dumps(inventory)


@pytest.mark.parametrize(
    "document",
    [
        {"project": {"dynamic": ["dependencies"]}},
        {"tool": {"poetry": {"dependencies": {"private-package": "https://private.example"}}}},
        {"project": {"dependencies": {"wrong": "shape"}}},
        {"project": {"optional-dependencies": {"bad/group": ["private-package"]}}},
    ],
)
def test_unavailable_or_invalid_python_declarations_are_unknown_not_no_dependencies(document):
    inventory = ecosystem.dependency_inventory("pyproject.toml", document)
    assert inventory["status"] == "partial" and inventory["gaps"]
    assert inventory["dependencies"] == []
    assert "private" not in json.dumps(inventory)


def test_absent_groups_differ_from_explicit_empty_declarations():
    absent = ecosystem.dependency_inventory("package.json", {})
    empty = ecosystem.dependency_inventory("package.json", {"dependencies": {}})
    unknown = ecosystem.summarize([], [])

    assert absent["status"] == unknown["status"] == "partial"
    assert absent["gaps"] and unknown["gaps"]
    assert empty["status"] == "complete" and empty["dependencies"] == []


def test_manifest_caps_cover_invalid_rows_groups_and_long_text(monkeypatch):
    monkeypatch.setattr(ecosystem, "MAX_DEPENDENCIES", 2)
    inventory = ecosystem.dependency_inventory(
        "requirements.txt", "https://invalid\ninvalid ???\nreal-package>=1"
    )
    assert inventory["dependencies"] == [] and any("limit" in gap for gap in inventory["gaps"])
    monkeypatch.setattr(ecosystem, "MAX_GROUPS", 1)
    groups = ecosystem.dependency_inventory(
        "pyproject.toml",
        {"project": {"optional-dependencies": {"one": ["first"], "two": ["second"]}}},
    )
    assert groups["dependencies"] == [{"name": "first", "group": "optional:one"}]
    assert any("group limit" in gap for gap in groups["gaps"])
    monkeypatch.setattr(ecosystem, "MAX_TEXT_CHARACTERS", 8)
    text = ecosystem.dependency_inventory("requirements.txt", "first\nsecond\nthird\n")
    assert text["status"] == "partial" and any("character limit" in gap for gap in text["gaps"])


def test_python_primitive_imports_are_locations_not_execution_or_framework_judgment():
    tree = ast.parse("""raise AssertionError("Captured source must not execute")
import sqlite3 as database
from http.server import BaseHTTPRequestHandler
from .sqlite3 import local_module
description = "import http.server"
""")
    result = ecosystem.python_signals("server.py", tree)

    assert result["signals"] == [
        {"kind": "stdlib_http_server", "path": "server.py", "line": 3},
        {"kind": "stdlib_sqlite", "path": "server.py", "line": 2},
    ]
    assert result["status"] == "complete"
    assert (
        ecosystem.python_signals("utility.py", ast.parse("def add(a, b):\n    return a + b\n"))[
            "signals"
        ]
        == []
    )
    summary = ecosystem.summarize([], [result])
    assert not {"ratings", "score", "recommended_framework"} & summary.keys()
    assert "can be appropriate" in summary["caveat"]


def test_ast_node_budget_also_bounds_a_single_large_import(monkeypatch):
    monkeypatch.setattr(ecosystem, "MAX_AST_NODES", 8)
    tree = ast.Module(
        body=[
            ast.Import(
                names=[ast.alias(name="unrelated") for _ in range(1000)]
                + [ast.alias(name="sqlite3")],
                lineno=1,
            )
        ],
        type_ignores=[],
    )

    result = ecosystem.python_signals("wide.py", tree)

    assert result["signals"] == [] and result["status"] == "partial"
    assert any("node limit" in gap for gap in result["gaps"])


def test_javascript_hints_ignore_strings_comments_and_keep_lexical_limits_explicit():
    text = """const sample = "document.createElement('not a call')";
// document.getElementById('not a call');
/* document.querySelector('not a call'); */
const button = document.createElement('button');
document.querySelector('#result').append(button);
const interpolation = `ignored ${document.createElement('span')}`;
"""
    result = ecosystem.javascript_signals("ui.js", text)

    assert result["signals"] == [
        {"kind": "direct_dom", "path": "ui.js", "line": 4},
        {"kind": "direct_dom", "path": "ui.js", "line": 5},
    ]
    assert result["status"] == "partial" and any("lexical" in gap for gap in result["gaps"])
    assert (
        ecosystem.javascript_signals("utility.js", "export const add = (a,b) => a+b;")["signals"]
        == []
    )


def test_javascript_signal_and_text_budgets_are_explicit(monkeypatch):
    monkeypatch.setattr(ecosystem, "MAX_SIGNALS", 2)
    text = "document.createElement('div');\n" * 10
    result = ecosystem.javascript_signals("large.js", text)
    assert [row["line"] for row in result["signals"]] == [1, 2]
    assert any("signal limit" in gap for gap in result["gaps"])
    monkeypatch.setattr(ecosystem, "MAX_TEXT_CHARACTERS", 30)
    result = ecosystem.javascript_signals("large.js", text)
    assert any("character limit" in gap for gap in result["gaps"])


def test_summary_is_deterministic_source_linked_and_bounded_without_mutating_inputs(monkeypatch):
    first = ecosystem.dependency_inventory(
        "a/package.json", {"dependencies": {"first": "1", "second": "2"}}
    )
    second = ecosystem.dependency_inventory(
        "b/pyproject.toml", {"project": {"dependencies": ["third>=3"]}}
    )
    hints = ecosystem.python_signals("db.py", ast.parse("import sqlite3\n"))
    before = deepcopy([first, second, hints])
    result = ecosystem.summarize([first, second], [hints])

    assert result == ecosystem.summarize([second, first], [hints])
    assert result["counts"] == {"dependencies": 3, "signals": 1}
    assert result["dependencies"][0] == {
        "name": "first",
        "group": "runtime",
        "path": "a/package.json",
        "line": None,
    }
    assert [first, second, hints] == before
    monkeypatch.setattr(ecosystem, "MAX_PROJECT_DEPENDENCIES", 1)
    limited = ecosystem.summarize([first, second], [hints])
    assert limited["counts"]["dependencies"] == 1 and limited["status"] == "partial"
    assert any("row limit" in gap for gap in limited["gaps"])
    monkeypatch.setattr(ecosystem, "MAX_INPUTS", 1)
    limited = ecosystem.summarize([first, second], [])
    assert any("input record limit" in gap for gap in limited["gaps"])
