"""Static leads stay bounded, source-local and distinct from quality judgments."""

from __future__ import annotations

import ast
import json

import pytest

from project_assess import collector, static_analysis


def record(path, source):
    return static_analysis.analyze_python(path, ast.parse(source))


def summary(*records, other=0):
    return static_analysis.summarize(list(records), len(records), other)


def candidates(result, kind):
    return [row for row in result["candidates"] if row["kind"] == kind]


def diagnostic(filename="app.py", *, code="F401", message="Unused import", line=1, fix=None):
    return {
        "filename": str(filename),
        "code": code,
        "message": message,
        "location": {"row": line, "column": 1},
        "end_location": {"row": line, "column": 8},
        "fix": fix,
    }


def ruff(rows, root, paths=None, redact=lambda text: text):
    return static_analysis.ruff_report(
        json.dumps(rows).encode(), root, {"app.py"} if paths is None else paths, redact
    )


def test_nested_scopes_do_not_inflate_outer_control_flow():
    source = """def outer(values):
    def inner(items):
        for item in items:
            if item and item.ready:
                return item
    return inner(values)
"""
    result = record("app.py", source)
    outer, inner = result["functions"]
    assert outer["location"]["line"] == 1
    assert outer["decisions"] == outer["nesting"] == 0
    assert inner["decisions"] >= 3
    assert inner["nesting"] >= 2
    assert candidates(summary(result), "complex_function") == []


def test_clones_require_substantial_exact_behavior_and_keep_auth_boundaries():
    def function(name, *, literal=10, callee="scale", decorator=""):
        return f'''{decorator}def {name}(values):
    """Description for {name}."""
    total = 0
    for value in values:
        total += {callee}(value)
    return total + {literal}
'''

    matching = [record("a.py", function("first")), record("b.py", function("second"))]
    changed_constant = record("constant.py", function("third", literal=20))
    changed_callee = record("callee.py", function("fourth", callee="delete"))
    guarded = record("guarded.py", function("fifth", decorator='@authorized("admin")\n'))
    tiny = record(
        "wrappers.py", "def one(x):\n    return delegate(x)\ndef two(x):\n    return delegate(x)\n"
    )
    result = summary(*matching, changed_constant, changed_callee, guarded, tiny)
    groups = candidates(result, "duplicate_function")
    assert len(groups) == 1
    assert {row["path"] for row in groups[0]["locations"]} == {"a.py", "b.py"}
    assert groups[0]["metrics"]["matching_functions"] == 2
    assert all(row["fingerprint"] is None for row in tiny["functions"])
    assert "not scores" in result["caveat"]
    assert "Required boundaries" in result["caveat"]


def test_relative_module_cycle_retains_deferred_phase_and_deterministic_locations():
    a = record("src/pkg/a.py", "from . import b\n")
    b = record("src/pkg/b.py", "def load():\n    from . import a\n    return a\n")
    init = record("src/pkg/__init__.py", "")
    result = summary(a, b, init)
    assert result == summary(init, b, a)
    cycle = candidates(result, "dependency_cycle")[0]
    assert cycle["metrics"]["modules"] == ["src/pkg/a.py", "src/pkg/b.py"]
    assert cycle["metrics"]["phases"] == {"deferred": 1, "eager": 1}
    assert {row["line"] for row in cycle["locations"]} == {1, 2}
    assert "not proof of a runtime import failure" in cycle["metrics"]["caveat"]


def test_type_only_imports_do_not_make_a_runtime_cycle():
    a = record(
        "src/pkg/a.py", "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from . import b\n"
    )
    b = record("src/pkg/b.py", "from . import a\n")
    assert candidates(summary(a, b), "dependency_cycle") == []


def test_type_checking_else_keeps_its_runtime_dependency():
    a = record(
        "src/pkg/a.py",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from . import types_only\nelse:\n    from . import b\n",
    )
    b = record("src/pkg/b.py", "from . import a\n")
    result = summary(a, b)
    cycle = candidates(result, "dependency_cycle")
    assert len(cycle) == 1
    assert any(edge["source"] == "src/pkg/a.py" for edge in cycle[0]["metrics"]["edges"])


def test_uncaptured_and_ambiguous_modules_do_not_create_invented_edges():
    consumer = record("consumer.py", "import external\nimport pkg\n")
    flat = record("pkg.py", "import consumer\n")
    package = record("src/pkg/__init__.py", "")
    result = summary(consumer, flat, package)
    assert candidates(result, "dependency_cycle") == []
    assert "Dynamic imports" in " ".join(result["gaps"])
    assert static_analysis.summarize([], 0, 1)["status"] == "unsupported"
    assert summary(consumer, other=1)["status"] == "partial"


def test_loop_io_is_a_located_lead_not_an_automatic_cache_recommendation():
    result = summary(
        record(
            "app.py",
            "def refresh(paths):\n    for path in paths:\n        current = path.read_text()\n        consume(current)\n",
        )
    )
    lead = candidates(result, "loop_io")[0]
    assert lead["locations"][0] == {"path": "app.py", "line": 3, "end_line": 3}
    assert "freshness" in lead["metrics"]["method"]
    assert "actual I/O require review" in lead["metrics"]["method"]


def test_loop_initialization_is_not_repeated_but_comprehension_body_is():
    parsed = record(
        "app.py",
        "def refresh(path, paths):\n"
        "    for line in path.read_text().splitlines():\n"
        "        consume(line)\n"
        "    return [item.read_bytes() for item in paths]\n",
    )
    lead = candidates(summary(parsed), "loop_io")[0]
    assert [location["line"] for location in lead["locations"]] == [4]


def test_collection_caps_total_static_symbols(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("def first():\n    pass\ndef second():\n    pass\n")
    (tmp_path / "b.py").write_text("def third():\n    pass\n")
    monkeypatch.setattr(collector, "MAX_STATIC_SYMBOLS", 1)
    result = collector.collect(tmp_path)
    analysis = result["facts"]["static_analysis"]
    assert result["facts"]["python"]["functions"] == 3
    assert analysis["summary"]["functions"] == 1
    assert analysis["status"] == "partial"
    assert any("symbol limit" in gap for gap in analysis["gaps"])


def test_ruff_arrays_share_the_cumulative_import_limit(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    paths = [tmp_path / "one.json", tmp_path / "two.json"]
    for path in paths:
        path.write_text("[]")
    monkeypatch.setattr(collector, "MAX_TEST_VALUE_REPORT_TOTAL_BYTES", 3)
    with pytest.raises(ValueError, match="cumulative byte limit"):
        collector.collect(root, paths)


def test_analysis_limits_are_partial_and_do_not_claim_no_risks(monkeypatch):
    monkeypatch.setattr(static_analysis, "MAX_NODES", 5)
    parsed = record("app.py", "def example(x):\n    if x:\n        return x + 1\n")
    result = summary(parsed)
    assert result["status"] == "partial"
    assert result["candidates"] == []
    assert any("node limit" in gap for gap in result["gaps"])
    monkeypatch.setattr(static_analysis, "MAX_NODES", 50_000)
    monkeypatch.setattr(static_analysis, "MAX_CANDIDATES", 1)
    parsed = record(
        "loops.py",
        "def one(xs):\n    for x in xs:\n        x.read_text()\ndef two(xs):\n    for x in xs:\n        x.read_bytes()\n",
    )
    result = summary(parsed)
    assert result["status"] == "partial"
    assert len(result["candidates"]) == 1
    assert result["summary"]["candidate_count"] == 2
    assert any("remaining candidates omitted" in gap for gap in result["gaps"])


def test_retained_leads_share_budget_across_kinds_areas_and_files(monkeypatch):
    def complex_functions(count):
        return "\n".join(
            f"def function_{number}(value):\n"
            + "".join(f"    if value == {branch}:\n        value += 1\n" for branch in range(10))
            + f"    return value + {number}\n"
            for number in range(count)
        )

    shared_body = (
        "def normalize(values):\n"
        "    total = 0\n"
        "    for value in values:\n"
        "        total += value * 3\n"
        "    return total + 7\n"
    )
    records = [
        record("docs/flood.py", complex_functions(30)),
        record("docs/other.py", complex_functions(1)),
        record("services/workflow.py", complex_functions(1)),
        record("services/a.py", "from . import b\n"),
        record("services/b.py", "from . import a\n"),
        record("services/clone_a.py", shared_body),
        record("services/clone_b.py", shared_body),
        record(
            "tools/read.py", "def read(paths):\n    for path in paths:\n        path.read_text()\n"
        ),
    ]
    monkeypatch.setattr(static_analysis, "MAX_CANDIDATES", 8)

    result = summary(*records)

    assert result == summary(*reversed(records))
    assert len(result["candidates"]) == 8
    assert {row["kind"] for row in result["candidates"]} == {
        "complex_function",
        "duplicate_function",
        "dependency_cycle",
        "loop_io",
    }
    assert {row["locations"][0]["path"] for row in candidates(result, "complex_function")} >= {
        "docs/flood.py",
        "docs/other.py",
        "services/workflow.py",
    }
    assert result["summary"]["candidate_count"] > len(result["candidates"])
    assert result["status"] == "partial"
    assert any("remaining candidates omitted" in gap for gap in result["gaps"])


def test_unresolved_imports_consume_the_resolution_budget(monkeypatch):
    monkeypatch.setattr(static_analysis, "MAX_IMPORT_TARGETS", 2)
    a = record("a.py", "import missing_one, missing_two, b\n")
    b = record("b.py", "import a\n")
    result = summary(a, b)
    assert result["status"] == "partial"
    assert candidates(result, "dependency_cycle") == []
    assert any("import target" in gap for gap in result["gaps"])


def test_ruff_keeps_only_captured_locations_and_never_retains_fix_edits(tmp_path):
    rows = [
        diagnostic(
            tmp_path / "app.py",
            line=3,
            fix={"applicability": "unsafe", "edits": [{"content": "raw-private-edit"}]},
        ),
        diagnostic("app.py", line=1, code="C901"),
        diagnostic(tmp_path.parent / "outside.py"),
        diagnostic("../outside.py"),
        diagnostic(".env"),
        diagnostic("not-captured.py"),
    ]
    result = ruff(rows, tmp_path)
    assert result["source_identity"] == "unverified"
    assert [(row["line"], row["code"]) for row in result["diagnostics"]] == [
        (1, "C901"),
        (3, "F401"),
    ]
    assert result["diagnostics"][1]["fix_applicability"] == "unsafe"
    assert "raw-private-edit" not in json.dumps(result)
    assert "edits" not in json.dumps(result)
    assert any("outside captured source scope" in gap for gap in result["gaps"])
    assert "zero findings is not a clean-project rating" in " ".join(result["gaps"])


def test_ruff_redacts_before_truncating_messages_and_bounds_rows(tmp_path, monkeypatch):
    calls = []
    secret = "sensitive-message-tail"
    message = "x" * 490 + secret

    def redact(text):
        calls.append(text)
        return text.replace(secret, "[redacted]")

    result = ruff([diagnostic(message=message)], tmp_path, redact=redact)
    assert calls == [message]
    assert len(result["diagnostics"][0]["message"]) <= 500
    assert secret not in json.dumps(result)
    monkeypatch.setattr(static_analysis, "MAX_DIAGNOSTICS", 2)
    result = ruff([diagnostic(line=index + 1) for index in range(5)], tmp_path)
    assert result["summary"] == {"diagnostics": 2, "supplied": 5}
    assert any("diagnostic limit" in gap for gap in result["gaps"])


@pytest.mark.parametrize(
    "payload",
    [
        b'[{"filename":"app.py","code":"F401","code":"F402"}]',
        b"[NaN]",
        b"[1]",
        b"{}",
        json.dumps([diagnostic(line=True)]).encode(),
        json.dumps([diagnostic(code="run(command)")]).encode(),
    ],
)
def test_ruff_rejects_malformed_diagnostics(payload, tmp_path):
    with pytest.raises(ValueError):
        static_analysis.ruff_report(payload, tmp_path, {"app.py"}, lambda text: text)


def test_empty_ruff_report_is_unverified_evidence_not_a_quality_score(tmp_path):
    result = ruff([], tmp_path)
    assert result["summary"]["diagnostics"] == 0
    assert result["source_identity"] == "unverified"
    assert "rule scope" in " ".join(result["gaps"])


def test_scan_collects_static_leads_and_imports_ruff_without_executing_target(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    sentinel = tmp_path / "must-not-exist"
    source = root / "app.py"
    source.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\ndef refresh(paths):\n    for path in paths:\n        path.read_text()\n"
    )
    (root / "alias.py").symlink_to(tmp_path / "outside.py")
    (root / ".env").write_text("credential=private-root-secret")
    report_path = tmp_path / "ruff.json"
    report_path.write_text(
        json.dumps(
            [
                diagnostic(
                    source,
                    message='api_key = "private-imported-secret"',
                    fix={"applicability": "safe", "edits": [{"content": "private-fix-secret"}]},
                ),
                diagnostic(root / "alias.py"),
                diagnostic(root / ".env"),
            ]
        )
    )
    result = collector.collect(root, [report_path])
    assert result == collector.collect(root, [report_path])
    assert not sentinel.exists()
    static = result["facts"]["static_analysis"]
    evidence = next(row for row in result["evidence"] if row["id"] == static["evidence_id"])
    assert candidates(evidence["stats"], "loop_io")
    imported = next(row for row in result["evidence"] if row["kind"] == "ruff")
    assert imported["stats"]["summary"]["diagnostics"] == 1
    assert imported["stats"]["diagnostics"][0]["path"] == "app.py"
    assert imported["stats"]["source_identity"] == "unverified"
    serialized = json.dumps(result)
    assert "private-imported-secret" not in serialized
    assert "private-fix-secret" not in serialized
    assert "private-root-secret" not in serialized
    assert "review" not in result and "ratings" not in result


def test_scan_shares_one_parse_with_the_test_value_inventory(tmp_path, monkeypatch):
    from project_assess.test_value import static as test_static

    source = "def test_values():\n    for value in range(20):\n        assert value >= 0\n"
    (tmp_path / "app.py").write_text(source)
    parse = ast.parse
    parsed = []

    def count_parse(text, *args, **kwargs):
        parsed.append(text)
        return parse(text, *args, **kwargs)

    def forbid_text_adapter(*args):
        raise AssertionError("scan must share its captured AST")

    monkeypatch.setattr(ast, "parse", count_parse)
    monkeypatch.setattr(test_static, "_python_file", forbid_text_adapter)
    result = collector.collect(tmp_path)
    assert parsed == [source]
    assert result["facts"]["static_analysis"]["summary"]["functions"] == 1
    assert result["facts"]["test_value_static"]["counts"]["definitions"] == 1
