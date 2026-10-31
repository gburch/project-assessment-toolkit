"""Broader architecture leads retain their uncertainty and bounded source identity."""

import ast

from project_assess import static_analysis as analysis


def scan(sources):
    records = [analysis.analyze_python(path, ast.parse(source)) for path, source in sources.items()]
    return analysis.summarize(records, len(records), 0)


def leads(result, kind):
    return [row for row in result["candidate_index"] if row["kind"] == kind]


def test_large_modules_keep_imports_later_functions_and_lower_bound_metrics(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_NODES", 50)
    monkeypatch.setattr(analysis, "MAX_FUNCTION_NODES", 40)
    source = (
        "def large(value):\n"
        + "".join(f"    if value == {number}:\n        value += 1\n" for number in range(60))
        + "    return value\n\n"
        + "def last():\n    return 3\n\nfrom . import peer\n"
    )
    result = scan({"src/pkg/large.py": source, "src/pkg/peer.py": "from . import large\n"})
    module = next(row for row in result["modules"] if row["path"].endswith("large.py"))
    assert module["function_count"] == module["analyzed_functions"] == 2
    assert module["partial_functions"] == 1
    assert {row["name"] for row in result["hotspots"]} == {"large", "last"}
    assert (
        next(row for row in result["hotspots"] if row["name"] == "large")["metric_basis"]
        == "lower_bound"
    )
    assert len(result["topology"]["edges"]) == 2
    assert result["topology"]["complete"]


def test_exhausted_detail_allowance_preserves_every_module_overview_and_topology(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_FILES", 1)
    records = [
        analysis.analyze_python(
            f"src/pkg/m{number}.py",
            ast.parse(f"from . import m{(number + 1) % 5}\ndef feature():\n    return {number}\n"),
            detail_budget=0,
        )
        for number in range(5)
    ]
    result = analysis.summarize(records, 5, 0)
    assert result["coverage"]["overview_files"] == 5
    assert result["coverage"]["functions_total"] == 5
    assert result["coverage"]["functions_analyzed"] == 0
    assert len(result["topology"]["edges"]) == 5
    assert {row["role"] for row in result["modules"]} == {"production"}
    assert result["status"] == "partial"


def test_near_clones_separate_binding_renames_from_callee_and_literal_differences():
    def function(name, collection, total, callee="transform", final=4):
        return (
            f"def {name}({collection}):\n    {total} = 0\n"
            f"    for item in {collection}:\n        {total} += {callee}(item)\n"
            f"    return {total} + {final}\n"
        )

    result = scan(
        {
            "src/a.py": function("first", "values", "total"),
            "src/b.py": function("second", "entries", "result"),
            "src/c.py": function("third", "values", "total", "remove", 5),
        }
    )
    clones = leads(result, "near_duplicate_function")
    assert any(
        row["confidence"] == "medium"
        and {item["path"] for item in row["locations"]} == {"src/a.py", "src/b.py"}
        for row in clones
    )
    shape = next(row for row in clones if len(row["locations"]) == 3)
    assert shape["confidence"] == "low"
    assert shape["metrics"]["literal_differences"]
    assert shape["metrics"]["callee_variants"] == [["remove"], ["transform"]]
    assert shape["counterevidence"]
    assert not leads(result, "duplicate_function")


def test_repeated_blocks_are_located_even_when_whole_functions_differ():
    shared = "    for value in values:\n        total += normalize(value)\n    total = clamp(total)\n    publish(total)\n"
    result = scan(
        {
            "src/a.py": "def first(values):\n    total = 10\n" + shared + "    return total\n",
            "src/b.py": "def second(values):\n    total = 20\n" + shared + "    return total * 2\n",
        }
    )
    blocks = leads(result, "duplicate_block")
    assert any({location["line"] for location in row["locations"]} == {3} for row in blocks)
    assert all(row["counterevidence"] for row in blocks)


def test_unreachable_statements_require_syntactic_proof_not_an_unused_guess():
    result = scan(
        {
            "src/flow.py": """def direct():
    return 1
    save()

def branches(flag):
    if flag:
        return 2
    else:
        raise ValueError()
    save()

def uncertain(flag):
    if flag:
        return 1
    save()
    try:
        return 2
    except ValueError:
        recover()
    publish()

def disabled():
    if False:
        save()
    return 1
"""
        }
    )
    proven = leads(result, "unreachable_statement")
    assert {row["locations"][0]["line"] for row in proven} == {3, 10, 24}
    assert {row["confidence"] for row in proven} == {"high"}
    assert all(row["caveat"] for row in proven)


def test_unused_private_symbol_and_shadowed_module_are_candidates_not_deletion_proof():
    result = scan(
        {
            "src/pkg/routing.py": "def _abandoned():\n    return 1\n",
            "src/pkg/routing/__init__.py": "from .policy import route\n",
            "src/pkg/routing/policy.py": "def route():\n    return 1\n",
            "src/pkg/kept.py": """__all__ = ["_exported"]
def _exported():
    return 1
@register
def _registered():
    return 2
def _used():
    return 3
def public():
    return _used()
""",
        }
    )
    unused = leads(result, "unused_symbol")
    assert [row["metrics"]["symbol"] for row in unused] == ["_abandoned"]
    assert unused[0]["confidence"] == "low"
    shadowed = leads(result, "shadowed_module")
    assert len(shadowed) == 1
    assert {row["path"] for row in shadowed[0]["locations"]} == {
        "src/pkg/routing.py",
        "src/pkg/routing/__init__.py",
    }
    assert shadowed[0]["counterevidence"]
    assert leads(result, "unreferenced_module")
    assert all(row["confidence"] == "low" for row in leads(result, "unreferenced_module"))


def test_index_exposes_leads_beyond_rich_sample_with_explicit_denominators(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_CANDIDATES", 1)
    monkeypatch.setattr(analysis, "MAX_INDEX", 2)
    result = scan(
        {
            "src/helpers.py": "def _one():\n    return 1\ndef _two():\n    return 2\ndef _three():\n    return 3\n"
        }
    )
    counts = result["candidate_counts"]
    assert counts["total"] == 4
    assert counts["retained"] == 1
    assert counts["indexed"] == 2
    assert counts["omitted_from_index"] == 2
    assert counts["by_kind"] == {"unreferenced_module": 1, "unused_symbol": 3}
    assert counts["by_role"] == {"production": 4}
    assert result["analyzer"]["version"] == "2"
    assert any("index limit" in gap for gap in result["gaps"])


def test_roles_preserve_unknown_and_classify_test_code_before_source_layout():
    result = scan(
        {
            path: ""
            for path in (
                "src/pkg/service.py",
                "src/pkg/tests/test_service.py",
                "tools/check.py",
                "entry.py",
            )
        }
    )
    roles = {row["path"]: row["role"] for row in result["modules"]}
    assert roles == {
        "src/pkg/service.py": "production",
        "src/pkg/tests/test_service.py": "test",
        "tools/check.py": "tooling",
        "entry.py": "unknown",
    }


def test_graph_resolution_budget_is_shared_across_modules(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_IMPORT_TARGETS", 3)
    result = scan(
        {
            "src/pkg/a.py": "import missing_a, missing_b, missing_c\n",
            "src/pkg/b.py": "from . import c\n",
            "src/pkg/c.py": "from . import b\n",
        }
    )
    assert {(edge["source"], edge["target"]) for edge in result["topology"]["edges"]} == {
        ("src/pkg/b.py", "src/pkg/c.py"),
        ("src/pkg/c.py", "src/pkg/b.py"),
    }
    assert not result["topology"]["complete"]
    assert leads(result, "dependency_cycle")


def test_deep_expression_keeps_metrics_when_recursive_clone_serialization_is_bounded():
    tree = ast.parse("def deep(value):\n    first = value\n    second = first\n    return second\n")
    expression = ast.Name(id="second", ctx=ast.Load())
    for _ in range(1500):
        expression = ast.BinOp(left=expression, op=ast.Add(), right=ast.Constant(value=1))
    tree.body[0].body[-1].value = expression
    record = analysis.analyze_python("src/deep.py", tree)
    assert len(record["functions"]) == 1
    assert record["functions"][0]["nodes_analyzed"] > 1000
    assert any("depth limit" in gap or "node limit" in gap for gap in record["gaps"])


def test_python_literal_forms_do_not_break_pattern_serialization():
    result = scan(
        {
            "src/literals.py": "def literals(value):\n    data = b'hello'\n    number = 1j\n    return (data, number, ..., value)\n"
        }
    )
    assert result["coverage"]["functions_analyzed"] == 1


def test_role_hints_cover_application_stacks_and_preserve_generated_uncertainty():
    assert analysis.source_role("frontend/src/App.test.tsx")["role"] == "test"
    assert analysis.source_role("web/components/dialog.spec.jsx")["role"] == "test"
    assert analysis.source_role("backend/server.py")["role"] == "production"
    assert analysis.source_role("frontend/src/App.tsx")["role"] == "production"
    assert analysis.source_role("web/client.ts")["role"] == "production"
    assert analysis.source_role("src/generated/client.py")["role"] == "unknown"
    assert analysis.source_role("src/api/service_pb2.py")["generated_hint"]
    assert analysis.source_role("vendor/copied.py")["vendor_hint"]
