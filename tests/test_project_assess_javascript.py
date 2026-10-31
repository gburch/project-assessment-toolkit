import json
from copy import deepcopy
from pathlib import Path

import pytest

from project_assess import javascript_analysis as javascript


@pytest.fixture
def parser_available():
    if not javascript.javascript_analyzer_identity()["available"]:
        pytest.skip("Optional analysis extra is not installed")


@pytest.mark.parametrize(
    "path,source",
    [
        ("src/app.js", "export function run(x) { if (x) return x; return 0; }"),
        (
            "src/app.jsx",
            "export const View = (x) => { if(x) return <div>{x}</div>; return null; };",
        ),
        ("src/app.ts", "export function run(x: number): number { if (x) return x; return 0; }"),
        (
            "src/app.tsx",
            "export const View = (x: number) => { if(x) return <div>{x}</div>; return null; };",
        ),
    ],
)
def test_actual_grammars_parse_four_source_forms_without_executing_them(
    parser_available, path, source, tmp_path
):
    marker = tmp_path / "executed"
    source += f"\nrequire('fs').writeFileSync({json.dumps(str(marker))}, 'executed');"

    record = javascript.analyze_javascript(path, source)

    assert record["available"] and record["parsed"] and record["status"] == "complete"
    assert record["role"] == "production"
    assert record["analyzer"]["version"] == "1"
    assert all(record["analyzer"]["packages"].values())
    assert record["module"]["function_count"] == 1
    assert record["functions"][0]["decisions"] == 1
    assert record["functions"][0]["nesting"] == 1
    assert not marker.exists()


def test_complexity_excludes_nested_functions_and_counts_real_operators(parser_available):
    source = """function outer(x) {
  function inner(y) { if(y) { while(y) { if(y) { for(;;) { break; } } } } }
  return x && x || x ?? 0;
}
function nested(x) { if(x) { while(x) { if(x) { for(;;) { break; } } } } }
"""
    record = javascript.analyze_javascript("src/app.js", source)
    functions = {row["name"]: row for row in record["functions"]}

    assert functions["outer"]["decisions"] == 3
    assert functions["outer"]["nesting"] == 0
    assert functions["inner"]["nesting"] == functions["nested"]["nesting"] == 4
    assert {
        row["metrics"]["symbol"]
        for row in record["candidates"]
        if row["kind"] == "complex_function"
    } == {"inner", "nested"}


def test_unreachable_proof_only_direct_siblings_excludes_hoisted_declarations(parser_available):
    source = """function run(x) {
  if (x) return 1;
  observe();
  return 2;
  function hoisted() { return 3; }
  var hoistedBinding;
  /* an ignored comment */
  neverCalled();
}
function stop() { throw new Error(); unreachable(); }
function branched(x) { if(x) { return 1; } else { return 2; } uncertain(); }
"""
    record = javascript.analyze_javascript("src/app.js", source)
    leads = [row for row in record["candidates"] if row["kind"] == "unreachable_statement"]

    assert len(leads) == 2
    assert leads[0]["locations"] == [{"path": "src/app.js", "line": 8, "end_line": 8}]
    assert leads[1]["locations"] == [{"path": "src/app.js", "line": 10, "end_line": 10}]
    assert all(row["confidence"] == "high" for row in leads)
    assert all("hoisted" in row["metrics"]["caveat"] for row in leads)


def test_unused_is_low_confidence_open_world_and_skips_exported_called_dynamic(parser_available):
    source = """function _candidate() { return 1; }
function _called() { return 2; }
_called();
export function _public() { return 3; }
function ordinaryPublicName() { return 4; }
const _arrow = () => 5;
"""
    record = javascript.analyze_javascript("src/app.js", source)
    leads = [row for row in record["candidates"] if row["kind"] == "unused_symbol"]

    assert len(leads) == 1 and leads[0]["metrics"]["symbol"] == "_candidate"
    assert leads[0]["confidence"] == "low"
    assert "external" in leads[0]["metrics"]["caveat"]
    assert record["module"]["exports"] == ["_public"]
    for extra in (
        "export {_candidate};",
        "eval(name);",
        "registry[name]();",
        "globalThis._candidate();",
        "const registry = {_candidate};",
    ):
        changed = javascript.analyze_javascript("src/app.js", source + extra)
        assert not [row for row in changed["candidates"] if row["kind"] == "unused_symbol"]


def test_duplicate_fingerprint_preserves_literals_operators_and_parameters(parser_available):
    source = """function alpha(x) { const y = x + 1; log(y); return y; }
function beta(x) { /* comment */ const y = x + 1; log(y); return y; }
function otherLiteral(x) { const y = x + 2; log(y); return y; }
function otherOperator(x) { const y = x - 1; log(y); return y; }
function otherParameter(z) { const y = x + 1; log(y); return y; }
"""
    record = javascript.analyze_javascript("src/app.js", source)
    before = deepcopy(record)
    summary = javascript.summarize_javascript([record])
    duplicates = [row for row in summary["candidates"] if row["kind"] == "near_duplicate_function"]

    assert record == before  # summary never mutates captured records
    assert len(duplicates) == 1 and duplicates[0]["metrics"]["matching_functions"] == 2
    assert [row["line"] for row in duplicates[0]["locations"]] == [1, 2]
    assert "not prove interchangeable" in duplicates[0]["metrics"]["caveat"]


def test_relative_module_graph_is_captured_only_typed_and_deterministic(parser_available):
    first = javascript.analyze_javascript(
        "src/a.ts",
        "import type {Shape} from './types'; import {run} from './b.js'; const c = import('./c'); import unrelated from 'external-package';",
    )
    second = javascript.analyze_javascript("src/b.ts", "export function run() { return 1; }")
    types = javascript.analyze_javascript("src/types.ts", "export type Shape = number;")
    third = javascript.analyze_javascript("src/c/index.ts", "export const c = 1;")
    records = [first, second, types, third]

    summary = javascript.summarize_javascript(records)

    assert summary == javascript.summarize_javascript(list(reversed(records)))
    assert summary["status"] == "complete" and summary["topology"]["complete"]
    edges = {row["target"]: row["phase"] for row in summary["topology"]["edges"]}
    assert edges == {
        "src/types.ts": "type_only",
        "src/b.ts": "static",
        "src/c/index.ts": "deferred",
    }
    assert "external-package" not in json.dumps(summary)
    assert first["imports"][0]["source"] == "./types"


def test_parse_errors_partial_metrics_never_clean_or_dead_code(parser_available):
    record = javascript.analyze_javascript(
        "src/broken.ts", "function _maybe(x: number) { return x; after(); } function broken( {"
    )
    summary = javascript.summarize_javascript([record])

    assert record["status"] == summary["status"] == "partial"
    assert record["parsed"] and record["module"]["overview_partial"]
    assert summary["coverage"]["parsed_files"] == 1
    assert summary["coverage"]["complete_files"] == 0
    assert not summary["topology"]["complete"]
    assert any("parse errors" in gap for gap in record["gaps"])
    assert all(row["partial"] for row in record["functions"])
    assert not [
        row
        for row in record["candidates"]
        if row["kind"] in {"unused_symbol", "unreachable_statement"}
    ]


def test_source_literals_credentials_and_invalid_import_spellings_not_retained(parser_available):
    secret = "synthetic-secret-never-retain-8d42"
    source = f"""import remote from 'https://user:{secret}@example.invalid/file.js';
import query from './local.js?token={secret}';
function run(x) {{ const password = '{secret}'; log(password); return x; }}
"""
    record = javascript.analyze_javascript("src/app.js", source)
    summary = javascript.summarize_javascript([record])

    assert secret not in json.dumps(record) and secret not in json.dumps(summary)
    assert record["imports"] == []
    assert record["status"] == summary["status"] == "partial"
    assert any("Unsupported relative" in gap for gap in summary["gaps"])


def test_unresolved_escaping_and_ambiguous_imports_are_explicit_gaps(parser_available):
    first = javascript.analyze_javascript(
        "src/a.js", "import './missing'; import '../../outside'; import './choice';"
    )
    records = [
        first,
        javascript.analyze_javascript("src/choice.js", ""),
        javascript.analyze_javascript("src/choice.ts", ""),
    ]
    summary = javascript.summarize_javascript(records)

    assert summary["status"] == "partial"
    assert not summary["topology"]["complete"]
    assert summary["topology"]["edges"] == []
    assert summary["topology"]["unresolved_relative_imports"] == 3


def test_bounds_keep_partial_status_and_honest_denominators(parser_available, monkeypatch):
    monkeypatch.setattr(javascript, "MAX_BYTES", 10)
    oversized = javascript.analyze_javascript("src/large.js", "function large() { return 1; }")
    assert oversized["status"] == "partial" and not oversized["parsed"]
    assert oversized["functions"] == []
    monkeypatch.setattr(javascript, "MAX_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(javascript, "MAX_FUNCTIONS", 2)
    limited = javascript.analyze_javascript(
        "src/many.js", "\n".join(f"function run{i}() {{ return {i}; }}" for i in range(5))
    )
    assert limited["status"] == "partial" and limited["module"]["function_count"] == 5
    assert len(limited["functions"]) == 2
    monkeypatch.setattr(javascript, "MAX_NODES", 5)
    nodes = javascript.analyze_javascript(
        "src/nodes.js", "function nested(x) { if(x) { if(x) { return x; } } }"
    )
    assert nodes["status"] == "partial" and nodes["module"]["overview_partial"]
    summary = javascript.summarize_javascript([limited, nodes, oversized], 4)
    assert summary["coverage"]["javascript_files"] == 4 and summary["status"] == "partial"
    assert any("lack AST" in gap for gap in summary["gaps"])


def test_rich_sample_and_index_are_bounded_across_kinds_roles(parser_available, monkeypatch):
    source = "\n".join(f"function _run{i}() {{ return 1; after(); }}" for i in range(5))
    records = [
        javascript.analyze_javascript(path, source) for path in ("src/app.js", "tests/app.js")
    ]
    monkeypatch.setattr(javascript, "MAX_CANDIDATES", 3)
    monkeypatch.setattr(javascript, "MAX_INDEX", 7)
    summary = javascript.summarize_javascript(records)

    assert len(summary["candidates"]) == 3 and len(summary["candidate_index"]) == 7
    assert summary["candidate_counts"]["total"] == 20
    assert summary["candidate_counts"]["omitted_from_index"] == 13
    assert {row["kind"] for row in summary["candidates"]} == {
        "unreachable_statement",
        "unused_symbol",
    }
    assert {row["role"] for row in summary["candidates"]} == {"production", "test"}
    assert summary["status"] == "partial"


def test_missing_extra_is_explicit_without_loading_any_target_or_auto_installing(monkeypatch):
    monkeypatch.setattr(javascript, "_PACKAGES", ("pat-synthetic-missing-parser-package",))

    def forbidden_import(name):
        raise AssertionError("No imports should be attempted when required packages are missing")

    monkeypatch.setattr(javascript.importlib, "import_module", forbidden_import)
    record = javascript.analyze_javascript("src/app.tsx", "throw new Error('never execute');")
    summary = javascript.summarize_javascript([record])

    assert record["available"] is False and record["status"] == "unavailable"
    assert record["functions"] == record["candidates"] == record["imports"] == []
    assert summary["status"] == "unavailable" and not summary["topology"]["complete"]
    assert summary["coverage"]["parsed_files"] == 0
    assert "assessor environment" in record["gaps"][0]


@pytest.mark.parametrize("unsafe_version", ["0.25.0", "0.26.0", "1.0.0"])
def test_unsupported_native_binding_never_imports_or_traverses_source(monkeypatch, unsafe_version):
    def installed(package):
        return unsafe_version if package == "tree-sitter" else "0.25.0"

    def forbidden_import(name):
        raise AssertionError("Unsupported bindings must be rejected before native API access")

    monkeypatch.setattr(javascript, "version", installed)
    monkeypatch.setattr(javascript.importlib, "import_module", forbidden_import)
    record = javascript.analyze_javascript("src/app.js", "function sample() { return 1; }")
    assert record["status"] == "unavailable" and not record["parsed"]
    assert record["analyzer"]["unavailable_reason"] == "unsupported_tree_sitter_version"
    assert any("No native source traversal" in gap for gap in record["gaps"])


def test_actual_bundled_report_app_parses_and_fingerprints_without_native_crash(parser_available):
    # Tiny fixtures missed a 0.26.0 native crash on this real, syntax-rich app.
    path = Path(javascript.__file__).with_name("static") / "app.js"
    record = javascript.analyze_javascript("src/project_assess/static/app.js", path.read_text())

    assert record["parsed"] and record["status"] == "complete"
    assert record["functions"] and any(row["fingerprint"] for row in record["functions"])
