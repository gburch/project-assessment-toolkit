"""Orientation retains source scope without turning area size into a judgment."""

from copy import deepcopy

import pytest

from project_assess.collector import collect
from project_assess.review_context import (
    MAX_AREAS,
    MAX_CITATIONS,
    build_challenge_evidence_index,
    get_system_map,
)


def source(path, identity, role="production", lines=10, **stats):
    return {"path": path, "id": identity, "lines": lines, "stats": {"role": role, **stats}}


def analysis(kind, identity, modules, edges=(), complete=True):
    return {
        "kind": kind,
        "id": identity,
        "stats": {
            "modules": modules,
            "topology": {"edges": list(edges), "complete": complete},
            "limits": {"edge_limit": 100},
            "gaps": [] if complete else ["Native graph is bounded"],
        },
    }


def test_area_names_preserve_namespaces_and_exclude_nonproduction_and_generated_source():
    snapshot = {
        "complete": True,
        "evidence": [
            source("src/package/orders/service.py", "e-orders"),
            source("lib/package/accounts/store.py", "e-accounts"),
            source("frontend/src/features/orders/view.tsx", "e-view"),
            source("entry.py", "e-root"),
            source("tests/test_orders.py", "e-test", role="test"),
            source("tools/check.py", "e-tool", role="tooling"),
            source("src/package/generated/schema.py", "e-generated", generated_hint=True),
            source("external/sample.py", "e-unknown", role="unknown"),
        ],
    }
    result = get_system_map(snapshot)
    assert {row["path"] for row in result["areas"]} == {
        "src/package/orders",
        "lib/package/accounts",
        "frontend/src/features/orders",
        "(root)",
    }
    assert result["production_files"] == 4
    assert result["excluded_files_by_role"] == {
        "generated_or_vendor": 1,
        "test": 1,
        "tooling": 1,
        "unknown": 1,
    }
    assert all(row["functions"] is None for row in result["areas"])


def test_native_counts_override_inventory_without_double_counting_or_lexical_substitution():
    path = "src/package/orders/service.py"
    result = get_system_map(
        {
            "evidence": [
                source(path, "e-source", lines=20, functions=999),
                analysis(
                    "static-analysis",
                    "e-native",
                    [{"path": path, "function_count": 3, "lines": 21, "overview_partial": True}],
                ),
                analysis("source-analysis", "e-inventory", [{"path": path, "lines": 20}]),
            ]
        }
    )
    area = result["areas"][0]
    assert (area["files"], area["modules"], area["functions"], area["lines"]) == (1, 1, 3, 20)
    assert area["functions_known_files"] == area["partial_modules"] == 1
    assert set(area["evidence_ids"]) == {"e-source", "e-native", "e-inventory"}
    assert result["status"] == "partial"


def test_cross_area_edges_keep_phases_and_citations_with_incomplete_scope_explicit():
    left, right = "src/package/orders/a.py", "src/package/ledger/b.py"
    edge = {"source": left, "target": right, "line": 2, "phase": "type_checking"}
    result = get_system_map(
        {
            "complete": False,
            "gaps": ["One captured file was omitted"],
            "evidence": [
                source(left, "e-left"),
                source(right, "e-right"),
                source("tests/test_ledger.py", "e-test", role="test"),
                analysis(
                    "static-analysis",
                    "e-analysis",
                    [],
                    [
                        edge,
                        edge,
                        {**edge, "line": 4, "phase": "deferred"},
                        {**edge, "target": "tests/test_ledger.py"},
                        {**edge, "target": "missing.py"},
                    ],
                    complete=False,
                ),
            ],
        }
    )
    dependency = result["cross_area_dependencies"][0]
    assert dependency["import_edges"] == 2
    assert dependency["phases"] == {"deferred": 1, "type_checking": 1}
    assert set(dependency["evidence_ids"]) == {"e-analysis", "e-left", "e-right"}
    assert result["excluded_nonproduction_or_uncaptured_import_edges"] == 2
    assert result["native_import_graphs"][0]["complete"] is False
    assert result["native_import_graphs"][0]["limits"] == {"edge_limit": 100}
    assert result["collection"]["complete"] is False and result["gaps"]


def test_area_and_citation_bounds_are_deterministic_and_never_infer_debt_from_size():
    entries = [source(f"src/package/area{i:02}/file.py", f"e-{i}") for i in range(25)]
    entries += [source(f"src/package/larger/file{i}.py", f"e-large-{i}") for i in range(8)]
    snapshot = {"evidence": entries}
    before = deepcopy(snapshot)
    result = get_system_map(snapshot)
    assert snapshot == before
    assert result == get_system_map({"evidence": list(reversed(entries))})
    assert len(result["areas"]) == MAX_AREAS and result["omitted_areas"] == 6
    larger = result["areas"][0]
    assert larger["path"] == "src/package/larger" and larger["files"] == 8
    assert len(larger["source_evidence_ids"]) == MAX_CITATIONS
    assert larger["omitted_source_evidence_ids"] == 3
    assert not ({"score", "debt", "priority", "capability", "burden"} & larger.keys())


def test_full_navigation_preserves_all_areas_dependencies_and_existing_compact_default():
    paths = [f"src/package/area{i:02}/file.py" for i in range(27)]
    snapshot = {
        "evidence": [source(path, f"e-{i}") for i, path in enumerate(paths)]
        + [
            analysis(
                "static-analysis",
                "e-analysis",
                [],
                [
                    {"source": path, "target": paths[(i + 1) % len(paths)], "line": 1}
                    for i, path in enumerate(paths)
                ],
                complete=False,
            )
        ],
    }
    before = deepcopy(snapshot)
    compact = get_system_map(snapshot)
    full = get_system_map(snapshot, compact=False)
    assert len(compact["areas"]) == len(compact["cross_area_dependencies"]) == 20
    assert compact["omitted_areas"] == compact["omitted_cross_area_dependencies"] == 7
    assert len(full["areas"]) == len(full["cross_area_dependencies"]) == 27
    assert full["omitted_areas"] == full["omitted_cross_area_dependencies"] == 0
    assert full["areas"][:20] == compact["areas"]
    assert full["cross_area_dependencies"][:20] == compact["cross_area_dependencies"]
    assert full["status"] == compact["status"] == "partial"
    assert snapshot == before


def test_missing_snapshot_fields_and_language_without_native_syntax_remain_unknown():
    empty = get_system_map({})
    assert empty["status"] == "not_collected" and empty["areas"] == [] and empty["gaps"]
    path = "src/package/payments/Service.java"
    result = get_system_map(
        {
            "evidence": [
                source(path, "e-java"),
                analysis(
                    "source-analysis", "e-text", [{"path": path, "language": "java", "lines": 10}]
                ),
            ]
        }
    )
    assert result["areas"][0]["functions"] is None
    assert result["areas"][0]["functions_known_files"] == 0
    assert result["native_import_graphs"] == [] and result["status"] == "partial"


def test_real_capture_provides_cited_module_counts_without_executing_source(tmp_path):
    root = tmp_path / "project"
    package = root / "src" / "sample" / "orders"
    package.mkdir(parents=True)
    script = package / "service.py"
    script.write_text("raise RuntimeError('must not execute')\ndef create_order():\n    return 1\n")
    before = script.read_bytes()
    snapshot = collect(root)
    result = get_system_map(snapshot)
    assert script.read_bytes() == before
    area = next(row for row in result["areas"] if row["path"] == "src/sample/orders")
    assert area["files"] == area["modules"] == area["functions"] == 1
    captured_ids = {entry["id"] for entry in snapshot["evidence"]}
    assert set(area["evidence_ids"]) <= captured_ids


def test_challenge_navigation_preserves_trace_and_area_breadth_under_tooling_noise():
    entries = [
        {"id": f"e-noise-{i}", "kind": "documentation", "path": f".agents/noise/{i:03}.md"}
        for i in range(200)
    ]
    entries += [
        {**source(f"src/product/area{i:02}/small.py", f"e-area-{i}"), "kind": "python"}
        for i in range(12)
    ]
    entries += [
        {**source("src/product/area00/large.py", "e-large", lines=2000), "kind": "python"},
        {**source("tests/test_integration.py", "e-test", role="test"), "kind": "python"},
        {"id": "e-manifest", "kind": "manifest", "path": "pyproject.toml"},
        {"id": "e-doc", "kind": "documentation", "path": "docs/architecture.md"},
        analysis(
            "static-analysis",
            "e-analysis",
            [
                {
                    "path": "src/product/area00/large.py",
                    "function_count": 40,
                    "pattern_functions": 0,
                    "overview_partial": True,
                }
            ],
        ),
    ]
    entries[-1]["path"] = "<static-analysis>"
    snapshot = {"evidence": entries}
    traces = [{"id": "valuable-change", "steps": [{"evidence_ids": ["e-test", "e-area-11"]}]}]
    before = deepcopy(snapshot)
    result = build_challenge_evidence_index(snapshot, traces, limit=20)
    reverse = build_challenge_evidence_index(
        {"evidence": list(reversed(entries))}, traces, limit=20
    )
    assert result == reverse and snapshot == before
    by_id = {row["id"]: row for row in result["items"]}
    assert {"e-test", "e-area-11", "e-large", "e-manifest", "e-doc"} <= by_id.keys()
    assert "production_area_owner" in by_id["e-large"]["selection_reasons"]
    assert "change_trace" in by_id["e-test"]["selection_reasons"]
    selection = result["selection"]
    assert selection["selected"] == 20 and selection["omitted"] == len(entries) - 20
    assert selection["production_areas"] == selection["represented_production_areas"] == 12
    assert selection["omitted_production_areas"] == 0
    assert not any("stats" in row or "excerpt" in row for row in result["items"])


def test_challenge_navigation_reports_omitted_areas_and_trace_records_without_grade_inference():
    entries = [
        {**source(f"src/pkg/area{i:02}/app.py", f"e-{i}"), "kind": "python"} for i in range(100)
    ]
    traces = [{"steps": [{"evidence_ids": [row["id"] for row in entries]}]}]
    result = build_challenge_evidence_index({"evidence": entries}, traces, limit=10)
    selection = result["selection"]
    assert len(result["items"]) == 10
    assert selection["omitted_trace_evidence"] == 90
    assert selection["omitted_production_areas"] == 90
    assert all("selection_reasons" in row for row in result["items"])
    assert not ({"confidence", "capability", "burden", "priority"} & selection.keys())


@pytest.mark.parametrize("limit", [0, 81, True, "20"])
def test_challenge_navigation_rejects_unbounded_or_invalid_limits(limit):
    with pytest.raises(ValueError, match="between 1 and 80"):
        build_challenge_evidence_index({}, [], limit=limit)
