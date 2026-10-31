"""Orientation retains source scope without turning area size into a judgment."""

from copy import deepcopy

from project_assess.collector import collect
from project_assess.review_context import MAX_AREAS, MAX_CITATIONS, get_system_map


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
