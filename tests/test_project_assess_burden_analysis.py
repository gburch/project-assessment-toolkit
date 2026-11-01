import ast
from copy import deepcopy

import pytest

from project_assess import burden_analysis as burden
from project_assess.rubric import DIMENSIONS


def analyze(text, **kwargs):
    return burden.analyze_change_gates("scripts/verification.py", ast.parse(text), **kwargs)


def source(path="src/app.py", kind="python", **stats):
    return {
        "id": path,
        "path": path,
        "kind": kind,
        "digest": "a" * 64,
        "lines": 2000,
        "stats": stats,
    }


def test_gate_relates_full_to_literal_path_rules_and_marks_mutation_without_execution():
    result = analyze("""
FILES = frozenset({"pyproject.toml", "src/policy.py"})
PREFIXES = ("src/core/", "ops/verification/")
def choose_verification(paths, mode):
    broad = [p for p in paths if p in FILES
             or any(p.startswith(prefix) for prefix in PREFIXES)
             or Path(p).name in {"store.py", "schema.py"}
             or p.endswith("/conftest.py")]
    broad.extend(load_policy())
    full = mode == "full" or bool(broad)
    raise RuntimeError("must never execute")
""")
    full = next(s for s in result["signals"] if s["context"]["decision_names"] == ["full"])
    assert full["locations"][0]["line"] == 10
    context = full["context"]
    assert "broad" in context["selector_references"]
    assert {(p["value"], p["match"]) for p in context["patterns"]} >= {
        ("src/policy.py", "membership_syntax"),
        ("src/core/", "prefix_syntax"),
        ("store.py", "basename_membership_syntax"),
        ("/conftest.py", "suffix_syntax"),
    }
    assert (
        next(p for p in context["patterns"] if p["value"] == "src/core/")["declaration_line"] == 3
    )
    assert context["selector_mutations"] == [
        {"selector": "broad", "line": 9, "operation": "extend"}
    ]
    assert context["policy_execution"] == "not_evaluated"
    assert "paths" in context["unresolved_references"]
    assert full["interpretation"] == "static_lead"
    assert any("no policy closure" in gap for gap in result["gaps"])
    assert result["coverage"]["patterns_retained"] == sum(
        len(s["context"]["patterns"]) for s in result["signals"]
    )


def test_gate_supports_conditional_true_and_globs_but_not_unrelated_broad_names():
    result = analyze("""
def test_gate(path):
    if fnmatch(path, "src/**/*.py"):
        run_full = True
""")
    assert result["signals"][0]["context"]["patterns"] == [
        {"value": "src/**/*.py", "match": "glob_syntax", "declaration_line": 3}
    ]
    unrelated = burden.analyze_change_gates(
        "src/formatter.py",
        ast.parse("""
def format_data(path):
    broad = path.startswith("src/")
"""),
    )
    assert unrelated["status"] == "complete"
    assert unrelated["signals"] == []
    assert analyze('full = mode in {"full", "quick"}')["signals"] == []


def test_shadowing_and_dynamic_selection_do_not_borrow_outer_literal_policy():
    result = analyze("""
PREFIXES = ("src/secret/",)
def choose_tests(paths, PREFIXES):
    broad = [p for p in paths if p.startswith(PREFIXES)]
    full = bool(broad)
""")
    assert all(not s["context"]["patterns"] for s in result["signals"])
    full = result["signals"][0]
    assert full["context"]["decision_names"] == ["full"]
    assert "PREFIXES" in full["context"]["unresolved_references"]
    assert result["coverage"]["unsupported_pattern_expressions"] > 0


def test_comprehension_aliases_stay_with_their_own_selector_expression():
    result = analyze("""
FIRST = ("src/first/",)
SECOND = ("src/second/",)
def test_gate(path):
    full = any(path.startswith(prefix) for prefix in FIRST) or any(path.endswith(prefix) for prefix in SECOND)
""")
    assert {(p["value"], p["match"]) for p in result["signals"][0]["context"]["patterns"]} == {
        ("src/first/", "prefix_syntax"),
        ("src/second/", "suffix_syntax"),
    }


@pytest.mark.parametrize("mutation", ["", "PREFIXES += load_policy()"])
def test_dynamic_comprehension_binding_and_augassign_never_borrow_outer_literals(mutation):
    expression = (
        "any(path.startswith(PREFIXES) for PREFIXES in runtime_values())"
        if not mutation
        else "path.startswith(PREFIXES)"
    )
    result = analyze(f"""
PREFIXES = ("src/outer/",)
{mutation}
def test_gate(path):
    full = {expression}
""")
    assert not any(
        p["value"] == "src/outer/" for s in result["signals"] for p in s["context"]["patterns"]
    )
    assert result["coverage"]["unsupported_pattern_expressions"] > 0


def test_gate_detail_and_traversal_limits_are_explicit_including_zero_retention():
    text = "\n".join(f'full_{i} = path.startswith(("src/{i}/", "ops/{i}/"))' for i in range(70))
    result = analyze(text, record_limit=1, pattern_limit=1)
    coverage = result["coverage"]
    assert result["status"] == "partial"
    assert coverage["candidates_observed"] == 70
    assert coverage["candidates_examined"] == burden.MAX_SELECTOR_CANDIDATES
    assert coverage["candidates_omitted"] == 6
    assert coverage["selectors_retained"] == 1
    assert coverage["selectors_omitted"] == burden.MAX_SELECTOR_CANDIDATES - 1
    assert coverage["patterns_retained"] == 1
    assert coverage["patterns_omitted"] == burden.MAX_SELECTOR_CANDIDATES * 2 - 1
    empty = analyze(text, record_limit=0)
    assert empty["signals"] == []
    assert empty["coverage"]["patterns_retained"] == 0
    assert empty["coverage"]["patterns_omitted"] > 0
    partial = analyze(text, node_limit=5)
    assert partial["status"] == "partial"
    assert partial["coverage"]["nodes_examined"] == 5
    assert analyze("x = 1")["status"] == "complete"


@pytest.mark.parametrize(
    "kwargs", [{"node_limit": True}, {"record_limit": -1}, {"pattern_limit": 257}]
)
def test_gate_rejects_invalid_bounds(kwargs):
    with pytest.raises(ValueError):
        analyze("x = 1", **kwargs)


def test_summary_binds_current_source_and_preserves_topology_limits_without_assigning_scores():
    evidence = [
        source(),
        source("tests/test_app.py"),
        {
            "id": "analysis",
            "kind": "static-analysis",
            "stats": {
                "status": "partial",
                "modules": [
                    {
                        "path": "src/app.py",
                        "role": "production",
                        "lines": 1700,
                        "inbound": 23,
                        "outbound": 11,
                        "inbound_complete": False,
                    }
                ],
                "hotspots": [
                    {
                        "path": "src/app.py",
                        "line": 2,
                        "end_line": 80,
                        "name": "change",
                        "decision_points": 42,
                        "metric_basis": "lower_bound",
                        "partial": True,
                    },
                    {"path": "tests/test_app.py", "line": 3, "decision_points": 21, "role": "test"},
                    {"path": "../foreign.py", "line": 1, "decision_points": 99},
                    {"path": "src/app.py", "line": 2001, "decision_points": 99},
                ],
                "candidate_index": [
                    {
                        "id": "cycle",
                        "kind": "dependency_cycle",
                        "locations": [
                            {"path": "src/app.py", "line": 1},
                            {"path": "../foreign.py", "line": 1},
                        ],
                    }
                ],
            },
        },
    ]
    result = burden.summarize_burden({"evidence": evidence})
    assert result["status"] == "partial"
    assert result["coverage"]["leads_observed"] == 4
    hotspot = next(r for r in result["leads"] if r["metrics"].get("name") == "change")
    assert hotspot["metrics"]["metric_basis"] == "lower_bound"
    assert hotspot["locations"][0]["source_evidence_id"] == "src/app.py"
    assert hotspot["locations"][0]["source_digest"] == "a" * 64
    assert hotspot["analysis_evidence_id"] == "analysis"
    assert set(result["dimensions"]) == set(DIMENSIONS)
    assert all(r["cost_status"] == "not_established" and "score" not in r for r in result["leads"])
    assert all(
        location["path"] != "../foreign.py" for r in result["leads"] for location in r["locations"]
    )
    assert result == burden.summarize_burden({"evidence": list(reversed(evidence))})


def test_duplicate_volume_does_not_displace_gate_or_complexity_and_zero_limit_is_explicit():
    gates = analyze('full = path.startswith("src/")')
    entry = source(change_gates=gates)
    entry["path"] = "scripts/verification.py"
    candidates = [
        {
            "id": str(i),
            "kind": "duplicate_block",
            "locations": [{"path": entry["path"], "line": i + 1}],
        }
        for i in range(50)
    ]
    assessment = {
        "evidence": [
            entry,
            {"id": "static", "kind": "static-analysis", "stats": {"candidate_index": candidates}},
        ]
    }
    result = burden.summarize_burden(assessment, limit=2)
    assert {r["kind"] for r in result["leads"]} == {"change_gate_selector", "duplicate_block"}
    assert result["coverage"]["leads_omitted"] == 49
    empty = burden.summarize_burden(assessment, limit=0)
    assert empty["leads"] == []
    assert empty["status"] == "partial"
    assert empty["dimensions"]["security"]["cost_status"] == "not_established"
    with pytest.raises(ValueError):
        burden.summarize_burden(assessment, limit=True)


def test_summary_routes_declared_coordination_and_reuses_control_context_across_dimensions():
    signals = []
    for kind, dim in [
        ("delivery.dependencies", "delivery"),
        ("security.authorization_declaration", "security"),
        ("operability.retry_policy", "operability"),
        ("extensibility.discovery_or_dispatch", "extensibility"),
        ("performance.io_in_loop", "performance"),
    ]:
        signals.append(
            {
                "kind": kind,
                "dimensions": [dim],
                "locations": [{"path": "src/app.py", "line": 1}],
                "confidence": "medium",
                "context": {"owner": "change", "binding": "unresolved_name"},
            }
        )
    result = burden.summarize_burden(
        {
            "evidence": [
                source(),
                {"id": "controls", "kind": "control-analysis", "stats": {"signals": signals}},
            ]
        }
    )
    assert all(
        result["dimensions"][d]["lead_count"] >= 1
        for d in ["security", "delivery", "operability", "extensibility", "performance"]
    )
    declared = next(r for r in result["leads"] if r["kind"] == "declared_gate_coordination")
    assert declared["interpretation"] == "declared_control"
    assert declared["cost_status"] == "not_established"


def test_timing_semantics_keep_summed_cases_distinct_from_wall_time_and_preserve_observations():
    observation = {
        "type": "change_cost",
        "scenario": {"name": "focused", "scope": "two files"},
        "sourceIdentity": {"overall": "match"},
        "results": [{"name": "wait", "value": 20, "unit": "seconds", "status": "observed"}],
        "limitations": ["Required final gate omitted"],
    }
    original = deepcopy(observation)
    result = burden.summarize_burden(
        {
            "evidence": [
                {"id": "junit", "kind": "junit", "stats": {"seconds": 3600}},
                {"id": "observed", "kind": "observation", "stats": observation},
            ]
        }
    )
    junit, supplied = result["timings"]
    assert junit["timing_semantics"] == "sum_testcase_elapsed"
    assert junit["wall_clock_seconds"] is None
    assert junit["completion"] == "unestablished"
    assert supplied["results"] == original["results"]
    assert supplied["limitations"] == original["limitations"]
    assert observation == original
    assert all(r["cost_status"] == "not_established" for r in result["dimensions"].values())
    assert any("absence is not proof" in gap for gap in result["gaps"])


def test_missing_mechanisms_and_observations_remain_explicit_gaps():
    result = burden.summarize_burden({"evidence": []})
    assert result["leads"] == []
    assert result["gaps"]
    assert all(
        r["lead_count"] == 0 and r["cost_status"] == "not_established"
        for r in result["dimensions"].values()
    )


def test_summary_records_input_detail_omissions(monkeypatch):
    monkeypatch.setattr(burden, "MAX_INPUT_ROWS", 1)
    result = burden.summarize_burden(
        {
            "evidence": [
                source(),
                {
                    "id": "static",
                    "kind": "static-analysis",
                    "stats": {
                        "hotspots": [
                            {"path": "src/app.py", "line": 1, "decision_points": 30},
                            {"path": "src/app.py", "line": 10, "decision_points": 50},
                        ]
                    },
                },
            ]
        }
    )
    assert result["status"] == "partial"
    assert result["coverage"]["input_rows_omitted"] == 1


def test_summary_ranks_largest_and_most_complex_surfaces_before_alphabetic_order():
    assessment = {
        "evidence": [
            source("src/a.py"),
            source("src/z.py"),
            {
                "id": "static",
                "kind": "static-analysis",
                "stats": {
                    "modules": [
                        {"path": "src/a.py", "lines": 1001, "role": "production"},
                        {"path": "src/z.py", "lines": 1900, "role": "production"},
                    ],
                    "hotspots": [
                        {"path": "src/a.py", "line": i + 1, "decision_points": i + 20}
                        for i in range(500)
                    ],
                },
            },
        ]
    }
    result = burden.summarize_burden(assessment, limit=2)
    assert (
        next(r for r in result["leads"] if r["kind"] == "large_change_surface")["locations"][0][
            "path"
        ]
        == "src/z.py"
    )
    assert (
        next(r for r in result["leads"] if r["kind"] == "complex_change_surface")["metrics"][
            "decision_points"
        ]
        == 519
    )
    assert result["coverage"]["leads_observed"] == 502
