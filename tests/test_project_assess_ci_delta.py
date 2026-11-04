"""CI changes retain full-inventory context and never infer verified closure."""

from copy import deepcopy

import pytest

from project_assess.ci_delta import build_ci_delta, render_ci_markdown


def lead(kind="complex_function", *, line=1, decisions=12, symbol="handle", path="app.py"):
    return {
        "kind": kind,
        "id": f"ephemeral-{line}-{decisions}",
        "locations": [{"path": path, "line": line, "end_line": line + 3}],
        "metrics": {"symbol": symbol, "decision_points": decisions, "control_nesting": 4},
    }


def snapshot(rows=(), *, identity="a", complete=True, status="complete"):
    return {
        "id": identity,
        "project_id": "project",
        "scope_digest": "standard-scope-v1",
        "source": {"manifest_digest": identity},
        "complete": complete,
        "facts": {"collection": {"supported_text_complete": complete}},
        "evidence": [
            {"kind": "python", "path": "app.py", "digest": identity},
            {
                "kind": "static-analysis",
                "path": "<static-analysis>",
                "stats": {
                    "schema_version": 1,
                    "analyzer": {"name": "python-ast", "version": "1"},
                    "status": status,
                    "coverage": {"python_files": 1},
                    "candidates": [],  # Rich sample is deliberately empty.
                    "candidate_index": list(rows),
                    "candidate_counts": {"omitted_from_index": 0},
                    "topology": {"edges": [{"source": "cli.py", "target": "app.py"}]},
                    "gaps": [],
                },
            },
        ],
    }


def test_line_motion_is_existing_and_metric_growth_is_worsening_without_review_scores():
    before = snapshot([lead()])
    moved = snapshot([lead(line=40)], identity="b")
    report = build_ci_delta(before, moved)
    assert report["counts"] == {"existing": 1}
    assert report["context"]["changed_files"] == ["app.py"]
    assert report["context"]["captured_callers"] == ["cli.py"]
    assert report["policy"]["mode"] == "advisory" and report["policy"]["exit_code"] == 0

    after = snapshot([lead(line=41, decisions=18)], identity="c")
    worsening = build_ci_delta(before, after, fail_on_kinds=["complex_function"])
    assert worsening["counts"] == {"worsened": 1}
    assert worsening["changes"][0]["key"] == report["changes"][0]["key"]
    assert worsening["policy"]["exit_code"] == 1
    assert worsening["policy"]["result"] == "fail"


def test_new_improved_and_disappeared_are_distinct_from_verified_closure():
    report = build_ci_delta(
        snapshot([lead(), lead(symbol="gone")]),
        snapshot([lead(decisions=10), lead(symbol="new")], identity="b"),
    )
    assert report["counts"] == {"improved": 1, "new": 1, "no_longer_observed": 1}
    assert "verified finding closure is separate" in report["caveat"]
    assert all(row["classification"] != "verified" for row in report["changes"])


@pytest.mark.parametrize("mutation", ["scope", "project", "producer", "manifest", "missing"])
def test_incompatible_evidence_never_clears_or_fails_policy(mutation):
    before, after = snapshot([lead()]), snapshot([lead(symbol="new")], identity="b")
    if mutation == "scope":
        after["scope_digest"] = "different-profile-or-config"
    elif mutation == "project":
        after["project_id"] = "other"
    elif mutation == "producer":
        after["evidence"][1]["stats"]["analyzer"]["version"] = "2"
    elif mutation == "manifest":
        after["source"] = {}
    else:
        after["evidence"].pop()
    report = build_ci_delta(before, after, fail_on_kinds=["complex_function"])
    assert report["status"] == "incompatible" and report["comparable"] is False
    assert set(report["counts"]) == {"unknown"}
    assert report["policy"]["result"] == "unknown" and report["policy"]["exit_code"] == 0


def test_partial_baseline_or_current_cannot_establish_introduction_or_clearance():
    report = build_ci_delta(snapshot(status="partial"), snapshot([lead()], identity="b"))
    assert report["counts"] == {"unknown": 1}
    assert "incomplete baseline" in report["changes"][0]["reason"]
    report = build_ci_delta(snapshot([lead()]), snapshot(identity="b", complete=False))
    assert report["counts"] == {"unknown": 1}
    assert "clearance is unknown" in report["changes"][0]["reason"]
    # An unrelated Deep optional analyzer gap does not erase complete native evidence.
    before, after = snapshot([lead()]), snapshot([lead(decisions=15)], identity="b")
    before["complete"] = after["complete"] = False
    assert build_ci_delta(before, after)["counts"] == {"worsened": 1}


def test_index_omissions_partial_metrics_and_aggregate_ambiguity_remain_unknown():
    before, after = snapshot([lead()]), snapshot([lead(decisions=15)], identity="b")
    after["evidence"][1]["stats"]["candidate_counts"]["omitted_from_index"] = 5
    assert build_ci_delta(before, after)["counts"] == {"unknown": 1}
    after = snapshot([lead(decisions=15)], identity="b")
    after["evidence"][1]["stats"]["candidate_index"][0]["metrics"]["partial"] = True
    assert build_ci_delta(before, after)["counts"] == {"unknown": 1}
    before = snapshot([lead(symbol=None), lead(symbol=None, line=30)])
    after = snapshot([lead(symbol=None)], identity="b")
    report = build_ci_delta(before, after)
    assert report["counts"] == {"unknown": 1}
    assert "multiple sites" in report["changes"][0]["reason"]


@pytest.mark.parametrize("after_decisions", [(18, 20), (18, 19)])
def test_equal_multiplicity_same_named_methods_cannot_hide_site_growth(after_decisions):
    before = snapshot([lead(line=1, decisions=12), lead(line=30, decisions=20)])
    after = snapshot(
        [lead(line=1, decisions=after_decisions[0]), lead(line=30, decisions=after_decisions[1])],
        identity="b",
    )
    report = build_ci_delta(before, after, fail_on_kinds=["complex_function"])
    assert report["counts"] == {"unknown": 1}
    assert report["changes"][0]["before"]["count"] == 2
    assert report["changes"][0]["after"]["count"] == 2
    assert report["policy"]["result"] == "unknown"
    assert report["policy"]["exit_code"] == 0


def test_only_known_presentation_limits_allow_complete_compact_inventory():
    before = snapshot()
    after = snapshot([lead()], identity="b", status="partial")
    after["evidence"][1]["stats"]["gaps"] = [
        "Static candidate limit reached; remaining candidates omitted",
        "Dynamic imports, runtime alias resolution, actual call frequency and change cost are not established",
    ]
    report = build_ci_delta(before, after)
    assert report["status"] == "complete" and report["counts"] == {"new": 1}
    after["evidence"][1]["stats"]["gaps"].append("New unknown analyzer limit")
    assert build_ci_delta(before, after)["status"] == "partial"
    after["evidence"][1]["stats"]["schema_version"] = 99
    report = build_ci_delta(before, after)
    assert report["status"] == "incompatible" and report["counts"] == {"unknown": 1}


def test_unrelated_legacy_leads_are_existing_and_default_policy_does_not_block():
    before = snapshot([lead(path="legacy.py")])
    after = deepcopy(before)
    after["id"] = "b"
    after["source"]["manifest_digest"] = "b"
    after["evidence"][0]["digest"] = "b"
    report = build_ci_delta(before, after)
    assert report["counts"] == {"existing": 1}
    assert report["policy"]["exit_code"] == 0
    assert "legacy.py" in report["changes"][0]["paths"]


def test_empty_incomplete_inventory_cannot_report_a_clean_pass():
    report = build_ci_delta(snapshot(), snapshot(complete=False))
    assert report["counts"] == {} and report["status"] == "partial"
    assert report["policy"]["result"] == "unknown"
    assert report["policy"]["exit_code"] == 0


def test_duplicate_producer_and_unsupported_policy_are_explicit():
    before, after = snapshot(), snapshot([lead()])
    before["evidence"].append(deepcopy(before["evidence"][1]))
    report = build_ci_delta(before, after)
    assert report["counts"] == {"unknown": 1}
    assert "ambiguous" in report["coverage"][0]["before"]["gaps"][0]
    for policy in (["complex_functoin"], "complex_function", [None]):
        with pytest.raises(ValueError, match="supported native"):
            build_ci_delta(before, after, fail_on_kinds=policy)


def test_report_is_deterministic_does_not_mutate_input_and_escapes_markdown():
    before = snapshot()
    after = snapshot([lead(path="[click](javascript:alert).py")])
    original = deepcopy((before, after))
    report = build_ci_delta(before, after)
    assert report == build_ci_delta(before, after)
    assert (before, after) == original
    markdown = render_ci_markdown(report)
    assert "\\[click\\]" in markdown
    assert "[click](javascript:" not in markdown
    assert "not defects" in markdown and "full captured inventories" in markdown


def test_real_standard_collection_detects_a_new_complex_function_without_ai(tmp_path):
    from project_assess.collector import collect

    source = tmp_path / "app.py"
    source.write_text("def handle(value):\n    return value\n")
    before = collect(tmp_path, analysis_profile="standard", analyzers=[])
    source.write_text(
        "def handle(value):\n"
        + "".join(f"    if value == {index}:\n        return {index}\n" for index in range(12))
        + "    return None\n"
    )
    after = collect(tmp_path, analysis_profile="standard", analyzers=[])
    for index, assessment in enumerate((before, after)):
        assessment.update(id=f"a{index}", project_id="same-project")
    report = build_ci_delta(before, after, fail_on_kinds=["complex_function"])
    assert report["comparable"] is True
    complex_rows = [row for row in report["changes"] if row["kind"] == "complex_function"]
    assert len(complex_rows) == 1 and complex_rows[0]["classification"] == "new"
    assert report["policy"]["exit_code"] == 1
    assert report["context"]["changed_files"] == ["app.py"]
