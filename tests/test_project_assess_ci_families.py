"""Rule-specific work and lexical identities keep unrelated limits out of CI claims."""

import ast
import hashlib

import pytest

from project_assess import generic_analysis, javascript_analysis, static_analysis
from project_assess.ci_delta import build_ci_delta, render_ci_markdown


def python_summary(sources, **options):
    records = [
        static_analysis.analyze_python(path, ast.parse(text), **options)
        for path, text in sources.items()
    ]
    return static_analysis.summarize(records, len(records), 0)


def assessment(stats, sources, identity="a", kind="static-analysis"):
    return {
        "id": identity,
        "project_id": "project",
        "scope_digest": "same-config",
        "source": {"manifest_digest": identity},
        "complete": True,
        "facts": {"collection": {"supported_text_complete": True}},
        "evidence": [
            {
                "path": path,
                "kind": "source",
                "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            }
            for path, text in sources.items()
        ]
        + [{"path": "<native>", "kind": kind, "stats": stats}],
    }


def function(name="handle", decisions=12, indent=""):
    return (
        indent
        + f"def {name}(value):\n"
        + "".join(
            indent + f"    if value == {index}:\n" + indent + f"        return {index}\n"
            for index in range(decisions)
        )
        + indent
        + "    return None\n"
    )


def complex_rows(report):
    return [row for row in report["changes"] if row["kind"] == "complex_function"]


def test_complete_metrics_compare_despite_unrelated_pattern_detail_limits():
    before = {"app.py": function(decisions=12)}
    after = {"app.py": function(decisions=18)}
    old, new = [python_summary(sources, detail_budget=0) for sources in (before, after)]
    assert old["status"] == new["status"] == "partial"
    assert old["candidate_coverage"]["families"]["complex_function"]["complete"]
    assert not old["candidate_coverage"]["families"]["duplicate_function"]["complete"]
    report = build_ci_delta(
        assessment(old, before), assessment(new, after, "b"), fail_on_kinds=["complex_function"]
    )
    assert complex_rows(report)[0]["classification"] == "worsened"
    assert report["status"] == "partial" and report["policy"]["result"] == "fail"
    assert "Family coverage before" in render_ci_markdown(report)


def test_selected_complete_family_can_pass_without_certifying_partial_other_families():
    sources = {"app.py": function()}
    stats = python_summary(sources, detail_budget=0)
    report = build_ci_delta(
        assessment(stats, sources),
        assessment(stats, sources, "b"),
        fail_on_kinds=["complex_function"],
    )
    assert report["status"] == "partial" and report["policy"]["result"] == "pass"
    assert report["policy"]["coverage"][0]["before"]["complete"]
    assert (
        build_ci_delta(assessment(stats, sources), assessment(stats, sources, "b"))["policy"][
            "result"
        ]
        == "unknown"
    )


def test_same_named_methods_and_nested_functions_have_stable_distinct_owners():
    def source(first):
        return (
            "class First:\n"
            + function(decisions=first, indent="    ")
            + "class Second:\n"
            + function(decisions=20, indent="    ")
            + "def outer():\n"
            + function(decisions=12, indent="    ")
        )

    before, after = {"app.py": source(12)}, {"app.py": "\n\n" + source(18)}
    old, new = [python_summary(sources) for sources in (before, after)]
    symbols = {
        row["metrics"]["qualified_symbol"]
        for row in new["candidate_index"]
        if row["kind"] == "complex_function"
    }
    assert symbols == {"First.handle", "Second.handle", "outer.handle"}
    report = build_ci_delta(assessment(old, before), assessment(new, after, "b"))
    assert sorted(row["classification"] for row in complex_rows(report)) == [
        "existing",
        "existing",
        "worsened",
    ]


@pytest.mark.parametrize("owner", [False, True])
def test_repeated_bindings_are_ambiguous_even_when_only_one_is_a_candidate(owner):
    if owner:
        before = "class A:\n" + function(indent="    ") + "class A:\n    pass\n"
        after = "class A:\n    pass\nclass A:\n" + function(indent="    ")
    else:
        before = function("f") + "def f(value):\n    return value\n"
        after = "def f(value):\n    return value\n" + function("f")
    old, new = [python_summary({"app.py": source}) for source in (before, after)]
    for stats in (old, new):
        row = next(row for row in stats["candidate_index"] if row["kind"] == "complex_function")
        assert row["metrics"]["qualified_symbol"] is None
    report = build_ci_delta(
        assessment(old, {"app.py": before}), assessment(new, {"app.py": after}, "b")
    )
    assert complex_rows(report)[0]["classification"] == "unknown"


def test_matched_complete_function_can_worsen_despite_another_partial_function():
    noise = "def noise(value):\n" + "".join(f"    value += {i}\n" for i in range(2000))
    before, after = (
        {"app.py": function(decisions=12) + noise},
        {"app.py": function(decisions=18) + noise},
    )
    old, new = [python_summary(sources) for sources in (before, after)]
    assert not old["candidate_coverage"]["families"]["complex_function"]["complete"]
    report = build_ci_delta(assessment(old, before), assessment(new, after, "b"))
    row = complex_rows(report)[0]
    assert (
        row["classification"] == "worsened"
        and row["comparison_scope"] == "matched_complete_function"
    )


@pytest.mark.parametrize("omission", ["unparsed_file", "overview", "partial_function", "index"])
def test_missing_work_never_establishes_new_or_cleared_complexity(omission, monkeypatch):
    before = {"app.py": "def handle(value):\n    return value\n"}
    after = {"app.py": function()}
    if omission == "overview":
        before["app.py"] += "value = 0\n" * 20
        monkeypatch.setattr(static_analysis, "MAX_OVERVIEW_NODES", 10)
    elif omission == "index":
        monkeypatch.setattr(static_analysis, "MAX_INDEX", 0)
    options = {"metric_node_budget": 1} if omission == "partial_function" else {}
    old, new = [python_summary(sources, **options) for sources in (before, after)]
    if omission == "unparsed_file":
        records = [
            static_analysis.analyze_python(path, ast.parse(text)) for path, text in before.items()
        ]
        old = static_analysis.summarize(records, 2, 0)
    report = build_ci_delta(
        assessment(old, before), assessment(new, after, "b"), fail_on_kinds=["complex_function"]
    )
    assert not any(
        row["classification"] in {"new", "worsened", "no_longer_observed"}
        for row in complex_rows(report)
    )
    assert report["policy"]["result"] == "unknown"


@pytest.mark.parametrize("damage", ["schema", "missing_family", "retention", "boolean_count"])
def test_local_metric_proof_cannot_override_invalid_family_contract(damage):
    before, after = {"app.py": function(decisions=12)}, {"app.py": function(decisions=18)}
    old, new = [python_summary(sources) for sources in (before, after)]
    document = new["candidate_coverage"]
    if damage == "schema":
        document["schema_version"] = 99
    elif damage == "missing_family":
        del document["families"]["complex_function"]
    elif damage == "retention":
        document["families"]["complex_function"]["candidates_indexed"] = 0
    else:
        document["families"]["complex_function"]["eligible_units"] = True
    report = build_ci_delta(assessment(old, before), assessment(new, after, "b"))
    assert complex_rows(report)[0]["classification"] == "unknown"


def test_selected_unimplemented_family_does_not_pass_an_empty_inventory():
    sources = {"app.py": "value = 1\n"}
    stats = python_summary(sources)
    for selected in (["redundant_condition"],):
        report = build_ci_delta(
            assessment(stats, sources), assessment(stats, sources, "b"), fail_on_kinds=selected
        )
        assert report["policy"]["result"] == "unknown"


def test_whole_file_clone_identity_survives_membership_changes_without_false_new():
    text = "\n".join(
        f'let repeated_{index} = "a sufficiently long repeated value"' for index in range(20)
    )
    sources = {name: text for name in ("a.swift", "b.swift", "c.swift")}
    old = generic_analysis.summarize_source_text(sources, max_blocks=0)
    assert old["candidate_coverage"]["families"]["duplicate_source_file"]["complete"]
    assert not old["candidate_coverage"]["families"]["duplicate_source_block"]["complete"]
    for current, classification, policy in [
        ({name: text for name in ("a.swift", "b.swift")}, "improved", "pass"),
        ({**sources, "d.swift": text}, "worsened", "fail"),
    ]:
        new = generic_analysis.summarize_source_text(current, max_blocks=0)
        report = build_ci_delta(
            assessment(old, sources, kind="source-analysis"),
            assessment(new, current, "b", "source-analysis"),
            fail_on_kinds=["duplicate_source_file"],
        )
        assert report["counts"] == {classification: 1} and report["policy"]["result"] == policy


def javascript_summary(text):
    record = javascript_analysis.analyze_javascript("app.js", text)
    if not record["available"]:
        pytest.skip("optional syntax parser unavailable")
    return javascript_analysis.summarize_javascript([record], 1)


def js_function(name="f", decisions=12, params="value"):
    return (
        f"function {name}({params}) {{"
        + "".join(f"if(value === {i}) return {i};" for i in range(decisions))
        + "return null;}"
    )


def test_javascript_named_object_and_class_method_owners_are_distinct():
    body = "".join(f"if(value === {i}) return {i};" for i in range(12))
    text = f"const api = {{handle(value) {{{body}}}}}; class A {{handle(value) {{{body}}}}}"
    stats = javascript_summary(text)
    assert {
        row["metrics"]["qualified_symbol"]
        for row in stats["candidate_index"]
        if row["kind"] == "complex_function"
    } == {"api.handle", "A.handle"}


@pytest.mark.parametrize(
    "source",
    [lambda long, short: long + short, lambda long, short: "{ " + long + " } { " + short + " }"],
)
def test_javascript_repeated_or_unnamed_block_bindings_are_not_singleton_identities(source):
    before = source(js_function(), js_function(decisions=0))
    after = source(js_function(decisions=0), js_function())
    old, new = javascript_summary(before), javascript_summary(after)
    report = build_ci_delta(
        assessment(old, {"app.js": before}, kind="javascript-analysis"),
        assessment(new, {"app.js": after}, "b", "javascript-analysis"),
    )
    assert complex_rows(report)[0]["classification"] == "unknown"


def test_javascript_clone_budget_is_distinct_from_complete_body_metrics():
    def source(parameters):
        args = ",".join(f"p{i}" for i in range(parameters))
        return js_function("first", params=args) + js_function("second", params=args)

    before, after = source(2500), source(3100)
    old, new = javascript_summary(before), javascript_summary(after)
    assert new["candidate_coverage"]["families"]["complex_function"]["complete"]
    assert not new["candidate_coverage"]["families"]["near_duplicate_function"]["complete"]
    report = build_ci_delta(
        assessment(old, {"app.js": before}, kind="javascript-analysis"),
        assessment(new, {"app.js": after}, "b", "javascript-analysis"),
    )
    clones = [row for row in report["changes"] if row["kind"] == "near_duplicate_function"]
    assert len(clones) == 1 and clones[0]["classification"] == "unknown"


def test_legacy_fallback_is_limited_to_rules_implemented_by_that_producer():
    sources = {"app.py": "value = 1\n"}
    stats = python_summary(sources)
    del stats["candidate_coverage"]
    for version, selected in [("4", "redundant_condition"), ("1", "near_duplicate_function")]:
        stats["analyzer"]["version"] = version
        report = build_ci_delta(
            assessment(stats, sources), assessment(stats, sources, "b"), fail_on_kinds=[selected]
        )
        assert report["policy"]["result"] == "unknown"
        assert report["policy"]["coverage"][0]["provider"] == "unadvertised rule"


def test_complete_static_graph_still_detects_new_dependency_cycles():
    before = {"a.py": "import b\n", "b.py": "value = 1\n"}
    after = {"a.py": "import b\n", "b.py": "import a\n"}
    old, new = [python_summary(sources) for sources in (before, after)]
    assert new["candidate_coverage"]["families"]["dependency_cycle"]["complete"]
    report = build_ci_delta(
        assessment(old, before), assessment(new, after, "b"), fail_on_kinds=["dependency_cycle"]
    )
    assert [
        row["classification"] for row in report["changes"] if row["kind"] == "dependency_cycle"
    ] == ["new"]
    assert report["policy"]["result"] == "fail"


def test_zero_javascript_inputs_do_not_need_an_optional_parser(monkeypatch):
    monkeypatch.setattr(
        javascript_analysis,
        "javascript_analyzer_identity",
        lambda: {"available": False, "name": "project-assess-tree-sitter", "version": "5"},
    )
    stats = javascript_analysis.summarize_javascript([], 0)
    assert stats["candidate_coverage"]["families"]["complex_function"]["complete"]
    report = build_ci_delta(
        assessment(stats, {}, kind="javascript-analysis"),
        assessment(stats, {}, "b", "javascript-analysis"),
        fail_on_kinds=["complex_function"],
    )
    assert report["policy"]["result"] == "pass"
