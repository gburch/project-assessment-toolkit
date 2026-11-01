import json
from copy import deepcopy

import pytest

from project_assess.collector import collect
from project_assess.review_plan import build_review_plan, dimension_coverage
from project_assess.rubric import DIMENSIONS


def source(path, identity, kind="python", role="production", **stats):
    return {
        "id": identity,
        "path": path,
        "kind": kind,
        "digest": "sha256:" + "a" * 64,
        "lines": 80,
        "stats": {"role": role, **stats},
    }


def snapshot(entries, **collection):
    return {
        "id": "a-fixture",
        "source": {"manifest_digest": "sha256:" + "b" * 64},
        "complete": True,
        "facts": {
            "collection": {
                "discovery_complete": True,
                "supported_text_complete": True,
                **collection,
            }
        },
        "evidence": entries,
    }


def test_first_run_sparse_utility_has_all_dimensions_without_invented_judgment(tmp_path):
    app = tmp_path / "utility.py"
    app.write_text(
        "raise RuntimeError('must not execute')\ndef summarize(values):\n    return len(values)\n"
    )
    (tmp_path / "README.md").write_text("# Setup\nRun the local utility.\n")
    captured = collect(tmp_path)
    before = deepcopy(captured)
    plan = build_review_plan(captured)
    assert set(plan["dimensions"]) == set(DIMENSIONS)
    for pack in plan["dimensions"].values():
        assert pack["status"] == "inspection_required"
        assert pack["needs_follow_up"]
        assert pack["questions"] and pack["source_tasks"]
        assert {task["path"] for task in pack["source_tasks"]} == {"utility.py", "README.md"}
        assert not {"capability", "burden", "confidence", "priority"}.intersection(pack)
    assert captured == before
    assert app.read_text().startswith("raise RuntimeError")


def test_framework_packets_connect_only_captured_native_imports_and_keep_binding_limits():
    contract = source("src/framework/contracts.py", "contract")
    provider = source("src/framework/providers/local.py", "provider")
    test = source("tests/test_provider.py", "test", role="test")
    unknown = source("external/Plugin.swift", "swift", kind="source")
    entries = [
        contract,
        provider,
        test,
        unknown,
        source("README.md", "guide", kind="documentation", role="unknown"),
        source("pyproject.toml", "manifest", kind="manifest", role="unknown"),
        {
            "id": "controls",
            "kind": "control-analysis",
            "stats": {
                "signals": [
                    {
                        "kind": "extension_contract",
                        "dimensions": ["extensibility"],
                        "locations": [{"path": contract["path"], "line": 10, "end_line": 12}],
                        "source_evidence_id": "contract",
                        "source_digest": contract["digest"],
                    },
                    {
                        "kind": "mismatched_signal",
                        "dimensions": ["extensibility"],
                        "locations": [{"path": provider["path"], "line": 7}],
                        "source_evidence_id": "wrong-source",
                    },
                ]
            },
        },
        {
            "id": "native",
            "kind": "static-analysis",
            "stats": {
                "topology": {
                    "edges": [
                        {
                            "source": provider["path"],
                            "target": contract["path"],
                            "line": 2,
                            "phase": "eager",
                        },
                        {
                            "source": test["path"],
                            "target": provider["path"],
                            "line": 1,
                            "phase": "deferred",
                        },
                        {"source": provider["path"], "target": "uncaptured.py", "line": 3},
                    ]
                }
            },
        },
        {
            "id": "joern",
            "kind": "analyzer-analysis",
            "stats": {"inferred_edges": [{"source": unknown["path"], "target": provider["path"]}]},
        },
    ]
    pack = build_review_plan(snapshot(entries), dimension="extensibility")["dimensions"][
        "extensibility"
    ]
    by_id = {task["evidence_id"]: task for task in pack["source_tasks"]}
    assert by_id["contract"]["strength"] == "located_signal"
    assert (by_id["contract"]["line"], by_id["contract"]["end_line"]) == (10, 12)
    assert by_id["provider"]["strength"] == "captured_import_context"
    assert "mismatched_signal" not in by_id["provider"]["signal_kinds"]
    assert len(pack["connections"]) == 2
    assert {edge["relationship"] for edge in pack["connections"]} == {"captured_import"}
    assert {edge["phase"] for edge in pack["connections"]} == {"eager", "deferred"}
    assert all(edge["analysis_evidence_id"] == "native" for edge in pack["connections"])
    assert pack["coverage"]["syntax_gaps"] == [
        {
            "path": unknown["path"],
            "evidence_id": "swift",
            "reason": "native_language_analysis_not_present",
        }
    ]


def test_deep_allocates_more_inspection_breadth_without_grade_or_coverage_promotion():
    entries = [source(f"src/product/area{i:02}/owner.py", f"owner-{i}") for i in range(24)]
    entries += [source(f"tests/noise/test_{i:03}.py", f"test-{i}", role="test") for i in range(120)]
    entries += [
        source("docs/operations.md", "ops", kind="documentation", role="unknown"),
        source("package.json", "manifest", kind="manifest", role="unknown"),
    ]
    standard = build_review_plan(snapshot(entries), dimension="operability")["dimensions"][
        "operability"
    ]
    deep_source = snapshot(entries, analysis_profile="deep")
    before = deepcopy(deep_source)
    deep = build_review_plan(deep_source, dimension="operability")["dimensions"]["operability"]
    assert len(standard["source_tasks"]) == 8 and len(deep["source_tasks"]) == 16
    assert (
        len({task["area"] for task in deep["source_tasks"] if task["role"] == "production"}) >= 10
    )
    assert {"ops", "manifest"} <= {task["evidence_id"] for task in deep["source_tasks"]}
    assert sum(task["role"] == "test" for task in deep["source_tasks"]) < 4
    assert deep["selection"]["omitted_source_records"] > 0
    assert deep["status"] == "inspection_required" and deep["needs_follow_up"]
    assert deep_source == before


def test_large_late_named_owner_is_not_hidden_by_lexical_order_within_its_area():
    small = source("src/core/a_small.py", "small")
    large = source("src/core/z_large.py", "large")
    large["lines"] = 4000
    captured = snapshot([small, large])
    task = build_review_plan(captured, dimension="maintainability", limit=1)["dimensions"][
        "maintainability"
    ]["source_tasks"][0]
    assert task["evidence_id"] == "large"
    assert task["strength"] == "inventory_seed"
    assert not {"score", "debt", "confidence"}.intersection(task)


def test_asset_skips_do_not_become_omitted_source_but_unknown_or_relevant_scope_stays_open():
    captured = snapshot(
        [],
        skipped_files=1,
        skipped_inputs=[
            {"path": "screenshots/large.png", "kind": None, "reason": "file-byte-limit"}
        ],
    )
    captured["complete"] = False
    for dimension in DIMENSIONS:
        coverage = dimension_coverage(captured, dimension)
        assert coverage["status"] == "complete" and coverage["collection_blockers"] == []
        assert coverage["asset_only_omissions"] and coverage["notes"]
    captured["facts"]["collection"]["skipped_inputs"].append(
        {"path": "src/recovery.py", "kind": "python", "reason": "deadline"}
    )
    captured["facts"]["collection"]["skipped_files"] = 2
    captured["facts"]["collection"]["supported_text_complete"] = False
    coverage = dimension_coverage(captured, "operability")
    assert coverage["status"] == "partial"
    assert coverage["material_omissions"][0]["path"] == "src/recovery.py"
    assert coverage["collection_blockers"]
    del captured["facts"]["collection"]["skipped_inputs"]
    assert dimension_coverage(captured, "operability")["collection_blockers"]
    assert dimension_coverage({}, "performance")["status"] == "unknown"


def test_unverified_asset_only_scope_and_unknown_assets_are_not_silently_cleared():
    captured = {
        "complete": False,
        "facts": {
            "collection": {
                "skipped_inputs": [{"path": "image.png", "kind": None, "reason": "file-byte-limit"}]
            }
        },
    }
    assert dimension_coverage(captured, "security")["collection_blockers"]
    captured["facts"]["collection"]["skipped_inputs"][0]["path"] = "unknown.payload"
    assert dimension_coverage(captured, "security")["material_omissions"]


def test_skipped_lockfile_preserves_dependency_limits_without_blanket_workflow_penalty():
    captured = snapshot(
        [],
        supported_text_complete=False,
        skipped_files=1,
        skipped_inputs=[
            {
                "path": "ops/tool/package-lock.json",
                "kind": "configuration",
                "reason": "file-byte-limit",
                "role": "tooling",
            }
        ],
    )
    captured["complete"] = False
    for dimension in ("documentation", "operability", "extensibility", "performance"):
        coverage = dimension_coverage(captured, dimension)
        assert coverage["collection_blockers"] == [] and coverage["status"] == "complete"
        omission = coverage["material_omissions"][0]
        assert omission["relevant"] is False and omission["scope_basis"] == "dependency_resolution"
        assert omission["uncertainty"] and coverage["notes"]
    for dimension in ("security", "testing", "maintainability", "delivery"):
        coverage = dimension_coverage(captured, dimension)
        assert coverage["collection_blockers"] and coverage["status"] == "partial"
        assert coverage["material_omissions"][0]["relevant"] is True
    captured["facts"]["collection"]["skipped_inputs"][0]["path"] = "src/recovery.py"
    captured["facts"]["collection"]["skipped_inputs"][0]["kind"] = "python"
    assert all(dimension_coverage(captured, d)["collection_blockers"] for d in DIMENSIONS)


def test_analysis_limits_are_dimension_specific_and_independent_of_source_capture():
    captured = snapshot(
        [
            {
                "id": "docs",
                "kind": "documentation-analysis",
                "stats": {"status": "partial", "gaps": ["link limit"]},
            },
            {
                "id": "controls",
                "kind": "control-analysis",
                "stats": {
                    "status": "partial",
                    "coverage": {
                        "dimensions": {
                            "operability": {"partial_files": 2},
                            "performance": {"partial_files": 0},
                        }
                    },
                    "gaps": ["one AST budget"],
                },
            },
        ]
    )
    assert {
        row["evidence_id"]
        for row in dimension_coverage(captured, "documentation")["analysis_limits"]
    } == {"docs"}
    assert {
        row["evidence_id"] for row in dimension_coverage(captured, "operability")["analysis_limits"]
    } == {"controls"}
    assert dimension_coverage(captured, "performance")["analysis_limits"] == []
    assert dimension_coverage(captured, "operability")["collection_blockers"] == []


def test_missing_source_and_review_gaps_create_follow_up_without_default_medium():
    captured = snapshot([])
    missing = build_review_plan(captured)
    assert all(pack["status"] == "missing_source" for pack in missing["dimensions"].values())
    review = {
        "ratings": {"documentation": {"confidence": "medium", "burden_confidence": "low"}},
        "coverage": {"dimension_reviews": {"documentation": {"status": "reviewed"}}},
    }
    result = build_review_plan(
        snapshot([source("README.md", "guide", kind="documentation")]),
        review,
        dimension="documentation",
    )
    assert result["dimensions"]["documentation"]["needs_follow_up"]
    assert review["ratings"]["documentation"]["burden_confidence"] == "low"


def test_history_context_keeps_only_actual_selected_path_observations_and_original_limits():
    revision = "a" * 40
    entries = [
        source("src/a/provider.py", "provider"),
        source("src/b/contracts.py", "contract"),
        source("src/c/other.py", "other"),
    ]
    history = {
        "id": "history",
        "kind": "change-history",
        "stats": {
            "status": "partial",
            "source_revision": revision,
            "head_observed": revision,
            "coverage": {"shallow": True, "boundary_commits_omitted": 1},
            "gaps": ["Shallow history"],
            "cochanges": [
                {"paths": [entries[0]["path"], entries[1]["path"]], "commits": 2},
                {"paths": [entries[0]["path"], "uncaptured.py"], "commits": 9},
            ],
            "commits": [
                {
                    "revision": "b" * 40,
                    "committed_at": "2026-10-31T12:00:00Z",
                    "paths": [entries[0]["path"], entries[1]["path"]],
                    "uncaptured_paths": 3,
                    "omitted_paths": 0,
                },
                {
                    "revision": revision,
                    "committed_at": "2026-11-01T12:00:00Z",
                    "paths": [],
                    "boundary_omitted": True,
                },
            ],
            "author": "must not retain",
            "message": "must not retain",
        },
    }
    captured = snapshot([*entries, history])
    captured["source"]["revision"] = revision
    pack = build_review_plan(captured, dimension="extensibility", limit=1)["dimensions"][
        "extensibility"
    ]
    context = pack["history_context"][0]
    assert context["evidence_id"] == "history" and "history" in pack["provider_evidence_ids"]
    assert context["coverage"]["shallow"] is True and context["gaps"] == ["Shallow history"]
    assert context["cochanges"] == [
        {
            "paths": [entries[0]["path"], entries[1]["path"]],
            "commits": 2,
            "source_evidence_ids": ["provider", "contract"],
            "relationship": "historical_cochange",
            "binding": "current_captured_path_names",
        }
    ]
    assert context["matching_commits"][0]["uncaptured_paths"] == 3
    assert len(context["matching_commits"]) == 1
    assert "must not retain" not in json.dumps(context)
    assert pack["connections"] == []
    history["stats"]["source_revision"] = "c" * 40
    mismatched = build_review_plan(captured, dimension="extensibility", limit=1)["dimensions"][
        "extensibility"
    ]["history_context"][0]
    assert mismatched["cochanges"] == [] and mismatched["matching_commits"] == []
    assert any("applicability" in gap for gap in mismatched["gaps"])


def test_complete_unrelated_history_does_not_become_dimension_change_evidence():
    captured = snapshot(
        [
            source("src/a/provider.py", "provider"),
            source("src/b/other.py", "other"),
            {
                "id": "history",
                "kind": "change-history",
                "stats": {
                    "status": "complete",
                    "source_revision": "a" * 40,
                    "head_observed": "a" * 40,
                    "cochanges": [{"paths": ["src/b/other.py"], "commits": 1}],
                    "commits": [],
                },
            },
        ]
    )
    captured["source"]["revision"] = "a" * 40
    pack = build_review_plan(captured, dimension="extensibility", limit=1)["dimensions"][
        "extensibility"
    ]
    assert pack["source_tasks"][0]["evidence_id"] == "provider"
    assert pack["history_context"] == []


def test_plans_are_deterministic_bounded_text_navigation_without_path_execution():
    path = "src/<script>$(touch never)</script>/recovery.py"
    entries = [
        source(path, "unsafe-text"),
        source("config/settings.toml", "config", kind="configuration"),
    ]
    entries += [source(f"src/area{i:02}/service.py", f"source-{i}") for i in range(100)]
    captured = snapshot(entries, analysis_profile="deep")
    before = deepcopy(captured)
    first = build_review_plan(captured, limit=3)
    second = build_review_plan({**captured, "evidence": entries[::-1]}, limit=3)
    assert first == second
    assert all(
        len(pack["source_tasks"]) <= 3 and len(pack["connections"]) <= 3
        for pack in first["dimensions"].values()
    )
    assert any(task["path"] == path for task in first["dimensions"]["operability"]["source_tasks"])
    assert all(
        task["operation"] == "source_context"
        for pack in first["dimensions"].values()
        for task in pack["source_tasks"]
    )
    assert len(json.dumps(first, allow_nan=False)) < 40000
    assert captured == before


@pytest.mark.parametrize("limit", [0, 33, True, "16"])
def test_invalid_bounds_are_rejected(limit):
    with pytest.raises(ValueError, match="between 1 and 32"):
        build_review_plan({}, limit=limit)


def test_unknown_dimensions_are_rejected():
    for function in (build_review_plan, dimension_coverage):
        with pytest.raises(ValueError, match="Unknown review-plan dimension"):
            function({}, dimension="overall")
