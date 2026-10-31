"""A public synthetic acceptance case for a broad first-pass diagnosis."""

from project_assess import collector
from project_assess.service import AssessmentService


def test_initial_handoff_retains_large_core_risks_under_noise_and_collection_budgets(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    for folder in ("src/product", "tests", ".agents"):
        (root / folder).mkdir(parents=True)
    body = (
        "    total = 0\n"
        + "".join(f"    if value > {number}:\n        total += 1\n" for number in range(11))
        + "    for path in paths:\n        total += len(path.read_text())\n"
        + "    return total\n    unreachable = 1\n"
    )
    core_sizes = 0
    for name, peer in (("core", "peer"), ("peer", "core")):
        text = (
            "# captured large core context\n" * 1500
            + f"from . import {peer}\nimport sqlite3\n"
            + f"def evaluate_{name}(value, paths):\n"
            + body
            + "".join(
                f"def helper_{number}(value):\n    return value + {number}\n"
                for number in range(50)
            )
        )
        core_sizes += len(text.encode())
        (root / f"src/product/{name}.py").write_text(text)
    noise = "".join(
        f'@pytest.mark.parametrize("value", [1, 2])\ndef test_noise_{number}(value):\n'
        + body.replace("paths", "[]")
        for number in range(20)
    )
    for number in range(12):
        (root / f"tests/test_noise_{number:02}.py").write_text(noise)
        (root / f".agents/noise_{number:02}.py").write_text(noise)
    # Deliberately allow both large product modules and only a small portion of
    # the abundant noise. Function detail is independently constrained.
    monkeypatch.setattr(collector, "MAX_TOTAL_BYTES", core_sizes + 2 * len(noise.encode()) + 100)
    monkeypatch.setattr(collector, "MAX_STATIC_SYMBOLS", 12)
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    history = service.history(snapshot["project_id"])
    handoff = service.overview(snapshot["id"])
    assert not handoff["complete"] and handoff["gap_count"]
    coverage = handoff["static_analysis"]["coverage"]
    assert coverage["functions_total"] == coverage["functions_analyzed"]
    assert coverage["functions_total"] > coverage["pattern_functions"]
    assert handoff["planning_status"]["status"] == "no_review"
    assert handoff["planning_status"]["gap_status"] == "no_goals"
    collection = snapshot["facts"]["collection"]
    assert collection["skipped_by_role"]["tooling"] == 12
    assert collection["skipped_by_role"]["test"] > 0
    graph = service.query_evidence(
        snapshot["id"], view="graph", role="production", kind="static-analysis"
    )
    modules = [row for row in graph["items"] if row["record_type"] == "module"]
    assert {row["path"] for row in modules} == {"src/product/core.py", "src/product/peer.py"}
    assert all(
        row["lines"] > 1500 and row["pattern_functions"] < row["function_count"] for row in modules
    )
    clones = service.query_evidence(
        snapshot["id"], view="candidates", candidate_kind="duplicate_function", role="production"
    )
    assert clones["items"] and {
        location["path"] for location in clones["items"][0]["locations"]
    } == {"src/product/core.py", "src/product/peer.py"}
    diagnosis = service.doctor(snapshot["id"], limit=12)
    leads = [row for group in diagnosis["groups"].values() for row in group]
    assert {row["family"] for row in leads} >= {"python_ast", "tests", "ecosystem", "dead_code"}
    assert any(
        row["kind"] == "complex_function"
        and any(location["path"].startswith("src/") for location in row["locations"])
        for row in leads
    )
    assert diagnosis["selection"]["omitted"] > 0 and diagnosis["status"] == "partial"
    assert (
        diagnosis["analysis_scope"]["candidate_counts"]["total"]
        >= diagnosis["analysis_scope"]["candidate_counts"]["retained"]
    )
    snippet = service.query_evidence(
        snapshot["id"], view="snippets", path="src/product/core.py", line=1503
    )
    assert snippet["items"] and any("evaluate_core" in row["excerpt"] for row in snippet["items"])
    assert service.history(snapshot["project_id"]) == history


def test_compact_handoff_distinguishes_comparable_goals_from_missing_diagnosis(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    review = service.review_template(snapshot["id"])
    for rating in review["ratings"].values():
        rating.update(
            capability=3,
            burden=2,
            confidence="medium",
            rationale="Synthetic source-backed review.",
            evidence_ids=[snapshot["evidence"][0]["id"]],
        )
    service.submit_review(snapshot["id"], review)
    service.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)
    history = service.history(snapshot["project_id"])
    handoff = service.overview(snapshot["id"])
    alignment = service.evolve(snapshot["id"])["goal_alignment"]
    assert handoff["planning_status"]["gap_status"] == alignment["status"] == "ready"
    assert handoff["planning_status"]["status"] == alignment["planning_status"] == "missing_plan"
    assert service.history(snapshot["project_id"]) == history
