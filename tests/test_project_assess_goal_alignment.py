import json
import sqlite3
from copy import deepcopy

import pytest

from project_assess.rubric import DIMENSIONS, rubric
from project_assess.service import AssessmentService, markdown_report


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("def add(a, b):\n    return a + b\n")
    service = AssessmentService(tmp_path / "state")
    return service, root, service.scan(root)


def save_review(service, snapshot, scores=None, *, capability=3, burden=1):
    review = service.review_template(snapshot["id"])
    evidence_id = next(row["id"] for row in snapshot["evidence"] if row["path"] == "app.py")
    for dimension, rating in review["ratings"].items():
        cap, cost = (scores or {}).get(dimension, (capability, burden))
        rating.update(
            capability=cap,
            burden=cost,
            confidence="medium",
            burden_basis="source_estimate",
            burden_confidence="low",
            rationale="A fixture judgment cites the captured implementation, not an automatic grade.",
            evidence_ids=[evidence_id],
        )
    return service.submit_review(snapshot["id"], review)


def save_goals(service, snapshot, *, capability=3, burden=2, revision=0):
    targets = {
        dimension: {"capability_min": capability, "burden_max": burden} for dimension in DIMENSIONS
    }
    return service.set_targets(snapshot["project_id"], targets, expected_revision=revision)


def rows(service):
    with sqlite3.connect(service.db_path) as db:
        return {
            table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in ("projects", "assessments", "reviews", "goals", "requests")
        }


def test_evolve_without_goals_invites_explicit_selection_without_creating_them(project):
    service, root, snapshot = project
    review = save_review(service, snapshot)
    before, source = rows(service), (root / "app.py").read_bytes()

    result = service.evolve(snapshot["id"])
    alignment = result["goal_alignment"]

    assert result["assessment_id"] == snapshot["id"]
    assert result["source"] == snapshot["source"]
    assert alignment["status"] == "no_goals"
    assert alignment["goal_revision"] == 0 and alignment["review_id"] == review["id"]
    assert alignment["missing_targets"] == list(DIMENSIONS)
    assert all(
        item["action"] == "set_target"
        and item["capability_gap"] is None
        and item["burden_gap"] is None
        for item in alignment["dimensions"].values()
    )
    assert service.doctor(snapshot["id"])["goal_alignment"] == alignment
    assert rows(service) == before
    assert (root / "app.py").read_bytes() == source


def test_saved_goals_without_review_need_evidence_not_zero_scores(project):
    service, _, snapshot = project
    goals = save_goals(service, snapshot)
    before = rows(service)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["status"] == "needs_review"
    assert alignment["review_id"] is None
    assert alignment["goal_revision"] == goals["revision"]
    assert alignment["missing_targets"] == []
    for item in alignment["dimensions"].values():
        assert item["action"] == "inspect"
        assert item["current"] == {"capability": None, "burden": None}
        assert item["target"] == {"capability_min": 3, "burden_max": 2}
        assert item["capability_gap"] is None and item["burden_gap"] is None
        assert item["confidence"] is None and item["burden_basis"] == "unknown"
        assert item["evidence_ids"] == []
    assert rows(service) == before


def test_alignment_routes_independent_axes_without_penalizing_excess_capability(project):
    service, _, snapshot = project
    scores = {
        "security": (1, 1),
        "testing": (2, 4),
        "documentation": (4, 4),
        "maintainability": (5, 1),
        "delivery": (None, 4),
        "operability": (1, None),
        "extensibility": (1, 1),
    }
    review = save_review(service, snapshot, scores)
    save_goals(service, snapshot)
    before = rows(service)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["status"] == "needs_review"
    expected = {
        "security": (2, 0, "strengthen"),
        "testing": (1, 2, "rebalance"),
        "documentation": (0, 2, "simplify"),
        "maintainability": (0, 0, "maintain"),
        "delivery": (None, 2, "inspect"),
        "operability": (2, None, "inspect"),
        "extensibility": (2, 0, "strengthen"),
    }
    for dimension, (capability_gap, burden_gap, action) in expected.items():
        item = alignment["dimensions"][dimension]
        assert (item["capability_gap"], item["burden_gap"], item["action"]) == (
            capability_gap,
            burden_gap,
            action,
        )
        assert item["evidence_ids"] == review["ratings"][dimension]["evidence_ids"]
        for field in ("confidence", "burden_basis", "burden_confidence"):
            assert item[field] == review["ratings"][dimension][field]
        assert item["next_step"] and item["verification"]
    assert "upkeep" in alignment["dimensions"]["delivery"]["next_step"]
    assert "unknown" in alignment["dimensions"]["operability"]["next_step"]
    assert "safeguards" in alignment["dimensions"]["testing"]["next_step"]
    assert rows(service) == before


def test_strengthening_names_full_target_before_optional_first_milestone(project):
    service, _, snapshot = project
    save_review(service, snapshot, capability=1)
    save_goals(service, snapshot, capability=4)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["status"] == "ready"  # Ready advice does not mean goals are already met.
    anchors = rubric()["dimensions"]
    for dimension, item in alignment["dimensions"].items():
        assert item["action"] == "strengthen" and item["capability_gap"] == 3
        assert item["current"] == {"capability": 1, "burden": 1}
        assert item["target"] == {"capability_min": 4, "burden_max": 2}
        assert item["next_capability"] == 2
        assert item["target_capability"] == 4
        assert item["target_anchor"] == anchors[dimension]["capability"][4]
        assert anchors[dimension]["capability"][4] in item["next_step"]
        assert "system changes" in item["next_step"]
    assert len({item["verification"] for item in alignment["dimensions"].values()}) == 7


def test_framework_rebalance_plans_full_extension_goal_with_cost_constraint(project):
    service, _, snapshot = project
    save_review(service, snapshot, {"extensibility": (2, 3)})
    goals = service.set_targets(snapshot["project_id"], profile="framework", expected_revision=0)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    extension = alignment["dimensions"]["extensibility"]
    assert alignment["goal_revision"] == goals["revision"]
    assert extension["action"] == "rebalance"
    assert (extension["capability_gap"], extension["burden_gap"]) == (2, 1)
    assert extension["current"] == {"capability": 2, "burden": 3}
    assert extension["target"] == {"capability_min": 4, "burden_max": 2}
    assert extension["next_capability"] == 3
    anchors = rubric()["dimensions"]["extensibility"]["capability"]
    assert extension["target_capability"] == 4 and extension["target_anchor"] == anchors[4]
    assert anchors[4] in extension["next_step"]
    assert "tradeoff" in extension["next_step"]
    assert "variation" in extension["verification"] and "compatibility" in extension["verification"]


def test_historical_snapshot_uses_its_own_review_and_latest_selected_goals(project):
    service, root, previous = project
    previous_review = save_review(service, previous, capability=1)
    save_goals(service, previous)
    (root / "app.py").write_text("def add(a, b):\n    return a + b + 1\n")
    current = service.scan(root)
    current_review = save_review(service, current, capability=5)
    goals = save_goals(service, current, capability=4, revision=1)
    before = rows(service)

    old = service.evolve(previous["id"])["goal_alignment"]
    new = service.evolve(current["id"])["goal_alignment"]

    assert old["goal_revision"] == new["goal_revision"] == goals["revision"]
    assert old["review_id"] == previous_review["id"]
    assert new["review_id"] == current_review["id"]
    assert all(
        item["capability_gap"] == 3 and item["action"] == "strengthen"
        for item in old["dimensions"].values()
    )
    assert all(item["action"] == "maintain" for item in new["dimensions"].values())
    assert service.doctor(previous["id"])["goal_alignment"] == old
    assert rows(service) == before


@pytest.mark.parametrize("old_record", ["assessments", "reviews"])
def test_prior_rubric_never_produces_current_rubric_change_advice(project, old_record):
    service, _, snapshot = project
    save_review(service, snapshot, capability=1, burden=4)
    save_goals(service, snapshot)
    with sqlite3.connect(service.db_path) as db:
        row_id, raw = db.execute(f"SELECT rowid,data FROM {old_record}").fetchone()
        document = json.loads(raw)
        document["rubric_version"] = "3"
        db.execute(f"UPDATE {old_record} SET data=? WHERE rowid=?", (json.dumps(document), row_id))
    before = rows(service)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["status"] == "not_comparable"
    assert all(
        item["action"] == "inspect"
        and item["capability_gap"] is None
        and item["burden_gap"] is None
        for item in alignment["dimensions"].values()
    )
    assert rows(service) == before


def test_current_review_with_full_targets_from_prior_rubric_needs_explicit_confirmation(project):
    service, root, old = project
    save_review(service, old)
    save_goals(service, old)
    with sqlite3.connect(service.db_path) as db:
        prior = deepcopy(old)
        prior["rubric_version"] = "3"
        db.execute("UPDATE assessments SET data=? WHERE id=?", (json.dumps(prior), old["id"]))
    (root / "app.py").write_text("def add(a, b):\n    return a + b + 1\n")
    current = service.scan(root)
    save_review(service, current, capability=1)
    before = rows(service)

    alignment = service.evolve(current["id"])["goal_alignment"]

    assert alignment["status"] == "not_comparable" and alignment["missing_targets"] == []
    assert all(
        item["action"] == "inspect"
        and item["capability_gap"] is None
        and item["burden_gap"] is None
        and item["next_capability"] is None
        for item in alignment["dimensions"].values()
    )
    assert service.doctor(current["id"])["goal_alignment"] == alignment
    assert rows(service) == before


@pytest.mark.parametrize("baseline_id", [None, "a_missing"])
def test_missing_legacy_goal_baseline_is_not_assumed_to_use_current_rubric(project, baseline_id):
    service, _, snapshot = project
    save_review(service, snapshot, capability=1)
    goals = save_goals(service, snapshot)
    goals["baseline_assessment_id"] = baseline_id
    with sqlite3.connect(service.db_path) as db:
        db.execute("UPDATE goals SET data=?", (json.dumps(goals),))
    before = rows(service)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["status"] == "not_comparable"
    assert all(item["action"] == "inspect" for item in alignment["dimensions"].values())
    assert rows(service) == before


def test_missing_legacy_target_requires_explicit_choice_without_mutating_history(project):
    service, _, snapshot = project
    save_review(service, snapshot, capability=1)
    goals = save_goals(service, snapshot)
    legacy = deepcopy(goals)
    legacy["targets"].pop("extensibility")
    with sqlite3.connect(service.db_path) as db:
        db.execute("UPDATE goals SET data=?", (json.dumps(legacy),))
    before = rows(service)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["status"] == "not_comparable"
    assert alignment["missing_targets"] == ["extensibility"]
    extension = alignment["dimensions"]["extensibility"]
    assert extension["action"] == "set_target"
    assert extension["target"] == {"capability_min": None, "burden_max": None}
    assert extension["capability_gap"] is None and extension["burden_gap"] is None
    assert alignment["dimensions"]["testing"]["action"] == "strengthen"
    assert service.history(snapshot["project_id"])["goals"] == [legacy]
    assert rows(service) == before


def test_projects_keep_independent_selected_targets_and_zero_does_not_force_extensions(
    project, tmp_path
):
    service, _, first = project
    save_review(service, first, capability=0, burden=0)
    low = save_goals(service, first, capability=0, burden=1)
    other_root = tmp_path / "framework"
    other_root.mkdir()
    (other_root / "app.py").write_text("def extension(value):\n    return value\n")
    second = service.scan(other_root)
    save_review(service, second, capability=0, burden=0)
    high = service.set_targets(second["project_id"], profile="framework", expected_revision=0)

    first_alignment = service.evolve(first["id"])["goal_alignment"]
    second_alignment = service.evolve(second["id"])["goal_alignment"]

    assert first_alignment["dimensions"]["extensibility"]["action"] == "maintain"
    assert second_alignment["dimensions"]["extensibility"]["action"] == "strengthen"
    assert second_alignment["dimensions"]["extensibility"]["capability_gap"] == 4
    assert service.history(first["project_id"])["goals"] == [low]
    assert service.history(second["project_id"])["goals"] == [high]


def test_evolve_rechecks_source_and_import_authority_before_returning_saved_advice(tmp_path):
    allowed, revoked = tmp_path / "allowed", tmp_path / "revoked"
    allowed.mkdir()
    revoked.mkdir()
    (allowed / "app.py").write_text("value = 1\n")
    (revoked / "app.py").write_text("value = 2\n")
    imported = revoked / "junit.xml"
    imported.write_text('<testsuite tests="1"><testcase name="captured"/></testsuite>')
    owner = AssessmentService(tmp_path / "state")
    forbidden_root = owner.scan(revoked)
    forbidden_import = owner.scan(allowed, [imported])
    save_review(owner, forbidden_import)
    save_goals(owner, forbidden_import)
    clean = owner.scan(allowed)
    save_review(owner, clean)
    restricted = AssessmentService(owner.state_dir, [allowed])
    before = rows(owner)

    # A clean current scan also retains the authorization boundary of the
    # imported snapshot used as the saved goal's rubric baseline.
    for snapshot in (forbidden_root, forbidden_import, clean):
        with pytest.raises(PermissionError):
            restricted.evolve(snapshot["id"])
    assert rows(owner) == before


def review_with_plan(service, snapshot, goals=None):
    """Synthetic authored roadmap; fixtures do not establish automatic grades."""
    review = service.review_template(snapshot["id"])
    evidence_id = next(row["id"] for row in snapshot["evidence"] if row["path"] == "app.py")
    for rating in review["ratings"].values():
        rating.update(
            capability=3,
            burden=1,
            rationale="Synthetic inspected behavior, with source-estimated upkeep.",
            recommendations=["Trace the shared change path before adding more independent checks."],
            evidence_ids=[evidence_id],
        )
    review["coverage"] = {
        "schema_version": 1,
        "scope": "whole_project",
        "examined": [
            {"area": "Public computation and shared callers", "evidence_ids": [evidence_id]}
        ],
        "unexamined": [
            {"area": "Production recovery", "reason": "No deployment evidence supplied."}
        ],
        "limitations": ["Source review only; runtime effectiveness remains unverified."],
        "validation": [
            {"check": "Full application suite", "status": "not_run", "evidence_ids": []}
        ],
    }
    review["plan"] = {
        "schema_version": 1,
        "diagnosis": "Repeated lifecycle ownership couples valuable changes across boundaries.",
        "target_state": "One clear lifecycle owner with tested public behavior and documented recovery.",
        "initiatives": [
            {
                "id": "lifecycle",
                "title": "Consolidate lifecycle ownership",
                "priority": "high",
                "root_cause": "Lifecycle responsibility is duplicated across boundary implementations.",
                "scope": "All affected entry points, durable state transitions and recovery callers.",
                "dimension_impacts": {
                    "maintainability": "Reduce coordinated edits without removing authority checks.",
                    "testing": "Exercise shared public outcomes rather than private call sequences.",
                },
                "evidence_ids": [evidence_id],
                "acceptance": [
                    "Required callers retain authorization, error and recovery behavior."
                ],
                "burden_effect": "Replace duplicate upkeep with one responsibility; no new framework.",
                "depends_on": [],
                "first_slice": "Move one lifecycle path and demonstrate its public contract.",
            },
            {
                "id": "recovery",
                "title": "Verify recovery guidance",
                "priority": "medium",
                "root_cause": "Recovery guidance and actual ownership can diverge.",
                "scope": "Operator recovery through every supported lifecycle entry point.",
                "dimension_impacts": {
                    "documentation": "Make the supported recovery task reliable."
                },
                "evidence_ids": [evidence_id],
                "acceptance": ["A reader follows source-matched recovery guidance successfully."],
                "burden_effect": "Maintain one canonical recovery explanation.",
                "depends_on": ["lifecycle"],
                "first_slice": "Trace the recovery task against the consolidated lifecycle.",
            },
        ],
    }
    if goals:
        review["plan"]["goal_revision"] = goals["revision"]
    return review


def test_markdown_report_preserves_full_roadmap_before_first_slice_and_review_limits(project):
    service, _, snapshot = project
    goals = save_goals(service, snapshot)
    review = review_with_plan(service, snapshot, goals)
    review["plan"]["diagnosis"] += " <script>unsafe()</script>"
    service.submit_review(snapshot["id"], review)
    text = markdown_report(service.get_report(snapshot["id"]))
    assert "Unexamined: Production recovery" in text
    assert "Full application suite: not\\_run" in text
    assert "&lt;script&gt;unsafe()&lt;/script&gt;" in text
    assert "<script>" not in text
    assert text.index("Full scope: All affected entry points") < text.index(
        "First implementation slice:"
    )
    assert "Acceptance:" in text and "Burden effect:" in text and "Dependencies: lifecycle" in text


def test_evolve_preserves_whole_project_plan_coverage_and_urgent_findings_when_goals_met(project):
    service, root, snapshot = project
    goals = save_goals(service, snapshot)
    review = review_with_plan(service, snapshot, goals)
    evidence_id = review["ratings"]["testing"]["evidence_ids"][0]
    review["findings"] = [
        {
            "severity": "critical",
            "title": "Synthetic critical boundary issue",
            "evidence_ids": [evidence_id],
        },
        {
            "severity": "high",
            "title": "Synthetic high recovery issue",
            "evidence_ids": [evidence_id],
        },
        {"severity": "low", "title": "Synthetic minor issue", "evidence_ids": [evidence_id]},
    ]
    saved = service.submit_review(snapshot["id"], review)
    before, source = rows(service), (root / "app.py").read_bytes()

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["planning_status"] == "ready"
    assert alignment["review_id"] == saved["id"]
    assert all(item["action"] == "maintain" for item in alignment["dimensions"].values())
    assert alignment["coverage"] == review["coverage"]
    assert alignment["plan"] == review["plan"]
    assert alignment["findings"] == review["findings"]
    assert alignment["urgent_findings"] == review["findings"][:2]
    for dimension, rating in review["ratings"].items():
        assert alignment["dimensions"][dimension]["rationale"] == rating["rationale"]
        assert alignment["dimensions"][dimension]["recommendations"] == rating["recommendations"]
    assert service.doctor(snapshot["id"])["goal_alignment"] == alignment
    assert service.get_report(snapshot["id"])["goal_alignment"] == alignment
    assert rows(service) == before and (root / "app.py").read_bytes() == source


def test_proposed_target_scenario_does_not_select_goals_or_turn_unknown_into_zero(project):
    service, _, snapshot = project
    review = review_with_plan(service, snapshot)
    review["ratings"]["testing"]["capability"] = None
    scenario = {dim: {"capability_min": 4, "burden_max": 2} for dim in DIMENSIONS}
    review["plan"]["assumed_targets"] = scenario
    service.submit_review(snapshot["id"], review)
    before = rows(service)

    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["status"] == "no_goals"
    assert alignment["planning_status"] == "scenario_unconfirmed"
    assert alignment["plan"]["assumed_targets"] == scenario
    assert alignment["dimensions"]["testing"]["current"]["capability"] is None
    assert alignment["dimensions"]["testing"]["target_capability"] is None
    assert alignment["dimensions"]["testing"]["capability_gap"] is None
    assert service.history(snapshot["project_id"])["goals"] == []
    assert rows(service) == before


@pytest.mark.parametrize("binding", ["goal_revision", "assumed_targets"])
def test_authored_plan_binding_expires_after_goal_change_without_rewriting_review(project, binding):
    service, _, snapshot = project
    goals = save_goals(service, snapshot)
    review = review_with_plan(service, snapshot)
    review["plan"][binding] = goals["revision"] if binding == "goal_revision" else goals["targets"]
    saved = service.submit_review(snapshot["id"], review)
    assert service.evolve(snapshot["id"])["goal_alignment"]["planning_status"] == "ready"

    save_goals(service, snapshot, capability=4, revision=1)
    before = rows(service)
    alignment = service.evolve(snapshot["id"])["goal_alignment"]

    assert alignment["planning_status"] == "targets_changed"
    assert alignment["plan"] == review["plan"]
    assert alignment["review_id"] == saved["id"]
    assert alignment["dimensions"]["testing"]["target_capability"] == 4
    assert rows(service) == before


def test_legacy_review_has_no_fabricated_roadmap_and_plan_without_binding_stays_unconfirmed(
    project,
):
    service, _, snapshot = project
    goals = save_goals(service, snapshot)
    legacy = review_with_plan(service, snapshot)
    legacy.pop("coverage")
    legacy.pop("plan")
    service.submit_review(snapshot["id"], legacy)
    alignment = service.evolve(snapshot["id"])["goal_alignment"]
    assert alignment["coverage"] is None and alignment["plan"] is None
    assert alignment["planning_status"] == "missing_plan"

    authored = review_with_plan(service, snapshot)
    service.submit_review(snapshot["id"], authored)
    assert (
        service.evolve(snapshot["id"])["goal_alignment"]["planning_status"]
        == "scenario_unconfirmed"
    )
    assert service.history(snapshot["project_id"])["goals"] == [goals]


@pytest.mark.parametrize(
    "invalid",
    [
        "coverage_citation",
        "validation_citation",
        "initiative_citation",
        "duplicate_id",
        "missing_dependency",
        "cycle",
    ],
)
def test_invalid_planning_never_partially_saves_review(project, invalid):
    service, _, snapshot = project
    review = review_with_plan(service, snapshot)
    if invalid == "coverage_citation":
        review["coverage"]["examined"][0]["evidence_ids"] = ["e_foreign"]
    elif invalid == "validation_citation":
        review["coverage"]["validation"][0]["status"] = "passed"
    elif invalid == "initiative_citation":
        review["plan"]["initiatives"][0]["evidence_ids"] = ["e_foreign"]
    elif invalid == "duplicate_id":
        review["plan"]["initiatives"][1]["id"] = "lifecycle"
    elif invalid == "missing_dependency":
        review["plan"]["initiatives"][0]["depends_on"] = ["missing"]
    else:
        review["plan"]["initiatives"][0]["depends_on"] = ["recovery"]
    before = rows(service)
    with pytest.raises(ValueError):
        service.submit_review(snapshot["id"], review)
    assert rows(service) == before
