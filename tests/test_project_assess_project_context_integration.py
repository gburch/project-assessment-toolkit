from copy import deepcopy

import pytest

from project_assess.project_context import project_context_template
from project_assess.service import AssessmentService, ConflictError, markdown_report


@pytest.fixture
def contextual(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# Local helper\nA focused job for one owner.\n")
    (root / "app.py").write_text("def run(value):\n    return value.strip()\n")
    service = AssessmentService(tmp_path / "state")
    assessment = service.scan(root)
    evidence_id = next(row["id"] for row in assessment["evidence"] if row["kind"] == "python")
    review = service.review_template(assessment["id"])
    review["coverage"]["scope"] = "focused"
    context = project_context_template()
    context["current"].update(
        milestone="personal_utility",
        readiness="prototype",
        confidence="medium",
        rationale="One implemented local job; execution is unverified.",
        evidence_ids=[evidence_id],
    )
    context["intended"].update(
        milestone="personal_app",
        basis="user_stated",
        confidence="high",
        statement="Keep this a dependable personal application with low upkeep.",
        attribution="Owner in this request",
        evidence_ids=[],
    )
    context["alignment"].update(
        direction="rebalance",
        rationale="Strengthen the needed boundary while reducing edit friction.",
        priorities=[
            {
                "dimension": "maintainability",
                "direction": "simplify",
                "rationale": "Preserve a direct workflow before adding future scope.",
                "initiative_ids": ["workflow"],
            }
        ],
        deferred=["Commercial and marketplace machinery without a current requirement."],
    )
    review["project_context"] = context
    review["plan"] = {
        "schema_version": 1,
        "diagnosis": "A small current workflow with a personal destination.",
        "target_state": "Useful personal workflows with proportionate upkeep.",
        "initiatives": [
            {
                "id": "workflow",
                "title": "Keep the workflow direct",
                "priority": "high",
                "root_cause": "Speculative coordination would obstruct current value.",
                "scope": "One existing caller and its important failure behavior.",
                "dimension_impacts": {"maintainability": "Avoid unnecessary coordinated edits."},
                "evidence_ids": [evidence_id],
                "acceptance": ["The supported caller remains correct."],
                "burden_effect": "Retain low upkeep.",
                "depends_on": [],
                "first_slice": "Trace the current public caller.",
            }
        ],
    }
    return service, assessment, review


def test_context_roundtrip_drives_all_reports_without_changing_numeric_goals(contextual):
    service, assessment, review = contextual
    goals = service.set_targets(
        assessment["project_id"], profile="public-production", expected_revision=0
    )
    original = deepcopy(assessment)
    saved = service.submit_review(assessment["id"], review)
    report = service.get_report(assessment["id"])
    context = report["project_context"]
    assert context["current"]["milestone"] == "personal_utility"
    assert context["intended"]["basis"] == "user_stated"
    assert context["alignment"]["priorities"][0]["dimension"] == "maintainability"
    assert context["saved_goal_revision"] == goals["revision"]
    assert report["assessment"] == original and report["goals"] == goals
    assert saved["ratings"] == report["review"]["ratings"]
    assert service.overview(assessment["id"])["project_context"] == context
    assert service.evolve(assessment["id"])["goal_alignment"]["project_context"] == context
    assert service.doctor(assessment["id"])["goal_alignment"]["project_context"] == context
    rendered = markdown_report(report)
    assert "Personal utility" in rendered and "Personal application" in rendered
    assert "Direct workflow before adding future scope".lower() in rendered.lower()
    assert len(service.history(assessment["project_id"])["goals"]) == 1


@pytest.mark.parametrize("fault", ["foreign", "duplicate", "initiative", "attribution"])
def test_invalid_context_is_rejected_atomically(contextual, fault):
    service, assessment, review = contextual
    if fault == "foreign":
        review["project_context"]["current"]["evidence_ids"] = ["not-in-snapshot"]
    elif fault == "duplicate":
        review["project_context"]["alignment"]["priorities"] *= 2
    elif fault == "initiative":
        review["project_context"]["alignment"]["priorities"][0]["initiative_ids"] = ["absent"]
    else:
        review["project_context"]["intended"]["attribution"] = None
    before = service.history(assessment["project_id"])
    with pytest.raises(ValueError):
        service.submit_review(assessment["id"], review, request_id="bad-context")
    assert service.history(assessment["project_id"]) == before


def test_context_changes_bind_challenge_but_do_not_create_engineering_progress(contextual):
    service, assessment, review = contextual
    service.set_targets(assessment["project_id"], profile="local-experiment", expected_revision=0)
    first = service.submit_review(assessment["id"], review)
    packet = service.challenge_template(assessment["id"], review)
    assert "project_intent" not in packet and "targets" not in packet
    assert "prompting_intent" not in packet
    assert "project_context" in packet["rubric"]
    review["project_context"]["intended"]["statement"] = (
        "The owner clarified the intended personal scope."
    )
    assert (
        service.challenge_template(assessment["id"], review)["draft_digest"]
        != packet["draft_digest"]
    )
    second = service.submit_review(assessment["id"], review)
    assert first["id"] != second["id"]
    assert service.progress(assessment["project_id"])["engineering_progress_steps"] == 0
    assert len(service.history(assessment["project_id"])["goals"]) == 1


def test_context_cannot_be_transferred_to_a_stale_source_snapshot(contextual):
    service, assessment, review = contextual
    service.scan(assessment["source"]["root"])
    with pytest.raises(ConflictError, match="stale"):
        service.submit_review(assessment["id"], review)
