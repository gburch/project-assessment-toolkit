from copy import deepcopy

import pytest

from project_assess.confidence import burden_support_assessment
from project_assess.service import AssessmentService, ConflictError


@pytest.fixture
def estimate(tmp_path):
    root = tmp_path / "utility"
    root.mkdir()
    (root / "app.py").write_text(
        "from policy import allowed\ndef run(value):\n    return allowed(value)\n"
    )
    (root / "policy.py").write_text("def allowed(value):\n    return value is not None\n")
    (root / "README.md").write_text(
        "# Utility\nChange the policy in one place; the caller keeps the same interface.\n"
    )
    service = AssessmentService(tmp_path / "state", allowed_roots=[root])
    assessment = service.scan(root)
    ids = {entry["path"]: entry["id"] for entry in assessment["evidence"]}
    review = service.review_template(assessment["id"], mode="fresh")
    review["methodology"]["reviewer_id"] = "fixture-author"
    review["methodology"]["dimensions"]["maintainability"] = "reassessed"
    source_ids = [ids["app.py"], ids["policy.py"], ids["README.md"]]
    review["coverage"].update(
        examined=[{"area": "Complete utility change path", "evidence_ids": source_ids}],
        unexamined=[],
    )
    review["coverage"]["dimension_reviews"]["maintainability"] = {
        "status": "reviewed",
        "rationale": "Inspected the complete bounded utility and its supported change.",
        "evidence_ids": source_ids,
    }
    review["ratings"]["maintainability"].update(
        capability=2,
        burden=1,
        confidence="medium",
        burden_confidence="medium",
        burden_basis="source_estimate",
        rationale="One policy edit preserves the direct caller contract; estimated light upkeep, without measured change duration.",
        evidence_ids=source_ids,
        burden_support={
            "claim": "The demonstrated policy change has localized, light structural upkeep.",
            "scope": "project",
            "scope_description": "The complete small utility and its only supported policy workflow.",
            "observation_ids": [],
            "change_trace_ids": ["policy-change"],
            "representativeness": "The caller and policy are the full supported implementation.",
            "counterevidence": "The caller retains its interface; there is no second policy definition to synchronize.",
            "freshness": "All cited bytes belong to this captured snapshot.",
            "limitations": ["Actual duration and frequency are not measured."],
            "corroboration_ids": [ids["app.py"]],
            "counterevidence_ids": [ids["README.md"]],
        },
    )
    review["change_traces"] = [
        {
            "id": "policy-change",
            "title": "Change one policy without changing the caller",
            "steps": [
                {
                    "owner": "Policy",
                    "change": "Edit the supported rule.",
                    "activity": "edit",
                    "evidence_ids": [ids["policy.py"]],
                },
                {
                    "owner": "Caller",
                    "change": "Inspect the unchanged interface and direct call.",
                    "activity": "inspection",
                    "evidence_ids": [ids["app.py"]],
                },
            ],
            "cost": "One local rule edit plus checking the existing caller; an estimate, not timed effort.",
            "invariant": "The caller preserves the supported policy outcome.",
            "counterevidence": "No extra registration or generated update is needed in this fixture.",
            "gaps": ["No observed timing."],
        }
    ]
    return service, assessment, review


def bind(service, assessment, review):
    packet = service.challenge_template(assessment["id"], review)
    review["challenge"] = {
        "schema_version": 1,
        "status": "completed",
        "reviewer_id": "fixture-independent",
        "independence": "declared",
        "draft_digest": packet["draft_digest"],
        "summary": "Synthetic independent support declaration for validation, not an actual expert review.",
        "evidence_ids": review["ratings"]["maintainability"]["evidence_ids"],
        "burden_dimensions": ["maintainability"],
        "gaps": ["Timing and experience unobserved."],
        "items": [],
    }


def test_medium_source_estimate_can_be_supported_without_runtime_or_history(estimate):
    service, assessment, review = estimate
    bind(service, assessment, review)
    before = deepcopy(assessment)
    saved = service.submit_review(assessment["id"], review)
    report = service.get_report(assessment["id"])
    support = report["confidence_assessment"]["dimensions"]["maintainability"]["burden"]["support"]
    assert support["status"] == "structured_support_present_for_declared_scope"
    assert support["standard"] == "source-estimate-v1"
    assert support["readiness"]["matched_cost_evidence_ids"] == []
    assert saved["ratings"]["maintainability"]["burden_basis"] == "source_estimate"
    assert service.get_report(assessment["id"])["assessment"] == before
    assert report["goals"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "missing_support",
        "no_corrob",
        "no_contrary",
        "unreviewed_source",
        "unlabeled_step",
        "missing_trace",
        "partial_project",
    ],
)
def test_medium_estimate_requires_more_than_a_confidence_label(estimate, fault):
    service, assessment, review = estimate
    support = review["ratings"]["maintainability"]["burden_support"]
    if fault == "missing_support":
        review["ratings"]["maintainability"].pop("burden_support")
    elif fault == "no_corrob":
        support["corroboration_ids"] = []
    elif fault == "no_contrary":
        support["counterevidence_ids"] = []
    elif fault == "unreviewed_source":
        review["coverage"]["dimension_reviews"]["maintainability"]["evidence_ids"] = review[
            "ratings"
        ]["maintainability"]["evidence_ids"][:1]
    elif fault == "unlabeled_step":
        review["change_traces"][0]["steps"][0].pop("activity")
    elif fault == "missing_trace":
        support["change_trace_ids"] = []
    else:
        review["coverage"]["dimension_reviews"]["maintainability"]["status"] = "partial"
    bind(service, assessment, review)
    with pytest.raises(ValueError, match="Medium source-estimate confidence lacks support"):
        service.submit_review(assessment["id"], review)
    assert service.get_report(assessment["id"])["review"] is None


def test_estimate_challenge_is_exact_draft_bound_and_dimension_specific(estimate):
    service, assessment, review = estimate
    bind(service, assessment, review)
    review["challenge"]["burden_dimensions"] = ["documentation"]
    with pytest.raises(ValueError, match="Medium source-estimate confidence lacks support"):
        service.submit_review(assessment["id"], review)
    bind(service, assessment, review)
    review["ratings"]["maintainability"]["burden_support"]["claim"] += " Changed scope."
    with pytest.raises(ConflictError, match="stale"):
        service.submit_review(assessment["id"], review)


def test_partial_workflow_does_not_become_project_scope(estimate):
    service, assessment, review = estimate
    review["coverage"]["dimension_reviews"]["maintainability"]["status"] = "partial"
    review["ratings"]["maintainability"]["burden_support"]["scope"] = "workflow"
    bind(service, assessment, review)
    service.submit_review(assessment["id"], review)
    result = service.get_report(assessment["id"])["confidence_assessment"]["dimensions"][
        "maintainability"
    ]["burden"]
    assert result["support"]["scope"] == "workflow"
    assert any("workflow only" in text for text in result["blockers"])
    assert any("breadth is partial" in text for text in result["blockers"])


def test_legacy_medium_estimate_is_not_reinterpreted_as_supported(estimate):
    service, assessment, review = estimate
    review["methodology"].pop("confidence_standard")
    review["ratings"]["maintainability"].pop("burden_support")
    bind(service, assessment, review)
    service.submit_review(assessment["id"], review)
    support = burden_support_assessment(assessment, review, "maintainability")
    assert support["status"] == "not_requested"


def test_new_support_fields_are_checked_even_without_template_flag(estimate):
    service, assessment, review = estimate
    review["methodology"].pop("confidence_standard")
    review["ratings"]["maintainability"]["burden_support"]["counterevidence_ids"] = []
    bind(service, assessment, review)
    with pytest.raises(ValueError, match="Medium source-estimate confidence lacks support"):
        service.submit_review(assessment["id"], review)


def test_source_estimate_cannot_claim_high_confidence_as_observed(estimate):
    service, assessment, review = estimate
    review["ratings"]["maintainability"]["burden_confidence"] = "high"
    bind(service, assessment, review)
    with pytest.raises(ValueError, match="High burden confidence lacks support"):
        service.submit_review(assessment["id"], review)
