"""High burden confidence needs scoped corroboration, not stronger labels."""

import json
import sqlite3
from copy import deepcopy
from pathlib import Path

import pytest

from project_assess.confidence import burden_support_assessment, confidence_assessment
from project_assess.rubric import DIMENSIONS
from project_assess.service import AssessmentService, ConflictError, _draft_digest


def supported():
    assessment = {
        "id": "assessment",
        "complete": True,
        "source": {"revision": "a" * 40, "manifest_digest": "sha256:current"},
        "scope_digest": "scope",
        "rubric_version": "5",
        "evidence": [
            {"id": "source", "kind": "python", "path": "src/service.py"},
            {
                "id": "experience",
                "kind": "burden-context",
                "stats": {
                    "attribution": {"role": "maintainer", "label": "Project maintainer"},
                    "period": {"start": "2026-10-01", "end": None},
                    "scope": {"label": "Ordinary testing changes", "paths": ["src/service.py"]},
                    "claims": [
                        {
                            "index": 0,
                            "dimensions": ["testing"],
                            "statement": "Required feedback repeatedly blocks ordinary changes.",
                            "frequency": "most_changes",
                            "frequency_scope": "joint_claim",
                            "workflow_stage": "required_gate",
                            "completion": "unknown",
                            "examples": [],
                        }
                    ],
                    "sourceIdentity": {"overall": "unverified"},
                },
            },
        ],
    }
    review = {
        "ratings": {
            dimension: {
                "capability": 2,
                "burden": None,
                "confidence": "medium",
                "burden_confidence": "low",
                "burden_basis": "unknown",
                "evidence_ids": [],
            }
            for dimension in DIMENSIONS
        },
        "coverage": {
            "scope": "whole_project",
            "dimension_reviews": {dimension: {"status": "reviewed"} for dimension in DIMENSIONS},
        },
        "methodology": {"reviewer_id": "author"},
        "change_traces": [
            {
                "id": "ordinary-change",
                "steps": [{"evidence_ids": ["source"]}],
            }
        ],
        "challenge": {
            "status": "completed",
            "reviewer_id": "challenger",
            "burden_dimensions": ["testing"],
        },
    }
    review["ratings"]["testing"].update(
        burden=3,
        burden_basis="observed",
        burden_confidence="high",
        evidence_ids=["source", "experience"],
        burden_support={
            "claim": "Ordinary testing changes incur experienced blocking feedback.",
            "scope": "project",
            "scope_description": "Testing upkeep for ordinary changes in the current project.",
            "observation_ids": ["experience"],
            "change_trace_ids": ["ordinary-change"],
            "representativeness": "The maintainer describes the normal change path, corroborated by the traced gate.",
            "counterevidence": "Focused checks can be fast; the completion gate still applies.",
            "freshness": "The recent experience remains applicable to the captured gate and source trace.",
            "limitations": ["No independent run duration was measured."],
        },
    )
    bind(assessment, review)
    return assessment, review


def bind(assessment, review):
    review["challenge"]["draft_digest"] = _draft_digest(assessment, review)


def support(assessment, review):
    return burden_support_assessment(assessment, review, "testing")


def test_attributed_experience_can_support_high_without_stopwatch_or_authenticated_identity():
    assessment, review = supported()
    original = deepcopy(review)
    result = support(assessment, review)
    assert result["status"] == "structured_support_present_for_declared_scope"
    assert result["gaps"] == [] and result["scope"] == "project"
    assert review == original
    projection = confidence_assessment(assessment, review)["dimensions"]
    assert projection["testing"]["burden"]["support"] == result
    assert projection["testing"]["capability"]["declared_confidence"] == "medium"
    assert projection["security"]["burden"]["support"]["status"] == "not_requested"


@pytest.mark.parametrize(
    "fault",
    [
        "missing_support",
        "estimated",
        "unscored",
        "missing_period",
        "joint_claim",
        "unreviewed",
        "partial_project",
        "uncited_observation",
        "foreign_observation",
        "foreign_trace",
        "uncaptured_trace",
        "unrelated_scope",
        "missing_representativeness",
        "missing_counterevidence",
        "missing_freshness",
        "uncovered_challenge",
        "same_reviewer",
        "stale_challenge",
    ],
)
def test_unsupported_high_claims_are_withheld_without_rewriting_grades(fault):
    assessment, review = supported()
    rating = review["ratings"]["testing"]
    context = assessment["evidence"][1]["stats"]
    claim = rating["burden_support"]
    if fault == "missing_support":
        del rating["burden_support"]
    elif fault == "estimated":
        rating["burden_basis"] = "source_estimate"
    elif fault == "unscored":
        rating["burden"] = None
    elif fault == "missing_period":
        context["period"] = {"start": None, "end": None}
    elif fault == "joint_claim":
        context["claims"][0]["dimensions"].append("security")
        context["claims"][0]["statement"] = "Slow tests OR security rework occur on most changes."
    elif fault == "unreviewed":
        review["coverage"]["dimension_reviews"]["testing"]["status"] = "unreviewed"
    elif fault == "partial_project":
        assessment["complete"] = False
    elif fault == "uncited_observation":
        rating["evidence_ids"].remove("experience")
    elif fault == "foreign_observation":
        claim["observation_ids"] = ["other-snapshot"]
    elif fault == "foreign_trace":
        claim["change_trace_ids"] = ["other-trace"]
    elif fault == "uncaptured_trace":
        review["change_traces"][0]["steps"][0]["evidence_ids"] = ["experience"]
    elif fault == "unrelated_scope":
        context["scope"]["paths"] = ["unrelated/service.py"]
    elif fault.startswith("missing_"):
        claim[fault.removeprefix("missing_")] = " "
    elif fault == "uncovered_challenge":
        review["challenge"]["burden_dimensions"] = ["security"]
    elif fault == "same_reviewer":
        review["challenge"]["reviewer_id"] = "AUTHOR"
    if fault != "stale_challenge":
        bind(assessment, review)
    else:
        claim["freshness"] += " A changed applicability claim."
    original = deepcopy(review)
    result = support(assessment, review)
    assert result["status"] == "withheld" and result["gaps"]
    assert review == original
    assert rating["burden_confidence"] == "high"


@pytest.mark.parametrize("semantics", ["summed_test_elapsed", "cpu"])
def test_summed_testcase_or_cpu_time_does_not_establish_wall_clock_change_cost(semantics):
    assessment, review = supported()
    claim = assessment["evidence"][1]["stats"]["claims"][0]
    claim.update(
        duration={"seconds": 3600, "semantics": semantics, "precision": "reported_measurement"},
        completion="complete",
    )
    bind(assessment, review)
    assert support(assessment, review)["status"] == "withheld"


def test_partial_quantified_run_is_not_promoted_to_complete_gate_cost():
    assessment, review = supported()
    claim = assessment["evidence"][1]["stats"]["claims"][0]
    claim.update(
        duration={"seconds": 3600, "semantics": "wall_elapsed", "precision": "approximate"},
        completion="partial",
    )
    bind(assessment, review)
    result = support(assessment, review)
    assert result["status"] == "withheld"
    assert result["readiness"]["partial_elapsed_evidence_ids"] == ["experience"]
    assert result["readiness"]["experience_evidence_ids"] == []


@pytest.mark.parametrize("kind", ["junit", "observation", "burden-analysis"])
def test_report_counts_identity_and_unrelated_metrics_do_not_prove_upkeep(kind):
    assessment, review = supported()
    assessment["evidence"][1] = {
        "id": "experience",
        "kind": kind,
        "stats": {
            "type": "performance",
            "sourceIdentity": {"overall": "matched"},
            "seconds": 3600,
            "tests": 10000,
            "results": [
                {"name": "wall_elapsed", "value": 3600, "unit": "seconds", "status": "observed"}
            ],
        },
    }
    bind(assessment, review)
    assert support(assessment, review)["status"] == "withheld"


def test_source_matched_explicit_change_cost_can_corroborate_scoped_burden():
    assessment, review = supported()
    assessment["evidence"][1] = {
        "id": "experience",
        "kind": "observation",
        "stats": {
            "type": "change_cost",
            "sourceIdentity": {"overall": "matched"},
            "scenario": {"scope": ["src/service.py"]},
            "results": [
                {"name": "wall_elapsed", "value": 300, "unit": "seconds", "status": "observed"}
            ],
        },
    }
    review["ratings"]["testing"]["burden_support"]["scope"] = "workflow"
    bind(assessment, review)
    assert support(assessment, review)["status"] == "structured_support_present_for_declared_scope"


def test_workflow_support_retains_explicit_narrow_scope_and_history_limits():
    assessment, review = supported()
    assessment["complete"] = False
    assessment["evidence"][1]["stats"]["sourceIdentity"]["overall"] = "mismatch"
    review["coverage"]["scope"] = "focused"
    review["coverage"]["dimension_reviews"]["testing"]["status"] = "partial"
    claim = review["ratings"]["testing"]["burden_support"]
    claim["scope"] = "workflow"
    claim["scope_description"] = "Only the ordinary service-change completion path."
    claim["freshness"] = (
        "Historical experience remains applicable to the same captured gate; the source trace reconciles its current mechanism."
    )
    bind(assessment, review)
    result = support(assessment, review)
    assert result["status"] == "structured_support_present_for_declared_scope"
    assert result["scope"] == "workflow"


def test_legacy_high_remains_declared_but_is_not_supported_by_default():
    assessment, review = supported()
    del review["ratings"]["testing"]["burden_support"]
    del review["challenge"]["burden_dimensions"]
    result = confidence_assessment(assessment, review)["dimensions"]["testing"]["burden"]
    assert result["declared_confidence"] == "high"
    assert result["support"]["status"] == "withheld"
    assert result["support"]["gaps"]


@pytest.mark.parametrize("confidence", ["low", "medium"])
def test_every_confidence_exposes_evidence_and_actual_activity_categories(confidence):
    assessment, review = supported()
    rating = review["ratings"]["testing"]
    rating.update(burden_confidence=confidence, burden_basis="source_estimate")
    claim = assessment["evidence"][1]["stats"]["claims"][0]
    claim["dimensions"] = ["testing", "security"]
    trace = review["change_traces"][0]
    trace["steps"] = [
        {"activity": "inspection", "evidence_ids": ["source"]},
        {"activity": "verification", "evidence_ids": ["source"]},
        {"evidence_ids": ["source"]},
    ]
    bind(assessment, review)
    before = deepcopy(review)
    result = support(assessment, review)
    inventory = result["readiness"]
    assert result["status"] == "not_requested"
    assert inventory["source_evidence_ids"] == ["source"]
    assert inventory["experience_evidence_ids"] == []
    assert inventory["limited_report_evidence_ids"] == ["experience"]
    assert inventory["trace_activities"] == {
        "edit": 0,
        "verification": 1,
        "inspection": 1,
        "unknown": 1,
    }
    assert inventory["recurrence"] == "not_established"
    assert inventory["challenge"] == "bound_dimension_review"
    assert inventory["next_steps"]
    assert review == before and rating["burden_confidence"] == confidence


def cost_observation(
    identity="experience", timestamp="2026-11-01T12:00:00Z", path="src/service.py"
):
    return {
        "id": identity,
        "kind": "observation",
        "stats": {
            "type": "change_cost",
            "observed_at": timestamp,
            "sourceIdentity": {"overall": "matched"},
            "scenario": {"scope": [path]},
            "results": [
                {"name": "blocked_wait", "value": 300, "unit": "seconds", "status": "observed"}
            ],
        },
    }


def test_one_observed_workflow_is_not_recurring_project_burden():
    assessment, review = supported()
    assessment["evidence"][1] = cost_observation()
    bind(assessment, review)
    assert support(assessment, review)["status"] == "withheld"
    assert support(assessment, review)["readiness"]["recurrence"] == "not_established"
    review["ratings"]["testing"]["burden_support"]["scope"] = "workflow"
    bind(assessment, review)
    assert support(assessment, review)["status"] == "structured_support_present_for_declared_scope"


def test_repeated_costs_require_distinct_instants_and_relevant_trace_scope():
    assessment, review = supported()
    assessment["evidence"][1] = cost_observation()
    assessment["evidence"].append(cost_observation("second", "2026-11-01T13:00:00+01:00"))
    rating = review["ratings"]["testing"]
    rating["evidence_ids"].append("second")
    rating["burden_support"]["observation_ids"].append("second")
    bind(assessment, review)
    assert support(assessment, review)["status"] == "withheld"
    # A second timezone spelling of the same instant is not another observation.
    assert support(assessment, review)["readiness"]["recurrence"] == "not_established"
    assessment["evidence"][-1]["stats"]["observed_at"] = "2026-11-02T12:00:00Z"
    assessment["evidence"][-1]["stats"]["scenario"]["scope"] = ["src/unrelated.py"]
    assessment["evidence"].append(
        {"id": "other-source", "kind": "python", "path": "src/unrelated.py"}
    )
    bind(assessment, review)
    assert support(assessment, review)["status"] == "withheld"
    assert support(assessment, review)["readiness"]["recurrence"] == "not_established"
    assessment["evidence"][-2]["stats"]["scenario"]["scope"] = ["src/service.py"]
    bind(assessment, review)
    result = support(assessment, review)
    assert result["status"] == "structured_support_present_for_declared_scope"
    assert result["readiness"]["recurrence"] == "multiple_dated_observations"


def test_isolated_experience_is_not_project_recurrence():
    assessment, review = supported()
    assessment["evidence"][1]["stats"]["claims"][0]["frequency"] = "isolated"
    bind(assessment, review)
    assert support(assessment, review)["status"] == "withheld"
    review["ratings"]["testing"]["burden_support"]["scope"] = "workflow"
    bind(assessment, review)
    assert support(assessment, review)["status"] == "structured_support_present_for_declared_scope"


def test_workflow_high_support_does_not_clear_project_breadth_blockers():
    assessment, review = supported()
    assessment["complete"] = False
    review["coverage"]["scope"] = "focused"
    review["coverage"]["dimension_reviews"]["testing"]["status"] = "partial"
    review["ratings"]["testing"]["burden_support"]["scope"] = "workflow"
    bind(assessment, review)
    burden = confidence_assessment(assessment, review)["dimensions"]["testing"]["burden"]
    assert burden["support"]["status"] == "structured_support_present_for_declared_scope"
    assert any("breadth is partial" in blocker for blocker in burden["blockers"])
    assert any("Collection is partial" in blocker for blocker in burden["blockers"])


def test_activity_relabeling_invalidates_the_old_challenge():
    assessment, review = supported()
    assert support(assessment, review)["readiness"]["challenge"] == "bound_dimension_review"
    review["change_traces"][0]["steps"][0]["activity"] = "inspection"
    assert support(assessment, review)["readiness"]["challenge"] == "not_established"
    assert support(assessment, review)["status"] == "withheld"


def test_explicit_elapsed_lower_bound_is_retained_without_becoming_completed_cost():
    assessment, review = supported()
    assessment["evidence"][1] = cost_observation()
    assessment["evidence"][1]["stats"]["results"][0]["name"] = "wall_elapsed_lower_bound"
    review["ratings"]["testing"]["burden_support"]["scope"] = "workflow"
    bind(assessment, review)
    result = support(assessment, review)
    assert result["status"] == "withheld"
    assert result["readiness"]["partial_elapsed_evidence_ids"] == ["experience"]
    assert result["readiness"]["matched_cost_evidence_ids"] == []


def test_summed_partial_case_time_is_not_a_wall_time_lower_bound():
    assessment, review = supported()
    claim = assessment["evidence"][1]["stats"]["claims"][0]
    claim.update(
        completion="partial", duration={"seconds": 5000, "semantics": "summed_test_elapsed"}
    )
    bind(assessment, review)
    assert support(assessment, review)["readiness"]["partial_elapsed_evidence_ids"] == []


@pytest.fixture
def service_draft(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "service.py").write_text("def complete_change():\n    return True\n")
    context_path = tmp_path / "maintainer-context.json"
    context_path.write_text(
        json.dumps(
            {
                "schema": "pat.burden-context.v1",
                "reported_at": "2026-11-01T12:00:00-05:00",
                "attribution": {"role": "maintainer", "label": "Current project maintainer"},
                "period": {"start": "2026-10-01", "end": None},
                "source": {"revision": None, "files": []},
                "scope": {"label": "Ordinary service changes", "paths": ["src/service.py"]},
                "claims": [
                    {
                        "dimensions": ["testing"],
                        "statement": "Required feedback blocks ordinary testing changes.",
                        "frequency": "most_changes",
                        "workflow_stage": "required_gate",
                        "completion": "unknown",
                    }
                ],
                "limitations": ["Experienced upkeep; no independently timed test execution."],
            }
        )
    )
    service = AssessmentService(tmp_path / "state")
    assessment = service.scan(root, reports=[context_path])
    source_id = next(entry["id"] for entry in assessment["evidence"] if entry["kind"] == "python")
    context_id = next(
        entry["id"] for entry in assessment["evidence"] if entry["kind"] == "burden-context"
    )
    review = service.review_template(assessment["id"], mode="fresh")
    review["methodology"]["reviewer_id"] = "author"
    review["methodology"]["dimensions"]["testing"] = "reassessed"
    review["coverage"]["scope"] = "whole_project"
    review["coverage"]["dimension_reviews"]["testing"].update(
        status="reviewed",
        rationale="Inspected the ordinary change path and attributed experience.",
        evidence_ids=[source_id, context_id],
    )
    review["ratings"]["testing"].update(
        capability=2,
        burden=3,
        confidence="medium",
        burden_confidence="high",
        burden_basis="observed",
        rationale="Experienced testing upkeep is corroborated by the current change trace.",
        evidence_ids=[source_id, context_id],
        burden_support=deepcopy(supported()[1]["ratings"]["testing"]["burden_support"]),
    )
    review["ratings"]["testing"]["burden_support"]["observation_ids"] = [context_id]
    review["change_traces"] = [
        {
            "id": "ordinary-change",
            "title": "Complete an ordinary service change",
            "steps": [
                {
                    "owner": "src/service.py:complete_change",
                    "change": "Trace the implementation and required completion feedback.",
                    "evidence_ids": [source_id],
                }
            ],
            "cost": "Attributed repeated blocking feedback; exact duration unknown.",
            "invariant": "Required checks still protect the ordinary change.",
            "counterevidence": "A focused iteration can complete earlier.",
            "gaps": ["No independently measured wall-clock cost."],
        }
    ]
    return service, assessment, review


def complete_service_challenge(service, assessment, review):
    # These tests inspect the final gate on drafts the earlier gates would refuse.
    digest = service.check_review(assessment["id"], review)["draft_digest"]
    review["challenge"] = {
        "schema_version": 1,
        "status": "completed",
        "reviewer_id": "challenger",
        "independence": "declared",
        "draft_digest": digest,
        "summary": "Independently inspected the testing scope, source trace and experience limits.",
        "evidence_ids": review["ratings"]["testing"]["evidence_ids"],
        "burden_dimensions": ["testing"],
        "gaps": ["Experience and independence remain attributed declarations."],
        "items": [],
    }
    return {"draft_digest": digest}


def rows(service):
    with sqlite3.connect(service.db_path) as db:
        return tuple(
            db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("reviews", "requests")
        )


def test_service_prepares_high_draft_before_challenge_and_accepts_exact_final_support(
    service_draft,
):
    service, assessment, review = service_draft
    packet = service.challenge_template(assessment["id"], review)
    complete_service_challenge(service, assessment, review)
    assert packet["draft_digest"] == _draft_digest(assessment, review)
    assert rows(service) == (0, 0)
    saved = service.submit_review(assessment["id"], review, request_id="supported-high")
    assert saved["ratings"]["testing"]["burden_confidence"] == "high"
    result = service.get_report(assessment["id"])["confidence_assessment"]["dimensions"]["testing"]
    assert result["burden"]["support"]["status"] == "structured_support_present_for_declared_scope"
    assert result["capability"]["declared_confidence"] == "medium"
    assert rows(service) == (1, 1)


def test_burden_query_path_and_role_filters_preserve_applicable_attributed_scope(service_draft):
    service, assessment, _ = service_draft
    result = service.query_evidence(
        assessment["id"],
        view="burden",
        dimension="testing",
        path="src/service.py",
        role="production",
        max_chars=100000,
    )
    context = next(
        row for row in result["items"] if row.get("kind") == "attributed_change_experience"
    )
    assert context["scope"]["paths"] == ["src/service.py"]
    assert "locations" not in context and "line" not in context
    assert result["burden_scope"][0]["coverage"] is not None


@pytest.mark.parametrize("fault", ["missing", "stale", "same_reviewer", "uncovered", "joint_only"])
def test_service_rejects_unestablished_high_support_atomically(service_draft, fault):
    service, assessment, review = service_draft
    complete_service_challenge(service, assessment, review)
    if fault == "missing":
        del review["ratings"]["testing"]["burden_support"]
        complete_service_challenge(service, assessment, review)
    elif fault == "stale":
        review["ratings"]["testing"]["burden_support"]["claim"] += " A changed claim."
    elif fault == "same_reviewer":
        review["challenge"]["reviewer_id"] = "AUTHOR"
    elif fault == "uncovered":
        review["challenge"]["burden_dimensions"] = []
    else:
        # A new legitimate import retains joint frequency without turning an
        # OR claim into separate causal observations for each dimension.
        context_path = service.state_dir.parent / "maintainer-context.json"
        data = json.loads(context_path.read_text())
        data["claims"][0]["dimensions"] = ["testing", "security"]
        data["claims"][0]["statement"] = "Slow tests OR security rework on most changes."
        context_path.write_text(json.dumps(data))
        assessment = service.scan(Path(assessment["source"]["root"]), reports=[context_path])
        source_id = next(
            entry["id"] for entry in assessment["evidence"] if entry["kind"] == "python"
        )
        context_id = next(
            entry["id"] for entry in assessment["evidence"] if entry["kind"] == "burden-context"
        )
        review["assessment_id"] = assessment["id"]
        review["source_digest"] = assessment["source"]["manifest_digest"]
        review["ratings"]["testing"]["evidence_ids"] = [source_id, context_id]
        review["ratings"]["testing"]["burden_support"]["observation_ids"] = [context_id]
        review["coverage"]["dimension_reviews"]["testing"]["evidence_ids"] = [
            source_id,
            context_id,
        ]
        review["change_traces"][0]["steps"][0]["evidence_ids"] = [source_id]
        complete_service_challenge(service, assessment, review)
    with pytest.raises((ValueError, ConflictError)):
        service.submit_review(assessment["id"], review, request_id="invalid-high")
    assert rows(service) == (0, 0)


@pytest.mark.parametrize(
    "fault", ["foreign_observation", "uncited_observation", "foreign_trace", "malformed_trace"]
)
def test_service_rejects_invalid_support_references_before_writes(service_draft, fault):
    service, assessment, review = service_draft
    support = review["ratings"]["testing"]["burden_support"]
    if fault == "foreign_observation":
        support["observation_ids"] = ["foreign"]
    elif fault == "uncited_observation":
        review["ratings"]["testing"]["evidence_ids"] = [
            review["change_traces"][0]["steps"][0]["evidence_ids"][0]
        ]
    elif fault == "foreign_trace":
        support["change_trace_ids"] = ["foreign"]
    else:
        support["change_trace_ids"] = ["../../outside"]
    with pytest.raises(ValueError):
        if fault == "uncited_observation":
            complete_service_challenge(service, assessment, review)
            service.submit_review(assessment["id"], review, request_id="invalid-reference")
        else:
            service.challenge_template(assessment["id"], review)
    assert rows(service) == (0, 0)


def test_legacy_stored_high_is_readable_and_withheld_without_history_rewrite(service_draft):
    service, assessment, review = service_draft
    review["ratings"]["testing"]["burden_confidence"] = "low"
    del review["ratings"]["testing"]["burden_support"]
    complete_service_challenge(service, assessment, review)
    saved = service.submit_review(assessment["id"], review)
    with sqlite3.connect(service.db_path) as db:
        legacy = json.loads(
            db.execute("SELECT data FROM reviews WHERE id=?", (saved["id"],)).fetchone()[0]
        )
        legacy["ratings"]["testing"]["burden_confidence"] = "high"
        del legacy["challenge"]["burden_dimensions"]
        serialized = json.dumps(legacy)
        db.execute("UPDATE reviews SET data=? WHERE id=?", (serialized, saved["id"]))
    report = service.get_report(assessment["id"])
    result = report["confidence_assessment"]["dimensions"]["testing"]["burden"]
    assert result["declared_confidence"] == "high" and result["support"]["status"] == "withheld"
    with sqlite3.connect(service.db_path) as db:
        assert (
            db.execute("SELECT data FROM reviews WHERE id=?", (saved["id"],)).fetchone()[0]
            == serialized
        )
