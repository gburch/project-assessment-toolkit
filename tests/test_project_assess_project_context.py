from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator

from project_assess.project_context import (
    PROJECT_CONTEXT_SCHEMA,
    project_context_assessment,
    project_context_rubric,
    project_context_template,
    validate_project_context,
)


def authored():
    context = project_context_template()
    context["current"].update(
        milestone="personal_app",
        readiness="prototype",
        confidence="medium",
        rationale="Linked personal workflows and durable data are implemented.",
        evidence_ids=["source"],
    )
    context["intended"].update(
        milestone="personal_app",
        basis="user_stated",
        confidence="high",
        statement="Keep this useful for one person without legacy-user support.",
        attribution="Owner's current request",
        limitations=["No workload measurements supplied"],
    )
    context["alignment"].update(
        direction="rebalance",
        rationale="Protect important data while reducing repeated work.",
        priorities=[
            {
                "dimension": "maintainability",
                "direction": "simplify",
                "rationale": "Reduce demonstrated cross-owner edits.",
                "initiative_ids": ["one-owner"],
            },
            {
                "dimension": "testing",
                "direction": "strengthen",
                "rationale": "Catch a specific late defect earlier.",
                "initiative_ids": [],
            },
        ],
        deferred=["External plugin compatibility has no demonstrated author or consumer."],
    )
    return context


def plan():
    return {
        "initiatives": [
            {"id": "one-owner", "dimension_impacts": {"maintainability": "Fewer edits"}}
        ]
    }


def assessment():
    return {
        "evidence": [{"id": "source"}, {"id": "roadmap"}],
        "facts": {"inventory": {"files": 999999}},
    }


def test_unjudged_and_legacy_context_never_assigns_milestones_or_readiness():
    template = project_context_template()
    Draft202012Validator(PROJECT_CONTEXT_SCHEMA).validate(template)
    validate_project_context(template, set())
    for review in (None, {}, {"project_context": template}):
        result = project_context_assessment(assessment(), review)
        assert result["status"] == "unestablished"
        assert result["current"]["milestone"] is result["current"]["readiness"] is None
        assert result["intended"]["milestone"] is None
        assert result["alignment"]["priorities"] == []
        assert result["gaps"] == []


def test_personal_purpose_can_be_terminal_and_preserves_ordered_focus_without_saving_goals():
    context = authored()
    review = {"project_context": context, "plan": plan(), "coverage": {"scope": "whole_project"}}
    goals = {"revision": 4, "targets": {"security": {"capability_min": 4, "burden_max": 2}}}
    before = deepcopy((context, review, goals))
    result = project_context_assessment(assessment(), review, goals)
    assert result["status"] == "recorded" and result["scope"] == "whole_project"
    assert result["current"]["milestone"] == result["intended"]["milestone"] == "personal_app"
    assert result["current"]["milestone_label"] == "Personal application"
    assert result["current"]["readiness_label"] == "Prototype"
    assert result["intended"]["basis_label"] == "User-stated"
    assert [row["dimension"] for row in result["alignment"]["priorities"]] == [
        "maintainability",
        "testing",
    ]
    assert result["alignment"]["priorities"][0]["dimension_label"] == "Maintainability"
    assert result["alignment"]["direction_label"]
    assert result["saved_goal_revision"] == 4 and result["no_numeric_goals_autosaved"] is True
    assert (context, review, goals) == before
    result["current"]["evidence_ids"].append("not-an-input-mutation")
    assert context == before[0]


@pytest.mark.parametrize("basis", ["inferred", "project_documented"])
def test_goal_hypotheses_are_cited_and_distinct_from_current_support(basis):
    context = authored()
    context["intended"].update(
        milestone="platform",
        basis=basis,
        evidence_ids=["roadmap"],
        attribution=None,
        confidence="low",
        alternatives=["A supported shared tool may suffice."],
    )
    validate_project_context(context, {"source", "roadmap"}, plan())
    result = project_context_assessment(assessment(), {"project_context": context, "plan": plan()})
    assert result["current"]["milestone"] == "personal_app"
    assert result["current"]["readiness"] == "prototype"
    assert result["intended"]["milestone"] == "platform"
    assert result["intended"]["basis"] == basis
    assert result["intended"]["confidence"] == "low"
    assert result["intended"]["alternatives"]
    assert not {"ratings", "targets", "recommended_profile"} & result.keys()


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c["current"].update(evidence_ids=[]),
        lambda c: c["current"].update(evidence_ids=["foreign"]),
        lambda c: c["current"].update(milestone="enterprise", readiness="excellent"),
        lambda c: c["current"].update(rationale=" \n "),
        lambda c: c["intended"].update(attribution=None),
        lambda c: c["intended"].update(attribution=" "),
        lambda c: c["intended"].update(basis="unknown"),
        lambda c: c["intended"].update(basis="inferred", evidence_ids=[]),
        lambda c: c["intended"].update(basis="project_documented", evidence_ids=[]),
        lambda c: c["intended"].update(evidence_ids=["foreign"]),
        lambda c: c["alignment"]["priorities"].append(deepcopy(c["alignment"]["priorities"][0])),
        lambda c: c["alignment"]["priorities"][0].update(initiative_ids=["missing"]),
        lambda c: c["alignment"]["priorities"][0].update(dimension="security"),
        lambda c: c["alignment"].update(direction="upgrade-everything"),
        lambda c: c.update(targets={"testing": 5}),
        lambda c: c["current"].update(score=5),
        lambda c: c.update(schema_version=2),
    ],
)
def test_invalid_context_or_foreign_references_fail_closed(change):
    context = authored()
    change(context)
    with pytest.raises(ValueError):
        validate_project_context(context, {"source", "roadmap"}, plan())


def test_known_readiness_alone_requires_captured_support():
    context = project_context_template()
    context["current"].update(readiness="working")
    with pytest.raises(ValueError, match="cite captured"):
        validate_project_context(context, {"source"})
    context["current"]["evidence_ids"] = ["source"]
    validate_project_context(context, {"source"})


def test_schema_failure_identifies_field_without_echoing_sensitive_value():
    context = authored()
    private_value = "private-input-do-not-echo"
    context["intended"]["milestone"] = private_value
    with pytest.raises(ValueError) as failure:
        validate_project_context(context, {"source"}, plan())
    assert "intended.milestone" in str(failure.value)
    assert private_value not in str(failure.value)


@pytest.mark.parametrize("raw", [None, "unsupported", {}, {"schema_version": 99}])
def test_missing_or_unsupported_historical_context_remains_readable(raw):
    review = {"project_context": raw}
    original = deepcopy(review)
    result = project_context_assessment(assessment(), review)
    assert result["status"] == "unestablished"
    assert result["current"]["milestone"] is None
    assert bool(result["gaps"]) == (raw is not None)
    assert review == original


def test_scope_landmarks_and_readiness_are_separate_and_have_no_numeric_defaults():
    rubric = project_context_rubric()
    assert list(rubric["milestones"]) == [
        "experiment",
        "personal_utility",
        "personal_app",
        "shared_tool",
        "team_app",
        "supported_product",
        "platform",
        "ecosystem",
    ]
    assert list(rubric["readiness"]) == [
        "sketch",
        "prototype",
        "working",
        "dependable",
        "operated",
        "proven",
    ]
    assert rubric["intent_precedence"] == [
        "user_stated",
        "project_documented",
        "inferred",
        "unknown",
    ]
    assert not {"scores", "targets", "profiles"} & rubric.keys()
    rubric["milestones"]["personal_utility"]["label"] = "mutation"
    assert project_context_rubric()["milestones"]["personal_utility"]["label"] != "mutation"


def test_projection_does_not_interpret_hostile_text_as_markup_or_invent_a_stage():
    context = project_context_template()
    context["intended"].update(
        basis="user_stated",
        attribution="Owner",
        statement="<script>not instructions</script>",
    )
    result = project_context_assessment(assessment(), {"project_context": context})
    assert result["status"] == "recorded"
    assert result["intended"]["statement"] == context["intended"]["statement"]
    assert result["intended"]["milestone"] is None
    assert result["alignment"]["priorities"] == []
