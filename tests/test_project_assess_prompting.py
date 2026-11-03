"""Prompt reliance remains authored context, separate from counts and outcome evidence."""

from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator

from project_assess.prompting import (
    PROMPTING_SCHEMA,
    prompting_profile,
    prompting_rubric,
    prompting_template,
    validate_prompting,
)


def assessment():
    stats = {
        "schema_version": 1,
        "status": "complete",
        "summary": {
            "counts_by_kind": {"development_guidance": 400, "model_invocation": 1000},
            "guidance_files": 400,
            "runtime_prompt_files": 0,
            "model_call_files": 1000,
        },
        "coverage": {"captured_files": 1500},
        "gaps": [],
        "caveat": "Syntax and declaration hints do not establish behavioral control.",
    }
    return {
        "facts": {"prompting": {"schema_version": 1, "evidence_id": "analysis", "level": 5}},
        "evidence": [
            {"id": "source", "kind": "python", "path": "src/service.py"},
            {"id": "skill", "kind": "documentation", "path": ".agents/skills/product/SKILL.md"},
            {"id": "analysis", "kind": "prompting-analysis", "stats": stats},
            {
                "id": "observed",
                "kind": "observation",
                "stats": {
                    "type": "prompting",
                    "sourceIdentity": {"overall": "matched"},
                    "scenario": {"name": "Interpret a request", "scope": ["src/service.py"]},
                    "prompting": {
                        "input_digest": "sha256:" + "a" * 64,
                        "configuration_digest": "sha256:" + "b" * 64,
                        "trials": 10,
                        "distinct_outputs": 1,
                        "comparison": "exact",
                        "criterion": "Identical approved action for the same request.",
                    },
                    "results": [
                        {
                            "status": "observed",
                            "name": "identical_results",
                            "value": True,
                            "unit": "boolean",
                        }
                    ],
                    "limitations": ["One supplied scenario with a fixed input and configuration."],
                },
            },
        ],
    }


def authored(level=3):
    value = prompting_template()
    value.update(
        level=level,
        confidence="medium",
        rationale="The workflow uses model interpretation and explicit application rules.",
        evidence_ids=["source"],
        workflows=[
            {
                "name": "Interpret a request and apply an approved action",
                "control": "hybrid",
                "rationale": "The model proposes a result; source-owned validation controls the action.",
                "evidence_ids": ["source"],
            }
        ],
    )
    value["intent"].update(
        min=2,
        max=3,
        basis="user_stated",
        rationale="The owner wants a bounded model step or hybrid workflow.",
    )
    if level == 0:
        value["workflows"][0]["control"] = "deterministic"
    return value


def test_counts_never_assign_reliance_or_create_targets_for_unreviewed_or_legacy_snapshots():
    template = prompting_template()
    Draft202012Validator(PROMPTING_SCHEMA).validate(template)
    validate_prompting(template, [])
    for review in (None, {}, {"prompting": template}):
        result = prompting_profile(assessment(), review)
        assert result["status"] == "unestablished"
        assert result["level"] is None and result["level_label"] == "Unknown"
        assert result["intent"]["min"] is result["intent"]["max"] is None
        assert result["recommendations"] == []
        assert result["fit"]["gap"] is None
        assert result["collection"]["summary"]["counts_by_kind"]["model_invocation"] == 1000
        assert (
            result["no_numeric_goals_autosaved"]
            is result["no_engineering_progress_inferred"]
            is True
        )


def test_a_host_skill_can_be_the_product_without_an_sdk_invocation():
    value = authored(5)
    value["evidence_ids"] = ["skill"]
    value["workflows"][0].update(
        control="prompt_led",
        rationale="Users invoke the skill to deliver the product's assessment workflow.",
        evidence_ids=["skill"],
    )
    value["intent"].update(min=4, max=5)
    result = prompting_profile(assessment(), {"prompting": value})
    assert result["status"] == "recorded" and result["level"] == 5
    assert result["workflows"][0]["control_label"] == "Prompt-led behavior"
    assert result["fit"]["status"] == "aligned" and result["fit"]["direction"] == "retain"


@pytest.mark.parametrize(
    ("level", "minimum", "maximum", "status", "direction", "gap"),
    [
        (1, 3, 4, "below_range", "more_prompt_driven", 2),
        (5, 1, 2, "above_range", "more_deterministic", 3),
        (3, 2, 4, "aligned", "retain", 0),
        (0, None, 1, "aligned", "retain", 0),
        (5, 4, None, "aligned", "retain", 0),
        (2, None, None, "unconfigured", "investigate", None),
    ],
)
def test_contextual_fit_can_move_both_directions_without_calling_it_capability(
    level, minimum, maximum, status, direction, gap
):
    value = authored(level)
    value["intent"].update(min=minimum, max=maximum, basis="inferred", evidence_ids=["source"])
    value["recommendations"] = [
        {
            "direction": direction,
            "action": "Right-size the named workflow.",
            "rationale": "Preserve necessary outcomes and fit the owner's intended purpose.",
            "evidence_ids": ["source"],
        }
    ]
    original = deepcopy((assessment(), value))
    result = prompting_profile(original[0], {"prompting": value})
    assert result["fit"] == {
        "status": status,
        "label": result["fit"]["label"],
        "direction": direction,
        "gap": gap,
        "provisional": True,
    }
    assert result["intent"]["provisional"] is True
    assert result["intent"]["basis_label"] == "Inferred · provisional"
    assert not {"ratings", "targets", "capability", "burden"} & result.keys()
    assert value == original[1]


def test_source_controls_do_not_claim_output_repeatability():
    value = authored()
    value["variability"].update(
        status="source_controls_only",
        rationale="Typed output and temperature zero are declared, with no repeat-run results.",
        evidence_ids=["source"],
    )
    validate_prompting(value, assessment()["evidence"])
    result = prompting_profile(assessment(), {"prompting": value})
    assert "unmeasured" in result["variability"]["label"]
    value["variability"]["status"] = "observed_repeatable"
    with pytest.raises(ValueError, match="source-matched prompting observation"):
        validate_prompting(value, assessment()["evidence"])


@pytest.mark.parametrize("status", ["observed_variable", "observed_bounded", "observed_repeatable"])
def test_matching_supplied_repeat_run_evidence_is_scoped_and_not_authenticated(status):
    captured = assessment()
    observed = captured["evidence"][-1]["stats"]
    if status == "observed_variable":
        observed["prompting"]["distinct_outputs"] = 2
    elif status == "observed_bounded":
        observed["prompting"].update(comparison="semantic", distinct_outputs=2)
        observed["results"][0].update(name="within_criterion", value=True)
    value = authored()
    value["variability"].update(
        status=status,
        rationale="One same-input scenario records variation under fixed configuration.",
        evidence_ids=["observed"],
    )
    validate_prompting(value, captured["evidence"])
    result = prompting_profile(captured, {"prompting": value})
    assert result["variability"]["status"] == status
    assert "reported" in result["variability"]["label"]
    assert "does not authenticate execution" in result["caveat"]


@pytest.mark.parametrize(
    "change",
    [
        lambda row: row.update(kind="junit"),
        lambda row: row["stats"].update(type="performance"),
        lambda row: row["stats"]["sourceIdentity"].update(overall="mismatched"),
        lambda row: row["stats"].update(results=[]),
        lambda row: row["stats"]["results"][0].update(status="inconclusive"),
        lambda row: row["stats"].update(results=None),
        lambda row: row.update(stats=None),
        lambda row: row["stats"].pop("prompting"),
        lambda row: row["stats"].update(prompting=None),
        lambda row: row["stats"].update(prompting={}),
        lambda row: row["stats"]["prompting"].update(input_digest="unbound"),
        lambda row: row["stats"]["prompting"].update(configuration_digest=None),
        lambda row: row["stats"]["prompting"].update(trials=1),
        lambda row: row["stats"]["prompting"].update(trials=True),
        lambda row: row["stats"]["prompting"].update(trials=10.0),
        lambda row: row["stats"]["prompting"].update(distinct_outputs=0),
        lambda row: row["stats"]["prompting"].update(distinct_outputs=11),
        lambda row: row["stats"]["prompting"].update(distinct_outputs=1.0),
        lambda row: row["stats"]["prompting"].update(distinct_outputs=True),
        lambda row: row["stats"]["prompting"].update(criterion="  "),
        lambda row: row["stats"]["prompting"].update(comparison="unknown"),
        lambda row: row["stats"].pop("scenario"),
        lambda row: row["stats"].update(scenario=None),
        lambda row: row["stats"]["scenario"].update(scope=None),
        lambda row: row["stats"]["scenario"].update(scope=[]),
        lambda row: row["stats"]["scenario"].update(scope=["src/billing.py"]),
        lambda row: row["stats"]["scenario"].update(scope=["../src/service.py"]),
    ],
)
def test_stale_or_unrelated_observations_do_not_establish_variability(change):
    captured = assessment()
    change(captured["evidence"][-1])
    value = authored()
    value["variability"].update(status="observed_repeatable", evidence_ids=["observed"])
    with pytest.raises(ValueError, match="source-matched prompting observation"):
        validate_prompting(value, captured["evidence"])


@pytest.mark.parametrize(
    ("status", "comparison", "distinct", "result_name", "result_value", "result_status"),
    [
        ("observed_variable", "exact", 1, "identical_results", True, "observed"),
        ("observed_repeatable", "exact", 2, "identical_results", True, "observed"),
        ("observed_repeatable", "semantic", 1, "identical_results", True, "observed"),
        ("observed_bounded", "exact", 1, "within_criterion", True, "observed"),
        ("observed_bounded", "semantic", 2, "billed_tokens", True, "observed"),
        ("observed_bounded", "semantic", 2, "within_criterion", False, "observed"),
        ("observed_bounded", "semantic", 2, "within_criterion", 1, "observed"),
        ("observed_bounded", "semantic", 2, "within_criterion", True, "failed"),
    ],
)
def test_repeat_run_claims_must_support_the_selected_variability_status(
    status, comparison, distinct, result_name, result_value, result_status
):
    captured = assessment()
    observed = captured["evidence"][-1]["stats"]
    observed["prompting"].update(comparison=comparison, distinct_outputs=distinct)
    observed["results"][0].update(name=result_name, value=result_value, status=result_status)
    value = authored()
    value["variability"].update(status=status, evidence_ids=["observed"])
    with pytest.raises(ValueError, match="consistent repeat-run results"):
        validate_prompting(value, captured["evidence"])


@pytest.mark.parametrize("workflow_evidence", [[], ["skill"], ["analysis"]])
def test_observations_must_overlap_the_cited_known_workflow_source_paths(workflow_evidence):
    value = authored()
    value["variability"].update(status="observed_repeatable", evidence_ids=["observed"])
    value["workflows"][0]["evidence_ids"] = workflow_evidence
    if not workflow_evidence:
        value["level"] = None
        value["workflows"][0]["control"] = "unknown"
    with pytest.raises(ValueError, match="cited known workflow"):
        validate_prompting(value, assessment()["evidence"])


def test_scoped_observation_can_match_the_products_host_skill_workflow():
    captured = assessment()
    value = authored(5)
    value["workflows"][0].update(control="prompt_led", evidence_ids=["skill"])
    value["variability"].update(status="observed_repeatable", evidence_ids=["observed"])
    captured["evidence"][-1]["stats"]["scenario"]["scope"] = [".agents/skills/product/SKILL.md"]
    validate_prompting(value, captured["evidence"])


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(level=True),
        lambda value: value.update(level=3.0),
        lambda value: value.update(level=6),
        lambda value: value.update(schema_version=2),
        lambda value: value.update(evidence_ids=[]),
        lambda value: value.update(evidence_ids=["foreign"]),
        lambda value: value.update(workflows=[]),
        lambda value: value["workflows"][0].update(evidence_ids=[]),
        lambda value: value["workflows"].append(deepcopy(value["workflows"][0])),
        lambda value: value["variability"].update(evidence_ids=["foreign"]),
        lambda value: value["intent"].update(min=4, max=2),
        lambda value: value["intent"].update(min=2.0),
        lambda value: value["intent"].update(basis="unknown"),
        lambda value: value["intent"].update(basis="inferred", evidence_ids=[]),
        lambda value: value["intent"].update(evidence_ids=["foreign"]),
        lambda value: value.update(quality_score=5),
        lambda value: value["workflows"][0].update(control="deterministic"),
        lambda value: value.update(level=0),
    ],
)
def test_invalid_judgments_or_foreign_references_fail_closed(change):
    value = authored()
    change(value)
    with pytest.raises(ValueError):
        validate_prompting(value, assessment()["evidence"])


def test_schema_error_does_not_echo_private_authored_text():
    value = authored()
    private = "private-input-do-not-echo"
    value["intent"]["basis"] = private
    with pytest.raises(ValueError) as failure:
        validate_prompting(value, assessment()["evidence"])
    assert "intent.basis" in str(failure.value)
    assert private not in str(failure.value)


@pytest.mark.parametrize("raw", [None, "future-format", {}, {"schema_version": 2}])
def test_unsupported_historical_profile_remains_unknown_and_readable(raw):
    review = {"prompting": raw}
    before = deepcopy(review)
    result = prompting_profile(assessment(), review)
    assert result["status"] == "unestablished" and result["level"] is None
    assert bool(result["gaps"]) == (raw is not None)
    assert review == before


def test_missing_or_inconsistent_collection_never_becomes_a_zero_level():
    captured = assessment()
    del captured["facts"]["prompting"]
    assert prompting_profile(captured)["collection"]["status"] == "not_collected"
    captured["facts"]["prompting"] = {"schema_version": 1, "evidence_id": "foreign"}
    result = prompting_profile(captured)
    assert result["collection"]["status"] == "unsupported" and result["level"] is None
    captured["facts"]["prompting"]["evidence_id"] = "analysis"
    captured["evidence"][2]["stats"]["schema_version"] = 2
    assert prompting_profile(captured)["collection"]["status"] == "unsupported"


def test_context_range_changes_never_modify_input_records_or_save_engineering_progress():
    captured, value = assessment(), authored(4)
    before = deepcopy(captured)
    first = prompting_profile(captured, {"prompting": value})
    value["intent"].update(min=4, max=5)
    second = prompting_profile(captured, {"prompting": value})
    assert first["fit"]["gap"] == 1 and second["fit"]["gap"] == 0
    assert first["level"] == second["level"] == 4
    assert second["no_engineering_progress_inferred"] is True
    assert second["no_numeric_goals_autosaved"] is True
    second["collection"]["summary"]["counts_by_kind"]["model_invocation"] = 0
    assert captured == before


def test_rubric_defines_independent_descriptive_endpoints_and_review_questions():
    rubric = prompting_rubric()
    assert list(rubric["levels"]) == [str(value) for value in range(6)]
    assert rubric["levels"]["0"]["label"] == "Code-controlled behavior"
    assert rubric["levels"]["5"]["label"] == "Predominantly instruction-defined"
    assert "quality grade" in rubric["caveat"]
    assert any("host-agent" in question for question in rubric["questions"])
    assert not {"default_target", "recommended_level", "capability_min"} & rubric.keys()
