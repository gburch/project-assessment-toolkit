"""Protect goal defaults and independent public rubric exports."""

import pytest

from project_assess.rubric import DIMENSIONS, PROFILES, RUBRIC_VERSION, rubric
from project_assess.service import AssessmentService


def test_rubric_exports_cannot_mutate_later_assessments():
    exported = rubric()
    original = rubric()

    exported["dimensions"]["testing"]["capability"][0] = "altered judgment rule"
    exported["dimensions"]["testing"]["burden"].clear()
    exported["profiles"]["local-experiment"]["targets"]["testing"]["capability_min"] = 5
    exported["burden_guidance"]["basis"].clear()
    exported["dimensions"]["maintainability"]["checks"]["rigidity"]["questions"].clear()
    exported["dimensions"]["extensibility"]["capability"].clear()
    exported["profiles"]["framework"]["targets"]["extensibility"]["capability_min"] = 0

    assert rubric() == original
    assert PROFILES["local-experiment"]["targets"]["testing"]["capability_min"] == 1


def test_rubric_exposes_distinct_estimated_observed_and_unknown_burden_basis():
    guidance = rubric()["burden_guidance"]
    assert set(guidance["basis"]) == {"source_estimate", "observed", "unknown"}
    assert all(
        isinstance(explanation, str) and explanation for explanation in guidance["basis"].values()
    )
    assert guidance["principle"] and guidance["confidence"]


@pytest.mark.parametrize(
    ("profile", "dimension", "minimum", "ceiling"),
    [
        ("local-experiment", "operability", 0, 1),
        ("local-experiment", "testing", 1, 1),
        ("internal-service", "security", 2, 2),
        ("public-production", "documentation", 2, 2),
        ("public-production", "testing", 3, 2),
        ("sensitive-critical", "security", 4, 3),
        ("local-experiment", "extensibility", 0, 1),
        ("internal-service", "extensibility", 0, 2),
        ("public-production", "extensibility", 0, 2),
        ("sensitive-critical", "extensibility", 0, 3),
        ("framework", "extensibility", 4, 2),
        ("framework", "security", 3, 2),
        ("framework", "operability", 2, 2),
    ],
)
def test_profiles_preserve_contextual_capability_and_burden_defaults(
    profile, dimension, minimum, ceiling
):
    assert PROFILES[profile]["targets"][dimension] == {
        "capability_min": minimum,
        "burden_max": ceiling,
    }


def test_every_profile_covers_all_dimensions_with_bounded_independent_goals():
    exported = rubric()
    assert exported["version"] == RUBRIC_VERSION
    assert set(exported["dimensions"]) == set(DIMENSIONS)
    for profile in exported["profiles"].values():
        assert set(profile["targets"]) == set(DIMENSIONS)
        for goals in profile["targets"].values():
            assert set(goals) == {"capability_min", "burden_max"}
            assert all(type(value) is int and 0 <= value <= 5 for value in goals.values())
    for anchors in exported["dimensions"].values():
        assert len(anchors["capability"]) == len(anchors["burden"]) == 6
        assert anchors["capability"] is not anchors["burden"]


def test_extensibility_is_an_independent_dimension_and_rigidity_stays_a_named_check():
    exported = rubric()
    assert len(DIMENSIONS) == 7
    assert "extensibility" in exported["dimensions"]
    assert "rigidity" not in DIMENSIONS
    assert "rigidity" in exported["dimensions"]["maintainability"]["checks"]
    framework = exported["profiles"]["framework"]["targets"]
    assert (
        framework["extensibility"]["capability_min"]
        > framework["maintainability"]["capability_min"]
    )
    assert PROFILES["local-experiment"]["targets"]["extensibility"]["capability_min"] == 0


@pytest.mark.parametrize("structure", ["delegating_layers", "injected_boundary"])
def test_architecture_candidates_alone_do_not_establish_maintenance_burden(tmp_path, structure):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# Local converter\nConvert a single value locally.\n")
    if structure == "delegating_layers":
        for level in range(4):
            following = (
                f"from layer_{level + 1} import convert as delegate\n"
                if level < 3
                else "def delegate(value):\n    return value * 2\n"
            )
            (root / f"layer_{level}.py").write_text(
                following + "\ndef convert(value):\n    return delegate(value)\n"
            )
    else:
        (root / "conversion.py").write_text(
            "from typing import Protocol\n\n"
            "class RateSource(Protocol):\n"
            "    def rate(self) -> int: ...\n\n"
            "def convert(value: int, source: RateSource) -> int:\n"
            "    return value * source.rate()\n"
        )
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root)
    template = service.review_template(captured["id"])

    assert service.get_report(captured["id"])["review"] is None
    assert template["ratings"]["maintainability"]["capability"] is None
    assert template["ratings"]["maintainability"]["burden"] is None
    assert template["ratings"]["extensibility"]["capability"] is None
    assert template["ratings"]["extensibility"]["burden"] is None
