import json
import re
import xml.etree.ElementTree as ET
from copy import deepcopy

import pytest

from project_assess.badges import badge, badge_data
from project_assess.rubric import DIMENSIONS

SVG = "{http://www.w3.org/2000/svg}"


def visible_text(root):
    return " ".join("".join(item.itertext()) for item in root.iter(SVG + "text"))


def assert_readable_text_bounds(root):
    width, height = float(root.attrib["width"]), float(root.attrib["height"])

    def inspect(element, inherited_size=16):
        size = float(element.attrib.get("font-size", inherited_size))
        if element.tag == SVG + "text":
            x, y = float(element.attrib["x"]), float(element.attrib["y"])
            assert size >= 8
            assert 0 < x < width
            assert size <= y and y + size / 4 <= height
            if "textLength" in element.attrib:
                length = float(element.attrib["textLength"])
                assert length >= 0
                anchor = element.attrib.get("text-anchor", "start")
                left = (
                    x - length / 2 if anchor == "middle" else x - length if anchor == "end" else x
                )
                assert 0 <= left and left + length <= width
        for child in element:
            inspect(child, size)

    inspect(root)


@pytest.fixture
def report():
    assessment = {
        "id": "a_" + "a" * 32,
        "created_at": "2026-10-30T17:00:00+00:00",
        "rubric_version": "4",
        "source": {
            "root": "/private/project-source",
            "revision": "ABCDEF0123" * 4,
            "manifest_digest": "sha256:" + "b" * 64,
        },
        "complete": True,
        "gaps": ["Private collection details"],
        "facts": {"private": "Private implementation details"},
        "evidence": [{"path": "private/path.py", "excerpt": "Private source excerpt"}],
        "findings": [],
    }
    review = {
        "id": "r_" + "c" * 32,
        "created_at": "2026-10-31T18:00:00+00:00",
        "assessment_id": assessment["id"],
        "source_digest": assessment["source"]["manifest_digest"],
        "rubric_version": assessment["rubric_version"],
        "ratings": {
            dimension: {
                "capability": 3,
                "burden": 2,
                "confidence": "medium",
                "burden_basis": "source_estimate",
                "burden_confidence": "low",
                "rationale": "Private review rationale",
                "evidence_ids": ["private-evidence-id"],
                "recommendations": ["Private recommendation"],
            }
            for dimension in DIMENSIONS
        },
        "findings": [],
    }
    return {"assessment": assessment, "review": review, "goals": {"private": "Private goal"}}


def test_badges_are_deterministic_shields_data_and_accessible_standalone_svg(report):
    original = deepcopy(report)
    data = badge_data(report)
    rendered = badge(report)

    assert set(data) == {"schemaVersion", "label", "message", "color", "pat"}
    assert data["schemaVersion"] == 1 and data["label"] == "PAT"
    assert "7/7 known" in data["message"] and "reported:" in data["message"]
    assert data["pat"]["revision"] == "abcdef0123ab"
    assert data["pat"]["source_digest"] == report["assessment"]["source"]["manifest_digest"]
    assert data["pat"]["reviewed_at"] == report["review"]["created_at"]
    assert data["pat"]["burden_basis"] == "source_estimate"
    assert data["pat"]["gap_count"] == 1 and data["pat"]["complete"] is True
    assert badge(report) == rendered and badge_data(report) == data and report == original
    root = ET.fromstring(rendered)
    assert (int(root.attrib["width"]), int(root.attrib["height"])) == (200, 60)
    ids = {item.attrib["id"] for item in root if "id" in item.attrib}
    assert root.tag == SVG + "svg" and root.attrib["role"] == "img"
    assert set(root.attrib["aria-labelledby"].split()) == ids
    assert root.findtext(SVG + "title") == data["label"] + ": " + data["message"]
    description = root.findtext(SVG + "desc")
    for value in (
        report["assessment"]["created_at"],
        report["review"]["created_at"],
        report["review"]["id"],
        report["assessment"]["source"]["manifest_digest"],
        "source_estimate",
        "security certification",
    ):
        assert value in description
    assert {item.tag.removeprefix(SVG) for item in root.iter()} <= {
        "svg",
        "title",
        "desc",
        "rect",
        "path",
        "g",
        "text",
    }
    for dimension in ("summary", *DIMENSIONS):
        card = ET.fromstring(badge(report, dimension))
        expected = badge_data(report, dimension)
        assert (int(card.attrib["width"]), int(card.attrib["height"])) == (200, 60)
        assert card.attrib["viewBox"] == "0 0 200 60"
        assert card.findtext(SVG + "title") == expected["label"] + ": " + expected["message"]
        assert_readable_text_bounds(card)
        visible = visible_text(card)
        if dimension == "summary":
            assert "7/7" in visible and "known" in visible.lower()
            assert re.search(r"0\s+critical", visible, re.IGNORECASE)
            assert re.search(r"0\s+high", visible, re.IGNORECASE)
        else:
            assert "Capability" in visible and "Burden" in visible
            assert "3/5" in visible and "2/5" in visible


def test_summary_counts_both_known_axes_without_averaging_or_treating_zero_as_unknown(report):
    ratings = report["review"]["ratings"]
    ratings["testing"]["capability"] = None
    ratings["documentation"]["burden"] = None
    ratings["delivery"]["capability"] = True
    ratings["operability"]["burden"] = 2.5
    ratings["maintainability"].update(capability=0, burden=0)

    data = badge_data(report)

    assert data["pat"]["known_dimensions"] == 3 and "3/7 known" in data["message"]
    assert "C0/5 B0/5" in badge_data(report, "maintainability")["message"]
    assert "C?/5 B2/5" in badge_data(report, "testing")["message"]
    assert "C3/5 B?/5" in badge_data(report, "documentation")["message"]
    assert "C?/5 B2/5" in badge_data(report, "delivery")["message"]
    assert "C3/5 B?/5" in badge_data(report, "operability")["message"]
    zero = visible_text(ET.fromstring(badge(report, "maintainability")))
    assert zero.count("0/5") == 2 and "?" not in zero
    unknown = visible_text(ET.fromstring(badge(report, "testing")))
    assert "?/5" in unknown and "2/5" in unknown


def test_reported_critical_and_high_findings_remain_visible_in_every_badge(report):
    report["assessment"]["findings"] = [
        {"severity": "critical", "message": "Private collector finding"},
        {"severity": "high"},
        {"severity": "medium"},
    ]
    report["review"]["findings"] = [{"severity": "high", "title": "Private reviewed finding"}]

    for dimension in ("summary", *DIMENSIONS):
        data = badge_data(report, dimension)
        assert data["pat"]["findings"] == {"critical": 1, "high": 2}
        assert "1 critical / 2 high" in data["message"]
        assert data["color"] == "9a6700"
        rendered = ET.fromstring(badge(report, dimension))
        visible = visible_text(rendered)
        assert re.search(r"1\s+critical", visible, re.IGNORECASE)
        assert re.search(r"2\s+high", visible, re.IGNORECASE)
        assert_readable_text_bounds(rendered)
    assert "Private" not in badge(report)


def test_unreviewed_and_incomplete_collection_are_explicit_even_with_missing_legacy_flag(report):
    report["review"] = None
    report["assessment"].pop("complete")

    for dimension in ("summary", *DIMENSIONS):
        data = badge_data(report, dimension)
        assert "unreviewed" in data["message"] and "partial scan" in data["message"]
        assert data["pat"]["review_status"] == "unreviewed"
        assert data["pat"]["known_dimensions"] == 0 and data["pat"]["complete"] is False
        assert data["pat"]["review_id"] is None and data["pat"]["reviewed_at"] is None
        if dimension != "summary":
            assert "C?/5 B?/5" in data["message"]
        rendered = ET.fromstring(badge(report, dimension))
        visible = visible_text(rendered).lower()
        assert "unreviewed" in visible and "partial scan" in visible
        if dimension != "summary":
            assert "?/5" in visible
        assert_readable_text_bounds(rendered)


def test_allowlisted_provenance_never_exports_paths_or_free_form_input(report):
    injected = '<script href="https://private.example">private-marker</script>'
    assessment, review = report["assessment"], report["review"]
    assessment.update(id=injected, rubric_version=injected, created_at=injected)
    assessment["source"].update(revision=injected, manifest_digest=injected)
    review.update(
        id=injected,
        assessment_id=injected,
        source_digest=injected,
        rubric_version=injected,
        created_at=injected,
    )
    for rating in review["ratings"].values():
        rating.update(confidence=injected, burden_basis=[injected], burden_confidence=injected)

    data, rendered = badge_data(report), badge(report)

    for field in (
        "assessment_id",
        "review_id",
        "revision",
        "source_digest",
        "rubric_version",
        "assessed_at",
        "reviewed_at",
    ):
        assert data["pat"][field] is None
    assert data["pat"]["confidence"] == data["pat"]["burden_basis"] == "unknown"
    exported = json.dumps(data) + rendered
    for private in (
        "private-marker",
        "/private/",
        "Private",
        "private/path.py",
        "private-evidence-id",
        "https://",
    ):
        assert private not in exported
    assert "href=" not in rendered and "<script" not in rendered
    ET.fromstring(rendered)


@pytest.mark.parametrize("key", ["assessment_id", "source_digest", "rubric_version"])
def test_mismatched_review_is_rejected_instead_of_badging_a_different_snapshot(report, key):
    report["review"][key] = "other-snapshot"
    with pytest.raises(ValueError, match="selected assessment"):
        badge_data(report)


def test_same_rubric_historical_review_retains_legacy_unknown_dimension(report):
    report["assessment"]["rubric_version"] = report["review"]["rubric_version"] = "3"
    report["review"]["ratings"].pop("extensibility")

    data = badge_data(report, "extensibility")

    assert data["message"] == "C?/5 B?/5"
    assert data["pat"]["rubric_version"] == "3"
    assert data["pat"]["review_id"] == report["review"]["id"]
    assert data["pat"]["known_dimensions"] == 6


def test_unknown_badge_dimension_is_rejected_without_echoing_input(report):
    with pytest.raises(ValueError) as error:
        badge(report, "private/path.py")
    assert "private" not in str(error.value)


def test_long_warning_badges_wrap_without_hiding_counts_or_partial_collection(report):
    compact = ET.fromstring(badge(report, "maintainability"))
    assert (int(compact.attrib["width"]), int(compact.attrib["height"])) == (200, 60)
    report["assessment"]["complete"] = False
    report["assessment"]["findings"] = [{"severity": "critical"}] * 100 + [
        {"severity": "high"}
    ] * 100

    for reviewed in (True, False):
        if not reviewed:
            report["review"] = None
        for dimension in ("summary", *DIMENSIONS):
            data = badge_data(report, dimension)
            wrapped = ET.fromstring(badge(report, dimension))
            visible = visible_text(wrapped).lower()
            assert int(wrapped.attrib["width"]) == 200 and int(wrapped.attrib["height"]) > 60
            assert re.search(r"100\s+critical", visible)
            assert re.search(r"100\s+high", visible)
            assert "partial scan" in visible
            assert wrapped.findtext(SVG + "title") == data["label"] + ": " + data["message"]
            if not reviewed:
                assert "unreviewed" in visible
            assert_readable_text_bounds(wrapped)
            assert "100 critical / 100 high" in data["message"]
            assert "partial scan" in data["message"]
