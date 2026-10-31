import json
import sqlite3
from copy import deepcopy

import pytest

from project_assess import service as service_module
from project_assess.rubric import DIMENSIONS
from project_assess.service import AssessmentService, markdown_report


@pytest.fixture
def captured(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src/app.py").write_text("def add(a, b):\n    return a + b\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    return service, snapshot


def document(service, snapshot, status="reviewed"):
    review = service.review_template(snapshot["id"])
    evidence_id = snapshot["evidence"][0]["id"]
    for dimension in DIMENSIONS:
        review["coverage"]["dimension_reviews"][dimension].update(
            status=status,
            rationale="Captured source supports this declared review scope.",
            evidence_ids=[evidence_id],
        )
        review["ratings"][dimension].update(capability=0, burden=0, evidence_ids=[evidence_id])
    return review


def test_template_and_shared_views_make_unreviewed_dimensions_explicit(captured):
    service, snapshot = captured
    template = service.review_template(snapshot["id"])
    dimensions = template["coverage"]["dimension_reviews"]
    assert set(dimensions) == set(DIMENSIONS)
    assert all(
        row["status"] == "unreviewed" and row["evidence_ids"] == [] for row in dimensions.values()
    )
    saved = service.submit_review(snapshot["id"], template)
    report = service.get_report(snapshot["id"])
    coverage = report["review_coverage"]
    assert coverage["status"] == "unreviewed"
    assert coverage["counts"]["unreviewed"] == len(DIMENSIONS)
    assert len(coverage["gaps"]) == len(DIMENSIONS)
    assert service.overview(snapshot["id"])["review_coverage"] == coverage
    assert service.evolve(snapshot["id"])["goal_alignment"]["review_coverage"] == coverage
    assert service.doctor(snapshot["id"])["goal_alignment"]["review_coverage"] == coverage
    assert report["review"] == saved and report["goals"] is None
    assert report["system_map"] == report["goal_alignment"]["system_map"]
    assert report["system_map"]["production_files"] == 1
    assert service.overview(snapshot["id"])["system_map"] == report["system_map"]
    assert service.doctor(snapshot["id"])["goal_alignment"]["system_map"] == report["system_map"]


def test_report_builds_one_system_map_and_reuses_it_in_shared_context(captured, monkeypatch):
    service, snapshot = captured
    calls = []
    original = service_module.get_system_map

    def counted(assessment):
        calls.append(assessment["id"])
        return original(assessment)

    monkeypatch.setattr(service_module, "get_system_map", counted)
    report = service.get_report(snapshot["id"])
    assert calls == [snapshot["id"]]
    assert report["system_map"] is report["goal_alignment"]["system_map"]
    assert "## Production source map" in markdown_report(report)


@pytest.mark.parametrize(
    "scope,status,expected",
    [
        ("whole_project", "reviewed", "broad"),
        ("whole_project", "partial", "partial"),
        ("focused", "reviewed", "focused"),
    ],
)
def test_breadth_is_an_explicit_declaration_separate_from_numeric_ratings(
    captured, scope, status, expected
):
    service, snapshot = captured
    review = document(service, snapshot, status)
    review["coverage"]["scope"] = scope
    service.submit_review(snapshot["id"], review)
    report = service.get_report(snapshot["id"])
    assert report["review_coverage"]["status"] == expected
    assert report["review_coverage"]["counts"][status] == len(DIMENSIONS)
    rendered = markdown_report(report)
    assert "Declared breadth: " + expected in rendered
    assert "performance: " + status in rendered
    assert report["review"]["ratings"]["testing"]["capability"] == 0


@pytest.mark.parametrize(
    "change",
    [
        "missing_dimension",
        "extra_dimension",
        "uncited_partial",
        "foreign_evidence",
        "numeric_capability",
        "numeric_burden",
    ],
)
def test_invalid_or_uncited_dimension_declarations_cannot_be_saved(captured, change):
    service, snapshot = captured
    review = service.review_template(snapshot["id"])
    dimensions = review["coverage"]["dimension_reviews"]
    if change == "missing_dimension":
        del dimensions[DIMENSIONS[-1]]
    elif change == "extra_dimension":
        dimensions["novelty"] = deepcopy(dimensions["testing"])
    elif change == "uncited_partial":
        dimensions["testing"]["status"] = "partial"
    elif change == "foreign_evidence":
        dimensions["testing"]["evidence_ids"] = ["foreign"]
    else:
        review["ratings"]["testing"].update(
            evidence_ids=[snapshot["evidence"][0]["id"]],
            **{"capability" if change == "numeric_capability" else "burden": 1},
        )
    with pytest.raises(ValueError):
        service.submit_review(snapshot["id"], review)
    assert service.get_report(snapshot["id"])["review"] is None


def test_legacy_whole_project_label_does_not_establish_breadth_or_rewrite_history(captured):
    service, snapshot = captured
    review = document(service, snapshot)
    del review["coverage"]["dimension_reviews"]
    saved = service.submit_review(snapshot["id"], review)
    with sqlite3.connect(service.db_path) as db:
        before = db.execute("SELECT data FROM reviews").fetchall()
    report = service.get_report(snapshot["id"])
    summary = report["review_coverage"]
    assert summary["scope"] == "whole_project" and summary["status"] == "unestablished"
    assert summary["counts"]["unestablished"] == len(DIMENSIONS)
    assert report["review"] == saved and "dimension_reviews" not in saved["coverage"]
    service.overview(snapshot["id"])
    service.doctor(snapshot["id"])
    with sqlite3.connect(service.db_path) as db:
        assert db.execute("SELECT data FROM reviews").fetchall() == before
    assert "dimension_reviews" not in json.loads(before[0][0])["coverage"]


def test_focused_review_can_carry_an_estimate_without_claiming_whole_project_review(captured):
    service, snapshot = captured
    review = document(service, snapshot)
    review["coverage"]["scope"] = "focused"
    review["coverage"]["dimension_reviews"]["security"].update(
        status="unreviewed",
        rationale="The security boundary was outside this focused review.",
        evidence_ids=[],
    )
    service.submit_review(snapshot["id"], review)
    summary = service.get_report(snapshot["id"])["review_coverage"]
    assert summary["status"] == "focused" and summary["counts"]["unreviewed"] == 1
    assert "security: unreviewed" in summary["gaps"]
