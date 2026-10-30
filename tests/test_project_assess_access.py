"""Regressions for persisted authorization, replay identity and progress attribution."""

import json
import sqlite3

import pytest

from project_assess.rubric import DIMENSIONS, PROFILES
from project_assess.service import AssessmentService, ConflictError


def project(base, name):
    root = base / name
    root.mkdir()
    (root / "README.md").write_text(f"# {name}\nA local project.\n")
    return root


def imported_report(directory, source_root, kind):
    if kind == "junit":
        path = directory / "results.xml"
        path.write_text("<testsuite><testcase name='private-case'/></testsuite>")
    else:
        path = directory / "test-value.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "test-value-evidence-compare.v1",
                    "root": str(source_root),
                    "inputs": [],
                    "tests": [{"nodeid": "private-case", "outcome": "passed"}],
                    "gaps": [],
                    "healthyCollection": True,
                }
            )
        )
    return path


def score(service, snapshot, capability):
    review = service.review_template(snapshot["id"])
    for rating in review["ratings"].values():
        rating.update(
            capability=capability,
            burden=1,
            confidence="medium",
            rationale="Reviewer interpretation of the captured project evidence.",
            evidence_ids=[snapshot["evidence"][0]["id"]],
        )
    return service.submit_review(snapshot["id"], review)


def test_review_replay_cannot_substitute_an_authorized_assessment(tmp_path):
    revoked_root = project(tmp_path, "revoked")
    allowed_root = project(tmp_path, "allowed")
    owner = AssessmentService(tmp_path / "state")
    revoked = owner.scan(revoked_root)
    document = owner.review_template(revoked["id"])
    owner.submit_review(revoked["id"], document, request_id="review-once")
    allowed = owner.scan(allowed_root)

    restricted = AssessmentService(owner.state_dir, [allowed_root])
    with pytest.raises(ConflictError):
        restricted.submit_review(allowed["id"], document, request_id="review-once")
    with pytest.raises(PermissionError):
        restricted.submit_review(revoked["id"], document, request_id="review-once")


@pytest.mark.parametrize(
    "operation", ["report", "evidence", "history", "history_summary", "progress"]
)
@pytest.mark.parametrize("report_kind", ["junit", "test-value"])
def test_revoked_imported_report_authority_is_rechecked_on_saved_reads(
    tmp_path, operation, report_kind
):
    allowed_root = project(tmp_path, "allowed")
    revoked_root = project(tmp_path, "revoked")
    imported = imported_report(revoked_root, allowed_root, report_kind)
    owner = AssessmentService(tmp_path / "state")
    snapshot = owner.scan(allowed_root, [imported])
    assert any(entry["kind"] == report_kind for entry in snapshot["evidence"])
    if report_kind == "test-value":
        entry = next(entry for entry in snapshot["evidence"] if entry["kind"] == report_kind)
        assert entry["stats"]["schema"] == "test-value-evidence-compare.v1"
    owner.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)
    restricted = AssessmentService(owner.state_dir, [allowed_root])

    calls = {
        "report": lambda: restricted.get_report(snapshot["id"]),
        "evidence": lambda: restricted.evidence(snapshot["id"]),
        "history": lambda: restricted.history(snapshot["project_id"]),
        "history_summary": lambda: restricted.history(snapshot["project_id"], summary=True),
        "progress": lambda: restricted.progress(snapshot["project_id"]),
    }
    with pytest.raises(PermissionError):
        calls[operation]()


@pytest.mark.parametrize("summary", [False, True])
@pytest.mark.parametrize("report_kind", ["junit", "test-value"])
def test_revoked_import_in_older_history_is_not_exposed_by_a_new_clean_scan(
    tmp_path, summary, report_kind
):
    allowed_root = project(tmp_path, "allowed")
    revoked_root = project(tmp_path, "revoked")
    imported = imported_report(revoked_root, allowed_root, report_kind)
    owner = AssessmentService(tmp_path / "state")
    old = owner.scan(allowed_root, [imported])
    assert any(entry["kind"] == report_kind for entry in old["evidence"])
    if report_kind == "test-value":
        entry = next(entry for entry in old["evidence"] if entry["kind"] == report_kind)
        assert entry["stats"]["schema"] == "test-value-evidence-compare.v1"
    owner.scan(allowed_root)
    restricted = AssessmentService(owner.state_dir, [allowed_root])

    with pytest.raises(PermissionError):
        restricted.history(old["project_id"], summary=summary)


@pytest.mark.parametrize("summary", [False, True])
def test_saved_history_requires_current_source_root_authority(tmp_path, summary):
    revoked_root = project(tmp_path, "revoked")
    allowed_root = project(tmp_path, "allowed")
    owner = AssessmentService(tmp_path / "state")
    revoked = owner.scan(revoked_root)
    owner.scan(allowed_root)
    restricted = AssessmentService(owner.state_dir, [allowed_root])

    with pytest.raises(PermissionError):
        restricted.history(revoked["project_id"], summary=summary)


def test_composite_reads_keep_one_snapshot_during_concurrent_goal_commit(tmp_path):
    root = project(tmp_path, "project")
    reader = AssessmentService(tmp_path / "state")
    captured = reader.scan(root)
    project_id = captured["project_id"]
    reader.set_targets(project_id, profile="internal-service", expected_revision=0)
    writer = AssessmentService(reader.state_dir)
    # WAL allows a real concurrent commit while the reader retains its snapshot.
    with sqlite3.connect(reader.db_path) as setup:
        assert setup.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"

    with reader._db() as connection:
        before = reader._goals(connection, project_id)
        writer.set_targets(project_id, profile="public-production", expected_revision=1)
        after = reader._goals(connection, project_id)
        assert before["revision"] == after["revision"] == 1

    report = reader.get_report(captured["id"])
    assert report["goals"]["revision"] == report["progress"]["goal_revision"] == 2


def test_edited_preset_goals_retain_origin_without_claiming_the_original_profile(tmp_path):
    root = project(tmp_path, "project")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    goals = {dimension: {"capability_min": 0, "burden_max": 5} for dimension in DIMENSIONS}

    edited = service.set_targets(
        snapshot["project_id"],
        targets=goals,
        profile="sensitive-critical",
        expected_revision=0,
    )
    assert edited["profile"] is None
    assert edited["based_on_profile"] == "sensitive-critical"
    assert edited["targets"] == goals

    unchanged = service.set_targets(
        snapshot["project_id"],
        targets=PROFILES["internal-service"]["targets"],
        profile="internal-service",
        expected_revision=1,
    )
    assert unchanged["profile"] == "internal-service"


def test_reassessing_latest_changed_source_does_not_increase_engineering_credit(tmp_path):
    root = project(tmp_path, "project")
    service = AssessmentService(tmp_path / "state")
    baseline = service.scan(root)
    score(service, baseline, 1)
    service.set_targets(baseline["project_id"], profile="public-production", expected_revision=0)
    (root / "README.md").write_text("# Project\nAn actual source change.\n")
    current = service.scan(root)
    score(service, current, 2)
    first = service.progress(baseline["project_id"])

    score(service, current, 3)
    revised = service.progress(baseline["project_id"])
    assert revised["event"] == "evidence_update"
    assert revised["engineering_progress_steps"] == first["engineering_progress_steps"]
    assert revised["steps_closer"] > first["steps_closer"]
