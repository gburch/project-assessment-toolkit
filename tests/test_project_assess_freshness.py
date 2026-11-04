"""Capture ordering and access degradation without changing immutable history."""

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from project_assess import service as module
from project_assess.service import AssessmentService, ConflictError


def test_slow_earlier_capture_cannot_replace_later_capture(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "app.py"
    source.write_text("value = 1\n")
    service = AssessmentService(tmp_path / "state")
    collect = module.collect
    captured, finish = Event(), Event()

    def delayed(*args, **kwargs):
        snapshot = collect(*args, **kwargs)
        if not captured.is_set():
            captured.set()
            assert finish.wait(10)
        return snapshot

    monkeypatch.setattr(module, "collect", delayed)
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(service.scan, root)
        assert captured.wait(10)
        source.write_text("value = 2\n")
        second = service.scan(root)
        finish.set()
        first = first.result(timeout=10)
    assert first["created_at"] < second["created_at"]
    assert first["collection"]["completed_at"] > second["collection"]["completed_at"]
    assert service.list_projects()[0]["latest_assessment_id"] == second["id"]
    assert service.get_report(first["id"])["assessment"] == first
    with pytest.raises(ConflictError, match="stale"):
        service.submit_review(first["id"], service.review_template(first["id"]))
    goals = service.set_targets(
        second["project_id"], profile="internal-service", expected_revision=0
    )
    assert goals["baseline_assessment_id"] == second["id"]


def test_revoked_old_import_does_not_block_current_report_or_change_goals(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    private = tmp_path / "private"
    private.mkdir()
    report = private / "results.xml"
    report.write_text('<testsuite><testcase name="secret-case"/></testsuite>')
    owner = AssessmentService(tmp_path / "state")
    old = owner.scan(root, [report])
    goals = owner.set_targets(old["project_id"], profile="internal-service", expected_revision=0)
    current = owner.scan(root)
    restricted = AssessmentService(owner.state_dir, [root])
    with pytest.raises(PermissionError):
        restricted.get_report(old["id"])
    result = restricted.get_report(current["id"])
    assert result["goals"] == goals
    assert result["progress"]["event"] == "comparison_unavailable"
    assert result["goal_alignment"]["comparison_unavailable"]
    assert str(private) not in json.dumps(result)
    assert "secret-case" not in json.dumps(result)
    assert restricted.overview(current["id"])["assessment_id"] == current["id"]
    assert restricted.evolve(current["id"])["assessment_id"] == current["id"]


def test_live_report_defers_large_evidence_without_mutating_saved_data(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    with service._db(write=True) as db:
        snapshot["evidence"][0]["stats"]["large_detail"] = ["UNOPENED_DETAIL"] * 200000
        db.execute(
            "UPDATE assessments SET data=? WHERE id=?", (json.dumps(snapshot), snapshot["id"])
        )
    full = service.get_report(snapshot["id"])
    compact = service.get_report(snapshot["id"], compact=True)
    assert len(json.dumps(full)) > 3_000_000
    assert len(json.dumps(compact)) < 200_000
    assert "UNOPENED_DETAIL" not in json.dumps(compact)
    assert compact["details_deferred"]
    assert all(entry["details_deferred"] for entry in compact["assessment"]["evidence"])
    assert service.evidence(snapshot["id"], snapshot["evidence"][0]["id"])["stats"]["large_detail"]
