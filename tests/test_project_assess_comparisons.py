"""Progress and history share comparison semantics without rewriting saved facts."""

import json

import pytest

from project_assess import report_export
from project_assess.service import AssessmentService


def review(service, snapshot, capability=2):
    draft = service.review_template(snapshot["id"])
    draft["coverage"]["scope"] = "focused"
    for rating in draft["ratings"].values():
        rating.update(
            capability=capability,
            burden=2,
            confidence="medium",
            rationale="Synthetic captured-source comparison judgment.",
            evidence_ids=[snapshot["evidence"][0]["id"]],
        )
    return service.submit_review(snapshot["id"], draft)


def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("VALUE = 1\n")
    return root, AssessmentService(tmp_path / "state")


def test_history_retains_source_evidence_and_goal_transition_identity(tmp_path):
    root, service = project(tmp_path)
    first = service.scan(root)
    first_review = review(service, first)
    service.set_targets(first["project_id"], profile="internal-service", expected_revision=0)
    same_source = service.scan(root)
    review(service, same_source, capability=3)
    report = service.get_report(same_source["id"])
    assert report["progress"]["event"] == "evidence_update"
    assert report["progress"]["engineering_progress_steps"] == 0
    assert report["timeline"][0]["comparison"]["event"] == "goal_baseline"
    assert report["timeline"][0]["review_id"] == first_review["id"]
    assert report["timeline"][0]["goal_revision"] == 1
    assert report["timeline"][-1]["comparison"] == {"comparable": True, "event": "evidence_update"}

    (root / "app.py").write_text("VALUE = 2\n")
    changed = service.scan(root)
    review(service, changed, capability=3)
    report = service.get_report(changed["id"])
    assert report["progress"]["event"] == "source_change"
    assert report["timeline"][-1]["comparison"] == {"comparable": True, "event": "source_change"}
    exported = report_export.dimension_map_data(report)["timeline"]
    for actual, saved in zip(exported, report["timeline"], strict=True):
        assert actual["comparison"] == saved["comparison"]
        for key in ("review_id", "rubric_version", "scope_digest", "manifest_digest"):
            assert actual[key] == saved[key]

    review(service, changed, capability=4)
    report = service.get_report(changed["id"])
    assert report["progress"]["event"] == "evidence_update"
    assert report["timeline"][-1]["comparison"]["event"] == "evidence_update"
    service.set_targets(first["project_id"], profile="public-production", expected_revision=1)
    report = service.get_report(changed["id"])
    assert report["progress"]["event"] == "goal_baseline"
    assert report["progress"]["engineering_progress_steps"] == 0
    assert report["timeline"][-1]["goal_revision"] == 2
    assert report["timeline"][-1]["comparison"]["event"] == "goal_baseline"


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope_digest", "different-analysis"),
        ("scope_digest", None),
        ("rubric_version", "legacy"),
        ("complete", False),
        ("manifest_digest", None),
    ],
)
def test_unknown_or_incompatible_history_does_not_claim_comparable_movement(tmp_path, field, value):
    root, service = project(tmp_path)
    first = service.scan(root)
    review(service, first)
    service.set_targets(first["project_id"], profile="internal-service", expected_revision=0)
    # Emulate a partial or legacy saved record; do not invent an engineering change.
    record = json.loads(json.dumps(first))
    if field == "manifest_digest":
        record["source"][field] = value
    else:
        record[field] = value
    with service._db(write=True) as db:
        db.execute("UPDATE assessments SET data=? WHERE id=?", (json.dumps(record), first["id"]))
    (root / "app.py").write_text("VALUE = 2\n")
    latest = service.scan(root)
    review(service, latest, capability=4)
    report = service.get_report(latest["id"])
    assert report["progress"]["comparable"] is False
    assert report["progress"]["engineering_progress_steps"] is None
    assert report["timeline"][-1]["comparison"] == {"comparable": False, "event": "not_comparable"}
    exported = report_export.dimension_map_data(report)["timeline"]
    assert exported[-1]["comparison"] == report["timeline"][-1]["comparison"]
    if field == "rubric_version":
        assert exported[0]["reviewed"] is False
        assert exported[0]["scores"]["testing"] == [None, None]


def test_legacy_export_without_comparison_identity_is_explicitly_unknown(tmp_path):
    _, service = project(tmp_path)
    first = service.scan(tmp_path / "project")
    review(service, first)
    report = service.get_report(first["id"])
    del report["timeline"][0]["comparison"]
    entry = report_export.dimension_map_data(report)["timeline"][0]
    assert entry["scores"]["testing"] == [2, 2]
    assert entry["comparison"] == {"comparable": False, "event": "unknown"}
