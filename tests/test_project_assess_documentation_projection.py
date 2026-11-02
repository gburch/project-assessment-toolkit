import hashlib
import json
import sqlite3
from copy import deepcopy

import pytest

from project_assess.documentation import maintenance_candidates
from project_assess.service import AssessmentService


def test_query_and_doctor_share_captured_documentation_leads_without_rescan(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    guide = root / "README.md"
    guide.write_text("# Setup\nRun `npm run retired-check`.\npassword = synthetic-example\n")
    (root / "package.json").write_text(json.dumps({"scripts": {"build": "build"}}))
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    sources = {entry["path"]: entry for entry in snapshot["evidence"]}
    before = service.history(snapshot["project_id"])
    guide.write_text("# Changed after capture\n")

    def no_rescan(*_args, **_kwargs):
        raise AssertionError("Diagnosis must use the saved snapshot")

    monkeypatch.setattr("project_assess.service.collect", no_rescan)
    query = service.query_evidence(snapshot["id"], view="candidates", kind="documentation-analysis")
    queried = next(
        row for row in query["items"] if row["kind"] == "documented_script_mismatch_hint"
    )
    diagnosis = service.doctor(snapshot["id"])
    diagnosed = next(
        row
        for rows in diagnosis["groups"].values()
        for row in rows
        if row["kind"] == "documented_script_mismatch_hint"
    )
    assert diagnosed["locations"] == queried["locations"]
    assert diagnosed["metrics"] == queried["metrics"]
    assert queried["source_identity"] == diagnosed["source_identity"] == "captured_snapshot"
    assert {location["path"] for location in queried["locations"]} == {"README.md", "package.json"}
    for location in queried["locations"]:
        captured = sources[location["path"]]
        assert location["source_evidence_id"] == captured["id"]
        assert location["source_digest"] == captured["digest"]
    assert (
        sources["README.md"]["digest"] != "sha256:" + hashlib.sha256(guide.read_bytes()).hexdigest()
    )
    assert queried["confidence"] == "low"
    assert diagnosed["candidate_confidence"] == {
        "level": "low",
        "basis": "captured_text",
        "defect_established": False,
        "change_safety": "requires_review",
    }
    assert set(diagnosed["evidence_ids"]) == {
        queried["evidence_id"],
        *queried["source_evidence_ids"],
    }
    assert (
        service.query_evidence(
            snapshot["id"],
            view="candidates",
            kind="documentation-analysis",
            candidate_kind="documented_script_mismatch_hint",
            path="package.json",
            line=1,
        )["matched"]
        == 1
    )
    assert query["documentation_scope"]["collection_status"] == "collected"
    assert service.history(snapshot["project_id"]) == before
    assert guide.read_text() == "# Changed after capture\n"


def test_documentation_family_survives_other_candidates_and_retains_collection_omissions(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text(
        "Canonical setup: `docs/old.md`\n" + "\n".join(f"`src/gone{n}.py`" for n in range(250))
    )
    (root / "AGENTS.md").write_text(
        "Canonical setup: `docs/current.md`\nRun `npm run retired-check`.\n"
    )
    (root / "docs").mkdir()
    (root / "docs/current.md").write_text("# Current setup\n")
    (root / "docs/old.md").write_text("# Other setup\n")
    (root / "package.json").write_text(json.dumps({"scripts": {"build": "build"}}))
    (root / "app.py").write_text(
        "".join(
            f"def classify_{n}(value):\n    result = 0\n"
            + "".join(f"    if value > {branch}:\n        result += 1\n" for branch in range(11))
            + "    return result\n\n"
            for n in range(70)
        )
    )
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    diagnosis = service.doctor(snapshot["id"], limit=30)
    rows = [row for group in diagnosis["groups"].values() for row in group]
    docs = [row for row in rows if row["family"] == "documentation"]
    assert len(rows) == 30
    assert any(row["kind"] == "documented_script_mismatch_hint" for row in docs)
    assert any(row["kind"] == "competing_authority_targets_hint" for row in docs)
    assert any(row["family"] == "python_ast" for row in rows)
    assert diagnosis["selection"]["families"]["documentation"]["omitted"] > 0
    scope = diagnosis["analysis_scope"]["documentation"]
    assert scope["collection_status"] == "partial"
    assert scope["analysis"][0]["coverage"]["maintenanceLeadsOmitted"] > 0
    query = service.query_evidence(snapshot["id"], view="candidates", kind="documentation-analysis")
    assert query["documentation_scope"]["collection_status"] == scope["collection_status"]
    assert query["documentation_scope"]["details_view"] == "coverage"
    coverage = service.query_evidence(
        snapshot["id"], view="coverage", kind="documentation-analysis"
    )
    assert coverage["items"][0]["coverage"]["maintenanceLeadsOmitted"] > 0
    assert diagnosis["status"] == "partial"
    assert service.history(snapshot["project_id"])["reviews"] == []


def test_documentation_projection_rejects_incompatible_identities_and_preserves_hint_meaning():
    source = {"id": "source", "kind": "documentation", "digest": "sha256:current"}
    lead = {
        "kind": "documented_path_unresolved_hint",
        "locations": [{"path": "AGENTS.md", "line": 2}],
        "metrics": {"status": "not_in_inspected_inventory", "basis": "membership is not existence"},
    }
    entry = {"stats": {"schema": "doc-value.captured.v2", "maintenanceLeads": [lead]}}
    sources = {"AGENTS.md": source}
    valid = maintenance_candidates(entry, sources)
    assert valid["candidates"][0]["metrics"] == lead["metrics"]
    for incompatible in (
        {"source_evidence_id": "other"},
        {"source_digest": "sha256:old"},
        {"path": "outside.md"},
    ):
        changed = deepcopy(entry)
        changed["stats"]["maintenanceLeads"][0]["locations"][0].update(incompatible)
        projected = maintenance_candidates(changed, sources)
        assert projected["candidates"] == []
        assert projected["status"] == "partial" and projected["omitted"] == 1
        assert projected["gaps"]
    assert entry["stats"]["maintenanceLeads"][0] == lead


def test_legacy_documentation_remains_queryable_without_claiming_collected_candidates(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# Setup\n`src/missing.py`\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    for entry in snapshot["evidence"]:
        if entry["kind"] == "documentation-analysis":
            entry["stats"]["schema"] = "doc-value.captured.v1"
            del entry["stats"]["maintenanceLeads"]
    with sqlite3.connect(service.db_path) as db:
        db.execute(
            "UPDATE assessments SET data=? WHERE id=?", (json.dumps(snapshot), snapshot["id"])
        )
    before = service.history(snapshot["project_id"])
    query = service.query_evidence(snapshot["id"], view="candidates", kind="documentation-analysis")
    assert query["items"] == []
    assert query["documentation_scope"]["projections"][0]["status"] == "not_collected"
    diagnosis = service.doctor(snapshot["id"])
    assert diagnosis["status"] == "partial"
    assert (
        diagnosis["analysis_scope"]["documentation"]["projections"][0]["status"] == "not_collected"
    )
    assert service.history(snapshot["project_id"]) == before


@pytest.mark.parametrize("kind", [None, "documentation-analysis", "static-analysis"])
def test_documentation_candidate_metadata_preserves_minimum_budget_pagination(tmp_path, kind):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "README.md").write_text("# Setup\n`src/missing.py`\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    offset = visited = 0
    while True:
        page = service.query_evidence(
            snapshot["id"], view="candidates", kind=kind, offset=offset, max_chars=2000
        )
        assert len(json.dumps(page, indent=2)) <= 2000
        if kind == "static-analysis":
            assert "documentation_scope" not in page
        visited += page["returned"]
        if page["next_offset"] is None:
            break
        assert page["next_offset"] > offset
        offset = page["next_offset"]
    assert visited == page["matched"]
