import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from project_assess.rubric import DIMENSIONS, PROFILES
from project_assess.service import AssessmentService, ConflictError, markdown_report


@pytest.fixture
def assessed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# Project\nRun checks with pytest.\n")
    (root / "app.py").write_text("def add(a, b):\n    return a + b\n")
    service = AssessmentService(tmp_path / "state")
    return service, root, service.scan(root)


def reviewed(service, snapshot, capability=2, burden=1):
    review = service.review_template(snapshot["id"])
    for rating in review["ratings"].values():
        rating.update(
            capability=capability,
            burden=burden,
            confidence="medium",
            rationale="Fixture reviewer interpretation of captured evidence.",
            evidence_ids=[snapshot["evidence"][0]["id"]],
        )
    return service.submit_review(snapshot["id"], review)


def test_facts_remain_immutable_and_absent_review_is_unknown(assessed):
    service, root, snapshot = assessed
    before = json.loads(json.dumps(snapshot))
    report = service.get_report(snapshot["id"])
    assert report["review"] is None and report["goals"] is None
    assert report["progress"]["event"] == "no_goals"
    reviewed(service, snapshot)
    assert service.get_report(snapshot["id"])["assessment"] == before
    rendered = markdown_report(service.get_report(snapshot["id"]))
    assert "| testing | 2 | 1 (estimated from source; low confidence) | medium |" in rendered
    assert {p.name for p in root.iterdir()} == {"app.py", "README.md"}


def test_badge_keeps_selected_snapshot_review_and_ignores_goal_changes(assessed):
    service, root, old = assessed
    reviewed(service, old, capability=2, burden=1)
    old_badge = service.get_badge(old["id"], "testing", format="json")
    (root / "app.py").write_text("def add(a, b):\n    return sum((a, b))\n")
    current = service.scan(root)
    reviewed(service, current, capability=4, burden=3)
    service.set_targets(current["project_id"], profile="public-production", expected_revision=0)
    assert service.get_badge(old["id"], "testing", format="json") == old_badge
    assert "C2/5 B1/5" in old_badge["message"]
    assert "C4/5 B3/5" in service.get_badge(current["id"], "testing", format="json")["message"]
    with pytest.raises(ValueError, match="format"):
        service.get_badge(current["id"], format="html")


def test_scan_persists_safe_test_value_evidence_and_keeps_claims_unrated(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    report = root / "test-value.json"
    report.write_text(
        json.dumps(
            {
                "schema": "test-value-evidence-compare.v1",
                "root": str(root),
                "inputs": [],
                "tests": [{"nodeid": "private-name", "outcome": "passed"}],
                "gaps": [],
                "healthyCollection": True,
                "confidentOverlap": True,
            }
        )
    )
    service = AssessmentService(tmp_path / "state", allowed_roots=[root])
    snapshot = service.scan(root, reports=[report])
    evidence = service.evidence(snapshot["id"])
    item = next(entry for entry in evidence if entry["kind"] == "test-value")
    assert item["stats"]["schema"] == "test-value-evidence-compare.v1"
    assert item["stats"]["claims"]["healthyCollection"] is True
    assert item["stats"]["claims"]["assessmentComplete"] is False
    assert "private-name" not in json.dumps(service.get_report(snapshot["id"]))


@pytest.mark.parametrize(
    "change", ["stale_digest", "foreign_evidence", "missing_citation", "bool", "extra", "fraction"]
)
def test_rejects_invalid_or_uncited_judgments(assessed, change):
    service, _, snapshot = assessed
    review = service.review_template(snapshot["id"])
    rating = review["ratings"]["testing"]
    rating.update(capability=2, evidence_ids=[snapshot["evidence"][0]["id"]])
    if change == "stale_digest":
        review["source_digest"] = "wrong"
    elif change == "foreign_evidence":
        rating["evidence_ids"] = ["foreign"]
    elif change == "missing_citation":
        rating["evidence_ids"] = []
    elif change == "bool":
        rating["capability"] = True
    elif change == "fraction":
        rating["capability"] = 2.4
    else:
        review["facts"] = {"invented": 999}
    with pytest.raises(ValueError):
        service.submit_review(snapshot["id"], review)
    assert not service.history(snapshot["project_id"])["reviews"]


def test_stale_review_cannot_override_new_scan(assessed):
    service, root, snapshot = assessed
    service.scan(root)
    with pytest.raises(ConflictError, match="stale"):
        service.submit_review(snapshot["id"], service.review_template(snapshot["id"]))


def test_capability_above_minimum_is_not_overinvestment_and_burden_can_improve(assessed):
    service, root, snapshot = assessed
    reviewed(service, snapshot, 3, 4)
    service.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)
    (root / "app.py").write_text(
        'def add(a, b):\n    """Keep the useful behavior."""\n    return a + b\n'
    )
    current = service.scan(root)
    reviewed(service, current, 3, 1)
    progress = service.progress(snapshot["project_id"])
    assert progress["event"] == "source_change"
    assert progress["remaining_steps"] == 0
    assert progress["engineering_progress_steps"] == len(DIMENSIONS) * 2
    assert all(
        v["capability_gap"] == 0 and v["burden_steps"] == 2 for v in progress["dimensions"].values()
    )


def test_retargeting_and_same_source_review_are_not_engineering_progress(assessed):
    service, _, snapshot = assessed
    reviewed(service, snapshot, 1, 4)
    service.set_targets(snapshot["project_id"], profile="public-production", expected_revision=0)
    reviewed(service, snapshot, 3, 1)
    evidence_update = service.progress(snapshot["project_id"])
    assert evidence_update["event"] == "evidence_update"
    assert evidence_update["steps_closer"] > 0
    assert evidence_update["engineering_progress_steps"] == 0
    goals = service.set_targets(
        snapshot["project_id"], profile="local-experiment", expected_revision=1
    )
    progress = service.progress(snapshot["project_id"])
    assert goals["engineering_progress_steps"] == 0
    assert progress["event"] == "goal_baseline" and progress["steps_closer"] == 0
    history = service.history(snapshot["project_id"])
    assert len(history["reviews"]) == 2 and len(history["goals"]) == 2


def test_unknown_components_never_become_zero(assessed):
    service, _, snapshot = assessed
    reviewed(service, snapshot, capability=2, burden=None)
    service.set_targets(snapshot["project_id"], profile="public-production", expected_revision=0)
    progress = service.progress(snapshot["project_id"])
    assert progress["remaining_steps"] is None and progress["steps_closer"] is None
    assert progress["dimensions"]["testing"]["burden_gap"] is None
    assert progress["dimensions"]["testing"]["capability_gap"] == 1


def test_incompatible_scope_has_no_comparable_progress(assessed, monkeypatch):
    service, root, snapshot = assessed
    reviewed(service, snapshot)
    service.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)
    import project_assess.service as module

    original = module.collect

    def changed_scope(*args, **kwargs):
        result = original(*args, **kwargs)
        result["scope_digest"] = "new-methodology"
        return result

    monkeypatch.setattr(module, "collect", changed_scope)
    current = service.scan(root)
    reviewed(service, current)
    progress = service.progress(snapshot["project_id"])
    assert not progress["comparable"] and progress["event"] == "not_comparable"
    assert progress["engineering_progress_steps"] is None


def test_source_supported_burden_estimates_are_kept_and_qualified(assessed):
    service, _, snapshot = assessed
    review = service.review_template(snapshot["id"])
    review["ratings"]["documentation"].update(
        capability=3,
        burden=3,
        burden_basis="source_estimate",
        burden_confidence="medium",
        confidence="high",
        rationale="Three entrypoints repeat the same current-status block, requiring coordinated edits; upkeep is estimated from source, not measured hours.",
        evidence_ids=[snapshot["evidence"][0]["id"]],
    )
    saved = service.submit_review(snapshot["id"], review)
    rating = saved["ratings"]["documentation"]
    assert rating["burden"] == 3 and rating["burden_basis"] == "source_estimate"
    assert rating["confidence"] == "high" and rating["burden_confidence"] == "medium"
    assert saved["ratings"]["operability"]["burden"] is None
    service.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)
    progress = service.progress(snapshot["project_id"])
    assert progress["dimensions"]["documentation"]["burden_gap"] == 1
    assert progress["provisional"]


def test_old_review_clients_do_not_imply_measured_burden(assessed):
    service, _, snapshot = assessed
    review = service.review_template(snapshot["id"])
    for rating in review["ratings"].values():
        rating.pop("burden_basis", None)
        rating.pop("burden_confidence", None)
        rating.update(burden=2, evidence_ids=[snapshot["evidence"][0]["id"]])
    saved = service.submit_review(snapshot["id"], review)
    assert all(
        r["burden_basis"] == "source_estimate" and r["burden_confidence"] == "low"
        for r in saved["ratings"].values()
    )


def test_observed_burden_metadata_and_unknown_remain_distinct(assessed):
    service, _, snapshot = assessed
    review = service.review_template(snapshot["id"])
    review["ratings"]["testing"].update(
        burden=2,
        burden_basis="observed",
        burden_confidence="high",
        rationale="Reviewer-supplied direct observation scoped to its evidence; validation does not certify the judgment.",
        evidence_ids=[snapshot["evidence"][0]["id"]],
    )
    saved = service.submit_review(snapshot["id"], review)
    assert saved["ratings"]["testing"]["burden_basis"] == "observed"
    assert saved["ratings"]["operability"]["burden_basis"] == "unknown"
    assert saved["ratings"]["operability"]["burden"] is None


def test_concurrent_goal_updates_one_wins_and_replay_is_idempotent(assessed):
    service, _, snapshot = assessed
    project = snapshot["project_id"]

    def save(_):
        try:
            return service.set_targets(project, profile="internal-service", expected_revision=0)
        except ConflictError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, range(2)))
    assert sum(r is not None for r in results) == 1
    kwargs = dict(profile="public-production", expected_revision=1, request_id="save-once")
    first = service.set_targets(project, **kwargs)
    assert service.set_targets(project, **kwargs) == first
    assert len(service.history(project)["goals"]) == 2
    with pytest.raises(ConflictError):
        service.set_targets(
            project, profile="local-experiment", expected_revision=1, request_id="save-once"
        )


def test_transactions_roll_back_interrupted_save_and_survive_reopen(assessed, monkeypatch):
    service, _, snapshot = assessed
    original = service._record_request

    def interrupted(*_):
        raise RuntimeError("interrupted before commit")

    monkeypatch.setattr(service, "_record_request", interrupted)
    with pytest.raises(RuntimeError):
        service.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)
    monkeypatch.setattr(service, "_record_request", original)
    reopened = AssessmentService(service.state_dir)
    assert reopened.history(snapshot["project_id"])["goals"] == []
    reopened.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)


def test_state_and_allowed_roots_are_enforced_before_access(assessed, tmp_path):
    service, root, snapshot = assessed
    with pytest.raises(ValueError, match="outside"):
        AssessmentService(root / "state", allowed_roots=[root])
    assert not (root / "state").exists()
    other = tmp_path / "other"
    other.mkdir()
    restricted = AssessmentService(service.state_dir, allowed_roots=[other])
    assert restricted.list_projects() == []
    with pytest.raises(PermissionError):
        restricted.get_report(snapshot["id"])
    with pytest.raises(PermissionError):
        restricted.scan(root)
    link = other / "escape"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(PermissionError):
        restricted.scan(link)


def test_profiles_are_optional_and_do_not_hide_critical_findings(assessed):
    service, _, snapshot = assessed
    review = service.review_template(snapshot["id"])
    review["findings"] = [
        {
            "severity": "critical",
            "title": "Fixture unresolved risk",
            "evidence_ids": [snapshot["evidence"][0]["id"]],
        }
    ]
    service.submit_review(snapshot["id"], review)
    service.set_targets(snapshot["project_id"], PROFILES["local-experiment"]["targets"], 0)
    report = service.get_report(snapshot["id"])
    assert report["review"]["findings"][0]["severity"] == "critical"
    assert "Fixture unresolved risk" in markdown_report(report)


@pytest.fixture
def legacy_six_dimension_state(assessed):
    service, root, snapshot = assessed
    reviewed(service, snapshot, capability=3, burden=1)
    service.set_targets(snapshot["project_id"], profile="internal-service", expected_revision=0)
    stored = {}
    with sqlite3.connect(service.db_path) as db:
        for table in ("assessments", "reviews", "goals"):
            row_id, raw = db.execute(f"SELECT rowid,data FROM {table}").fetchone()
            document = json.loads(raw)
            if table == "assessments":
                document["rubric_version"] = "3"
                document["scope_digest"] = "legacy-six-dimension-scope"
            elif table == "reviews":
                document["rubric_version"] = "3"
                document["ratings"].pop("extensibility")
            else:
                document["targets"].pop("extensibility")
            db.execute(f"UPDATE {table} SET data=? WHERE rowid=?", (json.dumps(document), row_id))
            stored[table] = document
    return service, root, stored


def test_legacy_six_dimension_history_reads_without_inventing_a_seventh_target(
    legacy_six_dimension_state,
):
    service, _, stored = legacy_six_dimension_state
    snapshot, old_review, old_goals = (stored[name] for name in ("assessments", "reviews", "goals"))
    with sqlite3.connect(service.db_path) as db:
        before = {
            table: db.execute(f"SELECT data FROM {table}").fetchall()
            for table in ("assessments", "reviews", "goals")
        }

    report = service.get_report(snapshot["id"])
    history = service.history(snapshot["project_id"])
    progress = service.progress(snapshot["project_id"])

    assert report["assessment"] == snapshot
    assert report["review"] == old_review
    assert report["goals"] == old_goals
    assert "extensibility" not in report["review"]["ratings"]
    assert "extensibility" not in report["goals"]["targets"]
    assert history["assessments"] == [snapshot]
    assert history["reviews"] == [old_review]
    assert history["goals"] == [old_goals]
    assert progress["missing_targets"] == ["extensibility"]
    assert not progress["comparable"] and progress["event"] == "not_comparable"
    assert progress["dimensions"]["extensibility"]["capability_gap"] is None
    assert progress["dimensions"]["extensibility"]["burden_gap"] is None
    assert progress["remaining_steps"] is None and progress["steps_closer"] is None
    with sqlite3.connect(service.db_path) as db:
        after = {
            table: db.execute(f"SELECT data FROM {table}").fetchall()
            for table in ("assessments", "reviews", "goals")
        }
    assert after == before


def test_legacy_targets_require_an_explicit_seventh_choice_and_preserve_prior_history(
    legacy_six_dimension_state,
):
    service, _, stored = legacy_six_dimension_state
    project_id = stored["assessments"]["project_id"]
    with pytest.raises(ValueError, match="extensibility"):
        service.set_targets(project_id, stored["goals"]["targets"], expected_revision=1)
    assert service.history(project_id)["goals"] == [stored["goals"]]

    selected = service.set_targets(project_id, profile="framework", expected_revision=1)

    assert selected["revision"] == 2
    assert selected["targets"]["extensibility"] == {"capability_min": 4, "burden_max": 2}
    assert service.history(project_id)["goals"] == [stored["goals"], selected]
    assert service.get_report(stored["assessments"]["id"])["review"] == stored["reviews"]


def test_new_extensibility_review_stays_unknown_until_explicitly_assessed(assessed):
    service, _, snapshot = assessed
    template = service.review_template(snapshot["id"])
    assert set(template["ratings"]) == set(DIMENSIONS)
    for dimension, rating in template["ratings"].items():
        if dimension != "extensibility":
            rating.update(
                capability=3,
                burden=1,
                confidence="medium",
                rationale="Fixture source supports this dimension; extension needs remain unassessed.",
                evidence_ids=[snapshot["evidence"][0]["id"]],
            )
    review = service.submit_review(snapshot["id"], template)
    service.set_targets(snapshot["project_id"], profile="framework", expected_revision=0)
    report = service.get_report(snapshot["id"])
    assert review["ratings"]["extensibility"]["capability"] is None
    assert review["ratings"]["extensibility"]["burden"] is None
    assert report["progress"]["dimensions"]["extensibility"]["capability_gap"] is None
    assert report["progress"]["remaining_steps"] is None


def test_two_projects_keep_distinct_extension_goals_without_penalizing_high_capability(
    assessed, tmp_path
):
    service, _, first = assessed
    second_root = tmp_path / "second-project"
    second_root.mkdir()
    (second_root / "README.md").write_text("# Second project\nA bounded converter.\n")
    second = service.scan(second_root)
    for snapshot, extension_capability in ((first, 5), (second, 2)):
        review = service.review_template(snapshot["id"])
        for dimension, rating in review["ratings"].items():
            rating.update(
                capability=extension_capability if dimension == "extensibility" else 3,
                burden=1,
                confidence="medium",
                rationale="Fixture reviewer distinguishes demonstrated capability from upkeep cost.",
                evidence_ids=[snapshot["evidence"][0]["id"]],
            )
        service.submit_review(snapshot["id"], review)
    first_goals = service.set_targets(first["project_id"], profile="framework", expected_revision=0)
    custom = deepcopy(first_goals["targets"])
    custom["extensibility"] = {"capability_min": 2, "burden_max": 1}
    service.set_targets(second["project_id"], custom, expected_revision=0)

    for project_id in (first["project_id"], second["project_id"]):
        progress = service.progress(project_id)
        assert progress["dimensions"]["extensibility"]["capability_gap"] == 0
        assert progress["dimensions"]["extensibility"]["burden_gap"] == 0
        assert progress["remaining_steps"] == 0
    assert service.get_report(first["id"])["goals"] == first_goals
    assert (
        service.get_report(second["id"])["goals"]["targets"]["extensibility"]
        == custom["extensibility"]
    )


def test_prototype_can_choose_no_extension_requirement_without_adding_frameworks(assessed):
    service, root, snapshot = assessed
    source_before = {path.name: path.read_bytes() for path in root.iterdir()}
    review = service.review_template(snapshot["id"])
    rating = review["ratings"]["extensibility"]
    assert rating["capability"] is None and rating["burden"] is None
    rating.update(
        capability=0,
        burden=0,
        confidence="medium",
        rationale="A single local converter has no selected extension requirement or plugin upkeep.",
        evidence_ids=[snapshot["evidence"][0]["id"]],
    )
    service.submit_review(snapshot["id"], review)
    goals = service.set_targets(
        snapshot["project_id"], profile="local-experiment", expected_revision=0
    )
    assert goals["targets"]["extensibility"] == {"capability_min": 0, "burden_max": 1}
    progress = service.progress(snapshot["project_id"])
    assert progress["dimensions"]["extensibility"]["capability_gap"] == 0
    assert progress["dimensions"]["extensibility"]["burden_gap"] == 0
    assert {path.name: path.read_bytes() for path in root.iterdir()} == source_before


def test_doctor_uses_saved_static_candidates_without_rescan_or_state_changes(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "app.py"
    source.write_text(
        "def first(value):\n    total = value + 1\n    doubled = total * 2\n    return doubled - value\n"
        "\ndef second(value):\n    total = value + 1\n    doubled = total * 2\n    return doubled - value\n"
        "\ndef load(paths):\n    values = []\n    for path in paths:\n        values.append(path.read_text())\n    return values\n"
        "\ndef classify(value):\n    score = 0\n"
        + "".join(f"    if value > {number}:\n        score += 1\n" for number in range(11))
        + "    return score\n"
    )
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root)
    source.write_text("raise RuntimeError('the changed assessed source must not run')\n")
    current_source = source.read_bytes()
    before = service.history(captured["project_id"])
    with sqlite3.connect(service.db_path) as db:
        request_rows = db.execute("SELECT * FROM requests").fetchall()

    def forbid_rescan(*_args, **_kwargs):
        raise AssertionError("Doctor must use its captured snapshot")

    monkeypatch.setattr("project_assess.service.collect", forbid_rescan)
    diagnosis = service.doctor(captured["id"])

    assert diagnosis["status"] == "complete"
    assert diagnosis["source"] == captured["source"]
    assert diagnosis["assessment_id"] == captured["id"]
    assert {candidate["kind"] for candidate in diagnosis["groups"]["reuse"]} >= {
        "duplicate_function"
    }
    assert {candidate["kind"] for candidate in diagnosis["groups"]["quality"]} >= {
        "complex_function"
    }
    assert {candidate["kind"] for candidate in diagnosis["groups"]["efficiency"]} >= {"loop_io"}
    evidence_ids = {entry["id"] for entry in captured["evidence"]}
    for candidates in diagnosis["groups"].values():
        for candidate in candidates:
            assert candidate["evidence_ids"] and set(candidate["evidence_ids"]) <= evidence_ids
            assert candidate["source_identity"] == "captured_snapshot"
            assert candidate["smallest_fix"] and candidate["verification"]
            assert all(
                location["path"] == "app.py" and location["line"] > 0
                for location in candidate["locations"]
            )
    assert "ratings" not in diagnosis
    summary = captured["facts"]["static_analysis"]
    rendered = markdown_report(service.get_report(captured["id"]))
    static_paragraph = next(
        paragraph for paragraph in rendered.split("\n\n") if summary["evidence_id"] in paragraph
    )
    assert summary["status"] in static_paragraph
    assert (
        f"{summary['coverage']['parsed_files']}/{summary['coverage']['python_files']}"
        in static_paragraph
    )
    assert str(summary["summary"]["candidate_count"]) in static_paragraph
    assert service.get_report(captured["id"])["review"] is None
    assert source.read_bytes() == current_source
    assert service.history(captured["project_id"]) == before
    with sqlite3.connect(service.db_path) as db:
        assert db.execute("SELECT * FROM requests").fetchall() == request_rows


def test_legacy_doctor_reports_missing_analysis_without_read_time_migration(assessed):
    service, _, captured = assessed
    captured["evidence"] = [
        entry
        for entry in captured["evidence"]
        if entry["kind"] not in {"static-analysis", "test-value-static-analysis"}
    ]
    captured["facts"].pop("static_analysis", None)
    captured["facts"].pop("test_value_static", None)
    raw = json.dumps(captured)
    with sqlite3.connect(service.db_path) as db:
        db.execute("UPDATE assessments SET data=? WHERE id=?", (raw, captured["id"]))

    diagnosis = service.doctor(captured["id"])

    assert diagnosis["status"] == "not_collected"
    assert diagnosis["groups"] == {"reuse": [], "quality": [], "efficiency": []}
    assert any("rescan" in gap.lower() for gap in diagnosis["gaps"])
    assert service.get_report(captured["id"])["review"] is None
    with sqlite3.connect(service.db_path) as db:
        assert (
            db.execute("SELECT data FROM assessments WHERE id=?", (captured["id"],)).fetchone()[0]
            == raw
        )
        assert db.execute("SELECT COUNT(*) FROM goals").fetchone()[0] == 0


def test_ecosystem_fit_projects_captured_source_without_grades_or_new_reads(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0.0.0"\ndependencies = ["requests>=2"]\n'
    )
    source = root / "app.py"
    source.write_text(
        "from http.server import BaseHTTPRequestHandler\nimport sqlite3\n"
        "raise RuntimeError('scan must not execute the project')\n"
    )
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root)
    summary = captured["facts"]["ecosystem_fit"]
    evidence = next(row for row in captured["evidence"] if row["id"] == summary["evidence_id"])
    history = service.history(captured["project_id"])
    source.write_text("# Syntax changed after capture\n")

    def forbid_rescan(*_args, **_kwargs):
        raise AssertionError("report and doctor must use captured ecosystem evidence")

    monkeypatch.setattr("project_assess.service.collect", forbid_rescan)
    diagnosis = service.doctor(captured["id"])
    ecosystem = diagnosis["ecosystem_fit"]
    assert ecosystem["evidence_id"] == evidence["id"]
    assert ecosystem["dependencies"] == evidence["stats"]["dependencies"]
    assert any(row["name"] == "requests" for row in ecosystem["dependencies"])
    assert {row["kind"] for row in ecosystem["signals"]} >= {
        "stdlib_http_server",
        "stdlib_sqlite",
    }
    candidates = [
        row for row in diagnosis["groups"]["reuse"] if row["kind"] == "ecosystem_fit_review"
    ]
    assert candidates
    source_id = next(row["id"] for row in captured["evidence"] if row["path"] == "app.py")
    for candidate in candidates:
        assert set(candidate["evidence_ids"]) == {evidence["id"], source_id}
        assert candidate["locations"][0]["path"] == "app.py"
        assert candidate["locations"][0]["line"] > 0
        assert "retain the current approach" in candidate["smallest_fix"]
        assert candidate["source_identity"] == "captured_snapshot"
    report = service.get_report(captured["id"])
    assert report["review"] is None and report["goals"] is None
    assert "ratings" not in diagnosis
    rendered = markdown_report(report)
    assert "## Ecosystem fit" in rendered
    assert "requests" in rendered and "stdlib\\_http\\_server" in rendered
    assert "Collection limits:" in rendered and summary["evidence_id"] in rendered
    assert "not a fit rating or a migration recommendation" in rendered
    assert source.read_text() == "# Syntax changed after capture\n"
    assert service.history(captured["project_id"]) == history


def test_ecosystem_doctor_keeps_source_leads_visible_among_many_test_signals(tmp_path):
    root = tmp_path / "project"
    (root / "tests").mkdir(parents=True)
    (root / "tests/test_dom.js").write_text("document.createElement('p');\n" * 15)
    (root / "z_app.py").write_text("from http.server import HTTPServer\n")
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root)
    candidates = [
        row
        for row in service.doctor(captured["id"])["groups"]["reuse"]
        if row["kind"] == "ecosystem_fit_review"
    ]
    assert len(candidates) == 16
    assert candidates[0]["locations"][0]["path"] == "z_app.py"
    assert candidates[0]["metrics"]["scope"] == "source"


def test_legacy_ecosystem_fit_stays_not_collected_without_migration(assessed):
    service, _, snapshot = assessed
    snapshot["facts"].pop("ecosystem_fit", None)
    snapshot["evidence"] = [
        row for row in snapshot["evidence"] if row["kind"] != "ecosystem-analysis"
    ]
    raw = json.dumps(snapshot)
    with sqlite3.connect(service.db_path) as db:
        db.execute("UPDATE assessments SET data=? WHERE id=?", (raw, snapshot["id"]))

    diagnosis = service.doctor(snapshot["id"])
    assert diagnosis["ecosystem_fit"]["status"] == "not_collected"
    assert "rescan" in diagnosis["ecosystem_fit"]["gaps"][0]
    assert "Collection: not_collected." in markdown_report(service.get_report(snapshot["id"]))
    assert service.get_report(snapshot["id"])["review"] is None
    with sqlite3.connect(service.db_path) as db:
        assert (
            db.execute("SELECT data FROM assessments WHERE id=?", (snapshot["id"],)).fetchone()[0]
            == raw
        )
        assert db.execute("SELECT COUNT(*) FROM goals").fetchone()[0] == 0


def test_ecosystem_markdown_escapes_hostile_source_paths(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "<img src=x onerror=window.pwned=1>.py").write_text("import sqlite3\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)

    rendered = markdown_report(service.get_report(snapshot["id"]))
    assert "&lt;img src=x onerror=window.pwned=1&gt;.py" in rendered
    assert "<img src=x" not in rendered


@pytest.mark.parametrize("change", ["summary_version", "evidence_version", "missing_reference"])
def test_ecosystem_fit_refuses_unsupported_or_missing_captured_evidence(assessed, change):
    service, _, snapshot = assessed
    if change == "summary_version":
        snapshot["facts"]["ecosystem_fit"]["schema_version"] = 99
    elif change == "missing_reference":
        snapshot["facts"]["ecosystem_fit"]["evidence_id"] = "missing"
    else:
        next(row for row in snapshot["evidence"] if row["kind"] == "ecosystem-analysis")["stats"][
            "schema_version"
        ] = 99
    raw = json.dumps(snapshot)
    with sqlite3.connect(service.db_path) as db:
        db.execute("UPDATE assessments SET data=? WHERE id=?", (raw, snapshot["id"]))

    diagnosis = service.doctor(snapshot["id"])
    assert diagnosis["ecosystem_fit"]["status"] == "unsupported"
    assert not any(row["kind"] == "ecosystem_fit_review" for row in diagnosis["groups"]["reuse"])
    report = service.get_report(snapshot["id"])
    assert report["review"] is None and report["goals"] is None
    assert "Collection: unsupported." in markdown_report(report)
    with sqlite3.connect(service.db_path) as db:
        assert (
            db.execute("SELECT data FROM assessments WHERE id=?", (snapshot["id"],)).fetchone()[0]
            == raw
        )


def test_doctor_shares_candidate_budget_with_ecosystem_and_reports_omissions(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    for number in range(12):
        (root / f"db{number}.py").write_text("import sqlite3\n")
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root)
    diagnosis = service.doctor(captured["id"])
    assert diagnosis["ecosystem_fit"]["signal_count"] == 12
    assert sum(row["kind"] == "ecosystem_fit_review" for row in diagnosis["groups"]["reuse"]) == 12
    assert diagnosis["selection"]["families"]["ecosystem"] == {
        "captured": 12,
        "returned": 12,
        "omitted": 0,
    }

    report = tmp_path / "ruff.json"
    report.write_text(
        json.dumps(
            [
                {
                    "code": "F821",
                    "filename": str(root / "db0.py"),
                    "location": {"row": 1, "column": 1},
                    "end_location": {"row": 1, "column": 2},
                    "message": "Supplied diagnostic",
                    "fix": None,
                }
            ]
            * 100
        )
    )
    current = service.scan(root, [report])
    diagnosis = service.doctor(current["id"])
    rows = [row for group in diagnosis["groups"].values() for row in group]
    assert len(rows) == 100
    assert {row["family"] for row in rows} == {"ruff", "ecosystem"}
    assert diagnosis["selection"]["families"]["ecosystem"]["returned"] == 12
    assert diagnosis["selection"]["families"]["ruff"] == {
        "captured": 100,
        "returned": 88,
        "omitted": 12,
    }
    assert diagnosis["selection"]["captured"] == 112
    assert diagnosis["selection"]["returned"] == 100
    assert diagnosis["selection"]["omitted"] == 12
    assert all(row["candidate_confidence"]["defect_established"] is False for row in rows)
    assert diagnosis["status"] == "partial"
    assert diagnosis["ecosystem_fit"]["signal_count"] == 12
    assert any("candidate limit reached" in gap for gap in diagnosis["gaps"])


def test_doctor_preserves_current_source_and_imported_report_authority(tmp_path):
    allowed = tmp_path / "allowed"
    revoked = tmp_path / "revoked"
    allowed.mkdir()
    revoked.mkdir()
    (allowed / "app.py").write_text("value = 1\n")
    (revoked / "app.py").write_text("value = 2\n")
    report = revoked / "test-value.json"
    report.write_text(
        json.dumps({"schema": "test-value-audit.v3", "root": str(allowed), "tests": [], "gaps": []})
    )
    owner = AssessmentService(tmp_path / "state")
    revoked_snapshot = owner.scan(revoked)
    imported_snapshot = owner.scan(allowed, [report])
    restricted = AssessmentService(owner.state_dir, [allowed])

    for snapshot in (revoked_snapshot, imported_snapshot):
        with pytest.raises(PermissionError):
            restricted.doctor(snapshot["id"])


def test_doctor_ruff_candidates_keep_imported_identity_unverified_and_rechecked(tmp_path):
    root = tmp_path / "project"
    reports = tmp_path / "reports"
    root.mkdir()
    reports.mkdir()
    (root / "app.py").write_text("value = missing\n")
    report = reports / "ruff.json"
    report.write_text(
        json.dumps(
            [
                {
                    "code": "F821",
                    "filename": str(root / "app.py"),
                    "location": {"row": 1, "column": 9},
                    "end_location": {"row": 1, "column": 16},
                    "message": "Undefined name missing",
                    "fix": None,
                }
            ]
        )
    )
    owner = AssessmentService(tmp_path / "state")
    captured = owner.scan(root, [report])

    diagnosis = owner.doctor(captured["id"])
    candidate = next(
        row for row in diagnosis["groups"]["quality"] if row["kind"] == "ruff_diagnostic"
    )
    assert candidate["source_identity"] == "unverified"
    assert candidate["code"] == "F821" and candidate["locations"][0]["line"] == 1
    assert candidate["evidence_ids"] == [
        next(entry["id"] for entry in captured["evidence"] if entry["kind"] == "ruff")
    ]
    assert "ratings" not in diagnosis
    restricted = AssessmentService(owner.state_dir, [root])
    with pytest.raises(PermissionError):
        restricted.doctor(captured["id"])


def test_doctor_projects_captured_test_and_javascript_matrix_leads_without_weaker_clone_flood(
    tmp_path,
):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "test_values.py"
    source.write_text(
        "".join(
            '@pytest.mark.parametrize("value", [1, 2])\n'
            f"def test_{name}(value):\n    total = value + 1\n    doubled = total * 2\n    assert doubled > value\n\n"
            for name in ("first", "second")
        )
    )
    (root / "values.test.js").write_text(
        'test.each([1, 2])("case", value => { expect(value).toBeTruthy(); });\n'
    )
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root)
    diagnosis = service.doctor(captured["id"])
    leads = diagnosis["groups"]["quality"]
    assert {row["kind"] for row in leads} >= {"test-static-lead", "javascript-matrix-lead"}
    assert sum(row["kind"] == "duplicate_function" for row in diagnosis["groups"]["reuse"]) == 1
    assert not any(
        row["kind"] == "shared-python-body" for rows in diagnosis["groups"].values() for row in rows
    )
    inventory = diagnosis["test_value_static"]
    assert inventory["counts"]["groups"] >= 1
    reference = next(
        entry for entry in captured["evidence"] if entry["id"] == inventory["evidence_id"]
    )
    assert reference["kind"] == "test-value-static-analysis"
    for lead in leads:
        assert lead["binding_ambiguous"]
        assert inventory["evidence_id"] in lead["evidence_ids"]
        assert lead["locations"][0]["path"] in {"test_values.py", "values.test.js"}
        assert lead["locations"][0]["line"] > 0
        assert lead["smallest_fix"] and lead["verification"]
    matrix = next(row for row in leads if row["kind"] == "javascript-matrix-lead")
    assert matrix["metrics"]["confidence"] == "low"
    assert service.get_report(captured["id"])["review"] is None


def test_doctor_uses_older_test_static_inventory_without_generic_ast_evidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "test_values.py").write_text(
        '@pytest.mark.parametrize("value", [1, 2])\ndef test_value(value):\n    assert value > 0\n'
    )
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root)
    captured["evidence"] = [
        entry for entry in captured["evidence"] if entry["kind"] != "static-analysis"
    ]
    captured["facts"].pop("static_analysis")
    with sqlite3.connect(service.db_path) as db:
        db.execute(
            "UPDATE assessments SET data=? WHERE id=?", (json.dumps(captured), captured["id"])
        )

    diagnosis = service.doctor(captured["id"])

    assert diagnosis["status"] == "partial"
    assert any(row["kind"] == "test-static-lead" for row in diagnosis["groups"]["quality"])
    assert diagnosis["test_value_static"]["schema"] == "test-value-static.v1"
    assert any("rescan" in gap.lower() for gap in diagnosis["gaps"])


def test_doctor_combines_test_static_and_ruff_evidence_with_one_candidate_bound(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "test_values.py"
    source.write_text(
        "".join(
            '@pytest.mark.parametrize("value", [1, 2])\n'
            f"def test_value_{number}(value):\n    assert value > 0\n\n"
            for number in range(60)
        )
    )
    (root / "app.py").write_text(
        "import sqlite3\n"
        + "".join(
            f"def classify_{number}(value):\n    result = 0\n"
            + "".join(f"    if value > {branch}:\n        result += 1\n" for branch in range(11))
            + "    return result\n    unreachable = 2\n\n"
            for number in range(70)
        )
        + "def stop():\n    return 1\n    unreachable = 2\n"
    )
    report = tmp_path / "ruff.json"
    report.write_text(
        json.dumps(
            [
                {
                    "code": "F821",
                    "filename": str(source),
                    "location": {"row": 1, "column": 1},
                    "end_location": {"row": 1, "column": 2},
                    "message": "Supplied diagnostic",
                    "fix": None,
                }
            ]
            * 51
        )
    )
    service = AssessmentService(tmp_path / "state")
    captured = service.scan(root, [report])

    diagnosis = service.doctor(captured["id"])
    candidates = [row for rows in diagnosis["groups"].values() for row in rows]

    assert len(candidates) == 100
    assert any(row["kind"] == "test-static-lead" for row in candidates)
    assert any(row["kind"] == "ruff_diagnostic" for row in candidates)
    assert {row["family"] for row in candidates} == {
        "python_ast",
        "tests",
        "ruff",
        "ecosystem",
        "dead_code",
    }
    unreachable = next(row for row in candidates if row["kind"] == "unreachable_statement")
    assert unreachable["candidate_confidence"]["level"] == "high"
    assert unreachable["candidate_confidence"]["change_safety"] == "requires_review"
    assert all(row["omitted"] >= 0 for row in diagnosis["selection"]["families"].values())
    assert diagnosis["selection"]["omitted"] > 0
    smaller = service.doctor(captured["id"], limit=5)
    assert smaller["selection"]["returned"] == smaller["selection"]["limit"] == 5
    assert {row["family"] for rows in smaller["groups"].values() for row in rows} == {
        "python_ast",
        "tests",
        "ruff",
        "ecosystem",
        "dead_code",
    }
    assert any("candidate limit" in gap.lower() for gap in diagnosis["gaps"])
    assert service.history(captured["project_id"])["reviews"] == []


def test_evidence_query_pages_filters_and_preserves_captured_state(tmp_path, monkeypatch):
    root = tmp_path / "project"
    (root / "tests").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src/app.py").write_text(
        "import sqlite3\ndef transform(value):\n    return value + 1\n"
    )
    (root / "tests/test_app.py").write_text("def test_result():\n    assert 2 == 2\n")
    service = AssessmentService(tmp_path / "state", [root])
    snapshot = service.scan(root)
    before = service.history(snapshot["project_id"])
    (root / "src/app.py").write_text("raise RuntimeError('must never run or be reread')\n")
    monkeypatch.setattr(
        "project_assess.service.collect", lambda *_args, **_kwargs: pytest.fail("query rescanned")
    )
    first = service.query_evidence(snapshot["id"], limit=1)
    found = list(first["items"])
    page = first
    while page["next_offset"] is not None:
        page = service.query_evidence(snapshot["id"], offset=page["next_offset"], limit=1)
        found.extend(page["items"])
    assert [row["id"] for row in found] == [row["id"] for row in snapshot["evidence"]]
    assert len({row["id"] for row in found}) == first["matched"]
    assert all("stats" not in row and "excerpt" not in row for row in found)
    production = service.query_evidence(
        snapshot["id"], kind="python", path="app.py", role="production"
    )
    assert [row["path"] for row in production["items"]] == ["src/app.py"]
    tests = service.query_evidence(snapshot["id"], kind="python", role="test")
    assert [row["path"] for row in tests["items"]] == ["tests/test_app.py"]
    assert first["source"] == snapshot["source"]
    assert service.overview(snapshot["id"])["review_id"] is None
    assert "evidence" not in service.overview(snapshot["id"])
    assert service.history(snapshot["project_id"]) == before


def test_evidence_query_exposes_captured_graph_hotspots_and_whole_scope(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.py").write_text(
        "import b\ndef choose(value):\n    result = 0\n"
        + "".join(f"    if value > {number}:\n        result += 1\n" for number in range(11))
        + "    return result\n"
    )
    (root / "b.py").write_text("import a\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    graph = service.query_evidence(snapshot["id"], view="graph")
    assert any(
        row.get("source") == "a.py" and row.get("target") == "b.py" for row in graph["items"]
    )
    assert {row["path"] for row in graph["items"] if row["record_type"] == "module"} == {
        "a.py",
        "b.py",
    }
    hotspots = service.query_evidence(snapshot["id"], view="hotspots", path="a.py")
    assert any(
        row["name"] == "choose" and row["decision_points"] >= 10 for row in hotspots["items"]
    )
    candidates = service.query_evidence(
        snapshot["id"], view="candidates", candidate_kind="complex_function", role="unknown"
    )
    assert candidates["items"] and {row["kind"] for row in candidates["items"]} == {
        "complex_function"
    }
    assert candidates["items"][0]["locations"][0]["path"] == "a.py"
    coverage = service.query_evidence(snapshot["id"], view="coverage")
    assert any(row.get("coverage", {}).get("python_files") == 2 for row in coverage["items"])
    assert coverage["collection_gap_count"] == len(snapshot["gaps"])
    provenance = service.query_evidence(snapshot["id"], view="provenance")
    assert provenance["items"][0]["source"] == snapshot["source"]


@pytest.mark.parametrize(
    "options",
    [
        {"offset": -1},
        {"limit": True},
        {"limit": 101},
        {"max_chars": 1999},
        {"view": "shell"},
        {"path": "x" * 257},
        {"line": 0},
    ],
)
def test_evidence_query_rejects_unbounded_or_invalid_requests(assessed, options):
    service, _, snapshot = assessed
    with pytest.raises(ValueError):
        service.query_evidence(snapshot["id"], **options)


def test_evidence_query_budget_is_explicit_and_pagination_does_not_stall(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text(
        "".join(
            f"def function_{number}(value):\n    return value + {number}\n" for number in range(30)
        )
    )
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    result = service.query_evidence(
        snapshot["id"], view="details", kind="static-analysis", max_chars=2000
    )
    assert len(json.dumps(result, indent=2)) <= 2000
    assert result["oversized_rows"] == 1
    assert result["items"][0]["omitted"] and result["next_offset"] is None
    assert service.query_evidence(snapshot["id"], view="graph", limit=1, max_chars=2000)["items"]


def test_snippet_query_is_candidate_centered_and_bound_to_captured_bytes(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "app.py"
    source.write_text(
        "# padding keeps the lead beyond the file-prefix excerpt\n" * 100
        + "def context_signal(value):\n    result = 0\n"
        + "".join(f"    if value > {number}:\n        result += 1\n" for number in range(11))
        + "    return result\n"
    )
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    captured_source = next(entry for entry in snapshot["evidence"] if entry["path"] == "app.py")
    assert "context_signal" not in captured_source["excerpt"]
    source.write_text("raise RuntimeError('changed live file')\n")
    snippet = service.query_evidence(
        snapshot["id"], view="snippets", path="app.py", line=101, candidate_kind="complex_function"
    )
    assert snippet["items"]
    assert len(snippet["items"]) == 1
    row = snippet["items"][0]
    assert "context_signal" in row["excerpt"] and "changed live file" not in row["excerpt"]
    assert row["line"] <= 101 <= row["end_line"]
    assert row["digest"] == captured_source["digest"]
    assert row["evidence_id"] == captured_source["id"]
    assert snippet["source"] == snapshot["source"]
    missing = service.query_evidence(snapshot["id"], view="snippets", path="app.py", line=10000)
    assert not missing["items"] and missing["gap"]


def test_source_context_checks_snapshot_digest_and_never_updates_history(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "app.py"
    source.write_text("# outside the prefix excerpt\n" * 100 + "value = 'captured context'\n")
    service = AssessmentService(tmp_path / "state", [root])
    snapshot = service.scan(root)
    evidence = next(row for row in snapshot["evidence"] if row["path"] == "app.py")
    before = service.history(snapshot["project_id"])
    context = service.source_context(snapshot["id"], evidence["id"], line=101, end_line=101)
    assert context["source_identity"] == "snapshot_matched_live_bytes"
    assert context["assessment_id"] == snapshot["id"] and context["source"] == snapshot["source"]
    assert context["digest"] == evidence["digest"] and "captured context" in context["excerpt"]
    assert context["line"] == context["end_line"] == 101
    source.write_text("value = 'changed since assessment'\n")
    with pytest.raises(ValueError, match="changed|digest|stale|match"):
        service.source_context(snapshot["id"], evidence["id"], line=1)
    with pytest.raises(ValueError, match="Unknown evidence"):
        service.source_context(snapshot["id"], "foreign-evidence")
    assert service.history(snapshot["project_id"]) == before


def test_javascript_doctor_and_query_share_source_bound_native_leads(tmp_path):
    pytest.importorskip("tree_sitter", reason="Native JavaScript analysis is an optional extra")
    pytest.importorskip("tree_sitter_typescript", reason="Native TypeScript grammar is optional")
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src/app.ts").write_text(
        "export function classify(value: number) {\n  let total = 0;\n"
        + "".join(f"  if (value > {number}) {{ total += 1; }}\n" for number in range(11))
        + "  return total;\n  const unreachable = 2;\n}\n"
    )
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    diagnosis = service.doctor(snapshot["id"], limit=2)
    candidates = [row for rows in diagnosis["groups"].values() for row in rows]
    assert {row["family"] for row in candidates} == {"javascript_ast", "dead_code"}
    assert all(row["source_identity"] == "captured_snapshot" for row in candidates)
    queried = service.query_evidence(
        snapshot["id"],
        view="candidates",
        kind="javascript-analysis",
        candidate_kind="complex_function",
        role="production",
    )
    assert queried["items"] and queried["items"][0]["locations"][0]["path"] == "src/app.ts"
    snippet = service.query_evidence(snapshot["id"], view="snippets", path="src/app.ts", line=1)
    assert any("classify" in row["excerpt"] for row in snippet["items"])
