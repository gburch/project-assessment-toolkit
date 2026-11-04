"""Review freshness and challenge receipts remain separate from source facts."""

import json
import sqlite3
from copy import deepcopy

import pytest

from project_assess.rubric import DIMENSIONS
from project_assess.service import AssessmentService, ConflictError, markdown_report


@pytest.fixture
def captured(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("def add(a, b):\n    return a + b\n")
    service = AssessmentService(tmp_path / "state")
    return service, service.scan(root)


def draft(service, snapshot, *, scope="whole_project", mode="fresh"):
    review = service.review_template(snapshot["id"], mode=mode)
    evidence_id = snapshot["evidence"][0]["id"]
    review["methodology"]["reviewer_id"] = "author-agent"
    review["coverage"]["scope"] = scope
    for dimension in DIMENSIONS:
        review["methodology"]["dimensions"][dimension] = "reassessed"
        review["ratings"][dimension].update(
            capability=2,
            burden=2,
            evidence_ids=[evidence_id],
            rationale="PROPOSED RATIONALE MUST NOT ANCHOR THE CHALLENGER",
        )
        review["coverage"]["dimension_reviews"][dimension].update(
            status="reviewed", rationale="Source inspected.", evidence_ids=[evidence_id]
        )
    review["change_traces"] = [
        {
            "id": "change-entrypoint",
            "title": "Add an operation at the public boundary",
            "steps": [
                {
                    "owner": "app.py:add",
                    "change": "Trace the caller and arithmetic behavior.",
                    "evidence_ids": [evidence_id],
                }
            ],
            "cost": "One implementation owner; no observed timing data.",
            "invariant": "Existing callers keep their result.",
            "counterevidence": "A single function has little architectural overhead.",
            "gaps": ["No representative workflow measurement."],
        }
    ]
    return review


def unavailable(review):
    review["challenge"] = {
        "schema_version": 1,
        "status": "unavailable",
        "summary": "No separate reviewer was available; this is provisional.",
        "gaps": ["Independent source inspection remains outstanding."],
    }
    return review


def completed(service, snapshot, review, *, decision="deferred"):
    packet = service.challenge_template(snapshot["id"], review)
    evidence_id = snapshot["evidence"][0]["id"]
    review["challenge"] = {
        "schema_version": 1,
        "status": "completed",
        "reviewer_id": "challenger-agent",
        "independence": "declared",
        "draft_digest": packet["draft_digest"],
        "summary": "Independently inspected the supplied source and change trace.",
        "evidence_ids": [evidence_id],
        "gaps": [],
        "items": [
            {
                "id": "workflow-evidence",
                "concern": "Runtime cost is still unmeasured.",
                "evidence_ids": [evidence_id],
                "response": {
                    "decision": decision,
                    "rationale": "Keep the measurement gap visible; no engineering fix is claimed.",
                    "evidence_ids": [evidence_id],
                },
            }
        ],
    }
    return review


def stored_rows(service):
    with sqlite3.connect(service.db_path) as db:
        return db.execute("SELECT data FROM reviews ORDER BY seq").fetchall()


def test_opt_in_template_and_legacy_reads_do_not_rewrite_history(captured):
    service, snapshot = captured
    legacy = service.review_template(snapshot["id"])
    assert "methodology" not in legacy
    service.submit_review(snapshot["id"], legacy)
    before = stored_rows(service)
    report = service.get_report(snapshot["id"])
    method = report["assessment_method"]
    assert method["status"] == method["completion"] == "unestablished"
    assert method["counts"]["unestablished"] == len(DIMENSIONS)
    assert "methodology" not in report["review"]
    assert service.overview(snapshot["id"])["assessment_method"]["status"] == "unestablished"
    assert stored_rows(service) == before
    fresh = service.review_template(snapshot["id"], mode="fresh")
    assert fresh["methodology"]["reviewer_id"] == "unassigned"
    assert set(fresh["methodology"]["dimensions"].values()) == {"unreviewed"}
    service.submit_review(snapshot["id"], fresh)  # Unknown dimensions remain saveable.
    with pytest.raises(ValueError, match="mode"):
        service.review_template(snapshot["id"], mode="automatic")


def test_fresh_scores_need_trace_and_challenge_or_explicit_provisional_status(captured):
    service, snapshot = captured
    review = draft(service, snapshot)
    for missing in ("challenge", "change_traces"):
        invalid = unavailable(deepcopy(review))
        invalid.pop(missing)
        with pytest.raises(ValueError, match="require a change trace"):
            service.submit_review(snapshot["id"], invalid)
    assert stored_rows(service) == []
    service.submit_review(snapshot["id"], unavailable(review))
    report = service.get_report(snapshot["id"])
    method = report["assessment_method"]
    assert method["status"] == "fresh" and method["completion"] == "provisional"
    assert method["trace_count"] == 1 and method["counts"]["reassessed"] == len(DIMENSIONS)
    assert service.evolve(snapshot["id"])["goal_alignment"]["assessment_method"] == method
    assert service.doctor(snapshot["id"])["goal_alignment"]["assessment_method"] == method
    overview = service.overview(snapshot["id"])["assessment_method"]
    assert "change_traces" not in overview and "items" not in overview["challenge"]
    assert overview["challenge"]["status"] == "unavailable"
    rendered = markdown_report(report)
    assert "Freshness: fresh; completion: provisional" in rendered
    assert "Change trace: Add an operation" in rendered


def test_score_free_challenge_packet_is_read_only_and_bound_to_the_draft(captured):
    service, snapshot = captured
    review = draft(service, snapshot)
    packet = service.challenge_template(snapshot["id"], review)
    text = json.dumps(packet)
    assert "PROPOSED RATIONALE" not in text
    assert "ratings" not in packet and "findings" not in packet and "plan" not in packet
    assert "review_id" not in packet and "review" not in packet["context"]
    assert "change_traces" not in packet and "burden_review" not in packet
    assert packet["schema_version"] == 2 and packet["stage"] == "independent_source_review"
    assert packet["context"]["evidence_selection"]["trace_cited"] == 0
    assert packet["context"]["evidence_index"] and packet["rubric"]
    assert stored_rows(service) == []
    assert (
        service.challenge_template(snapshot["id"], review)["draft_digest"] == packet["draft_digest"]
    )
    review["ratings"]["testing"]["burden_basis"] = "source_estimate"
    assert (
        service.challenge_template(snapshot["id"], review)["draft_digest"] == packet["draft_digest"]
    )


def test_unknown_fresh_review_without_a_trace_remains_provisional_after_challenge(captured):
    service, snapshot = captured
    review = service.review_template(snapshot["id"], mode="fresh")
    review["methodology"]["reviewer_id"] = "author-agent"
    completed(service, snapshot, review)
    service.submit_review(snapshot["id"], review)
    method = service.get_report(snapshot["id"])["assessment_method"]
    assert method["challenge"]["status"] == "completed"
    assert method["completion"] == "provisional"
    assert any("change trace" in gap for gap in method["gaps"])


@pytest.mark.parametrize("field", ["capability", "rationale", "trace", "coverage", "author"])
def test_challenge_receipt_rejects_changed_draft_without_partial_writes(captured, field):
    service, snapshot = captured
    review = completed(service, snapshot, draft(service, snapshot))
    if field == "capability":
        review["ratings"]["testing"]["capability"] = 3
    elif field == "rationale":
        review["ratings"]["testing"]["rationale"] = "Changed judgment."
    elif field == "trace":
        review["change_traces"][0]["cost"] = "Changed cost."
    elif field == "coverage":
        review["coverage"]["limitations"].append("New evidence limitation.")
    else:
        review["methodology"]["reviewer_id"] = "different-author"
    with pytest.raises(ConflictError, match="Challenge is stale"):
        service.submit_review(snapshot["id"], review)
    assert stored_rows(service) == []
    completed(service, snapshot, review)  # A follow-up binds the amended draft.
    service.submit_review(snapshot["id"], review)


@pytest.mark.parametrize("decision", ["accepted", "rejected", "deferred"])
def test_cited_challenge_responses_remain_visible_without_claiming_a_fix(captured, decision):
    service, snapshot = captured
    review = completed(service, snapshot, draft(service, snapshot), decision=decision)
    saved = service.submit_review(snapshot["id"], review)
    report = service.get_report(snapshot["id"])
    method = report["assessment_method"]
    assert method["completion"] == "completed"
    assert method["challenge"]["items"][0]["response"]["decision"] == decision
    assert "not authenticated" in method["caveat"]
    assert "do not mean engineering changes are complete" in method["caveat"]
    assert "Runtime cost is still unmeasured" in markdown_report(report)
    # Storage normalizes burden defaults without making the saved receipt stale.
    submitted = {
        key: value
        for key, value in saved.items()
        if key not in {"id", "schema_version", "created_at", "provenance"}
    }
    assert (
        service.challenge_template(snapshot["id"], submitted)["draft_digest"]
        == review["challenge"]["draft_digest"]
    )


@pytest.mark.parametrize(
    "location",
    ["trace", "challenge", "response", "same_reviewer", "same_reviewer_case", "blank_reviewer"],
)
def test_foreign_citations_and_same_reviewer_cannot_complete_challenge(captured, location):
    service, snapshot = captured
    review = completed(service, snapshot, draft(service, snapshot))
    if location == "trace":
        review["change_traces"][0]["steps"][0]["evidence_ids"] = ["foreign"]
    elif location == "challenge":
        review["challenge"]["evidence_ids"] = ["foreign"]
    elif location == "response":
        review["challenge"]["items"][0]["response"]["evidence_ids"] = ["foreign"]
    elif location == "same_reviewer":
        review["challenge"]["reviewer_id"] = "author-agent"
    elif location == "same_reviewer_case":
        review["challenge"]["reviewer_id"] = "AUTHOR-AGENT"
    else:
        review["challenge"]["reviewer_id"] = " "
    with pytest.raises(ValueError):
        service.submit_review(snapshot["id"], review)
    assert stored_rows(service) == []


def test_zero_concern_challenge_still_requires_current_inspection_citations(captured):
    service, snapshot = captured
    review = completed(service, snapshot, draft(service, snapshot))
    review["challenge"]["items"] = []
    invalid = deepcopy(review)
    invalid["challenge"]["evidence_ids"] = []
    with pytest.raises(ValueError, match="require evidence"):
        service.submit_review(snapshot["id"], invalid)
    saved = service.submit_review(snapshot["id"], review)
    assert saved["challenge"]["items"] == []


def refresh(service, snapshot, prior):
    review = draft(service, snapshot, mode="refresh")
    review["methodology"]["based_on_review_id"] = prior["id"]
    review["methodology"]["dimensions"] = {dim: "carried_forward" for dim in DIMENSIONS}
    return review


def test_refresh_labels_unchanged_judgments_without_pretending_they_are_fresh(captured):
    service, snapshot = captured
    prior = service.submit_review(snapshot["id"], unavailable(draft(service, snapshot)))
    new = service.scan(snapshot["source"]["root"])
    review = refresh(service, new, prior)
    service.submit_review(new["id"], review)
    method = service.get_report(new["id"])["assessment_method"]
    assert method["status"] == "refresh" and method["counts"]["carried_forward"] == len(DIMENSIONS)
    fresh = deepcopy(review)
    fresh["methodology"]["mode"] = "fresh"
    with pytest.raises(ValueError, match="cannot carry"):
        service.submit_review(new["id"], fresh)


@pytest.mark.parametrize(
    "change",
    ["source", "scope", "capability", "burden", "confidence", "burden_basis", "burden_confidence"],
)
def test_refresh_requires_unchanged_source_scope_axes_and_confidence(captured, change):
    service, snapshot = captured
    prior = service.submit_review(snapshot["id"], unavailable(draft(service, snapshot)))
    if change == "source":
        with open(snapshot["source"]["root"] + "/app.py", "a") as source:
            source.write("\nVALUE = 1\n")
    new = service.scan(
        snapshot["source"]["root"], analysis_profile="deep" if change == "scope" else "standard"
    )
    review = refresh(service, new, prior)
    if change not in {"source", "scope"}:
        review["ratings"]["testing"][change] = {
            "capability": 3,
            "burden": 3,
            "confidence": "high",
            "burden_basis": "observed",
            "burden_confidence": "high",
        }[change]
    with pytest.raises(ValueError):
        service.submit_review(new["id"], review)
    assert service.get_report(new["id"])["review"] is None


def test_prior_review_cannot_escape_allowed_project_roots(captured, tmp_path):
    service, snapshot = captured
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("def add(a, b):\n    return a + b\n")
    other = service.scan(outside)
    prior = service.submit_review(other["id"], unavailable(draft(service, other)))
    restricted = AssessmentService(service.state_dir, allowed_roots=[snapshot["source"]["root"]])
    review = refresh(restricted, snapshot, prior)
    with pytest.raises(PermissionError):
        restricted.submit_review(snapshot["id"], review)
    assert restricted.get_report(snapshot["id"])["review"] is None


def test_old_snapshot_and_mismatched_identity_cannot_prepare_challenge(captured):
    service, snapshot = captured
    review = draft(service, snapshot)
    review["source_digest"] = "mismatched"
    with pytest.raises(ConflictError, match="identity"):
        service.challenge_template(snapshot["id"], review)
    review["source_digest"] = snapshot["source"]["manifest_digest"]
    service.scan(snapshot["source"]["root"])
    with pytest.raises(ConflictError, match="stale"):
        service.challenge_template(snapshot["id"], review)


@pytest.mark.parametrize(
    "grade_prose",
    [
        "AUTHORED_GRADE_MARKER working burden 2/5 and capability C4",
        "AUTHORED_GRADE_MARKER Fort Knox, mature, negligible upkeep, four stars",
        "AUTHORED_GRADE_MARKER encoded score QzUvQjE= <img src=x onerror=alert(1)>",
    ],
)
def test_initial_packet_excludes_authored_prose_in_every_review_surface(captured, grade_prose):
    service, snapshot = captured
    review = draft(service, snapshot)
    baseline = service.challenge_template(snapshot["id"], review)
    source_id = snapshot["evidence"][0]["id"]
    for rating in review["ratings"].values():
        rating.update(rationale=grade_prose, recommendations=[grade_prose])
        rating["burden_support"] = {
            "claim": grade_prose,
            "scope": "workflow",
            "scope_description": grade_prose,
            "observation_ids": [],
            "change_trace_ids": ["change-entrypoint"],
            "representativeness": grade_prose,
            "counterevidence": grade_prose,
            "freshness": grade_prose,
            "limitations": [grade_prose],
        }
    trace = review["change_traces"][0]
    for key in ("title", "cost", "invariant", "counterevidence"):
        trace[key] = grade_prose
    trace["gaps"] = [grade_prose]
    trace["steps"][0].update(owner=grade_prose, change=grade_prose)
    review["findings"] = [{"severity": "high", "title": grade_prose, "evidence_ids": [source_id]}]
    review["project_context"]["intended"]["statement"] = grade_prose
    review["project_context"]["intended"]["alternatives"] = [grade_prose]
    review["prompting"]["intent"]["rationale"] = grade_prose
    review["prompting"]["recommendations"] = [
        {
            "direction": "retain",
            "action": grade_prose,
            "rationale": grade_prose,
            "evidence_ids": [source_id],
        }
    ]
    review["coverage"]["limitations"] = [grade_prose]
    for dimension in review["coverage"]["dimension_reviews"].values():
        dimension["rationale"] = grade_prose
    review["methodology"]["reviewer_id"] = grade_prose
    review["review_context"]["loaded_instructions"] = [
        {"path": "/authored/" + grade_prose, "sha256": "0" * 64, "read_status": "partial"}
    ]
    review["project_context"]["current"]["rationale"] = grade_prose
    review["project_context"]["alignment"]["rationale"] = grade_prose
    review["prompting"]["rationale"] = grade_prose
    review["prompting"]["variability"]["rationale"] = grade_prose
    review["plan"] = {
        "schema_version": 1,
        "diagnosis": grade_prose,
        "target_state": grade_prose,
        "initiatives": [
            {
                "id": "authored-plan",
                "title": grade_prose,
                "priority": "high",
                "root_cause": grade_prose,
                "scope": grade_prose,
                "dimension_impacts": {"maintainability": grade_prose},
                "evidence_ids": [source_id],
                "acceptance": [grade_prose],
                "burden_effect": grade_prose,
                "depends_on": [],
                "first_slice": grade_prose,
            }
        ],
    }
    service.set_targets(snapshot["project_id"], profile="sensitive-critical", expected_revision=0)
    packet = service.challenge_template(snapshot["id"], review)
    assert grade_prose not in json.dumps(packet)
    assert set(packet) == {
        "schema_version",
        "stage",
        "assessment_id",
        "source",
        "scope_digest",
        "rubric_version",
        "draft_digest",
        "context",
        "rubric",
        "instructions",
    }
    assert packet["draft_digest"] != baseline["draft_digest"]
    assert {key: value for key, value in packet.items() if key != "draft_digest"} == {
        key: value for key, value in baseline.items() if key != "draft_digest"
    }
    for key in (
        "ratings",
        "findings",
        "plan",
        "change_traces",
        "burden_review",
        "project_context",
        "project_intent",
        "prompting_intent",
        "targets",
        "review_context",
    ):
        assert key not in packet
    assert all(
        "change_trace" not in row["selection_reasons"]
        for row in packet["context"]["evidence_index"]
    )
    assert "exact authored draft" in " ".join(packet["instructions"])
    assert stored_rows(service) == []


def test_source_packet_preserves_captured_grade_like_names_without_authored_claims(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "claimed-C5-B0.md").write_text(
        "# Claimed old grade\nC5/B0 is an unverified project claim.\n"
    )
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    packet = service.challenge_template(snapshot["id"], service.review_template(snapshot["id"]))
    assert any(row["path"] == "claimed-C5-B0.md" for row in packet["context"]["evidence_index"])
    assert packet["source"]["manifest_digest"] == snapshot["source"]["manifest_digest"]
    assert "captured project" in " ".join(packet["instructions"])
