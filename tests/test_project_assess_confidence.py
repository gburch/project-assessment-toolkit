"""Confidence support verifies captured spans without promoting project grades."""

import json
import sqlite3
from copy import deepcopy

import pytest

from project_assess.confidence import confidence_assessment
from project_assess.service import AssessmentService, _draft_digest, markdown_report


@pytest.fixture
def captured(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "rules.py").write_text(
        "def configure(operations):\n"
        "    if len(operations) > 1:\n"
        "        raise ValueError('one executor per provider')\n"
        "    return operations[0]\n" + "# Additional source context.\n" * 90
    )
    (root / "settings.py").write_text("password = 'CANARY_NOT_A_REAL_PASSWORD'\n")
    (root / "README.md").write_text("# Utility\nUse configure for supported operations.\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    return service, root, snapshot


def authored(service, snapshot, *, path="rules.py", line=2, end_line=3):
    review = service.review_template(snapshot["id"])
    review["coverage"]["scope"] = "focused"
    entry = next(item for item in snapshot["evidence"] if item["path"] == path)
    context = service.source_context(snapshot["id"], entry["id"], line, end_line, 4000)
    review["findings"] = [
        {
            "severity": "high",
            "title": "Configuration refuses two operations.",
            "evidence_ids": [entry["id"]],
            "support": {
                "confidence": "high",
                "scope": "source",
                "rationale": "The explicit guard refuses this finite conditional case.",
                "citations": [
                    {key: context[key] for key in ("evidence_id", "line", "end_line", "excerpt")}
                ],
                "counterevidence": "A single operation remains supported; refusal may be intentional.",
                "limitations": ["No live configuration or provider operation was executed."],
            },
        }
    ]
    return review


def state_counts(service):
    with sqlite3.connect(service.db_path) as db:
        return [
            db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("reviews", "requests")
        ]


def test_grounded_source_finding_does_not_upgrade_either_project_axis(captured):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    review["ratings"]["maintainability"].update(
        capability=2,
        burden=3,
        confidence="medium",
        burden_confidence="low",
        burden_basis="source_estimate",
        evidence_ids=review["findings"][0]["evidence_ids"],
    )
    saved = service.submit_review(snapshot["id"], review)
    assert saved["ratings"]["maintainability"] == review["ratings"]["maintainability"]
    report = service.get_report(snapshot["id"])
    result = report["confidence_assessment"]
    assert result["findings"][0]["grounding"] == "verified_source_spans"
    assert result["summary"]["declared_high_source_findings"] == 1
    assert result["dimensions"]["maintainability"]["capability"]["declared_confidence"] == "medium"
    assert any(
        "estimated from source" in text
        for text in result["dimensions"]["maintainability"]["burden"]["blockers"]
    )
    assert service.overview(snapshot["id"])["confidence_assessment"] == result
    assert service.evolve(snapshot["id"])["goal_alignment"]["confidence_assessment"] == result
    assert service.doctor(snapshot["id"])["goal_alignment"]["confidence_assessment"] == result
    assert "excerpt" not in json.dumps(result) and "counterevidence" not in json.dumps(result)


def test_verified_receipt_survives_reopen_and_full_draft_digest(captured):
    service, root, snapshot = captured
    review = authored(service, snapshot)
    packet = service.challenge_template(snapshot["id"], review)
    saved = service.submit_review(snapshot["id"], review)
    receipt = saved["support_verification"]
    assert receipt["source_digest"] == snapshot["source"]["manifest_digest"]
    assert _draft_digest(snapshot, saved) == packet["draft_digest"]
    assert receipt["findings"][0]["citations"][0]["excerpt_sha256"]
    assert "CANARY_NOT_A_REAL_PASSWORD" not in json.dumps(receipt)
    (root / "rules.py").unlink()
    reopened = AssessmentService(service.state_dir)
    result = reopened.get_report(snapshot["id"])["confidence_assessment"]
    assert result["findings"][0]["grounding"] == "verified_source_spans"


@pytest.mark.parametrize("fault", ["excerpt", "line", "range", "foreign", "uncited", "derived"])
def test_wrong_or_uncaptured_claim_support_rejects_without_writes(captured, fault):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    citation = review["findings"][0]["support"]["citations"][0]
    if fault == "excerpt":
        citation["excerpt"] += " invented behavior"
    elif fault == "line":
        citation["line"] = 1
    elif fault == "range":
        citation["end_line"] = 83
    elif fault == "foreign":
        citation["evidence_id"] = "not-in-this-snapshot"
    elif fault == "uncited":
        citation["evidence_id"] = next(
            item["id"] for item in snapshot["evidence"] if item["path"] == "README.md"
        )
    else:
        citation["evidence_id"] = next(
            item["id"] for item in snapshot["evidence"] if item["kind"] == "static-analysis"
        )
        review["findings"][0]["evidence_ids"] = [citation["evidence_id"]]
    for operation in (service.challenge_template, service.submit_review):
        with pytest.raises(ValueError):
            operation(snapshot["id"], review)
    assert state_counts(service) == [0, 0]


@pytest.mark.parametrize("fault", ["stale", "symlink", "directory_symlink"])
def test_source_identity_is_checked_again_at_final_submission(captured, tmp_path, fault):
    service, root, snapshot = captured
    review = authored(service, snapshot)
    service.challenge_template(snapshot["id"], review)
    if fault == "stale":
        (root / "rules.py").write_text((root / "rules.py").read_text() + "# changed\n")
    elif fault == "symlink":
        destination = tmp_path / "outside.py"
        (root / "rules.py").rename(destination)
        (root / "rules.py").symlink_to(destination)
    else:
        destination = tmp_path / "outside-project"
        root.rename(destination)
        root.symlink_to(destination, target_is_directory=True)
    with pytest.raises(ValueError):
        service.submit_review(snapshot["id"], review, request_id="invalid-source")
    assert state_counts(service) == [0, 0]


def test_citation_cache_is_limited_to_one_validation_call(captured, monkeypatch):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    finding = review["findings"][0]
    entry_id = finding["evidence_ids"][0]
    context = service.source_context(snapshot["id"], entry_id, 4, 4, 4000)
    finding["support"]["citations"].append(
        {key: context[key] for key in ("evidence_id", "line", "end_line", "excerpt")}
    )
    from project_assess import source_context

    original = source_context._read_at
    reads = []

    def counted(*args, **kwargs):
        reads.append(args[1])
        return original(*args, **kwargs)

    monkeypatch.setattr(source_context, "_read_at", counted)
    service.challenge_template(snapshot["id"], review)
    assert reads == ["rules.py"]
    service.submit_review(snapshot["id"], review)
    assert reads == ["rules.py", "rules.py"]


def test_secret_redaction_is_part_of_exact_citation_identity(captured):
    service, _, snapshot = captured
    review = authored(service, snapshot, path="settings.py", line=1, end_line=1)
    citation = review["findings"][0]["support"]["citations"][0]
    assert "CANARY_NOT_A_REAL_PASSWORD" not in citation["excerpt"]
    unsafe = deepcopy(review)
    unsafe["findings"][0]["support"]["citations"][0]["excerpt"] = (
        "password = 'CANARY_NOT_A_REAL_PASSWORD'"
    )
    with pytest.raises(ValueError) as error:
        service.submit_review(snapshot["id"], unsafe)
    assert "CANARY_NOT_A_REAL_PASSWORD" not in str(error.value)
    saved = service.submit_review(snapshot["id"], review)
    assert "CANARY_NOT_A_REAL_PASSWORD" not in json.dumps(saved)


@pytest.mark.parametrize(
    "fault", ["too_many_finding", "too_many_review", "too_long_excerpt", "forged_receipt"]
)
def test_support_work_and_server_receipts_are_bounded(captured, fault):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    if fault == "too_many_finding":
        review["findings"][0]["support"]["citations"] *= 5
    elif fault == "too_many_review":
        review["findings"][0]["support"]["citations"] *= 4
        review["findings"] *= 9
    elif fault == "too_long_excerpt":
        review["findings"][0]["support"]["citations"][0]["excerpt"] = "x" * 4001
    else:
        review["support_verification"] = {"schema_version": 1, "findings": []}
    with pytest.raises(ValueError):
        service.submit_review(snapshot["id"], review)
    assert state_counts(service) == [0, 0]


@pytest.mark.parametrize("fault", ["missing", "text", "span", "digest", "claim"])
def test_confidence_projection_does_not_trust_labels_or_mismatched_receipts(captured, fault):
    service, _, snapshot = captured
    saved = service.submit_review(snapshot["id"], authored(service, snapshot))
    forged = deepcopy(saved)
    if fault == "missing":
        del forged["support_verification"]
    elif fault == "text":
        forged["findings"][0]["support"]["citations"][0]["excerpt"] += " unsupported"
    elif fault == "span":
        forged["support_verification"]["findings"][0]["citations"][0]["end_line"] += 1
    elif fault == "digest":
        forged["support_verification"]["findings"][0]["citations"][0]["digest"] = "sha256:wrong"
    else:
        forged["findings"][0]["title"] = "Every workflow is guaranteed safe."
    result = confidence_assessment(snapshot, forged)
    assert result["findings"][0]["declared_confidence"] == "high"
    assert result["findings"][0]["grounding"] == "unestablished"
    assert result["summary"]["declared_high_source_findings"] == 0


def test_runtime_and_observed_upkeep_declarations_do_not_manufacture_evidence(captured):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    review["ratings"]["testing"].update(
        capability=4,
        confidence="high",
        burden=2,
        burden_basis="observed",
        burden_confidence="high",
        evidence_ids=review["findings"][0]["evidence_ids"],
    )
    saved = service.submit_review(snapshot["id"], review)
    axes = service.get_report(snapshot["id"])["confidence_assessment"]["dimensions"]["testing"]
    assert saved["ratings"]["testing"]["confidence"] == "high"
    assert any("selected anchor" in text for text in axes["capability"]["blockers"])
    assert any("source files alone" in text for text in axes["burden"]["blockers"])
    assert axes["source_matched_report_count"] == 0


@pytest.mark.parametrize("dimension", ["security", "testing", "documentation", "performance"])
def test_matching_report_identity_is_not_scenario_or_upkeep_proof(captured, dimension):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    report = {
        "id": "supplied-report",
        "kind": "test-value",
        "path": "static-test-value.json",
        "stats": {"sourceIdentity": {"overall": "matched"}, "outcomes": {}},
    }
    assessment = deepcopy(snapshot)
    assessment["evidence"].append(report)
    review["ratings"][dimension].update(
        capability=4,
        confidence="high",
        burden=3,
        burden_basis="observed",
        burden_confidence="high",
        evidence_ids=[report["id"]],
    )
    review["coverage"]["dimension_reviews"][dimension]["status"] = "reviewed"
    review["coverage"]["validation"] = [
        {"check": "Unrelated source check", "status": "passed", "evidence_ids": [report["id"]]}
    ]
    projected = confidence_assessment(assessment, review)["dimensions"][dimension]
    assert projected["source_matched_report_count"] == 1
    assert any("matching identity alone" in text for text in projected["capability"]["blockers"])
    assert any("actual change-cost" in text for text in projected["burden"]["blockers"])
    assert projected["capability"]["grounding"] == "authored_judgment"
    assert projected["capability"]["declared_confidence"] == "high"


def test_completed_independent_challenge_does_not_substitute_for_grounding(captured):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    del review["findings"][0]["support"]
    review["methodology"] = service.review_template(snapshot["id"], mode="fresh")["methodology"]
    review["methodology"]["reviewer_id"] = "author"
    packet = service.challenge_template(snapshot["id"], review)
    review["challenge"] = {
        "schema_version": 1,
        "status": "completed",
        "reviewer_id": "critic",
        "independence": "declared",
        "draft_digest": packet["draft_digest"],
        "summary": "A separate source review was recorded.",
        "evidence_ids": review["findings"][0]["evidence_ids"],
        "gaps": [],
        "items": [],
    }
    service.submit_review(snapshot["id"], review)
    report = service.get_report(snapshot["id"])
    assert report["assessment_method"]["completion"] == "completed"
    assert report["confidence_assessment"]["findings"][0]["grounding"] == "unestablished"
    assert report["confidence_assessment"]["summary"]["declared_high_source_findings"] == 0


def test_inference_and_legacy_findings_keep_their_actual_scope(captured):
    service, _, snapshot = captured
    review = authored(service, snapshot)
    review["findings"][0]["support"]["scope"] = "inference"
    review["findings"].append(
        {
            "severity": "low",
            "title": "Legacy estimate",
            "evidence_ids": review["findings"][0]["evidence_ids"],
        }
    )
    saved = service.submit_review(snapshot["id"], review)
    result = confidence_assessment(snapshot, saved)
    assert result["summary"]["verified_source_findings"] == 1
    assert result["summary"]["declared_high_source_findings"] == 0
    assert result["findings"][1]["declared_confidence"] is None
    assert "support" not in saved["findings"][1]


def test_markdown_source_support_renders_hostile_text_literally(captured):
    service, root, _ = captured
    (root / "hostile.py").write_text(
        'def label():\n    return "<script>window.pwned = 1</script>"\n'
    )
    snapshot = service.scan(root)
    review = authored(service, snapshot, path="hostile.py", line=1, end_line=2)
    review["findings"][0]["title"] = "<script>window.titlePwned = 1</script>"
    review["findings"][0]["support"]["counterevidence"] = "<img onerror=alert(1)>"
    service.submit_review(snapshot["id"], review)
    rendered = markdown_report(service.get_report(snapshot["id"]))
    assert "verified\\_source\\_spans" in rendered
    assert "<script>" not in rendered and "<img onerror" not in rendered
    assert "&lt;script&gt;" in rendered and "&lt;img onerror" in rendered
