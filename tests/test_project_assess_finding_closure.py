"""Finite finding progress is independent of grades and conservative about missing inputs."""

from copy import deepcopy

import pytest

from project_assess.finding_closure import finding_reference, project_finding, validate_event

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
OTHER = "sha256:" + "c" * 64


def snapshot(identifier="a_old", digest=OLD):
    return {
        "id": identifier,
        "project_id": "p_test",
        "source": {"manifest_digest": digest, "revision": "d" * 40},
        "evidence": [
            {"id": "e_app", "path": "src/app.py", "digest": digest, "kind": "python"},
            {"id": "e_other", "path": "src/other.py", "digest": OLD, "kind": "python"},
        ],
        "findings": [
            {
                "title": "Keep this important finding visible",
                "severity": "high",
                "evidence_ids": ["e_app"],
            }
        ],
    }


def event(origin, current, **changes):
    return {
        "finding_id": finding_reference(origin)["finding_id"],
        "assessment_id": current["id"],
        "source_digest": current["source"]["manifest_digest"],
        "status": "verified",
        "actor": "independent reviewer",
        "rationale": "Source fix reviewed",
        "evidence_ids": ["e_app"],
        "scope": [{"path": "src/app.py", "digest": NEW}],
        "verification": {
            "basis": "source_review",
            "acceptance": "The duplicate branch is removed",
            "limitations": ["Source inspection; runtime behavior not measured"],
        },
        **changes,
    }


def test_reference_keeps_distinct_review_findings_separate_and_checks_binding():
    origin = snapshot()
    native = finding_reference(origin)
    review = {
        "id": "r_1",
        "assessment_id": origin["id"],
        "source_digest": OLD,
        "findings": deepcopy(origin["findings"]) * 2,
    }
    assert native == finding_reference(deepcopy(origin))
    assert native["source_files"] == [{"path": "src/app.py", "digest": OLD}]
    assert (
        len(
            {
                native["finding_id"],
                finding_reference(origin, review, 0)["finding_id"],
                finding_reference(origin, review, 1)["finding_id"],
            }
        )
        == 3
    )
    with pytest.raises(ValueError, match="bound"):
        finding_reference(origin, {**review, "source_digest": NEW})
    for index in (-1, True, 100):
        with pytest.raises(ValueError):
            finding_reference(origin, index=index)


def test_source_verified_fix_preserves_limits_without_awarding_a_score():
    origin, current = snapshot(), snapshot("a_new", NEW)
    decision = validate_event(event(origin, current), origin, None, current)
    assert decision["verification_label"] == "reviewer_verified"
    assert "capability" not in decision and "burden" not in decision
    projected = project_finding(finding_reference(origin), [{**decision, "id": "fe_1"}], current)
    assert projected["status"] == "verified" and projected["last_event_id"] == "fe_1"
    assert "supplied claims" in projected["caveat"]
    assert projected["finding"]["severity"] == "high"


def test_related_source_change_is_valid_even_if_originally_cited_file_is_unchanged():
    origin, current = snapshot(), snapshot("a_new", NEW)
    current["evidence"][0]["digest"] = OLD
    current["evidence"][1]["digest"] = NEW
    payload = event(
        origin,
        current,
        evidence_ids=["e_other"],
        scope=[{"path": "src/app.py", "digest": OLD}, {"path": "src/other.py", "digest": NEW}],
    )
    assert validate_event(payload, origin, None, current)["status"] == "verified"


def test_verified_scope_survives_unrelated_changes_but_requires_recheck_for_relevant_edits():
    origin, current = snapshot(), snapshot("a_new", NEW)
    decision = validate_event(event(origin, current), origin, None, current)
    current["id"] = "a_later"
    current["source"]["manifest_digest"] = OTHER
    current["evidence"][1]["digest"] = OTHER
    reference = finding_reference(origin)
    assert project_finding(reference, [decision], current)["status"] == "verified"
    current["evidence"][0]["digest"] = OTHER
    projected = project_finding(reference, [decision], current)
    assert projected["status"] == "needs_recheck" and projected["recorded_status"] == "verified"
    current["evidence"] = []
    assert project_finding(reference, [decision], current)["status"] == "needs_recheck"


def test_accepted_debt_is_visible_not_reported_as_remediation():
    origin, current = snapshot(), snapshot("a_new", OLD)
    payload = event(
        origin, current, status="accepted", scope=[{"path": "src/app.py", "digest": OLD}]
    )
    payload.pop("verification")
    decision = validate_event(payload, origin, None, current)
    projected = project_finding(finding_reference(origin), [decision], current)
    assert projected["status"] == "accepted"
    assert projected["finding"]["severity"] == "high"
    assert projected["verification_label"] == "not_verified"


@pytest.mark.parametrize(
    "change",
    [
        {"source_digest": OTHER},
        {"assessment_id": "a_stale"},
        {"finding_id": "f_" + "c" * 32},
        {"status": "needs_recheck"},
        {"actor": " "},
        {"extra": "ignored"},
        {"evidence_ids": ["e_missing"]},
        {"scope": []},
        {"verification": None},
        {"scope": [{"path": "../app.py", "digest": NEW}]},
        {"scope": [{"path": "/etc/passwd", "digest": NEW}]},
        {"scope": [{"path": "src/app.py", "digest": None}]},
        {"scope": [{"path": "src/app.py", "digest": OTHER}]},
        {"scope": [{"path": "src/app.py", "digest": NEW}] * 2},
        {"scope": [{"path": "src/other.py", "digest": OLD}]},
        {"rationale": "x" * 2001},
    ],
)
def test_invalid_forged_or_stale_events_are_rejected(change):
    origin, current = snapshot(), snapshot("a_new", NEW)
    with pytest.raises(ValueError):
        validate_event(event(origin, current, **change), origin, None, current)


def test_unchanged_source_reassessment_and_different_project_cannot_close_findings():
    origin, current = snapshot(), snapshot("a_new", OLD)
    with pytest.raises(ValueError, match="changed relevant"):
        validate_event(
            event(origin, current, scope=[{"path": "src/app.py", "digest": OLD}]),
            origin,
            None,
            current,
        )
    current = snapshot("a_new", NEW)
    current["project_id"] = "p_unrelated"
    with pytest.raises(ValueError, match="current project"):
        validate_event(event(origin, current), origin, None, current)


def observation():
    return {
        "id": "e_run",
        "path": "/outside/passed.json",
        "digest": OTHER,
        "kind": "observation",
        "stats": {
            "sourceIdentity": {
                "overall": "matched",
                "files": [{"path": "src/app.py", "digest": NEW, "status": "matched"}],
            },
            "results": [{"name": "targeted recovery", "status": "passed"}],
        },
    }


def test_execution_basis_needs_passed_source_matched_observation_and_is_not_authenticated():
    origin, current = snapshot(), snapshot("a_new", NEW)
    payload = event(origin, current)
    payload["verification"]["basis"] = "execution_report"
    payload["evidence_ids"].append("e_run")
    current["evidence"].append(observation())
    result = validate_event(payload, origin, None, current)
    assert result["verification_label"] == "supplied_execution_report"
    for mutation in ("failed", "mismatch", "wrong_digest", "unscoped", "junit"):
        changed = deepcopy(current)
        imported = changed["evidence"][-1]
        if mutation == "failed":
            imported["stats"]["results"][0]["status"] = "failed"
        elif mutation == "mismatch":
            imported["stats"]["sourceIdentity"]["overall"] = "mismatch"
        elif mutation == "wrong_digest":
            imported["stats"]["sourceIdentity"]["files"][0]["digest"] = OLD
        elif mutation == "unscoped":
            imported["stats"]["sourceIdentity"]["files"] = []
        else:
            imported["kind"] = "junit"
        with pytest.raises(ValueError, match="source-matched"):
            validate_event(payload, origin, None, changed)


def test_no_event_and_no_candidate_is_still_open():
    origin, current = snapshot(), snapshot("a_new", NEW)
    current["findings"] = []
    assert project_finding(finding_reference(origin), [], current)["status"] == "open"
