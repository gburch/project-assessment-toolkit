import json
from copy import deepcopy

import pytest

from project_assess.burden_context import SCHEMA, import_burden_context
from project_assess.observations import import_observation

REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
MANIFEST = [{"path": "src/app.py", "digest": DIGEST}]


def context():
    return {
        "schema": SCHEMA,
        "reported_at": "2026-11-01T12:00:00-05:00",
        "attribution": {"role": "maintainer", "label": "Project maintainer"},
        "source": {"revision": REVISION, "files": deepcopy(MANIFEST)},
        "period": {"start": "2026-10-01", "end": "2026-10-31"},
        "scope": {"label": "Meaningful source changes", "paths": ["src/app.py"]},
        "claims": [
            {
                "dimensions": ["testing", "security"],
                "statement": "Most changes encounter a test wait OR security rework.",
                "frequency": "most_changes",
                "workflow_stage": "mixed",
                "completion": "unknown",
                "duration": {
                    "seconds": 3600,
                    "semantics": "wall_elapsed",
                    "precision": "approximate",
                },
                "examples": [
                    {
                        "change": "Add an owner command field",
                        "hurdle": "A broad verification pass was required",
                        "impact": "The next change waited for feedback",
                        "paths": ["src/app.py"],
                    }
                ],
            }
        ],
        "limitations": ["Reported experience; no independent execution receipt"],
    }


def read(data, manifest=MANIFEST, revision=REVISION, redact=lambda value: value):
    return import_burden_context(json.dumps(data).encode(), manifest, revision, redact)


def test_attributed_context_is_bound_but_never_authenticated_or_graded():
    kind, result = read(context())
    assert kind == "burden-context"
    assert result["sourceIdentity"]["overall"] == "matched"
    assert result["attribution"] == {"role": "maintainer", "label": "Project maintainer"}
    assert result["coverage"]["claim_count"] == result["coverage"]["example_count"] == 1
    assert result["coverage"]["dimensions"] == ["security", "testing"]
    assert "supplied claims" in result["gaps"][0]
    assert "confidence" not in result and "burden" not in result
    assert "observed_at" not in result


def test_joint_frequency_is_not_promoted_into_individual_dimension_recurrence():
    _, result = read(context())
    claim = result["claims"][0]
    assert claim["dimensions"] == ["testing", "security"]
    assert claim["frequency"] == "most_changes"
    assert claim["frequency_scope"] == "joint_claim"
    assert any("separate dimension frequency" in gap for gap in result["gaps"])
    assert "dimension_frequencies" not in result["coverage"]


def test_unknown_source_period_and_scope_are_accepted_with_explicit_limits():
    data = context()
    data["source"] = {"revision": None, "files": []}
    data["period"] = {"start": None, "end": None}
    data["scope"]["paths"] = []
    _, result = read(data)
    assert result["sourceIdentity"]["overall"] == "unverified"
    assert result["coverage"]["declared_files"] == 0
    assert any("Experience period is incomplete" in gap for gap in result["gaps"])
    data["source"]["revision"] = REVISION
    assert read(data)[1]["sourceIdentity"]["overall"] == "unverified"


def test_historical_mismatch_and_unavailable_paths_remain_separate():
    data = context()
    data["source"]["revision"] = "c" * 40
    result = read(data, manifest=[])[1]
    assert result["sourceIdentity"]["overall"] == "mismatch"
    assert result["sourceIdentity"]["revision"] == "mismatch"
    assert result["coverage"]["source_unverified_files"] == 1
    assert result["coverage"]["captured_scope_paths"] == 0
    assert any("scope paths were not captured" in gap for gap in result["gaps"])


@pytest.mark.parametrize(
    "semantics", ["wall_elapsed", "blocked_wait", "active_effort", "summed_test_elapsed", "cpu"]
)
def test_timing_semantics_and_reported_precision_remain_explicit(semantics):
    data = context()
    data["claims"][0]["duration"].update(semantics=semantics, precision="reported_measurement")
    result = read(data)[1]
    duration = result["claims"][0]["duration"]
    assert duration == {
        "seconds": 3600,
        "semantics": semantics,
        "precision": "reported_measurement",
    }
    assert "not independently verified" in result["gaps"][0]
    assert any("complete workflow duration" in gap for gap in result["gaps"])
    assert any("not wall time" in gap for gap in result["gaps"]) == (
        semantics in {"cpu", "summed_test_elapsed"}
    )


def test_examples_are_optional_and_unknown_frequency_is_not_inferred():
    data = context()
    claim = data["claims"][0]
    claim.pop("examples")
    claim.pop("duration")
    claim["frequency"] = "unknown"
    result = read(data)[1]
    assert result["claims"][0]["examples"] == []
    assert result["coverage"]["example_count"] == 0
    assert any("claim frequencies are unknown" in gap for gap in result["gaps"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda x: x.update(raw_logs="do not retain arbitrary execution output"),
        lambda x: x.update(confidence="high"),
        lambda x: x["attribution"].update(authenticated=True),
        lambda x: x["claims"][0].update(burden=4),
        lambda x: x["claims"][0].update(frequency="verified_most_changes"),
        lambda x: x["claims"][0].update(dimensions=["testing", "testing"]),
        lambda x: x["claims"][0].update(dimensions=["unknown_dimension"]),
        lambda x: x["claims"][0]["duration"].update(semantics="measured_wall_time"),
        lambda x: x["claims"][0]["duration"].update(seconds=True),
        lambda x: x["claims"][0]["duration"].update(seconds=-1),
        lambda x: x["claims"][0]["duration"].update(seconds=1e20),
        lambda x: x.update(limitations=[]),
        lambda x: x["attribution"].update(label="  "),
        lambda x: x["claims"][0].update(statement="x" * 1001),
    ],
)
def test_raw_data_grades_ambiguous_metrics_and_oversized_text_fail_closed(mutate):
    data = context()
    mutate(data)
    with pytest.raises(ValueError, match="schema or fields"):
        read(data)


@pytest.mark.parametrize("where", ["source", "scope", "example"])
@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../app.py",
        "src/../app.py",
        "src//app.py",
        "./app.py",
        "C:app.py",
        r"C:\app.py",
        "src/\napp.py",
    ],
)
def test_every_path_surface_is_inert_and_contained(where, path):
    data = context()
    if where == "source":
        data["source"]["files"][0]["path"] = path
    elif where == "scope":
        data["scope"]["paths"] = [path]
    else:
        data["claims"][0]["examples"][0]["paths"] = [path]
    with pytest.raises(ValueError, match="project-relative"):
        read(data)


def test_duplicate_paths_and_examples_outside_declared_scope_are_rejected():
    data = context()
    data["source"]["files"] *= 2
    with pytest.raises(ValueError, match="unique"):
        read(data)
    data = context()
    data["claims"][0]["examples"][0]["paths"] = ["src/elsewhere.py"]
    with pytest.raises(ValueError, match="declared scope"):
        read(data)


@pytest.mark.parametrize("value", ["yesterday", "2026-11-01T12:00:00", "2026-11-01T12:00:00+99:00"])
def test_report_timestamp_requires_offset_but_is_never_execution_time(value):
    data = context()
    data["reported_at"] = value
    with pytest.raises(ValueError, match="timestamp"):
        read(data)


def test_experience_period_order_and_real_dates_do_not_depend_on_json_field_order():
    data = context()
    data["period"] = {"end": "2026-10-31", "start": "2026-10-01"}
    assert read(data)[1]["period"] == data["period"]
    data["period"] = {"start": "2026-11-02", "end": "2026-10-31"}
    with pytest.raises(ValueError, match="period"):
        read(data)
    data["period"] = {"start": "2026-02-30", "end": None}
    with pytest.raises(ValueError, match="period"):
        read(data)


def test_duplicate_json_fields_nonfinite_numbers_and_bytes_bound_are_rejected(monkeypatch):
    raw = json.dumps(context()).replace('"reported_at":', '"reported_at": "old", "reported_at":', 1)
    with pytest.raises(ValueError, match="Malformed"):
        import_burden_context(raw.encode(), MANIFEST, REVISION)
    for number in (float("nan"), float("inf"), -float("inf")):
        data = context()
        data["claims"][0]["duration"]["seconds"] = number
        with pytest.raises(ValueError):
            read(data)
    from project_assess import burden_context

    monkeypatch.setattr(burden_context, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="byte bound"):
        read(context())


def test_every_free_text_and_path_is_redacted_without_relabeling_semantics():
    data = context()
    data["source"]["files"][0]["path"] = "src/PRIVATE_APP.py"
    data["scope"]["paths"] = ["src/PRIVATE_APP.py"]
    data["claims"][0]["examples"][0]["paths"] = ["src/PRIVATE_APP.py"]
    data["attribution"]["label"] = "PRIVATE_REPORTER"
    data["scope"]["label"] = "PRIVATE_SCOPE"
    data["claims"][0]["statement"] = "PRIVATE_STATEMENT"
    data["claims"][0]["examples"][0].update(
        change="PRIVATE_CHANGE", hurdle="PRIVATE_HURDLE", impact="PRIVATE_IMPACT"
    )
    data["limitations"] = ["PRIVATE_LIMIT"]
    result = read(
        data,
        manifest=data["source"]["files"],
        redact=lambda s: "[REDACTED]" if "PRIVATE_" in s else s,
    )[1]
    assert "PRIVATE_" not in json.dumps(result)
    assert result["sourceIdentity"]["overall"] == "matched"
    assert result["sourceIdentity"]["files"][0]["path"] == "[REDACTED]"
    assert result["claims"][0]["duration"]["seconds"] == 3600
    assert result["claims"][0]["frequency_scope"] == "joint_claim"


def test_observation_import_keeps_existing_identity_and_coverage_contract():
    report = {
        "schema": "pat.observation.v1",
        "type": "change_cost",
        "observed_at": "2026-11-01T12:00:00-05:00",
        "source": {"revision": REVISION, "files": MANIFEST},
        "scenario": {"name": "known change", "scope": ["src/app.py"]},
        "results": [{"name": "elapsed", "value": 12, "unit": "seconds", "status": "observed"}],
        "limitations": ["Supplied result"],
    }
    kind, result = import_observation(json.dumps(report).encode(), MANIFEST, REVISION)
    assert kind == "observation"
    assert result["sourceIdentity"] == {
        "overall": "matched",
        "revision": "matched",
        "declared_revision": REVISION,
        "captured_revision": REVISION,
        "files": [{"path": "src/app.py", "digest": DIGEST, "status": "matched"}],
        "scope": "Only declared file identities and revision, not the complete project or runtime environment",
    }
    assert result["coverage"] == {
        "declared_files": 1,
        "source_matched_files": 1,
        "source_unverified_files": 0,
        "source_mismatched_files": 0,
    }
