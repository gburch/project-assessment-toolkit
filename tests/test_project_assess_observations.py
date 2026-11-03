import json
from copy import deepcopy

import pytest

from project_assess.observations import SCHEMA, import_observation

REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
MANIFEST = [{"path": "src/app.py", "digest": DIGEST}]


def observation():
    return {
        "schema": SCHEMA,
        "type": "performance",
        "observed_at": "2026-10-31T12:00:00-04:00",
        "source": {"revision": REVISION, "files": deepcopy(MANIFEST)},
        "scenario": {"name": "bounded workload", "scope": ["src/app.py"]},
        "results": [{"name": "p95", "value": 14.2, "unit": "ms", "status": "observed"}],
        "limitations": ["Synthetic workload, local device only"],
    }


def read(data, manifest=MANIFEST, revision=REVISION, redact=lambda text: text):
    return import_observation(json.dumps(data).encode(), manifest, revision, redact)


@pytest.mark.parametrize(
    "change",
    [
        {"trials": 1},
        {"trials": True},
        {"distinct_outputs": 4},
        {"input_digest": "raw prompt"},
        {"comparison": "schema"},
    ],
)
def test_prompting_observations_reject_insufficient_or_invalid_repeated_metadata(change):
    data = observation()
    data["type"] = "prompting"
    data["prompting"] = {
        "input_digest": "sha256:" + "a" * 64,
        "configuration_digest": "sha256:" + "b" * 64,
        "trials": 3,
        "distinct_outputs": 1,
        "comparison": "exact",
        "criterion": "Exact output bytes.",
    }
    data["prompting"].update(change)
    with pytest.raises(ValueError):
        read(data)


def test_prompting_observation_requires_its_specific_repeat_scenario():
    data = observation()
    data["type"] = "prompting"
    with pytest.raises(ValueError, match="repeated"):
        read(data)


@pytest.mark.parametrize(
    "kind", ["performance", "recovery", "delivery", "change_cost", "security", "extensibility"]
)
def test_existing_observation_types_bind_specific_source_without_certifying_execution(kind):
    data = observation()
    data["type"] = kind
    label, result = read(data)
    assert label == "observation"
    assert result["type"] == kind
    assert result["sourceIdentity"]["overall"] == "matched"
    assert result["coverage"]["source_matched_files"] == 1
    assert result["scenario"]["scope"] == ["src/app.py"]
    assert any("execution" in gap for gap in result["gaps"])
    assert "confidence" not in result and "capability" not in result


def test_source_mismatch_missing_file_and_unknown_revision_stay_distinct():
    data = observation()
    data["source"]["files"][0]["digest"] = "sha256:" + "c" * 64
    assert read(data)[1]["sourceIdentity"]["overall"] == "mismatch"
    assert read(observation(), manifest=[])[1]["sourceIdentity"]["overall"] == "unverified"
    assert read(observation(), revision=None)[1]["sourceIdentity"]["overall"] == "unverified"
    assert read(observation(), revision="d" * 40)[1]["sourceIdentity"]["overall"] == "mismatch"
    data = observation()
    data["source"]["revision"] = None
    assert read(data)[1]["sourceIdentity"]["overall"] == "unverified"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.update(raw_logs="secret execution output"),
        lambda data: data["results"][0].update(stdout="do not retain"),
        lambda data: data["results"][0].update(value="secret contents"),
        lambda data: data["scenario"].update(url="https://outside.example"),
        lambda data: data.update(schema="other.schema"),
        lambda data: data.update(type="testing"),
        lambda data: data.update(limitations=[]),
        lambda data: data["source"].update(files=[]),
        lambda data: data["results"][0].update(value=1e30),
    ],
)
def test_unsupported_fields_raw_logs_and_ambiguous_results_fail_closed(mutate):
    data = observation()
    mutate(data)
    with pytest.raises(ValueError):
        read(data)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../app.py",
        "src/../app.py",
        "./src/app.py",
        "src//app.py",
        r"C:\app.py",
        "C:app.py",
        "src/\napp.py",
    ],
)
def test_paths_are_inert_normalized_project_relative_identifiers(path):
    data = observation()
    data["source"]["files"][0]["path"] = path
    data["scenario"]["scope"] = [path]
    with pytest.raises(ValueError, match="project-relative"):
        read(data)


def test_duplicate_source_and_unbound_scenario_scope_are_rejected():
    data = observation()
    data["source"]["files"].append(deepcopy(data["source"]["files"][0]))
    with pytest.raises(ValueError, match="unique"):
        read(data)
    data = observation()
    data["scenario"]["scope"] = ["src/other.py"]
    with pytest.raises(ValueError, match="matching declared"):
        read(data)


@pytest.mark.parametrize(
    "timestamp", ["yesterday", "2026-10-31T12:00:00", "2026-10-31T12:00:00+99:00"]
)
def test_observation_time_requires_declared_timezone_but_is_not_verified(timestamp):
    data = observation()
    data["observed_at"] = timestamp
    with pytest.raises(ValueError, match="timestamp"):
        read(data)


def test_nonfinite_numbers_and_payload_bound_are_rejected(monkeypatch):
    for value in [float("nan"), float("inf"), -float("inf")]:
        data = observation()
        data["results"][0]["value"] = value
        with pytest.raises(ValueError):
            read(data)
    from project_assess import observations

    monkeypatch.setattr(observations, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="byte bound"):
        read(observation())


def test_import_redacts_textual_fields_and_keeps_raw_output_out_of_results():
    data = observation()
    data["scenario"]["name"] = "PRIVATE_SCENARIO"
    data["results"][0]["name"] = "PRIVATE_METRIC"
    data["limitations"] = ["PRIVATE_LIMITATION"]
    _, result = read(data, redact=lambda text: "[REDACTED]" if "PRIVATE_" in text else text)
    assert "PRIVATE_" not in json.dumps(result)
    assert result["results"][0]["value"] == 14.2
