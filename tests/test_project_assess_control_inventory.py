import hashlib
import json
from copy import deepcopy

import pytest

from project_assess.collector import collect
from project_assess.control_inventory import ControlInventory
from project_assess.service import AssessmentService


def record(path, dimension="security", count=5):
    return {
        "path": path,
        "language": "python",
        "dimensions": [dimension],
        "status": "complete",
        "coverage": {"signals_found": count},
        "signals": [
            {
                "kind": f"{dimension}.rule{i}",
                "dimensions": [dimension],
                "locations": [{"path": path, "line": i + 1, "end_line": i + 1}],
                "context": {"category": "risk_candidate"},
                "limitations": ["syntax only"],
            }
            for i in range(count)
        ],
    }


def entry(path):
    return {"path": path, "id": "e-" + path, "digest": "sha256:" + "a" * 64}


def test_global_retention_spreads_files_and_is_order_independent():
    inputs = [record("src/first/app.py"), record("src/last/app.py", "performance")]
    results = []
    for rows in (inputs, inputs[::-1]):
        inventory = ControlInventory(signal_limit=4)
        for row in rows:
            inventory.expect(row["path"], row["dimensions"])
            inventory.add(row, entry(row["path"]))
        results.append(inventory.summarize())
    assert results[0] == results[1]
    result = results[0]
    assert {s["locations"][0]["path"] for s in result["signals"]} == {r["path"] for r in inputs}
    assert len(result["signals"]) == 4
    assert result["coverage"]["signals_observed"] == 10
    assert result["coverage"]["signals_omitted"] == 6
    assert result["status"] == "partial"


def test_unsupported_uncaptured_and_zero_hit_files_are_distinct():
    inventory = ControlInventory()
    inventory.expect("src/Main.swift", ["security"], supported=False)
    inventory.expect("src/too-large.py", ["security"])
    inventory.expect("src/plain.py", ["security"])
    inventory.add(record("src/plain.py", count=0), entry("src/plain.py"))
    result = inventory.summarize()
    coverage = result["coverage"]["dimensions"]["security"]
    assert (
        coverage["unsupported_files"]
        == coverage["uncaptured_files"]
        == coverage["examined_files"]
        == 1
    )
    assert coverage["retained_signals"] == 0
    assert result["status"] == "partial"


def test_invalid_binding_and_budget_are_rejected():
    with pytest.raises(ValueError):
        ControlInventory(-1)
    with pytest.raises(ValueError):
        ControlInventory().add(record("src/a.py"), entry("src/b.py"))


def test_crowded_files_cannot_erase_an_entire_dimension_or_rule():
    inventory = ControlInventory(signal_limit=10)
    for index in range(100):
        row = record(f"src/ordinary{index}.py", "operability", count=1)
        inventory.add(row, entry(row["path"]))
    special = record("src/special.py", count=0)
    special["dimensions"] = ["security", "delivery", "operability", "extensibility", "performance"]
    special["signals"] = [
        record(special["path"], dimension, count=1)["signals"][0]
        for dimension in special["dimensions"]
    ]
    special["coverage"]["signals_found"] = 5
    inventory.add(special, entry(special["path"]))
    result = inventory.summarize()
    assert {dimension for row in result["signals"] for dimension in row["dimensions"]} == set(
        special["dimensions"]
    )
    assert result["coverage"]["signals_omitted"] == 95
    for dimension in special["dimensions"]:
        assert result["coverage"]["dimensions"][dimension]["observed_signals_lower_bound"] > 0


def test_capped_producer_kind_counts_remain_observed_counts():
    inventory = ControlInventory()
    row = record("src/a.py", count=1)
    row["coverage"] = {"signals_total": 100, "by_kind": {"security.rule0": 100}}
    inventory.add(row, entry(row["path"]))
    result = inventory.summarize()
    assert result["signal_counts"]["security.rule0"] == 100
    assert result["coverage"]["signals_observed"] == 100
    assert result["coverage"]["dimensions"]["security"]["observed_signals_lower_bound"] == 100


def test_global_budget_preserves_producer_semantic_option_variants():
    inventory = ControlInventory(signal_limit=3)
    for number in range(100):
        row = record(f"src/a{number}.py", "performance", count=1)
        row["signals"][0]["sampling_variant"] = "positive-timeout"
        inventory.add(row, entry(row["path"]))
    special = record("src/z.py", "performance", count=1)
    special["signals"][0]["sampling_variant"] = "nonpositive-timeout"
    inventory.add(special, entry(special["path"]))
    assert {row["sampling_variant"] for row in inventory.summarize()["signals"]} == {
        "positive-timeout",
        "nonpositive-timeout",
    }


def source_fixture(root):
    (root / "src").mkdir()
    (root / "src/app.py").write_text(
        "import subprocess as process\nimport requests as http\nfrom typing import Protocol\n"
        'raise RuntimeError("never execute")\n'
        "class Port(Protocol):\n    def send(self, value): ...\n"
        "def run(url):\n"
        '    process.run(["uv", "sync", "--locked"], shell=True, check=True)\n'
        "    for item in range(2):\n        http.get(url, verify=False, timeout=2)\n"
        '    try:\n        pass\n    except ValueError:\n        logger.exception("do-not-retain-payload")\n'
    )
    (root / ".github/workflows").mkdir(parents=True)
    (root / ".github/workflows/check.yml").write_text(
        "on: push\npermissions: read-all\njobs:\n  check:\n    timeout-minutes: 4\n"
        "    steps:\n      - uses: actions/checkout@v4\n      - run: uv sync --locked\n"
    )


def test_real_capture_covers_five_dimensions_without_execution_or_scores(tmp_path):
    source_fixture(tmp_path)
    snapshot = collect(tmp_path)
    evidence = next(e for e in snapshot["evidence"] if e["kind"] == "control-analysis")
    analysis = evidence["stats"]
    assert all(row["examined_files"] > 0 for row in analysis["coverage"]["dimensions"].values())
    assert {d for row in analysis["signals"] for d in row["dimensions"]} == {
        "security",
        "delivery",
        "operability",
        "extensibility",
        "performance",
    }
    assert "do-not-retain-payload" not in json.dumps(analysis)
    ids = {e["id"]: e for e in snapshot["evidence"]}
    for signal in analysis["signals"]:
        source = ids[signal["source_evidence_id"]]
        assert source["path"] == signal["locations"][0]["path"]
        assert source["digest"] == signal["source_digest"]
    assert not snapshot["findings"]


def test_partial_syntax_keeps_bound_unavailable_context(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    snapshot = collect(tmp_path)
    analysis = next(e["stats"] for e in snapshot["evidence"] if e["kind"] == "control-analysis")
    assert analysis["coverage"]["unavailable_files"] == 1
    assert analysis["files"][0]["source_evidence_id"]


def test_controls_query_pages_filters_and_uses_captured_identity(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source_fixture(root)
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    before = deepcopy(service.get_report(snapshot["id"]))
    seen, offset = [], 0
    while True:
        page = service.query_evidence(
            snapshot["id"], view="controls", dimension="security", limit=2, offset=offset
        )
        seen.extend(page["items"])
        if page["next_offset"] is None:
            break
        offset = page["next_offset"]
    assert len(seen) == page["matched"]
    assert all("security" in row["dimensions"] for row in seen)
    assert {row["record_type"] for row in seen} == {"control_file", "control_signal"}
    selected = service.query_evidence(
        snapshot["id"], view="controls", candidate_kind="security.shell_execution"
    )
    assert selected["items"]
    assert all(row["kind"] == "security.shell_execution" for row in selected["items"])
    (root / "src/app.py").write_text("changed source")
    after = service.query_evidence(
        snapshot["id"], view="controls", candidate_kind="security.shell_execution"
    )
    assert after == selected
    assert service.get_report(snapshot["id"])["review"] is None
    assert before["assessment"] == service.get_report(snapshot["id"])["assessment"]
    with pytest.raises(ValueError):
        service.query_evidence(snapshot["id"], view="index", dimension="security")


def test_observation_import_preserves_unverified_execution_and_stale_scope(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    payload = b"def answer():\n    return 42\n"
    (root / "app.py").write_bytes(payload)
    report = tmp_path / "observation.json"
    data = {
        "schema": "pat.observation.v1",
        "type": "performance",
        "observed_at": "2026-10-31T12:00:00-04:00",
        "source": {
            "revision": "a" * 40,
            "files": [
                {"path": "app.py", "digest": "sha256:" + hashlib.sha256(payload).hexdigest()}
            ],
        },
        "scenario": {"name": "bounded fixture", "scope": ["app.py"]},
        "results": [{"name": "p95", "value": 12, "unit": "ms", "status": "observed"}],
        "limitations": ["Supplied result, not authenticated"],
    }
    report.write_text(json.dumps(data))
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root, [report])
    imported = next(e for e in snapshot["evidence"] if e["kind"] == "observation")
    assert imported["stats"]["sourceIdentity"]["overall"] == "unverified"
    assert imported["stats"]["coverage"]["source_matched_files"] == 1
    assert service.get_report(snapshot["id"])["review"] is None
    data["source"]["files"][0]["digest"] = "sha256:" + "b" * 64
    report.write_text(json.dumps(data))
    other = service.scan(root, [report])
    imported = next(e for e in other["evidence"] if e["kind"] == "observation")
    assert imported["stats"]["sourceIdentity"]["overall"] == "mismatch"
