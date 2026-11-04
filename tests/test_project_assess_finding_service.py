"""Finding decisions preserve transactional, replay and authorization boundaries."""

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

import project_assess.service as service_module
from project_assess.finding_closure import finding_reference
from project_assess.report_identity import canonical
from project_assess.service import AssessmentService, ConflictError


def captured_pair(tmp_path, reports=()):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("def greet():\n    return 'old'\n")
    service = AssessmentService(tmp_path / "state")
    origin = service.scan(root, list(reports))
    source = next(row for row in origin["evidence"] if row["path"] == "app.py")
    origin["findings"] = [
        {"severity": "high", "title": "Fixture finding", "evidence_ids": [source["id"]]}
    ]
    # Seed a native finding without coupling transaction tests to a scanner heuristic.
    with service._db(write=True) as db:
        db.execute("UPDATE assessments SET data=? WHERE id=?", (canonical(origin), origin["id"]))
    (root / "app.py").write_text("def greet():\n    return 'new'\n")
    current = service.scan(root)
    source = next(row for row in current["evidence"] if row["path"] == "app.py")
    event = {
        "finding_id": finding_reference(origin)["finding_id"],
        "assessment_id": current["id"],
        "source_digest": current["source"]["manifest_digest"],
        "status": "verified",
        "actor": "fixture reviewer",
        "rationale": "The current scoped implementation was reviewed",
        "evidence_ids": [source["id"]],
        "scope": [{"path": "app.py", "digest": source["digest"]}],
        "verification": {
            "basis": "source_review",
            "acceptance": "Current implementation satisfies the finite condition",
            "limitations": ["Source review, not runtime proof"],
        },
    }
    return service, origin, current, event, root


def count(service, table):
    with service._db() as db:
        return db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_two_concurrent_decisions_require_compare_and_swap(tmp_path):
    service, origin, current, event, _ = captured_pair(tmp_path)
    barrier = Barrier(2)

    def record(actor):
        peer = AssessmentService(service.state_dir)
        barrier.wait()
        try:
            return peer.record_finding(origin["id"], {**event, "actor": actor})
        except ConflictError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(record, ["reviewer one", "reviewer two"]))
    assert outcomes.count("conflict") == 1 and count(service, "finding_events") == 1
    result = service.finding_status(current["id"])
    assert result["items"][0]["status"] == "verified"
    assert result["items"][0]["event_count"] == 1


def test_replay_returns_original_decision_and_payload_reuse_is_rejected(tmp_path):
    service, origin, current, event, root = captured_pair(tmp_path)
    first = service.record_finding(origin["id"], event, request_id="finding-request")
    assert service.record_finding(origin["id"], event, request_id="finding-request") == first
    with pytest.raises(ConflictError):
        service.record_finding(
            origin["id"], {**event, "rationale": "different"}, request_id="finding-request"
        )
    accepted = {key: value for key, value in event.items() if key != "verification"}
    accepted["status"] = "accepted"
    second = service.record_finding(origin["id"], accepted, expected_event_id=first["id"])
    assert second["id"] != first["id"]
    assert service.record_finding(origin["id"], event, request_id="finding-request") == first
    assert count(service, "finding_events") == 2
    (root / "app.py").write_text("def greet():\n    return 'newer'\n")
    newer = service.scan(root)
    # Replay preserves identity; a new decision against old source is rejected.
    assert service.record_finding(origin["id"], event, request_id="finding-request") == first
    with pytest.raises(ConflictError, match="latest"):
        service.record_finding(origin["id"], event, expected_event_id=second["id"])
    state = service.finding_status(newer["id"])["items"][0]
    assert state["status"] == "needs_recheck" and state["recorded_status"] == "accepted"


def test_request_failure_rolls_back_event_and_idempotency_record(tmp_path, monkeypatch):
    service, origin, _, event, _ = captured_pair(tmp_path)

    def interrupted(*args):
        raise RuntimeError("simulated interruption after event insertion")

    with monkeypatch.context() as context:
        context.setattr(service, "_record_request", interrupted)
        with pytest.raises(RuntimeError, match="interruption"):
            service.record_finding(origin["id"], event, request_id="interrupted")
    assert count(service, "finding_events") == 0 and count(service, "requests") == 0
    result = service.record_finding(origin["id"], event, request_id="interrupted")
    assert result["status"] == "verified" and count(service, "finding_events") == 1


def as_v1(service):
    with service._db(write=True) as db:
        before = list(db.execute("SELECT id,data FROM assessments ORDER BY seq"))
        db.execute("DROP TABLE finding_events")
        db.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
    return before


def test_state_v1_migration_preserves_old_records_and_is_repeatable(tmp_path):
    service, _, current, _, _ = captured_pair(tmp_path)
    before = as_v1(service)
    for _ in range(2):
        reopened = AssessmentService(service.state_dir)
        with reopened._db() as db:
            assert list(db.execute("SELECT id,data FROM assessments ORDER BY seq")) == before
            assert db.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone() == ("2",)
        assert reopened.finding_status(current["id"])["items"] == []


def test_interrupted_migration_rolls_back_table_and_version_then_reopens(tmp_path, monkeypatch):
    service, _, _, _, _ = captured_pair(tmp_path)
    before = as_v1(service)
    real_connect = sqlite3.connect

    class InterruptedConnection:
        def __init__(self, *args, **kwargs):
            self.connection = real_connect(*args, **kwargs)

        def execute(self, sql, *args):
            if sql.startswith("UPDATE metadata SET value='2'"):
                raise RuntimeError("migration interrupted")
            return self.connection.execute(sql, *args)

        def __getattr__(self, key):
            return getattr(self.connection, key)

    with monkeypatch.context() as context:
        context.setattr(service_module.sqlite3, "connect", InterruptedConnection)
        with pytest.raises(RuntimeError, match="migration interrupted"):
            AssessmentService(service.state_dir)
    with real_connect(service.db_path) as db:
        assert db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone() == (
            "1",
        )
        assert (
            db.execute("SELECT name FROM sqlite_master WHERE name='finding_events'").fetchall()
            == []
        )
        assert list(db.execute("SELECT id,data FROM assessments ORDER BY seq")) == before
    reopened = AssessmentService(service.state_dir)
    assert count(reopened, "finding_events") == 0


def test_revoked_historical_origin_does_not_leak_or_block_current_report(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    report = private / "sensitive-results.xml"
    report.write_text("<testsuite><testcase name='private-case'/></testsuite>")
    owner, origin, current, event, root = captured_pair(tmp_path, [report])
    owner.record_finding(origin["id"], event)
    restricted = AssessmentService(owner.state_dir, [root])
    visible = restricted.finding_status(current["id"])
    assert visible["items"] == [] and visible["unavailable_origins"] == 1
    assert "private-case" not in json.dumps(visible) and "Fixture finding" not in json.dumps(
        visible
    )
    assert restricted.get_report(current["id"])["assessment"]["id"] == current["id"]
    with pytest.raises(PermissionError):
        restricted.record_finding(origin["id"], event)
    with pytest.raises(PermissionError):
        restricted.finding_status(origin["id"])


def test_cli_finding_roundtrip(tmp_path, capsys):
    from project_assess.cli import main

    service, origin, current, event, _ = captured_pair(tmp_path)
    supplied = tmp_path / "decision.json"
    supplied.write_text(json.dumps(event))
    args = ["--state-dir", str(service.state_dir)]
    assert main([*args, "finding-event", origin["id"], "--input", str(supplied)]) == 0
    stored = json.loads(capsys.readouterr().out)
    assert stored["verification_label"] == "reviewer_verified"
    assert main([*args, "finding-status", current["id"]]) == 0
    rows = json.loads(capsys.readouterr().out)["items"]
    assert rows[0]["last_event_id"] == stored["id"] and rows[0]["status"] == "verified"


def test_real_mcp_finding_discovery_and_calls(tmp_path):
    import asyncio
    import sys

    mcp = pytest.importorskip("mcp")
    from mcp.client.stdio import stdio_client

    service, origin, current, event, root = captured_pair(tmp_path)
    params = mcp.StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "project_assess.cli",
            "--state-dir",
            str(service.state_dir),
            "mcp",
            "--allowed-root",
            str(root),
        ],
    )

    async def exercise():
        async with stdio_client(params) as (read, write):
            async with mcp.ClientSession(read, write, read_timeout_seconds=15) as session:
                await session.initialize()
                discovered = {row.name: row for row in (await session.list_tools()).tools}
                assert {"finding_status", "record_finding", "ci_delta"} <= set(discovered)
                assert discovered["finding_status"].annotations.read_only_hint
                assert not discovered["record_finding"].annotations.read_only_hint
                result = await session.call_tool(
                    "record_finding", {"origin_assessment_id": origin["id"], "event": event}
                )
                assert not result.is_error
                assert result.structured_content["status"] == "verified"
                status = await session.call_tool("finding_status", {"assessment_id": current["id"]})
                assert (
                    not status.is_error
                    and status.structured_content["items"][0]["status"] == "verified"
                )
                delta = await session.call_tool(
                    "ci_delta", {"before_id": origin["id"], "after_id": current["id"]}
                )
                assert not delta.is_error

    asyncio.run(exercise())


def test_revoked_verification_basis_cannot_leak_through_public_origin(tmp_path):
    service, origin, _, event, root = captured_pair(tmp_path)
    private = tmp_path / "private"
    private.mkdir()
    report = private / "results.xml"
    report.write_text('<testsuite><testcase name="private-verification-case"/></testsuite>')
    basis = service.scan(root, [report])
    event.update(
        assessment_id=basis["id"],
        source_digest=basis["source"]["manifest_digest"],
        rationale="PRIVATE_DECISION_RATIONALE",
    )
    event["verification"]["acceptance"] = "PRIVATE_ACCEPTANCE"
    service.record_finding(origin["id"], event)
    current = service.scan(root)
    restricted = AssessmentService(service.state_dir, [root])
    with pytest.raises(PermissionError):
        restricted.get_report(basis["id"])
    status = restricted.finding_status(current["id"])
    assert status["unavailable_events"] == 1
    result = json.dumps(restricted.get_report(current["id"]))
    assert "PRIVATE_DECISION_RATIONALE" not in result
    assert "PRIVATE_ACCEPTANCE" not in result
    assert "private-verification-case" not in result
    assert "reviewer_verified" not in result


def test_hidden_later_decision_does_not_resurrect_visible_verification(tmp_path):
    service, origin, current, event, root = captured_pair(tmp_path)
    public = service.record_finding(origin["id"], event)
    private = tmp_path / "private"
    private.mkdir()
    report = private / "results.xml"
    report.write_text('<testsuite><testcase name="private-case"/></testsuite>')
    basis = service.scan(root, [report])
    hidden = {key: value for key, value in event.items() if key != "verification"}
    hidden.update(
        assessment_id=basis["id"],
        source_digest=basis["source"]["manifest_digest"],
        status="open",
        rationale="PRIVATE_REOPEN_REASON",
    )
    service.record_finding(origin["id"], hidden, expected_event_id=public["id"])
    current = service.scan(root)
    restricted = AssessmentService(service.state_dir, [root])
    status = restricted.finding_status(current["id"])
    item = status["items"][0]
    assert item["status"] == "needs_recheck"
    assert item["verification"] is None and item["verification_label"] == "unavailable"
    assert item["last_event_id"] is None
    assert "PRIVATE_REOPEN_REASON" not in json.dumps(status)
