import asyncio
import json
import sys

import pytest

mcp = pytest.importorskip("mcp", reason="Run with --extra mcp for protocol integration tests")
from mcp.client.stdio import stdio_client  # noqa: E402


def test_real_stdio_discovery_scan_review_targets_and_boundaries(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# Project\nA minimal, captured project.\n")
    state = tmp_path / "state"
    reports = tmp_path / "reports"
    reports.mkdir()
    supplied = reports / "test-value.json"
    supplied.write_text(
        json.dumps(
            {
                "schema": "test-value-audit.v3",
                "root": str(root),
                "tests": [],
                "gaps": [],
                "healthyCollection": True,
                "confidentOverlap": True,
            }
        )
    )
    params = mcp.StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "project_assess.cli",
            "--state-dir",
            str(state),
            "mcp",
            "--allowed-root",
            str(root),
            "--allowed-root",
            str(reports),
        ],
    )

    async def exercise():
        async with stdio_client(params) as (read, write):
            async with mcp.ClientSession(read, write, read_timeout_seconds=15) as session:
                initialization = await session.initialize()
                assert initialization.server_info.name == "PAT"
                discovered = await session.list_tools()
                names = {tool.name for tool in discovered.tools}
                assert {
                    "scan_project",
                    "get_report",
                    "get_badge",
                    "submit_review",
                    "set_targets",
                    "get_progress",
                    "inspect_evidence",
                    "doctor",
                    "evolve",
                    "get_history",
                    "get_tool_info",
                    "start_assessment",
                    "query_evidence",
                    "inspect_source_context",
                } <= names
                assert all(
                    tool.annotations.read_only_hint
                    for tool in discovered.tools
                    if tool.name
                    in {
                        "get_report",
                        "get_badge",
                        "doctor",
                        "evolve",
                        "get_tool_info",
                        "query_evidence",
                    }
                )
                assert not next(
                    tool.annotations.read_only_hint
                    for tool in discovered.tools
                    if tool.name == "scan_project"
                )
                denied = await session.call_tool("scan_project", {"root": str(tmp_path)})
                assert denied.is_error
                captured = await session.call_tool(
                    "scan_project", {"root": str(root), "reports": [str(supplied)]}
                )
                assert not captured.is_error
                snapshot = captured.structured_content
                assert snapshot["source"]["root"] == str(root.resolve())
                identity = await session.call_tool("get_tool_info", {})
                assert not identity.is_error and identity.structured_content[
                    "code_digest"
                ].startswith("sha256:")
                assert identity.structured_content["allowed_roots"] == [
                    str(root.resolve()),
                    str(reports.resolve()),
                ]
                brief = await session.call_tool(
                    "get_report", {"assessment_id": snapshot["id"], "brief": True}
                )
                assert (
                    not brief.is_error
                    and brief.structured_content["assessment_id"] == snapshot["id"]
                )
                assert "evidence" not in brief.structured_content
                queried = await session.call_tool(
                    "query_evidence",
                    {"assessment_id": snapshot["id"], "path": "README.md", "limit": 1},
                )
                assert not queried.is_error and queried.structured_content["returned"] == 1
                assert queried.structured_content["items"][0]["path"] == "README.md"
                context = await session.call_tool(
                    "inspect_source_context",
                    {
                        "assessment_id": snapshot["id"],
                        "evidence_id": queried.structured_content["items"][0]["id"],
                        "line": 1,
                        "end_line": 1,
                    },
                )
                assert not context.is_error
                assert (
                    context.structured_content["source_identity"] == "snapshot_matched_live_bytes"
                )
                assert "# Project" in context.structured_content["excerpt"]
                invalid_query = await session.call_tool(
                    "query_evidence", {"assessment_id": snapshot["id"], "limit": 101}
                )
                assert invalid_query.is_error
                badge = await session.call_tool(
                    "get_badge", {"assessment_id": snapshot["id"], "dimension": "testing"}
                )
                assert not badge.is_error and badge.structured_content["schemaVersion"] == 1
                assert "C?/5" in badge.structured_content["message"]
                assert str(root) not in json.dumps(badge.structured_content)
                invalid_badge = await session.call_tool(
                    "get_badge", {"assessment_id": snapshot["id"], "dimension": "../private"}
                )
                assert invalid_badge.is_error
                diagnosis = await session.call_tool("doctor", {"assessment_id": snapshot["id"]})
                assert not diagnosis.is_error
                assert diagnosis.structured_content["selection"]["limit"] == 20
                assert diagnosis.structured_content["source"] == snapshot["source"]
                assert set(diagnosis.structured_content["groups"]) == {
                    "reuse",
                    "quality",
                    "efficiency",
                }
                assert "ratings" not in diagnosis.structured_content
                plan = await session.call_tool("evolve", {"assessment_id": snapshot["id"]})
                assert not plan.is_error
                assert plan.structured_content["assessment_id"] == snapshot["id"]
                assert plan.structured_content["source"] == snapshot["source"]
                assert plan.structured_content["goal_alignment"]["status"] == "no_goals"
                assert (
                    plan.structured_content["goal_alignment"]
                    == diagnosis.structured_content["goal_alignment"]
                )
                unknown_diagnosis = await session.call_tool("doctor", {"assessment_id": "unknown"})
                assert unknown_diagnosis.is_error
                documentation = snapshot["facts"]["documentation"]["doc_value"]
                inspected = await session.call_tool(
                    "inspect_evidence",
                    {"assessment_id": snapshot["id"], "evidence_id": documentation["evidence_id"]},
                )
                assert inspected.structured_content["evidence"]["kind"] == "documentation-analysis"
                evidence = await session.call_tool(
                    "inspect_evidence", {"assessment_id": snapshot["id"]}
                )
                assert not evidence.is_error
                imported = next(
                    item
                    for item in evidence.structured_content["evidence"]
                    if item["kind"] == "test-value"
                )
                assert imported["stats"]["claims"]["source"] == "supplied"
                assert imported["stats"]["sourceIdentity"]["overall"] == "unknown"
                template = await session.call_tool(
                    "review_template", {"assessment_id": snapshot["id"]}
                )
                reviewed = await session.call_tool(
                    "submit_review",
                    {
                        "assessment_id": snapshot["id"],
                        "review": template.structured_content,
                        "request_id": "review-once",
                    },
                )
                assert not reviewed.is_error
                targets = {
                    "project_id": snapshot["project_id"],
                    "profile": "local-experiment",
                    "expected_revision": 0,
                    "request_id": "targets-once",
                }
                saved = await session.call_tool("set_targets", targets)
                assert not saved.is_error and saved.structured_content["revision"] == 1
                plan = await session.call_tool("evolve", {"assessment_id": snapshot["id"]})
                assert not plan.is_error
                assert plan.structured_content["goal_alignment"]["goal_revision"] == 1
                testing = plan.structured_content["goal_alignment"]["dimensions"]["testing"]
                assert testing["capability_gap"] is None and testing["action"] == "inspect"
                replay = await session.call_tool("set_targets", targets)
                assert replay.structured_content == saved.structured_content
                conflict = await session.call_tool(
                    "set_targets", {**targets, "request_id": "another-save"}
                )
                assert conflict.is_error
                report = await session.call_tool("get_report", {"assessment_id": snapshot["id"]})
                assert (
                    report.structured_content["review"]["ratings"]["testing"]["capability"] is None
                )
                invalid = await session.call_tool("get_report", {"assessment_id": "unknown"})
                assert invalid.is_error

                source_before = (root / "README.md").read_bytes()
                scored = json.loads(json.dumps(template.structured_content))
                source_evidence = next(
                    entry["id"]
                    for entry in evidence.structured_content["evidence"]
                    if entry["path"] == "README.md"
                )
                for dimension, rating in scored["ratings"].items():
                    rating.update(
                        capability=2 if dimension == "extensibility" else 3,
                        burden=2,
                        confidence="medium",
                        burden_basis="source_estimate",
                        burden_confidence="low",
                        rationale="A synthetic scored review for this protocol fixture, not a real capability assessment.",
                        evidence_ids=[source_evidence],
                    )
                scored_review = await session.call_tool(
                    "submit_review",
                    {
                        "assessment_id": snapshot["id"],
                        "review": scored,
                        "request_id": "scored-review",
                    },
                )
                assert not scored_review.is_error
                scored_targets = {
                    dimension: {
                        "capability_min": 4 if dimension == "testing" else 3,
                        "burden_max": 2,
                    }
                    for dimension in scored["ratings"]
                }
                scored_goals = await session.call_tool(
                    "set_targets",
                    {
                        "project_id": snapshot["project_id"],
                        "targets": scored_targets,
                        "expected_revision": saved.structured_content["revision"],
                        "request_id": "scored-targets",
                    },
                )
                assert not scored_goals.is_error
                before = await session.call_tool(
                    "get_history", {"project_id": snapshot["project_id"]}
                )
                assert not before.is_error
                assert before.structured_content["reviews"][-1] == scored_review.structured_content
                assert before.structured_content["goals"][-1] == scored_goals.structured_content

                plan = await session.call_tool("evolve", {"assessment_id": snapshot["id"]})
                assert not plan.is_error
                assert plan.structured_content["assessment_id"] == snapshot["id"]
                assert plan.structured_content["project_id"] == snapshot["project_id"]
                assert plan.structured_content["source"] == snapshot["source"]
                alignment = plan.structured_content["goal_alignment"]
                assert alignment["status"] == "ready"
                assert alignment["review_id"] == scored_review.structured_content["id"]
                assert alignment["goal_revision"] == scored_goals.structured_content["revision"]
                for dimension, current, target in (("testing", 3, 4), ("extensibility", 2, 3)):
                    item = alignment["dimensions"][dimension]
                    assert item["action"] == "strengthen"
                    assert item["next_capability"] == target
                    assert item["current"] == {"capability": current, "burden": 2}
                    assert item["target"] == {"capability_min": target, "burden_max": 2}
                    assert (item["capability_gap"], item["burden_gap"]) == (1, 0)
                    assert item["evidence_ids"] == [source_evidence]
                assert all(
                    item["action"] == "maintain"
                    for dimension, item in alignment["dimensions"].items()
                    if dimension not in {"testing", "extensibility"}
                )
                after = await session.call_tool(
                    "get_history", {"project_id": snapshot["project_id"]}
                )
                assert not after.is_error
                assert after.structured_content == before.structured_content
                assert (root / "README.md").read_bytes() == source_before
                compact_scan = await session.call_tool("start_assessment", {"root": str(root)})
                assert (
                    not compact_scan.is_error and "evidence" not in compact_scan.structured_content
                )
                assert compact_scan.structured_content["assessment_id"] != snapshot["id"]
                assert (
                    compact_scan.structured_content["source"]["manifest_digest"]
                    == snapshot["source"]["manifest_digest"]
                )

    asyncio.run(exercise())
