import asyncio
import json
import os
import subprocess
import sys

import pytest

from project_assess.service import AssessmentService


@pytest.fixture
def captured(tmp_path):
    root = tmp_path / "project"
    package = root / "src" / "demo"
    package.mkdir(parents=True)
    (package / "provider.py").write_text(
        "from .contracts import invoke\n\ndef recover():\n    return invoke()\n"
    )
    (package / "contracts.py").write_text("def invoke():\n    return 1\n")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_provider.py").write_text(
        "from demo.provider import recover\ndef test_recovery():\n    assert recover() == 1\n"
    )
    (root / "README.md").write_text(
        "# Setup and recovery\nInspect src/demo/provider.py and preserve its contract.\n"
    )
    (root / "pyproject.toml").write_text('[project]\nname="demo"\nversion="0.0.0"\n')
    service = AssessmentService(tmp_path / "state", allowed_roots=[root])
    assessment = service.scan(root, analysis_profile="deep")
    return service, assessment, root


def test_review_plan_pages_keep_identity_source_locations_and_exact_source_context(captured):
    service, assessment, _ = captured
    full = service.query_evidence(
        assessment["id"], view="review-plan", dimension="extensibility", limit=100, max_chars=100000
    )
    assert full["source"] == assessment["source"]
    assert full["scope_digest"] == assessment["scope_digest"]
    assert full["review_plan_scope"]["version"] == "4"
    assert {row["record_type"] for row in full["items"]} >= {
        "dimension_review_scope",
        "source_task",
        "captured_connection",
    }
    assert full["next_offset"] is None and full["oversized_rows"] == 0
    paged, offset = [], 0
    while True:
        page = service.query_evidence(
            assessment["id"],
            view="review-plan",
            dimension="extensibility",
            offset=offset,
            limit=2,
            max_chars=100000,
        )
        assert page["offset"] == offset and page["returned"] == len(page["items"])
        assert page["source"] == full["source"]
        paged.extend(page["items"])
        if page["next_offset"] is None:
            break
        assert page["next_offset"] == offset + page["returned"]
        offset = page["next_offset"]
    assert paged == full["items"]
    sources = {entry["id"]: entry for entry in assessment["evidence"]}
    for row in full["items"]:
        assert row["dimension"] == "extensibility"
        if row["record_type"] == "source_task":
            original = sources[row["evidence_id"]]
            assert (row["path"], row["digest"]) == (original["path"], original["digest"])
            if row["path"].endswith("provider.py"):
                context = service.source_context(
                    assessment["id"], row["evidence_id"], row["line"], row["end_line"]
                )
                assert context["digest"] == row["digest"] and "recover" in context["excerpt"]
        elif row["record_type"] == "captured_connection":
            assert row["source_evidence_id"] in sources and row["target_evidence_id"] in sources


def test_review_plan_filters_located_tasks_and_keeps_unfiltered_scope_available(captured):
    service, assessment, _ = captured
    filtered = service.query_evidence(
        assessment["id"],
        view="review-plan",
        dimension="operability",
        path="src/demo/",
        role="production",
        max_chars=100000,
    )
    assert filtered["items"]
    for row in filtered["items"]:
        assert row["dimension"] == "operability"
        if row["record_type"] == "source_task":
            assert row["path"].startswith("src/demo/") and row["role"] == "production"
        else:
            assert any(location["path"].startswith("src/demo/") for location in row["locations"])
    scope = service.query_evidence(
        assessment["id"], view="review-plan", dimension="operability", max_chars=100000
    )["items"][0]
    assert scope["record_type"] == "dimension_review_scope" and scope["questions"]
    assert "selection" in scope and scope["selection"]["selected_source_records"] >= 2


def test_review_plan_output_budget_never_silently_skips_paging_positions(captured):
    service, assessment, _ = captured
    full = service.query_evidence(
        assessment["id"], view="review-plan", dimension="documentation", limit=100, max_chars=100000
    )
    offset, visited = 0, 0
    while True:
        page = service.query_evidence(
            assessment["id"],
            view="review-plan",
            dimension="documentation",
            limit=2,
            offset=offset,
            max_chars=4000,
        )
        assert len(json.dumps(page, indent=2)) <= 4000
        assert page["returned"] > 0
        assert page["matched"] == full["matched"]
        for index, row in enumerate(page["items"]):
            if "omitted" in row:
                assert page["oversized_rows"] == 1
                retry = service.query_evidence(
                    assessment["id"],
                    view="review-plan",
                    dimension="documentation",
                    limit=1,
                    offset=offset + index,
                    max_chars=100000,
                )
                assert retry["items"] == [full["items"][offset + index]]
            else:
                assert row == full["items"][offset + index]
        visited += page["returned"]
        if page["next_offset"] is None:
            break
        assert page["next_offset"] == offset + page["returned"]
        offset = page["next_offset"]
    assert visited == full["matched"]


@pytest.mark.parametrize(
    "filters",
    [{"dimension": "unknown"}, {"kind": "python"}, {"candidate_kind": "file"}, {"line": 1}],
)
def test_review_plan_rejects_inapplicable_filters(captured, filters):
    service, assessment, _ = captured
    with pytest.raises(ValueError):
        service.query_evidence(assessment["id"], view="review-plan", **filters)


def test_review_plan_keeps_saved_assessment_goals_and_history_unchanged_and_refuses_stale_context(
    captured, tmp_path
):
    service, assessment, root = captured
    service.set_targets(assessment["project_id"], profile="local-experiment", expected_revision=0)
    before = service.get_report(assessment["id"])
    history = service.history(assessment["project_id"])
    provider = root / "src" / "demo" / "provider.py"
    provider.write_text("raise RuntimeError('changed source must not execute')\n")
    result = service.query_evidence(
        assessment["id"],
        view="review-plan",
        dimension="operability",
        path="provider.py",
        max_chars=100000,
    )
    task = next(row for row in result["items"] if row["record_type"] == "source_task")
    assert task["digest"] == next(
        entry["digest"] for entry in assessment["evidence"] if entry["id"] == task["evidence_id"]
    )
    with pytest.raises(ValueError, match="changed since capture"):
        service.source_context(
            assessment["id"], task["evidence_id"], task["line"], task["end_line"]
        )
    after = service.get_report(assessment["id"])
    assert after["assessment"] == before["assessment"]
    assert after["review"] == before["review"]
    assert after["goals"] == before["goals"]
    assert service.history(assessment["project_id"]) == history
    denied = tmp_path / "other"
    denied.mkdir()
    restricted = AssessmentService(service.state_dir, allowed_roots=[denied])
    with pytest.raises(PermissionError):
        restricted.query_evidence(assessment["id"], view="review-plan")


def test_installed_cli_reads_same_review_packet(captured, tmp_path):
    service, assessment, _ = captured
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    command = [
        sys.executable,
        "-m",
        "project_assess.cli",
        "--state-dir",
        str(service.state_dir),
        "evidence-query",
        assessment["id"],
        "--view",
        "review-plan",
        "--dimension",
        "extensibility",
        "--max-chars",
        "100000",
    ]
    result = subprocess.run(
        command, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20, check=False
    )
    assert result.returncode == 0, result.stderr
    cli = json.loads(result.stdout)
    shared = service.query_evidence(
        assessment["id"], view="review-plan", dimension="extensibility", max_chars=100000
    )
    assert cli == shared


def test_real_mcp_discovers_and_queries_read_only_review_plan(captured):
    mcp = pytest.importorskip("mcp", reason="Optional MCP SDK not installed")
    from mcp.client.stdio import stdio_client

    service, assessment, root = captured
    before = service.history(assessment["project_id"])
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
            async with mcp.ClientSession(read, write, read_timeout_seconds=20) as session:
                await session.initialize()
                tools = await session.list_tools()
                query = next(tool for tool in tools.tools if tool.name == "query_evidence")
                assert query.annotations.read_only_hint
                response = await session.call_tool(
                    "query_evidence",
                    {
                        "assessment_id": assessment["id"],
                        "view": "review-plan",
                        "dimension": "performance",
                        "max_chars": 100000,
                    },
                )
                assert not response.is_error
                expected = service.query_evidence(
                    assessment["id"], view="review-plan", dimension="performance", max_chars=100000
                )
                assert response.structured_content == expected
                source_task = next(
                    row for row in expected["items"] if row["record_type"] == "source_task"
                )
                context = await session.call_tool(
                    "inspect_source_context",
                    {
                        "assessment_id": assessment["id"],
                        "evidence_id": source_task["evidence_id"],
                        "line": source_task["line"],
                        "end_line": source_task["end_line"],
                    },
                )
                assert (
                    not context.is_error
                    and context.structured_content["digest"] == source_task["digest"]
                )
                invalid = await session.call_tool(
                    "query_evidence",
                    {"assessment_id": assessment["id"], "view": "review-plan", "kind": "python"},
                )
                assert invalid.is_error

    asyncio.run(exercise())
    assert service.history(assessment["project_id"]) == before
