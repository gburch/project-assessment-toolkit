import hashlib
import json

import pytest

from project_assess.collector import collect
from project_assess.service import AssessmentService


@pytest.mark.parametrize(
    "suffix,body",
    [
        ("py", "assert elapsed < 0.1\n"),
        ("ts", "expect(durationMs).toBeLessThan(100);\n"),
    ],
)
def test_timing_leads_reach_cross_dimension_burden_with_source_identity(tmp_path, suffix, body):
    if suffix == "ts":
        from project_assess.javascript_analysis import javascript_analyzer_identity

        if not javascript_analyzer_identity()["available"]:
            pytest.skip("Optional analysis extra unavailable")
    root = tmp_path / "project"
    root.mkdir()
    source = root / f"test_speed.{suffix}"
    source.write_text(body)
    captured = collect(root)
    assert captured == collect(root)
    assert source.read_text() == body
    aggregate = next(row for row in captured["evidence"] if row["kind"] == "burden-analysis")
    lead = next(
        row
        for row in aggregate["stats"]["leads"]
        if row["kind"] == "performance.timing_threshold_hint"
    )
    assert lead["dimensions"] == ["performance", "testing", "maintainability", "delivery"]
    assert (
        lead["locations"][0]["source_digest"]
        == "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
    )
    assert lead["cost_status"] == "not_established"
    assert lead["metrics"]["headroom"] == "unestablished"
    service = AssessmentService(tmp_path / "state")
    scan = service.scan(root)
    for dimension in ("performance", "testing", "maintainability", "delivery"):
        queried = service.query_evidence(scan["id"], view="burden", dimension=dimension)
        assert any(row["kind"] == "performance.timing_threshold_hint" for row in queried["items"])
        assert service.review_template(scan["id"])["ratings"][dimension]["burden"] is None


def test_burden_collection_is_deterministic_bound_and_inert(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "verification.py"
    source.write_text(
        "raise RuntimeError('must never execute')\n"
        "BROAD_PATHS = ('src/security/', 'src/schema/')\n"
        "def choose(paths, mode):\n"
        "    broad = [p for p in paths if p.startswith(BROAD_PATHS)]\n"
        "    full = mode == 'full' or bool(broad)\n"
        "    return full\n"
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    report = reports / "experience.json"
    context = {
        "schema": "pat.burden-context.v1",
        "reported_at": "2026-11-01T12:00:00-05:00",
        "attribution": {"role": "maintainer", "label": "Maintainer"},
        "source": {"revision": None, "files": []},
        "period": {"start": None, "end": "2026-11-01"},
        "scope": {"label": "Meaningful changes", "paths": []},
        "claims": [
            {
                "dimensions": ["testing", "security"],
                "statement": "Most changes encounter a test wait OR security rework.",
                "frequency": "most_changes",
                "workflow_stage": "mixed",
                "completion": "unknown",
            }
        ],
        "limitations": ["Attributed experience; recurrence of each cause unknown"],
    }
    report.write_text(json.dumps(context))
    before = source.read_bytes()
    first = collect(root, [report])
    assert first == collect(root, [report])
    assert source.read_bytes() == before
    aggregate = next(e for e in first["evidence"] if e["kind"] == "burden-analysis")
    leads = aggregate["stats"]["leads"]
    gate = next(row for row in leads if row["kind"] == "change_gate_selector")
    location = gate["locations"][0]
    assert location["source_digest"] == "sha256:" + hashlib.sha256(before).hexdigest()
    assert gate["cost_status"] == "not_established"
    assert first["facts"]["reports"]["burden-context"]["files"] == 1
    service = AssessmentService(tmp_path / "state", allowed_roots=[root, reports])
    snapshot = service.scan(root, [report])
    queried = service.query_evidence(snapshot["id"], view="burden", dimension="security")
    assert {row["kind"] for row in queried["items"]} >= {
        "change_gate_selector",
        "attributed_change_experience",
    }
    experience = next(
        row for row in queried["items"] if row["kind"] == "attributed_change_experience"
    )
    assert experience["frequency_scope"] == "joint_claim"
    assert experience["sourceIdentity"]["overall"] == "unverified"
    assert queried["burden_scope"][0]["coverage"]["leads_retained"] >= 1
    assert "gaps" in queried["burden_scope"][0]
    assert "limits" in queried["burden_scope"][0]
    assert (
        service.query_evidence(snapshot["id"], view="burden", dimension="documentation")["items"]
        == []
    )
    with pytest.raises(ValueError):
        service.query_evidence(snapshot["id"], view="controls", dimension="testing")
    with pytest.raises(PermissionError):
        AssessmentService(tmp_path / "state", allowed_roots=[root]).get_report(snapshot["id"])


def test_junit_duration_remains_case_sum_in_burden_evidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    report = tmp_path / "junit.xml"
    report.write_text('<testsuite><testcase time="8"/><testcase time="9"/></testsuite>')
    snapshot = collect(root, [report])
    burden = next(e["stats"] for e in snapshot["evidence"] if e["kind"] == "burden-analysis")
    timing = burden["timings"][0]
    assert timing["seconds"] == 17
    assert timing["wall_clock_seconds"] is None
    assert timing["timing_semantics"] == "sum_testcase_elapsed"


def test_malformed_burden_context_remains_explicit(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    report = tmp_path / "bad.json"
    report.write_text('{"schema":"pat.burden-context.v1", "claims": []}')
    snapshot = collect(root, [report])
    assert not snapshot["complete"]
    assert any("Malformed or unsupported burden-context" in gap for gap in snapshot["gaps"])
