"""Prompting stays source-bound context across collection, saved review and reports."""

import hashlib
import json
import subprocess
from copy import deepcopy

import pytest

from project_assess import collector, prompting_analysis
from project_assess.report_export import report_html
from project_assess.report_markdown import markdown_report
from project_assess.rubric import DIMENSIONS
from project_assess.service import AssessmentService


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    files = {
        "app.py": "from openai import OpenAI\nclient = OpenAI()\ndef answer(value):\n    return client.responses.create(model='fixture', input=value)\nraise RuntimeError('never execute')\n",
        "contracts.py": "from jsonschema import validate\ndef check(value):\n    validate(value, {})\n",
        "README.md": "# Prompted fixture\nAn assistant with bounded output.\n",
        ".agents/skills/develop/SKILL.md": "# Development guidance\nInspect callers before edits.\n",
        "prompts/reply.txt": "PRIVATE_PROMPT_BODY_SENTINEL\n",
        "prompts/reply.jinja": "PRIVATE_TEMPLATE_BODY_SENTINEL {{ value }}\n",
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root, AssessmentService(tmp_path / "state")


def draft(service, snapshot):
    review = service.review_template(snapshot["id"])
    review["coverage"]["scope"] = "focused"
    by_path = {row["path"]: row["id"] for row in snapshot["evidence"]}
    profile = review["prompting"]
    profile.update(
        level=3,
        confidence="medium",
        rationale="Synthetic hybrid workflow.",
        evidence_ids=[by_path["app.py"]],
    )
    profile["workflows"] = [
        {
            "name": "Answer a request",
            "control": "hybrid",
            "rationale": "Model interpretation inside coded boundaries.",
            "evidence_ids": [by_path["app.py"]],
        }
    ]
    profile["variability"].update(
        status="source_controls_only",
        rationale="Validation constrains shape; repeated outcomes are unknown.",
        evidence_ids=[by_path["contracts.py"]],
    )
    profile["intent"].update(
        min=1,
        max=2,
        basis="inferred",
        rationale="A provisional synthetic target scenario.",
        evidence_ids=[by_path["README.md"]],
    )
    profile["recommendations"] = [
        {
            "direction": "more_deterministic",
            "action": "Keep a stable rule in code when useful.",
            "rationale": "A synthetic right-sizing example.",
            "evidence_ids": [by_path[".agents/skills/develop/SKILL.md"]],
        }
    ]
    return review, by_path


def test_collection_captures_assets_and_separates_hints_without_auto_judgment(project):
    root, service = project
    snapshot = service.scan(root)
    summary = snapshot["facts"]["prompting"]
    counts = summary["summary"]["counts_by_kind"]
    assert counts["development_guidance"] == 1
    assert counts["runtime_prompt_asset"] == 2
    assert counts["model_client_setup"] == counts["model_invocation"] == 1
    assert "files" not in summary["coverage"]
    record = next(row for row in snapshot["evidence"] if row["id"] == summary["evidence_id"])
    assert "PRIVATE_PROMPT_BODY_SENTINEL" not in json.dumps(record["stats"])
    signals = service.query_evidence(
        snapshot["id"], view="prompting", candidate_kind="model_invocation"
    )
    assert signals["matched"] == 1 and signals["items"][0]["path"] == "app.py"
    files = service.query_evidence(snapshot["id"], view="prompting", candidate_kind="file", limit=1)
    assert files["matched"] == 6 and files["next_offset"] == 1
    profile = service.get_report(snapshot["id"])["prompting"]
    assert profile["level"] is None and profile["variability"]["status"] == "unknown"
    assert service.get_report(snapshot["id"])["review"] is None


def test_profile_roundtrip_preserves_citations_goals_and_safe_exports(project):
    root, service = project
    snapshot = service.scan(root)
    service.set_targets(snapshot["project_id"], profile="local-experiment", expected_revision=0)
    goals = deepcopy(service.get_report(snapshot["id"])["goals"])
    review, by_path = draft(service, snapshot)
    hostile = "<img src=x onerror=window.promptingOops=1>"
    review["prompting"]["rationale"] = hostile
    service.submit_review(snapshot["id"], review)
    report = service.get_report(snapshot["id"])
    assert report["prompting"]["level"] == 3
    assert report["prompting"]["fit"]["direction"] == "more_deterministic"
    assert report["prompting"]["intent"]["provisional"]
    assert report["goals"] == goals and len(report["goals"]["targets"]) == len(DIMENSIONS) == 8
    assert report["assessment"] == snapshot
    assert service.doctor(snapshot["id"])["prompting"] == report["prompting"]
    assert service.evolve(snapshot["id"])["goal_alignment"]["prompting"] == report["prompting"]
    md, html = markdown_report(report), report_html(report)
    for name in ("app.py", "contracts.py", "README.md", ".agents/skills/develop/SKILL.md"):
        assert by_path[name] in md and by_path[name] in html
    assert snapshot["facts"]["prompting"]["evidence_id"] in md
    assert snapshot["facts"]["prompting"]["evidence_id"] in html
    assert hostile not in md and hostile not in html
    assert "&lt;img" in html and "unknown" in md.lower()
    before = service.query_evidence(snapshot["id"], view="prompting")
    (root / "app.py").write_text("changed after capture\n")
    assert service.query_evidence(snapshot["id"], view="prompting") == before


def test_foreign_profile_citation_rolls_back_saved_review(project):
    root, service = project
    snapshot = service.scan(root)
    review, _ = draft(service, snapshot)
    review["prompting"]["workflows"][0]["evidence_ids"] = ["e-foreign"]
    with pytest.raises(ValueError, match="snapshot"):
        service.submit_review(snapshot["id"], review)
    assert service.get_report(snapshot["id"])["review"] is None


def test_prompting_scan_is_not_starved_by_dedicated_deep_provider(project, monkeypatch):
    root, service = project
    instant = collector.time.monotonic()
    clock, events = [instant], []
    monkeypatch.setattr(collector.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(prompting_analysis, "_CLOCK", lambda: clock[0])
    original = collector.analyze_prompting

    def prompting(*args, **kwargs):
        events.append("prompting")
        return original(*args, **kwargs)

    def provider(name, *args, **kwargs):
        events.append(name)
        clock[0] += 3600
        return {
            "schema_version": 1,
            "analyzer": {"name": name},
            "available": False,
            "status": "unavailable",
            "configuration": {},
            "limits": {},
            "coverage": {},
            "summary": {},
            "candidates": [],
            "candidate_index": [],
            "gaps": [],
        }

    monkeypatch.setattr(collector, "analyze_prompting", prompting)
    monkeypatch.setattr(collector, "run_analyzer", provider)
    snapshot = service.scan(root, analysis_profile="deep")
    assert events[0] == "prompting" and set(events[1:]) == {"joern", "vulture"}
    assert snapshot["facts"]["prompting"]["summary"]["counts_by_kind"]["model_invocation"] == 1
    assert snapshot["facts"]["prompting"]["limits"]["seconds"] == 300


def test_prompting_observation_survives_import_and_supports_only_repeated_scope(project, tmp_path):
    root, service = project
    git = ["git", "-C", str(root)]
    subprocess.run([*git, "init", "-q"], check=True, capture_output=True)
    subprocess.run([*git, "add", "."], check=True, capture_output=True)
    subprocess.run(
        [
            *git,
            "-c",
            "user.name=PAT fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "Fixture",
        ],
        check=True,
        capture_output=True,
    )
    revision = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    content = (root / "app.py").read_bytes()
    receipt = {
        "schema": "pat.observation.v1",
        "type": "prompting",
        "observed_at": "2026-11-03T12:00:00Z",
        "source": {
            "revision": revision,
            "files": [
                {"path": "app.py", "digest": "sha256:" + hashlib.sha256(content).hexdigest()}
            ],
        },
        "scenario": {"name": "Repeated fixture input", "scope": ["app.py"]},
        "results": [
            {"name": "within_criterion", "value": True, "unit": "boolean", "status": "observed"}
        ],
        "prompting": {
            "input_digest": "sha256:" + "a" * 64,
            "configuration_digest": "sha256:" + "b" * 64,
            "trials": 3,
            "distinct_outputs": 1,
            "comparison": "exact",
            "criterion": "Exact output bytes for declared fixture.",
        },
        "limitations": ["Synthetic supplied claims; no authenticated execution."],
    }
    path = tmp_path / "repeated.json"
    path.write_text(json.dumps(receipt))
    snapshot = service.scan(root, reports=[path])
    review, _ = draft(service, snapshot)
    observed = next(row for row in snapshot["evidence"] if row["kind"] == "observation")
    review["prompting"]["variability"].update(
        status="observed_repeatable",
        rationale="Reported repeated exact comparison within the supplied scope.",
        evidence_ids=[observed["id"]],
    )
    service.submit_review(snapshot["id"], review)
    assert (
        service.get_report(snapshot["id"])["prompting"]["variability"]["status"]
        == "observed_repeatable"
    )
    assert observed["stats"]["prompting"]["trials"] == 3
    assert any("supplied" in gap for gap in observed["stats"]["gaps"])
