"""Shared profiles and analyzer evidence work across languages and adapters."""

import json
from copy import deepcopy

import pytest

from project_assess.service import AssessmentService


def project(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src/App.swift").write_text('func run() { print("inspection only") }\n')
    (root / "src/Main.java").write_text(
        'class Main { void run() { System.out.println("inspection only"); } }\n'
    )
    (root / "sentinel.py").write_text(
        "raise AssertionError('Assessment must never execute this project')\n"
    )
    return root, AssessmentService(tmp_path / "state")


def test_standard_deep_changes_evidence_scope_without_changing_source_or_goals(tmp_path):
    root, service = project(tmp_path)
    first = service.scan(root)
    review = service.review_template(first["id"])
    for rating in review["ratings"].values():
        rating.update(
            capability=2,
            burden=1,
            confidence="low",
            rationale="Synthetic cited judgment.",
            evidence_ids=[first["evidence"][0]["id"]],
        )
    service.submit_review(first["id"], review)
    goals = service.set_targets(
        first["project_id"], profile="internal-service", expected_revision=0
    )
    second = service.scan(root, analysis_profile="deep")
    assert first["source"] == second["source"]
    assert first["scope_digest"] != second["scope_digest"]
    assert second["facts"]["collection"]["analysis_profile"] == "deep"
    assert second["facts"]["collection"]["limits"]["supported_text_bytes"] == 256 * 1024 * 1024
    assert service.get_report(second["id"])["goals"] == goals
    assert not service.progress(first["project_id"])["comparable"]
    assert len(service.history(first["project_id"])["goals"]) == 1


def test_java_swift_sarif_uses_shared_evidence_doctor_and_digest_context(tmp_path):
    root, service = project(tmp_path)
    supplied = tmp_path / "findings.sarif"
    supplied.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Synthetic multi-language producer"}},
                        "results": [
                            {
                                "ruleId": "example",
                                "level": "warning",
                                "message": {"text": "Inspect this source contract."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": path},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                            for path in ("src/App.swift", "src/Main.java")
                        ],
                    }
                ],
            }
        )
    )
    snapshot = service.scan(root, reports=[supplied])
    sources = [row for row in snapshot["evidence"] if row["kind"] == "source"]
    assert {row["stats"]["language"] for row in sources} == {"swift", "java"}
    assert all(row["stats"]["syntax_analysis"] == "not_available" for row in sources)
    leads = service.query_evidence(snapshot["id"], view="candidates", kind="sarif")
    assert leads["matched"] == 2
    assert all(row["source_identity"] == "unverified" for row in leads["items"])
    doctor = service.doctor(snapshot["id"])
    assert doctor["selection"]["families"]["sarif"]["returned"] == 2
    entry = next(row for row in sources if row["path"].endswith("swift"))
    context = service.source_context(snapshot["id"], entry["id"], line=1)
    assert context["source_identity"] == "snapshot_matched_live_bytes"
    assert "func run()" in context["excerpt"]
    (root / "src/App.swift").write_text("changed source\n")
    with pytest.raises(ValueError, match="changed since capture"):
        service.source_context(snapshot["id"], entry["id"])


def test_optional_vulture_is_explicit_shared_evidence_with_independent_confidence(tmp_path):
    pytest.importorskip("vulture")
    root, service = project(tmp_path)
    (root / "src/app.py").write_text(
        'def public_api(unused_argument):\n    return 1\n    print("unreachable")\n'
        '\ndef live_body():\n    if True:\n        print("reachable")\nlive_body()\n'
    )
    first = service.scan(root)
    assert not first["facts"].get("optional_analysis")
    before = {
        row.relative_to(root).as_posix(): row.read_bytes()
        for row in root.rglob("*")
        if row.is_file()
    }
    second = service.scan(root, analyzers=["vulture"])
    assert first["source"] == second["source"]
    assert first["scope_digest"] != second["scope_digest"]
    entry = next(row for row in second["evidence"] if row["kind"] == "analyzer-analysis")
    assert entry["stats"]["analyzer"]["name"] == "vulture"
    query = service.query_evidence(second["id"], view="candidates", kind="analyzer-analysis")
    assert query["items"]
    assert any(row["metrics"].get("producer_confidence") == 100 for row in query["items"])
    assert all(row["confidence"] == "low" for row in query["items"])
    diagnosis = service.doctor(second["id"])
    assert diagnosis["selection"]["families"]["analyzer:vulture"]["returned"]
    redundant = next(
        row
        for rows in diagnosis["groups"].values()
        for row in rows
        if row["kind"] == "redundant_condition"
    )
    assert "reachable body" in redundant["smallest_fix"]
    assert "body still executes" in redundant["verification"]
    assert redundant["family"] == "analyzer:vulture"
    assert all(
        row["candidate_confidence"]["basis"] == "captured_source_producer"
        for rows in diagnosis["groups"].values()
        for row in rows
        if row["family"] == "analyzer:vulture"
    )
    assert service.get_report(second["id"])["review"] is None
    assert service.get_report(second["id"])["goals"] is None
    assert {
        row.relative_to(root).as_posix(): row.read_bytes()
        for row in root.rglob("*")
        if row.is_file()
    } == before


@pytest.mark.parametrize(
    "options",
    [
        {"analysis_profile": "unlimited"},
        {"analysis_profile": []},
        {"analyzers": "vulture"},
        {"analyzers": ["vulture", "vulture"]},
        {"analyzers": ["project_plugin"]},
        {"analyzers": [{"command": "execute"}]},
    ],
)
def test_invalid_options_preserve_assessment_history(tmp_path, options):
    root, service = project(tmp_path)
    first = service.scan(root)
    before = deepcopy(service.history(first["project_id"]))
    with pytest.raises(ValueError):
        service.scan(root, **options)
    assert service.history(first["project_id"]) == before


def test_another_trusted_provider_uses_registry_and_existing_interfaces_without_new_branches(
    tmp_path, monkeypatch
):
    from project_assess import analyzer_registry
    from project_assess.cli import parser

    root, service = project(tmp_path)
    calls = []

    def metadata():
        return {
            "name": "synthetic_java",
            "version": "1",
            "available": True,
            "optional": True,
            "languages": ["java"],
        }

    def analyze(sources, **options):
        calls.append(options)
        source = next(row for row in sources if row["path"].endswith(".java"))
        candidate = {
            "id": "synthetic-java-lead",
            "kind": "unused_symbol",
            "lens": "quality",
            "confidence": "low",
            "role": "production",
            "locations": [{"path": source["path"], "line": 1, "end_line": 1}],
            "metrics": {"producer_confidence": 60},
            "source_evidence_ids": [source["evidence_id"]],
            "caveat": "Synthetic contract proof; not a real Java analysis.",
        }
        return {
            "schema_version": 1,
            "analyzer": metadata(),
            "status": "complete",
            "available": True,
            "configuration": {},
            "coverage": {"files": 1},
            "modules": [],
            "candidates": [candidate],
            "candidate_index": [candidate],
            "candidate_counts": {"total": 1, "retained": 1, "indexed": 1, "omitted_from_index": 0},
            "summary": {"candidate_count": 1},
            "limits": {},
            "gaps": [],
        }

    monkeypatch.setattr(
        analyzer_registry,
        "_BUILTINS",
        {**analyzer_registry._BUILTINS, "synthetic_java": (metadata, analyze)},
    )
    args = parser().parse_args(["scan", str(root), "--analyzer", "synthetic_java"])
    assert args.analyzers == ["synthetic_java"]
    assert analyzer_registry.list_analyzers()[-1]["name"] == "vulture"
    snapshot = service.scan(root, analyzers=args.analyzers)
    query = service.query_evidence(snapshot["id"], view="candidates", kind="analyzer-analysis")
    assert query["matched"] == 1
    assert query["items"][0]["locations"][0]["path"] == "src/Main.java"
    diagnosis = service.doctor(snapshot["id"])
    assert diagnosis["selection"]["families"]["analyzer:synthetic_java"]["returned"] == 1
    assert len(calls) == 1 and calls[0]["analysis_profile"] == "standard"
