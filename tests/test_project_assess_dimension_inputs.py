import json

import pytest

from project_assess.collector import collect
from project_assess.dimension_inputs import dimension_inputs
from project_assess.rubric import DIMENSIONS
from project_assess.service import AssessmentService, markdown_report


def test_source_inventory_does_not_imply_dedicated_dimension_analysis():
    assessment = {
        "facts": {"collection": {"discovery_complete": True}},
        "evidence": [{"id": "s1", "kind": "source", "path": "src/Main.swift"}],
    }
    result = dimension_inputs(assessment)
    assert set(result["dimensions"]) == set(DIMENSIONS)
    assert result["providers"]["source"]["evidence_count"] == 1
    assert result["providers"]["python"]["evidence_count"] == 0
    assert result["providers"]["optional"]["evidence_count"] == 0
    for dimension in result["dimensions"].values():
        assert dimension["limitations"]
        assert all(provider in result["providers"] for provider in dimension["provider_ids"])
        assert "capability" not in dimension and "burden" not in dimension
    assert result["collection_scope"]["python_source_complete"] is None


def test_actual_analysis_limits_and_missing_test_roles_remain_visible():
    assessment = {
        "facts": {},
        "evidence": [
            {
                "id": "a1",
                "kind": "test-value-static-analysis",
                "path": "<test-value-static-analysis>",
                "stats": {
                    "status": "partial",
                    "coverage": {
                        "test_definitions": 0,
                        "omitted_files": 400,
                        "areas": [{"path": "tests", "files": 400}],
                    },
                },
            }
        ],
    }
    provider = dimension_inputs(assessment)["providers"]["tests"]
    assert provider["evidence_ids"] == ["a1"]
    assert provider["analysis"][0]["status"] == "partial"
    assert provider["analysis"][0]["coverage"] == {
        "test_definitions": 0,
        "omitted_files": 400,
    }


def test_context_is_deterministic_bounded_and_keeps_ci_citations():
    entries = [
        {"id": f"s{i}", "path": f"src/p{i}/module.py", "kind": "python"} for i in range(3000)
    ]
    entries.append({"id": "ci", "path": ".github/workflows/check.yml", "kind": "configuration"})
    facts = {
        "ci": {"paths": [".github/workflows/check.yml"]},
        "manifests": {"scripts": ["test", "build"]},
    }
    first = dimension_inputs({"facts": facts, "evidence": entries})
    second = dimension_inputs({"facts": facts, "evidence": entries[::-1]})
    assert first == second
    assert first["providers"]["source"]["evidence_count"] == 3001
    assert first["providers"]["source"]["omitted_evidence_ids"] == 2996
    assert first["providers"]["ci"]["evidence_ids"] == ["ci"]
    assert first["providers"]["ci"]["script_count"] == 2
    assert len(json.dumps(first)) < 16000


def test_collected_evidence_is_routed_without_executing_project(tmp_path):
    (tmp_path / "app.py").write_text("raise RuntimeError('must never execute')\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test_smoke():\n    assert True\n")
    (tmp_path / "README.md").write_text("# Setup\nSee [missing](missing.md).\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="sample"\nversion="1"\ndependencies=["httpx"]\n'
    )
    result = dimension_inputs(collect(tmp_path))
    assert result["providers"]["python"]["evidence_count"] == 1
    assert result["providers"]["tests"]["evidence_count"] == 1
    assert result["providers"]["documentation"]["evidence_count"] == 1
    assert result["providers"]["dependencies"]["evidence_count"] >= 1
    assert result["providers"]["reports"]["evidence_count"] == 0


def test_shared_handoffs_expose_inputs_without_creating_judgments(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("def answer():\n    return 42\n")
    service = AssessmentService(tmp_path / "state")
    assessment = service.scan(root)
    report = service.get_report(assessment["id"])
    expected = report["goal_alignment"]["dimension_inputs"]
    assert service.overview(assessment["id"])["dimension_inputs"] == expected
    draft = service.review_template(assessment["id"], mode="fresh")
    packet = service.challenge_template(assessment["id"], draft)
    assert packet["context"]["dimension_inputs"] == expected
    assert set(expected["dimensions"]) == set(DIMENSIONS)
    assert expected["dimensions"]["security"]["limitations"][0] in markdown_report(report)
    assert report["review"] is None


def test_delivery_scripts_keep_manifest_citations_without_ci_files():
    assessment = {
        "facts": {"manifests": {"scripts": ["check"]}},
        "evidence": [
            {
                "id": "manifest",
                "kind": "manifest",
                "path": "package.json",
                "stats": {"scripts": ["check"]},
            }
        ],
    }
    provider = dimension_inputs(assessment)["providers"]["ci"]
    assert provider["evidence_count"] == 1
    assert provider["evidence_ids"] == ["manifest"]
    assert provider["kinds"] == ["manifest"]


def test_non_ci_configuration_remains_available_for_boundary_review():
    result = dimension_inputs(
        {"evidence": [{"id": "policy", "kind": "configuration", "path": "config/access.yaml"}]}
    )
    assert result["providers"]["source"]["evidence_ids"] == ["policy"]
    assert "source" in result["dimensions"]["security"]["provider_ids"]
    assert "source" in result["dimensions"]["operability"]["provider_ids"]


def test_deep_docs_and_dead_code_are_shared_development_inputs_without_extra_commands(tmp_path):
    (tmp_path / "app.py").write_text(
        "raise RuntimeError('never execute')\ndef answer():\n    return 1\n    print('dead')\n"
    )
    (tmp_path / "AGENTS.md").write_text("# Development\nRun `npm run retired-check`.\n")
    (tmp_path / "package.json").write_text('{"scripts":{"check":"never execute"}}\n')
    result = dimension_inputs(collect(tmp_path, analysis_profile="deep"))
    assert result["collection_scope"]["analysis_profile"] == "deep"
    for provider in ("dead_code", "documentation"):
        row = result["providers"][provider]
        assert row["required_in_deep"]
        assert row["collection_status"] in {"collected", "partial"}
        assert row["evidence_ids"]
    for dimension in result["dimensions"].values():
        assert {"dead_code", "documentation", "guidance"} <= set(dimension["provider_ids"])
    documentation = result["providers"]["documentation"]["analysis"][0]
    assert documentation["coverage"]["analyzedDocuments"] == 1
    assert documentation["coverage"]["analysisProfile"] == "deep"
    assert (tmp_path / "app.py").read_text().startswith("raise RuntimeError")


def test_missing_or_unavailable_required_deep_analysis_stays_explicit():
    assessment = {
        "facts": {"collection": {"analysis_profile": "deep"}},
        "evidence": [{"id": "swift", "kind": "source", "path": "App.swift"}],
    }
    result = dimension_inputs(assessment)
    for provider in ("documentation", "dead_code"):
        assert result["providers"][provider]["collection_status"] == "not_collected"
        assert result["providers"][provider]["gaps"]
    assessment["evidence"].append(
        {
            "id": "missing-tool",
            "kind": "analyzer-analysis",
            "path": "<joern-analysis>",
            "stats": {"status": "unavailable", "gaps": ["Trusted tool is unavailable"]},
        }
    )
    provider = dimension_inputs(assessment)["providers"]["dead_code"]
    assert provider["collection_status"] == "partial"
    assert provider["analysis"][0]["status"] == "unavailable"
    assert "Trusted tool is unavailable" in provider["gaps"]


@pytest.mark.parametrize(
    "stats",
    [
        {"scope": {"capturedDocuments": 2, "analyzedDocuments": 1}},
        {"scope": {"richOmittedDocuments": 1}},
        {"scope": {"linksTruncated": True}},
        {"scope": {"maintenanceLeadsOmitted": 1}},
        {"referenceEvidence": {"scope": {"omittedCallers": 1}}},
        {"referenceEvidence": {"scope": {"commandReferencesOmitted": 1}}},
        {"referenceEvidence": {"scope": {"referenceCounts": {"path": {"omitted_matches": 1}}}}},
        {"driftEvidence": {"scope": {"pathReferencesOmitted": 1}}},
        {"driftEvidence": {"scope": {"authorityClaimsOmitted": 1}}},
        {"sections": {"windows": {"truncated": True}}},
        {"sections": {"progress": {"passage": {"uncomparedPairs": 1}}}},
        {"sections": {"skippedInputs": [{"path": "large.md"}]}},
    ],
)
def test_required_documentation_status_uses_structured_omissions(stats):
    from project_assess.review_plan import build_review_plan

    assessment = {
        "facts": {"collection": {"analysis_profile": "deep"}},
        "evidence": [
            {"id": "docs", "kind": "documentation-analysis", "path": "<docs>", "stats": stats}
        ],
    }
    provider = dimension_inputs(assessment)["providers"]["documentation"]
    assert provider["collection_status"] == provider["analysis"][0]["status"] == "partial"
    for pack in build_review_plan(assessment)["dimensions"].values():
        check = next(
            row for row in pack["required_checks"] if row["topic"] == "documentation_drift"
        )
        assert check["status"] == "partial" and check["evidence_ids"] == ["docs"]


def test_semantic_freshness_gap_is_not_an_invented_collection_omission():
    assessment = {
        "evidence": [
            {
                "id": "docs",
                "kind": "documentation-analysis",
                "stats": {
                    "scope": {"capturedDocuments": 1, "analyzedDocuments": 1},
                    "gaps": ["Semantic freshness is not established by syntax checks"],
                },
            }
        ]
    }
    provider = dimension_inputs(assessment)["providers"]["documentation"]
    assert provider["collection_status"] == provider["analysis"][0]["status"] == "collected"
    assert provider["gaps"]
