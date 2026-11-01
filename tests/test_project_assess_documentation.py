import hashlib
import json

import pytest

from project_assess import documentation
from project_assess.burden_analysis import summarize_burden
from project_assess.doc_value.markdown import is_agent_guidance


def source(path, text, kind="documentation"):
    return {
        "id": path,
        "path": path,
        "kind": kind,
        "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
        "lines": len(text.splitlines()),
        "stats": {},
    }


def test_captured_section_overlap_retains_locations_and_authority_as_hints():
    passage = " ".join(f"specific-instruction-{index}" for index in range(40))
    texts = {
        "README.md": f"# Setup\nCanonical setup guidance.\n{passage}\n",
        "docs/development.md": f"# Developer guide\nDifferent preface.\n{passage}\nExtra instruction.\n",
    }
    before = dict(texts)
    result = documentation.captured_documentation(texts, set(texts), deep=True)
    assert result["schema"] == "doc-value.captured.v2"
    assert result["exactDuplicates"] == []
    assert result["sections"]["passageLeads"]
    lead = next(
        row for row in result["maintenanceLeads"] if row["kind"] == "repeated_guidance_passage"
    )
    assert {loc["path"] for loc in lead["locations"]} == set(texts)
    assert all(loc["line"] >= 1 for loc in lead["locations"])
    assert "lexical" in lead["metrics"]["basis"]
    assert (
        result["referenceEvidence"]["authorityHints"][0]["basis"]
        == "declared authority hint, not verified authority"
    )
    assert texts == before


def test_generated_and_required_boilerplate_do_not_become_upkeep_leads():
    passage = " ".join(f"boilerplate-{index}" for index in range(40))
    texts = {
        "README.md": f"# Guide\n{passage}\n",
        "docs/generated-copy.md": f"# Guide\n{passage}\n",
        "LICENSE.md": f"# Terms\n{passage}\n",
    }
    result = documentation.captured_documentation(texts, set(texts))
    assert result["sections"]["passageLeads"]
    assert not any(row["kind"] == "repeated_guidance_passage" for row in result["maintenanceLeads"])
    evidence = [source(path, text) for path, text in texts.items()]
    evidence.append({"id": "analysis", "kind": "documentation-analysis", "stats": result})
    burden = summarize_burden({"evidence": evidence})
    assert not any(row["kind"] == "duplicate_guidance" for row in burden["leads"])
    authored = documentation.captured_documentation(
        {"AGENTS.md": "# Rules\nDo not edit owner data without review.\n"}, {"AGENTS.md"}
    )
    assert authored["documents"][0]["roleHint"] == "guidance"


def test_literal_source_and_document_callers_use_only_captured_paths():
    texts = {
        "README.md": "# Setup\nSee `src/adapter.py` and `outside.py`.\n",
        "docs/guide.md": "# Guide\nAdapter: `src/adapter.py`.\n",
    }
    sources = {"tests/test_policy.py": "assert 'docs/guide.md' in policy\n"}
    known = set(texts) | set(sources) | {"src/adapter.py"}
    result = documentation.captured_documentation(texts, known, captured_sources=sources)
    refs = result["referenceEvidence"]
    assert {row["target"] for row in refs["references"]} == {"src/adapter.py", "docs/guide.md"}
    assert refs["sharedSourceReferences"][0]["documents"] == 2
    caller = next(row for row in refs["references"] if row["kind"] == "literal_document_caller")
    assert caller["path"] == "tests/test_policy.py" and caller["line"] == 1
    assert "not an executed caller or mandatory edit" in caller["basis"]
    assert any(
        row["kind"] == "documentation_caller_coupling_hint" for row in result["maintenanceLeads"]
    )


def test_script_declaration_mismatch_is_bound_and_ambiguous_scope_is_not_a_mismatch():
    texts = {
        "README.md": "# Run\n```sh\nnpm --prefix frontend run removed\nnpm --prefix frontend run build\nnpm run local\n```\n"
    }
    manifests = {"package.json": ["local"], "frontend/package.json": ["build"]}
    result = documentation.captured_documentation(
        texts, set(texts) | set(manifests), manifest_scripts=manifests
    )
    commands = result["referenceEvidence"]["commands"]
    assert [row["status"] for row in commands] == [
        "not_declared_in_captured_manifest",
        "declared",
        "scope_unresolved",
    ]
    lead = next(
        row
        for row in result["maintenanceLeads"]
        if row["kind"] == "documented_script_mismatch_hint"
    )
    assert lead["locations"][1] == {"path": "frontend/package.json", "line": 1}
    assert "execution remain unverified" in lead["metrics"]["basis"]
    assert (
        len(
            [
                row
                for row in result["maintenanceLeads"]
                if row["kind"] == "documented_script_mismatch_hint"
            ]
        )
        == 1
    )


def test_cd_context_and_uncaptured_manifests_do_not_claim_a_missing_script():
    texts = {"README.md": "```sh\ncd another-project\nnpm run elsewhere\n```\n"}
    result = documentation.captured_documentation(
        texts, set(texts) | {"package.json"}, manifest_scripts={"package.json": ["local"]}
    )
    assert result["referenceEvidence"]["commands"][0]["status"] == "scope_unresolved"
    assert result["maintenanceLeads"] == []
    result = documentation.captured_documentation(
        {"README.md": "npm --prefix ../outside run secret\n"},
        {"README.md"},
        manifest_scripts={"../outside/package.json": ["secret"]},
    )
    assert result["referenceEvidence"]["commands"][0]["status"] == "scope_unresolved"


def test_sparse_docs_are_deterministic_and_rich_bounds_stay_explicit(monkeypatch):
    assert documentation.captured_documentation({}, set())["sections"]["sections"] == []
    texts = {"docs/b.md": "# B\n`src/x.py`\n", "docs/a.md": "# A\n`src/x.py`\n"}
    known = set(texts) | {"src/x.py"}
    assert documentation.captured_documentation(
        texts, known
    ) == documentation.captured_documentation(dict(reversed(list(texts.items()))), known)
    monkeypatch.setattr(documentation, "MAX_REFERENCES", 1)
    result = documentation.captured_documentation(texts, known)
    assert len(result["referenceEvidence"]["references"]) == 1
    assert "Documentation literal-reference limit reached" in result["gaps"]
    json.dumps(result, allow_nan=False)
    chosen, _, omitted = documentation._rich_inputs(texts, byte_limit=20)
    assert len(chosen) == 1 and len(omitted) == 1


def test_document_mentions_do_not_starve_source_document_callers(monkeypatch):
    monkeypatch.setattr(documentation, "MAX_REFERENCES", 4)
    paths = {f"src/module{index}.py" for index in range(8)}
    texts = {"README.md": "# Setup\n" + " ".join(f"`{path}`" for path in sorted(paths))}
    sources = {"tests/test_policy.py": "assert 'README.md' in guidance\n"}
    result = documentation.captured_documentation(
        texts, paths | set(texts) | set(sources), captured_sources=sources
    )
    reference = result["referenceEvidence"]
    assert len(reference["references"]) == 4
    assert any(row["kind"] == "literal_document_caller" for row in reference["references"])
    counts = reference["scope"]["referenceCounts"]
    assert counts["documented_path_reference"] == {
        "observed_matches": 8,
        "retained_locations": 3,
        "omitted_matches": 5,
    }
    assert counts["literal_document_caller"] == {
        "observed_matches": 1,
        "retained_locations": 1,
        "omitted_matches": 0,
    }
    assert reference["scope"]["referenceSelection"] == "relationship_kind_round_robin"


def test_collector_integration_never_executes_documented_commands(tmp_path):
    from project_assess.collector import collect

    marker = tmp_path / "ran"
    (tmp_path / "README.md").write_text(
        f"# Run\n```sh\nnpm run absent\npython -c 'open({str(marker)!r}, \"w\")'\n```\n"
    )
    (tmp_path / "package.json").write_text('{"scripts":{"build":"touch ran"}}')
    snapshot = collect(tmp_path, analysis_profile="deep")
    result = next(
        entry["stats"]
        for entry in snapshot["evidence"]
        if entry["kind"] == "documentation-analysis"
    )
    assert result["schema"] == "doc-value.captured.v2"
    assert not marker.exists()


def test_agent_guidance_survives_document_and_rich_byte_caps(monkeypatch):
    monkeypatch.setattr(documentation, "MAX_DOCUMENTS", 3)
    texts = {f"000-archive/{i:03}.md": "# History\nFinished.\n" for i in range(20)}
    guidance = {
        "AGENTS.md": "# Rules\nUse the source.\n",
        "CLAUDE.md": "# Rules\nCheck the code.\n",
        ".agents/skills/review/SKILL.md": "# Review\nInspect callers.\n",
    }
    texts.update(guidance)
    result = documentation.captured_documentation(texts, set(texts), deep=True)
    assert {row["path"] for row in result["documents"]} == set(guidance)
    assert all(row["agentGuidance"] for row in result["documents"])
    assert result["scope"]["agentGuidanceCaptured"] == 3
    assert result["scope"]["agentGuidanceAnalyzed"] == 3
    assert result["scope"]["agentGuidanceRich"] == 3
    assert len(result["scope"]["omittedDocumentPaths"]) == 20
    selected, _, omitted = documentation._rich_inputs(
        {"000-guide.md": "# Guide\nAnother guide.\n", "AGENTS.md": guidance["AGENTS.md"]},
        byte_limit=len(guidance["AGENTS.md"].encode()),
    )
    assert list(selected) == ["AGENTS.md"]
    assert omitted == ["000-guide.md"]


def test_path_drift_distinguishes_uncaptured_from_unknown_existence():
    texts = {"AGENTS.md": "Use `src/current.py`, `src/large.py` and `src/gone.py`.\n"}
    captured = set(texts) | {"src/current.py"}
    result = documentation.captured_documentation(
        texts, captured, inventory_paths=captured | {"src/large.py"}, deep=True
    )
    drift = result["driftEvidence"]
    assert drift["version"] == documentation.DRIFT_VERSION
    checks = {row["reference"]: row for row in drift["pathChecks"]}
    assert checks["src/current.py"]["status"] == "captured"
    assert checks["src/large.py"]["status"] == "present_not_captured"
    assert checks["src/gone.py"]["status"] == "not_in_inspected_inventory"
    assert all(row["agentGuidance"] for row in checks.values())
    assert all(row["path"] == "AGENTS.md" and row["line"] == 1 for row in checks.values())
    assert "never proves nonexistence" in drift["scope"]["caveat"]
    leads = {row["kind"]: row for row in result["maintenanceLeads"]}
    assert leads["documented_path_uncaptured_hint"]["metrics"]["reference"] == "src/large.py"
    assert leads["documented_path_unresolved_hint"]["metrics"]["reference"] == "src/gone.py"
    unknown = documentation.captured_documentation(texts, captured)
    assert not unknown["driftEvidence"]["scope"]["inventoryProvided"]
    assert {
        row["status"]
        for row in unknown["driftEvidence"]["pathChecks"]
        if row["reference"] != "src/current.py"
    } == {"not_in_captured_snapshot"}


def test_exact_subject_competing_authority_targets_remain_review_hints():
    texts = {
        "AGENTS.md": "Canonical setup: `docs/current.md`\nCanonical release: `docs/release.md`\n",
        "README.md": "Source of truth for setup: `docs/legacy.md`\n",
        "docs/current.md": "# Current setup\n",
        "docs/legacy.md": "# Alternate setup\n",
        "docs/release.md": "# Release\n",
    }
    result = documentation.captured_documentation(texts, set(texts), deep=True)
    conflicts = result["driftEvidence"]["authorityConflicts"]
    assert len(conflicts) == 1 and conflicts[0]["subject"] == "setup"
    assert {claim["targets"][0] for claim in conflicts[0]["claims"]} == {
        "docs/current.md",
        "docs/legacy.md",
    }
    lead = next(
        row
        for row in result["maintenanceLeads"]
        if row["kind"] == "competing_authority_targets_hint"
    )
    assert lead["locations"] == [{"path": "AGENTS.md", "line": 1}, {"path": "README.md", "line": 1}]
    assert "precedence may differ" in lead["metrics"]["basis"]
    # Different literal subjects do not establish contradictory authority.
    texts["README.md"] = "Canonical architecture: `docs/legacy.md`\n"
    assert not documentation.captured_documentation(texts, set(texts))["driftEvidence"][
        "authorityConflicts"
    ]


def test_drift_limits_and_ambiguous_paths_remain_explicit(monkeypatch):
    texts = {"docs/guide.md": "`same.py`\nCanonical setup: `same.py`\nCanonical build: `same.py`\n"}
    captured = set(texts) | {"same.py", "docs/same.py"}
    result = documentation.captured_documentation(texts, captured)
    assert result["driftEvidence"]["pathChecks"][0]["status"] == "ambiguous_captured_target"
    assert not result["driftEvidence"]["authorityConflicts"]
    monkeypatch.setattr(documentation, "MAX_REFERENCES", 1)
    monkeypatch.setattr(documentation, "MAX_AUTHORITY_CLAIMS", 1)
    result = documentation.captured_documentation(texts, captured)
    scope = result["driftEvidence"]["scope"]
    assert scope["pathReferencesObserved"] == 3 and scope["pathReferencesOmitted"] == 2
    assert scope["authorityClaimsObserved"] == 2 and scope["authorityClaimsOmitted"] == 1
    assert "Documentation drift path-reference limit reached" in result["gaps"]
    assert "Documentation explicit-authority claim limit reached" in result["gaps"]


def test_drift_does_not_treat_external_or_expanded_tokens_as_literal_paths():
    texts = {
        "AGENTS.md": "Read `../outside.py`; https://example.invalid/a.py and `${ROOT}/hidden.py`.\n"
    }
    result = documentation.captured_documentation(texts, set(texts), inventory_paths=set(texts))
    checks = result["driftEvidence"]["pathChecks"]
    assert len(checks) == 1
    assert checks[0]["reference"] == "../outside.py" and checks[0]["status"] == "outside_scope"
    assert not result["maintenanceLeads"]


@pytest.mark.parametrize(
    "path",
    [
        "AGENTS.md",
        "sub/CLAUDE.md",
        "GEMINI.md",
        ".agents/skills/review/SKILL.md",
        ".claude/skills/review/references/policy.md",
        ".agents/rules/testing.md",
        ".claude/rules/python.md",
        ".cursor/rules/python.mdc",
        ".cursor/rules/nested/typescript.md",
        ".github/copilot-instructions.md",
        ".github/instructions/python.instructions.md",
    ],
)
def test_shared_agent_guidance_classification_is_pure_and_covers_known_paths(path):
    assert is_agent_guidance(path)


@pytest.mark.parametrize(
    "path",
    ["README.md", ".claude/settings.json", ".agents/skills/review/run.py", ".cursor/state.json"],
)
def test_shared_agent_guidance_does_not_classify_configuration_or_scripts(path):
    assert not is_agent_guidance(path)


def test_inline_agent_commands_are_checked_without_prose_or_execution_and_caps_are_visible(
    monkeypatch,
):
    texts = {
        "AGENTS.md": "Run `npm run retired-check` then `npm run build`.\n"
        "`npm run build`\n"
        "Plain prose mentioning npm run hypothetical is not a literal command.\n"
    }
    known = set(texts) | {"package.json"}
    result = documentation.captured_documentation(
        texts, known, manifest_scripts={"package.json": ["build"]}, deep=True
    )
    commands = result["referenceEvidence"]["commands"]
    assert [(row["line"], row["script"], row["status"]) for row in commands] == [
        (1, "retired-check", "not_declared_in_captured_manifest"),
        (1, "build", "declared"),
        (2, "build", "declared"),
    ]
    assert (
        sum(row["kind"] == "documented_script_mismatch_hint" for row in result["maintenanceLeads"])
        == 1
    )
    monkeypatch.setattr(documentation, "MAX_COMMAND_REFERENCES", 1)
    result = documentation.captured_documentation(
        texts, known, manifest_scripts={"package.json": ["build"]}
    )
    scope = result["referenceEvidence"]["scope"]
    assert scope["commandReferencesObserved"] == 3
    assert scope["commandReferencesRetained"] == 1
    assert scope["commandReferencesOmitted"] == 2
    assert "Documentation command-reference limit reached" in result["gaps"]


def test_root_readme_survives_small_document_and_rich_byte_caps(monkeypatch):
    monkeypatch.setattr(documentation, "MAX_DOCUMENTS", 2)
    texts = {
        "000-generic.md": "# Guide\nGeneric.\n",
        "AGENTS.md": "# Rules\nInspect.\n",
        "README.MD": "# Setup\nInstall.\n",
    }
    result = documentation.captured_documentation(texts, set(texts), deep=True)
    assert [row["path"] for row in result["documents"]] == ["AGENTS.md", "README.MD"]
    assert result["scope"]["omittedDocumentPaths"] == ["000-generic.md"]
    rich, _, omitted = documentation._rich_inputs(
        texts,
        byte_limit=sum(len(texts[path].encode()) for path in ("AGENTS.md", "README.MD")),
    )
    assert list(rich) == ["AGENTS.md", "README.MD"]
    assert omitted == ["000-generic.md"]


def test_path_noise_does_not_hide_agent_command_and_authority_drift_at_maintenance_cap():
    texts = {
        "README.md": "Canonical setup: `docs/other.md`\n"
        + "\n".join(f"`src/gone{index}.py`" for index in range(250)),
        "AGENTS.md": "Canonical setup: `docs/current.md`\nRun `npm run retired-check`.\n",
        "docs/current.md": "# Setup\nCurrent.\n",
        "docs/other.md": "# Setup\nAlternate.\n",
    }
    result = documentation.captured_documentation(
        texts,
        set(texts) | {"package.json"},
        inventory_paths=set(texts) | {"package.json"},
        manifest_scripts={"package.json": ["build"]},
        deep=True,
    )
    leads = result["maintenanceLeads"]
    assert len(leads) == 200
    assert any(
        row["kind"] == "documented_script_mismatch_hint"
        and row["locations"][0] == {"path": "AGENTS.md", "line": 2}
        for row in leads
    )
    assert any(
        row["kind"] == "competing_authority_targets_hint"
        and {loc["path"] for loc in row["locations"]} == {"AGENTS.md", "README.md"}
        for row in leads
    )
    scope = result["scope"]
    counts = scope["maintenanceLeadCounts"]
    assert scope["maintenanceLeadsObserved"] == 252
    assert scope["maintenanceLeadsOmitted"] == 52
    assert counts["documented_path_unresolved_hint"] == {
        "observed": 250,
        "retained": 198,
        "omitted": 52,
    }
    assert counts["documented_script_mismatch_hint"]["retained"] == 1
    assert counts["competing_authority_targets_hint"]["retained"] == 1
