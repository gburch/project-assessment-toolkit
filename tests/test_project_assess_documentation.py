import hashlib
import json

from project_assess import documentation
from project_assess.burden_analysis import summarize_burden


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
