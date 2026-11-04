"""Agent-run assessments: early review checks, bounded views and findable evidence."""

from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from project_assess import joern_setup
from project_assess.cli import main
from project_assess.collector import _collapse_repeated_gaps, collect
from project_assess.documentation import _path_check, _path_suffixes
from project_assess.output_budget import BRIEF_CHARS, DOCTOR_CHARS, fit_budget
from project_assess.progress import report as report_progress
from project_assess.progress import stderr_progress
from project_assess.provenance import tool_info
from project_assess.report_markdown import markdown_report
from project_assess.review_plan import dimension_coverage
from project_assess.rubric import DIMENSIONS
from project_assess.service import AssessmentService, BurdenSupportError, _doctor_row_brief
from project_assess.source_controls import analyze_python_controls
from project_assess.static_analysis import role_scope, source_role


def _project(tmp_path, files):
    root = tmp_path / "project"
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    return root


@pytest.fixture
def scanned(tmp_path):
    root = _project(
        tmp_path,
        {
            "src/app.py": "def run():\n    return 1\n",
            "docs/guide.md": "See [app.py](../src/app.py).\n",
        },
    )
    service = AssessmentService(tmp_path / "state")
    return service, root, service.scan(str(root))


def _estimate(service, snapshot, *dimensions):
    """A fresh draft whose medium burden estimates all lack their required support."""
    review = service.review_template(snapshot["id"], mode="fresh")
    source = next(row["id"] for row in snapshot["evidence"] if row["kind"] == "python")
    for dimension in dimensions:
        review["ratings"][dimension].update(
            capability=3,
            burden=2,
            burden_basis="source_estimate",
            burden_confidence="medium",
            confidence="medium",
            rationale="Authored estimate.",
            evidence_ids=[source],
        )
        review["coverage"]["dimension_reviews"][dimension].update(
            status="reviewed", rationale="Reviewed.", evidence_ids=[source]
        )
    review["methodology"]["reviewer_id"] = "author"
    review["methodology"]["dimensions"].update(dict.fromkeys(dimensions, "reassessed"))
    review["change_traces"] = [
        {
            "id": "trace",
            "title": "Change",
            "steps": [{"owner": "app", "change": "edit", "evidence_ids": [source]}],
            "cost": "Small.",
            "invariant": "Holds.",
            "counterevidence": "None.",
            "gaps": [],
        }
    ]
    return review


def test_check_reports_every_failing_dimension_without_saving(scanned):
    service, _, snapshot = scanned
    review = _estimate(service, snapshot, "security", "testing")
    analysis = next(row["id"] for row in snapshot["evidence"] if row["kind"] == "burden-analysis")
    support = {
        "claim": "Burden.",
        "scope": "workflow",
        "scope_description": "One path.",
        "observation_ids": [],
        "change_trace_ids": [],
        "representativeness": "Typical.",
        "counterevidence": "None.",
        "freshness": "Current.",
        "limitations": [],
        "corroboration_ids": [analysis],
        "counterevidence_ids": [analysis],
    }
    review["ratings"]["security"]["burden_support"] = support
    result = service.check_review(snapshot["id"], review)
    assert result["valid"] is False and result["saved"] is False
    error = result["errors"][0]
    assert error["type"] == "burden_support"
    assert {issue["dimension"] for issue in error["issues"]} == {"security", "testing"}
    security = next(issue for issue in error["issues"] if issue["dimension"] == "security")
    fields = {gap["field"]: gap["failures"] for gap in security["gaps"]}
    assert any(analysis in item for item in fields["burden_support.corroboration_ids"])
    assert fields["burden_support.change_trace_ids"] == []
    assert analysis in error["message"] and "testing" in error["message"]
    assert service.get_report(snapshot["id"])["review"] is None
    missing = "e-" + "0" * 24
    review["ratings"]["security"]["burden_support"]["observation_ids"] = [missing]
    unknown = service.check_review(snapshot["id"], review)["errors"][0]
    assert unknown["type"] == "validation" and missing in unknown["message"]


@pytest.mark.parametrize("field", ["observation_ids", "change_trace_ids"])
def test_review_errors_never_echo_submitted_identifiers(scanned, field):
    service, _, snapshot = scanned
    token = "ghp_" + "a1b2c3d4" * 4
    review = _estimate(service, snapshot, "security")
    review["ratings"]["security"]["burden_support"] = {
        "claim": "Burden.",
        "scope": "workflow",
        "scope_description": "One path.",
        "observation_ids": [],
        "change_trace_ids": [],
        "representativeness": "Typical.",
        "counterevidence": "None.",
        "freshness": "Current.",
        "limitations": [],
        field: [token],
    }
    result = service.check_review(snapshot["id"], review)
    assert result["valid"] is False and token not in json.dumps(result)


def test_challenge_template_runs_final_checks_except_its_own_binding(scanned):
    service, _, snapshot = scanned
    review = _estimate(service, snapshot, "security")
    with pytest.raises(BurdenSupportError, match="corroboration_ids|burden_support"):
        service.challenge_template(snapshot["id"], review)


def test_challenge_template_accepts_support_awaiting_only_the_challenge(scanned):
    service, _, snapshot = scanned
    review = _estimate(service, snapshot, "security")
    source = review["ratings"]["security"]["evidence_ids"]
    review["change_traces"][0]["steps"][0]["activity"] = "edit"
    review["ratings"]["security"]["burden_support"] = {
        "claim": "Burden.",
        "scope": "workflow",
        "scope_description": "One path.",
        "observation_ids": [],
        "change_trace_ids": ["trace"],
        "representativeness": "Typical.",
        "counterevidence": "None.",
        "freshness": "Current.",
        "limitations": [],
        "corroboration_ids": source,
        "counterevidence_ids": source,
    }
    assert service.challenge_template(snapshot["id"], review)["draft_digest"]
    checked = service.check_review(snapshot["id"], review)
    assert checked["valid"] is False
    gaps = checked["errors"][0]["message"]
    assert "challenge" in gaps.lower() or "unavailability" in gaps


def test_review_check_cli_exits_nonzero_and_saves_nothing(scanned, tmp_path, capsys):
    service, _, snapshot = scanned
    draft = tmp_path / "draft.json"
    draft.write_text(json.dumps(_estimate(service, snapshot, "security")))
    state = ["--state-dir", str(tmp_path / "state")]
    assert main([*state, "review", snapshot["id"], "--input", str(draft), "--check"]) == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False
    assert service.get_report(snapshot["id"])["review"] is None
    draft.write_text(json.dumps(service.review_template(snapshot["id"])))
    assert main([*state, "review", snapshot["id"], "--input", str(draft), "--check"]) == 0


def test_schema_and_full_template_expose_optional_fields(scanned):
    service, _, snapshot = scanned
    schema = service.review_schema()
    assert {"plan", "challenge", "change_traces", "project_context"} <= set(schema["optional"])
    assert (
        "burden_support"
        in schema["review"]["properties"]["ratings"]["properties"]["security"]["properties"]
    )
    full = service.review_template(snapshot["id"], full=True)
    assert {"plan", "challenge", "methodology", "change_traces"} <= set(full)
    assert all("burden_support" in rating for rating in full["ratings"].values())
    assert service.check_review(snapshot["id"], full)["valid"] is True


def test_export_marks_unreviewed_bundles_and_keeps_evidence_opt_in(scanned, tmp_path, capsys):
    service, _, snapshot = scanned
    result = service.export_report(snapshot["id"])
    assert result["review_status"] == "unreviewed" and result["warnings"]
    assert result["evidence_bodies"] == "omitted"
    assert "Unreviewed snapshot" in Path(result["markdown"]).read_text()
    exported = json.loads(Path(result["json"]).read_text())
    assert exported["export"]["review_status"] == "unreviewed"
    assert not any("stats" in entry for entry in exported["assessment"]["evidence"])
    included = service.export_report(snapshot["id"], include_evidence=True)
    assert any(
        "stats" in entry
        for entry in json.loads(Path(included["json"]).read_text())["assessment"]["evidence"]
    )
    assert main(["--state-dir", str(tmp_path / "state"), "export-report", snapshot["id"]]) == 0
    assert "warning" in capsys.readouterr().err


def test_markdown_leads_with_decisions_before_appendices(scanned):
    service, _, snapshot = scanned
    text = markdown_report(service.get_report(snapshot["id"]))
    order = [
        text.index(heading)
        for heading in (
            "## Verdict",
            "## Scorecard",
            "## Findings",
            "## Improvement plan",
            "## Appendices",
            "## Confidence and evidence support",
            "## Collected facts",
            "## Goals and progress",
        )
    ]
    assert order == sorted(order)


def test_budgets_replace_sections_in_order_with_read_references():
    document = {"keep": "x", "low": "y" * 400, "nested": {"high": "z" * 400}}
    fitted = fit_budget(document, 1000, {"low": "cmd low", "nested.high": "cmd high"})
    assert fitted["low"]["read_with"] == "cmd low" and fitted["nested"]["high"] == "z" * 400
    assert fitted["output_budget"]["omitted_sections"] == ["low"]
    assert document["low"] == "y" * 400
    with pytest.raises(ValueError, match="budget"):
        fit_budget({"keep": "x" * 900}, 100, {"low": "cmd"})


def test_budgets_restore_sections_a_large_removal_made_room_for():
    document = {"useful": "u" * 300, "small": "s" * 300, "large": "x" * 3000}
    fitted = fit_budget(document, 1500, {"small": "cmd", "large": "cmd", "useful": "cmd"})
    assert fitted["small"] == "s" * 300 and fitted["useful"] == "u" * 300
    assert fitted["output_budget"]["omitted_sections"] == ["large"]


def test_doctor_brief_drops_source_bodies_but_keeps_located_leads():
    row = {
        "kind": "dependency_cycle",
        "snippets": ["x" * 5000],
        "locations": [{"path": f"m{index}.py"} for index in range(9)],
        "metrics": {"cycle": ["m" * 40] * 200},
    }
    brief = _doctor_row_brief(row, "a_1")
    assert "snippets" not in brief and len(brief["locations"]) == 5
    assert brief["locations_omitted"] == 4
    assert "--candidate-kind dependency_cycle" in brief["metrics"]["read_with"]
    assert row["locations"][8] == {"path": "m8.py"} and "snippets" in row


def test_repeated_per_file_limits_are_one_gap_with_examples():
    many = [f"Pattern analysis duplicate block window limit: f{i}.py:1" for i in range(6)]
    gaps = _collapse_repeated_gaps([*many, "Unsupported Markdown link markup: a.md", "Other"])
    assert gaps == [
        "Other",
        "Pattern analysis duplicate block window limit: 6 locations, including "
        "f0.py:1, f1.py:1, f2.py:1",
        "Unsupported Markdown link markup: a.md",
    ]


def test_partial_paths_matching_one_real_file_are_not_unresolved():
    captured = {"src/auth/sso.py", "src/a/util.py", "src/b/util.py", "docs/guide.md"}
    suffixes = _path_suffixes(captured)
    check = lambda raw: _path_check("docs/guide.md", raw, captured, None, suffixes)  # noqa: E731
    assert check("sso.py")["status"] == "partial_path_match"
    assert check("sso.py")["targets"] == ["src/auth/sso.py"]
    assert check("auth/sso.py")["status"] == "partial_path_match"
    assert check("util.py")["status"] == "not_in_captured_snapshot"
    assert check("gone.py")["status"] == "not_in_captured_snapshot"


def test_brief_and_doctor_stay_inside_hard_budgets_on_a_large_project(tmp_path):
    files = {
        f"src/area{index % 40}/module{index}.py": "".join(
            f"def function_{item}(value):\n    for row in value:\n"
            f"        open(row).read()\n    return value\n\n"
            for item in range(6)
        )
        for index in range(240)
    }
    files["AGENTS.md"] = "Guidance.\n"
    root = _project(tmp_path, files)
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(str(root))
    assert len(json.dumps(service.overview(snapshot["id"]), indent=2)) <= BRIEF_CHARS
    doctor = service.doctor(snapshot["id"], limit=25, brief=True)
    assert len(json.dumps(doctor, indent=2)) <= DOCTOR_CHARS
    assert doctor["groups"]["efficiency"], "io-in-loop leads must reach Doctor"
    assert "goal_alignment" in doctor and "plan" not in doctor["goal_alignment"]


def test_source_context_accepts_an_exact_path(scanned):
    service, _, snapshot = scanned
    result = service.source_context(snapshot["id"], path="src/app.py", end_line=1)
    expected = next(row["id"] for row in snapshot["evidence"] if row["path"] == "src/app.py")
    assert result["evidence_id"] == expected and "def run" in json.dumps(result)
    with pytest.raises(ValueError, match="exact relative path"):
        service.source_context(snapshot["id"], path="src/app")
    with pytest.raises(ValueError, match="exactly one"):
        service.source_context(snapshot["id"])


def test_empty_candidates_points_at_the_view_that_reports_the_kind(tmp_path):
    root = _project(
        tmp_path,
        {"src/app.py": "import requests\n\nfor url in urls:\n    requests.get(url, timeout=1)\n"},
    )
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(str(root))
    result = service.query_evidence(snapshot["id"], view="candidates", candidate_kind="io_in_loop")
    assert result["matched"] == 0
    assert "--view burden --candidate-kind performance.io_in_loop" in result["hint"]
    assert "hint" not in service.query_evidence(
        snapshot["id"], view="candidates", candidate_kind="no_such_kind"
    )


def test_candidate_kind_filters_deleted_documents_and_keeps_the_pointer(tmp_path):
    root = _project(
        tmp_path,
        {
            "src/app.py": "import requests\n\nfor url in urls:\n    requests.get(url, timeout=1)\n",
            "docs/STATUS.md": "status\n",
        },
    )
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "first")
    _git(root, "rm", "-q", "docs/STATUS.md")
    _git(root, "commit", "-qm", "second")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(str(root), analysis_profile="deep")
    other = service.query_evidence(snapshot["id"], view="candidates", candidate_kind="io_in_loop")
    assert other["matched"] == 0 and "--view burden" in other["hint"]


def test_omitted_brief_sections_read_back_without_the_full_report(scanned):
    service, _, snapshot = scanned
    section = service.overview(snapshot["id"], section="system_map")
    assert section["system_map"] == service.overview(snapshot["id"])["system_map"]
    assert set(section) == {"assessment_id", "section", "system_map"}
    gaps = service.overview(snapshot["id"], section="collection_gaps")
    assert gaps["collection_gaps"] == snapshot["gaps"]
    with pytest.raises(ValueError, match="Unknown report section"):
        service.overview(snapshot["id"], section="nope")


def test_read_with_references_are_commands_the_cli_accepts(tmp_path, capsys):
    files = {
        f"src/area{index % 40}/module{index}.py": "def f(value):\n    return value\n" * 40
        for index in range(600)
    }
    root = _project(tmp_path, files)
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(str(root))
    packet = service.challenge_template(snapshot["id"], service.review_template(snapshot["id"]))
    overview = service.overview(snapshot["id"])
    references = [
        value["read_with"]
        for document in (packet, packet["context"], overview)
        for value in document.values()
        if isinstance(value, dict) and value.get("omitted_for_budget")
    ]
    for reference in references:
        assert main(["--state-dir", str(tmp_path / "state"), *reference.split()]) == 0
        capsys.readouterr()


def test_oversized_rows_name_a_remedy_that_can_work(tmp_path):
    root = _project(tmp_path, {"src/app.py": "VALUE = 1\n" + "# padding line\n" * 4000})
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(str(root))
    rows = service.query_evidence(snapshot["id"], view="details", path="<", max_chars=2000)
    oversized = [row for row in rows["items"] if "omitted" in row]
    assert oversized and "max_chars" in oversized[0]["omitted"]
    assert "narrower view" not in oversized[0]["omitted"]


@pytest.mark.parametrize(
    ("path", "role", "generated"),
    [
        ("web_static/assets/index-BxY12z3a.js", "unknown", True),
        ("public/main.3f2a9c1b.js", "unknown", True),
        ("web/vendor.min.js", "unknown", True),
        ("src/oauth2Client-handler.js", "production", False),
        ("scripts/use-oauth2Client.js", "tooling", False),
        ("app/constants/ERROR_MESSAGES.js", "production", False),
        ("tests/ERROR_MESSAGES.js", "test", False),
        ("scripts/run-20240101.js", "tooling", False),
        ("lib/utf8-to-UTF16LE.js", "production", False),
        ("public/ERROR_MESSAGES.js", "unknown", False),
    ],
)
def test_build_output_is_generated_rather_than_production(path, role, generated):
    row = source_role(path)
    assert (row["role"], row["generated_hint"]) == (role, generated)


def test_collection_uses_nested_manifests_minified_text_and_outside_overrides(tmp_path):
    root = _project(
        tmp_path,
        {
            "console/package.json": "{}\n",
            "console/src/App.tsx": "export const App = () => null;\n",
            "console/src/App.test.tsx": "test('x', () => {});\n",
            "examples/demo/package.json": "{}\n",
            "examples/demo/src/index.js": "export default 1;\n",
            "bundle/app.js": "var a=1;" * 600,
            "qualification/tool.py": "VALUE = 1\n",
            "tools/x/package.json": "{}\n",
            "tools/x/src/a.js": "export default 1;\n",
            "docs/site/package.json": "{}\n",
            "docs/site/src/index.js": "export default 1;\n",
            "testdata/app/package.json": "{}\n",
            "testdata/app/src/a.js": "export default 1;\n",
        },
    )
    rules = {"schema_version": 1, "rules": [{"path": "qualification/*", "role": "tooling"}]}
    plain = collect(root)
    result = collect(root, role_overrides=rules)
    roles = {
        row["path"]: row["stats"].get("role")
        for row in result["evidence"]
        if row["kind"] in {"python", "javascript"}
    }
    assert roles["console/src/App.tsx"] == "production"
    assert roles["console/src/App.test.tsx"] == "test"
    assert roles["examples/demo/src/index.js"] == "unknown"
    assert roles["bundle/app.js"] == "unknown"
    assert roles["qualification/tool.py"] == "tooling"
    assert roles["tools/x/src/a.js"] == roles["docs/site/src/index.js"] == "tooling"
    assert roles["testdata/app/src/a.js"] == "unknown"
    assert plain["scope_digest"] != result["scope_digest"]
    with role_scope([]):
        assert source_role("console/src/App.tsx")["role"] == "unknown"
    for role in ("x", []):
        with pytest.raises(ValueError, match="role"):
            collect(
                root, role_overrides={"schema_version": 1, "rules": [{"path": "*", "role": role}]}
            )
    with pytest.raises(ValueError, match="Display name"):
        collect(root, display_name=" ")


def test_cli_rejects_role_overrides_inside_the_assessed_project(tmp_path, capsys):
    root = _project(tmp_path, {"a.py": "x = 1\n", "roles.json": "{}"})
    code = main(
        [
            "--state-dir",
            str(tmp_path / "state"),
            "scan",
            str(root),
            "--role-overrides",
            str(root / "roles.json"),
        ]
    )
    assert code == 2 and "outside the assessed project" in capsys.readouterr().err


def _signals(source):
    import ast

    return analyze_python_controls("src/app.py", ast.parse(source))["signals"]


@pytest.mark.parametrize(
    "body",
    [
        "except Exception:\n        failures += 1\n        continue",
        "except ReconcileError:\n        failed = True\n        continue",
        "except Exception:\n        metrics.incr('failed')",
        "except Exception:\n        pass",
    ],
)
def test_handlers_that_only_count_flag_or_continue_are_leads(body):
    source = f"def f(items):\n  for item in items:\n    try:\n        use(item)\n    {body}\n"
    kinds = [row["kind"] for row in _signals(source)]
    assert "operability.silent_exception_handler" in kinds


@pytest.mark.parametrize(
    "body",
    [
        "except Exception:\n        logger.exception('failed')",
        "except Exception:\n        get_logger().error('failed')",
        "except Exception:\n        raise",
        "except Exception as error:\n        failures.append(error)",
        "except Exception:\n        retry(item)",
        "except KeyError:\n        value = None",
    ],
)
def test_visible_or_handled_failures_are_not_silent_leads(body):
    source = f"def f(items):\n  for item in items:\n    try:\n        use(item)\n    {body}\n"
    signals = _signals(source)
    assert "operability.silent_exception_handler" not in [row["kind"] for row in signals]
    boundary = next(row for row in signals if row["kind"] == "operability.exception_boundary")
    assert {"logs", "raises"} <= boundary["context"].keys()


def test_silent_handler_reaches_doctor_as_a_lead_not_a_finding(tmp_path):
    root = _project(
        tmp_path,
        {
            "src/app.py": "def f(items):\n    for item in items:\n        try:\n            item()\n"
            "        except Exception:\n            continue\n"
        },
    )
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(str(root))
    leads = service.doctor(snapshot["id"])["groups"]["quality"]
    assert any(row["kind"] == "silent_exception_handler" for row in leads)
    assert not any("silent" in row.get("title", "") for row in snapshot["findings"])


def test_binary_archive_is_an_asset_omission_not_a_dimension_blocker(tmp_path):
    root = _project(
        tmp_path,
        {
            "src/app.py": "VALUE = 1\n",
            "release/source.tar.xz": b"\xfd7zXZ\x00" + b"x" * (9 * 1024 * 1024),
        },
    )
    snapshot = collect(root)
    for dimension in DIMENSIONS:
        coverage = dimension_coverage(snapshot, dimension)
        assert coverage["collection_blockers"] == []
        assert [row["path"] for row in coverage["asset_only_omissions"]] == [
            "release/source.tar.xz"
        ]


def test_hcl_and_guard_files_are_captured_configuration(tmp_path):
    root = _project(
        tmp_path,
        {"infra/main.tftest.hcl": 'run "plan" {}\n', "policy/rules.guard": "rule ok {}\n"},
    )
    kinds = {row["path"]: row["kind"] for row in collect(root)["evidence"]}
    assert kinds["infra/main.tftest.hcl"] == kinds["policy/rules.guard"] == "configuration"


def test_markdown_link_labels_are_not_path_claims(tmp_path):
    root = _project(
        tmp_path,
        {
            "src/auth/sso.py": "VALUE = 1\n",
            "docs/guide.md": "See [sso.py](../src/auth/sso.py) and [`old.py`](../src/gone.py).\n"
            "Also [sso.py][ref] and [spaced](<my doc.md>).\n"
            "Plain mention of src/missing.py stays checked.\n",
        },
    )
    entry = next(
        row for row in collect(root)["evidence"] if row["kind"] == "documentation-analysis"
    )
    leads = (
        [
            row["metrics"]["reference"]
            for row in entry["stats"]["maintenance_candidates"]
            if row["kind"] == "documented_path_unresolved_hint"
        ]
        if "maintenance_candidates" in entry["stats"]
        else None
    )
    text = json.dumps(entry["stats"])
    assert '"sso.py"' not in text.replace('"src/auth/sso.py"', "")
    assert '"doc.md"' not in text
    assert "../src/gone.py" in text and "src/missing.py" in text
    assert leads is None or "sso.py" not in leads


def _git(root, *arguments):
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        env={
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
            "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin",
        },
    )


def test_deleted_documents_are_path_only_leads_and_renames_are_not(tmp_path):
    secret = "CANARY_DELETED_DOCUMENT_BODY"
    root = _project(
        tmp_path,
        {"src/app.py": "VALUE = 1\n", "docs/STATUS.md": secret, "docs/old.md": "moved\n"},
    )
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "first")
    _git(root, "rm", "-q", "docs/STATUS.md")
    _git(root, "mv", "docs/old.md", "docs/new.md")
    _git(root, "commit", "-qm", "second")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(str(root), analysis_profile="deep")
    rows = service.query_evidence(
        snapshot["id"], view="candidates", candidate_kind="deleted_document_hint"
    )["items"]
    assert [row["path"] for row in rows] == ["docs/STATUS.md"]
    assert secret not in json.dumps(snapshot)
    assert service.overview(snapshot["id"])["deleted_documents"]["count"] == 1


def test_report_name_prefers_display_name_then_origin_then_directory(tmp_path):
    root = _project(tmp_path, {"src/app.py": "VALUE = 1\n"})
    assert collect(root)["source"]["display_name"] == "project"
    _git(root, "init", "-q")
    _git(root, "remote", "add", "origin", "https://user:token@example.invalid/org/widget.git")
    snapshot = collect(root)
    assert snapshot["source"]["display_name"] == "widget"
    assert "token" not in json.dumps(snapshot["source"])
    assert collect(root, display_name="Widget")["source"]["display_name"] == "Widget"
    (root / "sub").mkdir()
    (root / "sub" / "a.py").write_text("VALUE = 1\n")
    assert collect(root / "sub")["source"]["display_name"] == "sub"
    service = AssessmentService(tmp_path / "state")
    saved = service.scan(str(root))
    report = service.get_report(saved["id"])
    assert markdown_report(report).startswith("# Project assessment: widget")
    assert report["dimension_map"]["project"] == "widget"


def test_progress_prints_phases_and_heartbeats_only_when_requested(capfd):
    report_progress("silent without a listener")
    assert capfd.readouterr().err == ""
    import io

    stream = io.StringIO()
    with stderr_progress(stream=stream, heartbeat_seconds=0.01):
        report_progress("capturing source files")
        import time

        time.sleep(0.05)
    output = stream.getvalue()
    assert "capturing source files" in output and "still running" in output
    assert "finished" in output and "[0m" in output


def test_scan_cli_reports_progress_on_stderr_and_keeps_stdout_json(tmp_path, capsys):
    root = _project(tmp_path, {"a.py": "x = 1\n"})
    assert main(["--state-dir", str(tmp_path / "state"), "scan", str(root), "--brief"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["assessment_id"]
    assert "capturing source files" in captured.err and "finished" in captured.err


def test_tool_info_reports_revision_source_and_checkout_state():
    info = tool_info()
    assert {"source_revision", "revision_source", "dirty", "behind_origin_main"} <= info.keys()
    if info["revision_source"] == "git_checkout":
        assert isinstance(info["dirty"], bool)


def _archive(path, entries):
    with zipfile.ZipFile(path, "w") as bundle:
        for name, content in entries.items():
            bundle.writestr(name, content)


def test_joern_setup_verifies_the_pinned_digest_before_extracting(tmp_path, monkeypatch):
    import hashlib

    source = tmp_path / "release.zip"
    _archive(source, {"joern-cli/joern": "#!/bin/sh\n"})
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setattr(
        joern_setup, "_download", lambda _url, target: target.write_bytes(source.read_bytes())
    )
    monkeypatch.setattr(joern_setup, "_ASSETS", {("x", "y"): ("asset.zip", digest)})
    monkeypatch.setattr(joern_setup.sys, "platform", "x")
    monkeypatch.setattr(joern_setup.platform, "machine", lambda: "Y")
    result = joern_setup.setup_joern(tmp_path / "tools")
    assert Path(result["home"], "joern").is_file()
    assert not list((tmp_path / "tools").glob("*.partial"))
    with pytest.raises(ValueError, match="already exists"):
        joern_setup.setup_joern(tmp_path / "tools")
    monkeypatch.setattr(joern_setup, "_ASSETS", {("x", "y"): ("asset.zip", "0" * 64)})
    with pytest.raises(ValueError, match="digest mismatch"):
        joern_setup.setup_joern(tmp_path / "other")
    assert not (tmp_path / "other" / "joern-cli").exists()
    monkeypatch.setattr(joern_setup, "_ASSETS", {("x", "y"): ("asset.zip", digest)})

    def interrupted(_archive, _destination):
        raise OSError("disk full")

    monkeypatch.setattr(joern_setup, "_extract", interrupted)
    with pytest.raises(OSError, match="disk full"):
        joern_setup.setup_joern(tmp_path / "retry")
    assert not (tmp_path / "retry" / "joern-cli").exists()
    assert not (tmp_path / "retry" / ".joern-staging").exists()


def test_joern_setup_rejects_archive_escapes(tmp_path):
    archive = tmp_path / "bad.zip"
    _archive(archive, {"../escape": "x"})
    with pytest.raises(ValueError, match="unsafe"):
        joern_setup._extract(archive, tmp_path / "out")
    assert not (tmp_path / "escape").exists()
