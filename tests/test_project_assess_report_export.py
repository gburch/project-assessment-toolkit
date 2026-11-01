import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from project_assess import report_export
from project_assess.project_context import project_context_assessment, project_context_template
from project_assess.rubric import DIMENSIONS
from project_assess.service import AssessmentService


@pytest.fixture
def report(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text('raise RuntimeError("do not execute")\n')
    service = AssessmentService(tmp_path / "state")
    assessment = service.scan(project)
    draft = service.review_template(assessment["id"])
    del draft["coverage"]
    source_id = next(e["id"] for e in assessment["evidence"] if e["kind"] == "python")
    for rating in draft["ratings"].values():
        rating.update(
            capability=3,
            burden=2,
            confidence="medium",
            burden_confidence="low",
            burden_basis="source_estimate",
            rationale="A source-supported judgment.",
            recommendations=["Preserve the relevant behavior."],
            evidence_ids=[source_id],
        )
    service.submit_review(assessment["id"], draft)
    service.set_targets(assessment["project_id"], profile="public-production", expected_revision=0)
    monkeypatch.setattr(
        report_export,
        "_asset_text",
        lambda name: {
            "dimension-map.generated.js": "var PATDimensionMap={createDimensionMap:function(){}};",
            "dimension-map.css": ".dimension-map{min-width:0}",
            "THREE-LICENSE.txt": "The MIT License\nCopyright Three.js contributors",
        }[name],
    )
    return service.get_report(assessment["id"])


def test_model_uses_all_dimensions_and_separate_goals_and_confidence(report):
    original = deepcopy(report)
    model = report_export.dimension_map_data(report)
    assert [row["id"] for row in model["dimensions"]] == list(DIMENSIONS)
    assert model["assessment_id"] == report["assessment"]["id"]
    assert model["review_id"] == report["review"]["id"]
    security = model["dimensions"][0]
    assert security["capability"] == 3 and security["burden"] == 2
    assert security["capability_min"] == 3 and security["burden_max"] == 2
    assert security["capability_confidence"] == "medium"
    assert security["burden_confidence"] == "low"
    assert not model["preview_targets"]
    assert report == original


def contextual_report(report):
    context = project_context_template()
    source_id = next(e["id"] for e in report["assessment"]["evidence"] if e["kind"] == "python")
    context["current"].update(
        milestone="personal_utility",
        readiness="prototype",
        confidence="low",
        rationale="A focused local workflow in this presentation fixture.",
        evidence_ids=[source_id],
    )
    context["intended"].update(
        milestone="personal_utility",
        basis="user_stated",
        confidence="medium",
        statement="Keep this a focused local tool.",
        attribution="Owner statement in the fixture",
        alternatives=[],
        limitations=["No deployment evidence is claimed."],
    )
    context["alignment"].update(
        direction="maintain",
        rationale="Fit the current bounded purpose.",
        priorities=[
            {
                "dimension": "security",
                "direction": "investigate",
                "rationale": "Inspect the real local boundary.",
                "initiative_ids": [],
            },
            {
                "dimension": "maintainability",
                "direction": "maintain",
                "rationale": "Preserve the simple owner.",
                "initiative_ids": [],
            },
        ],
        deferred=["Multi-user platform machinery"],
    )
    report["review"]["project_context"] = context
    report["project_context"] = project_context_assessment(
        report["assessment"], report["review"], report["goals"]
    )
    return report


def test_html_context_precedes_engineering_scores_without_changing_them(report):
    before = deepcopy(report["review"]["ratings"])
    contextual_report(report)
    rendered = report_export.report_html(report)
    assert rendered.index('id="project-context-heading"') < rendered.index(
        'aria-label="Assessment badges"'
    )
    assert rendered.index('class="context-priorities"') < rendered.index('id="scores-heading"')
    section = rendered.split('id="project-context-heading"', 1)[1].split("</section>", 1)[0]
    assert section.index("Security") < section.index("Maintainability")
    assert (
        "Owner statement in the fixture" in section and "Multi-user platform machinery" in section
    )
    assert report["review"]["ratings"] == before
    assert len(report_export.dimension_map_data(report)["dimensions"]) == len(DIMENSIONS)
    report["review"].pop("project_context")
    report.pop("project_context")
    legacy = report_export.report_html(report)
    assert "No maturity or intended-purpose judgment is recorded" in legacy
    assert "Personal utility" not in legacy


def test_html_context_is_text_and_cannot_inject_markup(report):
    contextual_report(report)
    attack = '<img src=x onerror=alert(1)></script><script>alert("context")</script>'
    context = report["review"]["project_context"]
    context["current"]["rationale"] = attack
    context["intended"].update(
        statement=attack, attribution=attack, alternatives=[attack], limitations=[attack]
    )
    context["alignment"]["rationale"] = attack
    context["alignment"]["priorities"][0]["rationale"] = attack
    context["alignment"]["deferred"] = [attack]
    rendered = report_export.report_html(report)
    assert attack not in rendered and "&lt;img src=x onerror=" in rendered
    assert rendered.count("<script>") == rendered.count("</script>") == 1


def test_html_context_uses_saved_judgment_instead_of_a_detached_projection(report):
    contextual_report(report)
    report["project_context"]["current"]["milestone_label"] = "Detached stage label"
    rendered = report_export.report_html(report)
    assert "Detached stage label" not in rendered
    assert report["review"]["project_context"]["current"]["milestone"] == "personal_utility"


def test_unknown_partial_and_legacy_values_do_not_become_zero(report):
    report["review"]["ratings"]["security"].update(capability=None, burden=0)
    del report["review"]["ratings"]["security"]["burden_confidence"]
    report["review"]["ratings"]["testing"].update(capability=True, burden=float("nan"))
    report["goals"] = None
    rows = report_export.dimension_map_data(report)["dimensions"]
    assert rows[0]["capability"] is None and rows[0]["burden"] == 0
    assert rows[0]["capability_confidence"] == "unknown"
    assert rows[0]["burden_confidence"] == "low"
    assert rows[1]["capability"] is None and rows[1]["burden"] is None
    assert all(row["capability_min"] is None and row["burden_max"] is None for row in rows)
    report["review"] = None
    assert all(
        row["capability"] is None and row["burden"] is None
        for row in report_export.dimension_map_data(report)["dimensions"]
    )


def test_html_is_offline_and_hostile_text_cannot_escape_script_or_markup(report):
    attack = '"><img src=x onerror=alert(1)></script><script>alert("escaped")</script>&\u2028\u2029'
    report["review"]["ratings"]["security"]["rationale"] = attack
    report["review"]["ratings"]["security"]["recommendations"] = [attack]
    rendered = report_export.report_html(report)
    assert rendered.count("<script>") == 1 and rendered.count("</script>") == 1
    assert "<img src=x onerror=" not in rendered
    assert "&lt;img src=x onerror=" in rendered
    assert "\\u003c/script\\u003e" in rendered
    assert "\\u2028" in rendered and "\\u2029" in rendered
    assert rendered.count('src="data:image/svg+xml;base64,') == 9
    script = rendered.rsplit("<script>", 1)[1].split("</script>", 1)[0]
    script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert "sha256-" + script_hash in rendered
    assert "connect-src &#x27;none&#x27;" in rendered
    assert "unsafe-eval" not in rendered and "unsafe-inline" not in rendered
    assert 'src="https:' not in rendered and 'href="https:' not in rendered
    assert "The MIT License" in rendered


@pytest.mark.parametrize("operation", ["model", "html", "export"])
def test_foreign_review_is_rejected_before_any_export(report, tmp_path, operation):
    report["review"]["source_digest"] = "sha256:" + "0" * 64
    state = tmp_path / "output-state"
    state.mkdir()
    with pytest.raises(ValueError, match="Review does not match"):
        if operation == "model":
            report_export.dimension_map_data(report)
        elif operation == "html":
            report_export.report_html(report)
        else:
            report_export.export_report(report, state)
    assert not list(state.iterdir())


def test_private_bundle_is_complete_same_snapshot_and_relocatable(report, tmp_path):
    state = tmp_path / "export-state"
    state.mkdir(mode=0o700)
    result = report_export.export_report(report, state)
    folder = Path(result["directory"])
    assert folder.parent == state / "exports"
    assert result["assessment_id"] == report["assessment"]["id"]
    assert result["review_id"] == report["review"]["id"]
    assert result["source_digest"] == report["assessment"]["source"]["manifest_digest"]
    assert result["goal_revision"] == report["goals"]["revision"]
    assert set(result["badges"]) == {"summary", *DIMENSIONS}
    assert json.loads(Path(result["json"]).read_text()) == report
    assert "[Interactive 3D report](report.html)" in Path(result["markdown"]).read_text()
    for name, detail in result["files"].items():
        path = folder / name
        assert path.is_relative_to(state)
        assert detail["bytes"] == path.stat().st_size
        assert detail["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert path.stat().st_mode & 0o777 == 0o600
    for directory in (folder, folder / "badges", folder.parent):
        assert directory.stat().st_mode & 0o777 == 0o700
    assert len(result["files"]) == 12
    second = report_export.export_report(report, state)
    assert second["directory"] != result["directory"]
    assert Path(result["html"]).exists()


def test_markdown_keeps_hostile_review_text_inert(report, tmp_path):
    attack = "<img src=x onerror=alert(1)> ![track](https://untrusted.invalid/track)"
    report["review"]["ratings"]["security"].update(rationale=attack, recommendations=[attack])
    report["assessment"]["gaps"].append(attack)
    state = tmp_path / "output-state"
    state.mkdir()
    result = report_export.export_report(report, state)
    text = Path(result["markdown"]).read_text()
    assert "<img src=x onerror=" not in text
    assert "&lt;img src=x onerror=" in text
    assert "![track](" not in text
    assert "\\[track\\]" in text


def test_concurrent_exports_are_complete_and_unique(report, tmp_path):
    state = tmp_path / "output-state"
    state.mkdir()
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: report_export.export_report(report, state), range(4)))
    assert len({result["directory"] for result in results}) == 4
    assert len(list((state / "exports").iterdir())) == 4
    for result in results:
        assert json.loads(Path(result["json"]).read_text()) == report
        assert all((Path(result["directory"]) / name).is_file() for name in result["files"])


def test_interrupted_export_removes_partial_tree_and_preserves_existing(
    report, tmp_path, monkeypatch
):
    state = tmp_path / "output-state"
    state.mkdir()
    prior = report_export.export_report(report, state)
    prior_files = {name: (Path(prior["directory"]) / name).read_bytes() for name in prior["files"]}
    original = report_export._write_at
    count = 0

    def interrupted(fd, name, payload):
        nonlocal count
        count += 1
        if count == 4:
            raise OSError("simulated full disk")
        original(fd, name, payload)

    monkeypatch.setattr(report_export, "_write_at", interrupted)
    with pytest.raises(OSError, match="simulated full disk"):
        report_export.export_report(report, state)
    assert {p.name for p in (state / "exports").iterdir()} == {Path(prior["directory"]).name}
    assert prior_files == {
        name: (Path(prior["directory"]) / name).read_bytes() for name in prior_files
    }


def test_collision_never_replaces_an_existing_export(report, tmp_path, monkeypatch):
    state = tmp_path / "output-state"
    state.mkdir()
    token = "1" * 32
    monkeypatch.setattr(report_export.uuid, "uuid4", lambda: SimpleNamespace(hex=token))
    exports = state / "exports"
    exports.mkdir(mode=0o700)
    existing = exports / (report["assessment"]["id"] + "-" + token)
    existing.mkdir(mode=0o700)
    (existing / "preserve").write_text("earlier export")
    with pytest.raises(FileExistsError):
        report_export.export_report(report, state)
    assert (existing / "preserve").read_text() == "earlier export"
    assert list(exports.iterdir()) == [existing]


@pytest.mark.parametrize("link", ["exports", "state"])
def test_export_rejects_state_or_exports_symlinks(report, tmp_path, link):
    state = tmp_path / "output-state"
    outside = tmp_path / "outside"
    outside.mkdir()
    if link == "state":
        state.symlink_to(outside, target_is_directory=True)
    else:
        state.mkdir()
        (state / "exports").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        report_export.export_report(report, state)
    assert not list(outside.iterdir())


def test_export_rejects_project_containment_and_public_output_directory(report, tmp_path):
    root = Path(report["assessment"]["source"]["root"])
    with pytest.raises(ValueError, match="outside assessed projects"):
        report_export.export_report(report, root)
    state = tmp_path / "output-state"
    state.mkdir()
    other_project = state / "exports"
    other_project.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="outside assessed projects"):
        report_export.export_report(report, state, forbidden_roots=[other_project])
    other_project.chmod(0o755)
    with pytest.raises(PermissionError, match="private"):
        report_export.export_report(report, state)


def test_bad_assessment_name_cannot_choose_export_path(report, tmp_path):
    report["assessment"]["id"] = "../../outside"
    with pytest.raises(ValueError, match="Invalid assessment"):
        report_export.export_report(report, tmp_path)
    assert not (tmp_path / "exports").exists()


def test_missing_manifest_identity_fails_before_export_creation(report, tmp_path):
    del report["assessment"]["source"]["manifest_digest"]
    with pytest.raises(ValueError, match="source manifest identity"):
        report_export.export_report(report, tmp_path)
    assert not (tmp_path / "exports").exists()


def test_failed_publish_removes_staging_and_own_empty_reservation(report, tmp_path, monkeypatch):
    state = tmp_path / "output-state"
    state.mkdir()

    def fail_publish(*args, **kwargs):
        raise OSError("interrupted publish")

    monkeypatch.setattr(report_export.os, "rename", fail_publish)
    with pytest.raises(OSError, match="interrupted publish"):
        report_export.export_report(report, state)
    assert not list((state / "exports").iterdir())
