"""The shared CI operation enforces persisted authority and explicit policies."""

import json

import pytest

from project_assess.cli import main
from project_assess.service import AssessmentService


def new_project(tmp_path, name="project"):
    root = tmp_path / name
    root.mkdir()
    (root / "app.py").write_text("def handle(value):\n    return value\n")
    return root


def add_branches(root):
    (root / "app.py").write_text(
        "def handle(value):\n"
        + "".join(f"    if value == {index}:\n        return {index}\n" for index in range(12))
        + "    return None\n"
    )


def test_cli_native_delta_is_advisory_until_owner_selects_a_policy(tmp_path, capsys):
    root = new_project(tmp_path)
    service = AssessmentService(tmp_path / "state")
    before = service.scan(root)
    add_branches(root)
    after = service.scan(root)
    args = ["--state-dir", str(service.state_dir), "ci-delta", before["id"], after["id"]]
    assert main([*args, "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["new"] >= 1 and report["policy"]["mode"] == "advisory"
    assert main([*args, "--fail-on-kind", "complex_function", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["policy"]["result"] == "fail" and report["policy"]["violations"]
    assert main(args) == 0
    assert "# PAT CI delta" in capsys.readouterr().out
    assert main([*args, "--fail-on-kind", "typo"]) == 2
    assert "supported native candidate kinds" in capsys.readouterr().err


def test_service_does_not_compare_different_projects(tmp_path):
    service = AssessmentService(tmp_path / "state")
    first = service.scan(new_project(tmp_path, "first"))
    second = service.scan(new_project(tmp_path, "second"))
    with pytest.raises(ValueError, match="same project"):
        service.ci_delta(first["id"], second["id"])


@pytest.mark.parametrize("revoked_first", [False, True])
def test_delta_authorizes_both_saved_snapshots_and_supplied_reports(tmp_path, revoked_first):
    root = new_project(tmp_path)
    imports = tmp_path / "private-reports"
    imports.mkdir()
    report = imports / "junit.xml"
    report.write_text("<testsuite><testcase name='private-case'/></testsuite>")
    owner = AssessmentService(tmp_path / "state")
    with_report = owner.scan(root, reports=[report])
    clean = owner.scan(root)
    restricted = AssessmentService(owner.state_dir, [root])
    ids = [with_report["id"], clean["id"]]
    if not revoked_first:
        ids.reverse()
    with pytest.raises(PermissionError):
        restricted.ci_delta(*ids)
