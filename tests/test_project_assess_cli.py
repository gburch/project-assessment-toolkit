import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from project_assess.cli import main


def test_installed_cli_roundtrip_without_source_path_imports(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("# Project\nA starting point.\n")
    state = tmp_path / "state"
    args = ["--state-dir", str(state)]
    executable = Path(sys.executable).with_name("pat.exe" if os.name == "nt" else "pat")
    legacy_executable = Path(sys.executable).with_name(
        "project-assess.exe" if os.name == "nt" else "project-assess"
    )
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)

    def command(*arguments, program=executable):
        result = subprocess.run(
            [str(program), *args, *arguments],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    help_text = command("--help")
    assert help_text.startswith("usage: pat ") and "Project Assessment Toolkit" in help_text
    snapshot = json.loads(command("scan", str(root)))
    diagnosis = json.loads(command("doctor", snapshot["id"]))
    assert diagnosis["assessment_id"] == snapshot["id"]
    assert diagnosis["source"] == snapshot["source"]
    assert set(diagnosis["groups"]) == {"reuse", "quality", "efficiency"}
    assert "ratings" not in diagnosis
    plan = json.loads(command("evolve", snapshot["id"]))
    assert plan["assessment_id"] == snapshot["id"] and plan["source"] == snapshot["source"]
    assert plan["goal_alignment"]["status"] == "no_goals"
    assert plan["goal_alignment"] == diagnosis["goal_alignment"]
    review = json.loads(command("review-template", snapshot["id"]))
    path = tmp_path / "review.json"
    path.write_text(json.dumps(review))
    command("review", snapshot["id"], "--input", str(path))
    command(
        "targets",
        snapshot["project_id"],
        "--profile",
        "local-experiment",
        "--expected-revision",
        "0",
    )
    plan = json.loads(command("evolve", snapshot["id"]))
    assert plan["goal_alignment"]["goal_revision"] == 1
    testing = plan["goal_alignment"]["dimensions"]["testing"]
    assert testing["capability_gap"] is None and testing["action"] == "inspect"
    report = command("report", snapshot["id"], "--format", "markdown")
    assert "unknown" in report
    assert "Documentation evidence:" in report
    assert "not burden scores" in report

    evidence_id = next(row["id"] for row in snapshot["evidence"] if row["path"] == "README.md")
    for dimension, rating in review["ratings"].items():
        rating.update(
            capability=2 if dimension == "extensibility" else 3,
            burden=2,
            confidence="medium",
            burden_basis="source_estimate",
            burden_confidence="low",
            rationale="Fixture judgments exercise the public planning contract.",
            evidence_ids=[evidence_id],
        )
    path.write_text(json.dumps(review))
    scored_review = json.loads(command("review", snapshot["id"], "--input", str(path)))
    targets = {
        dimension: {"capability_min": 4 if dimension == "testing" else 3, "burden_max": 2}
        for dimension in review["ratings"]
    }
    target_path = tmp_path / "targets.json"
    target_path.write_text(json.dumps(targets))
    goals = json.loads(
        command(
            "targets",
            snapshot["project_id"],
            "--input",
            str(target_path),
            "--expected-revision",
            "1",
        )
    )
    assert goals["targets"] == targets and goals["profile"] is None
    history_before = json.loads(command("history", snapshot["project_id"]))
    state_before = {item.name: item.read_bytes() for item in state.iterdir() if item.is_file()}
    source_before = {item.name: item.read_bytes() for item in root.iterdir()}

    badge_json = json.loads(
        command("badge", snapshot["id"], "--dimension", "testing", "--format", "json")
    )
    assert badge_json["schemaVersion"] == 1
    assert "C3/5" in badge_json["message"] and "B2/5" in badge_json["message"]
    badge_svg = command("badge", snapshot["id"], "--dimension", "testing")
    assert ET.fromstring(badge_svg).tag == "{http://www.w3.org/2000/svg}svg"
    assert "C3/5" in badge_svg and str(root) not in badge_svg
    assert (
        command("badge", snapshot["id"], "--dimension", "testing", program=legacy_executable)
        == badge_svg
    )

    plan = json.loads(command("evolve", snapshot["id"]))
    assert json.loads(command("evolve", snapshot["id"], program=legacy_executable)) == plan

    assert plan["assessment_id"] == snapshot["id"] and plan["source"] == snapshot["source"]
    assert plan["project_id"] == snapshot["project_id"]
    alignment = plan["goal_alignment"]
    assert alignment["status"] == "ready"
    assert alignment["review_id"] == scored_review["id"]
    assert alignment["goal_revision"] == goals["revision"] == 2
    assert goals["baseline_assessment_id"] == snapshot["id"]
    assert goals["baseline_review_id"] == scored_review["id"]
    for dimension, capability, next_capability in (("testing", 3, 4), ("extensibility", 2, 3)):
        item = alignment["dimensions"][dimension]
        assert item["action"] == "strengthen" and item["next_capability"] == next_capability
        assert item["current"] == {"capability": capability, "burden": 2}
        assert item["target"] == {"capability_min": next_capability, "burden_max": 2}
        assert (item["capability_gap"], item["burden_gap"]) == (1, 0)
    assert all(
        item["action"] == "maintain"
        for dimension, item in alignment["dimensions"].items()
        if dimension not in {"testing", "extensibility"}
    )
    assert {
        item.name: item.read_bytes() for item in state.iterdir() if item.is_file()
    } == state_before
    assert {item.name: item.read_bytes() for item in root.iterdir()} == source_before
    assert json.loads(command("history", snapshot["project_id"])) == history_before

    skills = subprocess.run(
        [str(executable), "skills"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    catalog = json.loads(skills.stdout)
    assert {
        "project-assess",
        "doc-value",
        "test-value",
    } <= {row["name"] for row in catalog}
    for row in catalog:
        path = Path(row["path"])
        assert path.is_absolute() and path.is_file()
        assert path.name == "SKILL.md" and path.parent.name == row["name"]


def test_invalid_scan_never_creates_state_inside_source(tmp_path, capsys):
    assert main(["--state-dir", str(tmp_path / "state"), "scan", str(tmp_path)]) == 2
    assert not (tmp_path / "state").exists()
    error = capsys.readouterr().err
    assert error.startswith("pat:") and "outside" in error
