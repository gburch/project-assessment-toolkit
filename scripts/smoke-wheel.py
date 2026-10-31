#!/usr/bin/env python3
"""Offline PAT wheel delivery rehearsal; all artifacts and synthetic state stay outside source."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from project_assess.collector import _redact, collect

ROOT = Path(__file__).resolve().parents[1]
PROBE = r"""
import importlib.metadata as metadata, importlib.util, json, re, sys
from pathlib import Path
import project_assess.cli as cli
base = Path(cli.__file__).resolve().parent
assert base.is_relative_to(Path(sys.prefix).resolve())
assert not base.is_relative_to(Path(sys.argv[1]).resolve())
assert importlib.util.find_spec('mcp') is None
assert importlib.util.find_spec('tree_sitter') is None
assert importlib.util.find_spec('vulture') is None
for name in ('static/index.html', 'static/app.js', 'static/style.css', 'docs/PROJECT_ASSESS.md'):
    assert (base / name).is_file() and (base / name).read_bytes()
for name in ('project-assess', 'doc-value', 'test-value'):
    skill = base / '.agents/skills' / name / 'SKILL.md'
    assert skill.is_file()
    for target in re.findall(r'\]\(([^)]+)\)', skill.read_text()):
        if '://' not in target and not target.startswith('#'):
            resource = (skill.parent / target.split('#')[0]).resolve()
            assert resource.is_relative_to(base) and resource.is_file()
print(json.dumps({'version': metadata.version('pat-assess'), 'python': sys.version.split()[0],
                  'origin': str(base.relative_to(sys.prefix)), 'mcp_installed': False,
                  'analysis_installed': False, 'vulture_installed': False}))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, help="New private directory outside this checkout"
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Development proof only; not a committed-source release",
    )
    args = parser.parse_args()
    output = Path(args.output).expanduser().resolve()
    if output.is_relative_to(ROOT):
        parser.error("Output must be outside the PAT checkout")
    os.umask(0o077)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "UV_")) and key != "VIRTUAL_ENV"
    }
    env.update(UV_OFFLINE="1", UV_PYTHON_DOWNLOADS="never")
    if "UV_CACHE_DIR" in os.environ:
        env["UV_CACHE_DIR"] = os.environ["UV_CACHE_DIR"]
    uv = shutil.which("uv") or str(Path.home() / ".local/bin/uv")
    receipt = {
        "schema_version": 1,
        "status": "failed",
        "created_at": datetime.now(UTC).isoformat(),
        "checks": [],
    }
    step = "source identity"

    def run(command, *, cwd=output, expected=0):
        completed = subprocess.run(
            [str(value) for value in command],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if completed.returncode != expected:
            detail = _redact(completed.stderr).strip()[-1600:]
            raise RuntimeError(
                f"{step}: expected exit {expected}, received {completed.returncode}\n{detail}"
            )
        return completed.stdout

    def check(condition, name):
        if not condition:
            raise RuntimeError(name)
        receipt["checks"].append(name)

    try:
        git = ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", ROOT]
        clean = not run([*git, "status", "--porcelain"]).strip()
        if not clean and not args.allow_dirty:
            raise RuntimeError("Clean committed source required; --allow-dirty is development-only")
        source = collect(ROOT)
        check(source["complete"], "complete source capture")
        check(bool(source["source"]["revision"]), "Git source revision available")
        receipt["source"] = {
            **source["source"],
            "clean": clean,
            "proof_kind": "committed_source" if clean else "development_worktree",
        }
        step = "offline wheel build"
        receipt["builder"] = {
            "uv": run([uv, "--version"]).strip()[:160],
            "python": sys.version.split()[0],
        }
        run([uv, "build", "--wheel", "--offline", "--out-dir", output / "dist", ROOT], cwd=ROOT)
        wheels = list((output / "dist").glob("pat_assess-*.whl"))
        check(len(wheels) == 1, "one candidate wheel")
        wheel = wheels[0]
        receipt["wheel"] = {
            "file": wheel.name,
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        }
        constraints = output / "core-requirements.txt"
        constraints.write_text(
            run(
                [
                    uv,
                    "export",
                    "--locked",
                    "--offline",
                    "--no-dev",
                    "--no-emit-project",
                    "--no-hashes",
                ],
                cwd=ROOT,
            )
        )
        receipt["core_constraints_sha256"] = hashlib.sha256(constraints.read_bytes()).hexdigest()
        step = "fresh offline core installation"
        run([uv, "venv", "--offline", "--no-project", "--python", sys.executable, output / "venv"])
        python = output / "venv/bin/python"
        run(
            [
                uv,
                "pip",
                "install",
                "--offline",
                "--python",
                python,
                "--constraint",
                constraints,
                wheel,
            ]
        )
        receipt["installation"] = json.loads(run([python, "-I", "-c", PROBE, ROOT]))
        receipt["checks"].append("isolated wheel origins, bundled resources and core without MCP")
        project, state = output / "project", output / "state"
        project.mkdir()
        (project / "app.py").write_text("def add(a, b):\n    return a + b\n")
        (project / "app.js").write_text(
            "throw new Error('Assessment must not execute this source');\n"
        )
        (project / "app.swift").write_text(
            'fatalError("Assessment must not execute this source")\n'
        )
        pat = output / "venv/bin/pat"

        def cli(*arguments, state_dir=state, expected=0):
            value = run([pat, "--state-dir", state_dir, *arguments], expected=expected)
            return json.loads(value) if expected == 0 else None

        step = "public CLI roundtrip"
        snapshot = cli("scan", project)
        javascript = next(
            row for row in snapshot["evidence"] if row["kind"] == "javascript-analysis"
        )
        check(
            snapshot["facts"]["python"]["files"] == 1
            and not javascript["stats"]["analyzer"]["available"]
            and javascript["stats"]["gaps"],
            "core scan preserves Python facts and explicit unavailable JavaScript analysis",
        )
        generic = next(row for row in snapshot["evidence"] if row["kind"] == "source-analysis")
        check(
            generic["stats"]["coverage"]["languages"]["swift"] == 1,
            "core scan inventories Swift without a language executable",
        )
        optional = cli(
            "scan",
            project,
            "--analysis-profile",
            "deep",
            "--analyzer",
            "vulture",
            state_dir=output / "optional-state",
        )
        check(
            optional["facts"]["optional_analysis"]["vulture"]["status"] == "unavailable",
            "core scan preserves explicit unavailable optional-analyzer evidence",
        )
        review = cli("review-template", snapshot["id"])
        for rating in review["ratings"].values():
            rating.update(
                capability=2,
                burden=1,
                confidence="low",
                rationale="Synthetic delivery fixture judgment.",
                evidence_ids=[snapshot["evidence"][0]["id"]],
            )
        review_file = output / "review.json"
        review_file.write_text(json.dumps(review))
        saved = cli("review", snapshot["id"], "--input", review_file)
        goals = cli(
            "targets",
            snapshot["project_id"],
            "--profile",
            "internal-service",
            "--expected-revision",
            "0",
        )
        progress = cli("progress", snapshot["project_id"])
        check(
            saved["assessment_id"] == snapshot["id"]
            and goals["revision"] == progress["goal_revision"] == 1,
            "scan, cited review, goals and progress identities",
        )
        before = cli("history", snapshot["project_id"])
        state_bytes = {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()}
        step = "rejected changes preserve state"
        review["source_digest"] = "invalid-fixture-digest"
        review_file.write_text(json.dumps(review))
        cli("review", snapshot["id"], "--input", review_file, expected=2)
        cli(
            "targets",
            snapshot["project_id"],
            "--profile",
            "local-experiment",
            "--expected-revision",
            "0",
            expected=2,
        )
        check(
            state_bytes
            == {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()}
            and cli("history", snapshot["project_id"]) == before,
            "invalid review and stale goal CAS leave durable state unchanged",
        )
        step = "closed-state backup and restore"
        shutil.copytree(state, output / "backup")
        cli(
            "targets",
            snapshot["project_id"],
            "--profile",
            "public-production",
            "--expected-revision",
            "1",
        )
        shutil.copytree(output / "backup", output / "restored-state")
        check(
            cli("history", snapshot["project_id"], state_dir=output / "restored-state") == before
            and cli("progress", snapshot["project_id"], state_dir=output / "restored-state")
            == progress,
            "fresh restored state retains the earlier history and progress",
        )
        check(
            cli("progress", snapshot["project_id"])["goal_revision"] == 2,
            "rollback preserves the later original state",
        )
        step = "source remained stable"
        check(
            collect(ROOT)["source"] == source["source"],
            "source identity unchanged throughout delivery rehearsal",
        )
        receipt["status"] = "passed"
    except Exception as error:
        receipt["failure"] = {"step": step, "error": str(error)}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(output / "receipt.json")}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
