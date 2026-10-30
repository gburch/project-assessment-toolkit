#!/usr/bin/env python3
"""Collect and normalize coverage evidence from Vitest and node:test.

This is an evidence adapter for the portable test-value analyzer.  It does not
assign aggregate coverage to individual tests.  Vitest JSON/JUnit results bind
test identities and timings; Istanbul/LCOV and V8 artifacts remain suite/file
evidence unless a caller explicitly runs one isolated test invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SCHEMA = "test-value-evidence.v1"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def git_identity(root: Path) -> dict[str, Any]:
    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

    try:
        diff = subprocess.check_output(
            ["git", "-C", str(root), "diff", "--binary", "HEAD"],
            stderr=subprocess.DEVNULL,
        )
        return {
            "revision": git("rev-parse", "HEAD"),
            "trackedDirty": bool(git("status", "--porcelain", "--untracked-files=no")),
            "trackedDiffHash": "sha256:" + hashlib.sha256(diff).hexdigest(),
        }
    except (OSError, subprocess.CalledProcessError):
        return {"revision": None, "trackedDirty": None, "trackedDiffHash": None}


def files_under(root: Path, paths: list[str], suffixes: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in paths:
        path = (root / item).resolve()
        if not path.is_relative_to(root) or not path.exists():
            raise ValueError(f"path is outside --root or missing: {item}")
        candidates = [path] if path.is_file() else []
        if path.is_dir():
            for directory, names, filenames in os.walk(path):
                names[:] = sorted(
                    name
                    for name in names
                    if name not in {"node_modules", ".git", ".venv", "coverage", "__pycache__"}
                )
                candidates.extend(Path(directory) / name for name in sorted(filenames))
        for candidate in candidates:
            if (
                candidate.is_file()
                and candidate.suffix in suffixes
                and candidate.resolve().is_relative_to(root)
            ):
                if any(
                    part in {"node_modules", ".git", "coverage"}
                    for part in candidate.relative_to(root).parts
                ):
                    continue
                result[str(candidate.relative_to(root))] = digest(candidate)
    return result


def hash_paths(root: Path, paths: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in paths:
        path = (root / item).resolve()
        if not path.is_file() or not path.is_relative_to(root):
            raise ValueError(f"config path is outside --root or missing: {item}")
        result[str(path.relative_to(root))] = digest(path)
    return result


def runner_version(command: Path, root: Path) -> str | None:
    try:
        return subprocess.check_output([str(command), "--version"], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def command_result(
    command: list[str], root: Path, output: Path, env: dict[str, str]
) -> tuple[int, float]:
    started = time.monotonic()
    with output.open("w") as stream:
        completed = subprocess.run(
            command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, check=False
        )
    return completed.returncode, time.monotonic() - started


def parse_junit(path: Path, root: Path, ecosystem: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    result: list[dict[str, Any]] = []
    for case in ET.parse(path).getroot().iter("testcase"):
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        raw_duration = case.attrib.get("time")
        duration = float(raw_duration) if raw_duration not in (None, "") else None
        filename = case.attrib.get("file", classname)
        source = (root / filename).resolve() if filename else None
        if source and (not source.is_file() or not source.is_relative_to(root)):
            source = None
        relative = str(source.relative_to(root)) if source else classname
        outcome = (
            "failed"
            if case.find("failure") is not None or case.find("error") is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed"
        )
        node = f"{ecosystem}:{relative}::{name}" if relative else f"{ecosystem}:{name}"
        result.append(
            {
                "id": {
                    "ecosystem": ecosystem,
                    "file": relative,
                    "displayName": name,
                    "parameters": [],
                },
                "nodeid": node,
                "outcome": outcome,
                "phases": {
                    "call": {
                        "outcome": outcome,
                        "durationSeconds": duration,
                    }
                },
                "coverageFeatures": [],
                "attribution": "unknown",
                "source": str(source.relative_to(root)) if source else None,
            }
        )
    return result


def parse_vitest_json(path: Path, root: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text())
    result: list[dict[str, Any]] = []
    for file in data.get("testResults", []):
        filename = str(file.get("name", ""))
        try:
            rel = str(Path(filename).resolve().relative_to(root))
        except ValueError:
            rel = filename
        for assertion in file.get("assertionResults", []):
            name = (
                " ".join(assertion.get("fullName", assertion.get("title", "")))
                if isinstance(assertion.get("fullName"), list)
                else str(assertion.get("fullName", assertion.get("title", "")))
            )
            raw_duration = assertion.get("duration")
            duration = float(raw_duration) / 1000 if raw_duration is not None else None
            outcome = (
                "passed"
                if assertion.get("status") in {"passed", "pass"}
                else "skipped"
                if assertion.get("status") in {"pending", "skipped"}
                else "failed"
            )
            result.append(
                {
                    "id": {
                        "ecosystem": "vitest",
                        "file": rel,
                        "displayName": name,
                        "parameters": [],
                    },
                    "nodeid": f"vitest:{rel}::{name}",
                    "outcome": outcome,
                    "phases": {
                        "call": {
                            "outcome": outcome,
                            "durationSeconds": duration,
                        }
                    },
                    "coverageFeatures": [],
                    "attribution": "unknown",
                    "source": rel,
                }
            )
    return result


def core_features(
    path: Path, root: Path, allowed_sources: dict[str, str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Use the shared evidence importer; this adapter only adds runner provenance."""
    from project_assess.test_value.evidence import load_evidence

    document = load_evidence(path, root)
    features: list[dict[str, Any]] = []
    for source in document.get("sources", {}).values():
        relative = str(source.get("path"))
        if relative not in allowed_sources:
            document.setdefault("gaps", []).append(
                {"reason": "source-outside-explicit-scope", "path": relative}
            )
            continue
        # The shared importer may not trust an external artifact to identify
        # the source, but this adapter has the explicit source allow-list and
        # hashes it immediately before and after the runner.  Normalize that
        # identity here so LCOV/Istanbul evidence can be compared across
        # layers without retaining a stale ``source-hash-missing`` warning.
        source["hash"] = allowed_sources[relative]
        document["gaps"] = [
            gap
            for gap in document.get("gaps", [])
            if not (gap.get("reason") == "source-hash-missing" and gap.get("path") == relative)
        ]
        identity = {
            "language": "typescript"
            if Path(relative).suffix.lower() in {".ts", ".tsx"}
            else "javascript",
            "relativePath": relative,
            "sourceHash": source.get("hash"),
            "sourceMapHash": None,
        }
        features.extend(
            {
                "source": identity,
                "kind": "line",
                "location": {"line": int(line)},
                "phase": "combined",
                "attribution": "suite",
            }
            for line in sorted(source.get("lines", ()))
        )
        features.extend(
            {
                "source": identity,
                "kind": "branch",
                "location": {"branch": list(branch) if isinstance(branch, tuple) else branch},
                "phase": "combined",
                "attribution": "suite",
            }
            for branch in sorted(source.get("branches", ()))
        )
    return features, list(document.get("gaps", [])), document


def run(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    if not args.targets:
        raise ValueError("explicit test file targets are required")
    if any(not (root / target).is_file() for target in args.targets):
        raise ValueError("targets must be explicit existing test files")
    layer = args.layer or ("unit" if args.runner == "vitest" else "automation")
    execution_root = (root / args.cwd).resolve()
    if not execution_root.is_dir() or not execution_root.is_relative_to(root):
        raise ValueError("--cwd must name an existing directory inside --root")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = files_under(root, args.source, (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    tests = files_under(root, args.targets, (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    configs = hash_paths(root, args.config)
    before = git_identity(root)
    before_sources, before_tests, before_configs = sources, tests, configs
    log = output / "runner.log"
    env = os.environ.copy()
    command = [str(args.command), *args.runner_arg]
    executable_targets: list[str] = []
    for target in args.targets:
        target_path = (root / target.split("::", 1)[0]).resolve()
        if target_path.is_file() and target_path.is_relative_to(execution_root):
            executable_targets.append(str(target_path.relative_to(execution_root)))
        else:
            executable_targets.append(target)
    if args.test_name:
        escaped = re.escape(args.test_name)
        if args.runner == "vitest":
            command += ["run", f"--testNamePattern=^{escaped}$"]
        else:
            command += ["--test-name-pattern", f"^{escaped}$"]
    if args.runner == "vitest":
        if not args.test_name:
            command += ["run"]
        if args.config:
            config_path = (root / args.config[0]).resolve()
            command += [
                "--config",
                str(config_path.relative_to(execution_root))
                if config_path.is_relative_to(execution_root)
                else str(config_path),
            ]
        command += [
            "--reporter=json",
            f"--outputFile={output / 'vitest.json'}",
        ] + executable_targets
        if args.coverage:
            command += [
                "--coverage.enabled",
                "--coverage.provider=v8",
                "--coverage.reporter=json",
                f"--coverage.reportsDirectory={output / 'coverage'}",
            ]
    else:
        command += [
            "--test",
            "--test-reporter=junit",
            f"--test-reporter-destination={output / 'junit.xml'}",
        ] + executable_targets
        if args.coverage:
            command[1:1] = [
                "--experimental-test-coverage",
                "--test-reporter=lcov",
                f"--test-reporter-destination={output / 'coverage.info'}",
            ]
    exit_code, duration = command_result(command, execution_root, log, env)
    after = git_identity(root)
    after_sources = files_under(root, args.source, (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    after_tests = files_under(root, args.targets, (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    after_configs = hash_paths(root, args.config)
    if before != after:
        raise ValueError("source or tracked repository state changed during collection")
    features: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    _core_document: dict[str, Any] = {}
    if args.coverage and args.runner == "vitest":
        json_candidates = list((output / "coverage").glob("coverage-final.json")) + list(
            (output / "coverage").glob("*.json")
        )
        if json_candidates:
            features, core_gaps, _core_document = core_features(json_candidates[0], root, sources)
            gaps.extend(core_gaps)
        else:
            gaps.append({"reason": "coverage-artifact-missing", "provider": "vitest-v8"})
    elif args.runner == "node-test":
        coverage_path = output / "coverage.info"
        if coverage_path.is_file():
            features, core_gaps, _core_document = core_features(coverage_path, root, sources)
            gaps.extend(core_gaps)
        else:
            gaps.append({"reason": "coverage-artifact-missing", "provider": "node-lcov"})
    else:
        gaps.append({"reason": "coverage-not-requested"})
    if before_sources != after_sources:
        gaps.append({"reason": "source-changed-during-collection"})
    if before_tests != after_tests:
        gaps.append({"reason": "test-sources-changed-during-collection"})
    if before_configs != after_configs:
        gaps.append({"reason": "config-changed-during-collection"})
    observed = (
        parse_vitest_json(output / "vitest.json", root)
        if args.runner == "vitest"
        else parse_junit(output / "junit.xml", root, "node-test")
    )
    if exit_code != 0:
        gaps.append({"reason": "runner-failed", "exitCode": exit_code})
    coverage_unit = "file" if len(args.targets) == 1 else "suite"
    for feature in features:
        feature["attribution"] = coverage_unit
    for row in observed:
        row["attribution"] = "file" if row.get("source") else "unknown"
        row["coverageFeatures"] = []
        if row["outcome"] != "skipped" and row["phases"]["call"]["durationSeconds"] is None:
            gaps.append({"reason": "timing-missing", "testId": row["nodeid"]})
        if row["outcome"] != "skipped" and not row.get("source"):
            gaps.append({"reason": "test-source-identity-unavailable", "testId": row["nodeid"]})
    runnable = [row for row in observed if row["outcome"] != "skipped"]
    isolated = bool(
        args.test_name
        and exit_code == 0
        and len(runnable) == 1
        and runnable[0]["outcome"] == "passed"
        and runnable[0]["phases"]["call"]["durationSeconds"] is not None
        and features
        and not any(
            gap["reason"]
            in {
                "source-missing",
                "source-stale-or-hash-mismatch",
                "source-map-invalid",
                "source-map-line-mapping-unavailable",
                "coverage-artifact-missing",
                "source-changed-during-collection",
                "test-sources-changed-during-collection",
                "config-changed-during-collection",
                "timing-missing",
                "test-source-identity-unavailable",
            }
            for gap in gaps
        )
    )
    if isolated:
        test_id = runnable[0]["nodeid"]
        runnable[0]["coverageFeatures"] = features
        for feature in features:
            feature["attribution"] = "case"
            feature["testId"] = test_id
        # These importer warnings describe an aggregate artifact without
        # caller metadata.  The collector has supplied that metadata and the
        # exact one-case result proof above makes the attribution explicit.
        gaps = [
            gap
            for gap in gaps
            if gap["reason"]
            not in {"suite-only-unattributed", "provenance-layer-framework-provider-missing"}
        ]
        gaps.append({"reason": "combined-invocation-phase-not-split", "testId": test_id})
    elif features:
        gaps.append({"reason": "aggregate-coverage-not-per-test", "attribution": coverage_unit})
        if coverage_unit == "file":
            gaps = [
                gap
                for gap in gaps
                if gap["reason"]
                not in {"suite-only-unattributed", "provenance-layer-framework-provider-missing"}
            ]
    document = {
        "schema": SCHEMA,
        "tool": {
            "collectorHash": digest(Path(__file__).resolve()),
            "normalizerHash": digest(Path(__file__).resolve().with_name("evidence.py")),
        },
        "project": {
            "revision": after.get("revision"),
            "trackedDiffHash": after.get("trackedDiffHash"),
            "sourceHashes": sources,
            "testHashes": tests,
        },
        "scope": {
            "sources": sorted(sources),
            "targets": args.targets,
            "configs": sorted(configs),
            "cwd": str(execution_root.relative_to(root)),
        },
        "runner": {
            "ecosystem": args.runner,
            "layer": layer,
            "language": "typescript" if args.runner == "vitest" else "javascript",
            "command": command,
            "provider": "vitest-v8"
            if args.runner == "vitest" and args.coverage
            else "node-lcov"
            if args.runner == "node-test" and args.coverage
            else None,
            "versions": {
                "node": subprocess.check_output(
                    ["node", "--version"], cwd=execution_root, text=True
                ).strip(),
                "runner": runner_version(args.command, execution_root),
            },
            "cwd": str(execution_root.relative_to(root)),
        },
        "invocation": {
            "isolated": isolated,
            "selectedTests": [row["nodeid"] for row in runnable],
            "testName": args.test_name,
            "outcome": "passed" if exit_code == 0 else "failed",
        },
        "layer": layer,
        "tests": observed,
        "failures": [
            {"testId": row["nodeid"], "outcome": row["outcome"]}
            for row in observed
            if row["outcome"] == "failed"
        ],
        "coverageFeatures": features,
        "gaps": gaps
        + ([{"reason": "child-process-effects-unmeasured"}] if args.runner == "node-test" else []),
        "provenance": {
            "command": command,
            "exitCode": exit_code,
            "durationSeconds": duration,
            "sourceHashesBefore": before_sources,
            "sourceHashesAfter": after_sources,
            "testHashesBefore": before_tests,
            "testHashesAfter": after_tests,
            "configHashesBefore": before_configs,
            "configHashesAfter": after_configs,
            "sourceStable": before_sources == after_sources,
            "testStable": before_tests == after_tests,
            "configStable": before_configs == after_configs,
            "artifacts": [
                {"path": str(p.relative_to(output)), "hash": digest(p)}
                for p in output.rglob("*")
                if p.is_file() and p.name not in {"evidence.json"}
            ],
        },
    }
    (output / "evidence.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return exit_code


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runner", choices=("vitest", "node-test"), required=True)
    parser.add_argument(
        "--layer",
        help="portable caller label such as unit, integration, or automation",
    )
    parser.add_argument(
        "--command",
        type=Path,
        required=True,
        help="existing runner executable; no package installation is attempted",
    )
    parser.add_argument("--cwd", default=".", help="runner working directory inside --root")
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--config", action="append", default=[])
    parser.add_argument(
        "--runner-arg",
        action="append",
        default=[],
        help="existing runner option, e.g. --runner-arg=--maxWorkers=4; repeatable",
    )
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument(
        "--test-name",
        help="exact single test name to run and bind when it is the only passing case",
    )
    parser.add_argument("targets", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    args.targets = [item for item in args.targets if item != "--"]
    try:
        return run(args)
    except (
        OSError,
        ValueError,
        subprocess.CalledProcessError,
        ET.ParseError,
        json.JSONDecodeError,
    ) as error:
        print(f"test-value multilayer: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
