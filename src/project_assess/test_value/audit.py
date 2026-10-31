#!/usr/bin/env python3
"""Collect bounded pytest evidence and report coverage overlap for human review."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = "test-value-audit.v3"
PHASES = {"setup": "setup", "run": "call", "teardown": "teardown"}
DEFAULT_SOFT_TARGET = 70.0
GREEDY_SELECTION_BUDGET = 256
_SOURCE_TREE_CACHE: dict[str, tuple[str, ast.AST]] = {}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    temporary.replace(path)


def versions() -> dict[str, str | None]:
    result: dict[str, str | None] = {"python": sys.version.split()[0]}
    for package in ("pytest", "pytest-cov", "coverage"):
        try:
            result[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result[package] = None
    return result


def git_identity(root: Path) -> dict[str, Any]:
    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

    try:
        revision = git("rev-parse", "HEAD").decode().strip()
        status = git("status", "--porcelain", "--untracked-files=no")
        changes = git("diff", "--binary", "HEAD")
        return {
            "revision": revision,
            "trackedDirty": bool(status),
            "trackedDiffHash": "sha256:" + hashlib.sha256(changes).hexdigest(),
        }
    except (OSError, subprocess.CalledProcessError):
        return {"revision": None, "trackedDirty": None, "trackedDiffHash": None}


class Observations:
    """A pytest observer, loaded only in the explicitly requested test process."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.collected: list[str] = []
        self.deselected: list[str] = []
        self.errors: list[str] = []
        self.tests: dict[str, Any] = {}

    def pytest_collection_finish(self, session: Any) -> None:
        self.collected = [item.nodeid for item in session.items]

    def pytest_deselected(self, items: list[Any]) -> None:
        self.deselected.extend(item.nodeid for item in items)

    def pytest_collectreport(self, report: Any) -> None:
        if report.failed:
            self.errors.append(report.nodeid)

    def pytest_runtest_logreport(self, report: Any) -> None:
        row = self.tests.setdefault(report.nodeid, {"nodeid": report.nodeid, "phases": {}})
        previous = row["phases"].get(report.when)
        if previous:
            row["repeatedPhase"] = True
        row["phases"][report.when] = {
            "outcome": report.outcome,
            "seconds": report.duration,
            "expectedFailure": bool(getattr(report, "wasxfail", False)),
        }

    def pytest_sessionfinish(self, session: Any, exitstatus: int) -> None:
        for row in self.tests.values():
            phases = row["phases"]
            outcomes = [value["outcome"] for value in phases.values()]
            row["outcome"] = (
                "failed"
                if "failed" in outcomes
                else "skipped"
                if "skipped" in outcomes
                else "passed"
                if phases.get("call", {}).get("outcome") == "passed"
                else "incomplete"
            )
        write_json(
            self.path,
            {
                "schema": SCHEMA,
                "finished": True,
                "exitcode": int(exitstatus),
                "collected": self.collected,
                "deselected": self.deselected,
                "collectionErrors": self.errors,
                "tests": list(self.tests.values()),
            },
        )


def child(root: Path, output: Path, arguments: list[str]) -> int:
    import pytest

    os.chdir(root)
    return int(pytest.main(arguments, plugins=[Observations(output / "tests.json")]))


def sources(root: Path, requested: list[str], *, allow_files: bool = False) -> list[Path]:
    result = []
    for name in requested:
        path = (root / name).resolve()
        valid = path.is_dir() or (allow_files and path.is_file())
        if not valid or not path.is_relative_to(root):
            raise ValueError(f"--source must name a product source path inside --root: {name}")
        result.append(path)
    return result


def source_hashes(paths: list[Path], root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for directory in paths:
        if directory.is_file():
            candidates = [directory] if directory.suffix == ".py" else []
        elif directory.is_dir():
            candidates = sorted(directory.rglob("*.py"))
        else:
            candidates = []
        for path in candidates:
            if not path.is_relative_to(root) or any(
                part in {".venv", "node_modules", "__pycache__", ".git"}
                for part in path.relative_to(root).parts
            ):
                continue
            result[str(path.relative_to(root))] = digest(path)
    return result


def selected_test_paths(root: Path, targets: list[str]) -> list[Path]:
    paths: list[Path] = []
    for target in targets:
        path = (root / target.split("::", 1)[0]).resolve()
        if path.is_relative_to(root) and path not in paths:
            paths.append(path)
    return paths


def environment_identity(root: Path) -> dict[str, Any]:
    names = {
        "pytest.ini",
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        "pytest.toml",
        "conftest.py",
        "requirements.txt",
        "requirements.lock",
        "uv.lock",
    }
    files: dict[str, str] = {}
    for directory, directories, filenames in os.walk(root):
        directories[:] = [
            name
            for name in directories
            if name not in {".git", ".venv", "node_modules", "__pycache__"}
        ]
        for filename in filenames:
            if filename in names:
                path = Path(directory) / filename
                files[str(path.relative_to(root))] = digest(path)
    return {
        "python": sys.executable,
        "versions": versions(),
        "files": files,
        "env": {key: os.environ.get(key) for key in ("PYTHONPATH", "PYTEST_ADDOPTS")},
    }


def collect_single(args: argparse.Namespace) -> int:
    root, output = args.root.resolve(), args.output.resolve()
    if not 0 <= args.soft_target <= 100:
        raise ValueError("--soft-target must be a percentage between 0 and 100")
    selected = args.targets[1:] if args.targets[:1] == ["--"] else args.targets
    if not selected or any(value.startswith("-") for value in selected):
        raise ValueError(
            "provide explicit pytest file/directory/node targets after --, without flags"
        )
    for target in selected:
        path = (root / target.split("::", 1)[0]).resolve()
        if not path.exists() or not path.is_relative_to(root):
            raise ValueError(f"test target must exist inside --root: {target}")
    paths = sources(root, args.source)
    test_paths = selected_test_paths(root, selected)
    installed = versions()
    if any(installed[name] is None for name in ("pytest", "pytest-cov", "coverage")):
        raise ValueError(
            "run with the repository's Python containing pytest, pytest-cov and coverage"
        )
    output.mkdir(parents=True, exist_ok=False)
    config = output / "coverage.ini"
    config.write_text("[run]\nbranch = True\ndata_file = " + str(output / ".coverage") + "\n")
    pytest_args = [
        *selected,
        "--cov-reset",
        *(f"--cov={path}" for path in paths),
        "--cov-branch",
        "--cov-context=test",
        "--cov-report=",
        f"--cov-config={config}",
    ]
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "_pytest",
        str(root),
        str(output),
        *pytest_args,
    ]
    manifest = {
        "schema": SCHEMA,
        "root": str(root),
        "sources": [str(p) for p in paths],
        "targets": selected,
        "policy": {
            "softTargetPercent": args.soft_target,
            "criticalSources": list(args.critical),
            "protectedTests": list(args.protect_test),
        },
        "python": sys.executable,
        "toolVersions": installed,
        "toolHash": digest(Path(__file__)),
        "environment": environment_identity(root),
        "startedAt": datetime.now(UTC).isoformat(),
        "before": git_identity(root),
        "sourceBefore": source_hashes(paths, root),
        "testBefore": source_hashes(test_paths, root),
        "command": command,
        "exitcode": None,
        "finished": False,
    }
    write_json(output / "run.json", manifest)
    environment = {**os.environ, "COVERAGE_FILE": str(output / ".coverage")}
    started = time.monotonic()
    with (output / "pytest.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT
        )
        try:
            code = process.wait()
        except BaseException:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
    manifest.update(
        exitcode=code,
        finished=True,
        elapsedSeconds=time.monotonic() - started,
        after=git_identity(root),
        sourceAfter=source_hashes(paths, root),
        testAfter=source_hashes(test_paths, root),
    )
    manifest["artifactHashes"] = {
        name: digest(output / name)
        for name in (".coverage", "tests.json")
        if (output / name).is_file()
    }
    write_json(output / "run.json", manifest)
    if not getattr(args, "suppress_report", False):
        report(
            root,
            output / ".coverage",
            output / "tests.json",
            [],
            output,
            paths,
            soft_target=args.soft_target,
            critical_sources=args.critical,
            protected_tests=args.protect_test,
        )
    suffix = (
        f"; report: {output / 'report.md'}" if not getattr(args, "suppress_report", False) else ""
    )
    print(f"pytest exit {code}{suffix}; log: {output / 'pytest.log'}")
    return code if code >= 0 else 2


def _collection_identity(
    args: argparse.Namespace, selected: list[str], paths: list[Path]
) -> dict[str, Any]:
    """Return the inputs that make a shard result safe to resume."""
    return {
        "root": str(args.root.resolve()),
        "git": git_identity(args.root.resolve()),
        "targets": selected,
        "sources": [str(path.relative_to(args.root.resolve())) for path in paths],
        "sourceHashes": source_hashes(paths, args.root.resolve()),
        "testHashes": source_hashes(
            selected_test_paths(args.root.resolve(), selected), args.root.resolve()
        ),
        "softTargetPercent": args.soft_target,
        "criticalSources": list(args.critical),
        "protectedTests": list(args.protect_test),
        "toolHash": digest(Path(__file__).resolve()),
        "toolVersions": versions(),
        "environment": environment_identity(args.root.resolve()),
    }


def _merge_shards(
    root: Path,
    shard_dirs: list[Path],
    output: Path,
    identity: dict[str, Any],
    selected: list[str],
    batches: list[list[str]],
) -> int:
    """Merge successful shard artifacts through coverage.py's public data API."""
    from coverage import CoverageData

    output.mkdir(parents=True, exist_ok=True)
    merged_coverage = output / ".coverage"
    merged = CoverageData(basename=str(merged_coverage))
    merged.erase()
    rows: list[dict[str, Any]] = []
    collected: list[str] = []
    errors: list[str] = []
    shard_receipts: list[dict[str, Any]] = []
    duplicate_nodes: set[str] = set()
    seen_nodes: set[str] = set()
    seen_collected: set[str] = set()
    for shard, batch in zip(shard_dirs, batches, strict=True):
        run_path = shard / "run.json"
        tests_path = shard / "tests.json"
        coverage_path = shard / ".coverage"
        run = json.loads(run_path.read_text()) if run_path.is_file() else {}
        if not run_path.is_file() or not tests_path.is_file() or not coverage_path.is_file():
            shard_receipts.append({"path": str(shard), "status": "incomplete"})
            errors.append(f"missing or incomplete shard: {shard}")
            continue
        if run.get("exitcode") != 0 or not run.get("finished"):
            shard_receipts.append(
                {"path": str(shard), "status": "failed", "exitcode": run.get("exitcode")}
            )
            errors.append(f"failed shard: {shard}")
            continue
        expected_artifacts = {name: digest(shard / name) for name in (".coverage", "tests.json")}
        expected_policy = {
            "softTargetPercent": identity["softTargetPercent"],
            "criticalSources": identity["criticalSources"],
            "protectedTests": identity["protectedTests"],
        }
        if run.get("artifactHashes") != expected_artifacts:
            errors.append(f"artifact hash mismatch: {shard}")
            continue
        if (
            run.get("root") != str(root)
            or run.get("targets") != batch
            or run.get("policy") != expected_policy
            or run.get("sourceBefore") != identity["sourceHashes"]
            or run.get("testBefore") != source_hashes(selected_test_paths(root, batch), root)
            or run.get("sourceAfter") != run.get("sourceBefore")
            or run.get("testAfter") != run.get("testBefore")
            or run.get("before") != run.get("after")
            or run.get("before") != identity["git"]
            or run.get("toolHash") != identity["toolHash"]
            or run.get("toolVersions") != identity["toolVersions"]
            or run.get("environment") != identity["environment"]
        ):
            errors.append(f"shard identity mismatch: {shard}")
            continue
        try:
            document = json.loads(tests_path.read_text())
        except (OSError, json.JSONDecodeError):
            errors.append(f"invalid tests metadata: {shard}")
            continue
        if (
            document.get("schema") != SCHEMA
            or document.get("exitcode") != 0
            or not document.get("finished")
            or document.get("collectionErrors")
        ):
            errors.append(f"invalid tests metadata: {shard}")
            continue
        data = CoverageData(basename=str(coverage_path))
        data.read()
        merged.update(data)
        collected_nodes = document.get("collected", [])
        if len(collected_nodes) != len(set(collected_nodes)):
            errors.append(f"duplicate collected node identity: {shard}")
        if any(node in seen_collected for node in collected_nodes):
            errors.append(f"duplicate collected node across shards: {shard}")
        if any(
            not any(
                node == target or node.startswith(target + "::") or node.startswith(target + "[")
                for target in batch
            )
            for node in collected_nodes
        ):
            errors.append(f"out-of-batch collected node: {shard}")
        seen_collected.update(collected_nodes)
        expected_nodes = set(collected_nodes)
        for row in document.get("tests", []):
            node = row.get("nodeid")
            if node in seen_nodes:
                duplicate_nodes.add(str(node))
            if node not in expected_nodes:
                errors.append(f"out-of-batch observed node: {node}")
            seen_nodes.add(str(node))
            rows.append(row)
        collected.extend(document.get("collected", []))
        errors.extend(document.get("collectionErrors", []))
        shard_receipts.append(
            {
                "path": str(shard),
                "status": "passed",
                "exitcode": run.get("exitcode"),
                "artifactHashes": run.get("artifactHashes", {}),
            }
        )
    merged.write()
    if duplicate_nodes:
        errors.extend(
            f"duplicate node identity across shards: {node}" for node in sorted(duplicate_nodes)
        )
    write_json(
        output / "tests.json",
        {
            "schema": SCHEMA,
            "finished": not errors,
            "exitcode": 0 if not errors else 2,
            "collected": collected,
            "deselected": [],
            "collectionErrors": errors,
            "tests": rows,
        },
    )
    manifest = {
        "schema": SCHEMA,
        "root": str(root),
        "sources": identity["sources"],
        "targets": selected,
        "policy": {
            "softTargetPercent": identity["softTargetPercent"],
            "criticalSources": identity["criticalSources"],
            "protectedTests": identity["protectedTests"],
        },
        "toolVersions": identity["toolVersions"],
        "toolHash": identity["toolHash"],
        "environment": identity["environment"],
        "sourceBefore": identity["sourceHashes"],
        "testBefore": identity["testHashes"],
        "sourceAfter": source_hashes([root / source for source in identity["sources"]], root),
        "testAfter": source_hashes(selected_test_paths(root, selected), root),
        "before": git_identity(root),
        "after": git_identity(root),
        "finished": not errors,
        "exitcode": 0 if not errors else 2,
        "shards": shard_receipts,
        "requiredShardCount": len(shard_dirs),
        "duplicateNodes": sorted(duplicate_nodes),
        "artifactHashes": {
            name: digest(output / name)
            for name in (".coverage", "tests.json")
            if (output / name).is_file()
        },
    }
    write_json(output / "run.json", manifest)
    return 0 if not errors else 2


def _valid_shard_for_reuse(
    root: Path, shard: Path, batch: list[str], identity: dict[str, Any]
) -> bool:
    """Validate a prior shard receipt before allowing resume reuse."""
    run_path, tests_path, coverage_path = (
        shard / "run.json",
        shard / "tests.json",
        shard / ".coverage",
    )
    if not (run_path.is_file() and tests_path.is_file() and coverage_path.is_file()):
        return False
    try:
        run = json.loads(run_path.read_text())
        tests = json.loads(tests_path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    expected_hashes = {name: digest(shard / name) for name in (".coverage", "tests.json")}
    expected_tests = source_hashes(selected_test_paths(root, batch), root)
    expected_policy = {
        "softTargetPercent": identity["softTargetPercent"],
        "criticalSources": identity["criticalSources"],
        "protectedTests": identity["protectedTests"],
    }
    if (
        run.get("schema") != SCHEMA
        or run.get("root") != str(root)
        or run.get("targets") != batch
        or run.get("policy") != expected_policy
        or run.get("exitcode") != 0
        or not run.get("finished")
        or run.get("artifactHashes") != expected_hashes
        or run.get("sourceBefore") != identity["sourceHashes"]
        or run.get("sourceAfter") != run.get("sourceBefore")
        or run.get("testBefore") != expected_tests
        or run.get("testAfter") != run.get("testBefore")
        or run.get("before") != run.get("after")
        or run.get("before") != identity["git"]
        or run.get("toolHash") != identity["toolHash"]
        or run.get("toolVersions") != identity["toolVersions"]
        or run.get("environment") != identity["environment"]
    ):
        return False
    nodes = tests.get("collected", [])
    observed = [row.get("nodeid") for row in tests.get("tests", [])]
    return (
        tests.get("schema") == SCHEMA
        and tests.get("finished")
        and tests.get("exitcode") == 0
        and not tests.get("collectionErrors")
        and len(nodes) == len(set(nodes))
        and len(observed) == len(set(observed))
        and set(observed) == set(nodes)
    )


def collect(args: argparse.Namespace) -> int:
    root, output = args.root.resolve(), args.output.resolve()
    selected = args.targets[1:] if args.targets[:1] == ["--"] else args.targets
    if not selected or any(value.startswith("-") for value in selected):
        raise ValueError(
            "provide explicit pytest file/directory/node targets after --, without flags"
        )
    paths = sources(root, args.source)
    identity = _collection_identity(args, selected, paths)
    if args.batch_size is None:
        if args.resume:
            raise ValueError("--resume requires --batch-size")
        return collect_single(args)
    if args.batch_size < 1:
        raise ValueError("--batch-size must be positive")
    if any((root / target.split("::", 1)[0]).is_dir() for target in selected):
        raise ValueError(
            "--batch-size requires explicit test files or node IDs, not directory targets"
        )
    shards = [selected[i : i + args.batch_size] for i in range(0, len(selected), args.batch_size)]
    if args.resume:
        manifest_path = output / "manifest.json"
        if not manifest_path.is_file():
            raise ValueError("--resume requires an existing shard output with manifest.json")
        existing = json.loads(manifest_path.read_text())
        if (
            existing.get("identity") != identity
            or existing.get("selected") != selected
            or existing.get("shards") != shards
        ):
            raise ValueError("resume inputs do not match the original shard manifest")
    else:
        output.mkdir(parents=True, exist_ok=False)
    write_json(
        output / "manifest.json",
        {
            "schema": SCHEMA,
            "identity": identity,
            "selected": selected,
            "shards": shards,
            "status": "running",
        },
    )
    shard_dirs: list[Path] = []
    failed_seen = False
    for index, batch in enumerate(shards):
        shard = output / f"shard-{index:04d}"
        shard_dirs.append(shard)
        shard_args = argparse.Namespace(**vars(args))
        shard_args.output = shard
        shard_args.targets = ["--", *batch]
        shard_args.batch_size = None
        shard_args.suppress_report = True
        existing_run = shard / "run.json"
        reused = False
        if args.resume and existing_run.is_file():
            previous = json.loads(existing_run.read_text())
            previous_code = previous.get("exitcode")
            code = previous_code if isinstance(previous_code, int) else 2
            if _valid_shard_for_reuse(root, shard, batch, identity):
                reused = True
        if not reused:
            if shard.exists():
                prior = output / f"{shard.name}.prior-{int(time.time())}"
                shutil.move(str(shard), str(prior))
            try:
                code = collect_single(shard_args)
            except Exception:
                shard.mkdir(parents=True, exist_ok=True)
                write_json(shard / "failure.json", {"status": "incomplete", "targets": batch})
                code = 2
        if code != 0:
            failed_seen = True
    code = _merge_shards(root, shard_dirs, output, identity, selected, shards)
    report(
        root,
        output / ".coverage",
        output / "tests.json",
        [],
        output,
        sources(root, args.source),
        soft_target=args.soft_target,
        critical_sources=args.critical,
        protected_tests=args.protect_test,
    )
    code = 2 if failed_seen or code else 0
    write_json(
        output / "manifest.json",
        {
            "schema": SCHEMA,
            "identity": identity,
            "selected": selected,
            "shards": shards,
            "status": "complete" if code == 0 else "failed",
        },
    )
    return code


def load_observations(path: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if path is None or not path.is_file():
        return {}, {}
    document = json.loads(path.read_text())
    rows = document.get("tests", [])
    if not isinstance(rows, list):
        raise TypeError("tests artifact must contain a tests list")
    by_id = {}
    for row in rows:
        name = row["nodeid"]
        if name in by_id:
            raise ValueError(f"duplicate node ID in tests artifact: {name}")
        by_id[name] = row
    return document, by_id


def junit_timings(paths: list[Path], nodes: set[str]) -> tuple[dict[str, Any], list[Any], set[str]]:
    aliases: dict[tuple[str, str], set[str]] = defaultdict(set)
    for node in nodes:
        file, *parts = node.split("::")
        if not parts:
            continue
        module = file.removesuffix(".py").replace("/", ".")
        aliases[(".".join([module, *parts[:-1]]), parts[-1])].add(node)
    matches: dict[str, list[Any]] = defaultdict(list)
    unmatched = []
    ambiguous: set[str] = set()
    for path in paths:
        for case in ET.parse(path).getroot().iter("testcase"):
            key = (case.get("classname", ""), case.get("name", ""))
            found = aliases.get(key, set())
            if len(found) != 1:
                unmatched.append(
                    {
                        "artifact": str(path),
                        "classname": key[0],
                        "name": key[1],
                        "reason": "ambiguous" if found else "unmatched",
                    }
                )
                ambiguous.update(found)
                continue
            node = next(iter(found))
            outcome = (
                "failed"
                if case.find("failure") is not None or case.find("error") is not None
                else "skipped"
                if case.find("skipped") is not None
                else "passed"
            )
            matches[node].append(
                {"outcome": outcome, "durationSeconds": float(case.get("time", "0"))}
            )
    timing = {}
    for node, values in matches.items():
        if len(values) == 1:
            timing[node] = values[0]
        else:
            ambiguous.add(node)
            unmatched.append({"nodeid": node, "reason": "multiple-junit-cases"})
    return timing, unmatched, ambiguous


def matches_any(value: str, patterns: list[str]) -> bool:
    """Match explicit repository-relative policy globs, never inferred risk."""

    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def test_source_span(root: Path, nodeid: str) -> dict[str, Any] | None:
    """Return a small AST-based estimate of the test's authored source size.

    Parametrized node IDs contain values that are not Python identifiers.  The
    function name before the first ``[`` is therefore the stable lookup key.
    A missing or dynamic source is an explicit absence, not a guessed span.
    """

    file_name, *parts = nodeid.split("::")
    if not parts:
        return None
    path = (root / file_name).resolve()
    if not path.is_file() or not path.is_relative_to(root):
        return None
    function_name = parts[-1].split("[", 1)[0]
    try:
        source = path.read_text()
        fingerprint = hashlib.sha256(source.encode()).hexdigest()
        cached = _SOURCE_TREE_CACHE.get(str(path))
        if cached is None or cached[0] != fingerprint:
            tree = ast.parse(source)
            _SOURCE_TREE_CACHE[str(path)] = (fingerprint, tree)
        else:
            tree = cached[1]
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None
    if tree is None:
        return None
    matches = [
        item
        for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == function_name
    ]
    if not matches:
        return None
    # A test method name can repeat across classes.  Prefer the class path when
    # available; otherwise a unique function is the only non-ambiguous choice.
    if len(matches) > 1:
        class_name = parts[-2] if len(parts) > 1 else ""
        narrowed = [
            item
            for item in matches
            if any(
                isinstance(parent, ast.ClassDef) and parent.name == class_name
                for parent in ast.walk(tree)
                if item in getattr(parent, "body", [])
            )
        ]
        if len(narrowed) == 1:
            matches = narrowed
        else:
            return None
    item = matches[0]
    start = min(
        [decorator.lineno for decorator in getattr(item, "decorator_list", [])] + [int(item.lineno)]  # type: ignore[attr-defined]
    )
    end = getattr(item, "end_lineno", None)
    if end is None:
        return None
    return {
        "file": str(path.relative_to(root)),
        "startLine": start,
        "endLine": end,
        "sourceLines": end - start + 1,
    }


def executable_statement_coverage(
    root: Path,
    coverage_file: Path,
    measured_files: dict[str, str],
    critical_sources: list[str],
) -> dict[str, Any]:
    """Use coverage.py's public analysis2 API for a real statement denominator."""

    from coverage import Coverage
    from coverage.exceptions import CoverageException

    result: dict[str, Any] = {"files": {}, "total": {}, "ordinary": {}}
    coverage = Coverage(data_file=str(coverage_file))
    try:
        coverage.load()
    except (OSError, ValueError):
        return result
    total_statements = total_covered = ordinary_statements = ordinary_covered = 0
    for relative in sorted(measured_files):
        path = (root / relative).resolve()
        try:
            _filename, statements, _excluded, missing, _missing_branch = coverage.analysis2(
                str(path)
            )
        except (OSError, ValueError, CoverageException):
            continue
        statement_set = set(statements)
        missing_set = set(missing)
        covered = statement_set - missing_set
        is_critical = matches_any(relative, critical_sources)
        row = {
            "statements": len(statement_set),
            "covered": len(covered),
            "percent": round(100 * len(covered) / len(statement_set), 2) if statement_set else None,
            "critical": is_critical,
        }
        result["files"][relative] = row
        total_statements += len(statement_set)
        total_covered += len(covered)
        if not is_critical:
            ordinary_statements += len(statement_set)
            ordinary_covered += len(covered)
    result["total"] = {
        "statements": total_statements,
        "covered": total_covered,
        "percent": round(100 * total_covered / total_statements, 2) if total_statements else None,
    }
    result["ordinary"] = {
        "statements": ordinary_statements,
        "covered": ordinary_covered,
        "percent": round(100 * ordinary_covered / ordinary_statements, 2)
        if ordinary_statements
        else None,
    }
    return result


def report(
    root: Path,
    coverage_file: Path,
    observations: Path | None,
    junit: list[Path],
    output: Path,
    scope: list[Path],
    *,
    soft_target: float | None = None,
    critical_sources: list[str] | None = None,
    protected_tests: list[str] | None = None,
    detail: bool = False,
) -> dict[str, Any]:
    from coverage import CoverageData

    run_file = observations.parent / "run.json" if observations else None
    run = json.loads(run_file.read_text()) if run_file and run_file.is_file() else {}
    policy = run.get("policy", {}) if isinstance(run, dict) else {}
    if soft_target is None:
        soft_target = float(policy.get("softTargetPercent", DEFAULT_SOFT_TARGET))
    if critical_sources is None:
        critical_sources = list(policy.get("criticalSources", []))
    else:
        critical_sources = list(critical_sources)
    if protected_tests is None:
        protected_tests = list(policy.get("protectedTests", []))
    else:
        protected_tests = list(protected_tests)
    metadata, observed = load_observations(observations)
    if not 0 <= soft_target <= 100:
        raise ValueError("--soft-target must be a percentage between 0 and 100")
    warnings = [
        "Coverage measures execution, not assertion equivalence or safe deletion.",
        "Only selected sources and tests are measured; child/native/browser effects are unproven.",
        "Shared fixtures can be attributed to their first caller; setup is not unique test value.",
        (
            "AST source spans estimate authored maintenance; parametrized node IDs "
            "share one definition span and are not summed as unique lines."
        ),
        (
            "Review scores prioritize overlap, measured runtime, and source span; "
            "they are not semantic test-value or deletion proof."
        ),
    ]
    gaps: list[Any] = []
    feature_sets: dict[str, dict[str, set[tuple[Any, ...]]]] = defaultdict(
        lambda: {phase: set() for phase in ("setup", "call", "teardown")}
    )
    unassigned: set[tuple[Any, ...]] = set()
    unknown_contexts: set[str] = set()
    raw_contexts: dict[str, set[str]] = defaultdict(set)
    files: dict[str, str] = {}
    has_arcs = False
    if coverage_file.is_file():
        data = CoverageData(basename=str(coverage_file))
        data.read()
        has_arcs = data.has_arcs()
        if not scope and run:
            scope = [
                (root / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
                for p in run.get("sources", [])
            ]
        for filename in sorted(data.measured_files()):
            path = Path(filename)
            path = (root / path).resolve() if not path.is_absolute() else path.resolve()
            if not path.is_relative_to(root) or (
                scope and not any(path.is_relative_to(p) for p in scope)
            ):
                continue
            relative = str(path.relative_to(root))
            if path.is_file():
                files[relative] = digest(path)
            else:
                gaps.append({"path": relative, "reason": "source-missing"})
            data.set_query_contexts(None)
            context_lines: dict[str, set[int]] = defaultdict(set)
            for line, contexts in data.contexts_by_lineno(filename).items():
                for context in contexts:
                    context_lines[context].add(line)
            for context, lines in context_lines.items():
                features: set[tuple[Any, ...]] = {(relative, "line", line) for line in lines}
                if has_arcs:
                    data.set_query_context(context)
                    features.update((relative, "arc", a, b) for a, b in (data.arcs(filename) or []))
                name, separator, phase = context.rpartition("|")
                if separator and name and phase in PHASES and "::" in name:
                    raw_contexts[name].add(context)
                    feature_sets[name][PHASES[phase]].update(features)
                else:
                    unassigned.update(features)
                    if context:
                        unknown_contexts.add(context)
        data.set_query_contexts(None)
    else:
        gaps.append({"reason": "coverage-file-missing"})
    if not has_arcs:
        gaps.append({"reason": "branch-data-missing"})
    if not feature_sets:
        gaps.append({"reason": "per-test-contexts-missing"})
    if unknown_contexts:
        gaps.append(
            {
                "reason": "unrecognized-coverage-contexts",
                "contexts": sorted(unknown_contexts),
            }
        )
    names = set(feature_sets) | set(observed)
    timing, unmatched_junit, ambiguous = junit_timings(junit, names)
    if not metadata and not timing:
        gaps.append({"reason": "test-outcomes-and-timings-unavailable"})
    healthy = bool(
        metadata.get("finished")
        and metadata.get("exitcode") == 0
        and not metadata.get("collectionErrors")
    )
    if metadata and not healthy:
        gaps.append(
            {
                "reason": "pytest-run-incomplete-or-failed",
                "exitcode": metadata.get("exitcode"),
                "collectionErrors": metadata.get("collectionErrors", []),
            }
        )
    if run and (not run.get("finished") or run.get("exitcode") != 0):
        healthy = False
        gaps.append({"reason": "collection-manifest-incomplete-or-failed"})
    if run and (
        run.get("before") != run.get("after") or run.get("sourceBefore") != run.get("sourceAfter")
    ):
        healthy = False
        gaps.append({"reason": "source-changed-during-run"})
    if run and run.get("sourceAfter"):
        changed = [name for name, value in files.items() if run["sourceAfter"].get(name) != value]
        if changed:
            healthy = False
            gaps.append({"reason": "source-changed-since-collection", "paths": changed})
    if run:
        current_identity = git_identity(root)
        if run.get("after") and current_identity != run["after"]:
            healthy = False
            gaps.append({"reason": "repository-changed-since-collection"})
        test_after = run.get("testAfter")
        targets = run.get("targets", [])
        if test_after is None:
            if (
                run.get("after")
                and current_identity == run["after"]
                and current_identity.get("revision")
            ):
                gaps.append({"reason": "test-source-provenance-legacy-git-bound"})
                warnings.append(
                    "Test hashes predate this artifact format; exact Git identity "
                    "is the weaker binding."
                )
            else:
                healthy = False
                gaps.append({"reason": "test-source-provenance-missing"})
        elif not targets:
            healthy = False
            gaps.append({"reason": "test-target-provenance-missing"})
        else:
            current_tests = source_hashes(selected_test_paths(root, targets), root)
            if current_tests != test_after:
                healthy = False
                gaps.append(
                    {
                        "reason": "test-sources-changed-since-collection",
                        "paths": sorted(set(current_tests) | set(test_after)),
                    }
                )
    if run and (Path(run.get("root", "")).resolve() != root):
        healthy = False
        gaps.append({"reason": "artifact-root-mismatch"})
    if run:
        for name, artifact in ((".coverage", coverage_file), ("tests.json", observations)):
            expected = run.get("artifactHashes", {}).get(name)
            if (
                expected is None
                or artifact is None
                or not artifact.is_file()
                or digest(artifact) != expected
            ):
                healthy = False
                gaps.append({"reason": "artifact-hash-unbound-or-mismatched", "artifact": name})
    if any(gap["reason"] == "source-missing" for gap in gaps):
        healthy = False
    if unmatched_junit:
        gaps.append({"reason": "junit-identities-unmatched", "cases": unmatched_junit})
    if ambiguous:
        gaps.append({"reason": "ambiguous-timing-identities", "nodeids": sorted(ambiguous)})
    if not metadata:
        warnings.append(
            "Imported artifacts have no complete pytest observer; similarities are unranked."
        )
    elif not run:
        healthy = False
        gaps.append({"reason": "observation-provenance-unbound"})
    critical_obligation_gaps: list[dict[str, Any]] = []
    statement_coverage = executable_statement_coverage(root, coverage_file, files, critical_sources)
    if not statement_coverage["total"].get("statements"):
        gaps.append({"reason": "executable-statement-analysis-unavailable"})
    frequency: Counter[tuple[Any, ...]] = Counter()
    owners: dict[tuple[Any, ...], list[str]] = defaultdict(list)
    for name in sorted(feature_sets):
        for feature in feature_sets[name]["call"]:
            frequency[feature] += 1
            # A bounded witness sample avoids quadratic work on ubiquitous paths.
            # These witnesses are overlap leads, never a proposed replacement set.
            if len(owners[feature]) < 6:
                owners[feature].append(name)
    rows = []
    signatures: dict[str, list[str]] = defaultdict(list)
    candidates = []
    row_by_name: dict[str, dict[str, Any]] = {}
    for name in sorted(names):
        phases = feature_sets[name]
        call = phases["call"]
        observation = observed.get(name, {})
        measured_phases = observation.get("phases", {})
        fallback = timing.get(name, {})
        duration = (
            sum(p["seconds"] for p in measured_phases.values())
            if measured_phases
            else fallback.get("durationSeconds")
        )
        unique = {feature for feature in call if frequency[feature] == 1}
        row_critical_features = {
            feature for feature in call if matches_any(str(feature[0]), critical_sources)
        }
        explicit_protection = matches_any(name, protected_tests)
        protected = bool(row_critical_features or explicit_protection)
        overlap_ratio = len(call - unique) / len(call) if call else 0.0
        signature = (
            "sha256:" + hashlib.sha256(json.dumps(sorted(call)).encode()).hexdigest()
            if call
            else None
        )
        if signature:
            signatures[signature].append(name)
        by_file: dict[str, dict[str, list[Any]]] = {}
        for feature in sorted(call):
            item = by_file.setdefault(feature[0], {"lines": [], "arcs": []})
            item["lines" if feature[1] == "line" else "arcs"].append(
                feature[2] if feature[1] == "line" else list(feature[2:])
            )
        row = {
            "nodeid": name,
            "outcome": observation.get("outcome", fallback.get("outcome", "unknown")),
            "durationSeconds": duration,
            "setupSeconds": measured_phases.get("setup", {}).get("seconds"),
            "callSeconds": measured_phases.get("call", {}).get("seconds"),
            "teardownSeconds": measured_phases.get("teardown", {}).get("seconds"),
            "phases": measured_phases,
            "sourceSpan": test_source_span(root, name),
            "coverage": by_file if detail else None,
            "coverageRef": str(coverage_file),
            "phaseFeatureCounts": {phase: len(values) for phase, values in phases.items()},
            "uniqueLines": sum(f[1] == "line" for f in unique),
            "uniqueArcs": sum(f[1] == "arc" for f in unique),
            "overlapRatio": round(overlap_ratio, 4),
            "critical": protected,
            "criticalReasons": (
                (["critical-source"] if row_critical_features else [])
                + (["protected-test"] if explicit_protection else [])
            ),
            "signature": signature,
            "rawContexts": sorted(raw_contexts[name]),
        }
        if not detail:
            row.pop("coverage")
        rows.append(row)
        row_by_name[name] = {
            "name": name,
            "features": call,
            "criticalFeatures": row_critical_features,
            "critical": protected,
            "durationSeconds": duration,
            "sourceSpan": row["sourceSpan"],
            "eligible": bool(
                healthy
                and has_arcs
                and call
                and row["outcome"] == "passed"
                and name not in ambiguous
                and not observation.get("repeatedPhase")
                and not any(p.get("expectedFailure") for p in measured_phases.values())
            ),
        }
        if not call:
            gaps.append({"nodeid": name, "reason": "no-call-coverage"})
        if observation.get("repeatedPhase") or any(
            p.get("expectedFailure") for p in measured_phases.values()
        ):
            gaps.append({"nodeid": name, "reason": "rerun-or-expected-failure"})
            continue
        if row_by_name[name]["eligible"] and not protected:
            alternatives: Counter[str] = Counter()
            for feature in call:
                alternatives.update(other for other in owners[feature] if other != name)
            shared = len(call - unique)
            # A small unique ordinary footprint is not an automatic keep.  It
            # is still an investigation lead when most of the behavior overlaps
            # or its marginal footprint is small enough to replace cheaply.
            if overlap_ratio >= 0.5 or len(unique) <= 3:
                candidates.append(
                    {
                        "nodeid": name,
                        "recommendation": "investigate",
                        "durationSeconds": duration,
                        "callSeconds": row["callSeconds"],
                        "sourceLines": (row["sourceSpan"] or {}).get("sourceLines"),
                        "sharedFeatures": shared,
                        "uniqueFeatures": len(unique),
                        "overlapRatio": round(overlap_ratio, 4),
                        "overlappingTests": [other for other, _ in alternatives.most_common(5)],
                        "reason": (
                            "Low marginal measured call footprint; assertions and "
                            "distinct effects still require review."
                        ),
                    }
                )
    scoped_source_names: set[str] = set()
    for source_path in scope:
        source_path = source_path.resolve()
        if source_path.is_file() and source_path.suffix == ".py":
            scoped_source_names.add(str(source_path.relative_to(root)))
        elif source_path.is_dir():
            scoped_source_names.update(
                str(path.relative_to(root)) for path in source_path.rglob("*.py")
            )
    all_call_features = {feature for phases in feature_sets.values() for feature in phases["call"]}
    for pattern in critical_sources:
        matching_sources = {path for path in scoped_source_names if matches_any(path, [pattern])}
        if not matching_sources:
            gap_unmatched: dict[str, Any] = {
                "reason": "critical-source-pattern-unmatched",
                "pattern": pattern,
            }
            gaps.append(gap_unmatched)
            critical_obligation_gaps.append(gap_unmatched)
            continue
        source_features = {
            feature for feature in all_call_features if feature[0] in matching_sources
        }
        if not source_features:
            gap_unobserved: dict[str, Any] = {
                "reason": "critical-source-unobserved",
                "pattern": pattern,
                "sources": sorted(matching_sources),
            }
            gaps.append(gap_unobserved)
            critical_obligation_gaps.append(gap_unobserved)
        elif not any(
            row["eligible"] and any(feature in source_features for feature in row["features"])
            for row in row_by_name.values()
        ):
            gap_unmeasured: dict[str, Any] = {
                "reason": "critical-source-unmeasured",
                "pattern": pattern,
                "sources": sorted(matching_sources),
            }
            gaps.append(gap_unmeasured)
            critical_obligation_gaps.append(gap_unmeasured)
    for pattern in protected_tests:
        matching_tests = {name for name in names if matches_any(name, [pattern])}
        if not matching_tests:
            gap_unmatched_test: dict[str, Any] = {
                "reason": "protected-test-pattern-unmatched",
                "pattern": pattern,
            }
            gaps.append(gap_unmatched_test)
            critical_obligation_gaps.append(gap_unmatched_test)
            continue
        for name in sorted(matching_tests):
            row = row_by_name[name]
            if not row["eligible"] or not row["features"]:
                gap = {
                    "reason": "protected-test-unmeasured",
                    "pattern": pattern,
                    "nodeid": name,
                }
                gaps.append(gap)
                critical_obligation_gaps.append(gap)
    max_duration = max((float(item["durationSeconds"] or 0.0) for item in candidates), default=0.0)
    max_source_lines = max((int(item["sourceLines"] or 0) for item in candidates), default=0)
    for candidate in candidates:
        runtime_score = (
            float(candidate["durationSeconds"] or 0.0) / max_duration if max_duration else 0.0
        )
        source_score = (
            int(candidate["sourceLines"] or 0) / max_source_lines if max_source_lines else 0.0
        )
        candidate["reviewScore"] = round(
            0.6 * float(candidate["overlapRatio"]) + 0.3 * runtime_score + 0.1 * source_score,
            4,
        )
    groups = [
        {"signature": signature, "nodeids": members}
        for signature, members in sorted(signatures.items())
        if len(members) > 1
    ]
    eligible = [row for row in row_by_name.values() if row["eligible"]]
    protected_rows = [row for row in eligible if row["critical"]]
    ordinary_features: set[tuple[Any, ...]] = set()
    ordinary_lines: set[tuple[Any, ...]] = set()
    critical_observed_features: set[tuple[Any, ...]] = set()
    for row in eligible:
        for feature in row["features"]:
            if matches_any(str(feature[0]), critical_sources):
                critical_observed_features.add(feature)
            else:
                ordinary_features.add(feature)
                if feature[1] == "line":
                    ordinary_lines.add(feature)
    ordinary_statement_total = statement_coverage["ordinary"].get("statements", 0)
    ordinary_statement_observed = min(
        len({feature[0:3] for feature in ordinary_lines}),
        statement_coverage["ordinary"].get("covered", 0),
    )
    # The target is a floor for retained ordinary evidence, not a reason to
    # add tests or pretend that a narrow cohort covers the whole product.
    target_ordinary_statements = min(
        ordinary_statement_observed,
        int((ordinary_statement_total * soft_target + 99.9999) // 100)
        if ordinary_statement_total
        else ordinary_statement_observed,
    )
    selected_names: list[str] = []
    selected_features: set[tuple[Any, ...]] = set()
    selected_ordinary_lines: set[tuple[Any, ...]] = set()
    for row in protected_rows:
        selected_names.append(row["name"])
        selected_features.update(row["features"])
        selected_ordinary_lines.update(
            feature for feature in row["features"] if feature in ordinary_lines
        )
    remaining = [row for row in eligible if row["name"] not in selected_names]
    selection_iterations = 0
    while (
        len(selected_ordinary_lines) < target_ordinary_statements
        and remaining
        and selection_iterations < GREEDY_SELECTION_BUDGET
    ):
        selection_iterations += 1
        remaining_with_new_lines = [
            row
            for row in remaining
            if any(
                feature in ordinary_lines and feature not in selected_ordinary_lines
                for feature in row["features"]
            )
        ]
        if not remaining_with_new_lines:
            break
        best = max(
            remaining_with_new_lines,
            key=lambda row: (
                (
                    len(
                        {
                            feature
                            for feature in row["features"]
                            if feature in ordinary_lines and feature not in selected_ordinary_lines
                        }
                    )
                    + 0.25
                    * len(
                        {
                            feature
                            for feature in row["features"]
                            if feature in ordinary_features
                            and feature not in selected_features
                            and feature[1] == "arc"
                        }
                    )
                )
                / max(float(row.get("durationSeconds") or 0.0), 0.001),
                row["name"],
            ),
        )
        new_lines = {
            feature
            for feature in best["features"]
            if feature in ordinary_lines and feature not in selected_ordinary_lines
        }
        selected_names.append(best["name"])
        selected_features.update(best["features"])
        selected_ordinary_lines.update(new_lines)
        remaining.remove(best)
    selected_set = set(selected_names)
    target_met = len(selected_ordinary_lines) >= target_ordinary_statements
    selection_truncated = bool(
        not target_met and remaining and selection_iterations >= GREEDY_SELECTION_BUDGET
    )
    representative_complete = (
        target_met and not selection_truncated and not critical_obligation_gaps
    )
    if selection_truncated:
        gaps.append(
            {
                "reason": "representative-selection-budget-exhausted",
                "budget": GREEDY_SELECTION_BUDGET,
                "targetOrdinaryStatements": target_ordinary_statements,
                "retainedOrdinaryStatements": len(selected_ordinary_lines),
            }
        )
    elif not target_met:
        gaps.append(
            {
                "reason": "representative-selection-target-unreachable",
                "targetOrdinaryStatements": target_ordinary_statements,
                "retainedOrdinaryStatements": len(selected_ordinary_lines),
            }
        )
    for candidate in candidates:
        candidate["representative"] = candidate["nodeid"] in selected_set
        candidate["protected"] = False
    selected_rows = {row["name"]: row for row in eligible if row["name"] in selected_set}
    proposed_removals = []
    for row in eligible:
        if not representative_complete or row["name"] in selected_set or row["critical"]:
            continue
        all_witnesses = [
            selected_name
            for selected_name in selected_names
            if row["features"] & selected_rows[selected_name]["features"]
        ]
        witnesses = all_witnesses[:8]
        removal: dict[str, Any] = {
            "nodeid": row["name"],
            "recommendation": "investigate",
            "replacementProtection": witnesses,
            "reason": (
                "Outside the bounded representative set; validate assertions "
                "and effects before removal."
            ),
        }
        if len(all_witnesses) > len(witnesses):
            removal["replacementProtectionAdditionalCount"] = len(all_witnesses) - len(witnesses)
        if not witnesses:
            removal["replacementProtectionGap"] = (
                "No selected test shares a measured call feature; targeted "
                "fault-injection evidence is required before removal."
            )
        proposed_removals.append(removal)
    retained_ordinary_percent = (
        100 * len(selected_ordinary_lines) / ordinary_statement_total
        if ordinary_statement_total
        else None
    )
    ordinary_percent = statement_coverage["ordinary"].get("percent")
    ordinary_coverage_at_soft_target = (
        None if ordinary_percent is None else ordinary_percent >= soft_target
    )
    retained_observed_percent = (
        100 * len(selected_ordinary_lines) / len(ordinary_lines) if ordinary_lines else None
    )
    representative = {
        "tests": selected_names,
        "selectionBudget": GREEDY_SELECTION_BUDGET,
        "selectionIterations": selection_iterations,
        "targetMetWithinObserved": target_met,
        "ordinaryCoverageAtOrAboveSoftTarget": ordinary_coverage_at_soft_target,
        "selectionTruncated": selection_truncated,
        "representativeComplete": representative_complete,
        "protectedTests": [row["name"] for row in protected_rows],
        "proposedRemovals": proposed_removals,
        "softTargetPercent": soft_target,
        "ordinaryExecutableStatements": ordinary_statement_total,
        "ordinaryObservedStatements": ordinary_statement_observed,
        "targetRetainedOrdinaryStatements": target_ordinary_statements,
        "retainedOrdinaryStatements": len(selected_ordinary_lines),
        "retainedOrdinaryPercentOfExecutable": round(retained_ordinary_percent, 2)
        if retained_ordinary_percent is not None
        else None,
        "retainedObservedFeaturePercent": round(retained_observed_percent, 2)
        if retained_observed_percent is not None
        else None,
        "criticalObservedFeatures": len(critical_observed_features),
        "criticalFeaturesRetained": len(critical_observed_features & selected_features),
        "criticalCoveragePreserved": (
            not critical_obligation_gaps and critical_observed_features <= selected_features
        ),
        "criticalCoverageStatus": (
            "unmeasured"
            if critical_obligation_gaps
            else "preserved"
            if critical_sources or protected_tests
            else "no-policy"
        ),
        "note": (
            "Observed-footprint retention is not whole-product code coverage; "
            "this is advisory and never deletes tests."
        ),
    }
    candidates.sort(
        key=lambda row: (
            -row["reviewScore"],
            -(row["durationSeconds"] or 0),
            row["nodeid"],
        )
    )
    document = {
        "schema": SCHEMA,
        "root": str(root),
        "currentSource": git_identity(root),
        "collection": run,
        "sources": [str(p) for p in scope],
        "sourceHashes": files,
        "toolVersions": versions(),
        "branchData": has_arcs,
        "policy": {
            "softTargetPercent": soft_target,
            "criticalSources": critical_sources,
            "protectedTests": protected_tests,
        },
        "executableStatementCoverage": statement_coverage,
        "representativeSet": representative,
        "healthyCollection": healthy,
        "tests": rows,
        "identicalFootprints": groups,
        "rankedCandidates": candidates,
        "unassignedFeatureCount": len(unassigned),
        "gaps": gaps,
        "warnings": warnings,
        "artifacts": [
            {"path": str(p), "hash": digest(p)}
            for p in [coverage_file, observations, *junit]
            if p and p.is_file()
        ],
    }
    write_json(output / "report.json", document)
    markdown(output / "report.md", document)
    return document


def markdown(path: Path, document: dict[str, Any]) -> None:
    def label(value: Any) -> str:
        return str(value).replace("`", "\\`").replace("\n", " ")

    rows = document["tests"]
    lines = [
        "# Test-value audit",
        "",
        f"Repository: `{label(document['root'])}`",
        "",
        (
            f"{len(rows)} test identities; "
            f"{len(document['identicalFootprints'])} identical call-coverage groups; "
            f"{len(document['rankedCandidates'])} ranked review candidates."
        ),
        "",
        (
            "Advisory representative set: "
            f"{len(document['representativeSet']['tests'])} tests; "
            f"{len(document['representativeSet']['proposedRemovals'])} removal leads; "
            f"ordinary executable retention "
            f"{document['representativeSet']['retainedOrdinaryPercentOfExecutable']}% "
            f"(soft target {document['representativeSet']['softTargetPercent']}%)."
        ),
        "",
        (
            "Ranked items are investigation leads. Preserve distinct assertions, security inputs, "
            "and real effects. Evaluate one removal at a time; "
            "overlapping candidates can protect each other."
        ),
        "",
        "## Ranked review candidates",
        "",
    ]
    for item in document["rankedCandidates"]:
        duration = item["durationSeconds"]
        cost = f"{duration:.3f}s" if duration is not None else "time unknown"
        lines.append(f"- `{label(item['nodeid'])}` ({cost}): {item['reason']}")
        lines.append(
            "  Sample overlap: " + ", ".join(f"`{label(n)}`" for n in item["overlappingTests"])
        )
    if not document["rankedCandidates"]:
        lines.append("No candidates qualified for ranking in this measured scope.")
    lines.extend(["", "## Advisory representative set", ""])
    representative = document["representativeSet"]
    lines.append(
        f"- Retain {len(representative['tests'])} measured tests; "
        f"critical features preserved: {representative['criticalCoveragePreserved']}."
    )
    lines.append(
        f"- Ordinary executable statements retained: "
        f"{representative['retainedOrdinaryStatements']}/"
        f"{representative['ordinaryExecutableStatements']} "
        f"({representative['retainedOrdinaryPercentOfExecutable']}%); "
        f"observed-footprint retention: {representative['retainedObservedFeaturePercent']}%."
    )
    lines.append("- Proposed removals are review leads only; no source files are changed.")
    lines.extend(["", "## Identical coverage footprints", ""])
    for group in document["identicalFootprints"]:
        members = group["nodeids"]
        shown = ", ".join(f"`{label(name)}`" for name in members[:5])
        suffix = f" (+{len(members) - 5} more in JSON)" if len(members) > 5 else ""
        lines.append(f"- {shown}{suffix}")
    if not document["identicalFootprints"]:
        lines.append("No identical nonempty call footprints in this measured scope.")
    lines.extend(["", "## Evidence limits", ""])
    lines.extend(f"- {warning}" for warning in document["warnings"])
    lines.extend(f"- `{label(json.dumps(gap, sort_keys=True))}`" for gap in document["gaps"])
    lines.extend(
        [
            "",
            (
                "See report.json for per-test source coverage, unique features, phase timings, "
                "identical footprints, source hashes and artifact provenance."
            ),
            "",
        ]
    )
    path.write_text("\n".join(lines))


# The explicit collector can be launched by an assessed project's interpreter.
# Bootstrap only this tool's package; project execution starts at pytest below.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main(arguments: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if arguments[:1] == ["_pytest"]:
        return child(Path(arguments[1]), Path(arguments[2]), arguments[3:])
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("collect", "report"):
        command = sub.add_parser(name)
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True, help="new artifact directory")
        command.add_argument(
            "--source",
            action="append",
            default=[],
            required=name == "collect",
            help="product directory for collect, file/directory for report; repeatable",
        )
        command.add_argument(
            "--soft-target",
            type=float,
            default=DEFAULT_SOFT_TARGET if name == "collect" else None,
            help="advisory ordinary executable-statement retention target (percent; default 70)",
        )
        command.add_argument(
            "--critical",
            action="append",
            default=[] if name == "collect" else None,
            help="repository-relative source glob whose call coverage is protected; repeatable",
        )
        command.add_argument(
            "--protect-test",
            action="append",
            default=[] if name == "collect" else None,
            help="node-id glob to retain as an explicit critical test; repeatable",
        )
        if name == "collect":
            command.add_argument(
                "--python", help="existing assessed-project Python interpreter (no installation)"
            )
            command.add_argument(
                "--batch-size", type=int, help="split explicit pytest targets into resumable shards"
            )
            command.add_argument(
                "--resume",
                action="store_true",
                help="resume a prior --batch-size collection after validating its manifest",
            )
            command.add_argument("targets", nargs=argparse.REMAINDER)
        else:
            command.add_argument("--coverage", type=Path, required=True)
            command.add_argument(
                "--detail", action="store_true", help="include expanded per-test coverage maps"
            )
            evidence = command.add_mutually_exclusive_group()
            evidence.add_argument("--tests", type=Path)
            evidence.add_argument("--junit", type=Path, action="append", default=[])
    compare = sub.add_parser("compare", help="compare normalized non-pytest evidence")
    compare.add_argument("--root", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True, help="new comparison directory")
    compare.add_argument("--evidence", type=Path, action="append", required=True)
    compare.add_argument("--pytest-report", type=Path)
    compare.add_argument("--pytest-coverage", type=Path)
    inventory = sub.add_parser(
        "inventory", help="index bounded static test-value leads without executing the project"
    )
    inventory.add_argument("--root", type=Path, required=True)
    inventory.add_argument(
        "--output", type=Path, required=True, help="JSON file or output directory"
    )
    inventory.add_argument(
        "--scope",
        action="append",
        required=True,
        help="repository-relative source file or directory; repeatable",
    )
    args = parser.parse_args(arguments)
    try:
        if not args.root.is_dir():
            raise ValueError("--root must be an existing repository directory")
        if args.command == "inventory":
            from project_assess.test_value.static import analyze, write_report

            document = analyze(args.root.resolve(), args.scope)
            output = write_report(document, args.output, args.root.resolve())
            print(f"{document['counts']['candidates']} static review leads; {output}")
            return 0
        if args.command == "collect":
            if args.python:
                executable = Path(shutil.which(args.python) or args.python).expanduser().absolute()
                if not executable.is_file() or not os.access(executable, os.X_OK):
                    raise ValueError("--python must name an existing executable interpreter")
                if executable != Path(sys.executable).absolute():
                    probe = json.loads(
                        subprocess.check_output(
                            [
                                str(executable),
                                "-c",
                                "import json,sys;print(json.dumps({'version':list(sys.version_info[:2]),"
                                "'prefix':sys.prefix,'venv':sys.prefix!=sys.base_prefix}))",
                            ],
                            text=True,
                        )
                    )
                    if tuple(probe["version"]) < (3, 11):
                        raise ValueError("--python requires Python 3.11 or newer")
                    forwarded = list(arguments)
                    for index, value in enumerate(forwarded):
                        if value == "--python":
                            del forwarded[index : index + 2]
                            break
                        if value.startswith("--python="):
                            del forwarded[index]
                            break
                    environment = os.environ.copy()
                    environment["PATH"] = (
                        str(executable.parent) + os.pathsep + environment.get("PATH", "")
                    )
                    if probe["venv"]:
                        environment["VIRTUAL_ENV"] = probe["prefix"]
                    else:
                        environment.pop("VIRTUAL_ENV", None)
                    return subprocess.call(
                        [str(executable), str(Path(__file__).resolve()), *forwarded],
                        env=environment,
                    )
            return collect(args)
        if args.command == "compare":
            from project_assess.test_value.evidence import compare_evidence

            document = compare_evidence(
                args.root.resolve(),
                [path.resolve() for path in args.evidence],
                args.output.resolve(),
                pytest_report=args.pytest_report.resolve() if args.pytest_report else None,
                pytest_coverage=args.pytest_coverage.resolve() if args.pytest_coverage else None,
            )
            print(
                f"{len(document['crossLayerOverlap'])} overlap groups; {args.output / 'report.md'}"
            )
            return 0
        args.output.mkdir(parents=True, exist_ok=False)
        document = report(
            args.root.resolve(),
            args.coverage.resolve(),
            args.tests,
            args.junit or [],
            args.output.resolve(),
            sources(args.root.resolve(), args.source, allow_files=True),
            soft_target=args.soft_target,
            critical_sources=args.critical,
            protected_tests=args.protect_test,
            detail=args.detail,
        )
        print(f"{len(document['rankedCandidates'])} review candidates; {args.output / 'report.md'}")
        return 0
    except (OSError, ValueError, TypeError, ImportError, ET.ParseError) as error:
        print(f"test-value audit: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
