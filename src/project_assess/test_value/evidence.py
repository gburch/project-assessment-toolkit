"""Portable import and overlap analysis for non-pytest coverage artifacts."""

from __future__ import annotations

import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

EVIDENCE_SCHEMA = "test-value-evidence.v1"
COMPARE_SCHEMA = "test-value-evidence-compare.v1"


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def _source_path(root: Path, value: str) -> str | None:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return None


def _changed_inputs(root: Path, hashes: Any, reason: str) -> list[dict[str, Any]]:
    if not isinstance(hashes, dict):
        return []
    changed = []
    for value, expected in hashes.items():
        relative = _source_path(root, str(value))
        path = root / relative if relative is not None else None
        if path is None or not path.is_file() or _digest(path) != expected:
            changed.append(str(value))
    return [{"reason": reason, "paths": sorted(changed)}] if changed else []


def _hash_for(root: Path, path: str, provided: dict[str, Any]) -> tuple[str | None, bool]:
    expected = provided.get(path)
    actual_path = root / path
    actual = _digest(actual_path) if actual_path.is_file() else None
    if expected is None:
        return actual, False
    return str(expected), actual == expected


def _feature(source: str, kind: str, coordinate: Any, semantics: str) -> dict[str, Any]:
    return {
        "source": source,
        "kind": kind,
        "coordinate": coordinate,
        "coordinateSemantics": semantics,
    }


def _feature_key(
    item: dict[str, Any], source_records: dict[str, dict[str, Any]]
) -> tuple[Any, ...] | None:
    source = source_records.get(str(item.get("source")))
    if not source or not source.get("comparable"):
        return None
    kind = str(item.get("kind"))
    if kind == "line":
        return (source["path"], source["hash"], "line", int(item["coordinate"]))
    return (
        source["path"],
        source["hash"],
        kind,
        str(item.get("coordinateSemantics", "")),
        json.dumps(item.get("coordinate"), sort_keys=True, separators=(",", ":")),
    )


def _new_document(path: Path, root: Path, raw_hash: str, raw: dict[str, Any]) -> dict[str, Any]:
    invocation = raw.get("invocation", {}) if isinstance(raw.get("invocation"), dict) else {}
    return {
        "path": str(path),
        "artifactHash": raw_hash,
        "format": str(raw.get("format", "unknown")),
        "layer": raw.get("layer"),
        "framework": raw.get("framework"),
        "provider": raw.get("provider"),
        "invocation": invocation,
        "sources": {},
        "tests": [],
        "unassigned": [],
        "gaps": [],
        "provenance": raw.get("provenance", {}),
        "behaviorRefs": raw.get("behaviorRefs", []),
        "root": str(root),
    }


def _parse_collector_evidence(
    path: Path, root: Path, raw: dict[str, Any], raw_hash: str
) -> dict[str, Any]:
    runner = raw.get("runner", {})
    ecosystem = str(runner.get("ecosystem", "unknown"))
    provider = runner.get("provider") or ("v8" if ecosystem == "vitest" else "node-v8")
    exit_code = raw.get("provenance", {}).get("exitCode", 2)
    provenance = raw.get("provenance", {})
    raw_invocation = raw.get("invocation", {}) if isinstance(raw.get("invocation"), dict) else {}
    wrapper = {
        "format": "collector",
        "layer": raw.get("layer") or runner.get("layer") or ecosystem,
        "framework": ecosystem,
        "provider": provider,
        "invocation": {
            **raw_invocation,
            "isolated": raw_invocation.get("isolated", False),
            "outcome": raw_invocation.get("outcome", "passed" if exit_code == 0 else "failed"),
        },
        "provenance": provenance,
        "behaviorRefs": raw.get("behaviorRefs", []),
    }
    document = _new_document(path, root, raw_hash, wrapper)
    document["observedTestCount"] = len(raw.get("tests", []))
    if exit_code != 0:
        document["gaps"].append({"reason": "runner-failed", "exitCode": exit_code})
    document["gaps"].extend(raw.get("gaps", []))
    source_hashes = raw.get("project", {}).get("sourceHashes", {})
    document["gaps"].extend(
        _changed_inputs(
            root, raw.get("project", {}).get("testHashes"), "test-sources-changed-since-collection"
        )
    )
    document["gaps"].extend(
        _changed_inputs(
            root, provenance.get("configHashesAfter"), "config-changed-since-collection"
        )
    )
    for label in ("source", "test", "config"):
        before = provenance.get(f"{label}HashesBefore")
        after = provenance.get(f"{label}HashesAfter")
        if provenance.get(f"{label}Stable") is False:
            document["gaps"].append({"reason": f"{label}-changed-during-collection"})
        if before is not None and after is not None and before != after:
            reason = (
                "source-changed-during-collection"
                if label == "source"
                else "config-changed-during-collection"
                if label == "config"
                else f"{label}-sources-changed-during-collection"
            )
            document["gaps"].append({"reason": reason})
        if label == "source" and after is not None and after != source_hashes:
            document["gaps"].append({"reason": "source-stale-or-hash-mismatch"})
    for artifact in provenance.get("artifacts", []):
        if not isinstance(artifact, dict) or not artifact.get("path"):
            continue
        artifact_path = path.parent / str(artifact["path"])
        if not artifact_path.is_file() or (
            artifact.get("hash") and _digest(artifact_path) != artifact["hash"]
        ):
            document["gaps"].append(
                {"reason": "raw-artifact-hash-mismatch", "path": artifact["path"]}
            )

    def add_feature(feature: dict[str, Any], target: list[dict[str, Any]] | None = None) -> None:
        identity = feature.get("source", {})
        relative = _source_path(root, str(identity.get("relativePath", "")))
        if relative is None:
            document["gaps"].append({"reason": "source-identity-missing"})
            return
        record = _finish_source(
            document,
            root,
            relative,
            identity.get("sourceHash") or source_hashes.get(relative),
            generated=bool(identity.get("generated")),
        )
        kind = feature.get("kind")
        location = feature.get("location", {})
        if kind in {"statement", "function", "line"} and location.get("line") is not None:
            record["lines"].add(int(location["line"]))
            if target is not None:
                target.append(_feature(relative, "line", location["line"], "original-line"))
        elif kind == "branch":
            provided_branch = location.get("branch")
            if isinstance(provided_branch, (list, tuple)) and provided_branch:
                branch = tuple(provided_branch)
            else:
                branch = (
                    "istanbul-branch",
                    location.get("branchId"),
                    location.get("line"),
                    location.get("column"),
                )
            record["branches"].add(branch)
            if target is not None:
                target.append(_feature(relative, "branch", branch[1:], str(branch[0])))
        elif kind == "v8-range":
            branch = ("v8-range", location.get("startOffset"), location.get("endOffset"))
            record["branches"].add(branch)
            if target is not None:
                target.append(_feature(relative, "branch", branch[1:], "v8-range"))

    for feature in raw.get("coverageFeatures", []):
        add_feature(feature)

    def identity_text(value: Any) -> str:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":"))
            if isinstance(value, dict)
            else str(value)
        )

    selected = {identity_text(value) for value in document["invocation"].get("selectedTests", [])}
    selected_tests: list[dict[str, Any]] = []
    unselected_skips = 0
    selected_skips = 0
    for raw_test in raw.get("tests", []):
        test_id = raw_test.get("nodeid") or raw_test.get("id")
        if not test_id:
            document["gaps"].append({"reason": "test-identity-missing"})
            continue
        test_id = identity_text(test_id)
        if raw_test.get("outcome") in {"skipped", "pending"}:
            if selected and str(test_id) not in selected:
                unselected_skips += 1
            else:
                selected_skips += 1
        if selected and str(test_id) not in selected:
            continue
        features: list[dict[str, Any]] = []
        for feature in raw_test.get("coverageFeatures", raw_test.get("features", [])):
            add_feature(feature, features)
        selected_tests.append(
            {
                "id": str(test_id),
                "outcome": raw_test.get("outcome", "unknown"),
                "durationSeconds": raw_test.get("durationSeconds")
                or raw_test.get("phases", {}).get("call", {}).get("durationSeconds"),
                "features": features,
                "behaviorRefs": raw_test.get("behaviorRefs", []),
            }
        )
    document["tests"] = selected_tests
    document["observedTestCount"] = len(raw.get("tests", []))
    if unselected_skips:
        document["gaps"].append({"reason": "skipped-tests-unselected", "count": unselected_skips})
    if selected_skips:
        document["gaps"].append({"reason": "skipped-tests-unattributed", "count": selected_skips})
    selected_ids = [test["id"] for test in selected_tests]
    bound = (
        bool(selected_tests)
        and bool(selected)
        and len(selected_ids) == len(set(selected_ids))
        and set(selected_ids) == selected
        and all(test["outcome"] == "passed" for test in selected_tests)
        and document["invocation"].get("isolated") is True
    )
    if len(selected_ids) != len(set(selected_ids)):
        document["gaps"].append({"reason": "duplicate-executed-test-identities"})
    if not bound:
        document["gaps"].append(
            {"reason": "aggregate-coverage-not-per-test", "attribution": "suite"}
        )
        document["gaps"].append({"reason": "suite-only-unattributed"})
    return document


def _finish_source(
    document: dict[str, Any], root: Path, path: str, expected_hash: str | None, *, generated=False
) -> dict[str, Any]:
    actual_path = root / path
    actual_hash = _digest(actual_path) if actual_path.is_file() else None
    record = document["sources"].setdefault(
        path,
        {
            "path": path,
            "hash": expected_hash or actual_hash,
            "lines": set(),
            "branches": set(),
            "generated": generated,
            "comparable": bool(expected_hash and actual_hash == expected_hash),
        },
    )
    if not actual_path.is_file():
        document["gaps"].append({"reason": "source-missing", "path": path})
        record["comparable"] = False
    if expected_hash is None:
        document["gaps"].append({"reason": "source-hash-missing", "path": path})
        record["comparable"] = False
    elif actual_hash != expected_hash:
        document["gaps"].append(
            {"reason": "source-stale-or-hash-mismatch", "path": path, "expected": expected_hash}
        )
        record["comparable"] = False
    if generated:
        document["gaps"].append({"reason": "generated-or-unmapped-source", "path": path})
        record["comparable"] = False
    return record


def _binding(document: dict[str, Any], tests: list[dict[str, Any]]) -> bool:
    invocation = document["invocation"]
    if not tests:
        document["gaps"].append({"reason": "suite-only-unattributed"})
        return False
    if (
        invocation.get("isolated") is not True
        or invocation.get("outcome", "passed") != "passed"
        or not invocation.get("selectedTests")
    ):
        document["gaps"].append({"reason": "test-identity-unbound-or-nonisolated"})
        return False
    selected = {str(value) for value in invocation["selectedTests"]}
    actual = {str(test.get("id")) for test in tests}
    if actual != selected:
        document["gaps"].append({"reason": "test-identity-outside-selected-invocation"})
        return False
    if any(test.get("outcome") != "passed" for test in tests):
        document["gaps"].append({"reason": "test-outcome-not-passed"})
        return False
    return True


def _parse_test_list(document: dict[str, Any], raw_tests: Any) -> None:
    if not isinstance(raw_tests, list):
        return
    tests: list[dict[str, Any]] = []
    for raw in raw_tests:
        if not isinstance(raw, dict) or not raw.get("id"):
            document["gaps"].append({"reason": "test-identity-missing"})
            continue
        features = raw.get("features", [])
        if not isinstance(features, list):
            features = []
        tests.append(
            {
                "id": str(raw["id"]),
                "outcome": raw.get("outcome", document["invocation"].get("outcome", "unknown")),
                "durationSeconds": raw.get("durationSeconds"),
                "features": features,
                "behaviorRefs": raw.get("behaviorRefs", []),
            }
        )
    document["tests"] = tests


def _parse_normalized(path: Path, root: Path, raw: dict[str, Any], raw_hash: str) -> dict[str, Any]:
    if "project" in raw and "runner" in raw and "coverageFeatures" in raw:
        return _parse_collector_evidence(path, root, raw, raw_hash)
    document = _new_document(path, root, raw_hash, raw)
    if raw.get("schema") != EVIDENCE_SCHEMA:
        document["gaps"].append({"reason": "unsupported-evidence-schema"})
        return document
    if not all(document.get(name) for name in ("layer", "framework", "provider")):
        document["gaps"].append({"reason": "provenance-layer-framework-provider-missing"})
    if document["invocation"].get("outcome", "passed") != "passed":
        document["gaps"].append(
            {"reason": "invocation-failed", "outcome": document["invocation"].get("outcome")}
        )
    source_hashes = raw.get("sourceHashes", {})
    for source in raw.get("sources", []):
        if not isinstance(source, dict) or not source.get("path"):
            document["gaps"].append({"reason": "source-identity-missing"})
            continue
        relative = _source_path(root, str(source["path"]))
        if relative is None:
            document["gaps"].append({"reason": "source-outside-root", "path": source["path"]})
            continue
        record = _finish_source(
            document,
            root,
            relative,
            source.get("hash") or source_hashes.get(relative),
            generated=bool(source.get("generated")),
        )
        for line in source.get("lines", []):
            record["lines"].add(int(line))
        for branch in source.get("branches", []):
            record["branches"].add(
                (
                    source.get("branchSemantics", "normalized-branch"),
                    json.dumps(branch, sort_keys=True),
                )
            )
    _parse_test_list(document, raw.get("tests"))
    bound = _binding(document, document["tests"])
    if bound:
        for test in document["tests"]:
            test["features"] = [
                feature
                for feature in test["features"]
                if _feature_key(feature, document["sources"])
            ]
    else:
        for source in document["sources"].values():
            document["unassigned"].extend(
                [
                    _feature(source["path"], "line", line, "normalized-line")
                    for line in source["lines"]
                ]
            )
    return document


def _parse_istanbul(path: Path, root: Path, raw: dict[str, Any], raw_hash: str) -> dict[str, Any]:
    wrapper = raw
    coverage = raw.get("coverage", raw)
    document = _new_document(path, root, raw_hash, wrapper)
    document["format"] = "istanbul"
    if not all(document.get(name) for name in ("layer", "framework", "provider")):
        document["gaps"].append({"reason": "provenance-layer-framework-provider-missing"})
    if document["invocation"].get("outcome", "passed") != "passed":
        document["gaps"].append(
            {"reason": "invocation-failed", "outcome": document["invocation"].get("outcome")}
        )
    source_hashes = (
        wrapper.get("sourceHashes", {}) if isinstance(wrapper.get("sourceHashes"), dict) else {}
    )
    if not isinstance(coverage, dict):
        document["gaps"].append({"reason": "istanbul-coverage-invalid"})
        return document
    for raw_path, entry in coverage.items():
        if not isinstance(entry, dict):
            continue
        value = entry.get("path", raw_path)
        relative = _source_path(root, str(value))
        if relative is None:
            document["gaps"].append({"reason": "source-outside-root", "path": value})
            continue
        source_map = entry.get("inputSourceMap") or entry.get("sourceMap")
        line_map = entry.get("lineMap", {})
        generated = bool(entry.get("generated"))
        if (
            Path(relative).suffix.lower() in {".js", ".mjs", ".cjs"}
            and wrapper.get("coordinateDomain") != "original-source"
        ):
            generated = True
        if source_map is not None:
            if (
                not isinstance(source_map, dict)
                or source_map.get("version") != 3
                or not isinstance(source_map.get("sources"), list)
                or not isinstance(source_map.get("mappings"), str)
            ):
                document["gaps"].append({"reason": "source-map-invalid", "path": relative})
                generated = True
            elif source_map.get("sources"):
                mapped = _source_path(root, str(source_map["sources"][0]))
                if mapped is not None and isinstance(line_map, dict):
                    relative = mapped
                else:
                    document["gaps"].append(
                        {"reason": "source-map-line-mapping-unavailable", "path": relative}
                    )
                    generated = True
        record = _finish_source(
            document,
            root,
            relative,
            source_hashes.get(relative) or entry.get("hash"),
            generated=generated,
        )
        statement_map = entry.get("statementMap", {})
        for key, count in entry.get("s", {}).items():
            if count and isinstance(statement_map.get(key), dict):
                line = statement_map[key].get("start", {}).get("line")
                if line is not None:
                    record["lines"].add(int(line_map.get(str(line), line)))
        branch_map = entry.get("branchMap", {})
        for key, counts in entry.get("b", {}).items():
            for index, count in enumerate(counts if isinstance(counts, list) else []):
                if count:
                    location = branch_map.get(key, {}).get("locations", [])
                    record["branches"].add(
                        (
                            "istanbul-branch",
                            key,
                            index,
                            json.dumps(
                                location[index] if index < len(location) else {}, sort_keys=True
                            ),
                        )
                    )
    _parse_test_list(document, wrapper.get("tests"))
    if document["tests"] and _binding(document, document["tests"]):
        for test in document["tests"]:
            test["features"] = [
                feature
                for feature in test["features"]
                if _feature_key(feature, document["sources"])
            ]
    else:
        if not document["tests"]:
            document["gaps"].append({"reason": "suite-only-unattributed"})
        for source in document["sources"].values():
            document["unassigned"].extend(
                [
                    _feature(source["path"], "line", line, "istanbul-line")
                    for line in source["lines"]
                ]
            )
    return document


def _parse_lcov(path: Path, root: Path, text: str, raw_hash: str) -> dict[str, Any]:
    document = _new_document(path, root, raw_hash, {"format": "lcov"})
    document["format"] = "lcov"
    current: dict[str, Any] | None = None
    source_hashes: dict[str, Any] = {}
    for line in text.splitlines():
        if line.startswith("SF:"):
            value = _source_path(root, line[3:])
            current = None
            if value is not None:
                current = _finish_source(document, root, value, source_hashes.get(value))
        elif current is not None and line.startswith("DA:"):
            parts = line[3:].split(",")
            if len(parts) >= 2 and int(parts[1]) > 0:
                current["lines"].add(int(parts[0]))
        elif current is not None and line.startswith("BRDA:"):
            parts = line[5:].split(",")
            if len(parts) >= 4 and parts[3] not in ("-", "0"):
                current["branches"].add(("lcov-branch", parts[0], parts[1], parts[2]))
    document["gaps"].append({"reason": "suite-only-unattributed"})
    document["gaps"].append({"reason": "provenance-layer-framework-provider-missing"})
    return document


def _parse_cobertura(path: Path, root: Path, text: str, raw_hash: str) -> dict[str, Any]:
    document = _new_document(path, root, raw_hash, {"format": "cobertura"})
    document["format"] = "cobertura"
    try:
        tree = ET.fromstring(text)
    except ET.ParseError:
        document["gaps"].append({"reason": "cobertura-invalid-xml"})
        return document
    for line in tree.findall(".//class/lines/line"):
        filename = line.get("filename")
        number = line.get("number")
        if not filename or not number:
            continue
        relative = _source_path(root, filename)
        if relative is None:
            document["gaps"].append({"reason": "source-outside-root", "path": filename})
            continue
        record = _finish_source(document, root, relative, None)
        if int(line.get("hits", "0")) > 0:
            record["lines"].add(int(number))
        if line.get("branch") == "true":
            record["branches"].add(("cobertura-branch", number))
    document["gaps"].extend(
        [
            {"reason": "suite-only-unattributed"},
            {"reason": "provenance-layer-framework-provider-missing"},
        ]
    )
    return document


def _parse_junit(path: Path, root: Path, text: str, raw_hash: str) -> dict[str, Any]:
    document = _new_document(path, root, raw_hash, {"format": "junit"})
    try:
        tree = ET.fromstring(text)
    except ET.ParseError:
        document["gaps"].append({"reason": "junit-invalid-xml"})
        return document
    outcomes = {"passed": 0, "failed": 0, "skipped": 0}
    for case in tree.iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            outcomes["failed"] += 1
        elif case.find("skipped") is not None:
            outcomes["skipped"] += 1
        else:
            outcomes["passed"] += 1
    document["observedTestCount"] = sum(outcomes.values())
    document["outcomeSummary"] = outcomes
    document["gaps"].extend(
        [
            {"reason": "suite-only-unattributed"},
            {"reason": "provenance-layer-framework-provider-missing"},
        ]
    )
    return document


def load_evidence(path: Path, root: Path) -> dict[str, Any]:
    raw_hash = _digest(path)
    suffix = path.suffix.lower()
    if suffix in {".xml", ".cobertura"}:
        text = path.read_text()
        try:
            tag = ET.fromstring(text).tag.rsplit("}", 1)[-1]
        except ET.ParseError:
            tag = ""
        return (
            _parse_junit(path, root, text, raw_hash)
            if tag in {"testsuite", "testsuites"}
            else _parse_cobertura(path, root, text, raw_hash)
        )
    if suffix in {".lcov", ".info", ".dat"}:
        return _parse_lcov(path, root, path.read_text(), raw_hash)
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {
            "path": str(path),
            "artifactHash": raw_hash,
            "format": "unknown",
            "layer": None,
            "framework": None,
            "provider": None,
            "sources": {},
            "tests": [],
            "unassigned": [],
            "gaps": [{"reason": "evidence-invalid-json"}],
        }
    if isinstance(raw, dict) and raw.get("schema") == EVIDENCE_SCHEMA:
        return _parse_normalized(path, root, raw, raw_hash)
    return _parse_istanbul(path, root, raw if isinstance(raw, dict) else {}, raw_hash)


def _pytest_document(path: Path, root: Path, coverage: Path | None) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {
            "path": str(path),
            "format": "pytest-v3",
            "sources": {},
            "tests": [],
            "gaps": [{"reason": "pytest-report-invalid"}],
        }
    document = {
        "path": str(path),
        "artifactHash": _digest(path),
        "format": "pytest-v3",
        "layer": "python",
        "framework": "pytest",
        "provider": "coverage.py",
        "sources": {},
        "tests": [],
        "unassigned": [],
        "gaps": [],
    }
    if raw.get("healthyCollection") is not True:
        document["gaps"].append({"reason": "pytest-report-unhealthy-or-unverified"})
    collection = raw.get("collection")
    if isinstance(collection, dict):
        document["gaps"].extend(
            _changed_inputs(
                root, collection.get("testAfter"), "test-sources-changed-since-collection"
            )
        )
    if (
        not isinstance(collection, dict)
        or collection.get("finished") is not True
        or collection.get("exitcode") != 0
    ):
        document["gaps"].append({"reason": "pytest-collection-provenance-missing-or-failed"})
    hashes = raw.get("sourceHashes", {})
    if (
        isinstance(collection, dict)
        and collection.get("finished") is True
        and collection.get("exitcode") == 0
    ):
        if not isinstance(collection.get("sourceBefore"), dict) or not isinstance(
            collection.get("sourceAfter"), dict
        ):
            document["gaps"].append({"reason": "pytest-source-provenance-missing"})
        elif (
            collection["sourceBefore"] != collection["sourceAfter"]
            or collection["sourceAfter"] != hashes
        ):
            document["gaps"].append({"reason": "pytest-source-provenance-stale-or-mismatched"})
    for source, source_hash in hashes.items():
        relative = _source_path(root, source)
        if relative is not None:
            _finish_source(document, root, relative, source_hash)
    report_rows = {row.get("nodeid"): row for row in raw.get("tests", []) if row.get("nodeid")}
    if len(report_rows) != len([row for row in raw.get("tests", []) if row.get("nodeid")]):
        document["gaps"].append({"reason": "pytest-test-identities-ambiguous"})
    for row in raw.get("tests", []):
        if not row.get("nodeid"):
            document["gaps"].append({"reason": "test-identity-missing"})
            continue
        features: list[dict[str, Any]] = []
        for source, values in (row.get("coverage") or {}).items():
            relative = _source_path(root, source)
            if relative is None:
                continue
            features.extend(
                _feature(relative, "line", line, "coverage.py-line")
                for line in values.get("lines", [])
            )
            features.extend(
                _feature(relative, "branch", arc, "coverage.py-arc")
                for arc in values.get("arcs", [])
            )
        if features:
            document["tests"].append(
                {
                    "id": row.get("nodeid"),
                    "outcome": row.get("outcome"),
                    "durationSeconds": row.get("durationSeconds"),
                    "features": features,
                }
            )
    if (
        not any(test["features"] for test in document["tests"])
        and coverage is not None
        and coverage.is_file()
    ):
        try:
            from coverage import CoverageData

            expected_hash = (
                collection.get("artifactHashes", {}).get(".coverage")
                if isinstance(collection, dict)
                else None
            )
            if expected_hash is None:
                expected_hash = next(
                    (
                        artifact.get("hash")
                        for artifact in raw.get("artifacts", [])
                        if Path(str(artifact.get("path", ""))).name == ".coverage"
                    ),
                    None,
                )
            if expected_hash is None:
                document["gaps"].append({"reason": "pytest-coverage-provenance-missing"})
                raise ValueError("pytest coverage provenance missing")
            if _digest(coverage) != expected_hash:
                document["gaps"].append({"reason": "pytest-coverage-artifact-hash-mismatch"})
                raise ValueError("pytest coverage artifact hash mismatch")
            data = CoverageData(basename=str(coverage))
            data.read()
            context_features: dict[str, set[tuple[Any, ...]]] = defaultdict(set)
            phase_unassigned: dict[str, int] = defaultdict(int)
            context_unassigned = 0
            unrecognized_contexts: set[str] = set()
            for filename in data.measured_files():
                relative = _source_path(root, filename)
                if relative is None or relative not in hashes:
                    continue
                data.set_query_contexts(None)
                lines_by_context: dict[str, set[int]] = defaultdict(set)
                for line, contexts in data.contexts_by_lineno(filename).items():
                    for context in contexts:
                        test_id, separator, phase = context.rpartition("|")
                        if not separator:
                            context_unassigned += 1
                            if context:
                                unrecognized_contexts.add(context)
                            continue
                        if phase not in {"call", "run"}:
                            phase_unassigned[phase] += 1
                            if phase not in {"setup", "teardown"}:
                                unrecognized_contexts.add(context)
                            continue
                        lines_by_context[context].add(line)
                for context, lines in lines_by_context.items():
                    test_id = context.rsplit("|", 1)[0]
                    context_features[test_id].update(
                        (relative, "line", line, "coverage.py-line") for line in lines
                    )
                    data.set_query_context(context)
                    for arc in data.arcs(filename) or []:
                        context_features[test_id].add(
                            (relative, "branch", tuple(arc), "coverage.py-arc")
                        )
            data.set_query_contexts(None)
            if unrecognized_contexts:
                document["gaps"].append(
                    {
                        "reason": "pytest-coverage-contexts-unrecognized",
                        "count": len(unrecognized_contexts),
                        "contexts": sorted(unrecognized_contexts)[:6],
                    }
                )
            if context_unassigned:
                document["gaps"].append(
                    {
                        "reason": "pytest-coverage-context-phase-unassigned",
                        "count": context_unassigned,
                    }
                )
            if phase_unassigned:
                document["gaps"].append(
                    {
                        "reason": "pytest-coverage-non-call-contexts-unassigned",
                        "phases": dict(phase_unassigned),
                    }
                )
            for test_id, feature_keys in context_features.items():
                row = report_rows.get(test_id)
                if row is None:
                    document["gaps"].append(
                        {"reason": "pytest-coverage-context-identity-missing", "testId": test_id}
                    )
                    continue
                document["tests"].append(
                    {
                        "id": test_id,
                        "outcome": row.get("outcome", "unknown"),
                        "durationSeconds": row.get("durationSeconds"),
                        "features": [
                            _feature(source, kind, coordinate, semantics)
                            for source, kind, coordinate, semantics in sorted(feature_keys)
                        ],
                    }
                )
        except (OSError, ValueError):
            document["gaps"].append({"reason": "pytest-coverage-contexts-unreadable"})
    if not any(test["features"] for test in document["tests"]):
        document["gaps"].append({"reason": "pytest-report-detail-or-contexts-missing"})
    if coverage is not None and not coverage.is_file():
        document["gaps"].append({"reason": "pytest-coverage-missing"})
    for test in document["tests"]:
        if test.get("outcome") != "passed":
            document["gaps"].append({"reason": "test-outcome-not-passed", "testId": test["id"]})
            continue
        for feature in test["features"]:
            record = document["sources"].get(feature["source"])
            if record is None:
                continue
            if feature["kind"] == "line":
                record["lines"].add(int(feature["coordinate"]))
            elif feature["kind"] == "branch":
                record["branches"].add(("coverage.py-arc", *feature["coordinate"]))
    return document


def compare_evidence(
    root: Path,
    evidence_paths: list[Path],
    output: Path,
    *,
    pytest_report: Path | None = None,
    pytest_coverage: Path | None = None,
) -> dict[str, Any]:
    documents = [load_evidence(path, root) for path in evidence_paths]
    if pytest_report is not None:
        documents.insert(0, _pytest_document(pytest_report, root, pytest_coverage))
    gaps: list[dict[str, Any]] = []
    feature_index: dict[tuple[Any, ...], set[str]] = defaultdict(set)
    test_rows: list[dict[str, Any]] = []
    signatures: dict[str, list[str]] = defaultdict(list)
    behavior_relationships: dict[str, list[str]] = defaultdict(list)
    invalid_evidence = False
    for document in documents:
        gaps.extend({"artifact": document["path"], **gap} for gap in document.get("gaps", []))
        blocked_for_overlap = any(
            gap.get("reason")
            in {
                "invocation-failed",
                "runner-failed",
                "source-stale-or-hash-mismatch",
                "source-missing",
                "evidence-invalid-json",
                "pytest-report-unhealthy-or-unverified",
                "pytest-test-identities-ambiguous",
                "pytest-collection-provenance-missing-or-failed",
                "pytest-source-provenance-missing",
                "pytest-source-provenance-stale-or-mismatched",
                "duplicate-executed-test-identities",
                "test-identity-missing",
                "test-source-identity-unavailable",
                "test-outcome-not-passed",
                "skipped-tests-unattributed",
                "source-changed-during-collection",
                "test-changed-during-collection",
                "test-sources-changed-during-collection",
                "test-sources-changed-since-collection",
                "config-changed-since-collection",
                "config-changed-during-collection",
                "raw-artifact-hash-mismatch",
                "pytest-coverage-provenance-missing",
                "pytest-coverage-artifact-hash-mismatch",
                "pytest-coverage-context-identity-missing",
                "pytest-coverage-contexts-unrecognized",
            }
            for gap in document.get("gaps", [])
        )
        invalid_evidence = invalid_evidence or blocked_for_overlap
        for source in document["sources"].values():
            for line in source["lines"]:
                key = (source["path"], source.get("hash"), "line", line)
                if source.get("comparable") and not blocked_for_overlap:
                    feature_index[key].add(document["path"])
            for branch in source["branches"]:
                semantics = branch[0]
                key = (
                    source["path"],
                    source.get("hash"),
                    "branch",
                    str(document.get("provider")),
                    semantics,
                    branch[1:],
                )
                if source.get("comparable") and not blocked_for_overlap:
                    feature_index[key].add(document["path"])
        bound = bool(document.get("tests")) and not any(
            gap.get("reason") in {"test-identity-unbound-or-nonisolated", "suite-only-unattributed"}
            for gap in document.get("gaps", [])
        )
        if not bound:
            continue
        for test in document["tests"]:
            keys = sorted(
                key
                for feature in test.get("features", [])
                if (key := _feature_key(feature, document["sources"])) is not None
            )
            signature = (
                "sha256:" + hashlib.sha256(json.dumps(keys, sort_keys=True).encode()).hexdigest()
                if keys
                else None
            )
            if signature:
                signatures[signature].append(f"{document['path']}::{test['id']}")
            test_rows.append(
                {
                    "id": test["id"],
                    "artifact": document["path"],
                    "layer": document.get("layer"),
                    "framework": document.get("framework"),
                    "provider": document.get("provider"),
                    "outcome": test.get("outcome", "unknown"),
                    "durationSeconds": test.get("durationSeconds"),
                    "signature": signature,
                    "featureCount": len(keys),
                    "behaviorRefs": test.get("behaviorRefs", []),
                }
            )
            for behavior_ref in test.get("behaviorRefs", []):
                behavior_relationships[str(behavior_ref)].append(
                    f"{document['path']}::{test['id']}"
                )
    owner_groups: dict[tuple[str, ...], dict[str, Any]] = {}
    for key, owners in feature_index.items():
        if len(owners) < 2:
            continue
        group_key = tuple(sorted(owners))
        group = owner_groups.setdefault(
            group_key,
            {"artifacts": list(group_key), "lines": 0, "branches": 0, "branchSemantics": set()},
        )
        if key[2] == "line":
            group["lines"] += 1
        else:
            group["branches"] += 1
            group["branchSemantics"].add(f"{key[3]}:{key[4]}")
    overlaps = []
    for group in owner_groups.values():
        group["branchSemantics"] = sorted(group["branchSemantics"])
        group["coordinateCompatibility"] = {
            "lines": True,
            "branches": len(group["branchSemantics"]) == 1,
        }
        overlaps.append(group)
    overlaps.sort(
        key=lambda item: (
            -(item["lines"] + item["branches"]),
            item["artifacts"][0],
            item["artifacts"][-1],
        )
    )
    identical = [
        {"signature": signature, "tests": sorted(names)}
        for signature, names in signatures.items()
        if len(names) > 1
    ]
    document = {
        "schema": COMPARE_SCHEMA,
        "analyzer": {"moduleHash": _digest(Path(__file__)), "python": sys.version.split()[0]},
        "root": str(root),
        "inputs": [
            {
                "path": item["path"],
                "hash": item.get("artifactHash"),
                "format": item.get("format"),
                "layer": item.get("layer"),
                "framework": item.get("framework"),
                "provider": item.get("provider"),
                "outcome": item.get("invocation", {}).get("outcome"),
                "durationSeconds": item.get("invocation", {}).get("durationSeconds")
                or item.get("provenance", {}).get("durationSeconds"),
                "provenance": item.get("provenance", {}),
                "behaviorRefs": item.get("behaviorRefs", []),
                "outcomeSummary": item.get("outcomeSummary", {}),
                "sourceCount": len(item.get("sources", {})),
                "testCount": item.get("observedTestCount", len(item.get("tests", []))),
                "sources": [
                    {
                        "path": source["path"],
                        "hash": source.get("hash"),
                        "comparable": source.get("comparable", False),
                        "generated": source.get("generated", False),
                        "lineCount": len(source["lines"]),
                        "branchCount": len(source["branches"]),
                        "coordinateKinds": sorted(
                            {
                                "line" if source["lines"] else "",
                                "branch" if source["branches"] else "",
                            }
                            - {""}
                        ),
                    }
                    for source in item.get("sources", {}).values()
                ],
            }
            for item in documents
        ],
        "tests": test_rows,
        "identicalFootprints": identical,
        "crossLayerOverlap": overlaps,
        "behaviorRelationships": [
            {
                "behaviorRef": behavior_ref,
                "tests": sorted(test_ids),
                "note": "Declared relationship only; it does not establish coverage equivalence.",
            }
            for behavior_ref, test_ids in sorted(behavior_relationships.items())
        ],
        "gaps": gaps,
        "healthyCollection": not invalid_evidence
        and not any(gap.get("reason", "").endswith(("failed", "invalid")) for gap in gaps),
        "confidentOverlap": bool(overlaps)
        and not invalid_evidence
        and not any(
            gap.get("reason")
            in {
                "source-hash-missing",
                "source-stale-or-hash-mismatch",
                "suite-only-unattributed",
                "test-identity-unbound-or-nonisolated",
                "source-map-invalid",
                "source-map-line-mapping-unavailable",
                "invocation-failed",
                "runner-failed",
                "test-outcome-not-passed",
                "duplicate-executed-test-identities",
                "test-identity-missing",
                "test-source-identity-unavailable",
                "source-identity-missing",
                "source-missing",
                "source-changed-during-collection",
                "test-sources-changed-during-collection",
                "config-changed-during-collection",
                "raw-artifact-hash-mismatch",
                "skipped-tests-unattributed",
                "pytest-report-unhealthy-or-unverified",
                "pytest-collection-provenance-missing-or-failed",
            }
            for gap in gaps
        ),
        "warnings": [
            "Imported coverage is execution evidence, not assertion equivalence or deletion proof.",
            (
                "Suite-only artifacts remain unassigned unless an isolated successful invocation "
                "binds exact test identities."
            ),
            (
                "Line overlap requires exact repository-relative source path and source hash; "
                "branch overlap also requires compatible coordinate semantics."
            ),
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / "report.json.tmp"
    with temporary.open("w") as stream:
        json.dump(document, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    temporary.replace(output / "report.json")
    lines = [
        "# Test-value evidence comparison",
        "",
        (
            f"{len(documents)} artifacts; {len(test_rows)} bound tests; "
            f"{len(overlaps)} overlap groups."
        ),
        "",
        "## Evidence gaps",
        "",
    ]
    lines.extend(f"- `{json.dumps(gap, sort_keys=True)}`" for gap in gaps) or lines.append("- None")
    (output / "report.md").write_text("\n".join(lines) + "\n")
    return document
