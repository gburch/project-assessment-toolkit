"""Bounded, offline repository facts. Counts are observations, never maturity scores."""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
import selectors
import stat
import subprocess
import time
import tomllib
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque
from dataclasses import replace
from pathlib import Path

from .analyzer_registry import dedicated_phase_limits, run_analyzer, validate_analyzers
from .budgets import get_budget, pattern_allocations
from .burden_analysis import analyze_change_gates, summarize_burden
from .burden_context import SCHEMA as BURDEN_CONTEXT_SCHEMA
from .burden_context import import_burden_context
from .capture_context import attach_source_windows
from .control_inventory import ControlInventory
from .delivery_analysis import analyze_delivery, is_delivery_input
from .diagnostics import sarif_report
from .ecosystem import VERSION as ECOSYSTEM_VERSION
from .ecosystem import dependency_inventory, javascript_signals, python_signals
from .ecosystem import summarize as summarize_ecosystem
from .generic_analysis import source_language, source_text_facts, summarize_source_text
from .javascript_analysis import (
    analyze_javascript,
    javascript_analyzer_identity,
    summarize_javascript,
)
from .observations import SCHEMA as OBSERVATION_SCHEMA
from .observations import import_observation
from .provenance import tool_info
from .review_context import source_area
from .rubric import RUBRIC_VERSION
from .source_controls import analyze_python_controls
from .static_analysis import MAX_FILES as MAX_STATIC_FILES
from .static_analysis import MAX_SYMBOLS as MAX_STATIC_SYMBOLS
from .static_analysis import VERSION as STATIC_VERSION
from .static_analysis import analyze_python, ruff_report, source_role
from .static_analysis import summarize as summarize_static
from .test_value.assessment import summarize as summarize_test_value

MAX_FILES = 20_000
MAX_FILE_BYTES = 1024 * 1024
MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = get_budget("standard").supported_text_bytes
MAX_UNSUPPORTED_ASSET_BYTES = get_budget("standard").unsupported_asset_bytes
MAX_SCAN_SECONDS = get_budget("standard").deadline_seconds
MAX_REPORTS = 32
MAX_TEST_VALUE_REPORT_BYTES = 16 * 1024 * 1024
MAX_TEST_VALUE_REPORT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_STATIC_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_STATIC_DEFINITIONS = 2000
MAX_DETAIL_PER_FILE = get_budget("standard").pattern_functions_per_file
MAX_DEPTH = 64
MAX_EXCERPT = 800
MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_EXCLUDED_DIRECTORY_PREFIXES = 100
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".next",
    "dist",
    "build",
    "coverage",
    ".coverage",
    ".cache",
    ".artifacts",
    ".terraform",
    "vendor",
}
_SECRET_DIRS = {".aws", ".ssh", ".gnupg", ".keys", ".secrets", "credentials", "secrets"}
_SECRET_NAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "token",
    "tokens.json",
}
_JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_CONFIG = {".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".tf", ".sh"}
_SECRET_LINE = re.compile(
    r"(?i)(?:api[_-]?key|secret|password|passwd|credential|authorization|access[_-]?token|auth[_-]?token|token)"
    r"[\w\s\-\"']*\s*[:=]"
)
_TOKEN = re.compile(
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"|(?<![A-Za-z0-9])sk[-_][A-Za-z0-9_-]{16,}|(?i:bearer)\s+[A-Za-z0-9._~+/-]{8,}"
    r"|[A-Za-z][A-Za-z0-9+.-]*://[^\s/@]+:[^\s/@]+@"
)


def _digest(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def _bytes_digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _redact(value):
    lines, private = [], False
    for line in value.splitlines():
        if "-----BEGIN " in line and "PRIVATE KEY-----" in line:
            private = True
        sensitive = private or _SECRET_LINE.search(line)
        lines.append("[REDACTED SENSITIVE LINE]" if sensitive else _TOKEN.sub("[REDACTED]", line))
        if "-----END " in line and "PRIVATE KEY-----" in line:
            private = False
    return "\n".join(lines)


def _redact_data(value):
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, list):
        return [_redact_data(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_data(item) for key, item in value.items()}
    return value


def _secret_name(name):
    lowered = name.lower()
    return (
        lowered in _SECRET_NAMES
        or lowered.startswith(".env.")
        or lowered.startswith("service-account")
        or lowered.endswith((".pem", ".key", ".p12", ".pfx", ".keystore"))
    )


def _fingerprint(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_at(directory, name, limit):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input must be a regular file")
        if before.st_size > limit:
            raise ValueError("file byte limit exceeded")
        parts, consumed = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, limit - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > limit:
                raise ValueError("file byte limit exceeded")
            parts.append(chunk)
        after = os.fstat(descriptor)
        if _fingerprint(before) != _fingerprint(after):
            raise ValueError("source changed during collection")
        return b"".join(parts), _fingerprint(after)
    finally:
        os.close(descriptor)


def _open_directory(path):
    """Open canonical absolute directories without following a swapped ancestor."""
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _kind(path):
    suffix, name = path.suffix.lower(), path.name.lower()
    if suffix == ".py":
        return "python"
    if suffix in _JS:
        return "javascript"
    if source_language(path.as_posix()) is not None:
        return "source"
    if suffix in {".md", ".mdx", ".rst"} or name.startswith(("readme", "license")):
        return "documentation"
    if name in {"package.json", "pyproject.toml", "requirements.txt"}:
        return "manifest"
    if (
        suffix in _CONFIG
        or name in {"dockerfile", ".gitignore", "makefile"}
        or is_delivery_input(path.as_posix())
    ):
        return "configuration"
    return None


def _is_test(path):
    return source_role(path.as_posix())["role"] == "test"


def _priority(path):
    kind, role = _kind(path), source_role(path.as_posix())["role"]
    if (
        kind == "manifest"
        or is_delivery_input(path.as_posix())
        or path.name
        in {
            "src",
            "frontend",
            "backend",
            "web",
            "app",
            "apps",
            "services",
            "packages",
        }
    ):
        return 0
    if kind in {"python", "javascript", "source"} and role == "production":
        return 0
    if kind == "configuration" and role not in {"test", "tooling"}:
        return 1
    if kind in {"python", "javascript", "source"} and role == "unknown":
        return 1
    if path.name.lower() in {"readme.md", "agents.md", "contributing.md", "security.md"}:
        return 2
    if role == "test" or path.name in {"test", "tests", "e2e", "__tests__"}:
        return 3
    if role == "tooling" or path.name in {
        ".agents",
        ".claude",
        ".codex",
        "ops",
        "tools",
        "scripts",
        "evals",
    }:
        return 4
    return 5 if kind == "documentation" or path.name == "docs" else 6


def _parent_at(root_descriptor, path):
    """Reopen a discovered parent through contained directory FDs, never symlinks."""
    descriptor = os.dup(root_descriptor)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _python(text):
    tree = ast.parse(text)
    nodes = list(ast.walk(tree))
    functions = [n for n in nodes if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    forwarding = 0
    for function in functions:
        body = function.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        forwarding += (
            len(body) == 1
            and isinstance(body[0], ast.Return | ast.Expr)
            and isinstance(body[0].value, ast.Call)
            and not any(
                isinstance(n, ast.Await | ast.Yield | ast.YieldFrom) for n in ast.walk(body[0])
            )
        )

    def symbol(node):
        if isinstance(node, ast.Subscript):
            node = node.value
        return (
            node.id
            if isinstance(node, ast.Name)
            else node.attr
            if isinstance(node, ast.Attribute)
            else None
        )

    abstract = sum(
        any(symbol(base) in {"ABC", "Protocol"} for base in node.bases)
        or any(
            symbol(decorator) == "abstractmethod"
            for member in node.body
            if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef)
            for decorator in member.decorator_list
        )
        for node in nodes
        if isinstance(node, ast.ClassDef)
    )
    return {
        "functions": len(functions),
        "classes": sum(isinstance(n, ast.ClassDef) for n in nodes),
        "branches": sum(
            isinstance(n, ast.If | ast.For | ast.AsyncFor | ast.While | ast.Try | ast.Match)
            for n in nodes
        ),
        "assertions": sum(isinstance(n, ast.Assert) for n in nodes),
        "test_functions": sum(n.name.startswith("test_") for n in functions),
        "imports": sum(isinstance(n, ast.Import | ast.ImportFrom) for n in nodes),
        "forwarding_functions": forwarding,
        "abstract_classes": abstract,
    }, tree


def _javascript(text):
    # Deliberately lexical: discard comments and quoted strings before token counts.
    stripped = re.sub(
        r"/\*[\s\S]*?\*/|//[^\n]*|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`",
        " ",
        text,
    )
    return {
        "functions": len(re.findall(r"\bfunction\b|=>", stripped)),
        "branches": len(re.findall(r"\b(?:if|for|while|switch|catch)\b", stripped)),
        "test_cases": len(
            re.findall(r"\b(?:it|test)\s*(?:\.\s*(?:only|skip|each)\s*)?\(", stripped)
        ),
        "assertions": len(re.findall(r"\b(?:expect|assert)\s*[.(]", stripped)),
    }


def _documentation(text):
    return {
        "headings": len(re.findall(r"^#{1,6}\s", text, re.M)),
        "links": len(re.findall(r"\[[^\]\n]+\]\([^\)\n]+\)", text)),
        "code_blocks": len(re.findall(r"^\s*```", text, re.M)) // 2,
    }


def _analysis_paths(paths):
    """Alternate roles and areas before spending bounded detailed-analysis work."""
    groups = defaultdict(lambda: defaultdict(deque))
    for path in sorted(paths):
        groups[source_role(path)["role"]][source_area(path)].append(path)
    areas = {role: deque(sorted(group)) for role, group in groups.items()}
    order = ("test", "production", "unknown", "tooling")
    while any(areas.values()):
        for role in order:
            if not areas.get(role):
                continue
            area = areas[role].popleft()
            yield groups[role][area].popleft()
            if groups[role][area]:
                areas[role].append(area)


def _analysis_coverage(paths, analyzed, failed=(), definition_counts=None):
    """Describe captured-input selection without implying semantic coverage."""
    analyzed, failed = set(analyzed), set(failed)
    groups = {}
    roles = {}
    for path in sorted(paths):
        role, area = source_role(path)["role"], source_area(path)
        group = groups.setdefault(
            (role, area),
            {
                "role": role,
                "path": area,
                "eligible_files": 0,
                "analyzed_files": 0,
                "omitted_files": 0,
                "failed_files": 0,
            },
        )
        group["eligible_files"] += 1
        group["analyzed_files"] += path in analyzed
        group["omitted_files"] += path not in analyzed
        group["failed_files"] += path in failed
        counts = roles.setdefault(
            role,
            {"eligible_files": 0, "analyzed_files": 0, "omitted_files": 0, "failed_files": 0},
        )
        counts["eligible_files"] += 1
        counts["analyzed_files"] += path in analyzed
        counts["omitted_files"] += path not in analyzed
        counts["failed_files"] += path in failed
        if definition_counts is not None:
            examined, retained = definition_counts.get(path, (0, 0))
            for counter in (counts, group):
                counter["definitions_examined"] = counter.get("definitions_examined", 0) + examined
                counter["definitions_retained"] = counter.get("definitions_retained", 0) + retained
                counter["definitions_analyzed"] = counter.get("definitions_analyzed", 0) + retained
                counter["definitions_omitted"] = (
                    counter.get("definitions_omitted", 0) + examined - retained
                )
    result = {
        "selection": "role_then_area_round_robin",
        "eligible_files": len(paths),
        "analyzed_files": len(analyzed),
        "omitted_files": len(paths) - len(analyzed),
        "failed_files": len(failed),
        "roles": roles,
        "eligible_areas": len(groups),
        "analyzed_areas": sum(group["analyzed_files"] > 0 for group in groups.values()),
        "omitted_areas": sum(group["analyzed_files"] == 0 for group in groups.values()),
        "areas": list(groups.values())[:100],
        "omitted_coverage_areas": max(0, len(groups) - 100),
        "caveat": "Captured eligible inputs only. Roles and areas are path heuristics; analyzed files do not establish complete behavior or usage coverage.",
    }
    if definition_counts is not None:
        for key in (
            "definitions_examined",
            "definitions_analyzed",
            "definitions_retained",
            "definitions_omitted",
        ):
            result[key] = sum(counts[key] for counts in roles.values())
        result["definition_count_basis"] = (
            "Python AST definitions and lexical JavaScript registration candidates inventoried in selected files before bounded rich analysis; omitted files remain unknown."
        )
    return result


def _prepare_source_analysis(root, path, text, tree, quota):
    """Reuse the current captured AST for a preallocated share of rich detail."""
    from .test_value import static as static_tool

    kind, examined, failed = _kind(Path(path)), 0, False
    try:
        if kind == "python":
            functions = sorted(
                (
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                ),
                key=lambda node: node.lineno,
            )
            examined = len(functions)
            # Preserve both test oracles and helpers when one test file
            # contains many definitions, without rich work for every one.
            tests = [node for node in functions if node.name.startswith("test_")]
            helpers = [node for node in functions if not node.name.startswith("test_")]
            test_quota = min(len(tests), (quota + 1) // 2)
            helper_quota = min(len(helpers), quota - test_quota)
            test_quota = min(len(tests), quota - helper_quota)
            chosen = [
                group[i * len(group) // count]
                for group, count in ((tests, test_quota), (helpers, helper_quota))
                for i in range(count)
            ]
            found, found_gaps, _ = static_tool.python_rows(
                root / path, root, tree, selected_lines={node.lineno for node in chosen}
            )
            signals = python_signals(path, tree)
        else:
            offsets = static_tool._js_definition_offsets(text)
            examined = len(offsets)
            count = min(quota, len(offsets))
            selected_offsets = {offsets[i * len(offsets) // count] for i in range(count)}
            found, found_gaps = static_tool._js_file(
                root / path, root, text, selected_offsets=selected_offsets
            )
            found_gaps.append(
                {"path": path, "reason": "javascript-lexical-analysis-not-parse-proof"}
            )
            signals = javascript_signals(path, text)
    except (TypeError, ValueError, SyntaxError, RecursionError):
        failed = True
        found, found_gaps = [], [{"path": path, "reason": "static-analysis-error"}]
        signals = {
            "path": path,
            "status": "partial",
            "signals": [],
            "gaps": ["Source syntax analysis failed."],
        }
    if examined > len(found):
        found_gaps.append({"path": path, "reason": "static-definition-limit"})
    for row in found:
        if len(row.get("setupLeads", [])) > 32:
            row["setupLeadCount"] = len(row["setupLeads"])
            row["setupLeads"] = row["setupLeads"][:32]
            found_gaps.append({"path": path, "reason": "static-setup-lead-limit"})
    role = source_role(path)["role"]
    for signal in signals["signals"]:
        signal["scope"] = "test" if role == "test" else "tooling" if role == "tooling" else "source"
    return {"rows": found, "gaps": found_gaps}, signals, (examined, len(found)), failed


def _static_value_analysis(root, source_rows, manifest, revision, coverage):
    """Summarize bounded rows prepared from the collector's existing AST/text."""
    from .test_value import static as static_tool

    max_definitions, max_groups, max_candidates, max_gaps = MAX_STATIC_DEFINITIONS, 256, 512, 128
    rows, gaps = [], []
    pending = deque(path for path in _analysis_paths(source_rows) if source_rows[path]["rows"])
    queues = {path: deque(prepared["rows"]) for path, prepared in source_rows.items()}
    while pending:
        path = pending.popleft()
        rows.append(queues[path].popleft())
        if queues[path]:
            pending.append(path)
    for _, prepared in sorted(source_rows.items()):
        gaps.extend(prepared["gaps"])
    if coverage["omitted_files"]:
        gaps.append(
            {"reason": "static-input-omissions", "omitted_files": coverage["omitted_files"]}
        )

    raw_groups, raw_candidates = static_tool.summarize_rows(rows)
    groups = [
        {
            **group,
            "memberCount": len(group.get("members", [])),
            "members": list(group.get("members", []))[:32],
        }
        for group in raw_groups
    ]
    candidates = [
        {
            **candidate,
            **(
                {
                    "memberCount": len(candidate.get("members", [])),
                    "members": list(candidate.get("members", []))[:32],
                }
                if "members" in candidate
                else {}
            ),
        }
        for candidate in raw_candidates
    ]
    captured = {
        entry["path"]: entry["digest"] for entry in manifest if entry["path"] in source_rows
    }
    return {
        "schema": static_tool.SCHEMA,
        "tool": {
            "module": "project_assess.test_value.static",
            "adapterVersion": static_tool.VERSION,
            "moduleDigest": static_tool._module_digest(),
        },
        "provenance": {
            "root": str(root),
            "revision": revision,
            "manifestDigest": _digest(sorted(captured.items())),
            "sourceCount": len(captured),
            "capturedOnly": True,
        },
        "counts": {
            "files": len(captured),
            "definitions": len(rows),
            "groups": len(raw_groups),
            "candidates": len(raw_candidates),
            "gaps": len(gaps),
        },
        "coverage": coverage,
        "definitions": rows[:max_definitions],
        "groups": groups[:max_groups],
        "candidates": candidates[:max_candidates],
        "gaps": gaps[:max_gaps],
        "bounded": {
            "definitions": len(rows) <= max_definitions,
            "groups": len(groups) <= max_groups,
            "candidates": len(candidates) <= max_candidates,
            "gaps": len(gaps) <= max_gaps,
        },
    }


def _static_value_payload(analysis):
    """Keep retained-role coverage honest when the fixed byte budget trims rows."""
    coverage = analysis["coverage"]
    roles, areas = Counter(), Counter()
    for row in analysis["definitions"]:
        role, area = source_role(row["path"])["role"], source_area(row["path"])
        roles[role] += 1
        areas[(role, area)] += 1
    coverage["definitions_retained"] = len(analysis["definitions"])
    coverage["definitions_omitted"] = (
        coverage["definitions_examined"] - coverage["definitions_retained"]
    )
    coverage["definitions_output_omitted"] = (
        coverage["definitions_analyzed"] - coverage["definitions_retained"]
    )
    for role, group in coverage["roles"].items():
        group["definitions_retained"] = roles[role]
        group["definitions_omitted"] = group["definitions_examined"] - roles[role]
        group["definitions_output_omitted"] = group["definitions_analyzed"] - roles[role]
    for group in coverage["areas"]:
        retained = areas[(group["role"], group["path"])]
        group["definitions_retained"] = retained
        group["definitions_omitted"] = group["definitions_examined"] - retained
        group["definitions_output_omitted"] = group["definitions_analyzed"] - retained
    return json.dumps(analysis, sort_keys=True).encode()


def _json(payload):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(
        payload,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON value")),
    )


def _manifest(path, text):
    if path.name == "package.json":
        data = _json(text)
        if not isinstance(data, dict):
            raise ValueError("manifest must contain an object")
        groups = (
            data.get("dependencies", {}),
            data.get("devDependencies", {}),
            data.get("scripts", {}),
        )
        if not all(isinstance(group, dict) for group in groups):
            raise ValueError("invalid package manifest groups")
        result = {
            "ecosystem": "javascript",
            "dependencies": len(groups[0]),
            "dev_dependencies": len(groups[1]),
            "scripts": sorted(groups[2]),
        }
    elif path.name == "pyproject.toml":
        data = tomllib.loads(text)
        project = data.get("project", {})
        if not isinstance(project, dict):
            raise ValueError("invalid Python project group")
        dependencies, optional = (
            project.get("dependencies", []),
            project.get("optional-dependencies", {}),
        )
        if (
            not isinstance(dependencies, list)
            or not isinstance(optional, dict)
            or not all(isinstance(v, list) for v in optional.values())
        ):
            raise ValueError("invalid Python dependency groups")
        scripts = project.get("scripts", {})
        if not isinstance(scripts, dict):
            raise ValueError("invalid Python script group")
        result = {
            "ecosystem": "python",
            "dependencies": len(dependencies),
            "dev_dependencies": sum(
                len(v) for key, v in optional.items() if key in {"dev", "test", "tests", "testing"}
            ),
            "scripts": sorted(scripts),
        }
    else:
        data = text
        result = {
            "ecosystem": "python",
            "dependencies": sum(
                bool(line.strip()) and not line.lstrip().startswith(("#", "-"))
                for line in text.splitlines()
            ),
            "dev_dependencies": 0,
            "scripts": [],
        }
    result["dependency_inventory"] = dependency_inventory(path.as_posix(), data)
    return result


def _report(payload):
    if b"\x00" in payload or b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise ValueError("report DTDs, entities and non-UTF-compatible encodings forbidden")
    try:
        tree = ET.fromstring(payload)
    except ET.ParseError:
        raise ValueError("malformed XML report") from None
    pending, count = [(tree, 1)], 0
    while pending:
        element, depth = pending.pop()
        count += 1
        if count > 100_000 or depth > MAX_DEPTH:
            raise ValueError("XML report structure limit exceeded")
        pending.extend((child, depth + 1) for child in element)
    if tree.tag in {"testsuite", "testsuites"}:
        cases = list(tree.iter("testcase"))
        if not cases:
            raise ValueError("JUnit report contains no test cases")
        values = Counter(tests=len(cases), failures=0, errors=0, skipped=0)
        seconds = 0.0
        for case in cases:
            for key, tag in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped")):
                values[key] += case.find(tag) is not None
            try:
                duration = float(case.get("time", "0"))
            except ValueError:
                raise ValueError("invalid JUnit duration") from None
            if not math.isfinite(duration) or duration < 0:
                raise ValueError("invalid JUnit duration")
            seconds += duration
        if not math.isfinite(seconds):
            raise ValueError("invalid JUnit total duration")
        return "junit", {**values, "seconds": seconds}
    if tree.tag == "coverage":
        values = {}
        for key in ("lines-covered", "lines-valid", "branches-covered", "branches-valid"):
            raw = tree.get(key)
            if raw is not None:
                if not re.fullmatch(r"[0-9]{1,12}", raw):
                    raise ValueError("invalid Cobertura count")
                values[key.replace("-", "_")] = int(raw)
        for prefix in ("lines", "branches"):
            covered, valid = values.get(prefix + "_covered"), values.get(prefix + "_valid")
            if covered is not None and valid is not None and covered > valid:
                raise ValueError("Cobertura covered count exceeds valid count")
        if "lines_valid" not in values or "lines_covered" not in values:
            raise ValueError("Cobertura requires explicit line counts")
        return "cobertura", values
    raise ValueError("unsupported report type; expected JUnit or Cobertura")


def _test_value_report(payload, root, manifest, revision):
    """Parse one explicitly supplied JSON test-value report without imports."""
    try:
        document = _json(payload)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ValueError("malformed test-value JSON report") from None
    summary = summarize_test_value(document, root, manifest, revision)

    def redact_stats(value):
        if isinstance(value, dict):
            return {
                _TOKEN.sub("[REDACTED]", key): "[REDACTED]"
                if _SECRET_LINE.search(key + ":")
                else redact_stats(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact_stats(item) for item in value]
        return _redact(value) if isinstance(value, str) else value

    return "test-value", redact_stats(summary)


def _git_configuration(root):
    environment = {
        "PATH": os.defpath,
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_PAGER": "cat",
        "GIT_LITERAL_PATHSPECS": "1",
    }
    prefix = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=" + os.devnull,
        "-c",
        "core.untrackedCache=false",
        "-c",
        "safe.directory=" + str(root),
        "-C",
        str(root),
    ]

    return prefix, environment


def _git(root):
    prefix, environment = _git_configuration(root)

    def run(*args):
        result = subprocess.run(
            prefix + list(args), capture_output=True, env=environment, timeout=5, check=False
        )
        return (
            result.stdout.decode("utf-8", errors="replace").strip()
            if result.returncode == 0
            else None
        )

    try:
        top = run("rev-parse", "--show-toplevel")
        if top is None or Path(top).resolve() != root:
            return None, None
        revision = run("rev-parse", "--verify", "HEAD")
        # ``git status`` may run repository-configured clean filters. Metadata-only
        # reads avoid target execution; the content manifest identifies worktree bytes.
        return revision if revision and re.fullmatch(r"[0-9a-f]{40,64}", revision) else None, None
    except (OSError, subprocess.TimeoutExpired):
        return None, None


def _git_inventory(root):
    """Index/list operations do not refresh files or run clean filters or hooks."""
    prefix, environment = _git_configuration(root)
    try:
        check = subprocess.run(
            prefix + ["rev-parse", "--show-toplevel"],
            capture_output=True,
            env=environment,
            timeout=5,
            check=False,
        )
        if check.returncode != 0 or Path(os.fsdecode(check.stdout.strip())).resolve() != root:
            return (
                None,
                "filesystem",
                "No Git-root inventory; using bounded filesystem selection",
                False,
            )
        process = subprocess.Popen(
            prefix + ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return (
            None,
            "filesystem",
            "Git inventory unavailable; using bounded filesystem selection",
            False,
        )
    payload, count, deadline = bytearray(), 0, time.monotonic() + 5
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError("Git inventory time limit exceeded")
                chunk = os.read(
                    process.stdout.fileno(), min(65536, MAX_GIT_OUTPUT_BYTES - len(payload) + 1)
                )
                if not chunk:
                    break
                payload.extend(chunk)
                count += chunk.count(b"\0")
                if len(payload) > MAX_GIT_OUTPUT_BYTES or count > MAX_FILES:
                    raise ValueError("Git inventory file or byte limit exceeded")
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if process.returncode != 0 or (payload and not payload.endswith(b"\0")):
            raise ValueError("Git inventory could not be read completely")
        paths = {os.fsdecode(bytes(path)) for path in payload.split(b"\0") if path}
        if any(Path(path).is_absolute() or ".." in Path(path).parts for path in paths):
            raise ValueError("Git inventory contains an unsafe path")
        return (
            paths,
            "git-nonignored",
            "Git ignored/unselected paths are excluded; tracked ignored files remain eligible",
            False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        message = (
            str(exc)
            if isinstance(exc, ValueError)
            else "Git inventory could not be read completely"
        )
        return set(), "git-nonignored", message, True
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def collect(
    root: Path,
    reports: list[Path] | None = None,
    *,
    analysis_profile="standard",
    analyzers=None,
    git_snapshot=None,
) -> dict:
    """Collect facts without running target code or changing target files.

    ``complete`` means collection finished within its declared scope. It does not
    certify runtime behavior; excluded and unsupported inputs remain visible gaps.
    ``git_snapshot`` ({revision, paths, repository}) collects a private tree that
    was extracted from committed objects; Git is then read only from ``repository``.
    """
    from .test_value import static as static_tool

    budget = get_budget(analysis_profile)
    # Compatibility aliases remain useful for bounded tests; production profile
    # values have one immutable definition in budgets.py.
    if analysis_profile == "standard":
        budget = replace(
            budget,
            supported_text_bytes=MAX_TOTAL_BYTES,
            unsupported_asset_bytes=MAX_UNSUPPORTED_ASSET_BYTES,
            deadline_seconds=MAX_SCAN_SECONDS,
            pattern_functions=MAX_STATIC_SYMBOLS,
            pattern_functions_per_file=MAX_DETAIL_PER_FILE,
        )
    analyzers = validate_analyzers(analyzers)
    configured_limits = {
        **budget.as_dict(),
        "source_file_bytes": MAX_SOURCE_FILE_BYTES,
        "other_file_bytes": MAX_FILE_BYTES,
        "max_files": MAX_FILES,
        "max_depth": MAX_DEPTH,
        "max_reports": MAX_REPORTS,
        "max_json_report_bytes": MAX_TEST_VALUE_REPORT_BYTES,
        "max_json_reports_total_bytes": MAX_TEST_VALUE_REPORT_TOTAL_BYTES,
        "max_static_evidence_bytes": MAX_STATIC_EVIDENCE_BYTES,
        "max_static_definitions": MAX_STATIC_DEFINITIONS,
        "max_git_output_bytes": MAX_GIT_OUTPUT_BYTES,
        "excluded_directory_prefixes": MAX_EXCLUDED_DIRECTORY_PREFIXES,
    }
    dedicated = {
        name: limits
        for name in analyzers
        if (limits := dedicated_phase_limits(name, budget.name)) is not None
    }
    if dedicated:
        configured_limits["dedicated_analyzer_phases"] = dedicated
    deadline = time.monotonic() + budget.deadline_seconds
    root = Path(root).expanduser().absolute()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("assessment root must be a real directory")
    root = root.resolve(strict=True)
    reports = [Path(path).expanduser().absolute() for path in (reports or [])]
    if len(reports) > MAX_REPORTS:
        raise ValueError("report count limit exceeded")
    if len(set(reports)) != len(reports):
        raise ValueError("duplicate report paths")
    facts = {
        "inventory": {
            "files": 0,
            "bytes": 0,
            "source_files": 0,
            "test_files": 0,
            "documentation_files": 0,
            "lines": 0,
        },
        "python": {
            "files": 0,
            "functions": 0,
            "classes": 0,
            "branches": 0,
            "assertions": 0,
            "assertions_basis": "bare_ast_assert",
            "test_functions": 0,
            "imports": 0,
            "forwarding_functions": 0,
            "abstract_classes": 0,
        },
        "javascript": {
            "files": 0,
            "functions": 0,
            "branches": 0,
            "test_cases": 0,
            "assertions": 0,
            "method": "lexical",
        },
        "documentation": {"files": 0, "lines": 0, "headings": 0, "links": 0, "code_blocks": 0},
        "manifests": {
            "paths": [],
            "ecosystems": [],
            "dependencies": 0,
            "dev_dependencies": 0,
            "scripts": [],
        },
        "ci": {"paths": []},
        "reports": {},
    }
    evidence, findings, manifest, watched = [], [], [], []
    control_inventory = ControlInventory()
    evidence_paths = set()
    documentation_texts, python_analysis, javascript_analysis, captured_sources = {}, [], [], {}
    ecosystem_manifests, ecosystem_inputs = {}, []
    source_rows = {}
    source_definition_counts, source_analysis_failed = {}, set()
    analysis_reservations, analysis_selected = {}, set()
    analysis_reserved = analysis_retained = 0
    static_symbols = 0
    gaps, excluded, unsupported = [], Counter(), Counter()
    excluded_directory_prefixes = []
    inputs, skipped, unsearched_directories = [], [], []
    complete, supported_text_complete, assets_complete = True, True, True
    python_source_stable = True
    deadline_hit, visited, total, asset_total = False, 0, 0, 0
    if git_snapshot is None:
        revision, dirty = _git(root)
        selected, selection_mode, selection_gap, selection_failed = _git_inventory(root)
    else:
        revision, dirty = git_snapshot["revision"], None
        selected, selection_mode, selection_failed = set(git_snapshot["paths"]), "git-commit", False
        selection_gap = "Only paths committed at this revision are selected; untracked files of that time are unknown"
    if selection_gap:
        gaps.append(selection_gap)
    complete = not selection_failed
    supported_text_complete = assets_complete = complete
    selected_directories = set()
    supplied_report_paths = {os.path.normpath(str(path)) for path in reports}
    for path in selected or ():
        selected_directories.update(parent.as_posix() for parent in Path(path).parents)
    try:
        descriptor = _open_directory(root)
    except OSError:
        raise ValueError("assessment root must remain an accessible real directory") from None

    def add_evidence(path, payload, kind, text, stats):
        checksum = _bytes_digest(payload)
        entry = {
            "id": "e-" + _digest([path, checksum])[7:31],
            "path": path,
            "digest": checksum,
            "kind": kind,
            "lines": len(text.splitlines()),
            "excerpt": _redact(text[: MAX_EXCERPT * 2])[:MAX_EXCERPT],
            "stats": stats,
        }
        evidence.append(entry)
        evidence_paths.add(path)
        return entry["id"]

    def expired():
        nonlocal complete, deadline_hit
        if time.monotonic() >= deadline:
            complete = False
            if not deadline_hit:
                gaps.append(
                    "Cooperative collection deadline reached; unfinished surfaces remain explicit"
                )
            deadline_hit = True
        return deadline_hit

    def omit(path, kind, size, reason):
        nonlocal complete, supported_text_complete, assets_complete
        skipped.append(
            {
                "path": path.as_posix(),
                "kind": kind,
                "role": source_role(path.as_posix())["role"],
                "bytes": size,
                "reason": reason,
            }
        )
        complete = False
        if kind is None:
            assets_complete = False
        else:
            supported_text_complete = False

    def walk(directory, relative, depth):
        nonlocal complete, visited
        if expired():
            unsearched_directories.append({"path": relative.as_posix(), "reason": "deadline"})
            return
        if depth > MAX_DEPTH:
            gaps.append("Directory depth limit exceeded")
            unsearched_directories.append({"path": relative.as_posix(), "reason": "depth-limit"})
            complete = False
            return
        watched.append((str(relative), _fingerprint(os.fstat(directory))))
        try:
            with os.scandir(directory) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > MAX_FILES:
                        gaps.append("Directory entry limit exceeded")
                        unsearched_directories.append(
                            {"path": relative.as_posix(), "reason": "directory-entry-limit"}
                        )
                        complete = False
                        return
                names.sort(key=lambda name: (_priority(relative / name), name))
        except OSError:
            gaps.append("Unable to list a source directory")
            complete = False
            return
        for name in names:
            if expired():
                unsearched_directories.append({"path": relative.as_posix(), "reason": "deadline"})
                return
            if visited >= MAX_FILES:
                gaps.append(
                    "Repository discovery file limit exceeded; undiscovered paths are unknown"
                )
                unsearched_directories.append(
                    {"path": relative.as_posix(), "reason": "discovery-file-limit"}
                )
                complete = False
                return
            visited += 1
            if any(ord(char) < 32 for char in name):
                excluded["unsafe filenames"] += 1
                complete = False
                continue
            path = relative / name
            if (
                selected is not None
                and path.as_posix() not in selected
                and path.as_posix() not in selected_directories
            ):
                excluded["Git ignored/unselected paths"] += 1
                continue
            try:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    excluded["symlinks"] += 1
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if name in _SKIP_DIRS or name.lower() in _SECRET_DIRS:
                        reason = (
                            "dependency/build/VCS directories"
                            if name in _SKIP_DIRS
                            else "credential directories"
                        )
                        excluded[reason] += 1
                        if len(excluded_directory_prefixes) < MAX_EXCLUDED_DIRECTORY_PREFIXES:
                            excluded_directory_prefixes.append(
                                {"path": _redact(path.as_posix()), "reason": reason}
                            )
                        continue
                    child = os.open(
                        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                    )
                    try:
                        walk(child, path, depth + 1)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    excluded["nonregular files"] += 1
                    continue
                if os.path.normpath(str(root / path)) in supplied_report_paths:
                    continue
                if _secret_name(name):
                    excluded["credential files"] += 1
                    continue
                inputs.append((path, _fingerprint(info), info.st_size, _kind(path)))
            except (OSError, ValueError):
                gaps.append("Unable to inspect source input safely: " + path.as_posix())
                complete = False

    def capture(directory, path, expected):
        nonlocal \
            complete, \
            supported_text_complete, \
            assets_complete, \
            python_source_stable, \
            total, \
            asset_total, \
            static_symbols, \
            analysis_reserved, \
            analysis_retained
        name = path.name
        try:
            # A supplied report is handled below by its dedicated bounded
            # parser.  Do not also treat its JSON as project source, which
            # could expose test identities or report output in evidence.
            if os.path.normpath(str(root / path)) in supplied_report_paths:
                return
            if _secret_name(name):
                excluded["credential files"] += 1
                return
            kind = _kind(path)
            file_limit = (
                MAX_SOURCE_FILE_BYTES
                if kind in {"python", "javascript", "source"}
                else MAX_FILE_BYTES
            )
            payload, fingerprint = _read_at(
                directory,
                name,
                min(
                    file_limit,
                    (budget.unsupported_asset_bytes - asset_total)
                    if kind is None
                    else (budget.supported_text_bytes - total),
                ),
            )
            if fingerprint != expected:
                gaps.append("Source changed during collection")
                complete = False
                if kind is None:
                    assets_complete = False
                else:
                    supported_text_complete = False
                if kind == "python":
                    python_source_stable = False
            watched.append((str(path), fingerprint))
            if kind is None:
                asset_total += len(payload)
            else:
                total += len(payload)
            manifest.append(
                {
                    "path": path.as_posix(),
                    "digest": _bytes_digest(payload),
                    "bytes": len(payload),
                }
            )
            if kind is None:
                unsupported[path.suffix.lower() or "extensionless"] += 1
                return
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                gaps.append("Unsupported non-UTF-8 input: " + path.as_posix())
                complete = supported_text_complete = False
                return
            if "\x00" in text:
                gaps.append("Unsupported binary input: " + path.as_posix())
                complete = supported_text_complete = False
                return
            stats = {}
            control_record = None
            inventory = facts["inventory"]
            inventory["files"] += 1
            inventory["bytes"] += len(payload)
            inventory["lines"] += len(text.splitlines())
            if kind in {"python", "javascript"}:
                captured_sources[path.as_posix()] = text
                inventory["source_files"] += 1
                inventory["test_files"] += _is_test(path)
                facts[kind]["files"] += 1
                if kind == "python":
                    stats, tree = _python(text)
                    change_gates = _redact_data(
                        analyze_change_gates(
                            path.as_posix(),
                            tree,
                            node_limit=min(100000, budget.metric_nodes_per_file),
                        )
                    )
                    control_record = analyze_python_controls(
                        path.as_posix(), tree, node_limit=budget.metric_nodes_per_file
                    )
                    remaining = max(0, budget.pattern_functions - static_symbols)
                    record = analyze_python(
                        path.as_posix(),
                        tree,
                        detail_budget=min(fair_detail_budget, remaining),
                        metric_node_budget=budget.metric_nodes_per_file,
                    )
                    record["module"]["lines"] = len(text.splitlines())
                    if not remaining and record["module"]["function_count"]:
                        record["gaps"].append(
                            "Project static detail limit reached; module overview/imports retained"
                        )
                    static_symbols += record["module"].get(
                        "pattern_functions", len(record["functions"])
                    )
                    python_analysis.append(record)
                else:
                    stats = _javascript(text)
                    javascript_record = analyze_javascript(path.as_posix(), text)
                    javascript_analysis.append(javascript_record)
                    control_record = javascript_record.get("controls")
                key = path.as_posix()
                if key in analysis_reservations and not expired():
                    analysis_reserved -= analysis_reservations.pop(key)
                    quota = max(0, MAX_STATIC_DEFINITIONS - analysis_retained - analysis_reserved)
                    prepared, signals, counts, failed = _prepare_source_analysis(
                        root, key, text, tree if kind == "python" else None, quota
                    )
                    source_rows[key] = prepared
                    source_definition_counts[key] = counts
                    analysis_retained += counts[1]
                    if failed:
                        source_analysis_failed.add(key)
                    ecosystem_inputs.append(signals)
                for key, value in stats.items():
                    facts[kind][key] += value
                if kind == "python":
                    stats["change_gates"] = change_gates
                stats["is_test"] = _is_test(path)
            elif kind == "source":
                captured_sources[path.as_posix()] = text
                inventory["source_files"] += 1
                inventory["test_files"] += _is_test(path)
                stats = source_text_facts(path.as_posix(), text)
            elif kind == "documentation":
                documentation_texts[path.as_posix()] = text
                stats = _documentation(text)
                inventory["documentation_files"] += 1
                facts["documentation"]["files"] += 1
                facts["documentation"]["lines"] += len(text.splitlines())
                for key, value in stats.items():
                    facts["documentation"][key] += value
            elif kind == "manifest":
                stats = _redact_data(_manifest(path, text))
                manifests = facts["manifests"]
                manifests["paths"].append(path.as_posix())
                manifests["ecosystems"].append(stats["ecosystem"])
                for key in ("dependencies", "dev_dependencies"):
                    manifests[key] += stats[key]
                manifests["scripts"].extend(stats["scripts"])
                ecosystem_manifests[path.as_posix()] = stats["dependency_inventory"]
            if any(part in {".github", ".circleci", ".ssci"} for part in path.parts) or name in {
                "Jenkinsfile",
                ".gitlab-ci.yml",
            }:
                facts["ci"]["paths"].append(path.as_posix())
            if is_delivery_input(path.as_posix()):
                control_record = analyze_delivery(path.as_posix(), text)
            if kind == "source":
                control_record = {
                    "path": path.as_posix(),
                    "language": source_language(path.as_posix()),
                    "status": "unsupported",
                    "signals": [],
                    "coverage": {},
                    "gaps": [
                        "No control grammar for this source language; inventory/text evidence remains available."
                    ],
                }
            stats.update(source_role(path.as_posix()))
            add_evidence(path.as_posix(), payload, kind, text, stats)
            if control_record is not None:
                control_inventory.add(control_record, evidence[-1])
        except (OSError, ValueError, SyntaxError, RecursionError):
            key = path.as_posix()
            analysis_reserved -= analysis_reservations.pop(key, 0)
            if key in captured_sources and key in analysis_selected and key not in source_rows:
                source_analysis_failed.add(key)
                source_rows[key] = {
                    "rows": [],
                    "gaps": [{"path": key, "reason": "static-analysis-error"}],
                }
                source_definition_counts[key] = (0, 0)
                ecosystem_inputs.append(
                    {
                        "path": key,
                        "status": "partial",
                        "signals": [],
                        "gaps": ["Source syntax analysis failed."],
                    }
                )
            gaps.append("Unable to collect or parse input safely: " + path.as_posix())
            # Captured source bytes remain inspectable even when syntax or
            # metric analysis fails. Optional tools must receive evidence-backed
            # inputs rather than assume every captured text parsed successfully.
            if path.as_posix() in captured_sources and path.as_posix() not in evidence_paths:
                add_evidence(
                    path.as_posix(),
                    payload,
                    kind,
                    captured_sources[path.as_posix()],
                    {
                        **source_role(path.as_posix()),
                        "language": source_language(path.as_posix()),
                        "analysis_status": "incomplete",
                        "syntax_analysis": "not_completed",
                    },
                )
                control_inventory.add(
                    {
                        "path": path.as_posix(),
                        "language": source_language(path.as_posix()),
                        "status": "unavailable",
                        "signals": [],
                        "coverage": {},
                        "gaps": ["Captured source syntax/analysis could not be completed."],
                    },
                    evidence[-1],
                )
            omit(path, _kind(path), expected[3], "read-or-parse-error")

    try:
        walk(descriptor, Path("."), 0)
        discovery_complete = complete
        for path, _, _, kind in inputs:
            if kind in {"python", "javascript", "source"}:
                dimensions = ("security", "operability", "extensibility", "performance")
                if kind in {"python", "source"}:
                    dimensions = (*dimensions, "delivery")
                control_inventory.expect(path.as_posix(), dimensions, supported=kind != "source")
            elif is_delivery_input(path.as_posix()):
                control_inventory.expect(path.as_posix(), ("delivery", "security", "extensibility"))
        if not discovery_complete:
            supported_text_complete = assets_complete = False
        python_inputs = sum(
            kind == "python" and size <= MAX_SOURCE_FILE_BYTES for _, _, size, kind in inputs
        )
        detail_paths = list(
            _analysis_paths(
                path.as_posix()
                for path, _, size, kind in inputs
                if kind in {"python", "javascript"} and size <= MAX_SOURCE_FILE_BYTES
            )
        )[:MAX_STATIC_FILES]
        share, remainder = divmod(MAX_STATIC_DEFINITIONS, max(1, len(detail_paths)))
        analysis_reservations = {
            path: share + (index < remainder) for index, path in enumerate(detail_paths)
        }
        analysis_selected = set(detail_paths)
        analysis_reserved = sum(analysis_reservations.values())
        fair_detail_budget = min(
            budget.pattern_functions_per_file,
            max(1, budget.pattern_functions // max(python_inputs, 1)),
        )
        for path, expected, size, kind in sorted(
            inputs, key=lambda row: (row[3] is None, _priority(row[0]), row[0].as_posix())
        ):
            file_limit = (
                MAX_SOURCE_FILE_BYTES
                if kind in {"python", "javascript", "source"}
                else MAX_FILE_BYTES
            )
            remaining_bytes = (
                (budget.unsupported_asset_bytes - asset_total)
                if kind is None
                else (budget.supported_text_bytes - total)
            )
            reason = (
                "deadline"
                if expired()
                else "file-byte-limit"
                if size > file_limit
                else ("unsupported-asset-byte-limit" if kind is None else "total-byte-limit")
                if size > remaining_bytes
                else None
            )
            if reason:
                omit(path, kind, size, reason)
                continue
            try:
                parent = _parent_at(descriptor, path)
                try:
                    capture(parent, path, expected)
                finally:
                    os.close(parent)
            except OSError:
                omit(path, kind, size, "parent-changed-or-inaccessible")
        allocations = pattern_allocations(python_analysis, budget)
        for index, record in enumerate(python_analysis):
            allocated = allocations[record["path"]]
            used = record["module"].get("pattern_functions", len(record["functions"]))
            if allocated <= used:
                continue
            if expired():
                gaps.append(
                    "Pattern refill omitted after the cooperative deadline; cheap module evidence remains available"
                )
                break
            try:
                text = captured_sources[record["path"]]
                refreshed = analyze_python(
                    record["path"],
                    ast.parse(text),
                    detail_budget=allocated,
                    metric_node_budget=budget.metric_nodes_per_file,
                )
                refreshed["module"]["lines"] = len(text.splitlines())
                python_analysis[index] = refreshed
            except (ValueError, SyntaxError, RecursionError):
                gaps.append("Pattern refill could not be completed safely: " + record["path"])
                complete = False
        static_symbols = sum(
            row["module"].get("pattern_functions", len(row["functions"])) for row in python_analysis
        )
        for path, expected in watched:
            try:
                current = os.stat(path, dir_fd=descriptor, follow_symlinks=False)
                if _fingerprint(current) != expected:
                    raise ValueError("changed")
            except (OSError, ValueError):
                gaps.append("Source changed during collection")
                complete = supported_text_complete = assets_complete = False
                if stat.S_ISDIR(expected[2]) or _kind(Path(path)) == "python":
                    python_source_stable = False
    finally:
        os.close(descriptor)
    analysis_omissions = []
    native_paths = [
        path for path in captured_sources if _kind(Path(path)) in {"python", "javascript"}
    ]
    analyzed_paths = source_rows.keys() - source_analysis_failed
    source_value_coverage = _analysis_coverage(
        native_paths, analyzed_paths, source_analysis_failed, source_definition_counts
    )
    source_value_coverage["file_limit_omissions"] = len(set(native_paths) - analysis_selected)
    source_value_coverage["deadline_omissions"] = len(
        (set(native_paths) & analysis_selected) - source_rows.keys()
    )
    ecosystem_source_coverage = _analysis_coverage(
        native_paths, analyzed_paths, source_analysis_failed
    )
    ecosystem_source_coverage.update(
        {key: source_value_coverage[key] for key in ("file_limit_omissions", "deadline_omissions")}
    )
    if native_paths and expired():
        analysis_omissions.append({"analysis": "test-value-static", "reason": "deadline"})
    if native_paths and not expired():
        try:
            if source_value_coverage["deadline_omissions"]:
                analysis_omissions.append({"analysis": "test-value-static", "reason": "deadline"})
            if source_value_coverage["file_limit_omissions"]:
                gaps.append(
                    "Test-value static input file limit reached; remaining inputs were not analyzed"
                )
            analysis = _redact_data(
                _static_value_analysis(root, source_rows, manifest, revision, source_value_coverage)
            )
            for key in ("definitions", "groups", "candidates", "gaps"):
                analysis["bounded"][key] = len(analysis[key]) == analysis["counts"][key]
            analysis["bounded"]["output"] = False
            payload = _static_value_payload(analysis)
            truncated = False
            truncation_gap = {
                "reason": "static-evidence-output-bound",
                "detail": "drill-down leads omitted after bounded serialization",
            }
            if len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                # Keep aggregate counts and provenance, shrinking only the
                # drill-down leads until the evidence remains compact.
                while len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                    changed = False
                    for key in ("definitions", "groups", "candidates"):
                        if len(analysis[key]) > 1:
                            analysis[key] = analysis[key][: max(1, len(analysis[key]) // 2)]
                            analysis["bounded"][key] = False
                            truncated = True
                            changed = True
                            payload = _static_value_payload(analysis)
                            if len(payload) <= MAX_STATIC_EVIDENCE_BYTES:
                                break
                    if not changed:
                        break
                if truncated:
                    analysis["gaps"].append(truncation_gap)
                    analysis["bounded"]["gaps"] = False
                    payload = _static_value_payload(analysis)
                if len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                    if not truncated:
                        analysis["gaps"].append(truncation_gap)
                        analysis["bounded"]["gaps"] = False
                    for key in ("definitions", "groups", "candidates"):
                        analysis[key] = []
                        analysis["bounded"][key] = False
                    payload = _static_value_payload(analysis)
                    if len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                        analysis["gaps"] = [truncation_gap]
                        analysis["bounded"]["gaps"] = False
                        payload = _static_value_payload(analysis)
            # Serialize only after all flags and explicit truncation gaps are
            # finalized; the stored digest and stats must describe one payload.
            analysis["bounded"]["output"] = False
            payload = _static_value_payload(analysis)
            if len(payload) <= MAX_STATIC_EVIDENCE_BYTES:
                analysis["bounded"]["output"] = True
                payload = _static_value_payload(analysis)
                if len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                    analysis["bounded"]["output"] = False
                    payload = _static_value_payload(analysis)
            evidence_id = add_evidence(
                "<test-value-static-analysis>",
                payload,
                "test-value-static-analysis",
                "",
                analysis,
            )
            facts["test_value_static"] = {
                "evidence_id": evidence_id,
                "schema": analysis["schema"],
                "counts": analysis["counts"],
                "coverage": analysis["coverage"],
                "source_count": analysis["provenance"]["sourceCount"],
                "captured_only": True,
            }
            gaps.extend(
                f"Static analysis: {gap.get('reason', 'unknown gap')}"
                for gap in analysis["gaps"]
                if isinstance(gap, dict)
            )
        except (KeyError, TypeError, ValueError, SyntaxError, RecursionError):
            gaps.append("Static analysis could not be completed safely")
            complete = False
    # An omitted asset or dependency lockfile does not omit Python modules.
    # Discovery and changed directories remain conservative because they can
    # hide additional Python inputs; syntax/read failures also stay partial.
    python_source_complete = (
        discovery_complete
        and python_source_stable
        and not any(row["kind"] == "python" for row in skipped)
    )
    analysis = summarize_static(
        python_analysis,
        facts["python"]["files"],
        facts["javascript"]["files"],
        import_target_limit=budget.import_targets,
        source_complete=python_source_complete,
    )
    js_analysis = summarize_javascript(javascript_analysis, facts["javascript"]["files"])
    generic_analysis = _redact_data(
        summarize_source_text(
            captured_sources,
            max_blocks=budget.generic_blocks,
            deadline=deadline,
        )
    )
    optional_analyses = {}

    def add_optional_evidence(name, result):
        payload = json.dumps(result, sort_keys=True).encode()
        evidence_id = add_evidence(f"<{name}-analysis>", payload, "analyzer-analysis", "", result)
        facts.setdefault("optional_analysis", {})[name] = {
            key: value
            for key, value in result.items()
            if key not in {"candidates", "candidate_index", "modules", "topology", "hotspots"}
        }
        facts["optional_analysis"][name]["evidence_id"] = evidence_id
        gaps.extend(f"Optional analyzer {name}: {gap}" for gap in result["gaps"])

    if analyzers:
        source_evidence = {
            entry["path"]: entry for entry in evidence if entry["path"] in captured_sources
        }
        captured_rows = [
            {
                "path": path,
                "text": text,
                "evidence_id": source_evidence[path]["id"],
                "digest": source_evidence[path]["digest"],
                "role": source_role(path)["role"],
            }
            for path, text in sorted(captured_sources.items())
        ]
        snapshot_identity = {
            "root": str(root),
            "revision": revision,
            "manifest_digest": _digest(sorted(manifest, key=lambda item: item["path"])),
        }
        for name in analyzers:
            if name in dedicated:
                continue
            optional_analyses[name] = _redact_data(
                run_analyzer(
                    name,
                    captured_rows,
                    snapshot=snapshot_identity,
                    redact=_redact,
                    analysis_profile=budget.name,
                    deadline=deadline,
                )
            )
    attach_source_windows(
        [analysis, js_analysis, generic_analysis, *optional_analyses.values()],
        captured_sources,
        evidence,
        _redact,
        MAX_STATIC_EVIDENCE_BYTES,
    )
    context_bytes_used = analysis["source_context"]["retained_bytes"]
    payload = json.dumps(analysis, sort_keys=True).encode()
    evidence_id = add_evidence("<static-analysis>", payload, "static-analysis", "", analysis)
    facts["static_analysis"] = {
        key: value
        for key, value in analysis.items()
        if key not in {"candidates", "candidate_index", "modules", "topology", "hotspots"}
    }
    facts["static_analysis"]["evidence_id"] = evidence_id
    gaps.extend(analysis["gaps"])
    if facts["javascript"]["files"]:
        payload = json.dumps(js_analysis, sort_keys=True).encode()
        evidence_id = add_evidence(
            "<javascript-analysis>", payload, "javascript-analysis", "", js_analysis
        )
        facts["javascript_analysis"] = {
            key: value
            for key, value in js_analysis.items()
            if key not in {"candidates", "candidate_index", "modules", "topology", "hotspots"}
        }
        facts["javascript_analysis"]["evidence_id"] = evidence_id
        gaps.extend(js_analysis["gaps"])
    generic_payload = json.dumps(generic_analysis, sort_keys=True).encode()
    generic_id = add_evidence(
        "<source-analysis>", generic_payload, "source-analysis", "", generic_analysis
    )
    facts["source_analysis"] = {
        key: value
        for key, value in generic_analysis.items()
        if key not in {"candidates", "candidate_index", "modules", "topology", "hotspots"}
    }
    facts["source_analysis"]["evidence_id"] = generic_id
    gaps.extend(generic_analysis["gaps"])
    for name, result in optional_analyses.items():
        add_optional_evidence(name, result)
    if documentation_texts and expired():
        analysis_omissions.append({"analysis": "documentation", "reason": "deadline"})
    if documentation_texts and not expired():
        from .documentation import captured_documentation

        analysis = captured_documentation(
            documentation_texts,
            {entry["path"] for entry in manifest},
            captured_sources=captured_sources,
            manifest_scripts={
                entry["path"]: entry.get("stats", {}).get("scripts", [])
                for entry in evidence
                if entry.get("kind") == "manifest"
            },
            deep=budget.name == "deep",
        )

        analysis = _redact_data(analysis)
        payload = json.dumps(analysis, sort_keys=True).encode()
        evidence_id = add_evidence(
            "<documentation-analysis>", payload, "documentation-analysis", "", analysis
        )
        facts["documentation"]["doc_value"] = {
            "evidence_id": evidence_id,
            "words": analysis["words"],
            "bytes": analysis["bytes"],
            "tokensApprox": analysis["tokensApprox"],
            "exact_duplicate_groups": len(analysis["exactDuplicates"]),
            "local_link_leads": sum(
                "issue" in link and link["issue"] != "external-unverified"
                for link in analysis["links"]
            ),
            "scope": analysis["scope"],
        }
        gaps.extend(analysis["gaps"])
    controls = _redact_data(control_inventory.summarize())
    control_payload = json.dumps(controls, sort_keys=True).encode()
    control_id = add_evidence(
        "<control-analysis>", control_payload, "control-analysis", "", controls
    )
    facts["control_analysis"] = {
        key: controls[key]
        for key in ("schema_version", "version", "status", "coverage", "limits", "caveat")
    }
    facts["control_analysis"]["evidence_id"] = control_id
    gaps.extend("Control analysis: " + gap for gap in controls["gaps"])
    report_kinds = []
    unprocessed_reports = []
    json_report_total = 0
    for path in sorted(reports):
        if expired():
            unprocessed_reports.append(str(path))
            gaps.append("Supplied report was not collected before the cooperative deadline")
            continue
        if any(part.lower() in _SECRET_DIRS or _secret_name(part) for part in path.parts):
            raise ValueError("report path is excluded as credential material")
        # Resolve only to check parent symlinks, then read the original leaf with NOFOLLOW.
        try:
            if path.is_symlink() or path.resolve(strict=True) != path:
                raise ValueError("report path must not contain symlinks")
            report_fd = _open_directory(path.parent)
            try:
                is_sarif_report = path.suffix.lower() == ".sarif" or path.name.lower().endswith(
                    ".sarif.json"
                )
                is_json_report = path.suffix.lower() == ".json" or is_sarif_report
                limit = MAX_TEST_VALUE_REPORT_BYTES if is_json_report else MAX_FILE_BYTES
                payload, _ = _read_at(report_fd, path.name, limit)
            finally:
                os.close(report_fd)
        except OSError:
            raise ValueError("report must be an accessible regular file") from None
        if is_json_report:
            json_report_total += len(payload)
            if json_report_total > MAX_TEST_VALUE_REPORT_TOTAL_BYTES:
                raise ValueError("JSON report cumulative byte limit exceeded")
        if is_sarif_report:
            kind = "sarif"
            stats = sarif_report(payload, root, {entry["path"] for entry in manifest}, _redact)
            gaps.extend(stats["gaps"])
            if stats["status"] == "partial":
                complete = False
        elif is_json_report and payload.lstrip().startswith(b"["):
            kind = "ruff"
            stats = ruff_report(payload, root, {entry["path"] for entry in manifest}, _redact)
            gaps.extend(stats["gaps"])
        elif is_json_report:
            label = "test-value"
            try:
                document = _json(payload)
                if isinstance(document, dict) and document.get("schema") == OBSERVATION_SCHEMA:
                    label = "observation"
                    kind, stats = import_observation(payload, manifest, revision, _redact)
                elif isinstance(document, dict) and document.get("schema") == BURDEN_CONTEXT_SCHEMA:
                    label = "burden-context"
                    kind, stats = import_burden_context(payload, manifest, revision, _redact)
                else:
                    kind, stats = _test_value_report(payload, root, manifest, revision)
            except ValueError as exc:
                gaps.append("Malformed or unsupported " + label + " report: " + _redact(str(exc)))
                complete = False
                kind, stats = (
                    label,
                    {
                        "schema": None,
                        "gaps": {"count": 1, "reasons": ["malformed-or-unsupported-report"]},
                        "claims": {
                            "healthyCollection": None,
                            "confidentOverlap": None,
                            "assessmentComplete": False,
                        },
                    },
                )
        else:
            kind, stats = _report(payload)
        report_kinds.append(kind)
        # Never expose raw test output or Ruff/SARIF edit text; retain bounded,
        # redacted diagnostics and summaries from the dedicated adapters.
        add_evidence(str(path), payload, kind, json.dumps(stats, sort_keys=True), stats)
        previous = facts["reports"].setdefault(kind, {"files": 0})
        previous["files"] += 1
        if kind in {"ruff", "sarif"}:
            previous["diagnostics"] = (
                previous.get("diagnostics", 0) + stats["summary"]["diagnostics"]
            )
            if kind == "sarif":
                previous["source_identity"] = "unverified"
                previous["supplied"] = previous.get("supplied", 0) + stats["summary"]["supplied"]
        elif kind in {"test-value", "observation", "burden-context"}:
            # The adapter already returns bounded nested summaries.  Keep one
            # per supplied artifact; never merge claims as if they were facts.
            previous.setdefault("schemas", []).append(stats.get("schema"))
            previous.setdefault("source_identity", []).append(stats.get("sourceIdentity", {}))
            previous.setdefault("gaps", []).append(stats.get("gaps", {}))
        else:
            for key, value in stats.items():
                previous[key] = previous.get(key, 0) + value
    end_revision, end_dirty = _git(root) if git_snapshot is None else (revision, dirty)
    if (revision, dirty) != (end_revision, end_dirty):
        gaps.append("Git identity changed during collection")
        complete = supported_text_complete = assets_complete = False
    manifest_paths = list(_analysis_paths(ecosystem_manifests))[:MAX_STATIC_FILES]
    ecosystem_truncated = (
        len(ecosystem_manifests) > len(manifest_paths) or len(native_paths) > MAX_STATIC_FILES
    )
    ecosystem = _redact_data(
        summarize_ecosystem(
            [ecosystem_manifests[path] for path in manifest_paths], ecosystem_inputs
        )
    )
    ecosystem["coverage"] = ecosystem_source_coverage
    ecosystem["manifest_coverage"] = _analysis_coverage(ecosystem_manifests, manifest_paths)
    if ecosystem_truncated:
        ecosystem["gaps"].append("Ecosystem input file limit reached; inventory is partial")
        ecosystem["status"] = "partial"
    if ecosystem_source_coverage["omitted_files"]:
        ecosystem["gaps"].append(
            "Some captured ecosystem source inputs were not analyzed; inspect selection coverage and collection omissions."
        )
        ecosystem["status"] = "partial"
    if not supported_text_complete:
        ecosystem["gaps"].append("Source capture is incomplete; ecosystem evidence is partial")
        ecosystem["status"] = "partial"
    ecosystem_payload = json.dumps(ecosystem, sort_keys=True).encode()
    ecosystem_id = add_evidence(
        "<ecosystem-analysis>",
        ecosystem_payload,
        "ecosystem-analysis",
        ecosystem_payload.decode(),
        ecosystem,
    )
    facts["ecosystem_fit"] = {
        "schema_version": 1,
        "status": ecosystem["status"],
        "evidence_id": ecosystem_id,
        "dependency_count": ecosystem["counts"]["dependencies"],
        "signal_count": ecosystem["counts"]["signals"],
        "coverage": ecosystem["coverage"],
        "manifest_coverage": ecosystem["manifest_coverage"],
        "gaps": ecosystem["gaps"],
        "limits": ecosystem["limits"],
    }
    gaps.extend("Ecosystem fit: " + gap for gap in ecosystem["gaps"])
    facts["manifests"]["ecosystems"] = sorted(set(facts["manifests"]["ecosystems"]))
    facts["manifests"]["scripts"] = sorted(set(facts["manifests"]["scripts"]))
    # ``files``/``bytes`` describe recognized text inputs; these totals identify
    # every regular file whose bytes contributed to the source manifest.
    facts["inventory"]["recognized_files"] = facts["inventory"]["files"]
    facts["inventory"]["manifest_files"] = len(manifest)
    facts["inventory"]["manifest_bytes"] = total + asset_total
    facts["inventory"]["supported_input_bytes"] = total
    facts["inventory"]["unsupported_asset_bytes"] = asset_total
    role_counts = {
        role: {"files": 0, "bytes": 0, "lines": 0}
        for role in ("production", "test", "tooling", "unknown")
    }
    source_bytes = {row["path"]: row["bytes"] for row in manifest}
    for entry in evidence:
        if entry["kind"] in {"python", "javascript", "source"}:
            role = entry["stats"]["role"]
            role_counts[role]["files"] += 1
            role_counts[role]["bytes"] += source_bytes[entry["path"]]
            role_counts[role]["lines"] += entry["lines"]
    facts["inventory"]["roles"] = role_counts
    facts["collection"] = {
        "completeness_scope": "eligible regular files after configured directory, credential, symlink and Git selection exclusions",
        "excluded_directory_prefixes": excluded_directory_prefixes,
        "omitted_excluded_directory_prefixes": max(
            0,
            excluded["dependency/build/VCS directories"]
            + excluded["credential directories"]
            - len(excluded_directory_prefixes),
        ),
        "priority": "application source and manifests/configuration before tests, tooling and unsupported assets",
        "eligible_files_seen": len(inputs),
        "captured_files": len(manifest),
        "skipped_files": len(skipped),
        "skipped_by_reason": dict(sorted(Counter(row["reason"] for row in skipped).items())),
        "skipped_by_role": dict(sorted(Counter(row["role"] for row in skipped).items())),
        "skipped_inputs": sorted(skipped, key=lambda row: (row["path"], row["reason"])),
        "discovery_complete": discovery_complete,
        "unsearched_directories": sorted(
            unsearched_directories, key=lambda row: (row["path"], row["reason"])
        ),
        "python_detail_budget_per_file": fair_detail_budget,
        "python_detail_functions": static_symbols,
        "python_pattern_functions": static_symbols,
        "python_initial_pattern_quota": fair_detail_budget,
        "pattern_allocation": "initial module quota, then production/risk-weighted refill from captured text",
        "analysis_profile": budget.name,
        "limits": configured_limits,
        "supported_text_complete": supported_text_complete,
        "python_source_complete": python_source_complete,
        "unsupported_assets_complete": assets_complete,
        "deadline_exceeded": expired(),
        "deadline_kind": "cooperative; checks between bounded operations, not a process kill deadline",
        "unprocessed_reports": unprocessed_reports,
        "analysis_omissions": analysis_omissions,
        "python_pattern_modules": sum(
            row["module"].get("pattern_functions", len(row["functions"])) > 0
            for row in python_analysis
        ),
        "analyzers": list(analyzers),
        "caveat": "Role labels are path heuristics. Counts describe discovered/captured inputs, not the entire repository when discovery is incomplete, production LOC, test coverage or quality.",
    }
    if skipped:
        gaps.append(
            f"Source capture omitted {len(skipped)} regular input(s); exact paths/reasons are in facts.collection.skipped_inputs"
        )
    facts["maintainability"] = {
        "method": "static_review_hints",
        "forwarding_functions": facts["python"]["forwarding_functions"],
        "abstract_classes": facts["python"]["abstract_classes"],
        "caveat": "Python hints identify review candidates, not needless complexity. Useful delegation and dependency injection produce the same patterns; review their purpose before recommending changes.",
    }
    gaps.extend(f"Excluded {count} {kind}" for kind, count in sorted(excluded.items()))
    gaps.extend(
        f"Unsupported file kind {kind}: {count} file(s)"
        for kind, count in sorted(unsupported.items())
    )
    if not any(kind in {"junit", "cobertura", "test-value"} for kind in report_kinds):
        gaps.append(
            "No runtime test or coverage reports supplied; execution, coverage and flakiness are unknown"
        )
    if reports:
        gaps.append(
            "Supplied reports have no independently verified source identity; overlapping reports may duplicate cases or coverage"
        )
    if revision is not None and git_snapshot is None:
        gaps.append(
            "Git clean/dirty status is unknown; the content manifest identifies assessed worktree bytes"
        )
    gaps.append(
        "Source inspection does not establish live deployment controls or production behavior"
    )
    if facts["javascript"]["files"]:
        gaps.append("JavaScript/TypeScript counts are lexical estimates, not semantic analysis")
    # Core collection has finished, including documentation, supplied reports and
    # its cooperative deadline check. Explicit external work cannot consume that
    # budget or starve another analyzer. Each provider enforces its own hard cap.
    for name in dedicated:
        result = _redact_data(
            run_analyzer(
                name,
                captured_rows,
                snapshot=snapshot_identity,
                redact=_redact,
                analysis_profile=budget.name,
                deadline=None,
            )
        )
        attach_source_windows(
            [result],
            captured_sources,
            evidence,
            _redact,
            max(0, MAX_STATIC_EVIDENCE_BYTES - context_bytes_used),
        )
        context_bytes_used += result["source_context"]["retained_bytes"]
        optional_analyses[name] = result
        add_optional_evidence(name, result)
    if budget.name == "deep":
        from .change_history import collect_change_history

        prefix, environment = _git_configuration(
            Path(git_snapshot["repository"]) if git_snapshot else root
        )
        history = _redact_data(
            collect_change_history(
                prefix,
                environment,
                {entry["path"] for entry in manifest},
                revision,
                tip=revision if git_snapshot else "HEAD",
            )
        )
        history_id = add_evidence(
            "<change-history>",
            json.dumps(history, sort_keys=True).encode(),
            "change-history",
            "",
            history,
        )
        facts["change_history"] = {
            key: history[key] for key in ("version", "status", "coverage", "gaps", "caveat")
        }
        facts["change_history"]["evidence_id"] = history_id
    burden = _redact_data(
        summarize_burden({"evidence": evidence, "facts": facts}, limit=budget.burden_leads)
    )
    burden_id = add_evidence(
        "<burden-analysis>",
        json.dumps(burden, sort_keys=True).encode(),
        "burden-analysis",
        "",
        burden,
    )
    facts["burden_analysis"] = {
        key: burden[key] for key in ("version", "coverage", "gaps", "caveat")
    }
    facts["burden_analysis"]["evidence_id"] = burden_id
    from .review_plan import VERSION as review_plan_version

    scope = {
        "collector_version": 12,
        "review_plan_version": review_plan_version,
        "burden_analysis_version": burden["version"],
        "control_inventory_version": controls["version"],
        "control_signal_limit": controls["limits"]["signals"],
        "rubric_version": RUBRIC_VERSION,
        "max_files": MAX_FILES,
        "max_file_bytes": MAX_FILE_BYTES,
        "max_source_file_bytes": MAX_SOURCE_FILE_BYTES,
        "analysis_profile": budget.name,
        "budgets": configured_limits,
        "analyzers": list(analyzers),
        "max_total_bytes": budget.supported_text_bytes,
        "max_unsupported_asset_bytes": budget.unsupported_asset_bytes,
        "max_depth": MAX_DEPTH,
        "max_reports": MAX_REPORTS,
        "max_test_value_report_bytes": MAX_TEST_VALUE_REPORT_BYTES,
        "max_test_value_report_total_bytes": MAX_TEST_VALUE_REPORT_TOTAL_BYTES,
        "max_static_evidence_bytes": MAX_STATIC_EVIDENCE_BYTES,
        "max_static_definitions": MAX_STATIC_DEFINITIONS,
        "max_detail_per_file": budget.pattern_functions_per_file,
        "max_static_symbols": budget.pattern_functions,
        "capture_priority": "supported-text-first-v2",
        "max_git_output_bytes": MAX_GIT_OUTPUT_BYTES,
        "selection_mode": selection_mode,
        "excluded_dirs": sorted(_SKIP_DIRS | _SECRET_DIRS),
        "excluded_secret_names": sorted(_SECRET_NAMES),
        "supported_source_kinds": [
            "python",
            "javascript",
            "source",
            "documentation",
            "manifest",
            "configuration",
        ],
        "report_kinds": sorted(set(report_kinds)),
        "python": "ast",
        "static_analysis": {
            "version": STATIC_VERSION,
            "limits": facts["static_analysis"]["limits"],
        },
        "test_value_static": {"schema": static_tool.SCHEMA, "version": static_tool.VERSION},
        "javascript": "lexical",
        "javascript_analysis": javascript_analyzer_identity(),
        "source_analysis": {
            "version": generic_analysis["analyzer"]["version"],
            "limits": generic_analysis["limits"],
        },
        "optional_analysis": {
            name: {key: result[key] for key in ("analyzer", "configuration", "limits")}
            for name, result in optional_analyses.items()
        },
        "documentation": "doc-value.captured.v2",
        "change_history": {
            "version": "1",
            "max_commits": 30,
            "first_parent": True,
            "max_bytes": 524288,
        }
        if budget.name == "deep"
        else None,
        "ecosystem_fit": {"version": ECOSYSTEM_VERSION, "limits": ecosystem["limits"]},
    }
    return {
        "schema_version": 1,
        "rubric_version": RUBRIC_VERSION,
        "tool_provenance": {
            **tool_info(),
            "collection": {
                "analysis_profile": budget.name,
                "limits": configured_limits,
                "analyzers": list(analyzers),
            },
        },
        "source": {
            "root": str(root),
            "revision": revision,
            "manifest_digest": _digest(sorted(manifest, key=lambda item: item["path"])),
            "dirty": dirty,
        },
        "scope_digest": _digest(scope),
        "facts": facts,
        "evidence": sorted(evidence, key=lambda item: (item["path"], item["id"])),
        "gaps": sorted(set(gaps)),
        "findings": findings,
        "complete": complete,
    }
