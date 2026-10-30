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
from collections import Counter
from pathlib import Path

from .rubric import RUBRIC_VERSION
from .static_analysis import MAX_FILES as MAX_STATIC_FILES
from .static_analysis import MAX_SYMBOLS as MAX_STATIC_SYMBOLS
from .static_analysis import VERSION as STATIC_VERSION
from .static_analysis import analyze_python, ruff_report
from .static_analysis import summarize as summarize_static
from .test_value.assessment import summarize as summarize_test_value

MAX_FILES = 20_000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_REPORTS = 32
MAX_TEST_VALUE_REPORT_BYTES = 16 * 1024 * 1024
MAX_TEST_VALUE_REPORT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_STATIC_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_STATIC_DEFINITIONS = 2000
MAX_DEPTH = 64
MAX_EXCERPT = 800
MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024
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
_JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
_CONFIG = {".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".tf", ".sh"}
_SECRET_LINE = re.compile(
    r"(?i)(?:api[_-]?key|secret|password|passwd|credential|authorization|access[_-]?token|auth[_-]?token|token)"
    r"[\w\s\-\"']*\s*[:=]"
)
_TOKEN = re.compile(
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"|sk[-_][A-Za-z0-9_-]{16,}|(?i:bearer)\s+[A-Za-z0-9._~+/-]{8,}"
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
    if suffix in {".md", ".mdx", ".rst"} or name.startswith(("readme", "license")):
        return "documentation"
    if name in {"package.json", "pyproject.toml", "requirements.txt"}:
        return "manifest"
    if suffix in _CONFIG or name in {"dockerfile", ".gitignore", "makefile"}:
        return "configuration"
    return None


def _is_test(path):
    parts, stem = {p.lower() for p in path.parts}, path.stem.lower()
    return bool(parts & {"test", "tests", "__tests__", "spec", "specs"}) or (
        stem.startswith("test_") or stem.endswith(("_test", ".test", ".spec"))
    )


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


def _static_value_analysis(root, source_rows, manifest, revision):
    """Summarize bounded rows prepared from the collector's existing AST/text."""
    from .test_value import static as static_tool

    max_definitions, max_groups, max_candidates, max_gaps = MAX_STATIC_DEFINITIONS, 256, 512, 128
    rows, gaps = [], []
    for _, prepared in sorted(source_rows.items()):
        rows.extend(prepared["rows"])
        gaps.extend(prepared["gaps"])

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
        return {
            "ecosystem": "javascript",
            "dependencies": len(groups[0]),
            "dev_dependencies": len(groups[1]),
            "scripts": sorted(groups[2]),
        }
    if path.name == "pyproject.toml":
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
        return {
            "ecosystem": "python",
            "dependencies": len(dependencies),
            "dev_dependencies": sum(
                len(v) for key, v in optional.items() if key in {"dev", "test", "tests", "testing"}
            ),
            "scripts": sorted(scripts),
        }
    return {
        "ecosystem": "python",
        "dependencies": sum(
            bool(line.strip()) and not line.lstrip().startswith(("#", "-"))
            for line in text.splitlines()
        ),
        "dev_dependencies": 0,
        "scripts": [],
    }


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


def collect(root: Path, reports: list[Path] | None = None) -> dict:
    """Collect facts without running target code or changing target files.

    ``complete`` means collection finished within its declared scope. It does not
    certify runtime behavior; excluded and unsupported inputs remain visible gaps.
    """
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
    documentation_texts, python_analysis = {}, []
    source_rows = {}
    static_symbols, value_definitions = 0, 0
    gaps, excluded, unsupported = [], Counter(), Counter()
    complete, visited, total = True, 0, 0
    revision, dirty = _git(root)
    selected, selection_mode, selection_gap, selection_failed = _git_inventory(root)
    if selection_gap:
        gaps.append(selection_gap)
    complete = not selection_failed
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
        return entry["id"]

    def walk(directory, relative, depth):
        nonlocal complete, visited, total, static_symbols, value_definitions
        if depth > MAX_DEPTH:
            gaps.append("Directory depth limit exceeded")
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
                        complete = False
                        return
                names.sort()
        except OSError:
            gaps.append("Unable to list a source directory")
            complete = False
            return
        for name in names:
            if visited >= MAX_FILES or total >= MAX_TOTAL_BYTES:
                gaps.append("Repository file or total byte limit exceeded")
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
                        excluded[
                            "dependency/build/VCS directories"
                            if name in _SKIP_DIRS
                            else "credential directories"
                        ] += 1
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
                # A supplied report is handled below by its dedicated bounded
                # parser.  Do not also treat its JSON as project source, which
                # could expose test identities or report output in evidence.
                if os.path.normpath(str(root / path)) in supplied_report_paths:
                    continue
                if _secret_name(name):
                    excluded["credential files"] += 1
                    continue
                kind = _kind(path)
                payload, fingerprint = _read_at(
                    directory, name, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total)
                )
                watched.append((str(path), fingerprint))
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
                    continue
                try:
                    text = payload.decode("utf-8")
                except UnicodeDecodeError:
                    gaps.append("Unsupported non-UTF-8 input: " + path.as_posix())
                    complete = False
                    continue
                if "\x00" in text:
                    gaps.append("Unsupported binary input: " + path.as_posix())
                    complete = False
                    continue
                stats = {}
                inventory = facts["inventory"]
                inventory["files"] += 1
                inventory["bytes"] += len(payload)
                inventory["lines"] += len(text.splitlines())
                if kind in {"python", "javascript"}:
                    inventory["source_files"] += 1
                    inventory["test_files"] += _is_test(path)
                    facts[kind]["files"] += 1
                    if kind == "python":
                        stats, tree = _python(text)
                        if (
                            len(python_analysis) < MAX_STATIC_FILES
                            and static_symbols < MAX_STATIC_SYMBOLS
                        ):
                            record = analyze_python(path.as_posix(), tree)
                            remaining = MAX_STATIC_SYMBOLS - static_symbols
                            symbols = len(record["functions"]) + len(record["imports"])
                            if symbols > remaining:
                                record["functions"] = record["functions"][:remaining]
                                remaining -= len(record["functions"])
                                record["imports"] = record["imports"][:remaining]
                                record["gaps"].append("Project static symbol limit reached")
                            static_symbols += len(record["functions"]) + len(record["imports"])
                            python_analysis.append(record)
                    else:
                        stats = _javascript(text)
                    if (
                        len(source_rows) < MAX_STATIC_FILES
                        and value_definitions < MAX_STATIC_DEFINITIONS
                    ):
                        from .test_value import static as static_tool

                        try:
                            if kind == "python":
                                found, found_gaps, _ = static_tool.python_rows(
                                    root / path, root, tree
                                )
                            else:
                                found, found_gaps = static_tool._js_file(root / path, root, text)
                                found_gaps.append(
                                    {
                                        "path": path.as_posix(),
                                        "reason": "javascript-lexical-analysis-not-parse-proof",
                                    }
                                )
                        except (TypeError, ValueError, SyntaxError, RecursionError):
                            found, found_gaps = (
                                [],
                                [{"path": path.as_posix(), "reason": "static-analysis-error"}],
                            )
                        remaining = MAX_STATIC_DEFINITIONS - value_definitions
                        if len(found) > remaining:
                            found_gaps.append(
                                {"path": path.as_posix(), "reason": "static-definition-limit"}
                            )
                        found = found[:remaining]
                        for row in found:
                            if len(row.get("setupLeads", [])) > 32:
                                row["setupLeadCount"] = len(row["setupLeads"])
                                row["setupLeads"] = row["setupLeads"][:32]
                                found_gaps.append(
                                    {"path": path.as_posix(), "reason": "static-setup-lead-limit"}
                                )
                        value_definitions += len(found)
                        source_rows[path.as_posix()] = {"rows": found, "gaps": found_gaps}
                    else:
                        gaps.append(
                            "Test-value static input limit reached; remaining inputs were not analyzed"
                        )
                    for key, value in stats.items():
                        facts[kind][key] += value
                    stats["is_test"] = _is_test(path)
                elif kind == "documentation":
                    documentation_texts[path.as_posix()] = text
                    stats = _documentation(text)
                    inventory["documentation_files"] += 1
                    facts["documentation"]["files"] += 1
                    facts["documentation"]["lines"] += len(text.splitlines())
                    for key, value in stats.items():
                        facts["documentation"][key] += value
                elif kind == "manifest":
                    stats = _manifest(path, text)
                    manifests = facts["manifests"]
                    manifests["paths"].append(path.as_posix())
                    manifests["ecosystems"].append(stats["ecosystem"])
                    for key in ("dependencies", "dev_dependencies"):
                        manifests[key] += stats[key]
                    manifests["scripts"].extend(stats["scripts"])
                if any(
                    part in {".github", ".circleci", ".ssci"} for part in path.parts
                ) or name in {"Jenkinsfile", ".gitlab-ci.yml"}:
                    facts["ci"]["paths"].append(path.as_posix())
                add_evidence(path.as_posix(), payload, kind, text, stats)
            except (OSError, ValueError, SyntaxError, RecursionError):
                gaps.append("Unable to collect or parse input safely: " + path.as_posix())
                complete = False

    try:
        walk(descriptor, Path("."), 0)
        for path, expected in watched:
            try:
                current = os.stat(path, dir_fd=descriptor, follow_symlinks=False)
                if _fingerprint(current) != expected:
                    raise ValueError("changed")
            except (OSError, ValueError):
                gaps.append("Source changed during collection")
                complete = False
                break
    finally:
        os.close(descriptor)
    if source_rows:
        try:
            analysis = _redact_data(_static_value_analysis(root, source_rows, manifest, revision))
            for key in ("definitions", "groups", "candidates", "gaps"):
                analysis["bounded"][key] = len(analysis[key]) == analysis["counts"][key]
            analysis["bounded"]["output"] = False
            payload = json.dumps(analysis, sort_keys=True).encode()
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
                            payload = json.dumps(analysis, sort_keys=True).encode()
                            if len(payload) <= MAX_STATIC_EVIDENCE_BYTES:
                                break
                    if not changed:
                        break
                if truncated:
                    analysis["gaps"].append(truncation_gap)
                    analysis["bounded"]["gaps"] = False
                    payload = json.dumps(analysis, sort_keys=True).encode()
                if len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                    if not truncated:
                        analysis["gaps"].append(truncation_gap)
                        analysis["bounded"]["gaps"] = False
                    for key in ("definitions", "groups", "candidates"):
                        analysis[key] = []
                        analysis["bounded"][key] = False
                    payload = json.dumps(analysis, sort_keys=True).encode()
                    if len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                        analysis["gaps"] = [truncation_gap]
                        analysis["bounded"]["gaps"] = False
                        payload = json.dumps(analysis, sort_keys=True).encode()
            # Serialize only after all flags and explicit truncation gaps are
            # finalized; the stored digest and stats must describe one payload.
            analysis["bounded"]["output"] = False
            payload = json.dumps(analysis, sort_keys=True).encode()
            if len(payload) <= MAX_STATIC_EVIDENCE_BYTES:
                analysis["bounded"]["output"] = True
                payload = json.dumps(analysis, sort_keys=True).encode()
                if len(payload) > MAX_STATIC_EVIDENCE_BYTES:
                    analysis["bounded"]["output"] = False
                    payload = json.dumps(analysis, sort_keys=True).encode()
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
    analysis = summarize_static(
        python_analysis, facts["python"]["files"], facts["javascript"]["files"]
    )
    payload = json.dumps(analysis, sort_keys=True).encode()
    evidence_id = add_evidence("<static-analysis>", payload, "static-analysis", "", analysis)
    facts["static_analysis"] = {
        key: value for key, value in analysis.items() if key != "candidates"
    }
    facts["static_analysis"]["evidence_id"] = evidence_id
    gaps.extend(analysis["gaps"])
    if documentation_texts:
        from .documentation import captured_documentation

        analysis = captured_documentation(
            documentation_texts, {entry["path"] for entry in manifest}
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
    report_kinds = []
    json_report_total = 0
    for path in sorted(reports):
        if any(part.lower() in _SECRET_DIRS or _secret_name(part) for part in path.parts):
            raise ValueError("report path is excluded as credential material")
        # Resolve only to check parent symlinks, then read the original leaf with NOFOLLOW.
        try:
            if path.is_symlink() or path.resolve(strict=True) != path:
                raise ValueError("report path must not contain symlinks")
            report_fd = _open_directory(path.parent)
            try:
                is_json_report = path.suffix.lower() == ".json"
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
        if is_json_report and payload.lstrip().startswith(b"["):
            kind = "ruff"
            stats = ruff_report(payload, root, {entry["path"] for entry in manifest}, _redact)
            gaps.extend(stats["gaps"])
        elif is_json_report:
            try:
                kind, stats = _test_value_report(payload, root, manifest, revision)
            except ValueError as exc:
                gaps.append("Malformed or unsupported test-value report: " + str(exc))
                complete = False
                kind, stats = (
                    "test-value",
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
        # Never expose raw test output or Ruff edit text; retain bounded,
        # redacted diagnostics and summaries from the dedicated adapters.
        add_evidence(str(path), payload, kind, json.dumps(stats, sort_keys=True), stats)
        previous = facts["reports"].setdefault(kind, {"files": 0})
        previous["files"] += 1
        if kind == "ruff":
            previous["diagnostics"] = (
                previous.get("diagnostics", 0) + stats["summary"]["diagnostics"]
            )
        elif kind == "test-value":
            # The adapter already returns bounded nested summaries.  Keep one
            # per supplied artifact; never merge claims as if they were facts.
            previous.setdefault("schemas", []).append(stats.get("schema"))
            previous.setdefault("source_identity", []).append(stats.get("sourceIdentity", {}))
            previous.setdefault("gaps", []).append(stats.get("gaps", {}))
        else:
            for key, value in stats.items():
                previous[key] = previous.get(key, 0) + value
    end_revision, end_dirty = _git(root)
    if (revision, dirty) != (end_revision, end_dirty):
        gaps.append("Git identity changed during collection")
        complete = False
    facts["manifests"]["ecosystems"] = sorted(set(facts["manifests"]["ecosystems"]))
    facts["manifests"]["scripts"] = sorted(set(facts["manifests"]["scripts"]))
    # ``files``/``bytes`` describe recognized text inputs; these totals identify
    # every regular file whose bytes contributed to the source manifest.
    facts["inventory"]["recognized_files"] = facts["inventory"]["files"]
    facts["inventory"]["manifest_files"] = len(manifest)
    facts["inventory"]["manifest_bytes"] = total
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
    if revision is not None:
        gaps.append(
            "Git clean/dirty status is unknown; the content manifest identifies assessed worktree bytes"
        )
    gaps.append(
        "Source inspection does not establish live deployment controls or production behavior"
    )
    if facts["javascript"]["files"]:
        gaps.append("JavaScript/TypeScript counts are lexical estimates, not semantic analysis")
    scope = {
        "collector_version": 4,
        "rubric_version": RUBRIC_VERSION,
        "max_files": MAX_FILES,
        "max_file_bytes": MAX_FILE_BYTES,
        "max_total_bytes": MAX_TOTAL_BYTES,
        "max_depth": MAX_DEPTH,
        "max_reports": MAX_REPORTS,
        "max_test_value_report_bytes": MAX_TEST_VALUE_REPORT_BYTES,
        "max_test_value_report_total_bytes": MAX_TEST_VALUE_REPORT_TOTAL_BYTES,
        "max_static_evidence_bytes": MAX_STATIC_EVIDENCE_BYTES,
        "max_static_definitions": MAX_STATIC_DEFINITIONS,
        "max_git_output_bytes": MAX_GIT_OUTPUT_BYTES,
        "selection_mode": selection_mode,
        "excluded_dirs": sorted(_SKIP_DIRS | _SECRET_DIRS),
        "excluded_secret_names": sorted(_SECRET_NAMES),
        "supported_source_kinds": [
            "python",
            "javascript",
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
        "javascript": "lexical",
        "documentation": "doc-value.captured.v1",
    }
    return {
        "schema_version": 1,
        "rubric_version": RUBRIC_VERSION,
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
