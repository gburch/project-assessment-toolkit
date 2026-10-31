"""Fast, read-only static leads for test-value review.

This module intentionally stops short of deciding whether a test is redundant.
It indexes bounded source facts (including unknowns) so a reviewer can select a
small, high-value follow-up set before spending time on coverage collection.
It never imports or executes the assessed project.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = "test-value-static.v1"
VERSION = "2"
MAX_FILES = 2_000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 64_000_000
MAX_REPORT_BYTES = 4_000_000
SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
SKIP_PARTS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "coverage",
    "htmlcov",
    "vendor",
    ".tox",
}
_CALLS = {
    "popen",
    "process",
    "subprocess",
    "docker",
    "browser",
    "playwright",
    "selenium",
    "repository",
    "repo",
    "client",
    "sqlite3",
    "connect",
    "request",
    "requests",
    "git",
}
_UNITTEST_METHODS = frozenset(
    {
        "assertAlmostEqual",
        "assertCountEqual",
        "assertDictEqual",
        "assertEqual",
        "assertFalse",
        "assertGreater",
        "assertGreaterEqual",
        "assertIn",
        "assertIs",
        "assertIsInstance",
        "assertIsNone",
        "assertIsNot",
        "assertIsNotNone",
        "assertLess",
        "assertLessEqual",
        "assertListEqual",
        "assertLogs",
        "assertMultiLineEqual",
        "assertNoLogs",
        "assertNotAlmostEqual",
        "assertNotEqual",
        "assertNotIn",
        "assertNotIsInstance",
        "assertNotRegex",
        "assertRaises",
        "assertRaisesRegex",
        "assertRegex",
        "assertSequenceEqual",
        "assertSetEqual",
        "assertTrue",
        "assertTupleEqual",
        "assertWarns",
        "assertWarnsRegex",
    }
)


def _digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _module_digest() -> str:
    return _digest_bytes(Path(__file__).read_bytes())


def _git_identity(root: Path) -> dict[str, Any]:
    try:
        revision = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = None
    return {"revision": revision}


def _safe_scope(root: Path, raw: str) -> Path:
    lexical = (root / raw) if not Path(raw).is_absolute() else Path(raw)
    if any(part.is_symlink() for part in [lexical, *lexical.parents] if part.exists()):
        # Resolve only after rejecting links; a link that happens to remain
        # within root is still an unstable selection for a reproducible audit.
        raise ValueError(f"symlink scope is not allowed: {raw}")
    candidate = lexical.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"scope escapes --root: {raw}") from exc
    if not candidate.exists():
        raise ValueError(f"scope does not exist: {raw}")
    if candidate.is_symlink():
        raise ValueError(f"symlink scope is not allowed: {raw}")
    return candidate


def _files(root: Path, scopes: list[str]) -> tuple[list[Path], list[dict[str, str]]]:
    selected: list[Path] = []
    gaps: list[dict[str, str]] = []
    seen: set[Path] = set()
    for raw in scopes:
        if len(selected) >= MAX_FILES:
            gaps.append({"path": raw, "reason": "file-bound-exceeded"})
            break
        scope = _safe_scope(root, raw)
        if scope.is_file():
            paths = [scope]
        else:
            paths = []
            for directory, directories, filenames in os.walk(
                scope, topdown=True, followlinks=False
            ):
                # Prune before descent. This is important for large node_modules
                # and virtual environments: do not enumerate their contents just
                # to discard them after the fact.
                kept: list[str] = []
                for name in sorted(directories):
                    child = Path(directory) / name
                    if name in SKIP_PARTS:
                        continue
                    if child.is_symlink():
                        gaps.append(
                            {"path": str(child.relative_to(root)), "reason": "symlink-skipped"}
                        )
                        continue
                    kept.append(name)
                directories[:] = kept
                for name in sorted(filenames):
                    if Path(name).suffix.lower() not in SOURCE_EXTENSIONS:
                        continue
                    if len(paths) >= MAX_FILES:
                        gaps.append(
                            {
                                "path": str(Path(directory).relative_to(root)),
                                "reason": "file-bound-exceeded",
                            }
                        )
                        break
                    paths.append(Path(directory) / name)
                if len(paths) >= MAX_FILES:
                    break
        for path in paths:
            if path in seen or not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            seen.add(path)
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            if any(part in SKIP_PARTS for part in relative_parts):
                continue
            if path.is_symlink():
                gaps.append({"path": str(path.relative_to(root)), "reason": "symlink-skipped"})
                continue
            if len(selected) >= MAX_FILES:
                gaps.append({"path": str(path.relative_to(root)), "reason": "file-bound-exceeded"})
                break
            selected.append(path)
    return selected, gaps


def _span(node: ast.AST) -> dict[str, int]:
    return {
        "line": int(getattr(node, "lineno", 0)),
        "endLine": int(getattr(node, "end_lineno", getattr(node, "lineno", 0))),
    }


def _literal_count(node: ast.AST) -> tuple[int | None, bool]:
    """Return known number of cases and whether the value is dynamically unknown."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        if any(isinstance(item, ast.Starred) for item in node.elts):
            return None, True
        return len(node.elts), False
    if isinstance(node, ast.Dict):
        return len(node.keys), any(key is None for key in node.keys)
    if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp)):
        return None, True
    return None, True


def _decorator_name(node: ast.AST) -> str | None:
    """Only names and attributes are safe metadata; receivers may contain secrets."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _decorator_info(node: ast.AST) -> tuple[int, bool, list[str]]:
    count = 1
    dynamic = False
    names: list[str] = []
    decorators = getattr(node, "decorator_list", [])
    for decorator in decorators:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        dotted = _decorator_name(target)
        if dotted is None:
            if isinstance(target, ast.Attribute) and target.attr in {"parametrize", "parameterize"}:
                dynamic = True
            continue
        if dotted.endswith("parametrize") or dotted.endswith("parameterize"):
            names.append(dotted)
            if isinstance(decorator, ast.Call):
                values = (
                    decorator.args[1]
                    if len(decorator.args) >= 2
                    else next(
                        (
                            keyword.value
                            for keyword in decorator.keywords
                            if keyword.arg in {"argvalues", "values"}
                        ),
                        None,
                    )
                )
                if values is None:
                    dynamic = True
                    continue
                size, unknown = _literal_count(values)
                dynamic |= unknown
                if size is not None:
                    count *= size
    return count, dynamic, names


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return "call"


def _range_count(node: ast.Call) -> tuple[int | None, bool]:
    if (
        node.args
        and len(node.args) <= 3
        and all(
            isinstance(argument, ast.Constant) and isinstance(argument.value, int)
            for argument in node.args
        )
    ):
        try:
            return len(range(*(int(argument.value) for argument in node.args))), False
        except (OverflowError, ValueError):
            return None, True
    return None, True


def _body_hash(node: ast.AST) -> str:
    body = getattr(node, "body", [])
    normalized = ast.dump(ast.Module(body=body, type_ignores=[]), annotate_fields=True)
    return _digest_bytes(normalized.encode())


def _python_file(
    path: Path, root: Path, text: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, list[str]]]:
    relative = str(path.relative_to(root))
    try:
        tree = ast.parse(text, filename=relative)
    except SyntaxError as exc:
        return [], [{"path": relative, "reason": "python-parse-error", "detail": str(exc.msg)}], {}
    return python_rows(path, root, tree)


def _assertion_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef):
    """Attribute check syntax to its own body, excluding nested callable/class scopes."""
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def python_rows(
    path: Path, root: Path, tree: ast.Module
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, list[str]]]:
    """Index a captured AST without reading files, parsing again or executing source."""
    relative = str(path.relative_to(root))
    rows: list[dict[str, Any]] = []
    hashes: dict[str, list[str]] = defaultdict(list)

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.parents: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.parents.append(node.name)
            self.generic_visit(node)
            self.parents.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._function(node)

        def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            qualified = "::".join([relative, *self.parents, node.name])
            case_count, dynamic, decorators = _decorator_info(node)
            assertions = list(ast.walk(node))
            assert_nodes, unittest_methods = [], []
            for item in _assertion_nodes(node):
                if isinstance(item, ast.Assert):
                    assert_nodes.append(item)
                elif (
                    isinstance(item, ast.Call)
                    and isinstance(item.func, ast.Attribute)
                    and isinstance(item.func.value, ast.Name)
                    and item.func.value.id == "self"
                    and item.func.attr in _UNITTEST_METHODS
                ):
                    unittest_methods.append(item.func.attr)
            setup_leads: list[dict[str, Any]] = []
            for item in assertions:
                if isinstance(item, (ast.For, ast.AsyncFor)):
                    size, unknown = _literal_count(item.iter)
                    if isinstance(item.iter, ast.Call) and _call_name(item.iter) == "range":
                        size, unknown = _range_count(item.iter)
                    if unknown or (size is not None and size >= 10):
                        setup_leads.append(
                            {"kind": "loop", "span": _span(item), "iterations": size}
                        )
                elif isinstance(item, ast.Call):
                    raw_name = _call_name(item)
                    name = raw_name.lower()
                    if (
                        name in _CALLS
                        or name in {"__init__"}
                        or (raw_name[:1].isupper() and len(raw_name) > 2)
                    ):
                        setup_leads.append(
                            {"kind": "expensive-call", "span": _span(item), "name": raw_name}
                        )
            shapes = sorted({type(item.test).__name__ for item in assert_nodes})
            implementation_tokens = {
                "getsource",
                "__dict__",
                "mock_calls",
                "call_args",
                "sql",
                "schema",
            }
            implementation_heavy = any(
                isinstance(item, ast.Name)
                and item.id.lower() in implementation_tokens
                or isinstance(item, ast.Attribute)
                and item.attr.lower() in implementation_tokens
                or isinstance(item, ast.Constant)
                and isinstance(item.value, str)
                and any(token in item.value.lower() for token in implementation_tokens)
                for item in assertions
            )
            row = {
                "id": qualified,
                "kind": "test" if node.name.startswith("test_") else "function",
                "path": relative,
                "span": _span(node),
                "sourceLines": _span(node)["endLine"] - _span(node)["line"] + 1,
                "parameterization": {
                    "literalCases": case_count,
                    "dynamic": dynamic,
                    "decorators": decorators,
                },
                "assertions": {
                    "count": len(assert_nodes),
                    "countBasis": "bare_ast_assert",
                    "attribution": "own_function_body_excluding_nested_scopes",
                    "unittestStyleCallCount": len(unittest_methods),
                    "unittestStyleMethods": sorted(set(unittest_methods)),
                    "unittestStyleCallBasis": "known_self_method_syntax_binding_and_execution_unverified",
                    "otherCheckStyles": "unknown",
                    "shapes": shapes,
                    "implementationHeavyLead": implementation_heavy,
                },
                "setupLeads": setup_leads,
                "bodySignature": _body_hash(node),
            }
            rows.append(row)
            hashes[row["bodySignature"]].append(qualified)
            self.parents.append(node.name)
            self.generic_visit(node)
            self.parents.pop()

    Visitor().visit(tree)
    return rows, [], hashes


def summarize_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build indexed, advisory groups and leads from static rows.

    Body signatures intentionally do not establish equivalence. Every repeated
    body is marked binding-ambiguous: imports, parameters, decorators, fixtures,
    and surrounding namespace are not represented by the body hash alone.
    """
    body_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        signature = row.get("bodySignature")
        if signature:
            body_index[str(signature)].append(row)
    groups: list[dict[str, Any]] = []
    for signature, members in body_index.items():
        if len(members) < 2:
            continue
        member_ids = [str(item["id"]) for item in members]
        test_members = [str(item["id"]) for item in members if item.get("kind") == "test"]
        groups.append(
            {
                "signature": signature,
                "members": member_ids,
                "memberCount": len(member_ids),
                "testMembers": test_members,
                "category": "test-bodies" if len(test_members) > 1 else "helper-bodies",
                "bindingAmbiguous": True,
                "recommendation": "investigate",
            }
        )
    candidates: list[dict[str, Any]] = [
        {
            "kind": "shared-python-body",
            "members": group["members"],
            "memberCount": group["memberCount"],
            "bindingAmbiguous": True,
            "recommendation": "investigate",
        }
        for group in groups
        if group["category"] == "test-bodies"
    ]
    candidates.extend(
        {"kind": "test-static-lead", "id": row["id"], "recommendation": "investigate"}
        for row in rows
        if row.get("kind") == "test"
        and (
            row["parameterization"]["dynamic"]
            or row["parameterization"]["literalCases"] not in (None, 1)
            or row["setupLeads"]
            or row["assertions"]["implementationHeavyLead"]
        )
    )
    candidates.extend(
        {
            "kind": "javascript-matrix-lead",
            "id": row["id"],
            "matrix": row["matrix"],
            "confidence": "low",
            "recommendation": "investigate",
        }
        for row in rows
        if row.get("kind") == "js-matrix"
    )
    return groups, candidates


def _mask_js(text: str) -> str:
    result = list(text)
    i = 0
    quote: str | None = None
    while i < len(result):
        if quote:
            if result[i] == "\\":
                result[i] = " "
                if i + 1 < len(result):
                    result[i + 1] = " "
                    i += 2
                    continue
            elif result[i] == quote:
                result[i] = " "
                quote = None
            else:
                result[i] = "\n" if result[i] == "\n" else " "
            i += 1
            continue
        if result[i] in "'\"`":
            quote = result[i]
            # Keep one opaque token for the literal so a string-valued matrix
            # row remains countable, without leaking its contents.
            result[i] = "x"
            i += 1
        elif result[i : i + 2] == ["/", "/"]:
            while i < len(result) and result[i] != "\n":
                result[i] = " "
                i += 1
        elif result[i : i + 2] == ["/", "*"]:
            result[i : i + 2] = [" ", " "]
            i += 2
            while i + 1 < len(result) and result[i : i + 2] != ["*", "/"]:
                result[i] = "\n" if result[i] == "\n" else " "
                i += 1
            if i + 1 < len(result):
                result[i : i + 2] = [" ", " "]
                i += 2
        else:
            i += 1
    return "".join(result)


def _balanced_end(masked: str, start: int) -> int | None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for index in range(start, len(masked)):
        char = masked[index]
        if char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if not stack or stack.pop() != char:
                return None
            if not stack:
                return index
    return None


def _array_count(value: str) -> int | None:
    text = value.strip()
    if not text.startswith("["):
        return None
    if text.startswith("[...") or "..." in text:
        return None
    depth = 0
    items = 0
    has_value = False
    for char in text[1:-1]:
        if char in "[{(":
            depth += 1
            has_value = True
        elif char in "]})":
            depth -= 1
        elif char == "," and depth == 0:
            if has_value:
                items += 1
                has_value = False
        elif not char.isspace() and char != "x":
            # x is the opaque marker for a quoted string; it is still a value.
            has_value = True
        elif char == "x":
            has_value = True
    return items + (1 if has_value else 0)


def _first_js_argument(value: str) -> str:
    depth = 0
    for index, char in enumerate(value):
        if char in "[{(":
            depth += 1
        elif char in "]})":
            depth -= 1
        elif char == "," and depth == 0:
            return value[:index]
    return value


def _js_file(
    path: Path, root: Path, text: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    relative = str(path.relative_to(root))
    masked = _mask_js(text)
    rows: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    pattern = re.compile(r"\b(?:it|test|describe)\s*\(")
    for match in pattern.finditer(masked):
        end = _balanced_end(masked, match.end() - 1)
        if end is None:
            gaps.append({"path": relative, "reason": "javascript-unbalanced-registration"})
            continue
        line = masked.count("\n", 0, match.start()) + 1
        end_line = masked.count("\n", 0, end) + 1
        rows.append(
            {
                "id": f"{relative}:{line}:registration",
                "kind": "js-registration",
                "path": relative,
                "span": {"line": line, "endLine": end_line},
                "confidence": "low",
            }
        )
    each_pattern = re.compile(r"\.each\s*\(")
    for match in each_pattern.finditer(masked):
        end = _balanced_end(masked, match.end() - 1)
        if end is None:
            gaps.append({"path": relative, "reason": "javascript-unbalanced-each"})
            continue
        argument = _first_js_argument(masked[match.end() : end])
        rows.append(
            {
                "id": f"{relative}:{masked.count(chr(10), 0, match.start()) + 1}:matrix",
                "kind": "js-matrix",
                "path": relative,
                "span": {
                    "line": masked.count("\n", 0, match.start()) + 1,
                    "endLine": masked.count("\n", 0, end) + 1,
                },
                "confidence": "low",
                "matrix": {
                    "literalCases": _array_count(argument),
                    "dynamic": _array_count(argument) is None,
                },
            }
        )
    return rows, gaps


def analyze(root: Path, scopes: list[str]) -> dict[str, Any]:
    root = root.resolve()
    paths, gaps = _files(root, scopes)
    rows: list[dict[str, Any]] = []
    source_hashes: dict[str, str] = {}
    total_bytes = 0
    for path in paths:
        relative = str(path.relative_to(root))
        try:
            # Bound the read itself, including a file that grows after inventory.
            with path.open("rb") as source:
                data = source.read(min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total_bytes) + 1)
        except OSError as exc:
            gaps.append({"path": relative, "reason": "read-error", "detail": str(exc)})
            continue
        if len(data) > MAX_FILE_BYTES or total_bytes + len(data) > MAX_TOTAL_BYTES:
            gaps.append({"path": relative, "reason": "size-bound-exceeded"})
            continue
        total_bytes += len(data)
        source_hashes[relative] = _digest_bytes(data)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            gaps.append({"path": relative, "reason": "non-utf8-source"})
            continue
        if path.suffix.lower() == ".py":
            found, found_gaps, _ = _python_file(path, root, text)
            rows.extend(found)
            gaps.extend(found_gaps)
        else:
            found, found_gaps = _js_file(path, root, text)
            rows.extend(found)
            gaps.extend(found_gaps)
    groups, candidates = summarize_rows(rows)
    report = {
        "schema": SCHEMA,
        "generatedAt": datetime.now(UTC).isoformat(),
        "tool": {
            "module": "project_assess.test_value.static",
            "adapterVersion": VERSION,
            "moduleDigest": _module_digest(),
            "python": sys.version.split()[0],
        },
        "provenance": {
            "root": str(root),
            "scopes": scopes,
            "sourceHashes": source_hashes,
            "sourceBytes": total_bytes,
            **_git_identity(root),
        },
        "counts": {
            "files": len(source_hashes),
            "definitions": len(rows),
            "groups": len(groups),
            "candidates": len(candidates),
            "gaps": len(gaps),
        },
        "definitions": rows,
        "groups": groups,
        "candidates": candidates,
        "gaps": gaps,
    }
    return _compact_report(report)


def _compact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Keep default JSON useful and bounded while preserving total counts."""
    sections = ("definitions", "groups", "candidates")
    report["counts"].update({f"{name}Total": len(report[name]) for name in sections})
    report["omissions"] = {
        name: {"total": len(report[name]), "included": len(report[name]), "omitted": 0}
        for name in sections
    }
    report["omissions"]["compact"] = {
        "maxBytes": MAX_REPORT_BYTES,
        "reason": "bounded default report; use narrower scopes for complete detail",
    }
    # Preserve likely actionable rows first. Definitions are ordered by kind and
    # setup/parameterization signal; group and lead indexes are independently
    # useful, so they are retained until size pressure requires trimming.
    report["definitions"] = sorted(
        report["definitions"],
        key=lambda row: (
            row.get("kind") != "test",
            not bool(row.get("setupLeads")),
            -int(row.get("parameterization", {}).get("literalCases") or 0),
            not bool(row.get("parameterization", {}).get("dynamic")),
            -int(row.get("sourceLines", 0)),
        ),
    )
    report["groups"] = sorted(
        report["groups"],
        key=lambda row: (row.get("category") != "test-bodies", -int(row.get("memberCount", 0))),
    )
    report["candidates"] = sorted(report["candidates"], key=lambda row: row.get("kind", ""))
    while len(json.dumps(report, sort_keys=True, separators=(",", ":"))) + 1 > MAX_REPORT_BYTES:
        largest = max(
            sections, key=lambda name: len(json.dumps(report[name], separators=(",", ":")))
        )
        values = report[largest]
        if not values:
            raise ValueError("static report identity exceeds output bound; use narrower scopes")
        keep = len(values) // 2
        report[largest] = values[:keep]
        report["omissions"][largest] = {
            "total": report["counts"][f"{largest}Total"],
            "included": keep,
            "omitted": report["counts"][f"{largest}Total"] - keep,
        }
    return report


def write_report(report: dict[str, Any], output: Path, root: Path) -> Path:
    output = output.expanduser().resolve()
    root = root.resolve()
    if output == root or root in output.parents:
        raise ValueError("--output must be outside --root")
    if output.exists() and output.is_dir():
        output = output / "inventory.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return output
