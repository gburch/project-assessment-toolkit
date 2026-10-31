"""Deterministic leads from captured ASTs and explicitly supplied Ruff diagnostics.

No project imports, configuration loading, filesystem discovery or code execution.
The metrics locate review work; they do not establish defects or assign ratings.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from itertools import islice
from pathlib import Path, PurePosixPath

VERSION = "1"
MAX_FILES = 1000
MAX_SYMBOLS = 20_000
MAX_IMPORT_TARGETS = 20_000
MAX_MODULE_LENGTH = 4096
MAX_NODES = 50_000
MAX_FUNCTION_NODES = 6000
MAX_FUNCTIONS = 1000
MAX_CANDIDATES = 100
MAX_DIAGNOSTICS = 200
DECISION_THRESHOLD = 10
NESTING_THRESHOLD = 4
_FUNCTION = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_FUNCTION, ast.ClassDef, ast.Lambda)
_CONTROL = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match)


def _location(path, node):
    return {"path": path, "line": node.lineno, "end_line": node.end_lineno or node.lineno}


def _body(function):
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return body


def _nodes(body):
    stack = [(node, 0, False) for node in reversed(body)]
    while stack:
        node, depth, in_loop = stack.pop()
        yield node, depth, in_loop
        if isinstance(node, _SCOPES):
            continue
        next_depth = depth + isinstance(node, _CONTROL)
        children = []
        for field, value in ast.iter_fields(node):
            repeated = (
                (isinstance(node, (ast.For, ast.AsyncFor)) and field == "body")
                or (isinstance(node, ast.While) and field in {"test", "body"})
                or (
                    isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
                    and field in {"elt", "key", "value"}
                )
                or (isinstance(node, ast.comprehension) and field == "ifs")
            )
            for child in value if isinstance(value, list) else [value]:
                if isinstance(child, ast.AST):
                    children.append((child, next_depth, in_loop or repeated))
        stack.extend(reversed(children))


def _io_call(node):
    if not isinstance(node, ast.Call):
        return False
    target = node.func
    if isinstance(target, ast.Name):
        return target.id in {"open", "urlopen"}
    if isinstance(target, ast.Attribute):
        if target.attr in {"read_text", "read_bytes"}:
            return True
        if isinstance(target.value, ast.Name):
            return (target.value.id, target.attr) in {
                ("subprocess", "run"),
                ("subprocess", "check_output"),
                ("requests", "get"),
                ("requests", "post"),
                ("urllib", "urlopen"),
            }
    return False


def analyze_python(path: str, tree: ast.Module) -> dict:
    """Analyze an already parsed file, preserving literal/callee differences in clones."""
    nodes = list(islice(ast.walk(tree), MAX_NODES + 1))
    record = {"path": path, "functions": [], "imports": [], "gaps": []}
    if len(nodes) > MAX_NODES:
        record["gaps"].append(f"AST node limit reached: {path}")
        return record
    functions = [node for node in nodes if isinstance(node, _FUNCTION)]
    if len(functions) > MAX_FUNCTIONS:
        record["gaps"].append(f"Function limit reached: {path}")
    for function in functions[:MAX_FUNCTIONS]:
        body = _body(function)
        own_nodes = list(islice(_nodes(body), MAX_FUNCTION_NODES + 1))
        if len(own_nodes) > MAX_FUNCTION_NODES:
            record["gaps"].append(f"Function node limit reached: {path}:{function.lineno}")
            continue
        decisions = sum(
            isinstance(
                node,
                (
                    ast.If,
                    ast.IfExp,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.ExceptHandler,
                    ast.comprehension,
                ),
            )
            + (len(node.values) - 1 if isinstance(node, ast.BoolOp) else 0)
            + (max(len(node.cases) - 1, 0) if isinstance(node, ast.Match) else 0)
            for node, _, _ in own_nodes
        )
        nesting = max(
            (depth + isinstance(node, _CONTROL) for node, depth, _ in own_nodes), default=0
        )
        io = [_location(path, node) for node, _, in_loop in own_nodes if in_loop and _io_call(node)]
        # Do not compare stubs/wrappers. Exact ASTs retain arguments, literals,
        # callees, annotations and decorators; only definition names/locations
        # and the leading docstring are omitted. Equality is not safe merge proof.
        fingerprint = None
        if (
            len(body) >= 3
            and len(own_nodes) >= 20
            and not any(isinstance(n, _SCOPES) for n, _, _ in own_nodes)
        ):
            parts = [function.args, function.returns, *function.decorator_list, *body]
            canonical = [
                ast.dump(part, include_attributes=False) if part else None for part in parts
            ]
            fingerprint = hashlib.sha256(
                json.dumps([type(function).__name__, canonical]).encode()
            ).hexdigest()
        record["functions"].append(
            {
                "location": _location(path, function),
                "decisions": decisions,
                "nesting": nesting,
                "loop_io": io[:5],
                "fingerprint": fingerprint,
            }
        )
    stack = [(tree, "eager")]
    while stack:
        node, phase = stack.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            record["imports"].append(
                {
                    "module": node.module if isinstance(node, ast.ImportFrom) else None,
                    "level": node.level if isinstance(node, ast.ImportFrom) else 0,
                    "names": [alias.name for alias in node.names],
                    "phase": phase,
                    "location": _location(path, node),
                }
            )
        child_phase = (
            "deferred"
            if isinstance(node, (*_FUNCTION, ast.Lambda)) and phase != "type_checking"
            else phase
        )
        if isinstance(node, ast.If):
            test = node.test
            type_guard = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            )
            if type_guard:
                stack.extend((child, phase) for child in reversed(node.orelse))
                stack.extend((child, "type_checking") for child in reversed(node.body))
                continue
            child_phase = "conditional" if phase == "eager" else phase
        elif (
            isinstance(node, (ast.Try, ast.For, ast.AsyncFor, ast.While, ast.Match))
            and phase == "eager"
        ):
            child_phase = "conditional"
        stack.extend((child, child_phase) for child in reversed(list(ast.iter_child_nodes(node))))
    return record


def _module(path):
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts and parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _edges(records):
    modules = defaultdict(list)
    for record in records:
        modules[_module(record["path"])].append(record["path"])
    edges, examined, limited = [], 0, False
    depth = max((name.count(".") + 1 for name in modules), default=1)
    for record in records:
        path = record["path"]
        package = _module(path).split(".")
        if PurePosixPath(path).name != "__init__.py":
            package = package[:-1]
        for item in record["imports"]:
            if item["phase"] == "type_checking":
                continue
            base = item["module"]
            if item["level"]:
                if item["level"] > len(package):
                    continue
                base = ".".join(
                    package[: len(package) - item["level"] + 1] + ([base] if base else [])
                )
            if base is not None and len(base) > MAX_MODULE_LENGTH:
                limited = True
                continue
            targets = (
                item["names"]
                if base is None
                else (f"{base}.{name}" if base else name for name in item["names"])
            )
            for target in targets:
                if examined >= MAX_IMPORT_TARGETS:
                    return edges, True
                examined += 1
                if len(target) > MAX_MODULE_LENGTH:
                    limited = True
                    continue
                # Resolve only captured modules, never importlib or sys.path.
                # Captured module depth bounds prefix work even for a hostile
                # import containing thousands of unresolved dotted segments.
                parts = target.split(".", depth)[:depth]
                target = ""
                for end in range(len(parts), 0, -1):
                    prefix = ".".join(parts[:end])
                    if prefix in modules:
                        target = prefix
                        break
                if target in modules and len(modules[target]) == 1:
                    destination = modules[target][0]
                    if destination != path:
                        edges.append(
                            {
                                "source": path,
                                "target": destination,
                                "phase": item["phase"],
                                "line": item["location"]["line"],
                            }
                        )
    return sorted(
        {json.dumps(edge, sort_keys=True): edge for edge in edges}.values(),
        key=lambda row: (row["source"], row["target"], row["line"]),
    ), limited


def _components(paths, edges):
    """Iterative strongly connected components, bounded by captured modules."""
    graph, reverse = defaultdict(set), defaultdict(set)
    for edge in edges:
        graph[edge["source"]].add(edge["target"])
        reverse[edge["target"]].add(edge["source"])
    seen, order = set(), []
    for path in sorted(paths):
        stack = [(path, False)]
        while stack:
            current, done = stack.pop()
            if done:
                order.append(current)
            elif current not in seen:
                seen.add(current)
                stack.append((current, True))
                stack.extend(
                    (child, False)
                    for child in sorted(graph[current], reverse=True)
                    if child not in seen
                )
    seen = set()
    for path in reversed(order):
        if path in seen:
            continue
        group, stack = [], [path]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            group.append(current)
            stack.extend(sorted(reverse[current] - seen, reverse=True))
        if len(group) > 1:
            yield sorted(group)


def _round_robin(groups):
    pending = deque(iter(group) for group in groups)
    while pending:
        group = pending.popleft()
        candidate = next(group, None)
        if candidate is not None:
            yield candidate
            pending.append(group)


def _retained_candidates(candidates):
    """Share the bounded sample across kinds, source areas and individual files."""
    grouped = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for row in sorted(
        candidates,
        key=lambda item: (item["kind"], item["locations"][0]["path"], item["locations"][0]["line"]),
    ):
        path = row["locations"][0]["path"]
        parts = PurePosixPath(path).parts
        area = parts[0] if len(parts) > 1 else ""
        grouped[row["kind"]][area][path].append(row)
    kinds = []
    for kind in sorted(grouped):
        areas = []
        for area in sorted(grouped[kind]):
            files = grouped[kind][area]
            paths = sorted(files, key=lambda path: (hashlib.sha256(path.encode()).digest(), path))
            areas.append(_round_robin([files[path] for path in paths]))
        kinds.append(_round_robin(areas))
    return list(islice(_round_robin(kinds), MAX_CANDIDATES))


def summarize(records: list[dict], python_files: int, other_source_files: int) -> dict:
    selected = sorted(records, key=lambda row: row["path"])[:MAX_FILES]
    gaps = sorted({gap for record in selected for gap in record["gaps"]})
    if python_files > len(selected):
        gaps.append("Some Python files could not be analyzed within parse/file limits")
    if other_source_files:
        gaps.append(
            "JavaScript/TypeScript has lexical counts only; no semantic static analyzer was run"
        )
    gaps.append(
        "Dynamic imports, runtime alias resolution, actual call frequency and change cost are not established"
    )
    edges, edges_limited = _edges(selected)
    candidates, clones = [], defaultdict(list)
    if edges_limited:
        gaps.append("Static import target count or qualified-name limit reached")
    for record in selected:
        for function in record["functions"]:
            if function["fingerprint"]:
                clones[function["fingerprint"]].append(function["location"])
            if (
                function["decisions"] >= DECISION_THRESHOLD
                or function["nesting"] >= NESTING_THRESHOLD
            ):
                candidates.append(
                    {
                        "kind": "complex_function",
                        "lens": "quality",
                        "locations": [function["location"]],
                        "metrics": {
                            "decision_points": function["decisions"],
                            "control_nesting": function["nesting"],
                        },
                    }
                )
            if function["loop_io"]:
                candidates.append(
                    {
                        "kind": "loop_io",
                        "lens": "efficiency",
                        "locations": function["loop_io"],
                        "metrics": {
                            "method": "syntactic calls inside loops; shadowing, freshness and actual I/O require review"
                        },
                    }
                )
    for locations in clones.values():
        if len(locations) > 1:
            candidates.append(
                {
                    "kind": "duplicate_function",
                    "lens": "reuse",
                    "locations": sorted(locations, key=lambda row: (row["path"], row["line"]))[:20],
                    "metrics": {
                        "matching_functions": len(locations),
                        "normalization": "exact arguments/decorators/body AST; definition names, locations and leading docstrings omitted",
                    },
                }
            )
    for component in _components([record["path"] for record in selected], edges):
        internal = [
            edge for edge in edges if edge["source"] in component and edge["target"] in component
        ]
        candidates.append(
            {
                "kind": "dependency_cycle",
                "lens": "quality",
                "locations": [
                    {"path": edge["source"], "line": edge["line"], "end_line": edge["line"]}
                    for edge in internal[:20]
                ],
                "metrics": {
                    "modules": component[:20],
                    "module_count": len(component),
                    "phases": dict(sorted(Counter(edge["phase"] for edge in internal).items())),
                    "edges": internal[:20],
                    "caveat": "Captured dependency cycle, not proof of a runtime import failure; deferred/conditional edges retain their phase",
                },
            }
        )
    if len(candidates) > MAX_CANDIDATES:
        gaps.append("Static candidate limit reached; remaining candidates omitted")
    partial = (
        python_files > len(selected)
        or any(record["gaps"] for record in selected)
        or len(candidates) > MAX_CANDIDATES
        or bool(other_source_files)
        or edges_limited
    )
    return {
        "schema_version": 1,
        "analyzer": {"name": "project-assess-python-ast", "version": VERSION},
        "status": "unsupported" if not python_files else "partial" if partial else "complete",
        "coverage": {
            "python_files": python_files,
            "parsed_files": len(selected),
            "other_source_files": other_source_files,
        },
        "summary": {
            "functions": sum(len(record["functions"]) for record in selected),
            "dependency_edges": len(edges),
            "candidate_count": len(candidates),
        },
        "candidates": _retained_candidates(candidates),
        "gaps": gaps,
        "limits": {
            "files": MAX_FILES,
            "project_symbols": MAX_SYMBOLS,
            "import_targets": MAX_IMPORT_TARGETS,
            "qualified_name_characters": MAX_MODULE_LENGTH,
            "ast_nodes_per_file": MAX_NODES,
            "functions_per_file": MAX_FUNCTIONS,
            "nodes_per_function": MAX_FUNCTION_NODES,
            "candidates": MAX_CANDIDATES,
            "decision_threshold": DECISION_THRESHOLD,
            "nesting_threshold": NESTING_THRESHOLD,
        },
        "caveat": "Deterministic source leads, not scores or demonstrated defects. Required boundaries, tests and intentional fresh reads may justify these patterns. Decision points exclude nested scopes and are not Ruff/McCabe C901 complexity.",
    }


def ruff_report(payload: bytes, root: Path, manifest_paths: set[str], redact) -> dict:
    """Normalize supplied standard Ruff JSON. Never retain edit text or execute fixes."""

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate Ruff JSON key")
            result[key] = value
        return result

    rows = json.loads(
        payload,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite Ruff JSON")),
    )
    if not isinstance(rows, list):
        raise ValueError("Ruff report must be a JSON array")
    diagnostics, gaps = (
        [],
        [
            "Supplied Ruff diagnostics have unverified source identity, producer version, configuration and rule scope; zero findings is not a clean-project rating"
        ],
    )
    # Bound traversal too; do not trust arbitrarily many invalid leading rows.
    for row in rows[:MAX_DIAGNOSTICS]:
        if not isinstance(row, dict) or not isinstance(row.get("filename"), str):
            raise ValueError("Malformed Ruff diagnostic")
        path = Path(row["filename"])
        if not path.is_absolute():
            path = root / path
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            gaps.append("Ignored Ruff location outside captured source scope")
            continue
        if relative not in manifest_paths or ".." in path.parts:
            gaps.append("Ignored Ruff location outside captured source scope")
            continue
        code, message = row.get("code"), row.get("message")
        line = row.get("location", {}).get("row") if isinstance(row.get("location"), dict) else None
        end = (
            row.get("end_location", {}).get("row", line)
            if isinstance(row.get("end_location"), dict)
            else line
        )
        if (
            not isinstance(code, str)
            or not re.fullmatch(r"[A-Z]+[0-9]{3,4}", code)
            or not isinstance(message, str)
            or type(line) is not int
            or line < 1
            or type(end) is not int
            or end < line
        ):
            raise ValueError("Malformed Ruff code, message or source range")
        fix = row.get("fix")
        applicability = fix.get("applicability") if isinstance(fix, dict) else None
        diagnostics.append(
            {
                "code": code,
                "path": relative,
                "line": line,
                "end_line": end,
                "message": redact(message)[:500],
                "fix_applicability": applicability
                if isinstance(applicability, str)
                and applicability in {"safe", "unsafe", "display-only"}
                else None,
            }
        )
    if len(rows) > MAX_DIAGNOSTICS:
        gaps.append("Ruff diagnostic limit reached; remaining rows omitted")
    diagnostics.sort(key=lambda row: (row["path"], row["line"], row["code"], row["message"]))
    return {
        "schema_version": 1,
        "source_identity": "unverified",
        "summary": {"diagnostics": len(diagnostics), "supplied": len(rows)},
        "diagnostics": diagnostics,
        "gaps": sorted(set(gaps)),
    }
