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

from .analysis_patterns import function_patterns, pattern_candidates

VERSION = "3"
MAX_FILES = 1000
MAX_OVERVIEW_FILES = 20_000
MAX_SYMBOLS = 20_000
MAX_IMPORT_TARGETS = 20_000
MAX_MODULE_LENGTH = 4096
MAX_NODES = 50_000
MAX_OVERVIEW_NODES = 200_000
MAX_FUNCTION_NODES = 6000
MAX_FUNCTIONS = 1000
MAX_CANDIDATES = 100
MAX_INDEX = 20_000
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


def source_role(path: str) -> dict:
    """A transparent path heuristic; executable source is not necessarily product code."""
    parts = tuple(part.lower() for part in PurePosixPath(path).parts)
    name = parts[-1] if parts else ""
    generated = bool(set(parts[:-1]) & {"generated", "dist", "build"}) or bool(
        re.search(r"(?:\.generated\.|_pb2(?:_grpc)?\.py$)", name)
    )
    vendor = bool(
        set(parts[:-1])
        & {"vendor", "vendored", "third_party", "third-party", "node_modules", ".venv", "venv"}
    )
    if generated or vendor:
        role = "unknown"
    elif (
        set(parts[:-1]) & {"test", "tests", "__tests__", "spec", "specs", "e2e"}
        or name.startswith("test_")
        or re.search(r"(?:_test|\.test|\.spec)\.[^.]+$", name)
    ):
        role = "test"
    elif parts and parts[0] in {
        "src",
        "lib",
        "app",
        "apps",
        "services",
        "packages",
        "frontend",
        "backend",
        "web",
        "api",
    }:
        role = "production"
    elif set(parts[:-1]) & {
        ".agents",
        ".claude",
        ".codex",
        "scripts",
        "tools",
        "ops",
        "evals",
        "docs",
    }:
        role = "tooling"
    else:
        role = "unknown"
    return {
        "role": role,
        "role_basis": "path heuristic; project intent may differ",
        "generated_hint": generated,
        "vendor_hint": vendor,
    }


def _sample(items, limit):
    """Keep deterministic coverage across the file rather than only its prefix."""
    if limit <= 0:
        return []
    if len(items) <= limit:
        return items
    return [items[index * len(items) // limit] for index in range(limit)]


def _function_metrics(functions, node_budget):
    """Fair, cheap metric work independent of expensive clone/pattern slots."""
    rows = [
        {
            "decisions": 0,
            "nesting": 0,
            "nodes_analyzed": 0,
            "partial": False,
            "loop_io_nodes": [],
            "loop_io_count": 0,
        }
        for _ in functions
    ]
    pending = deque(
        (index, iter(_nodes(_body(function)))) for index, function in enumerate(functions)
    )
    used, probes = 0, 0

    def unfinished(index, iterator):
        nonlocal probes
        value = next(iterator, None)
        probes += value is not None
        rows[index]["partial"] = value is not None

    while pending and used < node_budget:
        index, iterator = pending.popleft()
        item = next(iterator, None)
        if item is None:
            continue
        node, depth, in_loop = item
        row = rows[index]
        row["nodes_analyzed"] += 1
        row["decisions"] += (
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
        )
        row["nesting"] = max(row["nesting"], depth + isinstance(node, _CONTROL))
        if in_loop and _io_call(node):
            row["loop_io_count"] += 1
            if len(row["loop_io_nodes"]) < 5:
                row["loop_io_nodes"].append(node)
        used += 1
        if row["nodes_analyzed"] >= MAX_FUNCTION_NODES:
            unfinished(index, iterator)
        else:
            pending.append((index, iterator))
    for index, iterator in pending:
        unfinished(index, iterator)
    return rows, used, probes


def analyze_python(
    path: str,
    tree: ast.Module,
    *,
    detail_budget: int | None = None,
    metric_node_budget: int | None = None,
) -> dict:
    """Retain a module overview and partial metrics even when detail budgets are reached."""
    record = {"path": path, "functions": [], "imports": [], "gaps": [], **source_role(path)}
    # The overview pass is distinct from detailed metric work. Exceeding the
    # old detailed-file bound must not erase every function/import in a module.
    nodes = list(islice(ast.walk(tree), MAX_OVERVIEW_NODES + 1))
    overview_partial = len(nodes) > MAX_OVERVIEW_NODES
    if overview_partial:
        record["gaps"].append(f"Module overview node limit reached: {path}")
        nodes = nodes[:MAX_OVERVIEW_NODES]
    functions = sorted(
        (node for node in nodes if isinstance(node, _FUNCTION)), key=lambda node: node.lineno
    )
    classes = [node for node in nodes if isinstance(node, ast.ClassDef)]
    loads = {
        node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    attributes = {node.attr for node in nodes if isinstance(node, ast.Attribute)}
    dynamic = any(
        isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec", "globals", "locals", "getattr", "__import__"}
            or isinstance(node.func, ast.Attribute)
            and node.func.attr in {"import_module", "entry_points", "load_entry_point"}
        )
        for node in nodes
    )
    exports, exports_unknown = set(), False
    for statement in tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                value = statement.value
                if isinstance(value, (ast.List, ast.Tuple)) and all(
                    isinstance(item, ast.Constant) and isinstance(item.value, str)
                    for item in value.elts
                ):
                    exports.update(item.value for item in value.elts)
                else:
                    exports_unknown = True
    definitions = [node for node in tree.body if isinstance(node, (*_FUNCTION, ast.ClassDef))]
    if len(loads | attributes) > MAX_SYMBOLS:
        record["gaps"].append(f"Module reference name limit reached: {path}")
    if len(definitions) > MAX_SYMBOLS or len(exports) > MAX_SYMBOLS:
        record["gaps"].append(f"Module definition/export limit reached: {path}")
    record["symbols"] = [
        {
            "name": node.name,
            "kind": "class" if isinstance(node, ast.ClassDef) else "function",
            "location": _location(path, node),
            "decorated": bool(node.decorator_list),
            "exported": node.name in exports,
            "referenced": node.name in loads or node.name in attributes,
        }
        for node in definitions[:MAX_SYMBOLS]
    ]
    record["references"] = sorted(loads | attributes)[:MAX_SYMBOLS]
    record["module"] = {
        "lines": max((getattr(node, "end_lineno", 0) or 0 for node in tree.body), default=0),
        "function_count": len(functions),
        "class_count": len(classes),
        "definition_count": len(definitions),
        "exports": sorted(exports)[:MAX_SYMBOLS],
        "exports_unknown": exports_unknown,
        "dynamic_resolution": dynamic,
        "main_guard": any(
            isinstance(statement, ast.If)
            and isinstance(statement.test, ast.Compare)
            and any(
                isinstance(child, ast.Name) and child.id == "__name__"
                for child in ast.walk(statement.test)
            )
            for statement in tree.body
        ),
        "overview_partial": overview_partial,
    }
    limit = MAX_FUNCTIONS if detail_budget is None else min(MAX_FUNCTIONS, max(0, detail_budget))
    if len(functions) > limit:
        record["gaps"].append(f"Function detail limit reached: {path}; module overview retained")
    metric_budget = MAX_NODES if metric_node_budget is None else max(0, metric_node_budget)
    metrics, metric_nodes, probes = _function_metrics(functions, metric_budget)
    selected = {id(function) for function in _sample(functions, limit)}
    for function, metric in zip(functions, metrics, strict=True):
        body = _body(function)
        partial = metric["partial"]
        if partial:
            record["gaps"].append(
                f"Function node limit reached: {path}:{function.lineno}; partial metrics retained"
            )
        pattern_analyzed = id(function) in selected
        own_nodes = list(islice(_nodes(body), MAX_FUNCTION_NODES + 1)) if pattern_analyzed else []
        pattern_partial = len(own_nodes) > MAX_FUNCTION_NODES
        own_nodes = own_nodes[:MAX_FUNCTION_NODES]
        if pattern_partial:
            record["gaps"].append(f"Pattern function node limit reached: {path}:{function.lineno}")
        # Do not compare stubs/wrappers. Exact ASTs retain arguments, literals,
        # callees, annotations and decorators; only definition names/locations
        # and the leading docstring are omitted. Equality is not safe merge proof.
        fingerprint = None
        if (
            pattern_analyzed
            and not pattern_partial
            and len(body) >= 3
            and len(own_nodes) >= 20
            and not any(isinstance(n, _SCOPES) for n, _, _ in own_nodes)
        ):
            parts = [function.args, function.returns, *function.decorator_list, *body]
            try:
                canonical = [
                    ast.dump(part, include_attributes=False) if part else None for part in parts
                ]
                fingerprint = hashlib.sha256(
                    json.dumps([type(function).__name__, canonical]).encode()
                ).hexdigest()
            except RecursionError:
                record["gaps"].append(
                    f"Clone serialization depth limit reached: {path}:{function.lineno}"
                )
        try:
            patterns = (
                function_patterns(path, function, own_nodes, partial=pattern_partial)
                if pattern_analyzed
                else {}
            )
        except RecursionError:
            patterns = {}
            record["gaps"].append(
                f"Pattern serialization depth limit reached: {path}:{function.lineno}"
            )
        record["functions"].append(
            {
                "location": _location(path, function),
                "name": function.name,
                "decisions": metric["decisions"],
                "nesting": metric["nesting"],
                "nodes_analyzed": metric["nodes_analyzed"],
                "partial": partial,
                "metric_basis": "lower_bound" if partial else "complete_function",
                "loop_io": [_location(path, node) for node in metric["loop_io_nodes"]],
                "loop_io_count": metric["loop_io_count"],
                "pattern_analyzed": pattern_analyzed,
                "pattern_partial": pattern_partial,
                "fingerprint": fingerprint,
                "patterns": patterns,
            }
        )
    record["module"]["analyzed_functions"] = len(record["functions"])
    record["module"]["partial_functions"] = sum(row["partial"] for row in record["functions"])
    record["module"].update(
        {
            "pattern_functions": len(selected),
            "pattern_function_limit": MAX_FUNCTIONS,
            "metric_node_budget": metric_budget,
            "metric_nodes": metric_nodes,
            "metric_probe_nodes": probes,
        }
    )
    for function in record["functions"]:
        for limit in function["patterns"].get("limits_reached", []):
            record["gaps"].append(
                f"Pattern analysis {limit}: {path}:{function['location']['line']}"
            )
    stack, examined = [(tree, "eager")], 0
    while stack:
        node, phase = stack.pop()
        examined += 1
        if examined > MAX_OVERVIEW_NODES:
            record["gaps"].append(f"Import traversal limit reached: {path}")
            break
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if len(record["imports"]) >= MAX_IMPORT_TARGETS:
                record["gaps"].append(f"Module import limit reached: {path}")
                break
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


def _edges(records, import_target_limit):
    modules = defaultdict(list)
    for record in records:
        modules[_module(record["path"])].append(record["path"])
    edges, cache = [], {}
    attempted, cached, skipped, ambiguous = 0, 0, 0, 0
    oversized, attempts_limited = False, False
    attempt_limit = min(1_000_000, max(1000, import_target_limit * 10))
    depth = max((name.count(".") + 1 for name in modules), default=1)

    def targets(record):
        path = record["path"]
        package = _module(path).split(".")
        if PurePosixPath(path).name != "__init__.py":
            package = package[:-1]
        for item in record["imports"]:
            base = item["module"]
            if item["level"]:
                if item["level"] > len(package):
                    continue
                base = ".".join(
                    package[: len(package) - item["level"] + 1] + ([base] if base else [])
                )
            if base is not None and len(base) > MAX_MODULE_LENGTH:
                yield path, item, None
                continue
            names = (
                item["names"]
                if base is None
                else (f"{base}.{name}" if base else name for name in item["names"])
            )
            for target in names:
                yield path, item, target

    # An import-heavy early file must not consume every graph-resolution slot.
    for path, item, target in _round_robin([targets(record) for record in records]):
        if attempted >= attempt_limit:
            attempts_limited = True
            break
        attempted += 1
        if target is None or len(target) > MAX_MODULE_LENGTH:
            oversized = True
            continue
        if target in cache:
            cached += 1
            destination = cache[target]
        elif len(cache) >= import_target_limit:
            skipped += 1
            continue
        else:
            # Cache successful, external/unresolved and ambiguous lookups alike.
            # Repeated imports in different files/phases still emit their edges.
            parts = target.split(".", depth)[:depth]
            prefix = ""
            for end in range(len(parts), 0, -1):
                name = ".".join(parts[:end])
                if name in modules:
                    prefix = name
                    break
            matches = modules.get(prefix, [])
            ambiguous += len(matches) > 1
            destination = matches[0] if len(matches) == 1 else None
            cache[target] = destination
        # Resolve captured modules only. Captured depth bounds prefix work for
        # hostile imports containing thousands of unresolved dotted segments.
        if destination is not None and destination != path:
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
    ), {
        "attempted": attempted,
        "cached": cached,
        "unique_work": len(cache),
        "limit": import_target_limit,
        "attempt_limit": attempt_limit,
        "budget_exhausted": bool(skipped),
        "budget_skipped_attempts": skipped,
        "attempt_limit_reached": attempts_limited,
        "qualified_name_limit_reached": oversized,
        "ambiguous_targets": ambiguous,
        "complete": not (skipped or attempts_limited or oversized or ambiguous),
    }


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


def _retained_candidates(candidates, limit=None):
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
    return list(islice(_round_robin(kinds), MAX_CANDIDATES if limit is None else limit))


def _dead_candidates(records, edges, *, graph_complete):
    """Unused is a closed-world lead; only syntactic unreachable code is proven."""
    references = {name for row in records for name in row.get("references", [])}
    references.update(name for row in records for item in row["imports"] for name in item["names"])
    inbound = {edge["target"] for edge in edges}
    paths = {row["path"] for row in records}
    candidates = []
    for record in records:
        path, module = record["path"], record.get("module", {})
        for symbol in record.get("symbols", []):
            name = symbol["name"]
            if (
                name.startswith("_")
                and not name.startswith("__")
                and name not in references
                and not symbol["referenced"]
                and not symbol["decorated"]
                and not symbol["exported"]
            ):
                candidates.append(
                    {
                        "kind": "unused_symbol",
                        "lens": "quality",
                        "confidence": "low",
                        "locations": [symbol["location"]],
                        "metrics": {
                            "symbol": name,
                            "definition_kind": symbol["kind"],
                            "observed_references": 0,
                            "dynamic_resolution": module.get("dynamic_resolution", False),
                            "overview_partial": module.get("overview_partial", False),
                            "exports_unknown": module.get("exports_unknown", False),
                        },
                        "counterevidence": [
                            "External consumers, string lookup, decorators, plugins and uncaptured callers may use this symbol.",
                            "Dynamic resolution or incomplete source coverage prevents a dead-code proof.",
                        ],
                        "caveat": "No captured static reference; confirm actual entrypoints and consumers before removal.",
                    }
                )
        package = PurePosixPath(path).with_suffix("").as_posix() + "/__init__.py"
        if PurePosixPath(path).name != "__init__.py" and package in paths:
            candidates.append(
                {
                    "kind": "shadowed_module",
                    "lens": "quality",
                    "confidence": "medium",
                    "locations": [
                        {"path": path, "line": 1, "end_line": 1},
                        {"path": package, "line": 1, "end_line": 1},
                    ],
                    "metrics": {
                        "module": _module(path),
                        "reason": "co-located module and package share an import name",
                    },
                    "counterevidence": [
                        "Import search paths, explicit file loaders and distribution contents can change the active implementation."
                    ],
                    "caveat": "Potential shadowing; verify caller and built-package resolution before deleting either implementation.",
                }
            )
        if (
            graph_complete
            and record.get("role") == "production"
            and path not in inbound
            and module.get("definition_count", 0)
            and not module.get("main_guard")
            and not module.get("exports")
            and not module.get("exports_unknown")
            and not module.get("dynamic_resolution")
            and PurePosixPath(path).stem
            not in {"__init__", "__main__", "app", "main", "cli", "wsgi", "asgi", "manage"}
        ):
            candidates.append(
                {
                    "kind": "unreferenced_module",
                    "lens": "quality",
                    "confidence": "low",
                    "locations": [{"path": path, "line": 1, "end_line": 1}],
                    "metrics": {"module": _module(path), "observed_inbound_imports": 0},
                    "counterevidence": [
                        "May be a public API, command entrypoint, plugin or dynamically loaded module; manifests and external consumers are not a closed world."
                    ],
                    "caveat": "Absence of a captured import is not evidence that a module is safely removable.",
                }
            )
    return candidates


def summarize(
    records: list[dict],
    python_files: int,
    other_source_files: int,
    *,
    import_target_limit: int | None = None,
    source_complete: bool = True,
) -> dict:
    import_limit = MAX_IMPORT_TARGETS if import_target_limit is None else import_target_limit
    if type(import_limit) is not int or not 1 <= import_limit <= 1_000_000:
        raise ValueError("import_target_limit must be an integer from 1 to 1000000")
    selected = sorted(records, key=lambda row: row["path"])[:MAX_OVERVIEW_FILES]
    gaps = sorted({gap for record in selected for gap in record["gaps"]})
    if python_files > len(selected):
        gaps.append("Some Python files could not be analyzed within parse/file limits")
    if other_source_files:
        gaps.append(
            "This Python analyzer excludes JavaScript/TypeScript; inspect separate javascript-analysis evidence for optional syntax analysis and its gaps"
        )
    gaps.append(
        "Dynamic imports, runtime alias resolution, actual call frequency and change cost are not established"
    )
    edges, resolution = _edges(selected, import_limit)
    edges_limited = not resolution["complete"]
    imports_partial = any(
        row.get("module", {}).get("dynamic_resolution")
        or any(
            gap.startswith(("Import traversal limit", "Module import limit")) for gap in row["gaps"]
        )
        for row in selected
    )
    graph_complete = (
        source_complete
        and python_files == len(selected)
        and not edges_limited
        and not imports_partial
    )
    if not source_complete:
        gaps.append("Source capture is incomplete; zero-inbound module leads are withheld")
    if not graph_complete:
        gaps.append("Static import graph is incomplete; unreferenced-module leads are withheld")
    candidates, clones, hotspots = [], defaultdict(list), []
    if edges_limited:
        gaps.append("Static import target count or qualified-name limit reached")
    for record in selected:
        for function in record["functions"]:
            hotspots.append(
                {
                    "path": record["path"],
                    "name": function.get("name"),
                    "line": function["location"]["line"],
                    "end_line": function["location"]["end_line"],
                    "role": record.get("role", "unknown"),
                    "decision_points": function["decisions"],
                    "control_nesting": function["nesting"],
                    "nodes_analyzed": function.get("nodes_analyzed"),
                    "partial": function.get("partial", False),
                    "metric_basis": function.get("metric_basis", "complete_function"),
                }
            )
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
                            "symbol": function.get("name"),
                            "partial": function.get("partial", False),
                            "metric_basis": function.get("metric_basis", "complete_function"),
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
    candidates.extend(pattern_candidates(selected))
    candidates.extend(_dead_candidates(selected, edges, graph_complete=graph_complete))
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
    runtime_edges = [edge for edge in edges if edge["phase"] != "type_checking"]
    components = list(_components([record["path"] for record in selected], runtime_edges))
    component_ids = {
        path: index for index, component in enumerate(components) for path in component
    }
    grouped_edges = defaultdict(list)
    for edge in runtime_edges:
        index = component_ids.get(edge["source"])
        if index is not None and index == component_ids.get(edge["target"]):
            grouped_edges[index].append(edge)
    for index, component in enumerate(components):
        internal = grouped_edges[index]
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
    roles = {row["path"]: row.get("role", "unknown") for row in selected}
    for candidate in candidates:
        candidate["roles"] = sorted(
            {roles.get(location["path"], "unknown") for location in candidate["locations"]}
        )
        candidate["role"] = candidate["roles"][0] if len(candidate["roles"]) == 1 else "unknown"
        candidate.setdefault("confidence", "medium")
        candidate["id"] = (
            "c-"
            + hashlib.sha256(
                json.dumps(
                    [candidate["kind"], candidate["locations"], candidate["metrics"]],
                    sort_keys=True,
                ).encode()
            ).hexdigest()[:24]
        )
    # A compact index makes the bounded rich sample navigable rather than the
    # only source of leads. Its own truncation and denominators remain explicit.
    ordered = sorted(
        _retained_candidates(candidates, MAX_INDEX),
        key=lambda row: (
            row["kind"],
            row["locations"][0]["path"],
            row["locations"][0]["line"],
            row["id"],
        ),
    )
    indexed = ordered
    if len(candidates) > MAX_INDEX:
        gaps.append("Static candidate index limit reached; remaining compact leads omitted")
    if len(candidates) > MAX_CANDIDATES:
        gaps.append("Static candidate limit reached; remaining candidates omitted")
    partial = (
        python_files > len(selected)
        or any(record["gaps"] for record in selected)
        or len(candidates) > MAX_CANDIDATES
        or bool(other_source_files)
        or edges_limited
        or not source_complete
    )
    inbound, outbound = (
        Counter(edge["target"] for edge in edges),
        Counter(edge["source"] for edge in edges),
    )
    modules = [
        {
            "path": row["path"],
            "module": _module(row["path"]),
            "role": row.get("role", "unknown"),
            "role_basis": row.get("role_basis", "unknown"),
            "generated_hint": row.get("generated_hint", False),
            "vendor_hint": row.get("vendor_hint", False),
            **row.get("module", {}),
            "inbound": inbound[row["path"]],
            "outbound": outbound[row["path"]],
            "inbound_complete": graph_complete,
            "degree_basis": "captured static edges; incomplete graphs provide lower bounds",
        }
        for row in selected
    ]
    retained = _retained_candidates(candidates)
    metric_budget = max(
        (row.get("module", {}).get("metric_node_budget", MAX_NODES) for row in selected),
        default=MAX_NODES,
    )
    return {
        "schema_version": 1,
        "analyzer": {"name": "project-assess-python-ast", "version": VERSION},
        "status": "unsupported" if not python_files else "partial" if partial else "complete",
        "coverage": {
            "python_files": python_files,
            "parsed_files": len(selected),
            "other_source_files": other_source_files,
            "overview_files": len(selected),
            "detailed_files": sum(
                bool(row.get("module", {}).get("pattern_functions", 0)) for row in selected
            ),
            "metric_files": sum(bool(row["functions"]) for row in selected),
            "pattern_files": sum(
                bool(row.get("module", {}).get("pattern_functions", 0)) for row in selected
            ),
            "pattern_functions": sum(
                row.get("module", {}).get("pattern_functions", 0) for row in selected
            ),
            "functions_total": sum(
                row.get("module", {}).get("function_count", len(row["functions"]))
                for row in selected
            ),
            "functions_analyzed": len(hotspots),
            "partial_functions": sum(row["partial"] for row in hotspots),
            "metric_functions_observed": sum(bool(row.get("nodes_analyzed")) for row in hotspots),
        },
        "summary": {
            "functions": sum(len(record["functions"]) for record in selected),
            "dependency_edges": len(edges),
            "candidate_count": len(candidates),
        },
        "candidates": retained,
        "candidate_index": indexed,
        "candidate_counts": {
            "total": len(candidates),
            "retained": len(retained),
            "indexed": len(indexed),
            "omitted_from_index": len(candidates) - len(indexed),
            "by_kind": dict(sorted(Counter(row["kind"] for row in candidates).items())),
            "by_role": dict(sorted(Counter(row["role"] for row in candidates).items())),
        },
        "modules": modules,
        "topology": {
            "edges": edges,
            "complete": graph_complete,
            "resolution": resolution,
            "source_complete": source_complete,
            "caveat": "Captured static imports, including type-checking, conditional and deferred phases; type-checking edges are excluded from runtime-cycle leads. Not a runtime call graph, reachability proof or verified entrypoint inventory.",
        },
        "hotspots": sorted(
            hotspots,
            key=lambda row: (
                -row["decision_points"],
                -row["control_nesting"],
                row["path"],
                row["line"],
            ),
        )[:MAX_CANDIDATES],
        "gaps": gaps,
        "limits": {
            "files": MAX_FILES,
            "overview_files": MAX_OVERVIEW_FILES,
            "project_symbols": MAX_SYMBOLS,
            "import_targets": import_limit,
            "import_attempts": resolution["attempt_limit"],
            "qualified_name_characters": MAX_MODULE_LENGTH,
            "ast_nodes_per_file": metric_budget,
            "metric_nodes_per_file": metric_budget,
            "default_metric_nodes_per_file": MAX_NODES,
            "overview_nodes_per_file": MAX_OVERVIEW_NODES,
            "functions_per_file": MAX_FUNCTIONS,
            "nodes_per_function": MAX_FUNCTION_NODES,
            "candidates": MAX_CANDIDATES,
            "candidate_index": MAX_INDEX,
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
