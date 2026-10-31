"""Optional, bounded syntax analysis of captured JavaScript and TypeScript text.

Only installed Tree-sitter bindings and bundled grammars are loaded. Project
configuration, imports, plugins and code are never executed or resolved on disk.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import posixpath
import re
from collections import Counter, defaultdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import PurePosixPath

from .static_analysis import source_role

VERSION = "1"
SUPPORTED_TREE_SITTER = ">=0.25.2,<0.26"
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 100_000
MAX_FUNCTION_NODES = 6000
MAX_FUNCTIONS = 1000
MAX_FILES = 1000
MAX_CANDIDATES = 100
MAX_INDEX = 20_000
MAX_IMPORTS = 20_000
DECISION_THRESHOLD = 10
NESTING_THRESHOLD = 4
_PACKAGES = ("tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript")
_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "generator_function_declaration",
    "generator_function",
    "arrow_function",
    "method_definition",
}
_CONTROLS = {
    "if_statement",
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
    "catch_clause",
    "ternary_expression",
}
_DECISIONS = _CONTROLS - {"try_statement", "switch_statement"} | {"switch_case"}
_HOISTED = {
    "function_declaration",
    "generator_function_declaration",
    "variable_declaration",
    "function_signature",
    "interface_declaration",
    "type_alias_declaration",
    "empty_statement",
}
_RELATIVE = re.compile(r"\.{1,2}/[A-Za-z0-9_./@+~-]{1,4090}\Z")
_CAVEAT = (
    "Syntax leads, not scores, proven defects, type checking or a runtime call graph. "
    "No project configuration or plugins were loaded. Aliases, external consumers "
    "and dynamic behavior remain open-world."
)


def javascript_analyzer_identity():
    """Report the optional trusted parser identity without probing assessed files."""
    packages = {}
    for package in _PACKAGES:
        try:
            packages[package] = version(package)
        except PackageNotFoundError:
            packages[package] = None
    release = re.fullmatch(r"0\.25\.(\d+)", packages.get("tree-sitter") or "")
    supported = release is not None and int(release[1]) >= 2
    available = all(packages.values()) and supported
    reason = None
    if not all(packages.values()):
        reason = "missing_dependencies"
    elif not supported:
        # 0.26.0 reproducibly corrupts Node traversal on the real report app;
        # a Python exception cannot contain its native segmentation fault.
        reason = "unsupported_tree_sitter_version"
    if available:
        try:
            binding = importlib.import_module("tree_sitter")
            javascript = importlib.import_module("tree_sitter_javascript")
            typescript = importlib.import_module("tree_sitter_typescript")
            # ABI/API incompatibility is unavailability, never a healthy empty scan.
            for capsule in (
                javascript.language(),
                typescript.language_typescript(),
                typescript.language_tsx(),
            ):
                binding.Parser(binding.Language(capsule))
        except (ImportError, AttributeError, TypeError, ValueError, OSError):
            available = False
            reason = "incompatible_bindings"
    return {
        "name": "project-assess-tree-sitter",
        "version": VERSION,
        "available": available,
        "packages": packages,
        "supported_tree_sitter": SUPPORTED_TREE_SITTER,
        "unavailable_reason": reason,
    }


def _parser(path):
    binding = importlib.import_module("tree_sitter")
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".ts", ".tsx", ".mts", ".cts"}:
        grammar = importlib.import_module("tree_sitter_typescript")
        capsule = grammar.language_tsx() if suffix == ".tsx" else grammar.language_typescript()
    else:
        capsule = importlib.import_module("tree_sitter_javascript").language()
    return binding.Parser(binding.Language(capsule))


def _walk(node, limit, *, own_scope=False):
    stack = [(node, 0)]
    count = 0
    while stack and count < limit:
        current, nesting = stack.pop()
        count += 1
        yield current, nesting
        if (
            own_scope
            and current is not node
            and current.type in _FUNCTIONS | {"class", "class_declaration"}
        ):
            continue
        depth = nesting + (current.type in _CONTROLS)
        stack.extend((child, depth) for child in reversed(current.named_children))


def _text(node, raw, limit=256):
    if node is None:
        return ""
    return raw[node.start_byte : node.end_byte][:limit].decode("utf-8", errors="replace")


def _location(path, node):
    return {"path": path, "line": node.start_point.row + 1, "end_line": node.end_point.row + 1}


def _name(node, raw):
    name = node.child_by_field_name("name")
    if name is None and node.parent and node.parent.type in {"variable_declarator", "pair"}:
        name = node.parent.child_by_field_name("name") or node.parent.child_by_field_name("key")
    if name is not None and name.type in {
        "identifier",
        "property_identifier",
        "private_property_identifier",
    }:
        return _text(name, raw)
    return f"anonymous@{node.start_point.row + 1}"


def _relative_string(node, raw):
    if node is None or node.type != "string":
        return None
    value = _text(node, raw, 4096)
    if len(value) < 3 or value[0] not in {"'", '"'} or value[-1] != value[0]:
        return None
    value = value[1:-1]
    # Omit URLs, queries, escapes and arbitrary source strings, including credentials.
    return value if _RELATIVE.fullmatch(value) else None


def _fingerprint(node, raw):
    """Exact syntax equality of parameters/body, excluding comments and definition names."""
    body = node.child_by_field_name("body")
    parameters = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
    if body is None or len(body.named_children) < 3:
        return None
    digest, stack, count = hashlib.sha256(), [body], 0
    if parameters is not None:
        stack.append(parameters)
    while stack:
        current = stack.pop()
        count += 1
        if count > MAX_FUNCTION_NODES:
            return None
        if current.type == "comment":
            continue
        children = [child for child in current.children if child.type != "comment"]
        digest.update(current.type.encode() + b":" + str(len(children)).encode() + b"\0")
        if not children:
            digest.update(hashlib.sha256(raw[current.start_byte : current.end_byte]).digest())
        else:
            stack.extend(reversed(children))
    return digest.hexdigest() if count >= 20 else None


def _candidate(kind, lens, locations, metrics, confidence="medium"):
    return {
        "kind": kind,
        "lens": lens,
        "locations": locations,
        "metrics": metrics,
        "confidence": confidence,
    }


def analyze_javascript(path: str, text: str) -> dict:
    """Parse supplied text only; partial metrics are lower bounds, never clean bills."""
    identity = javascript_analyzer_identity()
    record = {
        "schema_version": 1,
        "available": identity["available"],
        "analyzer": identity,
        "status": "unavailable" if not identity["available"] else "complete",
        "parsed": False,
        "path": path,
        **source_role(path),
        "imports": [],
        "functions": [],
        "candidates": [],
        "module": {
            "lines": text.count("\n") + bool(text),
            "function_count": 0,
            "exports": [],
            "dynamic_resolution": False,
            "overview_partial": False,
            "imports_partial": False,
        },
        "gaps": [],
    }
    if not identity["available"]:
        record["gaps"].append(
            f"Installed Tree-sitter binding is unsupported; use {SUPPORTED_TREE_SITTER} in the assessor environment. No native source traversal was attempted."
            if identity["unavailable_reason"] == "unsupported_tree_sitter_version"
            else "Optional JavaScript AST analysis unavailable; install the analysis extra in the assessor environment, not the assessed project."
        )
        return record
    # Bound before UTF-8 allocation as well as before native parsing.
    if len(text) > MAX_BYTES:
        record["status"] = "partial"
        record["module"]["overview_partial"] = True
        record["gaps"].append("JavaScript AST byte limit reached; source was not parsed")
        return record
    raw = text.encode("utf-8", errors="replace")
    if len(raw) > MAX_BYTES:
        record["status"] = "partial"
        record["module"]["overview_partial"] = True
        record["gaps"].append("JavaScript AST byte limit reached; source was not parsed")
        return record
    try:
        parser = _parser(path)
        tree = parser.parse(raw)
    except (ImportError, AttributeError, TypeError, ValueError, OSError):
        record["status"] = "partial"
        record["module"]["overview_partial"] = True
        record["gaps"].append("JavaScript parser failed; no source or error text retained")
        return record
    nodes = list(_walk(tree.root_node, MAX_NODES + 1))
    record["parsed"] = True
    partial = len(nodes) > MAX_NODES or tree.root_node.has_error
    if len(nodes) > MAX_NODES:
        nodes = nodes[:MAX_NODES]
        record["gaps"].append("JavaScript AST node limit reached; overview and metrics are partial")
    if tree.root_node.has_error:
        record["gaps"].append(
            "JavaScript/TypeScript parse errors or missing syntax; metrics are partial and dead-code leads suppressed"
        )
    references = Counter(
        _text(node, raw)
        for node, _ in nodes
        if node.type in {"identifier", "property_identifier", "shorthand_property_identifier"}
    )
    functions = [node for node, _ in nodes if node.type in _FUNCTIONS]
    record["module"]["function_count"] = len(functions)
    record["module"]["overview_partial"] = partial
    exported = set()
    dynamic = False
    for node, _ in nodes:
        if node.type == "export_statement":
            declaration = node.child_by_field_name("declaration")
            if declaration is not None:
                name = declaration.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    exported.add(_text(name, raw))
                for child in declaration.named_children:
                    if child.type == "variable_declarator":
                        name = child.child_by_field_name("name")
                        if name is not None and name.type == "identifier":
                            exported.add(_text(name, raw))
            for child in node.named_children:
                if child.type == "export_clause":
                    for specifier in child.named_children:
                        name = specifier.child_by_field_name(
                            "alias"
                        ) or specifier.child_by_field_name("name")
                        if name is not None and name.type == "identifier":
                            exported.add(_text(name, raw))
        source, kind, phase = None, None, "static"
        if node.type in {"import_statement", "export_statement"}:
            source, kind = node.child_by_field_name("source"), node.type
            if any(child.type == "type" for child in node.children):
                phase = "type_only"
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function and _text(function, raw) in {"require", "import"}:
                arguments = node.child_by_field_name("arguments")
                source = (
                    arguments.named_children[0]
                    if arguments and arguments.named_child_count == 1
                    else None
                )
                kind, phase = "literal_call", "deferred"
                if source is None or source.type != "string":
                    dynamic = True
                    partial = True
                    record["module"]["imports_partial"] = True
                    record["gaps"].append(
                        "Nonliteral module loading is unresolved; module graph is partial"
                    )
            if function and _text(function, raw) in {"eval", "Function"}:
                dynamic = True
        if node.type in {"with_statement", "subscript_expression"}:
            dynamic = True
        if kind and source is not None:
            relative = _relative_string(source, raw)
            if relative:
                if len(record["imports"]) < MAX_IMPORTS:
                    record["imports"].append(
                        {
                            "source": relative,
                            "line": node.start_point.row + 1,
                            "phase": phase,
                            "kind": kind,
                        }
                    )
                else:
                    partial = True
                    record["gaps"].append("JavaScript import limit reached")
                    record["module"]["imports_partial"] = True
            elif source.type == "string" and _text(source, raw, 4096)[1:2] == ".":
                partial = True
                record["module"]["imports_partial"] = True
                record["gaps"].append(
                    "Unsupported relative import spelling omitted; no raw literal retained"
                )
    record["module"].update(exports=sorted(exported)[:MAX_FUNCTIONS], dynamic_resolution=dynamic)
    if len(functions) > MAX_FUNCTIONS:
        record["gaps"].append("JavaScript function detail limit reached; overview retained")
        partial = True
    # Evenly spread function details across the captured file.
    selected = (
        functions
        if len(functions) <= MAX_FUNCTIONS
        else [functions[i * len(functions) // MAX_FUNCTIONS] for i in range(MAX_FUNCTIONS)]
    )
    for function in selected:
        body = function.child_by_field_name("body")
        if body is None:
            continue
        own = list(_walk(body, MAX_FUNCTION_NODES + 1, own_scope=True))
        function_partial = record["module"]["overview_partial"] or len(own) > MAX_FUNCTION_NODES
        if len(own) > MAX_FUNCTION_NODES:
            partial = True
            record["gaps"].append(
                "JavaScript function node limit reached; partial metrics retained"
            )
            own = own[:MAX_FUNCTION_NODES]
        decisions = sum(
            node.type in _DECISIONS
            or node.type == "binary_expression"
            and _text(node.child_by_field_name("operator"), raw) in {"&&", "||", "??"}
            for node, _ in own
        )
        nesting = max((depth + (node.type in _CONTROLS) for node, depth in own), default=0)
        location, name = _location(path, function), _name(function, raw)
        record["functions"].append(
            {
                "name": name,
                "location": location,
                "decisions": decisions,
                "nesting": nesting,
                "lines": location["end_line"] - location["line"] + 1,
                "partial": function_partial,
                "fingerprint": None if function_partial else _fingerprint(function, raw),
            }
        )
        if decisions >= DECISION_THRESHOLD or nesting >= NESTING_THRESHOLD:
            record["candidates"].append(
                _candidate(
                    "complex_function",
                    "quality",
                    [location],
                    {
                        "symbol": name,
                        "decision_points": decisions,
                        "control_nesting": nesting,
                        "partial": function_partial,
                        "metric_basis": "lower_bound" if function_partial else "complete_function",
                    },
                )
            )
        if (
            not partial
            and not dynamic
            and name.startswith("_")
            and references[name] == 1
            and name not in exported
            and function.type in {"function_declaration", "generator_function_declaration"}
            and function.parent.type == "program"
        ):
            record["candidates"].append(
                _candidate(
                    "unused_symbol",
                    "quality",
                    [location],
                    {
                        "symbol": name,
                        "basis": "Private top-level function has no other captured identifier reference",
                        "caveat": "Low-confidence open-world candidate: external scripts, exports and dynamic callers may use it; absence of a local reference does not authorize deletion.",
                    },
                    "low",
                )
            )
    if not partial:
        for node, _ in nodes:
            if node.type != "statement_block":
                continue
            terminated, locations = False, []
            for statement in node.named_children:
                if statement.type == "comment":
                    continue
                if terminated and statement.type not in _HOISTED:
                    locations.append(_location(path, statement))
                if statement.type in {"return_statement", "throw_statement"}:
                    terminated = True
            if locations:
                record["candidates"].append(
                    _candidate(
                        "unreachable_statement",
                        "quality",
                        locations[:20],
                        {
                            "statements": len(locations),
                            "proof": "Direct sibling statements after unconditional return or throw in the same block",
                            "caveat": "Syntactic execution reachability only; hoisted declarations excluded, and bindings or external contracts can still prevent safe deletion.",
                        },
                        "high",
                    )
                )
    if len(record["candidates"]) > MAX_INDEX:
        record["candidates"] = record["candidates"][:MAX_INDEX]
        record["gaps"].append("JavaScript per-file candidate index limit reached")
        partial = True
    record["status"] = "partial" if partial else "complete"
    record["gaps"] = sorted(set(record["gaps"]))
    return record


def _retained(candidates, limit):
    buckets = defaultdict(list)
    for candidate in sorted(
        candidates,
        key=lambda row: (row["locations"][0]["path"], row["locations"][0]["line"], row["id"]),
    ):
        buckets[(candidate["kind"], candidate["role"])].append(candidate)
    result, keys, index = [], sorted(buckets), 0
    while keys and len(result) < limit:
        keys = [key for key in keys if index < len(buckets[key])]
        for key in keys:
            if len(result) >= limit:
                break
            result.append(buckets[key][index])
        index += 1
    return result


def summarize_javascript(records: list[dict], javascript_files: int | None = None) -> dict:
    """Summarize captured records; resolve relative imports only against their paths."""
    total = len(records) if javascript_files is None else javascript_files
    selected = sorted(records, key=lambda row: row["path"])[:MAX_FILES]
    identity = selected[0]["analyzer"] if selected else javascript_analyzer_identity()
    gaps = {gap for row in selected for gap in row["gaps"]}
    if total > len(selected):
        gaps.add("JavaScript file limit or collection gap; some files lack AST analysis")
    candidates, clones, hotspots = [], defaultdict(list), []
    roles = {row["path"]: row["role"] for row in selected}
    paths, edges, unresolved = set(roles), [], 0
    for row in selected:
        candidates.extend(dict(candidate) for candidate in row["candidates"])
        for function in row["functions"]:
            hotspots.append(
                {
                    "path": row["path"],
                    "name": function["name"],
                    "line": function["location"]["line"],
                    "end_line": function["location"]["end_line"],
                    "role": row["role"],
                    "decision_points": function["decisions"],
                    "control_nesting": function["nesting"],
                    "partial": function["partial"],
                }
            )
            if function["fingerprint"]:
                clones[function["fingerprint"]].append(function["location"])
        for imported in row["imports"]:
            base = posixpath.normpath(
                posixpath.join(posixpath.dirname(row["path"]), imported["source"])
            )
            options = {base}
            suffix = PurePosixPath(base).suffix
            if not suffix:
                options.update(
                    base + extension for extension in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
                )
                options.update(
                    base + "/index" + extension for extension in (".js", ".jsx", ".ts", ".tsx")
                )
            elif suffix == ".js" and base not in paths:
                options.update(base[:-3] + extension for extension in (".ts", ".tsx"))
            matches = sorted(options & paths)
            if len(matches) == 1 and len(edges) < MAX_IMPORTS:
                edges.append(
                    {
                        "source": row["path"],
                        "target": matches[0],
                        "line": imported["line"],
                        "phase": imported["phase"],
                    }
                )
            else:
                unresolved += 1
    for locations in clones.values():
        if len(locations) > 1:
            candidates.append(
                _candidate(
                    "near_duplicate_function",
                    "reuse",
                    sorted(locations, key=lambda item: (item["path"], item["line"]))[:20],
                    {
                        "matching_functions": len(locations),
                        "normalization": "Exact parameter/body syntax including identifiers, literals and operators; only comments and definition names omitted",
                        "caveat": "Structural equality does not prove interchangeable responsibilities or a useful abstraction.",
                    },
                )
            )
    for candidate in candidates:
        candidate["roles"] = sorted(
            {roles[location["path"]] for location in candidate["locations"]}
        )
        candidate["role"] = candidate["roles"][0] if len(candidate["roles"]) == 1 else "unknown"
        candidate["id"] = (
            "js-"
            + hashlib.sha256(
                json.dumps(
                    [candidate["kind"], candidate["locations"], candidate["metrics"]],
                    sort_keys=True,
                ).encode()
            ).hexdigest()[:24]
        )
    if unresolved:
        gaps.add(
            "Some relative imports were unresolved, ambiguous or exceeded the edge limit; package aliases and tsconfig resolution are unsupported"
        )
    if len(candidates) > MAX_CANDIDATES:
        gaps.add(
            "JavaScript rich candidate sample is bounded; inspect the compact index and module overview"
        )
    if len(candidates) > MAX_INDEX:
        gaps.add("JavaScript candidate index limit reached")
    partial = (
        total > len(selected)
        or any(row["status"] != "complete" for row in selected)
        or unresolved > 0
        or len(candidates) > MAX_CANDIDATES
    )
    retained, indexed = _retained(candidates, MAX_CANDIDATES), _retained(candidates, MAX_INDEX)
    inbound, outbound = (
        Counter(edge["target"] for edge in edges),
        Counter(edge["source"] for edge in edges),
    )
    return {
        "schema_version": 1,
        "available": identity["available"],
        "analyzer": identity,
        "status": "unavailable"
        if not identity["available"]
        else "unsupported"
        if not total
        else "partial"
        if partial
        else "complete",
        "coverage": {
            "javascript_files": total,
            "parsed_files": sum(row["parsed"] for row in selected),
            "complete_files": sum(row["status"] == "complete" for row in selected),
            "overview_files": len(selected),
            "functions_total": sum(row["module"]["function_count"] for row in selected),
            "functions_analyzed": len(hotspots),
            "partial_functions": sum(row["partial"] for row in hotspots),
        },
        "summary": {
            "functions": len(hotspots),
            "dependency_edges": len(edges),
            "candidate_count": len(candidates),
        },
        "modules": [
            {
                "path": row["path"],
                "role": row["role"],
                "role_basis": row["role_basis"],
                "status": row["status"],
                **row["module"],
                "inbound": inbound[row["path"]],
                "outbound": outbound[row["path"]],
            }
            for row in selected
        ],
        "topology": {
            "edges": edges,
            "complete": not unresolved
            and total == len(selected)
            and all(row["status"] == "complete" for row in selected),
            "unresolved_relative_imports": unresolved,
            "caveat": "Captured relative imports only; no filesystem, package, alias or tsconfig resolution. Type-only/deferred edges retain their phase; not a runtime graph or entrypoint inventory.",
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
        "gaps": sorted(gaps),
        "limits": {
            "bytes_per_file": MAX_BYTES,
            "ast_nodes_per_file": MAX_NODES,
            "nodes_per_function": MAX_FUNCTION_NODES,
            "functions_per_file": MAX_FUNCTIONS,
            "files": MAX_FILES,
            "import_edges": MAX_IMPORTS,
            "candidates": MAX_CANDIDATES,
            "candidate_index": MAX_INDEX,
            "decision_threshold": DECISION_THRESHOLD,
            "nesting_threshold": NESTING_THRESHOLD,
        },
        "caveat": _CAVEAT,
    }
