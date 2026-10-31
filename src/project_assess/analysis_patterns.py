"""Bounded AST patterns. Similarity is review evidence, never permission to merge/delete."""

from __future__ import annotations

import ast
import hashlib
import json
from collections import defaultdict

MAX_BLOCKS = 32
MAX_UNREACHABLE = 100
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_FUNCTIONS, ast.ClassDef, ast.Lambda)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _location(path, node, end=None):
    return {
        "path": path,
        "line": node.lineno,
        "end_line": (end or node).end_lineno or (end or node).lineno,
    }


def _canonical(node, bindings, *, shape=False):
    if isinstance(node, list):
        return [_canonical(item, bindings, shape=shape) for item in node]
    if not isinstance(node, ast.AST):
        return node
    fields = []
    for name, value in ast.iter_fields(node):
        if isinstance(node, ast.Name) and name == "id":
            value = "identifier" if shape else bindings.get(value, value)
        elif isinstance(node, ast.arg) and name == "arg":
            value = "argument" if shape else bindings.get(value, value)
        elif isinstance(node, ast.Constant) and name == "value":
            value = type(value).__name__ if shape else repr(value)
        elif isinstance(node, ast.Attribute) and name == "attr" and shape:
            value = "attribute"
        fields.append((name, _canonical(value, bindings, shape=shape)))
    return [type(node).__name__, fields]


def _terminates(statement):
    # No guesses about calls, loops, try/finally, match completeness or exceptions.
    if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    return (
        isinstance(statement, ast.If)
        and bool(statement.body)
        and bool(statement.orelse)
        and _suite_terminates(statement.body)
        and _suite_terminates(statement.orelse)
    )


def _suite_terminates(body):
    return any(_terminates(statement) for statement in body)


def _suites(body, observed=None):
    pending = [body]
    while pending:
        suite = pending.pop()
        if observed is not None:
            suite = [statement for statement in suite if id(statement) in observed]
        yield suite
        for statement in reversed(suite):
            if isinstance(statement, _SCOPES):
                continue
            for _, value in ast.iter_fields(statement):
                if isinstance(value, list):
                    if value and all(isinstance(item, ast.stmt) for item in value):
                        pending.append(value)
                    else:
                        for item in value:
                            if isinstance(item, (ast.ExceptHandler, ast.match_case)):
                                pending.append(item.body)


def function_patterns(path, function, own_nodes, *, partial=False):
    """Reuse a bounded function traversal and leave incomplete similarity unknown."""
    result = {
        "near_fingerprint": None,
        "shape_fingerprint": None,
        "blocks": [],
        "unreachable": [],
        "limits_reached": [],
    }
    observed = {id(node) for node, _, _ in own_nodes}
    body = function.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            body = body[1:]
    for suite in _suites(body, observed):
        terminator = None
        for statement in suite:
            if id(statement) not in observed:
                continue
            if terminator is not None:
                result["unreachable"].append(
                    {
                        "kind": "unreachable_statement",
                        "lens": "quality",
                        "locations": [_location(path, statement)],
                        "confidence": "high",
                        "metrics": {
                            "reason": "statement follows unconditional control transfer in the same suite",
                            "terminator_line": terminator.lineno,
                        },
                        "caveat": "Syntactic reachability only; preserve surrounding cleanup and public contracts.",
                    }
                )
                if len(result["unreachable"]) >= MAX_UNREACHABLE:
                    result["limits_reached"].append("unreachable statement limit")
                    return result
            elif _terminates(statement):
                terminator = statement
        # Literal false branches are unreachable without evaluating project code.
        for statement in suite:
            if id(statement) not in observed:
                continue
            if isinstance(statement, (ast.If, ast.While)) and isinstance(
                statement.test, ast.Constant
            ):
                if statement.test.value is False and statement.body:
                    result["unreachable"].append(
                        {
                            "kind": "unreachable_statement",
                            "lens": "quality",
                            "locations": [_location(path, statement.body[0], statement.body[-1])],
                            "confidence": "high",
                            "metrics": {
                                "reason": "body guarded by the literal False",
                                "guard_line": statement.lineno,
                            },
                            "caveat": "The guard may intentionally retain disabled scaffolding; review intent before removal.",
                        }
                    )
                    if len(result["unreachable"]) >= MAX_UNREACHABLE:
                        result["limits_reached"].append("unreachable statement limit")
                        return result
    if (
        partial
        or len(body) < 3
        or len(own_nodes) < 20
        or any(isinstance(node, _SCOPES) for node, _, _ in own_nodes)
    ):
        return result
    parameters = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    parameters += [arg for arg in (function.args.vararg, function.args.kwarg) if arg]
    names = [arg.arg for arg in parameters]
    names.extend(
        node.id
        for node, _, _ in own_nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    )
    bindings = {name: f"local_{index}" for index, name in enumerate(dict.fromkeys(names))}
    contract = [
        type(function).__name__,
        ast.dump(function.returns) if function.returns else None,
        [ast.dump(node) for node in function.decorator_list],
    ]
    normalized = [_canonical(function.args, bindings), _canonical(body, bindings)]
    result["near_fingerprint"] = _digest([contract, normalized])
    result["shape_fingerprint"] = _digest(
        [
            contract,
            _canonical(function.args, bindings, shape=True),
            _canonical(body, bindings, shape=True),
        ]
    )
    result["pattern_details"] = {
        "callees": sorted(
            {
                node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                for node, _, _ in own_nodes
                if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
            }
        )[:20],
        "literal_digest": _digest(
            [ast.dump(node) for node, _, _ in own_nodes if isinstance(node, ast.Constant)]
        ),
        "signature_digest": _digest(ast.dump(function.args)),
    }
    for suite in _suites(body):
        for index in range(max(len(suite) - 2, 0)):
            block = suite[index : index + 3]
            if any(
                isinstance(node, _SCOPES) for statement in block for node in ast.walk(statement)
            ):
                continue
            if sum(1 for statement in block for _ in ast.walk(statement)) < 20:
                continue
            result["blocks"].append(
                {
                    "fingerprint": _digest(_canonical(block, bindings)),
                    "location": _location(path, block[0], block[-1]),
                    "statements": 3,
                }
            )
            if len(result["blocks"]) >= MAX_BLOCKS:
                result["limits_reached"].append("duplicate block window limit")
                return result
    return result


def pattern_candidates(records):
    near, shapes, blocks = defaultdict(list), defaultdict(list), defaultdict(list)
    candidates = []
    for record in records:
        for function in record["functions"]:
            patterns = function.get("patterns", {})
            candidates.extend(dict(row) for row in patterns.get("unreachable", []))
            for groups, key in ((near, "near_fingerprint"), (shapes, "shape_fingerprint")):
                if patterns.get(key):
                    groups[patterns[key]].append(function)
            for block in patterns.get("blocks", []):
                blocks[block["fingerprint"]].append(block)
    emitted = set()
    for groups, normalization, confidence in (
        (near, "local bindings normalized; literals, callees and decorators retained", "medium"),
        (shapes, "same AST shape; identifiers, attributes and literal values may differ", "low"),
    ):
        for functions in groups.values():
            if len(functions) < 2 or len({row.get("fingerprint") for row in functions}) == 1:
                continue
            identity = tuple(
                (row["location"]["path"], row["location"]["line"]) for row in functions
            )
            if identity in emitted:
                continue
            emitted.add(identity)
            details = [row["patterns"].get("pattern_details", {}) for row in functions]
            candidates.append(
                {
                    "kind": "near_duplicate_function",
                    "lens": "reuse",
                    "confidence": confidence,
                    "locations": [row["location"] for row in functions[:20]],
                    "metrics": {
                        "matching_functions": len(functions),
                        "normalization": normalization,
                        "callee_variants": [
                            list(values)
                            for values in sorted(
                                {tuple(item.get("callees", [])) for item in details}
                            )
                        ][:20],
                        "literal_differences": len({item.get("literal_digest") for item in details})
                        > 1,
                        "signature_differences": len(
                            {item.get("signature_digest") for item in details}
                        )
                        > 1,
                    },
                    "counterevidence": [
                        "Parameter names can be public keyword contracts; provider, literal, side-effect and authorization differences may be intentional."
                    ],
                    "caveat": "Similarity does not establish interchangeable behavior or a safe shared abstraction.",
                }
            )
    for rows in blocks.values():
        locations = {tuple(row["location"].items()): row["location"] for row in rows}
        if len(locations) < 2:
            continue
        candidates.append(
            {
                "kind": "duplicate_block",
                "lens": "reuse",
                "confidence": "medium",
                "locations": list(locations.values())[:20],
                "metrics": {
                    "matching_blocks": len(locations),
                    "statements": 3,
                    "normalization": "local bindings normalized; literals and callees retained",
                },
                "counterevidence": [
                    "Bindings, enclosing guards, cleanup, exceptions and callers may require distinct blocks."
                ],
                "caveat": "A repeated block is a review lead, not proof that extraction lowers upkeep.",
            }
        )
    return candidates
