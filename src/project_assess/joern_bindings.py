"""Bounded captured-syntax counterchecks for Joern's unread-binding hints."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import PurePosixPath

MAX_BYTES = 2 * 1024**2
MAX_NODES = 200_000


class _Bindings:
    def __init__(self):
        self.parents = [None]
        self.kinds = ["module"]
        self.bound = [defaultdict(list)]
        self.uncertain = set()
        self.locations = defaultdict(set)
        self.location_symbols = defaultdict(set)
        self.reads = []
        self.functions = {}
        self.parameter_contracts = {}

    def scope(self, parent, kind):
        self.parents.append(parent)
        self.kinds.append(kind)
        self.bound.append(defaultdict(list))
        return len(self.parents) - 1

    def closure_parent(self, scope):
        # Python class namespaces are visible while evaluating defaults/bases,
        # but methods/lambdas/comprehensions close over the surrounding scope.
        while self.kinds[scope] == "class":
            scope = self.parents[scope]
        return scope

    def declare(self, scope, name, line, kind):
        key = (scope, name)
        self.bound[scope][name].append(line)
        self.locations[(line, name, kind)].add(key)
        self.location_symbols[(line, name)].add(key)

    def finish(self, expired):
        self.used = set()
        resolved = {}
        work = 0
        if expired():
            return None
        for scope, name in self.reads:
            current, trail, owner = scope, [], None
            while current is not None:
                work += 1
                if work > MAX_NODES or work % 256 == 0 and expired():
                    return None
                key = (current, name)
                if key in resolved:
                    owner = resolved[key]
                    break
                trail.append(key)
                if name in self.bound[current]:
                    owner = key
                    break
                current = self.parents[current]
            work += len(trail)
            if work > MAX_NODES:
                return None
            for key in trail:
                resolved[key] = owner
            if owner is not None:
                self.used.add(owner)
        return None if expired() else self

    def check(self, line, name, kind):
        if name.startswith("_"):
            return "intentional_discard_hint"
        if (line, name) in self.functions:
            return self.functions[(line, name)]
        matches = self.locations.get((line, name, kind), ())
        if not matches:
            # Some producer locals are original parameters/destructuring. Only
            # an observed read can reject such a mismatch; never qualify it dead.
            others = self.location_symbols.get((line, name), ())
            if len(others) == 1 and next(iter(others)) in self.used:
                return "source_read_or_capture"
        if len(matches) != 1:
            return "source_binding_scope_unknown"
        key = next(iter(matches))
        if key in self.used:
            return "source_read_or_capture"
        scope, symbol = key
        if kind == "parameter" and scope in self.parameter_contracts:
            return self.parameter_contracts[scope]
        if len(self.bound[scope][symbol]) != 1:
            return "source_binding_scope_unknown"
        if scope in self.uncertain:
            return "source_binding_scope_unknown"
        return "source_unread"


def _python(text, expired):
    index = _Bindings()
    stack = [(ast.parse(text), 0)]
    count = 0
    while stack:
        node, scope = stack.pop()
        count += 1
        if count > MAX_NODES or count % 256 == 0 and expired():
            return None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                index.declare(scope, node.name, node.lineno, "local")
                index.functions[(node.lineno, node.name)] = (
                    "decorated_function_binding"
                    if node.decorator_list
                    else "function_binding_contract_unknown"
                )
                stack.extend((item, scope) for item in node.decorator_list)
                if node.returns:
                    stack.append((node.returns, scope))
            arguments = node.args
            # Defaults execute in the defining scope, including closure defaults.
            stack.extend((item, scope) for item in arguments.defaults)
            stack.extend((item, scope) for item in arguments.kw_defaults if item)
            child = index.scope(index.closure_parent(scope), "function")
            if not isinstance(node, ast.Lambda):
                statements = [
                    item
                    for item in node.body
                    if not (
                        isinstance(item, ast.Expr)
                        and isinstance(item.value, ast.Constant)
                        and isinstance(item.value.value, str)
                    )
                ]
                if len(statements) == 1 and isinstance(statements[0], ast.Raise):
                    index.parameter_contracts[child] = "raising_stub_signature"
                elif node.decorator_list:
                    index.parameter_contracts[child] = "decorated_signature_contract_unknown"
                elif not node.name.startswith("_") or node.name.startswith("__"):
                    index.parameter_contracts[child] = "public_signature_contract_unknown"
            else:
                index.parameter_contracts[child] = "callback_signature_contract_unknown"
            args = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
            args.extend(arg for arg in (arguments.vararg, arguments.kwarg) if arg)
            for arg in args:
                index.declare(child, arg.arg, arg.lineno, "parameter")
                if arg.annotation:
                    stack.append((arg.annotation, scope))
            body = [node.body] if isinstance(node, ast.Lambda) else node.body
            stack.extend((item, child) for item in body)
            continue
        if isinstance(node, ast.ClassDef):
            index.declare(scope, node.name, node.lineno, "local")
            index.functions[(node.lineno, node.name)] = "function_binding_contract_unknown"
            stack.extend(
                (item, scope) for item in [*node.bases, *node.keywords, *node.decorator_list]
            )
            child = index.scope(index.closure_parent(scope), "class")
            index.uncertain.add(child)
            stack.extend((item, child) for item in node.body)
            continue
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            # Assignment-expression and comprehension ownership is deliberately
            # unresolved; a same-named child binding must not hide an outer read.
            index.uncertain.add(scope)
            child = index.scope(index.closure_parent(scope), "comprehension")
            index.uncertain.add(child)
            stack.extend((item, child) for item in ast.iter_child_nodes(node))
            continue
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            index.uncertain.add(scope)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                index.reads.append((scope, node.id))
            elif isinstance(node.ctx, (ast.Store, ast.Del)):
                index.declare(scope, node.id, node.lineno, "local")
        elif isinstance(node, ast.alias):
            name = node.asname or node.name.split(".")[0]
            index.declare(scope, name, node.lineno, "local")
        elif isinstance(node, ast.ExceptHandler) and node.name:
            index.declare(scope, node.name, node.lineno, "local")
        stack.extend((item, scope) for item in ast.iter_child_nodes(node))
    return index.finish(expired)


def _javascript(path, text, expired):
    from .javascript_analysis import _FUNCTIONS, _parser, javascript_analyzer_identity

    if not javascript_analyzer_identity()["available"]:
        return None
    raw = text.encode("utf-8")
    tree = _parser(path).parse(raw)
    if tree.root_node.has_error:
        return None
    index = _Bindings()
    stack = [(tree.root_node, 0)]
    nodes, owners = [], {}
    scopes = {"statement_block", "for_in_statement", "for_statement", "catch_clause", "switch_body"}
    while stack:
        node, scope = stack.pop()
        if len(nodes) >= MAX_NODES or len(nodes) % 256 == 0 and expired():
            return None
        nodes.append(node)
        owners[node.id] = scope
        if node.type in _FUNCTIONS:
            child = index.scope(scope, "function")
            name = node.child_by_field_name("name")
            if name is not None:
                symbol = raw[name.start_byte : name.end_byte].decode()
                index.declare(scope, symbol, name.start_point.row + 1, "local")
                index.functions[(name.start_point.row + 1, symbol)] = (
                    "function_binding_contract_unknown"
                )
            private = name is not None and raw[name.start_byte : name.end_byte].startswith(b"_")
            private = private or any(
                item.type == "accessibility_modifier"
                and raw[item.start_byte : item.end_byte] == b"private"
                for item in node.named_children
            )
            if not private:
                index.parameter_contracts[child] = "public_or_callback_signature_unknown"
            for item in node.named_children:
                stack.append((item, scope if item == name else child))
        else:
            child = index.scope(scope, "block") if node.type in scopes else scope
            stack.extend((item, child) for item in node.named_children)
    declarations = set()

    def declare(node, kind, *, function_scope=False):
        if node is None:
            return
        scope = owners[node.id]
        if node.type in {"array_pattern", "object_pattern", "rest_pattern"}:
            for item in node.named_children:
                declare(item, kind, function_scope=function_scope)
            return
        if node.type in {"assignment_pattern", "object_assignment_pattern", "pair_pattern"}:
            declare(
                node.child_by_field_name("left") or node.child_by_field_name("value"),
                kind,
                function_scope=function_scope,
            )
            return
        if node.type not in {"identifier", "shorthand_property_identifier_pattern"}:
            index.uncertain.add(scope)
            return
        if function_scope:
            while index.kinds[scope] not in {"module", "function"}:
                scope = index.parents[scope]
        symbol = raw[node.start_byte : node.end_byte].decode()
        index.declare(scope, symbol, node.start_point.row + 1, kind)
        declarations.add(node.id)

    for node in nodes:
        if node.type == "variable_declarator":
            declare(
                node.child_by_field_name("name"),
                "local",
                function_scope=node.parent.type == "variable_declaration",
            )
        elif node.type == "for_in_statement":
            declare(node.child_by_field_name("left"), "local")
        elif node.type == "catch_clause":
            declare(node.child_by_field_name("parameter"), "local")
        elif node.type in {"required_parameter", "optional_parameter"}:
            declare(node.child_by_field_name("pattern"), "parameter")
        elif node.type == "formal_parameters":
            for item in node.named_children:
                if item.type in {
                    "identifier",
                    "assignment_pattern",
                    "array_pattern",
                    "object_pattern",
                    "rest_pattern",
                }:
                    declare(item, "parameter")
        elif node.type == "arrow_function":
            declare(node.child_by_field_name("parameter"), "parameter")
        elif node.type in _FUNCTIONS:
            name = node.child_by_field_name("name")
            if name is not None:
                declarations.add(name.id)
    for node in nodes:
        if (
            node.type not in {"identifier", "shorthand_property_identifier"}
            or node.id in declarations
        ):
            continue
        parent = node.parent
        if (
            parent
            and parent.type == "assignment_expression"
            and node == parent.child_by_field_name("left")
        ):
            # A simple assignment writes; compound assignments remain reads.
            continue
        if parent and parent.type in {"import_specifier", "import_clause", "namespace_import"}:
            index.uncertain.add(owners[node.id])
            continue
        index.reads.append((owners[node.id], raw[node.start_byte : node.end_byte].decode()))
    return index.finish(expired)


class BindingCountercheck:
    """Source contradictions reject leads; lack of a read never proves deletion safe."""

    def __init__(self, sources, expired):
        self.sources, self.expired, self.cache = sources, expired, {}

    def check(self, path, line, symbol, kind):
        if path not in self.cache:
            text = self.sources[path].get("text")
            if not isinstance(text, str):
                text = "\n".join(self.sources[path]["lines"])
            result = None
            try:
                if len(text.encode("utf-8")) <= MAX_BYTES and not self.expired():
                    suffix = PurePosixPath(path).suffix.lower()
                    if suffix == ".py":
                        result = _python(text, self.expired)
                    elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
                        result = _javascript(path, text, self.expired)
            except (
                SyntaxError,
                ValueError,
                TypeError,
                AttributeError,
                ImportError,
                OSError,
                RecursionError,
            ):
                pass
            self.cache[path] = result
        index = self.cache[path]
        return (
            index.check(line, symbol, kind)
            if index is not None
            else "source_syntax_unavailable_or_bounded"
        )
