"""Bounded source-control inventory from the already parsed JavaScript syntax.

Signals identify syntax and review locations, never vulnerabilities, effective
controls, inferred runtime behavior or a project score.
"""

from __future__ import annotations

import hashlib
import heapq
import re
from collections import Counter, defaultdict

MAX_SIGNALS = 64
MAX_SCOPE_DEPTH = 64
DIMENSIONS = ["security", "operability", "extensibility", "performance"]
_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "generator_function_declaration",
    "generator_function",
    "arrow_function",
    "method_definition",
}
_LOOPS = {"for_statement", "for_in_statement", "while_statement", "do_statement"}
_MODULES = {
    "child_process",
    "fs",
    "fs/promises",
    "crypto",
    "https",
    "http",
    "events",
    "node:child_process",
    "node:fs",
    "node:fs/promises",
    "node:crypto",
    "node:https",
    "node:http",
    "node:events",
}
_OPTIONS = {
    "shell",
    "timeout",
    "signal",
    "concurrency",
    "maxRetries",
    "highWaterMark",
    "limit",
    "batchSize",
    "rejectUnauthorized",
}
_CAVEAT = "Syntax inventory only: names, options and boundaries do not establish control effectiveness, exposure, workload cost or safe changes."


def _text(node, raw, bound=256):
    return (
        raw[node.start_byte : node.end_byte][:bound].decode("utf-8", errors="replace")
        if node
        else ""
    )


def _callee(node, raw, depth=0):
    if node is None or depth > 16:
        return None
    if node.type in {"identifier", "property_identifier"}:
        value = _text(node, raw)
        return value if re.fullmatch(r"[A-Za-z_$][\w$]{0,127}", value) else None
    if node.type == "member_expression":
        base = _callee(node.child_by_field_name("object"), raw, depth + 1)
        prop = _callee(node.child_by_field_name("property"), raw, depth + 1)
        return base + "." + prop if base and prop and len(base + prop) < 256 else None
    return None


def _literal(node, raw):
    if node and node.type == "string":
        value = _text(node, raw, 256)
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0] and "\\" not in value:
            return value[1:-1]
    return None


def _scope(node):
    current = node.parent
    for _ in range(MAX_SCOPE_DEPTH):
        if current is None:
            break
        if current.type in _FUNCTIONS or current.type == "program":
            return current.id
        current = current.parent
    return None


def _bindings(pattern, raw):
    """Only declaration patterns: defaults/type annotations are not bindings."""
    pending, names, seen = [pattern] if pattern else [], set(), 0
    while pending and seen < 1000:
        node = pending.pop()
        seen += 1
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            names.add(_text(node, raw))
        elif node.type in {"required_parameter", "optional_parameter"}:
            child = node.child_by_field_name("pattern") or node.child_by_field_name("name")
            if child:
                pending.append(child)
        elif node.type in {"assignment_pattern", "object_assignment_pattern"}:
            child = node.child_by_field_name("left")
            if child:
                pending.append(child)
        elif node.type == "pair_pattern":
            child = node.child_by_field_name("value")
            if child:
                pending.append(child)
        elif node.type in {"formal_parameters", "object_pattern", "array_pattern", "rest_pattern"}:
            pending.extend(node.named_children)
    return names, bool(pending)


def _imports(nodes, raw):
    aliases, require_sites = defaultdict(dict), {}
    for node, _ in nodes:
        module = None
        if node.type == "import_statement":
            module = _literal(node.child_by_field_name("source"), raw)
            if module not in _MODULES:
                continue
            module = module.removeprefix("node:")
            for clause in node.named_children:
                if clause.type != "import_clause":
                    continue
                for child in clause.named_children:
                    if child.type == "identifier":
                        aliases[_scope(node)][_text(child, raw)] = module
                    elif child.type == "namespace_import":
                        names = [x for x in child.named_children if x.type == "identifier"]
                        if names:
                            aliases[_scope(node)][_text(names[-1], raw)] = module
                    elif child.type == "named_imports":
                        for spec in child.named_children:
                            name = spec.child_by_field_name("name")
                            local = spec.child_by_field_name("alias") or name
                            if name and local:
                                aliases[_scope(node)][_text(local, raw)] = (
                                    module + "." + _text(name, raw)
                                )
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if not value or value.type != "call_expression":
                continue
            if _callee(value.child_by_field_name("function"), raw) != "require":
                continue
            args = value.child_by_field_name("arguments")
            module = (
                _literal(args.named_children[0], raw)
                if args and args.named_child_count == 1
                else None
            )
            if module not in _MODULES:
                continue
            module = module.removeprefix("node:")
            name = node.child_by_field_name("name")
            if name and name.type == "identifier":
                aliases[_scope(node)][_text(name, raw)] = module
                require_sites[(_scope(node), _text(name, raw))] = node
            elif name and name.type == "object_pattern":
                for prop in name.named_children:
                    if prop.type == "shorthand_property_identifier_pattern":
                        aliases[_scope(node)][_text(prop, raw)] = module + "." + _text(prop, raw)
                        require_sites[(_scope(node), _text(prop, raw))] = node
                    elif prop.type == "pair_pattern":
                        key, local = (
                            prop.child_by_field_name("key"),
                            prop.child_by_field_name("value"),
                        )
                        if key and local and local.type == "identifier":
                            aliases[_scope(node)][_text(local, raw)] = (
                                module + "." + _text(key, raw)
                            )
    return aliases, require_sites


def _options(arguments, raw):
    result = {}
    for argument in arguments:
        if argument.type != "object":
            continue
        pairs = argument.named_children
        if len(pairs) > 64:
            result["options_partial"] = True
        for pair in pairs[:64]:
            key, value = pair.child_by_field_name("key"), pair.child_by_field_name("value")
            name = (
                _text(key, raw)
                if key and key.type in {"property_identifier", "identifier"}
                else _literal(key, raw)
            )
            if name not in _OPTIONS or not value:
                continue
            text = _text(value, raw, 32)
            result[name] = (
                text == "true"
                if value.type in {"true", "false"}
                else int(text)
                if value.type == "number" and re.fullmatch(r"\d{1,9}", text)
                else "dynamic"
            )
    return result


def _variant(context):
    """Closed semantic shapes, never payload values or high-cardinality owners."""
    options = context.get("options", {})
    shapes = []
    for key in sorted(_OPTIONS & options.keys()):
        value = options[key]
        shape = (
            "true"
            if value is True
            else "false"
            if value is False
            else "positive"
            if type(value) is int and value > 0
            else "nonpositive"
            if type(value) is int
            else "dynamic"
        )
        shapes.append((key, shape))
    return (
        context["category"],
        str(context.get("shell_option", "absent")),
        bool(context.get("implicit_shell")),
        context.get("algorithm", "absent"),
        bool(context.get("jsx_attribute")),
        tuple(shapes),
    )


def analyze_javascript_controls(path, raw, nodes, *, partial=False, node_limit=100_000):
    """Reuse capped native nodes; retain diverse fixed-size signals per file."""
    aliases, require_sites = _imports(nodes, raw)
    scopes, truncated_bindings = defaultdict(Counter), False
    mutated = set()
    for node, _ in nodes:
        if node.type in _FUNCTIONS:
            names, clipped = _bindings(
                node.child_by_field_name("parameters") or node.child_by_field_name("parameter"), raw
            )
            scopes[node.id].update(names)
            truncated_bindings |= clipped
            if node.type in {"function_expression", "generator_function"}:
                name = node.child_by_field_name("name")
                if name:
                    scopes[node.id].update([_text(name, raw)])
        if node.type == "catch_clause":
            names, clipped = _bindings(node.child_by_field_name("parameter"), raw)
            scopes[_scope(node)].update(names)
            truncated_bindings |= clipped
        if node.type == "variable_declarator":
            names, clipped = _bindings(node.child_by_field_name("name"), raw)
            scopes[_scope(node)].update(names)
            truncated_bindings |= clipped
        elif node.type == "import_clause":
            for child in node.named_children:
                if child.type == "identifier":
                    scopes[_scope(node)].update([_text(child, raw)])
                elif child.type == "namespace_import":
                    names = [x for x in child.named_children if x.type == "identifier"]
                    if names:
                        scopes[_scope(node)].update([_text(names[-1], raw)])
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        name = spec.child_by_field_name("alias") or spec.child_by_field_name("name")
                        if name:
                            scopes[_scope(node)].update([_text(name, raw)])
        elif node.type in {"function_declaration", "class_declaration", "class"}:
            name = node.child_by_field_name("name")
            if name:
                scopes[_scope(node)].update([_text(name, raw)])
        elif node.type in {
            "assignment_expression",
            "augmented_assignment_expression",
            "update_expression",
        }:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            name = _callee(target, raw)
            if name:
                mutated.add(name.split(".", 1)[0])
    buckets, counts, variants = defaultdict(list), Counter(), Counter()
    unresolved_calls, scope_omissions, partial_options = 0, 0, 0

    def resolve(name, node):
        if not name:
            return None, "unresolved"
        if _scope(node) is None:
            return None, "scope_depth_limit"
        head, *tail = name.split(".")
        if head in mutated or truncated_bindings:
            return None, "mutated_or_partial_binding"
        current = node.parent
        for _ in range(MAX_SCOPE_DEPTH):
            if current is None:
                break
            if current.type in _FUNCTIONS or current.type == "program":
                if scopes[current.id][head]:
                    alias = aliases[current.id].get(head)
                    # A known import/require must be the sole declaration.
                    site = require_sites.get((current.id, head))
                    require_shadowed = "require" in mutated
                    parent = site.parent if site else None
                    for _ in range(MAX_SCOPE_DEPTH):
                        if parent is None:
                            break
                        if parent.type in _FUNCTIONS or parent.type == "program":
                            require_shadowed |= bool(scopes[parent.id]["require"])
                        parent = parent.parent
                    require_shadowed |= parent is not None
                    if alias and scopes[current.id][head] == 1 and not require_shadowed:
                        return ".".join([alias, *tail]), "import_binding"
                    if tail and head not in {"console", "Promise", "AbortSignal", "customElements"}:
                        return name, "local_member"
                    return None, "shadowed"
            current = current.parent
        return name, "unresolved_member" if tail else "unshadowed_global"

    def emit(
        kind, dimensions, node, *, name=None, resolution="syntax", category="mechanism", extra=None
    ):
        owner, repeated, current = "<module>", False, node.parent
        for _ in range(MAX_SCOPE_DEPTH):
            if current is None:
                break
            if current.type in _FUNCTIONS:
                owner = _callee(current.child_by_field_name("name"), raw) or "<anonymous>"
                break
            repeated |= current.type in _LOOPS
            current = current.parent
        counts[kind] += 1
        signal = {
            "kind": kind,
            "dimensions": dimensions,
            "locations": [
                {"path": path, "line": node.start_point.row + 1, "end_line": node.end_point.row + 1}
            ],
            "context": {
                "owner": owner,
                "scope_partial": _scope(node) is None,
                "callee": name,
                "resolution": resolution,
                "in_loop": repeated,
                "category": category,
                **(extra or {}),
            },
            "method": "tree_sitter_syntax",
            "confidence": "hint"
            if category == "name_hint"
            or resolution in {"unresolved_member", "local_member"}
            or partial
            else "source",
            "limitations": [_CAVEAT],
        }
        variant = _variant(signal["context"])
        signal["sampling_variant"] = hashlib.sha256(repr(variant).encode()).hexdigest()
        round_number = variants[(kind, variant)]
        variants[(kind, variant)] += 1
        category_rank = {"risk_candidate": 0, "mechanism": 1, "name_hint": 2}[category]
        fingerprint = int(hashlib.sha256(repr(variant).encode()).hexdigest(), 16)
        rank = (round_number, category_rank, fingerprint, node.start_point.row)
        item = (*(-value for value in rank), counts[kind], signal)
        bucket = buckets[kind]
        if len(bucket) < MAX_SIGNALS:
            heapq.heappush(bucket, item)
        elif rank < tuple(-value for value in bucket[0][:4]):
            heapq.heapreplace(bucket, item)

    for node, _ in nodes:
        if node.type == "catch_clause":
            emit("exception_handler", ["operability"], node)
        if node.type in {"interface_declaration", "abstract_class_declaration"}:
            emit("interface_declaration", ["extensibility"], node)
        if (
            node.type == "method_definition"
            and _text(node.child_by_field_name("name"), raw) == "constructor"
        ):
            params, clipped = _bindings(node.child_by_field_name("parameters"), raw)
            if params:
                emit(
                    "constructor_parameters",
                    ["extensibility"],
                    node,
                    extra={"parameter_count": len(params), "partial": clipped},
                )
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            name = _callee(left, raw)
            if name and name.rsplit(".", 1)[-1] in {"innerHTML", "outerHTML"}:
                emit(
                    "html_sink",
                    ["security"],
                    node,
                    name=name,
                    resolution="unresolved_member",
                    category="risk_candidate",
                )
        if (
            node.type == "jsx_attribute"
            and node.named_child_count
            and _text(node.named_children[0], raw) == "dangerouslySetInnerHTML"
        ):
            emit(
                "html_sink",
                ["security"],
                node,
                category="risk_candidate",
                extra={"jsx_attribute": True},
            )
        if node.type not in {"call_expression", "new_expression"}:
            continue
        target = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        name, resolution = resolve(_callee(target, raw), node)
        if not name:
            unresolved_calls += 1
            scope_omissions += resolution == "scope_depth_limit"
            continue
        if resolution in {"unresolved_member", "local_member"}:
            unresolved_calls += 1
        args_node = node.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node else []
        options = _options(args, raw)
        partial_options += bool(options.get("options_partial"))
        tail, head = name.rsplit(".", 1)[-1], name.split(".", 1)[0]
        if name in {"eval", "Function"}:
            emit(
                "dynamic_code_execution",
                ["security"],
                node,
                name=name,
                resolution=resolution,
                category="risk_candidate",
                extra={"argument_literal": bool(args and args[0].type == "string")},
            )
        if (
            resolution == "import_binding"
            and name.startswith("child_process.")
            and tail
            in {
                "exec",
                "execSync",
                "execFile",
                "execFileSync",
                "spawn",
                "spawnSync",
            }
        ):
            shell = tail in {"exec", "execSync"} or options.get("shell") is True
            emit(
                "shell_execution" if shell else "process_execution",
                ["security"],
                node,
                name=name,
                resolution=resolution,
                category="risk_candidate",
                extra={
                    "shell_option": options.get(
                        "shell",
                        "unresolved_options" if options.get("options_partial") else "default",
                    ),
                    "implicit_shell": tail in {"exec", "execSync"},
                },
            )
        if (
            resolution == "import_binding"
            and name in {"https.request", "https.get"}
            and options.get("rejectUnauthorized") is False
        ):
            emit(
                "tls_verification_disabled",
                ["security"],
                node,
                name=name,
                resolution=resolution,
                category="risk_candidate",
            )
        if resolution == "import_binding" and name == "crypto.timingSafeEqual":
            emit("constant_time_comparison", ["security"], node, name=name, resolution=resolution)
        if name == "crypto.createHash" and args and _literal(args[0], raw) in {"md5", "sha1"}:
            emit(
                "legacy_hash_algorithm",
                ["security"],
                node,
                name=name,
                resolution=resolution,
                category="risk_candidate",
                extra={"algorithm": _literal(args[0], raw)},
            )
        if tail in {"query", "execute"}:
            shape = args[0].type if args else "missing"
            interpolated = args and (
                shape == "binary_expression"
                or shape == "template_string"
                and any(x.type == "template_substitution" for x in args[0].named_children)
            )
            emit(
                "interpolated_query_argument" if interpolated else "query_call",
                ["security", "performance"] if interpolated else ["performance"],
                node,
                name=name,
                resolution=resolution,
                category="name_hint",
                extra={"argument_shape": shape, "argument_count": len(args)},
            )
        if (
            name.startswith("console.")
            and tail in {"debug", "info", "warn", "error", "log", "trace"}
            or head in {"logger", "log"}
            and tail in {"debug", "info", "warn", "error", "exception"}
        ):
            emit(
                "diagnostic_logging",
                ["operability"],
                node,
                name=name,
                resolution=resolution,
                category="name_hint" if head != "console" else "mechanism",
            )
        if name in {"setTimeout", "setInterval"}:
            emit(
                "timer_schedule",
                ["operability", "performance"],
                node,
                name=name,
                resolution=resolution,
                extra={"delay_literal": bool(len(args) > 1 and args[1].type == "number")},
            )
        if tail.lower() in {"retry", "backoff", "checkpoint", "flush", "persist"}:
            emit(
                "recovery_call_hint",
                ["operability"],
                node,
                name=name,
                resolution=resolution,
                category="name_hint",
            )
        if tail in {"register", "use", "plugin", "addPlugin", "define"}:
            emit(
                "registration_call_hint",
                ["extensibility"],
                node,
                name=name,
                resolution=resolution,
                category="name_hint",
            )
        if (
            tail in {"get", "route"}
            and args
            and _literal(args[0], raw)
            in {"/health", "/healthz", "/ready", "/readyz", "/live", "/livez"}
        ):
            emit(
                "health_route_hint",
                ["operability"],
                node,
                name=name,
                resolution=resolution,
                category="name_hint",
            )
        if name in {"Promise.all", "Promise.allSettled"}:
            emit("promise_batch", ["performance"], node, name=name, resolution=resolution)
        if name in {"AbortController", "AbortSignal.timeout"} or options.keys() & {
            "timeout",
            "signal",
            "concurrency",
            "highWaterMark",
            "limit",
            "batchSize",
        }:
            emit(
                "resource_bound_configuration",
                ["performance", "operability"],
                node,
                name=name,
                resolution=resolution,
                category="mechanism"
                if name in {"AbortController", "AbortSignal.timeout", "fetch"}
                else "name_hint",
                extra={"options": options},
            )
        if head.lower() in {"cache", "lrucache", "memo"} and tail in {
            "get",
            "set",
            "has",
            "delete",
        }:
            emit(
                "cache_access_hint",
                ["performance"],
                node,
                name=name,
                resolution=resolution,
                category="name_hint",
            )
        io = (
            name == "fetch"
            or resolution == "import_binding"
            and name.startswith(("fs.", "fs/promises.", "http.", "https."))
            or tail in {"query", "execute"}
        )
        if io:
            current, repeated = node.parent, False
            for _ in range(MAX_SCOPE_DEPTH):
                if current is None or current.type in _FUNCTIONS:
                    break
                repeated |= current.type in _LOOPS
                current = current.parent
            if repeated:
                emit(
                    "io_in_loop",
                    ["performance"],
                    node,
                    name=name,
                    resolution=resolution,
                    category="name_hint" if tail in {"query", "execute"} else "mechanism",
                )
        if (
            resolution == "import_binding"
            and name == "events.once"
            and len(args) > 1
            and _literal(args[1], raw) == "drain"
        ):
            emit(
                "stream_backpressure_event",
                ["performance", "operability"],
                node,
                name=name,
                resolution=resolution,
            )
    buckets = {
        kind: [
            item[-1]
            for item in sorted(bucket, key=lambda item: tuple(-value for value in item[:4]))
        ]
        for kind, bucket in buckets.items()
    }
    signals, index = [], 0
    while len(signals) < MAX_SIGNALS:
        advanced = False
        for kind in sorted(buckets):
            if index < len(buckets[kind]) and len(signals) < MAX_SIGNALS:
                signals.append(buckets[kind][index])
                advanced = True
        if not advanced:
            break
        index += 1
    omitted = sum(counts.values()) - len(signals)
    gaps = []
    if partial:
        gaps.append("JavaScript syntax/node traversal is partial; control inventory is incomplete.")
    if omitted:
        gaps.append("Per-file control signal limit reached; counts include omitted signals.")
    if scope_omissions:
        gaps.append("Enclosing-scope depth limit reached; affected call resolution omitted.")
    if partial_options:
        gaps.append("Call option-property limit reached; unexamined option values remain unknown.")
    if truncated_bindings:
        gaps.append(
            "Binding-pattern limit reached; global/import call resolution withheld where uncertain."
        )
    return {
        "path": path,
        "language": "javascript/typescript",
        "dimensions": list(DIMENSIONS),
        "status": "partial" if gaps else "complete",
        "coverage": {
            "nodes_examined": len(nodes),
            "node_limit": node_limit,
            "scope_depth_limit": MAX_SCOPE_DEPTH,
            "scope_omissions": scope_omissions,
            "unresolved_or_shadowed_calls": unresolved_calls,
            "partial_option_calls": partial_options,
            "signals_total": sum(counts.values()),
            "retention": "kind_rounds_with_context_variant_rounds",
            "signals_retained": len(signals),
            "signals_omitted": omitted,
            "by_kind": dict(sorted(counts.items())),
        },
        "signals": signals,
        "gaps": gaps,
        "caveat": _CAVEAT,
    }
