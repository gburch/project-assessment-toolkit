"""Bounded source mechanisms and review leads from an already parsed Python AST.

Imported names are resolved conservatively within lexical scopes. These records
describe syntax, never runtime effectiveness, exploitability or rubric levels.
"""

from __future__ import annotations

import ast
import hashlib
from collections import Counter, defaultdict

from .static_analysis import source_role

VERSION = "1"
DIMENSIONS = ("security", "delivery", "operability", "extensibility", "performance")
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_SCOPES = (*_FUNCTIONS, ast.ClassDef)
_LOOPS = (ast.For, ast.AsyncFor, ast.While, ast.comprehension)
_BUILTINS = {"eval", "exec", "open"}
_HTTP = {
    f"{module}.{verb}"
    for module in ("requests", "httpx")
    for verb in ("get", "post", "put", "patch", "delete", "request", "head")
}
_PROCESSES = {
    f"subprocess.{name}" for name in ("run", "Popen", "call", "check_call", "check_output")
}
_LOCKS = {
    f"{module}.{name}" for module in ("threading", "multiprocessing") for name in ("Lock", "RLock")
} | {"asyncio.Lock"}
_AUTH = {
    "django.contrib.auth.decorators.login_required",
    "django.contrib.auth.decorators.permission_required",
    "flask_login.login_required",
    "flask_login.fresh_login_required",
}
_GATES = {
    "authorize",
    "check_permission",
    "require_permission",
    "require_approval",
    "verify_token",
    "assert_authorized",
}
_IO = _HTTP | _PROCESSES | {"builtins.open", "urllib.request.urlopen"}
_CAVEAT = "Observed syntax and conservative name binding only; controls may be bypassed, intentional or ineffective. Runtime, complete call resolution and absence claims are unsupported."


def _name(node):
    parts = []
    while len(parts) < 20:
        if isinstance(node, ast.Name):
            return ".".join([node.id, *reversed(parts)])[:320]
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            break
    return ""


def _value(node):
    """Describe literal shape without retaining secret-bearing argument text."""
    if isinstance(node, ast.Constant):
        if node.value is None:
            return "none"
        if type(node.value) is bool:
            return "true" if node.value else "false"
        if type(node.value) in {int, float}:
            return "positive_literal" if node.value > 0 else "nonpositive_literal"
        return "literal"
    return "expression" if node is not None else "absent_on_call"


def _inventory(tree, limit):
    scopes = {
        0: {"parent": None, "class": False, "owner": "<module>", "bindings": {}, "star": False}
    }
    rows, stack = [], [(tree, 0, False, False)]

    def bind(scope, name, target=None):
        bindings = scopes[scope]["bindings"]
        bindings[name] = target if name not in bindings or bindings[name] == target else None

    while stack and len(rows) < limit:
        node, scope, in_loop, in_handler = stack.pop()
        rows.append((node, scope, in_loop, in_handler))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    scopes[scope]["star"] = True
                else:
                    target = (
                        (alias.name if alias.asname else alias.name.split(".")[0])
                        if isinstance(node, ast.Import)
                        else (
                            f"{node.module}.{alias.name}"
                            if node.module and not node.level
                            else None
                        )
                    )
                    bind(scope, alias.asname or alias.name.split(".")[0], target)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(scope, node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(scope, _name(node).split(".")[0])
        elif isinstance(node, ast.arg):
            bind(scope, node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(scope, node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(scope, name)
        if isinstance(node, _SCOPES):
            if hasattr(node, "name"):
                bind(scope, node.name)
            child_scope = id(node)
            scopes[child_scope] = {
                "parent": scope,
                "class": isinstance(node, ast.ClassDef),
                "owner": (scopes[scope]["owner"] + "." + getattr(node, "name", "<lambda>"))[-160:],
                "bindings": {},
                "star": False,
                "definition_loop": in_loop,
                "definition_handler": in_handler,
            }
            for field, value in reversed(list(ast.iter_fields(node))):
                values = value if isinstance(value, list) else [value]
                for child in reversed(values):
                    if isinstance(child, ast.AST):
                        body_scope = child_scope if field in {"body", "args"} else scope
                        inner_body = field == "body" and isinstance(node, _FUNCTIONS)
                        stack.append(
                            (
                                child,
                                body_scope,
                                False if inner_body else in_loop,
                                False if inner_body else in_handler,
                            )
                        )
        else:
            if isinstance(node, ast.arguments):
                frame = scopes[scope]
                for field, value in reversed(list(ast.iter_fields(node))):
                    for child in reversed(value if isinstance(value, list) else [value]):
                        if isinstance(child, ast.AST):
                            default = field in {"defaults", "kw_defaults"}
                            stack.append(
                                (
                                    child,
                                    frame["parent"] if default else scope,
                                    frame.get("definition_loop", False) if default else False,
                                    frame.get("definition_handler", False) if default else False,
                                )
                            )
                continue
            if isinstance(node, ast.arg) and node.annotation is not None:
                frame = scopes[scope]
                stack.append(
                    (
                        node.annotation,
                        frame["parent"],
                        frame.get("definition_loop", False),
                        frame.get("definition_handler", False),
                    )
                )
                continue
            for child in reversed(list(ast.iter_child_nodes(node))):
                # Loop iterable expressions execute outside the repeated body;
                # nested function/class scopes reset both contextual flags.
                repeated = in_loop or (
                    isinstance(node, _LOOPS) and child in getattr(node, "body", [])
                )
                repeated |= isinstance(node, ast.While) and child is node.test
                if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    repeated = in_loop or child in [
                        getattr(node, key, None) for key in ("elt", "key", "value")
                    ]
                stack.append(
                    (child, scope, repeated, in_handler or isinstance(node, ast.ExceptHandler))
                )
    return rows, scopes, bool(stack)


def analyze_python_controls(path, tree, node_limit=200_000, signal_limit=64):
    """Inspect each eligible file, then retain signals fairly across rule kinds."""
    if (
        type(node_limit) is not int
        or node_limit < 1
        or type(signal_limit) is not int
        or signal_limit < 1
    ):
        raise ValueError("Control analysis limits must be positive integers")
    rows, scopes, partial = _inventory(tree, node_limit)

    def resolve(node, scope):
        raw = _name(node)
        if not raw or partial:
            return None
        first, *suffix = raw.split(".")
        current, skip_class = scope, isinstance(node, ast.AST) and not scopes[scope]["class"]
        while current is not None:
            frame = scopes[current]
            if not (skip_class and frame["class"]):
                if frame["star"]:
                    return None
                if first in frame["bindings"]:
                    target = frame["bindings"][first]
                    return ".".join([target, *suffix]) if target else None
            current = frame["parent"]
        return "builtins." + raw if first in _BUILTINS else None

    buckets, counts = defaultdict(list), Counter()

    def emit(kind, dimensions, node, scope, loop, handler, category="mechanism", **details):
        target = node.func if isinstance(node, ast.Call) else node
        resolved = resolve(target, scope)
        context = {
            "category": category,
            "owner": scopes[scope]["owner"],
            "callee": (resolved or _name(target))[:160],
            "binding": "resolved_import_or_builtin" if resolved else "unresolved_name",
            "in_loop": loop,
            "in_exception_handler": handler,
            **details,
        }
        signal = {
            "kind": kind,
            "dimensions": dimensions,
            "locations": [
                {
                    "path": path,
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", None) or node.lineno,
                }
            ],
            "context": context,
            "method": "python_ast",
            "confidence": "low" if category == "name_hint" or not resolved else "medium",
            "limitations": [
                "Source mechanism or review candidate only; inspect callers, required contracts and runtime applicability."
            ],
        }
        counts[kind] += 1
        # Retain bounded deterministic samples across the file rather than all
        # observations or an ordered prefix. Fixed rule kinds bound this cache.
        rank = hashlib.sha256(f"{kind}:{node.lineno}:{context['owner']}".encode()).hexdigest()
        bucket = buckets[(kind, category)]
        bucket.append((rank, signal))
        if len(bucket) > signal_limit:
            bucket.remove(max(bucket, key=lambda row: row[0]))

    for node, scope, loop, handler in rows:
        if isinstance(node, ast.ClassDef):
            bases = [resolve(base, scope) for base in node.bases]
            known = sorted(
                base
                for base in bases
                if base in {"typing.Protocol", "typing_extensions.Protocol", "abc.ABC"}
            )
            if known:
                emit(
                    "extensibility.interface",
                    ["extensibility"],
                    node,
                    scope,
                    loop,
                    handler,
                    bases=known,
                )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in {"health", "healthcheck", "health_check", "readiness", "liveness"}:
                emit(
                    "operability.health_entrypoint_hint",
                    ["operability"],
                    node,
                    scope,
                    loop,
                    handler,
                    "name_hint",
                )
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                annotation = resolve(arg.annotation, scope) if arg.annotation else None
                if annotation in {"typing.Callable", "collections.abc.Callable"} or (
                    node.name == "__init__"
                    and arg.annotation is not None
                    and arg.arg
                    in {"client", "store", "adapter", "provider", "handler", "factory", "executor"}
                ):
                    emit(
                        "extensibility.injected_parameter_hint",
                        ["extensibility"],
                        arg,
                        scope,
                        loop,
                        handler,
                        "name_hint",
                        parameter=arg.arg[:80],
                        annotation=(_name(arg.annotation) or "complex_annotation")[:160],
                    )
            for decorator in node.decorator_list:
                auth_target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if resolve(auth_target, scope) in _AUTH:
                    emit(
                        "security.authorization_declaration",
                        ["security"],
                        decorator,
                        scope,
                        loop,
                        handler,
                        integration_only=True,
                    )
                if isinstance(decorator, ast.Call):
                    continue
                declared = resolve(decorator, scope)
                if declared in {
                    "abc.abstractmethod",
                    "functools.singledispatch",
                    "functools.singledispatchmethod",
                }:
                    emit(
                        "extensibility.dispatch_or_abstract_declaration",
                        ["extensibility"],
                        decorator,
                        scope,
                        loop,
                        handler,
                    )
                if declared in {"functools.cache", "functools.lru_cache"}:
                    emit(
                        "performance.cache_declaration",
                        ["performance"],
                        decorator,
                        scope,
                        loop,
                        handler,
                        maxsize="implicit_default",
                    )
        if isinstance(node, ast.ExceptHandler):
            emit(
                "operability.exception_boundary",
                ["operability"],
                node,
                scope,
                loop,
                handler,
                "name_hint",
                exception_type=(_name(node.type) or "bare_or_composite")[:160],
                pass_only=bool(node.body)
                and all(isinstance(statement, ast.Pass) for statement in node.body),
                direct_return=any(isinstance(statement, ast.Return) for statement in node.body),
                direct_raise=any(isinstance(statement, ast.Raise) for statement in node.body),
                bare_reraise=any(
                    isinstance(statement, ast.Raise) and statement.exc is None
                    for statement in node.body
                ),
            )
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                expression = item.context_expr
                target = expression.func if isinstance(expression, ast.Call) else expression
                name = _name(target).rsplit(".", 1)[-1].strip("_")
                known = resolve(target, scope) in _LOCKS
                transaction = name in {"transaction", "atomic", "savepoint"} or name.endswith(
                    ("_transaction", "_savepoint")
                )
                synchronization = (
                    known or name in {"lock", "mutex"} or name.endswith(("_lock", "_mutex"))
                )
                if transaction or synchronization:
                    emit(
                        "performance.transaction_context_hint"
                        if transaction
                        else "performance.synchronization_context_hint",
                        ["performance", "operability"],
                        expression,
                        scope,
                        loop,
                        handler,
                        "mechanism" if known else "name_hint",
                        asynchronous=isinstance(node, ast.AsyncWith),
                        constructed_in_context=isinstance(expression, ast.Call),
                    )
        if not isinstance(node, ast.Call):
            continue
        callee, raw = resolve(node.func, scope), _name(node.func)
        terminal = raw.rsplit(".", 1)[-1]
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        common = (node, scope, loop, handler)
        if (callee or raw).rsplit(".", 1)[-1] in _GATES:
            emit("security.access_gate_call_hint", ["security"], *common, "name_hint")
        if callee in {"builtins.eval", "builtins.exec"}:
            emit(
                "security.dynamic_code_execution",
                ["security"],
                *common,
                "risk_candidate",
                argument_shape=_value(node.args[0] if node.args else None),
            )
        if callee in _PROCESSES and _value(keywords.get("shell")) == "true":
            emit("security.shell_execution", ["security"], *common, "risk_candidate", shell="true")
        if callee in _PROCESSES:
            command = node.args[0] if node.args else keywords.get("args")
            argv = command.elts if isinstance(command, (ast.List, ast.Tuple)) else []
            tokens = [
                item.value
                for item in argv
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            ]
            emit(
                "delivery.process_launch",
                ["delivery", "operability"],
                *common,
                command_form="literal_argv"
                if argv and len(tokens) == len(argv)
                else "mixed_argv"
                if argv
                else "literal_string"
                if isinstance(command, ast.Constant)
                else "expression",
                check=_value(keywords.get("check")),
                shell=_value(keywords.get("shell")),
                timeout=_value(keywords.get("timeout")),
                known_flags=sorted(
                    set(tokens)
                    & {"--locked", "--frozen", "--require-hashes", "--verify", "--ff-only"}
                ),
                revision_query=bool(
                    len(tokens) == len(argv)
                    and len(tokens) > 1
                    and tokens[0] == "git"
                    and tokens[1] == "rev-parse"
                ),
            )
        if callee in {
            "pickle.load",
            "pickle.loads",
            "dill.load",
            "dill.loads",
            "marshal.load",
            "marshal.loads",
        }:
            emit("security.object_deserialization", ["security"], *common, "risk_candidate")
        if callee in {"yaml.load", "yaml.load_all"}:
            loader_node = keywords.get("Loader", node.args[1] if len(node.args) > 1 else None)
            loader = resolve(loader_node, scope)
            emit(
                "security.yaml_loader",
                ["security"],
                *common,
                "mechanism"
                if loader in {"yaml.SafeLoader", "yaml.CSafeLoader"}
                else "risk_candidate",
                loader="safe_loader"
                if loader in {"yaml.SafeLoader", "yaml.CSafeLoader"}
                else "unestablished_loader",
            )
        if terminal in {"execute", "executemany", "executescript"}:
            query = node.args[0] if node.args else None
            interpolated = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(query, ast.Call)
                and isinstance(query.func, ast.Attribute)
                and query.func.attr == "format"
            )
            parameters = len(node.args) > 1 or bool(set(keywords) & {"parameters", "params"})
            emit(
                "performance.query_call_hint",
                ["performance"],
                *common,
                "name_hint",
                query_shape=_value(query),
                separate_parameters=parameters,
                interpolated_argument=interpolated,
            )
            if interpolated:
                emit(
                    "security.interpolated_execute_hint",
                    ["security"],
                    *common,
                    "name_hint",
                    interpolated_argument=True,
                )
            elif parameters:
                emit(
                    "security.separate_query_parameters_hint",
                    ["security"],
                    *common,
                    "name_hint",
                    separate_parameters=True,
                )
        if terminal in {"fetchall", "fetchmany"}:
            emit(
                "performance.result_materialization_hint",
                ["performance"],
                *common,
                "name_hint",
                fetch_mode="all_rows" if terminal == "fetchall" else "batch_rows",
                batch_bound=_value(node.args[0] if node.args else keywords.get("size")),
            )
        if callee in {"hmac.compare_digest", "secrets.compare_digest"}:
            emit("security.constant_time_comparison", ["security"], *common)
        if callee in _HTTP and "verify" in keywords:
            emit(
                "security.tls_verification_argument",
                ["security"],
                *common,
                "risk_candidate" if _value(keywords["verify"]) == "false" else "mechanism",
                verify=_value(keywords["verify"]),
            )
        if callee in _IO:
            emit(
                "performance.io_call",
                ["performance", "operability"],
                *common,
                timeout=_value(keywords.get("timeout")),
            )
            if loop:
                emit(
                    "performance.io_in_loop",
                    ["performance"],
                    *common,
                    "risk_candidate",
                    timeout=_value(keywords.get("timeout")),
                )
        if callee in {"time.sleep", "asyncio.sleep"}:
            emit(
                "operability.wait",
                ["operability", "performance"],
                *common,
                delay=_value(node.args[0] if node.args else None),
            )
        if callee in {
            "tenacity.retry",
            "backoff.on_exception",
            "backoff.on_predicate",
            "urllib3.util.retry.Retry",
            "urllib3.Retry",
        }:
            emit("operability.retry_policy", ["operability"], *common)
        if (
            callee
            and (
                callee.startswith("logging.")
                and terminal
                in {"debug", "info", "warning", "error", "exception", "critical", "getLogger"}
            )
            or (
                terminal in {"debug", "info", "warning", "error", "exception", "critical"}
                and raw.rsplit(".", 1)[0] in {"logger", "log", "self.logger", "self.log"}
            )
        ):
            emit(
                "operability.logging",
                ["operability"],
                *common,
                "mechanism" if callee else "name_hint",
                structured_context="extra" in keywords,
                exception_context=terminal == "exception" or "exc_info" in keywords,
            )
        if terminal in {"backup", "checkpoint", "restore", "recover", "save_checkpoint"}:
            emit("operability.recovery_call_hint", ["operability"], *common, "name_hint")
        if callee in {
            "functools.singledispatch",
            "functools.singledispatchmethod",
            "importlib.metadata.entry_points",
            "importlib.import_module",
        }:
            emit("extensibility.discovery_or_dispatch", ["extensibility"], *common)
        if terminal == "register" or terminal.startswith("register_"):
            emit("extensibility.registration_hint", ["extensibility"], *common, "name_hint")
        if callee in {"functools.cache", "functools.lru_cache"}:
            emit(
                "performance.cache_declaration",
                ["performance"],
                *common,
                maxsize=_value(keywords.get("maxsize")),
            )
        if callee in _LOCKS | {
            "queue.Queue",
            "asyncio.Queue",
            "asyncio.Semaphore",
            "threading.Semaphore",
            "threading.BoundedSemaphore",
            "concurrent.futures.ThreadPoolExecutor",
            "concurrent.futures.ProcessPoolExecutor",
        }:
            limit = next(
                (keywords[key] for key in ("maxsize", "value", "max_workers") if key in keywords),
                node.args[0] if node.args else None,
            )
            emit(
                "performance.admission_or_concurrency_control",
                ["performance", "operability"],
                *common,
                configured_bound="mutex_constructor" if callee in _LOCKS else _value(limit),
            )
        if callee == "itertools.islice" or terminal in {
            "fetchmany",
            "paginate",
            "iter_pages",
            "iter_chunks",
            "bulk_insert",
            "executemany",
        }:
            emit(
                "performance.batch_or_pagination_hint",
                ["performance"],
                *common,
                "mechanism" if callee == "itertools.islice" else "name_hint",
                bound_arguments=sorted(
                    key
                    for key in keywords
                    if key in {"limit", "page_size", "batch_size", "max_items", "chunk_size"}
                ),
            )
    # Preserve different observations of one rule: a safe-loader flood must not
    # hide an unknown loader, nor enabled TLS checks a disabled-check candidate.
    buckets = {
        key: sorted((row[1] for row in bucket), key=lambda signal: signal["locations"][0]["line"])
        for key, bucket in buckets.items()
    }
    retained, index = [], 0
    while len(retained) < signal_limit and any(index < len(bucket) for bucket in buckets.values()):
        for key in sorted(
            buckets,
            key=lambda key: ({"risk_candidate": 0, "mechanism": 1, "name_hint": 2}[key[1]], key[0]),
        ):
            if index < len(buckets[key]) and len(retained) < signal_limit:
                retained.append(buckets[key][index])
        index += 1
    retained.sort(key=lambda row: (row["locations"][0]["line"], row["kind"]))
    omitted = sum(counts.values()) - len(retained)
    return {
        "path": path,
        "language": "python",
        "role": source_role(path)["role"],
        "dimensions": list(DIMENSIONS),
        "status": "partial" if partial or omitted else "complete",
        "coverage": {
            "nodes_examined": len(rows),
            "node_limit": node_limit,
            "node_limit_reached": partial,
            "signals_found": sum(counts.values()),
            "signals_retained": len(retained),
            "signals_omitted": omitted,
            "signal_limit": signal_limit,
            "selection": "kind_and_category_round_robin_with_risk_candidates_first",
            "scope": "Supported Python syntax rules only; zero hits never establish absence of controls or risks.",
        },
        "signals": retained,
        "signal_counts": dict(sorted(counts.items())),
        "gaps": (
            ["AST node limit reached; binding and control inventory remain incomplete."]
            if partial
            else []
        )
        + (
            ["Per-file signal retention limit reached; observed counts exceed retained detail."]
            if omitted
            else []
        ),
        "caveat": _CAVEAT,
    }
