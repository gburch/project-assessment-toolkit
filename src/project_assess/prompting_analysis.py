"""Located prompting hints from captured text, without grading or target execution."""

from __future__ import annotations

import ast
import hashlib
import heapq
import json
import math
import re
import time
from collections import Counter, defaultdict, deque
from pathlib import PurePosixPath

from .generic_analysis import source_area, source_language
from .source_controls import _inventory, _name
from .static_analysis import source_role

VERSION = "2"
MAX_FILES = 20_000
MAX_FILE_BYTES = 4 * 1024**2
MAX_BYTES = 256 * 1024**2
MAX_NODES = 200_000
MAX_SIGNALS = 240
_CLOCK = time.monotonic
_UNPARSED = object()
KINDS = (
    "development_guidance",
    "runtime_prompt_asset",
    "model_client_setup",
    "model_invocation",
    "agent_orchestration",
    "output_contract",
    "evaluation_signal",
)
CAVEAT = (
    "Captured paths and import/call syntax are review hints, not a reliance level, "
    "a prompting percentage, runtime use, AI authorship or observed output variability. "
    "Skills may support development or be product-facing host-agent instructions; inspect "
    "their consumers. Schemas, seeds and temperature settings do not prove deterministic "
    "or repeatable outcomes. Missing signals never establish absence of model behavior."
)
_JS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_ASSETS = {".md", ".txt", ".prompt", ".jinja", ".jinja2", ".j2", ".yaml", ".yml", ".json", ".toml"}
_CONSTRUCTORS = {
    "openai.OpenAI": "openai",
    "openai.AsyncOpenAI": "openai",
    "openai.AzureOpenAI": "openai",
    "openai.AsyncAzureOpenAI": "openai",
    "anthropic.Anthropic": "anthropic",
    "anthropic.AsyncAnthropic": "anthropic",
    "langchain_openai.ChatOpenAI": "langchain",
    "langchain_openai.AzureChatOpenAI": "langchain",
    "langchain_anthropic.ChatAnthropic": "langchain",
    "langchain_google_genai.ChatGoogleGenerativeAI": "langchain",
    "jsonschema.Draft202012Validator": "jsonschema",
    "jsonschema.Draft7Validator": "jsonschema",
    "bedrock.BedrockRuntimeClient": "bedrock",
}
_DIRECT = {
    "litellm.completion",
    "litellm.acompletion",
    "litellm.responses",
    "ai.generateText",
    "ai.streamText",
    "ai.generateObject",
    "ai.streamObject",
    "openai.ChatCompletion.create",
    "openai.Completion.create",
}
_AGENTS = {
    "crewai.Agent",
    "crewai.Crew",
    "crewai.Task",
    "langgraph.graph.StateGraph",
    "autogen.AssistantAgent",
    "autogen_agentchat.agents.AssistantAgent",
    "agents.Agent",
    "agents.Runner.run",
    "agents.Runner.run_sync",
    "langchain.agents.create_agent",
}
_VALIDATION = {"jsonschema.validate", "pydantic.TypeAdapter.validate_python"}
_JS_MODULES = {
    "openai": ("openai", "openai.OpenAI"),
    "@anthropic-ai/sdk": ("anthropic", "anthropic.Anthropic"),
    "@langchain/openai": ("langchain_openai", None),
    "@langchain/anthropic": ("langchain_anthropic", None),
    "@langchain/langgraph": ("langgraph.graph", None),
    "@aws-sdk/client-bedrock-runtime": ("bedrock", None),
    "@openai/agents": ("agents", None),
    "ai": ("ai", None),
}


def _guidance(path):
    parts, name = PurePosixPath(path).parts, PurePosixPath(path).name.lower()
    return (
        name in {"agents.md", "claude.md", "copilot-instructions.md", "skill.md"}
        or ".agents" in parts
        or ".claude" in parts
        or ".cursor" in parts
        or name.endswith((".instructions.md", ".cursorrules"))
    )


def is_prompt_asset(path):
    p = PurePosixPath(path)
    return p.suffix.lower() in _ASSETS and (
        any(part.lower() in {"prompts", "prompt", "instructions"} for part in p.parts[:-1])
        or p.stem.lower() in {"prompt", "prompts", "system_prompt", "system-prompt"}
        or "agents" in {part.lower() for part in p.parts[:-1]}
        and p.stem.lower() not in {"readme", "architecture", "contributing"}
        or p.suffix.lower() == ".prompt"
        or bool(
            re.search(r"(?:^|[._-])(?:system|developer|user)[._-]prompt(?:[._-]|$)", p.name.lower())
        )
    )


def _workflow_root(path):
    """Group a package's files: a schema in pkg/schemas can validate a call in pkg/llm."""
    directories = PurePosixPath(path).parts[:-1]
    start = next(
        (
            index + 1
            for index, part in enumerate(directories)
            if part in {"src", "lib", "packages", "apps", "services"}
        ),
        0,
    )
    return "/".join(directories[: start + 1]) or "(root)"


def _call_kind(target):
    if _CONSTRUCTORS.get(target) == "jsonschema":
        return "output_contract"
    if target in _CONSTRUCTORS and _CONSTRUCTORS[target] != "jsonschema":
        return "model_client_setup"
    if target in _DIRECT:
        return "model_invocation"
    if target in _AGENTS:
        return "agent_orchestration"
    if target in _VALIDATION or target == "jsonschema.validate":
        return "output_contract"
    provider, _, method = target.partition(":")
    if not method and target.startswith("openai."):
        provider, method = target.split(".", 1)
    if (
        provider == "openai"
        and method
        in {
            "responses.create",
            "responses.parse",
            "chat.completions.create",
            "beta.chat.completions.parse",
        }
        or provider == "anthropic"
        and method in {"messages.create", "messages.stream", "beta.messages.create"}
        or provider == "langchain"
        and method in {"invoke", "ainvoke", "stream", "astream", "batch", "abatch"}
        or provider == "bedrock"
        and method
        in {
            "converse",
            "converse_stream",
            "invoke_model",
            "invoke_model_with_response_stream",
            "send",
        }
    ):
        return "model_invocation"
    return "output_contract" if provider == "jsonschema" and method == "validate" else None


def _python(text, *, tree=_UNPARSED):
    return python_prompting_facts(ast.parse(text) if tree is _UNPARSED else tree)


def python_prompting_facts(tree):
    """Extract bounded facts from an existing tree; never retain or reparse it."""
    if not isinstance(tree, ast.AST):
        return [], "partial", "Python syntax unavailable; SDK bindings were not inferred."
    rows, scopes, partial = _inventory(tree, MAX_NODES)
    if partial:
        return [], "partial", "Python syntax node limit reached; bindings were not inferred."
    stores = Counter(
        (scope, node.id)
        for node, scope, *_ in rows
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    )
    # A constructor does not preserve SDK method identity after monkey-patching.
    # Ignore receiver aliases entirely when a member is mutated in any scope;
    # resolving the affected object across closures would require data flow.
    mutated = {
        _name(node).split(".")[0]
        for node, *_ in rows
        if isinstance(node, (ast.Attribute, ast.Subscript))
        and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    instances = {}

    def resolve(name, scope):
        head, *tail = name.split(".")
        if head in mutated:
            return None
        current = scope
        for _ in range(64):
            if current is None:
                return None
            frame = scopes[current]
            if frame["star"]:
                return None
            if not (not scopes[scope]["class"] and frame["class"]) and head in frame["bindings"]:
                value = instances.get((current, head)) or frame["bindings"][head]
                if not value:
                    return None
                join = "" if value.endswith(":") else "."
                return value + (join + ".".join(tail) if tail else "")
            current = frame["parent"]
        return None

    for node, scope, *_ in rows:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if (
            len(targets) != 1
            or not isinstance(targets[0], ast.Name)
            or not isinstance(node.value, ast.Call)
        ):
            continue
        key = (scope, targets[0].id)
        constructor = resolve(_name(node.value.func), scope)
        provider = _CONSTRUCTORS.get(constructor)
        if (
            constructor == "boto3.client"
            and node.value.args
            and isinstance(node.value.args[0], ast.Constant)
            and node.value.args[0].value == "bedrock-runtime"
        ):
            provider = "bedrock"
        if provider and stores[key] == 1:
            instances[key] = provider + ":"
    output = []
    for node, scope, *_ in rows:
        if not isinstance(node, ast.Call):
            continue
        target = resolve(_name(node.func), scope)
        kind = _call_kind(target or "")
        if (
            target == "boto3.client"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "bedrock-runtime"
        ):
            kind = "model_client_setup"
        if kind:
            output.append(
                (
                    kind,
                    node.lineno,
                    {
                        "binding": "import_and_call_syntax",
                        "operation": "generation"
                        if kind == "model_invocation"
                        else "client_construction"
                        if kind == "model_client_setup"
                        else "declaration_or_call",
                    },
                )
            )
            if kind == "model_invocation":
                keys = {kw.arg for kw in node.keywords}
                text_format = any(
                    kw.arg == "text"
                    and isinstance(kw.value, ast.Dict)
                    and any(
                        isinstance(key, ast.Constant) and key.value == "format"
                        for key in kw.value.keys
                    )
                    for kw in node.keywords
                )
                if text_format or keys & {
                    "response_format",
                    "output_schema",
                    "tools",
                    "tool_choice",
                }:
                    output.append(
                        (
                            "output_contract",
                            node.lineno,
                            {
                                "mechanism": "model_output_or_tool_option",
                                "enforcement": "unverified",
                            },
                        )
                    )
                if keys & {"temperature", "seed"}:
                    output.append(
                        (
                            "output_contract",
                            node.lineno,
                            {
                                "mechanism": "sampling_configuration",
                                "repeatability": "unestablished",
                            },
                        )
                    )
        # This is a test-shape hint only. Generic assertions are not model evals.
        if target in {"deepeval.assert_test", "promptfoo.evaluate", "ragas.evaluate"}:
            output.append(
                (
                    "evaluation_signal",
                    node.lineno,
                    {"mechanism": "imported_model_evaluation_call", "execution": "unverified"},
                )
            )
    return output, "complete", None


def _javascript(path, text):
    from .javascript_analysis import _parser, _walk, javascript_analyzer_identity
    from .js_controls import _FUNCTIONS, _bindings, _callee, _literal, _text

    if not javascript_analyzer_identity()["available"]:
        return (
            [],
            "unsupported",
            "JavaScript/TypeScript syntax unavailable; use the assessor's analysis extra.",
        )
    raw = text.encode("utf-8")
    tree = _parser(path).parse(raw)
    nodes = list(_walk(tree.root_node, MAX_NODES + 1))
    if len(nodes) > MAX_NODES or tree.root_node.has_error:
        return (
            [],
            "partial",
            "JavaScript/TypeScript syntax is incomplete or bounded; SDK bindings remain unknown.",
        )
    declarations, aliases, instances, mutated = defaultdict(Counter), defaultdict(dict), {}, set()
    scope_types = _FUNCTIONS | {
        "program",
        "statement_block",
        "catch_clause",
        "class",
        "class_body",
        "for_statement",
        "for_in_statement",
        "switch_body",
    }
    scope_nodes = {node.id: node for node, _ in nodes if node.type in scope_types}

    def scope_of(node, *, function_only=False):
        current = node.parent
        for _ in range(64):
            if current is None:
                return None
            if current.type in (_FUNCTIONS | {"program"} if function_only else scope_types):
                return current.id
            current = current.parent
        return None

    def declaration_scope(node):
        # var escapes a block; let/const remain within their lexical block.
        return scope_of(
            node,
            function_only=node.parent is not None and node.parent.type == "variable_declaration",
        )

    for node, _ in nodes:
        scope = scope_of(node)
        if node.type in _FUNCTIONS:
            names, _ = _bindings(
                node.child_by_field_name("parameters") or node.child_by_field_name("parameter"), raw
            )
            declarations[node.id].update(names)
        if node.type == "catch_clause":
            names, _ = _bindings(node.child_by_field_name("parameter"), raw)
            declarations[node.id].update(names)
        if node.type in {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "function_expression",
            "generator_function",
            "class",
        }:
            name = node.child_by_field_name("name")
            if name:
                named_scope = (
                    node.id
                    if node.type in {"function_expression", "generator_function", "class"}
                    else scope
                )
                declarations[named_scope][_text(name, raw)] += 1
        if node.type == "variable_declarator":
            names, _ = _bindings(node.child_by_field_name("name"), raw)
            declarations[declaration_scope(node)].update(names)
        if node.type in {
            "assignment_expression",
            "augmented_assignment_expression",
            "update_expression",
        }:
            target = _callee(
                node.child_by_field_name("left") or node.child_by_field_name("argument"), raw
            )
            if target:
                mutated.add(target.split(".")[0])
        if node.type != "import_statement":
            continue
        module = _literal(node.child_by_field_name("source"), raw)
        canonical, default = _JS_MODULES.get(module, (None, None))
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for child in clause.named_children:
                if child.type == "identifier":
                    name = _text(child, raw)
                    declarations[scope][name] += 1
                    if default:
                        aliases[scope][name] = default
                elif child.type == "namespace_import":
                    names = [n for n in child.named_children if n.type == "identifier"]
                    if names:
                        name = _text(names[-1], raw)
                        declarations[scope][name] += 1
                        if canonical:
                            aliases[scope][name] = canonical
                elif child.type == "named_imports":
                    for spec in child.named_children:
                        local = spec.child_by_field_name("alias") or spec.child_by_field_name(
                            "name"
                        )
                        imported = spec.child_by_field_name("name")
                        if local and imported:
                            name = _text(local, raw)
                            declarations[scope][name] += 1
                            if canonical:
                                aliases[scope][name] = canonical + "." + _text(imported, raw)

    def resolve(name, node):
        if not name:
            return None
        head, *tail = name.split(".")
        if head in mutated:
            return None
        current = scope_of(node)
        for _ in range(64):
            if current is None:
                return None
            if declarations[current][head]:
                value = instances.get((current, head)) or aliases[current].get(head)
                if declarations[current][head] != 1 or not value:
                    return None
                join = "" if value.endswith(":") else "."
                return value + (join + ".".join(tail) if tail else "")
            current = scope_of(scope_nodes[current])
        return None

    for node, _ in nodes:
        if node.type != "variable_declarator":
            continue
        name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        if (
            name is None
            or name.type != "identifier"
            or value is None
            or value.type != "new_expression"
        ):
            continue
        constructor = resolve(_callee(value.child_by_field_name("constructor"), raw), node)
        if provider := _CONSTRUCTORS.get(constructor):
            instances[(declaration_scope(node), _text(name, raw))] = provider + ":"
    output, commonjs = [], False
    for node, _ in nodes:
        if node.type not in {"call_expression", "new_expression"}:
            continue
        target = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        args = node.child_by_field_name("arguments")
        if _callee(target, raw) == "require" and args and args.named_children:
            commonjs |= _literal(args.named_children[0], raw) in _JS_MODULES
        kind = _call_kind(resolve(_callee(target, raw), node) or "")
        if kind:
            output.append(
                (
                    kind,
                    node.start_point.row + 1,
                    {
                        "binding": "ES_import_and_call_syntax",
                        "operation": "generation"
                        if kind == "model_invocation"
                        else "client_construction"
                        if kind == "model_client_setup"
                        else "declaration_or_call",
                    },
                )
            )
            if kind == "model_invocation":
                args = node.child_by_field_name("arguments")
                options = args.named_children[0] if args and args.named_children else None
                pairs = options.named_children if options and options.type == "object" else []
                keys = {
                    _text(pair.child_by_field_name("key"), raw).strip("\"'")
                    for pair in pairs
                    if pair.type == "pair"
                }
                text_format = any(
                    pair.type == "pair"
                    and _text(pair.child_by_field_name("key"), raw).strip("\"'") == "text"
                    and (value := pair.child_by_field_name("value")) is not None
                    and value.type == "object"
                    and any(
                        _text(child.child_by_field_name("key"), raw).strip("\"'") == "format"
                        for child in value.named_children
                        if child.type == "pair"
                    )
                    for pair in pairs
                )
                if text_format or keys & {
                    "response_format",
                    "tools",
                    "tool_choice",
                    "schema",
                    "output",
                }:
                    output.append(
                        (
                            "output_contract",
                            node.start_point.row + 1,
                            {
                                "mechanism": "model_output_or_tool_option",
                                "enforcement": "unverified",
                            },
                        )
                    )
                if keys & {"temperature", "seed"}:
                    output.append(
                        (
                            "output_contract",
                            node.start_point.row + 1,
                            {
                                "mechanism": "sampling_configuration",
                                "repeatability": "unestablished",
                            },
                        )
                    )
    return (
        output,
        "partial" if commonjs else "complete",
        "CommonJS SDK bindings were not resolved; model calls through them remain unknown."
        if commonjs
        else None,
    )


def analyze_prompting(sources, *, deadline=None, python_facts=None):
    """Inspect bounded captured strings; never read a project path or infer a score."""
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_FILES:
        raise ValueError("Prompting sources must be bounded captured records")
    if deadline is not None and (type(deadline) not in {int, float} or not math.isfinite(deadline)):
        raise ValueError("Prompting deadline must be finite")
    if python_facts is not None and not isinstance(python_facts, dict):
        raise ValueError("Cached Python prompting facts must be a path mapping")
    prepared, seen = [], set()
    for row in sources:
        if not isinstance(row, dict) or not isinstance(row.get("text"), str):
            raise ValueError("Prompting sources require captured text")
        path = row.get("path")
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 4096
            or "\\" in path
            or "\x00" in path
        ):
            raise ValueError("Invalid captured prompting path")
        p = PurePosixPath(path)
        if (
            not p.parts
            or p.is_absolute()
            or ".." in p.parts
            or path in seen
            or p.as_posix() != path
        ):
            raise ValueError("Prompting source paths must be unique and contained")
        if any(
            not isinstance(row.get(key), str) or not 1 <= len(row[key]) <= 256
            for key in ("evidence_id", "digest")
        ):
            raise ValueError("Prompting sources require captured identities")
        seen.add(path)
        role = row.get("role")
        if not isinstance(role, str) or role not in {
            "production",
            "test",
            "tooling",
            "generated",
            "unknown",
        }:
            role = source_role(path)["role"]
        prepared.append({**row, "role": role})
    files, gaps, input_bytes = [], set(), 0
    counts, role_counts, file_sets = Counter(), Counter(), defaultdict(set)
    samples, representatives = defaultdict(list), defaultdict(list)
    file_seen, file_representatives, file_counts = set(), {}, Counter()
    unconfirmed_contracts = []

    def keep(collection, lane, signal):
        rank = int(signal["id"][3:], 16)
        item = (-rank, signal["id"], signal)
        heap = collection[lane]
        if len(heap) < MAX_SIGNALS:
            heapq.heappush(heap, item)
        elif heap and rank < -heap[0][0]:
            heapq.heapreplace(heap, item)

    def emit(row, kind, line, basis, context):
        signal = {
            "kind": kind,
            "path": row["path"],
            "line": line,
            "end_line": line,
            "source_evidence_id": row["evidence_id"],
            "digest": row["digest"],
            "role": row["role"],
            "basis": basis,
            "context": context,
            "caveat": "Located syntax/path hint; inspect the consuming workflow and current intent. No output variability or project reliance is established.",
        }
        signal["id"] = (
            "pr-" + hashlib.sha256(json.dumps(signal, sort_keys=True).encode()).hexdigest()[:24]
        )
        if signal["id"] in file_seen:
            return
        file_seen.add(signal["id"])
        counts[kind] += 1
        role_counts[row["role"]] += 1
        file_counts[kind] += 1
        file_sets[kind].add(row["path"])
        lane = (kind, row["role"])
        keep(samples, lane, signal)
        current = file_representatives.get(lane)
        if current is None or signal["id"] < current["id"]:
            file_representatives[lane] = signal

    for row in sorted(prepared, key=lambda r: r["path"]):
        file_seen, file_representatives, file_counts = set(), {}, Counter()
        path, text = row["path"], row["text"]
        record = {
            "path": path,
            "role": row["role"],
            "status": "complete",
            "syntax": "asset_path_only",
        }
        if deadline is not None and _CLOCK() >= deadline:
            record.update(status="not_analyzed", reason="deadline")
        elif len(text) > MAX_FILE_BYTES or len(text.encode("utf-8")) > MAX_FILE_BYTES:
            record.update(status="not_analyzed", reason="file_byte_limit")
        elif input_bytes + len(text.encode("utf-8")) > MAX_BYTES:
            record.update(status="not_analyzed", reason="input_byte_limit")
        if record["status"] == "not_analyzed":
            files.append(record)
            gaps.add(
                "Captured text omitted by prompting work bounds; missing signals remain unknown."
            )
            continue
        input_bytes += len(text.encode("utf-8"))
        if text.strip() and _guidance(path):
            emit(
                row,
                "development_guidance",
                1,
                "guidance_path_hint",
                {"consumption": "development_or_product_host_agent_scope_unverified"},
            )
        elif text.strip() and is_prompt_asset(path):
            emit(
                row,
                "runtime_prompt_asset",
                1,
                "prompt_asset_path_hint",
                {"consumption": "runtime_use_unverified"},
            )
        if PurePosixPath(path).name.lower() in {
            "promptfoo.yaml",
            "promptfoo.yml",
            "promptfooconfig.yaml",
            "promptfooconfig.yml",
        }:
            emit(
                row,
                "evaluation_signal",
                1,
                "evaluation_configuration_path_hint",
                {"execution": "unverified"},
            )
        try:
            if path.endswith(".py"):
                if python_facts is not None and path in python_facts:
                    hints, status, gap = (
                        python_facts[path]
                        if python_facts[path] is not None
                        else python_prompting_facts(None)
                    )
                else:
                    hints, status, gap = _python(text)
                record.update(syntax="python_ast", status=status)
            elif PurePosixPath(path).suffix.lower() in _JS:
                hints, status, gap = _javascript(path, text)
                record.update(syntax="javascript_typescript_ast", status=status)
            elif source_language(path):
                hints, gap = (
                    [],
                    "Prompting call analysis supports Python and JavaScript/TypeScript only; other source syntax remains unexamined.",
                )
                record.update(status="unsupported", syntax="unsupported")
            else:
                hints, gap = [], None
            schema_only = [
                hint
                for hint in hints
                if hint[0] == "output_contract" and "mechanism" not in hint[2]
            ]
            if schema_only:
                unconfirmed_contracts.append((row, record, schema_only))
            for kind, line, context in hints:
                if not (kind == "output_contract" and "mechanism" not in context):
                    emit(row, kind, line, "import_and_call_syntax", context)
            if gap:
                gaps.add(gap)
        except (
            SyntaxError,
            ValueError,
            RecursionError,
            ImportError,
            AttributeError,
            TypeError,
            OSError,
        ):
            record.update(status="partial", reason="syntax_unavailable_or_invalid")
            gaps.add(
                "A captured source could not be parsed; no raw source or parser errors retained."
            )
        record["signal_counts"] = dict(sorted(file_counts.items()))
        for lane, signal in file_representatives.items():
            keep(representatives, lane, signal)
        files.append(record)
    # General schema validation is an output contract only beside model or prompt use.
    model_areas = {
        _workflow_root(path)
        for kind in (
            "model_client_setup",
            "model_invocation",
            "agent_orchestration",
            "runtime_prompt_asset",
        )
        for path in file_sets[kind]
    }
    schema_without_model_context = 0
    for row, record, hints in unconfirmed_contracts:
        if _workflow_root(row["path"]) not in model_areas:
            schema_without_model_context += len(hints)
            continue
        file_seen, file_representatives, file_counts = set(), {}, Counter()
        for kind, line, context in hints:
            emit(row, kind, line, "import_and_call_syntax", context)
        record["signal_counts"] = dict(
            sorted((Counter(record.get("signal_counts", {})) + file_counts).items())
        )
        for lane, signal in file_representatives.items():
            keep(representatives, lane, signal)
    lanes = defaultdict(list)
    for lane in samples:
        # Prefer one location from distinct files before additional locations.
        areas = defaultdict(deque)
        for item in sorted(representatives[lane], key=lambda item: item[1]):
            areas[source_area(item[2]["path"])].append(item[2])
        first = []
        while areas:
            for area in sorted(list(areas)):
                first.append(areas[area].popleft())
                if not areas[area]:
                    del areas[area]
        remaining = [item[2] for item in sorted(samples[lane], key=lambda item: item[1])]
        lanes[lane] = deque(first + remaining)
    retained, retained_ids = [], set()
    while lanes and len(retained) < MAX_SIGNALS:
        for lane in sorted(list(lanes)):
            if len(retained) >= MAX_SIGNALS:
                break
            signal = lanes[lane].popleft()
            if signal["id"] not in retained_ids:
                retained.append(signal)
                retained_ids.add(signal["id"])
            if not lanes[lane]:
                del lanes[lane]
    signal_count = sum(counts.values())
    if signal_count > len(retained):
        gaps.add(
            "Prompting signal details are sampled across kinds and source roles; counts include omitted details."
        )
    statuses = Counter(row["status"] for row in files)
    return {
        "schema_version": 1,
        "analyzer": {"name": "project-assess-prompting", "version": VERSION},
        "status": "partial" if gaps else "complete",
        "coverage": {
            "input_files": len(prepared),
            "examined_files": len(files) - statuses["not_analyzed"],
            "partial_files": statuses["partial"],
            "unsupported_files": statuses["unsupported"],
            "omitted_files": statuses["not_analyzed"],
            "input_bytes": input_bytes,
            "schema_validation_without_model_context": schema_without_model_context,
            "syntax_languages": ["python", "javascript", "typescript"],
            "files": files,
        },
        "summary": {
            "signal_count": signal_count,
            "retained_signals": len(retained),
            "counts_by_kind": {kind: counts[kind] for kind in KINDS},
            "counts_by_role": dict(sorted(role_counts.items())),
            **{
                key: len(file_sets[kind])
                for key, kind in (
                    ("guidance_files", "development_guidance"),
                    ("runtime_prompt_files", "runtime_prompt_asset"),
                    ("model_call_files", "model_invocation"),
                )
            },
        },
        "signals": sorted(retained, key=lambda r: (r["path"], r["line"], r["kind"], r["id"])),
        "limits": {
            "files": MAX_FILES,
            "file_bytes": MAX_FILE_BYTES,
            "input_bytes": MAX_BYTES,
            "syntax_nodes_per_file": MAX_NODES,
            "retained_signals": MAX_SIGNALS,
        },
        "gaps": sorted(gaps),
        "caveat": CAVEAT,
    }
