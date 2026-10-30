"""Bounded facts from captured manifests and syntax; no discovery or target execution."""

from __future__ import annotations

import ast
import re
from itertools import islice

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

VERSION = "1"
MAX_DEPENDENCIES = 500
MAX_GROUPS = 100
MAX_REQUIREMENT_CHARACTERS = 4096
MAX_TEXT_CHARACTERS = 1024 * 1024
MAX_AST_NODES = 20_000
MAX_SIGNALS = 100
MAX_INPUTS = 1000
MAX_PROJECT_DEPENDENCIES = 500
MAX_PROJECT_SIGNALS = 500
CAVEAT = (
    "Dependencies are declarations, not resolved installations or proven runtime use. "
    "Versions, compatibility, support, vulnerability status and performance were not verified. "
    "Syntax hints do not establish reimplementation or excess burden; standard-library and "
    "direct DOM code can be appropriate. Review actual requirements, callers and upkeep "
    "before recommending reuse or a framework."
)


def _name(value, *, javascript=False):
    if not isinstance(value, str) or len(value) > 214:
        return None
    value = value.lower() if javascript else canonicalize_name(value)
    pattern = (
        r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
        if javascript
        else r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    )
    return value if re.fullmatch(pattern, value) else None


def dependency_inventory(path: str, document: dict | str) -> dict:
    """Capture declared names only; never expose constraints, URLs or directive text."""
    dependencies, gaps, examined = set(), set(), 0

    def add(entries, group, *, javascript=False):
        nonlocal examined
        if not isinstance(entries, dict if javascript else list):
            gaps.add("A dependency group has an unsupported structure.")
            return
        for entry in entries:
            if examined >= MAX_DEPENDENCIES:
                gaps.add("Manifest dependency declaration limit reached.")
                break
            examined += 1
            if javascript:
                name = _name(entry, javascript=True)
                if not isinstance(entries[entry], str):
                    name = None
            else:
                if isinstance(entry, dict) and "include-group" in entry:
                    gaps.add("Dependency group includes were not resolved.")
                    continue
                if not isinstance(entry, str) or len(entry) > MAX_REQUIREMENT_CHARACTERS:
                    gaps.add("A requirement declaration has an unsupported structure or size.")
                    continue
                if entry.lstrip().startswith("-"):
                    gaps.add("Requirement options and file includes were not resolved.")
                    continue
                try:
                    requirement = Requirement(entry)
                except (InvalidRequirement, RecursionError):
                    gaps.add("A requirement declaration could not be parsed.")
                    continue
                name = _name(requirement.name)
                if requirement.url:
                    gaps.add("Direct-reference dependency origins were not verified.")
            if name is None:
                gaps.add("An invalid dependency name or declaration was omitted.")
            else:
                dependencies.add((name, group))

    def named_groups(groups, prefix):
        if not isinstance(groups, dict):
            gaps.add("A dependency group collection has an unsupported structure.")
            return
        for index, (group, entries) in enumerate(groups.items()):
            if index >= MAX_GROUPS:
                gaps.add("Manifest dependency group limit reached.")
                break
            normalized = _name(group)
            if normalized is None or len(normalized) > 64:
                gaps.add("An invalid dependency group name was omitted.")
                continue
            add(entries, prefix + normalized)

    name = path.rsplit("/", 1)[-1].lower()
    supported_groups = False
    if name == "requirements.txt" and isinstance(document, str):
        if len(document) > MAX_TEXT_CHARACTERS:
            gaps.add("Requirements text character limit reached.")
        lines = document[:MAX_TEXT_CHARACTERS].splitlines()
        add(
            [
                re.split(r"\s+#", line, maxsplit=1)[0].strip()
                for line in lines
                if line.strip() and not line.lstrip().startswith("#")
            ],
            "runtime",
        )
        supported_groups = True
    elif name == "package.json" and isinstance(document, dict):
        for key, group in (
            ("dependencies", "runtime"),
            ("devDependencies", "dev"),
            ("peerDependencies", "peer"),
            ("optionalDependencies", "optional"),
        ):
            if key in document:
                supported_groups = True
                add(document[key], group, javascript=True)
    elif name == "pyproject.toml" and isinstance(document, dict):
        project = document.get("project", {})
        if not isinstance(project, dict):
            gaps.add("The Python project dependency declaration is malformed.")
            project = {}
        if "dependencies" in project:
            supported_groups = True
            add(project["dependencies"], "runtime")
        if "optional-dependencies" in project:
            supported_groups = True
            named_groups(project["optional-dependencies"], "optional:")
        dynamic = project.get("dynamic", [])
        if not isinstance(dynamic, list) or any(
            value in ("dependencies", "optional-dependencies") for value in dynamic
        ):
            gaps.add("Dynamic Python dependency declarations were not resolved.")
        build = document.get("build-system", {})
        if not isinstance(build, dict):
            gaps.add("The Python build dependency declaration is malformed.")
        elif "requires" in build:
            supported_groups = True
            add(build["requires"], "build")
        if "dependency-groups" in document:
            supported_groups = True
            named_groups(document["dependency-groups"], "dev:")
        tool = document.get("tool", {})
        if isinstance(tool, dict) and (
            "poetry" in tool
            or isinstance(tool.get("pdm"), dict)
            and "dev-dependencies" in tool["pdm"]
            or isinstance(tool.get("uv"), dict)
            and "dev-dependencies" in tool["uv"]
        ):
            gaps.add("Legacy tool-specific dependency declarations were not analyzed.")
        if "project" not in document:
            gaps.add("Standard Python runtime dependency declarations were not captured.")
    else:
        gaps.add("The dependency manifest format or structure is unsupported.")
    if not supported_groups:
        gaps.add("No supported dependency groups were captured in this manifest.")
    return {
        "path": path,
        "dependencies": [{"name": name, "group": group} for name, group in sorted(dependencies)],
        "gaps": sorted(gaps),
        "status": "partial" if gaps else "complete",
    }


def python_signals(path: str, tree: ast.Module) -> dict:
    """Locate syntactic primitive imports; module resolution and actual use stay unknown."""
    signals, gaps, visited = set(), set(), 0
    stack = [(None, iter((tree,)))]
    while stack:
        parent, children = stack[-1]
        try:
            node = next(children)
        except StopIteration:
            stack.pop()
            continue
        visited += 1
        if visited > MAX_AST_NODES:
            gaps.add("Python ecosystem syntax node limit reached.")
            break
        module, location = None, node
        if isinstance(node, ast.alias) and isinstance(parent, ast.Import):
            module, location = node.name, parent
        elif isinstance(node, ast.ImportFrom) and not node.level:
            module = node.module
        kind = {
            "http.server": "stdlib_http_server",
            "sqlite3": "stdlib_sqlite",
            "sqlite3.dbapi2": "stdlib_sqlite",
        }.get(module)
        if kind:
            signals.add((kind, location.lineno))
            if len(signals) >= MAX_SIGNALS:
                gaps.add("Python ecosystem signal limit reached.")
                break
        stack.append((node, iter(ast.iter_child_nodes(node))))
    return {
        "path": path,
        "signals": [{"kind": kind, "path": path, "line": line} for kind, line in sorted(signals)],
        "gaps": sorted(gaps),
        "status": "partial" if gaps else "complete",
    }


_JS_IGNORED = re.compile(
    r"""//[^\n]*|/\*[\s\S]*?(?:\*/|$)|"(?:\\[\s\S]|[^"\\])*(?:"|$)|'(?:\\[\s\S]|[^'\\])*(?:'|$)|`(?:\\[\s\S]|[^`\\])*(?:`|$)"""
)
_DOM_CALL = re.compile(
    r"\bdocument\s*\.\s*(?:createElement|querySelector|querySelectorAll|getElementById|addEventListener)\s*\("
)


def javascript_signals(path: str, text: str) -> dict:
    """Locate direct DOM calls lexically; no configuration or JavaScript is evaluated."""
    gaps = {
        "JavaScript hints are lexical; aliases, template expressions, regex literals and runtime behavior were not resolved."
    }
    if len(text) > MAX_TEXT_CHARACTERS:
        gaps.add("JavaScript ecosystem text character limit reached.")
    text = text[:MAX_TEXT_CHARACTERS]
    masked = _JS_IGNORED.sub(lambda match: " " * len(match[0]), text)
    lines, cursor, line = set(), 0, 1
    for index, match in enumerate(_DOM_CALL.finditer(masked)):
        if index >= MAX_SIGNALS:
            gaps.add("JavaScript ecosystem signal limit reached.")
            break
        line += text.count("\n", cursor, match.start())
        cursor = match.start()
        lines.add(line)
    return {
        "path": path,
        "signals": [{"kind": "direct_dom", "path": path, "line": line} for line in sorted(lines)],
        "gaps": sorted(gaps),
        "status": "partial",
    }


def summarize(manifests, signalresults) -> dict:
    """Combine bounded captured inputs without selecting frameworks or assigning scores."""
    gaps, dependencies, signals = set(), {}, {}
    for inputs, target, cap, key in (
        (manifests, dependencies, MAX_PROJECT_DEPENDENCIES, "dependencies"),
        (signalresults, signals, MAX_PROJECT_SIGNALS, "signals"),
    ):
        selected = list(islice(inputs, MAX_INPUTS + 1))
        if len(selected) > MAX_INPUTS:
            gaps.add("Ecosystem input record limit reached.")
        if key == "dependencies" and not selected:
            gaps.add(
                "No supported dependency manifests were captured; dependency inventory is unknown."
            )
        for item in sorted(selected[:MAX_INPUTS], key=lambda item: item["path"]):
            gaps.update(item["gaps"])
            if item["status"] != "complete":
                gaps.add("Some captured ecosystem inputs were incomplete.")
            for row in item[key]:
                if len(target) >= cap:
                    gaps.add("Project ecosystem output row limit reached.")
                    break
                projected = (
                    {**row, "path": item["path"], "line": None}
                    if key == "dependencies"
                    else dict(row)
                )
                identity = tuple(
                    projected[field]
                    for field in (
                        ("path", "group", "name")
                        if key == "dependencies"
                        else ("path", "line", "kind")
                    )
                )
                target[identity] = projected
    return {
        "schema_version": 1,
        "dependencies": [dependencies[key] for key in sorted(dependencies)],
        "signals": [signals[key] for key in sorted(signals)],
        "counts": {"dependencies": len(dependencies), "signals": len(signals)},
        "gaps": sorted(gaps),
        "status": "partial" if gaps else "complete",
        "limits": {
            "dependencies_per_manifest": MAX_DEPENDENCIES,
            "groups_per_manifest": MAX_GROUPS,
            "requirement_characters": MAX_REQUIREMENT_CHARACTERS,
            "text_characters": MAX_TEXT_CHARACTERS,
            "python_ast_nodes": MAX_AST_NODES,
            "signals_per_file": MAX_SIGNALS,
            "input_records": MAX_INPUTS,
            "project_dependencies": MAX_PROJECT_DEPENDENCIES,
            "project_signals": MAX_PROJECT_SIGNALS,
        },
        "caveat": CAVEAT,
    }
