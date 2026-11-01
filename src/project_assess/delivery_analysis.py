"""Bounded delivery declarations from captured configuration; no execution or resolution."""

from __future__ import annotations

import json
import re
import tomllib
from collections import Counter, defaultdict
from pathlib import PurePosixPath

from .static_analysis import source_role

VERSION = "1"
MAX_BYTES = 1024 * 1024
MAX_NODES = 30_000
MAX_DEPTH = 40
MAX_SIGNALS = 64
_LOCKS = {
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "Package.resolved",
    "gradle.lockfile",
}
_CAVEAT = "Literal captured configuration, not executed CI, resolved actions/orbs, reproducible installation or safe release/rollback."
_COMMANDS = {
    "test": re.compile(r"\b(?:pytest|unittest|vitest|jest|playwright|test)\b"),
    "build": re.compile(r"\b(?:build|compile|tsc|webpack|vite)\b"),
    "locked_install": re.compile(
        r"\b(?:npm\s+ci|uv\s+sync[^\n]*(?:--locked|--frozen)|(?:pnpm|yarn)\s+install[^\n]*(?:--frozen-lockfile|--immutable))\b"
    ),
    "artifact": re.compile(
        r"\b(?:upload-artifact|download-artifact|store_artifacts|persist_to_workspace|attach_workspace)\b"
    ),
    "release": re.compile(r"\b(?:deploy|publish|release|push)\b"),
    "rollback": re.compile(r"\b(?:rollback|rollout\s+undo|revert)\b"),
}


def is_delivery_input(path):
    parts, name = PurePosixPath(path).parts, PurePosixPath(path).name
    return (
        name in _LOCKS | {"package.json", "pyproject.toml", "Jenkinsfile", ".gitlab-ci.yml"}
        or (".circleci" in parts and name in {"config.yml", "config.yaml"})
        or (
            len(parts) >= 3
            and parts[-3:-1] == (".github", "workflows")
            and name.endswith((".yml", ".yaml"))
        )
    )


def _label(value):
    return (
        value
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_./@+-]{1,200}", value)
        else "<dynamic-or-unsupported>"
    )


def _scalar(node):
    return getattr(node, "value", None) if node is not None and node.id == "scalar" else None


def _map(node):
    return (
        {_scalar(key): value for key, value in node.value}
        if node is not None and node.id == "mapping"
        else {}
    )


def _sequence(node):
    if node is None:
        return []
    return node.value if node.id == "sequence" else [node]


def _yaml_tree(text):
    import yaml

    # Compose representation nodes only. No constructors, imports or objects from
    # the assessed configuration are loaded. BaseLoader preserves `on` as text.
    for count, token in enumerate(yaml.scan(text, Loader=yaml.BaseLoader), 1):
        if count > MAX_NODES * 4:
            raise ValueError("YAML token bound")
        if isinstance(token, yaml.tokens.TagToken):
            raise ValueError("Explicit YAML tags unsupported")
    node = yaml.compose(text, Loader=yaml.BaseLoader)
    count, pending = 0, [(node, 0, frozenset())] if node else []
    gaps = set()
    while pending:
        current, depth, ancestors = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH or id(current) in ancestors:
            raise ValueError("YAML node/depth/alias bound")
        parents = ancestors | {id(current)}
        if current.id == "mapping":
            keys = [_scalar(key) for key, _ in current.value]
            if None in keys or len(keys) != len(set(keys)):
                raise ValueError("Non-scalar or duplicate YAML key")
            if "<<" in keys:
                gaps.add("YAML merge keys were not resolved")
            pending.extend((child, depth + 1, parents) for pair in current.value for child in pair)
        elif current.id == "sequence":
            pending.extend((child, depth + 1, parents) for child in current.value)
        elif current.id == "scalar" and ("${{" in current.value or "<<" in current.value):
            gaps.add("Configuration expressions were not evaluated")
    return node, count, gaps


def analyze_delivery(path, text):
    """Return source-located declarations, including explicit unsupported/partial scope."""
    signals, gaps, total, nodes = [], set(), 0, 0
    dimensions = ["delivery"]
    unsupported = False
    language = "yaml" if path.endswith((".yml", ".yaml")) else "manifest"

    def add(kind, node=None, owner="workflow", **context):
        nonlocal total
        total += 1
        line = node.start_mark.line + 1 if node is not None else 1
        end = (
            max(line, node.end_mark.line + (bool(node.end_mark.column)))
            if node is not None
            else line
        )
        signals.append(
            {
                "kind": kind,
                "dimensions": ["delivery", "security"]
                if kind in {"delivery.permissions", "delivery.reference", "delivery.trigger"}
                else ["extensibility", "delivery"]
                if kind.startswith("extensibility.")
                else ["delivery"],
                "locations": [{"path": path, "line": line, "end_line": end}],
                "context": {"owner": _label(owner), **context},
                "method": "literal_configuration" if node is not None else "captured_manifest",
                "limitations": [_CAVEAT],
            }
        )

    def commands(value, node=None, owner="workflow"):
        if isinstance(value, str):
            for category, pattern in _COMMANDS.items():
                if pattern.search(value):
                    add(
                        "delivery.command",
                        node,
                        owner,
                        category=category,
                        classification="lexical_hint",
                    )

    def reference(node, owner):
        value = _scalar(node) or ""
        pin = (
            "dynamic"
            if "${{" in value or "<<" in value
            else "local"
            if value.startswith("./")
            else "digest"
            if re.search(r"@sha256:[0-9a-fA-F]{64}$", value)
            else "commit_sha"
            if re.search(r"@[0-9a-fA-F]{40}$", value)
            else "tag_or_branch"
        )
        add("delivery.reference", node, owner, pin=pin)
        if pin == "dynamic":
            gaps.add("Dynamic references were not resolved")
        commands(value, node, owner)

    def fields(mapping, owner):
        for field in (
            "permissions",
            "timeout-minutes",
            "continue-on-error",
            "concurrency",
            "environment",
            "if",
            "no_output_timeout",
            "resource_class",
            "parallelism",
        ):
            if field not in mapping:
                continue
            node, context = mapping[field], {}
            if field == "permissions":
                values = _map(node)
                context["policy"] = (
                    _scalar(node)
                    if _scalar(node) in {"read-all", "write-all"}
                    else "explicit_mapping"
                    if node.id == "mapping"
                    else "dynamic_or_unsupported"
                )
                context["write_scopes"] = sorted(
                    _label(key) for key, value in values.items() if _scalar(value) == "write"
                )
                context["scope_count"] = len(values)
            elif field == "continue-on-error":
                context["allowed"] = (
                    _scalar(node)
                    if _scalar(node) in {"true", "false"}
                    else "dynamic_or_unsupported"
                )
            elif field in {"timeout-minutes", "parallelism"}:
                value = _scalar(node) or ""
                context["value"] = (
                    int(value) if re.fullmatch(r"\d{1,6}", value) else "dynamic_or_unsupported"
                )
            elif field == "if":
                value = _scalar(node) or ""
                context = {
                    "expression_present": True,
                    "failure_or_always_hint": bool(
                        re.search(r"\b(?:always|failure|cancelled)\s*\(", value)
                    ),
                }
            else:
                context["declared"] = True
            add("delivery." + field.replace("-", "_"), node, owner, **context)

    def needs(node, owner):
        values, dynamic = [], 0
        for child in _sequence(node):
            names = list(_map(child)) if child.id == "mapping" else [_scalar(child)]
            for name in names:
                if name is not None and "${{" not in name and "<<" not in name:
                    values.append(_label(name))
                else:
                    dynamic += 1
        add(
            "delivery.dependencies",
            node,
            owner,
            needs=values[:100],
            omitted_needs=max(0, len(values) - 100),
            dynamic_needs=dynamic,
        )
        if dynamic:
            gaps.add("Dynamic job dependencies were not resolved")

    try:
        if len(text.encode()) > MAX_BYTES:
            raise ValueError("Delivery input byte bound")
        name = PurePosixPath(path).name
        if name in _LOCKS:
            add("delivery.lockfile", name=name, contents_validated=False)
        elif name in {"package.json", "pyproject.toml"}:
            dimensions.append("extensibility")
            data = json.loads(text) if name == "package.json" else tomllib.loads(text)
            project = data.get("project", {}) if name == "pyproject.toml" else data
            scripts = project.get("scripts", {})
            if not isinstance(scripts, dict):
                raise ValueError("Unsupported manifest script structure")
            for key, value in sorted(scripts.items())[:100]:
                if isinstance(value, str):
                    add("delivery.script", owner=_label(key), name=_label(key))
                    # package.json scripts are commands; Python entry points are
                    # callable declarations, not shell commands.
                    if name == "package.json":
                        commands(value, owner=_label(key))
            if len(scripts) > 100:
                gaps.add("Manifest script bound")
            if scripts:
                add("extensibility.entry_points", declaration="scripts", entry_count=len(scripts))
            for field in (
                ("exports", "bin", "peerDependencies", "engines")
                if name == "package.json"
                else ("entry-points", "requires-python")
            ):
                if field not in project:
                    continue
                value = project[field]
                shape = (
                    "mapping"
                    if isinstance(value, dict)
                    else "sequence"
                    if isinstance(value, list)
                    else "string"
                    if isinstance(value, str)
                    else "unsupported"
                )
                add(
                    "extensibility.compatibility"
                    if field in {"peerDependencies", "engines", "requires-python"}
                    else "extensibility.entry_points",
                    declaration=field,
                    shape=shape,
                    entry_count=len(value) if isinstance(value, (dict, list)) else 1,
                )
                if shape == "unsupported":
                    gaps.add("Unsupported manifest extension declaration shape")
        elif not is_delivery_input(path) or name in {"Jenkinsfile", ".gitlab-ci.yml"}:
            unsupported = True
            dimensions = []
            gaps.add("CI dialect unsupported; captured source remains inspectable")
        else:
            dimensions.append("security")
            try:
                import yaml
            except ImportError:
                return {
                    "path": path,
                    "language": language,
                    **source_role(path),
                    "status": "unavailable",
                    "dimensions": dimensions,
                    "coverage": {
                        "nodes_examined": 0,
                        "signals_total": 0,
                        "signals_retained": 0,
                        "signals_omitted": 0,
                    },
                    "signals": [],
                    "gaps": ["PyYAML unavailable"],
                }
            try:
                tree, nodes, parse_gaps = _yaml_tree(text)
                gaps.update(parse_gaps)
            except yaml.YAMLError as exc:
                raise ValueError("Unsupported or malformed YAML") from exc
            data = _map(tree)
            if not data:
                raise ValueError("CI configuration must be a mapping")
            provider = "circleci" if ".circleci" in PurePosixPath(path).parts else "github_actions"
            add("delivery.workflow", tree, provider=provider)
            fields(data, "workflow")
            if provider == "github_actions":
                triggers = data.get("on")
                if triggers is not None:
                    names = (
                        list(_map(triggers))
                        if triggers.id == "mapping"
                        else [_scalar(item) for item in _sequence(triggers)]
                    )
                    add(
                        "delivery.trigger", triggers, events=[_label(event) for event in names[:20]]
                    )
            if "orbs" in data:
                gaps.add("CircleCI orb implementations were not resolved")
            if "setup" in data:
                gaps.add("CircleCI continuation configuration was not resolved")
            if "jobs" not in data or data["jobs"].id != "mapping":
                gaps.add("Job definitions are missing or have unsupported shape")
            for owner, node in _map(data.get("jobs")).items():
                if node.id != "mapping":
                    gaps.add("A job has unsupported shape")
                    continue
                mapping = _map(node)
                add("delivery.job", node, owner)
                fields(mapping, owner)
                if "needs" in mapping:
                    needs(mapping["needs"], owner)
                if "uses" in mapping:
                    reference(mapping["uses"], owner)
                for step in _sequence(mapping.get("steps")):
                    details = _map(step)
                    fields(details, owner)
                    if "uses" in details:
                        reference(details["uses"], owner)
                    run = details.get("run")
                    if run is not None:
                        run_data = _map(run)
                        fields(run_data, owner)
                        commands(
                            _scalar(run_data.get("command")) if run_data else _scalar(run),
                            run,
                            owner,
                        )
                    for artifact in (
                        "store_artifacts",
                        "store_test_results",
                        "persist_to_workspace",
                        "attach_workspace",
                    ):
                        if artifact in details:
                            add("delivery.artifact", details[artifact], owner, operation=artifact)
                for image in _sequence(mapping.get("docker")):
                    value = _map(image).get("image")
                    if value is not None:
                        reference(value, owner)
                container = mapping.get("container")
                if container is not None:
                    image = _map(container).get("image") if container.id == "mapping" else container
                    if image is not None:
                        reference(image, owner)
            if provider == "circleci":
                for workflow in _map(data.get("workflows")).values():
                    for job in _sequence(_map(workflow).get("jobs")):
                        for owner, node in _map(job).items():
                            mapping = _map(node)
                            actual = _scalar(mapping.get("name")) or owner
                            if "requires" in mapping:
                                needs(mapping["requires"], actual)
                            if _scalar(mapping.get("type")) == "approval":
                                add("delivery.approval", mapping["type"], actual)
                            if "filters" in mapping:
                                add("delivery.filters", mapping["filters"], actual, declared=True)
    except (
        ValueError,
        TypeError,
        AttributeError,
        RecursionError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ):
        gaps.add("Input malformed or exceeds supported structure bounds")
    counts = Counter(signal["kind"] for signal in signals)
    if total > MAX_SIGNALS:
        gaps.add("Delivery signal output bound")
        groups = defaultdict(list)
        for signal in signals:
            context = signal["context"]
            feature = tuple(
                str(context.get(key, ""))
                for key in ("category", "declaration", "pin", "policy", "operation", "allowed")
            ) + (str(bool(context.get("write_scopes"))),)
            groups[(signal["kind"], feature)].append(signal)
        signals = []
        kinds = sorted(groups)
        for index, kind in enumerate(kinds):
            quota = MAX_SIGNALS // len(kinds) + (index < MAX_SIGNALS % len(kinds))
            rows = sorted(
                groups[kind], key=lambda row: (row["context"]["owner"], row["locations"][0]["line"])
            )
            count = min(quota, len(rows))
            signals.extend(rows[i * len(rows) // count] for i in range(count))
    return {
        "path": path,
        "language": language,
        **source_role(path),
        "status": "unsupported" if unsupported else "partial" if gaps else "complete",
        "dimensions": dimensions,
        "coverage": {
            "nodes_examined": nodes,
            "signals_total": total,
            "signals_retained": len(signals),
            "signals_omitted": total - len(signals),
            "signals_by_kind": dict(sorted(counts.items())),
            "selection": "kind_share_then_owner_location_spread",
        },
        "signals": signals,
        "gaps": sorted(gaps),
    }
