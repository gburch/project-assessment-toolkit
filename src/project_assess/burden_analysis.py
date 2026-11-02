"""Bounded change-hurdle leads from captured syntax and existing analysis.

This module does not execute project policy or infer a burden score.  A gate's
declared scope, a complex owner and a supplied duration answer different questions.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict, deque

from .rubric import DIMENSIONS

VERSION = "3"
MAX_LEADS = 200
MAX_SELECTOR_CANDIDATES = 64
MAX_EXPRESSION_NODES = 4000
MAX_INPUT_ROWS = 30000
_CHANGE_MECHANISMS = {
    "security.authorization_declaration",
    "operability.retry_policy",
    "operability.wait",
    "extensibility.discovery_or_dispatch",
    "extensibility.dispatch_or_abstract_declaration",
    "performance.io_in_loop",
    "performance.synchronization_context_hint",
    "performance.transaction_context_hint",
}
_SOURCE_KINDS = {"python", "javascript", "source", "configuration", "manifest", "documentation"}
_DECISION = re.compile(r"(?:^|_)(?:full|full_suite|all_tests|broad)(?:$|_)", re.I)
_CONTEXT = re.compile(r"verif|test|quality|pipeline|gate|(?:^|[/_.])ci(?:[/_.]|$)", re.I)
_CAVEAT = (
    "Static hurdle leads and declarations, not experienced cost, executed policy or burden scores. "
    "Trace the actual valuable change, required completion path and contrary maintainer experience; "
    "necessary safeguards and waits still count as cost."
)


def _walk(tree, limit):
    pending, nodes, parents = [tree], [], {}
    while pending and len(nodes) < limit:
        node = pending.pop()
        nodes.append(node)
        children = list(ast.iter_child_nodes(node))
        for child in children:
            parents[id(child)] = node
        pending.extend(reversed(children))
    return nodes, parents, bool(pending)


def _scope(node, parents):
    current = parents.get(id(node))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)):
            return current
        current = parents.get(id(current))
    return None


def _literal_strings(node):
    values, pending, examined = [], [node], 0
    while pending and examined < 1024:
        current = pending.pop()
        examined += 1
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            values.append(current.value)
        elif isinstance(current, (ast.Tuple, ast.List, ast.Set)):
            pending.extend(reversed(current.elts))
        elif (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id in {"frozenset", "tuple", "list", "set"}
            and len(current.args) == 1
            and not current.keywords
        ):
            pending.append(current.args[0])
        else:
            return None
    return None if pending else values


def _name(node):
    parts = []
    while isinstance(node, ast.Attribute) and len(parts) < 20:
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts)) if parts else None


def analyze_change_gates(path, tree, *, node_limit=100000, record_limit=32, pattern_limit=128):
    """Inspect the existing Python AST for full/broad check-selector relationships.

    Names identify candidate gate decisions; literal membership/startswith/glob
    relations describe their syntax only.  Dynamic calls, policy loading and
    mutations remain unresolved.  Project code and wrappers are never evaluated.
    """
    if (
        type(node_limit) is not int
        or not 1 <= node_limit <= 100000
        or type(record_limit) is not int
        or not 0 <= record_limit <= 64
        or type(pattern_limit) is not int
        or not 0 <= pattern_limit <= 256
    ):
        raise ValueError("Invalid change-gate analysis bounds")
    nodes, parents, truncated = _walk(tree, node_limit)
    assignments, bound, mutations = defaultdict(list), defaultdict(set), defaultdict(list)
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    scope = _scope(node, parents)
                    assignments[(id(scope), target.id)].append((node.value, node))
                    bound[id(scope)].add(target.id)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            scope = _scope(node, parents)
            assignments[(id(scope), node.target.id)].append((None, node))
            bound[id(scope)].add(node.target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            bound[id(node)].update(
                arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            )
            if node.args.vararg:
                bound[id(node)].add(node.args.vararg.arg)
            if node.args.kwarg:
                bound[id(node)].add(node.args.kwarg.arg)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr in {"append", "extend", "add", "update", "insert", "remove", "clear"}
        ):
            mutations[(id(_scope(node, parents)), node.func.value.id)].append(node)

    def resolve(name, scope):
        while scope is not None:
            rows = assignments.get((id(scope), name), [])
            if name in bound[id(scope)]:
                return rows[0] if len(rows) == 1 else None
            scope = _scope(scope, parents)
        return None

    signals, found, patterns_seen, patterns_kept = [], 0, 0, 0
    unresolved_total, candidates_seen, candidates_examined = 0, 0, 0
    unsupported_patterns, mutation_total = 0, 0
    for assignment in nodes:
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            continue
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        decisions = [
            target.id
            for target in targets
            if isinstance(target, ast.Name) and _DECISION.search(target.id)
        ]
        if not decisions or _literal_strings(assignment.value) is not None:
            continue
        scope = _scope(assignment, parents)
        owner = getattr(scope, "name", "<module>")
        if not _CONTEXT.search(path + "/" + owner):
            continue
        candidates_seen += 1
        if candidates_examined >= MAX_SELECTOR_CANDIDATES:
            continue
        candidates_examined += 1
        expressions = [assignment.value] if assignment.value is not None else []
        parent = parents.get(id(assignment))
        if isinstance(parent, ast.If):
            expressions.append(parent.test)
        # Follow only same-scope, unambiguous local selector assignments.  The
        # small fixed depth exposes bool(broad) <- comprehension <- literal set.
        expanded, referenced, unresolved, seen = [], set(), set(), set()
        pending = deque((expression, scope, 0) for expression in expressions)
        expression_nodes = 0
        while pending and expression_nodes < MAX_EXPRESSION_NODES:
            expression, active_scope, depth = pending.popleft()
            if id(expression) in seen:
                continue
            seen.add(id(expression))
            expr_nodes, _, expr_truncated = _walk(
                expression, MAX_EXPRESSION_NODES - expression_nodes
            )
            expression_nodes += len(expr_nodes)
            expanded.extend(expr_nodes)
            truncated |= expr_truncated
            for child in expr_nodes:
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    row = resolve(child.id, active_scope)
                    if row is not None and child.id not in decisions:
                        referenced.add(child.id)
                        if depth < 3 and row[0] is not None:
                            pending.append((row[0], _scope(row[1], parents), depth + 1))
                        elif row[0] is not None and not isinstance(row[0], ast.Constant):
                            unresolved.add(child.id)
                    elif child.id not in {"bool", "any", "all", "True", "False"}:
                        unresolved.add(child.id)
        truncated |= bool(pending)
        aliases = {}
        for child in expanded:
            if isinstance(child, ast.comprehension) and isinstance(child.target, ast.Name):
                row = resolve(child.iter.id, scope) if isinstance(child.iter, ast.Name) else None
                values = _literal_strings(row[0] if row else child.iter)
                if values is not None:
                    aliases[(id(parents.get(id(child))), child.target.id)] = (
                        values,
                        row[1] if row else child,
                    )
        patterns, dedup = [], set()

        def add_patterns(
            value,
            match,
            declaration,
            *,
            scope=scope,
            aliases=aliases,
            assignment=assignment,
            dedup=dedup,
            patterns=patterns,
            unresolved=unresolved,
        ):
            nonlocal patterns_seen, patterns_kept, unsupported_patterns
            row = resolve(value.id, scope) if isinstance(value, ast.Name) else None
            aliased, comprehension_bound = None, False
            ancestor = parents.get(id(value))
            while ancestor is not None and isinstance(value, ast.Name):
                if isinstance(
                    ancestor, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
                ):
                    if any(
                        isinstance(g.target, ast.Name) and g.target.id == value.id
                        for g in ancestor.generators
                    ):
                        comprehension_bound = True
                        aliased = aliases.get((id(ancestor), value.id))
                        break
                ancestor = parents.get(id(ancestor))
            values = (
                aliased[0]
                if aliased
                else None
                if comprehension_bound
                else _literal_strings(row[0] if row else value)
            )
            origin = aliased[1] if aliased else row[1] if row else declaration
            if values is None:
                unsupported_patterns += 1
                if isinstance(value, ast.Name):
                    unresolved.add(value.id)
                return
            for literal in values:
                # Gate path inventory deliberately excludes arbitrary long values
                # and non-path string flags; parent redaction still applies.
                if not ("/" in literal or "." in literal or any(c in literal for c in "*?[]")):
                    continue
                if len(literal) > 300 or any(ord(c) < 32 for c in literal):
                    continue
                key = (literal, match, getattr(origin, "lineno", assignment.lineno))
                if key in dedup:
                    continue
                dedup.add(key)
                patterns_seen += 1
                if len(signals) < record_limit and patterns_kept < pattern_limit:
                    patterns.append({"value": literal, "match": match, "declaration_line": key[2]})
                    patterns_kept += 1

        for child in expanded:
            if isinstance(child, ast.Compare):
                for op, value in zip(child.ops, child.comparators, strict=True):
                    if isinstance(op, (ast.In, ast.NotIn)):
                        match = (
                            "basename_membership_syntax"
                            if isinstance(child.left, ast.Attribute) and child.left.attr == "name"
                            else "membership_syntax"
                        )
                        add_patterns(value, match, child)
            elif isinstance(child, ast.Call):
                name = _name(child.func) or ""
                if name.endswith((".startswith", ".endswith", ".match", ".fnmatch")) or name in {
                    "fnmatch",
                    "fnmatchcase",
                }:
                    if child.args:
                        match = (
                            "prefix_syntax"
                            if name.endswith(".startswith")
                            else "suffix_syntax"
                            if name.endswith(".endswith")
                            else "glob_syntax"
                        )
                        add_patterns(
                            child.args[0]
                            if name.endswith((".startswith", ".endswith", ".match"))
                            else child.args[-1],
                            match,
                            child,
                        )
        if not dedup and not referenced:
            continue
        found += 1
        unresolved_total += len(unresolved)
        selector_mutations = []
        for name in sorted(set(decisions) | referenced):
            for mutation in mutations.get((id(scope), name), []):
                mutation_total += 1
                if len(selector_mutations) < 16:
                    selector_mutations.append(
                        {"selector": name, "line": mutation.lineno, "operation": mutation.func.attr}
                    )
        if len(signals) < record_limit:
            signals.append(
                {
                    "kind": "change_gate_selector",
                    "dimensions": ["testing", "delivery", "security"],
                    "locations": [
                        {
                            "path": path,
                            "line": assignment.lineno,
                            "end_line": getattr(assignment, "end_lineno", assignment.lineno),
                        }
                    ],
                    "interpretation": "static_lead",
                    "context": {
                        "owner": owner[:200],
                        "decision_names": decisions,
                        "selector_references": sorted(referenced)[:32],
                        "unresolved_references": sorted(unresolved)[:32],
                        "patterns": patterns,
                        "selector_mutations": selector_mutations,
                        "policy_execution": "not_evaluated",
                    },
                    "limitations": [
                        "Literal selector syntax does not prove runtime gate selection, frequency, cost or safe relaxation; dynamic policy and helper behavior need source review."
                    ],
                }
            )
    mutations_retained = sum(len(s["context"]["selector_mutations"]) for s in signals)
    partial = (
        truncated
        or len(signals) < found
        or patterns_kept < patterns_seen
        or candidates_examined < candidates_seen
        or mutations_retained < mutation_total
    )
    return {
        "version": VERSION,
        "status": "partial" if partial else "complete",
        "signals": signals,
        "coverage": {
            "nodes_examined": len(nodes),
            "node_limit": node_limit,
            "candidates_observed": candidates_seen,
            "candidates_examined": candidates_examined,
            "candidates_omitted": candidates_seen - candidates_examined,
            "selectors_observed": found,
            "selectors_retained": len(signals),
            "selectors_omitted": found - len(signals),
            "patterns_observed": patterns_seen,
            "patterns_retained": patterns_kept,
            "patterns_omitted": patterns_seen - patterns_kept,
            "unresolved_references": unresolved_total,
            "unsupported_pattern_expressions": unsupported_patterns,
            "selector_mutations_observed": mutation_total,
            "selector_mutations_retained": mutations_retained,
            "selector_mutations_omitted": mutation_total - mutations_retained,
        },
        "gaps": (["Change-gate traversal or retained detail is partial."] if partial else [])
        + (
            [
                "Some selector references, mutations or literal patterns remain dynamic, unsupported or bounded; no policy closure is claimed."
            ]
            if unresolved_total or unsupported_patterns or mutation_total
            else []
        ),
        "caveat": _CAVEAT,
    }


def summarize_burden(assessment, *, limit=80):
    """Route captured facts into deterministic, source-bound hurdle review leads."""
    if type(limit) is not int or not 0 <= limit <= MAX_LEADS:
        raise ValueError("Invalid burden lead limit")
    evidence = assessment.get("evidence", [])
    sources = {row["path"]: row for row in evidence if row.get("kind") in _SOURCE_KINDS}
    lead_cache, by_kind, dimensions = (
        defaultdict(list),
        Counter(),
        {d: {"lead_count": 0, "evidence_ids": set()} for d in DIMENSIONS},
    )
    gaps, timings, traversal_partial = set(), [], False
    input_rows_omitted, input_rows_examined = 0, 0

    def bounded(rows):
        nonlocal input_rows_omitted, input_rows_examined
        retained = min(len(rows), MAX_INPUT_ROWS - input_rows_examined)
        input_rows_omitted += len(rows) - retained
        input_rows_examined += retained
        return rows[:retained]

    def priority(row):
        metrics = row["metrics"]

        def numeric(name):
            value = metrics.get(name, 0)
            return value if type(value) in {int, float} else 0

        return (
            int(bool(metrics.get("generated_hint") or metrics.get("vendor_hint"))),
            -numeric("lines"),
            -numeric("decision_points"),
            -numeric("control_nesting"),
            -numeric("module_count"),
            -numeric("matching_functions"),
            -int("full" in metrics.get("decision_names", [])),
            row["locations"][0]["path"],
            row["locations"][0]["line"],
            row["id"],
        )

    def emit(kind, dims, locations, metrics, interpretation="static_lead", analysis_id=None):
        bound_locations, ids = [], []
        for location in locations[:8]:
            entry = sources.get(location.get("path"))
            if entry is None:
                continue
            line = location.get("line", 1)
            end = location.get("end_line", line)
            if type(line) is not int or type(end) is not int or not 1 <= line <= end:
                continue
            if type(entry.get("lines")) is int and end > entry["lines"]:
                continue
            bound_locations.append(
                {
                    "path": location["path"],
                    "line": line,
                    "end_line": end,
                    "source_evidence_id": entry["id"],
                    "source_digest": entry["digest"],
                }
            )
            ids.append(entry["id"])
        if not bound_locations:
            return
        dims = [d for d in dims if d in DIMENSIONS]
        key = json.dumps([kind, dims, bound_locations, metrics], sort_keys=True)
        row = {
            "id": "h-" + hashlib.sha256(key.encode()).hexdigest()[:24],
            "kind": kind,
            "dimensions": dims,
            "locations": bound_locations,
            "metrics": metrics,
            "interpretation": interpretation,
            "evidence_ids": list(dict.fromkeys(ids)),
            "analysis_evidence_id": analysis_id,
            "cost_status": "not_established",
            "required_review": "Trace a valuable change through its actual required path; reconcile necessity, simpler alternatives, experienced frequency and contrary observations.",
        }
        bucket = lead_cache[kind]
        bucket.append(row)
        if len(bucket) >= MAX_LEADS * 2:
            bucket.sort(key=priority)
            del bucket[MAX_LEADS:]
        by_kind[kind] += 1
        for d in dims:
            dimensions[d]["lead_count"] += 1
            dimensions[d]["evidence_ids"].update(ids)

    for entry in evidence:
        stats, kind = entry.get("stats", {}), entry.get("kind")
        if kind == "python":
            gate = stats.get("change_gates", {})
            traversal_partial |= gate.get("status") == "partial"
            for signal in bounded(gate.get("signals", [])):
                emit(
                    "change_gate_selector",
                    signal["dimensions"],
                    signal["locations"],
                    signal["context"],
                    analysis_id=entry["id"],
                )
        if kind in {"static-analysis", "javascript-analysis"}:
            traversal_partial |= stats.get("status") == "partial"
            modules = bounded(stats.get("modules", []))
            module_context = {module["path"]: module for module in modules}
            for module in modules:
                if module.get("role") != "production" or module.get("lines", 0) < 1000:
                    continue
                emit(
                    "large_change_surface",
                    ["maintainability"],
                    [{"path": module["path"], "line": 1}],
                    {
                        key: module[key]
                        for key in (
                            "lines",
                            "function_count",
                            "inbound",
                            "outbound",
                            "inbound_complete",
                            "overview_partial",
                            "role_basis",
                            "generated_hint",
                            "vendor_hint",
                        )
                        if key in module
                    },
                    analysis_id=entry["id"],
                )
            for hotspot in bounded(stats.get("hotspots", [])):
                if hotspot.get("decision_points", 0) < 20 and hotspot.get("control_nesting", 0) < 4:
                    continue
                dims = ["testing"] if hotspot.get("role") == "test" else ["maintainability"]
                emit(
                    "complex_change_surface",
                    dims,
                    [hotspot],
                    {
                        "generated_hint": module_context.get(hotspot.get("path"), {}).get(
                            "generated_hint", False
                        ),
                        "vendor_hint": module_context.get(hotspot.get("path"), {}).get(
                            "vendor_hint", False
                        ),
                        **{
                            key: hotspot[key]
                            for key in (
                                "name",
                                "decision_points",
                                "control_nesting",
                                "metric_basis",
                                "partial",
                            )
                            if key in hotspot
                        },
                    },
                    analysis_id=entry["id"],
                )
            candidates = stats.get("candidate_index", stats.get("candidates", []))
            for candidate in bounded(candidates):
                name = candidate.get("kind", "")
                if name not in {
                    "dependency_cycle",
                    "duplicate_block",
                    "duplicate_function",
                    "near_duplicate_function",
                }:
                    continue
                dims = ["testing"] if candidate.get("role") == "test" else ["maintainability"]
                emit(
                    name,
                    dims,
                    candidate.get("locations", []),
                    {
                        "producer_confidence": candidate.get("confidence"),
                        "candidate_id": candidate.get("id"),
                        **{
                            key: value
                            for key, value in candidate.get("metrics", {}).items()
                            if key
                            in {
                                "module_count",
                                "matching_functions",
                                "matching_blocks",
                                "statements",
                            }
                            and type(value) in {int, float}
                        },
                    },
                    analysis_id=entry["id"],
                )
        elif kind == "control-analysis":
            traversal_partial |= stats.get("status") == "partial"
            for signal in bounded(stats.get("signals", [])):
                name = signal.get("kind", "")
                if name in {"performance.timing_threshold_hint", "timing_threshold_hint"}:
                    emit(
                        "performance.timing_threshold_hint",
                        ["performance", "testing", "maintainability", "delivery"],
                        signal.get("locations", []),
                        signal.get("context", {}),
                        analysis_id=entry["id"],
                    )
                    continue
                if name in _CHANGE_MECHANISMS:
                    emit(
                        name,
                        signal.get("dimensions", []),
                        signal.get("locations", []),
                        {
                            "producer_confidence": signal.get("confidence"),
                            **signal.get("context", {}),
                        },
                        analysis_id=entry["id"],
                    )
                    continue
                if name not in {
                    "delivery.dependencies",
                    "delivery.approval",
                    "delivery.concurrency",
                    "delivery.environment",
                    "delivery.parallelism",
                }:
                    continue
                emit(
                    "declared_gate_coordination",
                    ["delivery", "testing", "security"],
                    signal.get("locations", []),
                    {"control_kind": name, **signal.get("context", {})},
                    "declared_control",
                    entry["id"],
                )
        elif kind == "documentation-analysis":
            document_roles = {
                row["path"]: row.get("roleHint") for row in stats.get("documents", [])
            }
            for group in bounded(stats.get("exactDuplicates", [])):
                authored = [
                    path
                    for path in group
                    if document_roles.get(path) not in {"generated", "required_record"}
                ]
                if len(authored) < 2:
                    continue
                emit(
                    "duplicate_guidance",
                    ["documentation"],
                    [{"path": path, "line": 1} for path in authored],
                    {
                        "matching_documents": len(authored),
                        "generated_or_required_records_omitted": len(group) - len(authored),
                    },
                    analysis_id=entry["id"],
                )
            for lead in bounded(stats.get("maintenanceLeads", [])):
                emit(
                    lead["kind"],
                    ["documentation", "maintainability"],
                    lead.get("locations", []),
                    lead.get("metrics", {}),
                    "lexical_relationship_needs_review",
                    entry["id"],
                )
        elif kind == "junit":
            timings.append(
                {
                    "evidence_id": entry["id"],
                    "kind": "junit",
                    "seconds": stats.get("seconds"),
                    "timing_semantics": "sum_testcase_elapsed",
                    "wall_clock_seconds": None,
                    "run_identity": "unestablished",
                    "completion": "unestablished",
                    "caveat": "Summed case durations include overlap/fixture waits and are not whole-gate wall time, CPU time or maintenance effort.",
                }
            )
        elif kind == "observation":
            timings.append(
                {
                    "evidence_id": entry["id"],
                    "kind": "observation",
                    "observation_type": stats.get("type"),
                    "scenario": stats.get("scenario"),
                    "sourceIdentity": stats.get("sourceIdentity"),
                    "results": stats.get("results"),
                    "limitations": stats.get("limitations", []),
                    "caveat": "Supplied results retain their declared units/status; matching source does not authenticate execution or make the scenario representative.",
                }
            )

    # Kind rounds prevent many duplicate windows from displacing gate/complexity leads.
    groups = defaultdict(deque)
    for kind, rows in lead_cache.items():
        groups[kind].extend(sorted(rows, key=priority)[:MAX_LEADS])
    selected = []
    while groups and len(selected) < limit:
        for kind in sorted(groups):
            if len(selected) == limit:
                break
            selected.append(groups[kind].popleft())
            if not groups[kind]:
                del groups[kind]
    if not timings:
        gaps.add(
            "No supplied timing/change-cost observation is captured; intended fast paths do not establish experienced upkeep."
        )
    gate_files = [entry for entry in evidence if entry.get("kind") == "python"]
    gate_missing = sum("change_gates" not in entry.get("stats", {}) for entry in gate_files)
    if gate_missing:
        traversal_partial = True
        gaps.add(
            "Some captured Python files lack completed gate analysis; their gate scope is unknown."
        )
    if not by_kind["change_gate_selector"] and not by_kind["declared_gate_coordination"]:
        gaps.add(
            "No supported required-gate selector/declaration was identified; absence is not proof of a cheap completion path."
        )
    if traversal_partial or input_rows_omitted:
        gaps.add(
            "Underlying source/control analysis is partial; inspect its independent limits and omissions."
        )
    timings.sort(key=lambda row: row["evidence_id"])
    for d, row in dimensions.items():
        row["evidence_ids"] = sorted(row["evidence_ids"])[:100]
        row["retained_leads"] = sum(d in lead["dimensions"] for lead in selected)
        row["cost_status"] = "not_established"
        row["required_evidence"] = (
            "Attributed maintainer/change experience or applicable observed completion paths, with frequency, scope, waits/rework and counterevidence."
        )
    return {
        "schema_version": 1,
        "version": VERSION,
        "status": "partial"
        if traversal_partial
        or input_rows_omitted
        or len(selected) < sum(by_kind.values())
        or len(timings) > 32
        else "complete",
        "leads": selected,
        "dimensions": dimensions,
        "timings": timings[:32],
        "coverage": {
            "leads_observed": sum(by_kind.values()),
            "leads_retained": len(selected),
            "leads_omitted": sum(by_kind.values()) - len(selected),
            "by_kind": dict(sorted(by_kind.items())),
            "timing_records_observed": len(timings),
            "timing_records_omitted": max(0, len(timings) - 32),
            "input_rows_omitted": input_rows_omitted,
            "input_rows_examined": input_rows_examined,
            "gate_input_python_files": len(gate_files),
            "gate_examined_python_files": len(gate_files) - gate_missing,
            "gate_unavailable_python_files": gate_missing,
            "gate_syntax_scope": "Python selector rules only; other languages and dynamic policy are not evaluated.",
        },
        "limits": {
            "leads": limit,
            "timing_records": 32,
            "locations_per_lead": 8,
            "input_rows_total": MAX_INPUT_ROWS,
            "temporary_leads_per_kind": MAX_LEADS * 2,
        },
        "gaps": sorted(gaps),
        "caveat": _CAVEAT,
    }
