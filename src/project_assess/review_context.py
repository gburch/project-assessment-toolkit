"""A bounded path-based orientation map, not semantic domains or a risk ranking."""

from collections import Counter, defaultdict, deque
from pathlib import PurePosixPath

from .generic_analysis import source_area, source_language
from .static_analysis import source_role

MAX_AREAS = 20
MAX_DEPENDENCIES = 20
MAX_CITATIONS = 5


def _number(value):
    return value if type(value) is int and value >= 0 else None


def build_challenge_evidence_index(assessment, change_traces, limit=80):
    """Select captured navigation across traces, production areas and support.

    Selection is a bounded inspection aid, not evidence that the reviewer read
    these records or that their size/shape establishes a score.
    """
    if type(limit) is not int or not 1 <= limit <= 80:
        raise ValueError("Challenge evidence limit must be between 1 and 80")
    evidence = sorted(assessment.get("evidence", []), key=lambda e: (e.get("path", ""), e["id"]))
    by_id = {e["id"]: e for e in evidence}
    modules = {}
    for entry in evidence:
        if entry.get("kind") in {"static-analysis", "javascript-analysis"}:
            for row in entry.get("stats", {}).get("modules", []):
                modules[row["path"]] = row
    production, support = defaultdict(list), defaultdict(list)
    roles = {}

    def cost(entry):
        row = modules.get(entry["path"], {})
        functions, patterns = (
            _number(row.get("function_count")),
            _number(row.get("pattern_functions")),
        )
        partial = bool(
            row.get("overview_partial")
            or row.get("partial_functions")
            or row.get("status") in {"partial", "unavailable", "unsupported"}
        )
        partial |= functions is not None and patterns is not None and patterns < functions
        return (
            -partial,
            -(functions or 0),
            -(_number(entry.get("lines")) or 0),
            entry["path"],
            entry["id"],
        )

    for entry in evidence:
        path, stats = entry.get("path", ""), entry.get("stats", {})
        role = stats.get("role") or source_role(path)["role"]
        roles[entry["id"]] = role
        if (
            source_language(path)
            and role == "production"
            and not any(stats.get(key) for key in ("generated_hint", "vendor_hint"))
        ):
            production[source_area(path)].append(entry)
        else:
            category = (
                "test"
                if role == "test"
                else "documentation"
                if entry.get("kind") == "documentation"
                else "configuration"
                if entry.get("kind") in {"manifest", "configuration", "ci"}
                else "analysis"
                if entry.get("kind", "").endswith("-analysis")
                else "other"
            )
            support[category].append(entry)
    for entries in production.values():
        entries.sort(key=cost)
    for entries in support.values():
        entries.sort(
            key=lambda e: (
                roles[e["id"]] == "tooling",
                PurePosixPath(e.get("path", "")).name.lower()
                not in {
                    "readme.md",
                    "pyproject.toml",
                    "package.json",
                    "architecture.md",
                    "operations.md",
                    "setup.md",
                },
                e.get("path", ""),
                e["id"],
            )
        )
    cited = list(
        dict.fromkeys(
            identity
            for trace in change_traces
            for step in trace.get("steps", [])
            for identity in step.get("evidence_ids", [])
            if identity in by_id
        )
    )
    picked = {}

    def select(entry, reason):
        identity = entry["id"]
        if identity not in picked and len(picked) < limit:
            picked[identity] = {
                key: entry[key] for key in ("id", "kind", "path", "digest", "lines") if key in entry
            }
            picked[identity]["selection_reasons"] = []
        if identity in picked and reason not in picked[identity]["selection_reasons"]:
            picked[identity]["selection_reasons"].append(reason)

    for identity in cited[: max(1, limit // 3)]:
        select(by_id[identity], "change_trace")
    support_slots = min(12, limit // 4)
    # One costly/partial owner per area precedes additional owners from any
    # single subtree. Areas absent from the bounded system map still compete.
    areas = sorted(production, key=lambda area: (cost(production[area][0]), area))
    for area in areas:
        if len(picked) >= limit - support_slots:
            break
        select(production[area][0], "production_area_owner")
    categories = [
        key
        for key in ("configuration", "documentation", "test", "analysis", "other")
        if support[key]
    ]
    positions = Counter()
    remaining = support_slots
    while remaining and len(picked) < limit:
        advanced = False
        for category in categories:
            while (
                positions[category] < len(support[category])
                and support[category][positions[category]]["id"] in picked
            ):
                positions[category] += 1
            if positions[category] < len(support[category]):
                select(support[category][positions[category]], "support_" + category)
                positions[category] += 1
                remaining -= 1
                advanced = True
                if not remaining or len(picked) >= limit:
                    break
        if not advanced:
            break
    for identity in cited:
        select(by_id[identity], "change_trace")
    queues = {area: deque(production[area]) for area in areas}
    while queues and len(picked) < limit:
        for area in list(queues):
            entry = queues[area].popleft()
            if entry["id"] not in picked:
                select(entry, "additional_production_owner")
            if not queues[area]:
                del queues[area]
    for entry in evidence:
        if entry["id"] not in picked:
            select(entry, "captured_context")
    production_ids = {entry["id"] for entries in production.values() for entry in entries}
    represented = {source_area(e["path"]) for e in picked.values() if e["id"] in production_ids}
    return {
        "items": list(picked.values()),
        "selection": {
            "method": (
                "trace_then_production_area_breadth_then_support"
                if cited
                else "production_area_breadth_then_support"
            ),
            "limit": limit,
            "selected": len(picked),
            "omitted": max(0, len(evidence) - len(picked)),
            "trace_cited": len(cited),
            "trace_selected": len(set(cited) & picked.keys()),
            "omitted_trace_evidence": len(set(cited) - picked.keys()),
            "production_areas": len(production),
            "represented_production_areas": len(set(production) & represented),
            "omitted_production_areas": len(set(production) - represented),
            "caveat": "Selection covers captured records only and does not certify review breadth, semantic ownership, severity or confidence; use evidence queries for omitted records.",
        },
    }


def get_system_map(assessment, *, compact=True):
    """Group captured production paths/imports; compact=False supplies query paging."""
    evidence = assessment.get("evidence", [])
    analyses = sorted(
        [
            e
            for e in evidence
            if e.get("kind") in {"source-analysis", "static-analysis", "javascript-analysis"}
        ],
        key=lambda e: (e["kind"] != "source-analysis", e["kind"], e.get("id", "")),
    )
    modules, analysis_ids = {}, defaultdict(set)
    for entry in analyses:
        for row in entry.get("stats", {}).get("modules", []):
            modules.setdefault(row["path"], {}).update(row)
            if entry.get("id"):
                analysis_ids[row["path"]].add(entry["id"])
    sources = {e["path"]: e for e in evidence if source_language(e.get("path", ""))}
    areas, production, excluded = {}, {}, Counter()
    for path, source in sorted(sources.items()):
        row, stats = modules.get(path, {}), source.get("stats", {})
        role = stats.get("role") or row.get("role") or source_role(path)["role"]
        if any(stats.get(key) or row.get(key) for key in ("generated_hint", "vendor_hint")):
            role = "generated_or_vendor"
        if role != "production":
            excluded[role] += 1
            continue
        area = source_area(path)
        production[path] = area
        group = areas.setdefault(
            area,
            {
                "path": area,
                "files": 0,
                "modules": 0,
                "functions": 0,
                "functions_known_files": 0,
                "lines": 0,
                "lines_known_files": 0,
                "partial_modules": 0,
                "source_evidence_ids": [],
                "analysis_evidence_ids": set(),
            },
        )
        group["files"] += 1
        group["modules"] += path in modules
        group["partial_modules"] += bool(
            row.get("overview_partial")
            or row.get("status") in {"partial", "unavailable", "unsupported"}
        )
        for field, value in (
            ("functions", row.get("function_count")),
            ("lines", source.get("lines", row.get("lines"))),
        ):
            if (value := _number(value)) is not None:
                group[field] += value
                group[field + "_known_files"] += 1
        if source.get("id"):
            group["source_evidence_ids"].append(source["id"])
        group["analysis_evidence_ids"].update(analysis_ids[path])
    dependencies, graphs, seen = {}, [], set()
    excluded_edges = 0
    for entry in analyses:
        if entry["kind"] == "source-analysis":
            continue
        stats = entry.get("stats", {})
        topology = stats.get("topology", {})
        edges = topology.get("edges", [])
        graphs.append(
            {
                "evidence_id": entry.get("id"),
                "kind": entry["kind"],
                "complete": topology.get("complete"),
                "source_complete": topology.get("source_complete"),
                "edge_count": len(edges),
                "limits": stats.get("limits", {}),
                "gaps": stats.get("gaps", [])[:5],
            }
        )
        for edge in edges:
            source, target = edge.get("source"), edge.get("target")
            if source not in production or target not in production:
                excluded_edges += 1
                continue
            key = (source, target, edge.get("line"), edge.get("phase", "unknown"))
            if key in seen or production[source] == production[target]:
                continue
            seen.add(key)
            pair = (production[source], production[target])
            group = dependencies.setdefault(
                pair,
                {
                    "source_area": pair[0],
                    "target_area": pair[1],
                    "import_edges": 0,
                    "phases": Counter(),
                    "evidence_ids": set(),
                },
            )
            group["import_edges"] += 1
            group["phases"][key[3]] += 1
            group["evidence_ids"].update(
                v
                for v in (entry.get("id"), sources[source].get("id"), sources[target].get("id"))
                if v
            )
    for group in areas.values():
        for field in ("functions", "lines"):
            if not group[field + "_known_files"]:
                group[field] = None
        ids = group["source_evidence_ids"]
        group["omitted_source_evidence_ids"] = max(0, len(ids) - MAX_CITATIONS)
        group["source_evidence_ids"] = ids[:MAX_CITATIONS]
        group["analysis_evidence_ids"] = sorted(group["analysis_evidence_ids"])
        group["evidence_ids"] = (group["analysis_evidence_ids"] + ids)[:MAX_CITATIONS]
    for group in dependencies.values():
        group["phases"] = dict(sorted(group["phases"].items()))
        ids = sorted(group["evidence_ids"])
        group["evidence_ids"], group["omitted_evidence_ids"] = (
            ids[:MAX_CITATIONS],
            max(0, len(ids) - MAX_CITATIONS),
        )
    area_rows = sorted(areas.values(), key=lambda row: (-row["files"], row["path"]))
    dependency_rows = sorted(
        dependencies.values(),
        key=lambda row: (-row["import_edges"], row["source_area"], row["target_area"]),
    )
    if compact:
        area_rows = area_rows[:MAX_AREAS]
        dependency_rows = dependency_rows[:MAX_DEPENDENCIES]
    return {
        "schema_version": 1,
        "status": "not_collected"
        if not sources
        else "complete"
        if assessment.get("complete") is True
        and graphs
        and all(g["complete"] is True for g in graphs)
        else "partial",
        "heuristic": "Use the first src/lib container, then a package and subtree when available; otherwise the first two directories. Preserve original path prefixes; root files use (root).",
        "production_files": len(production),
        "excluded_files_by_role": dict(sorted(excluded.items())),
        "area_count": len(areas),
        "areas": area_rows,
        "omitted_areas": len(areas) - len(area_rows),
        "cross_area_dependencies": dependency_rows,
        "omitted_cross_area_dependencies": len(dependencies) - len(dependency_rows),
        "excluded_nonproduction_or_uncaptured_import_edges": excluded_edges,
        "native_import_graphs": graphs,
        "collection": {
            "complete": assessment.get("complete"),
            "gaps": assessment.get("gaps", [])[:5],
        },
        "gaps": assessment.get("gaps", [])[:5]
        + (
            [
                f"{excluded['unknown']} captured source file(s) have unknown roles and are omitted from this production map; inspect the inventory before judging scope."
            ]
            if excluded["unknown"]
            else []
        )
        + (
            []
            if assessment.get("complete") is True
            else [
                "Collection completeness is unknown or partial; this map covers captured records only."
            ]
        ),
        "limits": {
            "areas": MAX_AREAS if compact else None,
            "dependencies": MAX_DEPENDENCIES if compact else None,
            "citations_per_group": MAX_CITATIONS,
        },
        "caveat": "Path/role heuristics are orientation, not semantic domains, debt, grades or priority. Counts cover captured records; partial module counts can be lower bounds and unknown function counts remain unknown. Native static import phases are not runtime calls or cycle proof. Larger areas need not have more debt.",
    }
