"""A bounded path-based orientation map, not semantic domains or a risk ranking."""

from collections import Counter, defaultdict
from pathlib import PurePosixPath

from .generic_analysis import source_language
from .static_analysis import source_role

MAX_AREAS = 20
MAX_DEPENDENCIES = 20
MAX_CITATIONS = 5


def _area(path):
    directories = PurePosixPath(path).parts[:-1]
    start = next((i + 1 for i, part in enumerate(directories) if part in {"src", "lib"}), 0)
    return "/".join(directories[: start + min(2, len(directories) - start)]) or "(root)"


def _number(value):
    return value if type(value) is int and value >= 0 else None


def get_system_map(assessment):
    """Summarize captured production paths and native imports without reading source."""
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
        area = _area(path)
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
        "areas": sorted(areas.values(), key=lambda row: (-row["files"], row["path"]))[:MAX_AREAS],
        "omitted_areas": max(0, len(areas) - MAX_AREAS),
        "cross_area_dependencies": sorted(
            dependencies.values(),
            key=lambda row: (-row["import_edges"], row["source_area"], row["target_area"]),
        )[:MAX_DEPENDENCIES],
        "omitted_cross_area_dependencies": max(0, len(dependencies) - MAX_DEPENDENCIES),
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
            "areas": MAX_AREAS,
            "dependencies": MAX_DEPENDENCIES,
            "citations_per_group": MAX_CITATIONS,
        },
        "caveat": "Path/role heuristics are orientation, not semantic domains, debt, grades or priority. Counts cover captured records; partial module counts can be lower bounds and unknown function counts remain unknown. Native static import phases are not runtime calls or cycle proof. Larger areas need not have more debt.",
    }
