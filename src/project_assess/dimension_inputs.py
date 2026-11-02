"""Route existing deterministic evidence to rubric questions without assigning scores."""

from collections import Counter, defaultdict

from .rubric import DIMENSIONS

_PROVIDERS = {
    "source": (
        ("python", "javascript", "source", "configuration"),
        "Captured source/configuration inventory and locations; syntax support varies by language.",
    ),
    "dependencies": (
        ("manifest", "ecosystem-analysis"),
        "Declared dependencies and narrow ecosystem hints.",
    ),
    "python": (
        ("static-analysis",),
        "Python structure, complexity, imports, reuse and reachability leads.",
    ),
    "javascript": (
        ("javascript-analysis",),
        "JavaScript/TypeScript structure, imports and reuse leads.",
    ),
    "generic": (("source-analysis",), "Language-neutral inventory and exact-text reuse leads."),
    "tests": (
        ("test-value-static-analysis",),
        "Test definitions, setup and implementation-coupling leads.",
    ),
    "documentation": (
        ("documentation-analysis",),
        "Documentation drift, literal command/path and authority relationships, duplication and link/anchor leads; inspect their effect on development and the intended source of truth.",
    ),
    "dead_code": (
        ("static-analysis", "javascript-analysis", "analyzer-analysis"),
        "Native and selected analyzer unused, unreferenced and unreachable-code leads; inspect actual reads, effects, registrations and supported contracts before judging disuse.",
    ),
    "guidance": (
        ("documentation",),
        "Captured guidance for source inspection; semantic correctness is unverified.",
    ),
    "ci": (
        (),
        "Captured CI configuration paths and manifest script names; workflow semantics are unverified.",
    ),
    "diagnostics": (
        ("ruff", "sarif"),
        "Supplied diagnostics; source binding and rule scope need inspection.",
    ),
    "reports": (
        ("junit", "coverage", "test-value"),
        "Supplied test observations; inspect source identity and scenario scope.",
    ),
    "optional": (
        ("analyzer-analysis",),
        "Explicit optional analyzer models and candidates with their own limits.",
    ),
    "controls": (
        ("control-analysis",),
        "Located Python/JS control signals and CI/manifest declarations, with per-file and per-dimension rule coverage.",
    ),
    "observations": (
        ("observation",),
        "Imported workload, recovery, delivery, change-cost, security or compatibility observations; identity matching does not authenticate execution.",
    ),
    "burden": (
        ("burden-analysis", "burden-context"),
        "Required-gate selectors, change-surface leads and attributable experience; inspect scope, recurrence and timing semantics before judging upkeep.",
    ),
}

# Shared providers are intentional. Their presence does not establish a control,
# a dimension's quality, or that an agent inspected the relevant source paths.
_DIMENSION_PROVIDERS = {
    "security": (
        "controls",
        "observations",
        "source",
        "dependencies",
        "ci",
        "diagnostics",
        "optional",
        "guidance",
    ),
    "testing": ("source", "python", "javascript", "tests", "reports", "observations", "ci"),
    "documentation": ("guidance", "documentation", "source", "observations"),
    "maintainability": (
        "source",
        "python",
        "javascript",
        "generic",
        "dependencies",
        "optional",
        "diagnostics",
        "observations",
    ),
    "delivery": ("controls", "observations", "ci", "dependencies", "guidance", "reports", "source"),
    "operability": (
        "controls",
        "observations",
        "source",
        "python",
        "javascript",
        "guidance",
        "diagnostics",
    ),
    "extensibility": (
        "controls",
        "observations",
        "source",
        "python",
        "javascript",
        "dependencies",
        "optional",
        "guidance",
    ),
    "performance": (
        "controls",
        "observations",
        "source",
        "python",
        "javascript",
        "optional",
        "guidance",
    ),
}
_GAPS = {
    "security": [
        "Fixed risky-API, TLS and declaration rules are not full vulnerability, authorization/dataflow or dependency-vulnerability analysis.",
        "Inspect relevant entry points, authority, validation and failure paths; supplied diagnostics cover only their selected rules.",
    ],
    "testing": [
        "Definition/setup sampling may omit tests or helpers; inspect role coverage and analysis limits.",
        "Test counts and definitions do not establish critical-behavior coverage, effectiveness or passing execution.",
    ],
    "documentation": [
        "Link and duplication checks do not establish semantic freshness, usable setup or successful recovery instructions.",
    ],
    "maintainability": [
        "Complexity, reuse and import hints do not establish unnecessary architecture or rigidity; inspect callers, invariants and representative changes.",
    ],
    "delivery": [
        "Workflow gates, pins, permissions and command declarations are syntax facts; expressions, external actions and actual release/rollback effectiveness remain unverified.",
        "Inspect actual workflows and their failure/recovery paths; test reports alone do not establish release safety.",
    ],
    "operability": [
        "Logging, catch/retry, health and recovery signals include unresolved naming hints; inspect ownership, failure handling and runbook applicability.",
        "Source controls do not establish successful diagnosis or recovery in operation.",
    ],
    "extensibility": [
        "Interface/import hints do not establish usable extension points, compatibility or change cost; trace required variants through real callers.",
    ],
    "performance": [
        "I/O-loop, query, paging/batching, timeout, cache and admission hints do not establish bottlenecks or complete dynamic behavior.",
        "Capacity and latency need applicable workload observations; imported observations remain supplied claims even with matching source identity.",
    ],
}


def _compact(value):
    """Retain small scalar coverage facts; large per-file/area rows stay queryable."""
    return {
        key: item
        for key, item in value.items()
        if item is None or isinstance(item, (str, bool, int, float))
    }


def _coverage(value):
    result = _compact(value)
    for key in ("by_role", "roles"):
        if isinstance(value.get(key), dict):
            result[key] = {
                role: _compact(row)
                for role, row in value[key].items()
                if role in {"production", "test", "tooling", "unknown"} and isinstance(row, dict)
            }
    if isinstance(value.get("dimensions"), dict):
        result["dimensions"] = {
            dimension: _compact(row)
            for dimension, row in value["dimensions"].items()
            if dimension in DIMENSIONS and isinstance(row, dict)
        }
    return result


def _analysis_partial(entry):
    stats = entry.get("stats", {})
    if stats.get("status") in {"partial", "unavailable", "unsupported", "not_collected"}:
        return True
    if entry.get("kind") != "documentation-analysis":
        return False
    scope = stats.get("scope", {})
    references = stats.get("referenceEvidence", {}).get("scope", {})
    drift = stats.get("driftEvidence", {}).get("scope", {})
    sections = stats.get("sections", {})
    progress = sections.get("progress", {})
    counts = [
        scope.get("richOmittedDocuments", 0),
        scope.get("maintenanceLeadsOmitted", 0),
        references.get("omittedCallers", 0),
        references.get("commandReferencesOmitted", 0),
        *(row.get("omitted_matches", 0) for row in references.get("referenceCounts", {}).values()),
        drift.get("pathReferencesOmitted", 0),
        drift.get("authorityClaimsOmitted", 0),
        progress.get("passage", {}).get("uncomparedPairs", 0),
        progress.get("section", {}).get("uncomparedPairs", 0),
    ]
    captured, analyzed = scope.get("capturedDocuments"), scope.get("analyzedDocuments")
    return (
        type(captured) is int
        and type(analyzed) is int
        and captured > analyzed
        or any(type(value) is int and value > 0 for value in counts)
        or scope.get("linksTruncated") is True
        or sections.get("windows", {}).get("truncated") is True
        or bool(sections.get("skippedInputs"))
    )


def dimension_inputs(assessment):
    """Describe available inputs and missing analysis, independently of authored grades."""
    by_kind = defaultdict(list)
    for entry in assessment.get("evidence", []):
        by_kind[entry["kind"]].append(entry)
    facts = assessment.get("facts", {})
    ci_paths = set(facts.get("ci", {}).get("paths", []))
    providers = {}
    for name, (kinds, purpose) in _PROVIDERS.items():
        entries = (
            [
                entry
                for entry in assessment.get("evidence", [])
                if entry.get("path") in ci_paths
                or (entry["kind"] == "manifest" and entry.get("stats", {}).get("scripts"))
            ]
            if name == "ci"
            else [entry for kind in kinds for entry in by_kind[kind]]
        )
        entries.sort(key=lambda entry: (entry.get("path", ""), entry["id"]))
        providers[name] = {
            "purpose": purpose,
            "evidence_count": len(entries),
            "evidence_ids": [entry["id"] for entry in entries[:5]],
            "omitted_evidence_ids": max(0, len(entries) - 5),
            "kinds": sorted({entry["kind"] for entry in entries}) if name == "ci" else list(kinds),
            "analysis": [
                {
                    "evidence_id": entry["id"],
                    "status": entry.get("stats", {}).get(
                        "status",
                        "partial"
                        if _analysis_partial(entry)
                        else "collected"
                        if entry["kind"] == "documentation-analysis"
                        else "unestablished",
                    ),
                    "coverage": _coverage(
                        entry.get("stats", {}).get(
                            "coverage", entry.get("stats", {}).get("scope", {})
                        )
                    ),
                }
                for entry in entries
                if entry["kind"].endswith("-analysis")
            ][:5],
        }
        if name in {"documentation", "dead_code"}:
            providers[name]["required_in_deep"] = True
            providers[name]["collection_status"] = (
                "not_collected"
                if not entries
                else "partial"
                if any(_analysis_partial(entry) for entry in entries)
                else "collected"
            )
            providers[name]["gaps"] = list(
                dict.fromkeys(
                    gap for entry in entries for gap in entry.get("stats", {}).get("gaps", [])
                )
            )[:3]
            if not entries:
                providers[name]["gaps"].append(
                    "No supporting analysis was collected; absence of evidence is not a clean result."
                )
        if name == "tests":
            providers[name]["retained_definition_kinds"] = dict(
                sorted(
                    Counter(
                        row.get("kind", "unestablished")
                        for entry in entries
                        for row in entry.get("stats", {}).get("definitions", [])
                    ).items()
                )
            )
            providers[name]["definition_count_basis"] = (
                "Retained static definitions only; not all project tests or passing results."
            )
    providers["ci"]["script_count"] = len(facts.get("manifests", {}).get("scripts", []))
    collection = facts.get("collection", {})
    return {
        "schema_version": 1,
        "collection_scope": {
            key: collection.get(key)
            for key in (
                "discovery_complete",
                "python_source_complete",
                "supported_text_complete",
                "deadline_exceeded",
                "completeness_scope",
                "analysis_profile",
            )
        },
        "providers": providers,
        "dimensions": {
            dimension: {
                "provider_ids": list(
                    dict.fromkeys(
                        [
                            *_DIMENSION_PROVIDERS[dimension],
                            "documentation",
                            "guidance",
                            "dead_code",
                            "burden",
                        ]
                    )
                ),
                "limitations": list(_GAPS[dimension]),
                "control_coverage": facts.get("control_analysis", {})
                .get("coverage", {})
                .get("dimensions", {})
                .get(dimension),
                "burden_coverage": facts.get("burden_analysis", {}).get("coverage", {}),
            }
            for dimension in DIMENSIONS
        },
        "caveat": (
            "This directory routes deterministic inputs and explicitly missing analysis, not scores "
            "or verified review coverage. Empty providers mean no such evidence was collected, not "
            "that the project lacks the practice. Counts cover the captured, post-exclusion scope. "
            "Use paginated evidence queries and source context to inspect the relevant workflows."
        ),
    }
