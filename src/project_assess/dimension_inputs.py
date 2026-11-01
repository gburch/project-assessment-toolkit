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
        "Documentation duplication and local link/anchor checks.",
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
}

# Shared providers are intentional. Their presence does not establish a control,
# a dimension's quality, or that an agent inspected the relevant source paths.
_DIMENSION_PROVIDERS = {
    "security": ("source", "dependencies", "ci", "diagnostics", "optional", "guidance"),
    "testing": ("source", "python", "javascript", "tests", "reports", "ci"),
    "documentation": ("guidance", "documentation", "source"),
    "maintainability": (
        "source",
        "python",
        "javascript",
        "generic",
        "dependencies",
        "optional",
        "diagnostics",
    ),
    "delivery": ("ci", "dependencies", "guidance", "reports", "source"),
    "operability": ("source", "python", "javascript", "guidance", "diagnostics"),
    "extensibility": ("source", "python", "javascript", "dependencies", "optional", "guidance"),
    "performance": ("source", "python", "javascript", "optional", "guidance"),
}
_GAPS = {
    "security": [
        "No built-in vulnerability or authorization-boundary analysis; dependency declarations and redaction do not establish security.",
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
        "CI/script inventory has no dedicated gate, release-provenance or rollback-control analysis.",
        "Inspect actual workflows and their failure/recovery paths; test reports alone do not establish release safety.",
    ],
    "operability": [
        "No dedicated health, telemetry, retry/checkpoint or recovery-control inventory; these require source and runbook inspection.",
        "Source controls do not establish successful diagnosis or recovery in operation.",
    ],
    "extensibility": [
        "Interface/import hints do not establish usable extension points, compatibility or change cost; trace required variants through real callers.",
    ],
    "performance": [
        "Shared structure and narrow Python loop-I/O leads do not inventory all query, pagination, batching, backpressure or contention controls.",
        "Capacity and latency remain unknown without applicable workload observations; no generic benchmark-report importer is available.",
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
    return result


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
                    "status": entry.get("stats", {}).get("status", "unestablished"),
                    "coverage": _coverage(entry.get("stats", {}).get("coverage", {})),
                }
                for entry in entries
                if entry["kind"].endswith("-analysis")
            ][:5],
        }
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
            )
        },
        "providers": providers,
        "dimensions": {
            dimension: {
                "provider_ids": list(_DIMENSION_PROVIDERS[dimension]),
                "limitations": list(_GAPS[dimension]),
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
