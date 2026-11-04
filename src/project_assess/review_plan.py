"""Bounded inspection plans assembled from captured evidence, never project grades."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from pathlib import PurePosixPath

from .dimension_inputs import dimension_inputs
from .doc_value.markdown import is_agent_guidance
from .generic_analysis import source_area
from .rubric import DIMENSIONS
from .static_analysis import source_role

VERSION = "4"
MAX_TASKS = 32
_SOURCE_KINDS = {"python", "javascript", "source", "documentation", "configuration", "manifest"}
_BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".mp3",
    ".mp4",
    ".mov",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".zst",
    ".7z",
    ".rar",
    ".jar",
    ".war",
    ".whl",
    ".deb",
    ".rpm",
    ".dmg",
    ".iso",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".wasm",
    ".bin",
    ".wav",
    ".flac",
    ".webm",
    ".mkv",
    ".avi",
    ".bmp",
    ".tif",
    ".tiff",
    ".otf",
    ".eot",
    ".parquet",
    ".sqlite",
    ".onnx",
}
_LOCK_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "uv.lock",
    "poetry.lock",
    "cargo.lock",
    "gemfile.lock",
    "composer.lock",
    "package.resolved",
}
_DEPENDENCY_DIMENSIONS = {"security", "testing", "maintainability", "delivery"}
_DEAD_CODE_KINDS = {"unused_symbol", "unreachable_statement", "unreferenced_module"}
MAX_DIMENSION_REPEATS = 2
_DEEP_QUESTIONS = [
    "Review dead-code leads against actual reads, initializer effects, entry points, callbacks, registries and public contracts; distinguish unreachable code from unresolved or intentional unused bindings.",
    "Compare agent instructions, skills and canonical guidance with current code, manifest commands and their callers. Trace a documented rule or source-of-truth conflict to its development impact in this dimension; do not treat documentation as incidental assets.",
]
_QUESTIONS = {
    "security": [
        "Trace a relevant authority or dependency change through validation, callers, required checks and failure handling.",
        "Identify which coordinated edits preserve a current safety requirement and which duplicate the same rule.",
    ],
    "testing": [
        "Trace a valuable behavior change through setup, selected checks, required completion gates, reuse and reruns.",
        "Inspect distinct failure protection and a favorable focused path before proposing more tests or deletion.",
    ],
    "documentation": [
        "Trace a representative code or configuration change to its authoritative setup, interface and recovery guidance.",
        "Identify actual repeated updates, prose-test coupling and inconsistent commands; distinguish generated guidance from manual upkeep.",
    ],
    "maintainability": [
        "Trace a valuable change across state owners, callers, contracts and required checks; distinguish edits from inspection.",
        "Inspect a simpler existing path and the invariant behind each layer before judging rigidity, duplication or architecture.",
    ],
    "delivery": [
        "Trace a supported change from qualification through release correspondence, failure and rollback.",
        "Inspect exactness, reuse and required manual coordination; declarations do not establish a successful delivery.",
    ],
    "operability": [
        "Trace a representative failure from detection through diagnosis, state ownership, recovery and required manual steps.",
        "Compare runbook instructions with callers, retries, timeouts and cleanup; implemented recovery is not demonstrated recovery.",
    ],
    "extensibility": [
        "Trace an existing relevant variant through its contract, implementation, registration, configuration, tests and guidance.",
        "Identify genuine core edits and compatibility upkeep; compare a simpler existing variant before recommending a framework.",
    ],
    "performance": [
        "Trace an important request or data path through queries, materialization, locks, bounds and caches.",
        "Identify upkeep when changing workload shape or limits; distinguish optimization maintenance from measured capacity or latency.",
        "Before recommending benchmarks, establish a current user need or credible workload risk; existing observations or occasional advisory measurements may suffice.",
        "Inspect timing thresholds against representative variance and useful headroom, required gates, reruns and baseline-edit churn; syntax alone cannot establish flakiness or excessive burden.",
    ],
}
_PATH_HINTS = {
    "security": ("auth", "policy", "permission", "credential", "security"),
    "testing": ("test", "verify", "verification", "fixture", "conftest"),
    "documentation": ("readme", "docs/", "guidance", "setup", "architecture"),
    "maintainability": ("store", "service", "integration", "model", "workflow"),
    "delivery": ("release", "deploy", "build", "verify", ".github/", ".circleci/"),
    "operability": ("recover", "operation", "health", "monitor", "runner", "backup"),
    "extensibility": ("provider", "adapter", "plugin", "contract", "registry", "catalog"),
    "performance": ("cache", "budget", "queue", "query", "performance", "benchmark"),
}


def _validate_dimension(dimension):
    if dimension is not None and dimension not in DIMENSIONS:
        raise ValueError("Unknown review-plan dimension")


def _navigation_penalty(path, role_hint=None):
    parts = PurePosixPath(path.lower()).parts
    archived = bool(parts and parts[0] in {"output", "evals", ".artifacts"})
    archived |= "docs" in parts and bool(
        set(parts) & {"archive", "archives", "history", "plans", "specs", "evidence", "generated"}
    )
    archived |= "tests" in parts and bool(set(parts) & {"fixtures", "evidence"})
    return int(archived or role_hint in {"history", "required_record", "raw_evidence", "generated"})


def _family(kind):
    return next(
        (
            name
            for name in (
                "compatibility",
                "entry_points",
                "interface",
                "registration",
                "dispatch",
                "injected",
                "constructor",
                "cache",
                "pagination",
                "batch",
                "admission",
                "query",
                "io_in_loop",
                "materialization",
                "synchronization",
                "transaction",
                "recovery",
                "health",
                "logging",
                "exception",
                "wait",
                "timer",
                "process",
                "guidance",
                "caller",
                "script",
            )
            if name in kind
        ),
        kind,
    )


def _analysis_dimensions(kind):
    if kind == "documentation-analysis":
        return set(DIMENSIONS)
    if kind == "test-value-static-analysis":
        return {"testing", "maintainability"}
    if kind in {"static-analysis", "javascript-analysis", "source-analysis", "analyzer-analysis"}:
        return set(DIMENSIONS) - {"documentation"}
    return set()


def dimension_coverage(assessment, dimension):
    """Separate missing source from asset-only skips and analysis-specific limits.

    A complete source inventory is not semantic review coverage. Asset skips do
    not prove omitted source, while unknown discovery/capture scope stays open.
    """
    if dimension not in DIMENSIONS:
        raise ValueError("Unknown review-plan dimension")
    collection = assessment.get("facts", {}).get("collection", {})
    material, assets, blockers, notes = [], [], [], []
    skipped = collection.get("skipped_inputs", [])
    for row in skipped:
        item = {key: row[key] for key in ("path", "kind", "reason", "role") if key in row}
        path = row.get("path", "")
        asset = row.get("kind") is None and PurePosixPath(path).suffix.lower() in _BINARY_SUFFIXES
        if asset:
            assets.append(item)
        else:
            dependency_lock = (
                row.get("kind") in {"configuration", "manifest"}
                and PurePosixPath(path).name.lower() in _LOCK_NAMES
            )
            affected = _DEPENDENCY_DIMENSIONS if dependency_lock else set(DIMENSIONS)
            item["affected_dimensions"] = [name for name in DIMENSIONS if name in affected]
            item["relevant"] = dimension in affected
            item["scope_basis"] = (
                "dependency_resolution" if dependency_lock else "source_or_unclassified_input"
            )
            if dependency_lock:
                item["uncertainty"] = (
                    "Dependency resolution and compatibility remain unknown; inspect relevance before extending an unrelated workflow claim to dependency/runtime guarantees."
                )
            material.append(item)
    relevant_omissions = [item for item in material if item["relevant"]]
    if relevant_omissions:
        blockers.append(
            f"{len(relevant_omissions)} supported or unclassified input(s) relevant to {dimension} were not captured; inspect their paths and scope."
        )
    if len(material) > len(relevant_omissions):
        notes.append(
            "Skipped dependency lockfiles restrict dependency/reproducibility claims rather than establishing missing production workflow source; their compatibility and runtime relevance still needs inspection."
        )
    if assets:
        notes.append(
            f"{len(assets)} binary asset(s) were skipped, not supported source; inspect asset content separately if this dimension depends on it."
        )
    if collection.get("discovery_complete") is False or collection.get("unsearched_directories"):
        blockers.append(
            "Discovery left unsearched scope; important source or workflows may be absent."
        )
    declared_skips = collection.get("skipped_files")
    if type(declared_skips) is int and declared_skips > len(skipped):
        blockers.append("Some skipped inputs lack retained paths; their relevance remains unknown.")
    if collection.get("supported_text_complete") is False and not material:
        blockers.append(
            "Supported-text capture is incomplete without enough located omissions to establish this dimension's scope."
        )
    if assessment.get("complete") is False and not skipped and not blockers:
        blockers.append(
            "Collection is partial without located source/asset omission details; assess its materiality."
        )
    if assessment.get("complete") is False and assets and not material:
        if (
            collection.get("discovery_complete") is not True
            or collection.get("supported_text_complete") is not True
        ):
            blockers.append(
                "Asset-only retained skips do not establish complete source capture or discovery; their scope remains unverified."
            )
    if assessment.get("complete") is None and not collection:
        blockers.append("Collection completeness is unestablished.")
    limits = []
    for entry in assessment.get("evidence", []):
        kind, stats = entry.get("kind"), entry.get("stats", {})
        if kind == "control-analysis":
            cover = stats.get("coverage", {}).get("dimensions", {}).get(dimension, {})
            limited = any(
                cover.get(key, 0)
                for key in (
                    "partial_files",
                    "unavailable_files",
                    "unsupported_files",
                    "uncaptured_files",
                    "omitted_signals_lower_bound",
                )
            )
            relevant = bool(cover)
        else:
            relevant = dimension in _analysis_dimensions(kind)
            limited = (
                stats.get("status")
                in {
                    "partial",
                    "unavailable",
                    "unsupported",
                    "not_collected",
                }
                or bool(stats.get("gaps"))
                or stats.get("topology", {}).get("complete") is False
            )
        if relevant and limited:
            limits.append(
                {
                    "evidence_id": entry.get("id"),
                    "kind": kind,
                    "status": stats.get("status", "partial"),
                    "gaps": list(stats.get("gaps", []))[:3],
                }
            )
    if limits:
        notes.append(
            "Analysis limits remain independent of source capture; inspect affected paths manually or retain the specific unsupported claim."
        )
    syntax_gaps = [
        {
            "path": entry["path"],
            "evidence_id": entry["id"],
            "reason": "native_language_analysis_not_present",
        }
        for entry in assessment.get("evidence", [])
        if entry.get("kind") == "source" and isinstance(entry.get("path"), str)
    ]
    if syntax_gaps:
        notes.append(
            "Some captured languages have no native Python/JS syntax analysis; inspect source text and optional analyzer coverage before making structural claims."
        )

    def key(row):
        return row.get("path", ""), row.get("reason", "")

    return {
        "dimension": dimension,
        "status": "unknown"
        if assessment.get("complete") is None and not collection
        else "partial"
        if blockers
        else "complete",
        "collection_blockers": blockers,
        "notes": notes,
        "material_omissions": sorted(material, key=key)[:5],
        "asset_only_omissions": sorted(assets, key=key)[:5],
        "analysis_limits": sorted(
            limits, key=lambda row: (row["kind"], row.get("evidence_id") or "")
        )[:10],
        "syntax_gaps": sorted(syntax_gaps, key=lambda row: row["path"])[:5],
        "omission_counts": {
            "located_source_or_unknown": len(material),
            "relevant_to_dimension": len(relevant_omissions),
            "binary_assets": len(assets),
        },
        "omitted_detail_counts": {
            "material": max(0, len(material) - 5),
            "assets": max(0, len(assets) - 5),
            "analyses": max(0, len(limits) - 10),
            "syntax": max(0, len(syntax_gaps) - 5),
        },
        "caveat": "Capture and syntax scope only; this does not establish reviewed workflow breadth, absence of risk or confidence.",
    }


def _context(assessment):
    entries = sorted(
        assessment.get("evidence", []), key=lambda row: (row.get("path", ""), row["id"])
    )
    sources = {
        row["path"]: row
        for row in entries
        if row.get("kind") in _SOURCE_KINDS and isinstance(row.get("path"), str)
    }
    signals, edges = defaultdict(list), {}
    for entry in entries:
        stats, kind = entry.get("stats", {}), entry.get("kind")
        if kind in {"control-analysis", "burden-analysis", "documentation-analysis"}:
            located = stats.get("signals", []) + stats.get("leads", [])
            if kind == "documentation-analysis":
                located += [
                    {**row, "dimensions": list(DIMENSIONS)}
                    for row in stats.get("maintenanceLeads", [])
                ]
            for signal in located:
                for dimension in signal.get("dimensions", []):
                    if dimension in DIMENSIONS:
                        locations = signal.get("locations") or (
                            [signal] if "path" in signal else []
                        )
                        for location in locations[:8]:
                            source = sources.get(location.get("path"))
                            if source is None:
                                continue
                            identity = location.get(
                                "source_evidence_id", signal.get("source_evidence_id")
                            )
                            digest = location.get("source_digest", signal.get("source_digest"))
                            if (
                                identity is not None
                                and identity != source["id"]
                                or digest is not None
                                and digest != source.get("digest")
                            ):
                                continue
                            signals[dimension].append(
                                (
                                    source["id"],
                                    location,
                                    str(signal.get("kind", "source_signal")),
                                    entry["id"],
                                    signal.get("context", {}).get("binding", "unestablished"),
                                )
                            )
        if kind in {"static-analysis", "javascript-analysis", "analyzer-analysis"}:
            for candidate in stats.get("candidate_index", stats.get("candidates", [])):
                if candidate.get("kind") not in _DEAD_CODE_KINDS:
                    continue
                for location in candidate.get("locations", [])[:8]:
                    source = sources.get(location.get("path"))
                    if source is None:
                        continue
                    identities = candidate.get("source_evidence_ids", [])
                    digest = candidate.get("metrics", {}).get("source_digest")
                    if (
                        identities
                        and source["id"] not in identities
                        or (digest is not None and digest != source.get("digest"))
                    ):
                        continue
                    signals["dead_code"].append(
                        (
                            source["id"],
                            location,
                            candidate["kind"],
                            entry["id"],
                            "review_lead_not_disuse_proof",
                        )
                    )
        if kind in {"static-analysis", "javascript-analysis"}:
            for edge in stats.get("topology", {}).get("edges", []):
                if edge.get("source") not in sources or edge.get("target") not in sources:
                    continue
                if type(edge.get("line")) is not int or edge["line"] < 1:
                    continue
                row = {
                    "source": edge["source"],
                    "target": edge["target"],
                    "line": edge["line"],
                    "phase": edge.get("phase", "unestablished"),
                    "analysis_evidence_id": entry["id"],
                    "source_evidence_id": sources[edge["source"]]["id"],
                    "target_evidence_id": sources[edge["target"]]["id"],
                    "relationship": "captured_import",
                }
                edges[(row["source"], row["target"], row["line"], row["phase"], entry["id"])] = row
    return sources, signals, [edges[key] for key in sorted(edges)]


def _history_context(assessment, selected_paths, sources):
    """Keep selected-path history observations separate from import relationships."""
    contexts = []
    revision = assessment.get("source", {}).get("revision")
    for entry in sorted(assessment.get("evidence", []), key=lambda row: row["id"]):
        if entry.get("kind") != "change-history" or len(contexts) == 2:
            continue
        stats, pairs, commits = entry.get("stats", {}), [], []
        matched = bool(
            revision
            and stats.get("source_revision") == revision
            and stats.get("head_observed") == revision
        )
        if matched:
            for group in stats.get("cochanges", []):
                paths = group.get("paths", [])
                if (
                    not paths
                    or any(path not in sources for path in paths)
                    or not selected_paths.intersection(paths)
                ):
                    continue
                if type(group.get("commits")) is not int or group["commits"] < 1:
                    continue
                pairs.append(
                    {
                        "paths": list(paths),
                        "commits": group["commits"],
                        "source_evidence_ids": [sources[path]["id"] for path in paths],
                        "relationship": "historical_cochange",
                        "binding": "current_captured_path_names",
                    }
                )
            for commit in stats.get("commits", []):
                paths = commit.get("paths", [])
                if commit.get("boundary_omitted") or not selected_paths.intersection(paths):
                    continue
                known = [path for path in paths if path in sources]
                commits.append(
                    {
                        "revision": commit.get("revision"),
                        "committed_at": commit.get("committed_at"),
                        "paths": known[:8],
                        "omitted_context_paths": max(0, len(known) - 8),
                        "uncaptured_paths": commit.get("uncaptured_paths"),
                        "omitted_paths": commit.get("omitted_paths"),
                    }
                )
        gaps = list(stats.get("gaps", []))[:4]
        if not matched:
            gaps.append(
                "History applicability to the captured source revision is unestablished; no co-change groups are used."
            )
        if not pairs and not commits and not gaps:
            continue
        contexts.append(
            {
                "evidence_id": entry["id"],
                "status": stats.get("status", "unestablished"),
                "source_revision": stats.get("source_revision"),
                "head_observed": stats.get("head_observed"),
                "coverage": {
                    key: stats.get("coverage", {}).get(key)
                    for key in (
                        "selection",
                        "commit_limit",
                        "commits_retained",
                        "shallow",
                        "boundary_commits_omitted",
                        "uncaptured_path_occurrences",
                        "retention_path_omissions",
                    )
                },
                "cochanges": pairs[:4],
                "omitted_cochange_groups": max(0, len(pairs) - 4),
                "matching_commits": commits[:3],
                "omitted_matching_commits": max(0, len(commits) - 3),
                "gaps": gaps,
                "caveat": "Observed local historical path co-change, not mandatory edits, effort, elapsed time or representative change frequency. Commit dates are not workflow execution times; historical file contents were not inspected.",
            }
        )
    return contexts


def build_review_plan(assessment, review=None, *, dimension=None, limit=None):
    """Plan bounded follow-up using existing facts; the host performs the review."""
    _validate_dimension(dimension)
    profile = assessment.get("facts", {}).get("collection", {}).get("analysis_profile", "standard")
    if limit is None:
        limit = 16 if profile == "deep" else 8
    if type(limit) is not int or not 1 <= limit <= MAX_TASKS:
        raise ValueError("Review-plan limit must be between 1 and 32")
    review = review or {}
    sources, signals, edges = _context(assessment)
    by_id = {entry["id"]: entry for entry in sources.values()}
    documentation_ids = {
        entry["id"]
        for entry in assessment.get("evidence", [])
        if entry.get("kind") == "documentation-analysis"
    }
    doc_roles = {
        row["path"]: row.get("roleHint")
        for entry in assessment.get("evidence", [])
        if entry.get("kind") == "documentation-analysis"
        for row in entry.get("stats", {}).get("documents", [])
    }
    inputs = dimension_inputs(assessment)
    packs = {}
    # Dimensions choose in order, so a file already routed elsewhere yields to fresh source.
    routed = Counter()
    for name in [dimension] if dimension else DIMENSIONS:
        candidates = {}

        def add(entry, reason, location=None, signal_kind=None, *, candidates=candidates):
            identity = entry["id"]
            task = candidates.setdefault(
                identity,
                {
                    "evidence_id": identity,
                    "path": entry["path"],
                    "digest": entry.get("digest"),
                    "kind": entry["kind"],
                    "role": entry.get("stats", {}).get("role")
                    or source_role(entry["path"])["role"],
                    "area": source_area(entry["path"]),
                    "line": 1,
                    "end_line": min(30, entry.get("lines", 30) or 30),
                    "selection_reasons": [],
                    "signal_kinds": [],
                    "strength": "inventory_seed",
                    "source_identity": "captured_snapshot",
                    "operation": "source_context",
                },
            )
            if reason not in task["selection_reasons"]:
                task["selection_reasons"].append(reason)
            if (
                location
                and type(location.get("line")) is int
                and location["line"] > 0
                and task["strength"] == "inventory_seed"
            ):
                task["line"] = location["line"]
                task["end_line"] = min(
                    max(location.get("end_line", task["line"]), task["line"]), task["line"] + 39
                )
                task["strength"] = "located_signal"
            if (
                signal_kind
                and signal_kind not in task["signal_kinds"]
                and len(task["signal_kinds"]) < 6
            ):
                task["signal_kinds"].append(signal_kind)
            return task

        for entry in sources.values():
            if entry.get("stats", {}).get("generated_hint") or entry.get("stats", {}).get(
                "vendor_hint"
            ):
                continue
            add(entry, "captured_context")
            if profile == "deep" and is_agent_guidance(entry["path"]):
                add(entry, "agent_guidance")
            if any(hint in entry["path"].lower() for hint in _PATH_HINTS[name]):
                add(entry, "filename_navigation_hint")
        for identity, location, kind, analysis_id, binding in sorted(
            signals[name] + (signals["dead_code"] if profile == "deep" else []),
            key=lambda row: (by_id[row[0]]["path"], row[1].get("line", 1), row[2]),
        ):
            task = add(by_id[identity], "dimension_signal", location, kind)
            if kind in _DEAD_CODE_KINDS:
                add(by_id[identity], "dead_code_candidate")
            elif analysis_id in documentation_ids:
                add(by_id[identity], "documentation_drift")
            task.setdefault("analysis_evidence_ids", [])
            if analysis_id not in task["analysis_evidence_ids"]:
                task["analysis_evidence_ids"].append(analysis_id)
            task.setdefault("binding_states", [])
            if binding not in task["binding_states"]:
                task["binding_states"].append(binding)
            task.setdefault("mechanism_families", [])
            if _family(kind) not in task["mechanism_families"]:
                task["mechanism_families"].append(_family(kind))
        rating = review.get("ratings", {}).get(name, {})
        for identity in rating.get("evidence_ids", []):
            if identity in by_id:
                add(by_id[identity], "authored_rating_citation")
        relevant_paths = {
            task["path"]
            for task in candidates.values()
            if any(
                reason in task["selection_reasons"]
                for reason in (
                    "dimension_signal",
                    "filename_navigation_hint",
                    "authored_rating_citation",
                )
            )
        }
        for edge in edges:
            if edge["source"] not in relevant_paths and edge["target"] not in relevant_paths:
                continue
            for path in (edge["source"], edge["target"]):
                task = add(sources[path], "captured_import_neighbor")
                if task["strength"] == "inventory_seed":
                    task["strength"] = "captured_import_context"

        def saturated(task, *, name=name):
            """Shared guidance or configuration stops recurring unless this dimension cites it."""
            return (
                name != "documentation"
                and task["kind"] in {"documentation", "configuration", "manifest"}
                and routed[task["evidence_id"]] >= MAX_DIMENSION_REPEATS
                and not {"dimension_signal", "authored_rating_citation"}
                & set(task["selection_reasons"])
            )

        def rank(task, *, name=name):
            reasons = task["selection_reasons"]
            direct = any(kind.startswith(name + ".") for kind in task["signal_kinds"])
            tier = (
                0
                if direct or name == "documentation" and "dimension_signal" in reasons
                else 1
                if "dimension_signal" in reasons
                else 2
                if any(
                    reason in reasons
                    for reason in ("filename_navigation_hint", "authored_rating_citation")
                )
                else 3
                if "captured_import_neighbor" in reasons
                else 4
            )
            canonical = PurePosixPath(task["path"]).stem.lower() in {
                "readme",
                "agents",
                "claude",
                "contributing",
                "architecture",
                "development",
                "operations",
                "setup",
                "installation",
                "recovery",
                "runbook",
                *DIMENSIONS,
            }
            return (
                _navigation_penalty(task["path"], doc_roles.get(task["path"])),
                saturated(task),
                task["kind"] in {"python", "javascript", "source"} and task["role"] == "unknown",
                not (profile == "deep" and is_agent_guidance(task["path"])),
                not canonical if task["kind"] == "documentation" else False,
                task["role"] == "tooling" and task["kind"] != "documentation",
                task["kind"] == "configuration",
                tier,
                -sum(hint in task["path"].lower() for hint in _PATH_HINTS[name]),
                len(PurePosixPath(task["path"]).parts) if task["kind"] == "documentation" else 0,
                -(by_id[task["evidence_id"]].get("lines") or 0),
                task["path"],
                task["evidence_id"],
            )

        queues = defaultdict(deque)
        for task in sorted(candidates.values(), key=rank):
            if saturated(task):
                continue
            category = (
                "guidance"
                if task["kind"] == "documentation"
                else "configuration"
                if task["kind"] in {"manifest", "configuration"}
                else "test"
                if task["role"] == "test"
                else "production"
            )
            queues[(category, task["area"])].append(task)
        order = sorted(queues, key=lambda key: (rank(queues[key][0]), key))
        chosen = {}
        for category in (
            ("guidance", "production", "configuration", "test")
            if name == "documentation"
            else ("production", "guidance", "configuration", "test")
        ):
            matches = [key for key in order if key[0] == category]
            if matches and len(chosen) < limit:
                task = queues[matches[0]].popleft()
                chosen[task["evidence_id"]] = task
        if profile == "deep":
            for reason in ("agent_guidance", "dead_code_candidate", "documentation_drift"):
                task = next(
                    (
                        task
                        for task in sorted(candidates.values(), key=rank)
                        if reason in task["selection_reasons"]
                    ),
                    None,
                )
                if task and len(chosen) < limit:
                    chosen[task["evidence_id"]] = task
        if name == "documentation":
            guidance = [
                task
                for task in sorted(candidates.values(), key=rank)
                if task["kind"] == "documentation"
                and not _navigation_penalty(task["path"], doc_roles.get(task["path"]))
            ]
            for task in guidance[: max(1, limit // 3)]:
                if len(chosen) < limit:
                    chosen[task["evidence_id"]] = task
        production = [
            task
            for task in sorted(candidates.values(), key=rank)
            if task["kind"] in {"python", "javascript", "source"}
            and task["role"] not in {"test", "tooling"}
            and not _navigation_penalty(task["path"])
        ]
        # A qualification or sample file whose name matches a hint must not lead the
        # dimension when classified production source exists.
        production = [task for task in production if task["role"] == "production"] or production
        named = sorted(
            (
                task
                for task in production
                if "filename_navigation_hint" in task["selection_reasons"]
            ),
            key=lambda task: (
                -sum(hint in task["path"].lower() for hint in _PATH_HINTS[name]),
                rank(task),
            ),
        )
        if named and len(chosen) < limit:
            chosen[named[0]["evidence_id"]] = named[0]
        families = sorted(
            {family for task in production for family in task.get("mechanism_families", [])}
        )
        for family in families[: max(1, limit // 2)]:
            task = next(
                (
                    task
                    for task in production
                    if family in task.get("mechanism_families", [])
                    and task["evidence_id"] not in chosen
                ),
                None,
            )
            if task and len(chosen) < limit:
                chosen[task["evidence_id"]] = task
        while len(chosen) < limit and any(queues.values()):
            for key in order:
                if queues[key] and len(chosen) < limit:
                    task = queues[key].popleft()
                    chosen[task["evidence_id"]] = task
        for task in sorted(candidates.values(), key=rank):
            # With nothing better to route, shared context is still worth reading.
            if saturated(task) and len(chosen) < limit:
                chosen[task["evidence_id"]] = task
        routed.update(chosen.keys())
        selected_paths = {task["path"] for task in chosen.values()}
        connections = [
            edge
            for edge in edges
            if edge["source"] in selected_paths or edge["target"] in selected_paths
        ]
        providers = inputs["dimensions"][name]["provider_ids"]
        history = _history_context(assessment, selected_paths, sources)
        history_ids = {entry["evidence_id"] for entry in history}
        evidence_ids = sorted(history_ids) + sorted(
            {
                identity
                for provider in providers
                for identity in inputs["providers"][provider]["evidence_ids"]
            }
            - history_ids
        )
        status = (
            review.get("coverage", {})
            .get("dimension_reviews", {})
            .get(name, {})
            .get("status", "unreviewed")
        )
        follow_up = [
            {
                "operation": "evidence_query",
                "view": "controls"
                if name in {"security", "delivery", "operability", "extensibility", "performance"}
                else "burden",
                "dimension": name,
                "reason": "Inspect complementary and contrary signals, including retained-detail omissions.",
            }
        ]
        follow_up += [
            {
                "operation": "source_context",
                "evidence_id": task["evidence_id"],
                "line": task["line"],
                "reason": "Inspect current captured bytes, callers and protected outcomes; do not infer required edits from navigation.",
            }
            for task in list(chosen.values())[:3]
        ]
        packs[name] = {
            "dimension": name,
            "status": "inspection_required" if chosen else "missing_source",
            "questions": _QUESTIONS[name]
            + (_DEEP_QUESTIONS if profile == "deep" else [])
            + [
                "What favorable path or contrary evidence changes the estimate, and what important scope remains unexamined?"
            ],
            "source_tasks": list(chosen.values()),
            "connections": connections[:limit],
            "history_context": history,
            "selection": {
                "available_source_records": len(candidates),
                "selected_source_records": len(chosen),
                "omitted_source_records": len(candidates) - len(chosen),
                "related_import_edges": len(connections),
                "omitted_import_edges": max(0, len(connections) - limit),
                "method": "dimension_mechanism_families_then_role_and_area_rounds",
            },
            "provider_evidence_ids": evidence_ids[:20],
            "omitted_provider_evidence_ids": max(0, len(evidence_ids) - 20),
            "coverage": dimension_coverage(assessment, name),
            "review_status": status,
            "needs_follow_up": status != "reviewed"
            or any(rating.get(key) in {None, "low"} for key in ("confidence", "burden_confidence")),
            "follow_up": follow_up,
        }
        if profile == "deep":
            packs[name]["required_checks"] = [
                {
                    "topic": topic,
                    "status": inputs["providers"][provider]["collection_status"],
                    "evidence_ids": inputs["providers"][provider]["evidence_ids"],
                    "gaps": inputs["providers"][provider]["gaps"],
                    "operation": "evidence_query",
                    "view": "candidates" if provider == "dead_code" else "index",
                    "kind": None if provider == "dead_code" else "documentation-analysis",
                    "interpretation": "Required review input; collected evidence is not verified disuse, freshness, development impact or a score.",
                }
                for topic, provider in (
                    ("dead_code", "dead_code"),
                    ("documentation_drift", "documentation"),
                )
            ]
    return {
        "schema_version": 1,
        "version": VERSION,
        "assessment_id": assessment.get("id"),
        "source_digest": assessment.get("source", {}).get("manifest_digest"),
        "analysis_profile": profile,
        "dimensions": packs,
        "limits": {
            "source_tasks_per_dimension": limit,
            "connections_per_dimension": limit,
            "selection_is_not_exhaustive": True,
        },
        "caveat": "Deterministic inspection navigation, not authored change traces, reviewed coverage, scores or confidence. Located syntax and captured imports need caller/invariant review; unselected paths remain queryable. No target code or configuration was executed.",
    }
