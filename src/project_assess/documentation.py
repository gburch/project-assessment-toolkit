"""Documentation leads derived only from bytes captured by the source collector."""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections import Counter, defaultdict, deque
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from .doc_value.markdown import (
    UNSUPPORTED_LINK_RE,
    documentation_role,
    headings,
    is_agent_guidance,
    local_links,
    without_fences,
    words,
)
from .doc_value.sections import analyze_sections
from .static_analysis import source_role

SCHEMA = "doc-value.captured.v2"
MAX_DOCUMENTS = 2000
MAX_LINKS = 2000
MAX_REFERENCES = 1000
MAX_COMMAND_REFERENCES = 200
MAX_AUTHORITY_CLAIMS = 100
MAX_MAINTENANCE_LEADS = 200
DRIFT_VERSION = "1"
_PATH_REFERENCE = re.compile(
    r"(?<![\w/.-])(?:[\w.-]+/)*[\w.-]+\.(?:md|mdx|mdc|rst|adoc|py|js|jsx|ts|tsx|java|swift|go|rs|sh|json|toml|ya?ml|ini|cfg)(?![\w/.-])",
    re.I,
)
_SCRIPT_COMMAND = re.compile(
    r"^(?:\$\s*)?(?:npm|pnpm)(?:\s+--prefix\s+(?P<prefix>[\w./-]+))?\s+run\s+(?P<script>[\w:-]+)(?:\s|$)"
)
_AUTHORITY_SUBJECT = re.compile(
    r"\b(?:source of truth for|authoritative source for|canonical)\s+"
    r"(?P<subject>[\w][\w /-]{0,59})\s*:\s*`?(?P<target>[^`\s]+)",
    re.I,
)


def _document_priority(path):
    name = PurePosixPath(path)
    rank = (
        0
        if is_agent_guidance(path)
        else 1
        if name.parent == PurePosixPath(".")
        and name.name.casefold()
        in {"readme", "readme.md", "readme.mdx", "readme.rst", "readme.adoc"}
        else 2
    )
    return (rank, path)


def _path_check(path, raw, captured, inventory):
    targets = {raw, posixpath.normpath(posixpath.join(posixpath.dirname(path), raw))}
    targets = {
        target
        for target in targets
        if not target.startswith("/") and target != ".." and not target.startswith("../")
    }
    matches = sorted(targets.intersection(captured))
    if matches:
        status = "captured" if len(matches) == 1 else "ambiguous_captured_target"
    elif inventory is not None and (matches := sorted(targets.intersection(inventory))):
        status = "present_not_captured" if len(matches) == 1 else "ambiguous_inventory_target"
    else:
        matches = sorted(targets)
        status = (
            "outside_scope"
            if not targets
            else "not_in_inspected_inventory"
            if inventory is not None
            else "not_in_captured_snapshot"
        )
    return {"reference": raw, "status": status, "targets": matches}


def _role(path, text):
    """Use the standalone audit's pure lexical role hints, never its file walker."""
    hint, reasons = documentation_role(PurePosixPath(path), text, PurePosixPath("."))
    generated = re.search(
        r"(?im)^.{0,12}(?:automatically generated|generated file|this file is generated)\b",
        text[:2000],
    )
    if generated:
        return "generated", [*reasons, "opening text resembles generated output"]
    return hint, reasons


def _rich_inputs(texts, *, byte_limit):
    roles = {path: _role(path, text) for path, text in texts.items()}
    order = {
        "guidance": 0,
        "unknown": 1,
        "required_record": 2,
        "history": 3,
        "raw_evidence": 4,
        "generated": 5,
    }
    selected, omitted, used = {}, [], 0
    for path in sorted(
        texts, key=lambda p: (_document_priority(p)[0], order.get(roles[p][0], 1), p)
    ):
        size = len(texts[path].encode("utf-8"))
        if used + size > byte_limit:
            omitted.append(path)
        else:
            selected[path] = texts[path]
            used += size
    return selected, roles, omitted


def _maintenance_sample(leads):
    groups = defaultdict(deque)
    for lead in sorted(
        leads,
        key=lambda lead: (
            not any(is_agent_guidance(location["path"]) for location in lead["locations"])
        ),
    ):
        groups[lead["kind"]].append(lead)
    selected = []
    while len(selected) < MAX_MAINTENANCE_LEADS and any(groups.values()):
        for kind in sorted(groups):
            if groups[kind] and len(selected) < MAX_MAINTENANCE_LEADS:
                selected.append(groups[kind].popleft())
    return selected


def maintenance_candidates(entry, sources):
    """Project retained lexical leads with captured identities, never confirmed drift."""
    stats = entry.get("stats", {})
    if stats.get("schema") != SCHEMA or not isinstance(stats.get("maintenanceLeads"), list):
        return {
            "status": "not_collected",
            "candidates": [],
            "omitted": 0,
            "gaps": ["Documentation maintenance leads are unavailable for this captured schema."],
        }
    leads = stats["maintenanceLeads"]
    candidates, omitted = [], max(0, len(leads) - MAX_MAINTENANCE_LEADS)
    for lead in leads[:MAX_MAINTENANCE_LEADS]:
        if not isinstance(lead, dict) or not isinstance(lead.get("kind"), str):
            omitted += 1
            continue
        locations = []
        if isinstance(lead.get("locations"), list):
            for location in lead["locations"]:
                source = sources.get(location.get("path")) if isinstance(location, dict) else None
                if (
                    source is None
                    or source.get("kind")
                    not in {
                        "python",
                        "javascript",
                        "source",
                        "documentation",
                        "configuration",
                        "manifest",
                    }
                    or type(location.get("line")) is not int
                    or location["line"] < 1
                    or not isinstance(source.get("digest"), str)
                    or type(location.get("end_line", location["line"])) is not int
                    or location.get("end_line", location["line"]) < location["line"]
                    or location.get("source_evidence_id", source["id"]) != source["id"]
                    or location.get("source_digest", source.get("digest")) != source.get("digest")
                ):
                    break
                locations.append(
                    {
                        **location,
                        "source_evidence_id": source["id"],
                        "source_digest": source.get("digest"),
                    }
                )
        if not locations or len(locations) != len(lead.get("locations", [])):
            omitted += 1
            continue
        candidates.append(
            {
                **lead,
                "locations": locations,
                "lens": "reuse" if lead.get("kind") == "repeated_guidance_passage" else "quality",
                "confidence": "low",
                "source_identity": "captured_snapshot",
                "source_evidence_ids": sorted(
                    {location["source_evidence_id"] for location in locations}
                ),
            }
        )
    return {
        "status": "partial" if omitted else "complete",
        "candidates": candidates,
        "omitted": omitted,
        "gaps": [
            "Some documentation leads lack compatible captured locations or exceed the projection limit."
        ]
        if omitted
        else [],
    }


def _reference_evidence(
    texts, manifest_paths, sources, scripts, *, byte_limit, inventory_paths=None
):
    """Literal relationships only; never infer command execution or required edits."""
    references, commands, authority, gaps = [], [], [], []
    reference_groups = defaultdict(deque)
    reference_observed = Counter()
    seen_references = set()
    reference_dropped = False
    captured = set(manifest_paths)
    packages = {
        path: set(names)
        for path, names in scripts.items()
        if PurePosixPath(path).name == "package.json" and path in captured
    }
    by_target = defaultdict(list)
    examined_bytes = examined_files = 0
    omitted_callers = []
    path_checks, path_observed, authority_claims, authority_observed = [], 0, [], 0
    commands_observed = 0
    inventory = set(inventory_paths) if inventory_paths is not None else None
    seen_paths = set()

    def add(row):
        nonlocal reference_dropped
        reference_observed[row["kind"]] += 1
        signature = (row["kind"], row["path"], row["line"], row["target"])
        if signature in seen_references:
            return
        bucket = reference_groups[row["kind"]]
        if len(bucket) < MAX_REFERENCES:
            seen_references.add(signature)
            bucket.append(row)
        else:
            reference_dropped = True

    for path in sorted(texts, key=_document_priority):
        text = texts[path]
        for line, content in enumerate(text.splitlines(), 1):
            if len(authority) < 100 and re.search(
                r"\b(?:canonical|source of truth|authoritative|generated from)\b", content, re.I
            ):
                authority.append(
                    {
                        "path": path,
                        "line": line,
                        "text": content.strip()[:240],
                        "basis": "declared authority hint, not verified authority",
                    }
                )
            for match in _PATH_REFERENCE.finditer(content):
                raw = match.group()
                signature = (path, line, raw)
                # URL/variable fragments are not literal local file assertions.
                token = content[max(0, match.start() - 200) : match.end()].rsplit(maxsplit=1)[-1]
                if signature not in seen_paths and not any(
                    marker in token for marker in ("://", "${", "{{", "*", "<")
                ):
                    seen_paths.add(signature)
                    path_observed += 1
                    if len(path_checks) < MAX_REFERENCES:
                        path_checks.append(
                            {
                                "path": path,
                                "line": line,
                                **_path_check(path, raw, captured, inventory),
                                "agentGuidance": is_agent_guidance(path),
                                "basis": "literal path compared with captured and supplied inspected inventory; exclusions and physical existence remain unverified",
                            }
                        )
                targets = {raw, posixpath.normpath(posixpath.join(posixpath.dirname(path), raw))}
                for target in sorted(targets.intersection(captured)):
                    if target == path:
                        continue
                    row = {
                        "kind": "documented_path_reference",
                        "path": path,
                        "line": line,
                        "target": target,
                        "basis": "literal captured path mention; relationship needs review",
                    }
                    add(row)
                    if PurePosixPath(target).suffix.lower() not in {
                        ".md",
                        ".mdx",
                        ".mdc",
                        ".rst",
                        ".adoc",
                    }:
                        by_target[target].append(row)
            claim = _AUTHORITY_SUBJECT.search(content)
            if claim and _PATH_REFERENCE.fullmatch(claim.group("target")):
                authority_observed += 1
                if len(authority_claims) < MAX_AUTHORITY_CLAIMS:
                    check = _path_check(path, claim.group("target"), captured, inventory)
                    authority_claims.append(
                        {
                            "path": path,
                            "line": line,
                            "subject": " ".join(claim.group("subject").casefold().split()),
                            **check,
                            "basis": "explicit lexical authority subject/target declaration; precedence and applicability need review",
                        }
                    )
            candidates = [content.strip().strip("`"), *re.findall(r"`([^`\n]+)`", content)]
            for candidate in dict.fromkeys(candidates):
                command = _SCRIPT_COMMAND.match(candidate)
                if not command:
                    continue
                commands_observed += 1
                if len(commands) >= MAX_COMMAND_REFERENCES:
                    continue
                prefix = command.group("prefix")
                target = (
                    posixpath.normpath(posixpath.join(prefix, "package.json"))
                    if prefix
                    else next(iter(packages), None)
                    if len(packages) == 1
                    else None
                )
                # A shell's working directory is not established by a document path.
                if not prefix and re.search(r"(?m)^\s*(?:\$\s*)?cd\s+", text):
                    target = None
                declared = packages.get(target)
                commands.append(
                    {
                        "path": path,
                        "line": line,
                        "script": command.group("script"),
                        "manifest": target if declared is not None else None,
                        "status": "declared"
                        if declared is not None and command.group("script") in declared
                        else "not_declared_in_captured_manifest"
                        if declared is not None
                        else "scope_unresolved",
                        "basis": "literal documented command compared with captured manifest script names; working directory, intent and execution remain unverified",
                    }
                )
    doc_paths = set(texts)
    groups = defaultdict(lambda: defaultdict(deque))
    for path in sorted(sources):
        role = source_role(path)["role"]
        area = "/".join(PurePosixPath(path).parent.parts[:3]) or "."
        groups[role][area].append(path)
    areas = {role: deque(sorted(values)) for role, values in groups.items()}
    caller_order = []
    while any(areas.values()):
        for role in sorted(areas):
            if not areas[role]:
                continue
            area = areas[role].popleft()
            caller_order.append(groups[role][area].popleft())
            if groups[role][area]:
                areas[role].append(area)
    for path in caller_order:
        text = sources[path]
        size = len(text.encode("utf-8"))
        if examined_bytes + size > byte_limit:
            omitted_callers.append(path)
            continue
        examined_bytes += size
        examined_files += 1
        for line, content in enumerate(text.splitlines(), 1):
            for match in _PATH_REFERENCE.finditer(content):
                target = match.group()
                if target in doc_paths:
                    add(
                        {
                            "kind": "literal_document_caller",
                            "path": path,
                            "line": line,
                            "target": target,
                            "basis": "exact documentation path in captured source; not an executed caller or mandatory edit",
                        }
                    )
    if omitted_callers:
        gaps.append("Documentation caller byte limit reached; omitted callers remain unknown")
    while len(references) < MAX_REFERENCES and any(reference_groups.values()):
        for kind in sorted(reference_groups):
            if reference_groups[kind] and len(references) < MAX_REFERENCES:
                references.append(reference_groups[kind].popleft())
    retained = Counter(row["kind"] for row in references)
    counts = {
        kind: {
            "observed_matches": count,
            "retained_locations": retained[kind],
            "omitted_matches": count - retained[kind],
        }
        for kind, count in sorted(reference_observed.items())
    }
    if reference_dropped or any(reference_groups.values()):
        gaps.append("Documentation literal-reference limit reached")
    if path_observed > len(path_checks):
        gaps.append("Documentation drift path-reference limit reached")
    if authority_observed > len(authority_claims):
        gaps.append("Documentation explicit-authority claim limit reached")
    if commands_observed > len(commands):
        gaps.append("Documentation command-reference limit reached")
    claims_by_subject = defaultdict(list)
    for claim in authority_claims:
        if claim["status"] in {"captured", "present_not_captured"}:
            claims_by_subject[claim["subject"]].append(claim)
    conflicts = [
        {
            "subject": subject,
            "claims": claims,
            "basis": "same literal subject names different known targets; scopes, intent and precedence may differ",
        }
        for subject, claims in sorted(claims_by_subject.items())
        if len({claim["targets"][0] for claim in claims}) > 1
    ]
    return {
        "references": references,
        "commands": commands,
        "authorityHints": authority,
        "driftEvidence": {
            "version": DRIFT_VERSION,
            "pathChecks": path_checks,
            "authorityClaims": authority_claims,
            "authorityConflicts": conflicts,
            "scope": {
                "pathReferencesObserved": path_observed,
                "pathReferencesRetained": len(path_checks),
                "pathReferencesOmitted": path_observed - len(path_checks),
                "authorityClaimsObserved": authority_observed,
                "authorityClaimsRetained": len(authority_claims),
                "authorityClaimsOmitted": authority_observed - len(authority_claims),
                "pathReferenceLimit": MAX_REFERENCES,
                "authorityClaimLimit": MAX_AUTHORITY_CLAIMS,
                "inventoryProvided": inventory is not None,
                "caveat": "Inventory is the caller's inspected scope, not a complete filesystem. Missing membership never proves nonexistence, semantic drift or disuse.",
            },
        },
        "sharedSourceReferences": [
            {"target": target, "references": rows[:8], "documents": len({r["path"] for r in rows})}
            for target, rows in sorted(by_target.items())
            if len({r["path"] for r in rows}) > 1
        ][:100],
        "scope": {
            "referenceSelection": "relationship_kind_round_robin",
            "referenceCounts": counts,
            "referenceCountBasis": "Observed literal matches; retained locations are unique by kind, path, line and target. Omitted matches include repeated same-line locations.",
            "callerBytesExamined": examined_bytes,
            "callerFilesExamined": examined_files,
            "callerFilesCaptured": len(sources),
            "callerSelection": "role_area_round_robin",
            "callerByteLimit": byte_limit,
            "omittedCallerPaths": omitted_callers[:100],
            "omittedCallers": len(omitted_callers),
            "referenceLimit": MAX_REFERENCES,
            "commandReferencesObserved": commands_observed,
            "commandReferencesRetained": len(commands),
            "commandReferencesOmitted": commands_observed - len(commands),
            "commandReferenceLimit": MAX_COMMAND_REFERENCES,
        },
        "gaps": sorted(set(gaps)),
    }


def captured_documentation(
    texts: dict[str, str],
    manifest_paths: set[str],
    *,
    captured_sources: dict[str, str] | None = None,
    manifest_scripts: dict[str, list[str]] | None = None,
    inventory_paths: set[str] | None = None,
    deep: bool = False,
) -> dict:
    selected = {path: texts[path] for path in sorted(texts, key=_document_priority)[:MAX_DOCUMENTS]}
    documents, links, gaps = [], [], []
    by_hash = defaultdict(list)
    known = set(manifest_paths)
    for name in manifest_paths:
        known.update(str(parent) for parent in PurePosixPath(name).parents)
    anchors = {}
    links_truncated = False
    for name, text in selected.items():
        if UNSUPPORTED_LINK_RE.search(without_fences(text)):
            gaps.append(f"Unsupported Markdown link markup: {name}")
        payload = text.encode("utf-8")
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        documents.append(
            {
                "path": name,
                "sha256": digest,
                "bytes": len(payload),
                "words": len(words(text)),
                "tokensApprox": round(len(text) / 4),
            }
        )
        by_hash[digest].append(name)
        for target in local_links(text):
            if len(links) >= MAX_LINKS:
                links_truncated = True
                break
            row = {"source": name, "target": target}
            try:
                parsed = urlsplit(target)
            except ValueError:
                row["issue"] = "unsupported-link"
                links.append(row)
                continue
            if parsed.scheme or parsed.netloc:
                row["issue"] = "external-unverified"
            else:
                path = unquote(parsed.path)
                resolved = posixpath.normpath(
                    posixpath.join(posixpath.dirname(name), path) if path else name
                )
                if resolved.startswith("/") or resolved == ".." or resolved.startswith("../"):
                    row["issue"] = "outside-captured-root"
                elif resolved not in known:
                    row["issue"] = "unresolved-or-excluded-target"
                elif parsed.fragment:
                    if resolved not in selected:
                        row["issue"] = "anchor-not-captured"
                    else:
                        if resolved not in anchors:
                            anchors[resolved] = headings(selected[resolved])
                        available, unsupported = anchors[resolved]
                        if unquote(parsed.fragment).lower() not in available:
                            row["issue"] = "uncertain-anchor" if unsupported else "missing-anchor"
                        else:
                            row["resolved"] = resolved
                else:
                    row["resolved"] = resolved
            links.append(row)
    if len(texts) > len(selected):
        gaps.append("Documentation input limit reached; remaining documents were not analyzed")
    if links_truncated:
        gaps.append("Documentation link limit reached; remaining links were not analyzed")
    rich_texts, roles, rich_omitted = _rich_inputs(
        selected, byte_limit=4_000_000 if deep else 1_000_000
    )
    sections = analyze_sections(
        rich_texts,
        max_pairs=500 if deep else 100,
        max_sections=2000 if deep else 500,
        max_windows=8000 if deep else 2000,
    )
    references = _reference_evidence(
        rich_texts,
        manifest_paths,
        captured_sources or {},
        manifest_scripts or {},
        byte_limit=32_000_000 if deep else 8_000_000,
        inventory_paths=inventory_paths,
    )
    for row in documents:
        row["roleHint"], row["roleReasons"] = roles[row["path"]]
        row["agentGuidance"] = is_agent_guidance(row["path"])
    if rich_omitted:
        gaps.append(
            "Rich documentation byte limit reached; remaining documents have only basic inventory/link evidence"
        )
    gaps.extend(sections["gaps"])
    gaps.extend(references["gaps"])
    maintenance = []
    drift = references.pop("driftEvidence")
    for check in drift["pathChecks"]:
        if check["status"] in {
            "not_in_captured_snapshot",
            "not_in_inspected_inventory",
            "present_not_captured",
        }:
            maintenance.append(
                {
                    "kind": "documented_path_uncaptured_hint"
                    if check["status"] == "present_not_captured"
                    else "documented_path_unresolved_hint",
                    "locations": [{"path": check["path"], "line": check["line"]}],
                    "metrics": {
                        "reference": check["reference"],
                        "status": check["status"],
                        "basis": check["basis"],
                    },
                }
            )
    for conflict in drift["authorityConflicts"]:
        maintenance.append(
            {
                "kind": "competing_authority_targets_hint",
                "locations": [
                    {"path": claim["path"], "line": claim["line"]} for claim in conflict["claims"]
                ],
                "metrics": {"subject": conflict["subject"], "basis": conflict["basis"]},
            }
        )
    for lead in sections["passageLeads"]:
        left, right = lead["left"], lead["right"]
        if left["path"] == right["path"] or any(
            roles[p][0] in {"generated", "required_record"} for p in (left["path"], right["path"])
        ):
            continue
        maintenance.append(
            {
                "kind": "repeated_guidance_passage",
                "locations": [
                    {"path": item["path"], "line": item["lineStart"], "end_line": item["lineEnd"]}
                    for item in (left, right)
                ],
                "metrics": {"similarity": lead["similarity"], "basis": lead["basis"]},
            }
        )
    for command in references["commands"]:
        if command["status"] == "not_declared_in_captured_manifest":
            maintenance.append(
                {
                    "kind": "documented_script_mismatch_hint",
                    "locations": [
                        {"path": command["path"], "line": command["line"]},
                        {"path": command["manifest"], "line": 1},
                    ],
                    "metrics": {"script": command["script"], "basis": command["basis"]},
                }
            )
    for caller in references["references"]:
        if caller["kind"] == "literal_document_caller":
            maintenance.append(
                {
                    "kind": "documentation_caller_coupling_hint",
                    "locations": [
                        {"path": caller["path"], "line": caller["line"]},
                        {"path": caller["target"], "line": 1},
                    ],
                    "metrics": {"basis": caller["basis"]},
                }
            )
    selected_maintenance = _maintenance_sample(maintenance)
    maintenance_observed = Counter(row["kind"] for row in maintenance)
    maintenance_retained = Counter(row["kind"] for row in selected_maintenance)
    return {
        "schema": SCHEMA,
        "method": "Captured source bytes only; lexical leads, not ratings or deletion decisions",
        "documents": documents,
        "words": sum(row["words"] for row in documents),
        "bytes": sum(row["bytes"] for row in documents),
        "tokensApprox": sum(row["tokensApprox"] for row in documents),
        "exactDuplicates": [names for names in by_hash.values() if len(names) > 1],
        "links": links,
        "sections": sections,
        "referenceEvidence": references,
        "driftEvidence": drift,
        "maintenanceLeads": selected_maintenance,
        "scope": {
            "capturedDocuments": len(texts),
            "analyzedDocuments": len(selected),
            "maxDocuments": MAX_DOCUMENTS,
            "maxLinks": MAX_LINKS,
            "linksTruncated": links_truncated,
            "richDocuments": len(rich_texts),
            "richOmittedPaths": rich_omitted[:100],
            "richOmittedDocuments": len(rich_omitted),
            "maintenanceLeadsObserved": len(maintenance),
            "maintenanceLeadsOmitted": len(maintenance) - len(selected_maintenance),
            "maintenanceLeadLimit": MAX_MAINTENANCE_LEADS,
            "maintenanceLeadSelection": "kind_round_robin_agent_guidance_first",
            "maintenanceLeadCounts": {
                kind: {
                    "observed": count,
                    "retained": maintenance_retained[kind],
                    "omitted": count - maintenance_retained[kind],
                }
                for kind, count in sorted(maintenance_observed.items())
            },
            "analysisProfile": "deep" if deep else "standard",
            "documentSelection": "agent_guidance_then_root_readme_then_path",
            "agentGuidanceCaptured": sum(is_agent_guidance(path) for path in texts),
            "agentGuidanceAnalyzed": sum(is_agent_guidance(path) for path in selected),
            "agentGuidanceRich": sum(is_agent_guidance(path) for path in rich_texts),
            "omittedDocumentPaths": [path for path in sorted(texts) if path not in selected][:100],
        },
        "gaps": gaps
        + [
            "Unresolved links may name missing, excluded or uncaptured inputs; inspect before judging",
            "External links, semantic freshness and navigation accuracy are not verified by collection",
        ],
    }
