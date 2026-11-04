"""Pure snapshot projections and Markdown report serialization."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .confidence import confidence_assessment
from .project_context import project_context_assessment
from .prompting import prompting_profile
from .rubric import DIMENSIONS


def _ecosystem_fit(assessment):
    """Read bounded ecosystem evidence from this snapshot, never the current worktree."""
    summary = assessment["facts"].get("ecosystem_fit")
    if summary is None:
        return {
            "status": "not_collected",
            "gaps": ["Ecosystem fit was not collected for this snapshot; rescan to capture it."],
        }
    evidence = next(
        (
            entry
            for entry in assessment["evidence"]
            if entry["id"] == summary.get("evidence_id") and entry["kind"] == "ecosystem-analysis"
        ),
        None,
    )
    if evidence is None or summary.get("schema_version") != 1:
        return {
            **summary,
            "status": "unsupported",
            "gaps": [
                *summary.get("gaps", []),
                "Captured ecosystem evidence is missing or unsupported; rescan with a compatible collector.",
            ],
        }
    stats = evidence["stats"]
    if stats.get("schema_version") != 1:
        return {
            **summary,
            "status": "unsupported",
            "gaps": [
                *summary.get("gaps", []),
                "Captured ecosystem-analysis schema is unsupported; use a compatible collector.",
            ],
        }
    return {
        **summary,
        "dependencies": stats["dependencies"],
        "constraint_styles": stats.get("constraint_styles", []),
        "constraint_style_counts": stats.get("constraint_style_counts", {}),
        "signals": stats["signals"],
        "caveat": stats["caveat"],
    }


def _review_coverage(review):
    """Summarize authored breadth without upgrading missing historical declarations."""
    coverage = (review or {}).get("coverage", {})
    recorded = coverage.get("dimension_reviews")
    dimensions = {}
    for dimension in DIMENSIONS:
        row = (recorded or {}).get(dimension)
        if row is None:
            row = {
                "status": "unestablished" if review else "unreviewed",
                "rationale": "Dimension-specific review coverage was not recorded."
                if review
                else "No saved review.",
                "evidence_ids": [],
            }
        dimensions[dimension] = {
            "status": row["status"],
            "rationale": row["rationale"],
            "evidence_ids": list(row["evidence_ids"]),
        }
    counts = {
        status: sum(row["status"] == status for row in dimensions.values())
        for status in ("reviewed", "partial", "unreviewed", "unestablished")
    }
    scope = coverage.get("scope", "unknown")
    if review is None or counts["unreviewed"] == len(DIMENSIONS):
        status = "unreviewed"
    elif recorded is None:
        status = "unestablished"
    elif scope == "focused":
        status = "focused"
    elif scope == "whole_project" and counts["reviewed"] == len(DIMENSIONS):
        status = "broad"
    else:
        status = "partial"
    return {
        "scope": scope,
        "status": status,
        "dimensions": dimensions,
        "counts": counts,
        "gaps": [
            f"{dimension}: {row['status']}"
            for dimension, row in dimensions.items()
            if row["status"] != "reviewed"
        ],
        "examined_count": len(coverage.get("examined", [])),
        "unexamined_count": len(coverage.get("unexamined", [])),
        "limitation_count": len(coverage.get("limitations", [])),
        "caveat": "Coverage records the author's declared scope and citations; it does not verify review depth, correctness or runtime coverage.",
    }


def _markdown_text(value):
    text = html.escape(str(value), quote=False).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "[", "]", "|"):
        text = text.replace(character, "\\" + character)
    return text


def _project_context_markdown(report):
    context = project_context_assessment(
        report["assessment"], report.get("review"), report.get("goals")
    )
    lines = ["", "## Project maturity, purpose and focus", ""]
    if context["status"] == "unestablished":
        return lines + [
            "Project scope, readiness and intended destination have not been established in this review."
        ]
    current, intended, alignment = (context[key] for key in ("current", "intended", "alignment"))
    lines += [
        "Current: "
        + _markdown_text(current["milestone_label"])
        + " · "
        + _markdown_text(current["readiness_label"])
        + "; declared confidence: "
        + _markdown_text(current["confidence"])
        + ".",
        "",
        _markdown_text(current["rationale"]),
        "",
        "Intended destination: "
        + _markdown_text(intended["milestone_label"])
        + "; "
        + _markdown_text(intended["basis_label"])
        + "; declared confidence: "
        + _markdown_text(intended["confidence"])
        + ".",
        "",
        _markdown_text(intended["statement"]),
    ]
    if intended["attribution"]:
        lines.append("Attribution: " + _markdown_text(intended["attribution"]))
    lines += [
        "",
        "Alignment: " + _markdown_text(alignment["direction_label"]),
        "",
        _markdown_text(alignment["rationale"]),
    ]
    if alignment["priorities"]:
        lines += ["", "Ranked focus:", ""]
        for rank, area in enumerate(alignment["priorities"], 1):
            lines.append(
                f"{rank}. "
                + _markdown_text(area["dimension_label"])
                + " — "
                + _markdown_text(area["direction_label"])
                + ": "
                + _markdown_text(area["rationale"])
            )
            if area["initiative_ids"]:
                lines.append(
                    "   Plan initiatives: " + _markdown_text(", ".join(area["initiative_ids"]))
                )
    for title, values in (
        ("Deferred work", alignment["deferred"]),
        ("Alternative intentions", intended["alternatives"]),
        ("Context limits", [*intended["limitations"], *context["gaps"]]),
    ):
        if values:
            lines += ["", title + ":", "", *["- " + _markdown_text(value) for value in values]]
    lines += [
        "",
        "Context evidence: "
        + _markdown_text(
            ", ".join(dict.fromkeys(current["evidence_ids"] + intended["evidence_ids"]))
            or "Attributable user intent; no captured intent citation"
        ),
        "",
        _markdown_text(context["profile_note"]),
        "",
        _markdown_text(context["caveat"]),
    ]
    return lines


def _confidence_markdown(assessment, review):
    confidence = confidence_assessment(assessment, review)
    lines = ["", "## Confidence and evidence support", "", _markdown_text(confidence["caveat"])]
    for dimension, axes in confidence["dimensions"].items():
        lines += ["", "### " + _markdown_text(dimension), ""]
        for axis in ("capability", "burden"):
            value = axes[axis]
            lines.append(
                "- "
                + axis
                + " confidence (declared): "
                + _markdown_text(value.get("declared_confidence") or "unestablished")
            )
            lines.extend("  - " + _markdown_text(blocker) for blocker in value["blockers"])
            if axis == "burden" and value.get("support"):
                support = value["support"]
                lines.append(
                    "  - Structured burden support: "
                    + _markdown_text(support["status"])
                    + "; scope: "
                    + _markdown_text(support.get("scope") or "undeclared")
                )
                lines.extend("  - " + _markdown_text(gap) for gap in support.get("gaps", []))
                readiness = support.get("readiness", {})
                if readiness:
                    lines.append(
                        "  - Burden evidence: "
                        + "; ".join(
                            f"{label}: {len(readiness.get(key, []))}"
                            for label, key in (
                                ("source", "source_evidence_ids"),
                                ("attributed experience", "experience_evidence_ids"),
                                ("matched cost reports", "matched_cost_evidence_ids"),
                                ("partial elapsed reports", "partial_elapsed_evidence_ids"),
                                ("limited reports", "limited_report_evidence_ids"),
                            )
                        )
                    )
                    lines.append(
                        "  - Declared trace activities: "
                        + _markdown_text(
                            "; ".join(
                                f"{activity}: {count}"
                                for activity, count in readiness["trace_activities"].items()
                            )
                        )
                        + "; recurrence: "
                        + _markdown_text(readiness["recurrence"])
                        + "; challenge: "
                        + _markdown_text(readiness["challenge"])
                    )
                    lines.extend(
                        "  - Next evidence: " + _markdown_text(step)
                        for step in readiness["next_steps"]
                    )
    for row in confidence["findings"]:
        lines += [
            "",
            "### Finding: " + _markdown_text(row["title"]),
            "",
            "Declared confidence: "
            + _markdown_text(row["declared_confidence"] or "unestablished")
            + "; scope: "
            + _markdown_text(row["scope"])
            + "; source grounding: "
            + _markdown_text(row["grounding"])
            + ".",
        ]
        support = (review or {}).get("findings", [])[row["index"]].get("support")
        if support is None:
            continue
        lines += [
            "",
            _markdown_text(support["rationale"]),
            "Counterevidence: " + _markdown_text(support["counterevidence"]),
        ]
        for citation in support["citations"]:
            lines += [
                "",
                "Evidence: "
                + _markdown_text(citation["evidence_id"])
                + "; lines "
                + str(citation["line"])
                + "–"
                + str(citation["end_line"])
                + ".",
                "",
                *["> " + _markdown_text(line) for line in citation["excerpt"].splitlines()],
            ]
        lines.extend("- Limitation: " + _markdown_text(item) for item in support["limitations"])
    return lines


def _planning_markdown(alignment):
    lines = ["", "## Assessment method", ""]
    method = alignment.get("assessment_method", {})
    lines += [
        "Freshness: "
        + _markdown_text(method.get("status", "unestablished"))
        + "; completion: "
        + _markdown_text(method.get("completion", "unestablished"))
        + ".",
        "",
        _markdown_text(method.get("caveat", "Freshness was not recorded.")),
        "",
    ]
    for dimension, row in method.get("dimensions", {}).items():
        lines.append("- " + _markdown_text(dimension) + ": " + _markdown_text(row["label"]))
    for gap in method.get("gaps", []):
        lines.append("- Limitation: " + _markdown_text(gap))
    for trace in method.get("change_traces", []):
        lines += ["", "### Change trace: " + _markdown_text(trace["title"]), ""]
        for step in trace["steps"]:
            lines.append(
                "- "
                + _markdown_text(step["owner"])
                + ": "
                + _markdown_text(step["change"])
                + "; activity (declared): "
                + _markdown_text(step.get("activity", "unknown"))
                + "; evidence: "
                + _markdown_text(", ".join(step["evidence_ids"]))
            )
        for label, key in (
            ("Change cost", "cost"),
            ("Invariant", "invariant"),
            ("Counterevidence", "counterevidence"),
        ):
            lines.append(label + ": " + _markdown_text(trace[key]))
        lines.extend("- Trace gap: " + _markdown_text(gap) for gap in trace["gaps"])
    challenge = method.get("challenge", {})
    lines += ["", "Challenge: " + _markdown_text(challenge.get("status", "unrecorded")) + "."]
    if challenge.get("reviewer_id"):
        lines.append("Declared challenger: " + _markdown_text(challenge["reviewer_id"]))
    if challenge.get("summary"):
        lines.append(_markdown_text(challenge["summary"]))
    for item in challenge.get("items", []):
        response = item["response"]
        lines += [
            "- Concern: "
            + _markdown_text(item["concern"])
            + "; evidence: "
            + _markdown_text(", ".join(item["evidence_ids"])),
            "  Response: "
            + _markdown_text(response["decision"])
            + "; "
            + _markdown_text(response["rationale"])
            + "; evidence: "
            + _markdown_text(", ".join(response["evidence_ids"])),
        ]
    lines.extend("- Challenge gap: " + _markdown_text(gap) for gap in challenge.get("gaps", []))
    lines += ["", "## Review coverage", ""]
    summary = alignment.get("review_coverage")
    if summary:
        lines += [
            "Declared breadth: "
            + _markdown_text(summary["status"])
            + "; "
            + str(summary["counts"]["reviewed"])
            + "/"
            + str(len(DIMENSIONS))
            + " dimensions reviewed.",
            "",
            _markdown_text(summary["caveat"]),
            "",
        ]
        for dimension, row in summary["dimensions"].items():
            lines.append(
                "- "
                + _markdown_text(dimension)
                + ": "
                + _markdown_text(row["status"])
                + "; "
                + _markdown_text(row["rationale"])
                + "; evidence: "
                + _markdown_text(", ".join(row["evidence_ids"]) or "none recorded")
            )
        lines.append("")
    coverage = alignment.get("coverage")
    if coverage:
        lines.append("Scope: " + _markdown_text(coverage["scope"]) + ".")
        for area in coverage["examined"]:
            lines.append(
                "- Examined: "
                + _markdown_text(area["area"])
                + "; evidence: "
                + _markdown_text(", ".join(area["evidence_ids"]))
            )
        for area in coverage["unexamined"]:
            lines.append(
                "- Unexamined: "
                + _markdown_text(area["area"])
                + ": "
                + _markdown_text(area["reason"])
            )
        lines.extend("- Limitation: " + _markdown_text(value) for value in coverage["limitations"])
        for check in coverage["validation"]:
            lines.append(
                "- Validation: "
                + _markdown_text(check["check"])
                + ": "
                + _markdown_text(check["status"])
                + "; evidence: "
                + _markdown_text(", ".join(check["evidence_ids"]))
            )
    else:
        lines.append("Review coverage was not recorded.")
    inputs = alignment.get("dimension_inputs")
    if inputs:
        lines += [
            "",
            "## Deterministic inputs",
            "",
            _markdown_text(inputs["caveat"]),
            "",
            "| Dimension | Available evidence providers | Missing analysis and limits |",
            "| --- | --- | --- |",
        ]
        for dimension, row in inputs["dimensions"].items():
            available = [
                name for name in row["provider_ids"] if inputs["providers"][name]["evidence_count"]
            ]
            lines.append(
                "| "
                + _markdown_text(dimension)
                + " | "
                + _markdown_text(", ".join(available) or "none collected")
                + " | "
                + _markdown_text(" ".join(row["limitations"]))
                + " |"
            )
    system = alignment.get("system_map")
    if system:
        lines += [
            "",
            "## Production source map",
            "",
            "Captured map: "
            + _markdown_text(system["status"])
            + "; "
            + str(system["production_files"])
            + " production files across "
            + str(system["area_count"])
            + " path areas.",
            "",
            _markdown_text(system["caveat"]),
            "",
        ]
        for area in system["areas"]:
            functions = "unknown" if area["functions"] is None else str(area["functions"])
            lines.append(
                "- "
                + _markdown_text(area["path"])
                + ": "
                + str(area["files"])
                + " files; functions: "
                + functions
                + "; evidence: "
                + _markdown_text(", ".join(area["evidence_ids"]) or "none recorded")
            )
        for dependency in system["cross_area_dependencies"]:
            lines.append(
                "- Static imports: "
                + _markdown_text(dependency["source_area"])
                + " → "
                + _markdown_text(dependency["target_area"])
                + ": "
                + str(dependency["import_edges"])
                + "; evidence: "
                + _markdown_text(", ".join(dependency["evidence_ids"]))
            )
        lines.append(
            "Omitted from this bounded view: "
            + str(system["omitted_areas"])
            + " areas; "
            + str(system["omitted_cross_area_dependencies"])
            + " import pairs."
        )
    lines += [
        "",
        "## Improvement plan",
        "",
        "Planning status: " + _markdown_text(alignment.get("planning_status", "unknown")) + ".",
    ]
    plan = alignment.get("plan")
    if not plan:
        return lines + [
            "",
            "No authored roadmap was recorded; numeric goals do not supply a diagnosis.",
        ]
    lines += [
        "",
        "Diagnosis: " + _markdown_text(plan["diagnosis"]),
        "",
        "Target state: " + _markdown_text(plan["target_state"]),
    ]
    for item in plan["initiatives"]:
        lines += ["", "### " + _markdown_text(item["title"]), ""]
        for label, value in (
            ("Priority", item["priority"]),
            ("Root cause", item["root_cause"]),
            ("Full scope", item["scope"]),
            ("Burden effect", item["burden_effect"]),
            ("Dependencies", ", ".join(item["depends_on"]) or "None"),
            ("Evidence", ", ".join(item["evidence_ids"])),
        ):
            lines.append(label + ": " + _markdown_text(value))
        lines += ["", "Dimension impacts:", ""]
        lines.extend(
            "- " + _markdown_text(key) + ": " + _markdown_text(value)
            for key, value in item["dimension_impacts"].items()
        )
        lines += [
            "",
            "Acceptance:",
            "",
            *["- " + _markdown_text(value) for value in item["acceptance"]],
        ]
        lines += ["", "First implementation slice: " + _markdown_text(item["first_slice"])]
    return lines


def _prompting_markdown(report):
    profile = prompting_profile(report["assessment"], report.get("review"))
    paths = {entry["id"]: entry["path"] for entry in report["assessment"]["evidence"]}

    def cites(identities):
        return "Evidence: " + ", ".join(
            _markdown_text(f"{identity} ({paths.get(identity, 'unknown')})")
            for identity in identities
        )

    level = profile["level"]
    lines = [
        "",
        "## Behavioral prompt reliance",
        "",
        (f"Prompt reliance: {level}/5 · " if level is not None else "Prompt reliance: unknown · ")
        + _markdown_text(profile["level_label"])
        + ".",
        "",
        _markdown_text(profile["rationale"]),
    ]
    if profile["evidence_ids"]:
        lines += ["", cites(profile["evidence_ids"])]
    intent = profile["intent"]
    if intent["min"] is not None or intent["max"] is not None:
        lines += [
            "",
            "Preferred context range: "
            + _markdown_text(
                f"{intent['min'] if intent['min'] is not None else 'any'}–{intent['max'] if intent['max'] is not None else 'any'}; {intent['basis_label']}"
            )
            + ".",
            _markdown_text(intent["rationale"]),
            _markdown_text(profile["fit"]["label"]),
        ]
        if intent["evidence_ids"]:
            lines.append(cites(intent["evidence_ids"]))
    lines += [
        "",
        "Output variability: " + _markdown_text(profile["variability"]["label"]) + ".",
        _markdown_text(profile["variability"]["rationale"]),
    ]
    if profile["variability"]["evidence_ids"]:
        lines.append(cites(profile["variability"]["evidence_ids"]))
    collection = profile["collection"]
    lines += ["", "Collection: " + _markdown_text(collection["status"]) + "."]
    if collection.get("evidence_id"):
        lines.append(cites([collection["evidence_id"]]))
    for kind, count in collection.get("summary", {}).get("counts_by_kind", {}).items():
        label = (
            "guidance / skill assets (consumer unverified)"
            if kind == "development_guidance"
            else kind.replace("_", " ")
        )
        lines.append("- " + _markdown_text(label) + ": " + _markdown_text(count))
    for workflow in profile["workflows"]:
        lines += [
            "",
            "- "
            + _markdown_text(workflow["name"])
            + " · "
            + _markdown_text(workflow["control_label"])
            + ": "
            + _markdown_text(workflow["rationale"]),
        ]
        if workflow["evidence_ids"]:
            lines.append(cites(workflow["evidence_ids"]))
    for recommendation in profile["recommendations"]:
        lines += [
            "",
            "- "
            + _markdown_text(recommendation["direction_label"])
            + ": "
            + _markdown_text(recommendation["action"]),
            _markdown_text(recommendation["rationale"]),
        ]
        if recommendation["evidence_ids"]:
            lines.append(cites(recommendation["evidence_ids"]))
    lines += ["", _markdown_text(profile["caveat"]), _markdown_text(profile["profile_note"])]
    lines += ["- " + _markdown_text(gap) for gap in [*profile["gaps"], *collection.get("gaps", [])]]
    return lines


def markdown_report(report):
    assessment = report["assessment"]
    lines = [
        "# Project assessment: " + _markdown_text(Path(assessment["source"]["root"]).name),
        "",
        f"Snapshot: `{assessment['id']}`; rubric: {assessment['rubric_version']}",
        "",
        "Capability and burden are evidence-backed judgments; missing evidence is unknown.",
        *_project_context_markdown(report),
        *_prompting_markdown(report),
        "",
        "| Dimension | Capability | Burden and evidence | Capability confidence |",
        "|---|---:|---:|---|",
    ]
    ratings = (report["review"] or {}).get("ratings", {})
    for dimension in DIMENSIONS:
        rating = ratings.get(dimension, {})
        burden = rating.get("burden")
        burden_text = "unknown"
        if burden is not None:
            basis = (
                "observed" if rating.get("burden_basis") == "observed" else "estimated from source"
            )
            burden_text = (
                f"{burden} ({basis}; declared {rating.get('burden_confidence', 'low')} confidence)"
            )
        lines.append(
            f"| {dimension} | {rating.get('capability') if rating.get('capability') is not None else 'unknown'} | {burden_text} | {rating.get('confidence', 'unknown')} |"
        )
    lines += _confidence_markdown(assessment, report["review"])
    facts = assessment["facts"]
    inventory = facts.get("inventory", {})
    lines += [
        "",
        "## Collected facts",
        "",
        f"Manifest files: {inventory.get('manifest_files', 'unknown')}; recognized text files: "
        f"{inventory.get('recognized_files', 'unknown')}; source files: "
        f"{inventory.get('source_files', 'unknown')}; test files: "
        f"{inventory.get('test_files', 'unknown')}; documentation files: "
        f"{inventory.get('documentation_files', 'unknown')}.",
    ]
    architecture = facts.get("maintainability")
    documentation = facts.get("documentation", {}).get("doc_value")
    if documentation:
        lines += [
            "",
            f"Documentation evidence: {documentation['words']} words; "
            f"{documentation['exact_duplicate_groups']} exact duplicate groups; "
            f"{documentation['local_link_leads']} local-link leads. These are bounded source "
            "observations, not burden scores, semantic equivalence or deletion decisions. "
            f"Inspect evidence {documentation['evidence_id']} for locations, scope and gaps.",
        ]
    if architecture:
        lines += [
            "",
            f"Architecture review hints: {architecture['forwarding_functions']} forwarding functions; "
            f"{architecture['abstract_classes']} abstract/interface classes. These are syntactic "
            "inspection candidates, not burden scores; justified boundaries can produce the same patterns.",
        ]
    analysis = facts.get("static_analysis")
    if analysis:
        coverage = analysis["coverage"]
        lines += [
            "",
            f"Static analysis: {analysis['status']}; Python files parsed "
            f"{coverage['parsed_files']}/{coverage['python_files']}; "
            f"other source files {coverage['other_source_files']}; "
            f"{analysis['summary']['candidate_count']} candidate leads. "
            "These are inspection leads, not defects or ratings. "
            f"Evidence: {analysis['evidence_id']}.",
        ]
    ecosystem = _ecosystem_fit(assessment)
    lines += ["", "## Ecosystem fit", "", f"Collection: {ecosystem['status']}."]
    if ecosystem["status"] in {"complete", "partial"}:
        lines += [
            "",
            f"Captured dependency declarations: {ecosystem['dependency_count']}; "
            f"syntax signals: {ecosystem['signal_count']}. "
            "These are review leads, not a fit rating or a migration recommendation. "
            f"Evidence: {_markdown_text(ecosystem['evidence_id'])}.",
            "",
            _markdown_text(ecosystem["caveat"]),
            "",
            "Dependency inventory:",
        ]
        for dependency in ecosystem["dependencies"]:
            location = dependency["path"]
            if dependency.get("line"):
                location += f":{dependency['line']}"
            lines.append(
                f"- {_markdown_text(dependency['name'])} "
                f"({_markdown_text(dependency['group'])}) — {_markdown_text(location)}"
            )
        if not ecosystem["dependencies"]:
            lines.append("- No declarations captured; runtime dependencies may still exist.")
        lines += ["", "Syntax signals to inspect:"]
        for signal in ecosystem["signals"]:
            location = signal["path"]
            if signal.get("line"):
                location += f":{signal['line']}"
            lines.append(f"- {_markdown_text(signal['kind'])} — {_markdown_text(location)}")
        if not ecosystem["signals"]:
            lines.append("- No supported signals captured; this does not establish fit.")
        lines += [
            "",
            "Collection limits: " + _markdown_text(json.dumps(ecosystem["limits"], sort_keys=True)),
        ]
    lines += ["", *["- " + _markdown_text(gap) for gap in ecosystem.get("gaps", [])]]
    lines += ["", "## Evidence gaps", ""]
    lines += ["- " + _markdown_text(gap) for gap in assessment["gaps"]] or [
        "- No collector gaps recorded."
    ]
    for dimension, rating in ratings.items():
        lines += ["", f"## {dimension.capitalize()}", "", _markdown_text(rating["rationale"])]
        lines += ["- " + _markdown_text(r) for r in rating["recommendations"]]
        lines += ["", "Evidence: " + ", ".join(rating["evidence_ids"])]
    lines += ["", "## Findings", ""]
    for finding in assessment["findings"] + (report["review"] or {}).get("findings", []):
        lines.append(
            "- "
            + _markdown_text(finding.get("severity", "unknown"))
            + ": "
            + _markdown_text(finding.get("title", finding.get("message", "Finding")))
        )
    lines += _planning_markdown(
        {
            **report.get("goal_alignment", {}),
            "review_coverage": report.get("review_coverage") or _review_coverage(report["review"]),
        }
    )
    decisions = [
        item for item in report.get("finding_status", {}).get("items", []) if item["event_count"]
    ]
    if decisions:
        lines += [
            "",
            "## Finding verification and accepted debt",
            "",
            report["finding_status"]["caveat"],
            "",
        ]
        for item in decisions:
            lines.append(
                "- "
                + _markdown_text(
                    f"{item['finding']['severity']}: {item['finding']['title']} — {item['status']} ({item['verification_label']})"
                )
            )
            if item.get("verification"):
                lines.append("  " + _markdown_text(item["verification"]["acceptance"]))
    lines += [
        "",
        "## Goals and progress",
        "",
        "```json",
        json.dumps({"goals": report["goals"], "progress": report["progress"]}, indent=2),
        "```",
        "",
    ]
    return "\n".join(lines)
