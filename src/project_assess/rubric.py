"""Versioned assessment anchors and opt-in project goal profiles.

Anchors guide evidence-backed judgment; file counts never assign these levels.
Capability and maintenance burden are independent measurements.
"""

from copy import deepcopy
from typing import Any

DIMENSIONS = (
    "security",
    "testing",
    "documentation",
    "maintainability",
    "delivery",
    "operability",
    "extensibility",
)
RUBRIC_VERSION = "4"

_BURDEN_GUIDANCE = {
    "principle": (
        "Burden measures upkeep, coordination and friction, including justified safeguards. "
        "All burden anchors permit source-supported estimates; time logs are not required. "
        "Cite concrete work implied by the inspected design or workflow, not artifact counts alone."
    ),
    "basis": {
        "source_estimate": (
            "Estimate from traced edit sites, coupling, duplicated guidance, fixtures, gates or "
            "operating steps. State the inference and limitations without claiming measured time or toil."
        ),
        "observed": (
            "Support with direct execution, change history, incident records or maintainer evidence "
            "demonstrating the relevant maintenance or coordination cost."
        ),
        "unknown": (
            "Use when the available evidence cannot support a defensible estimate, for example "
            "unsupported source, unavailable workflows or counts without inspection."
        ),
    },
    "confidence": (
        "Rate burden confidence independently of capability confidence. Use low confidence for "
        "limited source inference, and increase it when inspected workflows, history or direct "
        "observations corroborate the cost. Levels 4–5 need evidence of dominating burden."
    ),
    "examples": {
        "simple_source": (
            "A traced direct implementation with light documented upkeep can justify burden 1 "
            "as a low-confidence source estimate without runtime or time records."
        ),
        "counts_only": (
            "Many files, tests, classes or forwarding functions alone cannot establish excess burden."
        ),
    },
}

_ANCHORS = {
    "security": {
        "capability": [
            "Wide open: observed critical boundaries lack basic protection.",
            "Basic hygiene: secrets, dependencies and obvious access boundaries receive attention.",
            "Protected boundaries: explicit access controls and security checks cover known risks.",
            "Deliberate defense: least privilege, threat-aware validation and auditability are evidenced.",
            "Defense in depth: current validation demonstrates layered controls and critical failure handling.",
            "Fort Knox ambition: independent, current adversarial evidence supports high assurance across applicable boundaries.",
        ],
        "burden": [
            "Security upkeep adds negligible friction to ordinary work.",
            "Light recurring upkeep and occasional security review.",
            "Regular security maintenance with manageable review and access friction.",
            "Security upkeep and repeated approval work materially slow routine changes.",
            "Security tooling, exceptions or duplicated controls dominate many changes.",
            "Security administration dominates the project's available engineering effort.",
        ],
    },
    "testing": {
        "capability": [
            "No repeatable checks validate project behavior.",
            "Early checks: smoke tests or a small set of happy paths.",
            "Focused protection: repeatable tests cover important behavior and selected failure cases.",
            "Dependable suite: balanced checks cover critical behavior, integrations and applicable failure modes.",
            "Broad assurance: current results demonstrate reliable validation of applicable system, concurrency, security and recovery risks.",
            "Exceptional assurance: repeated adversarial or independent validation demonstrates that the strategy detects critical defects.",
        ],
        "burden": [
            "Test upkeep and feedback overhead are negligible.",
            "Fast feedback and light fixture or assertion upkeep.",
            "Manageable runtime, fixtures and routine test maintenance.",
            "Flakiness, slow feedback or brittle tests regularly delay changes.",
            "Maintaining or repairing tests takes much of the effort for ordinary changes.",
            "Tests have taken over: suite upkeep and feedback delays dominate engineering work.",
        ],
    },
    "documentation": {
        "capability": [
            "No usable guidance explains how to work with the project.",
            "Basic instructions explain the purpose and how to get started.",
            "Usable onboarding and guidance cover main workflows and important interfaces.",
            "Accurate architecture, decisions, contracts and operating guidance support routine work.",
            "Comprehensive maintained references and runbooks are validated through relevant checks or use.",
            "Continuously validated guidance demonstrably supports unfamiliar users and demanding operational tasks.",
        ],
        "burden": [
            "Documentation upkeep and navigation effort are negligible.",
            "A small, clear source of guidance requires light upkeep.",
            "Regular documentation maintenance and navigation remain manageable.",
            "Duplication, stale guidance or extensive required edits repeatedly slow work.",
            "Documentation updates and reconciliation dominate many ordinary changes.",
            "Documentation has taken over: publication and reconciliation dominate project work.",
        ],
    },
    "maintainability": {
        "checks": {
            "rigidity": {
                "purpose": "Find unnecessary resistance to making a valuable change.",
                "questions": [
                    "For a representative valuable change, which rule, test or workflow obstructs it?",
                    "What important current outcome would fail if that constraint were relaxed?",
                    "Could a simpler constraint preserve that protection with less change friction?",
                ],
                "examples": [
                    "Tests coupled to private implementation details or cosmetic snapshots.",
                    "Historical coverage gates or mandatory documentation for trivial internal edits.",
                ],
                "guardrails": (
                    "Preserve security, durable-data and actual compatibility guarantees. "
                    "Past agent decisions remain revisable unless backed by a current requirement or invariant."
                ),
                "reporting": (
                    "Cite the change, obstacle, protected outcome and proportionate alternative "
                    "in existing rationale/findings. Reflect supported cost in burden with evidence "
                    "and confidence; counts alone do not establish rigidity. No separate score."
                ),
            },
            "ecosystem_fit": {
                "version": 1,
                "purpose": "Match bespoke code and library/framework reuse to demonstrated needs.",
                "questions": [
                    "Which requirements, exposure, workload, team and lifecycle constraints justify the current choice?",
                    "Could a maintained library reduce ownership of custom HTTP, auth, routing, state/cache or validation behavior?",
                    "Could a smaller dependency or direct implementation replace framework setup that a small utility does not need?",
                    "What migration, upgrade, security and compatibility costs would each option introduce?",
                ],
                "guardrails": (
                    "Both direct code and framework reuse can fit well. Package presence, count, age "
                    "or popularity never assign scores or justify automatic migration. Current version "
                    "support, licenses and vulnerabilities remain unknown offline; verify official "
                    "sources when researching a recommendation. Preserve required contracts."
                ),
                "reporting": (
                    "Use existing maintainability capability/burden rationale, findings and evidence. "
                    "Cite concrete behavior, the reuse or simplification option, migration/upkeep cost "
                    "and a smallest useful experiment with acceptance evidence. User stack preferences "
                    "are descriptive context, not a global gate or an additional score."
                ),
            },
        },
        "capability": [
            "Ordinary changes cannot be made predictably because structure and dependencies are unclear.",
            "Basic organization and conventions make small changes understandable.",
            "Clear responsibilities and interfaces support common changes.",
            "Cohesive modules, controlled dependencies and automated checks support safe evolution.",
            "Evidence from substantial changes demonstrates stable boundaries and manageable coupling.",
            "Repeated independent change evidence demonstrates exceptional adaptability and comprehensibility.",
        ],
        "burden": [
            "Structural upkeep and change coordination are negligible.",
            "Simple conventions and light abstractions require little upkeep.",
            "Architecture and tooling impose manageable coordination and maintenance.",
            "Coupling, duplication or layers without demonstrated purpose regularly amplify change effort.",
            "Speculative frameworks, duplicated adapters or structural coordination dominate many ordinary changes.",
            "Architecture and framework upkeep dominate development of useful behavior.",
        ],
    },
    "delivery": {
        "capability": [
            "No repeatable process produces and releases the intended software.",
            "A documented manual build or release path exists.",
            "Repeatable automated checks and packaging support the main delivery path.",
            "Source-bound builds, review gates and defined release and rollback procedures support controlled delivery.",
            "Current execution evidence verifies release provenance, failure recovery and the applicable deployment path.",
            "Repeated independent end-to-end evidence demonstrates controlled delivery and recovery under adverse conditions.",
        ],
        "burden": [
            "Build and release overhead is negligible.",
            "A short delivery path requires light maintenance.",
            "Build time, release steps and pipeline upkeep remain manageable.",
            "Slow pipelines, repeated handoffs or fragile release steps materially delay changes.",
            "Pipeline upkeep and release coordination dominate many changes.",
            "The delivery process consumes most available engineering effort.",
        ],
    },
    "operability": {
        "capability": [
            "No usable means exists to determine whether the intended workload is healthy.",
            "Basic logs and manual health checks support initial diagnosis.",
            "Useful diagnostic signals and operating instructions cover important behavior.",
            "Defined health signals, actionable alerts and recovery guidance support routine operation.",
            "Current workload and incident or exercise evidence validates diagnosis, alerting and recovery.",
            "Repeated independent operational exercises demonstrate resilience and effective response to critical failures.",
        ],
        "burden": [
            "Operational upkeep and interruption are negligible.",
            "Light monitoring and occasional manual attention suffice.",
            "Operational work, alerts and tooling have manageable recurring cost.",
            "Alert noise, toil or diagnostic complexity repeatedly interrupt engineering.",
            "Operational toil and tooling upkeep dominate many working periods.",
            "Operating the project consumes most available engineering effort.",
        ],
    },
    "extensibility": {
        "checks": {
            "extension_fit": {
                "purpose": "Match extension machinery to the project's actual variation needs.",
                "questions": [
                    "What variation is needed, how often, and who authors it: local, internal, external or untrusted code?",
                    "Can one representative extension use supported contracts without unnecessary core edits?",
                    "Which authoring guidance, compatibility checks and failure or isolation boundaries does that extension need?",
                    "Would a localized function, configuration option or injected dependency meet the need more simply?",
                ],
                "guardrails": (
                    "High extensibility and low rigidity are compatible. Preserve necessary contracts "
                    "and trust boundaries; sensitivity alone does not imply a need for plugins. "
                    "An absence of extension need can justify capability 0. Plugin counts alone do not assign a score."
                ),
                "reporting": (
                    "Distinguish a missing seam, a brittle extension contract and a speculative framework. "
                    "Cite a representative extension, the simplest adequate seam, its risks and a bounded "
                    "proof or next step through existing rationale/findings/recommendations."
                ),
            }
        },
        "capability": [
            "Single purpose: no supported extension seam; appropriate when no variation is needed.",
            "Localized functions, configuration or injected dependencies support small variations.",
            "Supported APIs or adapters accommodate known variants.",
            "Deliberate extension points support substantive features without core edits, with proportionate contracts and examples.",
            "Current evidence demonstrates independently authored extensions using versioned contracts, lifecycle and failure boundaries, and authoring guidance.",
            "Sustained compatibility evidence demonstrates multiple externally maintained extensions working across versions.",
        ],
        "burden": [
            "Extension upkeep and extra machinery are negligible.",
            "Localized seams add little configuration or compatibility maintenance.",
            "Supported variation and extension contracts require manageable compatibility upkeep.",
            "Repeated core edits, brittle contracts or configuration combinations materially amplify extension work.",
            "Framework machinery and option or test matrices dominate many feature changes.",
            "Extension machinery and ecosystem compatibility dominate development of useful behavior.",
        ],
    },
}


def _profile(title: str, minima: tuple[int, ...], burden_max: int) -> dict[str, Any]:
    return {
        "title": title,
        "targets": {
            dimension: {"capability_min": minimum, "burden_max": burden_max}
            for dimension, minimum in zip(DIMENSIONS, minima, strict=True)
        },
    }


PROFILES = {
    "local-experiment": _profile("Local experiment", (1, 1, 1, 1, 1, 0, 0), 1),
    "internal-service": _profile("Internal service", (2, 2, 2, 2, 2, 2, 0), 2),
    "public-production": _profile("Public production", (3, 3, 2, 3, 3, 3, 0), 2),
    "sensitive-critical": _profile("Sensitive or critical", (4, 4, 3, 3, 4, 4, 0), 3),
    "framework": _profile("Framework or library", (3, 3, 3, 3, 3, 2, 4), 2),
}


def rubric() -> dict[str, Any]:
    """Return independent JSON-compatible rubric data for a report or reviewer."""
    return {
        "version": RUBRIC_VERSION,
        "burden_guidance": deepcopy(_BURDEN_GUIDANCE),
        "dimensions": deepcopy(_ANCHORS),
        "profiles": deepcopy(PROFILES),
    }
