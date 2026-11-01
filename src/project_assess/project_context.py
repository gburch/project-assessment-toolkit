"""Evidence-backed project scope and purpose, independent of engineering scores."""

from copy import deepcopy

from jsonschema import Draft202012Validator

from .rubric import DIMENSIONS

VERSION = "1"
_MILESTONES = {
    "experiment": (
        "Exploration",
        "An idea or bounded proof is being explored; a supported useful workflow is not yet established.",
        "Inspect the hypothesis, implemented paths, missing pieces and explicit validation limits.",
    ),
    "personal_utility": (
        "Personal utility",
        "One person uses a focused tool to complete a bounded job.",
        "Trace the useful input/output path, its caller and relevant local data or failure risks.",
    ),
    "personal_app": (
        "Personal application",
        "One person depends on several connected application workflows and ongoing use; saved settings or data alone do not make a focused utility an application.",
        "Inspect linked workflows, state ownership, everyday changes and applicable recovery.",
    ),
    "shared_tool": (
        "Shared tool",
        "Other people can independently perform a bounded job through a usable interface.",
        "Inspect independent setup/use, interface boundaries and the protection each user needs.",
    ),
    "team_app": (
        "Team application",
        "Collaborators share workflows, state or operational responsibilities.",
        "Trace shared-state changes, identity/authority where needed, ownership and recovery.",
    ),
    "supported_product": (
        "Public / commercial application",
        "Independent users receive a supported product; charging money is not required.",
        "Inspect user onboarding, supported workflows, releases and support obligations; distinguish declarations from actual use.",
    ),
    "platform": (
        "Extension platform",
        "Others build integrations or extensions through deliberately supported contracts.",
        "Trace an extension authored outside the core and its compatibility, isolation and lifecycle needs.",
    ),
    "ecosystem": (
        "Ecosystem foundation",
        "Independent authors or operators depend on a sustained family of integrations and contracts.",
        "Inspect independent consumers, compatibility commitments, evolution, ownership and retirement evidence.",
    ),
}
_READINESS = {
    "sketch": "Purpose or design is described; a coherent implementation is not established.",
    "prototype": "Some important paths are implemented; completeness and validation remain limited.",
    "working": "The primary useful workflow is supported by applicable implementation and validation evidence.",
    "dependable": "Important failures and repeatable changes have credible protection for the intended scope.",
    "operated": "Applicable release, diagnosis, support and recovery have operational evidence.",
    "proven": "Repeated independent change or operating evidence supports the claimed reliability and commitments.",
}
_BASIS_LABELS = {
    "user_stated": "User-stated",
    "project_documented": "Project-documented",
    "inferred": "Inferred · provisional",
    "unknown": "Unknown",
}
_DIRECTION_LABELS = {
    "maintain": "Maintain fit",
    "strengthen": "Strengthen needed capability",
    "simplify": "Reduce unnecessary burden",
    "rebalance": "Strengthen and simplify",
    "clarify": "Clarify purpose or evidence",
    "investigate": "Investigate before changing",
}
_CAVEAT = (
    "Milestones describe scope and readiness, not project age, business value or an overall quality score. "
    "A dependable personal utility may be complete for its purpose. Larger scope is not automatically better. "
    "Source declarations do not establish real users, successful execution or operational effectiveness."
)
_PROFILE_NOTE = (
    "Purpose guides proportionate recommendations. Numeric profiles and targets remain user choices; "
    "this context neither infers nor saves them."
)
_TEXT = {"type": "string", "minLength": 1, "maxLength": 12000, "pattern": r"\S"}
_TEXTS = {"type": "array", "items": _TEXT, "maxItems": 30}
_IDS = {
    "type": "array",
    "maxItems": 200,
    "uniqueItems": True,
    "items": {"type": "string", "minLength": 1, "maxLength": 200, "pattern": r"\S"},
}
_CONFIDENCE = {"enum": ["low", "medium", "high"]}


def _object(properties):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


PROJECT_CONTEXT_SCHEMA = _object(
    {
        "schema_version": {"const": 1},
        "current": _object(
            {
                "milestone": {"enum": [None, *_MILESTONES]},
                "readiness": {"enum": [None, *_READINESS]},
                "confidence": _CONFIDENCE,
                "rationale": _TEXT,
                "evidence_ids": _IDS,
            }
        ),
        "intended": _object(
            {
                "milestone": {"enum": [None, *_MILESTONES]},
                "basis": {"enum": list(_BASIS_LABELS)},
                "confidence": _CONFIDENCE,
                "statement": _TEXT,
                "attribution": {"anyOf": [_TEXT, {"type": "null"}]},
                "evidence_ids": _IDS,
                "alternatives": _TEXTS,
                "limitations": _TEXTS,
            }
        ),
        "alignment": _object(
            {
                "direction": {
                    "enum": ["maintain", "strengthen", "simplify", "rebalance", "clarify"]
                },
                "rationale": _TEXT,
                "priorities": {
                    "type": "array",
                    "maxItems": len(DIMENSIONS),
                    "items": _object(
                        {
                            "dimension": {"enum": list(DIMENSIONS)},
                            "direction": {
                                "enum": [
                                    "strengthen",
                                    "simplify",
                                    "rebalance",
                                    "maintain",
                                    "investigate",
                                ]
                            },
                            "rationale": _TEXT,
                            "initiative_ids": {
                                "type": "array",
                                "maxItems": 100,
                                "uniqueItems": True,
                                "items": {
                                    "type": "string",
                                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$",
                                },
                            },
                        }
                    ),
                },
                "deferred": _TEXTS,
            }
        ),
    }
)


def project_context_rubric():
    """Return scope landmarks and independent readiness anchors, never score defaults."""
    return {
        "schema_version": 1,
        "version": VERSION,
        "milestones": {
            key: {"label": label, "description": description, "evidence": evidence}
            for key, (label, description, evidence) in _MILESTONES.items()
        },
        "readiness": {
            key: {"label": key.capitalize(), "description": description}
            for key, description in _READINESS.items()
        },
        "intent_precedence": ["user_stated", "project_documented", "inferred", "unknown"],
        "guidance": [
            "Landmarks can branch or remain a final destination; commerce is not a prerequisite for a platform.",
            "Separate present support from aspiration; a prototype targeting a platform is not already a proven platform.",
            "Infer intent provisionally from applicable documentation, callers and workflows; retain alternatives and contrary evidence.",
            "Current user intent overrides repository claims. A README is documented intent, not live adoption or runtime proof.",
            "Preserve an explicitly chosen destination even when current code serves a smaller scope; explain the gap. Audience or importance alone does not confirm an exact milestone.",
            "Rank applicable critical obligations, blocked valuable work and demonstrated burden before speculative growth. Preserve important personal data and security regardless of audience size.",
            "Do not derive milestones or readiness from file counts, dependency choices, age, revenue or test percentages.",
        ],
        "caveat": _CAVEAT,
        "profile_note": _PROFILE_NOTE,
    }


def validate_project_context(context, evidence_ids, plan=None):
    """Validate authored context references; neither authenticate intent nor infer grades."""
    errors = sorted(
        Draft202012Validator(PROJECT_CONTEXT_SCHEMA).iter_errors(context),
        key=lambda e: list(map(str, e.path)),
    )
    if errors:
        error = errors[0]
        path = ".".join(map(str, error.absolute_path)) or "<document>"
        raise ValueError(f"Invalid project context at {path}: violates {error.validator}")
    captured = set(evidence_ids)
    current, intended = context["current"], context["intended"]
    for row in (current, intended):
        if not set(row["evidence_ids"]) <= captured:
            raise ValueError("Project context cites evidence outside its captured snapshot")
    if (current["milestone"] is not None or current["readiness"] is not None) and not current[
        "evidence_ids"
    ]:
        raise ValueError("Known current milestone or readiness must cite captured evidence")
    if intended["basis"] == "user_stated" and not intended["attribution"]:
        raise ValueError("User-stated intent needs explicit attribution")
    if intended["basis"] in {"inferred", "project_documented"} and not intended["evidence_ids"]:
        raise ValueError("Inferred or documented intent must cite captured evidence")
    if intended["basis"] == "unknown" and intended["milestone"] is not None:
        raise ValueError("Unknown intended purpose must retain an unknown milestone")
    priorities = context["alignment"]["priorities"]
    if len({row["dimension"] for row in priorities}) != len(priorities):
        raise ValueError("Project context priorities must have unique dimensions")
    initiatives = {row["id"]: row for row in (plan or {}).get("initiatives", [])}
    for row in priorities:
        if not set(row["initiative_ids"]) <= initiatives.keys():
            raise ValueError("Project context priorities cite unknown plan initiatives")
        if any(
            row["dimension"] not in initiatives[identity].get("dimension_impacts", {})
            for identity in row["initiative_ids"]
        ):
            raise ValueError("Linked initiatives must declare the priority dimension impact")


def project_context_template():
    """Return an unjudged template; adding the field does not establish maturity."""
    return {
        "schema_version": 1,
        "current": {
            "milestone": None,
            "readiness": None,
            "confidence": "low",
            "rationale": "No evidence-backed scope/readiness judgment is recorded.",
            "evidence_ids": [],
        },
        "intended": {
            "milestone": None,
            "basis": "unknown",
            "confidence": "low",
            "statement": "Intended purpose is not established.",
            "attribution": None,
            "evidence_ids": [],
            "alternatives": [],
            "limitations": ["No intended-purpose review is recorded."],
        },
        "alignment": {
            "direction": "clarify",
            "rationale": "Review purpose and current scope before claiming a maturity fit or growth requirement.",
            "priorities": [],
            "deferred": [],
        },
    }


def project_context_assessment(assessment, review, goals=None):
    """Read saved context without mutating records, guessing stages or saving goals."""
    review = review or {}
    raw = review.get("project_context")
    context, status, gaps = project_context_template(), "unestablished", []
    if raw is not None:
        try:
            validate_project_context(
                raw, {row["id"] for row in assessment.get("evidence", [])}, review.get("plan")
            )
        except ValueError:
            gaps.append(
                "Recorded project context is unsupported or inconsistent; review it against this snapshot before relying on it."
            )
        else:
            context = deepcopy(raw)
            if (
                context["current"]["milestone"] is not None
                or context["current"]["readiness"] is not None
                or context["intended"]["basis"] != "unknown"
                or context["alignment"]["direction"] != "clarify"
                or context["alignment"]["priorities"]
            ):
                status = "recorded"
    current, intended, alignment = context["current"], context["intended"], context["alignment"]
    current["milestone_label"] = (
        _MILESTONES[current["milestone"]][0] if current["milestone"] else "Unknown"
    )
    current["readiness_label"] = (
        current["readiness"].capitalize() if current["readiness"] else "Unknown"
    )
    intended["milestone_label"] = (
        _MILESTONES[intended["milestone"]][0] if intended["milestone"] else "Unknown"
    )
    intended["basis_label"] = _BASIS_LABELS[intended["basis"]]
    alignment["direction_label"] = _DIRECTION_LABELS[alignment["direction"]]
    for row in alignment["priorities"]:
        row["dimension_label"] = (
            "Performance & Scalability"
            if row["dimension"] == "performance"
            else row["dimension"].capitalize()
        )
        row["direction_label"] = _DIRECTION_LABELS[row["direction"]]
    return {
        **context,
        "version": VERSION,
        "status": status,
        "scope": review.get("coverage", {}).get("scope", "unknown"),
        "saved_goal_revision": (goals or {}).get("revision"),
        "no_numeric_goals_autosaved": True,
        "profile_note": _PROFILE_NOTE,
        "caveat": _CAVEAT,
        "gaps": gaps,
    }
