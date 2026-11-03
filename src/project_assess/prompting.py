"""Authored behavioral prompt reliance, separate from engineering capability and goals."""

from copy import deepcopy
from re import fullmatch

from jsonschema import Draft202012Validator

from .report_identity import normalize_report_path

VERSION = "1"
_LEVELS = {
    0: (
        "Code-controlled behavior",
        "Explicit code controls the assessed useful workflows without model interpretation; external state or randomness can still vary outputs.",
    ),
    1: (
        "Optional model assistance",
        "Model assistance enriches an otherwise usable deterministic workflow.",
    ),
    2: ("Bounded model step", "A model performs a defined step inside a code-controlled workflow."),
    3: (
        "Hybrid behavior",
        "Prompts and deterministic logic both materially control useful workflows.",
    ),
    4: (
        "Prompt-led workflows",
        "Prompts or agents lead important workflows, with coded tools or boundaries.",
    ),
    5: (
        "Predominantly instruction-defined",
        "The product's useful behavior is primarily defined by prompts, skills or agent instructions.",
    ),
}
_CONTROL_LABELS = {
    "deterministic": "Deterministic logic",
    "hybrid": "Prompts and deterministic logic",
    "prompt_led": "Prompt-led behavior",
    "unknown": "Control not established",
}
_BASIS_LABELS = {
    "user_stated": "User-stated",
    "project_documented": "Project-documented",
    "inferred": "Inferred · provisional",
    "unknown": "Unknown",
}
_VARIABILITY_LABELS = {
    "unknown": "Output variability unknown",
    "source_controls_only": "Source controls identified; variability unmeasured",
    "observed_variable": "Variation reported in the observed scenario",
    "observed_bounded": "Bounded variation reported in the observed scenario",
    "observed_repeatable": "Repeatability reported in the observed scenario",
}
_DIRECTION_LABELS = {
    "retain": "Retain the intended balance",
    "more_deterministic": "Move suitable behavior into deterministic logic",
    "more_prompt_driven": "Use prompting where flexibility serves the purpose",
    "investigate": "Investigate before changing the balance",
}
_CAVEAT = (
    "Behavioral prompt reliance is a descriptive project characteristic, not a quality grade, "
    "AI-authorship estimate or percentage of code produced by AI. Development guidance alone "
    "does not establish product behavior; a host-run skill can itself be the product. "
    "Prompt-led behavior can fit the intended purpose. Source controls, typed outputs and "
    "temperature settings do not establish repeatable outcomes. Observations remain supplied "
    "claims; matching source identity does not authenticate execution or prove future results."
)
_PROFILE_NOTE = (
    "The intended reliance range is authored context, not a saved capability target. "
    "Changing it establishes no engineering progress and never writes numerical goals."
)
_TEXT = {"type": "string", "minLength": 1, "maxLength": 12000, "pattern": r"\S"}
_IDS = {
    "type": "array",
    "maxItems": 200,
    "uniqueItems": True,
    "items": {"type": "string", "minLength": 1, "maxLength": 200, "pattern": r"\S"},
}
_LEVEL = {"type": ["integer", "null"], "minimum": 0, "maximum": 5}


def _object(properties):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


PROMPTING_SCHEMA = _object(
    {
        "schema_version": {"const": 1},
        "level": _LEVEL,
        "confidence": {"enum": ["low", "medium", "high"]},
        "rationale": _TEXT,
        "evidence_ids": _IDS,
        "workflows": {
            "type": "array",
            "maxItems": 30,
            "items": _object(
                {
                    "name": _TEXT,
                    "control": {"enum": list(_CONTROL_LABELS)},
                    "rationale": _TEXT,
                    "evidence_ids": _IDS,
                }
            ),
        },
        "variability": _object(
            {
                "status": {"enum": list(_VARIABILITY_LABELS)},
                "rationale": _TEXT,
                "evidence_ids": _IDS,
            }
        ),
        "intent": _object(
            {
                "min": _LEVEL,
                "max": _LEVEL,
                "basis": {"enum": list(_BASIS_LABELS)},
                "rationale": _TEXT,
                "evidence_ids": _IDS,
            }
        ),
        "recommendations": {
            "type": "array",
            "maxItems": 10,
            "items": _object(
                {
                    "direction": {"enum": list(_DIRECTION_LABELS)},
                    "action": _TEXT,
                    "rationale": _TEXT,
                    "evidence_ids": _IDS,
                }
            ),
        },
    }
)


def prompting_rubric():
    """Return descriptive anchors and review questions, never score defaults."""
    return {
        "schema_version": 1,
        "version": VERSION,
        "name": "Behavioral prompt reliance",
        "levels": {
            str(level): {"label": label, "description": description}
            for level, (label, description) in _LEVELS.items()
        },
        "questions": [
            "Which useful workflows are controlled by code, model interpretation or both? Include host-agent products and skills when they deliver the product's behavior.",
            "Are skills merely development guidance, or do users depend on their instructions to deliver the actual product workflow?",
            "Where are model outputs advisory, validated, transformed into actions or allowed to change durable state?",
            "Which deterministic boundaries protect outcomes, and which only constrain syntax?",
            "Is output variation acceptable or valuable for the intended purpose? Which supplied same-scenario observations actually measure it?",
            "Could code reduce costly prompt interpretation in a stable rule, or could prompting remove unnecessary custom machinery for a flexible task?",
        ],
        "guidance": [
            "Do not compute a reliance level from file, prompt, token, SDK, instruction or test counts. Record representative workflows and contrary evidence.",
            "Existing AI development instructions do not establish runtime or product reliance. Repository contents do not establish AI authorship.",
            "High reliance may be appropriate for a creative assistant or agent product; deterministic logic may fit stable exact transformations. Match the intended purpose and consequences of variation.",
            "JSON schemas, validation, retries, model pins, seeds and temperature zero are source controls, not measured repeatability or correctness.",
            "For observed variability, cite a source-matched prompting observation and inspect its input, model/configuration, repeat-run scenario, results and limitations. Presence of a report does not verify it.",
            "An intended range may be provisional. Do not save or silently modify capability targets, or treat a context edit as engineering progress.",
            "Recommendations can move either direction or retain the balance. Preserve useful variability, necessary deterministic protection and the selected capability minimums.",
        ],
        "caveat": _CAVEAT,
        "profile_note": _PROFILE_NOTE,
    }


def prompting_template():
    """Create an unjudged profile without inventing a preferred level."""
    return {
        "schema_version": 1,
        "level": None,
        "confidence": "low",
        "rationale": "Behavioral prompt reliance has not been reviewed.",
        "evidence_ids": [],
        "workflows": [],
        "variability": {
            "status": "unknown",
            "rationale": "No applicable repeat-run evidence is recorded.",
            "evidence_ids": [],
        },
        "intent": {
            "min": None,
            "max": None,
            "basis": "unknown",
            "rationale": "The intended balance has not been established.",
            "evidence_ids": [],
        },
        "recommendations": [],
    }


def _evidence_by_id(evidence):
    if isinstance(evidence, dict):
        return {key: value if isinstance(value, dict) else {} for key, value in evidence.items()}
    return {row["id"]: row for row in evidence if isinstance(row, dict) and "id" in row} | {
        row: {} for row in evidence if isinstance(row, str)
    }


def _has_observed_prompting_result(entry, status, workflow_paths):
    stats = entry.get("stats", {})
    if entry.get("kind") != "observation" or not isinstance(stats, dict):
        return False
    identity, results = stats.get("sourceIdentity"), stats.get("results")
    if not (
        stats.get("type") == "prompting"
        and isinstance(identity, dict)
        and identity.get("overall") == "matched"
        and isinstance(results, list)
        and any(
            isinstance(row, dict) and row.get("status") in {"observed", "passed", "failed"}
            for row in results
        )
    ):
        return False
    repeated = stats.get("prompting")
    scenario = stats.get("scenario")
    if not isinstance(repeated, dict) or not isinstance(scenario, dict):
        return False
    if not all(
        isinstance(repeated.get(key), str) and fullmatch(r"sha256:[0-9a-f]{64}", repeated[key])
        for key in ("input_digest", "configuration_digest")
    ):
        return False
    trials, distinct = repeated.get("trials"), repeated.get("distinct_outputs")
    if (
        type(trials) is not int
        or not 2 <= trials <= 1000000
        or type(distinct) is not int
        or not 1 <= distinct <= trials
        or repeated.get("comparison") not in {"exact", "semantic"}
        or not isinstance(repeated.get("criterion"), str)
        or not repeated["criterion"].strip()
    ):
        return False
    scope = scenario.get("scope")
    if not isinstance(scope, list):
        return False
    try:
        scoped_paths = {normalize_report_path(path) for path in scope}
    except (TypeError, ValueError):
        return False
    if not scoped_paths.intersection(workflow_paths):
        return False
    if status == "observed_variable":
        return distinct > 1
    if status == "observed_repeatable":
        return repeated["comparison"] == "exact" and distinct == 1
    return repeated["comparison"] == "semantic" and any(
        isinstance(row, dict)
        and row.get("name") == "within_criterion"
        and row.get("value") is True
        and row.get("status") in {"observed", "passed"}
        for row in results
    )


def validate_prompting(value, evidence):
    """Validate attribution and observation boundaries, not the authored interpretation."""
    errors = sorted(
        Draft202012Validator(PROMPTING_SCHEMA).iter_errors(value),
        key=lambda error: list(map(str, error.path)),
    )
    if errors:
        error = errors[0]
        path = ".".join(map(str, error.absolute_path)) or "<document>"
        raise ValueError(f"Invalid prompting profile at {path}: violates {error.validator}")
    for level in (value["level"], value["intent"]["min"], value["intent"]["max"]):
        if level is not None and type(level) is not int:
            raise ValueError("Prompting reliance levels must be integer rubric steps")
    by_id = _evidence_by_id(evidence)
    rows = [
        value,
        value["variability"],
        value["intent"],
        *value["workflows"],
        *value["recommendations"],
    ]
    if any(not set(row["evidence_ids"]) <= by_id.keys() for row in rows):
        raise ValueError("Prompting profile cites evidence outside its captured snapshot")
    known_workflows = [row for row in value["workflows"] if row["control"] != "unknown"]
    if any(not row["evidence_ids"] for row in known_workflows):
        raise ValueError("Known workflow control must cite captured evidence")
    if value["level"] is not None and (not value["evidence_ids"] or not known_workflows):
        raise ValueError("Known prompting reliance requires cited representative workflows")
    if value["level"] == 0 and any(row["control"] != "deterministic" for row in known_workflows):
        raise ValueError(
            "Code-controlled reliance conflicts with a model-involved product workflow"
        )
    if (
        value["level"] is not None
        and value["level"] > 0
        and not any(row["control"] in {"hybrid", "prompt_led"} for row in known_workflows)
    ):
        raise ValueError("Model reliance requires a cited model-involved product workflow")
    names = [row["name"].casefold().strip() for row in value["workflows"]]
    if len(names) != len(set(names)):
        raise ValueError("Prompting workflow names must be distinct")
    intent = value["intent"]
    minimum, maximum = intent["min"], intent["max"]
    if minimum is not None and maximum is not None and minimum > maximum:
        raise ValueError("Intended prompting range is inverted")
    if intent["basis"] == "unknown" and (minimum is not None or maximum is not None):
        raise ValueError("Unknown prompting intent must retain an unknown range")
    if intent["basis"] in {"inferred", "project_documented"} and not intent["evidence_ids"]:
        raise ValueError("Inferred or documented prompting intent must cite captured evidence")
    variability = value["variability"]
    if variability["status"] == "source_controls_only" and not variability["evidence_ids"]:
        raise ValueError("Source variability controls must cite captured evidence")
    if variability["status"].startswith("observed_"):
        observations = [by_id[identity] for identity in variability["evidence_ids"]]
        workflow_paths = set()
        for workflow in known_workflows:
            for identity in workflow["evidence_ids"]:
                path = by_id[identity].get("path")
                if path is not None:
                    try:
                        workflow_paths.add(normalize_report_path(path))
                    except (TypeError, ValueError):
                        pass
        if not any(
            _has_observed_prompting_result(row, variability["status"], workflow_paths)
            for row in observations
        ):
            raise ValueError(
                "Observed variability requires a source-matched prompting observation with "
                "consistent repeat-run results scoped to a cited known workflow"
            )
    if any(
        not row["evidence_ids"]
        for row in value["recommendations"]
        if row["direction"] != "investigate"
    ):
        raise ValueError("Prompting recommendations must cite supporting captured evidence")


def _collection(assessment):
    summary = assessment.get("facts", {}).get("prompting")
    empty = {
        "status": "not_collected",
        "evidence_id": None,
        "summary": {},
        "coverage": {},
        "gaps": ["Prompting evidence was not collected for this snapshot; rescan to capture it."],
        "caveat": _CAVEAT,
    }
    if summary is None:
        return empty
    if not isinstance(summary, dict):
        return {
            **empty,
            "status": "unsupported",
            "gaps": ["Captured prompting summary is unsupported."],
        }
    entry = next(
        (
            row
            for row in assessment.get("evidence", [])
            if row.get("id") == summary.get("evidence_id")
            and row.get("kind") == "prompting-analysis"
        ),
        None,
    )
    stats = (entry or {}).get("stats", {})
    stats = stats if isinstance(stats, dict) else {}
    if (
        type(summary.get("schema_version")) is not int
        or summary.get("schema_version") != 1
        or type(stats.get("schema_version")) is not int
        or stats.get("schema_version") != 1
    ):
        return {
            **empty,
            "status": "unsupported",
            "evidence_id": summary.get("evidence_id"),
            "gaps": [
                "Captured prompting evidence is missing or unsupported; rescan with a compatible collector."
            ],
        }
    return {
        "status": stats.get("status", "unsupported"),
        "evidence_id": entry["id"],
        "summary": deepcopy(stats.get("summary", {})),
        "coverage": {
            key: deepcopy(value)
            for key, value in stats.get("coverage", {}).items()
            if key != "files"
        }
        | {"files_retained_in_evidence": len(stats.get("coverage", {}).get("files", []))},
        "gaps": list(stats.get("gaps", [])),
        "caveat": stats.get("caveat", _CAVEAT),
    }


def _fit(level, intent):
    provisional = intent["basis"] == "inferred"
    result = {
        "status": "unestablished",
        "label": "Behavioral prompt reliance unknown",
        "direction": "investigate",
        "gap": None,
        "provisional": provisional,
    }
    if level is None:
        return result
    minimum, maximum = intent["min"], intent["max"]
    if minimum is None and maximum is None:
        return {**result, "status": "unconfigured", "label": "Intended balance not established"}
    if minimum is not None and level < minimum:
        return {
            **result,
            "status": "below_range",
            "label": "Below the intended reliance range",
            "direction": "more_prompt_driven",
            "gap": minimum - level,
        }
    if maximum is not None and level > maximum:
        return {
            **result,
            "status": "above_range",
            "label": "Above the intended reliance range",
            "direction": "more_deterministic",
            "gap": level - maximum,
        }
    return {
        **result,
        "status": "aligned",
        "label": "Within the intended reliance range",
        "direction": "retain",
        "gap": 0,
    }


def prompting_profile(assessment, review=None):
    """Project a saved profile without inferring reliance, writing goals or rereading source."""
    profile, status, gaps = prompting_template(), "unestablished", []
    raw = (review or {}).get("prompting")
    if raw is not None:
        try:
            validate_prompting(raw, assessment.get("evidence", []))
        except ValueError:
            gaps.append(
                "Recorded prompting profile is unsupported or inconsistent with this snapshot; review it before relying on it."
            )
        else:
            profile = deepcopy(raw)
            if (
                profile["level"] is not None
                or profile["workflows"]
                or profile["recommendations"]
                or profile["intent"]["basis"] != "unknown"
                or profile["variability"]["status"] != "unknown"
            ):
                status = "recorded"
    profile["level_label"] = (
        _LEVELS[profile["level"]][0] if profile["level"] is not None else "Unknown"
    )
    for row in profile["workflows"]:
        row["control_label"] = _CONTROL_LABELS[row["control"]]
    profile["variability"]["label"] = _VARIABILITY_LABELS[profile["variability"]["status"]]
    profile["intent"].update(
        basis_label=_BASIS_LABELS[profile["intent"]["basis"]],
        provisional=profile["intent"]["basis"] == "inferred",
    )
    for row in profile["recommendations"]:
        row["direction_label"] = _DIRECTION_LABELS[row["direction"]]
    return {
        **profile,
        "version": VERSION,
        "name": "Behavioral prompt reliance",
        "status": status,
        "fit": _fit(profile["level"], profile["intent"]),
        "collection": _collection(assessment),
        "no_numeric_goals_autosaved": True,
        "no_engineering_progress_inferred": True,
        "profile_note": _PROFILE_NOTE,
        "caveat": _CAVEAT,
        "gaps": gaps,
    }
