"""Strict, bounded imports of existing observations; identity is separate from truth."""

from __future__ import annotations

import json
from datetime import datetime

from jsonschema import Draft202012Validator

from .report_identity import match_source_identity, normalize_report_path

SCHEMA = "pat.observation.v1"
MAX_BYTES = 1024 * 1024
_TEXT = {"type": "string", "minLength": 1, "maxLength": 1000}
_PATH = {"type": "string", "minLength": 1, "maxLength": 4096}
_SOURCE_FILE = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"path": _PATH, "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}},
    "required": ["path", "digest"],
}
_DOCUMENT = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "schema": {"const": SCHEMA},
        "type": {
            "enum": [
                "performance",
                "recovery",
                "delivery",
                "change_cost",
                "security",
                "extensibility",
                "prompting",
            ]
        },
        "observed_at": {"type": "string", "maxLength": 100},
        "source": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "revision": {
                    "anyOf": [
                        {"type": "string", "pattern": "^[0-9a-f]{40}(?:[0-9a-f]{24})?$"},
                        {"type": "null"},
                    ]
                },
                "files": {"type": "array", "minItems": 1, "maxItems": 500, "items": _SOURCE_FILE},
            },
            "required": ["revision", "files"],
        },
        "scenario": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "name": _TEXT,
                "scope": {"type": "array", "minItems": 1, "maxItems": 500, "items": _PATH},
            },
            "required": ["name", "scope"],
        },
        "results": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 100},
                    "value": {"type": ["number", "boolean"], "minimum": -1e15, "maximum": 1e15},
                    "unit": {"type": "string", "minLength": 1, "maxLength": 100},
                    "status": {"enum": ["observed", "passed", "failed", "inconclusive"]},
                },
                "required": ["name", "value", "unit", "status"],
            },
        },
        "limitations": {"type": "array", "minItems": 1, "maxItems": 30, "items": _TEXT},
        "prompting": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "input_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "configuration_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "trials": {"type": "integer", "minimum": 2, "maximum": 1000000},
                "distinct_outputs": {"type": "integer", "minimum": 1, "maximum": 1000000},
                "comparison": {"enum": ["exact", "semantic"]},
                "criterion": _TEXT,
            },
            "required": [
                "input_digest",
                "configuration_digest",
                "trials",
                "distinct_outputs",
                "comparison",
                "criterion",
            ],
        },
    },
    "required": ["schema", "type", "observed_at", "source", "scenario", "results", "limitations"],
}


def import_observation(payload, manifest, revision, redact=lambda value: value):
    """Validate declared observations and match only their explicit source scope."""
    if len(payload) > MAX_BYTES:
        raise ValueError("Observation byte bound exceeded")
    try:
        data = json.loads(
            payload, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite number"))
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Malformed observation JSON") from exc
    if not Draft202012Validator(_DOCUMENT).is_valid(data):
        raise ValueError("Unsupported observation schema or fields")
    try:
        instant = datetime.fromisoformat(data["observed_at"].replace("Z", "+00:00"))
        if instant.utcoffset() is None:
            raise ValueError("Missing timestamp offset")
    except ValueError as exc:
        raise ValueError("Observation timestamp requires ISO8601 timezone") from exc
    files = data["source"]["files"]
    if data["type"] == "prompting":
        repeated = data.get("prompting")
        if repeated is None or repeated["distinct_outputs"] > repeated["trials"]:
            raise ValueError("Prompting observations require consistent repeated-scenario metadata")
    elif "prompting" in data:
        raise ValueError("Repeated prompting metadata requires a prompting observation")
    paths = [normalize_report_path(row["path"]) for row in files]
    scope = [normalize_report_path(path) for path in data["scenario"]["scope"]]
    if len(paths) != len(set(paths)) or len(scope) != len(set(scope)):
        raise ValueError("Observation source/scope paths must be unique")
    if not set(scope) <= set(paths):
        raise ValueError("Observation scenario scope needs matching declared file identities")
    identity, coverage = match_source_identity(data["source"], manifest, revision, redact)
    gaps = []
    if identity["overall"] != "matched":
        gaps.append(
            "Declared source identity is mismatched or not established against this capture"
        )
    gaps.append(
        "Observation origin, authorship, reported timestamp, execution and scenario relevance are supplied claims; matching source does not verify them"
    )
    return "observation", {
        "schema": SCHEMA,
        "type": data["type"],
        "observed_at": data["observed_at"],
        "scenario": {
            "name": redact(data["scenario"]["name"]),
            "scope": [redact(path) for path in scope],
        },
        "results": [
            {**row, "name": redact(row["name"]), "unit": redact(row["unit"])}
            for row in data["results"]
        ],
        "limitations": [redact(value) for value in data["limitations"]],
        **(
            {
                "prompting": {
                    **data["prompting"],
                    "criterion": redact(data["prompting"]["criterion"]),
                }
            }
            if "prompting" in data
            else {}
        ),
        "sourceIdentity": identity,
        "coverage": coverage,
        "gaps": gaps,
        "caveat": "An imported observation is evidence for contextual review, not an authenticated result, passing project grade or permission to execute assessed code.",
    }
