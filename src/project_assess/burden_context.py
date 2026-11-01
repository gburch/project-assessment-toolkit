"""Bounded attributable change experience, separate from execution measurements."""

from __future__ import annotations

import json
from datetime import date, datetime

from jsonschema import Draft202012Validator

from .report_identity import match_source_identity, normalize_report_path
from .rubric import DIMENSIONS

SCHEMA = "pat.burden-context.v1"
MAX_BYTES = 256 * 1024
_TEXT = {"type": "string", "minLength": 1, "maxLength": 1000, "pattern": r"\S"}
_PATH = {"type": "string", "minLength": 1, "maxLength": 4096}
_PATHS = {"type": "array", "maxItems": 128, "items": _PATH}
_DATE = {"anyOf": [{"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"}, {"type": "null"}]}


def _object(properties, required=None):
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties) if required is None else required,
    }


_EXAMPLE = _object({"change": _TEXT, "hurdle": _TEXT, "impact": _TEXT, "paths": _PATHS})
_DURATION = _object(
    {
        "seconds": {"type": "number", "minimum": 0, "maximum": 31_536_000},
        "semantics": {
            "enum": ["wall_elapsed", "blocked_wait", "active_effort", "summed_test_elapsed", "cpu"]
        },
        "precision": {"enum": ["approximate", "reported_measurement"]},
    }
)
_CLAIM = _object(
    {
        "dimensions": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(DIMENSIONS),
            "uniqueItems": True,
            "items": {"enum": list(DIMENSIONS)},
        },
        "statement": _TEXT,
        "frequency": {
            "enum": ["unknown", "isolated", "some_changes", "most_changes", "all_changes"]
        },
        "workflow_stage": {
            "enum": [
                "focused_iteration",
                "required_gate",
                "setup",
                "queue_wait",
                "rerun",
                "recovery",
                "mixed",
                "unknown",
            ]
        },
        "completion": {"enum": ["complete", "partial", "unknown"]},
        "duration": _DURATION,
        "examples": {"type": "array", "maxItems": 8, "items": _EXAMPLE},
    },
    required=["dimensions", "statement", "frequency", "workflow_stage", "completion"],
)
_DOCUMENT = _object(
    {
        "schema": {"const": SCHEMA},
        "reported_at": {"type": "string", "minLength": 1, "maxLength": 100},
        "attribution": _object(
            {
                "role": {"enum": ["maintainer", "contributor", "reviewer", "other"]},
                "label": {**_TEXT, "maxLength": 200},
            }
        ),
        "source": _object(
            {
                "revision": {
                    "anyOf": [
                        {"type": "string", "pattern": "^[0-9a-f]{40}(?:[0-9a-f]{24})?$"},
                        {"type": "null"},
                    ]
                },
                "files": {
                    "type": "array",
                    "maxItems": 256,
                    "items": _object(
                        {
                            "path": _PATH,
                            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                        }
                    ),
                },
            }
        ),
        "period": _object({"start": _DATE, "end": _DATE}),
        "scope": _object({"label": _TEXT, "paths": _PATHS}),
        "claims": {"type": "array", "minItems": 1, "maxItems": 64, "items": _CLAIM},
        "limitations": {"type": "array", "minItems": 1, "maxItems": 30, "items": _TEXT},
    }
)


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _paths(values):
    paths = [normalize_report_path(value) for value in values]
    if len(paths) != len(set(paths)):
        raise ValueError("Burden context paths must be unique")
    return paths


def import_burden_context(payload, manifest, revision, redact=lambda value: value):
    """Retain supplied experience and semantics without authenticating its claims."""
    if len(payload) > MAX_BYTES:
        raise ValueError("Burden context byte bound exceeded")
    try:
        data = json.loads(
            payload,
            object_pairs_hook=_unique_fields,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite number")),
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Malformed burden context JSON") from exc
    if not Draft202012Validator(_DOCUMENT).is_valid(data):
        raise ValueError("Unsupported burden context schema or fields")
    try:
        instant = datetime.fromisoformat(data["reported_at"].replace("Z", "+00:00"))
        if instant.utcoffset() is None:
            raise ValueError("Missing timestamp offset")
    except ValueError as exc:
        raise ValueError("Burden context report timestamp requires ISO8601 timezone") from exc
    try:
        start, end = (
            date.fromisoformat(data["period"][key]) if data["period"][key] else None
            for key in ("start", "end")
        )
        if start is not None and end is not None and start > end:
            raise ValueError("Reversed period")
    except ValueError as exc:
        raise ValueError(
            "Burden context experience period requires ordered ISO dates or null"
        ) from exc
    _paths([row["path"] for row in data["source"]["files"]])
    scope_paths = _paths(data["scope"]["paths"])
    claims = []
    for index, claim in enumerate(data["claims"]):
        examples = []
        for example in claim.get("examples", []):
            paths = _paths(example["paths"])
            if scope_paths and not set(paths) <= set(scope_paths):
                raise ValueError("Burden context example paths must belong to declared scope")
            examples.append(
                {
                    **{key: redact(example[key]) for key in ("change", "hurdle", "impact")},
                    "paths": [redact(path) for path in paths],
                }
            )
        claims.append(
            {
                "index": index,
                "dimensions": claim["dimensions"],
                "statement": redact(claim["statement"]),
                "frequency": claim["frequency"],
                "frequency_scope": "joint_claim",
                "workflow_stage": claim["workflow_stage"],
                "completion": claim["completion"],
                **({"duration": claim["duration"]} if "duration" in claim else {}),
                "examples": examples,
            }
        )
    identity, coverage = match_source_identity(data["source"], manifest, revision, redact)
    captured_paths = {row["path"] for row in manifest}
    coverage.update(
        claim_count=len(claims),
        example_count=sum(len(claim["examples"]) for claim in claims),
        dimensions=[
            dimension
            for dimension in DIMENSIONS
            if any(dimension in c["dimensions"] for c in claims)
        ],
        scope_paths=len(scope_paths),
        captured_scope_paths=len(set(scope_paths) & captured_paths),
    )
    gaps = [
        "Attribution, report date, experience period, frequency, examples and durations are supplied claims, not independently verified execution or observed effort."
    ]
    if identity["overall"] != "matched":
        gaps.append(
            "Declared source identity is mismatched or not established against this capture"
        )
    if start is None or end is None:
        gaps.append("Experience period is incomplete; recency and applicability need review.")
    if coverage["captured_scope_paths"] < len(scope_paths):
        gaps.append("Some declared scope paths were not captured; scope remains a reported claim.")
    if any(len(claim["dimensions"]) > 1 for claim in claims):
        gaps.append(
            "Multi-dimension frequencies apply jointly; separate dimension frequency is not established."
        )
    if any(claim["frequency"] == "unknown" for claim in claims):
        gaps.append(
            "Some claim frequencies are unknown; recurring cost is not established for those claims."
        )
    if any(
        c.get("duration", {}).get("semantics") in {"cpu", "summed_test_elapsed"} for c in claims
    ):
        gaps.append("CPU and summed test elapsed durations are not wall time or blocked waiting.")
    if any(c["completion"] != "complete" for c in claims):
        gaps.append("Partial or unknown completion cannot establish a complete workflow duration.")
    return "burden-context", {
        "schema": SCHEMA,
        "reported_at": data["reported_at"],
        "attribution": {
            "role": data["attribution"]["role"],
            "label": redact(data["attribution"]["label"]),
        },
        "period": data["period"],
        "scope": {
            "label": redact(data["scope"]["label"]),
            "paths": [redact(p) for p in scope_paths],
        },
        "claims": claims,
        "limitations": [redact(value) for value in data["limitations"]],
        "sourceIdentity": identity,
        "coverage": coverage,
        "gaps": gaps,
        "caveat": "Source identity binds only declared files/revision; it never authenticates a reporter, timing or representative cost. Context does not assign grades, confidence or permission to execute assessed code.",
    }
