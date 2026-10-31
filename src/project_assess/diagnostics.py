"""Bounded import of located SARIF 2.1 diagnostics, never tool or fix execution."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

MAX_DIAGNOSTICS = 2000
MAX_RUNS = 100
MAX_BYTES = 16 * 1024 * 1024
_IDENTITY_GAP = (
    "Supplied SARIF diagnostics have unverified source identity, producer configuration "
    "and rule scope; producer levels are claims and zero diagnostics is not a clean-project rating"
)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate SARIF JSON key")
        result[key] = value
    return result


def _nonfinite(_):
    raise ValueError("Nonfinite SARIF JSON")


def _path(uri, root, manifest_paths):
    if not isinstance(uri, str) or not uri or len(uri) > 8192:
        return None
    try:
        parsed = urlsplit(uri)
        if parsed.scheme not in {"", "file"} or parsed.netloc or parsed.query or parsed.fragment:
            return None
        if parsed.scheme == "file" and not parsed.path.startswith("/"):
            return None
        value = unquote(parsed.path, errors="strict")
    except (ValueError, UnicodeError):
        return None
    if "\x00" in value or "\\" in value or ".." in value.split("/") or value.startswith("//"):
        return None
    path = PurePosixPath(value)
    if path.is_absolute():
        try:
            path = path.relative_to(PurePosixPath(root.as_posix()))
        except ValueError:
            return None
    relative = path.as_posix()
    return relative if relative in manifest_paths else None


def sarif_report(payload: bytes, root: Path, manifest_paths: set[str], redact) -> dict:
    """Retain literal text and the first explicit source location of each result.

    This intentionally supports a located subset of SARIF. It does not resolve
    URI bases, artifact indexes, localized messages or external property files.
    Those omissions remain explicit rather than fetching or guessing source.
    """
    diagnostics, gaps = [], {_IDENTITY_GAP}
    result = {
        "schema_version": 1,
        "source_identity": "unverified",
        "status": "partial",
        "summary": {"diagnostics": 0, "supplied": 0, "runs": 0, "results_examined": 0},
        "diagnostics": diagnostics,
        "gaps": [],
        "limits": {
            "bytes": MAX_BYTES,
            "runs": MAX_RUNS,
            "diagnostics": MAX_DIAGNOSTICS,
            "message_characters": 500,
            "tool_characters": 128,
            "code_characters": 128,
        },
    }
    try:
        if len(payload) > MAX_BYTES:
            raise ValueError("SARIF byte limit exceeded")
        document = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if (
            not isinstance(document, dict)
            or document.get("version") != "2.1.0"
            or not isinstance(document.get("runs"), list)
        ):
            raise ValueError("Unsupported SARIF document")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        result["gaps"] = sorted(
            gaps
            | {"Malformed, oversized or unsupported SARIF 2.1.0 report; no diagnostics imported"}
        )
        return result
    partial = bool(document.get("inlineExternalProperties"))
    if partial:
        gaps.add(
            "SARIF inline external properties were not resolved; their diagnostics remain unknown"
        )
    runs = document["runs"]
    result["summary"]["runs"] = len(runs)
    if len(runs) > MAX_RUNS:
        gaps.add("SARIF run limit reached; remaining runs were not inspected")
        partial = True
    for run in runs[:MAX_RUNS]:
        if not isinstance(run, dict):
            gaps.add("Malformed SARIF run omitted")
            partial = True
            continue
        tool = run.get("tool", {}).get("driver") if isinstance(run.get("tool"), dict) else None
        name = tool.get("name") if isinstance(tool, dict) else None
        rows = run.get("results", [])
        if not isinstance(name, str) or not name or not isinstance(rows, list):
            gaps.add("Malformed SARIF tool or results omitted")
            partial = True
            continue
        safe_name = redact(name)[:128]
        result["summary"]["supplied"] += len(rows)
        if run.get("externalPropertyFileReferences"):
            gaps.add(
                "SARIF external property files were not loaded; their diagnostics remain unknown"
            )
            partial = True
        remaining = MAX_DIAGNOSTICS - result["summary"]["results_examined"]
        if len(rows) > remaining:
            gaps.add("SARIF diagnostic traversal limit reached; remaining results omitted")
            partial = True
        for row in rows[:remaining]:
            result["summary"]["results_examined"] += 1
            if not isinstance(row, dict):
                gaps.add("Malformed SARIF result omitted")
                partial = True
                continue
            code, message, level = row.get("ruleId"), row.get("message"), row.get("level")
            text = message.get("text") if isinstance(message, dict) else None
            locations = row.get("locations")
            if (
                not isinstance(code, str)
                or not code
                or not isinstance(text, str)
                or not text
                or not isinstance(locations, list)
                or not locations
            ):
                gaps.add(
                    "SARIF results without a rule, literal text or explicit location were omitted"
                )
                partial = True
                continue
            if len(locations) > 1:
                gaps.add("Only the first SARIF result location was retained")
                partial = True
            location = locations[0]
            physical = location.get("physicalLocation") if isinstance(location, dict) else None
            artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
            region = physical.get("region") if isinstance(physical, dict) else None
            if (
                not isinstance(artifact, dict)
                or artifact.get("uriBaseId") is not None
                or artifact.get("index") is not None
            ):
                gaps.add(
                    "SARIF artifact indexes, URI bases or missing physical locations are unsupported"
                )
                partial = True
                continue
            path = _path(artifact.get("uri"), root, manifest_paths)
            if path is None:
                gaps.add(
                    "SARIF location outside captured source scope or unsupported URI was omitted"
                )
                partial = True
                continue
            line = region.get("startLine") if isinstance(region, dict) else None
            end = region.get("endLine", line) if isinstance(region, dict) else None
            if (
                type(line) is not int
                or not 1 <= line <= 2_147_483_647
                or type(end) is not int
                or not line <= end <= 2_147_483_647
            ):
                gaps.add("SARIF result without a supported positive source line range was omitted")
                partial = True
                continue
            if level is not None and (
                not isinstance(level, str) or level not in {"none", "note", "warning", "error"}
            ):
                gaps.add("Unsupported SARIF producer level retained as unknown")
                level = None
                partial = True
            if message.get("arguments") or message.get("id"):
                gaps.add("SARIF message arguments and localized references were not expanded")
                partial = True
            diagnostics.append(
                {
                    "tool": safe_name,
                    "code": redact(code)[:128],
                    "producer_level": level,
                    "message": redact(text)[:500],
                    "path": path,
                    "line": line,
                    "end_line": end,
                }
            )
    diagnostics.sort(
        key=lambda row: (row["path"], row["line"], row["tool"], row["code"], row["message"])
    )
    result["summary"]["diagnostics"] = len(diagnostics)
    result["gaps"] = sorted(gaps)
    result["status"] = "partial" if partial else "complete"
    return result
