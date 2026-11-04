"""Advisory native-analysis deltas; observed leads are neither grades nor closure."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import PurePosixPath

_KINDS = {"static-analysis", "javascript-analysis", "source-analysis"}
_LEGACY_VERSIONS = {
    "project-assess-python-ast": {"1", "2", "3", "4"},
    "project-assess-tree-sitter": {"1", "2", "3", "4"},
    "project-assess-source-text": {"1", "2"},
}
_LEGACY_KINDS = {
    "project-assess-python-ast": {
        "complex_function",
        "loop_io",
        "duplicate_function",
        "near_duplicate_function",
        "duplicate_block",
        "dependency_cycle",
        "shadowed_module",
        "unreachable_statement",
        "unreferenced_module",
        "unused_symbol",
    },
    "project-assess-tree-sitter": {
        "complex_function",
        "near_duplicate_function",
        "unused_symbol",
        "unreachable_statement",
    },
    "project-assess-source-text": {"duplicate_source_file", "duplicate_source_block"},
}
NATIVE_KINDS = (
    "complex_function",
    "dependency_cycle",
    "duplicate_block",
    "duplicate_function",
    "duplicate_source_block",
    "duplicate_source_file",
    "loop_io",
    "near_duplicate_function",
    "redundant_condition",
    "shadowed_module",
    "unreachable_statement",
    "unreferenced_module",
    "unused_symbol",
)
_METRICS = {
    "complex_function": ("decision_points", "control_nesting"),
    "duplicate_function": ("matching_functions",),
    "near_duplicate_function": ("matching_functions",),
    "duplicate_block": ("matching_blocks",),
    "dependency_cycle": ("module_count",),
    "duplicate_source_file": ("matching_locations",),
    "duplicate_source_block": ("matching_locations",),
}
_CAVEAT = (
    "Native candidates are review leads, not defects, project grades or verified fixes. "
    "A disappeared lead is only no longer observed; verified finding closure is separate. "
    "This compares full captured inventories, not only changed lines."
)
_PRESENTATION_GAPS = {
    "Static candidate limit reached; remaining candidates omitted",
    "Generic rich candidate sample is bounded; use the compact index",
    "JavaScript rich candidate sample is bounded; inspect the compact index and module overview",
    "Dynamic imports, runtime alias resolution, actual call frequency and change cost are not established",
}


def _inventory_complete(stats):
    if stats.get("status") == "complete":
        return True
    # A bounded rich presentation is not a truncated compact candidate index.
    # Unknown gaps still fail closed rather than guessing from denominator counts.
    gaps = stats.get("gaps", [])
    return (
        bool(gaps)
        and stats.get("status") == "partial"
        and all(
            gap in _PRESENTATION_GAPS
            or gap.startswith("This Python analyzer excludes JavaScript/TypeScript;")
            or gap.startswith("Language-neutral text evidence does not establish syntax,")
            for gap in gaps
        )
    )


def _providers(assessment):
    providers = {}
    capture_complete = (
        assessment.get("facts", {})
        .get("collection", {})
        .get("supported_text_complete", assessment.get("complete") is True)
    )
    for entry in assessment.get("evidence", []):
        if entry.get("kind") not in _KINDS:
            continue
        stats = entry.get("stats", {})
        name = stats.get("analyzer", {}).get("name", entry["kind"])
        # Duplicate producer records cannot silently overwrite one another.
        if name in providers:
            providers[name]["complete"] = False
            providers[name]["families"] = {}
            providers[name]["duplicate"] = True
            providers[name]["gaps"].append("Duplicate producer evidence; matching is ambiguous")
            continue
        rows = stats.get("candidate_index", stats.get("candidates", []))
        counts = stats.get("candidate_counts", {})
        coverage = stats.get("coverage", {})
        legacy = "candidate_coverage" not in stats and stats.get("analyzer", {}).get(
            "version"
        ) in _LEGACY_VERSIONS.get(name, set())
        families = stats.get("candidate_coverage", {})
        family_schema = (
            isinstance(families, dict)
            and families.get("schema_version") == 1
            and isinstance(families.get("families"), dict)
        )
        eligible = next(
            (
                coverage[key]
                for key in ("python_files", "javascript_files", "source_files")
                if key in coverage
            ),
            None,
        )
        providers[name] = {
            "identity": [stats.get("schema_version"), stats.get("analyzer")],
            "supported": stats.get("schema_version") == 1
            and isinstance(stats.get("analyzer", {}).get("version"), str)
            and (legacy or family_schema),
            "complete": capture_complete
            and (_inventory_complete(stats) or eligible == 0)
            and counts.get("omitted_from_index", 0) == 0
            and (legacy or family_schema),
            "status": stats.get("status", "unknown"),
            "coverage": coverage,
            "gaps": list(stats.get("gaps", [])),
            "rows": rows,
            "edges": stats.get("topology", {}).get("edges", []),
            "families": families,
            "capture_complete": capture_complete,
            "duplicate": False,
            "legacy": legacy,
            "legacy_kinds": {
                "complex_function",
                "loop_io",
                "duplicate_function",
                "dependency_cycle",
            }
            if name == "project-assess-python-ast"
            and stats.get("analyzer", {}).get("version") == "1"
            else _LEGACY_KINDS.get(name, set()),
        }
    return providers


def _key(provider, row):
    metrics = row.get("metrics", {})
    paths = sorted({loc["path"] for loc in row.get("locations", []) if "path" in loc})
    symbol = metrics.get("qualified_symbol") or metrics.get("symbol") or metrics.get("name")
    unestablished = "qualified_symbol" in metrics and (
        not metrics["qualified_symbol"] or metrics.get("identity_complete") is not True
    )
    # No source line numbers, evidence hashes or numeric measurements in the key:
    # moving code or increasing complexity must not reset its identity.
    if unestablished:
        symbol = None
    anchor = (
        [symbol, metrics.get("reason")]
        if symbol
        else metrics.get("fingerprint") or metrics.get("reason") or metrics.get("module") or ""
    )
    strong_group = (
        row.get("kind") in {"duplicate_source_file", "duplicate_source_block", "duplicate_function"}
        and isinstance(metrics.get("fingerprint"), str)
        and re.fullmatch("[0-9a-f]{64}", metrics["fingerprint"])
    )
    value = (
        [provider, row.get("kind"), metrics["fingerprint"]]
        if strong_group
        else [provider, row.get("kind"), paths, anchor]
    )
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:24]
    return (
        "delta-" + digest,
        paths,
        (
            "unestablished_symbol"
            if unestablished
            else "content_fingerprint"
            if strong_group
            else "qualified_symbol"
            if metrics.get("qualified_symbol")
            else "symbol"
            if symbol
            else "aggregate_paths_and_reason"
        ),
    )


def _family_scope(provider, kind):
    """An explicit producer scope cannot override missing capture or retention."""
    if provider is None:
        return {"complete": False, "reason": "Producer evidence is missing"}
    document = provider["families"]
    if not isinstance(document, dict) or document and document.get("schema_version") != 1:
        return {"complete": False, "reason": "Unsupported rule-family coverage"}
    families = document.get("families", {})
    if not isinstance(families, dict):
        return {"complete": False, "reason": "Invalid rule-family coverage"}
    scope = families.get(kind)
    if scope is None:
        if document or not provider["legacy"] or kind not in provider["legacy_kinds"]:
            return {"complete": False, "reason": "Producer does not advertise this rule family"}
        return {"complete": provider["complete"], "reason": "Legacy whole-provider completeness"}
    if not isinstance(scope, dict):
        return {"complete": False, "reason": "Invalid rule-family coverage"}
    counts = [
        scope.get(key)
        for key in (
            "eligible_units",
            "analyzed_units",
            "partial_units",
            "candidates_observed",
            "candidates_indexed",
        )
    ]
    valid = all(type(value) is int and value >= 0 for value in counts)
    eligible, analyzed, partial, observed, indexed = counts if valid else (0, 0, 1, 0, 1)
    valid = (
        valid
        and type(scope.get("complete")) is bool
        and eligible >= analyzed
        and partial <= analyzed
        and observed >= indexed
        and indexed == sum(row.get("kind") == kind for row in provider["rows"])
    )
    complete = (
        scope.get("complete") is True
        and valid
        and eligible == analyzed
        and partial == 0
        and observed == indexed
        and provider["capture_complete"]
        and not provider["duplicate"]
        and indexed == sum(row.get("kind") == kind for row in provider["rows"])
    )
    return {
        **scope,
        "valid": valid,
        "complete": complete,
        "reason": "Producer rule-family coverage and compact retention"
        if complete
        else "Rule-family analysis, capture or compact retention is incomplete",
    }


def _groups(provider, rows):
    groups = defaultdict(list)
    for row in rows:
        key, _, _ = _key(provider, row)
        groups[key].append(row)
    return groups


def _complete_function_pair(left, right):
    """Matched local metrics can be complete despite unrelated omitted work."""
    if len(left) != 1 or len(right) != 1 or left[0].get("kind") != "complex_function":
        return False
    return all(
        row.get("metrics", {}).get("identity_complete") is True
        and row["metrics"].get("qualified_symbol")
        and row["metrics"].get("partial") is False
        and row["metrics"].get("metric_basis") == "complete_function"
        and all(type(row["metrics"].get(key)) is int for key in _METRICS["complex_function"])
        for row in (*left, *right)
    )


def _measurements(rows):
    values = {}
    for row in rows:
        for key in _METRICS.get(row.get("kind"), ()):
            value = row.get("metrics", {}).get(key)
            if type(value) in {int, float}:
                values[key] = max(values.get(key, value), value)
    return values


def _change(old, new, *, comparable, old_complete, new_complete):
    if not comparable:
        return "unknown", "Source scope, project or producer rules are incompatible"
    if not old:
        return (
            ("new", "Absent from the complete baseline native inventory")
            if old_complete
            else ("unknown", "Newly observed; incomplete baseline cannot establish introduction")
        )
    if not new:
        return (
            (
                "no_longer_observed",
                "Absent from the current complete native inventory; not verified closure",
            )
            if new_complete
            else ("unknown", "Not observed in incomplete current evidence; clearance is unknown")
        )
    # A bare symbol or weak anchor can aggregate distinct code sites, including
    # same-named methods. Equal counts and maximum metrics do not prove continuity.
    if len(old) > 1 or len(new) > 1:
        return "unknown", "Aggregate identity matches multiple sites; inspect locations"
    before, after = _measurements(old), _measurements(new)
    if before != after:
        if not (old_complete and new_complete) or any(
            row.get("metrics", {}).get("partial") for row in (*old, *new)
        ):
            return "unknown", "Measurement changed with incomplete analysis"
        if before.keys() != after.keys():
            return "unknown", "Comparable measurements are missing"
        up = any(after[key] > before[key] for key in before)
        down = any(after[key] < before[key] for key in before)
        if up and down:
            return "unknown", "Measurements moved in both directions"
        if up:
            return "worsened", "Native complexity or repetition measurement increased"
        if down:
            return (
                "improved",
                "Native complexity or repetition measurement decreased; not verified closure",
            )
    return "existing", "Observed in both snapshots; no measured worsening"


def _files(assessment):
    return {
        row["path"]: row.get("digest")
        for row in assessment.get("evidence", [])
        if isinstance(row.get("path"), str) and not row["path"].startswith("<")
    }


def build_ci_delta(before, after, *, fail_on_kinds=()):
    """Compare authorized snapshots supplied by the shared service.

    Missing or incompatible evidence is unknown, never a clean result. The optional
    explicit policy fails on new/worsened native kinds, not on human burden grades.
    Code is never executed, scanned or modified by this projection.
    """
    if not isinstance(fail_on_kinds, (tuple, list)) or any(
        not isinstance(kind, str) or kind not in NATIVE_KINDS for kind in fail_on_kinds
    ):
        raise ValueError("fail_on_kinds must be a list of supported native candidate kinds")
    reasons = []
    for key in ("project_id", "scope_digest"):
        if not before.get(key) or before[key] != after.get(key):
            reasons.append(key + " differs or is missing")
    for assessment in (before, after):
        if not assessment.get("source", {}).get("manifest_digest"):
            reasons.append("Source manifest identity is missing")
    base, head = _providers(before), _providers(after)
    if not base or not head:
        reasons.append("Native producer evidence is missing")
    changes, coverage = [], []
    old_files, new_files = _files(before), _files(after)
    for name in sorted(base.keys() | head.keys()):
        old, new = base.get(name), head.get(name)
        compatible = (
            not reasons
            and old is not None
            and new is not None
            and old["supported"]
            and new["supported"]
            and old["identity"] == new["identity"]
        )
        coverage.append(
            {
                "provider": name,
                "comparable": compatible,
                "before": {key: old[key] for key in ("status", "complete", "coverage", "gaps")}
                if old
                else None,
                "after": {key: new[key] for key in ("status", "complete", "coverage", "gaps")}
                if new
                else None,
            }
        )
        old_groups = _groups(name, old["rows"] if old else [])
        new_groups = _groups(name, new["rows"] if new else [])
        for key in sorted(old_groups.keys() | new_groups.keys()):
            left, right = old_groups.get(key, []), new_groups.get(key, [])
            row = (right or left)[0]
            _, paths, basis = _key(name, row)
            old_scope, new_scope = (
                _family_scope(old, row.get("kind")),
                _family_scope(new, row.get("kind")),
            )
            local_metrics = (
                old_scope.get("valid") is True
                and new_scope.get("valid") is True
                and _complete_function_pair(left, right)
                and all(old_files.get(path) and new_files.get(path) for path in paths)
            )
            classification, reason = _change(
                left,
                right,
                comparable=compatible,
                old_complete=old_scope["complete"] or local_metrics,
                new_complete=new_scope["complete"] or local_metrics,
            )
            if left and right and basis == "unestablished_symbol":
                classification, reason = (
                    "unknown",
                    "Lexical function ownership is unestablished; inspect locations",
                )
            if row.get("kind") not in NATIVE_KINDS:
                classification, reason = "unknown", "Unsupported native candidate kind"
            if (
                classification in {"new", "no_longer_observed"}
                and row.get("kind")
                in {
                    "duplicate_function",
                    "duplicate_block",
                    "near_duplicate_function",
                    "duplicate_source_file",
                    "duplicate_source_block",
                }
                and basis != "content_fingerprint"
            ):
                classification, reason = (
                    "unknown",
                    "Stable duplicate-group fingerprint is unavailable; introduction or clearance is unknown",
                )
            changes.append(
                {
                    "key": key,
                    "provider": name,
                    "kind": row.get("kind"),
                    "paths": paths,
                    "identity_basis": basis,
                    "classification": classification,
                    "reason": reason,
                    "family_coverage": {"before": old_scope, "after": new_scope},
                    "comparison_scope": "matched_complete_function"
                    if local_metrics
                    else "rule_family",
                    "before": {
                        "count": len(left),
                        "measurements": _measurements(left),
                        "locations": [loc for item in left for loc in item.get("locations", [])],
                    },
                    "after": {
                        "count": len(right),
                        "measurements": _measurements(right),
                        "locations": [loc for item in right for loc in item.get("locations", [])],
                    },
                }
            )
    old_files, new_files = _files(before), _files(after)
    changed = sorted(
        path
        for path in old_files.keys() | new_files.keys()
        if old_files.get(path) != new_files.get(path)
    )
    callers = sorted(
        {
            edge["source"]
            for provider in head.values()
            for edge in provider["edges"]
            if edge.get("target") in changed and edge.get("source")
        }
    )
    violations = [
        row["key"]
        for row in changes
        if row["kind"] in fail_on_kinds and row["classification"] in {"new", "worsened"}
    ]
    compatible = not reasons and all(row["comparable"] for row in coverage)
    reasons.extend(
        row["provider"] + ": missing, unsupported or changed producer identity"
        for row in coverage
        if not row["comparable"]
    )
    incomplete = not coverage or any(
        not row["before"]
        or not row["after"]
        or not row["before"]["complete"]
        or not row["after"]["complete"]
        for row in coverage
    )
    selected_coverage = []
    for kind in sorted(set(fail_on_kinds)):
        producers = [
            name
            for name in base.keys() | head.keys()
            if any(
                kind in (provider or {}).get("families", {}).get("families", {})
                or (provider or {}).get("legacy")
                and kind in (provider or {}).get("legacy_kinds", set())
                for provider in (base.get(name), head.get(name))
            )
        ]
        if producers:
            for name in sorted(producers):
                old_scope, new_scope = (
                    _family_scope(base.get(name), kind),
                    _family_scope(head.get(name), kind),
                )
                selected_coverage.append(
                    {"provider": name, "kind": kind, "before": old_scope, "after": new_scope}
                )
        else:
            selected_coverage.append(
                {
                    "provider": "unadvertised rule",
                    "kind": kind,
                    "before": {
                        "complete": False,
                        "reason": "No producer advertises this selected rule",
                    },
                    "after": {
                        "complete": False,
                        "reason": "No producer advertises this selected rule",
                    },
                }
            )
    policy_incomplete = (
        any(not row[axis]["complete"] for row in selected_coverage for axis in ("before", "after"))
        if fail_on_kinds
        else incomplete
    )
    policy_unknown = any(
        row["classification"] == "unknown" and (not fail_on_kinds or row["kind"] in fail_on_kinds)
        for row in changes
    )
    return {
        "schema_version": 1,
        "method": "native_inventory_delta.v2",
        "baseline_assessment_id": before.get("id"),
        "assessment_id": after.get("id"),
        "source": {"before": before.get("source", {}), "after": after.get("source", {})},
        "status": "incompatible" if not compatible else "partial" if incomplete else "complete",
        "comparable": compatible,
        "gaps": sorted(set(reasons)),
        "coverage": coverage,
        "context": {
            "scope": "full captured native inventories",
            "changed_files": changed,
            "changed_areas": sorted({str(PurePosixPath(path).parent) for path in changed}),
            "captured_callers": callers,
            "callers_basis": "captured static import edges, not complete runtime callers",
        },
        "supported_kinds": list(NATIVE_KINDS),
        "available_kinds": sorted({row["kind"] for row in changes if row["kind"]}),
        "counts": dict(sorted(Counter(row["classification"] for row in changes).items())),
        "changes": changes,
        "policy": {
            "mode": "selected_native_kinds" if fail_on_kinds else "advisory",
            "fail_on_kinds": sorted(set(fail_on_kinds)),
            "violations": violations,
            "coverage": selected_coverage,
            "result": "fail"
            if violations
            else "unknown"
            if not compatible or policy_incomplete or policy_unknown
            else "pass",
            "exit_code": 1 if violations else 0,
        },
        "caveat": _CAVEAT,
    }


def _escape(value):
    text = str(value).replace("\\", "\\\\").replace("\n", " ").replace("\r", " ")
    for char in "`*_{}[]<>|":
        text = text.replace(char, "\\" + char)
    return text


def render_ci_markdown(report):
    """A compact review summary; full located rows remain in the JSON report."""
    lines = [
        "# PAT CI delta",
        "",
        f"Status: {_escape(report['status'])}. Policy: {_escape(report['policy']['result'])}.",
        "",
        report["caveat"],
        "",
        "| Change | Count |",
        "| --- | ---: |",
    ]
    lines.extend(f"| {_escape(kind)} | {count} |" for kind, count in report["counts"].items())
    lines.extend(
        [
            "",
            "| Classification | Kind | Paths | Family coverage before → after | Reason |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    rows = [row for row in report["changes"] if row["classification"] != "existing"]
    lines.extend(
        f"| {_escape(row['classification'])} | {_escape(row['kind'])} | {_escape(', '.join(row['paths']))} | {'complete' if row['family_coverage']['before']['complete'] else 'partial'} → {'complete' if row['family_coverage']['after']['complete'] else 'partial'} | {_escape(row['reason'])} |"
        for row in rows[:50]
    )
    if len(rows) > 50:
        lines.extend(["", f"{len(rows) - 50} more changed groups are in the JSON report."])
    lines.extend(["", "Coverage and unknowns:", ""])
    for item in report["coverage"]:
        left, right = item["before"] or {}, item["after"] or {}
        lines.append(
            f"- {_escape(item['provider'])}: {_escape(left.get('status', 'missing'))} → {_escape(right.get('status', 'missing'))}; comparable: {item['comparable']}."
        )
    lines.extend("- " + _escape(reason) for reason in report["gaps"])
    for item in report["policy"].get("coverage", []):
        left, right = item["before"], item["after"]
        lines.append(
            f"- Selected rule {_escape(item['kind'])} ({_escape(item['provider'])}): {'complete' if left['complete'] else 'partial'} → {'complete' if right['complete'] else 'partial'}. {_escape(right.get('reason', ''))}"
        )
    return "\n".join(lines) + "\n"
