"""Offline report presentation and private, snapshot-bound export bundles."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import stat
import uuid
from pathlib import Path

from .badges import MARK, badge_assets, badge_data
from .collector import _open_directory
from .confidence import confidence_assessment
from .rubric import DIMENSIONS

_STATIC = Path(__file__).with_name("static")
_LABELS = {
    d: "Performance & Scalability" if d == "performance" else d.capitalize() for d in DIMENSIONS
}
_STYLE = """
:root{color-scheme:light dark;--bg:#faf8f3;--surface:#fff;--hover:#faf8f3;--well:#f0ede4;--plot:#f7f5ef;--text:#13223b;--text-soft:#3e4860;--muted:#5b6478;--line:#e7e2d6;--line-soft:#efebe1;--amber:#f2ae12;--amber-ink:#6e4a00;--cream:#fbebbf;--rust:#b4471f;--focus:#13223b;font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text)}a{color:var(--text);text-decoration-color:#e0b54a;text-underline-offset:3px}a:hover{text-decoration-color:var(--text)}
h1,h2,h3{line-height:1.25;overflow-wrap:anywhere}p,li,td,th,summary,dd{overflow-wrap:anywhere}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.875em}
button,input,select{font:inherit}button:focus-visible,select:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.bar{background:var(--surface);border-bottom:1px solid var(--line)}.bar-inner,main{max-width:1120px;margin:auto;padding-inline:1.5rem}.bar-inner{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem;min-height:4rem;padding-block:.6rem}
.brand{display:inline-flex;align-items:center;gap:.6rem;font-weight:700;letter-spacing:.02em}.brand svg{width:34px;height:34px}.project{font-weight:600}.stamp{color:var(--muted);font-size:.875rem}.bar-actions{margin-left:auto;display:flex;gap:.5rem;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;min-height:2rem;padding:0 .8rem;border-radius:1rem;font-size:.8125rem;font-weight:600;text-decoration:none;background:var(--well);color:var(--text)}.chip-partial{background:var(--cream);color:var(--amber-ink)}
main{padding-block:3rem 4rem;display:flex;flex-direction:column;gap:3.5rem}section{min-width:0}
.verdict{display:flex;flex-direction:column;gap:1rem}.verdict h1{margin:0;font-size:clamp(1.75rem,4vw,2.25rem);font-weight:600;letter-spacing:-.01em;max-width:52rem}.lede{margin:0;font-size:1.0625rem;color:var(--text-soft);max-width:48rem}
.purpose{display:flex;flex-wrap:wrap;gap:.5rem 2rem;margin:.25rem 0 0;font-size:.9375rem}.purpose div{display:flex;gap:.5rem;align-items:baseline}.purpose dt{color:var(--muted)}.purpose dd{margin:0;font-weight:600}
.section-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:.5rem 1rem;margin-bottom:1rem}.section-head h2{margin:0;font-size:1.375rem;font-weight:600}.section-head p{margin:0;color:var(--muted);font-size:.875rem}
.next-cards{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,28rem),1fr));gap:1rem;counter-reset:rank}
.next-card{counter-increment:rank;background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:1.25rem 1.4rem;display:flex;flex-direction:column;gap:.75rem}.next-card header{display:flex;align-items:center;gap:.6rem;font-size:.8125rem;font-weight:600;color:var(--muted)}.next-card header::before{content:counter(rank);width:1.65rem;height:1.65rem;border-radius:50%;background:var(--cream);color:#13223b;display:inline-flex;align-items:center;justify-content:center;font-weight:700}
.next-card h3{margin:0;font-size:1.0625rem;font-weight:600}.next-card h3 a{text-decoration:none}.next-card h3 a:hover{text-decoration:underline}.next-card p{margin:0;font-size:.9375rem;color:var(--text-soft)}.label{color:var(--muted)}
.tags{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:auto}.tag{font-size:.8125rem;padding:.15rem .65rem;border-radius:1rem;background:var(--well);color:var(--text-soft)}
.list{background:var(--surface);border:1px solid var(--line);border-radius:14px}.finding{border-bottom:1px solid var(--line-soft)}.finding:last-child{border-bottom:0}
.finding>summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.35rem 1.25rem;align-items:center;padding:1rem 1.4rem}.finding>summary::-webkit-details-marker{display:none}
.finding h3{margin:0;font-size:1rem;font-weight:500}.finding .where{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8125rem;color:var(--muted)}.finding-tags{display:inline-flex;align-items:center;gap:.6rem;font-size:.8125rem;color:var(--muted);white-space:nowrap}
.finding-body{padding:0 1.4rem 1.25rem;display:grid;gap:.75rem;max-width:52rem}.finding-body h4{margin:.25rem 0 0;font-size:.875rem}.finding-body p,.finding-body ul{margin:0}.paths{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8125rem;padding-left:1.1rem}
.dot{display:inline-block;width:.65rem;height:.65rem;border-radius:50%;border:1.5px solid var(--text);background:var(--amber)}.dot-medium{background:linear-gradient(90deg,var(--amber) 50%,var(--surface) 50%)}.dot-low,.dot-unknown{background:var(--surface);border-style:dashed}
.sev{font-weight:600;color:var(--text)}.sev-critical,.sev-high{color:var(--rust)}
.more{border-top:1px solid var(--line);gap:0;display:flex;flex-direction:column}.more>details{border-bottom:1px solid var(--line)}.more>details>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:1rem;min-height:3.5rem}.more>details>summary::-webkit-details-marker{display:none}
.more>details>summary::before{content:"";width:.45rem;height:.45rem;border-right:1.6px solid var(--muted);border-bottom:1.6px solid var(--muted);transform:rotate(-45deg);transition:transform .15s;flex:none;margin:0 .2rem}.more>details[open]>summary::before{transform:rotate(45deg)}
.more>details>summary h2{margin:0;font-size:1.0625rem;font-weight:600}.more>details>summary span{margin-left:auto;color:var(--muted);font-size:.875rem;text-align:right}.more .body{padding:0 0 1.5rem 1.6rem;max-width:56rem}.more h3{font-size:1rem;margin:1.25rem 0 .4rem}
.secondary{color:var(--muted)}.initiative{padding:1rem 0;border-bottom:1px solid var(--line-soft)}.initiative h3{margin-top:0}.initiative dl{display:grid;grid-template-columns:9rem minmax(0,1fr);gap:.4rem 1rem;margin:.5rem 0}.initiative dt{color:var(--muted)}.initiative dd{margin:0}
.context-summary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem 2rem}.context-summary article{min-width:0}.context-priorities li{padding:.3rem 0}.context-priorities p{margin:.3rem 0}
.badges{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center}.badges img{max-width:100%;height:auto}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}th,td{text-align:left;vertical-align:top;padding:.6rem .4rem;border-bottom:1px solid var(--line)}.table-wrap{overflow-x:auto}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8125rem;padding:1rem;background:var(--surface);border:1px solid var(--line);border-radius:10px;max-height:24rem;overflow:auto}
footer{color:var(--muted);font-size:.8125rem;margin:0}
@media(prefers-color-scheme:dark){:root{--bg:#0e1626;--surface:#16223a;--hover:#1a2843;--well:#22304b;--plot:#1a2640;--text:#eee9db;--text-soft:#cdd3de;--muted:#a9b2c4;--line:#2a3854;--line-soft:#24324d;--cream:#4a4026;--amber-ink:#f6d27a;--rust:#e07a55;--focus:#f2ae12}a{text-decoration-color:#f2ae12}.next-card header::before{color:#13223b;background:#f2ae12}}
@media(max-width:640px){.bar-inner,main{padding-inline:1rem}main{padding-block:2rem 3rem;gap:2.5rem}.context-summary{grid-template-columns:1fr}.finding>summary{grid-template-columns:1fr;padding:1rem}.finding-body{padding:0 1rem 1rem}.more .body{padding-left:0}.initiative dl{grid-template-columns:1fr}.bar-actions{margin-left:0}}
"""


def _score(value):
    return value if type(value) is int and 0 <= value <= 5 else None


def _confidence(value):
    return value if isinstance(value, str) and value in {"low", "medium", "high"} else "unknown"


def dimension_map_data(report):
    """Normalize saved ratings/goals; incomplete axes never acquire zero coordinates."""
    badge_data(report)  # Reuse the badge projection's source/review binding check.
    assessment, review = report["assessment"], report.get("review") or {}
    ratings = review.get("ratings", {})
    targets = (report.get("goals") or {}).get("targets", {})
    confidence = confidence_assessment(assessment, review)
    entries = {entry["id"]: entry for entry in assessment.get("evidence", [])}
    initiatives = {}
    for item in (review.get("plan") or {}).get("initiatives", []):
        for dimension, effect in (item.get("dimension_impacts") or {}).items():
            initiatives.setdefault(dimension, []).append(
                {"id": item.get("id"), "title": item.get("title", "Initiative"), "effect": effect}
            )
    rows = []
    for dimension in DIMENSIONS:
        rating, target = ratings.get(dimension, {}), targets.get(dimension, {})
        capability, burden = _score(rating.get("capability")), _score(rating.get("burden"))
        support = confidence["dimensions"][dimension]
        readiness = support["burden"]["support"]["readiness"]
        source_ids = set(readiness["source_evidence_ids"])
        references = [
            {"id": identity, "path": entries[identity]["path"], "kind": entries[identity]["kind"]}
            for identity in dict.fromkeys(rating.get("evidence_ids", []))
            if identity in source_ids and isinstance(entries[identity].get("path"), str)
        ]
        rows.append(
            {
                "id": dimension,
                "label": _LABELS[dimension],
                "capability": capability,
                "burden": burden,
                "capability_min": _score(target.get("capability_min")),
                "burden_max": _score(target.get("burden_max")),
                "capability_confidence": _confidence(rating.get("confidence"))
                if capability is not None
                else "unknown",
                "burden_confidence": _confidence(rating.get("burden_confidence", "low"))
                if burden is not None
                else "unknown",
                "burden_basis": rating.get("burden_basis", "source_estimate")
                if burden is not None
                else "unknown",
                "rationale": rating.get("rationale", "No reviewed judgment is saved."),
                "recommendations": rating.get("recommendations", []),
                "evidence_ids": rating.get("evidence_ids", []),
                "confidence_notes": list(
                    dict.fromkeys(support["capability"]["blockers"] + support["burden"]["blockers"])
                ),
                "burden_evidence": {
                    label: len(readiness[key])
                    for label, key in (
                        ("source", "source_evidence_ids"),
                        ("experience", "experience_evidence_ids"),
                        ("matched_cost", "matched_cost_evidence_ids"),
                        ("partial_elapsed", "partial_elapsed_evidence_ids"),
                    )
                },
                "burden_next_steps": list(readiness["next_steps"]),
                "evidence_references": references[:5],
                "evidence_reference_total": len(references),
                "initiatives": initiatives.get(dimension, []),
            }
        )
    return {
        "schema_version": 1,
        "assessment_id": assessment["id"],
        "review_id": review.get("id"),
        "project": Path(assessment["source"]["root"]).name,
        "preview_targets": False,
        "complete": assessment.get("complete") is True,
        "dimensions": rows,
        "timeline": _timeline(report, rows),
    }


def _timeline(report, rows):
    """Snapshots oldest first; the shown one is always last and unknown never becomes zero."""
    assessment = report["assessment"]

    def entry(identity, created, revision, reviewed, scores):
        revision = (
            revision
            if isinstance(revision, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", revision)
            else None
        )
        return {
            "assessment_id": identity,
            "date": created[:10] if isinstance(created, str) else None,
            "revision": revision[:7].lower() if revision else None,
            "reviewed": reviewed,
            "scores": scores,
        }

    earlier = [
        entry(
            item.get("assessment_id"),
            item.get("created_at"),
            item.get("revision"),
            item.get("reviewed") is True,
            {
                dimension: [
                    _score(((item.get("ratings") or {}).get(dimension) or {}).get(axis))
                    for axis in ("capability", "burden")
                ]
                for dimension in DIMENSIONS
            },
        )
        for item in report.get("timeline") or []
        if isinstance(item, dict) and item.get("assessment_id") != assessment["id"]
    ]
    current = entry(
        assessment["id"],
        assessment.get("created_at"),
        assessment.get("source", {}).get("revision"),
        report.get("review") is not None,
        {row["id"]: [row["capability"], row["burden"]] for row in rows},
    )
    return [*earlier[-11:], current]


def _text(value):
    return html.escape(str(value), quote=True)


def _list(values):
    return "<ul>" + "".join("<li>" + _text(value) + "</li>" for value in values) + "</ul>"


def _script_json(value):
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _asset_text(name):
    return (_STATIC / name).read_text(encoding="utf-8")


def _hash(value):
    return base64.b64encode(hashlib.sha256(value.encode()).digest()).decode("ascii")


def _value(value):
    return "Unknown" if value is None else f"{value} / 5"


_SEVERITY = ("critical", "high", "medium", "low")


def _first_sentence(text):
    """Split an authored diagnosis into a headline and the remaining sentences."""
    text = " ".join(str(text or "").split())
    match = re.search(r"(?<=[.!?])\s+(?=[A-Z0-9])", text)
    return (text[: match.start()], text[match.end() :]) if match else (text, "")


def _plain(value):
    return str(value).replace("_", " ")


def _evidence_label(entry):
    """Show project paths as written; files outside the project only by name."""
    path = str(entry.get("path", ""))
    return Path(path).name if path.startswith("/") else path


def _context_html(context):
    """Present the shared authored context; this renderer assigns no milestones."""
    lines = ['<details id="purpose"><summary><h2 id="project-context-heading">Purpose and fit</h2>']
    if context.get("status") != "recorded":
        lines.append('<span>Not recorded</span></summary><div class="body">')
        lines.append(
            "<p>No maturity or intended-purpose judgment is recorded for this review. Existing engineering scores are unchanged.</p>"
        )
    else:
        current, intended, alignment = context["current"], context["intended"], context["alignment"]
        lines.append(
            "<span>"
            + _text(intended.get("basis_label", "Unknown"))
            + " · "
            + _text(intended["confidence"])
            + ' confidence</span></summary><div class="body">'
        )
        lines += [
            '<div class="context-summary"><article><h3>Today</h3><p><strong>'
            + _text(current.get("milestone_label", "Unknown"))
            + " · "
            + _text(current.get("readiness_label", "Unknown"))
            + "</strong> · "
            + _text(current["confidence"])
            + " confidence</p><p>"
            + _text(current["rationale"])
            + "</p></article><article><h3>Intended</h3><p><strong>"
            + _text(intended.get("milestone_label", "Unknown"))
            + "</strong> · "
            + _text(intended.get("basis_label", "Unknown"))
            + "</p><p>"
            + _text(intended["statement"])
            + "</p>",
        ]
        if intended.get("attribution"):
            lines.append('<p class="secondary">' + _text(intended["attribution"]) + "</p>")
        lines.append("</article></div>")
        lines.append(
            "<h3>"
            + _text(alignment.get("direction_label", "Unknown"))
            + "</h3><p>"
            + _text(alignment["rationale"])
            + "</p>"
        )
        if alignment["priorities"]:
            lines.append('<ol class="context-priorities">')
            for priority in alignment["priorities"]:
                lines.append(
                    "<li><strong>"
                    + _text(priority.get("dimension_label", "Unknown"))
                    + " · "
                    + _text(priority.get("direction_label", "Unknown"))
                    + "</strong><p>"
                    + _text(priority["rationale"])
                    + "</p>"
                )
                if priority["initiative_ids"]:
                    lines.append(
                        '<p class="secondary">'
                        + " · ".join(
                            '<a href="#initiative-' + _text(i) + '">' + _text(i) + "</a>"
                            for i in priority["initiative_ids"]
                        )
                        + "</p>"
                    )
                lines.append("</li>")
            lines.append("</ol>")
        for title, values in (
            ("Deferred on purpose", alignment["deferred"]),
            ("Alternative goals", intended["alternatives"]),
            ("Limits on purpose", intended["limitations"]),
        ):
            if values:
                lines.append("<h3>" + title + "</h3>" + _list(values))
    if context.get("gaps"):
        lines.append("<h3>Context gaps</h3>" + _list(context["gaps"]))
    lines.append(
        '<p class="secondary">'
        + _text(
            context.get(
                "profile_note",
                "Scope milestones are not quality grades or required growth steps. Existing numeric goals remain independent.",
            )
        )
        + "</p></div></details>"
    )
    return "\n".join(lines)


def _verdict_html(report, context, plan):
    review = report.get("review")
    if plan and plan.get("diagnosis"):
        headline, rest = _first_sentence(plan["diagnosis"])
    elif review:
        headline, rest = (
            "Reviewed, without an improvement plan",
            "Scores below are the saved judgment.",
        )
    else:
        headline, rest = (
            "Collected, not yet reviewed",
            "Source facts are captured; no scores are judged.",
        )
    lines = [
        '<section class="verdict" aria-labelledby="verdict-heading"><h1 id="verdict-heading">'
        + _text(headline)
        + "</h1>"
    ]
    if rest:
        lines.append('<p class="lede">' + _text(rest) + "</p>")
    if context.get("status") == "recorded":
        current, intended = context["current"], context["intended"]
        lines.append('<dl class="purpose">')
        for title, value in (
            (
                "Today",
                f"{current.get('milestone_label', 'Unknown')} · {current.get('readiness_label', 'Unknown')}",
            ),
            ("Intended", intended.get("milestone_label", "Unknown")),
            ("Direction", context["alignment"].get("direction_label", "Unknown")),
        ):
            lines.append("<div><dt>" + title + "</dt><dd>" + _text(value) + "</dd></div>")
        lines.append("</dl>")
    lines.append("</section>")
    return "\n".join(lines)


def _next_html(plan):
    items = (plan or {}).get("initiatives", [])
    if not items:
        return ""
    lines = [
        '<section aria-labelledby="next-heading"><div class="section-head"><h2 id="next-heading">Do next</h2>'
        '<a href="#plan">Full plan</a></div><ol class="next-cards">'
    ]
    for item in items:
        anchor = "#initiative-" + _text(item["id"]) if item.get("id") else "#plan"
        lines.append(
            '<li class="next-card"><header>'
            + _text(_plain(item.get("priority", "Priority not set")).capitalize())
            + '</header><h3><a href="'
            + anchor
            + '">'
            + _text(item.get("title", "Initiative"))
            + "</a></h3>"
        )
        if item.get("first_slice"):
            lines.append(
                '<p><span class="label">First step · </span>' + _text(item["first_slice"]) + "</p>"
            )
        impacts = [d for d in DIMENSIONS if d in (item.get("dimension_impacts") or {})]
        if impacts:
            lines.append(
                '<div class="tags">'
                + "".join('<span class="tag">' + _text(_LABELS[d]) + "</span>" for d in impacts)
                + "</div>"
            )
        lines.append("</li>")
    lines.append("</ol></section>")
    return "\n".join(lines)


def _findings_html(assessment, review):
    findings = assessment.get("findings", []) + review.get("findings", [])
    findings = sorted(
        findings,
        key=lambda f: _SEVERITY.index(f.get("severity")) if f.get("severity") in _SEVERITY else 9,
    )
    entries = {entry["id"]: entry for entry in assessment.get("evidence", [])}
    counts = [
        f"{sum(f.get('severity') == level for f in findings)} {level}"
        for level in _SEVERITY
        if any(f.get("severity") == level for f in findings)
    ]
    lines = [
        '<section aria-labelledby="findings-heading"><div class="section-head"><h2 id="findings-heading">Findings</h2><p>'
        + _text(" · ".join(counts) or "None recorded")
        + "</p></div>"
    ]
    if not findings:
        lines.append(
            "<p>No findings were recorded. This is not proof of absent risks.</p></section>"
        )
        return "\n".join(lines)
    lines.append('<div class="list">')
    for finding in findings:
        support = finding.get("support", {})
        severity = finding.get("severity", "unknown")
        confidence = _confidence(support.get("confidence"))
        paths = [
            _evidence_label(entries[i])
            for i in dict.fromkeys(finding.get("evidence_ids", []))
            if i in entries and entries[i].get("path")
        ]
        lines.append(
            '<details class="finding"><summary><h3>'
            + _text(finding.get("title", finding.get("message", "Finding")))
            + '</h3><span class="finding-tags"><span class="sev sev-'
            + _text(severity)
            + '">'
            + _text(severity.capitalize())
            + '</span><span class="dot dot-'
            + confidence
            + '" aria-hidden="true"></span>'
            + _text(confidence.capitalize())
            + " confidence</span>"
        )
        if paths:
            lines.append(
                '<span class="where">'
                + _text(paths[0])
                + (_text(f"  +{len(paths) - 1} more") if len(paths) > 1 else "")
                + "</span>"
            )
        lines.append('</summary><div class="finding-body">')
        if support.get("rationale"):
            lines.append("<p>" + _text(support["rationale"]) + "</p>")
        if paths:
            lines.append(
                '<h4>Where</h4><ul class="paths">'
                + "".join("<li>" + _text(p) + "</li>" for p in paths)
                + "</ul>"
            )
        if support.get("counterevidence"):
            lines.append("<h4>Keep intact</h4><p>" + _text(support["counterevidence"]) + "</p>")
        if support.get("limitations"):
            lines.append("<h4>Limits</h4>" + _list(support["limitations"]))
        if support.get("scope"):
            lines.append('<p class="secondary">Scope: ' + _text(_plain(support["scope"])) + "</p>")
        lines.append("</div></details>")
    lines.append("</div></section>")
    return "\n".join(lines)


def _plan_html(plan):
    lines = [
        '<details id="plan"><summary><h2 id="plan-heading">Improvement plan</h2><span>'
        + ("Diagnosis, target state, done-checks" if plan else "Not saved")
        + '</span></summary><div class="body">'
    ]
    if not plan:
        lines.append(
            "<p>No authored improvement plan is saved. Source leads and numeric targets do not supply a diagnosis.</p>"
        )
    else:
        lines.append("<p>" + _text(plan.get("diagnosis", "")) + "</p>")
        if plan.get("target_state"):
            lines.append("<h3>Target state</h3><p>" + _text(plan["target_state"]) + "</p>")
        for item in plan.get("initiatives", []):
            lines.append(
                '<article class="initiative"'
                + (' id="initiative-' + _text(item["id"]) + '"' if item.get("id") else "")
                + "><h3>"
                + _text(item.get("title", "Initiative"))
                + "</h3><dl>"
            )
            for label, key in (
                ("Priority", "priority"),
                ("Root cause", "root_cause"),
                ("Scope", "scope"),
                ("Burden effect", "burden_effect"),
                ("First step", "first_slice"),
            ):
                if item.get(key):
                    lines.append(
                        "<dt>"
                        + label
                        + "</dt><dd>"
                        + _text(_plain(item[key]) if key == "priority" else item[key])
                        + "</dd>"
                    )
            impacts = item.get("dimension_impacts") or {}
            for dimension in DIMENSIONS:
                if dimension in impacts:
                    lines.append(
                        "<dt>"
                        + _text(_LABELS[dimension])
                        + "</dt><dd>"
                        + _text(impacts[dimension])
                        + "</dd>"
                    )
            if item.get("depends_on"):
                lines.append(
                    "<dt>Depends on</dt><dd>" + _text(", ".join(item["depends_on"])) + "</dd>"
                )
            lines.append("</dl>")
            if item.get("acceptance"):
                lines.append("<h4>Done when</h4>" + _list(item["acceptance"]))
            lines.append("</article>")
    lines.append("</div></details>")
    return "\n".join(lines)


def _coverage_html(report, model, confidence):
    assessment = report["assessment"]
    gaps = assessment.get("gaps", [])
    lines = [
        '<details id="coverage"><summary><h2 id="coverage-heading">Coverage and confidence</h2><span>'
        + ("Complete" if model["complete"] else "Partial")
        + _text(f" · {len(gaps)} gaps")
        + '</span></summary><div class="body">',
        "<p>"
        + (
            "Collection completed within its declared scope."
            if model["complete"]
            else "Collection is partial; scores are judged on the retained scope."
        )
        + " "
        + (
            "Targets are the saved goals."
            if report.get("goals")
            else "No goals are saved; target values remain unknown."
        )
        + "</p>",
    ]
    readiness = {
        row["id"]: confidence["dimensions"][row["id"]]["burden"]["support"]["readiness"]
        for row in model["dimensions"]
    }
    lines.append(
        '<div class="table-wrap"><table><thead><tr><th scope="col">Dimension</th>'
        '<th scope="col">Burden basis</th><th scope="col">Source</th><th scope="col">Experience</th>'
        '<th scope="col">Recurrence</th></tr></thead><tbody>'
    )
    for row in model["dimensions"]:
        item = readiness[row["id"]]
        lines.append(
            '<tr><th scope="row">'
            + _text(row["label"])
            + "</th><td>"
            + _text(_plain(row["burden_basis"]))
            + "</td><td>"
            + str(len(item["source_evidence_ids"]))
            + "</td><td>"
            + str(len(item["experience_evidence_ids"]))
            + "</td><td>"
            + _text(_plain(item["recurrence"]))
            + "</td></tr>"
        )
    lines.append("</tbody></table></div>")
    caveats = list(dict.fromkeys(item["caveat"] for item in readiness.values()))
    lines += ['<p class="secondary">' + _text(c) + "</p>" for c in caveats]
    if gaps:
        lines.append(
            "<details><summary>"
            + _text(f"{len(gaps)} collection gaps")
            + "</summary>"
            + _list(gaps[:200])
            + ('<p class="secondary">More in report.json.</p>' if len(gaps) > 200 else "")
            + "</details>"
        )
    lines.append("</div></details>")
    return "\n".join(lines)


def report_html(report):
    """Render an offline document with no external resources or executable report text."""
    model = dimension_map_data(report)
    from .project_context import project_context_assessment

    context = project_context_assessment(
        report["assessment"], report.get("review"), report.get("goals")
    )
    confidence = confidence_assessment(report["assessment"], report.get("review"))
    assessment, review = report["assessment"], report.get("review") or {}
    plan = review.get("plan") or report.get("goal_alignment", {}).get("plan")
    badges = badge_assets(report)
    bundle = _asset_text("dimension-map.generated.js")
    if re.search(r"</script", bundle, re.I):
        raise ValueError("Graph bundle contains an unsafe script boundary")
    script = (
        bundle
        + "\n;PATDimensionMap.createDimensionMap(document.getElementById('dimension-map'),"
        + _script_json(model)
        + ");\n"
    )
    style = _STYLE + "\n" + _asset_text("dimension-map.css")
    if re.search(r"</style", style, re.I):
        raise ValueError("Graph stylesheet contains an unsafe style boundary")
    policy = (
        "default-src 'none'; script-src 'sha256-"
        + _hash(script)
        + "'; style-src 'sha256-"
        + _hash(style)
        + "'; img-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; "
        "form-action 'none'"
    )

    def badge_image(name):
        data = base64.b64encode(badges[name + ".svg"].encode()).decode("ascii")
        return f'<img alt="{_text("PAT " + _LABELS.get(name, "snapshot"))}" src="data:image/svg+xml;base64,{data}">'

    revision = assessment.get("source", {}).get("revision")
    created = assessment.get("created_at")
    lines = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        '<meta http-equiv="Content-Security-Policy" content="' + _text(policy) + '">',
        "<title>PAT — "
        + _text(model["project"])
        + "</title><style>"
        + style
        + "</style></head><body>",
        '<header class="bar"><div class="bar-inner"><span class="brand">'
        '<svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
        + MARK.format(transform="translate(0 0)")
        + '</svg>PAT</span><span class="project">'
        + _text(model["project"])
        + "</span>"
        + ('<code class="stamp">' + _text(str(revision)[:7]) + "</code>" if revision else "")
        + ('<span class="stamp">' + _text(str(created)[:10]) + "</span>" if created else "")
        + '<span class="bar-actions">'
        + (
            ""
            if model["complete"]
            else '<a class="chip chip-partial" href="#coverage">'
            + _text(f"Partial scan · {len(assessment.get('gaps', []))} gaps")
            + "</a>"
        )
        + ("" if report.get("review") else '<span class="chip">Unreviewed</span>')
        + '<a class="chip" href="#downloads">Downloads</a></span></div></header><main>',
        _verdict_html(report, context, plan),
        _next_html(plan),
        '<section aria-labelledby="map-heading"><div class="section-head"><h2 id="map-heading">Dimensions</h2></div>'
        '<div id="dimension-map"></div><noscript><div class="table-wrap"><table>'
        '<thead><tr><th scope="col">Dimension</th><th scope="col">Capability</th><th scope="col">Upkeep burden</th>'
        '<th scope="col">Target: capability ≥ · burden ≤</th><th scope="col">Why</th></tr></thead><tbody>',
    ]
    for row in model["dimensions"]:
        lines.append(
            '<tr><th scope="row">'
            + _text(row["label"])
            + "</th><td>"
            + _value(row["capability"])
            + " · "
            + _text(row["capability_confidence"])
            + "</td><td>"
            + _value(row["burden"])
            + " · "
            + _text(row["burden_confidence"])
            + "</td><td>"
            + _value(row["capability_min"])
            + " · "
            + _value(row["burden_max"])
            + "</td><td>"
            + _text(row["rationale"])
            + "</td></tr>"
        )
    lines += [
        "</tbody></table></div></noscript></section>",
        _findings_html(assessment, review),
        '<section class="more" aria-label="Plan, context and evidence">',
        _plan_html(plan),
        _context_html(context),
        _coverage_html(report, model, confidence),
        '<details id="downloads"><summary><h2>Downloads</h2><span>report.md · report.json · badges</span></summary>'
        '<div class="body"><p><a href="report.md">report.md</a> · <a href="report.json">report.json</a> '
        '<span class="secondary">beside this file in the export folder</span></p>'
        '<div class="badges" aria-label="Assessment badges">'
        + "".join(badge_image(d) for d in ("summary", *DIMENSIONS))
        + "</div></div></details>",
        '<details id="about"><summary><h2>About this snapshot</h2><span>Rubric '
        + _text(assessment.get("rubric_version", "unknown"))
        + " · PAT "
        + _text(assessment.get("tool_provenance", {}).get("version", "unknown"))
        + '</span></summary><div class="body"><dl class="purpose">',
    ]
    for title, value in (
        ("Assessment", model["assessment_id"]),
        ("Review", model["review_id"] or "Not saved"),
        ("Source", revision or "Revision unknown"),
        ("Captured", created or "Time unknown"),
        ("Reviewed", review.get("created_at", "Not saved")),
    ):
        lines.append("<div><dt>" + title + "</dt><dd><code>" + _text(value) + "</code></dd></div>")
    lines += [
        "</dl><p>Assessment and review are frozen records. Source binding verifies captured identity, "
        "not runtime effectiveness or the truth of a judgment. Finding severity is separate from confidence.</p>",
        "<details><summary>Three.js license</summary><pre>"
        + _text(_asset_text("THREE-LICENSE.txt"))
        + "</pre></details></div></details></section>",
        "<footer>Static snapshot of source and supplied evidence. Runtime behaviour may differ.</footer>",
        "</main><script>" + script + "</script></body></html>",
    ]
    return "\n".join(line for line in lines if line)


def _write_at(directory, name, payload):
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _remove_at(parent, name):
    """Clean only a private owned staging/reservation tree, never follow a link."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except FileNotFoundError:
        return
    try:
        for child in os.listdir(fd):
            if stat.S_ISDIR(os.stat(child, dir_fd=fd, follow_symlinks=False).st_mode):
                _remove_at(fd, child)
            else:
                os.unlink(child, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent)


def export_report(report, state_dir, *, forbidden_roots=()):
    """Write a fresh private bundle under configured state, without target writes."""
    from .service import markdown_report

    assessment = report["assessment"]
    assessment_id = assessment["id"]
    if not isinstance(assessment_id, str) or not re.fullmatch(r"a_[0-9a-f]{1,64}", assessment_id):
        raise ValueError("Invalid assessment identity for export")
    source_digest = assessment.get("source", {}).get("manifest_digest")
    if not isinstance(source_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", source_digest
    ):
        raise ValueError("Export requires a captured source manifest identity")
    state = Path(state_dir).expanduser().absolute()
    if ".." in state.parts:
        raise ValueError("Export state path must be canonical")
    destination = state / "exports"
    for root in [assessment["source"]["root"], *forbidden_roots]:
        if destination.is_relative_to(Path(root).expanduser().resolve()):
            raise ValueError("Report exports must be outside assessed projects")
    badges = badge_assets(report)
    markdown = "\n".join(
        ["[Interactive 3D report](report.html)", "", "![PAT snapshot](badges/summary.svg)", ""]
        + [f"![PAT {_LABELS[d]}](badges/{d}.svg)" for d in DIMENSIONS]
        + ["", markdown_report(report)]
    )
    contents = {
        "report.html": report_html(report).encode(),
        "report.md": markdown.encode(),
        "report.json": (
            json.dumps(report, ensure_ascii=True, allow_nan=False, indent=2) + "\n"
        ).encode(),
        **{"badges/" + name: data.encode() for name, data in badges.items()},
    }
    token = uuid.uuid4().hex
    staged, final = ".pending-" + token, assessment_id + "-" + token
    state_fd = _open_directory(state)
    exports_fd = pending_fd = badges_fd = None
    created = reserved = False
    try:
        try:
            os.mkdir("exports", mode=0o700, dir_fd=state_fd)
        except FileExistsError:
            pass
        exports_fd = os.open(
            "exports", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd
        )
        info = os.fstat(exports_fd)
        if info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise PermissionError("Report export directory must be private to its owner")
        os.mkdir(staged, mode=0o700, dir_fd=exports_fd)
        created = True
        pending_fd = os.open(
            staged, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=exports_fd
        )
        os.mkdir("badges", mode=0o700, dir_fd=pending_fd)
        badges_fd = os.open(
            "badges", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pending_fd
        )
        for name, payload in contents.items():
            _write_at(
                badges_fd if name.startswith("badges/") else pending_fd, Path(name).name, payload
            )
        # Reserve exclusively: rename must never replace an earlier export, even
        # in the unlikely event of a token collision. Only our empty reservation
        # is replaced after every artifact has been written successfully.
        os.mkdir(final, mode=0o700, dir_fd=exports_fd)
        reserved = True
        os.rename(staged, final, src_dir_fd=exports_fd, dst_dir_fd=exports_fd)
        created = reserved = False
    except BaseException:
        if created:
            _remove_at(exports_fd, staged)
        if reserved:
            _remove_at(exports_fd, final)
        raise
    finally:
        for fd in (badges_fd, pending_fd, exports_fd, state_fd):
            if fd is not None:
                os.close(fd)
    folder = destination / final
    return {
        "schema_version": 1,
        "assessment_id": assessment_id,
        "review_id": (report.get("review") or {}).get("id"),
        "source_digest": source_digest,
        "goal_revision": (report.get("goals") or {}).get("revision"),
        "directory": str(folder),
        "html": str(folder / "report.html"),
        "markdown": str(folder / "report.md"),
        "json": str(folder / "report.json"),
        "badges": {name.removesuffix(".svg"): str(folder / "badges" / name) for name in badges},
        "files": {
            name: {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            for name, payload in contents.items()
        },
    }
