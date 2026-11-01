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

from .badges import badge_assets, badge_data
from .collector import _open_directory
from .rubric import DIMENSIONS

_STATIC = Path(__file__).with_name("static")
_LABELS = {
    d: "Performance & Scalability" if d == "performance" else d.capitalize() for d in DIMENSIONS
}
_STYLE = """
:root{color-scheme:light dark;--bg:#f5f4ef;--surface:#fffefa;--text:#202e34;--muted:#52656b;--line:#ccd6d5;--accent:#08615b;--accent-text:#fff;--focus:#08615b;--warn:#8c3927;font:16px/1.6 system-ui,-apple-system,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text)}main{max-width:1120px;margin:auto;padding:2rem}h1,h2,h3{line-height:1.25;overflow-wrap:anywhere}h1{font-size:2.2rem;letter-spacing:-.04em;margin:.25rem 0}h2{margin-top:0}section{margin:2rem 0 3rem}p,li,td,th,summary{overflow-wrap:anywhere}a{color:var(--accent)}.secondary{color:var(--muted)}.eyebrow{letter-spacing:.1em;text-transform:uppercase;color:var(--accent);font-size:.8rem}.badges{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center}.badges img{max-width:100%;height:auto}table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}th,td{text-align:left;vertical-align:top;padding:.65rem .4rem;border-bottom:1px solid var(--line)}.table-wrap{overflow-x:auto}details{margin:1rem 0}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85rem;padding:1rem;background:var(--surface);border:1px solid var(--line);border-radius:.5rem}code{overflow-wrap:anywhere}.context-summary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem 2rem}.context-summary article{min-width:0}.context-priorities li{padding:.3rem 0}.context-priorities p{margin:.3rem 0}.finding,.initiative{padding:1rem 0;border-bottom:1px solid var(--line)}button,input,select{font:inherit}button:focus-visible,select:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
@media(prefers-color-scheme:dark){:root{--bg:#152126;--surface:#1c2c31;--text:#e8f1ee;--muted:#b1c6c3;--line:#405557;--accent:#8edbd0;--accent-text:#122e2a;--focus:#8edbd0;--warn:#ffbba7}}
@media(max-width:540px){.context-summary{grid-template-columns:1fr}main{padding:1rem}h1{font-size:1.8rem}th,td{padding:.5rem .25rem;font-size:.88rem}.badges{display:grid;grid-template-columns:1fr}}
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
    rows = []
    for dimension in DIMENSIONS:
        rating, target = ratings.get(dimension, {}), targets.get(dimension, {})
        capability, burden = _score(rating.get("capability")), _score(rating.get("burden"))
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
    }


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


def _context_html(context):
    """Present the shared authored context; this renderer assigns no milestones."""
    lines = [
        '<section aria-labelledby="project-context-heading"><h2 id="project-context-heading">Project maturity and intended purpose</h2>'
    ]
    if context.get("status") != "recorded":
        lines.append(
            "<p>No maturity or intended-purpose judgment is recorded for this review. Existing engineering scores are unchanged.</p>"
        )
    else:
        current, intended = context["current"], context["intended"]
        lines += [
            '<div class="context-summary"><article><h3>Current codebase</h3><p><strong>'
            + _text(current.get("milestone_label", "Unknown"))
            + " · "
            + _text(current.get("readiness_label", "Unknown"))
            + "</strong></p><p>Declared confidence: "
            + _text(current["confidence"])
            + "</p><p>"
            + _text(current["rationale"])
            + '</p><p class="secondary">Evidence: '
            + _text(", ".join(current["evidence_ids"]) or "none recorded")
            + "</p></article><article><h3>Intended destination</h3><p><strong>"
            + _text(intended.get("milestone_label", "Unknown"))
            + "</strong></p><p>Basis: "
            + _text(intended.get("basis_label", "Unknown"))
            + "; declared confidence: "
            + _text(intended["confidence"])
            + "</p><p>"
            + _text(intended["statement"])
            + "</p>",
        ]
        if intended.get("attribution"):
            lines.append("<p>Attribution: " + _text(intended["attribution"]) + "</p>")
        lines.append(
            '<p class="secondary">Evidence: '
            + _text(", ".join(intended["evidence_ids"]) or "no captured source citation")
            + "</p></article></div>"
        )
        alignment = context["alignment"]
        lines += [
            "<h3>Fit and ranked focus</h3><p><strong>"
            + _text(alignment.get("direction_label", "Unknown"))
            + "</strong> — "
            + _text(alignment["rationale"])
            + "</p>"
        ]
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
                        '<p class="secondary">Plan initiatives: '
                        + ", ".join(
                            '<a href="#initiative-'
                            + _text(identity)
                            + '">'
                            + _text(identity)
                            + "</a>"
                            for identity in priority["initiative_ids"]
                        )
                        + "</p>"
                    )
                lines.append("</li>")
            lines.append("</ol>")
        else:
            lines.append("<p>No ranked focus areas are recorded.</p>")
        for title, values in (
            ("Deferred work", alignment["deferred"]),
            ("Alternative goals", intended["alternatives"]),
            ("Intent limitations", intended["limitations"]),
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
        + "</p></section>"
    )
    return "\n".join(lines)


def report_html(report):
    """Render an offline document with no external resources or executable report text."""
    from .service import markdown_report

    model = dimension_map_data(report)
    from .project_context import project_context_assessment

    context = project_context_assessment(
        report["assessment"], report.get("review"), report.get("goals")
    )
    assessment, review = report["assessment"], report.get("review") or {}
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

    lines = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        '<meta http-equiv="Content-Security-Policy" content="' + _text(policy) + '">',
        "<title>PAT — "
        + _text(model["project"])
        + "</title><style>"
        + style
        + "</style></head><body><main>",
        '<header><p class="eyebrow">Project Assessment Toolkit</p><h1>'
        + _text(model["project"])
        + "</h1>",
        '<p class="secondary">Captured assessment '
        + _text(model["assessment_id"])
        + "; review "
        + _text(model["review_id"] or "not saved")
        + "; source "
        + _text(assessment.get("source", {}).get("revision") or "revision unknown")
        + "; rubric "
        + _text(assessment.get("rubric_version", "unknown"))
        + ".</p>",
        '<p class="secondary">Captured '
        + _text(assessment.get("created_at", "time unknown"))
        + "; reviewed "
        + _text(review.get("created_at", "not saved"))
        + "; PAT "
        + _text(assessment.get("tool_provenance", {}).get("version", "version unknown"))
        + ".</p>",
        "<p>Capability describes what works; burden describes the cost of keeping it working. "
        "Higher capability and lower burden are preferable. Useful capability above a minimum has no penalty.</p>",
        "<p>"
        + (
            "A saved review is shown."
            if report.get("review")
            else "Collection only: no authored review is saved."
        )
        + (
            " Collection completed within its declared scope."
            if model["complete"]
            else " Collection is partial; inspect the retained scope and gaps."
        )
        + "</p>",
        "</header>",
        _context_html(context),
        '<section aria-label="Assessment badges"><div class="badges">'
        + "".join(badge_image(d) for d in ("summary", *DIMENSIONS))
        + "</div></section>",
        '<section aria-labelledby="map-heading"><h2 id="map-heading">Explore capability and burden</h2>'
        '<div id="dimension-map"></div><noscript><p>Interactive exploration needs JavaScript. The scorecard and report below remain available.</p></noscript></section>',
        '<section aria-labelledby="scores-heading"><h2 id="scores-heading">Scorecard</h2><div class="table-wrap"><table>'
        "<caption>Current values and saved goals; confidence is declared independently for each axis.</caption>"
        '<thead><tr><th scope="col">Dimension</th><th scope="col">Capability</th><th scope="col">Burden</th>'
        '<th scope="col">Confidence C / B</th><th scope="col">Goal min C / max B</th></tr></thead><tbody>',
    ]
    for row in model["dimensions"]:
        lines.append(
            '<tr><th scope="row">'
            + _text(row["label"])
            + "</th><td>"
            + _value(row["capability"])
            + "</td><td>"
            + _value(row["burden"])
            + "</td><td>"
            + _text(row["capability_confidence"])
            + " / "
            + _text(row["burden_confidence"])
            + "</td><td>"
            + _value(row["capability_min"])
            + " / "
            + _value(row["burden_max"])
            + "</td></tr>"
        )
    lines += ["</tbody></table></div>"]
    for row in model["dimensions"]:
        lines.append(
            '<details id="dimension-'
            + row["id"]
            + '"><summary>'
            + _text(row["label"])
            + " rationale and recommendations</summary><p>"
            + _text(row["rationale"])
            + "</p>"
        )
        lines.append(
            "<p>Burden basis: "
            + _text(row["burden_basis"])
            + ". Evidence: "
            + _text(", ".join(row["evidence_ids"]) or "none recorded")
            + ".</p>"
        )
        lines.append(_list(row["recommendations"]) + "</details>")
    lines += [
        '</section><section aria-labelledby="findings-heading"><h2 id="findings-heading">Findings</h2>'
    ]
    findings = assessment.get("findings", []) + review.get("findings", [])
    for finding in findings:
        support = finding.get("support", {})
        lines.append(
            '<article class="finding"><h3>'
            + _text(finding.get("severity", "unknown").capitalize())
            + ": "
            + _text(finding.get("title", finding.get("message", "Finding")))
            + "</h3>"
        )
        if support:
            lines.append(
                "<p>"
                + _text(support.get("rationale", ""))
                + '</p><p class="secondary">Declared finding confidence: '
                + _text(support.get("confidence", "unknown"))
                + "; scope: "
                + _text(support.get("scope", "unknown"))
                + ".</p>"
            )
            lines.append(
                "<p>Counterevidence: "
                + _text(support.get("counterevidence", "Not recorded"))
                + "</p>"
                + _list(support.get("limitations", []))
            )
        lines.append(
            '<p class="secondary">Evidence: '
            + _text(", ".join(finding.get("evidence_ids", [])) or "none recorded")
            + ".</p></article>"
        )
    if not findings:
        lines.append("<p>No findings were recorded. This is not proof of absent risks.</p>")
    plan = review.get("plan") or report.get("goal_alignment", {}).get("plan")
    lines += [
        '</section><section aria-labelledby="plan-heading"><h2 id="plan-heading">Diagnosis and improvement plan</h2>'
    ]
    if plan:
        lines += [
            "<p>"
            + _text(plan.get("diagnosis", ""))
            + "</p><p>Target state: "
            + _text(plan.get("target_state", ""))
            + "</p>"
        ]
        for item in plan.get("initiatives", []):
            lines.append(
                '<article class="initiative"'
                + (' id="initiative-' + _text(item["id"]) + '"' if item.get("id") else "")
                + "><h3>"
                + _text(item.get("title", "Initiative"))
                + "</h3>"
            )
            for label, key in (
                ("Priority", "priority"),
                ("Root cause", "root_cause"),
                ("Scope", "scope"),
                ("Burden effect", "burden_effect"),
                ("First slice", "first_slice"),
            ):
                lines.append(
                    "<p><strong>"
                    + label
                    + ":</strong> "
                    + _text(item.get(key, "Not recorded"))
                    + "</p>"
                )
            lines.append(
                "<p>Acceptance evidence:</p>" + _list(item.get("acceptance", [])) + "</article>"
            )
    else:
        lines.append(
            "<p>No authored improvement plan is saved. Source leads and numeric targets do not supply a diagnosis.</p>"
        )
    lines += [
        '</section><section aria-labelledby="coverage-heading"><h2 id="coverage-heading">Coverage, confidence and progress</h2>',
        "<p>Assessment and review are frozen records. Source binding verifies captured identity, not runtime effectiveness or the truth of a judgment. "
        "Badges show the same saved ratings; finding severity is separate from confidence.</p>",
        "<p>"
        + (
            "Saved goals are shown in the scorecard."
            if report.get("goals")
            else "No goals are saved; target values remain unknown."
        )
        + "</p>",
        "<details><summary>Complete assessment, evidence scope and progress</summary><pre>"
        + _text(markdown_report(report))
        + "</pre></details>",
        "<details><summary>Three.js license</summary><pre>"
        + _text(_asset_text("THREE-LICENSE.txt"))
        + "</pre></details>",
        "</section></main><script>" + script + "</script></body></html>",
    ]
    return "\n".join(lines)


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
