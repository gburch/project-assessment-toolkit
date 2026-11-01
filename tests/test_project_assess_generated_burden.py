"""Generated/vendor context must survive syntax summaries into burden leads."""

import hashlib
from copy import deepcopy

import pytest

from project_assess import javascript_analysis as javascript
from project_assess.burden_analysis import summarize_burden
from project_assess.service import AssessmentService


@pytest.fixture(autouse=True)
def parser_available():
    if not javascript.javascript_analyzer_identity()["available"]:
        pytest.skip("Optional analysis extra is not installed")


def complex_function(name):
    return (
        f"export function {name}(x) {{\n"
        "  if(x) { while(x) { if(x) { for(;;) { if(x) { return x; } } } } }\n"
        "  return 0;\n"
        "}\n"
    )


def burden_from_sources(sources):
    records = [javascript.analyze_javascript(path, text) for path, text in sources.items()]
    summary = javascript.summarize_javascript(records)
    evidence = [
        {
            "id": path,
            "kind": "javascript",
            "path": path,
            "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            "lines": text.count("\n") + bool(text),
            "stats": record,
        }
        for (path, text), record in zip(sources.items(), records, strict=True)
    ]
    evidence.append(
        {
            "id": "js-analysis",
            "kind": "javascript-analysis",
            "path": "<javascript-analysis>",
            "stats": summary,
        }
    )
    return summary, {"evidence": evidence}


def test_real_scan_preserves_generated_hint_without_excluding_authored_unknown_or_imports(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "ui").mkdir()
    (root / "src/report.generated.js").write_text(complex_function("generated"))
    (root / "ui/owner.js").write_text(
        "import {generated} from '../src/report.generated.js';\n"
        + complex_function("owner")
        + "throw new Error('Assessment must not execute this source');\n"
    )

    snapshot = AssessmentService(tmp_path / "state").scan(root)
    summary = next(e["stats"] for e in snapshot["evidence"] if e["kind"] == "javascript-analysis")
    modules = {row["path"]: row for row in summary["modules"]}
    assert modules["src/report.generated.js"]["generated_hint"] is True
    assert modules["ui/owner.js"]["role"] == "unknown"
    assert modules["ui/owner.js"]["generated_hint"] is False
    assert modules["ui/owner.js"]["vendor_hint"] is False
    assert summary["topology"]["edges"][0]["target"] == "src/report.generated.js"
    assert summary["coverage"]["parsed_files"] == 2
    hotspots = {row["path"]: row for row in summary["hotspots"]}
    assert hotspots["src/report.generated.js"]["generated_hint"] is True
    assert hotspots["ui/owner.js"]["generated_hint"] is False

    leads = {
        row["locations"][0]["path"]: row
        for row in summarize_burden(snapshot)["leads"]
        if row["kind"] == "complex_change_surface"
    }
    assert set(leads) == {"src/report.generated.js", "ui/owner.js"}
    assert leads["src/report.generated.js"]["metrics"]["generated_hint"] is True
    assert leads["ui/owner.js"]["metrics"]["generated_hint"] is False
    for path, lead in leads.items():
        source = next(e for e in snapshot["evidence"] if e["path"] == path)
        assert lead["locations"][0]["source_digest"] == source["digest"]
        assert lead["cost_status"] == "not_established"


def test_vendor_and_generated_leads_stay_qualified_when_authored_unknown_has_priority():
    sources = {
        "src/bundle.generated.js": complex_function("generated"),
        "vendor/sdk.js": complex_function("vendor"),
        "ui/owner.js": complex_function("owner"),
    }
    summary, assessment = burden_from_sources(sources)
    original = deepcopy(assessment)
    result = summarize_burden(assessment, limit=1)

    assert assessment == original
    assert summary == javascript.summarize_javascript(
        [javascript.analyze_javascript(path, text) for path, text in reversed(sources.items())]
    )
    assert result["coverage"]["by_kind"]["complex_change_surface"] == 3
    assert result["coverage"]["leads_omitted"] == 2
    assert result["leads"][0]["locations"][0]["path"] == "ui/owner.js"
    modules = {row["path"]: row for row in summary["modules"]}
    assert modules["vendor/sdk.js"]["vendor_hint"] is True
    assert modules["vendor/sdk.js"]["generated_hint"] is False
    full = summarize_burden(assessment)
    vendor = next(row for row in full["leads"] if row["locations"][0]["path"] == "vendor/sdk.js")
    assert vendor["metrics"]["vendor_hint"] is True
    assert len(summary["candidate_index"]) == 3  # Review leads remain visible; none are deleted.


def test_generated_qualifiers_do_not_turn_omitted_detail_into_complete_coverage(monkeypatch):
    monkeypatch.setattr(javascript, "MAX_FUNCTIONS", 1)
    generated = javascript.analyze_javascript(
        "src/bundle.generated.js", complex_function("first") + complex_function("second")
    )
    authored = javascript.analyze_javascript("ui/owner.js", complex_function("owner"))

    summary = javascript.summarize_javascript([generated, authored])

    assert summary["status"] == "partial"
    assert summary["coverage"]["functions_total"] == 3
    assert summary["coverage"]["functions_analyzed"] == 2
    modules = {row["path"]: row for row in summary["modules"]}
    assert modules["src/bundle.generated.js"]["generated_hint"] is True
    assert modules["src/bundle.generated.js"]["status"] == "partial"
    assert modules["src/bundle.generated.js"]["omitted_function_details"] == 1
    assert modules["ui/owner.js"]["generated_hint"] is False
    assert modules["ui/owner.js"]["status"] == "complete"
    assert not summary["topology"]["complete"]
