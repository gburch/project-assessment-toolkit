"""Large per-file analyzer evidence must not hide its coverage totals."""

import json
from copy import deepcopy

from project_assess.service import AssessmentService, _coverage_summary, canonical


def test_detailed_coverage_stays_queryable_while_summary_views_fit_their_budget(tmp_path):
    root = tmp_path / "project"
    (root / "src/pkg").mkdir(parents=True)
    (root / "src/pkg/main.py").write_text("def run(value):\n    return value\n")
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    rows = [
        {"path": f"src/pkg/module_{index:04}.py", "count": 20, "retained": 10}
        for index in range(1961)
    ]
    table = {"status": "partial", "count": 1964, "omitted": 3, "rows": rows}
    compatibility = {
        "adjusted_files": 700,
        "numeric_keys": 1400,
        "unsupported_numeric_keys": 0,
        "files": [
            {"path": f"src/pkg/typed_{index:04}.ts", "source_digest": "sha256:" + "a" * 64}
            for index in range(700)
        ],
    }
    methods = {"count": 74963, "omitted": 54963, "source_files": 1964, "file_coverage": table}
    coverage = {
        "eligible_files": 2374,
        "modeled_files": 2373,
        "batches": [
            {
                "status": "partial",
                "model_sections": {"methods": methods},
                "ast_compatibility": compatibility,
            }
        ],
    }
    stats = {
        "schema_version": 1,
        "status": "partial",
        "analyzer": {"name": "joern"},
        "coverage": coverage,
        "candidate_counts": {"total": 0},
        "candidates": [],
        "gaps": [],
        "modules": [
            {
                "path": "src/pkg/main.py",
                "role": "production",
                "method_rows_retained": 10,
                "method_model_count": 20,
            }
        ],
    }
    evidence = {
        "id": "e-joern",
        "path": "<joern-analysis>",
        "kind": "analyzer-analysis",
        "digest": "sha256:" + "b" * 64,
        "lines": 0,
        "stats": stats,
    }
    snapshot["evidence"].append(evidence)
    snapshot["facts"]["optional_analysis"] = {
        "joern": {
            "coverage": deepcopy(coverage),
            "status": "partial",
            "evidence_id": evidence["id"],
        },
        "legacy": {"status": "unavailable"},
    }
    original = canonical(snapshot)
    with service._db(write=True) as db:
        db.execute("UPDATE assessments SET data=? WHERE id=?", (original, snapshot["id"]))
    brief = service.overview(snapshot["id"])
    assert brief["optional_analysis"]["legacy"] == {"status": "unavailable"}
    reply = service.query_evidence(snapshot["id"], view="coverage", max_chars=48000, limit=100)
    query = next(row for row in reply["items"] if row.get("evidence_id") == evidence["id"])
    doctor = service.doctor(snapshot["id"])
    diagnosis = next(
        row for row in doctor["analysis_scope"]["analyses"] if row["evidence_id"] == evidence["id"]
    )
    assert len(json.dumps(reply, indent=2)) <= 48000 and reply["oversized_rows"] == 0
    assert len(canonical(brief)) < 48000
    for value in (
        brief["optional_analysis"]["joern"]["coverage"],
        query["coverage"],
        diagnosis["coverage"],
    ):
        batch = value["batches"][0]
        method_summary = batch["model_sections"]["methods"]
        detail = method_summary["file_coverage"]
        assert value["eligible_files"] == 2374 and method_summary["count"] == 74963
        assert detail["count"] == 1964 and detail["omitted"] == 3
        assert "rows" not in detail and detail["rows_retained_in_evidence"] == 1961
        assert detail["details_available"] and detail["details_path"].endswith("file_coverage.rows")
        ast = batch["ast_compatibility"]
        assert "files" not in ast and ast["files_retained_in_evidence"] == 700
        assert ast["numeric_keys"] == 1400 and ast["unsupported_numeric_keys"] == 0
    modules = service.query_evidence(snapshot["id"], view="graph", path="src/pkg/main.py")["items"]
    module = next(row for row in modules if row["evidence_id"] == evidence["id"])
    assert module["method_rows_retained"] == 10 and module["method_model_count"] == 20
    assert service.evidence(snapshot["id"], evidence["id"])["stats"]["coverage"] == coverage
    assert service.get_report(snapshot["id"])["assessment"] == snapshot
    with service._db() as db:
        assert (
            db.execute("SELECT data FROM assessments WHERE id=?", (snapshot["id"],)).fetchone()[0]
            == original
        )


def test_legacy_or_unrelated_coverage_is_preserved():
    for coverage in (
        {},
        {"parsed_files": 7},
        {"batches": [{"other": {"rows": [1, 2]}}]},
        {"batches": [None]},
    ):
        original = deepcopy(coverage)
        assert _coverage_summary(coverage) == coverage == original
