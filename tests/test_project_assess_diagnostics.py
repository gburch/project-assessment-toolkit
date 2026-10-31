"""Supplied SARIF remains bounded, source-local, redacted and unverified."""

import json
from copy import deepcopy

import pytest

from project_assess import collector, diagnostics
from project_assess.cli import main
from project_assess.service import AssessmentService


def diagnostic(
    uri="app.py", *, line=1, code="rule/custom", message="Inspect this behavior", level="warning"
):
    return {
        "ruleId": code,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
    }


def report(rows, *, name="Synthetic ESLint", **fields):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": name}}, "results": rows}],
        **fields,
    }


def parse(document, root, paths=None, redact=collector._redact):
    return diagnostics.sarif_report(
        json.dumps(document).encode(), root, {"app.py"} if paths is None else paths, redact
    )


def test_standard_sarif_keeps_only_located_diagnostic_fields_and_producer_claims(tmp_path):
    row = diagnostic()
    row["fixes"] = [
        {
            "artifactChanges": [
                {"replacements": [{"insertedContent": {"text": "raw-fix-must-not-appear"}}]}
            ]
        }
    ]
    row["message"]["markdown"] = "raw-markdown-must-not-appear"
    row["properties"] = {"secret": "raw-properties-must-not-appear"}
    document = report([row], **{"$schema": "https://example.invalid/never-fetch-a-schema"})

    result = parse(document, tmp_path)

    assert result["status"] == "complete" and result["source_identity"] == "unverified"
    assert result["summary"] == {"diagnostics": 1, "supplied": 1, "runs": 1, "results_examined": 1}
    assert result["diagnostics"] == [
        {
            "tool": "Synthetic ESLint",
            "code": "rule/custom",
            "producer_level": "warning",
            "message": "Inspect this behavior",
            "path": "app.py",
            "line": 1,
            "end_line": 1,
        }
    ]
    serialized = json.dumps(result)
    for excluded in ("raw-fix", "raw-markdown", "raw-properties", "never-fetch"):
        assert excluded not in serialized
    assert "zero diagnostics is not a clean-project rating" in result["gaps"][0]


def test_relative_absolute_and_percent_decoded_file_uris_match_captured_paths_only(tmp_path):
    rows = [
        diagnostic("./app.py"),
        diagnostic(str(tmp_path / "app.py")),
        diagnostic((tmp_path / "app.py").as_uri()),
        diagnostic("src/file%20name.ts"),
    ]
    result = parse(report(rows), tmp_path, {"app.py", "src/file name.ts"})

    assert result["summary"]["diagnostics"] == 4 and result["status"] == "complete"
    assert {row["path"] for row in result["diagnostics"]} == {"app.py", "src/file name.ts"}
    assert str(tmp_path) not in json.dumps(result)


@pytest.mark.parametrize(
    "uri",
    [
        "../app.py",
        "src/../app.py",
        "%2e%2e/app.py",
        "src/%2e%2e/app.py",
        "src%2F..%2Fapp.py",
        "/elsewhere/app.py",
        "file:///elsewhere/app.py",
        "file://remote-host/app.py",
        "file:app.py",
        "https://user:private-uri-value@example.invalid/app.py",
        "//remote-host/app.py",
        "app.py?token=private-uri-value",
        "app.py#fragment",
        "app%00.py",
        "src\\app.py",
        "uncaptured.py",
    ],
)
def test_uri_escapes_network_and_uncaptured_paths_are_omitted_without_raw_values(tmp_path, uri):
    result = parse(report([diagnostic(uri)]), tmp_path)
    assert result["status"] == "partial" and result["diagnostics"] == []
    assert any("source scope" in gap for gap in result["gaps"])
    assert "private-uri-value" not in json.dumps(result)


def test_redaction_happens_before_field_caps_and_no_edit_text_is_retained(tmp_path):
    marker = "private-field-tail-that-crosses-the-output-cap"
    seen = []

    def redact(value):
        seen.append(len(value))
        return value.replace(marker, "[redacted]")

    result = parse(
        report(
            [diagnostic(code="c" * 120 + marker, message="m" * 490 + marker)],
            name="n" * 120 + marker,
        ),
        tmp_path,
        redact=redact,
    )

    assert any(length > 500 for length in seen)
    row = result["diagnostics"][0]
    assert len(row["message"]) <= 500 and len(row["code"]) <= 128 and len(row["tool"]) <= 128
    assert "private-field" not in json.dumps(result)
    token = "ghp_" + "SYNTHETIC" * 3
    redacted = parse(report([diagnostic(message=token)], name=token), tmp_path)
    assert token not in json.dumps(redacted)
    assert "[REDACTED]" in json.dumps(redacted)


@pytest.mark.parametrize(
    "payload",
    [
        b"{",
        b"[]",
        b'{"version":"1.0","runs":[]}',
        b'{"version":"2.1.0","runs":null}',
        b'{"version":"2.1.0","version":"2.1.0","runs":[]}',
        b'{"version":"2.1.0","runs":[],"ignored":NaN}',
    ],
)
def test_invalid_documents_return_explicit_partial_import_without_exception_or_echo(
    tmp_path, payload
):
    result = diagnostics.sarif_report(payload, tmp_path, {"app.py"}, collector._redact)
    assert result["status"] == "partial" and result["diagnostics"] == []
    assert result["source_identity"] == "unverified"
    assert any("Malformed" in gap for gap in result["gaps"])


def test_malformed_nested_rows_and_unsupported_bases_are_partial_not_healthy(tmp_path):
    rows = [None, diagnostic(line=True), diagnostic(line=-1), diagnostic()]
    rows[3]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "%SRCROOT%"
    unknown_level = diagnostic(level={"unsafe": "untrusted"})
    rows.append(unknown_level)
    multiple = diagnostic()
    multiple["locations"].append(deepcopy(multiple["locations"][0]))
    rows.append(multiple)
    document = report(rows)
    document["runs"].extend([None, {"tool": [], "results": []}])
    result = parse(document, tmp_path)

    assert result["status"] == "partial" and len(result["diagnostics"]) == 2
    assert any(row["producer_level"] is None for row in result["diagnostics"])
    assert any("URI bases" in gap for gap in result["gaps"])
    assert any("first SARIF" in gap for gap in result["gaps"])
    assert any("Malformed SARIF" in gap for gap in result["gaps"])


def test_traversal_run_and_byte_limits_are_explicit_even_for_invalid_prefixes(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(diagnostics, "MAX_DIAGNOSTICS", 2)
    result = parse(report([None, diagnostic(), diagnostic()]), tmp_path)
    assert result["summary"]["supplied"] == 3 and result["summary"]["results_examined"] == 2
    assert len(result["diagnostics"]) == 1 and result["status"] == "partial"
    assert any("traversal limit" in gap for gap in result["gaps"])
    monkeypatch.setattr(diagnostics, "MAX_RUNS", 1)
    document = report([])
    document["runs"].append(deepcopy(document["runs"][0]))
    assert any("run limit" in gap for gap in parse(document, tmp_path)["gaps"])
    monkeypatch.setattr(diagnostics, "MAX_BYTES", 5)
    assert parse(report([]), tmp_path)["status"] == "partial"


def test_default_2000_result_cap_and_deterministic_normalization(tmp_path):
    rows = [diagnostic(line=index + 1) for index in range(2001)]
    bounded = parse(report(rows), tmp_path)
    assert len(bounded["diagnostics"]) == bounded["summary"]["results_examined"] == 2000
    assert bounded["summary"]["supplied"] == 2001 and bounded["status"] == "partial"
    assert parse(report(rows[:5]), tmp_path) == parse(report(list(reversed(rows[:5]))), tmp_path)


@pytest.mark.parametrize("suffix", [".sarif", ".sarif.json"])
def test_cli_import_query_doctor_and_report_authorization(tmp_path, capsys, suffix):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text(
        "raise AssertionError('Assessment must not execute target code')\n"
    )
    supplied = tmp_path / ("native" + suffix)
    row = diagnostic(message='api_key = "private-sarif-message"', level="error")
    row["fixes"] = [{"description": {"text": "private-sarif-fix"}}]
    supplied.write_text(json.dumps(report([row])))
    state = tmp_path / "state"
    args = ["--state-dir", str(state)]
    assert main([*args, "scan", str(root), "--report", str(supplied)]) == 0
    snapshot = json.loads(capsys.readouterr().out)
    entry = next(row for row in snapshot["evidence"] if row["kind"] == "sarif")
    assert snapshot["facts"]["reports"]["sarif"] == {
        "files": 1,
        "diagnostics": 1,
        "source_identity": "unverified",
        "supplied": 1,
    }
    assert entry["stats"]["source_identity"] == "unverified"
    assert "private-sarif" not in json.dumps(snapshot)
    service = AssessmentService(state)
    before = service.history(snapshot["project_id"])
    assert (
        main(
            [
                *args,
                "evidence-query",
                snapshot["id"],
                "--view",
                "candidates",
                "--candidate-kind",
                "sarif_diagnostic",
            ]
        )
        == 0
    )
    query = json.loads(capsys.readouterr().out)
    assert len(query["items"]) == 1 and query["items"][0]["source_identity"] == "unverified"
    assert query["items"][0]["producer_level"] == "error" and "severity" not in query["items"][0]
    assert main([*args, "doctor", snapshot["id"], "--limit", "10"]) == 0
    doctor = json.loads(capsys.readouterr().out)
    candidate = next(
        row for row in doctor["groups"]["quality"] if row["kind"] == "sarif_diagnostic"
    )
    assert candidate["family"] == "sarif" and candidate["source_identity"] == "unverified"
    assert candidate["candidate_confidence"]["basis"] == "supplied_unverified_diagnostic"
    assert not candidate["candidate_confidence"]["defect_established"]
    assert all(
        row["capability"] is row["burden"] is None
        for row in service.review_template(snapshot["id"])["ratings"].values()
    )
    assert service.history(snapshot["project_id"]) == before
    restricted = AssessmentService(state, [root])
    with pytest.raises(PermissionError, match="report is outside"):
        restricted.get_report(snapshot["id"])


def test_sarif_uses_existing_safe_report_reads_and_json_total_budget(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    path = tmp_path / "report.sarif"
    path.write_text(json.dumps(report([])))
    alias = tmp_path / "alias.sarif"
    alias.symlink_to(path)
    with pytest.raises(ValueError, match="symlinks"):
        collector.collect(root, [alias])
    monkeypatch.setattr(collector, "MAX_TEST_VALUE_REPORT_TOTAL_BYTES", 5)
    with pytest.raises(ValueError, match="cumulative byte limit"):
        collector.collect(root, [path])


def test_large_ruff_report_does_not_hide_distinct_sarif_family(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    ruff = tmp_path / "ruff.json"
    ruff.write_text(
        json.dumps(
            [
                {
                    "filename": "app.py",
                    "code": "F401",
                    "message": f"Synthetic diagnostic {index}",
                    "location": {"row": 1},
                }
                for index in range(100)
            ]
        )
    )
    sarif = tmp_path / "native.sarif"
    sarif.write_text(json.dumps(report([diagnostic()])))
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root, [ruff, sarif])

    doctor = service.doctor(snapshot["id"], limit=2)

    assert {row["family"] for group in doctor["groups"].values() for row in group} == {
        "ruff",
        "sarif",
    }
    assert sum(len(group) for group in doctor["groups"].values()) == 2


def test_malformed_sarif_does_not_abort_project_scan_or_hide_import_gap(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    supplied = tmp_path / "invalid.sarif"
    supplied.write_text('{"version":"2.1.0","runs": "private-malformed-value"}')
    snapshot = collector.collect(root, [supplied])
    entry = next(row for row in snapshot["evidence"] if row["kind"] == "sarif")
    assert entry["stats"]["status"] == "partial" and not snapshot["complete"]
    assert any("Malformed" in gap for gap in snapshot["gaps"])
    assert "private-malformed-value" not in json.dumps(snapshot)
