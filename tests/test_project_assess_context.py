"""Source drill-down remains bounded, redacted and tied to captured bytes."""

import os
from copy import deepcopy

import pytest

from project_assess.provenance import tool_info
from project_assess.service import AssessmentService, _goal_alignment
from project_assess.source_context import read_context


def fixture(tmp_path, content):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "app.py"
    source.write_text(content)
    service = AssessmentService(tmp_path / "state")
    snapshot = service.scan(root)
    entry = next(row for row in snapshot["evidence"] if row["path"] == "app.py")
    return root, source, service, snapshot, entry


def test_context_reads_real_location_after_initial_excerpt_and_refuses_changed_bytes(tmp_path):
    root, source, _, _, entry = fixture(tmp_path, "# overview\n" * 120 + "value = 1\n")
    context = read_context(root, entry, line=121, end_line=121)
    assert context["excerpt"] == "value = 1"
    assert context["source_identity"] == "snapshot_matched_live_bytes"
    assert context["digest"] == entry["digest"]
    before = source.stat()
    source.write_text("# overview\n" * 120 + "value = 2\n")
    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ValueError, match="changed since capture"):
        read_context(root, entry, line=121)


def test_context_redacts_private_material_whose_marker_is_outside_requested_range(tmp_path):
    content = 'value = """-----BEGIN PRIVATE KEY-----\nnever-expose-this-line\n-----END PRIVATE KEY-----"""\n'
    root, _, _, _, entry = fixture(tmp_path, content)
    result = read_context(root, entry, line=2, end_line=2)
    assert "never-expose" not in result["excerpt"]
    assert "REDACTED" in result["excerpt"]


def test_large_captured_source_context_uses_the_source_bound_and_counts_trailing_comments(tmp_path):
    content = "value = 1\n" + "# retained trailing context\n" * 50000
    assert len(content.encode()) > 1024 * 1024
    root, _, _, snapshot, entry = fixture(tmp_path, content)
    result = read_context(root, entry, line=50001, end_line=50001)
    assert result["excerpt"] == "# retained trailing context"
    analysis = next(row for row in snapshot["evidence"] if row["kind"] == "static-analysis")
    assert analysis["stats"]["modules"][0]["lines"] == 50001


def test_context_denies_symlink_replacement_even_when_outside_bytes_match(tmp_path):
    root, source, _, _, entry = fixture(tmp_path, "value = 1\n")
    outside = tmp_path / "outside.py"
    outside.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(outside)
    with pytest.raises(ValueError, match="inaccessible"):
        read_context(root, entry)


def test_context_denies_swapped_parent_symlink(tmp_path):
    root, source, _, _, entry = fixture(tmp_path, "value = 1\n")
    moved = tmp_path / "moved"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError, match="inaccessible"):
        read_context(root, entry)
    assert (moved / source.name).read_text() == "value = 1\n"


@pytest.mark.parametrize(
    "options", [{"line": 0}, {"line": True}, {"end_line": 0}, {"max_chars": 100000}]
)
def test_context_rejects_ambiguous_or_unbounded_parameters(tmp_path, options):
    root, _, _, _, entry = fixture(tmp_path, "value = 1\n")
    with pytest.raises(ValueError):
        read_context(root, entry, **options)


def test_context_excludes_report_and_synthetic_ids_and_bounds_line_count(tmp_path):
    root, _, _, _, entry = fixture(tmp_path, "# line\n" * 300)
    result = read_context(root, entry, line=1, end_line=300)
    assert result["truncated"] and result["end_line"] == 200
    assert len(result["excerpt"].splitlines()) == 200
    foreign = {**entry, "kind": "junit", "path": "/outside/report.xml"}
    with pytest.raises(ValueError, match="captured source"):
        read_context(root, foreign)


def test_character_budget_reports_only_displayed_lines_and_a_continuation(tmp_path):
    root, _, _, _, entry = fixture(tmp_path, ("# " + "x" * 98 + "\n") * 30)
    result = read_context(root, entry, line=1, end_line=30, max_chars=256)
    assert len(result["excerpt"]) == 256
    assert len(result["excerpt"].splitlines()) == result["end_line"] == 3
    assert result["truncated"] and result["line_truncated"]
    assert result["next_line"] == 3
    continuation = read_context(root, entry, line=result["next_line"], end_line=4)
    assert continuation["excerpt"].splitlines()[0] == "# " + "x" * 98
    assert continuation["end_line"] == 4 and continuation["next_line"] is None


def test_tool_identity_separates_available_instructions_from_read_claims():
    first = tool_info()
    assert first == tool_info()
    assert first["distribution"] == "pat-assess"
    assert first["code_digest"].startswith("sha256:")
    assert first["available_instructions"]
    assert all(
        row["status"] == "available_not_attested_read" for row in first["available_instructions"]
    )
    assert all(len(row["sha256"]) == 64 for row in first["available_instructions"])


def test_source_critical_findings_survive_evolve_without_review_or_goals(tmp_path):
    _, _, _, snapshot, entry = fixture(tmp_path, "value = 1\n")
    snapshot = deepcopy(snapshot)
    critical = {
        "severity": "critical",
        "title": "Synthetic source boundary finding",
        "evidence_ids": [entry["id"]],
    }
    snapshot["findings"] = [critical]
    alignment = _goal_alignment(snapshot, None, None, None)
    assert alignment["urgent_findings"] == [critical]
    assert alignment["status"] == "no_goals"
