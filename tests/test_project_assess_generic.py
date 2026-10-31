"""Portable facts/reuse leads remain useful without pretending to understand a language."""

import json

from project_assess import generic_analysis as generic


def statements(prefix="source"):
    return "\n".join(f'    sink.record("{prefix}-{number}", value);' for number in range(18))


def test_swift_java_inventory_and_literal_block_reuse_without_execution():
    shared = statements()
    sources = {
        "src/First.swift": "func first() {\n" + shared + "\n}",
        "src/Second.swift": "func second() {\n" + shared + "\n}",
        "src/Main.java": "class Main { void run() {\n" + statements("other") + "\n} }",
    }
    result = generic.summarize_source_text(sources)
    assert result == generic.summarize_source_text(dict(reversed(list(sources.items()))))
    assert result["coverage"]["languages"] == {"java": 1, "swift": 2}
    assert all(row["syntax_analysis"] == "not_available" for row in result["modules"])
    blocks = [row for row in result["candidates"] if row["kind"] == "duplicate_source_block"]
    assert len(blocks) == 1  # Adjacent matching windows describe one copied region.
    assert {loc["path"] for row in blocks for loc in row["locations"]} == {
        "src/First.swift",
        "src/Second.swift",
    }
    assert all("semantic equivalence" in row["caveat"] for row in blocks)
    assert "complex_function" not in {row["kind"] for row in result["candidate_index"]}
    assert "swift" in " ".join(result["gaps"])


def test_exact_file_match_retains_literal_and_whitespace_differences():
    text = statements()
    result = generic.summarize_source_text(
        {
            "src/first.java": text,
            "src/second.java": text,
            "src/literals.java": text.replace("source", "different"),
            "src/indent.java": text.replace("    ", "  "),
        }
    )
    files = [row for row in result["candidates"] if row["kind"] == "duplicate_source_file"]
    assert len(files) == 1
    assert {row["path"] for row in files[0]["locations"]} == {"src/first.java", "src/second.java"}


def test_block_budget_preserves_all_module_facts_and_prioritizes_application_source():
    sources = {
        ".agents/first.swift": statements("tooling"),
        "tests/test_second.swift": statements("testing"),
        "src/ops/first.swift": "func first() {\n" + statements() + "\n}",
        "src/ops/second.swift": "func second() {\n" + statements() + "\n}",
    }
    result = generic.summarize_source_text(sources, max_blocks=18)
    assert result["status"] == "partial"
    assert result["coverage"]["source_files"] == 4
    assert result["coverage"]["blocks_examined"] == 18
    assert not result["coverage"]["block_analysis_complete"]
    assert any(row["kind"] == "duplicate_source_block" for row in result["candidates"])


def test_deadline_does_not_turn_unsearched_reuse_into_a_healthy_result(monkeypatch):
    monkeypatch.setattr(generic.time, "monotonic", lambda: 10)
    result = generic.summarize_source_text({"src/a.swift": statements()}, deadline=9)
    assert result["status"] == "partial"
    assert result["coverage"]["source_files"] == 1
    assert result["coverage"]["blocks_examined"] == 0
    assert any("deadline" in gap for gap in result["gaps"])


def test_literals_are_never_retained_in_generic_analysis_and_comments_are_not_code_proof():
    secret = "synthetic-private-value-never-serialize"
    result = generic.summarize_source_text(
        {
            "src/one.swift": statements(secret),
            "src/two.swift": statements(secret),
            "src/comments.java": "\n".join("// license text " + str(n) for n in range(30)),
        }
    )
    assert secret not in json.dumps(result)
    assert not any(
        loc["path"] == "src/comments.java"
        for row in result["candidates"]
        if row["kind"] == "duplicate_source_block"
        for loc in row["locations"]
    )


def test_supported_extension_inventory_requires_no_per_language_executables():
    for path, language in (
        ("a.swift", "swift"),
        ("a.java", "java"),
        ("a.rs", "rust"),
        ("a.go", "go"),
        ("a.kt", "kotlin"),
        ("a.cs", "csharp"),
    ):
        assert generic.source_language(path) == language
    assert generic.source_language("a.png") is None


def test_overlapping_matches_with_different_repeat_counts_remain_exact_windows():
    first, repeated, last = (
        "startUniqueOperation(0);\n",
        "doRepeatedOperation(0);\n",
        "endUniqueOperation(0);\n",
    )
    sources = {
        "src/A.swift": first + repeated * 11 + last,
        "src/B.swift": first + repeated * 12 + last,
    }
    result = generic.summarize_source_text(sources)
    blocks = [row for row in result["candidate_index"] if row["kind"] == "duplicate_source_block"]
    assert len(blocks) == 2
    for block in blocks:
        values = []
        for location in block["locations"]:
            assert set(location) == {"path", "line", "end_line"}
            selected = sources[location["path"]].splitlines()[
                location["line"] - 1 : location["end_line"]
            ]
            values.append("\n".join(line for line in selected if line.strip()))
        assert len(set(values)) == 1
        assert len(values[0].splitlines()) == generic.BLOCK_LINES


def test_aligned_nonblank_windows_still_merge_across_different_blank_line_spacing():
    shared = statements()
    sources = {
        "src/A.swift": "func first() {\n" + shared + "\n} // first only\n",
        "src/B.swift": "func second() {\n"
        + "\n\n".join(shared.splitlines())
        + "\n} // second only\n",
    }
    result = generic.summarize_source_text(sources)
    blocks = [row for row in result["candidate_index"] if row["kind"] == "duplicate_source_block"]
    assert len(blocks) == 1
    assert {
        location["path"]: (location["line"], location["end_line"])
        for location in blocks[0]["locations"]
    } == {
        "src/A.swift": (2, 19),
        "src/B.swift": (2, 36),
    }
