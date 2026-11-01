import json
import subprocess

import pytest

from project_assess import change_history
from project_assess.collector import _git_configuration


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def commit(root, files, message="private commit message must not be retained"):
    for path, text in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    git(root, "add", "-A")
    git(root, "commit", "-qm", message, "--allow-empty")
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "private author identity")
    git(root, "config", "user.email", "private@example.invalid")
    return root


def read(root, names, revision, **kwargs):
    return change_history.collect_change_history(
        *_git_configuration(root), names, revision, **kwargs
    )


def test_history_retains_only_captured_paths_and_cochange_not_people_or_messages(repository):
    first = commit(
        repository,
        {"src/app.py": "first\n", "docs/guide.md": "guide\n", ".env": "secret-unretained\n"},
    )
    second = commit(repository, {"src/app.py": "second\n", "docs/guide.md": "revised\n"})
    names = {"src/app.py", "docs/guide.md"}
    result = read(repository, names, second)
    assert result == read(repository, names, second)
    assert [row["revision"] for row in result["commits"]] == [second, first]
    assert result["cochanges"] == [{"paths": ["docs/guide.md", "src/app.py"], "commits": 2}]
    assert result["coverage"]["uncaptured_path_occurrences"] == 1
    assert all(row["paths"] == sorted(names) for row in result["commits"])
    serialized = json.dumps(result)
    for secret in (
        ".env",
        "private author identity",
        "private@example.invalid",
        "private commit message",
        "secret-unretained",
    ):
        assert secret not in serialized
    assert "not required edit sites" in result["caveat"]


def test_history_limits_older_commits_and_path_pairs_explicitly(repository, monkeypatch):
    for n in range(4):
        revision = commit(repository, {f"src/{name}.py": str(n) for name in "abc"})
    monkeypatch.setattr(change_history, "MAX_PATHS_PER_COMMIT", 2)
    monkeypatch.setattr(change_history, "MAX_COCHANGES", 1)
    result = read(repository, {f"src/{name}.py" for name in "abc"}, revision, max_commits=2)
    assert result["coverage"]["commits_observed"] == 3
    assert result["coverage"]["commits_retained"] == 2
    assert result["coverage"]["retention_path_omissions"] == 2
    assert all(len(row["paths"]) == 2 for row in result["commits"])
    assert any("commit limit" in gap for gap in result["gaps"])
    assert any("path or pair retention" in gap for gap in result["gaps"])


def test_missing_revision_does_not_launch_git_and_head_mismatch_does_not_rebind(
    repository, monkeypatch
):
    revision = commit(repository, {"app.py": "source\n"})
    mismatch = read(repository, {"app.py"}, "f" * 40)
    assert mismatch["head_observed"] == revision
    assert mismatch["status"] == "unavailable"
    assert mismatch["commits"] == [] and mismatch["cochanges"] == []
    assert any("does not match" in gap for gap in mismatch["gaps"])
    monkeypatch.setattr(
        change_history.subprocess, "Popen", lambda *a, **k: pytest.fail("must not launch Git")
    )
    assert read(repository, {"app.py"}, None)["status"] == "unavailable"


def test_hostile_git_extensions_are_not_executed(repository, tmp_path):
    revision = commit(repository, {"app.py": "source\n"})
    marker = tmp_path / "executed"
    script = tmp_path / "hostile.sh"
    script.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n")
    script.chmod(0o755)
    git(repository, "config", "core.fsmonitor", str(script))
    git(repository, "config", "core.hooksPath", str(script))
    git(repository, "config", "diff.external", str(script))
    git(repository, "config", "gpg.program", str(script))
    git(repository, "config", "log.showSignature", "true")
    result = read(repository, {"app.py"}, revision)
    assert result["commits"][0]["paths"] == ["app.py"]
    assert not marker.exists()


def test_shallow_and_empty_commits_remain_explicit(repository, tmp_path):
    commit(repository, {"app.py": "one\n", "docs/guide.md": "guide\n"})
    revision = commit(repository, {})
    complete = read(repository, {"app.py", "docs/guide.md"}, revision)
    assert complete["status"] == "complete"
    assert complete["commits"][0]["paths"] == []
    shallow = tmp_path / "shallow"
    subprocess.check_call(
        ["git", "clone", "--depth=1", "--no-local", "-q", str(repository), str(shallow)]
    )
    result = read(shallow, {"app.py", "docs/guide.md"}, revision)
    assert result["coverage"]["shallow"] is True
    assert result["status"] == "partial"
    assert any("shallow" in gap for gap in result["gaps"])
    assert result["commits"][0]["boundary_omitted"] is True
    assert result["commits"][0]["paths"] == []
    assert result["cochanges"] == []
    assert result["coverage"]["boundary_commits_omitted"] == 1


def test_oversized_output_is_bounded_and_does_not_return_partial_metadata(repository, monkeypatch):
    revision = commit(repository, {"app.py": "source\n"})
    monkeypatch.setattr(change_history, "MAX_OUTPUT_BYTES", 16)
    result = read(repository, {"app.py"}, revision)
    assert result["status"] == "unavailable"
    assert result["commits"] == []
    assert any("byte limit" in gap for gap in result["gaps"])


@pytest.mark.parametrize(
    "payload", [b"bad", b"\0wrong\0date\0\0", b"\0" + b"a" * 40 + b"\0no-date\0\0"]
)
def test_malformed_metadata_does_not_masquerade_as_history(payload):
    with pytest.raises(ValueError):
        change_history._parse_history(payload)


def test_history_parameter_bounds_are_not_project_options(repository):
    for options in (
        {"max_commits": 0},
        {"max_commits": 31},
        {"max_commits": True},
        {"timeout_seconds": 6},
        {"timeout_seconds": 0},
    ):
        with pytest.raises(ValueError):
            read(repository, set(), None, **options)
