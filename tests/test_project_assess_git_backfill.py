import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime

import pytest

from project_assess import git_backfill, report_export
from project_assess.cli import main
from project_assess.service import AssessmentService, ConflictError


def git(root, *args, env=None):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, env={**os.environ, **(env or {})}
    ).strip()


def commit(root, files, date="2026-09-10T12:00:00+00:00"):
    for path, text in files.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    git(root, "add", "-A")
    dates = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    git(root, "commit", "-qm", "change", "--allow-empty", env=dates)
    return git(root, "rev-parse", "HEAD")


def fingerprint(root):
    """Names, bytes and modification times of everything, including .git."""
    rows = []
    for directory, names, files in os.walk(root):
        names.sort()
        for name in sorted(files):
            path = os.path.join(directory, name)
            info = os.lstat(path)
            payload = b"" if os.path.islink(path) else open(path, "rb").read()
            rows.append((path, info.st_mtime_ns, hashlib.sha256(payload).hexdigest()))
    return rows


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Backfill Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    return root


def ratings(service, snapshot):
    draft = service.review_template(snapshot["id"])
    del draft["coverage"]
    source_id = next(e["id"] for e in snapshot["evidence"] if e["kind"] == "python")
    for rating in draft["ratings"].values():
        rating.update(
            capability=2,
            burden=3,
            confidence="medium",
            burden_confidence="low",
            burden_basis="source_estimate",
            rationale="A source-supported judgment.",
            recommendations=[],
            evidence_ids=[source_id],
        )
    return draft


def test_backfill_reads_git_objects_without_running_filters_or_writing_the_project(
    repository, tmp_path
):
    marker = tmp_path / "filter-ran"
    # A repository-configured smudge filter would run on checkout or git archive.
    git(repository, "config", "filter.trap.smudge", f"touch {marker}; cat")
    old = commit(
        repository,
        {
            ".gitattributes": "*.py filter=trap\n",
            "src/app.py": "VALUE = 1\n",
            ".env": "API_KEY=never-copied\n",
            "node_modules/pkg/index.js": "module.exports = 1\n",
        },
    )
    (repository / "link.py").symlink_to("src/app.py")
    commit(repository, {"src/app.py": "VALUE = 2\n"}, date="2026-10-20T12:00:00+00:00")
    before = fingerprint(repository)
    service = AssessmentService(tmp_path / "state")

    result = service.backfill(repository, revisions=[old[:12]])

    assert fingerprint(repository) == before
    assert not marker.exists()
    (row,) = result["snapshots"]
    assert row["status"] == "captured" and row["revision"] == old
    snapshot = service.history(result["project_id"])["assessments"][0]
    source = snapshot["source"]
    assert source["root"] == str(repository.resolve()) and source["revision"] == old
    assert source["origin"]["kind"] == "git-commit"
    assert source["origin"]["committed_at"] == "2026-09-10T12:00:00Z"
    assert source["origin"]["as_of"] == "2026-09-10T12:00:00+00:00"
    assert source["origin"]["tree"] == git(repository, "rev-parse", old + "^{tree}")
    assert source["origin"]["extraction"]["omitted"]["credential_files"] == 1
    assert source["origin"]["extraction"]["omitted"]["excluded_directory_files"] == 1
    assert snapshot["facts"]["collection"]["excluded_directory_prefixes"] == [
        {"path": "node_modules", "reason": "dependency/build/VCS directories"}
    ]
    app = next(e for e in snapshot["evidence"] if e["path"] == "src/app.py")
    assert app["digest"] == "sha256:" + hashlib.sha256(b"VALUE = 1\n").hexdigest()
    assert "never-copied" not in json.dumps(snapshot)
    tree = git_backfill.snapshot_directory(service.state_dir, result["project_id"], old)
    assert not (tree / ".env").exists() and not (tree / ".git").exists()
    assert oct((tree / "src" / "app.py").stat().st_mode & 0o777) == "0o600"
    assert any("Facts from committed Git objects only" in gap for gap in snapshot["gaps"])


def test_monthly_selection_takes_each_month_end_state_and_reports_empty_months(repository):
    august = commit(repository, {"a.py": "1\n"}, date="2026-08-15T12:00:00+00:00")
    commit(repository, {"a.py": "2\n"}, date="2026-09-10T12:00:00+00:00")
    september = commit(repository, {"a.py": "3\n"}, date="2026-09-20T12:00:00-07:00")
    october = commit(repository, {"a.py": "4\n"}, date="2026-10-05T12:00:00+00:00")

    plan = git_backfill.select_commits(
        repository, months=4, today=datetime(2026, 11, 1, 9, tzinfo=UTC)
    )

    assert [row["revision"] for row in plan["commits"]] == [august, september, october]
    assert [row["selected_by"] for row in plan["commits"]] == [
        ["month-end 2026-08"],
        ["month-end 2026-09"],
        ["month-end 2026-10"],
    ]
    assert plan["commits"][1]["as_of"] == "2026-09-20T19:00:00+00:00"
    assert plan["gaps"] == ["No first-parent commit before 2026-08-01"]


def test_tags_and_revisions_are_bounded_and_never_parsed_as_options(repository):
    first = commit(repository, {"a.py": "1\n"})
    git(repository, "tag", "v1")
    second = commit(repository, {"a.py": "2\n"}, date="2026-10-01T00:00:00+00:00")
    git(repository, "tag", "-a", "v2", "-m", "annotated")

    tags = git_backfill.select_commits(repository, tags=5)
    assert [row["revision"] for row in tags["commits"]] == [first, second]
    assert [row["selected_by"] for row in tags["commits"]] == [["tag v1"], ["tag v2"]]

    listed = git_backfill.select_commits(repository, revisions=["v2", "HEAD", "missing"])
    assert [row["revision"] for row in listed["commits"]] == [second]
    assert listed["commits"][0]["selected_by"] == ["revision v2", "revision HEAD"]
    assert listed["gaps"] == ["Unknown or non-commit revision: missing"]

    for bad in (["--output=/tmp/x"], ["HEAD:secret.txt"], ["a b"], ["x"] * 13, []):
        with pytest.raises(ValueError, match="Revisions must be"):
            git_backfill.select_commits(repository, revisions=bad)
    for selection in ({}, {"months": 1, "tags": 1}):
        with pytest.raises(ValueError, match="exactly one"):
            git_backfill.select_commits(repository, **selection)
    for count in (0, 13, True, "3"):
        with pytest.raises(ValueError, match="from 1 to 12"):
            git_backfill.select_commits(repository, months=count)


def test_unsafe_paths_and_corrupt_objects_are_never_written():
    assert git_backfill._safe_parts("src/app.py") == ("src", "app.py")
    for path in ("../escape.py", "a/.GIT/config", "/abs.py", "a/./b.py", "bad\nname.py"):
        assert git_backfill._safe_parts(path) is None
    payload = b"VALUE = 1\n"
    oid = hashlib.sha1(b"blob %d\0" % len(payload) + payload).hexdigest()
    assert git_backfill._verified(oid, payload)
    assert not git_backfill._verified(oid, b"VALUE = 2\n")


def test_backfills_stack_by_commit_date_behind_the_live_scan_and_stay_unrated(repository, tmp_path):
    old = commit(repository, {"app.py": "VALUE = 1\n"}, date="2026-08-01T00:00:00+00:00")
    middle = commit(repository, {"app.py": "VALUE = 2\n"}, date="2026-09-01T00:00:00+00:00")
    commit(repository, {"app.py": "VALUE = 3\n"}, date="2026-10-01T00:00:00+00:00")
    service = AssessmentService(tmp_path / "state")
    live = service.scan(repository)
    service.submit_review(live["id"], ratings(service, live))

    # Inserted after the live scan, yet ordered by commit date before it.
    result = service.backfill(repository, revisions=[middle, old])
    assert [row["revision"] for row in result["snapshots"]] == [old, middle]
    repeat = service.backfill(repository, revisions=[old])
    assert repeat["snapshots"][0]["status"] == "existing"

    (project,) = service.list_projects()
    assert project["latest_assessment_id"] == live["id"]
    timeline = report_export.dimension_map_data(service.get_report(live["id"]))["timeline"]
    assert [entry["revision"] for entry in timeline] == [
        old[:7],
        middle[:7],
        live["source"]["revision"][:7],
    ]
    assert [entry["origin"] for entry in timeline] == ["git-commit", "git-commit", "scan"]
    assert [entry["date"] for entry in timeline[:2]] == ["2026-08-01", "2026-09-01"]
    assert all(entry["reviewed"] is False for entry in timeline[:2])
    assert all(entry["scores"]["security"] == [None, None] for entry in timeline[:2])
    assert timeline[2]["scores"]["security"] == [2, 3]
    summary = service.history(project["id"], summary=True)["assessments"]
    assert [row["origin"] for row in summary] == ["scan", "git-commit", "git-commit"]


def test_hindsight_reviews_are_labelled_and_read_the_private_tree(repository, tmp_path):
    old = commit(repository, {"app.py": "VALUE = 1\n"})
    commit(repository, {"app.py": "VALUE = 2\n"}, date="2026-10-01T00:00:00+00:00")
    service = AssessmentService(tmp_path / "state")
    live = service.scan(repository)
    result = service.backfill(repository, revisions=[old])
    backfilled = service.history(result["project_id"])["assessments"][-1]
    source_id = next(e["id"] for e in backfilled["evidence"] if e["kind"] == "python")

    # The live file changed; context still comes from the commit's verified bytes.
    context = service.source_context(backfilled["id"], source_id)
    assert "VALUE = 1" in context["excerpt"]

    review = service.submit_review(backfilled["id"], ratings(service, backfilled))
    assert review["hindsight"]["source_as_of"] == "2026-09-10T12:00:00+00:00"
    assert "hindsight" in review["hindsight"]["note"]
    timeline = report_export.dimension_map_data(service.get_report(live["id"]))["timeline"]
    assert timeline[0]["reviewed"] and timeline[0]["hindsight"]
    assert timeline[0]["scores"]["security"] == [2, 3]
    assert not timeline[1]["hindsight"]
    # Live scans keep their stale-review guard.
    newer = service.scan(repository)
    with pytest.raises(ConflictError, match="stale"):
        service.submit_review(live["id"], ratings(service, live))
    assert service.list_projects()[0]["latest_assessment_id"] == newer["id"]


def test_cli_backfill_requires_one_selection_and_reports_json(repository, tmp_path, capsys):
    revision = commit(repository, {"app.py": "VALUE = 1\n"})
    state = str(tmp_path / "state")
    with pytest.raises(SystemExit):
        main(["--state-dir", state, "backfill", str(repository)])
    assert main(["--state-dir", state, "backfill", str(repository), "--months", "13"]) == 2
    assert "from 1 to 12" in capsys.readouterr().err
    assert main(["--state-dir", state, "backfill", str(repository), "--revision", "HEAD"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["snapshots"][0]["revision"] == revision
    assert output["selection"]["mode"] == "revisions"
