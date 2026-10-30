import json
import subprocess

import pytest

from project_assess import collector


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_collects_deterministic_python_javascript_docs_and_manifests_without_execution(tmp_path):
    sentinel = tmp_path / "executed"
    write(
        tmp_path,
        "app.py",
        f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n"
        "class Example:\n    def run(self, value):\n        if value:\n            return value\n",
    )
    write(tmp_path, "tests/test_app.py", "def test_run():\n    assert 1 == 1\n")
    write(
        tmp_path,
        "src/app.test.ts",
        '// test("fake", () => {});\nconst text = "function if test()";\n'
        'test("works", () => { expect(true).toBe(true); });\n',
    )
    write(tmp_path, "README.md", "# App\n[Guide](docs/guide.md)\n```python\npass\n```\n")
    write(
        tmp_path,
        "package.json",
        '{"dependencies":{"react":"1"},"devDependencies":{"test":"2"},"scripts":{"test":"do not execute"}}',
    )
    write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname="fixture"\ndependencies=["example"]\n[project.optional-dependencies]\ndev=["pytest"]\naws=["boto3"]\n',
    )
    write(tmp_path, ".github/workflows/check.yml", "jobs: {}\n")

    result = collector.collect(tmp_path)

    assert result == collector.collect(tmp_path)
    assert result["complete"]
    assert result["source"]["revision"] is None
    assert result["source"]["manifest_digest"].startswith("sha256:")
    assert result["facts"]["python"]["functions"] == 2
    assert result["facts"]["python"]["branches"] == 1
    assert result["facts"]["python"]["test_functions"] == 1
    assert result["facts"]["javascript"]["test_cases"] == 1
    assert result["facts"]["javascript"]["functions"] == 1
    assert result["facts"]["javascript"]["branches"] == 0
    assert result["facts"]["documentation"]["headings"] == 1
    assert result["facts"]["documentation"]["code_blocks"] == 1
    documentation = result["facts"]["documentation"]["doc_value"]
    captured = next(row for row in result["evidence"] if row["id"] == documentation["evidence_id"])
    assert captured["kind"] == "documentation-analysis"
    assert captured["stats"]["links"][0]["issue"] == "unresolved-or-excluded-target"
    assert result["facts"]["inventory"]["test_files"] == 2
    assert result["facts"]["manifests"]["dependencies"] == 2
    assert result["facts"]["manifests"]["dev_dependencies"] == 2
    assert result["facts"]["ci"]["paths"] == [".github/workflows/check.yml"]
    assert not sentinel.exists()
    assert any("lexical" in gap for gap in result["gaps"])
    assert any("unknown" in gap for gap in result["gaps"])


def test_documentation_leads_use_captured_bytes_without_following_uncaptured_links(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    text = "# Guide\n\nUse the existing supported recovery operation.\n"
    write(root, "docs/guide.md", text)
    write(root, "docs/copy.md", text)
    write(
        root,
        "README.md",
        "# App\n[guide](docs/guide.md#guide) [missing anchor](docs/guide.md#absent) "
        "[excluded](.env) [outside](../outside.md) [bad](http://[bad)\n",
    )
    write(root, ".env", "api_key=private\n")
    write(tmp_path, "outside.md", "# Outside\n")

    snapshot = collector.collect(root)
    summary = snapshot["facts"]["documentation"]["doc_value"]
    evidence = next(row for row in snapshot["evidence"] if row["id"] == summary["evidence_id"])
    analysis = evidence["stats"]
    assert analysis["exactDuplicates"] == [["docs/copy.md", "docs/guide.md"]]
    links = {row["target"]: row for row in analysis["links"]}
    assert links["docs/guide.md#guide"]["resolved"] == "docs/guide.md"
    assert links["docs/guide.md#absent"]["issue"] == "missing-anchor"
    assert links[".env"]["issue"] == "unresolved-or-excluded-target"
    assert links["../outside.md"]["issue"] == "outside-captured-root"
    assert links["http://[bad"]["issue"] == "unsupported-link"
    assert "private" not in json.dumps(analysis)
    assert {row["path"] for row in analysis["documents"]} == {
        "README.md",
        "docs/copy.md",
        "docs/guide.md",
    }
    assert {row["path"]: row["sha256"] for row in analysis["documents"]} == {
        row["path"]: row["digest"] for row in snapshot["evidence"] if row["kind"] == "documentation"
    }
    write(root, "docs/guide.md", "# Revised\n\nUse the updated recovery operation.\n")
    revised = collector.collect(root)
    assert revised["source"]["manifest_digest"] != snapshot["source"]["manifest_digest"]
    assert revised["scope_digest"] == snapshot["scope_digest"]
    assert revised["facts"]["documentation"]["doc_value"]["exact_duplicate_groups"] == 0
    assert analysis["exactDuplicates"] == [["docs/copy.md", "docs/guide.md"]]


def test_static_value_leads_use_captured_source_and_do_not_change_doc_facts(tmp_path):
    sentinel = tmp_path / "executed"
    write(
        tmp_path,
        "tests/test_values.py",
        "import pytest\n"
        "def test_first():\n    assert 1 == 1\n"
        "def test_second():\n    assert 1 == 1\n"
        "@pytest.mark.parametrize('value', [1, 2])\n"
        "def test_matrix(value):\n    assert value\n"
        f"Path({str(sentinel)!r}).touch()\n",
    )
    write(
        tmp_path,
        "tests/values.test.ts",
        "test.each([[1], [2]])('value', (value) => expect(value).toBeTruthy());\n",
    )
    write(tmp_path, "README.md", "# Product\nKeep this guide concise.\n")
    result = collector.collect(tmp_path)
    summary = result["facts"]["test_value_static"]
    evidence = next(row for row in result["evidence"] if row["id"] == summary["evidence_id"])
    analysis = evidence["stats"]
    assert analysis["schema"] == "test-value-static.v1"
    assert analysis["provenance"]["capturedOnly"] is True
    assert analysis["counts"]["groups"] >= 1
    assert analysis["counts"]["candidates"] >= 2
    assert any(row["kind"] == "js-matrix" for row in analysis["definitions"])
    assert result["facts"]["documentation"]["files"] == 1
    assert result["facts"]["documentation"]["doc_value"]["exact_duplicate_groups"] == 0
    assert not sentinel.exists()


def test_content_identity_changes_while_collection_scope_remains_comparable(tmp_path):
    path = write(tmp_path, "app.py", "value = 1\n")
    first = collector.collect(tmp_path)
    path.write_text("value = 2\n")
    second = collector.collect(tmp_path)
    assert first["source"]["manifest_digest"] != second["source"]["manifest_digest"]
    assert first["scope_digest"] == second["scope_digest"]

    def source_id(snapshot):
        return next(entry["id"] for entry in snapshot["evidence"] if entry["path"] == "app.py")

    assert source_id(first) != source_id(second)
    unknown = write(tmp_path, "library.go", "package one\n")
    third = collector.collect(tmp_path)
    unknown.write_text("package two\n")
    fourth = collector.collect(tmp_path)
    assert third["source"]["manifest_digest"] != fourth["source"]["manifest_digest"]
    assert third["scope_digest"] == fourth["scope_digest"]
    assert any("Unsupported file kind .go" in gap for gap in fourth["gaps"])


def test_never_reads_secrets_or_traverses_symlinks_and_redacts_evidence(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    forbidden = write(tmp_path, "outside.py", 'secret = "outside-payload"\n')
    write(root, ".env", "inside-env-payload")
    write(root, ".env.example", "inside-template-payload")
    write(root, ".keys/private.py", "inside-key-payload")
    write(root, ".aws/config", "inside-aws-payload")
    write(root, "node_modules/library/index.js", "dependency-payload")
    (root / "escape.py").symlink_to(forbidden)
    (root / "escape-dir").symlink_to(tmp_path, target_is_directory=True)
    synthetic_access_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    write(
        root,
        "app.py",
        f'api_key = "source-secret-value"\nvalue = "{synthetic_access_key}"\n',
    )
    read_names = []
    original = collector._read_at

    def recording_read(directory, name, limit):
        read_names.append(name)
        return original(directory, name, limit)

    monkeypatch.setattr(collector, "_read_at", recording_read)
    result = collector.collect(root)
    serialized = json.dumps(result)
    assert read_names == ["app.py"]
    for value in (
        "inside-env-payload",
        "inside-template-payload",
        "inside-key-payload",
        "inside-aws-payload",
        "outside-payload",
        "dependency-payload",
        "source-secret-value",
        synthetic_access_key,
    ):
        assert value not in serialized
    assert "REDACTED" in serialized
    assert any("symlinks" in gap for gap in result["gaps"])
    assert any("credential" in gap for gap in result["gaps"])


def test_git_metadata_does_not_run_filters_or_fsmonitor(tmp_path):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "Fixture")
    write(tmp_path, "app.py", "value = 1\n")
    git("add", "app.py")
    git("commit", "-qm", "fixture")
    expected_sha = git("rev-parse", "HEAD").stdout.decode().strip()
    filter_sentinel, monitor_sentinel = tmp_path / "filter-ran", tmp_path / "monitor-ran"
    git("config", "core.fsmonitor", f"touch {monitor_sentinel}")
    git("config", "filter.malicious.clean", f"touch {filter_sentinel}")
    write(tmp_path, ".gitattributes", "*.py filter=malicious\n")
    write(tmp_path, "app.py", "value = 200\n")

    result = collector.collect(tmp_path)

    assert result["source"]["revision"] == expected_sha
    assert result["source"]["dirty"] is None
    assert not filter_sentinel.exists()
    assert not monitor_sentinel.exists()


def test_git_ignore_selection_excludes_artifacts_but_retains_tracked_ignored_files(tmp_path):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    write(tmp_path, ".gitignore", "work/\n")
    write(tmp_path, "app.py", "pass\n")
    ignored = write(tmp_path, "work/ignored.py", "value = 1\n")
    first = collector.collect(tmp_path)
    ignored.write_text("value = 2\n")
    second = collector.collect(tmp_path)
    assert first["complete"] and second["complete"]
    assert first["source"]["manifest_digest"] == second["source"]["manifest_digest"]
    assert not any(entry["path"].startswith("work/") for entry in first["evidence"])
    assert any("Git ignored" in gap for gap in first["gaps"])
    git("add", "-f", "work/ignored.py")
    third = collector.collect(tmp_path)
    assert third["facts"]["inventory"]["manifest_files"] == 3
    assert any(entry["path"] == "work/ignored.py" for entry in third["evidence"])
    ignored.write_text("value = 3\n")
    fourth = collector.collect(tmp_path)
    assert third["source"]["manifest_digest"] != fourth["source"]["manifest_digest"]


def test_git_inventory_is_bounded_and_missing_git_has_explicit_filesystem_fallback(
    tmp_path, monkeypatch
):
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True, capture_output=True)
    write(tmp_path, "long-source-filename.py", "pass\n")
    monkeypatch.setattr(collector, "MAX_GIT_OUTPUT_BYTES", 4)
    result = collector.collect(tmp_path)
    assert not result["complete"]
    assert any("Git inventory file or byte limit" in gap for gap in result["gaps"])
    monkeypatch.setattr(
        collector, "_git_configuration", lambda root: (["/nonexistent-git-command"], {})
    )
    fallback = collector.collect(tmp_path)
    assert fallback["complete"]
    assert fallback["facts"]["python"]["files"] == 1
    assert any("Git inventory unavailable" in gap for gap in fallback["gaps"])


def test_report_aggregates_are_bounded_and_do_not_expose_test_output(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    junit = write(
        tmp_path,
        "junit.xml",
        '<testsuites><testsuite><testcase name="private-test-name" time="1.5"><failure>private-test-output</failure></testcase><testcase name="other" time="2"><skipped/></testcase></testsuite></testsuites>',
    )
    coverage = write(
        tmp_path,
        "coverage.xml",
        '<coverage lines-covered="8" lines-valid="10" branches-covered="2" branches-valid="4"><packages/></coverage>',
    )
    first = collector.collect(root, [junit, coverage])
    assert first["facts"]["reports"]["junit"] == {
        "files": 1,
        "tests": 2,
        "failures": 1,
        "errors": 0,
        "skipped": 1,
        "seconds": 3.5,
    }
    assert first["facts"]["reports"]["cobertura"]["lines_covered"] == 8
    assert "private-test-name" not in json.dumps(first)
    assert "private-test-output" not in json.dumps(first)
    junit.write_text('<testsuite><testcase name="changed" time="3"/></testsuite>')
    second = collector.collect(root, [junit, coverage])
    assert first["scope_digest"] == second["scope_digest"]
    assert first["evidence"] != second["evidence"]
    assert any("source identity" in gap for gap in first["gaps"])


def test_in_repository_xml_reports_do_not_leak_raw_output(tmp_path):
    report = write(
        tmp_path,
        "junit.xml",
        '<testsuite><testcase name="private-name"><failure>private-output</failure></testcase></testsuite>',
    )
    result = collector.collect(tmp_path, [report])
    assert result["facts"]["reports"]["junit"]["tests"] == 1
    assert "private-name" not in json.dumps(result)
    assert "private-output" not in json.dumps(result)


def test_test_value_json_reports_are_summarized_and_identity_checked(tmp_path):
    source = write(tmp_path, "app.py", "value = 1\n")
    digest = collector._bytes_digest(source.read_bytes())
    report = write(
        tmp_path,
        "test-value.json",
        json.dumps(
            {
                "schema": "test-value-audit.v3",
                "root": str(tmp_path),
                "currentSource": {"revision": "old-revision"},
                "sourceHashes": {"app.py": digest},
                "toolVersions": {
                    "python": "ghp_abcdefghijklmnop123456789",
                    "api_key": "private-version-field",
                },
                "healthyCollection": True,
                "confidentOverlap": True,
                "tests": [
                    {
                        "nodeid": "private-test-id",
                        "outcome": "passed",
                        "attribution": "case",
                        "phases": {"call": {"durationSeconds": 0.25}},
                    }
                ],
                "identicalFootprints": [{"tests": ["private-test-id"]}],
                "rankedCandidates": [{"nodeid": "private-test-id"}],
                "gaps": [],
            }
        ),
    )
    result = collector.collect(tmp_path, [report])
    evidence = next(item for item in result["evidence"] if item["kind"] == "test-value")
    assert evidence["stats"]["schema"] == "test-value-audit.v3"
    assert evidence["stats"]["counts"]["tests"] == 1
    assert evidence["stats"]["sourceIdentity"] == {
        "root": "matched",
        "revision": "unknown",
        "sourceHashes": "matched",
        "overall": "unknown",
    }
    assert evidence["stats"]["claims"]["assessmentComplete"] is False
    assert "private-test-id" not in json.dumps(result)
    assert "ghp_abcdefghijklmnop123456789" not in json.dumps(result)
    assert "private-version-field" not in json.dumps(result)
    assert evidence["stats"]["counts"]["coverageFeatures"] is None
    assert result["facts"]["reports"]["test-value"]["files"] == 1

    for source_path in (
        "../app.py",
        "./../app.py",
        "..\\app.py",
        str(tmp_path / ".." / tmp_path.name / "app.py"),
    ):
        data = json.loads(report.read_text())
        data["sourceHashes"] = {source_path: digest}
        report.write_text(json.dumps(data))
        unsafe = collector.collect(tmp_path, [report])
        item = next(entry for entry in unsafe["evidence"] if entry["kind"] == "test-value")
        assert item["stats"]["sourceIdentity"]["sourceHashes"] == "unknown"

    hidden = write(tmp_path, ".retained.py", "value = 2\n")
    data["sourceHashes"] = {hidden.name: collector._bytes_digest(hidden.read_bytes())}
    report.write_text(json.dumps(data))
    safe = collector.collect(tmp_path, [report])
    item = next(entry for entry in safe["evidence"] if entry["kind"] == "test-value")
    assert item["stats"]["sourceIdentity"]["sourceHashes"] == "matched"


def test_normalized_test_value_evidence_schema_is_accepted_without_loading_artifacts(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    report = write(
        tmp_path,
        "evidence.json",
        json.dumps(
            {
                "schema": "test-value-evidence.v1",
                "project": {"sourceHashes": {}},
                "tests": [],
                "gaps": [{"reason": "aggregate-coverage-not-per-test"}],
                "provenance": {"artifacts": [{"path": "/not-read", "hash": "sha256:x"}]},
            }
        ),
    )
    result = collector.collect(root, [report])
    evidence = next(item for item in result["evidence"] if item["kind"] == "test-value")
    assert evidence["stats"]["schema"] == "test-value-evidence.v1"
    assert evidence["stats"]["gaps"]["reasons"] == ["aggregate-coverage-not-per-test"]


@pytest.mark.parametrize(
    "payload",
    [
        '{"schema":"test-value-audit.v2"}',
        '{"schema":"test-value-audit.v3","tests":[}',
        '{"schema":"test-value-audit.v3","a":{"a":{"a":{"a":{"a":1}}}}}',
    ],
)
def test_malformed_or_unsupported_test_value_json_is_an_explicit_gap(tmp_path, payload):
    root = tmp_path / "root"
    root.mkdir()
    report = write(tmp_path, "test-value.json", payload)
    result = collector.collect(root, [report])
    assert not result["complete"]
    assert any("test-value report" in gap.lower() for gap in result["gaps"])
    evidence = next(item for item in result["evidence"] if item["kind"] == "test-value")
    assert evidence["stats"]["claims"]["assessmentComplete"] is False


@pytest.mark.parametrize(
    "payload",
    [
        '<!DOCTYPE test [<!ENTITY x "bad">]><testsuite><testcase name="&x;"/></testsuite>',
        "<testsuite>",
        "<testsuite/>",
        '<testsuite><testcase time="NaN"/></testsuite>',
        '<testsuite><testcase time="-1"/></testsuite>',
        '<coverage lines-covered="11" lines-valid="10"/>',
        '<coverage line-rate="0.5"/>',
        "<unrecognized/>",
    ],
)
def test_rejects_malformed_unsupported_or_unsafe_reports(tmp_path, payload):
    root = tmp_path / "root"
    root.mkdir()
    report = write(tmp_path, "report.xml", payload)
    with pytest.raises(ValueError):
        collector.collect(root, [report])


def test_rejects_report_symlinks_missing_paths_credentials_and_duplicates(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    report = write(tmp_path, "report.xml", "<testsuite><testcase/></testsuite>")
    link = tmp_path / "linked.xml"
    link.symlink_to(report)
    credential = write(tmp_path, ".keys/report.xml", report.read_text())
    for paths in ([link], [tmp_path / "missing.xml"], [credential], [report, report]):
        with pytest.raises(ValueError):
            collector.collect(root, paths)


def test_invalid_python_and_duplicate_manifest_keys_are_incomplete(tmp_path):
    write(tmp_path, "broken.py", "def missing(:\n")
    write(tmp_path, "package.json", '{"scripts":{},"scripts":{}}')
    result = collector.collect(tmp_path)
    assert not result["complete"]
    assert any("broken.py" in gap for gap in result["gaps"])
    assert any("package.json" in gap for gap in result["gaps"])


def test_source_changes_during_collection_are_detected(tmp_path, monkeypatch):
    path = write(tmp_path, "app.py", "value = 1\n")
    original = collector._read_at

    def changing_read(directory, name, limit):
        result = original(directory, name, limit)
        path.write_text("value = 200\n")
        return result

    monkeypatch.setattr(collector, "_read_at", changing_read)
    result = collector.collect(tmp_path)
    assert not result["complete"]
    assert any("Source changed" in gap for gap in result["gaps"])


def test_new_source_files_during_collection_are_detected(tmp_path, monkeypatch):
    write(tmp_path, "app.py", "value = 1\n")
    original = collector._read_at

    def adding_read(directory, name, limit):
        result = original(directory, name, limit)
        write(tmp_path, "added.py", "value = 2\n")
        return result

    monkeypatch.setattr(collector, "_read_at", adding_read)
    result = collector.collect(tmp_path)
    assert not result["complete"]
    assert any("Source changed" in gap for gap in result["gaps"])


def test_bounds_are_explicit_and_do_not_report_successful_empty_collection(tmp_path, monkeypatch):
    write(tmp_path, "app.py", "value = 1\n")
    monkeypatch.setattr(collector, "MAX_FILE_BYTES", 4)
    result = collector.collect(tmp_path)
    assert not result["complete"]
    assert result["facts"]["inventory"]["files"] == 0
    assert result["gaps"]


def test_directory_entries_and_report_bytes_are_bounded(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    for number in range(3):
        write(root, f"file{number}.py", "pass\n")
    monkeypatch.setattr(collector, "MAX_FILES", 2)
    result = collector.collect(root)
    assert not result["complete"]
    assert "Directory entry limit exceeded" in result["gaps"]
    report = write(tmp_path, "large.xml", "<testsuite><testcase/></testsuite>")
    monkeypatch.setattr(collector, "MAX_FILE_BYTES", 4)
    with pytest.raises(ValueError, match="byte limit"):
        collector.collect(root, [report])


def test_root_must_be_a_real_directory(tmp_path):
    file = write(tmp_path, "app.py", "pass\n")
    link = tmp_path / "linked"
    link.symlink_to(tmp_path, target_is_directory=True)
    for path in (file, link, tmp_path / "missing"):
        with pytest.raises(ValueError):
            collector.collect(path)


def test_architecture_hints_distinguish_direct_code_from_review_candidates(tmp_path):
    write(tmp_path, "direct.py", "def calculate(value):\n    return value * 2\n")
    first = collector.collect(tmp_path)
    assert first["facts"]["maintainability"]["forwarding_functions"] == 0
    assert first["facts"]["maintainability"]["abstract_classes"] == 0
    write(
        tmp_path,
        "layers.py",
        "from typing import Protocol\n"
        "class WorkerPort(Protocol):\n    def run(self, value): ...\n"
        "class Layer:\n"
        "    def __init__(self, next_layer):\n        self.next_layer = next_layer\n"
        "    def run(self, value):\n        return self.next_layer.run(value)\n"
        "def entry(worker, value):\n    return Layer(worker).run(value)\n",
    )
    result = collector.collect(tmp_path)
    assert result["facts"]["maintainability"]["forwarding_functions"] == 2
    assert result["facts"]["maintainability"]["abstract_classes"] == 1
    per_file = next(entry for entry in result["evidence"] if entry["path"] == "layers.py")
    assert per_file["stats"]["forwarding_functions"] == 2
    assert per_file["stats"]["abstract_classes"] == 1
    assert result["findings"] == []


def test_useful_injection_has_same_hints_without_automatic_burden_judgment(tmp_path):
    write(
        tmp_path,
        "injection.py",
        "from abc import ABC, abstractmethod\n"
        "class Storage(ABC):\n"
        "    @abstractmethod\n    def get(self, key): ...\n"
        "class Application:\n"
        "    def __init__(self, store):\n        self.store = store\n"
        "    def get(self, key):\n"
        '        """Keep storage injectable for deterministic tests."""\n'
        "        return self.store.get(key)\n"
        "async def asynchronous(store, key):\n    return await store.get(key)\n"
        "def generator(store):\n    return store.get((yield 1))\n",
    )
    result = collector.collect(tmp_path)
    hints = result["facts"]["maintainability"]
    assert hints["method"] == "static_review_hints"
    assert hints["forwarding_functions"] == 1
    assert hints["abstract_classes"] == 1
    assert "Useful delegation and dependency injection" in hints["caveat"]
    assert "burden" not in hints
    assert result["findings"] == []
