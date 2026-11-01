import json

import pytest

from project_assess import delivery_analysis as delivery


def test_github_literals_keep_on_dependencies_and_source_locations_without_raw_values():
    text = """name: checks
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - run: uv sync --locked && pytest
      - uses: actions/upload-artifact@v4
  deploy:
    needs: [test]
    environment: production
    if: ${{ failure() }}
    continue-on-error: false
    steps:
      - run: TOKEN=PRIVATE_VALUE deploy && rollback
"""
    result = delivery.analyze_delivery(".github/workflows/check.yml", text)
    signals = result["signals"]
    assert result["dimensions"] == ["delivery", "security"]
    assert next(row for row in signals if row["kind"] == "delivery.trigger")["context"][
        "events"
    ] == ["push", "pull_request"]
    assert next(row for row in signals if row["kind"] == "delivery.dependencies")["context"][
        "needs"
    ] == ["test"]
    assert {row["context"]["pin"] for row in signals if row["kind"] == "delivery.reference"} == {
        "commit_sha",
        "tag_or_branch",
    }
    assert (
        next(row for row in signals if row["kind"] == "delivery.timeout_minutes")["locations"][0][
            "line"
        ]
        == 8
    )
    assert (
        next(row for row in signals if row["kind"] == "delivery.permissions")["context"][
            "write_scopes"
        ]
        == []
    )
    assert {"test", "locked_install", "artifact", "release", "rollback"} <= {
        row["context"]["category"] for row in signals if row["kind"] == "delivery.command"
    }
    assert result["status"] == "partial"
    serialized = json.dumps(result)
    assert (
        "PRIVATE_VALUE" not in serialized and "TOKEN=" not in serialized and "${{" not in serialized
    )


def test_circleci_literal_approval_requires_and_timeout():
    result = delivery.analyze_delivery(
        ".circleci/config.yml",
        """version: 2.1
jobs:
  check:
    docker:
      - image: cimg/python:3.12
    steps:
      - run:
          command: pytest
          no_output_timeout: 10m
      - store_test_results:
          path: results
workflows:
  release:
    jobs:
      - check
      - hold:
          type: approval
          requires: [check]
      - deploy:
          requires:
            - hold: [success]
          filters:
            branches:
              only: main
""",
    )
    assert result["status"] == "complete"
    assert {row["kind"] for row in result["signals"]} >= {
        "delivery.approval",
        "delivery.dependencies",
        "delivery.no_output_timeout",
        "delivery.artifact",
        "delivery.filters",
    }
    assert {
        row["context"]["owner"]
        for row in result["signals"]
        if row["kind"] == "delivery.dependencies"
    } == {"hold", "deploy"}
    assert result["coverage"]["nodes_examined"] > 0


@pytest.mark.parametrize(
    "text",
    [
        "jobs: {}\njobs: {}\n",
        "jobs: &cycle {again: *cycle}\n",
        'jobs: !!python/object/apply:os.system ["touch marker"]\n',
        "---\njobs: {}\n---\njobs: {}\n",
    ],
)
def test_ambiguous_or_hostile_yaml_is_explicitly_partial(text, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = delivery.analyze_delivery(".github/workflows/check.yml", text)
    assert result["status"] == "partial"
    assert result["gaps"] and result["signals"] == []
    assert not (tmp_path / "marker").exists()


def test_bounded_alias_expansion_and_nested_merge_limit_remain_explicit(monkeypatch):
    monkeypatch.setattr(delivery, "MAX_NODES", 25)
    result = delivery.analyze_delivery(
        ".circleci/config.yml", "x: &x [a,b,c,d,e,f]\ny: [*x,*x,*x,*x,*x]\njobs: {}\n"
    )
    assert result["status"] == "partial" and result["signals"] == []
    monkeypatch.setattr(delivery, "MAX_NODES", 30000)
    result = delivery.analyze_delivery(
        ".circleci/config.yml",
        "base: &base {resource_class: small}\njobs:\n  test:\n    <<: *base\n    steps: []\n",
    )
    assert "YAML merge keys were not resolved" in result["gaps"]
    assert not any(row["kind"] == "delivery.resource_class" for row in result["signals"])


def test_signal_budget_spreads_kinds_and_late_owner_context(monkeypatch):
    monkeypatch.setattr(delivery, "MAX_SIGNALS", 12)
    text = (
        "jobs:\n"
        + "".join(f"  job{i}:\n    steps:\n      - run: pytest\n" for i in range(100))
        + "  zlast:\n    steps:\n      - run: deploy && rollback\n"
    )
    result = delivery.analyze_delivery(".github/workflows/check.yml", text)
    assert len(result["signals"]) <= 12
    assert result["coverage"]["signals_total"] > 200
    assert result["coverage"]["signals_omitted"] > 0
    assert any(row["context"].get("category") == "rollback" for row in result["signals"])
    assert result == delivery.analyze_delivery(".github/workflows/check.yml", text)


def test_manifest_entry_points_and_compatibility_are_declarations_not_shell_execution():
    python = delivery.analyze_delivery(
        "pyproject.toml",
        """[project]
requires-python = ">=3.11"
[project.scripts]
test = "package:test"
[project.entry-points.example]
plugin = "package:Plugin"
""",
    )
    assert python["dimensions"] == ["delivery", "extensibility"]
    assert {"extensibility.entry_points", "extensibility.compatibility"} <= {
        row["kind"] for row in python["signals"]
    }
    assert not any(row["kind"] == "delivery.command" for row in python["signals"])
    node = delivery.analyze_delivery(
        "package.json",
        json.dumps(
            {
                "scripts": {"check": "npm ci && npm test"},
                "exports": {".": "./index.js"},
                "peerDependencies": {"react": "PRIVATE_CONSTRAINT"},
                "engines": {"node": ">=20"},
            }
        ),
    )
    assert node["status"] == "complete"
    assert "PRIVATE_CONSTRAINT" not in json.dumps(node)
    assert any(row["context"].get("category") == "locked_install" for row in node["signals"])


def test_lockfile_presence_and_unsupported_ci_do_not_imply_validation():
    lock = delivery.analyze_delivery("uv.lock", "not validated")
    assert lock["signals"][0]["context"]["contents_validated"] is False
    unsupported = delivery.analyze_delivery(".gitlab-ci.yml", "stages: [test]\n")
    assert unsupported["status"] == "unsupported" and not unsupported["dimensions"]
    assert unsupported["signals"] == []


def test_delivery_input_recognition_does_not_misclassify_arbitrary_yaml():
    assert delivery.is_delivery_input(".github/workflows/check.yaml")
    assert delivery.is_delivery_input("packages/app/package.json")
    assert not delivery.is_delivery_input("config/service.yaml")
