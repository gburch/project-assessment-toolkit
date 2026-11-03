"""Qualify Deep dataflow using the real contained Joern adapter on synthetic source.

Set PAT_JOERN_HOME and PAT_JOERN_JAVA_HOME to the qualified external tools, then run:
uv run --locked python scripts/test-joern-dataflow.py --output /tmp/pat-dataflow-proof

The fixtures are parsed, never imported, built or executed. This optional check is
separate from offline pytest; elapsed times are observations, not acceptance gates.
"""

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from project_assess import joern_analysis as adapter

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/joern_dataflow"
LANGUAGES = ("python", "typescript", "java")


def digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def sources_for(language):
    return [
        {
            "path": "src/" + path.name.removesuffix(".txt"),
            "text": path.read_text(),
            "digest": digest(path.read_bytes()),
            "evidence_id": "e-fixture-" + path.name,
            "role": "production",
        }
        for path in sorted((FIXTURES / language).iterdir())
        if path.is_file()
    ]


def run_case(name, sources, output, profile="deep"):
    started = time.monotonic()
    result = adapter.analyze_joern(
        sources,
        snapshot={
            "root": str(output),
            "revision": "synthetic-dataflow-fixtures",
            "manifest_digest": digest(json.dumps(sources, sort_keys=True).encode()),
        },
        analysis_profile=profile,
    )
    (output / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
    return result, round(time.monotonic() - started, 3)


def fixture_checks(result):
    flow = result.get("dataflow_analysis", {})
    paths = flow.get("paths", [])

    def method(node, name):
        # Frontends qualify method names differently; fixture names are distinct.
        return name in node.get("method", "")

    cross_file = [
        row
        for row in paths
        if row["source"]["name"] == "payload"
        and method(row["source"], "entry")
        and len({step["path"] for step in row["steps"]}) > 1
        and row["interprocedural"]
    ]
    overwrite_paths = [
        row
        for row in paths
        if row["kind"] == "parameter_to_return" and method(row["sink"], "overwritten")
    ]
    entry_names = {row["source"]["name"] for row in overwrite_paths}
    candidates = result.get("candidate_index", [])
    checks = {
        "deep_dataflow_completed": flow.get("status") == "complete",
        "all_fixture_files_modeled": result.get("coverage", {}).get("modeled_files")
        == result.get("coverage", {}).get("eligible_files"),
        "cross_file_parameter_flow": bool(cross_file),
        "operation_flow": any(row["kind"] == "parameter_to_operation" for row in paths),
        "cross_file_caller_to_operation": any(
            row["kind"] == "parameter_to_operation"
            and row["source"]["name"] in {"operation_payload", "operationPayload"}
            and method(row["sink"], "relay")
            and len({step["path"] for step in row["steps"]}) > 1
            and row["interprocedural"]
            for row in paths
        ),
        "unrelated_parameter_not_operation_input": not any(
            row["kind"] == "parameter_to_operation"
            and row["source"]["name"] in {"unrelated_payload", "unrelatedPayload"}
            for row in paths
        ),
        "replacement_reaches_return": "replacement" in entry_names,
        "overwritten_source_does_not_reach_return": "obsolete" not in entry_names
        and "replacement" in entry_names,
        "callback_parameter_not_cleanup": not any(
            row.get("metrics", {}).get("symbol") in {"unused_context", "unusedContext"}
            for row in candidates
        ),
        "binding_leads_preserve_initializer_warning": all(
            "initializer" in row.get("caveat", "").lower()
            for row in candidates
            if row.get("metrics", {}).get("symbol") == "unused"
        ),
        "flow_steps_have_source_identity": bool(paths)
        and all(
            step.get("source_evidence_id") and step.get("digest", "").startswith("sha256:")
            for row in paths
            for step in row["steps"]
        ),
    }
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New directory outside checkout")
    parser.add_argument("--language", choices=LANGUAGES, action="append")
    parser.add_argument(
        "--skip-large", action="store_true", help="Omit the large Python method probe"
    )
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.is_relative_to(ROOT):
        parser.error("Output must be outside the checkout")
    home, java, _, _, _ = adapter._tools()
    if home.is_relative_to(ROOT) or java.is_relative_to(ROOT):
        parser.error("Operator tools must be outside the checkout")
    if adapter._sandbox()[0] is None:
        parser.error("Qualified OS containment is unavailable")
    os.umask(0o077)
    output.mkdir(parents=True, exist_ok=False)
    original_fixtures = {
        str(path): digest(path.read_bytes()) for path in FIXTURES.rglob("*") if path.is_file()
    }
    implementation = {
        str(Path(adapter.__file__).with_name(name)): digest(
            Path(adapter.__file__).with_name(name).read_bytes()
        )
        for name in ("joern_analysis.py", "joern_dataflow.py", "joern_bindings.py")
    }
    query = adapter.QUERY_PATH.read_bytes()
    receipts = []
    for language in args.language or LANGUAGES:
        result, seconds = run_case(language, sources_for(language), output)
        checks = fixture_checks(result)
        receipts.append({"case": language, "seconds": seconds, "checks": checks})
        print(json.dumps(receipts[-1]), flush=True)

    standard, seconds = run_case("standard", sources_for("python"), output, "standard")
    receipts.append(
        {
            "case": "standard",
            "seconds": seconds,
            "checks": {
                "dataflow_not_run": standard.get("dataflow_analysis", {}).get("status") == "not_run"
            },
        }
    )
    if not args.skip_large:
        # Distinct reaching definitions exceed the old 4,000-definition ceiling.
        # The text is input to static analysis only, never executed.
        text = (
            "def large(payload):\n"
            + "".join(f"    value_{index} = payload\n" for index in range(4200))
            + "    return value_4199\n"
        )
        sources = [
            {
                "path": "src/large.py",
                "text": text,
                "digest": digest(text.encode()),
                "evidence_id": "e-large",
                "role": "production",
            }
        ]
        result, seconds = run_case("large", sources, output)
        combined = result.get("dataflow_analysis", {})
        batches = combined.get("batches", [])
        flow = batches[0] if len(batches) == 1 else {}
        checks = {
            "method_exceeds_former_threshold": flow.get("maximum_definitions_observed", 0) > 4000,
            "large_method_not_skipped": flow.get("methods_skipped") == 0,
            "large_method_flow_found": any(
                row["source"]["name"] == "payload" and row["kind"] == "parameter_to_return"
                for row in combined.get("paths", [])
            ),
        }
        receipts.append({"case": "large", "seconds": seconds, "checks": checks})
        print(json.dumps(receipts[-1]), flush=True)
    unchanged = all(
        Path(path).is_file() and digest(Path(path).read_bytes()) == value
        for path, value in original_fixtures.items()
    )
    receipt = {
        "status": "passed"
        if unchanged and all(all(case["checks"].values()) for case in receipts)
        else "failed",
        "query_sha256": hashlib.sha256(query).hexdigest(),
        "query_unchanged": query == adapter.QUERY_PATH.read_bytes(),
        "implementation_hashes": implementation,
        "implementation_unchanged": all(
            digest(Path(path).read_bytes()) == value for path, value in implementation.items()
        ),
        "fixture_hashes": original_fixtures,
        "fixtures_unchanged": unchanged,
        "target_code_executed": False,
        "cases": receipts,
        "scope": "Synthetic supported-language dataflow cases; no proof of whole-project completeness or safe deletion.",
    }
    if not receipt["query_unchanged"] or not receipt["implementation_unchanged"]:
        receipt["status"] = "failed"
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    if receipt["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
