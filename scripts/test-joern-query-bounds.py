"""Qualify endpoint process bounds and persisted-overlay resume with real Joern.

The synthetic source is parsed, never executed. The probe replaces one trusted
query statement with a controlled sleep after its in-flight marker, on the first
worker only. It then requires a fresh worker to recover the overlay and continue.
Elapsed times are observations, not a benchmark gate.
"""

import argparse
import hashlib
import json
import time
from pathlib import Path

from project_assess import joern_analysis as adapter
from project_assess import joern_dataflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--tamper-overlay",
        action="store_true",
        help="Corrupt the private saved graph before resume and require rejection",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = output / "fixture"
    fixture.mkdir()
    text = "def emit(value):\n    print(value)\n    return value\n\ndef caller(payload):\n    return emit(payload)\n"
    sources = [
        {
            "path": "app.py",
            "text": text,
            "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            "evidence_id": "e-synthetic-bounds",
            "role": "production",
        }
    ]
    module_paths = {"adapter": Path(adapter.__file__), "normalizer": Path(joern_dataflow.__file__)}
    module_hashes = {
        name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in module_paths.items()
    }
    query = adapter.QUERY_PATH.read_text()
    marker = "            engine.backwards(List(sink), parameterNodes)"
    assert query.count(marker) == 1
    probe = query.replace(marker, "            if (resume.isEmpty) Thread.sleep(120000)\n" + marker)
    probe_path = output / "probe.sc"
    probe_path.write_text(probe)
    original_path, original_configuration, original_run = (
        adapter.QUERY_PATH,
        adapter._joern_configuration,
        adapter._run,
    )

    def run(argv, **kwargs):
        if args.tamper_overlay and any(value.startswith("resumeFile=") for value in argv):
            overlay = Path(str(kwargs["output"]) + ".overlay.bin")
            overlay.chmod(0o600)
            overlay.write_bytes(overlay.read_bytes() + b"tampered")
        return original_run(argv, **kwargs)

    def configuration(profile):
        limits, overrides = original_configuration(profile)
        limits["endpoint_seconds"] = 2
        limits["dataflow"]["endpoint_seconds"] = 2
        limits["seconds"] = 180
        return limits, overrides

    started = time.monotonic()
    try:
        adapter.QUERY_PATH, adapter._joern_configuration, adapter._run = (
            probe_path,
            configuration,
            run,
        )
        result = adapter.analyze_joern(
            sources,
            snapshot={
                "root": str(fixture),
                "revision": "synthetic-bounds",
                "manifest_digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            },
            analysis_profile="deep",
        )
    finally:
        adapter.QUERY_PATH, adapter._joern_configuration, adapter._run = (
            original_path,
            original_configuration,
            original_run,
        )
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    flow = result.get("dataflow_analysis", {})
    batch = result.get("coverage", {}).get("batches", [{}])[0]
    endpoints = flow.get("batches", [{}])[0].get("selection", {}).get("endpoints", [])
    q = flow.get("batches", [{}])[0].get("queries", {})
    checks = {
        "one_first_endpoint_timed_out": batch.get("endpoint_timeouts") == 1,
        "worker_restarted": batch.get("query_attempts") == 2,
        "persisted_overlay_reused": batch.get("overlay_reused") is True,
        "base_source_model_retained": batch.get("modeled_files") == 1,
        "timed_out_is_unknown": len([row for row in endpoints if row["status"] == "timed_out"]) == 1
        and q.get("sinks_timed_out") == 1
        and q.get("sinks_pending") == 1,
        "remaining_endpoints_completed": bool(endpoints)
        and q.get("sinks_queried") == len(endpoints) - 1,
        "positive_control_paths_retained": len(flow.get("paths", [])) > 0,
        "flow_stays_partial": flow.get("status") == "partial",
        "producer_completed_after_restart": batch.get("process_status") == "complete",
        "production_query_unchanged": adapter.QUERY_PATH.read_text() == query,
    }
    if args.tamper_overlay:
        checks = {
            "tampered_overlay_rejected": batch.get("process_status") == "resume_load_error",
            "base_source_model_retained": batch.get("modeled_files") == 1,
            "no_untrusted_resume_paths": flow.get("status") == "partial" and not flow.get("paths"),
            "no_retry_loop_after_bad_graph": batch.get("query_attempts") == 2,
            "production_query_unchanged": adapter.QUERY_PATH.read_text() == query,
        }
    receipt = {
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
        "probe_query_sha256": hashlib.sha256(probe.encode()).hexdigest(),
        "tool": {
            k: result.get("analyzer", {}).get(k)
            for k in [
                "name",
                "version",
                "adapter_version",
                "query_version",
                "component_hashes",
                "jdk_version",
            ]
        },
        "target_code_executed": False,
        "tamper_probe": args.tamper_overlay,
        "python_module_sha256": module_hashes,
        "scope": "Synthetic Python first-in-flight stall, actual process kill/reap and persisted-overlay resume; missing endpoint remains unknown. Not whole-language correctness or runtime execution.",
    }
    assert module_hashes == {
        name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in module_paths.items()
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt), flush=True)
    if receipt["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
