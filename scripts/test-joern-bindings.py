"""Qualify callable-binding classifications using real Joern on synthetic TS.

Requires PAT_JOERN_HOME and PAT_JOERN_JAVA_HOME. Source is parsed, never run.
Elapsed time is an observation, not a benchmark or acceptance threshold.
"""

import argparse
import hashlib
import json
import time
from pathlib import Path

from project_assess import joern_analysis as adapter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    texts = {
        "src/library.ts": "export function original(payload: string) { return payload; }\n",
        "src/main.ts": """import { original as imported } from './library';
function local(payload: string) { return payload; }
function replacement(payload: string) { return payload; }
export function direct(payload: string) { return local(payload); }
export function importedCall(payload: string) { return imported(payload); }
export function rebound(payload: string) {
  let f = (value: string) => value;
  f = (value: string) => value;
  return f(payload);
}
export function conditional(payload: string, choose: boolean) {
  let f = (value: string) => value;
  if (choose) f = (value: string) => value;
  return f(payload);
}
export function shadow(imported: (value: string) => string, payload: string) {
  return imported(payload);
}
""",
    }
    sources = [
        {
            "path": path,
            "text": text,
            "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            "evidence_id": "e-" + Path(path).stem,
            "role": "production",
        }
        for path, text in texts.items()
    ]
    started = time.monotonic()
    query = adapter.QUERY_PATH.read_bytes()
    # Qualify actual REF-bound definitions even when the frontend emits no
    # located CALL target. This instrumentation does not add graph edges.
    hook = b"""
    val probeRows = Arr()
    cpg.call.filter(call => Set("rebound", "conditional")(call.method.name) && call.name == "f").foreach { call =>
      val bindings = calleeBindings(call)
      bindings.foreach { declaration =>
        boundMethods.get(declaration.id).foreach { names => names.foreach { name =>
          cpg.method.find(method => method.fullName == name && locatedSource(method)).foreach { target =>
            val (status, basis, confidence) = qualification(call, target, bindings, Set.empty[String])
            probeRows.value += Obj("caller" -> call.method.name, "target" -> target.fullName,
              "status" -> status, "basis" -> basis,
              "writes" -> bindingWrites.get(declaration.id).map(_.size).getOrElse(0))
          }
        }}
      }
    }
    result("binding_qualification_probe") = probeRows
"""
    marker = b'    attempt("methods") {'
    if query.count(marker) != 1:
        raise ValueError("Expected one method section for the qualification probe")
    probe = query.replace(marker, hook + marker)
    probe_path = output / "binding-probe.sc"
    probe_path.write_bytes(probe)
    production_path, original_run = adapter.QUERY_PATH, adapter._run
    probe_rows = []

    def run(argv, *, output=None, **kwargs):
        status = original_run(argv, output=output, **kwargs)
        if output and output.is_file():
            probe_rows.extend(json.loads(output.read_text()).get("binding_qualification_probe", []))
        return status

    try:
        adapter.QUERY_PATH, adapter._run = probe_path, run
        result = adapter.analyze_joern(
            sources,
            snapshot={
                "root": str(output),
                "revision": "synthetic-bindings",
                "manifest_digest": "sha256:"
                + hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
            },
            analysis_profile="standard",
        )
    finally:
        adapter.QUERY_PATH, adapter._run = production_path, original_run
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    calls = result.get("topology", {}).get("calls", [])

    def named(caller):
        return [row for row in calls if row["caller_name"] == caller]

    checks = {
        "direct_call_supported": any(
            row["dependency_status"] == "source_supported" for row in named("direct")
        ),
        "explicit_import_retained_as_unresolved": bool(named("importedCall"))
        and all(row["dependency_status"] == "unresolved" for row in named("importedCall")),
        "reassignment_not_supported": bool(named("rebound"))
        and all(row["dependency_status"] != "source_supported" for row in named("rebound")),
        "conditional_reassignment_not_supported": bool(named("conditional"))
        and all(row["dependency_status"] != "source_supported" for row in named("conditional")),
        "parameter_shadow_not_supported": bool(named("shadow"))
        and all(row["dependency_status"] != "source_supported" for row in named("shadow")),
        "rebound_definitions_directly_qualified": all(
            any(row["caller"] == caller for row in probe_rows)
            and all(
                row["status"] == "producer_inferred" and row["writes"] >= 2
                for row in probe_rows
                if row["caller"] == caller
            )
            for caller in ("rebound", "conditional")
        ),
        "query_unchanged": query == adapter.QUERY_PATH.read_bytes(),
    }
    receipt = {
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "query_sha256": hashlib.sha256(query).hexdigest(),
        "probe_query_sha256": hashlib.sha256(probe).hexdigest(),
        "direct_qualification_rows": probe_rows,
        "target_code_executed": False,
        "scope": "Synthetic TypeScript direct/import, reassignment, branch and shadow cases. Imports and callable calls remain unresolved; instrumentation directly qualifies actual bound definitions without adding CALL edges. No reaching-definition or runtime-call proof.",
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt), flush=True)
    if receipt["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
