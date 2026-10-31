"""Replay Joern sampling regressions using trusted operator tools, without a project scan.

With PAT_JOERN_HOME and PAT_JOERN_JAVA_HOME configured, run:
uv run --locked python scripts/test-joern-sampling.py --output /tmp/pat-sampling-proof

Requires the pinned Joern/JDK and qualified OS containment. Not part of offline pytest.
"""

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from project_assess import joern_analysis as adapter

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New directory outside checkout")
    output = parser.parse_args().output.expanduser().resolve()
    if output.is_relative_to(ROOT):
        parser.error("Output must be outside the checkout")
    os.umask(0o077)
    output.mkdir(parents=True, exist_ok=False)
    query = adapter.QUERY_PATH.read_bytes()
    fixture = (ROOT / "tests/fixtures/joern_sampling_probe.sc").read_bytes()
    text = query.decode()
    helpers = text[
        text.index("  var truncatedValues = 0L") : text.index(
            "  // Separate supported dependencies"
        )
    ]
    script = output / "sampling-probe.sc"
    script.write_text(
        "import scala.collection.mutable\nimport scala.util.control.NonFatal\n"
        "import java.nio.charset.StandardCharsets.UTF_8\nimport java.nio.file.{Files, Paths}\n"
        "import ujson.{Arr, Bool, Null, Num, Obj, Str, Value}\n"
        "@main def exec(out: String): Unit = {\n  val errors = Arr()\n  val result = Obj()\n"
        + helpers
        + fixture.decode()
        + "}\n"
    )
    script.chmod(0o400)
    home, java, paths, _, _ = adapter._tools()
    if home.is_relative_to(ROOT) or java.is_relative_to(ROOT):
        parser.error("Operator tools must be outside the checkout")
    containment, binary = adapter._sandbox()
    if containment is None:
        parser.error("Qualified OS containment is unavailable")
    limits = adapter.joern_limits("standard")
    env = adapter._environment(paths, java, output, limits)
    result = output / "result.json"
    command = [str(paths["repl"]), "--script", str(script), "--param", "out=" + str(result)]
    started = time.monotonic()
    status = adapter._run(
        adapter._contained_command(command, output, ROOT, containment, binary, output),
        workspace=output,
        cwd=output,
        env=env,
        stop=started + limits["seconds"],
        limits=limits,
        output=result,
    )
    if status != "complete":
        raise SystemExit("Sampling probe did not complete: " + status)
    data = json.loads(result.read_text())
    assert data["status"] == "passed"
    assert data["max_heap_bytes"] <= limits["heap_gib"] * 1024**3
    assert data["active_processors"] <= limits["active_processors"]
    assert data["java_version"].startswith("21.")
    assert query == adapter.QUERY_PATH.read_bytes()
    receipt = {
        "status": "passed",
        "query_sha256": hashlib.sha256(query).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "seconds": round(time.monotonic() - started, 3),
        "containment": containment,
        "target_code_executed": False,
        "checks": {key: value for key, value in data.items() if isinstance(value, bool)},
    }
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
