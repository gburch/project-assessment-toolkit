"""Optional, contained Joern analysis of captured source; never project execution."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from pathlib import Path, PurePosixPath

from .joern_bindings import MAX_BYTES as BINDING_BYTES
from .joern_bindings import MAX_NODES as BINDING_NODES
from .joern_bindings import BindingCountercheck
from .joern_dataflow import normalize_dataflow
from .progress import report as report_progress
from .static_analysis import _retained_candidates, source_role

VERSION = "15"
QUERY_VERSION = "10"
JOERN_VERSION = "4.0.669"
QUERY_PATH = Path(__file__).parent / "resources" / "joern.sc"
MAX_INPUT_RECORDS = 20_000
MAX_CANDIDATES = 100
MAX_INDEX = 20_000
_FRONTENDS = {
    "python": "pysrc2cpg",
    "javascript": "jssrc2cpg",
    "java": "javasrc2cpg",
}
_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mts": "javascript",
    ".cts": "javascript",
    ".java": "java",
    ".swift": "swift",
}
_PROFILES = {
    "standard": {
        "seconds": 120,
        "files": 256,
        "bytes": 32 * 1024**2,
        "bytes_per_file": 2 * 1024**2,
        "heap_gib": 2,
    },
    "deep": {
        "seconds": 3600,
        "files": 20_000,
        "bytes": 512 * 1024**2,
        "bytes_per_file": 8 * 1024**2,
        "heap_gib": 8,
    },
}
_CAVEAT = (
    "Joern models captured source, not runtime behavior or complete resolution. "
    "No modeled read is a review lead, not permission to remove a binding, initializer "
    "or required callback, override or public parameter. Deep adds modeled parameter-value "
    "paths with default library semantics, not runtime taint or authorization proof. "
    "Constant-guard reachability and zero-caller deletion analysis are not performed."
)
_clock = time.monotonic

# Fixed transport only: Babel receives original bytes; Joern receives original
# source identities. No project configuration or TypeScript typemap is loaded.
_ASTGEN_TRANSPORT = r"""import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

INTERFACE = b'{"type":"TSInterfaceDeclaration",'


def interface_names(payload, counts):
    node = json.loads(payload)
    if not isinstance(node, dict) or node.get("type") != "TSInterfaceDeclaration":
        raise ValueError("Unexpected interface node")
    body = node.get("body", {})
    if not isinstance(body, dict) or body.get("type") != "TSInterfaceBody" or not isinstance(body.get("body"), list):
        counts["unexpected_interfaces"] += 1
        return payload
    changed = 0
    for member in body["body"]:
        if not isinstance(member, dict):
            counts["unexpected_interfaces"] += 1
            continue
        if member.get("type") != "TSPropertySignature" or member.get("computed") is True:
            continue
        key = member.get("key", {})
        if not isinstance(key, dict) or key.get("type") != "NumericLiteral":
            continue
        value = key.get("value")
        if type(value) not in (int, float) or not 0 <= value <= 9007199254740991 or int(value) != value:
            counts["unsupported_numeric_keys"] += 1
            continue
        key["value"] = str(int(value))
        changed += 1
    counts["numeric_keys"] += changed
    return json.dumps(node, ensure_ascii=True, separators=(",", ":")).encode() if changed else payload


def copy_ast(original, restored, initial, counts):
    buffer, eof = initial, False
    decoder = json.JSONDecoder()
    while buffer or not eof:
        at = buffer.find(INTERFACE)
        if at < 0:
            retained = 0 if eof else min(len(buffer), len(INTERFACE) - 1)
            restored.write(buffer[:len(buffer) - retained])
            buffer = buffer[-retained:] if retained else b""
        else:
            restored.write(buffer[:at])
            buffer = buffer[at:]
            while True:
                try:
                    text = buffer.decode("utf-8")
                    _, end = decoder.raw_decode(text)
                    end = len(text[:end].encode("utf-8"))
                    if end > MAX_INTERFACE_BYTES:
                        counts["bounded_interfaces"] += 1
                        restored.write(buffer[:end])
                    else:
                        restored.write(interface_names(buffer[:end], counts))
                    buffer = buffer[end:]
                    break
                except RecursionError:
                    counts["unexpected_interfaces"] += 1
                    restored.write(buffer)
                    buffer = b""
                    break
                except (UnicodeError, json.JSONDecodeError):
                    if len(buffer) > MAX_INTERFACE_BYTES or eof:
                        counts["bounded_interfaces" if not eof else "unexpected_interfaces"] += 1
                        restored.write(buffer)
                        buffer = b""
                        break
                    chunk = original.read(64 * 1024)
                    buffer += chunk
                    eof = not chunk
            continue
        if not eof:
            chunk = original.read(64 * 1024)
            buffer += chunk
            eof = not chunk


manifest = Path(__file__).with_suffix(".json")
if manifest.stat().st_size > 32 * 1024**2:
    raise ValueError("Oversized transport manifest")
settings = json.loads(manifest.read_text())
MAX_INTERFACE_BYTES = settings["max_interface_bytes"]
compatibility = []
binary = settings["binary"]
args = sys.argv[1:]
if args == ["--version"]:
    os.execv(binary, [binary, "--version"])
args = [arg for arg in args if arg != "--no-tsTypes"]
if len(args) != 4 or args[:3] != ["-t", "ts", "-o"]:
    raise ValueError("Unsupported AST transport arguments")
workspace, source = Path(settings["workspace"]), Path(settings["source"])
output = Path(args[3]).resolve()
if Path.cwd().resolve() != source or not output.is_relative_to(workspace):
    raise ValueError("AST transport escaped its workspace")
transport = Path(settings["transport"])
completed = subprocess.run(
    [binary, "--src", str(transport), "--output", str(output), "--type", "ts", "--no-tsTypes"],
    cwd=transport, stdin=subprocess.DEVNULL, check=False,
)
if completed.returncode:
    raise SystemExit(completed.returncode)
prefix = re.compile(rb'^\{"fullName":("(?:\\.|[^"\\])*"),"relativeName":("(?:\\.|[^"\\])*"),"ast":')
for row in settings["files"]:
    alias = transport / row["alias"]
    if hashlib.sha256(alias.read_bytes()).hexdigest() != row["sha256"]:
        raise ValueError("AST transport source changed")
    ast = output / (row["alias"] + ".json")
    if not ast.exists():
        continue
    if ast.is_symlink() or ast.stat().st_size > settings["max_ast_bytes"]:
        raise ValueError("Invalid AST transport output")
    temporary = ast.with_suffix(".pat-restored")
    counts = dict(numeric_keys=0, bounded_interfaces=0, unexpected_interfaces=0, unsupported_numeric_keys=0)
    with ast.open("rb") as original, temporary.open("xb") as restored:
        header = original.read(64 * 1024)
        match = prefix.match(header)
        if not match or json.loads(match[1]) != str(alias) or json.loads(match[2]) != row["alias"]:
            raise ValueError("Unexpected pinned AST header")
        identity = {"fullName": str(source / row["path"]), "relativeName": row["path"]}
        restored.write(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()[:-1] + b',"ast":')
        copy_ast(original, restored, header[match.end():], counts)
    if any(counts.values()):
        with ast.open("rb") as stream:
            producer = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        with temporary.open("rb") as stream:
            consumer = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        compatibility.append({"path": row["path"], "source_digest": "sha256:" + row["sha256"],
            "producer_ast_digest": producer, "consumer_ast_digest": consumer, **counts})
    temporary.replace(ast)
(workspace / "ast-compatibility.json").write_text(json.dumps({"schema_version": 1, "files": compatibility}))
"""


def joern_limits(analysis_profile):
    return _joern_configuration(analysis_profile)[0]


def _joern_configuration(analysis_profile):
    if not isinstance(analysis_profile, str) or analysis_profile not in _PROFILES:
        raise ValueError("Unknown analysis profile")
    limits = {
        **_PROFILES[analysis_profile],
        "endpoint_seconds": 60,
        "max_query_restarts": 32,
        "thread_stack_mib": 32 if analysis_profile == "deep" else None,
        "active_processors": 2,
        "workspace_bytes": (16 if analysis_profile == "deep" else 8) * 1024**3,
        "query_json_bytes": (128 if analysis_profile == "deep" else 32) * 1024**2,
        "log_bytes": 8 * 1024**2,
        "candidates": MAX_CANDIDATES,
        "candidate_index": MAX_INDEX,
        "input_records": MAX_INPUT_RECORDS,
        "dataflow": {
            "enabled": analysis_profile == "deep",
            "max_definitions": 50_000,
            "max_call_depth": 8,
            "paths": 20_000,
            "paths_per_sink": 64,
            "steps_per_path": 64,
            "max_arguments": 1000,
            "max_output_argument_expansion": 1000,
            "selected_sinks": 2048,
            "selection_policy": "priority_file_method_round_robin_v1",
        },
        "flow_checkpoint_bytes": 32 * 1024**2,
        "language_scheduling": "smallest_first_equal_remaining_time_v2",
        "javascript_frontend": {
            "bytes_per_file": 5 * 1024**2,
            "lines_per_file": 50_000,
            "bytes_per_line": 10_000,
            "emscripten": "unsupported",
            "interface_node_bytes": 2 * 1024**2,
        },
        "deadline_mode": "dedicated hard subprocess deadline; bounded normalization",
    }
    overrides = {}
    for name, field, maximum in (
        ("PAT_JOERN_TIMEOUT_SECONDS", "seconds", 86_400),
        ("PAT_JOERN_HEAP_GIB", "heap_gib", 64),
        ("PAT_JOERN_ACTIVE_PROCESSORS", "active_processors", 32),
        ("PAT_JOERN_ENDPOINT_SECONDS", "endpoint_seconds", 300),
    ):
        raw = os.environ.get(name)
        if raw is None:
            continue
        if (
            not isinstance(raw, str)
            or len(raw) > len(str(maximum))
            or re.fullmatch(r"[1-9][0-9]*", raw) is None
            or int(raw) > maximum
        ):
            raise ValueError(f"{name} must be a positive decimal integer from 1 to {maximum}")
        profile_default = limits[field]
        limits[field] = int(raw)
        overrides[field] = {
            "environment_variable": name,
            "value": limits[field],
            "profile_default": profile_default,
        }
    limits["dataflow"].update(
        endpoint_seconds=limits["endpoint_seconds"],
        max_query_restarts=limits["max_query_restarts"],
        isolation="reaped_process_group_with_immutable_overlay_resume",
    )
    return limits, overrides


def _hash_file(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def _home(name):
    value = os.environ.get(name, "")
    if not value or not Path(value).is_absolute():
        raise ValueError("Operator tool homes must be absolute")
    path = Path(value).resolve(strict=True)
    if not path.is_dir():
        raise ValueError("Operator tool home is not a directory")
    return path


def _contained_file(home, relative, *, executable=False):
    path = home / relative
    if not path.resolve(strict=True).is_relative_to(home) or not path.is_file():
        raise ValueError("Required tool component is outside its home")
    if executable and not os.access(path, os.X_OK):
        raise ValueError("Required tool component is not executable")
    return path


def _sandbox():
    if sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file():
        return "macos-sandbox-exec", "/usr/bin/sandbox-exec"
    if sys.platform.startswith("linux") and (binary := shutil.which("bwrap", path="/usr/bin:/bin")):
        return "linux-bwrap", binary
    return None, None


def _tools():
    home, java = _home("PAT_JOERN_HOME"), _home("PAT_JOERN_JAVA_HOME")
    release = _contained_file(java, "release")
    if release.stat().st_size > 64 * 1024:
        raise ValueError("Invalid JDK release metadata")
    match = re.search(r'^JAVA_VERSION="(21(?:\.[^"\n]*)?)"$', release.read_text(), re.M)
    if not match:
        raise ValueError("Joern requires the qualified JDK 21")
    paths = {
        "query": QUERY_PATH,
        "java": _contained_file(java, "bin/java", executable=True),
        "repl": _contained_file(home, "bin/repl-bridge", executable=True),
    }
    for language, frontend in _FRONTENDS.items():
        paths[language] = _contained_file(
            home, f"frontends/{frontend}/bin/{frontend}", executable=True
        )
        paths[language + "_jar"] = _contained_file(
            home, f"frontends/{frontend}/lib/io.joern.{frontend}-{JOERN_VERSION}.jar"
        )
        if (home / f"frontends/{frontend}/conf/application.ini").exists():
            paths[language + "_config"] = _contained_file(
                home, f"frontends/{frontend}/conf/application.ini"
            )
    if (home / "conf/application.ini").exists():
        paths["repl_config"] = _contained_file(home, "conf/application.ini")
    for name in ("joern-cli", "semanticcpg", "x2cpg", "dataflowengineoss"):
        paths[name] = _contained_file(home, f"lib/io.joern.{name}-{JOERN_VERSION}.jar")
    arm = platform.machine().lower() in {"arm64", "aarch64"}
    js_binary = (
        ("astgen-macos-arm" if arm else "astgen-macos")
        if sys.platform == "darwin"
        else ("astgen-linux-arm" if arm else "astgen-linux")
    )
    paths["astgen"] = _contained_file(
        home, "frontends/jssrc2cpg/bin/astgen/" + js_binary, executable=True
    )
    if not QUERY_PATH.is_file() or QUERY_PATH.stat().st_size > 1024**2:
        raise ValueError("Bundled Joern query is missing or oversized")
    hashes = {name: _hash_file(path) for name, path in sorted(paths.items())}
    hashes["jdk_release"] = _hash_file(release)
    return home, java, paths, match[1], hashes


def joern_info():
    result = {
        "name": "joern",
        "version": JOERN_VERSION,
        "adapter_version": VERSION,
        "query_version": QUERY_VERSION,
        "javascript_transport": {
            "version": "2",
            "sha256": hashlib.sha256(_ASTGEN_TRANSPORT.encode()).hexdigest(),
            "source_identity": "original_captured_paths",
            "type_maps": "not_run",
            "ast_compatibility": "Direct noncomputed TypeScript interface safe-integer property names for the pinned consumer; source bytes, node kinds and locations are unchanged",
            "ast_compatibility_version": "1",
            "ast_digest_scope": "Producer uses transport paths; consumer restores captured paths and applies only the recorded scoped compatibility",
            "module_mode": "Babel unambiguous syntax; .mts/.cts host module-resolution parity is unverified",
        },
        "available": False,
        "optional": True,
        "languages": ["python", "javascript", "typescript", "java"],
        "unqualified_languages": ["swift"],
        "unqualified_reason": "The pinned Swift frontend is not qualified under required write containment; Swift execution is disabled",
        "license": "Apache-2.0",
        "selection": "explicit",
        "execution": "contained external tool on captured source",
        "dataflow": "deep_profile",
    }
    try:
        _, _, _, jdk_version, hashes = _tools()
        containment, _ = _sandbox()
        result.update(jdk_version=jdk_version, component_hashes=hashes, containment=containment)
        result["available"] = containment is not None
        if containment is None:
            result["unavailable_reason"] = "Qualified OS containment is unavailable"
    except (OSError, ValueError, UnicodeError):
        result["unavailable_reason"] = (
            "Configure qualified external Joern and JDK homes; no installation is performed"
        )
    return result


def _relative(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\x00" in value
        or "\\" in value
    ):
        raise ValueError("Analyzer sources require captured relative paths")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() == ".":
        raise ValueError("Analyzer sources require captured relative paths")
    return path.as_posix()


def _javascript_guard(raw):
    # These are the pinned astgen's bounded-input guards, not quality findings.
    if len(raw) > 5 * 1024**2:
        return "javascript_frontend_file_byte_limit"
    if b"// EMSCRIPTEN_START_ASM" in raw:
        return "javascript_frontend_emscripten"
    lines = raw.split(b"\n")
    if len(lines) > 50_000:
        return "javascript_frontend_line_limit"
    if any(len(line) > 10_000 for line in lines):
        return "javascript_frontend_line_byte_limit"
    return None


def _javascript_transport(workspace, stage, batch, paths, limits):
    transport = stage.parent / "transport"
    transport.mkdir()
    rows = []
    for index, (path, source) in enumerate(sorted(batch.items())):
        suffix = PurePosixPath(path).suffix.lower()
        if suffix in {".mts", ".cts"}:
            suffix = ".ts"
        alias = f"unit{index:05d}{suffix}"
        target = transport / alias
        target.write_text(source["text"], encoding="utf-8")
        target.chmod(0o400)
        rows.append(
            {"alias": alias, "path": path, "sha256": source["digest"].removeprefix("sha256:")}
        )
    script = workspace / "astgen-transport.py"
    script.write_text(_ASTGEN_TRANSPORT)
    script.with_suffix(".json").write_text(
        json.dumps(
            {
                "binary": str(paths["astgen"]),
                "workspace": str(workspace),
                "source": str(stage),
                "transport": str(transport),
                "files": rows,
                "max_ast_bytes": limits["workspace_bytes"],
                "max_interface_bytes": limits["javascript_frontend"]["interface_node_bytes"],
            }
        )
    )
    runtime = Path(sys.executable).resolve(strict=True)
    launcher = workspace / "astgen-transport"
    launcher.write_text(
        "#!/bin/sh\nexec "
        + shlex.quote(str(runtime))
        + " -I -S "
        + shlex.quote(str(script))
        + ' "$@"\n'
    )
    launcher.chmod(0o500)
    return launcher


def _javascript_compatibility(workspace, stage, batch):
    """Validate the fixed transport's source-bound AST compatibility receipt."""
    path = workspace / "ast-compatibility.json"
    if path.is_symlink() or path.stat().st_size > 32 * 1024**2:
        raise ValueError("Invalid AST compatibility receipt")
    value = json.loads(path.read_text())
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not isinstance(value.get("files"), list)
        or len(value["files"]) > len(batch)
    ):
        raise ValueError("Invalid AST compatibility receipt")
    fields = (
        "numeric_keys",
        "bounded_interfaces",
        "unexpected_interfaces",
        "unsupported_numeric_keys",
    )
    totals = {field: 0 for field in fields}
    records, seen = [], set()
    for row in value["files"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid AST compatibility file")
        source = _source_path(row.get("path"), stage, batch)
        if source is None or source in seen or row.get("source_digest") != batch[source]["digest"]:
            raise ValueError("Invalid AST compatibility identity")
        seen.add(source)
        if any(not _integer(row.get(field)) for field in fields) or any(
            not isinstance(row.get(field), str)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", row[field]) is None
            for field in ("producer_ast_digest", "consumer_ast_digest")
        ):
            raise ValueError("Invalid AST compatibility counts or digests")
        records.append(
            {
                "path": source,
                **{
                    field: row[field]
                    for field in (
                        *fields,
                        "source_digest",
                        "producer_ast_digest",
                        "consumer_ast_digest",
                    )
                },
            }
        )
        for field in fields:
            totals[field] += row[field]
    return {
        "version": "1",
        "scope": "direct noncomputed TypeScript interface safe-integer property names",
        "adjusted_files": sum(row["numeric_keys"] > 0 for row in records),
        **totals,
        "files": records,
    }


def _environment(paths, java, workspace, limits):
    home, temporary = workspace / "home", workspace / "tmp"
    home.mkdir()
    temporary.mkdir()
    stack = f" -Xss{limits['thread_stack_mib']}m" if limits.get("thread_stack_mib") else ""
    return {
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "JAVA_HOME": str(java),
        "PATH": str(java / "bin") + ":/usr/bin:/bin",
        "JAVA_OPTS": f"-Xmx{limits['heap_gib']}g -XX:ActiveProcessorCount={limits['active_processors']}{stack}",
        "_JAVA_OPTIONS": (
            f"-Xmx{limits['heap_gib']}g -XX:ActiveProcessorCount={limits['active_processors']}{stack} "
            f"-Duser.home={json.dumps(str(home), ensure_ascii=False)} "
            f"-Djava.io.tmpdir={json.dumps(str(temporary), ensure_ascii=False)}"
        ),
        "ASTGEN_BIN": str(paths["astgen"]),
        "LANG": "C.UTF-8",
        "LC_ALL": "C",
        "NO_COLOR": "1",
    }


def _contained_command(argv, workspace, original_root, containment, binary, cwd):
    if containment == "macos-sandbox-exec":

        def quote(path):
            return json.dumps(str(path), ensure_ascii=False)

        policy = (
            "(version 1) (allow default) (deny network*) (deny file-write*) "
            f"(allow file-write* (subpath {quote(workspace)})) "
            '(allow file-write-data (literal "/dev/null")) '
            f"(deny file-read* (subpath {quote(original_root)}))"
        )
        policy += " ".join(
            f"(deny file-write* (subpath {quote(workspace / language / name)}))"
            for language in _FRONTENDS
            for name in ("source", "transport")
        )
        return [binary, "-p", policy, *argv]
    hidden = workspace / "hidden-original"
    hidden.mkdir(exist_ok=True)
    command = [
        binary,
        "--die-with-parent",
        "--unshare-net",
        "--unshare-pid",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(workspace),
        str(workspace),
        "--ro-bind",
        str(hidden),
        str(original_root),
    ]
    for language in _FRONTENDS:
        for name in ("source", "transport"):
            stage = workspace / language / name
            if stage.is_dir():
                command.extend(["--ro-bind", str(stage), str(stage)])
    return [*command, "--chdir", str(cwd), "--", *argv]


def _workspace_size(workspace):
    size = 0
    for directory, _, names in os.walk(workspace, followlinks=False):
        for name in names:
            try:
                info = (Path(directory) / name).lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                size += info.st_size
    return size


def _signal_group(process, sig):
    """Signal a group, treating one that holds only an exited leader as already gone.

    Darwin answers EPERM rather than ESRCH while the only member is an unreaped zombie.
    Reaping settles that case; a refusal that persists is real and still raises.
    """
    for attempt in range(_SIGNAL_RETRIES, -1, -1):
        try:
            os.killpg(process.pid, sig)
            return
        except ProcessLookupError:
            return
        except PermissionError:
            process.poll()
            if not attempt:
                raise
            time.sleep(0.02)


def _stop_group(process):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        _signal_group(process, sig)
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
    process.wait(timeout=2)


class _ProcessStatus(str):
    """Keep source-free producer diagnostics alongside the actual process outcome."""

    def __new__(cls, terminal_status, *, engine_failed=False, model_pruned=False, endpoint_id=None):
        value = super().__new__(cls, "analysis_engine_error" if engine_failed else terminal_status)
        value.terminal_status = terminal_status
        value.engine_failed = engine_failed
        value.model_pruned = model_pruned
        value.endpoint_id = endpoint_id
        return value


_SIGNAL_RETRIES = 25
_UNKNOWN_ENDPOINT = object()
_INVALID_ENDPOINT = object()


def _run(argv, *, workspace, cwd, env, stop, limits, output=None, flow_watch=None):
    """Discard bounded logs and always reap the whole process group, including orphans."""
    status, logged, next_disk = "complete", 0, 0.0
    engine_error, model_pruned, tails = False, False, {}
    watched_endpoint, endpoint_began, timed_out_endpoint = None, None, None

    def inspect(stream, data):
        # Joern can catch worker failures and still exit zero with empty paths.
        # Retain only fixed failure markers, never source, commands or raw logs.
        nonlocal engine_error, model_pruned
        combined = tails.get(stream, b"") + data
        if any(
            marker in combined
            for marker in (
                b"SolveTask failed",
                b"java.lang.StackOverflowError",
                b"java.lang.OutOfMemoryError",
                b"java.util.concurrent.ExecutionException:",
            )
        ):
            engine_error = True
        if any(
            marker in combined
            for marker in (
                b"Too many arguments for parameter:",
                b"Too many new tasks in expansion of unresolved output arguments",
            )
        ):
            model_pruned = True
        tails[stream] = combined[-128:]

    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            shell=False,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        error._pat_joern_worker_operation = "process_start"
        raise
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                selector.register(stream, selectors.EVENT_READ)
            while process.poll() is None:
                now = _clock()
                if now >= stop:
                    status = "timeout"
                    break
                if flow_watch and output:
                    marker = _active_endpoint(output, flow_watch)
                    if marker is _INVALID_ENDPOINT and watched_endpoint is None:
                        status = "invalid_endpoint_progress"
                        break
                    if (
                        marker not in (_UNKNOWN_ENDPOINT, _INVALID_ENDPOINT)
                        and marker != watched_endpoint
                    ):
                        watched_endpoint, endpoint_began = marker, now if marker else None
                    if watched_endpoint and now - endpoint_began >= flow_watch["seconds"]:
                        status, timed_out_endpoint = "endpoint_timeout", watched_endpoint
                        break
                if now >= next_disk:
                    if _workspace_size(workspace) > limits["workspace_bytes"]:
                        status = "workspace_limit"
                        break
                    if (
                        output
                        and output.exists()
                        and output.lstat().st_size > limits["query_json_bytes"]
                    ):
                        status = "query_output_limit"
                        break
                    next_disk = now + 0.5
                for key, _ in selector.select(timeout=min(0.1, max(0, stop - now))):
                    data = os.read(key.fd, 65536)
                    inspect(key.fd, data)
                    if not data:
                        selector.unregister(key.fileobj)
                    logged += len(data)
                    if logged > limits["log_bytes"]:
                        status = "log_limit"
                        break
                if status != "complete":
                    break
            code = process.poll()
            while ready := selector.select(timeout=0):
                for key, _ in ready:
                    data = os.read(key.fd, 65536)
                    inspect(key.fd, data)
                    logged += len(data)
                    if not data:
                        selector.unregister(key.fileobj)
                if logged > limits["log_bytes"]:
                    break
            if logged > limits["log_bytes"]:
                status = "log_limit"
            if status == "complete" and code != 0:
                status = "tool_failed"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        error._pat_joern_worker_operation = "process_monitor"
        raise
    finally:
        try:
            _stop_group(process)
        except (OSError, subprocess.SubprocessError) as error:
            error._pat_joern_worker_operation = "process_reap"
            raise
        finally:
            process.stdout.close()
            process.stderr.close()
    if status == "complete" and (
        _workspace_size(workspace) > limits["workspace_bytes"]
        or output
        and output.exists()
        and output.lstat().st_size > limits["query_json_bytes"]
    ):
        status = "output_limit"
    return _ProcessStatus(
        status,
        engine_failed=engine_error,
        model_pruned=model_pruned,
        endpoint_id=timed_out_endpoint,
    )


def _active_endpoint(output, watch):
    """Only a fully validated fresh idle marker may clear an endpoint timer."""
    fresh = False
    try:
        path = output.with_name(output.name + ".flow-progress.json")
        marker = _read_json(path, 512 * 1024)
        if not isinstance(marker, dict):
            return _UNKNOWN_ENDPOINT
        if (
            marker.get("query_version") != QUERY_VERSION
            or marker.get("run_token") != watch["run_token"]
            or marker.get("attempt_token") != watch["attempt_token"]
        ):
            return _UNKNOWN_ENDPOINT
        fresh = True
        if "_flow" not in watch:
            checkpoint = _read_json(output.with_name(output.name + ".flow.json"), 32 * 1024**2)
            flow = checkpoint["dataflow_analysis"]
            selection = flow["selection"]
            ids = [row["id"] for row in selection["endpoints"]]
            digest = hashlib.sha256("\n".join(ids).encode()).hexdigest()
            if (
                checkpoint.get("query_version") != QUERY_VERSION
                or checkpoint.get("run_token") != watch["run_token"]
                or checkpoint.get("base_sha256") != marker.get("base_sha256")
                or len(ids) > 2048
                or len(set(ids)) != len(ids)
                or digest != selection["plan_digest"]
                or digest != marker.get("plan_digest")
            ):
                return _INVALID_ENDPOINT
            watch.update(
                # The checkpoint can advance after the marker was atomically read.
                # Bind immutable plan/scope here, not a later completion lower bound.
                _flow={"selection": selection, "queries": {**flow["queries"], "sinks_queried": 0}},
                _base_sha256=checkpoint["base_sha256"],
            )
        diagnostic = _flow_progress(
            path, watch["run_token"], watch["_base_sha256"], watch["_flow"], value=marker
        )
        if diagnostic["status"] != "valid":
            return _INVALID_ENDPOINT
        previous = watch.get("_last")
        if previous and (
            not set(previous["completed_endpoint_ids"]) <= set(marker["completed_endpoint_ids"])
            or not set(previous["timed_out_endpoint_ids"]) <= set(marker["timed_out_endpoint_ids"])
            or marker["sinks_queried"] < previous["sinks_queried"]
            or marker["engine_queries_started"] < previous["engine_queries_started"]
            or marker["elapsed_seconds"] < previous["elapsed_seconds"]
            or previous["current_endpoint_id"] is not None
            and previous["current_endpoint_id"] != marker["current_endpoint_id"]
            and previous["current_endpoint_id"] not in marker["completed_endpoint_ids"]
            and previous["current_endpoint_id"] not in marker["timed_out_endpoint_ids"]
        ):
            return _INVALID_ENDPOINT
        watch["_last"] = marker
        if marker["stage"] == "querying":
            return marker["current_endpoint_id"]
        return None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return _INVALID_ENDPOINT if fresh else _UNKNOWN_ENDPOINT


def _read_json(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Invalid query output")
        payload = stream.read(maximum + 1)
    if len(payload) > maximum:
        raise ValueError("Oversized query output")

    def nonfinite(_):
        raise ValueError("Nonfinite query value")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate query key")
            result[key] = value
        return result

    return json.loads(payload, parse_constant=nonfinite, object_pairs_hook=pairs)


def _read_result(path, maximum):
    result = _read_json(path, maximum)
    if (
        not isinstance(result, dict)
        or type(result.get("schema_version")) is not int
        or result.get("schema_version") != 1
        or result.get("query_version") != QUERY_VERSION
    ):
        raise ValueError("Unsupported query output")
    if result.get("dataflow") not in {"not_run", "complete", "partial", "error"}:
        raise ValueError("Unqualified dataflow analysis")
    return result


def _checkpoint_digest(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Invalid checkpoint base")
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _recover_flow_checkpoint(path, base, base_sha256, run_token, limits, stage, sources, clean):
    """Admit only a finished, source-bound prefix from this invocation and base."""
    value = _read_json(path, limits["flow_checkpoint_bytes"])
    fields = {
        "schema_version",
        "query_version",
        "checkpoint",
        "run_token",
        "base_sha256",
        "overlays",
        "truncated_values",
        "dataflow_analysis",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["query_version"] != QUERY_VERSION
        or value["checkpoint"] != "dataflow_progress"
        or value["run_token"] != run_token
        or base.get("run_token") != run_token
        or value["base_sha256"] != base_sha256
        or value["overlays"]
        != sorted(set(base.get("metadata", {}).get("overlays", [])) | {"dataflowOss"})
        or not _integer(value["truncated_values"])
        or value["truncated_values"] > 2**53
        or not isinstance(value["dataflow_analysis"], dict)
        or value["dataflow_analysis"].get("status") != "partial"
        or value["dataflow_analysis"].get("methods_total") != base.get("methods", {}).get("count")
    ):
        raise ValueError("Unqualified flow checkpoint")
    flow, gaps = normalize_dataflow(
        {
            "query_version": QUERY_VERSION,
            "dataflow": "partial",
            "dataflow_analysis": value["dataflow_analysis"],
        },
        stage=stage,
        sources=sources,
        clean=clean,
    )
    flow.update(checkpoint_recovered=True, overlay="dataflowOss", base_sha256=base_sha256)
    gaps.add(
        "Recovered completed flow queries from an interrupted producer; unfinished work remains unknown"
    )
    return flow, gaps


def _flow_progress(path, run_token, base_sha256, flow=None, *, value=None):
    """Inspect bounded scalar diagnostics separately from usable path evidence."""
    if value is None and not path.exists():
        return {"status": "unavailable"}
    counters = (
        "source_parameter_count",
        "sinks_total",
        "sinks_eligible",
        "sinks_selected",
        "sinks_not_selected",
        "sinks_skipped",
        "sinks_queried",
        "sinks_pending",
        "engine_queries",
        "engine_queries_started",
        "sinks_proven_empty",
    )
    times = ("elapsed_seconds", "flow_elapsed_seconds", "maximum_endpoint_seconds")
    fields = {
        "schema_version",
        "query_version",
        "run_token",
        "base_sha256",
        "plan_digest",
        "stage",
        "by_category",
        "flow_budget_seconds",
        "budget_origin",
        "current_endpoint_started_seconds",
        *counters,
        *times,
    }
    try:
        if value is None:
            value = _read_json(path, 512 * 1024)
        resumed_fields = {
            "attempt_token",
            "current_endpoint_id",
            "completed_endpoint_ids",
            "timed_out_endpoint_ids",
        }
        if (
            not isinstance(value, dict)
            or set(value) not in (fields, fields | resumed_fields)
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["query_version"] != QUERY_VERSION
            or value["run_token"] != run_token
            or value["base_sha256"] != base_sha256
            or not isinstance(value["plan_digest"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["plan_digest"]) is None
            or value["stage"]
            not in {"ready", "querying", "finished", "finished_with_timeouts", "budget_exhausted"}
            or value["budget_origin"] != "query_body_start"
            or type(value["flow_budget_seconds"]) is not int
            or not 1 <= value["flow_budget_seconds"] <= 86_400
            or any(not _integer(value[key]) or value[key] > 2**53 for key in counters)
            or any(
                type(value[key]) not in {int, float}
                or not 0 <= value[key] <= 86_400
                or not math.isfinite(value[key])
                for key in times
            )
        ):
            raise ValueError("Invalid tracing progress")
        current = value["current_endpoint_started_seconds"]
        explicit = "completed_endpoint_ids" in value
        completed = value.get("completed_endpoint_ids", [])
        timed_out = value.get("timed_out_endpoint_ids", [])
        if explicit and (
            not isinstance(value["attempt_token"], str)
            or re.fullmatch("[0-9a-f]{32}", value["attempt_token"]) is None
            or not isinstance(completed, list)
            or not isinstance(timed_out, list)
            or any(
                not isinstance(item, str) or re.fullmatch("[0-9a-f]{64}", item) is None
                for item in [*completed, *timed_out]
            )
            or len(set(completed)) != len(completed)
            or len(set(timed_out)) != len(timed_out)
            or set(completed).intersection(timed_out)
            or len(completed) != value["sinks_queried"]
            or len(timed_out) > value["sinks_pending"]
            or (value["current_endpoint_id"] is None) != (value["stage"] != "querying")
            or value["current_endpoint_id"] is not None
            and (
                not isinstance(value["current_endpoint_id"], str)
                or re.fullmatch("[0-9a-f]{64}", value["current_endpoint_id"]) is None
                or value["current_endpoint_id"] in [*completed, *timed_out]
            )
        ):
            raise ValueError("Invalid explicit endpoint progress")
        if (
            value["sinks_selected"] > 2048
            or value["sinks_total"] != value["sinks_eligible"] + value["sinks_skipped"]
            or value["sinks_eligible"] != value["sinks_selected"] + value["sinks_not_selected"]
            or value["sinks_selected"] != value["sinks_queried"] + value["sinks_pending"]
            or value["sinks_queried"] != value["engine_queries"] + value["sinks_proven_empty"]
            or value["engine_queries_started"] - value["engine_queries"]
            != len(timed_out) + (value["stage"] == "querying")
            or (current is None) != (value["stage"] != "querying")
            or current is not None
            and (
                type(current) not in {int, float}
                or not 0 <= current <= value["elapsed_seconds"]
                or not math.isfinite(current)
            )
            or value["flow_elapsed_seconds"] > value["elapsed_seconds"]
            or value["maximum_endpoint_seconds"] > value["flow_elapsed_seconds"]
            or value["stage"] == "finished"
            and value["sinks_pending"] != 0
            or value["stage"] == "finished_with_timeouts"
            and (not explicit or not timed_out or value["sinks_pending"] != len(timed_out))
            or value["stage"] == "budget_exhausted"
            and value["sinks_pending"] == 0
        ):
            raise ValueError("Inconsistent tracing progress")
        categories = (
            "named_effect_hint",
            "lifecycle_name_hint",
            "source_supported_cross_file",
            "breadth",
        )
        counts = value["by_category"]
        if not isinstance(counts, dict) or set(counts) != set(categories):
            raise ValueError("Missing tracing categories")
        for row in counts.values():
            if (
                not isinstance(row, dict)
                or set(row) != {"candidates", "selected", "queried"}
                or any(not _integer(number) or number > 2**53 for number in row.values())
                or not row["candidates"] >= row["selected"] >= row["queried"]
            ):
                raise ValueError("Invalid tracing category counts")
        if any(
            sum(row[key] for row in counts.values()) != value[field]
            for key, field in (
                ("candidates", "sinks_eligible"),
                ("selected", "sinks_selected"),
                ("queried", "sinks_queried"),
            )
        ):
            raise ValueError("Inconsistent tracing category totals")
        if flow and "selection" in flow:
            if value["plan_digest"] != flow["selection"]["plan_digest"]:
                raise ValueError("Progress belongs to another plan")
            for key in (
                "sinks_total",
                "sinks_eligible",
                "sinks_selected",
                "sinks_not_selected",
                "sinks_skipped",
            ):
                if value[key] != flow["queries"][key]:
                    raise ValueError("Progress belongs to another query scope")
            if value["sinks_queried"] < flow["queries"]["sinks_queried"]:
                raise ValueError("Progress predates its checkpoint")
            selected = flow["selection"]["endpoints"]
            if explicit and not (
                set(completed)
                | set(timed_out)
                | ({value["current_endpoint_id"]} if value["current_endpoint_id"] else set())
            ) <= {row["id"] for row in selected}:
                raise ValueError("Progress endpoints lie outside the plan")
            prefix = (
                [row for row in selected if row["id"] in completed]
                if explicit
                else selected[: value["sinks_queried"]]
            )
            if any(
                counts[category]["queried"] != sum(row["category"] == category for row in prefix)
                for category in categories
            ):
                raise ValueError("Progress does not match its completed prefix")
        return {
            "status": "valid",
            **{
                key: value[key]
                for key in fields - {"schema_version", "query_version", "run_token", "base_sha256"}
            },
            **(
                {
                    "sinks_timed_out": len(timed_out),
                    "current_endpoint_id": value["current_endpoint_id"],
                }
                if explicit
                else {}
            ),
        }
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return {"status": "invalid"}


def _phase_progress(path, profile):
    """Keep bounded, source-free query timing; never relay raw diagnostics."""
    if not path.exists():
        return {"status": "unavailable"}
    stages = (
        "import",
        "default_overlays",
        "postprocessing",
        "base_evidence",
        "definition_accounting",
        "dataflow_overlay",
        "dataflow_queries",
    )
    if profile == "standard":
        stages = stages[:4]
    expected = [f"{stage}_{state}" for stage in stages for state in ("started", "completed")]
    try:
        value = _read_json(path, 8192)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "query_version", "phases"}
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["query_version"] != QUERY_VERSION
            or not isinstance(value["phases"], list)
            or not 1 <= len(value["phases"]) <= len(expected)
        ):
            raise ValueError("Invalid phase metadata")
        events, previous = [], 0.0
        for name, row in zip(expected, value["phases"], strict=False):
            if (
                not isinstance(row, dict)
                or set(row) != {"phase", "elapsed_seconds"}
                or row["phase"] != name
                or type(row["elapsed_seconds"]) not in {int, float}
                or not previous <= row["elapsed_seconds"] <= 86_400
                or not math.isfinite(row["elapsed_seconds"])
            ):
                raise ValueError("Invalid phase event")
            previous = row["elapsed_seconds"]
            events.append({"phase": name, "elapsed_seconds": previous})
        return {
            "status": "complete" if len(events) == len(expected) else "partial",
            "timing_scope": "query_body_only",
            "last_phase": events[-1]["phase"],
            "events": events,
            "durations_seconds": {
                stages[index // 2]: events[index + 1]["elapsed_seconds"]
                - events[index]["elapsed_seconds"]
                for index in range(0, len(events) - 1, 2)
            },
        }
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return {"status": "invalid"}


def _source_path(value, stage, sources):
    if not isinstance(value, str):
        return None
    try:
        path = PurePosixPath(value)
        if path.is_absolute():
            path = path.relative_to(stage.as_posix())
        relative = _relative(path.as_posix())
    except ValueError:
        return None
    return relative if relative in sources else None


def _integer(value):
    return type(value) is int and value >= 0


def _normalize(raw, stage, sources, workspace, clean, stop):
    methods, calls, candidates, modeled = [], [], [], set()
    omissions = Counter()
    gaps = set()
    binding_checks = Counter()
    countercheck = BindingCountercheck(sources, lambda: _clock() >= stop)

    def text(value):
        return clean(str(value).replace(str(workspace), "<analysis>"))[:1024]

    files = raw.get("source_files", {})
    if (
        not isinstance(files, dict)
        or not isinstance(files.get("rows"), list)
        or len(files["rows"]) > 20_000
    ):
        raise ValueError("Invalid source coverage")
    for row in files.get("rows", []):
        if isinstance(row, dict) and row.get("identity_truncated"):
            omissions["truncated_model_identity"] += 1
            continue
        if isinstance(row, dict) and (path := _source_path(row.get("path"), stage, sources)):
            modeled.add(path)
        else:
            omissions["unlocated_model_file"] += 1
    if set(sources) - modeled:
        omissions["staged_file_without_model"] += len(set(sources) - modeled)

    def rows(section):
        value = raw.get(section, {})
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("rows"), list)
            or len(value["rows"]) > (200_000 if section == "methods" else 50_000)
        ):
            raise ValueError("Invalid query section")
        if value.get("status") != "complete" or value.get("omitted", 0):
            gaps.add(f"Joern {section} is partial or bounded")
        for row in value["rows"]:
            if _clock() >= stop:
                gaps.add("Joern normalization deadline reached")
                break
            if not isinstance(row, dict):
                omissions["invalid_model_row"] += 1
                continue
            if row.get("identity_truncated"):
                omissions["truncated_model_identity"] += 1
                continue
            path = _source_path(row.get("path"), stage, sources)
            line = row.get("line")
            if (
                path is None
                or type(line) is not int
                or not 1 <= line <= len(sources[path]["lines"])
            ):
                omissions["unlocated_or_external_model_row"] += 1
                continue
            yield path, line, row

    for path, line, row in rows("methods"):
        methods.append(
            {
                "path": path,
                "source_evidence_id": sources[path]["evidence_id"],
                "digest": sources[path]["digest"],
                "line": line,
                "name": text(row.get("name", "")),
                "full_name": text(row.get("full_name", "")),
                "is_external": row.get("is_external") is True,
                "is_abstract": row.get("is_abstract") is True,
                "is_constructor": row.get("is_constructor") is True,
                "has_body": row.get("has_body") is True,
            }
        )
    for path, line, row in rows("calls"):
        target = _source_path(row.get("target_path"), stage, sources)
        dependency = row.get("dependency_status")
        if dependency not in {"source_supported", "producer_inferred", "unresolved", "rejected"}:
            omissions["unqualified_call_target"] += 1
            continue
        if dependency == "rejected":
            omissions["rejected_call_target"] += 1
            continue
        if target is None:
            dependency = "unresolved"
        calls.append(
            {
                "path": path,
                "source_evidence_id": sources[path]["evidence_id"],
                "digest": sources[path]["digest"],
                "line": line,
                "caller_name": text(row.get("caller_name", "")),
                "caller_full_name": text(row.get("caller_full_name", "")),
                "target_path": target,
                "target_source_evidence_id": sources[target]["evidence_id"] if target else None,
                "target_digest": sources[target]["digest"] if target else None,
                "target_name": text(row.get("target_name", "")),
                "target_full_name": text(row.get("target_full_name", "")),
                "resolution": "internal"
                if dependency == "source_supported"
                else "external_or_unresolved",
                "dependency_status": dependency,
                "dependency_basis": text(row.get("dependency_basis", "unknown")),
                "confidence": "medium" if dependency == "source_supported" else "low",
            }
        )
    for path, line, row in rows("unread_bindings"):
        symbol, kind = row.get("symbol"), row.get("binding_kind")
        if (
            row.get("cleanup_status") != "review_candidate"
            or row.get("capture_status") != "not_captured"
            or row.get("signature_status")
            != ("private_direct_only" if kind == "parameter" else "not_applicable")
            or row.get("basis") != "identifier_REF_reads_with_capture_and_function_escape_checks"
        ):
            omissions["unqualified_binding_contract"] += 1
            continue
        if (
            not isinstance(symbol, str)
            or len(symbol) > 256
            or not re.fullmatch(r"(?:[^\W\d]|[$_])(?:\w|[$])*", symbol)
        ):
            omissions["generated_or_unvalidated_binding"] += 1
            continue
        if symbol in {"self", "this", "cls", "_"} or symbol.startswith(("_tmp_", "__tmp")):
            omissions["generated_or_unvalidated_binding"] += 1
            continue
        if (
            row.get("is_abstract")
            or row.get("has_body") is not True
            or kind == "parameter"
            and row.get("is_constructor")
        ):
            omissions["abstract_bodyless_or_constructor_binding"] += 1
            continue
        if (
            kind not in {"local", "parameter"}
            or type(row.get("read_count")) is not int
            or row.get("read_count") != 0
            or not re.search(
                r"(?<![\w$])" + re.escape(symbol) + r"(?![\w$])", sources[path]["lines"][line - 1]
            )
        ):
            omissions["generated_or_unvalidated_binding"] += 1
            continue
        checked = countercheck.check(path, line, symbol, kind)
        binding_checks[checked] += 1
        if checked != "source_unread":
            if checked.endswith("unknown") or checked == "source_syntax_unavailable_or_bounded":
                gaps.add(
                    "Joern unread-binding source qualification is incomplete; unsupported or ambiguous bindings are not cleanup leads"
                )
            continue
        candidate = {
            "kind": "unused_symbol",
            "lens": "quality",
            "confidence": "low",
            "locations": [{"path": path, "line": line, "end_line": line}],
            "metrics": {
                "diagnostic_subtype": "no_modeled_read",
                "binding_kind": kind,
                "symbol": text(symbol),
                "method": text(row.get("method_full_name", "")),
                "read_count": 0,
                "reference_count": row.get("reference_count")
                if _integer(row.get("reference_count"))
                else None,
                "capture_status": row["capture_status"],
                "signature_status": row["signature_status"],
                "basis": row["basis"],
                "source_digest": sources[path]["digest"],
                "source_countercheck": "no_read_found_in_bounded_captured_syntax",
            },
            "role": sources[path]["role"],
            "roles": [sources[path]["role"]],
            "source_identity": "captured_snapshot",
            "source_evidence_ids": [sources[path]["evidence_id"]],
            "caveat": _CAVEAT,
            "counterevidence": [
                "Preserve initializer effects and required callback, override and public signature contracts; modeled unread does not prove safe deletion."
            ],
        }
        candidate["id"] = (
            "j-" + hashlib.sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest()[:24]
        )
        candidates.append(candidate)
    for key, value in raw.items():
        if isinstance(value, dict) and value.get("omitted"):
            gaps.add(f"Joern {key} rows were omitted by query bounds")
    if raw.get("errors") or raw.get("gaps"):
        gaps.add("Joern reported incomplete model sections; raw error text is not retained")
    if omissions:
        gaps.add(
            "Joern generated, unlocated or unsupported declaration models were excluded; absence is unknown"
        )
    edge_sets = []
    for section, status in (
        ("module_edges", "source_supported"),
        ("inferred_module_edges", "producer_inferred"),
    ):
        aggregate = raw.get(section)
        edges = Counter()
        if (
            not isinstance(aggregate, dict)
            or not isinstance(aggregate.get("rows"), list)
            or len(aggregate["rows"]) > 100_000
        ):
            raise ValueError("Missing or invalid qualified module edges")
        for row in aggregate["rows"]:
            if not isinstance(row, dict):
                raise ValueError("Invalid module edge")
            if row.get("identity_truncated"):
                omissions["truncated_model_identity"] += 1
                continue
            source = _source_path(row.get("source"), stage, sources)
            target = _source_path(row.get("target"), stage, sources)
            if source and target and _integer(row.get("count")) and row["count"] > 0:
                edges[(source, target)] += row["count"]
            else:
                omissions["unlocated_module_edge"] += 1
        if aggregate.get("count_is_lower_bound") or aggregate.get("omitted"):
            gaps.add(f"Joern {status} aggregate method-call edges are bounded lower limits")
        edge_sets.append(edges)
    return (
        methods,
        calls,
        candidates,
        modeled,
        omissions,
        gaps,
        *edge_sets,
        dict(sorted(binding_checks.items())),
    )


def _method_sampling_metadata(value, stage, sources, analysis_profile="standard"):
    """Keep bounded per-file model coverage distinct from retained normalized rows."""
    fields = ("source_files", "retained_files", "omitted_files", "row_byte_limit", "byte_omissions")
    deep = analysis_profile == "deep"
    metadata_bytes = (2048 if deep else 256) * 1024
    row_bytes = (48 if deep else 6) * 1024**2 - metadata_bytes - 4096
    if (
        not isinstance(value, dict)
        or value.get("sampling") != "max_min_per_file_then_round_robin"
        or any(not _integer(value.get(field)) for field in (*fields, "count", "omitted"))
        or value["source_files"] > len(sources)
        or value["retained_files"] + value["omitted_files"] != value["source_files"]
        or value["row_byte_limit"] != row_bytes
        or value["byte_omissions"] > (200_000 if deep else 20_000)
        or value["omitted"] > value["count"]
    ):
        raise ValueError("Invalid method sampling metadata")
    coverage = value.get("file_coverage")
    if (
        not isinstance(coverage, dict)
        or coverage.get("status") not in {"complete", "partial"}
        or any(
            not _integer(coverage.get(field))
            for field in ("count", "omitted", "limit", "byte_limit")
        )
        or coverage["count"] != value["source_files"]
        or coverage["limit"] != coverage["count"]
        or coverage["byte_limit"] != metadata_bytes
        or not isinstance(coverage.get("rows"), list)
        or len(coverage["rows"]) > len(sources)
        or coverage["omitted"] + len(coverage["rows"]) != coverage["count"]
        or coverage["status"] == "complete"
        and coverage["omitted"] != 0
    ):
        raise ValueError("Invalid method file coverage")
    rows, seen, unlocated = [], set(), 0
    for row in coverage["rows"]:
        if not isinstance(row, dict) or type(row.get("identity_truncated")) is not bool:
            raise ValueError("Invalid method file coverage row")
        if row.get("identity_truncated") is True:
            unlocated += 1
            continue
        path = _source_path(row.get("path"), stage, sources)
        if (
            path is None
            or path in seen
            or not _integer(row.get("count"))
            or row["count"] == 0
            or not _integer(row.get("retained"))
            or row["retained"] > row["count"]
        ):
            raise ValueError("Invalid method file coverage identity or count")
        seen.add(path)
        rows.append({"path": path, "count": row["count"], "retained": row["retained"]})
    if (
        coverage["status"] == "complete"
        and not unlocated
        and (
            sum(row["count"] for row in rows) != value["count"]
            or sum(row["retained"] for row in rows) != value["count"] - value["omitted"]
            or sum(row["retained"] > 0 for row in rows) != value["retained_files"]
        )
    ):
        raise ValueError("Inconsistent complete method sampling counts")
    return {
        "sampling": value["sampling"],
        **{field: value[field] for field in fields},
        "file_coverage": {
            "status": "partial" if unlocated else coverage["status"],
            "count": coverage["count"],
            "omitted": coverage["omitted"] + unlocated,
            "limit": coverage["limit"],
            "byte_limit": coverage["byte_limit"],
            "rows": rows,
        },
    }


def _model_metadata(raw, limits):
    metadata, metrics = raw.get("metadata"), raw.get("metrics")
    if not isinstance(metadata, dict) or not isinstance(metrics, dict):
        raise ValueError("Missing model metadata")
    maximum, processors, java = (
        metadata.get(key) for key in ("max_heap_bytes", "active_processors", "java_version")
    )
    if not _integer(maximum) or not 0 < maximum <= limits["heap_gib"] * 1024**3:
        raise ValueError("Unqualified effective Java heap")
    if not _integer(processors) or not 0 < processors <= limits["active_processors"]:
        raise ValueError("Unqualified effective processor count")
    if not isinstance(java, str) or len(java) > 64 or not java.startswith("21."):
        raise ValueError("Unqualified effective Java version")
    safe_metadata = {
        "max_heap_bytes": maximum,
        "active_processors": processors,
        "java_version": java,
    }
    for key in ("languages", "overlays"):
        values = metadata.get(key, [])
        if (
            not isinstance(values, list)
            or len(values) > 32
            or any(not isinstance(item, str) or len(item) > 128 for item in values)
        ):
            raise ValueError("Invalid bounded model metadata")
        safe_metadata[key] = sorted(values)
    overlays = [name for name in safe_metadata["overlays"] if "dataflow" in name.lower()]
    if any(name != "dataflowOss" for name in overlays):
        raise ValueError("Unqualified dataflow overlay")
    requested = limits["dataflow"]["enabled"]
    actual = raw.get("dataflow")
    if not requested and (overlays or actual != "not_run"):
        raise ValueError("Dataflow was not requested")
    if requested and (actual == "not_run" or actual in {"complete", "partial"} and not overlays):
        raise ValueError("Missing requested dataflow analysis or overlay")
    safe_metrics = {}
    for key in ("nodes", "edges", "methods", "calls"):
        value = metrics.get(key)
        if not _integer(value) or value > 2**53:
            raise ValueError("Invalid model metric")
        safe_metrics[key] = value
    edge_counts = metrics.get("edge_counts", {})
    if not isinstance(edge_counts, dict):
        raise ValueError("Invalid edge counts")
    safe_metrics["edge_counts"] = {}
    for key in (
        "CFG",
        "REF",
        "CALL",
        "CDG",
        *(["REACHING_DEF"] if "REACHING_DEF" in edge_counts else []),
    ):
        value = edge_counts.get(key)
        if not _integer(value) or value > 2**53:
            raise ValueError("Invalid model edge count")
        safe_metrics["edge_counts"][key] = value
    return safe_metadata, safe_metrics


def analyze_joern(
    sources, *, snapshot=None, config=None, redact=None, analysis_profile="standard", deadline=None
):
    if config is not None and (not isinstance(config, dict) or config):
        raise ValueError("Joern accepts no caller scripts, arguments or project configuration")
    limits, operator_overrides = _joern_configuration(analysis_profile)
    began = _clock()
    if deadline is not None and (type(deadline) not in {int, float} or not math.isfinite(deadline)):
        raise ValueError("Analyzer deadline must be finite")
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_INPUT_RECORDS:
        raise ValueError("Analyzer sources must be bounded captured records")
    selected, seen = [], set()
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("text"), str):
            raise ValueError("Analyzer sources require captured text")
        path = _relative(source.get("path"))
        if path in seen:
            raise ValueError("Analyzer source paths must be unique")
        seen.add(path)
        if any(
            not isinstance(source.get(key), str) or not 1 <= len(source[key]) <= 256
            for key in ("digest", "evidence_id")
        ):
            raise ValueError("Analyzer sources require captured identities")
        language = _LANGUAGES.get(PurePosixPath(path).suffix.lower())
        if language:
            role = source.get("role")
            if role not in {"production", "test", "tooling", "generated", "unknown"}:
                role = source_role(path)["role"]
            selected.append({**source, "path": path, "language": language, "role": role})
    selected.sort(
        key=lambda row: (
            {"production": 0, "unknown": 1, "test": 2, "tooling": 3}.get(row["role"], 4),
            row["path"],
        )
    )
    source_by_path = {source["path"]: source for source in selected}
    identity = joern_info()
    result = {
        "schema_version": 1,
        "analyzer": identity,
        "available": identity["available"],
        "status": "unavailable",
        "configuration": {
            "analysis_profile": analysis_profile,
            "project_config_loaded": False,
            "dependency_fetch": False,
            "build": False,
            "dataflow": "requested" if analysis_profile == "deep" else "not_run",
            "javascript_type_maps": "not_run",
        },
        "provenance": {
            "operator_overrides": operator_overrides,
            "snapshot": {
                key: snapshot[key]
                for key in ("revision", "manifest_digest")
                if isinstance(snapshot, dict) and key in snapshot
            },
            "source_identity": "captured_snapshot",
        },
        "coverage": {
            "captured_source_files": len(sources),
            "eligible_files": len(selected),
            "unsupported_source_files": len(sources) - len(selected),
            "staged_files": 0,
            "modeled_files": 0,
            "input_bytes": 0,
            "batches": [],
        },
        "summary": {"methods": None, "calls": None, "candidate_count": 0, "dataflow": "not_run"},
        "dataflow_analysis": {"status": "not_run", "batches": [], "paths": []},
        "modules": [],
        "topology": {"complete": False, "edges": [], "methods": [], "calls": [], "caveat": _CAVEAT},
        "candidates": [],
        "candidate_index": [],
        "candidate_counts": {
            "total": 0,
            "retained": 0,
            "indexed": 0,
            "omitted_from_index": 0,
            "by_kind": {},
            "by_role": {},
        },
        "limits": limits,
        "gaps": [],
        "caveat": _CAVEAT,
    }
    unqualified = sum(source["language"] == "swift" for source in selected)
    result["coverage"]["unqualified_source_files"] = unqualified
    if selected and unqualified == len(selected):
        result.update(status="unsupported", gaps=[identity["unqualified_reason"]])
        result["coverage"]["omissions"] = {"unsupported_language": unqualified}
        return result
    if not identity["available"]:
        result["gaps"] = [identity.get("unavailable_reason", "Qualified Joern is unavailable")]
        if "containment" in identity and identity["containment"] is None:
            result["status"] = "unsupported"
        return result
    if not selected:
        result.update(
            status="unsupported",
            gaps=[
                "No qualified captured Python, JS/TS or Java source was supplied; Swift is unsupported"
            ],
        )
        return result
    if (
        not isinstance(snapshot, dict)
        or not isinstance(snapshot.get("root"), str)
        or not Path(snapshot["root"]).is_absolute()
    ):
        result.update(
            status="unsupported",
            gaps=["Original absolute snapshot root is required for containment"],
        )
        return result
    stop = (
        min(began + limits["seconds"], deadline)
        if deadline is not None
        else began + limits["seconds"]
    )
    omissions, gaps, all_candidates, all_methods, all_calls = Counter(), set(), [], [], []
    skipped = {}
    if len(sources) != len(selected):
        gaps.add(
            "Joern excludes unsupported captured source types; this is not whole-project semantic coverage"
        )
    if unqualified:
        gaps.add(identity["unqualified_reason"])
    modeled, batches, successful = set(), [], 0
    method_file_coverage = {}
    edges, inferred_edges = Counter(), Counter()
    flow_batches, flow_paths = [], []
    staged = {}
    clean = redact or (lambda value: value)
    operation, active_language = "setup", None
    try:
        home, java, paths, _, hashes = _tools()
        if hashes != identity.get("component_hashes"):
            raise ValueError("Tool identity changed")
        original = Path(snapshot["root"]).resolve()
        if home.is_relative_to(original) or java.is_relative_to(original):
            result.update(
                status="unsupported", gaps=["Operator tool homes must be outside the assessed root"]
            )
            return result
        if any(source["language"] == "javascript" for source in selected) and Path(
            sys.executable
        ).resolve().is_relative_to(original):
            result.update(
                status="unsupported",
                gaps=["Trusted AST transport runtime must be outside the assessed root"],
            )
            return result
        temporary = Path(tempfile.gettempdir()).resolve()
        if temporary.is_relative_to(original):
            result.update(
                status="unsupported",
                gaps=["Assessor temporary storage must be outside the assessed root"],
            )
            return result
        containment, binary = _sandbox()
        if containment is None:
            raise ValueError("Qualified containment is unavailable")
        result["provenance"].update(
            tool_home=str(home), java_home=str(java), containment=containment
        )
        with tempfile.TemporaryDirectory(prefix="pat-joern-", dir=temporary) as directory:
            workspace = Path(directory)
            env = _environment(paths, java, workspace, limits)
            query = workspace / "query.sc"
            query.write_bytes(paths["query"].read_bytes())
            operation = "source_staging"
            staged = {}
            for source in selected:
                if source["language"] not in _FRONTENDS:
                    omissions["unsupported_language"] += 1
                    continue
                raw = source["text"].encode("utf-8")
                reason = (
                    "deadline"
                    if _clock() >= stop
                    else "file_limit"
                    if len(staged) >= limits["files"]
                    else "file_byte_limit"
                    if len(raw) > limits["bytes_per_file"]
                    else "input_byte_limit"
                    if result["coverage"]["input_bytes"] + len(raw) > limits["bytes"]
                    else "source_digest_mismatch"
                    if "sha256:" + hashlib.sha256(raw).hexdigest() != source["digest"]
                    else _javascript_guard(raw)
                    if source["language"] == "javascript"
                    else None
                )
                if reason:
                    omissions[reason] += 1
                    skipped[source["path"]] = reason
                    continue
                stage = workspace / source["language"] / "source"
                path = stage / source["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(0o400)
                staged[source["path"]] = {**source, "lines": source["text"].splitlines()}
                result["coverage"]["input_bytes"] += len(raw)
            result["coverage"]["staged_files"] = len(staged)
            # Unused time only rolls forward, so the smallest batch runs first and the
            # largest can use whatever the others did not need.
            batch_sizes = Counter()
            for source in staged.values():
                batch_sizes[source["language"]] += len(source["text"])
            languages = sorted(
                (language for language in _FRONTENDS if batch_sizes[language]),
                key=lambda language: (batch_sizes[language], language),
            )
            for language_index, language in enumerate(languages):
                active_language = language
                batch = {
                    path: source
                    for path, source in staged.items()
                    if source["language"] == language
                }
                if not batch:
                    continue
                language_began = _clock()
                assigned_seconds = max(0, stop - language_began) / (len(languages) - language_index)
                language_stop = min(stop, language_began + assigned_seconds)
                if _clock() >= stop:
                    omissions["deadline"] += len(batch)
                    batches.append(
                        {"language": language, "staged_files": len(batch), "status": "timeout"}
                    )
                    continue
                stage = workspace / language / "source"
                cwd = stage.parent
                cpg, output = workspace / language / "cpg.bin", workspace / language / "result.json"
                run_token = uuid.uuid4().hex
                flags = [
                    f"-J-Xmx{limits['heap_gib']}g",
                    f"-J-XX:ActiveProcessorCount={limits['active_processors']}",
                    "-J-Duser.home=" + env["HOME"],
                    "-J-Djava.io.tmpdir=" + env["TMPDIR"],
                ]
                if limits.get("thread_stack_mib"):
                    flags.append(f"-J-Xss{limits['thread_stack_mib']}m")
                parser = [str(paths[language]), *flags, str(stage), "--output", str(cpg)]
                if language == "java":
                    parser.extend(["--delombok-mode", "no-delombok"])
                if language == "javascript":
                    env["ASTGEN_BIN"] = str(
                        _javascript_transport(workspace, stage, batch, paths, limits)
                    )
                    parser.append("--no-tsTypes")
                compatibility = None
                parse_began = time.perf_counter()
                operation = "parser_process"
                report_progress(f"joern: parsing {language}")
                status = _run(
                    _contained_command(parser, workspace, original, containment, binary, cwd),
                    workspace=workspace,
                    cwd=cwd,
                    env=env,
                    stop=language_stop,
                    limits=limits,
                )
                parse_seconds = time.perf_counter() - parse_began
                query_seconds = None
                query_attempts, endpoint_timeouts = 0, []
                query_work_seconds = max(1, min(86_400, int(language_stop - _clock() - 15)))
                if status == "complete" and language == "javascript":
                    try:
                        compatibility = _javascript_compatibility(workspace, stage, batch)
                        if any(
                            compatibility[field]
                            for field in (
                                "bounded_interfaces",
                                "unexpected_interfaces",
                                "unsupported_numeric_keys",
                            )
                        ):
                            gaps.add(
                                "Pinned JavaScript AST compatibility was bounded or unsupported; inspect the source-bound receipt and model coverage"
                            )
                    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                        status = "unvalidated_ast_compatibility"
                if status == "complete":
                    command = [
                        str(paths["repl"]),
                        *flags,
                        "--script",
                        str(query),
                        "--param",
                        "cpgFile=" + str(cpg),
                        "--param",
                        "out=" + str(output),
                        "--param",
                        "profile=" + analysis_profile,
                        "--param",
                        "runToken=" + run_token,
                        "--param",
                        "flowSeconds=" + str(query_work_seconds),
                    ]
                    query_began = time.perf_counter()
                    query_attempts, endpoint_timeouts = 0, []
                    query_model_pruned = False
                    overlay_digest = None
                    while True:
                        operation = "query_process"
                        attempt_token = uuid.uuid4().hex
                        attempt_command = [*command, "--param", "attemptToken=" + attempt_token]
                        if query_attempts:
                            attempt_command[
                                attempt_command.index("flowSeconds=" + str(query_work_seconds))
                            ] = "flowSeconds=" + str(
                                max(1, min(86_400, int(language_stop - _clock() - 15)))
                            )
                            attempt_command[attempt_command.index("cpgFile=" + str(cpg))] = (
                                "cpgFile=" + str(output) + ".overlay.bin"
                            )
                            attempt_command += [
                                "--param",
                                "resumeFile=" + str(output) + ".resume.json",
                            ]
                            # Reuse the validated graph, never the SDK's mutable prior workspace.
                            shutil.rmtree(cwd / "workspace", ignore_errors=True)
                        query_attempts += 1
                        report_progress(
                            f"joern: querying {language} (attempt {query_attempts}, "
                            f"{len(endpoint_timeouts)} endpoint timeouts)"
                        )
                        status = _run(
                            _contained_command(
                                attempt_command, workspace, original, containment, binary, cwd
                            ),
                            workspace=workspace,
                            cwd=cwd,
                            env=env,
                            stop=language_stop,
                            limits=limits,
                            output=output,
                            **(
                                {
                                    "flow_watch": {
                                        "run_token": run_token,
                                        "attempt_token": attempt_token,
                                        "seconds": limits["endpoint_seconds"],
                                    }
                                }
                                if analysis_profile == "deep"
                                else {}
                            ),
                        )
                        query_model_pruned = query_model_pruned or getattr(
                            status, "model_pruned", False
                        )
                        if status != "endpoint_timeout":
                            break
                        operation = "resume_checkpoint"
                        try:
                            base_path = output.with_name(output.name + ".base.json")
                            overlay_path = output.with_name(output.name + ".overlay.bin")
                            digest = _checkpoint_digest(overlay_path, limits["workspace_bytes"])
                            if overlay_digest is not None and overlay_digest != digest:
                                raise ValueError("Immutable overlay changed")
                            overlay_digest = digest
                            base_hash = _checkpoint_digest(base_path, limits["query_json_bytes"])
                            base = _read_result(base_path, limits["query_json_bytes"])
                            recovered, _ = _recover_flow_checkpoint(
                                output.with_name(output.name + ".flow.json"),
                                base,
                                base_hash,
                                run_token,
                                limits,
                                stage,
                                batch,
                                clean,
                            )
                            endpoint_id = status.endpoint_id
                            plan = recovered["selection"]
                            if (
                                endpoint_id not in {row["id"] for row in plan["endpoints"]}
                                or endpoint_id in plan.get("completed_endpoint_ids", [])
                                or endpoint_id in endpoint_timeouts
                            ):
                                raise ValueError("Timed-out endpoint is not pending in this plan")
                            endpoint_timeouts.append(endpoint_id)
                            if (
                                query_attempts > limits["max_query_restarts"]
                                or _clock() >= language_stop
                            ):
                                break
                            resume = {
                                "query_version": QUERY_VERSION,
                                "run_token": run_token,
                                "base_sha256": base_hash,
                                "overlay_sha256": overlay_digest,
                                "plan_digest": plan["plan_digest"],
                                "timed_out_endpoint_ids": endpoint_timeouts,
                            }
                            output.with_name(output.name + ".resume.json").write_text(
                                json.dumps(resume)
                            )
                            # Preserve the original parser source path; the cached graph is read-only.
                            overlay_path.chmod(0o400)
                        except (
                            OSError,
                            ValueError,
                            TypeError,
                            KeyError,
                            UnicodeError,
                            RecursionError,
                        ):
                            status = "invalid_resume_checkpoint"
                            break
                    query_seconds = time.perf_counter() - query_began
                    if query_attempts > 1 and status == "complete":
                        try:
                            resumed = _read_result(output, limits["query_json_bytes"])
                            if any(
                                row.get("section") == "load_or_overlays"
                                for row in resumed.get("errors", [])
                            ):
                                status = "resume_load_error"
                        except (
                            OSError,
                            ValueError,
                            TypeError,
                            KeyError,
                            UnicodeError,
                            RecursionError,
                        ):
                            status = "invalid_resume_output"
                    status = _ProcessStatus(
                        getattr(status, "terminal_status", str(status)),
                        engine_failed=getattr(status, "engine_failed", False),
                        model_pruned=query_model_pruned,
                        endpoint_id=getattr(status, "endpoint_id", None),
                    )
                process_status = status
                operation = "model_normalization"
                report_progress(f"joern: normalizing {language}")
                producer_diagnostics = {
                    "terminal_status": getattr(status, "terminal_status", str(status)),
                    "engine_failed": getattr(
                        status, "engine_failed", status == "analysis_engine_error"
                    ),
                    "model_pruned": getattr(status, "model_pruned", False),
                }
                phase_progress = _phase_progress(
                    output.with_name(output.name + ".phases.json"), analysis_profile
                )
                model_status, modeled_count = "unknown", 0
                counts, metadata, metrics = {}, {}, {}
                detail_status = "unknown"
                validated = checkpoint_recovered = False
                flow_checkpoint_recovered = False
                flow_checkpoint_status = "unavailable"
                flow_progress = {"status": "unavailable"}
                base_output = output.with_name(output.name + ".base.json")
                if (
                    status == "complete"
                    or analysis_profile == "deep"
                    and (output.is_file() or base_output.is_file())
                ):
                    try:
                        for path, source in batch.items():
                            staged_path = stage / path
                            if (
                                staged_path.is_symlink()
                                or _hash_file(staged_path) != source["digest"]
                            ):
                                raise ValueError("Staged source identity changed")
                        recovered_output = (
                            base_output
                            if process_status != "complete" and base_output.is_file()
                            else output
                        )
                        raw = _read_result(recovered_output, limits["query_json_bytes"])
                        if raw.get("run_token") != run_token:
                            raise ValueError("Query output belongs to another invocation")
                        if process_status != "complete":
                            checkpoint_recovered = (
                                raw.get("checkpoint") == "base_before_dataflow"
                                and raw.get("dataflow") == "error"
                            )
                            if process_status == "analysis_engine_error":
                                raw["dataflow"] = "error"
                                raw["dataflow_analysis"] = {"status": "error"}
                            elif not checkpoint_recovered:
                                raise ValueError(
                                    "Incomplete process has no qualified base checkpoint"
                                )
                        metadata, metrics = _model_metadata(raw, limits)
                        flow, flow_gaps = normalize_dataflow(
                            raw, stage=stage, sources=batch, clean=clean
                        )
                        base_sha256 = None
                        if analysis_profile == "deep" and base_output.is_file():
                            try:
                                base_sha256 = _checkpoint_digest(
                                    base_output, limits["query_json_bytes"]
                                )
                            except (OSError, ValueError):
                                flow_checkpoint_status = "invalid"
                                flow_progress = {"status": "invalid"}
                                flow_gaps.add("Optional checkpoint base could not be qualified")
                        if base_sha256 is not None:
                            flow_output = output.with_name(output.name + ".flow.json")
                            if producer_diagnostics["engine_failed"]:
                                flow_checkpoint_status = "vetoed_worker_failure"
                            elif producer_diagnostics["terminal_status"] == "log_limit":
                                flow_checkpoint_status = "vetoed_incomplete_diagnostics"
                                flow_gaps.add(
                                    "Flow recovery withheld after the diagnostic log limit"
                                )
                            elif flow_output.exists() and flow["status"] == "error":
                                try:
                                    flow_base = (
                                        raw
                                        if recovered_output == base_output
                                        else _read_result(base_output, limits["query_json_bytes"])
                                    )
                                    if flow_base.get("checkpoint") != "base_before_dataflow":
                                        raise ValueError("Missing immutable flow base")
                                    flow, recovered_gaps = _recover_flow_checkpoint(
                                        flow_output,
                                        flow_base,
                                        base_sha256,
                                        run_token,
                                        limits,
                                        stage,
                                        batch,
                                        clean,
                                    )
                                    flow_gaps = recovered_gaps
                                    flow_checkpoint_recovered = True
                                    flow_checkpoint_status = "usable"
                                except (
                                    OSError,
                                    ValueError,
                                    TypeError,
                                    KeyError,
                                    UnicodeError,
                                    RecursionError,
                                ):
                                    flow_checkpoint_status = "invalid"
                                    flow_gaps.add(
                                        "Flow checkpoint could not be qualified; base evidence remains available"
                                    )
                            elif flow_output.exists():
                                flow_checkpoint_status = "not_needed"
                            flow_progress = _flow_progress(
                                output.with_name(output.name + ".flow-progress.json"),
                                run_token,
                                base_sha256,
                                flow,
                            )
                        if (
                            process_status == "endpoint_timeout"
                            and flow_progress.get("status") == "valid"
                            and flow_progress.get("current_endpoint_id") in endpoint_timeouts
                            and flow.get("selection")
                        ):
                            timed_out = set(flow["selection"].get("timed_out_endpoint_ids", []))
                            timed_out.update(endpoint_timeouts)
                            pending = {
                                row["id"]
                                for row in flow["selection"]["endpoints"]
                                if row["status"] != "completed"
                            }
                            if not timed_out <= pending:
                                raise ValueError(
                                    "Killed endpoint conflicts with completed evidence"
                                )
                            for row in flow["selection"]["endpoints"]:
                                if row["id"] in timed_out:
                                    row["status"] = "timed_out"
                            flow["selection"]["timed_out_endpoint_ids"] = sorted(timed_out)
                            flow["queries"]["sinks_timed_out"] = len(timed_out)
                            flow["status"] = flow["paths"]["status"] = "partial"
                            flow["paths"]["count_is_lower_bound"] = True
                            flow_gaps.add(
                                "Assessor killed individually bounded endpoint workers; timed-out endpoints remain unknown"
                            )
                        if producer_diagnostics["model_pruned"] and flow["status"] in {
                            "complete",
                            "partial",
                        }:
                            flow["status"] = flow["paths"]["status"] = "partial"
                            flow["paths"]["count_is_lower_bound"] = True
                            flow["model_pruned"] = True
                            flow_gaps.add(
                                "Joern pruned bounded argument expansion; retained witnesses do not establish complete reachability"
                            )
                        (
                            methods,
                            calls,
                            candidates,
                            files,
                            dropped,
                            model_gaps,
                            module_edges,
                            inferred_module_edges,
                            binding_checks,
                        ) = _normalize(
                            raw,
                            stage,
                            batch,
                            workspace,
                            clean,
                            _clock() + 30,
                        )
                        model_gaps.update(flow_gaps)
                        method_sampling = _method_sampling_metadata(
                            raw.get("methods"), stage, batch, analysis_profile
                        )
                        if method_sampling["file_coverage"]["status"] != "complete":
                            model_gaps.add(
                                "Joern per-file method coverage metadata is bounded or unlocated; absent file counts remain unknown"
                            )
                        counts = {
                            section: {
                                key: raw.get(section, {}).get(key)
                                for key in ("status", "count", "omitted")
                            }
                            for section in (
                                "methods",
                                "calls",
                                "unread_bindings",
                                "source_files",
                                "module_edges",
                                "inferred_module_edges",
                            )
                        }
                        counts["methods"].update(method_sampling)
                        detail_status = (
                            "partial"
                            if dropped
                            or any(
                                value.get("status") != "complete"
                                or value.get("omitted")
                                or value.get("byte_omissions")
                                for value in counts.values()
                            )
                            else "complete"
                        )
                        for section, fields in (
                            ("methods", ("external_models", "unlocated_models")),
                            ("module_edges", ("occurrences", "omitted_occurrences")),
                            ("inferred_module_edges", ("occurrences", "omitted_occurrences")),
                        ):
                            value = raw.get(section, {})
                            for field in fields:
                                if field in value:
                                    if not _integer(value[field]):
                                        raise ValueError("Invalid model section count")
                                    counts[section][field] = value[field]
                            if "count_is_lower_bound" in value:
                                if type(value["count_is_lower_bound"]) is not bool:
                                    raise ValueError("Invalid model section bound")
                                counts[section]["count_is_lower_bound"] = value[
                                    "count_is_lower_bound"
                                ]
                        classifications = raw.get("calls", {}).get("classifications")
                        if classifications is not None:
                            if not isinstance(classifications, dict) or any(
                                key
                                not in {
                                    "source_supported",
                                    "producer_inferred",
                                    "unresolved",
                                    "rejected",
                                }
                                or not _integer(value)
                                for key, value in classifications.items()
                            ):
                                raise ValueError("Invalid call classification counts")
                            counts["calls"]["classifications"] = classifications
                        counts["unread_bindings"]["source_countercheck"] = {
                            "counts": binding_checks,
                            "max_bytes_per_file": BINDING_BYTES,
                            "max_nodes_per_file": BINDING_NODES,
                            "basis": "Captured Python AST or installed JavaScript/TypeScript syntax with lexical binding scopes; source contradictions and unknown contracts suppress cleanup leads",
                            "change_safety": "unverified",
                        }
                        unread = raw.get("unread_bindings", {})
                        if "suppressed" in unread:
                            suppressed = unread["suppressed"]
                            if (
                                not isinstance(suppressed, dict)
                                or len(suppressed) > 64
                                or any(
                                    not isinstance(reason, str)
                                    or re.fullmatch(r"[a-z_]{1,100}", reason) is None
                                    or not _integer(count)
                                    for reason, count in suppressed.items()
                                )
                            ):
                                raise ValueError("Invalid model suppression counts")
                            counts["unread_bindings"]["suppressed"] = suppressed
                        if "captured_declarations" in unread:
                            if not _integer(unread["captured_declarations"]):
                                raise ValueError("Invalid captured declaration count")
                            counts["unread_bindings"]["captured_declarations"] = unread[
                                "captured_declarations"
                            ]
                        method_file_coverage.update(
                            (row["path"], row["count"])
                            for row in method_sampling["file_coverage"]["rows"]
                        )
                        all_methods.extend(methods)
                        all_calls.extend(calls)
                        all_candidates.extend(candidates)
                        modeled.update(files)
                        modeled_count = len(files)
                        model_status = "partial" if dropped or model_gaps else "complete"
                        omissions.update(dropped)
                        gaps.update(model_gaps)
                        edges.update(module_edges)
                        inferred_edges.update(inferred_module_edges)
                        successful += bool(files)
                        flow_batches.append({"language": language, **flow})
                        flow_paths.extend(flow["paths"]["rows"])
                        validated = True
                    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                        status = "unvalidated_output_or_source"
                if status != "complete":
                    gaps.add(
                        f"Joern {language} analysis did not complete: {status}; missing results remain unknown"
                    )
                operation = "batch_summary"
                batches.append(
                    {
                        "language": language,
                        "staged_files": len(batch),
                        "status": model_status if validated else status,
                        "process_status": process_status,
                        "base_checkpoint_recovered": checkpoint_recovered and validated,
                        "dataflow_worker_failed": process_status == "analysis_engine_error",
                        "query_attempts": query_attempts,
                        "endpoint_timeouts": len(endpoint_timeouts),
                        "overlay_reused": query_attempts > 1
                        and any(
                            event["phase"] == "dataflow_queries_started"
                            for event in phase_progress.get("events", [])
                        ),
                        "producer_diagnostics": producer_diagnostics,
                        "flow_checkpoint_recovered": flow_checkpoint_recovered,
                        "flow_checkpoint_status": flow_checkpoint_status,
                        "flow_progress": flow_progress,
                        "model_metrics_scope": "base_before_dataflow"
                        if checkpoint_recovered
                        else "query_final",
                        "time_budget": {
                            "policy": "smallest_first_equal_remaining_time_v2",
                            "assigned_seconds": round(assigned_seconds, 3),
                            "remaining_languages": len(languages) - language_index - 1,
                            "query_body_allowance_seconds": query_work_seconds,
                            "normalization_guard_seconds": 30,
                        },
                        "detail_status": detail_status if validated else "unknown",
                        "modeled_files": modeled_count,
                        "model_sections": counts,
                        "model_metadata": metadata,
                        "model_metrics": metrics,
                        "ast_compatibility": compatibility,
                        "timing": {
                            "parser_seconds": round(parse_seconds, 3),
                            "query_process_seconds": round(query_seconds, 3)
                            if query_seconds is not None
                            else None,
                        },
                        "phase_progress": phase_progress,
                    }
                )
                shutil.rmtree(cwd)
            operation, active_language = "module_summary", None
            if unqualified:
                batches.append(
                    {
                        "language": "swift",
                        "status": "unsupported",
                        "process_status": "not_run",
                        "staged_files": 0,
                        "modeled_files": 0,
                        "eligible_files": unqualified,
                    }
                )
            retained_method_rows = Counter(row["path"] for row in all_methods)
            result["modules"] = [
                {
                    "path": source["path"],
                    "source_evidence_id": source["evidence_id"],
                    "digest": source["digest"],
                    "role": source["role"],
                    "language": source["language"],
                    "staged": source["path"] in staged,
                    "modeled": source["path"] in modeled,
                    "method_rows_retained": retained_method_rows[source["path"]]
                    if source["path"] in method_file_coverage
                    else None,
                    "method_model_count": method_file_coverage.get(source["path"]),
                }
                | (
                    {"skip_reason": skipped[source["path"]]}
                    if source["path"] in skipped
                    else {"skip_reason": "unsupported_language"}
                    if source["language"] not in _FRONTENDS
                    else {}
                )
                for source in sorted(selected, key=lambda row: row["path"])
            ]
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        RecursionError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        result["provenance"]["failure"] = {
            "operation": operation,
            "language": active_language,
            "exception_type": type(error).__name__,
        }
        worker_operation = getattr(error, "_pat_joern_worker_operation", None)
        if worker_operation in {"process_start", "process_monitor", "process_reap"}:
            result["provenance"]["failure"]["worker_operation"] = worker_operation
        gaps.add(
            "Joern setup or output could not be validated safely; raw diagnostics are not retained"
        )
    if omissions:
        gaps.add(
            "Joern source or model rows were omitted; inspect coverage and do not infer absence"
        )
    if len(all_candidates) > MAX_CANDIDATES:
        gaps.add("Joern rich candidate sample is bounded; inspect the compact index")
    all_candidates = list({row["id"]: row for row in all_candidates}.values())
    result["topology"].update(
        method_sampling_caveat="Per-file counts describe bounded source-located method models, not source functions or proof of absence. Missing file metadata remains unknown.",
        methods=sorted(all_methods, key=lambda row: (row["path"], row["line"], row["full_name"])),
        calls=sorted(
            all_calls, key=lambda row: (row["path"], row["line"], row["target_full_name"])
        ),
        edges=[
            {
                "source": source,
                "target": target,
                "source_evidence_id": source_by_path[source]["evidence_id"],
                "source_digest": source_by_path[source]["digest"],
                "target_source_evidence_id": source_by_path[target]["evidence_id"],
                "target_digest": source_by_path[target]["digest"],
                "kind": "source_supported_method_call",
                "count": count,
            }
            for (source, target), count in sorted(edges.items())
        ],
        inferred_edges=[
            {
                "source": source,
                "target": target,
                "source_evidence_id": source_by_path[source]["evidence_id"],
                "source_digest": source_by_path[source]["digest"],
                "target_source_evidence_id": source_by_path[target]["evidence_id"],
                "target_digest": source_by_path[target]["digest"],
                "kind": "producer_inferred_method_call",
                "count": count,
                "confidence": "low",
            }
            for (source, target), count in sorted(inferred_edges.items())
        ],
    )
    result["candidates"] = _retained_candidates(all_candidates, MAX_CANDIDATES)
    result["candidate_index"] = _retained_candidates(all_candidates, MAX_INDEX)
    result["candidate_counts"] = {
        "total": len(all_candidates),
        "retained": len(result["candidates"]),
        "indexed": len(result["candidate_index"]),
        "omitted_from_index": max(0, len(all_candidates) - MAX_INDEX),
        "by_kind": dict(Counter(row["kind"] for row in all_candidates)),
        "by_role": dict(sorted(Counter(row["role"] for row in all_candidates).items())),
    }
    result["coverage"].update(
        modeled_files=len(modeled), batches=batches, omissions=dict(sorted(omissions.items()))
    )
    expected_batches = {source["language"] for source in staged.values()}
    ran_batches = {batch["language"] for batch in flow_batches}
    flow_status = (
        "not_run"
        if analysis_profile != "deep"
        else "complete"
        if expected_batches
        and ran_batches == expected_batches
        and all(batch["status"] == "complete" for batch in flow_batches)
        else "error"
        if not flow_batches or all(batch["status"] == "error" for batch in flow_batches)
        else "partial"
    )
    result["dataflow_analysis"] = {
        "status": flow_status,
        "batches": flow_batches,
        "paths": sorted({row["id"]: row for row in flow_paths}.values(), key=lambda row: row["id"]),
        "caveat": "Modeled value paths with default semantics; missing paths are unknown, not proof of disuse, isolation, authorization or runtime safety.",
    }
    result["coverage"]["phases"] = {
        "input": {
            "eligible": len(selected),
            "staged": len(staged),
            "omitted": len(selected) - len(staged),
        },
        "model": {
            "staged": len(staged),
            "modeled": len(modeled),
            "omitted": len(set(staged) - modeled),
        },
        "detail": {
            "status": "complete"
            if successful and all(batch.get("detail_status") == "complete" for batch in batches)
            else "partial",
            "retained_methods": len(all_methods),
            "retained_calls": len(all_calls),
        },
        "dataflow": {
            "status": flow_status,
            "retained_paths": len(result["dataflow_analysis"]["paths"]),
            **{
                key: sum(batch[field] for batch in flow_batches)
                if flow_batches and all(type(batch.get(field)) is int for batch in flow_batches)
                else None
                for key, field in (
                    ("methods_analyzed", "methods_analyzed"),
                    ("methods_skipped", "methods_skipped"),
                )
            },
            **{
                key: sum(batch["queries"][key] for batch in flow_batches)
                if flow_batches
                and all(type(batch.get("queries", {}).get(key)) is int for batch in flow_batches)
                else None
                for key in (
                    "sinks_total",
                    "sinks_eligible",
                    "sinks_selected",
                    "sinks_not_selected",
                    "sinks_pending",
                    "sinks_skipped",
                    "sinks_queried",
                    "engine_queries",
                    "sinks_proven_empty",
                    "sinks_timed_out",
                    "paths_truncated",
                )
            },
            "paths_omitted": sum(batch["paths"]["omitted"] for batch in flow_batches)
            if flow_batches
            and all(type(batch["paths"].get("omitted")) is int for batch in flow_batches)
            else None,
        },
    }
    result["summary"].update(
        methods=len(all_methods) if successful else None,
        calls=len(all_calls) if successful else None,
        candidate_count=len(all_candidates),
        dataflow=flow_status,
        value_paths=len(result["dataflow_analysis"]["paths"]),
        counts_are_lower_bounds=bool(gaps or omissions),
        count_basis="retained validated source-located rows; producer section totals are in coverage.batches",
    )
    result["status"] = "complete" if successful and not gaps and not omissions else "partial"
    result["gaps"] = sorted(gaps)
    return result
