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
from collections import Counter
from pathlib import Path, PurePosixPath

from .joern_bindings import MAX_BYTES as BINDING_BYTES
from .joern_bindings import MAX_NODES as BINDING_NODES
from .joern_bindings import BindingCountercheck
from .static_analysis import _retained_candidates, source_role

VERSION = "5"
QUERY_VERSION = "3"
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
        "seconds": 1800,
        "files": 4000,
        "bytes": 128 * 1024**2,
        "bytes_per_file": 8 * 1024**2,
        "heap_gib": 8,
    },
}
_CAVEAT = (
    "Joern models captured source, not runtime behavior or complete resolution. "
    "No modeled read is a review lead, not permission to remove a binding, initializer "
    "or required callback, override or public parameter. No dataflow overlay, constant-guard "
    "reachability or zero-caller deletion analysis was run."
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
    if not isinstance(analysis_profile, str) or analysis_profile not in _PROFILES:
        raise ValueError("Unknown analysis profile")
    return {
        **_PROFILES[analysis_profile],
        "active_processors": 2,
        "workspace_bytes": 8 * 1024**3,
        "query_json_bytes": 32 * 1024**2,
        "log_bytes": 8 * 1024**2,
        "candidates": MAX_CANDIDATES,
        "candidate_index": MAX_INDEX,
        "input_records": MAX_INPUT_RECORDS,
        "javascript_frontend": {
            "bytes_per_file": 5 * 1024**2,
            "lines_per_file": 50_000,
            "bytes_per_line": 10_000,
            "emscripten": "unsupported",
            "interface_node_bytes": 2 * 1024**2,
        },
        "deadline_mode": "dedicated hard subprocess deadline; bounded normalization",
    }


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
    for name in ("joern-cli", "semanticcpg", "x2cpg"):
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
        "dataflow": "not_run",
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
    return {
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "JAVA_HOME": str(java),
        "PATH": str(java / "bin") + ":/usr/bin:/bin",
        "JAVA_OPTS": f"-Xmx{limits['heap_gib']}g -XX:ActiveProcessorCount={limits['active_processors']}",
        "_JAVA_OPTIONS": (
            f"-Xmx{limits['heap_gib']}g -XX:ActiveProcessorCount={limits['active_processors']} "
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


def _stop_group(process):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
    process.wait(timeout=2)


def _run(argv, *, workspace, cwd, env, stop, limits, output=None):
    """Discard bounded logs and always reap the whole process group, including orphans."""
    status, logged, next_disk = "complete", 0, 0.0
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
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                selector.register(stream, selectors.EVENT_READ)
            while process.poll() is None:
                now = _clock()
                if now >= stop:
                    status = "timeout"
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
                    if not data:
                        selector.unregister(key.fileobj)
                    logged += len(data)
                    if logged > limits["log_bytes"]:
                        status = "log_limit"
                        break
                if status != "complete":
                    break
            code = process.poll()
            for key, _ in selector.select(timeout=0):
                logged += len(os.read(key.fd, 65536))
            if logged > limits["log_bytes"]:
                status = "log_limit"
            if status == "complete" and code != 0:
                status = "tool_failed"
    finally:
        _stop_group(process)
        process.stdout.close()
        process.stderr.close()
    if status == "complete" and (
        _workspace_size(workspace) > limits["workspace_bytes"]
        or output
        and output.exists()
        and output.lstat().st_size > limits["query_json_bytes"]
    ):
        status = "output_limit"
    return status


def _read_result(path, maximum):
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

    result = json.loads(payload, parse_constant=nonfinite, object_pairs_hook=pairs)
    if (
        not isinstance(result, dict)
        or type(result.get("schema_version")) is not int
        or result.get("schema_version") != 1
        or result.get("query_version") != QUERY_VERSION
    ):
        raise ValueError("Unsupported query output")
    if result.get("dataflow") != "not_run":
        raise ValueError("Unqualified dataflow analysis")
    return result


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
        or len(files["rows"]) > 4000
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
            or len(value["rows"]) > 50_000
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


def _method_sampling_metadata(value, stage, sources):
    """Keep bounded per-file model coverage distinct from retained normalized rows."""
    fields = ("source_files", "retained_files", "omitted_files", "row_byte_limit", "byte_omissions")
    if (
        not isinstance(value, dict)
        or value.get("sampling") != "max_min_per_file_then_round_robin"
        or any(not _integer(value.get(field)) for field in (*fields, "count", "omitted"))
        or value["source_files"] > len(sources)
        or value["retained_files"] + value["omitted_files"] != value["source_files"]
        or value["row_byte_limit"] != 6 * 1024**2 - 256 * 1024 - 4096
        or value["byte_omissions"] > 20_000
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
        or coverage["byte_limit"] != 256 * 1024
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
    if any("dataflow" in name.lower() for name in safe_metadata["overlays"]):
        raise ValueError("Unqualified dataflow overlay")
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
    for key in ("CFG", "REF", "CALL", "CDG"):
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
    limits = joern_limits(analysis_profile)
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
            "dataflow": "not_run",
            "javascript_type_maps": "not_run",
        },
        "provenance": {
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
    clean = redact or (lambda value: value)
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
            for language in _FRONTENDS:
                batch = {
                    path: source
                    for path, source in staged.items()
                    if source["language"] == language
                }
                if not batch:
                    continue
                if _clock() >= stop:
                    omissions["deadline"] += len(batch)
                    batches.append(
                        {"language": language, "staged_files": len(batch), "status": "timeout"}
                    )
                    continue
                stage = workspace / language / "source"
                cwd = stage.parent
                cpg, output = workspace / language / "cpg.bin", workspace / language / "result.json"
                flags = [
                    f"-J-Xmx{limits['heap_gib']}g",
                    f"-J-XX:ActiveProcessorCount={limits['active_processors']}",
                    "-J-Duser.home=" + env["HOME"],
                    "-J-Djava.io.tmpdir=" + env["TMPDIR"],
                ]
                parser = [str(paths[language]), *flags, str(stage), "--output", str(cpg)]
                if language == "java":
                    parser.extend(["--delombok-mode", "no-delombok"])
                if language == "javascript":
                    env["ASTGEN_BIN"] = str(
                        _javascript_transport(workspace, stage, batch, paths, limits)
                    )
                    parser.append("--no-tsTypes")
                compatibility = None
                status = _run(
                    _contained_command(parser, workspace, original, containment, binary, cwd),
                    workspace=workspace,
                    cwd=cwd,
                    env=env,
                    stop=stop,
                    limits=limits,
                )
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
                    ]
                    status = _run(
                        _contained_command(command, workspace, original, containment, binary, cwd),
                        workspace=workspace,
                        cwd=cwd,
                        env=env,
                        stop=stop,
                        limits=limits,
                        output=output,
                    )
                process_status = status
                model_status, modeled_count = "unknown", 0
                counts, metadata, metrics = {}, {}, {}
                if status == "complete":
                    try:
                        for path, source in batch.items():
                            staged_path = stage / path
                            if (
                                staged_path.is_symlink()
                                or _hash_file(staged_path) != source["digest"]
                            ):
                                raise ValueError("Staged source identity changed")
                        raw = _read_result(output, limits["query_json_bytes"])
                        metadata, metrics = _model_metadata(raw, limits)
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
                        ) = _normalize(raw, stage, batch, workspace, clean, stop)
                        method_sampling = _method_sampling_metadata(
                            raw.get("methods"), stage, batch
                        )
                        if method_sampling["file_coverage"]["status"] != "complete":
                            model_gaps.add(
                                "Joern per-file method coverage metadata is bounded or unlocated; absent file counts remain unknown"
                            )
                        counts = {
                            section: {
                                key: raw.get(section, {}).get(key) for key in ("count", "omitted")
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
                    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                        status = "unvalidated_output_or_source"
                if status != "complete":
                    gaps.add(
                        f"Joern {language} analysis did not complete: {status}; missing results remain unknown"
                    )
                batches.append(
                    {
                        "language": language,
                        "staged_files": len(batch),
                        "status": model_status if status == "complete" else status,
                        "process_status": process_status,
                        "modeled_files": modeled_count,
                        "model_sections": counts,
                        "model_metadata": metadata,
                        "model_metrics": metrics,
                        "ast_compatibility": compatibility,
                    }
                )
                shutil.rmtree(cwd)
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
    ):
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
    result["summary"].update(
        methods=len(all_methods) if successful else None,
        calls=len(all_calls) if successful else None,
        candidate_count=len(all_candidates),
        counts_are_lower_bounds=bool(gaps or omissions),
        count_basis="retained validated source-located rows; producer section totals are in coverage.batches",
    )
    result["status"] = "complete" if successful and not gaps and not omissions else "partial"
    result["gaps"] = sorted(gaps)
    return result
