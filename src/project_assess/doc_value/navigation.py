#!/usr/bin/env python3
"""Read-only, receipt-backed document search/read for navigation experiments."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

MAX_BYTES = 1_000_000
MAX_GIT_OUTPUT_BYTES = 4_000_000
TEXT = {
    ".md",
    ".rst",
    ".txt",
    ".py",
    ".sh",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".js",
    ".mjs",
    ".ts",
}
SKIP = {".git", ".venv", "node_modules", "__pycache__", "var", "dist", ".cache"}


def git(root: Path, *arguments: str) -> bytes:
    from ..collector import _git_configuration

    prefix, environment = _git_configuration(root)
    process = subprocess.run(
        [*prefix, *arguments],
        capture_output=True,
        check=False,
        env=environment,
        timeout=5,
    )
    if process.returncode:
        raise subprocess.CalledProcessError(
            process.returncode, [*prefix, *arguments], process.stdout
        )
    if len(process.stdout) > MAX_GIT_OUTPUT_BYTES:
        raise ValueError("Git metadata exceeds the bounded output limit")
    return process.stdout


def relative(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("paths must be relative and confined to --root")
    return path.as_posix()


def candidates(root: Path, revision: str | None, scopes: list[str]) -> list[str]:
    if revision:
        names = git(root, "ls-tree", "-r", "--name-only", revision).decode().splitlines()
    else:
        names = []
        for folder, subdirs, files in os.walk(root, followlinks=False):
            subdirs[:] = [name for name in subdirs if name not in SKIP]
            names.extend(str((Path(folder) / name).relative_to(root)) for name in files)
    return sorted(
        n
        for n in names
        if not any(p in SKIP for p in Path(n).parts)
        and (Path(n).suffix in TEXT or Path(n).name in {"AGENTS.md", "README", "Makefile"})
        and (not scopes or any(n == s or n.startswith(s.rstrip("/") + "/") for s in scopes))
    )


def payload(root: Path, revision: str | None, name: str) -> tuple[str, str]:
    name = relative(name)
    if revision:
        obj = git(root, "rev-parse", f"{revision}:{name}").decode().strip()
        size = int(git(root, "cat-file", "-s", obj))
        if size > MAX_BYTES:
            raise ValueError("file exceeds the bounded text-read limit")
        data = git(root, "cat-file", "blob", obj)
    else:
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise ValueError("file unavailable, outside root, or above the text-read limit")
        data = path.read_bytes()
    return data.decode("utf-8"), hashlib.sha256(data).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", help="fixed Git revision; omit for a non-Git/working tree")
    parser.add_argument(
        "--receipt", type=Path, required=True, help="one private JSONL per trial, outside root"
    )
    parser.add_argument("--scope", action="append", default=[])
    sub = parser.add_subparsers(dest="operation", required=True)
    search = sub.add_parser("search")
    search.add_argument("pattern", help="case-insensitive regular expression")
    search.add_argument("--limit", type=int, default=12)
    read = sub.add_parser("read")
    read.add_argument("path")
    read.add_argument("--start", type=int, default=1)
    read.add_argument("--lines", type=int, default=60)
    args = parser.parse_args(argv)
    root, receipt = args.root.expanduser().resolve(), args.receipt.expanduser().resolve()
    if receipt.is_relative_to(root):
        parser.error("--receipt must resolve outside --root")
    if not root.is_dir():
        parser.error("--root must be a directory")
    sources: dict[str, str] = {}
    unavailable: list[str] = []
    try:
        revision = (
            git(root, "rev-parse", "--verify", args.revision + "^{commit}").decode().strip()
            if args.revision
            else None
        )
        scopes = [relative(s) for s in args.scope]
        if args.operation == "read":
            if not 1 <= args.lines <= 200 or args.start < 1:
                raise ValueError("read needs --start >= 1 and 1..200 --lines")
            name = relative(args.path)
            if scopes and not any(
                name == s or name.startswith(s.rstrip("/") + "/") for s in scopes
            ):
                raise ValueError("read path is outside the declared --scope")
            text, digest = payload(root, revision, name)
            sources[name] = digest
            output = "\n".join(
                f"{name}:{i + 1}: {line}"
                for i, line in enumerate(text.splitlines())
                if args.start <= i + 1 < args.start + args.lines
            )
        else:
            if not 1 <= args.limit <= 50:
                raise ValueError("search --limit must be 1..50")
            pattern = re.compile(args.pattern, re.IGNORECASE)
            hits: list[str] = []
            for name in candidates(root, revision, scopes):
                try:
                    text, digest = payload(root, revision, name)
                except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
                    unavailable.append(name)
                    continue
                for i, line in enumerate(text.splitlines()):
                    if pattern.search(line):
                        sources[name] = digest
                        hits.append(f"{name}:{i + 1}: {line}")
                        if len(hits) >= args.limit:
                            break
                if len(hits) >= args.limit:
                    break
            output = "\n".join(hits) or "(no matches in the selected bounded text scope)"
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    # Count exactly the emitted passages, including path/line labels and repeat reads.
    output += "\n"
    row = {
        "at": datetime.now(UTC).isoformat(),
        "root": str(root),
        "revision": revision,
        "operation": args.operation,
        "request": vars(args) | {"root": str(root), "receipt": str(receipt)},
        "sources": sources,
        "unavailable": unavailable,
        "characters": len(output),
        "words": len(re.findall(r"[A-Za-z0-9][A-Za-z0-9_/-]*", output)),
        "tokensApprox": round(len(output) / 4),
        "outputSha256": hashlib.sha256(output.encode()).hexdigest(),
        "output": output,
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with receipt.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
