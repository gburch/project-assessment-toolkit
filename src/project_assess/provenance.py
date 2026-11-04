"""Identity of the trusted assessment installation, never of a target's code."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from importlib import metadata
from pathlib import Path


def _revision(package):
    repository = package.parents[1]
    git = repository / ".git"
    try:
        if git.is_file():
            pointer = git.read_text().strip()
            if not pointer.startswith("gitdir: "):
                return None
            git = (repository / pointer[8:]).resolve()
        if not git.is_dir():
            return None
        head = (git / "HEAD").read_text().strip()
        if re.fullmatch(r"[0-9a-f]{40,64}", head):
            return head
        if not head.startswith("ref: refs/") or ".." in head:
            return None
        common = git
        if (git / "commondir").is_file():
            common = (git / (git / "commondir").read_text().strip()).resolve()
        ref = head[5:]
        for directory in (git, common):
            path = directory / ref
            if path.is_file():
                value = path.read_text().strip()
                return value if re.fullmatch(r"[0-9a-f]{40,64}", value) else None
        packed = common / "packed-refs"
        if packed.is_file() and packed.stat().st_size <= 1024 * 1024:
            for line in packed.read_text().splitlines():
                if line.endswith(" " + ref):
                    return line.split()[0]
    except (OSError, ValueError):
        pass
    return None


def _embedded_revision(package):
    """Read the identity stamped into a wheel or a git-archive export."""
    from ._build_revision import REVISION

    if re.fullmatch(r"[0-9a-f]{40,64}", REVISION):
        return REVISION
    stamped = package / "_build_revision.txt"
    try:
        value = stamped.read_text().strip() if stamped.is_file() else ""
    except OSError:
        return None
    return value if re.fullmatch(r"[0-9a-f]{40,64}", value) else None


def _checkout_state(package, revision):
    """Compare a source checkout with local refs only; this never contacts a remote."""
    repository = package.parents[1]
    if not (repository / ".git").exists() or not revision:
        return {"dirty": None, "behind_origin_main": None}

    def git(*arguments):
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            timeout=5,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
        return completed.stdout.strip() if completed.returncode == 0 else None

    try:
        status = git("status", "--porcelain", "--untracked-files=no")
        behind = git("rev-list", "--count", f"{revision}..refs/remotes/origin/main")
    except (OSError, subprocess.SubprocessError):
        return {"dirty": None, "behind_origin_main": None}
    return {
        "dirty": None if status is None else bool(status),
        "behind_origin_main": int(behind) if behind and behind.isdigit() else None,
    }


def tool_info():
    """Report installed file identity and available instructions, not claimed reads."""
    package = Path(__file__).resolve().parent
    skills = package / ".agents/skills"
    if not skills.is_dir():
        skills = package.parents[1] / ".agents/skills"
    hashes = {}
    for path in sorted(package.rglob("*")):
        if (
            path.is_file()
            and not path.is_relative_to(skills)
            and path.suffix in {".py", ".js", ".html", ".css", ".sc"}
        ):
            hashes[path.relative_to(package).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    instructions = []
    if skills.is_dir():
        for path in sorted(skills.rglob("*")):
            if not path.is_file() or path.suffix not in {
                ".md",
                ".py",
                ".js",
                ".html",
                ".css",
                ".sc",
            }:
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes["skills/" + path.relative_to(skills).as_posix()] = digest
            if path.suffix == ".md":
                instructions.append(
                    {"path": str(path), "sha256": digest, "status": "available_not_attested_read"}
                )
    versions = {}
    for name in (
        "pat-assess",
        "PyYAML",
        "mcp",
        "tree-sitter",
        "tree-sitter-javascript",
        "tree-sitter-typescript",
    ):
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    wheel_hash = None
    try:
        installed = metadata.distribution("pat-assess")
        direct = json.loads(installed.read_text("direct_url.json") or "{}")
        wheel_hash = direct.get("archive_info", {}).get("hashes", {}).get("sha256")
    except (metadata.PackageNotFoundError, ValueError, OSError):
        pass
    git_revision = _revision(package)
    revision = git_revision or _embedded_revision(package)
    return {
        "schema_version": 1,
        "name": "PAT",
        "distribution": "pat-assess",
        "version": versions["pat-assess"],
        "package_root": str(package),
        "source_revision": revision,
        "revision_source": "git_checkout"
        if git_revision
        else "embedded_at_build"
        if revision
        else None,
        **_checkout_state(package, git_revision),
        "code_digest": "sha256:"
        + hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(),
        "installed_wheel_sha256": wheel_hash,
        "dependencies": versions,
        "available_instructions": instructions,
        "caveat": "Installed files and available instructions do not prove what an agent loaded; record complete/partial reads in review_context.",
    }
