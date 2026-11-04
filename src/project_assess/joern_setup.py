"""Fetch the one Joern release the adapter is qualified against; never during a scan."""

from __future__ import annotations

import hashlib
import platform
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

from .joern_analysis import JOERN_VERSION

_RELEASE = f"https://github.com/joernio/joern/releases/download/v{JOERN_VERSION}"
# GitHub's recorded asset digests for the pinned release; a mismatch stops before extraction.
_ASSETS = {
    ("linux", "aarch64"): (
        "joern-cli-linux-arm64.zip",
        "efda49102439522832b683fc61729c00fd52ece207d0e668808392d6c7cef06a",
    ),
    ("linux", "x86_64"): (
        "joern-cli-linux-x86_64.zip",
        "200bcfd7d90b06bd4f3204f346d02c506bf37060700194b3e34ca4a7d33bf97d",
    ),
    ("darwin", "arm64"): (
        "joern-cli-macos-arm64.zip",
        "7684df418d6f901d8deae7df5a297b9726cb0e642e8b3c3f0532cbc1ed3544b0",
    ),
    ("darwin", "x86_64"): (
        "joern-cli-macos-x86_64.zip",
        "92539046c26d2d4b1a15ae6dcf4eca3b83a7a9b49afd0880248699c61fc214a2",
    ),
}


def _download(url, target):
    with urllib.request.urlopen(url, timeout=60) as response, target.open("wb") as output:
        shutil.copyfileobj(response, output, 1024 * 1024)


def _extract(archive, destination):
    """Reject links and paths that leave the destination; zipfile drops execute bits."""
    root = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            mode = member.external_attr >> 16
            target = (root / member.filename).resolve()
            if (mode & 0o170000) == 0o120000 or not target.is_relative_to(root):
                raise ValueError("Joern archive contains an unsafe entry")
            bundle.extract(member, root)
            if mode & 0o111 and not member.is_dir():
                target.chmod(target.stat().st_mode | 0o111)


def setup_joern(destination):
    asset = _ASSETS.get((sys.platform, platform.machine().lower()))
    if asset is None:
        raise ValueError(f"No pinned Joern {JOERN_VERSION} asset for this platform")
    name, expected = asset
    directory = Path(destination).expanduser().absolute()
    home = directory / "joern-cli"
    if home.exists():
        raise ValueError(f"{home} already exists; choose an empty destination")
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / (name + ".partial")
    staging = directory / ".joern-staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        print(f"pat: downloading {name} (about 1.8 GiB)", file=sys.stderr, flush=True)
        _download(f"{_RELEASE}/{name}", archive)
        with archive.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise ValueError(f"Joern archive digest mismatch for {name}; nothing was installed")
        # A failed extraction must not leave a home that blocks the retry.
        _extract(archive, staging)
        (staging / "joern-cli").rename(home)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
    return {
        "joern_version": JOERN_VERSION,
        "sha256": expected,
        "home": str(home),
        "next_steps": [
            f"export PAT_JOERN_HOME={home}",
            "export PAT_JOERN_JAVA_HOME=/absolute/path/to/jdk-21-home",
            "pat analyzers",
        ],
    }
