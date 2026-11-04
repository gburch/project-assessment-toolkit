"""Stamp the source commit into built artifacts, whose files have no Git metadata."""

from __future__ import annotations

import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_DESTINATIONS = {
    "sdist": "src/project_assess/_build_revision.txt",
    "wheel": "project_assess/_build_revision.txt",
}


def _git(root, *arguments):
    completed = subprocess.run(
        ["git", "-C", root, *arguments], capture_output=True, text=True, timeout=5
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


class RevisionHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if self.target_name not in _DESTINATIONS or version != "standard":
            return
        try:
            top = _git(self.root, "rev-parse", "--show-toplevel")
            revision = _git(self.root, "rev-parse", "HEAD")
            changes = _git(self.root, "status", "--porcelain", "--untracked-files=no")
        except (OSError, subprocess.SubprocessError):
            return
        # A wheel built from an sdist keeps the sdist's stamp. A modified tree gets none,
        # because no commit identifies its contents.
        if not top or Path(top).resolve() != Path(self.root).resolve() or not revision or changes:
            return
        stamp = Path(self.directory) / f".pat-build-revision-{self.target_name}"
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(revision + "\n")
        build_data["force_include"][str(stamp)] = _DESTINATIONS[self.target_name]
