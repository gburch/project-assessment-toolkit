"""The navigation probe records actual emitted context and confines reads."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

COMMAND = [sys.executable, "-m", "project_assess.doc_value.navigation"]


class NavigationProbeTest(unittest.TestCase):
    def test_receipts_measure_read_search_and_reject_outside_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            docs = root / "docs"
            docs.mkdir(parents=True)
            (docs / "guide.md").write_text("# Guide\n\nUse the existing recovery command.\n")
            (root / "internal.txt").write_text("private fixture\n")
            receipt = Path(tmp) / "trial.jsonl"
            prefix = [
                *COMMAND,
                "--root",
                str(root),
                "--scope",
                "docs",
                "--receipt",
                str(receipt),
            ]
            emitted = []
            for operation in (
                ["read", "docs/guide.md", "--lines", "3"],
                ["search", "recovery", "--limit", "2"],
            ):
                result = subprocess.run(prefix + operation, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                emitted.append(result.stdout)
            rows = [json.loads(row) for row in receipt.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(sum(row["characters"] for row in rows), sum(map(len, emitted)))
            for row, output in zip(rows, emitted, strict=True):
                self.assertEqual(row["output"], output)
                self.assertEqual(row["outputSha256"], hashlib.sha256(output.encode()).hexdigest())
                self.assertIn("docs/guide.md", row["sources"])
            result = subprocess.run(
                prefix + ["read", "internal.txt"], capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(receipt.read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
