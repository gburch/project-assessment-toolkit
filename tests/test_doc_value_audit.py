#!/usr/bin/env python3
"""Small real-CLI boundary check for doc_value_audit.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from project_assess.doc_value import audit as audit_module

COMMAND = [sys.executable, "-m", "project_assess.doc_value.audit"]


def run_git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


class DocValueCliTest(unittest.TestCase):
    def test_links_deleted_reference_and_output_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            root.mkdir()
            docs = root / "docs"
            docs.mkdir()
            outside = Path(temp) / "outside.md"
            outside.write_text("outside\n", encoding="utf-8")
            current = (
                '# Current\n\n[self](#current) [missing](<missing.md> "Title") '
                "[web](https://example.com)\n"
            )
            (docs / "current.md").write_text(current, encoding="utf-8")
            (docs / "copy.md").write_text(current, encoding="utf-8")
            (docs / "old.md").write_text("# Old\n", encoding="utf-8")
            (docs / "caller.md").write_text("See docs/old.md\n", encoding="utf-8")
            (docs / "private.md").write_text("# Private\n", encoding="utf-8")
            (docs / "rename source.md").write_text("# Rename\n", encoding="utf-8")
            secrets = root / "secrets"
            secrets.mkdir()
            (secrets / "hidden.md").write_text("do not inspect\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "worker.py").write_text("# source\n", encoding="utf-8")
            (docs / "escape.md").symlink_to(outside)
            run_git(root, "init", "-q")
            run_git(root, "config", "user.email", "doc-value@example.com")
            run_git(root, "config", "user.name", "doc-value")
            run_git(root, "add", "docs", "secrets", "-A")
            run_git(root, "commit", "-qm", "fixture")
            base = run_git(root, "rev-parse", "HEAD")
            run_git(root, "rm", "-q", "docs/old.md")
            run_git(root, "mv", "docs/rename source.md", "docs/renamed source.md")
            (docs / "new.md").write_text("# New\n\nAdded after the baseline.\n", encoding="utf-8")
            (docs / "staged.md").write_text(
                "# Staged\n\nAdded to the index only.\n", encoding="utf-8"
            )
            run_git(root, "add", "docs/staged.md")
            (docs / "private.md").write_text("# Private changed\n", encoding="utf-8")
            (root / "src" / "worker.py").write_text("# source changed\n", encoding="utf-8")
            (docs / "assets").mkdir()
            (docs / "assets" / "new.bin").write_bytes(b"\x00\x01new")

            # A hostile repository may advertise clean-filter and fsmonitor
            # helpers.  The assessment must not execute either while reading
            # normal, base-delta, or untracked-file evidence.
            marker = Path(temp) / "repository-extension-ran"
            marker_script = Path(temp) / "repository-extension.sh"
            marker_script.write_text(
                f"#!/bin/sh\nprintf x >> {str(marker)!r}\ncat\n",
                encoding="utf-8",
            )
            marker_script.chmod(0o755)
            (root / ".gitattributes").write_text("*.md filter=marker\n", encoding="utf-8")
            run_git(root, "add", ".gitattributes")
            run_git(root, "commit", "-qm", "attributes")
            run_git(root, "config", "filter.marker.clean", f"sh {marker_script}")
            run_git(root, "config", "filter.marker.smudge", "cat")
            run_git(root, "config", "core.fsmonitor", f"sh {marker_script}")
            marker.unlink(missing_ok=True)

            with tempfile.TemporaryDirectory() as receipt_dir:
                receipt = Path(receipt_dir) / "receipt.json"
                completed = subprocess.run(
                    [
                        *COMMAND,
                        "--root",
                        str(root),
                        "--output",
                        str(receipt),
                        "--base",
                        base,
                        "--path",
                        "docs",
                        "--exclude",
                        "docs/private*",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertFalse(marker.exists(), "assessment invoked a repository extension")
                report = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertIsNone(report["identity"]["trackedDirty"])
                self.assertFalse(report["identity"]["statusRead"])
                self.assertTrue(any("unverified-external-link" in gap for gap in report["gaps"]))
                self.assertTrue(any("symlink-escape" in gap for gap in report["gaps"]))
                self.assertFalse(
                    any(link.get("issue") == "missing-anchor" for link in report["links"])
                )
                self.assertTrue(any(link["target"] == "missing.md" for link in report["links"]))
                self.assertTrue(report["exactDuplicates"])
                deleted = report["delta"]["deletedInboundReferences"]["docs/old.md"]
                self.assertIn("docs/caller.md", deleted["exactPathMentions"])
                added = next(
                    row
                    for row in report["delta"]["changedDocuments"]
                    if row["path"] == "docs/new.md"
                )
                self.assertTrue(added.get("untracked"))
                self.assertEqual(added["after"]["words"], 5)
                staged = next(
                    row
                    for row in report["delta"]["changedDocuments"]
                    if row["path"] == "docs/staged.md"
                )
                self.assertFalse(staged.get("untracked", False))
                self.assertIn(
                    "docs/renamed source.md",
                    {row["path"] for row in report["delta"]["changedDocuments"]},
                )
                self.assertNotIn(
                    "docs/private.md", {row["path"] for row in report["delta"]["changedDocuments"]}
                )
                self.assertNotIn(
                    "src/worker.py", {row["path"] for row in report["delta"]["changedDocuments"]}
                )
                artifacts = {row["path"] for row in report["inventory"]["binaryArtifacts"]}
                self.assertIn("docs/assets/new.bin", artifacts)

                normal_receipt = Path(receipt_dir) / "normal.json"
                normal = subprocess.run(
                    [
                        *COMMAND,
                        "--root",
                        str(root),
                        "--output",
                        str(normal_receipt),
                        "--path",
                        "docs",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(normal.returncode, 0, normal.stderr)
                self.assertFalse(marker.exists(), "assessment invoked a repository extension")

            refused = subprocess.run(
                [
                    *COMMAND,
                    "--root",
                    str(root),
                    "--output",
                    str(root / "inside.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse((root / "inside.json").exists())

    def test_non_git_binary_and_config_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            assets = root / "docs" / "assets"
            assets.mkdir(parents=True)
            (root / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
            (root / "docs" / "second.md").write_text("# Second\n", encoding="utf-8")
            (assets / "diagram.bin").write_bytes(b"\x00\x01diagram")
            (root / "settings.json").write_text('{"mode":"test"}\n', encoding="utf-8")
            source = root / "src"
            source.mkdir()
            (source / "main.py").write_text('open("docs/guide.md")\n', encoding="utf-8")
            (source / "basename.py").write_text('name = "guide.md"\n', encoding="utf-8")
            with tempfile.TemporaryDirectory() as receipt_dir:
                receipt = Path(receipt_dir) / "receipt.json"
                completed = subprocess.run(
                    [
                        *COMMAND,
                        "--root",
                        str(root),
                        "--output",
                        str(receipt),
                        "--callers",
                        "src",
                        "--max-files",
                        "1",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                report = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(report["inventory"]["mode"], "filesystem-fallback")
                self.assertEqual(report["inventory"]["count"], 1)
                self.assertTrue(report["inventory"]["textLimit"]["applied"])
                artifacts = {row["path"]: row for row in report["inventory"]["binaryArtifacts"]}
                self.assertEqual(artifacts["docs/assets/diagram.bin"]["words"], None)
                self.assertEqual(artifacts["settings.json"]["role"], "config")
                caller_evidence = report["callerReferences"]["docs/guide.md"]
                self.assertIn("src/main.py", caller_evidence["exactPath"])
                self.assertIn("src/basename.py", caller_evidence["basenameLead"])

    def test_capped_baseline_does_not_claim_unproven_addition(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            docs = root / "docs"
            docs.mkdir(parents=True)
            (docs / "keep.md").write_text("# Keep\n", encoding="utf-8")
            (docs / "old.md").write_text("# Old\n", encoding="utf-8")
            run_git(root, "init", "-q")
            run_git(root, "config", "user.email", "doc-value@example.com")
            run_git(root, "config", "user.name", "doc-value")
            run_git(root, "add", "docs")
            run_git(root, "commit", "-qm", "fixture")
            base = run_git(root, "rev-parse", "HEAD")
            (docs / "new.md").write_text("# New\n", encoding="utf-8")
            receipt = Path(temp) / "receipt.json"
            with mock.patch.object(audit_module, "MAX_DELTA_PATHS", 1):
                result = audit_module.main(
                    [
                        "--root",
                        str(root),
                        "--output",
                        str(receipt),
                        "--base",
                        base,
                        "--path",
                        "docs",
                    ]
                )
            self.assertEqual(result, 0)
            report = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertIn("delta-base-path-limit:1", report["delta"]["gaps"])
            self.assertNotIn(
                "docs/new.md", {row["path"] for row in report["delta"]["changedDocuments"]}
            )

    def test_sections_find_late_passage_and_same_file_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            docs = root / "docs"
            docs.mkdir()
            procedure = " ".join(f"procedure-step-{index}" for index in range(500))
            filler = " ".join(f"filler-{index}" for index in range(13_000))
            (docs / "late-a.md").write_text(
                "# Operations\n\n```text\n# Not a heading\n```\n\n"
                f"{filler}\n\n## Procedure\n\n{procedure}\n\n"
                f"## Procedure Copy\n\n{procedure}\n\n## Security\n\n"
                "Use isolated keys and deny unsafe access.\n\n"
                "## Recovery\n\nRestore from the verified snapshot and reconcile state.\n",
                encoding="utf-8",
            )
            (docs / "late-b.md").write_text(
                "---\nowner: fixture\n---\n\n"
                f"# Runbook\n\nShort context.\n\n## Procedure\n\n{procedure}\n\n"
                "## Security\n\nRotate credentials before restoring service.\n\n"
                "## Recovery\n\nValidate the backup before opening traffic.\n",
                encoding="utf-8",
            )
            with tempfile.TemporaryDirectory() as receipt_dir:
                receipt = Path(receipt_dir) / "receipt.json"
                completed = subprocess.run(
                    [
                        *COMMAND,
                        "--root",
                        str(root),
                        "--output",
                        str(receipt),
                        "--sections",
                        "--summary",
                        "--top",
                        "3",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                report = json.loads(receipt.read_text(encoding="utf-8"))
                sections = report["sectionAnalysis"]
                self.assertTrue(sections["enabled"])
                self.assertGreater(len(sections["sections"]), 0)
                headings = {row["heading"] for row in sections["sections"]}
                self.assertNotIn("owner: fixture", headings)
                self.assertNotIn("Not a heading", headings)
                self.assertGreater(sections["windows"]["indexed"], 0)
                self.assertGreater(sections["progress"]["candidatePairs"], 0)
                duplicate_group = next(
                    group
                    for group in sections["exactSectionDuplicates"]
                    if sum("late-a.md" in item for item in group) >= 2
                )
                self.assertGreaterEqual(len(duplicate_group), 2)
                passage = next(
                    lead
                    for lead in sections["passageLeads"]
                    if {lead["left"]["path"], lead["right"]["path"]}
                    == {"docs/late-a.md", "docs/late-b.md"}
                )
                self.assertGreater(passage["left"]["wordStart"], 12_000)
                self.assertIn("headingPath", passage["left"])
                self.assertIn("lineStart", passage["right"])
                self.assertNotIn("sameMeaning", passage)
                self.assertNotIn("semanticEquivalent", passage)
                for lead in sections["passageLeads"]:
                    if lead["left"]["path"] == lead["right"]["path"]:
                        self.assertNotEqual(
                            (
                                lead["left"]["sectionLineStart"],
                                lead["left"]["sectionLineEnd"],
                            ),
                            (
                                lead["right"]["sectionLineStart"],
                                lead["right"]["sectionLineEnd"],
                            ),
                        )
                security_or_recovery = [
                    lead
                    for lead in sections["passageLeads"]
                    if any(
                        heading in {"Security", "Recovery"}
                        for side in (lead["left"], lead["right"])
                        for heading in side["headingPath"]
                    )
                ]
                self.assertFalse(security_or_recovery)
                self.assertIn("section leads", completed.stdout)


if __name__ == "__main__":
    unittest.main()
