"""Markdown grammar and standalone compatibility across the shared import boundary."""

from __future__ import annotations

import subprocess
import sys

from project_assess.doc_value import audit, markdown


def test_shared_markdown_helpers_preserve_existing_words_fences_links_and_anchors():
    text = """# Title & Words
# Title & Words
Setext Title
============
```text
# Hidden heading
[hidden](hidden.md)
```
[guide](<docs/space file.md> "Title")
![image](assets/plot.png)
[ref][]
[ref]: docs/ref.md
<https://example.com/page>
<mailto:reader@example.com>
<h2 id="custom">HTML <em>Heading</em></h2>
"""
    anchors, unsupported = markdown.headings(text)
    assert anchors == {
        "title-words": 1,
        "title-words-1": 1,
        "setext-title": 1,
        "html-heading": 1,
    }
    assert unsupported
    assert markdown.local_links(text) == [
        "docs/space file.md",
        "assets/plot.png",
        "docs/ref.md",
        "https://example.com/page",
        "mailto:reader@example.com",
    ]
    assert markdown.UNSUPPORTED_LINK_RE.search(markdown.without_fences(text))
    assert markdown.without_fences("before\n~~~text\nhidden\n~~~\nafter") == "before\nafter"
    assert markdown.words("Foo_BAR /api/v1 a-b 42") == ["foo_bar", "api/v1", "a-b", "42"]


def test_standalone_audit_preserves_existing_helper_imports():
    for name in (
        "words",
        "without_fences",
        "headings",
        "local_links",
        "INLINE_LINK_RE",
        "REFERENCE_LINK_RE",
        "AUTOLINK_RE",
        "UNSUPPORTED_LINK_RE",
    ):
        assert getattr(audit, name) is getattr(markdown, name)


def test_captured_documentation_does_not_load_standalone_audit_or_collector():
    # A fresh interpreter makes the import boundary observable independently of
    # other tests that legitimately load the standalone audit or source reader.
    code = """import sys
from project_assess.documentation import captured_documentation
result = captured_documentation(
    {"README.md": "# Guide\\n[local](#guide)\\n"}, {"README.md"}
)
assert result["links"] == [{"source": "README.md", "target": "#guide", "resolved": "README.md"}]
assert "project_assess.doc_value.audit" not in sys.modules
assert "project_assess.collector" not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, timeout=10
    )
    assert completed.returncode == 0, completed.stderr
