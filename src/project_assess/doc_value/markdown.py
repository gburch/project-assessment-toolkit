"""Pure lexical Markdown helpers shared by captured evidence and standalone audits."""

from __future__ import annotations

import re
from collections import Counter


def words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9][A-Za-z0-9_/-]*", text.lower())


def without_fences(text: str) -> str:
    result: list[str] = []
    fenced = False
    for line in text.splitlines():
        if re.match(r"^\s{0,3}(```|~~~)", line):
            fenced = not fenced
            continue
        if not fenced:
            result.append(line)
    return "\n".join(result)


def _underscore_emphasis(text: str) -> bool:
    outside_code = re.sub(r"(`+)[^`]*\1", "", text)
    return re.search(r"(?<!\w)_{1,2}\w+_{1,2}(?!\w)", outside_code) is not None


def headings(text: str) -> tuple[dict[str, int], bool]:
    result: dict[str, int] = {}
    seen: Counter[str] = Counter()
    unsupported = False
    lines = without_fences(text).splitlines()
    for index, line in enumerate(lines):
        m = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if m:
            unsupported |= _underscore_emphasis(m.group(1))
            slug = re.sub(r"[^a-z0-9_ -]", "", m.group(1).lower())
            base = re.sub(r"\s+", "-", slug.strip())
            occurrence = seen[base]
            seen[base] += 1
            result[base if occurrence == 0 else f"{base}-{occurrence}"] = 1
        elif (
            line.strip()
            and index + 1 < len(lines)
            and re.match(r"^\s*(=+|-+)\s*$", lines[index + 1])
        ):
            unsupported |= _underscore_emphasis(line)
            base = re.sub(r"[^a-z0-9_ -]", "", line.lower())
            base = re.sub(r"\s+", "-", base.strip())
            occurrence = seen[base]
            seen[base] += 1
            result[base if occurrence == 0 else f"{base}-{occurrence}"] = 1
    for match in re.finditer(r"<h[1-6]\b[^>]*>(.*?)</h[1-6]>", without_fences(text), re.I | re.S):
        inner = re.sub(r"<[^>]+>", "", match.group(1))
        base = re.sub(r"[^a-z0-9_ -]", "", inner.lower())
        base = re.sub(r"\s+", "-", base.strip())
        occurrence = seen[base]
        seen[base] += 1
        result[base if occurrence == 0 else f"{base}-{occurrence}"] = 1
        unsupported = True
    if re.search(r"<h[1-6]\b[^>]*\bid\s*=", without_fences(text), re.I):
        unsupported = True
    return result, unsupported


INLINE_LINK_RE = re.compile(
    r"!?\[[^\]]*\]\(\s*(<[^>]*>|[^\s)]+)(?:\s+(?:['\"][^'\"]*['\"]|\([^)]*\)))?\s*\)"
)
REFERENCE_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))", re.MULTILINE)
AUTOLINK_RE = re.compile(r"<((?:https?://|mailto:)[^>]+)>")
UNSUPPORTED_LINK_RE = re.compile(r"\[[^\]]+\]\[[^\]]*\]")


def local_links(text: str) -> list[str]:
    result: list[str] = []
    clean = without_fences(text)
    for regex in (INLINE_LINK_RE, REFERENCE_LINK_RE, AUTOLINK_RE):
        for match in regex.finditer(clean):
            target = next((group for group in match.groups() if group is not None), "")
            if target:
                result.append(target.strip("<>"))
    return result
