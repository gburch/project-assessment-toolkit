"""Heading-aware, lexical section and passage evidence for doc-value.

This module reports locations and similarity leads only. It does not decide
whether two sections have the same meaning or whether either one is removable.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any

WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_/-]*")
FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
ATX_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
SETEXT_RE = re.compile(r"^\s*(=+|-+)\s*$")
HTML_HEADING_RE = re.compile(r"<h[1-6]\b[^>]*>.*?</h[1-6]>", re.I | re.S)


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_words(text: str) -> list[str]:
    return WORD_RE.findall(text.lower())


def line_tokens(lines: list[str], start: int, end: int) -> tuple[list[str], list[int]]:
    tokens: list[str] = []
    line_numbers: list[int] = []
    for index in range(start, end):
        row = WORD_RE.findall(lines[index].lower())
        tokens.extend(row)
        line_numbers.extend([index + 1] * len(row))
    return tokens, line_numbers


def parse_sections(path: str, text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Parse headings outside fences while retaining all content in spans."""
    lines = text.splitlines()
    headings: list[tuple[int, int, str]] = []
    gaps: list[str] = []
    fence: tuple[str, int] | None = None
    frontmatter_end = 0
    if lines and lines[0].strip() == "---":
        for index in range(1, len(lines)):
            if lines[index].strip() in {"---", "..."}:
                frontmatter_end = index + 1
                break
        if not frontmatter_end:
            gaps.append(f"unclosed-frontmatter:{path}")
    for index, line in enumerate(lines):
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group(1)
            if fence is None:
                fence = (marker[0], len(marker))
            elif marker[0] == fence[0] and len(marker) >= fence[1]:
                fence = None
            continue
        if fence is not None or index < frontmatter_end:
            continue
        match = ATX_RE.match(line)
        if match:
            headings.append(
                (index, len(match.group(1)), match.group(2).strip().rstrip("#").strip())
            )
            continue
        if index + 1 < len(lines) and line.strip() and SETEXT_RE.match(lines[index + 1]):
            headings.append(
                (index, 1 if lines[index + 1].lstrip().startswith("=") else 2, line.strip())
            )
    if fence is not None:
        gaps.append(f"unclosed-fence:{path}")
    if HTML_HEADING_RE.search("\n".join(lines)):
        gaps.append(f"unsupported-html-heading-markup:{path}")
    sections: list[dict[str, Any]] = []
    heading_paths: list[list[str]] = []
    stack: list[tuple[int, str]] = []
    for _line_index, level, title in headings:
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, title))
        heading_paths.append([item[1] for item in stack])
    for heading_index, (line_index, level, title) in enumerate(headings):
        end = len(lines)
        for next_index in range(heading_index + 1, len(headings)):
            next_line, next_level, _ = headings[next_index]
            if next_level <= level:
                end = next_line
                break
        heading_path = heading_paths[heading_index]
        setext = line_index + 1 < len(lines) and SETEXT_RE.match(lines[line_index + 1])
        content_start = line_index + (2 if setext else 1)
        full_tokens, _ = line_tokens(lines, content_start, end)
        owned_end = (
            headings[heading_index + 1][0] if heading_index + 1 < len(headings) else len(lines)
        )
        tokens, line_numbers = line_tokens(lines, content_start, owned_end)
        document_prefix = normalize_words("\n".join(lines[:content_start]))
        sections.append(
            {
                "id": f"{path}#section-{len(sections) + 1}",
                "path": path,
                "heading": title,
                "headingPath": heading_path,
                "level": level,
                "lineStart": line_index + 1,
                "lineEnd": end,
                "contentStart": content_start + 1,
                "contentEnd": end,
                "ownedContentStart": content_start + 1,
                "ownedContentEnd": owned_end,
                "words": len(full_tokens),
                "ownedWords": len(tokens),
                "documentWordStart": len(document_prefix),
                "documentWordEnd": len(document_prefix) + len(full_tokens),
                "ownedDocumentWordEnd": len(document_prefix) + len(tokens),
                "sha256": digest(" ".join(full_tokens)),
                "ownedSha256": digest(" ".join(tokens)),
                "_tokens": tokens,
                "_text": " ".join(tokens),
                "_line_numbers": line_numbers,
            }
        )
    if not headings and text.strip():
        tokens, line_numbers = line_tokens(lines, 0, len(lines))
        sections.append(
            {
                "id": f"{path}#preamble",
                "path": path,
                "heading": "(preamble)",
                "headingPath": [],
                "level": 0,
                "lineStart": 1,
                "lineEnd": len(lines),
                "contentStart": 1,
                "contentEnd": len(lines),
                "words": len(tokens),
                "ownedContentStart": 1,
                "ownedContentEnd": len(lines),
                "ownedWords": len(tokens),
                "documentWordStart": 0,
                "documentWordEnd": len(tokens),
                "sha256": digest(" ".join(tokens)),
                "ownedSha256": digest(" ".join(tokens)),
                "_tokens": tokens,
                "_text": " ".join(tokens),
                "_line_numbers": line_numbers,
            }
        )
    return sections, gaps


def location(section: dict[str, Any], start: int, end: int) -> dict[str, Any]:
    line_numbers = section["_line_numbers"]
    if line_numbers and start < len(line_numbers):
        line_start = line_numbers[start]
        line_end = line_numbers[min(end, len(line_numbers)) - 1]
    else:
        line_start = section["ownedContentStart"]
        line_end = section["ownedContentEnd"]
    return {
        "path": section["path"],
        "headingPath": section["headingPath"],
        "lineStart": line_start,
        "lineEnd": line_end,
        "sectionLineStart": section["contentStart"],
        "sectionLineEnd": section["contentEnd"],
        "wordStart": section["documentWordStart"] + start,
        "wordEnd": section["documentWordStart"] + end,
        "sectionWordStart": start,
        "sectionWordEnd": end,
    }


def analyze_sections(
    texts: dict[str, str],
    *,
    max_pairs: int = 2000,
    window_words: int = 160,
    window_step: int = 80,
    max_sections: int = 5000,
    max_windows: int = 50000,
    shingle_words: int = 5,
    rare_shingle_cap: int = 12,
    exact_run_words: int = 20,
) -> dict[str, Any]:
    sections: list[dict[str, Any]] = []
    gaps: list[str] = []
    skipped: list[str] = []
    for path in sorted(texts):
        parsed, parse_gaps = parse_sections(path, texts[path])
        gaps.extend(parse_gaps)
        if len(sections) + len(parsed) > max_sections:
            skipped.append(path)
            gaps.append(f"section-limit:{path}:{max_sections}")
            continue
        sections.extend(parsed)
    section_rows = [
        {key: value for key, value in section.items() if not key.startswith("_")}
        for section in sections
    ]
    exact: dict[str, list[str]] = defaultdict(list)
    for section in sections:
        exact[section["ownedSha256"]].append(section["id"])
    exact_leads = [ids for ids in exact.values() if len(ids) > 1]

    windows: list[dict[str, Any]] = []
    truncated_inputs: list[str] = []
    for window_section_index, section in enumerate(sections):
        tokens = section["_tokens"]
        if len(tokens) <= window_words:
            starts = [0] if tokens else []
        else:
            starts = list(range(0, len(tokens) - window_words + 1, max(1, window_step)))
            if starts[-1] != len(tokens) - window_words:
                starts.append(len(tokens) - window_words)
        for start in starts:
            if len(windows) >= max_windows:
                truncated_inputs.extend(item["path"] for item in sections[window_section_index:])
                break
            end = min(start + window_words, len(tokens))
            window_tokens = tokens[start:end]
            windows.append(
                {
                    "id": f"{section['id']}@{start}-{end}",
                    "section": section,
                    "start": start,
                    "end": end,
                    "tokens": window_tokens,
                    "text": " ".join(window_tokens),
                }
            )
        if len(windows) >= max_windows:
            truncated_inputs.extend(item["path"] for item in sections[window_section_index + 1 :])
            break

    index: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for index_value, window in enumerate(windows):
        tokens = window["tokens"]
        shingles = {
            tuple(tokens[i : i + shingle_words])
            for i in range(max(0, len(tokens) - shingle_words + 1))
        }
        for shingle in shingles:
            index[shingle].append(index_value)
    candidate_strength: dict[tuple[int, int], int] = defaultdict(int)
    for values in index.values():
        if 1 < len(values) <= rare_shingle_cap:
            for left_index, left in enumerate(values):
                for right in values[left_index + 1 :]:
                    if windows[left]["section"]["id"] == windows[right]["section"]["id"]:
                        continue
                    candidate_strength[(min(left, right), max(left, right))] += 1
    candidates = set(candidate_strength)
    passage_leads: list[dict[str, Any]] = []
    passage_signatures: set[tuple[str, int, str, int]] = set()
    passage_candidate_inputs: set[str] = {
        windows[index]["section"]["path"] for pair in candidates for index in pair
    }
    passage_compared_inputs: set[str] = set()
    containment_leads: list[dict[str, Any]] = []
    passage_compared = 0
    ordered_candidates = sorted(
        candidates,
        key=lambda pair: (
            -candidate_strength[pair],
            pair,
        ),
    )
    for left_index, right_index in ordered_candidates:
        if passage_compared >= max_pairs:
            break
        left_window = windows[left_index]
        right_window = windows[right_index]
        passage_compared_inputs.update(
            (left_window["section"]["path"], right_window["section"]["path"])
        )
        passage_compared += 1
        ratio = SequenceMatcher(None, left_window["tokens"], right_window["tokens"]).ratio()
        match = max(
            SequenceMatcher(
                None, left_window["tokens"], right_window["tokens"]
            ).get_matching_blocks(),
            key=lambda block: block.size,
        )
        if ratio >= 0.86 or match.size >= exact_run_words:
            exact_run = match.size >= exact_run_words
            left_start = left_window["start"] + (match.a if exact_run else 0)
            right_start = right_window["start"] + (match.b if exact_run else 0)
            left_end = left_start + (match.size if exact_run else len(left_window["tokens"]))
            right_end = right_start + (match.size if exact_run else len(right_window["tokens"]))
            signature = (
                left_window["section"]["path"],
                left_start,
                right_window["section"]["path"],
                right_start,
            )
            if signature in passage_signatures:
                continue
            passage_signatures.add(signature)
            passage_leads.append(
                {
                    "kind": "passage-exact-run" if exact_run else "passage-overlap",
                    "similarity": round(ratio, 3),
                    "basis": (
                        "rare-shingle candidate plus exact shared token run; lexical lead only"
                        if exact_run
                        else (
                            "rare-shingle candidate plus token sequence similarity; "
                            "lexical lead only"
                        )
                    ),
                    "left": location(left_window["section"], left_start, left_end),
                    "right": location(right_window["section"], right_start, right_end),
                }
            )
    section_candidates: set[tuple[int, int]] = set()
    section_index: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for index_value, section in enumerate(sections):
        tokens = section["_tokens"]
        shingles = {
            tuple(tokens[i : i + shingle_words])
            for i in range(max(0, len(tokens) - shingle_words + 1))
        }
        for shingle in shingles:
            section_index[shingle].append(index_value)
    for values in section_index.values():
        if 1 < len(values) <= rare_shingle_cap:
            for left_index, left in enumerate(values):
                for right in values[left_index + 1 :]:
                    section_candidates.add((min(left, right), max(left, right)))
    section_compared = 0
    section_candidate_inputs: set[str] = {
        sections[index]["path"] for pair in section_candidates for index in pair
    }
    section_compared_inputs: set[str] = set()
    for left_index, right_index in sorted(section_candidates):
        if section_compared >= max_pairs:
            break
        left_section, right_section = sections[left_index], sections[right_index]
        section_compared_inputs.update((left_section["path"], right_section["path"]))
        section_compared += 1
        if (
            left_section["path"] == right_section["path"]
            and left_section["sha256"] == right_section["sha256"]
        ):
            continue
        shorter, longer = sorted(
            (left_section, right_section), key=lambda item: len(item["_tokens"])
        )
        if (
            shorter["_text"]
            and shorter["_text"] in longer["_text"]
            and len(shorter["_tokens"]) < len(longer["_tokens"])
        ):
            containment_leads.append(
                {
                    "kind": "section-containment",
                    "basis": "full normalized section text contained in another; lexical lead only",
                    "shorter": location(shorter, 0, len(shorter["_tokens"])),
                    "longer": location(longer, 0, len(longer["_tokens"])),
                }
            )

    for section in sections:
        section.pop("_tokens", None)
        section.pop("_text", None)
    return {
        "enabled": True,
        "limits": {
            "maxPairs": max_pairs,
            "windowWords": window_words,
            "windowStep": window_step,
            "maxSections": max_sections,
            "maxWindows": max_windows,
            "shingleWords": shingle_words,
            "rareShingleCap": rare_shingle_cap,
            "exactRunWords": exact_run_words,
        },
        "sections": section_rows,
        "windows": {
            "indexed": len(windows),
            "max": max_windows,
            "truncated": bool(truncated_inputs),
            "truncatedInputs": sorted(set(truncated_inputs)),
        },
        "exactSectionDuplicates": exact_leads,
        "containmentLeads": containment_leads,
        "passageLeads": passage_leads,
        "progress": {
            "documentsIndexed": len(texts),
            "sectionsIndexed": len(sections),
            "candidatePairs": len(candidates) + len(section_candidates),
            "comparedPairs": passage_compared + section_compared,
            "pairBudgetExhausted": (passage_compared >= max_pairs and bool(candidates))
            or (section_compared >= max_pairs and bool(section_candidates)),
            "passage": {
                "candidatePairs": len(candidates),
                "comparedPairs": passage_compared,
                "uncomparedPairs": max(0, len(candidates) - passage_compared),
                "budgetExhausted": passage_compared >= max_pairs and bool(candidates),
                "candidateInputs": sorted(passage_candidate_inputs),
                "uncomparedInputs": sorted(passage_candidate_inputs - passage_compared_inputs),
            },
            "section": {
                "candidatePairs": len(section_candidates),
                "comparedPairs": section_compared,
                "uncomparedPairs": max(0, len(section_candidates) - section_compared),
                "budgetExhausted": (section_compared >= max_pairs and bool(section_candidates)),
                "candidateInputs": sorted(section_candidate_inputs),
                "uncomparedInputs": sorted(section_candidate_inputs - section_compared_inputs),
            },
        },
        "skippedInputs": skipped,
        "gaps": sorted(set(gaps)),
    }
