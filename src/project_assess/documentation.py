"""Documentation leads derived only from bytes captured by the source collector."""

from __future__ import annotations

import hashlib
import posixpath
from collections import defaultdict
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from .doc_value.markdown import UNSUPPORTED_LINK_RE, headings, local_links, without_fences, words

MAX_DOCUMENTS = 2000
MAX_LINKS = 2000


def captured_documentation(texts: dict[str, str], manifest_paths: set[str]) -> dict:
    selected = dict(sorted(texts.items())[:MAX_DOCUMENTS])
    documents, links, gaps = [], [], []
    by_hash = defaultdict(list)
    known = set(manifest_paths)
    for name in manifest_paths:
        known.update(str(parent) for parent in PurePosixPath(name).parents)
    anchors = {}
    links_truncated = False
    for name, text in selected.items():
        if UNSUPPORTED_LINK_RE.search(without_fences(text)):
            gaps.append(f"Unsupported Markdown link markup: {name}")
        payload = text.encode("utf-8")
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        documents.append(
            {
                "path": name,
                "sha256": digest,
                "bytes": len(payload),
                "words": len(words(text)),
                "tokensApprox": round(len(text) / 4),
            }
        )
        by_hash[digest].append(name)
        for target in local_links(text):
            if len(links) >= MAX_LINKS:
                links_truncated = True
                break
            row = {"source": name, "target": target}
            try:
                parsed = urlsplit(target)
            except ValueError:
                row["issue"] = "unsupported-link"
                links.append(row)
                continue
            if parsed.scheme or parsed.netloc:
                row["issue"] = "external-unverified"
            else:
                path = unquote(parsed.path)
                resolved = posixpath.normpath(
                    posixpath.join(posixpath.dirname(name), path) if path else name
                )
                if resolved.startswith("/") or resolved == ".." or resolved.startswith("../"):
                    row["issue"] = "outside-captured-root"
                elif resolved not in known:
                    row["issue"] = "unresolved-or-excluded-target"
                elif parsed.fragment:
                    if resolved not in selected:
                        row["issue"] = "anchor-not-captured"
                    else:
                        if resolved not in anchors:
                            anchors[resolved] = headings(selected[resolved])
                        available, unsupported = anchors[resolved]
                        if unquote(parsed.fragment).lower() not in available:
                            row["issue"] = "uncertain-anchor" if unsupported else "missing-anchor"
                        else:
                            row["resolved"] = resolved
                else:
                    row["resolved"] = resolved
            links.append(row)
    if len(texts) > len(selected):
        gaps.append("Documentation input limit reached; remaining documents were not analyzed")
    if links_truncated:
        gaps.append("Documentation link limit reached; remaining links were not analyzed")
    return {
        "schema": "doc-value.captured.v1",
        "method": "Captured source bytes only; lexical leads, not ratings or deletion decisions",
        "documents": documents,
        "words": sum(row["words"] for row in documents),
        "bytes": sum(row["bytes"] for row in documents),
        "tokensApprox": sum(row["tokensApprox"] for row in documents),
        "exactDuplicates": [names for names in by_hash.values() if len(names) > 1],
        "links": links,
        "scope": {
            "capturedDocuments": len(texts),
            "analyzedDocuments": len(selected),
            "maxDocuments": MAX_DOCUMENTS,
            "maxLinks": MAX_LINKS,
            "linksTruncated": links_truncated,
        },
        "gaps": gaps
        + [
            "Unresolved links may name missing, excluded or uncaptured inputs; inspect before judging",
            "External links, semantic freshness and navigation accuracy are not verified by collection",
        ],
    }
