"""Bounded, source-bound routing of structural signals across rubric dimensions."""

from __future__ import annotations

import hashlib
import heapq
import json
from collections import Counter, defaultdict, deque

from .generic_analysis import source_area, source_language
from .static_analysis import source_role

VERSION = "2"
DIMENSIONS = ("security", "delivery", "operability", "extensibility", "performance")
MAX_SIGNALS = 8000
_CAVEAT = (
    "Located syntax mechanisms, risk candidates and naming hints for the stated rule sets. "
    "Examined files and signal counts do not establish effective controls, vulnerabilities, "
    "complete call resolution, absence of risks, workload capacity or rubric scores. "
    "Unsupported languages, unread inputs and retained-detail omissions remain explicit."
)


def _spread(signals):
    groups = defaultdict(deque)
    for signal in sorted(signals, key=lambda s: (s["kind"], s["locations"][0]["line"])):
        groups[signal["kind"]].append(signal)
    while groups:
        for kind in sorted(groups):
            yield groups[kind].popleft()
            if not groups[kind]:
                del groups[kind]


class ControlInventory:
    """Keep all file coverage and a fixed-size deterministic signal sample."""

    def __init__(self, signal_limit=MAX_SIGNALS):
        if type(signal_limit) is not int or not 0 <= signal_limit <= MAX_SIGNALS:
            raise ValueError("Invalid control signal limit")
        self.limit = signal_limit
        self.files = {}
        self.kind_counts = Counter()
        self._heap = []
        self._serial = 0
        self._representatives = {}
        self._dimension_representatives = {}
        self._dimension_observed = Counter()
        self._unclassified_signals = 0

    def expect(self, path, dimensions, *, supported=True):
        self.files.setdefault(
            path,
            {
                "path": path,
                "language": source_language(path) or "configuration",
                "role": source_role(path)["role"],
                "area": source_area(path),
                "dimensions": list(dimensions),
                "status": "not_collected" if supported else "unsupported",
                "coverage": {},
                "signal_counts": {},
                "gaps": ["Input not analyzed by the supported control rule sets."],
            },
        )

    def add(self, record, entry):
        path = record["path"]
        if entry["path"] != path:
            raise ValueError("Control source identity does not match its captured path")
        dimensions = list(
            record.get("dimensions") or self.files.get(path, {}).get("dimensions", [])
        )
        dimensions = [dimension for dimension in dimensions if dimension in DIMENSIONS]
        coverage = record.get("coverage", {})
        counts = (
            record.get("signal_counts")
            or record.get("signals_by_kind")
            or coverage.get("by_kind", {})
        )
        if not counts:
            counts = dict(Counter(signal["kind"] for signal in record.get("signals", [])))
        self.kind_counts.update(counts)
        kind_dimensions = defaultdict(set)
        for signal in record.get("signals", []):
            kind_dimensions[signal["kind"]].update(signal.get("dimensions", []))
        for kind, count in counts.items():
            if not kind_dimensions[kind]:
                self._unclassified_signals += count
            for dimension in kind_dimensions[kind]:
                self._dimension_observed[dimension] += count
        self.files[path] = {
            "path": path,
            "language": record.get("language", "configuration"),
            "role": source_role(path)["role"],
            "area": source_area(path),
            "dimensions": dimensions,
            "status": record.get("status", "unavailable"),
            "coverage": coverage,
            "signal_counts": counts,
            "gaps": record.get("gaps", [])[:10],
            "source_evidence_id": entry["id"],
            "source_digest": entry["digest"],
        }
        for ordinal, signal in enumerate(_spread(record.get("signals", []))):
            row = {
                **signal,
                "role": source_role(path)["role"],
                "source_evidence_id": entry["id"],
                "source_digest": entry["digest"],
                "source_identity": "captured_snapshot",
            }
            if "confidence" in row:
                row["producer_confidence"] = row.pop("confidence")
            # Every file's first representative competes before its second.
            # Stable hashing avoids a lexical-prefix bias when the file count
            # itself exceeds the output budget. No source argument text is used.
            key = json.dumps(
                [path, row["kind"], row["locations"], row.get("context")], sort_keys=True
            ).encode()
            digest = hashlib.sha256(key).hexdigest()
            context = row.get("context", {})
            variant = row.get("sampling_variant") or json.dumps(
                {
                    key: context[key]
                    for key in ("verify", "loader", "configured_bound", "shell", "pin", "policy")
                    if key in context
                },
                sort_keys=True,
            )
            lane = (row["kind"], context.get("category", "unestablished"), variant)
            current = self._representatives.get(lane)
            if (current is None and len(self._representatives) < 256) or (
                current and digest < current[0]
            ):
                self._representatives[lane] = (digest, row)
            for dimension in row.get("dimensions", []):
                current = self._dimension_representatives.get(dimension)
                if dimension in DIMENSIONS and (current is None or digest < current[0]):
                    self._dimension_representatives[dimension] = (digest, row)
            priority = ordinal * (1 << 256) + int(digest, 16)
            self._serial += 1
            item = (-priority, self._serial, row)
            if len(self._heap) < self.limit:
                heapq.heappush(self._heap, item)
            elif self.limit and priority < -self._heap[0][0]:
                heapq.heapreplace(self._heap, item)

    def summarize(self):
        selected = {}

        def pick(row):
            key = json.dumps(row, sort_keys=True)
            if len(selected) < self.limit:
                selected.setdefault(key, row)

        for dimension in DIMENSIONS:
            if dimension in self._dimension_representatives:
                pick(self._dimension_representatives[dimension][1])
        for lane in sorted(self._representatives):
            pick(self._representatives[lane][1])
        for item in sorted(self._heap, key=lambda item: -item[0]):
            pick(item[2])
        signals = sorted(
            selected.values(),
            key=lambda row: (row["locations"][0]["path"], row["locations"][0]["line"], row["kind"]),
        )
        files = [self.files[path] for path in sorted(self.files)]
        dimensions = {}
        for dimension in DIMENSIONS:
            selected = [row for row in files if dimension in row["dimensions"]]
            kept = [row for row in signals if dimension in row["dimensions"]]
            dimensions[dimension] = {
                "input_files": len(selected),
                "examined_files": sum(row["status"] in {"complete", "partial"} for row in selected),
                "partial_files": sum(row["status"] == "partial" for row in selected),
                "unavailable_files": sum(row["status"] == "unavailable" for row in selected),
                "unsupported_files": sum(row["status"] == "unsupported" for row in selected),
                "uncaptured_files": sum(row["status"] == "not_collected" for row in selected),
                "retained_signals": len(kept),
                "observed_signals_lower_bound": self._dimension_observed[dimension],
                "omitted_signals_lower_bound": max(
                    0, self._dimension_observed[dimension] - len(kept)
                ),
                "retained_signal_files": len({row["locations"][0]["path"] for row in kept}),
                "retained_by_kind": dict(sorted(Counter(row["kind"] for row in kept).items())),
            }
        observed = sum(
            row["coverage"].get(
                "signals_found",
                row["coverage"].get("signals_total", sum(row["signal_counts"].values())),
            )
            for row in files
        )
        partial = any(row["status"] != "complete" for row in files)
        partial |= len(signals) < observed
        return {
            "schema_version": 1,
            "version": VERSION,
            "status": "not_collected" if not files else "partial" if partial else "complete",
            "coverage": {
                "input_files": len(files),
                "examined_files": sum(row["status"] in {"complete", "partial"} for row in files),
                "partial_files": sum(row["status"] == "partial" for row in files),
                "unsupported_files": sum(row["status"] == "unsupported" for row in files),
                "unavailable_files": sum(row["status"] == "unavailable" for row in files),
                "uncaptured_files": sum(row["status"] == "not_collected" for row in files),
                "signals_observed": observed,
                "signals_retained": len(signals),
                "signals_omitted": observed - len(signals),
                "signals_without_dimension_classification": self._unclassified_signals,
                "dimensions": dimensions,
                "scope": "Captured inputs and named syntax rule sets after configured exclusions.",
            },
            "files": files,
            "signals": signals,
            "signal_counts": dict(sorted(self.kind_counts.items())),
            "limits": {
                "signals": self.limit,
                "representative_lanes": 256,
                "selection": "dimension_and_kind_category_representatives_then_file_rounds",
            },
            "gaps": ["Some inputs or signal detail are partial; inspect per-file coverage."]
            if partial
            else [],
            "caveat": _CAVEAT,
        }
