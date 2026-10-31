"""Fixed local collection profiles; target repositories cannot configure them."""

from collections import deque
from dataclasses import asdict, dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class AnalysisBudget:
    name: str
    supported_text_bytes: int
    unsupported_asset_bytes: int
    deadline_seconds: int
    pattern_functions: int
    pattern_functions_per_file: int
    import_targets: int
    generic_blocks: int
    metric_nodes_per_file: int

    def as_dict(self):
        return asdict(self)


PROFILES = MappingProxyType(
    {
        "standard": AnalysisBudget(
            "standard", 64 * 1024 * 1024, 16 * 1024 * 1024, 120, 20_000, 64, 20_000, 40_000, 200_000
        ),
        "deep": AnalysisBudget(
            "deep",
            256 * 1024 * 1024,
            16 * 1024 * 1024,
            300,
            60_000,
            256,
            100_000,
            120_000,
            1_000_000,
        ),
    }
)


def get_budget(profile: str) -> AnalysisBudget:
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError("analysis_profile must be standard or deep")
    return PROFILES[profile]


def pattern_allocations(records, budget):
    """Reuse spare slots across actual demand, favoring production and risky modules."""
    allocations = {
        row["path"]: row["module"].get("pattern_functions", len(row["functions"]))
        for row in records
    }
    remaining = max(0, budget.pattern_functions - sum(allocations.values()))
    queues = {role: deque() for role in ("production", "test", "tooling", "unknown")}
    needs = {}
    for row in sorted(
        records,
        key=lambda row: (
            -max((function.get("decisions", 0) for function in row["functions"]), default=0),
            row["path"],
        ),
    ):
        demand = min(
            row["module"]["function_count"],
            budget.pattern_functions_per_file,
            row["module"].get("pattern_function_limit", 1000),
        )
        if demand > allocations[row["path"]]:
            needs[row["path"]] = demand
            queues.get(row.get("role"), queues["unknown"]).append(row["path"])
    while remaining and any(queues.values()):
        for role in ("production", "production", "test", "tooling", "unknown"):
            if not remaining or not queues[role]:
                continue
            path = queues[role].popleft()
            allocations[path] += 1
            remaining -= 1
            if allocations[path] < needs[path]:
                queues[role].append(path)
    return allocations
