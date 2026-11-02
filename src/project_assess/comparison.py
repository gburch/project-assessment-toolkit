"""Shared comparison semantics for progress and snapshot presentation."""


def compare_assessments(baseline, current, baseline_review, current_review, first_review):
    """Distinguish source movement from changes in evidence; unknowns fail closed."""
    comparable = all(
        isinstance(baseline.get(key), str)
        and bool(baseline[key])
        and baseline[key] == current.get(key)
        for key in ("rubric_version", "scope_digest")
    ) and all(
        snapshot.get("complete") is True
        and isinstance(snapshot.get("source", {}).get("manifest_digest"), str)
        and bool(snapshot["source"]["manifest_digest"])
        for snapshot in (baseline, current)
    )
    if not comparable:
        return {"comparable": False, "event": "not_comparable"}
    same_source = baseline["source"]["manifest_digest"] == current["source"]["manifest_digest"]
    same_review = (current_review or {}).get("id") == (baseline_review or {}).get("id")
    if baseline["id"] == current["id"] and same_review:
        event = "goal_baseline"
    elif same_source or (current_review or {}).get("id") != (first_review or {}).get("id"):
        event = "evidence_update"
    else:
        event = "source_change"
    return {"comparable": True, "event": event}
