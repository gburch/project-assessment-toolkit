# Existing observations

Use `scan ROOT --report FILE.json` to import already available workload, recovery, delivery, change-cost, security or extension evidence. Importing a report never runs a benchmark, provider, migration, restore, project dependency or script. No new observation is required merely to assess a small project.

The `pat.observation.v1` contract accepts only the fields below. Save the report outside the assessed project and configure allowed roots to include it when applicable. Use captured source records for real revision and file digests; illustrative hashes below must be replaced.

```json
{
  "schema": "pat.observation.v1",
  "type": "performance",
  "observed_at": "2026-10-31T12:00:00-04:00",
  "source": {
    "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "files": [
      {"path": "src/app.py", "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
    ]
  },
  "scenario": {"name": "Representative local workload", "scope": ["src/app.py"]},
  "results": [{"name": "p95", "value": 14.2, "unit": "ms", "status": "observed"}],
  "limitations": ["Supplied local measurement; environment and execution not independently verified"]
}
```

`type` is `performance`, `recovery`, `delivery`, `change_cost`, `security` or `extensibility`. Results contain finite numbers or booleans, a name/unit, and `observed`, `passed`, `failed` or `inconclusive` status. The timestamp requires a timezone. Limitations must be nonempty. Raw logs, arbitrary attachments, unknown fields, duplicate/escaping paths and nonfinite values are rejected. Scenario paths must be included in the declared source-file set.

Source matching requires the captured revision and every declared file digest to match. A null/unavailable revision leaves identity unverified; changed hashes/revisions produce mismatch. The retained `sourceIdentity` lists declared/captured revisions and per-file status. This binding covers the declared files, not the whole runtime environment or undisclosed inputs.

Treat all measurements, author identity, timestamp and execution as supplied claims. A matched report can still have an irrelevant scenario, stale environment, weak oracle or misleading metric. Inspect its scope against the exact rubric proposition; source matching and `passed` labels never automatically raise a score or confidence. Report an assessment update separately from source improvement or goal changes.
