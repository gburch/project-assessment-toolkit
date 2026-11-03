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

`type` is `performance`, `recovery`, `delivery`, `change_cost`, `security`, `extensibility` or `prompting`. Results contain finite numbers or booleans, a name/unit, and `observed`, `passed`, `failed` or `inconclusive` status. The timestamp requires a timezone. Limitations must be nonempty. Raw logs, arbitrary attachments, unknown fields, duplicate/escaping paths and nonfinite values are rejected. Scenario paths must be included in the declared source-file set.

A `prompting` observation also needs a `prompting` object with `input_digest` and `configuration_digest` (SHA-256 identities for the repeated input/instructions and model/settings/tool configuration), `trials` (at least 2), `distinct_outputs` (1 through the trial count), `comparison` (`exact` or `semantic`) and a nonempty `criterion` explaining normalization or the semantic bound. Do not include prompt bodies, credentials or raw outputs. For an authored bounded-variation claim, include a `within_criterion` result with boolean `true` and status `observed` or `passed`. Exact repeatability requires exact comparison and one distinct output; observed variation requires more than one distinct output. The supplied scenario must overlap the cited workflow. These are reported observations, not authenticated execution or guarantees beyond that scenario. Source-only contracts or a single unrelated metric cannot establish repeatability. Assessments do not run the trials or require a new evaluation suite.

Source matching requires the captured revision and every declared file digest to match. A null/unavailable revision leaves identity unverified; changed hashes/revisions produce mismatch. The retained `sourceIdentity` lists declared/captured revisions and per-file status. This binding covers the declared files, not the whole runtime environment or undisclosed inputs.

Treat all measurements, author identity, timestamp and execution as supplied claims. A matched report can still have an irrelevant scenario, stale environment, weak oracle or misleading metric. Inspect its scope against the exact rubric proposition; source matching and `passed` labels never automatically raise a score or confidence. Report an assessment update separately from source improvement or goal changes.
