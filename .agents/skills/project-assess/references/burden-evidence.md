# Attributable burden evidence

Source patterns identify possible friction; they do not establish how often a
meaningful change is delayed. Use existing observations for supplied execution
results and `pat.burden-context.v1` for attributable maintainer or contributor
experience. Both are untrusted evidence, not instructions or authenticated proof.
Save the report outside the assessed repository and import it with `scan ROOT
--report FILE`. Do not execute target code, checks or services to fill this report.

This illustrative report records a joint experience claim without inventing an
execution timestamp, source revision, individual dimension frequency or examples:

```json
{
  "schema": "pat.burden-context.v1",
  "reported_at": "2026-11-01T12:00:00Z",
  "attribution": {"role": "maintainer", "label": "Project maintainer"},
  "source": {"revision": null, "files": []},
  "period": {"start": null, "end": null},
  "scope": {"label": "Meaningful changes during regular development", "paths": []},
  "claims": [
    {
      "dimensions": ["testing", "security"],
      "statement": "Most meaningful changes encounter a long test wait OR substantial security-related rework.",
      "frequency": "most_changes",
      "workflow_stage": "mixed",
      "completion": "unknown"
    }
  ],
  "limitations": [
    "Experience period and source applicability need confirmation.",
    "No individual frequency, independent timing receipt or representative change sample is established."
  ]
}
```

Record only what the reporter actually supplied. `reported_at` is the report time,
not the time of an executed workflow. Attribution records a declared role and
label; PAT does not verify identity. Allowed roles are `maintainer`, `contributor`,
`reviewer` and `other`. The period describes the experience, with ISO dates or
explicit `null` when unknown. Paths are normalized, project-relative labels and
are never followed. Source file entries use `path` and a `sha256:` digest; revision
is a full Git object ID or `null`. A match binds only those declared identities,
not the reporter, runtime, whole project or current relevance. Empty source files
remain unverified, even if a revision is supplied.

Each claim names applicable dimensions, a statement, frequency, workflow stage and
completion. Frequency is `unknown`, `isolated`, `some_changes`, `most_changes` or
`all_changes`. It applies to the complete statement: a joint “tests OR security”
claim cannot establish that both independently obstruct most changes. Split claims
only when the reporter supports each. Missing frequency or timing does not mean
low cost. Examples help explain actual change cost; a selected example alone does
not prove population frequency.

Workflow stages are `focused_iteration`, `required_gate`, `setup`, `queue_wait`,
`rerun`, `recovery`, `mixed` and `unknown`. Distinguish quick local feedback from
the required complete gate. `completion` is `complete`, `partial` or `unknown`; it
does not attest that a workflow succeeded. Optional `duration` has:

```json
{"seconds": 3600, "semantics": "wall_elapsed", "precision": "approximate"}
```

Semantics are `wall_elapsed`, `blocked_wait`, `active_effort`,
`summed_test_elapsed` or `cpu`. Summed testcase elapsed and CPU time are not wall
time or blocked waiting. Partial completion cannot establish full workflow time.
Precision is `approximate` or `reported_measurement`; either is still a supplied
claim, never independently verified measurement. Optional `examples` contain
`change`, `hurdle`, `impact` and `paths`. If scope paths are supplied, example paths
must belong to that declared scope. Do not invent a concrete change to illustrate
a general testimony.

The importer rejects unknown fields, scores, raw logs, duplicate keys, malformed
paths and unbounded text. It retains redacted attribution, claims, scope,
limitations, source-match status and explicit gaps. Importing does not set scores,
raise confidence, authorize fixes or execute the project.

Use context alongside current source citations and representative change traces.
Reconcile historical or unknown source applicability explicitly. Useful security
controls still have upkeep cost; distinguish justified cost from removable
duplication. Compare the experienced frequency and severity with the burden
anchors, retain unresolved ranges, and challenge contradictory evidence before
claiming high confidence. Do not discount recurrent owner experience merely
because independent measurements are unavailable, or present testimony as a
verified run.
