# PAT user guide

PAT (Project Assessment Toolkit) is a standalone local tool for assessing software projects. The distribution is `pat-assess`; the canonical CLI is `pat`, with `project-assess` retained as an alias. The assessment skill and Python package retain the names `project-assess` and `project_assess`. No AI service is required: the tool collects facts, and a person or optional agent adds evidence-backed judgment. Scans do not execute the assessed repository or assign ratings from file counts.

Each dimension has two independent integer ratings from 0 to 5:

| Dimension | Capability examples | Excess burden examples |
| --- | --- | --- |
| Security | Wide open → basic hygiene → protected boundaries → deliberate defense → defense in depth → Fort Knox ambition | Repeated access friction, duplicated controls, exception administration |
| Testing | No checks → smoke tests → critical paths → dependable suite → broad assurance → exceptional assurance | Flaky suites, slow feedback, brittle fixtures, tests dominating changes |
| Documentation | None → getting started → usable onboarding → architecture and operating guidance → validated references → continuously validated guidance | Stale duplicates, reconciliation work, publication dominating changes |
| Maintainability | Unpredictable changes → basic organization → clear interfaces → cohesive modules → demonstrated change safety → exceptional adaptability | Unnecessary layers, speculative frameworks, duplicated adapters and coordination |
| Delivery | No repeatable path → manual instructions → automated packaging → controlled releases → validated release/recovery → adverse-condition assurance | Slow pipelines, fragile steps, repeated handoffs |
| Operability | No health visibility → logs → useful signals → actionable operation → exercised response → demonstrated resilience | Alert noise, diagnostic complexity and recurring toil |
| Extensibility | Single purpose → local seams → supported APIs/adapters → deliberate extension points → independently authored extensions → sustained external ecosystem | Repeated core edits, brittle contracts, speculative framework machinery and option matrices |

Burden ranges from negligible overhead (0) to practices dominating available engineering effort (5), including justified safeguards. High capability is not penalized. Missing evidence is **unknown**, not zero; a dimension can have known capability and unknown burden. Capability levels 4–5 require validation beyond the presence of configuration files. “Fort Knox ambition” is a rubric label, not a security certification.

The rubric accepts **source estimates** of burden: inspected repeated edit sites, duplicated guidance, coupled fixtures, release gates and runbook steps can establish likely upkeep without time logs. A traced direct implementation with light upkeep can merit burden 1 with low confidence. Set `burden_basis` to `source_estimate`, `observed` or `unknown`, with independent `burden_confidence`; the existing `confidence` applies to capability. The rationale explains the inferred or observed cost and its limits. Counts alone cannot establish burden, and a reviewer should retain unknown when the source or workflow cannot support an estimate. Earlier reviews with numeric burden are treated as low-confidence source estimates; rubric changes start a new comparison series.

Maintainability review challenges whether the architecture fits demonstrated requirements, including complexity accumulated through AI-assisted changes. Static hints identify candidates for inspection, such as trivial delegation layers or speculative plugin/configuration scaffolding; they never assign burden automatically. A useful finding cites a concrete example, its actual need and estimated or observed cost, the simplest viable alternative preserving required contracts, and a bounded next step. Injection, security and isolation boundaries can justify additional structure. Apply the same proportionality judgment to tests, documentation, controls and delivery processes; higher investment is not a universal goal.

**Rigidity** remains a maintainability check: constraints that obstruct valuable changes without protecting a current important outcome. Trace the change, the obstructing test/rule/process, the value or risk protected, and a proportionate simpler alternative. Examples include implementation-detail assertions, unjustified coverage gates and documentation taxes; inspect actual callers before judging. Earlier AI decisions can be revised while preserving current security, durable-data and integration guarantees. Explain static inferences and confidence in the existing assessment; rule counts alone are insufficient.

**Ecosystem fit** is also a named maintainability check, with no separate score. `facts.ecosystem_fit` and `ecosystem-analysis` evidence collect dependency declarations and narrow Python/DOM leads for review. Compare bespoke HTTP/auth/routing/state/cache/validation work with an appropriate maintained library, and oversized framework setup with a simpler utility implementation. Judge actual requirements, exposure, workload, team, lifecycle, security and compatibility; cite a concrete behavior, migration/upkeep cost and smallest useful experiment preserving contracts. Package presence, count or age does not establish quality. Current support, version currency, licenses and vulnerabilities remain unknown offline; verify official sources when researching alternatives. Stack preferences are descriptive context, not global gates. Existing user-selected maintainability capability/burden goals apply; rubric 4 and its seven score scales are unchanged.

Collector 5 records ecosystem evidence version 1 in its collection scope. Older snapshots report this evidence as `not_collected`; rescan to collect it. Progress comparisons require compatible collection scopes, so runs across this scope change are not comparable. Existing ratings and goals remain saved; the new evidence neither re-rates them nor selects new goals.

Rubric 4 adds **extensibility** as the seventh tunable dimension. Establish the needed variation, frequency and authors, then trace a representative extension through supported contracts. Distinguish a missing seam, brittle contract and speculative framework; recommend the simplest adequate seam with proportionate documentation, tests and isolation. A single-purpose project can appropriately target 0. Capability 4–5 needs demonstrated independent extensions and compatibility, not plugin counts. High extensibility and low rigidity can coexist. Earlier reviews and goals retain unconfigured extensibility rather than a zero. Rubric 4 starts a new comparison series; re-rating old evidence is not engineering progress.

## Local workflow

Requires macOS or Linux, Python 3.11+ and uv. From the PAT checkout:

```bash
uv sync --locked
uv run --locked pat --state-dir /path/outside/repos/assessment-state scan /path/to/project
uv run --locked pat --state-dir /path/outside/repos/assessment-state list
uv run --locked pat --state-dir /path/outside/repos/assessment-state report ASSESSMENT_ID --format markdown
uv run --locked pat --state-dir /path/outside/repos/assessment-state doctor ASSESSMENT_ID
uv run --locked pat --state-dir /path/outside/repos/assessment-state evolve ASSESSMENT_ID
uv run --locked pat --state-dir /path/outside/repos/assessment-state evidence ASSESSMENT_ID
uv run --locked pat --state-dir /path/outside/repos/assessment-state rubric
uv run --locked pat --state-dir /path/outside/repos/assessment-state review-template ASSESSMENT_ID
uv run --locked pat --state-dir /path/outside/repos/assessment-state review ASSESSMENT_ID --input /path/outside/repos/review.json
uv run --locked pat --state-dir /path/outside/repos/assessment-state serve
```

Use the URL printed by `serve` to scan a new project path, inspect saved evidence, submit a review, adjust targets and see progress. Saved projects can be scanned again from the project selector. `--port N` chooses a port. State must remain outside assessed roots, so collecting a report does not change the source being measured. Existing test or analysis reports can be supplied through the CLI with repeated `scan --report FILE` options; supplied results retain their evidence limitations.

In the app, open the review editor for the current snapshot, load its template or import review JSON, and fill it using the captured evidence and rubric. Submit explicitly when ready. A rescan needs a review bound to the new snapshot; an old or mismatched review is rejected. Each numeric judgment needs cited evidence; inspection can support a labeled burden estimate without execution or time records.

For the CLI workflow, save the JSON printed by `review-template` to a file outside the assessed repository, fill it, then pass it to `review --input`.

The [project-assess skill](../.agents/skills/project-assess/SKILL.md) guides evidence review and judgment. Its structured review is bound to an assessment ID, source digest and rubric version. It supplies each dimension's scores, confidence, rationale, evidence IDs and recommendations; findings retain separate severity and evidence. Review submission cannot overwrite collected metrics or source identity. Its validation checks structure and provenance, not the truth of an agent's conclusion.

## GitHub badges

`badge ASSESSMENT_ID` exports a saved assessment without running the project or changing its ratings, goals or state. By default it prints a summary SVG to stdout. Choose a destination explicitly; the shell redirection below writes the files:

```bash
mkdir -p docs/badges
uv run --locked pat --state-dir /path/outside/repos/pat-state badge ASSESSMENT_ID \
  > docs/badges/summary.svg
uv run --locked pat --state-dir /path/outside/repos/pat-state badge ASSESSMENT_ID \
  --dimension testing > docs/badges/testing.svg
```

Use `--dimension summary` or any of the seven dimension names. SVG cards label capability and burden separately on their 0–5 scales; cyan and gold distinguish the axes, not good/bad grades. JSON badges retain `Cx/5` and `Bx/5`. Unknown values display `?`. The summary counts a dimension as known only when both scores are numeric. Reported critical/high finding counts include records in the selected snapshot and saved review; they are not an aggregate quality score or proof of absent risks. Unreviewed assessments and partial scans are labeled.

Commit the SVGs and reference them relative to the README on GitHub:

```markdown
![PAT assessment summary](docs/badges/summary.svg)
![PAT testing capability and burden](docs/badges/testing.svg)
```

You can wrap an image in a Markdown link to a report URL you intentionally make public. `--format json` exports the selected badge in the [Shields Endpoint format](https://shields.io/badges/endpoint-badge), with sanitized PAT provenance:

```bash
uv run --locked pat --state-dir /path/outside/repos/pat-state badge ASSESSMENT_ID \
  --dimension testing --format json > docs/badges/testing.json
```

If you host that JSON at a public URL, Shields can render it as an endpoint badge. PAT does not host it or add a service dependency; committed SVGs need neither.

The read-only MCP tool `get_badge(assessment_id, dimension="summary")` returns the same public JSON.

Exports omit private evidence content, rationale and local paths, but publish ratings, assessment date, confidence, burden basis, source revision/digest and assessment metadata. Inspect the artifact before sharing it. Badges reflect the saved assessment and review: they have no live host or automatic review, and only update when regenerated. To reflect changed code, scan and review it first, then export the new assessment. Unknown ratings remain unknown.

## Doctor and Evolve

`doctor ASSESSMENT_ID` groups captured static-analysis candidates into **reuse**, **quality** and **efficiency**, with source locations, evidence references and suggested verification. The Python equivalent is `AssessmentService.doctor(assessment_id)`; the same read-only operation is available over MCP. It reads the saved snapshot without executing or editing the assessed project. An older snapshot without these facts reports `not_collected`; rescan when the additional evidence is wanted.

`evolve ASSESSMENT_ID` returns a focused read-only next-step plan from the snapshot's saved review and selected goals; doctor includes the same orientation under `goal_alignment`. It can recommend `strengthen`, `simplify`, `rebalance` or `maintain`, with gaps and acceptance guidance; gather unknown evidence while keeping known gaps visible, and choose unconfigured targets explicitly. Without selected goals, it recommends their selection and saves nothing. Strengthen one rubric step through the smallest protection or seam addressing a real risk or variant, name acceptance proof and respect the burden ceiling. A simpler interface can increase capability without more layers. The [Evolve guide](../.agents/skills/project-assess/references/evolve-review.md) complements simplification; neither changes scores, goals or source automatically. Changing a target is not engineering progress.

Python AST analysis can identify complex functions, normalized duplicate bodies, dependency-cycle leads and repeated I/O patterns. These are bounded hints, not proof of needless complexity, equivalent behavior or measured runtime cost. When capped, retained candidates share the budget across analysis kinds, source areas and files; totals and omission gaps remain visible. The sample is not an exhaustive list or a priority ranking. Function-local imports may defer dependencies intentionally; repeated checks can protect freshness, authorization or transactions. Supplied Ruff diagnostics retain unverified source identity, including any fix suggestions. Inspect the relevant source and callers before assigning impact, trusting a fix or choosing a score.

For review of recent work, focus on the requested changes. Search existing helpers and references before recommending reuse, then propose the smallest useful change and its closest verifier. Assessment produces advice; separately authorized implementation may apply high-confidence behavior-preserving fixes and validate them. Preserve errors, permissions, transactions and concurrency. The [focused skill guidance](../.agents/skills/project-assess/references/simplify-review.md) supplies review detail without adding a required checklist, line-count target or plugin architecture.

For an owner-requested Python lint pass, run Ruff separately from the PAT checkout and import its JSON afterward:

```bash
uv run --extra dev --locked ruff --version
uv run --extra dev --locked ruff check --isolated --no-cache --select F,B,SIM,PERF,C901 \
  --output-format json --output-file /path/outside/repos/ruff.json /path/to/project
uv run --locked pat --state-dir /path/outside/repos/assessment-state scan /path/to/project --report /path/outside/repos/ruff.json
```

`--isolated` ignores repository configuration. Ruff exits 1 for findings and 2 for abnormal termination; inspect that status instead of masking failures. This pass collects hints without adding new repository gates. See [Ruff configuration](https://docs.astral.sh/ruff/configuration/) and [exit codes](https://docs.astral.sh/ruff/linter/#exit-codes).

Bare JSON does not bind the Ruff version, selected rules/configuration, root, revision or source hashes to the snapshot. An empty report is not a clean-project score. JSON can include fix suggestions with differing safety; inspect applicability and relevant behavior before any authorized change. See [Ruff fix safety](https://docs.astral.sh/ruff/linter/#fix-safety).

JavaScript semantic analysis, type checking, comprehensive security analysis and dependency-vulnerability checks remain evidence gaps. Basic Python AST leads and documentation/test facts do not establish those capabilities.

## Documentation evidence and navigation

Normal `scan` output includes a bounded `documentation-analysis` evidence item
derived from the files the collector already captured. It reports words/bytes,
exact-duplicate groups, local-link leads and collection gaps. These are facts for
review, not an automatic documentation score, burden estimate or deletion plan.

For stale or redundant material, run the generic read-only audit with receipts
outside the assessed root:

```bash
uv run --locked doc-value --root /path/to/project --sections --summary \
  --output /path/outside/doc-value.json
uv run --locked doc-value --root /path/to/project --base BASE_REF \
  --output /path/outside/doc-value-delta.json
```

Run these commands from the PAT checkout (or use installed `doc-value`
commands), not from the assessed project's environment. A `--base` receipt
compares selected raw working-tree bytes with base blobs; it does not reproduce
Git status or rename detection, and records dirty/ambiguous paths as gaps.
Section receipts retain progress, window/pair budgets and skipped, truncated or
uncompared inputs. A missing match is not proof of semantic coverage or accuracy.

Use `doc-value-nav` only when a bounded navigation experiment is useful. Pin the
revision and scope, retain search/read receipts, and compare emitted
`characters`/`tokensApprox` as context-cost estimates (not elapsed time):

```bash
uv run --locked doc-value-nav --root /path/to/project --revision REV \
  --scope docs --receipt /path/outside/doc-nav.jsonl search "question terms" --limit 12
```

Read [the doc-value skill](../.agents/skills/doc-value/SKILL.md) for caller,
section and cleanup guidance. A receipt is usable as assessment evidence only
when its root, revision, selected scope and source hashes match the assessment;
lexical similarity and link reachability do not prove semantic redundancy. The
assessment workflow remains read-only and advisory. Apply edits only with the
owner's explicit cleanup authorization, preserving current authority, security,
recovery, provenance and contractual records.

For Python callers, the same service backs the CLI, local app and MCP adapter:

```python
from project_assess.service import AssessmentService

service = AssessmentService("/path/outside/repos/assessment-state")
snapshot = service.scan("/path/to/project")
report = service.get_report(snapshot["id"])
```

## Test value evidence

The separate `test-value` and `test-value-js` commands collect explicitly selected
tests using the project's environment and analyze their value and overlap. They
run tests only when the owner requests and explicitly invokes collection; `pat scan` remains read-only.

```bash
uv run --locked test-value collect --python /project/.venv/bin/python --root /project --source src --output /outside/test-run -- tests/test_feature.py
uv run --extra test-value --locked test-value compare --root /project --output /outside/comparison --evidence /outside/js-run/evidence.json --pytest-report /outside/test-run/report.json --pytest-coverage /outside/test-run/.coverage
uv run --locked pat --state-dir /outside/assessment-state scan /project --report /outside/test-run/report.json --report /outside/comparison/report.json
```

Pytest collection uses the selected interpreter's existing pytest, pytest-cov and
coverage.py. The optional `test-value` extra supplies coverage.py for analysis;
it does not install project test dependencies. JavaScript/TypeScript collection
uses an explicit existing Vitest or Node runner. See the
[test-value skill](../.agents/skills/test-value/SKILL.md) for exact-case selection,
batch/resume, runner options and import formats.

Imported reports retain bounded counts, cost/phase and attribution summaries,
source identity, provenance and gaps. Reported health and overlap remain supplied
claims, separate from source-identity verification and reviewer ratings. Missing
or stale evidence cannot establish coverage, equivalent assertions or safe test
removal. JSON test-value reports have separate 16 MiB per-file and 64 MiB combined
limits; source and XML limits are unchanged. Keep reports and state outside the
assessed project.

## Goals and progress

Goals use a **capability minimum** and **burden ceiling** per dimension. Select a suggested profile or save custom values; a scan never chooses goals for you.

| Profile | Security | Testing | Documentation | Maintainability | Delivery | Operability | Extensibility | Burden ceiling, all dimensions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `local-experiment` | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 1 |
| `internal-service` | 2 | 2 | 2 | 2 | 2 | 2 | 0 | 2 |
| `public-production` | 3 | 3 | 2 | 3 | 3 | 3 | 0 | 2 |
| `sensitive-critical` | 4 | 4 | 3 | 3 | 4 | 4 | 0 | 3 |
| `framework` | 3 | 3 | 3 | 3 | 3 | 2 | 4 | 2 |

The framework or library preset is optional and editable. The risk-oriented presets impose no minimum extensibility: choose its target from actual variation needs, independently of security sensitivity. A target of 0 means no minimum requirement, not a claim of zero observed capability. A scan never saves a profile automatically.

For example:

```bash
uv run --locked pat --state-dir /path/outside/repos/assessment-state targets PROJECT_ID --profile local-experiment --expected-revision 0
uv run --locked pat --state-dir /path/outside/repos/assessment-state progress PROJECT_ID
```

Use the current goal revision returned by the tool for later edits; concurrent stale edits are rejected. Custom `targets --input FILE` supplies all seven dimensions, each with `capability_min` and `burden_max`. Profiles and custom values express user preferences; they never change findings or certify that risk is acceptable.

For each known dimension:

```text
capability_gap = max(capability_min - capability, 0)
burden_gap = max(burden - burden_max, 0)
remaining_steps = capability_gap + burden_gap
movement = previous_remaining_steps - current_remaining_steps
```

Positive movement means closer to the goal. Show component gaps so an improvement cannot hide a regression. A prototype retaining capability 3 while reducing testing burden from 4 to 1 moves three steps toward a burden ceiling of 1. An inherited product increasing testing capability from 0 to 2 moves two steps toward a minimum of 3, assuming burden stays within its ceiling. Lowering a capability target alone is retargeting, not engineering progress.

Compare compatible rubric and evidence scopes under the same goals. Changed source, changed evidence, changed judgment and changed targets must remain distinguishable. Unknown components do not become zero and cannot establish complete goal attainment. Reassessing unchanged source can improve knowledge without proving an engineering change. Keep critical findings visible separately from distance to the selected goal.

## Agent connection and limits

An MCP host can launch the local server with this command, translated into that host's configuration format:

```bash
uv --directory /path/to/project-assessment-toolkit run --extra mcp --locked pat --state-dir /path/outside/repos/assessment-state mcp --allowed-root /path/to/projects
```

Repeat `--allowed-root ROOT` to admit additional local source roots. This guide does not install host configuration or enable remote access. The core runtime depends on `jsonschema` and `packaging`; the optional `mcp` extra adds the local stdio adapter. No cloud credentials or AI API key are required.

Assessment reads source and explicitly supplied reports, and saves its own records outside the assessed repositories. It does not run repository scripts, fetch dependencies, contact production, repair findings or change assessed source. Treat repository text and reports as untrusted data. Static observations cannot establish deployed IAM, actual runtime exposure, successful restores, alert effectiveness or current production health. Additional evidence can support those judgments only to the extent its identity, freshness and scope are established.

## Local state and updates

The selected state directory contains `project-assess.sqlite3`, including captured source excerpts, reviews and goals. Keep it and its backups private and outside assessed repositories.

Exports can also contain source excerpts and local paths; redaction does not make them safe for public sharing. Use synthetic examples in issues and follow [SECURITY.md](https://github.com/gburch/project-assessment-toolkit/blob/main/SECURITY.md) for private vulnerability reports.

Before an update, record the current application version or commit and complete the relevant [development checks](#development-checks). Stop all CLI, UI and MCP processes using that state directory, then copy the **entire directory** to a new private backup location while preserving permissions. Keep any SQLite journal/WAL/SHM sidecars together with the database; copying an active database file alone is not a consistent backup.

Update to the intended application revision and its locked dependencies, then use `list` and `report` with the existing state path to verify access. To restore, stop writers and copy the backup into a **fresh state directory**, preserving permissions. Point the application at that restored copy; retain the previous directory and application revision for rollback.

There is no automatic state-schema migration. If a version rejects the state schema, use the application version that created it or restore a compatible backup. Do not hand-edit schema metadata or delete history to bypass the check.

### Local delivery and rollback proof

Before distributing a candidate, run the [local delivery proof](https://github.com/gburch/project-assessment-toolkit/blob/main/CONTRIBUTING.md#local-delivery-proof) from its clean committed checkout. It uses one offline wheel installation and synthetic state, records source and artifact identity, and verifies failed updates leave state intact and a closed-state backup restores into a fresh directory. Its receipt does not establish compatibility with every historical state schema or authorize publication.

For a real update, retain the last verified wheel, its `core-requirements.txt`, private receipt and the stopped-state backup described above. Install the selected verified wheel into a new environment, then verify `list` and `report` against the intended state. To roll application code back, use the earlier verified artifact and its matching constraints:

```bash
uv venv --offline /path/outside/repos/pat-rollback
uv pip install --offline --python /path/outside/repos/pat-rollback/bin/python \
  --constraint /path/to/prior-proof/core-requirements.txt /path/to/prior-proof/dist/VERIFIED_WHEEL.whl
/path/outside/repos/pat-rollback/bin/pat --state-dir /path/to/fresh-restored-state list
```

Restore the complete stopped-state backup into that fresh state directory before the last command; keep the later state and application environment for investigation. Use an artifact compatible with the backup's schema. This is a manual local rollback, with no automatic migration or provider operation.

For common problems:

- **UI reports a generic failure:** use `list` or `report ASSESSMENT_ID` from a terminal with the same `--state-dir` to inspect local errors. Check directory permissions and that the original source root remains accessible and permitted by any MCP allowed roots.
- **Database locked:** stop competing processes using that state directory, then retry. Preserve database sidecars.
- **Goals changed elsewhere:** reload the report, review the current goals and save with the returned revision.
- **Project missing:** confirm the state path. Saved reads recheck the original source root, so moved/deleted roots or narrower MCP permissions can make an existing record inaccessible.

## Development checks

See [CONTRIBUTING.md](https://github.com/gburch/project-assessment-toolkit/blob/main/CONTRIBUTING.md) for Python, Ruff, browser and skill checks. The guide above uses the core runtime; add the optional `mcp` extra when connecting an MCP host.
