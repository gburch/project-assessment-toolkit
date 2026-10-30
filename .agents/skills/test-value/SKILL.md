---
name: test-value
description: Reduce test maintenance and runtime using risk, coverage, and test value across pytest, JavaScript/TypeScript, and automation layers. Use for pruning, overlap audits, or reviewing test growth; protect critical behavior without chasing percentages.
---

# Test value

Optimize for less test code and execution cost while protecting important user
outcomes. A unique executed line, a historic assertion, or an imaginable bug does
not by itself justify keeping a test.

Use roughly **70% as a soft planning target for ordinary code**. Above that point,
additional tests need a practical risk justification. This is neither a mandatory
minimum nor a maximum: do not add tests just to reach it or delete valuable tests
just to get below it. State the measured source/test scope and denominator; a
small cohort is not repository-wide coverage.

## Protect what matters

Identify critical behavior from its callers and effects: authorization, credentials,
provider writes, destructive operations, durable-data integrity, and costly known
regressions. Keep meaningful allowed/denied and recovery proofs at the real boundary.
A test using a database, restarting a fixture, or touching a file is not automatically
critical. Read-only presentation, cosmetic geometry, convenience wrappers, and
defensive permutations may accept lower coverage.

## Audit and prune

PAT owns the canonical helpers in `project_assess.test_value`. Use the
`test-value` and `test-value-js` commands from an installed package or the PAT
checkout (`uv run`). This skill's scripts are thin entry wrappers that also run
with a project's Python 3.11+. Pytest
collection uses the project's pytest, pytest-cov, and coverage.py. Reporting imports
no target application. Preserve the project's runner configuration and dependency
files; missing optional instrumentation can use a separate measurement environment.
`collect` runs pytest; `report` reuses its artifacts.

Before each new audit batch, refresh PAT from its upstream main and use the
current installed build or checkout. Record that revision and keep it fixed for
the invocation; refresh again before final review. Do not overwrite concurrent
work or mix artifacts from different tool versions silently.

Start broad and cheap with a source inventory, then measure selected leads:

```sh
test-value inventory --root /path/to/project --scope tests --scope src \
  --scope frontend/src --output /path/outside/static-inventory.json
```

The bounded inventory indexes Python bodies, literal test matrices, assertion
patterns and possible expensive setup. JavaScript/TypeScript registrations and
matrices are lexical leads with lower confidence. It imports no application code.
Inspect gaps and dynamic counts; repeated bodies may bind different helpers and
are never deletion proof. Use the existing project assessment for broader source
and documentation facts, and `doc-value` for section duplication, local links and
callers. Run only the project's relevant configured static checks (for example
Ruff/MyPy or ESLint/TypeScript) during an authorized cleanup. Reuse installed
tools and narrow their scope; do not install a scanner collection or execute
repository-defined scripts as part of a read-only assessment.

```sh
test-value collect --python /path/to/project/.venv/bin/python \
  --root /path/to/project --source src/package --soft-target 70 \
  --output /path/to/private/run -- tests/test_feature.py
test-value report \
  --root /path/to/project --coverage /path/to/private/run/.coverage \
  --tests /path/to/private/run/tests.json --output /path/to/private/report
```

Use repeatable `--critical 'src/package/auth/*'` source globs and
`--protect-test '*::test_provider_write*'` node-ID globs for project-specific
protection. `report` inherits collection policy unless flags override it.
Configure these designations explicitly for each project. Narrow
source scope to exclude pytest hooks and instrumentation. Match test identities
conservatively; incomplete runs, ambiguous timing, contextless data, and unmeasured
child/browser effects are evidence gaps. Proposals remain advisory.

For larger selections, add `--batch-size 20` to `collect` with explicit test
files or node IDs. It runs sequential batches and combines their evidence before
ranking overlap across batches. After the collector exits, resume with the
**same command plus `--resume`**;
keep the original source, selection, policy, tool, and environment. Successful
compatible batches are reused; failed or incomplete attempts remain visible.
Changed inputs require a new output directory. Inspect aggregate health and gaps
before using recommendations; completed batches alone do not prove a complete run.
Reports are compact by default. Use `report --detail` when expanded per-test
footprints are needed; the bound raw coverage remains available for drill-down.

### Campaign loop

When the owner requests continued pruning, treat that request as authorization
to keep applying the remaining bounded selection; do not stop after one small
group or wait for a separate “next” prompt. Keep a compact external queue in the
existing handoff or artifact metadata, with one row per file/family: source
identity, selection, disposition (`retain`, `consolidate`, `remove`, or
`investigate`), reason, and next evidence. Refresh the queue after each accepted
batch so interrupted work resumes without rescanning completed groups.

Prioritize measured runtime and setup cost, then large local parameter matrices
and repeated bodies. Use bounded parallel owners for independent files, combine
several compatible groups into one candidate before the independent review and
final project gate, and continue through pending queue rows while useful,
evidence-backed work remains. Keep critical paths protected and make the number
and identity of unreviewed files visible. Stop only when the queue is exhausted,
remaining work has no justified benefit, or a concrete evidence/authority block
needs the owner. This is a foreground workflow: it adds no scheduler, daemon,
mandatory interface, deletion quota, or coverage target.

For JavaScript/TypeScript, use `test-value-js --runner vitest`
or `--runner node-test` with an existing `--command`, explicit test files, `--source`,
`--root`, and a new `--output`. Use `--cwd` for a configured subproject and
`--coverage` to measure it. `--test-name` selects an exact case; attribution requires
the results to prove exactly one successful executed case. Its footprint includes
imports and hooks; it is not pytest call-only coverage. Broader runs remain aggregate.
Preserve command-specific project options with repeatable `--runner-arg=OPTION`.

Compare layers with `test-value compare --root PROJECT --output NEW
--evidence RUN/evidence.json --evidence OTHER/evidence.json`. It also imports
Istanbul JSON, LCOV, Cobertura, and compatible pytest reports with their raw coverage.
Read [the report contract](references/report-contract.md) for import binding and gaps.
Only exact source paths, hashes, and compatible coordinates establish measured
overlap. Keep branch models distinct. Generated browser bundles need verified
original-source mapping; parent coverage does not prove browser or child effects.
Optional `behaviorRefs` express reviewed relationships across languages, never
automatic equivalence. Do not combine these into a single product-coverage percentage.

Rank near-overlap, marginal **important** behavior, test-source size, repeated
setup, and measured runtime. Include low-risk tests with some unique coverage;
do not require identical footprints or unchanged line/branch unions. Prefer a
small representative set and whole-outcome integration proofs over field-by-field
assertions, exhaustive ordinary enum cases, wrapper checks, and cosmetic snapshots.

Before editing, name the retained important outcome and the ordinary risk accepted.
Use targeted fault controls for the named critical failure classes when needed;
do not invent a special-case mutation for every removed input. Compare the same
real selection before/after, without coverage instrumentation when claiming
runtime savings. Report net test lines and comparable runtime, not
just fewer parameter IDs. A passing reduced suite alone proves no equivalence.

For an PAT assessment, import completed JSON reports through
`pat --state-dir STATE scan PROJECT --report REPORT`. Assessment scans
never execute tests. Imported health, overlap and pruning fields are supplied
claims; inspect source-identity status and gaps before citing them in a testing
capability/burden review. Do not turn coverage percentages into ratings.

## Review additions

The existing independent reviewer asks: which practical failure does this new test
protect, how likely/costly is it, and why is existing coverage insufficient? Prefer
extending a useful test. Unsupported growth or loss of critical protection blocks
approval; loss of low-value incidental coverage does not.

Keep evidence in tool artifacts, the existing PR description, or an existing
handoff. Add no standalone audit documents or extra review stages. Follow the
project's execution, privacy, and release gates; change no global coverage gate.
