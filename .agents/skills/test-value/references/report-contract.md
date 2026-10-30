# Audit report contract

The portable helper emits a versioned JSON report and a human-readable Markdown
summary. Reports should retain enough provenance to reproduce the observation:

- repository root, source scope, revision when available, selected targets, and
  Python/pytest/coverage versions;
- every raw pytest node ID and its outcome, duration, and setup/call/teardown
  phase data;
- bound raw line/branch contexts, stable per-test signatures, phase counts and
  unique line/arc evidence; compact reports avoid repeating full footprints;
- unmatched JUnit or coverage contexts, ambiguous joins, failed collection, and
  warnings about subprocess/native/browser coverage;
- ranked overlap and low-marginal-coverage candidates, estimated test-source
  size, phase costs, and unique lines/arcs for risk review;
- project-supplied critical source/test patterns, the soft ordinary-code target,
  executable-statement denominators, and an advisory representative set.

Batch collection keeps its original selection, partition and input identity in
`manifest.json`, preserves individual attempts, and produces one combined report.
Only compatible successful batches can contribute healthy aggregate evidence;
missing, failed, duplicate or mismatched measurements remain explicit gaps.
Resume repeats the original command with `--resume`. Raw coverage remains the
drill-down evidence; aggregate health does not make pruning automatic.

The analyzer emits `investigate` candidates only. `retain`, `consolidate`, and
`remove` are reviewer dispositions, recorded after inspecting the candidate's
assertions and behavior. Record retained important protection and accepted
ordinary risk. Use targeted negative controls where critical failure protection
is uncertain. Incidental unique coverage need not be preserved; overlap alone
does not establish equivalent assertions. The soft target is neither a global
coverage ceiling nor an instruction to add tests to reach a percentage.

## Other runners and cross-layer comparison

`scripts/test_value_multilayer.py` collects Vitest JSON with the installed V8
provider, or native `node:test` JUnit and LCOV. `--root` is the repository;
`--cwd` selects its configured subproject. `--config` names the runner config
first and any additional files to hash afterward. `--layer` labels the measured
layer. Use explicit file targets and a new output directory.

`--test-name` escapes and anchors an exact full name. Only one successful executed
case with stable inputs and complete results can receive its invocation footprint.
Skipped cases receive none. Without that proof, coverage remains at file/suite
level. JavaScript invocation coverage includes imports and hooks; the collector
records that its setup/call/teardown phases are not split.

`test_value_audit.py compare` accepts repeatable `--evidence` paths. Optional
`--pytest-report` and `--pytest-coverage` add compatible Python evidence. Istanbul,
LCOV, and Cobertura imports preserve suite-level observations; bare files lack
collection-time source hashes and test attribution. A normalized
`test-value-evidence.v1` artifact supplies those bindings and raw artifact hashes.
Do not invent historical hashes from the current checkout.

Comparison uses exact repository-relative paths, content hashes, original-source
lines, and separately named branch coordinate models. Original TS coordinates
from the official remapping provider can be compared; unverified generated bundles
and source maps remain gaps. Indexed ownership groups and signature hashes expose
shared execution without expanding every pair of tests. These are review leads,
not equivalent assertions or approved removals.

Optional per-test `behaviorRefs` link explicitly declared behavior across languages.
They remain relationships for assertion review, separate from measured source
overlap. Browser, provider, native, and subprocess effects require their own
evidence. Report the tested scope and missing layers rather than a single combined
product-coverage percentage.
