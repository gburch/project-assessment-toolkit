# Use PAT to choose useful engineering work

PAT separates captured facts, authored judgment and owner-selected goals. The CLI
does not call an AI service, score a project automatically or repair it. A person
or optional host agent turns the evidence into a cited review and improvement plan.

These examples assume `pat` is installed in PAT's environment; from its checkout,
use `uv run --locked pat` instead. Keep state and imported reports outside assessed
projects. See the [local workflow](PROJECT_ASSESS.md#local-workflow) for review
submission and independent challenge. The examples are independent; replace paths
and use matching assessment/project IDs for the project you intend to review.

## 1. Turn a CI threshold into a reviewable report

Use a threshold to request inspection, rather than equating a metric with a quality
score. For example, an existing complexity rule can flag a change for review:

```bash
PAT_STATE="$(mktemp -d "${RUNNER_TEMP:-/tmp}/pat-ci.XXXXXX")"
pat --state-dir "$PAT_STATE" scan "$PWD" --brief > "$PAT_STATE/scan.json"
python3 - "$PAT_STATE/scan.json" "$PAT_STATE/review-requested" <<'PY'
import json, sys
from pathlib import Path
scan = json.load(open(sys.argv[1]))
counts = scan.get("static_analysis", {}).get("candidate_counts", {}).get("by_kind", {})
if counts.get("complex_function", 0) or not scan["complete"]:
    Path(sys.argv[2]).write_text(scan["assessment_id"] + "\n")
    print("PAT review requested:", scan["assessment_id"])
PY
if [ -f "$PAT_STATE/review-requested" ]; then
    PAT_ASSESSMENT="$(cat "$PAT_STATE/review-requested")"
    pat --state-dir "$PAT_STATE" doctor "$PAT_ASSESSMENT" --limit 20 > "$PAT_STATE/doctor.json"
    pat --state-dir "$PAT_STATE" export-report "$PAT_ASSESSMENT" > "$PAT_STATE/export.json"
    python3 - "$PAT_STATE/export.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
print("Unreviewed facts report:", manifest["html"])
print("Private artifact directory:", manifest["directory"])
PY
fi
```

This illustrative trigger reports raw Python complexity leads or incomplete
collection. Choose thresholds for your own review needs. It does not fail a build
for a burden score, establish a defect or replace existing behavior/security tests.
The trigger generates Doctor output and an **unreviewed facts report**. Its export
manifest supplies the actual HTML, Markdown, JSON and badge paths; it has no authored
scores until a review is saved. Retain that directory and the manifest through your
existing private artifact mechanism; source and exports can contain sensitive data.

An optional **external host AI loop** can read that snapshot, use `project-assess`
to author and challenge a source-bound review, and propose one useful maintenance
slice. Give the host a bounded implementation scope, test commands and PR
permissions when you want an ongoing maintenance loop. After a reviewed change,
rescan with comparable settings, review again and inspect progress. PAT
provides the local evidence/review commands; it does not schedule that loop,
invoke the model, open a PR or run target tests itself.

**Useful decision:** a long function owns one atomic transaction, so retain that
boundary; remove duplicated validation around it instead of splitting it merely
to pass the metric. A saved capability/burden threshold needs a current, bound
review and explicit unknown/coverage handling; raw CI metrics cannot supply it.

## 2. Evaluate a third-party project before adopting it

Inspect an existing local checkout without installing its dependencies, loading
its plugins, running its code/tests or contacting its services:

```bash
PAT_STATE="/absolute/path/outside-projects/pat-state"
mkdir -p "$PAT_STATE"
pat --state-dir "$PAT_STATE" scan /absolute/path/to/vendor-checkout --brief > "$PAT_STATE/vendor.json"
PAT_ASSESSMENT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["assessment_id"])' "$PAT_STATE/vendor.json")"
pat --state-dir "$PAT_STATE" doctor "$PAT_ASSESSMENT" --limit 20
pat --state-dir "$PAT_STATE" evidence-query "$PAT_ASSESSMENT" --view review-plan --dimension security
```

Ask the reviewer: “Trace setup, one valuable workflow, dependency/upgrade ownership,
permissions and failure recovery. Estimate adoption and upkeep burden for our use;
give directional security findings with citations, counterevidence and unknowns.”

**Fictional reviewed example, not a claim about an actual package:**

| Area | Capability / burden | Confidence and interpretation |
| --- | --- | --- |
| Security | 2 / 2 | Low: explicit authentication boundaries; deployment and recovery unverified. |
| Maintainability | 2 / 3 | Medium source estimate: a representative upgrade crosses three independent version policies. |

**Adoption verdict:** pilot the bounded read-only adapter; defer adopting the whole
platform until the integration and upgrade costs fit. A real review needs captured
citations and contrary evidence for its scores. This is directional due diligence,
not security certification, a vulnerability audit or proof of safe use. Deep can
add bounded analysis when needed; missing or partial analyzers stay gaps.

## 3. Steer personal → enterprise → personal

Use [`project-maturity`](../.agents/skills/project-maturity/SKILL.md) to establish
current scope/readiness and [`project-intent`](../.agents/skills/project-intent/SKILL.md)
to record the owner's destination. “Enterprise” is a requirement to unpack, not a
PAT milestone or automatic quality upgrade: shared staff workflows may need
`team_app`; independently supported customers may need `supported_product`.

**Example:** an owner moves a personal app toward shared staff use. Rank identity,
shared-state isolation, onboarding and recovery against those actual workflows.
Later the owner returns to personal use. Their current statement overrides an
older enterprise roadmap: defer unused tenancy/extension machinery, while keeping
active data, credential, action-approval and recovery protections.

Scope landmarks and numeric goal profiles are separate. After the owner selects
numeric targets, obtain the project ID from `pat --state-dir "$PAT_STATE" list`
and read its current goal revision. For example, **only after selecting** the
`internal-service` profile:

```bash
PAT_PROJECT="PROJECT_ID_FROM_LIST"
PAT_GOAL_REVISION="$(pat --state-dir "$PAT_STATE" progress "$PAT_PROJECT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["goal_revision"])')"
pat --state-dir "$PAT_STATE" targets "$PAT_PROJECT" --profile internal-service --expected-revision "$PAT_GOAL_REVISION"
```

For the return to personal scope, prepare an owner-approved JSON file containing
all eight `capability_min` / `burden_max` pairs, then reload the revision before
saving it:

```bash
PAT_GOAL_REVISION="$(pat --state-dir "$PAT_STATE" progress "$PAT_PROJECT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["goal_revision"])')"
pat --state-dir "$PAT_STATE" targets "$PAT_PROJECT" --input "$PAT_STATE/personal-targets.json" --expected-revision "$PAT_GOAL_REVISION"
pat --state-dir "$PAT_STATE" history "$PAT_PROJECT"
```

Each save establishes a new goal baseline at the latest assessment/review. Changing
the target changes neither source nor scores and is **not engineering progress**.
There is no universal personal-app target profile; choose values for this owner.

## 4. Evolve to the next useful stage within a burden ceiling

After a cited review and any confirmed goals are saved:

```bash
pat --state-dir "$PAT_STATE" evolve "$PAT_ASSESSMENT"
pat --state-dir "$PAT_STATE" progress "$PAT_PROJECT"
```

Evolve returns the saved diagnosis, coverage, authored roadmap and goal alignment.
It preserves missing reviews/plans; it does not invent a plan or implement one.
Ask `project-assess` to plan the **full intended outcome**, dependencies and
acceptance evidence within the selected burden ceilings, then choose a first slice.

**Useful decision:** moving a working shared tool toward dependable team use may
need recoverable shared-state changes and clear access ownership. The roadmap
covers that destination; the first slice exercises one restore/conflict path.
It does not stop at “add one test,” demand microservices or silently relax the
burden ceiling. A dependable personal app can also be the final intended state;
maturity landmarks are not a mandatory promotion ladder.

## 5. Steer an AI toward improvement rather than accumulation

The bundled skills are `project-assess`, `project-maturity`, `project-intent`,
`test-value` and `doc-value` (`pat skills` locates them). Doctor and Evolve are
commands used by `project-assess`; “simplify” is a direction in the review, not a
separate command or bundled skill.

Give the host agent a concrete instruction such as:

> Use project-assess, project-maturity and project-intent for this personal app.
> First assess read-only. Trace the owner-visible change loop, current callers and
> state/security boundaries; use Doctor leads and Evolve's saved goal alignment.
> Produce a cited diagnosis and full improvement roadmap before choosing a slice.
> For every proposed addition, identify the current missing capability or the
> existing work it removes. Prefer removing duplicated policy, brittle assertions
> or redundant ownership where the protected outcome survives. Preserve active
> data, authorization, recovery and supported integrations. Explain “retain” when
> existing code is adequate. Keep unknowns explicit and do not save new goals or
> implement changes without authorization.

**Useful output:** one shared policy replaces independently maintained copies,
and one outcome test replaces cosmetic prose assertions. Acceptance shows fewer
edit sites and the same important failure protection. Adding a forwarding layer,
new verifier or benchmark platform without reducing the demonstrated cost does
not satisfy that improvement. A separately authorized implementation can then be
rescanned and reviewed against the same purpose and comparable evidence scope.

See the [assessment skill](../.agents/skills/project-assess/SKILL.md),
[Doctor/Evolve guide](PROJECT_ASSESS.md#doctor-and-evolve) and
[goals/progress workflow](PROJECT_ASSESS.md#goals-and-progress) for details.
