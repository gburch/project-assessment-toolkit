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
| Performance & Scalability (`performance`) | Basic workload controls → deliberate bounds → measured objectives/headroom → exercised growth and recovery → sustained independent capacity evidence | Tuning, cache coordination and capacity machinery dominating ordinary work |
| Extensibility | Single purpose → local seams → supported APIs/adapters → deliberate extension points → independently authored extensions → sustained external ecosystem | Repeated core edits, brittle contracts, speculative framework machinery and option matrices |

Burden ranges from negligible overhead (0) to practices dominating available engineering effort (5), including justified safeguards. High capability is not penalized. Missing evidence is **unknown**, not zero; a dimension can have known capability and unknown burden. Capability levels 4–5 require validation beyond the presence of configuration files. “Fort Knox ambition” is a rubric label, not a security certification.

The rubric accepts **source estimates** of burden: inspected repeated edit sites, duplicated guidance, coupled fixtures, release gates and runbook steps can establish likely upkeep without time logs. A traced direct implementation with light upkeep can merit burden 1 with low confidence. Set `burden_basis` to `source_estimate`, `observed` or `unknown`, with independent `burden_confidence`; the existing `confidence` applies to capability. The rationale explains the inferred or observed cost and its limits. Counts alone cannot establish burden, and a reviewer should retain unknown when the source or workflow cannot support an estimate. Earlier reviews with numeric burden are treated as low-confidence source estimates; rubric changes start a new comparison series.

Maintainability review challenges whether the architecture fits demonstrated requirements, including complexity accumulated through AI-assisted changes. Static hints identify candidates for inspection, such as trivial delegation layers or speculative plugin/configuration scaffolding; they never assign burden automatically. A useful finding cites a concrete example, its actual need and estimated or observed cost, the simplest viable alternative preserving required contracts, and a bounded next step. Injection, security and isolation boundaries can justify additional structure. Apply the same proportionality judgment to tests, documentation, controls and delivery processes; higher investment is not a universal goal.

**Rigidity** remains a maintainability check: constraints that obstruct valuable changes without protecting a current important outcome. Trace the change, the obstructing test/rule/process, the value or risk protected, and a proportionate simpler alternative. Examples include implementation-detail assertions, unjustified coverage gates and documentation taxes; inspect actual callers before judging. Earlier AI decisions can be revised while preserving current security, durable-data and integration guarantees. Explain static inferences and confidence in the existing assessment; rule counts alone are insufficient.

**Ecosystem fit** is also a named maintainability check, with no separate score. `facts.ecosystem_fit` and `ecosystem-analysis` evidence collect dependency declarations and narrow Python/DOM leads for review. Compare bespoke HTTP/auth/routing/state/cache/validation work with an appropriate maintained library, and oversized framework setup with a simpler utility implementation. Judge actual requirements, exposure, workload, team, lifecycle, security and compatibility; cite a concrete behavior, migration/upkeep cost and smallest useful experiment preserving contracts. Package presence, count or age does not establish quality. Current support, version currency, licenses and vulnerabilities remain unknown offline; verify official sources when researching alternatives. Stack preferences are descriptive context, not global gates. Existing user-selected maintainability capability/burden goals apply; the maintainability goals remain independently tunable.

PAT 0.3.0 uses collector 7 and Python analyzer 3; ecosystem evidence remains version 1. Collection scope records the analysis profile, settings, selected analyzers and optional parser availability/versions. Earlier snapshots remain readable but do not gain new facts; rescan to collect missing evidence. Progress requires compatible scopes, so runs across these changes are not comparable. Existing reviews, goals and baselines remain saved without automatic reset. Newly visible leads, changed judgment or an installation update are not engineering progress.

Rubric 4 adds **extensibility** as the seventh tunable dimension. Establish the needed variation, frequency and authors, then trace a representative extension through supported contracts. Distinguish a missing seam, brittle contract and speculative framework; recommend the simplest adequate seam with proportionate documentation, tests and isolation. A single-purpose project can appropriately target 0. Capability 4–5 needs demonstrated independent extensions and compatibility, not plugin counts. High extensibility and low rigidity can coexist. Earlier reviews and goals retain unconfigured extensibility rather than a zero. Rubric 4 starts a new comparison series; re-rating old evidence is not engineering progress.

Rubric 5 adds **Performance & Scalability** as the eighth tunable dimension (`performance` in JSON/CLI). State the intended workload, response/resource objectives and growth expectations. Inspect bounded queries, pagination, batching, backpressure and shared-state contention. Source patterns are leads, not proven bottlenecks; capability 3 requires representative source-linked measurements, and higher levels require saturation/recovery evidence. A local utility need not scale horizontally. Rate optimization and capacity upkeep separately from raw resource use. Existing reviews and goals retain unknown/unconfigured performance; no target is silently saved, and rubric 5 starts a new comparison series.

Whole-project maintainability review also traces **systemic debt**: domains, shared stores/transactions, duplicate models, lifecycle ownership, dependency cycles, and the edit/coordination cost of a representative valuable change. Monolithic deployment or size alone does not assign a grade. Prefer the smallest adequate ownership boundary; modularization need not introduce services. Group evidenced symptoms into root-cause initiatives and a target state before choosing the first slice.

Broad scoring starts with the shared **system map**, a bounded inventory of captured production areas and phased cross-area imports. It helps a reviewer inspect the system before local Doctor candidates; paths and counts do not establish semantic ownership or quality. Reviews record per-dimension coverage (`reviewed`, `partial`, `unreviewed`) with rationale and citations. Whole-project unreviewed dimensions cannot receive numeric grades. Reports and Evolve distinguish broad, partial, focused and unestablished review scope. Legacy records remain readable with breadth unestablished; structural validation does not prove the truth or completeness of a review.

## Scanner coverage

Source discovery, captured bytes, parsed syntax, detailed analysis and source actually inspected by a reviewer have separate scopes. Completeness describes eligible inputs after dependency/build, credential and symlink exclusions; inspect exclusions and unsupported languages as well as budget omissions. An inventory or an analysis row does not establish whole-project understanding.

The brief and shared report alignment expose `dimension_inputs`: a bounded directory of existing evidence providers, their captured IDs/coverage and the analysis missing for each dimension. Shared providers deliberately support multiple questions. Empty providers mean no such evidence was collected, rather than a missing practice in the assessed project.

| Dimension | Deterministic inputs available | Important limits |
|---|---|---|
| Security | Import-aware risky APIs/TLS flags, authorization integration/gate hints, CI permissions/references, declared dependencies, supplied Ruff/SARIF | No complete authorization/dataflow analysis, exploit proof or vulnerability-database lookup; redaction protects collection |
| Testing | Test/setup hints, native syntax metrics, supplied JUnit/coverage/test-value results | Sampling, scenario relevance, effectiveness and source binding remain explicit |
| Documentation | Duplicate text, local links/anchors, captured guidance | Semantic freshness and usability require review or observations |
| Maintainability | Complexity, imports, reuse, interface/forwarding and dead-code leads | Necessity, rigidity and actual change amplification require caller/change context |
| Delivery | GitHub Actions/CircleCI jobs, dependencies, permissions, timeouts, failures, pins, artifacts, command categories; lockfiles and manifest/process declarations | Dynamic expressions/external actions and actual reproducible release/rollback effectiveness remain unknown |
| Operability | Logging, catches, waits/retry, health and recovery/checkpoint/queue hints; imported recovery observations | Naming hints and declared mechanisms require actual diagnosis/recovery context |
| Extensibility | Interfaces, injection/registration/discovery hints, entry points/exports and compatibility declarations | Extension usability and compatibility require actual variant/caller inspection |
| Performance | Python/JS I/O-loop, query, batch/paging, timeout, cache, admission/backpressure/synchronization hints; imported observations | No full dynamic model or workload capacity proof; unresolved receivers/options remain explicit |

Use `evidence-query ID --view areas` and `--view area-dependencies` with `--offset`/`--limit` to enumerate the complete captured production directory and cross-area import groups. These views accept `--path`; other semantic filters are unsupported. Responses preserve source/scope identity, citation omissions and graph limits. The compact map still shows 20 areas/dependency groups, and the independent challenge packet remains a bounded navigation sample. Continue through `next_offset` and choose source inspections appropriate to the project's workflows before using local Doctor candidates to prioritize work.

Collection version 9 selects test-value and ecosystem inputs across roles and path areas after discovery, reuses the original source parse, and assembles bounded detail after capture. JavaScript retains cheap module overviews beyond its rich-detail budget; generic block comparison distributes its existing window budget across files/areas. Coverage reports distinguish examined detail from retained output. These changes do not add scores or execute assessed code, and they do not make every analysis complete.

Collection version 10 adds one shared `control-analysis` record. It preserves per-file status, source evidence identity, observed/retained kind counts and per-dimension coverage; native syntax traversal and per-file signal work remain bounded. The global 8,000-signal sample reserves dimension/kind/semantic-variant representatives before file rounds, with a bounded representative pool. Inspect all omissions: counts are not maturity measures and zero hits are not absence proof. Other source languages remain explicit unsupported inputs for these native control rules; optional models and supplied SARIF remain separate evidence.

Use `evidence-query ID --view controls --dimension security` (or delivery/operability/extensibility/performance), with ordinary pagination/path/role filters. This view includes coverage rows and located signals; `--candidate-kind file` selects only coverage, while a signal kind selects those records. YAML locations are source nodes; JSON/TOML manifest facts have document-level locators. The report and UI show scanner scope separately from score confidence. YAML data parsing uses [PyYAML's representation API](https://pyyaml.org/wiki/PyYAMLDocumentation), with bounded token/node/depth handling and rejected ambiguous/custom-tag constructs; it loads no assessed configuration as code. PyYAML is [MIT licensed](https://github.com/yaml/pyyaml/blob/main/LICENSE).

Existing workload/recovery/delivery/change-cost/security/extension observations can be imported as [versioned JSON reports](../.agents/skills/project-assess/references/observation-report.md). Matching declared revision/file hashes establishes only that scope's source identity. Origin, execution, timestamp, scenario relevance and effectiveness remain supplied claims; importing evidence changes no score or goal.

Use `evidence-query ID --view burden --dimension testing` (any of the eight dimensions) to inspect shared burden hurdles, coverage and imported context. The app's **Burden hurdles** view exposes the same evidence. Source patterns identify possible costly mechanisms; attributed experience describes reported change cost. Neither assigns a score. Follow pagination and inspect omissions before claiming broad coverage.

Import attributable maintainer or contributor experience with `scan ROOT --report FILE` using [`pat.burden-context.v1`](../.agents/skills/project-assess/references/burden-evidence.md). Keep reports outside assessed repositories. Record attribution, report time, experience period, scope, frequency, workflow stage, timing semantics and limitations without inventing measurements. Unknown source identity or dates remain explicit gaps. A joint “tests OR security on most changes” claim does not establish individual frequency for both; summed testcase time is not wall time or blocked waiting. A matching revision does not authenticate the reporter or establish current applicability.

## Local workflow

Requires macOS or Linux, Python 3.11+ and uv. From the PAT checkout:

```bash
uv sync --locked
uv run --locked pat info
uv run --locked pat analyzers
uv run --locked pat --state-dir /path/outside/repos/assessment-state scan /path/to/project --brief
uv run --locked pat --state-dir /path/outside/repos/assessment-state list
uv run --locked pat --state-dir /path/outside/repos/assessment-state report ASSESSMENT_ID --brief
uv run --locked pat --state-dir /path/outside/repos/assessment-state evidence-query ASSESSMENT_ID --view areas --limit 20
uv run --locked pat --state-dir /path/outside/repos/assessment-state evidence-query ASSESSMENT_ID --view area-dependencies --limit 20
uv run --locked pat --state-dir /path/outside/repos/assessment-state evidence-query ASSESSMENT_ID --view coverage
uv run --locked pat --state-dir /path/outside/repos/assessment-state evidence-query ASSESSMENT_ID --view graph --role production
uv run --locked pat --state-dir /path/outside/repos/assessment-state evidence-query ASSESSMENT_ID --view candidates --limit 20
uv run --locked pat --state-dir /path/outside/repos/assessment-state evidence-query ASSESSMENT_ID --view burden --dimension maintainability --limit 20
uv run --locked pat --state-dir /path/outside/repos/assessment-state source-context ASSESSMENT_ID EVIDENCE_ID --line 120 --end-line 160
uv run --locked pat --state-dir /path/outside/repos/assessment-state doctor ASSESSMENT_ID
uv run --locked pat --state-dir /path/outside/repos/assessment-state evolve ASSESSMENT_ID
uv run --locked pat --state-dir /path/outside/repos/assessment-state rubric
uv run --locked pat --state-dir /path/outside/repos/assessment-state review-template ASSESSMENT_ID --mode fresh
uv run --locked pat --state-dir /path/outside/repos/assessment-state challenge-template ASSESSMENT_ID --input /path/outside/repos/review.json
uv run --locked pat --state-dir /path/outside/repos/assessment-state review ASSESSMENT_ID --input /path/outside/repos/review.json
uv run --locked pat --state-dir /path/outside/repos/assessment-state serve
```

Start with `info` and brief output rather than dumping a large report into an agent's context. Installation identity and available instruction hashes do not prove which instructions an agent read. `evidence-query` supports index, details, candidates, snippets, graph, hotspots, coverage, provenance, areas, area-dependencies, controls and burden views; narrow by supported `--path`, `--role`, `--kind`, `--candidate-kind` or `--dimension` filters. Follow `next_offset` with `--offset`; `--limit` and `--max-chars` bound each response. Full `report`/`evidence` exports remain available. Captured snippets are redacted, bounded windows; `source-context` reads another bounded range only when current complete file bytes match that snapshot's digest, otherwise rescan or locate the matching source. None of these operations executes target code.

Use the URL printed by `serve` to scan a new project path, inspect saved evidence, submit a review, adjust targets and see progress. Saved projects can be scanned again from the project selector. `--port N` chooses a port. State must remain outside assessed roots, so collecting a report does not change the source being measured. Existing test or analysis reports can be supplied through the CLI with repeated `scan --report FILE` options; supplied results retain their evidence limitations.

In the app, open the review editor for the current snapshot, load its template or import review JSON, and fill it using the captured evidence and rubric. Submit explicitly when ready. A rescan needs a review bound to the new snapshot; an old or mismatched review is rejected. Each numeric judgment needs cited evidence; inspection can support a labeled burden estimate without execution or time records.

For the CLI workflow, save the JSON printed by `review-template` to a file outside the assessed repository, fill it, then pass it to `review --input`.

PAT 0.6.0 adds explicit **review freshness**, **change traces** and an **independent challenge**. Select `fresh` to reassess the current snapshot or `refresh` to declare retained judgments. Every dimension records reassessed, carried-forward or unreviewed origin. Carry-forward requires an authorized earlier review with identical source revision, manifest, collection scope and rubric; legacy reviews keep freshness unestablished. These labels describe the review method, not a time-based claim that source or runtime is current.

Change traces cite ordered owners and edits for representative valuable changes, their cost, protected invariants, counterevidence and gaps. `challenge-template` validates a draft and returns a score-free source-bound packet for an independent agent or human. PAT does not call an AI service. Save the critic's cited concerns and explicit accepted/rejected/deferred responses in the review; a substantive draft amendment requires a new digest and follow-up. Reviewer independence is declared, not authenticated. A fresh whole-project assessment needs a trace and completed challenge for its completed method label; an unavailable challenge stays provisional. Partial source coverage, unknown grades and unresolved concerns remain visible. See the [workflow and field reference](../.agents/skills/project-assess/references/evolve-review.md#freshness-change-traces-and-independent-challenge).

The [project-assess skill](../.agents/skills/project-assess/SKILL.md) guides evidence review and judgment. Its structured review is bound to an assessment ID, source digest and rubric version. It supplies each dimension's scores, confidence, rationale, evidence IDs and recommendations; findings retain separate severity and evidence. Review submission cannot overwrite collected metrics or source identity. Its validation checks structure and provenance, not the truth of an agent's conclusion.

A whole-project review also records honest `coverage` (examined and unexamined areas, limitations and validation) and an authored `plan` (diagnosis, full target state and ranked root-cause initiatives with acceptance, burden effects, dependencies and first slices). These fields are optional for compatibility, not automatically completed by static analysis. A focused review must state its boundary. See the [review field reference](../.agents/skills/project-assess/references/evolve-review.md#optional-structured-review-fields) for the exact shape rather than inventing a second schema.

Optional `review_context` records `tool_code_digest` and `loaded_instructions: [{path, sha256, read_status}]`, where `read_status` is `complete` or `partial` and `sha256` is the file's 64-character lowercase digest. Preserve the template's tool identity and list only instructions actually read. An empty list makes no read claim. Installed instructions being available—and a recorded hash—do not prove that an agent loaded or followed them.

PAT 0.7.0 separates **finding confidence** from **score confidence**. Optional finding `support` records a source or inference claim, confidence, rationale, counterevidence, limitations and exact redacted line citations. PAT checks each passage against matching captured file bytes at challenge preparation and submission, then saves server verification receipts. Reports expose `confidence_assessment` with grounded findings and the evidence still missing for broader scores. Raw confidence labels remain declarations; verified text does not certify reasoning, runtime effectiveness or observed burden. Legacy reviews remain readable without invented support. See the [field and confidence guide](../.agents/skills/project-assess/references/evolve-review.md#confidence-support).

High declared burden confidence requires a scored `observed` burden and explicit rating `burden_support`: `claim`, `scope` (`project` or `workflow`), `scope_description`, `observation_ids`, `change_trace_ids`, `representativeness`, `counterevidence`, `freshness` and `limitations`. Cite applicable dimension-specific attributed experience with a stated period, or source-matched `change_cost` observations with an observed numeric `wall_elapsed`, `blocked_wait`, `active_effort` or `change_elapsed` result in `s`, `sec`, `seconds`, `ms`, `minutes`, `min`, `hours` or `h`. Other report labels and testcase sums cannot satisfy this requirement. Explain current applicability, selected changes and contrary evidence; trace the hurdle to current captured source. Project scope also requires complete collection and a reviewed whole-project dimension; narrower evidence can support a declared workflow scope.

Have a distinct declared reviewer challenge that support against the exact draft and snapshot, recording the applicable names in `challenge.burden_dimensions`. Amendments require a new bound challenge. Final submission rejects unsupported high burden confidence; lower-confidence source estimates remain useful. Reports and each rating card show `confidence_assessment.dimensions[DIMENSION].burden.support` status, scope and gaps as **support prerequisites**, not verified confidence. Meeting structural prerequisites cannot authenticate testimony, prove representativeness or certify a score.

Challenge packets now select a deterministic mix of trace citations, production areas and supporting evidence, with selection reasons and omissions. Collector 8 separates Python capture completeness from unrelated asset/dependency omissions and preserves ordinary `task_*` path labels during credential redaction. Joern adapter 4 includes captured source identities on graph rows; its fixed query remains version 3. Vulture samples across source areas within the existing work budget and records area coverage. These collection changes create a new comparison scope; they neither rewrite prior facts/goals nor record engineering progress. Whole-project capture and dynamic graph limits remain explicit.

## GitHub badges

`badge ASSESSMENT_ID` exports a saved assessment without running the project or changing its ratings, goals or state. By default it prints a summary SVG to stdout. Choose a destination explicitly; the shell redirection below writes the files:

```bash
mkdir -p docs/badges
uv run --locked pat --state-dir /path/outside/repos/pat-state badge ASSESSMENT_ID \
  > docs/badges/summary.svg
uv run --locked pat --state-dir /path/outside/repos/pat-state badge ASSESSMENT_ID \
  --dimension testing > docs/badges/testing.svg
```

Use `--dimension summary` or any of the eight dimension names. SVG cards label capability and burden separately on their 0–5 scales; cyan and gold distinguish the axes, not good/bad grades. JSON badges retain `Cx/5` and `Bx/5`. Unknown values display `?`. The summary counts a dimension as known only when both scores are numeric. Reported critical/high finding counts include records in the selected snapshot and saved review; they are not an aggregate quality score or proof of absent risks. Unreviewed assessments and partial scans are labeled.

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

`doctor ASSESSMENT_ID` groups captured static-analysis candidates into **reuse**, **quality** and **efficiency**, with source locations, evidence references and suggested verification. Its bounded sample shares space across evidence families; use `--limit 20` for a compact first pass and `evidence-query` for the larger captured index. The Python equivalent is `AssessmentService.doctor(assessment_id)`; the same read-only operation is available over MCP. It reads the saved snapshot without executing or editing the assessed project. Older snapshots without the facts report them as not collected; rescan when wanted.

`evolve ASSESSMENT_ID` returns the saved diagnosis, coverage, findings, recommendations and authored plan alongside numeric goal alignment; doctor shares that orientation under `goal_alignment`. It preserves missing reviews/plans and unconfirmed or changed targets explicitly. `ready` means the bindings match, not that goals are met or a plan is validated. Plan the full intended outcome and acceptance evidence before choosing a first slice; an intermediate rubric step is a milestone. Keep unknown evidence and independently known gaps visible, preserve useful capability and respect the burden ceiling. Without selected goals, a scenario stays provisional and nothing is saved. The [Evolve guide](../.agents/skills/project-assess/references/evolve-review.md) gives the planning detail. Neither command changes scores, goals or source automatically.

Python analyzer 3 separates broad, cheap function metrics from expensive clone/pattern work. Every discovered function receives metric coverage within explicit node bounds; incomplete metrics are lower bounds. Pattern slots are sampled and spare capacity redistributed, with separate counts. Module/import overviews remain available after pattern budgets are exhausted. Import resolution caches repeated targets and reports attempts, cache hits, unique work and completeness. Incomplete capture or graphs withhold unreferenced-module leads; a zero observed degree is not proof of disuse. Exact matches preserve literal/callee/decorator differences; broader similarity carries lower confidence and counterevidence. Public exports, entry points and dynamic/plugin calls remain open-world. Even an unreachable yield can intentionally establish an async-generator contract. Static confidence never proves safe deletion, interchangeable behavior or a rating.

Collection prioritizes application source and manifests/configuration before tests, tooling and unsupported assets. Production source roots take precedence over nested `ops`/`tools` names; tests and generated/vendor hints retain deliberate separate handling. Repository source inputs are bounded at 8 MiB each and other repository files at 1 MiB; supplied reports have separate limits. Choose collection work with `scan ROOT --analysis-profile standard|deep`, independently of scoring goals:

| Profile | Supported text | Separate unsupported assets | Cooperative deadline | Python pattern slots, total / per file | Unique import resolutions |
| --- | ---: | ---: | ---: | ---: | ---: |
| `standard` | 64 MiB | 16 MiB | 120 s | 20,000 / 64 | 20,000 |
| `deep` | 256 MiB | 16 MiB | 300 s | 60,000 / 256 | 100,000 |

Deadlines are checked between bounded operations, not enforced by killing a parser or process; one operation may overrun. `facts.collection` records skipped paths/reasons, discovery and supported-text/unsupported-asset coverage separately. Each analyzer also reports its own metric, pattern and graph limits; deep does not promise complete analysis. Role counts are captured-input heuristics, not production LOC or test coverage. Response limits are unchanged: a diverse 100-item rich sample, bounded compact index and 4 MiB shared source windows still require pagination and inspection of omissions. A partial asset inventory is distinct from missing source or uncertain syntax/graph evidence.

The language-neutral `source-analysis` baseline inventories captured Swift, Java and other recognized source and finds exact file/block text reuse. It does not infer syntax, complexity, reachability or semantic equivalence. Native Python and optional JavaScript syntax evidence remain separate. For richer language-specific diagnostics, existing externally produced SARIF uses the shared query/Doctor/UI path without a new per-language adapter.

For optional JavaScript/TypeScript syntax analysis, install `uv sync --extra analysis --locked` in **PAT's environment** and select `--extra analysis` on `uv run` commands that need it. Tree-sitter parses captured JS/JSX/TS/TSX and supplies bounded source/module/dependency leads; parser errors, limits and availability remain explicit. The core installation keeps lexical counts and reports AST analysis unavailable. This performs no type checking, target imports, dependency installation or configuration loading. AST topology is not a runtime call graph. Function-local imports and repeated checks may preserve timing, freshness, authorization or transactions.

Optional [Vulture](https://github.com/jendrikseipp/vulture) unused-code analysis is selected explicitly:

```bash
uv sync --extra vulture --locked
uv run --extra vulture --locked pat analyzers
uv run --extra vulture --locked pat --state-dir /path/outside/repos/assessment-state scan /path/to/project --analysis-profile deep --analyzer vulture --brief
```

PAT uses Vulture's [`scan` and `get_unused_code` API](https://github.com/jendrikseipp/vulture/blob/main/vulture/core.py) on bounded captured strings, not filesystem scavenging, project configuration or whitelist files. Producer confidence is separate from PAT confidence and safe-removal judgment; dynamic uses, public contracts and unreachable generator markers require inspection. Vulture has its own input/work limits and reports omissions. The fixed built-in registry accepts only named trusted adapters; installation does not autorun them or discover project plugins. Vulture remains a separate [MIT-licensed dependency](https://github.com/jendrikseipp/vulture/blob/main/LICENSE.txt); no upstream code is vendored. Optional providers use `analyzer-analysis`; Ruff and SARIF retain their compatible evidence kinds.

### Optional Joern analysis

PAT 0.5.2 can explicitly run a fixed [Joern 4.0.669](https://github.com/joernio/joern/releases/tag/v4.0.669) adapter for captured Python, JavaScript/TypeScript and Java source. These languages passed real adapter qualification under containment. Swift is unqualified and unsupported in this adapter release: SwiftAstGen's Foundation atomic file writes failed under containment, and no safe private redirect was established. PAT does not invoke it or weaken the sandbox; metadata reports `unqualified_languages` and scans retain an explicit unsupported gap. Prepare a trusted installation outside the assessed project, with [JDK 21](https://github.com/joernio/joern/blob/v4.0.669/README.md#requirements), then configure its absolute roots in PAT's environment:

```bash
export PAT_JOERN_HOME=/absolute/path/to/joern-cli
export PAT_JOERN_JAVA_HOME=/absolute/path/to/jdk-home
uv run --locked pat analyzers
uv run --locked pat --state-dir /path/outside/repos/assessment-state scan /path/to/project --analysis-profile deep --analyzer joern --brief
```

Repeat `--analyzer vulture` when that separate provider is also wanted and installed. The UI exposes the same registered provider selection. No Python extra installs Joern or its JDK; PAT never downloads them during scanning. Joern remains a separate [Apache-2.0-licensed tool](https://github.com/joernio/joern/blob/v4.0.669/LICENSE), with separate JDK distribution terms.

The adapter stages only bounded captured source in a private temporary workspace and runs PAT's bundled query. It does not run assessed code, builds, dependency installers, project configuration, scripts or plugins. Execution requires a working `sandbox-exec` on macOS or `bwrap` on Linux; missing tools or unavailable sandboxing produce explicit unavailable/unsupported evidence. It does not fall back to unsandboxed execution or arbitrary user queries.

Joern runs **after core collection**, with a separate hard process budget: 120 seconds / 2 GiB heap for standard, or 1,800 seconds / 8 GiB for deep, with the JVM active-processor count set to two. Deep input is capped at 4,000 files, 128 MiB total and 8 MiB per file. These limits do not expand what core collection captured. Timeouts, omitted inputs, query/model limits and partial results remain visible; deep selects more work, not a different quality scale or complete analysis.

The JS/TS adapter uses byte-identical private transport files to bypass upstream test/hidden/declaration filename filters, then restores original captured paths in AST headers before CPG construction. Import literals, source text and offsets are preserved. For Joern 4.0.669, a narrow compatibility pass converts safe-integer TypeScript interface property-key values to the member-name representation its converter expects. Original source, node kinds, spans and unrelated AST nodes are preserved; bounded receipts identify adjusted consumer ASTs and unsupported shapes. This is a producer-AST compatibility adjustment, not an edit to assessed code. Type maps and target configuration are disabled; `.mts`/`.cts` use TypeScript grammar. Fixed upstream size, line-count and maximum-line-length guards remain explicit coverage gaps.

Inspect the provider's coverage and provenance alongside its bounded method/reference, unread-binding and module-call facts. Generated nodes, abstract signatures and constructor parameters need source normalization. Captured bindings and required public/callback signatures are suppressed as cleanup leads. Only source-supported method calls enter the primary dependency graph; broad producer-inferred targets remain separately queryable as `inferred_edge` records. Source methods are sampled before external stubs. Query 3 allocates max-min row quotas across source files and admits rows round-robin within the existing 20,000-row / 6 MiB section bounds. Stable source-derived ranks spread samples within files; oversized rows do not block other files. Per-file counts and retained rows expose sample omissions, and normalized module records report retained method rows. Brief and coverage views retain aggregate sampling/compatibility counts; full per-file details remain in the original evidence. Use bounded graph queries with a path filter for individual module counts. These are model counts, not proof of absent methods or semantic completeness. Partial aggregate bounds remain explicit. Unread parameters can preserve callbacks and public contracts; unresolved calls are not evidence of disuse. Current queries do not promise constant-guard reachability, taint analysis or full OSS dataflow (`dataflow: not_run`). Empty results, graph edges and producer confidence never establish safe deletion, runtime behavior or a score. Selecting Joern records a different evidence scope without resetting goals or turning added evidence into engineering progress.

Maintainers with the qualified Joern/JDK can replay the sampler’s skew, ordering, relocation and byte-budget regressions using `uv run --offline --locked python scripts/test-joern-sampling.py --output /path/outside/repos/new-proof`. This optional contained check uses the production helper and fixed synthetic fixtures; it performs no project scan and is separate from offline pytest.

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

Import existing externally produced **SARIF 2.1** using `scan ROOT --report /path/outside/repos/findings.sarif` (or `.sarif.json`). PAT keeps bounded, redacted diagnostics for paths captured in that snapshot; unsupported locations and report constructs remain explicit gaps. Producer/source identity stays unverified, and producer levels are not PAT severity judgments. This reuses reports from analyzers you selected; PAT does not run those tools, load target configuration, follow external report files or retain/apply fix text. An empty report does not establish project health.

Type checking, comprehensive security analysis, dependency-vulnerability checks and verified runtime behavior remain separate evidence gaps. Syntax analysis and documentation/test facts do not establish those capabilities. Supplied Ruff diagnostics, including fix suggestions, retain unverified source identity until independently corroborated.

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

Captured Python test inventory keeps `assertions.count` as the number of bare
`assert` statements, labeled `countBasis: bare_ast_assert`. Adapter 2 separately
reports recognized `self.assertEqual(...)`, `self.assertRaises(...)` and other
known unittest-style calls. Both counts exclude nested function/class/lambda
scopes from the enclosing function. Calls are syntax observations: binding,
execution and custom assertion helpers remain unverified. The aggregate
`facts.python.assertions` also counts only bare `assert` statements and labels
that basis. Counts do not establish test effectiveness or justify pruning.

Older snapshots retain their original data. Doctor labels their bare counts as
legacy and leaves uncollected unittest-style counts unknown. Adapter 2 is part
of collection scope, so rescanning cannot present a counting change as
engineering progress against an older scope.

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

| Profile | Security | Testing | Documentation | Maintainability | Delivery | Operability | Extensibility | Performance | Burden ceiling, all dimensions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `local-experiment` | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 1 |
| `internal-service` | 2 | 2 | 2 | 2 | 2 | 2 | 0 | 2 | 2 |
| `public-production` | 3 | 3 | 2 | 3 | 3 | 3 | 0 | 3 | 2 |
| `sensitive-critical` | 4 | 4 | 3 | 3 | 4 | 4 | 0 | 3 | 3 |
| `framework` | 3 | 3 | 3 | 3 | 3 | 2 | 4 | 2 | 2 |

The framework or library preset is optional and editable. The risk-oriented presets impose no minimum extensibility: choose its target from actual variation needs, independently of security sensitivity. A target of 0 means no minimum requirement, not a claim of zero observed capability. A scan never saves a profile automatically.

For example:

```bash
uv run --locked pat --state-dir /path/outside/repos/assessment-state targets PROJECT_ID --profile local-experiment --expected-revision 0
uv run --locked pat --state-dir /path/outside/repos/assessment-state progress PROJECT_ID
```

Use the current goal revision returned by the tool for later edits; concurrent stale edits are rejected. Custom `targets --input FILE` supplies all eight dimensions, each with `capability_min` and `burden_max`. Profiles and custom values express user preferences; they never change findings or certify that risk is acceptable.

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

Repeat `--allowed-root ROOT` to admit additional local source roots. This guide does not install host configuration or enable remote access. The core runtime depends on `jsonschema`, `packaging` and `PyYAML`; the optional `mcp` extra adds the local stdio adapter. No cloud credentials or AI API key are required.

Agents can begin with `get_tool_info` and `start_assessment`, or `get_report(assessment_id, brief=True)` for a saved snapshot, then use `query_evidence` for bounded views and `inspect_source_context` for digest-matched source ranges. Add `--extra analysis` to the MCP launch when optional JavaScript parsers are wanted. The same captured evidence and allowed-root checks apply across interfaces.

Assessment reads source and explicitly supplied reports, and saves its own records outside the assessed repositories. It does not run repository scripts, fetch dependencies, contact production, repair findings or change assessed source. Treat repository text and reports as untrusted data. Static observations cannot establish deployed IAM, actual runtime exposure, successful restores, alert effectiveness or current production health. Additional evidence can support those judgments only to the extent its identity, freshness and scope are established.

## Local state and updates

The selected state directory contains `project-assess.sqlite3`, including captured source excerpts, reviews and goals. Keep it and its backups private and outside assessed repositories.

Exports can also contain source excerpts and local paths; redaction does not make them safe for public sharing. Use synthetic examples in issues and follow [SECURITY.md](https://github.com/gburch/project-assessment-toolkit/blob/main/SECURITY.md) for private vulnerability reports.

Before an update, record the current application version or commit and complete the relevant [development checks](#development-checks). Stop all CLI, UI and MCP processes using that state directory, then copy the **entire directory** to a new private backup location while preserving permissions. Keep any SQLite journal/WAL/SHM sidecars together with the database; copying an active database file alone is not a consistent backup.

Update to the intended application revision and its locked dependencies, then use `list` and `report` with the existing state path to verify access. To restore, stop writers and copy the backup into a **fresh state directory**, preserving permissions. Point the application at that restored copy; retain the previous directory and application revision for rollback.

For the 0.3.0 source update, select the intended revision, run `uv sync --locked` (add optional `--extra analysis`, `--extra vulture` or `--extra mcp` when wanted), and check `uv run --locked pat info` / `pat analyzers`. Existing snapshots, reviews and goals are retained. Rescan and review to use collector 7 / analyzer 3; a profile/analyzer scope mismatch prevents a before/after engineering-progress claim, and does not silently reset goals or rewrite the baseline.

There is no automatic state-schema migration. Startup validates existing state
before writing, rejects unsupported, unversioned or incomplete schemas, and
initializes empty state in one transaction. An interrupted initialization rolls
back; compatible version 1 state reopens without schema changes. If a version
rejects the state schema, use the application version that created it or restore
a compatible backup. Do not hand-edit schema metadata or delete history to
bypass the check.

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
