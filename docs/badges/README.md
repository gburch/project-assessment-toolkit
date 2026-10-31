# PAT self-assessment

Self-assessed snapshot using rubric 4 and [source 29761f8](https://github.com/gburch/project-assessment-toolkit/tree/29761f8874fbfb590c091be61cdf086aacccadee). Badges describe this saved assessment, not a live certification.

![PAT summary](summary.svg?v=3)

| Dimension | Capability / 5 | Burden / 5 |
|---|---:|---:|
| [Security](security.svg) | 3 | 2 |
| [Testing](testing.svg) | 4 | 2 |
| [Documentation](documentation.svg) | 3 | 2 |
| [Maintainability](maintainability.svg) | 3 | 2 |
| [Delivery](delivery.svg) | 3 | 2 |
| [Operability](operability.svg) | 2 | 2 |
| [Extensibility](extensibility.svg) | 2 | 2 |

Capability confidence is medium. Every burden score is a **source estimate with low confidence**, based on inspected maintenance work, not measured upkeep hours.

## Goals and progress

All seven selected goals are met in this assessment. Goal revision 1 keeps capability minimums at security 3, testing 4, documentation 3, maintainability 3, delivery 3, operability 2 and extensibility 2, with burden ceilings of 2 throughout.

Compared with [baseline 125f681](https://github.com/gburch/project-assessment-toolkit/tree/125f6818e2c5b60822f3c6ee4e659c536e50fe2a), **delivery capability moves 2 → 3**, while its estimated burden remains 2. All other scores are unchanged. Rubric 4, evidence scope and goals are unchanged; PAT records one engineering step and zero remaining goal gaps.

The [offline wheel rehearsal](https://github.com/gburch/project-assessment-toolkit/blob/29761f8874fbfb590c091be61cdf086aacccadee/scripts/smoke-wheel.py) binds clean committed source and its manifest to a wheel digest and locked core constraints. A fresh isolated installation checks installed resource origins, bundled skills/guide/UI and operation without MCP. A real CLI scenario checks scan, cited review, targets and progress, rejected writes that preserve state, and restoration of stopped synthetic state into a fresh directory.

The [candidate procedure](https://github.com/gburch/project-assessment-toolkit/blob/29761f8874fbfb590c091be61cdf086aacccadee/CONTRIBUTING.md#local-delivery-proof) defines checks before distribution and artifact retention. [Update/rollback guidance](https://github.com/gburch/project-assessment-toolkit/blob/29761f8874fbfb590c091be61cdf086aacccadee/docs/PROJECT_ASSESS.md#local-state-and-updates) covers compatible application and state recovery. This supports controlled local delivery 3. Same-version synthetic state restoration is verified; cross-version migration, hosted deployment and level-4 assurance are not established.

## UI and scanner corrections

The app now supports first-project scans and explicit cited JSON review submission through the existing service. Protected writes, allowed-root checks, immutable facts, stale-review rejection and unsaved drafts remain covered by HTTP and browser checks.

Capped static leads share the existing budget across kinds, source areas and files. Literal heading underscores are retained; ambiguous underscore emphasis is uncertain. Test-source spans refresh from content rather than trusting size and timestamp. These corrections keep supported inputs and bounds unchanged. Newly visible leads are not credited as engineering progress.

## Ecosystem fit

**Appropriate for the current local toolkit.** This check informs maintainability **3/5** and estimated burden **2/5**; it adds no eighth score.

| Area | Evidence and decision |
|---|---|
| Targeted library reuse | [Declarations](https://github.com/gburch/project-assessment-toolkit/blob/29761f8874fbfb590c091be61cdf086aacccadee/pyproject.toml) include `jsonschema`, `packaging` and optional `mcp`. Requirement parsing uses the standard `packaging.Requirement` parser. Keep this focused reuse. |
| Local HTTP | [Loopback report server](https://github.com/gburch/project-assessment-toolkit/blob/29761f8874fbfb590c091be61cdf086aacccadee/src/project_assess/web.py) uses fixed routes, origin/token controls and bounded bodies. Keep its local scope; a hosted multi-user service would need a fresh design review. |
| Persistence | [SQLite service](https://github.com/gburch/project-assessment-toolkit/blob/29761f8874fbfb590c091be61cdf086aacccadee/src/project_assess/service.py) implements immutable snapshots, transactions, replay identity and source authority. A different persistence layer would still need those guarantees. |
| Report UI | [One vanilla DOM interface](https://github.com/gburch/project-assessment-toolkit/blob/29761f8874fbfb590c091be61cdf086aacccadee/src/project_assess/static/app.js) uses safe insertion and stale-response guards. No demonstrated state-management burden currently justifies a framework migration. |

Deterministic collection found **11 declaration records** across two supported manifests (10 distinct names), and **10 syntax clues**: 4 in source, 3 in tooling and 3 in tests. These counts locate review work; they are not issues or scores. Development and optional dependencies stay distinct from core runtime declarations.

The ecosystem analysis is **partial** because JavaScript hints are lexical: aliases, template expressions, regular-expression literals and runtime behavior are unresolved. Declared packages do not prove runtime use. Version currency, compatibility, support, licensing, vulnerabilities and performance were not verified.

Reconsider the stack when remote/multi-user serving becomes a requirement, state-schema changes become frequent, or repeated multi-view state bugs demonstrate an ownership cost. Start with one small experiment preserving required behavior; no migration is recommended by this assessment.

## Validation and scope

**264 Python tests passed without skips**, including real CLI/MCP calls, access restrictions, concurrency, recovery, scanner corrections and goal semantics. Ruff, formatting, skill validation and the full browser harness passed. Browser checks cover a genuinely empty service through first scan/review, invalid/stale submissions, bounded imports, draft/race handling, keyboard access, mobile layouts, accessibility and actual SVG text bounds.

The clean committed-source wheel proof passed separately. Its source manifest matches this assessment. Raw imported JUnit retains unverified source identity; separately recorded source hashes corroborated the implementation checks without rewriting collector facts.

Source capture was complete for supported text. Static analysis remains partial: 100 of 103 leads retained, all 43 Python files parsed, and two JavaScript files analyzed lexically. Unsupported assets, dynamic behavior, semantic freshness, dependency health and long-term upkeep remain outside the proof. No critical/high findings were recorded; that does not prove their absence.

Assessment: `a_e17040aec0954425ad5fc85daeb2ec8d`; review: `r_c7cbcf3f747741da9a1d142c5a66b075`.
Source manifest: `sha256:260ae55354a07f19a78aa5c1895a96bf9b364be6037fc73395b15993c2e1a9d0`.

Use the [guide](../PROJECT_ASSESS.md) for evidence limits and exporting your own badges. Full local state, captured excerpts and private execution receipts stay outside the repository. The publication commit updates this summary and SVG snapshots; the assessment stays pinned to the implementation revision above.
