# PAT self-assessment

Self-assessed snapshot captured 2026-10-30, using rubric 4 and [source e098398](https://github.com/gburch/project-assessment-toolkit/tree/e0983985f8f87d50654c5134df8e2996814940b5). Badges describe this saved assessment, not a live certification.

![PAT summary](summary.svg)

| Dimension | Capability / 5 | Burden / 5 |
|---|---:|---:|
| [Security](security.svg) | 3 | 2 |
| [Testing](testing.svg) | 4 | 2 |
| [Documentation](documentation.svg) | 3 | 2 |
| [Maintainability](maintainability.svg) | 3 | 2 |
| [Delivery](delivery.svg) | 2 | 2 |
| [Operability](operability.svg) | 2 | 2 |
| [Extensibility](extensibility.svg) | 2 | 2 |

Capability confidence is medium. Every burden score is a **source estimate with low confidence**, based on inspected maintenance work, not measured upkeep hours.

## Ecosystem fit

**Appropriate for the current local toolkit.** This check informs maintainability **3/5** and estimated burden **2/5**; it adds no eighth score.

| Area | Evidence and decision |
|---|---|
| Targeted library reuse | [Declarations](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/pyproject.toml) include `jsonschema`, `packaging` and optional `mcp`. Requirement parsing uses the standard `packaging.Requirement` parser. Keep this focused reuse. |
| Local HTTP | [Loopback report server](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/src/project_assess/web.py) uses fixed routes, origin/token controls and bounded bodies. Keep its local scope; a hosted multi-user service would need a fresh design review. |
| Persistence | [SQLite service](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/src/project_assess/service.py) implements immutable snapshots, transactions, replay identity and source authority. A different persistence layer would still need those guarantees. |
| Report UI | [One vanilla DOM interface](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/src/project_assess/static/app.js) uses safe insertion and stale-response guards. No demonstrated state-management burden currently justifies a framework migration. |

Deterministic collection found **11 declaration records** across two supported manifests (10 distinct names), and **9 syntax clues**: 4 in source, 2 in tooling and 3 in tests. These counts locate review work; they are not issues or scores. Development and optional dependencies stay distinct from core runtime declarations.

The ecosystem analysis is **partial** because JavaScript hints are lexical: aliases, template expressions, regular-expression literals and runtime behavior are unresolved. Declared packages do not prove runtime use. Version currency, compatibility, support, licensing, vulnerabilities and performance were not verified.

Reconsider the stack when remote/multi-user serving becomes a requirement, state-schema changes become frequent, or repeated multi-view state bugs demonstrate an ownership cost. Start with one small experiment preserving required behavior; no migration is recommended by this assessment.

## Validation and scope

**242 Python tests passed without skips**, including real CLI/MCP calls, access restrictions, concurrency, recovery and ecosystem boundaries. Ruff, offline packaging, skill validation and browser acceptance passed. Browser checks cover hostile ecosystem content, evidence navigation, keyboard access, mobile layouts and accessibility. The core wheel also ran this self-scan without the optional MCP package.

Evidence: [ecosystem tests](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/tests/test_project_assess_ecosystem.py), [capture tests](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/tests/test_project_assess_collector.py), [service tests](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/tests/test_project_assess_service.py), [browser checks](https://github.com/gburch/project-assessment-toolkit/blob/e0983985f8f87d50654c5134df8e2996814940b5/scripts/test-project-assess-browser.mjs).

No critical or high findings were recorded; this is not proof of absent risks. Deployed security, independent assurance and long-term change cost remain unverified. Imported JUnit source identity is not independently verified by collection; the reviewer corroborated the local implementation checks separately.

Collector 5 adds ecosystem evidence and changes the collection scope. This report claims no comparable score progress over earlier collector scopes. Existing saved ratings and goals remain unchanged; no project goals were selected or changed.

Assessment: `a_95f056f67a4848109cc26da6fdb46017`; review: `r_96397d07c9ec459c8e0fcf555a8a0db6`.
Source manifest: `sha256:5c6653823e979364733eca7f171315318fbe541276804cd695696eb6797b1ff2`.

Use the [guide](../PROJECT_ASSESS.md) for evidence limits, ecosystem review and publishing your own badges. Full local state and captured source evidence stay private.
