# PAT self-assessment

Self-assessed snapshot captured 2026-10-30, using rubric 4 and [source d80d84d](https://github.com/gburch/project-assessment-toolkit/tree/d80d84dfc3f41d213f9c6e48b9876a252d12a0ee). Badges describe this saved assessment, not a live certification.

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

Capability confidence is medium. Every burden score is a **source estimate with low confidence**, based on the inspected maintenance work; these are not measured upkeep hours.

Maintainability includes architecture and rigidity. The badge feature uses one pure renderer behind the shared authorized service, with small CLI/MCP adapters. No new rigidity issue was demonstrated. Extensibility supports known interfaces; a plugin framework would add machinery without a demonstrated need.

**Validation:** 215 Python tests passed without skips, including real CLI/MCP calls, access restrictions, concurrent writes and recovery. Ruff, offline packaging and the browser checks passed. Badge previews covered unknown scores, partial scans, reported findings and readable mobile layouts.

Evidence: [boundary and recovery tests](https://github.com/gburch/project-assessment-toolkit/blob/d80d84dfc3f41d213f9c6e48b9876a252d12a0ee/tests/test_project_assess_service.py), [access tests](https://github.com/gburch/project-assessment-toolkit/blob/d80d84dfc3f41d213f9c6e48b9876a252d12a0ee/tests/test_project_assess_access.py), [badge tests](https://github.com/gburch/project-assessment-toolkit/blob/d80d84dfc3f41d213f9c6e48b9876a252d12a0ee/tests/test_project_assess_badges.py), [browser checks](https://github.com/gburch/project-assessment-toolkit/blob/d80d84dfc3f41d213f9c6e48b9876a252d12a0ee/scripts/test-project-assess-browser.mjs), [shared service](https://github.com/gburch/project-assessment-toolkit/blob/d80d84dfc3f41d213f9c6e48b9876a252d12a0ee/src/project_assess/service.py), [renderer](https://github.com/gburch/project-assessment-toolkit/blob/d80d84dfc3f41d213f9c6e48b9876a252d12a0ee/src/project_assess/badges.py) and [operating guide](../PROJECT_ASSESS.md).

**Limits:** no critical or high findings were recorded; that is not proof of absent risks. JavaScript semantic analysis, deployed security, independent assurance, long-term change cost and operational toil remain unverified. Imported JUnit identity is not independently verified by collection; the reviewer corroborated the local run separately. No project goals were selected or changed.

Assessment: `a_512ed09513dc43c09e92f5314c792bfa`; review: `r_ee7b74335beb42269e18b1329033424d`.
Source manifest: `sha256:b9a95a414701c6487981efb40264cf560220468eec572972ed7361eef038bf01`.

Use the [badge guide](../PROJECT_ASSESS.md#github-badges) to publish your own reviewed snapshot. Full local state and captured source evidence stay private.
