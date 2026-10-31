# Contributing to PAT

Small changes with a demonstrated benefit are welcome. Describe the problem, resulting behavior and relevant validation in your issue or pull request. Use synthetic examples rather than private source, assessment exports or credentials. Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Set up and check a change

Requires macOS or Linux, Python 3.11+ and [uv](https://docs.astral.sh/uv/). The browser checks also need Node.js 22.12+.

```bash
git clone https://github.com/gburch/project-assessment-toolkit.git
cd project-assessment-toolkit
uv sync --extra dev --extra mcp --extra analysis --locked
uv run --extra mcp --extra analysis --locked pytest -q
uv run --extra mcp --locked ruff check src tests
uv run --extra mcp --locked ruff format --check src tests
```

The default tests use local synthetic projects and state; keep them offline and free of cloud credentials. Use checks appropriate to the change: focused tests while working and the full suite for behavior or contract changes. Prose-only edits usually need command and link review. Exercise the real CLI or MCP adapter when changing its contract.

The optional `analysis` extra supplies Tree-sitter syntax parsers for JavaScript/TypeScript; the separate `vulture` extra enables the opt-in captured-source provider. Add `--extra vulture` to sync/run when testing that provider. Neither extra installs target dependencies or executes target code. Preserve a usable core installation with explicit unavailable evidence. Analyzer changes need representative source/test/tooling, large-file, truncation and uncertainty cases; keep capture, cheap metrics, sampled patterns and graph completeness distinct. Run the relevant tests after installing locked dependencies; they then stay offline. Collection scope changes must remain distinguishable from changes in project quality.

For changes to the local report UI or browser behavior:

```bash
npm ci
npm run browser:install
npm run test:browser
```

Dependency and browser installation can download packages. Browser checks use the repository's Playwright/axe dependencies and Chromium; run `browser:install` when it is missing. Screenshots go into ignored `.artifacts/`. Report assets are bundled directly; no frontend build or publication step is needed.

For skill changes, run `uv run --locked pat skills`, check that the returned entry points and referenced resources exist, and try a realistic synthetic scenario through the documented commands. Use your agent's skill validator when available. Review the resulting advice as well as the JSON: plausible syntax is not evidence of a useful assessment.

## Local delivery proof

After the relevant checks, rehearse delivery from a clean, committed PAT checkout:

```bash
uv run --offline --locked python scripts/smoke-wheel.py --output /path/outside/repos/pat-release-proof
```

Use a **new directory outside the checkout**. The command builds one wheel, exports locked core constraints and installs the wheel into a fresh environment using the existing uv cache. It verifies installed resource origins, bundled skills/guide/UI and operation without MCP. A real CLI scenario exercises scan, cited review, targets and progress, rejected review/CAS changes, and backup/restore of closed synthetic state. No personal assessment state is opened or copied.

`receipt.json` records the source revision/manifest, wheel digest, checks and any failed step. A pass requires source identity to remain unchanged. Retain the wheel, constraints and private receipt together; this is a local proof, not publication or deployment. A missing offline dependency fails rather than downloading it. `--allow-dirty` is only for development rehearsals and labels the receipt accordingly; it does not prove a committed release. See the [update and rollback procedure](docs/PROJECT_ASSESS.md#local-state-and-updates) before changing an installation or real state.

## Preserve the boundaries

- Keep scans read-only: do not execute assessed code, import its plugins, install its dependencies or contact its services. Separate test-value runtime collectors run only when explicitly requested.
- Keep collected facts, reviewer judgments and user-selected goals distinct. Preserve unknowns, evidence identity, versioned rubrics and compatible history. Static hints never become automatic scores.
- Preserve source/report access checks, secret handling, transaction consistency, concurrent-update checks and idempotency. Cover a changed boundary with meaningful behavior or recovery evidence.
- Prefer the existing shared service and the smallest adequate seam. Search callers, exports, entry points and dynamic/plugin use before extracting a helper or removing an apparent duplicate or unused symbol. Static confidence is confidence in the lead, not safe deletion. Avoid speculative frameworks, test quotas and new gates without a current need.

Keep documentation beside its canonical workflow and link to it rather than duplicating instructions. Retain third-party attribution and license notices if introducing external material. Contributions are distributed under the repository's [MIT license](LICENSE).

For another analyzer, first check whether existing captured facts or externally supplied SARIF suffice. Register a built-in provider's trusted name/availability in the [fixed registry](src/project_assess/analyzer_registry.py) and CLI selection, add a bounded captured-source adapter using the existing `analyzer-analysis` evidence shape, and supply an optional dependency when needed plus focused identity/limits/unavailable tests. Reuse shared queries, Doctor and UI; do not add target-discovered plugins, command/config loading or a parallel per-language framework. The [Vulture adapter](src/project_assess/vulture_analysis.py) uses the upstream API without vendoring its code; preserve its [MIT attribution](https://github.com/jendrikseipp/vulture/blob/main/LICENSE.txt).
