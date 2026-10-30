# Contributing to PAT

Small changes with a demonstrated benefit are welcome. Describe the problem, resulting behavior and relevant validation in your issue or pull request. Use synthetic examples rather than private source, assessment exports or credentials. Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Set up and check a change

Requires macOS or Linux, Python 3.11+ and [uv](https://docs.astral.sh/uv/). The browser checks also need Node.js 22.12+.

```bash
git clone https://github.com/gburch/project-assessment-toolkit.git
cd project-assessment-toolkit
uv sync --extra dev --extra mcp --locked
uv run --extra mcp --locked pytest -q
uv run --extra mcp --locked ruff check src tests
uv run --extra mcp --locked ruff format --check src tests
```

The default tests use local synthetic projects and state; keep them offline and free of cloud credentials. Use checks appropriate to the change: focused tests while working and the full suite for behavior or contract changes. Prose-only edits usually need command and link review. Exercise the real CLI or MCP adapter when changing its contract.

For changes to the local report UI or browser behavior:

```bash
npm ci
npm run browser:install
npm run test:browser
```

Dependency and browser installation can download packages. Browser checks use the repository's Playwright/axe dependencies and Chromium; run `browser:install` when it is missing. Screenshots go into ignored `.artifacts/`. Report assets are bundled directly; no frontend build or publication step is needed.

For skill changes, run `uv run --locked pat skills`, check that the returned entry points and referenced resources exist, and try a realistic synthetic scenario through the documented commands. Use your agent's skill validator when available. Review the resulting advice as well as the JSON: plausible syntax is not evidence of a useful assessment.

## Preserve the boundaries

- Keep scans read-only: do not execute assessed code, import its plugins, install its dependencies or contact its services. Separate test-value runtime collectors run only when explicitly requested.
- Keep collected facts, reviewer judgments and user-selected goals distinct. Preserve unknowns, evidence identity, versioned rubrics and compatible history. Static hints never become automatic scores.
- Preserve source/report access checks, secret handling, transaction consistency, concurrent-update checks and idempotency. Cover a changed boundary with meaningful behavior or recovery evidence.
- Prefer the existing shared service and the smallest adequate seam. Search callers and references before extracting a helper or removing an apparent duplicate. Avoid speculative frameworks, test quotas and new gates without a current need.

Keep documentation beside its canonical workflow and link to it rather than duplicating instructions. Retain third-party attribution and license notices if introducing external material. Contributions are distributed under the repository's [MIT license](LICENSE).
