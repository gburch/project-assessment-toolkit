# Focused simplification review

Use the doctor's captured reuse, quality and efficiency candidates to identify useful changes, not to maximize findings. For recent-work review, focus on the user's changed paths or supplied diff and the relevant callers. Exclude generated/vendor output and mechanical lockfile churn unless included in the request. A full-project assessment can sample representative costly paths; it need not propose a repository-wide rewrite.

## What to inspect

- **Reuse:** search nearby utilities, shared modules and tests before proposing another helper. Compare actual responsibilities, error handling and trust boundaries. Normalized duplicate bodies are structural similarity, not proof of interchangeable behavior.
- **Quality:** trace redundant state, brittle contracts, unnecessary delegation and unclear control flow. Dependency cycles need import timing and caller context; function-local imports may deliberately avoid initialization cycles. Mutable defaults or broad exception handlers need behavioral investigation before recommending a change.
- **Efficiency:** trace repeated reads/computation, broad loads, missing cleanup and hot-path work. Distinguish measured cost from source inference. Repeated authorization, freshness or concurrency checks may protect different moments; preserve their purpose. Parallelism requires compatible ordering, failure and transaction semantics.

For each credible finding, cite the captured location, explain the concrete cost or failure risk, identify the smallest useful change and name its closest verifier. Before changing a shared function, route, type, export or public string, search direct and dynamic references, re-exports, tests and mocks. Prefer an established local API when it preserves the required behavior. A bounded extraction is useful only when it simplifies real callers.

Imported Ruff diagnostics are supplied, source-unverified leads. Match them to the captured source before using their locations; suggested fix applicability does not establish behavioral safety or authorize application.

## When fixes are authorized

A request for assessment or doctor output authorizes advice. When implementation is also authorized, apply only high-confidence changes within that scope. Preserve outputs, error handling, permissions, source/evidence identity, transactions, concurrency and required performance properties. Inspect the final diff and run the closest relevant lint, type, unit or integration check; report the result and any gap. A suspected behavior bug needs explicit treatment as a bug fix, not a claim of behavior-preserving simplification.

Keep meaningful security, injection, isolation and domain boundaries. Avoid clever one-liners, line-count targets, generic plugin frameworks and broad helper merges. Skip uncertain candidates whose proof cost exceeds their value; explain the uncertainty when useful. No fixed number of review passes, findings or subagents is required.
