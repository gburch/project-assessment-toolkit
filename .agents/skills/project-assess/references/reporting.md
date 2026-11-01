# Run completion and reporting

## Finish the requested work

For an ordinary "run PAT" request, carry collection through to a reviewed assessment.
The normal CLI path is `scan` → inspect captured evidence and rubric →
`review-template --mode fresh` → author ratings, coverage, change traces and plan →
the applicable `challenge-template` / independent review → `review --input FILE` →
read back `report --format json` and `report --format markdown`. Use the shared MCP
operations when connected instead. These are phases of the same assessment, not
separate tasks requiring another user prompt. Do not ask whether to interpret the
scan when the user already requested an assessment.

Honor explicit scan/inventory-only or existing-output retrieval requests. A brief
assessment still needs judgment and a useful verdict; JSON or Markdown selects
presentation, not whether to review the source and complete the assessment.

Use the judgment, scope and challenge guidance in the main skill. A scan cannot
populate the authored review by itself. Inspect representative areas across the
system map and relevant dimension providers; do not stop after the first test
leads or translate every candidate into a confirmed finding. Group symptoms into
the important causes and full intended improvement, then choose a first slice.

Missing selected goals means there is no saved target comparison. Complete the
assessment and give a clearly provisional improvement scenario without saving
targets or blocking on profile selection. Missing runtime proof limits the
corresponding claims; it does not prohibit a defensible cited source estimate.
Read and judge the source before deciding that a score is unknown. Neither
capability nor burden should be fabricated to fill the scorecard.

Collection or parser limits do not by themselves justify omitting judgment: inspect
the available source and provide the defensible assessment with its limits.
If source access, review support or a user-imposed deadline prevents completion, state **collection
only** or **provisional assessment**, explain what was actually reviewed, deliver
the supported findings, and identify the concrete remaining work. An unavailable
independent reviewer remains explicit and does not turn a limited judgment into
validated assurance. Do not label an unreviewed scan as a completed assessment.

## Give the user the assessment inline

Scale detail to the project and requested scope. A substantial project needs a
substantive explanation; avoid replacing it with scan statistics and links.
Organize the response so the user can assess the judgment without opening files:

- **Verdict and context:** what the project does, whom it serves, what fits its
  needs and the principal constraints or costs of valuable change.
- **Scorecard:** current capability and burden for all eight dimensions in a
  whole-project review, with separate confidence for each axis and selected
  capability minimums/burden ceilings when available. Explain unknowns. For a
  focused review, identify the unreviewed dimensions rather than reasserting old
  grades. State unresolved ranges beside a working point, not only in a footer.
- **Concrete findings:** prioritize the material issues and strengths with
  inspected path/line examples or captured evidence references, their practical
  effect, confidence and important counterevidence. Explain architecture,
  complexity, DRY/coupling, rigidity and upkeep when supported; tests are one input.
  Distinguish confirmed mechanisms, inferred consequences and unconfirmed leads.
- **Right-sized improvement plan:** explain the main causes, adequate target
  state, coherent initiatives, expected capability/burden direction, preserved
  guarantees and acceptance evidence. Give the first useful slice within that
  plan. Avoid inventing exact score gains, time savings or a deletion quota.
- **Coverage and confidence:** identify source/tool versions, review freshness,
  analyzed and inspected scope, omissions, actually selected optional analyzers,
  imported versus executed evidence, and the challenge result. Explain which
  limits affect the judgment; a Deep profile is not proof Joern ran or that
  runtime behavior was verified. Collection counts belong here, as context.
- **Goals and progress:** compare equivalent saved scopes when possible. Separate
  engineering change from new evidence, changed judgment or changed targets. With
  no goals/history, state that without withholding the diagnosis or plan.
- **Saved result:** include the assessment/review identity and readable report
  links or receipts for drill-down. Links supplement the inline result. Verify
  that the exported report includes the submitted judgment, not the earlier
  unreviewed scan. If saving fails, preserve the authored report and state the
  failure; do not claim persistence.

Keep severity separate from confidence: a high-confidence observation of a
necessary control is not automatically a high-severity defect. Do not report
thousands of static candidates as thousands of problems or inflate confidence
because a challenge completed. Useful controls can still impose costly burden.

## Focused modes

For Doctor, give the inspected diagnosis, material candidates with confirmed or
unresolved status, related causes and a proportionate remedy/verification plan.
Keep its scope visible; a focused Doctor run need not create whole-project grades.
For Evolve, explain goal gaps, full intended improvement, priorities, expected
burden tradeoffs and the first slice. If the saved assessment is absent or stale
for the requested judgment, gather or refresh enough evidence before presenting
recommendations; explicitly requested retrieval of existing output stays retrieval.

Test-value and doc-value reports remain focused on their own evidence and outcomes.
Use their companion skills when those audits are requested; a whole-project PAT
assessment does not authorize test execution or cleanup through another skill.
