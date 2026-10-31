"use strict";

let dims = [];
let titles = {};
const $ = (id) => document.getElementById(id);
const MAX_REVIEW_BYTES = 256 * 1024;
const state = { token: null, rubric: null, projects: [], project: null, report: null, targets: {}, revision: 0, dirty: false, load: 0, loading: true, saving: false, reviewLoading: false, reviewDirty: false, reviewAssessment: null, reviewRequest: null };
let queryLoad = 0;
let queryNext = null;
let queryParams = null;

function scanOptions() {
  return { analysis_profile: $("analysis-profile").value, analyzers: Array.from($("optional-analyzers").querySelectorAll("input[data-analyzer]:checked"), (input) => input.dataset.analyzer) };
}

function renderAnalyzers(analyzers) {
  const container = $("optional-analyzers");
  container.replaceChildren();
  for (const analyzer of analyzers) {
    const title = analyzer.title || analyzer.name[0].toUpperCase() + analyzer.name.slice(1);
    const languages = (analyzer.languages || []).map((language) => language[0].toUpperCase() + language.slice(1)).join("/");
    const label = node("label", undefined, "inline-check");
    const input = node("input");
    input.type = "checkbox";
    input.id = `analyzer-${analyzer.name}`;
    input.dataset.analyzer = analyzer.name;
    input.disabled = state.loading || state.saving;
    const status = node("p", analyzer.available ? `${title} ${analyzer.version || ""} is available. Findings need caller and contract review.` : `${title}${analyzer.version ? ` ${analyzer.version} is unavailable` : " is not installed"}. Selecting it records unavailable evidence; scanning never installs it.`, "secondary");
    status.id = `${analyzer.name}-status`;
    input.setAttribute("aria-describedby", status.id);
    label.htmlFor = input.id;
    label.append(input, node("span", `Include ${title}${languages ? ` ${languages}` : ""} analysis`));
    const option = node("div");
    option.append(label, status);
    container.append(option);
  }
  if (!analyzers.length) container.append(node("p", "No optional analyzers are registered.", "secondary"));
}

function node(tag, text, className) {
  const el = document.createElement(tag);
  if (tag === "pre") el.tabIndex = 0;
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
function message(text, error = false) {
  $("error").hidden = !error;
  $(error ? "error" : "status").textContent = text;
}
async function api(path, body) {
  const opts = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers = { "Content-Type": "application/json", "X-Project-Assess-Token": state.token };
    opts.body = JSON.stringify(body);
  }
  const response = await fetch(path, opts);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
  return result;
}
function scoreMax(dim) { return state.rubric.dimensions[dim].capability.length - 1; }
function score(value, dim) { return Number.isInteger(value) ? `${value} / ${scoreMax(dim)}` : "Unknown"; }
function jsonText(value) { return JSON.stringify(value, null, 2); }
function rubDescription(dim, axis, value) {
  return Number.isInteger(value) ? state.rubric.dimensions?.[dim]?.[axis]?.[value] || "" : "Evidence is insufficient to assign a value.";
}
function renderRatings(report) {
  $("ratings").replaceChildren();
  for (const dim of dims) {
    const rating = report.review?.ratings?.[dim];
    const box = node("article", undefined, "rating");
    const header = node("header");
    header.append(node("h3", titles[dim]), node("span", rating ? `Capability · ${rating.confidence} confidence` : "Not reviewed", "confidence"));
    box.append(header);
    for (const axis of ["capability", "burden"]) {
      const value = rating?.[axis];
      const row = node("div", undefined, "score-row");
      row.append(node("span", axis === "capability" ? "Capability" : "Upkeep burden"), node("span", score(value, dim), "score-value"));
      box.append(row);
      if (Number.isInteger(value)) {
        const track = node("div", undefined, "track");
        track.setAttribute("aria-hidden", "true");
        const fill = node("div", undefined, "fill");
        fill.style.width = `${value / scoreMax(dim) * 100}%`;
        track.append(fill);
        box.append(track);
      }
      if (axis === "burden" && Number.isInteger(value)) {
        const basis = rating.burden_basis === "observed" ? "Observed" : "Estimated from source";
        box.append(node("p", `${basis} · ${rating.burden_confidence || "low"} confidence`, "secondary"));
      }
      box.append(node("p", rubDescription(dim, axis, value), "secondary"));
    }
    const architecture = report.assessment.facts?.maintainability;
    if (dim === "maintainability" && architecture) {
      const detail = node("details");
      detail.id = "architecture-hints";
      detail.append(node("summary", "Architecture hints to review"));
      detail.append(node("p", `Forwarding functions: ${architecture.forwarding_functions ?? 0}. Abstract or protocol classes: ${architecture.abstract_classes ?? 0}.`));
      detail.append(node("p", "These patterns can be useful boundaries. Counts are review hints, never an automatic burden score.", "secondary"));
      const candidates = (report.assessment.evidence || []).filter((evidence) =>
        (evidence.stats?.forwarding_functions || 0) + (evidence.stats?.abstract_classes || 0) > 0
      ).sort((a, b) =>
        ((b.stats.forwarding_functions || 0) + (b.stats.abstract_classes || 0)) -
        ((a.stats.forwarding_functions || 0) + (a.stats.abstract_classes || 0)) || a.path.localeCompare(b.path)
      );
      detail.append(node("p", `${candidates.length} candidate file${candidates.length === 1 ? "" : "s"}; showing ${Math.min(8, candidates.length)} with the most hints.`, "evidence-meta"));
      if (candidates.length) {
        const list = node("ul");
        for (const evidence of candidates.slice(0, 8)) {
          list.append(node("li", `${evidence.path}: ${evidence.stats.forwarding_functions || 0} forwarding functions; ${evidence.stats.abstract_classes || 0} abstract or protocol classes.`));
        }
        detail.append(list);
      }
      box.append(detail);
    }
    if (rating?.rationale) {
      const detail = node("details");
      detail.append(node("summary", "Why this rating"), node("p", rating.rationale));
      if (rating.evidence_ids?.length) detail.append(node("p", `Evidence: ${rating.evidence_ids.join(", ")}`, "evidence-meta"));
      box.append(detail);
    }
    $("ratings").append(box);
  }
}
function validTarget(dim, value) {
  return Number.isInteger(value) && value >= 0 && value <= scoreMax(dim);
}
function missingTargets() {
  return dims.filter((dim) => !validTarget(dim, state.targets[dim]?.capability_min) ||
    !validTarget(dim, state.targets[dim]?.burden_max));
}
function updateControls() {
  $("analysis-profile").disabled = state.loading || state.saving;
  for (const input of $("optional-analyzers").querySelectorAll("input[data-analyzer]")) input.disabled = state.loading || state.saving;
  const busy = state.loading || state.saving || !state.report;
  $("scan").disabled = !state.token || state.loading || state.saving;
  $("scan-root").disabled = state.loading || state.saving;
  $("profile").disabled = busy;
  for (const input of $("goal-controls").querySelectorAll("input")) input.disabled = busy;
  $("save").disabled = busy || !state.dirty || missingTargets().length > 0;
  $("rescan").disabled = busy;
  for (const id of ["review-load", "review-file", "review-json"]) $(id).disabled = busy || state.reviewLoading;
  $("review-submit").disabled = busy || state.reviewLoading || !state.reviewDirty ||
    state.reviewAssessment !== state.report?.assessment.id || !$("review-json").value.trim();
}
function allowDiscard() {
  return !(state.dirty || state.reviewDirty) ||
    window.confirm("Discard unsaved target or review edits? Sent requests will still finish.");
}
function resetReview() {
  state.reviewLoading = false;
  state.reviewDirty = false;
  state.reviewAssessment = null;
  state.reviewRequest = null;
  $("review-json").value = "";
  $("review-file").value = "";
  $("review-editor").open = false;
  $("review-state").textContent = "Load a template or import a review for this snapshot.";
}
function currentSnapshot(load, id) {
  return load === state.load && state.report?.assessment.id === id;
}
function dirty() {
  state.dirty = true;
  updateControls();
  const missing = missingTargets();
  $("goal-state").textContent = missing.length ? `Saved goals need targets for ${missing.map((dim) => titles[dim]).join(", ")}` : "Unsaved targets";
}
function renderControls(goals) {
  state.revision = goals?.revision || 0;
  state.dirty = false;
  state.targets = Object.fromEntries(dims.map((dim) => [dim, goals ? {
    capability_min: goals.targets[dim]?.capability_min ?? null,
    burden_max: goals.targets[dim]?.burden_max ?? null
  } : { capability_min: 0, burden_max: scoreMax(dim) }]));
  const missing = missingTargets();
  $("profile").value = missing.length ? "" : goals?.profile || "";
  $("goal-controls").replaceChildren();
  for (const dim of dims) {
    const row = node("div", undefined, "goal-row");
    row.append(node("h3", titles[dim]));
    const pair = node("div", undefined, "control-pair");
    for (const axis of ["capability_min", "burden_max"]) {
      const label = node("label");
      const heading = node("span", undefined, "control-heading");
      const name = axis === "capability_min" ? "Capability minimum" : "Burden ceiling";
      const selected = state.targets[dim][axis];
      const value = node("output", Number.isInteger(selected) ? `${selected} / ${scoreMax(dim)}` : "Not set", "score-value");
      const input = node("input");
      input.type = Number.isInteger(selected) ? "range" : "number";
      input.min = "0";
      input.max = String(scoreMax(dim));
      input.step = "1";
      input.value = selected ?? "";
      if (input.type === "number") input.placeholder = "Not set";
      input.setAttribute("aria-valuetext", Number.isInteger(selected) ? `${selected} of ${scoreMax(dim)}` : "Not set");
      input.id = `${dim}-${axis}`;
      input.setAttribute("aria-label", `${titles[dim]} ${name.toLowerCase()}`);
      value.htmlFor = input.id;
      heading.append(node("span", name), value);
      input.addEventListener("input", () => {
        const chosen = input.value === "" ? null : Number(input.value);
        state.targets[dim][axis] = chosen;
        const valid = validTarget(dim, chosen);
        value.textContent = chosen === null ? "Not set" : valid ? `${chosen} / ${scoreMax(dim)}` : `Choose 0–${scoreMax(dim)}`;
        input.setAttribute("aria-valuetext", valid ? `${chosen} of ${scoreMax(dim)}` : value.textContent);
        $("profile").value = "";
        dirty();
      });
      label.append(heading, input);
      pair.append(label);
    }
    row.append(pair);
    $("goal-controls").append(row);
  }
  $("goal-state").textContent = missing.length ? `Saved goals need targets for ${missing.map((dim) => titles[dim]).join(", ")}` :
    goals ? `Saved goal version ${goals.revision}` : "No goals saved. Choose a profile or adjust targets.";
  updateControls();
}
function renderProgress(progress) {
  $("progress").replaceChildren();
  if (!progress || !state.report.goals) {
    $("progress-summary").textContent = "Save goals to establish your first baseline.";
    return;
  }
  const eventLabels = {
    no_goals: "Save goals to establish your first baseline.",
    goal_baseline: "New goal baseline. No engineering progress is recorded for changing goals.",
    evidence_update: "Assessment/evidence update. Re-rating a snapshot adds no engineering progress.",
    source_change: "Source changed since the goal baseline. Capability and burden movement are shown separately.",
    not_comparable: "Evidence scope or rubric changed. These assessments are not comparable."
  };
  $("progress-summary").textContent = eventLabels[progress.event] || "Capability and burden gaps are tracked separately. Unknown evidence is not a zero.";
  if (progress.assessment_id && progress.assessment_id !== state.report.assessment.id) {
    $("progress-summary").append(` Progress uses the latest assessment (${progress.assessment_id}); the evidence above belongs to the historical assessment you selected.`);
  }
  if (progress.provisional) $("progress-summary").append(" Movement includes estimates or low-confidence ratings.");
  const values = progress.dimensions || progress.gaps || {};
  for (const dim of dims) {
    const value = values[dim];
    if (!value) continue;
    const row = node("div", undefined, "progress-row");
    const show = (v) => Number.isInteger(v) ? `${v} step${v === 1 ? "" : "s"}` : "Unknown";
    row.append(node("strong", titles[dim]), node("span", `Capability gap: ${show(value.capability_gap)}`), node("span", `Burden gap: ${show(value.burden_gap)}`));
    if (value.capability_steps !== undefined || value.burden_steps !== undefined) {
      row.append(node("span", `Movement — capability: ${value.capability_steps ?? "unknown"}; burden: ${value.burden_steps ?? "unknown"}`));
    }
    $("progress").append(row);
  }
  const remaining = progress.remaining_steps;
  const movement = progress.steps_closer;
  if (Number.isInteger(remaining)) $("progress-summary").append(` Remaining gap: ${remaining} rubric steps.`);
  if (Number.isInteger(movement)) $("progress-summary").append(` Assessed movement from baseline: ${movement > 0 ? "+" : ""}${movement} steps closer.`);
  const engineering = progress.engineering_progress_steps;
  if (Number.isInteger(engineering)) $("progress-summary").append(` Engineering progress: ${engineering > 0 ? "+" : ""}${engineering} rubric steps.`);
}
function renderFindings(report) {
  const findings = [...(report.assessment.findings || []), ...(report.review?.findings || [])];
  $("findings").replaceChildren();
  for (const finding of findings) {
    const item = node("div", undefined, "finding");
    item.append(node("span", `${finding.severity || "Observation"}: `, "severity"), node("span", finding.title || finding.message || "Evidence observation"));
    if (finding.evidence_ids?.length) item.append(node("p", `Evidence: ${finding.evidence_ids.join(", ")}`, "evidence-meta"));
    $("findings").append(item);
  }
  const recommendations = dims.flatMap((d) => (report.review?.ratings?.[d]?.recommendations || []).map((text) => `${titles[d]}: ${text}`));
  $("recommendations").replaceChildren(...recommendations.map((text) => node("li", text)));
  $("findings-empty").textContent = !report.review ? "An evidence-backed skill review can add ratings and recommendations. File counts alone do not establish maturity or excess burden." : findings.length || recommendations.length ? "" : "No findings or recommendations recorded. This is not a certification.";
}
function textList(parent, heading, items) {
  parent.append(node("h3", heading));
  if (!items?.length) { parent.append(node("p", "None recorded.", "secondary")); return; }
  const list = node("ul");
  list.append(...items.map((item) => node("li", item)));
  parent.append(list);
}
function renderAlignment(alignment) {
  const states = {
    no_review: "No saved review. Diagnosis, coverage and an improvement plan remain unknown.",
    missing_plan: "No full improvement plan recorded. Numeric directions alone are not a roadmap.",
    scenario_unconfirmed: "Proposed or unbound plan: select targets explicitly and confirm the plan. No goals are saved automatically.",
    targets_changed: "Saved goals differ from this plan's assumptions. Review the plan before using it for the new targets.",
    not_comparable: "The saved plan and goals use incompatible rubric identities. Reconfirm them before choosing changes.",
    ready: "Plan is bound to the selected goals. This does not mean the goals are achieved or the plan is independently validated."
  };
  $("plan-state").textContent = states[alignment?.planning_status] || "Planning context was not recorded for this report.";
  $("plan-urgent").replaceChildren();
  if (alignment?.urgent_findings?.length) {
    textList($("plan-urgent"), "Critical and high findings remain priorities", alignment.urgent_findings.map((finding) => `${finding.severity}: ${finding.title || finding.message} · Evidence: ${(finding.evidence_ids || []).join(", ") || "see captured finding"}`));
  }
  const coverage = $("review-coverage");
  coverage.replaceChildren();
  if (alignment?.coverage) {
    const value = alignment.coverage;
    const details = node("details");
    details.append(node("summary", `Review coverage · ${value.scope === "whole_project" ? "whole project" : "focused"}`));
    textList(details, "Examined areas", value.examined.map((area) => `${area.area} · Evidence: ${area.evidence_ids.join(", ")}`));
    textList(details, "Unexamined areas", value.unexamined.map((area) => `${area.area}: ${area.reason}`));
    textList(details, "Limits on conclusions", value.limitations);
    textList(details, "Validation evidence", value.validation.map((check) => `${check.check}: ${check.status} · Evidence: ${check.evidence_ids.join(", ") || "none supplied"}`));
    coverage.append(details);
    if (value.unexamined.length || value.limitations.length) coverage.append(node("p", `${value.unexamined.length} unexamined area(s); ${value.limitations.length} review limitation(s). Collection counts do not establish review coverage.`, "secondary"));
  } else coverage.append(node("p", "Review coverage was not recorded. Examined and unexamined areas remain unknown.", "secondary"));
  const container = $("improvement-plan");
  container.replaceChildren();
  const plan = alignment?.plan;
  if (plan) {
    container.append(node("h3", "Diagnosis"), node("p", plan.diagnosis), node("h3", "Full target state"), node("p", plan.target_state));
    const list = node("ol", undefined, "plan-list");
    for (const initiative of plan.initiatives) {
      const item = node("li", undefined, "initiative");
      item.append(node("h3", `${initiative.title} · ${initiative.priority}`), node("p", `Root cause: ${initiative.root_cause}`), node("p", `Full scope: ${initiative.scope}`));
      textList(item, "Intended dimension effects", Object.entries(initiative.dimension_impacts).map(([dim, effect]) => `${titles[dim] || dim}: ${effect}`));
      textList(item, "Acceptance for the full outcome", initiative.acceptance);
      item.append(node("p", `Upkeep effect: ${initiative.burden_effect}`), node("p", `Depends on: ${initiative.depends_on.join(", ") || "No dependencies recorded"}`), node("p", `Evidence: ${initiative.evidence_ids.join(", ")}`, "evidence-meta"));
      const first = node("details");
      first.append(node("summary", "First implementation slice"), node("p", initiative.first_slice));
      item.append(first);
      list.append(item);
    }
    container.append(list);
    if (!plan.initiatives.length) container.append(node("p", "No change initiatives recorded. Preserve useful capability and keep unresolved findings visible."));
  }
  $("dimension-guidance").replaceChildren();
  for (const [dim, value] of Object.entries(alignment?.dimensions || {})) {
    const detail = node("details");
    detail.append(node("summary", `${titles[dim] || dim} · ${value.action}`), node("p", value.rationale || "No judgment rationale recorded."), node("p", value.next_step), node("p", `Acceptance direction: ${value.verification}`));
    if (value.recommendations?.length) textList(detail, "Saved recommendations", value.recommendations);
    $("dimension-guidance").append(detail);
  }
}
function resetEvidenceBrowser(assessment) {
  ++queryLoad;
  queryNext = queryParams = null;
  $("evidence-query-form").reset();
  $("query-results").replaceChildren();
  $("query-state").textContent = "Choose filters and query the saved snapshot.";
  $("query-submit").disabled = false;
  $("query-more").hidden = true;
  for (const [id, values, label] of [
    ["query-kind", [...new Set(assessment.evidence.map((entry) => entry.kind))], "All kinds"],
    ["query-candidate", [...new Set(assessment.evidence.flatMap((entry) => Object.keys(entry.stats?.candidate_counts?.by_kind || {}).concat((entry.stats?.candidates || []).map((candidate) => candidate.kind).filter(Boolean))))], "All leads"]
  ]) {
    $(id).replaceChildren(node("option", label));
    $(id).firstChild.value = "";
    for (const value of values.sort()) { const option = node("option", value); option.value = value; $(id).append(option); }
  }
}
function evidenceResult(row, load, assessmentId) {
  const item = node("details", undefined, "evidence-result");
  const location = row.locations?.[0] || (row.path ? row : null);
  item.append(node("summary", `${row.kind || row.name || row.record_type || row.evidence_kind || "Evidence"}${location ? ` · ${location.path}${location.line ? `:${location.line}` : ""}` : ""}`), node("pre", jsonText(row)));
  // Join by captured path; analysis evidence IDs cannot authorize arbitrary file reads.
  const source = location && state.report.assessment.evidence.find((entry) => entry.path === location.path && ["python", "javascript", "source", "documentation", "manifest", "configuration"].includes(entry.kind));
  if (source) {
    const button = node("button", "Read matching source context");
    button.type = "button";
    const context = node("div", undefined, "context-result");
    context.setAttribute("aria-live", "polite");
    button.addEventListener("click", async () => {
      if (!currentSnapshot(load, assessmentId)) return;
      button.disabled = true;
      context.replaceChildren(node("p", "Checking captured source identity…"));
      try {
        const line = Number.isInteger(location.line) ? location.line : 1;
        const parameters = new URLSearchParams({ assessment_id: assessmentId, evidence_id: source.id, line: String(line), end_line: String(Math.min(location.end_line || line + 39, line + 39)), max_chars: "8000" });
        const result = await api(`/api/source-context?${parameters}`);
        if (!currentSnapshot(load, assessmentId)) return;
        context.replaceChildren(node("p", `${result.path}:${result.line}–${result.end_line} · ${result.source_identity}`, "evidence-meta"), node("pre", result.excerpt), node("p", `${result.caveat}${result.truncated ? " Range was truncated." : ""}`, "secondary"));
      } catch (error) {
        if (currentSnapshot(load, assessmentId)) context.replaceChildren(node("p", error.message, "severity"));
      } finally { if (currentSnapshot(load, assessmentId)) button.disabled = false; }
    });
    item.append(button, context);
  }
  return item;
}
async function queryEvidence(append = false) {
  if (!state.report || state.loading || (append && queryNext === null)) return;
  const load = state.load;
  const assessmentId = state.report.assessment.id;
  const ticket = ++queryLoad;
  const parameters = append ? new URLSearchParams(queryParams) : new URLSearchParams({ assessment_id: assessmentId, limit: "20", max_chars: "16000" });
  if (!append) for (const [key, id] of [["view", "query-view"], ["kind", "query-kind"], ["role", "query-role"], ["candidate_kind", "query-candidate"], ["path", "query-path"]]) {
    if ($(id).value) parameters.set(key, $(id).value);
  }
  parameters.set("offset", String(append ? queryNext : 0));
  queryParams = parameters.toString();
  $("query-submit").disabled = $("query-more").disabled = true;
  $("query-state").textContent = "Querying captured evidence…";
  try {
    const result = await api(`/api/evidence-query?${parameters}`);
    if (!currentSnapshot(load, assessmentId) || ticket !== queryLoad) return;
    if (!append) $("query-results").replaceChildren();
    $("query-results").append(...result.items.map((row) => evidenceResult(row, load, assessmentId)));
    queryNext = result.next_offset;
    $("query-more").hidden = queryNext === null;
    const analysis = (result.analysis_scope || []).map((entry) => `${entry.status || "unknown"}: ${entry.candidate_counts.indexed ?? "unknown"}/${entry.candidate_counts.total ?? "unknown"} leads indexed`).join("; ");
    $("query-state").textContent = `${result.matched} matching row(s); ${$("query-results").children.length} shown. ${result.collection_complete ? "" : "Source collection is partial. "}${result.gap || ""}${result.oversized_rows ? " Oversized rows omitted; narrow the view or filters." : ""}${analysis ? ` Analysis scope: ${analysis}.` : ""}`;
  } catch (error) {
    if (currentSnapshot(load, assessmentId) && ticket === queryLoad) $("query-state").textContent = error.message;
  } finally {
    if (currentSnapshot(load, assessmentId) && ticket === queryLoad) $("query-submit").disabled = $("query-more").disabled = false;
  }
}
$("evidence-query-form").addEventListener("submit", (event) => { event.preventDefault(); queryEvidence(); });
$("query-more").addEventListener("click", () => queryEvidence(true));
$("evidence-query-form").addEventListener("input", () => {
  ++queryLoad;
  queryNext = null;
  $("query-more").hidden = true;
  $("query-submit").disabled = false;
  $("query-state").textContent = "Filters changed. Query evidence to apply them.";
});
function renderEvidence(assessment) {
  resetEvidenceBrowser(assessment);
  $("facts").textContent = jsonText(assessment.facts);
  $("coverage").textContent = `Rubric ${assessment.rubric_version}; ${assessment.evidence?.length || 0} evidence records. ${assessment.complete === false ? "Collection is incomplete." : "Source collection completed; runtime assurance still requires evidence."}`;
  $("gaps").replaceChildren();
  if (assessment.gaps?.length) {
    const list = node("ul");
    list.append(...assessment.gaps.map((gap) => node("li", typeof gap === "string" ? gap : jsonText(gap))));
    $("gaps").append(list);
  }
  $("evidence").replaceChildren();
  $("evidence-summary").textContent = `Captured evidence (${assessment.evidence?.length || 0} records)`;
  for (const evidence of assessment.evidence || []) {
    const detail = node("details");
    detail.dataset.evidenceId = evidence.id;
    detail.append(node("summary", `${evidence.path} · ${evidence.kind}`), node("p", `${evidence.id} · ${evidence.digest}`, "evidence-meta"));
    if (evidence.stats) detail.append(node("pre", jsonText(evidence.stats)));
    if (evidence.excerpt) detail.append(node("pre", evidence.excerpt));
    $("evidence").append(detail);
  }
  $("ecosystem-fit")?.remove();
  const ecosystem = assessment.facts?.ecosystem_fit;
  const captured = (assessment.evidence || []).find((evidence) =>
    evidence.id === ecosystem?.evidence_id && evidence.kind === "ecosystem-analysis"
  );
  const detail = node("details");
  detail.id = "ecosystem-fit";
  detail.append(node("summary", "Ecosystem fit"));
  if (!ecosystem) {
    detail.append(node("p", "Not collected for this snapshot. Scan again to capture ecosystem evidence."));
  } else {
    const supported = ecosystem.schema_version === 1 && captured?.stats?.schema_version === 1;
    const status = supported ? ecosystem.status : "unsupported";
    detail.append(node("p", `Collection: ${status}. Dependency declarations: ${supported ? ecosystem.dependency_count ?? "unknown" : "unknown"}; syntax signals: ${supported ? ecosystem.signal_count ?? "unknown" : "unknown"}.`));
    if (!supported) detail.append(node("p", "Captured ecosystem evidence is missing or unsupported. Scan again with a compatible collector."));
    detail.append(node("p", "Declarations and syntax signals are review leads, not a fit rating or a migration recommendation. Existing primitives may be the best fit.", "secondary"));
    if (ecosystem.gaps?.length) {
      const gaps = node("ul");
      gaps.append(...ecosystem.gaps.map((gap) => node("li", gap)));
      detail.append(gaps);
    }
    if (captured) {
      const button = node("button", "Inspect Ecosystem fit evidence");
      button.type = "button";
      button.addEventListener("click", () => {
        const record = Array.from($("evidence").children).find((entry) => entry.dataset.evidenceId === captured.id);
        if (!record) return;
        $("evidence-summary").parentElement.open = true;
        record.open = true;
        record.querySelector("summary").focus();
        record.scrollIntoView({ block: "nearest" });
      });
      detail.append(button);
    }
  }
  $("gaps").before(detail);
}
function renderHistory(history) {
  $("history").replaceChildren();
  const events = [
    ...history.assessments.map((record) => ({ ...record, type: "Source scan", assessment_id: record.id })),
    ...history.reviews.map((record) => ({ ...record, type: "Review · evidence update" })),
    ...history.goals.map((record) => ({ ...record, type: "Goal change · new baseline", message: `Goal version ${record.revision}. No engineering progress recorded.` }))
  ].sort((a, b) => (a.created_at || "").localeCompare(b.created_at || ""));
  for (const event of [...events].reverse()) {
    const item = node("div", undefined, "event");
    item.append(node("strong", event.type));
    item.append(node("small", event.created_at));
    if (event.message) item.append(node("p", event.message));
    const id = event.assessment_id;
    if (id) {
      const button = node("button", "View assessment");
      button.type = "button";
      button.addEventListener("click", () => { if (allowDiscard()) loadReport(id); });
      item.append(button);
    }
    $("history").append(item);
  }
  if (!events.length) $("history").append(node("p", "No history events recorded.", "secondary"));
}
async function loadReport(id) {
  const load = ++state.load;
  state.loading = true;
  state.saving = false;
  state.dirty = false;
  state.report = null;
  resetReview();
  $("report").hidden = true;
  updateControls();
  message("Loading assessment…");
  try {
    const result = await api(`/api/report?assessment_id=${encodeURIComponent(id)}`);
    if (load !== state.load) return;
    state.report = result;
    state.project = state.projects.find((p) => p.id === result.assessment.project_id);
    $("report").hidden = false;
    $("empty").hidden = true;
    $("project-name").textContent = state.project.name;
    const source = result.assessment.source;
    $("source").textContent = `${source.root} · ${source.revision || "Unversioned source"}${source.dirty ? " · modified worktree" : ""}`;
    const collection = result.assessment.facts?.collection || {};
    $("analysis-profile").value = collection.analysis_profile || "standard";
    for (const input of $("optional-analyzers").querySelectorAll("input[data-analyzer]")) input.checked = (collection.analyzers || []).includes(input.dataset.analyzer);
    $("analysis-scope").textContent = `Analysis: ${collection.analysis_profile || "legacy"}${collection.supported_text_complete === undefined ? "" : ` · supported text ${collection.supported_text_complete ? "captured" : "partial"}`}${collection.deadline_exceeded ? " · analysis deadline reached" : ""}${collection.analyzers?.length ? ` · optional: ${collection.analyzers.join(", ")}` : ""}.`;
    renderRatings(result);
    renderControls(result.goals);
    renderProgress(result.progress);
    renderFindings(result);
    renderAlignment(result.goal_alignment);
    renderEvidence(result.assessment);
    const history = await api(`/api/history?project_id=${encodeURIComponent(result.assessment.project_id)}`);
    if (load !== state.load) return;
    renderHistory(history);
    message(`Assessment ${result.assessment.id}. Ratings are evidence-backed judgments, separate from collected facts.`);
  } catch (error) {
    if (load === state.load) message(error.message, true);
  } finally {
    if (load === state.load) {
      state.loading = false;
      updateControls();
    }
  }
}
function renderProjectOptions(selected) {
  $("project").replaceChildren(node("option", "Choose a project"));
  $("project").firstChild.value = "";
  for (const project of state.projects) {
    const option = node("option", project.name || project.root);
    option.value = project.id;
    $("project").append(option);
  }
  $("project").value = selected || "";
}
async function loadProjects(selected) {
  const load = state.load;
  const projects = await api("/api/projects");
  if (load !== state.load) return;
  state.projects = projects;
  const project = state.projects.find((p) => p.id === selected) || state.projects[0];
  renderProjectOptions(project?.id);
  if (project) {
    $("project").value = project.id;
    state.project = project;
    await loadReport(project.latest_assessment_id);
  } else {
    state.loading = false;
    $("empty").hidden = false;
    $("report").hidden = true;
    message("No projects have been assessed yet.");
  }
  updateControls();
}
$("project").addEventListener("change", async () => {
  if (!allowDiscard()) {
    $("project").value = state.project?.id || "";
    return;
  }
  const project = state.projects.find((p) => p.id === $("project").value);
  if (!project) {
    ++state.load;
    state.project = null;
    state.report = null;
    state.loading = false;
    state.saving = false;
    state.dirty = false;
    resetReview();
    $("report").hidden = true;
    updateControls();
    return;
  }
  state.project = project;
  await loadReport(project.latest_assessment_id);
});
$("profile").addEventListener("change", () => {
  if (state.loading || state.saving || !state.report) return;
  const name = $("profile").value;
  const profile = state.rubric.profiles?.[name];
  if (!profile) return;
  renderControls({ revision: state.revision, targets: profile.targets, profile: name });
  dirty();
});
$("goal-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.loading || state.saving || !state.dirty || missingTargets().length || !state.project ||
      state.report?.assessment.project_id !== state.project.id) return;
  const projectId = state.project.id;
  const load = state.load;
  const payload = {
    project_id: projectId,
    targets: structuredClone(state.targets),
    expected_revision: state.revision,
    profile: $("profile").value || null
  };
  const current = () => load === state.load && state.project?.id === projectId;
  state.saving = true;
  updateControls();
  try {
    const goals = await api("/api/targets", payload);
    if (!current()) return;
    state.report.goals = goals;
    renderControls(goals);
    const [progress, history, evolve] = await Promise.all([
      api(`/api/progress?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/history?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/evolve?assessment_id=${encodeURIComponent(state.report.assessment.id)}`)
    ]);
    if (!current()) return;
    renderProgress(progress);
    renderHistory(history);
    state.report.goal_alignment = evolve.goal_alignment;
    renderAlignment(evolve.goal_alignment);
    message("Goals saved. This starts a new baseline; it does not record engineering progress.");
  } catch (error) {
    if (current()) message(`${error.message}. Reload the report if another session changed its goals.`, true);
  } finally {
    if (current()) {
      state.saving = false;
      updateControls();
    }
  }
});
$("rescan").addEventListener("click", async () => {
  if (!state.project || !state.report || state.loading || state.saving || !allowDiscard()) return;
  const project = state.project;
  const projectId = project.id;
  const load = state.load;
  state.saving = true;
  updateControls();
  message("Inspecting project files…");
  try {
    const snapshot = await api("/api/scan", { project_id: projectId, ...scanOptions() });
    project.latest_assessment_id = snapshot.id;
    if (load !== state.load || state.project?.id !== projectId) return;
    await loadReport(snapshot.id);
  } catch (error) {
    if (load === state.load) message(error.message, true);
  } finally {
    if (load === state.load) {
      state.saving = false;
      updateControls();
    }
  }
});
$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const root = $("scan-root").value.trim();
  if (!root || !state.token || state.loading || state.saving || !allowDiscard()) return;
  const load = state.load;
  state.saving = true;
  updateControls();
  message("Inspecting project files…");
  try {
    const snapshot = await api("/api/scan", { root, ...scanOptions() });
    const known = state.projects.find((project) => project.id === snapshot.project_id);
    if (known) known.latest_assessment_id = snapshot.id;
    const projects = await api("/api/projects");
    // Register completed scans without changing the active view or its drafts.
    for (const project of projects) {
      const existing = state.projects.find((item) => item.id === project.id);
      if (existing) Object.assign(existing, project);
      else state.projects.push(project);
    }
    renderProjectOptions($("project").value);
    if (load !== state.load) return;
    $("project").value = snapshot.project_id;
    await loadReport(snapshot.id);
  } catch (error) {
    if (load === state.load) message(error.message, true);
  } finally {
    if (load === state.load) {
      state.saving = false;
      updateControls();
    }
  }
});
$("review-load").addEventListener("click", async () => {
  if (!state.report || state.loading || state.saving || state.reviewLoading ||
      (state.reviewDirty && !window.confirm("Replace the unsaved review JSON with a fresh template?"))) return;
  const load = state.load;
  const id = state.report.assessment.id;
  state.reviewLoading = true;
  updateControls();
  try {
    const review = await api(`/api/review-template?assessment_id=${encodeURIComponent(id)}`);
    if (!currentSnapshot(load, id)) return;
    $("review-json").value = jsonText(review);
    state.reviewAssessment = id;
    state.reviewRequest = null;
    state.reviewDirty = true;
    $("review-state").textContent = "Unsaved review template. Edit judgments and evidence citations before submitting.";
  } catch (error) {
    if (currentSnapshot(load, id)) message(error.message, true);
  } finally {
    if (currentSnapshot(load, id)) {
      state.reviewLoading = false;
      updateControls();
    }
  }
});
$("review-file").addEventListener("change", async () => {
  const file = $("review-file").files[0];
  if (!file || !state.report || state.loading || state.saving || state.reviewLoading) return;
  const load = state.load;
  const id = state.report.assessment.id;
  state.reviewLoading = true;
  updateControls();
  try {
    if (file.size > MAX_REVIEW_BYTES) throw new Error("Review JSON files must be at most 256 KiB");
    const review = JSON.parse(await file.text());
    if (!currentSnapshot(load, id)) return;
    $("review-json").value = jsonText(review);
    state.reviewAssessment = id;
    state.reviewRequest = null;
    state.reviewDirty = true;
    $("review-state").textContent = "Imported JSON is unsaved. Check its snapshot identity, judgments and citations, then submit explicitly.";
  } catch (error) {
    if (currentSnapshot(load, id)) message(error.message, true);
  } finally {
    if (currentSnapshot(load, id)) {
      $("review-file").value = "";
      state.reviewLoading = false;
      updateControls();
    }
  }
});
$("review-json").addEventListener("input", () => {
  if (!state.report || state.loading || state.saving || state.reviewLoading) return;
  state.reviewAssessment = state.report.assessment.id;
  state.reviewRequest = null;
  state.reviewDirty = true;
  $("review-state").textContent = "Unsaved review JSON";
  updateControls();
});
$("review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.report || state.loading || state.saving || state.reviewLoading || !state.reviewDirty ||
      state.reviewAssessment !== state.report.assessment.id) return;
  const load = state.load;
  const id = state.report.assessment.id;
  let review;
  try {
    if (new TextEncoder().encode($("review-json").value).length > MAX_REVIEW_BYTES) throw new Error("Review JSON must be at most 256 KiB");
    review = JSON.parse($("review-json").value);
  } catch (error) {
    message(error.message, true);
    return;
  }
  state.reviewRequest ||= crypto.randomUUID();
  const payload = { assessment_id: id, review, request_id: state.reviewRequest };
  if (new TextEncoder().encode(JSON.stringify(payload)).length > MAX_REVIEW_BYTES) {
    message("Review JSON and its request metadata must fit within 256 KiB", true);
    return;
  }
  state.saving = true;
  updateControls();
  let saved;
  try {
    saved = await api("/api/review", payload);
    if (!currentSnapshot(load, id)) return;
    state.report.review = saved;
    state.reviewDirty = false;
    $("review-state").textContent = `Saved review ${saved.id}`;
    renderRatings(state.report);
    renderFindings(state.report);
    const projectId = state.report.assessment.project_id;
    const [progress, history, evolve] = await Promise.all([
      api(`/api/progress?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/history?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/evolve?assessment_id=${encodeURIComponent(id)}`)
    ]);
    if (!currentSnapshot(load, id)) return;
    renderProgress(progress);
    renderHistory(history);
    state.report.goal_alignment = evolve.goal_alignment;
    renderAlignment(evolve.goal_alignment);
    message("Review saved. Collected facts and project files are unchanged.");
  } catch (error) {
    if (currentSnapshot(load, id)) message(saved ? `Review saved, but the report refresh failed: ${error.message}` : error.message, true);
  } finally {
    if (currentSnapshot(load, id)) {
      state.saving = false;
      updateControls();
    }
  }
});
async function init() {
  const [session, rubric, analyzers] = await Promise.all([api("/api/session"), api("/api/rubric"), api("/api/analyzers")]);
  state.token = session.token;
  state.rubric = rubric;
  renderAnalyzers(analyzers);
  dims = Object.keys(rubric.dimensions);
  titles = Object.fromEntries(dims.map((d) => [d, d[0].toUpperCase() + d.slice(1)]));
  for (const [key, profile] of Object.entries(rubric.profiles || {})) {
    const option = node("option", profile.title);
    option.value = key;
    $("profile").append(option);
  }
  await loadProjects();
}
init().catch((error) => message(error.message, true));
