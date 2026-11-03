"use strict";

let dims = [];
let titles = {};
const $ = (id) => document.getElementById(id);
const MAX_REVIEW_BYTES = 256 * 1024;
const CONTROL_DIMENSIONS = new Set(["security", "delivery", "operability", "extensibility", "performance"]);
const state = { token: null, rubric: null, projects: [], project: null, report: null, targets: {}, revision: 0, dirty: false, load: 0, loading: true, saving: false, reviewLoading: false, reviewDirty: false, reviewAssessment: null, reviewRequest: null };
let queryLoad = 0;
let queryNext = null;
let queryParams = null;
let dimensionMap = null;

function clearVisuals() {
  dimensionMap?.dispose();
  dimensionMap = null;
  $("dimension-map").replaceChildren();
  $("badges").replaceChildren();
  $("project-context").replaceChildren();
  $("prompting-profile")?.remove();
  $("download-report").removeAttribute("href");
}

function updateDimensionMap() {
  if (!dimensionMap || !state.report) return;
  const model = state.report.dimension_map;
  dimensionMap.update({ ...model, preview_targets: state.dirty,
    dimensions: model.dimensions.map((row) => {
      const goal = state.dirty ? state.targets[row.id] : state.report.goals?.targets?.[row.id];
      return { ...row, capability_min: goal?.capability_min ?? null, burden_max: goal?.burden_max ?? null };
    }) });
}

function renderVisuals(report) {
  clearVisuals();
  const query = `assessment_id=${encodeURIComponent(report.assessment.id)}`;
  $("download-report").href = `/api/report-download?${query}`;
  for (const name of ["summary", ...dims]) {
    const svg = report.badges?.[`${name}.svg`];
    if (!svg) continue;
    const link = node("a");
    link.href = `/api/badge?${query}&dimension=${encodeURIComponent(name)}`;
    link.download = `pat-${name}.svg`;
    const image = node("img");
    image.alt = name === "summary" ? "PAT assessment summary" : `PAT ${titles[name]}: capability ${report.review?.ratings?.[name]?.capability ?? "unknown"}, burden ${report.review?.ratings?.[name]?.burden ?? "unknown"}`;
    image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
    link.append(image);
    $("badges").append(link);
  }
  if (globalThis.PATDimensionMap && report.dimension_map) {
    dimensionMap = globalThis.PATDimensionMap.createDimensionMap($("dimension-map"), report.dimension_map, {
      onSelect: (dimension) => {
        const card = document.getElementById(`rating-${dimension}`);
        card?.classList.add("map-selected");
        for (const other of document.querySelectorAll(".rating.map-selected")) if (other !== card) other.classList.remove("map-selected");
      },
    });
    updateDimensionMap();
  } else {
    $("dimension-map").append(node("p", "The 3D view is unavailable. The complete scorecard and evidence remain below."));
  }
}

function scanOptions() {
  const analyzers = Array.from($("optional-analyzers").querySelectorAll("input[data-analyzer]:checked"))
    .filter((input) => input.dataset.autoIncluded !== "true").map((input) => input.dataset.analyzer);
  return { analysis_profile: $("analysis-profile").value, analyzers };
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
    input.dataset.deepDefault = String((analyzer.default_profiles || []).includes("deep"));
    input.disabled = state.loading || state.saving;
    const status = node("p", analyzer.available ? `${title} ${analyzer.version || ""} is available. Findings need caller and contract review.` : `${title}${analyzer.version ? ` ${analyzer.version} is unavailable` : " is not installed"}. Selecting it records unavailable evidence; scanning never installs it.`, "secondary");
    status.id = `${analyzer.name}-status`;
    if (input.dataset.deepDefault === "true") status.append(" Included automatically with Deep; the checkbox selects it for Standard.");
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
function renderProjectContext(report) {
  const parent = $("project-context"), context = report.project_context;
  parent.replaceChildren();
  if (context?.status !== "recorded") {
    parent.append(node("p", "No maturity or intended-purpose judgment is recorded for this review. Existing engineering scores are unchanged."));
  } else {
    const current = context.current, intended = context.intended;
    const summary = node("div", undefined, "context-summary");
    const present = node("article");
    present.append(node("h3", "Current codebase"), node("p", `${current.milestone_label || "Unknown"} · ${current.readiness_label || "Unknown"}`, "context-milestone"), node("p", `Declared confidence: ${current.confidence}`, "secondary"), node("p", current.rationale), node("p", `Evidence: ${current.evidence_ids.join(", ") || "none recorded"}`, "evidence-meta"));
    const destination = node("article");
    destination.append(node("h3", "Intended destination"), node("p", intended.milestone_label || "Unknown", "context-milestone"), node("p", `Basis: ${intended.basis_label || "Unknown"}; declared confidence: ${intended.confidence}`, "secondary"), node("p", intended.statement));
    if (intended.attribution) destination.append(node("p", `Attribution: ${intended.attribution}`));
    destination.append(node("p", `Evidence: ${intended.evidence_ids.join(", ") || "no captured source citation"}`, "evidence-meta"));
    summary.append(present, destination);
    parent.append(summary);
    const alignment = context.alignment;
    parent.append(node("h3", "Fit and ranked focus"), node("p", `${alignment.direction_label || "Unknown"} · ${alignment.rationale}`));
    if (alignment.priorities.length) {
      const priorities = node("ol", undefined, "context-priorities");
      for (const priority of alignment.priorities) {
        const item = node("li");
        item.append(node("strong", `${priority.dimension_label || "Unknown"} · ${priority.direction_label || "Unknown"}`), node("p", priority.rationale));
        if (priority.initiative_ids.length) {
          const links = node("p", "Plan initiatives: ", "evidence-meta");
          priority.initiative_ids.forEach((id, index) => {
            if (index) links.append(document.createTextNode(", "));
            const link = node("a", id);
            link.href = `#initiative-${encodeURIComponent(id)}`;
            links.append(link);
          });
          item.append(links);
        }
        priorities.append(item);
      }
      parent.append(priorities);
    } else parent.append(node("p", "No ranked focus areas are recorded."));
    for (const [title, values] of [["Deferred work", alignment.deferred], ["Alternative goals", intended.alternatives], ["Intent limitations", intended.limitations]]) {
      if (values.length) textList(parent, title, values);
    }
  }
  if (context?.gaps?.length) textList(parent, "Context gaps", context.gaps);
  parent.append(node("p", context?.profile_note || "Scope milestones are not quality grades or required growth steps. Existing numeric goals remain independent.", "secondary"));
  renderPrompting(report);
}
function renderPrompting(report) {
  $("prompting-profile")?.remove();
  const profile = report.prompting;
  const cite = (parent, ids) => {
    if (ids?.length) parent.append(node("p", `Evidence: ${ids.join(", ")}`, "evidence-meta"));
  };
  const section = node("section");
  section.id = "prompting-profile";
  section.setAttribute("aria-labelledby", "prompting-heading");
  const heading = node("h2", "Prompting and behavior control");
  heading.id = "prompting-heading";
  section.append(heading, node("p", "Code-controlled behavior → bounded model steps → prompt-led workflows. The appropriate balance depends on the project's purpose.", "secondary"));
  const summary = node("div", undefined, "context-summary");
  const current = node("article");
  current.id = "prompting-runtime";
  current.append(node("h3", "Product prompt reliance"));
  const knownLevel = Number.isInteger(profile?.level) && profile.level >= 0 && profile.level <= 5;
  current.append(node("p", knownLevel ? `${profile.level} / 5 · ${profile.level_label || "Reviewed level"}` : "Unknown · no runtime reliance level established", "context-milestone"));
  if (profile?.confidence) current.append(node("p", `Declared confidence: ${profile.confidence}`, "secondary"));
  current.append(node("p", profile?.rationale || "No prompting judgment is recorded for this snapshot."));
  cite(current, profile?.evidence_ids);
  const intended = node("article");
  intended.id = "prompting-intent";
  intended.append(node("h3", "Intended balance"));
  const intent = profile?.intent;
  const hasMinimum = Number.isInteger(intent?.min) && intent.min >= 0 && intent.min <= 5;
  const hasMaximum = Number.isInteger(intent?.max) && intent.max >= 0 && intent.max <= 5;
  const range = hasMinimum && hasMaximum ? `${intent.min === intent.max ? intent.min : `${intent.min}–${intent.max}`} / 5` : hasMinimum ? `At least ${intent.min} / 5` : hasMaximum ? `At most ${intent.max} / 5` : "No intended range recorded";
  intended.append(node("p", range, "context-milestone"));
  if (intent) {
    const basis = intent.basis_label || intent.basis || "Unknown";
    intended.append(node("p", `Basis: ${basis}${intent.provisional && !basis.toLowerCase().includes("provisional") ? " · provisional" : ""}`, "secondary"));
    if (intent.rationale) intended.append(node("p", intent.rationale));
    cite(intended, intent.evidence_ids);
  }
  if (profile?.fit?.label) intended.append(node("p", profile.fit.label));
  intended.append(node("p", "This range is review context. Capability and burden goals remain independent.", "secondary"));
  summary.append(current, intended);
  section.append(summary);
  const variability = profile?.variability;
  const variation = node("div");
  variation.id = "prompting-variability";
  variation.append(node("h3", "Output variability"), node("p", variability?.label || "Unknown · no runtime repeatability evidence"));
  if (variability?.rationale) variation.append(node("p", variability.rationale));
  cite(variation, variability?.evidence_ids);
  section.append(variation);
  if (profile?.workflows?.length) {
    const details = node("details");
    details.append(node("summary", "Behavior by workflow"));
    const list = node("ul");
    for (const workflow of profile.workflows) {
      const item = node("li");
      item.append(node("p", `${workflow.name}: ${workflow.control_label || workflow.control || "Unknown"}`), node("p", workflow.rationale));
      cite(item, workflow.evidence_ids);
      list.append(item);
    }
    details.append(list);
    section.append(details);
  }
  const collection = profile?.collection;
  const detail = node("details");
  detail.id = "prompting-collected";
  detail.append(node("summary", "Prompting evidence and coverage"));
  if (!collection || collection.status === "not_collected") {
    detail.append(node("p", "Not collected for this snapshot. Scan again to capture prompting evidence."));
  } else {
    const facts = collection.summary || {}, counts = facts.counts_by_kind || {};
    const count = (value) => Number.isInteger(value) && value >= 0 ? value : "unknown";
    detail.append(node("p", `Collection: ${collection.status}. Development guidance: ${count(facts.guidance_files)} file(s), ${count(counts.development_guidance)} signal(s).`));
    detail.append(node("p", `Runtime hints: ${count(facts.runtime_prompt_files)} prompt-asset file(s), ${count(counts.model_invocation)} model invocation(s), ${count(counts.agent_orchestration)} orchestration signal(s).`));
    detail.append(node("p", `Model client setup: ${count(counts.model_client_setup)} signal(s). Setup declarations do not establish a model invocation.`));
    detail.append(node("p", `Controls and evaluation hints: ${count(counts.output_contract)} output-contract signal(s), ${count(counts.evaluation_signal)} evaluation signal(s).`));
    detail.append(node("p", "Development skills and signal counts do not establish runtime prompt reliance or repeatable output.", "secondary"));
    if (collection.gaps?.length) textList(detail, "Collection gaps", collection.gaps);
    const captured = (report.assessment?.evidence || []).find((entry) => entry.id === collection.evidence_id && entry.kind === "prompting-analysis");
    if (captured) {
      const inspect = node("button", "Inspect Prompting evidence");
      inspect.type = "button";
      inspect.addEventListener("click", () => {
        const record = Array.from($("evidence").children).find((entry) => entry.dataset.evidenceId === captured.id);
        if (!record) return;
        $("evidence-summary").parentElement.open = true;
        record.open = true;
        record.querySelector("summary").focus();
        record.scrollIntoView({ block: "nearest" });
      });
      detail.append(inspect);
    }
  }
  section.append(detail);
  if (profile?.recommendations?.length) {
    section.append(node("h3", "Right-size the balance"));
    const list = node("ul");
    for (const recommendation of profile.recommendations) {
      const item = node("li", undefined, "prompting-recommendation");
      item.append(node("p", `${recommendation.direction_label || recommendation.direction}: ${recommendation.action}`), node("p", recommendation.rationale));
      cite(item, recommendation.evidence_ids);
      list.append(item);
    }
    section.append(list);
  }
  if (profile?.gaps?.length) textList(section, "Judgment gaps", profile.gaps);
  section.append(node("p", profile?.caveat || "Prompt reliance is a project characteristic. High or low reliance can fit the intended purpose; observed variability needs applicable runtime evidence.", "secondary"));
  $("project-context").closest("section").after(section);
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
function freshnessLabel(method, dim) {
  const origin = method?.dimensions?.[dim];
  const labels = { reassessed: "Reassessed", carried_forward: "Carried forward", unreviewed: "Not reviewed", unestablished: "Freshness not established" };
  return origin?.label || labels[origin?.origin] || "Freshness not established";
}
function renderBurdenSupport(parent, support) {
  const labels = { not_requested: "Not requested", withheld: "Incomplete", structured_support_present_for_declared_scope: "Present for declared scope" };
  const detail = node("details");
  detail.append(node("summary", `Burden support prerequisites · ${labels[support?.status] || "Not recorded"}`));
  detail.append(node("p", `Declared scope: ${support?.scope || "Not recorded"}`));
  if (support?.claim) detail.append(node("p", support.claim));
  const readiness = support?.readiness;
  if (readiness) {
    const inventory = node("div", undefined, "burden-readiness");
    inventory.append(node("p", "Captured burden evidence"));
    const counts = [
      ["Cited source records", readiness.source_evidence_ids],
      ["Applicable attributed experience", readiness.experience_evidence_ids],
      ["Source-matched change-cost reports", readiness.matched_cost_evidence_ids],
      ["Partial elapsed reports", readiness.partial_elapsed_evidence_ids],
      ["Reports needing applicability review", readiness.limited_report_evidence_ids],
      ["Related change traces", readiness.trace_ids],
    ];
    const list = node("ul");
    list.append(...counts.map(([label, rows]) => node("li", `${label}: ${rows?.length || 0}`)));
    inventory.append(list);
    const activities = readiness.trace_activities || {};
    inventory.append(node("p", `Declared trace activities · edit ${activities.edit || 0} · verification ${activities.verification || 0} · inspection ${activities.inspection || 0} · unknown ${activities.unknown || 0}`));
    if (readiness.trace_selection === "shared_source_citations") inventory.append(node("p", "Traces share cited source; their relevance still needs review.", "secondary"));
    const recurrence = { reported_recurring: "Recurring experience reported", multiple_dated_observations: "Multiple dated observations supplied", not_established: "Not established" };
    inventory.append(node("p", `Recurrence: ${recurrence[readiness.recurrence] || "Not established"}`));
    inventory.append(node("p", `Independent challenge: ${readiness.challenge === "bound_dimension_review" ? "Exact-draft dimension review recorded" : "Not established"}`));
    textList(inventory, "Next useful evidence", readiness.next_steps || []);
    if (readiness.caveat) inventory.append(node("p", readiness.caveat, "secondary"));
    detail.append(inventory);
  }
  textList(detail, "Support gaps", support?.gaps || []);
  detail.append(node("p", "These checks describe supporting evidence and review prerequisites. They do not verify confidence, reporter identity or the burden judgment. Source hurdles and reported change experience remain distinct.", "secondary"));
  parent.append(detail);
}
function renderRatings(report) {
  $("ratings").replaceChildren();
  for (const dim of dims) {
    const rating = report.review?.ratings?.[dim];
    const box = node("article", undefined, "rating");
    box.id = `rating-${dim}`;
    const header = node("header");
    header.append(node("h3", titles[dim]), node("span", rating ? `Capability · declared ${rating.confidence} confidence` : "Not reviewed", "confidence"));
    box.append(header);
    box.append(node("p", freshnessLabel(report.assessment_method, dim), "evidence-meta"));
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
        box.append(node("p", `${basis} · declared ${rating.burden_confidence || "low"} confidence`, "secondary"));
      }
      box.append(node("p", rubDescription(dim, axis, value), "secondary"));
      const support = (report.confidence_assessment || report.goal_alignment?.confidence_assessment)?.dimensions?.[dim]?.[axis];
      if (support?.blockers?.length) {
        const detail = node("details");
        detail.append(node("summary", `${axis === "capability" ? "Capability" : "Burden"} confidence limits`));
        textList(detail, "Evidence still needed", support.blockers);
        box.append(detail);
      }
      if (axis === "burden") renderBurdenSupport(box, support?.support);
    }
    const controlCoverage = report.goal_alignment?.dimension_inputs?.dimensions?.[dim]?.control_coverage;
    if (controlCoverage) {
      const detail = node("details");
      detail.id = `scanner-${dim}`;
      detail.append(node("summary", "Scanner coverage"));
      detail.append(node("p", `${controlCoverage.examined_files} of ${controlCoverage.input_files} eligible files examined for supported rules; ${controlCoverage.partial_files} partial, ${controlCoverage.unsupported_files} unsupported, ${controlCoverage.uncaptured_files} uncaptured.`));
      detail.append(node("p", `${controlCoverage.retained_signals} located signals retained. These describe source mechanisms or review hints; they do not establish effectiveness or a score.`, "secondary"));
      box.append(detail);
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
  for (const input of $("optional-analyzers").querySelectorAll("input[data-analyzer]")) {
    const included = $("analysis-profile").value === "deep" && input.dataset.deepDefault === "true";
    if (included && input.dataset.autoIncluded !== "true") {
      input.dataset.wasChecked = String(input.checked);
      input.checked = true;
    } else if (!included && input.dataset.autoIncluded === "true") {
      input.checked = input.dataset.wasChecked === "true";
    }
    input.dataset.autoIncluded = String(included);
    input.disabled = state.loading || state.saving || included;
  }
  const busy = state.loading || state.saving || !state.report;
  $("scan").disabled = !state.token || state.loading || state.saving;
  $("scan-root").disabled = state.loading || state.saving;
  $("profile").disabled = busy;
  for (const input of $("goal-controls").querySelectorAll("input")) input.disabled = busy;
  $("save").disabled = busy || !state.dirty || missingTargets().length > 0;
  $("rescan").disabled = busy;
  for (const id of ["backfill-mode", "backfill-count", "backfill-revisions", "backfill"]) $(id).disabled = busy || !state.token;
  for (const id of ["review-mode", "review-load", "review-file", "review-json"]) $(id).disabled = busy || state.reviewLoading;
  $("review-submit").disabled = busy || state.reviewLoading || !state.reviewDirty ||
    state.reviewAssessment !== state.report?.assessment.id || !$("review-json").value.trim();
  $("challenge-load").disabled = busy || state.reviewLoading ||
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
  resetChallenge();
}
function resetChallenge() {
  $("challenge-result").hidden = true;
  $("challenge-result").open = false;
  $("challenge-json").textContent = "";
}
function currentSnapshot(load, id) {
  return load === state.load && state.report?.assessment.id === id;
}
function dirty() {
  state.dirty = true;
  updateControls();
  updateDimensionMap();
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
  const collected = report.assessment.findings || [];
  const findings = [...collected, ...(report.review?.findings || [])];
  const confidence = report.confidence_assessment || report.goal_alignment?.confidence_assessment;
  $("findings").replaceChildren();
  for (const [index, finding] of findings.entries()) {
    const item = node("div", undefined, "finding");
    item.append(node("span", `${finding.severity || "Observation"}: `, "severity"), node("span", finding.title || finding.message || "Evidence observation"));
    if (finding.evidence_ids?.length) item.append(node("p", `Evidence: ${finding.evidence_ids.join(", ")}`, "evidence-meta"));
    if (finding.support) {
      const support = finding.support;
      const grounding = confidence?.findings?.find((row) => row.index === index - collected.length);
      const detail = node("details");
      detail.append(node("summary", `${support.scope} finding · declared ${support.confidence} confidence · ${grounding?.grounding === "verified_source_spans" ? "source spans verified" : "source support unestablished"}`));
      detail.append(node("p", support.rationale), node("p", `Counterevidence: ${support.counterevidence}`));
      for (const citation of support.citations || []) {
        detail.append(node("p", `${citation.evidence_id}:${citation.line}–${citation.end_line}`, "evidence-meta"), node("pre", citation.excerpt));
      }
      textList(detail, "Remaining uncertainty", support.limitations || []);
      item.append(detail);
    }
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
function renderAssessmentMethod(parent, method) {
  const status = { fresh: "Fresh assessment", refresh: "Assessment refresh", unestablished: "Assessment freshness not established" };
  const completion = { completed: "completed", provisional: "provisional", unestablished: "completion not established" };
  const summary = node("p", `${status[method?.status] || status.unestablished} · ${completion[method?.completion] || completion.unestablished}`);
  summary.id = "assessment-method";
  parent.append(summary);
  if (!method) return;
  if (method.reviewer_id) parent.append(node("p", `Reviewer: ${method.reviewer_id}${method.based_on_review_id ? ` · Based on review: ${method.based_on_review_id}` : ""}`, "evidence-meta"));
  if (method.counts) parent.append(node("p", `${method.counts.reassessed || 0} reassessed · ${method.counts.carried_forward || 0} carried forward · ${method.counts.unreviewed || 0} unreviewed · ${method.counts.unestablished || 0} without freshness records`, "secondary"));
  const traces = method.change_traces || [];
  const traceDetails = node("details");
  traceDetails.append(node("summary", `Change traces (${traces.length})`));
  for (const trace of traces) {
    const item = node("article", undefined, "initiative");
    item.append(node("h3", trace.title || trace.id));
    textList(item, "Change path", (trace.steps || []).map((step) => `${step.owner}: ${step.change} · Evidence: ${(step.evidence_ids || []).join(", ") || "none"}`));
    item.append(node("p", `Change cost: ${trace.cost}`), node("p", `Preserve: ${trace.invariant}`), node("p", `Counterevidence: ${trace.counterevidence}`));
    textList(item, "Trace gaps", trace.gaps || []);
    traceDetails.append(item);
  }
  if (!traces.length) traceDetails.append(node("p", "No change traces recorded.", "secondary"));
  parent.append(traceDetails);
  const challenge = method.challenge || { status: "unrecorded" };
  const details = node("details");
  details.append(node("summary", `Independent challenge · ${challenge.status}`));
  if (challenge.reviewer_id) details.append(node("p", `Reviewer: ${challenge.reviewer_id} · Independence: ${challenge.independence || "unestablished"}`, "evidence-meta"));
  if (challenge.summary) details.append(node("p", challenge.summary));
  for (const item of challenge.items || []) {
    const entry = node("article", undefined, "initiative");
    entry.append(node("h3", item.concern), node("p", `Evidence: ${(item.evidence_ids || []).join(", ") || "none"}`, "evidence-meta"));
    if (item.response) entry.append(node("p", `${item.response.decision}: ${item.response.rationale}`), node("p", `Response evidence: ${(item.response.evidence_ids || []).join(", ") || "none"}`, "evidence-meta"));
    details.append(entry);
  }
  textList(details, "Challenge gaps", challenge.gaps || []);
  parent.append(details);
  if (method.gaps?.length) textList(parent, "Assessment method gaps", method.gaps);
  if (method.caveat) parent.append(node("p", method.caveat, "secondary"));
}
function renderConfidence(parent, confidence) {
  if (!confidence) return;
  const verified = (confidence.findings || []).filter((row) => row.grounding === "verified_source_spans");
  const high = verified.filter((row) => row.declared_confidence === "high" && row.scope === "source");
  const detail = node("details");
  detail.id = "confidence-evidence";
  detail.append(node("summary", "Confidence and supporting evidence"));
  detail.append(node("p", `${verified.length} finding(s) have verified source spans; ${high.length} declare high confidence in a source claim. Project score confidence remains separate.`));
  if (confidence.caveat) detail.append(node("p", confidence.caveat, "secondary"));
  for (const [dim, axes] of Object.entries(confidence.dimensions || {})) {
    for (const axis of ["capability", "burden"]) {
      const support = axes[axis];
      if (support?.blockers?.length) textList(detail, `${titles[dim] || dim} · ${axis}`, support.blockers);
    }
  }
  parent.append(detail);
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
  renderAssessmentMethod(coverage, alignment?.assessment_method);
  renderConfidence(coverage, alignment?.confidence_assessment);
  const breadth = alignment?.review_coverage;
  const breadthLabels = { broad: "Broad review recorded", partial: "Partial project review", focused: "Focused review", unestablished: "Review breadth not established", unreviewed: "Project not reviewed" };
  coverage.append(node("p", breadthLabels[breadth?.status] || "Review breadth not established"));
  if (breadth?.dimensions) {
    const detail = node("details");
    detail.append(node("summary", "Review coverage by dimension"));
    textList(detail, "Reviewed scope and gaps", Object.entries(breadth.dimensions).map(([dim, value]) => `${titles[dim] || dim}: ${value.status} · ${value.rationale || "No review scope recorded"} · Evidence: ${(value.evidence_ids || []).join(", ") || "none"}`));
    coverage.append(detail);
  }
  const map = alignment?.system_map;
  if (map) {
    const detail = node("details");
    detail.append(node("summary", "Production system overview"));
    detail.append(node("p", `${map.status}: ${map.production_files} captured production file(s) across ${map.area_count} path area(s); ${map.omitted_areas} area(s) and ${map.omitted_cross_area_dependencies} cross-area dependency group(s) omitted by display bounds.`));
    textList(detail, "Captured areas", (map.areas || []).map((area) => `${area.path}: ${area.files} file(s) · ${area.lines ?? "?"} lines · ${area.partial_modules} partial module(s) · Evidence: ${(area.evidence_ids || []).join(", ")}`));
    textList(detail, "Cross-area static imports", (map.cross_area_dependencies || []).map((edge) => `${edge.source_area} → ${edge.target_area}: ${edge.import_edges} edge(s) · ${Object.entries(edge.phases || {}).map(([phase, count]) => `${phase}: ${count}`).join(", ")} · Evidence: ${(edge.evidence_ids || []).join(", ")}`));
    textList(detail, "Overview limits", map.gaps || []);
    if (map.caveat) detail.append(node("p", map.caveat, "secondary"));
    coverage.append(detail);
  }
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
      if (initiative.id) item.id = `initiative-${initiative.id}`;
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
  updateEvidenceDimensionFilter();
  $("query-burden-scope")?.remove();
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
function updateEvidenceDimensionFilter() {
  const view = $("query-view").value;
  const filter = $("query-dimension");
  filter.disabled = !["controls", "burden", "review-plan"].includes(view);
  for (const id of ["query-kind", "query-candidate"]) $(id).disabled = view === "review-plan";
  for (const option of filter.options) option.disabled = view === "controls" && !!option.value && !CONTROL_DIMENSIONS.has(option.value);
  if (filter.selectedOptions[0]?.disabled) filter.value = "";
}
function renderBurdenScope(result) {
  $("query-burden-scope")?.remove();
  if (!result.burden_scope) return;
  const detail = node("details");
  detail.id = "query-burden-scope";
  detail.open = true;
  detail.append(node("summary", "Burden analysis scope"));
  detail.append(node("p", "Counts cover the retained analysis; filters select evidence rows below.", "secondary"));
  if (result.caveat) detail.append(node("p", result.caveat, "secondary"));
  for (const scope of result.burden_scope.slice(0, 4)) {
    const coverage = scope.coverage || {};
    detail.append(node("p", `${scope.status || "unknown"} · ${coverage.leads_retained ?? "unknown"} / ${coverage.leads_observed ?? "unknown"} leads retained; ${coverage.leads_omitted ?? "unknown"} omitted. Input rows omitted: ${coverage.input_rows_omitted ?? "unknown"}.`));
    detail.append(node("p", `Timing records: ${scope.timing_records ?? "unknown"} retained / ${coverage.timing_records_observed ?? "unknown"} observed; ${coverage.timing_records_omitted ?? "unknown"} omitted. These are supplied records, not verified runs or wall waits.`, "secondary"));
    if (scope.timing_view) detail.append(node("p", scope.timing_view, "secondary"));
    textList(detail, "Scope gaps", (scope.gaps || []).slice(0, 4));
    const omittedGaps = Math.max(0, (scope.gaps || []).length - 4) + (scope.omitted_gaps || 0);
    if (omittedGaps) detail.append(node("p", `${omittedGaps} additional scope gaps are in the captured evidence.`, "secondary"));
    const button = node("button", "Inspect complete burden scope");
    button.type = "button";
    button.addEventListener("click", () => {
      const record = Array.from($("evidence").children).find((entry) => entry.dataset.evidenceId === scope.evidence_id);
      if (!record) return;
      $("evidence-summary").parentElement.open = true;
      record.open = true;
      record.querySelector("summary").focus();
      record.scrollIntoView({ block: "nearest" });
    });
    detail.append(button);
  }
  if (!result.burden_scope.length) detail.append(node("p", "Burden analysis was not collected in this snapshot.", "secondary"));
  if (result.burden_scope.length > 4) detail.append(node("p", `${result.burden_scope.length - 4} additional analysis scopes are in the captured evidence.`, "secondary"));
  $("query-results").before(detail);
}
function evidenceResult(row, load, assessmentId) {
  const item = node("details", undefined, "evidence-result");
  const location = row.locations?.[0] || (row.path ? row : null);
  item.append(node("summary", `${row.kind || row.name || row.record_type || row.evidence_kind || "Evidence"}${location ? ` · ${location.path}${location.line ? `:${location.line}` : ""}` : ""}`), node("pre", jsonText(row)));
  // Prefer source identity; display labels may be redacted or ambiguous.
  const sourceId = row.source_evidence_id || location?.source_evidence_id;
  const source = (sourceId || location) && state.report.assessment.evidence.find((entry) =>
    (sourceId ? entry.id === sourceId : entry.path === location.path) &&
    ["python", "javascript", "source", "documentation", "manifest", "configuration"].includes(entry.kind));
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
    if (!$(id).disabled && $(id).value) parameters.set(key, $(id).value);
  }
  const view = $("query-view").value;
  const dimension = $("query-dimension").value;
  if (!append && dimension && (["burden", "review-plan"].includes(view) || view === "controls" && CONTROL_DIMENSIONS.has(dimension))) parameters.set("dimension", dimension);
  parameters.set("offset", String(append ? queryNext : 0));
  queryParams = parameters.toString();
  $("query-submit").disabled = $("query-more").disabled = true;
  $("query-state").textContent = "Querying captured evidence…";
  if (!append) $("query-burden-scope")?.remove();
  try {
    const result = await api(`/api/evidence-query?${parameters}`);
    if (!currentSnapshot(load, assessmentId) || ticket !== queryLoad) return;
    renderBurdenScope(result);
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
$("query-view").addEventListener("change", updateEvidenceDimensionFilter);
$("query-more").addEventListener("click", () => queryEvidence(true));
$("evidence-query-form").addEventListener("input", () => {
  ++queryLoad;
  queryNext = null;
  $("query-burden-scope")?.remove();
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
    ...history.assessments.map((record) => ({ ...record, type: record.origin === "git-commit" ? `Git backfill · source as of ${(record.as_of || "").slice(0, 10)}` : "Source scan", assessment_id: record.id })),
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
  clearVisuals();
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
    $("source").textContent = `${source.root} · ${source.revision || "Unversioned source"}${source.dirty ? " · modified worktree" : ""}${source.origin?.kind === "git-commit" ? ` · Git backfill committed ${source.origin.committed_at}` : ""}`;
    const collection = result.assessment.facts?.collection || {};
    $("analysis-profile").value = collection.analysis_profile || "standard";
    for (const input of $("optional-analyzers").querySelectorAll("input[data-analyzer]")) {
      input.dataset.autoIncluded = "false";
      input.checked = (collection.requested_analyzers || collection.analyzers || []).includes(input.dataset.analyzer);
    }
    $("analysis-scope").textContent = `Analysis: ${collection.analysis_profile || "legacy"}${collection.supported_text_complete === undefined ? "" : ` · supported text ${collection.supported_text_complete ? "captured" : "partial"}`}${collection.deadline_exceeded ? " · analysis deadline reached" : ""}${collection.analyzers?.length ? ` · analyzers: ${collection.analyzers.join(", ")}` : ""}.`;
    renderRatings(result);
    renderControls(result.goals);
    renderVisuals(result);
    renderProjectContext(result);
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
    clearVisuals();
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
    updateDimensionMap();
    const [progress, history, evolve] = await Promise.all([
      api(`/api/progress?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/history?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/evolve?assessment_id=${encodeURIComponent(state.report.assessment.id)}`)
    ]);
    if (!current()) return;
    renderProgress(progress);
    renderHistory(history);
    state.report.goal_alignment = evolve.goal_alignment;
    state.report.project_context = evolve.goal_alignment.project_context || state.report.project_context;
    renderProjectContext(state.report);
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
$("analysis-profile").addEventListener("change", updateControls);
$("backfill-mode").addEventListener("change", () => {
  const listed = $("backfill-mode").value === "revisions";
  $("backfill-count-label").hidden = listed;
  $("backfill-revisions-label").hidden = !listed;
});
$("backfill-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.project || !state.report || state.loading || state.saving || !allowDiscard()) return;
  const mode = $("backfill-mode").value;
  const selection = mode === "revisions"
    ? { revisions: $("backfill-revisions").value.split(/[\s,]+/).filter(Boolean) }
    : { [mode]: Number($("backfill-count").value) };
  if (mode === "revisions" && !selection.revisions.length) return message("List at least one commit, tag or branch name.", true);
  const projectId = state.project.id;
  const currentId = state.report.assessment.id;
  const load = state.load;
  state.saving = true;
  updateControls();
  message("Reading earlier commits from local Git objects…");
  try {
    const result = await api("/api/backfill", { project_id: projectId, analysis_profile: $("analysis-profile").value, ...selection });
    const count = (status) => result.snapshots.filter((row) => row.status === status).length;
    const parts = [`Captured ${count("captured")} earlier commit${count("captured") === 1 ? "" : "s"}`];
    if (count("existing")) parts.push(`${count("existing")} already saved`);
    if (count("unavailable")) parts.push(`${count("unavailable")} unavailable`);
    const gaps = [...result.gaps, ...result.snapshots.flatMap((row) => row.status === "unavailable" ? row.gaps || [] : [])];
    if (load !== state.load || state.project?.id !== projectId) return;
    await loadReport(currentId);
    message(`${parts.join(", ")}. Their ratings stay unknown until reviewed.${gaps.length ? ` ${gaps.slice(0, 2).join(". ")}.` : ""}`);
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
    const review = await api(`/api/review-template?assessment_id=${encodeURIComponent(id)}&mode=${encodeURIComponent($("review-mode").value)}`);
    if (!currentSnapshot(load, id)) return;
    $("review-json").value = jsonText(review);
    state.reviewAssessment = id;
    state.reviewRequest = null;
    state.reviewDirty = true;
    resetChallenge();
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
    resetChallenge();
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
  resetChallenge();
  $("review-state").textContent = "Unsaved review JSON";
  updateControls();
});
function reviewDraft() {
  if (new TextEncoder().encode($("review-json").value).length > MAX_REVIEW_BYTES) throw new Error("Review JSON must be at most 256 KiB");
  return JSON.parse($("review-json").value);
}
$("challenge-load").addEventListener("click", async () => {
  if (!state.report || state.loading || state.saving || state.reviewLoading ||
      state.reviewAssessment !== state.report.assessment.id) return;
  const load = state.load;
  const id = state.report.assessment.id;
  let review;
  try {
    review = reviewDraft();
  } catch (error) {
    message(error.message, true);
    return;
  }
  state.reviewLoading = true;
  resetChallenge();
  updateControls();
  try {
    const packet = await api("/api/challenge-template", { assessment_id: id, review });
    if (!currentSnapshot(load, id)) return;
    $("challenge-json").textContent = jsonText(packet);
    $("challenge-result").hidden = false;
    $("challenge-result").open = true;
    message("Challenge packet prepared. Give it to a separate reviewer, then record the challenge and responses in your review JSON.");
  } catch (error) {
    if (currentSnapshot(load, id)) message(error.message, true);
  } finally {
    if (currentSnapshot(load, id)) {
      state.reviewLoading = false;
      updateControls();
    }
  }
});
$("review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.report || state.loading || state.saving || state.reviewLoading || !state.reviewDirty ||
      state.reviewAssessment !== state.report.assessment.id) return;
  const load = state.load;
  const id = state.report.assessment.id;
  let review;
  try {
    review = reviewDraft();
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
    state.report.assessment_method = null;
    state.report.confidence_assessment = null;
    if (state.report.goal_alignment) state.report.goal_alignment.confidence_assessment = null;
    const confidencePanel = $("confidence-evidence");
    if (confidencePanel) confidencePanel.replaceChildren(node("summary", "Confidence and supporting evidence"), node("p", "Updated confidence evidence is loading. Reload the report if refreshing fails."));
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
    state.report.assessment_method = evolve.goal_alignment.assessment_method;
    state.report.confidence_assessment = evolve.goal_alignment.confidence_assessment;
    renderRatings(state.report);
    renderFindings(state.report);
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
  titles = Object.fromEntries(dims.map((d) => [d, rubric.dimensions[d].title || d[0].toUpperCase() + d.slice(1)]));
  for (const [key, profile] of Object.entries(rubric.profiles || {})) {
    const option = node("option", profile.title);
    option.value = key;
    $("profile").append(option);
  }
  await loadProjects();
}
init().catch((error) => message(error.message, true));
