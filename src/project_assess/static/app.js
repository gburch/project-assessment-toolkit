"use strict";

let dims = [];
let titles = {};
const $ = (id) => document.getElementById(id);
const MAX_REVIEW_BYTES = 256 * 1024;
const state = { token: null, rubric: null, projects: [], project: null, report: null, targets: {}, revision: 0, dirty: false, load: 0, loading: true, saving: false, reviewLoading: false, reviewDirty: false, reviewAssessment: null, reviewRequest: null };

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
function renderEvidence(assessment) {
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
    renderRatings(result);
    renderControls(result.goals);
    renderProgress(result.progress);
    renderFindings(result);
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
    const [progress, history] = await Promise.all([
      api(`/api/progress?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/history?project_id=${encodeURIComponent(projectId)}`)
    ]);
    if (!current()) return;
    renderProgress(progress);
    renderHistory(history);
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
    const snapshot = await api("/api/scan", { project_id: projectId });
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
    const snapshot = await api("/api/scan", { root });
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
    const [progress, history] = await Promise.all([
      api(`/api/progress?project_id=${encodeURIComponent(projectId)}`),
      api(`/api/history?project_id=${encodeURIComponent(projectId)}`)
    ]);
    if (!currentSnapshot(load, id)) return;
    renderProgress(progress);
    renderHistory(history);
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
  const [session, rubric] = await Promise.all([api("/api/session"), api("/api/rubric")]);
  state.token = session.token;
  state.rubric = rubric;
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
