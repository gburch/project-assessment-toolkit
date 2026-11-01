import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";

let instances = 0;
const SCORE_MAX = 5;
const STEP = 1.35;
const DEPTH = 1.1;
const score = (value) => Number.isInteger(value) && value >= 0 && value <= SCORE_MAX;
const show = (value) => score(value) ? `${value} / ${SCORE_MAX}` : "Unknown";
const capabilityGap = (row) => score(row.capability) && score(row.capability_min) ? Math.max(row.capability_min - row.capability, 0) : null;
const burdenGap = (row) => score(row.burden) && score(row.burden_max) ? Math.max(row.burden - row.burden_max, 0) : null;
const basisLabel = (basis) => ({ observed: "Observed or reported", source_estimate: "Source estimate", unknown: "Basis unknown" })[basis] || "Basis unknown";

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

/** A read-only view. Goal edits and persistence belong to the enclosing report. */
export function createDimensionMap(container, initialModel, { onSelect } = {}) {
  const instance = `pat-dimension-map-${++instances}`;
  const signalController = new AbortController();
  const { signal } = signalController;
  let model, dimensions = [], selectedId, disposed = false, frame = 0;
  let graphics = null, view = "3d", mode = "compare", labels = [];
  const projected = new THREE.Vector3();
  const cameraTarget = new THREE.Vector3(0, 2.5, -2.75);
  const darkTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const narrowLayout = window.matchMedia("(max-width: 940px)");
  container.classList.add("dimension-map");

  const introduction = element("p", "Compare what the project can do with what it costs to maintain. Capability has a minimum; burden has a ceiling. Extra useful capability needs no reduction.", "dm-introduction");
  const navigation = element("div", undefined, "dm-navigation");
  const modes = element("div", undefined, "dm-modes");
  modes.setAttribute("role", "group");
  modes.setAttribute("aria-label", "Comparison view");
  const modeButtons = new Map();
  for (const [id, title] of [["compare", "Compare dimensions"], ["3d", "Explore in 3D"]]) {
    const button = element("button", title);
    button.type = "button";
    button.addEventListener("click", () => setMode(id), { signal });
    modeButtons.set(id, button);
    modes.append(button);
  }
  const targetState = element("p", undefined, "dm-target-state");
  navigation.append(modes, targetState);
  const summary = element("p", undefined, "dm-summary");
  summary.setAttribute("role", "status");
  const workspace = element("div", undefined, "dm-workspace");
  const overview = element("div", undefined, "dm-overview");
  const comparison = element("div", undefined, "dm-comparison");
  const headings = element("div", undefined, "dm-comparison-head");
  headings.setAttribute("aria-hidden", "true");
  headings.append(element("span", "Dimension"), element("span", "Capability · higher is useful"), element("span", "Burden · lower is lighter"));
  comparison.append(element("p", "Dot: current score · Vertical mark: target · Scores are 0–5 rubric steps", "dm-reading-key"), headings);
  const spatial = element("div", undefined, "dm-spatial");
  const toolbar = element("div", undefined, "dm-toolbar");
  const presets = element("div", undefined, "dm-presets");
  presets.setAttribute("role", "group");
  presets.setAttribute("aria-label", "Graph view");
  const presetButtons = new Map();
  for (const [id, title] of [["3d", "3D overview"], ["capability", "Capability view"], ["burden", "Burden view"]]) {
    const button = element("button", title);
    button.type = "button";
    button.dataset.view = id;
    button.addEventListener("click", () => setView(id), { signal });
    presetButtons.set(id, button);
    presets.append(button);
  }
  const reset = element("button", "Reset view");
  reset.type = "button";
  reset.addEventListener("click", () => setView("3d"), { signal });
  const selectorLabel = element("label", "Inspect dimension");
  selectorLabel.htmlFor = `${instance}-select`;
  const selector = element("select");
  selector.id = `${instance}-select`;
  selector.addEventListener("change", () => select(selector.value, true), { signal });
  selectorLabel.append(selector);
  toolbar.append(presets, reset, selectorLabel);

  const legend = element("div", undefined, "dm-legend");
  const currentKey = element("span", "● Current", "dm-key dm-key-current");
  const goalKey = element("span", "◇ Goal boundary", "dm-key dm-key-goal");
  const gapKey = element("span", "┄ Required improvement", "dm-key dm-key-gap");
  const outsideKey = element("span", "● Outside selected targets", "dm-key dm-key-outside");
  legend.append(currentKey, goalKey, gapKey, outsideKey);
  const stage = element("div", undefined, "dm-stage");
  const axisGuide = element("div", undefined, "dm-axis-guide");
  axisGuide.append(element("span", "Height · capability 0–5"), element("span", "Depth · burden 0–5"));
  const overlay = element("div", undefined, "dm-labels");
  overlay.setAttribute("aria-hidden", "true");
  stage.append(axisGuide, overlay);
  const help = element("p", "Height shows capability; depth shows burden. Select a named lane to inspect it. Drag to orbit; use the view buttons for aligned projections. The comparison view shows exact scores without rotation.", "dm-help");
  help.id = `${instance}-help`;
  const status = element("p", undefined, "dm-status");
  status.setAttribute("role", "status");
  const retry = element("button", "Try 3D again");
  retry.type = "button";
  retry.hidden = true;
  retry.addEventListener("click", startGraphics, { signal });
  const list = element("div", undefined, "dm-dimensions");
  list.setAttribute("role", "group");
  list.setAttribute("aria-label", "Dimension scores");
  list.addEventListener("click", (event) => {
    const button = event.target.closest?.("button[data-dimension]");
    if (button && list.contains(button)) select(button.dataset.dimension, true);
  }, { signal });
  const detail = element("div", undefined, "dm-detail");
  spatial.append(toolbar, legend, stage, help, status, retry);
  comparison.append(list);
  overview.append(comparison, spatial);
  workspace.append(overview, detail);
  container.replaceChildren(introduction, navigation, summary, workspace);

  function rows() { return dimensions.filter((row) => score(row.capability) && score(row.burden)); }
  function hasGoal(row) { return score(row.capability_min) && score(row.burden_max); }
  function needsImprovement(row) {
    return capabilityGap(row) > 0 || burdenGap(row) > 0;
  }
  function setMode(next) {
    mode = next;
    container.dataset.mode = mode;
    for (const [id, button] of modeButtons) button.setAttribute("aria-pressed", String(id === mode));
    comparison.hidden = mode !== "compare";
    spatial.hidden = mode !== "3d";
    placeDetail();
    if (mode === "3d") {
      if (!graphics && container.dataset.renderer !== "unavailable") startGraphics();
      fit();
    }
  }
  function position(index, capability, burden) {
    return new THREE.Vector3((index - (dimensions.length - 1) / 2) * STEP, capability, -burden * DEPTH);
  }
  function palette() {
    return {
      current: new THREE.Color(getComputedStyle(currentKey).color),
      goal: new THREE.Color(getComputedStyle(goalKey).color),
      attention: new THREE.Color(getComputedStyle(container).getPropertyValue("--warn") || "#8c3927"),
    };
  }
  function label(text, location, kind) {
    const node = element("span", text, `dm-label dm-label-${kind}`);
    overlay.append(node);
    labels.push({ node, location, kind });
  }
  function requestRender() {
    if (disposed || !graphics || frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      if (!graphics || disposed || !container.isConnected) return;
      const { renderer, scene, camera } = graphics;
      try { renderer.render(scene, camera); }
      catch { unavailable(); return; }
      const width = stage.clientWidth, height = stage.clientHeight;
      for (const item of labels) {
        projected.copy(item.location).project(camera);
        const hidden = Math.abs(projected.x) > 1 || Math.abs(projected.y) > 1 || projected.z < -1 || projected.z > 1 ||
          view === "burden" && item.kind.startsWith("capability") ||
          view === "capability" && item.kind.startsWith("burden") ||
          width < 500 && item.kind.endsWith("tick") && !item.kind.startsWith("dimension") && item.node.textContent !== "5";
        item.node.hidden = hidden;
        if (hidden) continue;
        const halfWidth = item.node.offsetWidth / 2 + 5;
        item.node.style.left = `${Math.max(halfWidth, Math.min(width - halfWidth, (projected.x + 1) / 2 * width))}px`;
        item.node.style.top = `${Math.max(12, Math.min(height - 12, (1 - projected.y) / 2 * height))}px`;
      }
    });
  }
  function fit(force = false) {
    if (!graphics || !stage.clientWidth || !stage.clientHeight) return;
    const { camera, renderer } = graphics;
    const width = stage.clientWidth, height = stage.clientHeight, aspect = width / height;
    if (force !== true && graphics.width === width && graphics.height === height) {
      requestRender();
      return;
    }
    camera.updateMatrixWorld();
    let extentX = 0, extentY = 0;
    for (const x of [-6.2, 6.2]) for (const y of [-0.8, 6.1]) for (const z of [-6.5, 0.8]) {
      const point = new THREE.Vector3(x, y, z).applyMatrix4(camera.matrixWorldInverse);
      extentX = Math.max(extentX, Math.abs(point.x));
      extentY = Math.max(extentY, Math.abs(point.y));
    }
    const halfHeight = Math.max(extentY, extentX / aspect) * 1.07;
    camera.left = -halfHeight * aspect;
    camera.right = halfHeight * aspect;
    camera.top = halfHeight;
    camera.bottom = -halfHeight;
    camera.updateProjectionMatrix();
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height, false);
    graphics.width = width;
    graphics.height = height;
    requestRender();
  }
  function setView(next) {
    view = next;
    for (const [id, button] of presetButtons) button.setAttribute("aria-pressed", String(id === view));
    if (!graphics) return;
    const { camera, controls } = graphics;
    camera.zoom = 1;
    controls.target.copy(cameraTarget);
    camera.up.set(0, 1, 0);
    if (view === "capability") camera.position.set(0, 2.5, 18);
    else if (view === "burden") camera.position.set(0, 22, -2.65);
    else camera.position.set(12, 10, 14);
    camera.lookAt(cameraTarget);
    controls.update();
    fit(true);
  }
  function clearMarks() {
    if (!graphics) return;
    for (const geometry of graphics.dynamicGeometry) geometry.dispose();
    graphics.dynamicGeometry.length = 0;
    graphics.marks.clear();
    graphics.pickable.length = 0;
    labels = [];
    overlay.replaceChildren();
  }
  function line(points, material) {
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    graphics.dynamicGeometry.push(geometry);
    const result = new THREE.Line(geometry, material);
    if (material.isLineDashedMaterial) result.computeLineDistances();
    graphics.marks.add(result);
  }
  function rebuild() {
    if (!graphics) return;
    clearMarks();
    const { marks, sphere, diamond, materials, pickable } = graphics;
    const right = Math.max(4.8, (dimensions.length - 1) / 2 * STEP);
    for (let n = 0; n <= SCORE_MAX; n++) {
      line([new THREE.Vector3(-right, 0, -n * DEPTH), new THREE.Vector3(right, 0, -n * DEPTH)], materials.grid);
      if (n) {
        label(String(n), new THREE.Vector3(right + 0.5, 0, -n * DEPTH), "burden-tick");
        label(String(n), new THREE.Vector3(-right - 0.45, n, 0), "capability-tick");
      }
    }
    line([new THREE.Vector3(-right, 0, 0), new THREE.Vector3(-right, 5, 0)], materials.axis);
    line([new THREE.Vector3(right, 0, 0), new THREE.Vector3(right, 0, -5 * DEPTH)], materials.axis);
    label("C ↑", new THREE.Vector3(-right - 0.3, 5.7, 0), "capability-axis");
    label("B →", new THREE.Vector3(right, 0, -6.2), "burden-axis");
    dimensions.forEach((row, index) => {
      const front = position(index, 0, 0), back = position(index, 0, 5);
      line([front, back], materials.grid);
      line([front, position(index, 5, 0)], materials.grid);
      const shortLabel = { security: "Security", testing: "Testing", documentation: "Docs", maintainability: "Maintain.", delivery: "Delivery", operability: "Operability", extensibility: "Extensibility", performance: "Performance" }[row.id] || row.label;
      label(shortLabel, position(index, -0.45, 0), "dimension-tick");
      const selected = row.id === selectedId;
      if (score(row.capability) && score(row.burden)) {
        const current = new THREE.Mesh(sphere, needsImprovement(row) ? materials.attention : materials.current);
        current.position.copy(position(index, row.capability, row.burden));
        current.scale.setScalar(selected ? 1.5 : 1);
        current.userData.dimension = row.id;
        marks.add(current);
        pickable.push(current);
        line([position(index, 0, row.burden), current.position], selected ? materials.axis : materials.grid);
        if (selected) label(`${row.label} · C${row.capability} · B${row.burden}`, current.position.clone().add(new THREE.Vector3(0, 0.6, 0)), "selected");
      }
      if (hasGoal(row)) {
        const anchor = new THREE.Mesh(diamond, materials.goal);
        anchor.position.copy(position(index, row.capability_min, row.burden_max));
        anchor.userData.dimension = row.id;
        anchor.scale.setScalar(selected ? 1.2 : 0.85);
        marks.add(anchor);
        pickable.push(anchor);
        if (selected) line([
          position(index, row.capability_min, 0), anchor.position,
          position(index, 5, row.burden_max), position(index, 5, 0),
          position(index, row.capability_min, 0),
        ], materials.region);
        if (needsImprovement(row) && score(row.capability) && score(row.burden)) {
          // Connect to the nearest acceptable point, never to a lower capability.
          line([position(index, row.capability, row.burden), position(index, Math.max(row.capability, row.capability_min), Math.min(row.burden, row.burden_max))], materials.gap);
        }
      }
    });
    requestRender();
  }
  function releaseGraphics() {
    if (!graphics) return;
    const previous = graphics;
    clearMarks();
    graphics = null;
    previous.events.abort();
    previous.controls.dispose();
    for (const resource of [previous.sphere, previous.diamond, ...Object.values(previous.materials)]) resource.dispose();
    previous.renderer.dispose();
    previous.renderer.domElement.remove();
    previous.renderer.forceContextLoss();
  }
  function unavailable() {
    releaseGraphics();
    container.dataset.renderer = "unavailable";
    status.textContent = "The 3D renderer is unavailable. Compare dimensions still shows every known score, target, confidence and explanation.";
    retry.hidden = false;
    for (const button of [...presetButtons.values(), reset]) button.disabled = true;
  }
  function startGraphics() {
    if (disposed) return;
    releaseGraphics();
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
      const scene = new THREE.Scene();
      const camera = new THREE.OrthographicCamera(-10, 10, 8, -8, 0.1, 150);
      const controls = new OrbitControls(camera, renderer.domElement);
      controls.enableDamping = false;
      controls.enableZoom = false;
      controls.minZoom = 0.6;
      controls.maxZoom = 4;
      controls.minPolarAngle = 0.01;
      controls.maxPolarAngle = Math.PI / 2 + 0.1;
      controls.target.copy(cameraTarget);
      controls.addEventListener("change", requestRender);
      const colors = palette();
      const materials = {
        current: new THREE.MeshStandardMaterial({ color: colors.current, roughness: 0.28, metalness: 0.15 }),
        attention: new THREE.MeshStandardMaterial({ color: colors.attention, roughness: 0.28, metalness: 0.15 }),
        goal: new THREE.MeshBasicMaterial({ color: colors.goal, wireframe: true }),
        grid: new THREE.LineBasicMaterial({ color: colors.goal, transparent: true, opacity: 0.16 }),
        axis: new THREE.LineBasicMaterial({ color: colors.goal, transparent: true, opacity: 0.55 }),
        region: new THREE.LineDashedMaterial({ color: colors.goal, transparent: true, opacity: 0.25, dashSize: 0.13, gapSize: 0.1 }),
        gap: new THREE.LineDashedMaterial({ color: colors.current, dashSize: 0.16, gapSize: 0.1 }),
      };
      const marks = new THREE.Group();
      scene.add(marks, new THREE.AmbientLight(0xffffff, 2.4));
      const light = new THREE.DirectionalLight(0xffffff, 3.1);
      light.position.set(-4, 10, 10);
      scene.add(light);
      graphics = { renderer, scene, camera, controls, marks, materials, events: new AbortController(), pickable: [], dynamicGeometry: [], sphere: new THREE.SphereGeometry(0.16, 20, 14), diamond: new THREE.OctahedronGeometry(0.2) };
      const events = { signal: graphics.events.signal };
      renderer.domElement.setAttribute("role", "img");
      renderer.domElement.setAttribute("aria-label", "Interactive 3D capability and burden graph. The same exact scores and goals are available in the dimension controls.");
      renderer.domElement.setAttribute("aria-describedby", help.id);
      renderer.domElement.addEventListener("webglcontextlost", (event) => {
        event.preventDefault();
        if (!disposed && graphics?.renderer === renderer) unavailable();
      }, events);
      let start;
      renderer.domElement.addEventListener("pointerdown", (event) => { start = [event.clientX, event.clientY]; }, events);
      renderer.domElement.addEventListener("pointerup", (event) => {
        if (!graphics || !start || Math.hypot(event.clientX - start[0], event.clientY - start[1]) > 6) return;
        const bounds = renderer.domElement.getBoundingClientRect();
        const pointer = new THREE.Vector2((event.clientX - bounds.left) / bounds.width * 2 - 1, -(event.clientY - bounds.top) / bounds.height * 2 + 1);
        const ray = new THREE.Raycaster();
        ray.setFromCamera(pointer, graphics.camera);
        const hit = ray.intersectObjects(graphics.pickable)[0];
        if (hit) select(hit.object.userData.dimension, true);
      }, events);
      stage.prepend(renderer.domElement);
      container.dataset.renderer = "webgl";
      retry.hidden = true;
      for (const button of [...presetButtons.values(), reset]) button.disabled = false;
      status.textContent = graphStatus();
      setView(view);
      rebuild();
    } catch {
      if (!graphics) { renderer?.dispose(); renderer?.forceContextLoss(); }
      unavailable();
    }
  }
  function graphStatus() {
    const count = rows().length, missing = dimensions.length - count;
    return `${count} of ${dimensions.length} dimensions plotted${missing ? `; ${missing} have an unknown score and are not positioned at zero` : ""}. ${model.preview_targets ? "Goal preview is unsaved." : dimensions.some(hasGoal) ? "Goal boundaries use saved targets." : "No goal boundaries are configured."}`;
  }
  function renderDetail() {
    const row = dimensions.find((item) => item.id === selectedId);
    detail.replaceChildren();
    if (!row) return;
    detail.append(element("h3", row.label));
    const values = element("dl", undefined, "dm-values");
    for (const [title, value] of [
      ["Capability", show(row.capability)], ["Upkeep burden", show(row.burden)],
      ["Capability minimum", score(row.capability_min) ? show(row.capability_min) : "Not set"],
      ["Burden ceiling", score(row.burden_max) ? show(row.burden_max) : "Not set"],
    ]) {
      const pair = element("div");
      pair.append(element("dt", title), element("dd", value));
      values.append(pair);
    }
    detail.append(values);
    const cg = capabilityGap(row), bg = burdenGap(row);
    if (cg !== null || bg !== null) {
      const gaps = [cg !== null ? `capability +${cg}` : "capability unknown", bg !== null ? `burden −${bg}` : "burden unknown"];
      detail.append(element("p", cg === 0 && bg === 0 ? "Within both targets. Extra useful capability has no penalty." : `Goal distance: ${gaps.join(", ")} rubric steps. Extra capability needs no reduction.`, "dm-gap-summary"));
    }
    if (!score(row.capability) || !score(row.burden)) detail.append(element("p", "Unknown is not zero. The known axis remains visible in Compare dimensions; a complete point needs both axes in 3D.", "dm-note"));
    detail.append(element("p", `Declared confidence: capability ${row.capability_confidence || "unknown"}; burden ${row.burden_confidence || "unknown"}. Burden basis: ${basisLabel(row.burden_basis)}.`, "dm-note"));
    if (row.recommendations?.length) {
      detail.append(element("h4", "Recommended next steps"));
      const recommendations = element("ul");
      for (const text of row.recommendations.slice(0, 3)) recommendations.append(element("li", text));
      detail.append(recommendations);
      if (row.recommendations.length > 3) detail.append(element("p", `${row.recommendations.length - 3} more recommendations are in the full assessment.`, "dm-note"));
    }
    if (row.rationale) {
      const reasoning = element("details", undefined, "dm-reasoning");
      reasoning.append(element("summary", "Why these ratings?"), element("p", row.rationale, "dm-rationale"));
      detail.append(reasoning);
    }
    const evidence = element("details", undefined, "dm-evidence");
    evidence.append(element("summary", "Evidence and confidence"));
    if (row.burden_evidence) {
      const counts = row.burden_evidence;
      evidence.append(element("p", `Burden support: ${counts.source} source records; ${counts.experience} attributed experience reports; ${counts.matched_cost} source-matched cost reports; ${counts.partial_elapsed} partial elapsed reports. Counts are not a confidence grade.`, "dm-note"));
    }
    if (row.confidence_notes?.length) evidence.append(textList(row.confidence_notes));
    if (row.burden_next_steps?.length) {
      evidence.append(element("h4", "What would strengthen confidence?"), textList(row.burden_next_steps));
    }
    if (row.evidence_references?.length) {
      evidence.append(textList(row.evidence_references.map((item) => `${item.path} · ${item.kind} · ${item.id}`)));
      if (row.evidence_reference_total > row.evidence_references.length) evidence.append(element("p", `${row.evidence_reference_total - row.evidence_references.length} more source references are in the full assessment.`, "dm-note"));
    }
    else if (row.evidence_ids?.length) evidence.append(element("p", `Captured evidence: ${row.evidence_ids.slice(0, 5).join(", ")}${row.evidence_ids.length > 5 ? `; ${row.evidence_ids.length - 5} more in the full assessment` : ""}.`, "dm-note"));
    detail.append(evidence);
  }
  function textList(values) {
    const result = element("ul");
    for (const text of values) result.append(element("li", text));
    return result;
  }
  function axis(row, kind) {
    const isCapability = kind === "capability";
    const title = isCapability ? "Capability" : "Burden";
    const value = row[kind], target = row[isCapability ? "capability_min" : "burden_max"];
    const gap = isCapability ? capabilityGap(row) : burdenGap(row);
    const axisNode = element("span", undefined, `dm-axis dm-axis-${kind}`);
    axisNode.append(element("span", `${title} ${show(value)}`, "dm-axis-value"));
    const track = element("span", undefined, "dm-track");
    track.setAttribute("aria-hidden", "true");
    for (let n = 0; n <= SCORE_MAX; n++) {
      const tick = element("span", String(n), "dm-tick");
      tick.style.left = `${n / SCORE_MAX * 100}%`;
      track.append(tick);
    }
    if (score(target)) {
      const tick = element("span", undefined, "dm-target");
      tick.dataset.value = String(target);
      tick.style.left = `${target / SCORE_MAX * 100}%`;
      track.append(tick);
    }
    if (score(value)) {
      const marker = element("span", undefined, "dm-current");
      marker.dataset.value = String(value);
      marker.style.left = `${value / SCORE_MAX * 100}%`;
      track.append(marker);
    } else track.classList.add("dm-track-unknown");
    axisNode.append(track);
    const targetText = score(target) ? `${isCapability ? "Minimum" : "Ceiling"} ${target}` : `No ${isCapability ? "minimum" : "ceiling"} set`;
    axisNode.append(element("span", targetText, "dm-axis-target"));
    const gapText = !score(value) ? `${title} unknown` : gap === null ? "Target not set" : gap > 0 ? `${isCapability ? "Raise capability" : "Reduce burden"} by ${gap} ${gap === 1 ? "step" : "steps"}` : isCapability ? "Minimum met" : "Within ceiling";
    const gapLabel = element("span", gapText, "dm-axis-gap");
    gapLabel.hidden = !score(target);
    if (gap > 0) { gapLabel.classList.add("dm-outside"); axisNode.dataset.outside = "true"; }
    axisNode.append(gapLabel, element("span", `Confidence: ${row[`${kind}_confidence`] || "unknown"}`, "dm-confidence"));
    if (!isCapability) axisNode.append(element("span", basisLabel(row.burden_basis), "dm-basis"));
    return axisNode;
  }
  function select(id, notify = false) {
    if (!dimensions.some((row) => row.id === id)) return;
    selectedId = id;
    selector.value = id;
    container.dataset.selectedDimension = id;
    for (const button of list.querySelectorAll("button[data-dimension]")) button.setAttribute("aria-pressed", String(button.dataset.dimension === id));
    renderDetail();
    placeDetail();
    rebuild();
    if (notify && typeof onSelect === "function") onSelect(id);
  }
  function placeDetail() {
    const selected = [...list.querySelectorAll("button[data-dimension]")].find((button) => button.dataset.dimension === selectedId);
    if (narrowLayout.matches && mode === "compare" && selected) selected.after(detail);
    else workspace.append(detail);
  }
  function update(nextModel) {
    if (disposed) return;
    model = nextModel || {};
    dimensions = Array.isArray(model.dimensions) ? model.dimensions.slice(0, 8).filter((row) => row && typeof row.id === "string" && typeof row.label === "string") : [];
    const previous = selectedId;
    selector.replaceChildren();
    // Keep the shared inspector alive while rebuilding comparison controls.
    workspace.append(detail);
    list.replaceChildren();
    dimensions.forEach((row) => {
      const option = element("option", row.label);
      option.value = row.id;
      selector.append(option);
      const button = element("button", undefined, "dm-dimension");
      button.type = "button";
      button.dataset.dimension = row.id;
      button.append(element("span", row.label, "dm-dimension-name"), axis(row, "capability"), axis(row, "burden"));
      list.append(button);
    });
    const anyTargets = dimensions.some((row) => score(row.capability_min) || score(row.burden_max));
    targetState.textContent = model.preview_targets ? "Unsaved target preview" : anyTargets ? "Saved targets" : "Targets not set";
    for (const key of [goalKey, gapKey, outsideKey]) key.hidden = !anyTargets;
    const comparableC = dimensions.filter((row) => capabilityGap(row) !== null).length;
    const comparableB = dimensions.filter((row) => burdenGap(row) !== null).length;
    const missing = dimensions.filter((row) => !score(row.capability) || !score(row.burden)).length;
    const summaries = [];
    if (comparableC) summaries.push(`${dimensions.filter((row) => capabilityGap(row) > 0).length} of ${comparableC} capabilities below minimum`);
    if (comparableB) summaries.push(`${dimensions.filter((row) => burdenGap(row) > 0).length} of ${comparableB} burdens above ceiling`);
    summaries.push(`${missing} of ${dimensions.length} dimensions have unknown scores`);
    summary.textContent = summaries.join(" · ") + (comparableC && comparableB ? ". Counts can overlap." : ".");
    container.dataset.currentCount = String(rows().length);
    container.dataset.goalCount = String(dimensions.filter(hasGoal).length);
    container.dataset.guideCount = String(dimensions.filter(needsImprovement).length);
    if (graphics) status.textContent = graphStatus();
    if (dimensions.length) select(dimensions.some((row) => row.id === previous) ? previous : dimensions[0].id);
    else {
      selectedId = null;
      delete container.dataset.selectedDimension;
      detail.replaceChildren();
      rebuild();
    }
  }
  const observer = new ResizeObserver(fit);
  observer.observe(stage);
  const changeTheme = () => {
    if (!graphics) return;
    const colors = palette();
    for (const name of ["current", "gap"]) graphics.materials[name].color.copy(colors.current);
    graphics.materials.attention.color.copy(colors.attention);
    for (const name of ["goal", "grid", "axis", "region"]) graphics.materials[name].color.copy(colors.goal);
    requestRender();
  };
  darkTheme.addEventListener("change", changeTheme);
  narrowLayout.addEventListener("change", placeDetail);
  update(initialModel);
  setMode("compare");
  return {
    update,
    dispose() {
      if (disposed) return;
      disposed = true;
      cancelAnimationFrame(frame);
      frame = 0;
      observer.disconnect();
      darkTheme.removeEventListener("change", changeTheme);
      narrowLayout.removeEventListener("change", placeDetail);
      signalController.abort();
      releaseGraphics();
      container.replaceChildren();
      for (const name of ["renderer", "mode", "currentCount", "goalCount", "guideCount", "selectedDimension"]) delete container.dataset[name];
    },
  };
}
