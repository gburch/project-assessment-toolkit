import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";

let instances = 0;
const SCORE_MAX = 5;
const STEP = 1.35;
const DEPTH = 1.1;
const score = (value) => Number.isInteger(value) && value >= 0 && value <= SCORE_MAX;
const show = (value) => score(value) ? `${value} / ${SCORE_MAX}` : "Unknown";

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
  let graphics = null, view = "3d", labels = [];
  const projected = new THREE.Vector3();
  const cameraTarget = new THREE.Vector3(0, 2.5, -2.75);
  const darkTheme = window.matchMedia("(prefers-color-scheme: dark)");
  container.classList.add("dimension-map");

  const introduction = element("p", "Explore capability and its upkeep cost together. Height is capability; depth is burden. Each numbered lane is an engineering dimension.", "dm-introduction");
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
  legend.append(currentKey, goalKey, gapKey);
  const stage = element("div", undefined, "dm-stage");
  const axisGuide = element("div", undefined, "dm-axis-guide");
  axisGuide.append(element("span", "Height · capability 0–5"), element("span", "Depth · burden 0–5"));
  const overlay = element("div", undefined, "dm-labels");
  overlay.setAttribute("aria-hidden", "true");
  stage.append(axisGuide, overlay);
  const help = element("p", "Numbered lanes match the dimensions below. Drag to orbit · scroll or pinch to zoom, or use the keyboard-accessible view and dimension controls. Higher capability is welcome; burden is a ceiling.", "dm-help");
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
  container.replaceChildren(introduction, toolbar, legend, stage, help, status, retry, list, detail);

  function rows() { return dimensions.filter((row) => score(row.capability) && score(row.burden)); }
  function hasGoal(row) { return score(row.capability_min) && score(row.burden_max); }
  function needsImprovement(row) {
    return hasGoal(row) && score(row.capability) && score(row.burden) &&
      (row.capability < row.capability_min || row.burden > row.burden_max);
  }
  function position(index, capability, burden) {
    return new THREE.Vector3((index - (dimensions.length - 1) / 2) * STEP, capability, -burden * DEPTH);
  }
  function palette() {
    return {
      current: new THREE.Color(getComputedStyle(currentKey).color),
      goal: new THREE.Color(getComputedStyle(goalKey).color),
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
  function fit() {
    if (!graphics || !stage.clientWidth || !stage.clientHeight) return;
    const { camera, renderer } = graphics;
    const width = stage.clientWidth, height = stage.clientHeight, aspect = width / height;
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
    fit();
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
      label(String(index + 1).padStart(2, "0"), position(index, -0.3, 0), "dimension-tick");
      const selected = row.id === selectedId;
      if (score(row.capability) && score(row.burden)) {
        const current = new THREE.Mesh(sphere, materials.current);
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
        line([
          position(index, row.capability_min, 0), anchor.position,
          position(index, 5, row.burden_max), position(index, 5, 0),
          position(index, row.capability_min, 0),
        ], materials.region);
        if (needsImprovement(row)) {
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
    status.textContent = "The 3D renderer is unavailable. Every score, goal and explanation remains available in the dimension controls below.";
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
      controls.minZoom = 0.6;
      controls.maxZoom = 4;
      controls.minPolarAngle = 0.01;
      controls.maxPolarAngle = Math.PI / 2 + 0.1;
      controls.target.copy(cameraTarget);
      controls.addEventListener("change", requestRender);
      const colors = palette();
      const materials = {
        current: new THREE.MeshStandardMaterial({ color: colors.current, roughness: 0.28, metalness: 0.15 }),
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
    if (hasGoal(row) && score(row.capability) && score(row.burden)) {
      const capabilityGap = Math.max(row.capability_min - row.capability, 0);
      const burdenGap = Math.max(row.burden - row.burden_max, 0);
      detail.append(element("p", capabilityGap || burdenGap ? `Goal distance: capability +${capabilityGap}, burden −${burdenGap} rubric steps. Extra capability needs no reduction.` : "Within both targets. Extra useful capability has no penalty.", "dm-gap-summary"));
    }
    if (!score(row.capability) || !score(row.burden)) detail.append(element("p", "An unknown axis keeps this dimension off the plot; its known value is preserved above.", "dm-note"));
    detail.append(element("p", `Declared confidence: capability ${row.capability_confidence || "unknown"}; burden ${row.burden_confidence || "unknown"}. Burden basis: ${row.burden_basis || "unknown"}.`, "dm-note"));
    if (row.rationale) detail.append(element("p", row.rationale, "dm-rationale"));
    if (row.recommendations?.length) {
      const recommendations = element("ul");
      for (const text of row.recommendations.slice(0, 3)) recommendations.append(element("li", text));
      detail.append(recommendations);
      if (row.recommendations.length > 3) detail.append(element("p", `${row.recommendations.length - 3} more recommendations are in the full assessment.`, "dm-note"));
    }
    if (row.evidence_ids?.length) detail.append(element("p", `Captured evidence: ${row.evidence_ids.slice(0, 5).join(", ")}${row.evidence_ids.length > 5 ? `; ${row.evidence_ids.length - 5} more in the full assessment` : ""}.`, "dm-note"));
  }
  function select(id, notify = false) {
    if (!dimensions.some((row) => row.id === id)) return;
    selectedId = id;
    selector.value = id;
    container.dataset.selectedDimension = id;
    for (const button of list.children) button.setAttribute("aria-pressed", String(button.dataset.dimension === id));
    renderDetail();
    rebuild();
    if (notify && typeof onSelect === "function") onSelect(id);
  }
  function update(nextModel) {
    if (disposed) return;
    model = nextModel || {};
    dimensions = Array.isArray(model.dimensions) ? model.dimensions.slice(0, 8).filter((row) => row && typeof row.id === "string" && typeof row.label === "string") : [];
    const previous = selectedId;
    selector.replaceChildren();
    list.replaceChildren();
    dimensions.forEach((row, index) => {
      const option = element("option", row.label);
      option.value = row.id;
      selector.append(option);
      const button = element("button", undefined, "dm-dimension");
      button.type = "button";
      button.dataset.dimension = row.id;
      button.append(element("span", `${String(index + 1).padStart(2, "0")} ${row.label}`, "dm-dimension-name"), element("span", `Capability ${show(row.capability)} · Burden ${show(row.burden)}`, "dm-dimension-values"));
      list.append(button);
    });
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
    for (const name of ["goal", "grid", "axis", "region"]) graphics.materials[name].color.copy(colors.goal);
    requestRender();
  };
  darkTheme.addEventListener("change", changeTheme);
  update(initialModel);
  startGraphics();
  setView("3d");
  return {
    update,
    dispose() {
      if (disposed) return;
      disposed = true;
      cancelAnimationFrame(frame);
      frame = 0;
      observer.disconnect();
      darkTheme.removeEventListener("change", changeTheme);
      signalController.abort();
      releaseGraphics();
      container.replaceChildren();
      for (const name of ["renderer", "currentCount", "goalCount", "guideCount", "selectedDimension"]) delete container.dataset[name];
    },
  };
}
