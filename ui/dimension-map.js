import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";

let instances = 0;
const SCORE_MAX = 5;
const LAYER_GAP = 2.4;
const SVG_NS = "http://www.w3.org/2000/svg";
const score = (value) => Number.isInteger(value) && value >= 0 && value <= SCORE_MAX;
const show = (value) => score(value) ? `${value} / ${SCORE_MAX}` : "Unknown";
const capabilityGap = (row) => score(row.capability) && score(row.capability_min) ? Math.max(row.capability_min - row.capability, 0) : null;
const burdenGap = (row) => score(row.burden) && score(row.burden_max) ? Math.max(row.burden - row.burden_max, 0) : null;
const basisLabel = (basis) => ({ observed: "observed or reported", source_estimate: "estimated from source", unknown: "basis unknown" })[basis] || "basis unknown";
// Every track reads the same way: the better end is on the right, so burden runs heavy to light.
const along = (kind, value) => kind === "capability" ? value / SCORE_MAX : (SCORE_MAX - value) / SCORE_MAX;
const percent = (fraction) => `${Math.round(fraction * 1000) / 10}%`;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function svg(tag, attributes = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

/** A read-only view. Goal edits and persistence belong to the enclosing report. */
export function createDimensionMap(container, initialModel, { onSelect } = {}) {
  const instance = `pat-dimension-map-${++instances}`;
  const signalController = new AbortController();
  const { signal } = signalController;
  let model, dimensions = [], timeline = [], selectedId, disposed = false, frame = 0;
  let graphics = null, view = "angle", mode = "compare", labels = [];
  const projected = new THREE.Vector3();
  const darkTheme = window.matchMedia("(prefers-color-scheme: dark)");
  container.classList.add("dimension-map");

  const head = element("div", undefined, "dm-head");
  const summary = element("p", undefined, "dm-summary");
  summary.setAttribute("role", "status");
  const targetState = element("p", undefined, "dm-target-state");
  const modes = element("div", undefined, "dm-modes");
  modes.setAttribute("role", "group");
  modes.setAttribute("aria-label", "View");
  const modeButtons = new Map();
  for (const [id, title] of [["compare", "Dimensions"], ["map", "Level map"], ["3d", "What moved"]]) {
    const button = element("button", title);
    button.type = "button";
    button.addEventListener("click", () => setMode(id), { signal });
    modeButtons.set(id, button);
    modes.append(button);
  }
  head.append(summary, modes);
  const status = element("p", undefined, "dm-status");
  status.setAttribute("role", "status");

  const workspace = element("div", undefined, "dm-workspace");
  const comparison = element("div", undefined, "dm-comparison");
  const headings = element("div", undefined, "dm-comparison-head");
  headings.setAttribute("aria-hidden", "true");
  const scale = (title, low, high) => {
    const node = element("span", undefined, "dm-scale");
    node.append(element("b", title), element("span", `${low} → ${high}`));
    return node;
  };
  headings.append(targetState, scale("Capability", "0", "5"), scale("Upkeep burden", "heavy", "light"), element("span", "Evidence", "dm-evidence-head"));
  const list = element("div", undefined, "dm-dimensions");
  list.setAttribute("role", "group");
  list.setAttribute("aria-label", "Dimension scores");
  list.addEventListener("click", (event) => {
    const button = event.target.closest?.("button[data-dimension]");
    if (button && list.contains(button)) select(button.dataset.dimension, true);
  }, { signal });
  comparison.append(headings, list);

  const levelMap = element("div", undefined, "dm-levelmap");
  const plot = element("div", undefined, "dm-plot");
  const plotSvg = svg("svg", { viewBox: "0 0 600 580", "aria-hidden": "true", focusable: "false" });
  const clusters = element("div", undefined, "dm-clusters");
  clusters.setAttribute("role", "group");
  clusters.setAttribute("aria-label", "Dimensions by capability and burden");
  plot.append(plotSvg, clusters);
  const levelLegend = element("div", undefined, "dm-level-legend");
  levelLegend.setAttribute("role", "group");
  levelLegend.setAttribute("aria-label", "Level map dimension key");
  levelLegend.addEventListener("click", (event) => {
    const button = event.target.closest?.("button[data-dimension]");
    if (!button || !levelLegend.contains(button)) return;
    const id = button.dataset.dimension;
    select(id, true);
    // Selection rebuilds the plot; keep keyboard navigation in the visible key.
    [...levelLegend.querySelectorAll("button")].find((item) => item.dataset.dimension === id)?.focus();
  }, { signal });
  const unplotted = element("p", undefined, "dm-note");
  levelMap.append(plot, levelLegend, unplotted);

  const spatial = element("div", undefined, "dm-spatial");
  const toolbar = element("div", undefined, "dm-toolbar");
  const presets = element("div", undefined, "dm-presets");
  presets.setAttribute("role", "group");
  presets.setAttribute("aria-label", "Camera");
  const presetButtons = new Map();
  for (const [id, title] of [["angle", "Angle"], ["latest", "Latest"], ["capability", "Capability over time"], ["burden", "Burden over time"]]) {
    const button = element("button", title);
    button.type = "button";
    button.addEventListener("click", () => setView(id), { signal });
    presetButtons.set(id, button);
    presets.append(button);
  }
  const selectorLabel = element("label", "Inspect dimension");
  selectorLabel.htmlFor = `${instance}-select`;
  const selector = element("select");
  selector.id = `${instance}-select`;
  selector.addEventListener("change", () => select(selector.value, true), { signal });
  selectorLabel.append(selector);
  toolbar.append(presets, selectorLabel);
  const stage = element("div", undefined, "dm-stage");
  const overlay = element("div", undefined, "dm-labels");
  overlay.setAttribute("aria-hidden", "true");
  stage.append(overlay);
  const stageNote = element("p", undefined, "dm-note dm-stage-note");
  const retry = element("button", "Try 3D again");
  retry.type = "button";
  retry.hidden = true;
  retry.addEventListener("click", startGraphics, { signal });
  spatial.append(toolbar, stage, stageNote, retry);

  const detail = element("div", undefined, "dm-detail");
  workspace.append(comparison, levelMap, spatial, detail);
  container.replaceChildren(head, status, workspace);

  function rows() { return dimensions.filter((row) => score(row.capability) && score(row.burden)); }
  function hasGoal(row) { return score(row.capability_min) && score(row.burden_max); }
  function needsImprovement(row) { return capabilityGap(row) > 0 || burdenGap(row) > 0; }
  function level(row) { return hasGoal(row) && score(row.capability) && score(row.burden) && !needsImprovement(row); }
  function selectedRow() { return dimensions.find((row) => row.id === selectedId); }

  function setMode(next) {
    mode = next;
    container.dataset.mode = mode;
    for (const [id, button] of modeButtons) button.setAttribute("aria-pressed", String(id === mode));
    comparison.hidden = mode !== "compare";
    levelMap.hidden = mode !== "map";
    spatial.hidden = mode !== "3d";
    placeDetail();
    if (mode === "3d") {
      if (!graphics && container.dataset.renderer !== "unavailable") startGraphics();
      fit();
    }
  }

  // Level map: one flat plot of every dimension; coincident scores share a labelled cluster.
  const X0 = 56, Y0 = 16, SIZE = 520;
  const px = (burden) => X0 + SIZE * along("burden", burden);
  const py = (capability) => Y0 + SIZE * (1 - capability / SCORE_MAX);
  function renderLevelMap() {
    plotSvg.replaceChildren();
    clusters.replaceChildren();
    levelLegend.replaceChildren();
    plotSvg.append(svg("rect", { x: X0, y: Y0, width: SIZE, height: SIZE, rx: 14, class: "dm-plot-ground" }));
    const row = selectedRow();
    if (row && hasGoal(row)) {
      const left = px(row.burden_max), top = py(SCORE_MAX), bottom = py(row.capability_min);
      plotSvg.append(svg("rect", { x: left, y: top, width: X0 + SIZE - left, height: bottom - top, class: "dm-plot-zone" }));
    }
    for (let n = 1; n < SCORE_MAX; n++) {
      plotSvg.append(svg("line", { x1: X0 + SIZE * n / SCORE_MAX, y1: Y0, x2: X0 + SIZE * n / SCORE_MAX, y2: Y0 + SIZE, class: "dm-plot-grid" }));
      plotSvg.append(svg("line", { x1: X0, y1: Y0 + SIZE * n / SCORE_MAX, x2: X0 + SIZE, y2: Y0 + SIZE * n / SCORE_MAX, class: "dm-plot-grid" }));
    }
    if (row && hasGoal(row)) {
      const left = px(row.burden_max), bottom = py(row.capability_min);
      plotSvg.append(svg("path", { d: `M${left} ${Y0} V${bottom} H${X0 + SIZE}`, class: "dm-plot-target" }));
      if (needsImprovement(row) && score(row.capability) && score(row.burden)) {
        // Point to the nearest acceptable position, never to a lower capability.
        const to = [px(Math.min(row.burden, row.burden_max)), py(Math.max(row.capability, row.capability_min))];
        plotSvg.append(svg("line", { x1: px(row.burden), y1: py(row.capability), x2: to[0], y2: to[1], class: "dm-plot-gap" }));
        plotSvg.append(svg("circle", { cx: to[0], cy: to[1], r: 4, class: "dm-plot-gap-end" }));
      }
    }
    for (const [x, y, text, anchor, extra] of [[X0, 562, "heavy", "start"], [X0 + SIZE / 2, 562, "Upkeep burden", "middle", "dm-plot-title"], [X0 + SIZE, 562, "light", "end"], [44, Y0 + SIZE + 4, "0", "end"], [44, Y0 + 10, "5", "end"]]) {
      const node = svg("text", { x, y, "text-anchor": anchor, class: extra || "dm-plot-label" });
      node.textContent = text;
      plotSvg.append(node);
    }
    const capabilityTitle = svg("text", { x: 30, y: Y0 + SIZE / 2, "text-anchor": "middle", transform: `rotate(-90 30 ${Y0 + SIZE / 2})`, class: "dm-plot-title" });
    capabilityTitle.textContent = "Capability";
    plotSvg.append(capabilityTitle);
    const groups = new Map();
    for (const item of rows()) {
      const key = `${item.capability}:${item.burden}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(item);
    }
    for (const members of groups.values()) {
      const { capability, burden } = members[0];
      const x = px(burden), y = py(capability);
      const button = element("button", String(members.length), "dm-cluster");
      button.type = "button";
      button.dataset.state = members.every(level) ? "level" : members.some(needsImprovement) ? "outside" : "plain";
      button.style.left = percent(x / 600);
      button.style.top = percent(y / 580);
      button.style.setProperty("--size", `${26 + members.length * 6}px`);
      button.setAttribute("aria-pressed", String(members.some((item) => item.id === selectedId)));
      button.setAttribute("aria-label", `${members.map((item) => item.label).join(", ")}: capability ${capability}, burden ${burden}; ${members.length} ${members.length === 1 ? "dimension" : "dimensions"}`);
      button.addEventListener("click", () => {
        // Repeated clicks step through dimensions that share one position.
        const at = members.findIndex((item) => item.id === selectedId);
        select(members[(at + 1) % members.length].id, true);
      }, { signal });
      const names = element("span", members.map((item) => item.label).join("\n"), "dm-cluster-names");
      names.setAttribute("aria-hidden", "true");
      names.dataset.side = burden > 2 ? "left" : "right";
      names.style.left = percent(x / 600);
      names.style.top = percent(y / 580);
      clusters.append(button, names);
      const group = element("div", undefined, "dm-level-key-group");
      group.append(element("p", `Capability ${capability} · Burden ${burden}`, "dm-level-key-score"));
      const choices = element("div", undefined, "dm-level-key-choices");
      for (const item of members) {
        const choice = element("button", item.label);
        choice.type = "button";
        choice.dataset.dimension = item.id;
        choice.setAttribute("aria-pressed", String(item.id === selectedId));
        choices.append(choice);
      }
      group.append(choices);
      levelLegend.append(group);
    }
    const missing = dimensions.filter((item) => !score(item.capability) || !score(item.burden));
    unplotted.textContent = missing.length ? `Not plotted: ${missing.map((item) => item.label).join(", ")} (unknown score)` : "";
    unplotted.hidden = !missing.length;
  }

  // What moved: each snapshot is one level map, stacked back in time.
  function palette() {
    const style = getComputedStyle(container);
    const read = (name, fallback) => new THREE.Color((style.getPropertyValue(name) || fallback).trim() || fallback);
    return {
      level: read("--amber", "#f2ae12"), outside: read("--rust", "#b4471f"), plain: read("--amber", "#f2ae12"),
      ink: read("--text", "#13223b"), line: read("--line", "#e7e2d6"), zone: read("--zone-solid", "#fbebbf"),
      surface: read("--surface", "#ffffff"),
    };
  }
  function layerZ(index) { return (index - (timeline.length - 1)) * LAYER_GAP; }
  function point(index, capability, burden, layer) {
    return new THREE.Vector3((SCORE_MAX - burden) - SCORE_MAX / 2 + (index - 3.5) * 0.05, capability, layerZ(layer));
  }
  function center() { return new THREE.Vector3(0, 2.5, layerZ(0) / 2); }
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
        const hidden = Math.abs(projected.x) > 1 || Math.abs(projected.y) > 1 || projected.z < -1 || projected.z > 1;
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
    const width = stage.clientWidth, height = stage.clientHeight;
    if (graphics.width !== width || graphics.height !== height) {
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(width, height, false);
      graphics.width = width;
      graphics.height = height;
    }
    requestRender();
  }
  function setView(next) {
    view = next;
    for (const [id, button] of presetButtons) button.setAttribute("aria-pressed", String(id === view));
    if (!graphics) return;
    const { camera, controls } = graphics;
    const target = center(), depth = -layerZ(0), distance = 15 + depth * 0.7;
    camera.up.set(0, 1, 0);
    if (view === "latest") camera.position.set(0, 2.5, distance);
    else if (view === "capability") camera.position.set(distance + 1, 2.5, target.z);
    else if (view === "burden") { camera.position.set(0, distance + 2, target.z + 0.01); camera.up.set(0, 0, -1); }
    else camera.position.set(distance * 0.55, 2.5 + distance * 0.42, target.z + distance * 0.72);
    controls.target.copy(target);
    camera.lookAt(target);
    controls.update();
    fit();
  }
  function clearMarks() {
    if (!graphics) return;
    for (const resource of graphics.dynamic) resource.dispose();
    graphics.dynamic.length = 0;
    graphics.marks.clear();
    graphics.pickable.length = 0;
    labels = [];
    overlay.replaceChildren();
  }
  function track(resource) { graphics.dynamic.push(resource); return resource; }
  function historyLabel(snapshot) {
    if (!snapshot.reviewed) return "not reviewed";
    const comparison = snapshot.comparison;
    if (!comparison || comparison.event === "unknown") return "comparison unknown";
    if (comparison.event === "initial") return "initial assessment";
    if (comparison.event === "goal_baseline") return "new goal baseline";
    if (comparison.event === "evidence_update") return "evidence update";
    if (comparison.comparable !== true) return "not comparable";
    return comparison.event === "source_change" ? "source change" : "comparison unknown";
  }
  function line(points, material) {
    const result = new THREE.Line(track(new THREE.BufferGeometry().setFromPoints(points)), material);
    if (material.isLineDashedMaterial) result.computeLineDistances();
    graphics.marks.add(result);
  }
  function tube(from, to, material) {
    // WebGL lines are one pixel wide; a thin tube keeps a trail readable at any angle.
    const direction = to.clone().sub(from);
    const segment = new THREE.Mesh(track(new THREE.CylinderGeometry(1, 1, 1, 10, 1, true)), material);
    segment.scale.set(material === graphics.materials.trail ? 0.035 : 0.018, direction.length(), material === graphics.materials.trail ? 0.035 : 0.018);
    segment.position.copy(from).add(direction.multiplyScalar(0.5));
    segment.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), to.clone().sub(from).normalize());
    graphics.marks.add(segment);
  }
  function rebuild() {
    if (!graphics) return;
    clearMarks();
    const { marks, sphere, materials, pickable } = graphics;
    const row = selectedRow();
    const latest = timeline.length - 1;
    let trailCount = 0;
    timeline.forEach((snapshot, layer) => {
      const z = layerZ(layer), current = layer === latest;
      const plane = new THREE.Mesh(track(new THREE.PlaneGeometry(SCORE_MAX, SCORE_MAX)), current ? materials.surface : materials.ghost);
      plane.position.set(0, 2.5, z - 0.01);
      marks.add(plane);
      const h = SCORE_MAX / 2;
      line([new THREE.Vector3(-h, 0, z), new THREE.Vector3(h, 0, z), new THREE.Vector3(h, 5, z), new THREE.Vector3(-h, 5, z), new THREE.Vector3(-h, 0, z)], snapshot.reviewed ? materials.edge : materials.unreviewed);
      for (let n = 1; n < SCORE_MAX; n++) {
        line([new THREE.Vector3(-h + n, 0, z), new THREE.Vector3(-h + n, 5, z)], materials.grid);
        line([new THREE.Vector3(-h, n, z), new THREE.Vector3(h, n, z)], materials.grid);
      }
      if (snapshot.reviewed && row && hasGoal(row)) {
        const left = SCORE_MAX - row.burden_max - h, bottom = row.capability_min;
        const zone = new THREE.Mesh(track(new THREE.PlaneGeometry(h - left, SCORE_MAX - bottom)), current ? materials.zone : materials.ghostZone);
        zone.position.set((left + h) / 2, (bottom + SCORE_MAX) / 2, z);
        marks.add(zone);
        if (current) line([new THREE.Vector3(left, 5, z), new THREE.Vector3(left, bottom, z), new THREE.Vector3(h, bottom, z)], materials.target);
      }
      const date = snapshot.date || "Date unknown";
      label(`${date} · ${historyLabel(snapshot)}`, new THREE.Vector3(-h + 0.6, 5.35, z), current ? "layer-current" : "layer");
    });
    label("heavy", new THREE.Vector3(-2.2, -0.35, 0), "axis");
    label("light", new THREE.Vector3(2.2, -0.35, 0), "axis");
    label("capability", new THREE.Vector3(-3.1, 2.5, 0), "axis");
    dimensions.forEach((item, index) => {
      const selected = item.id === selectedId;
      let previous = null;
      timeline.forEach((snapshot, layer) => {
        const [capability, burden] = snapshot.scores?.[item.id] || [];
        if (!snapshot.reviewed || !score(capability) || !score(burden)) { previous = null; return; }
        const at = point(index, capability, burden, layer);
        const goalRow = { ...item, capability, burden };
        const mark = new THREE.Mesh(sphere, level(goalRow) ? materials.level : needsImprovement(goalRow) ? materials.outside : materials.plain);
        mark.position.copy(at);
        mark.scale.setScalar((layer === latest ? 1.3 : 0.9) * (selected ? 1.45 : 1));
        mark.userData.dimension = item.id;
        marks.add(mark);
        pickable.push(mark);
        if (previous && snapshot.comparison?.comparable === true && snapshot.comparison.event === "source_change") {
          tube(previous, at, selected ? materials.trail : materials.faintTrail);
          trailCount++;
        }
        previous = at;
        if (selected && layer === latest) label(`${item.label} · C${capability} · B${burden}`, at.clone().add(new THREE.Vector3(0, 0.55, 0)), "selected");
      });
    });
    container.dataset.trailCount = String(trailCount);
    requestRender();
  }
  function releaseGraphics() {
    if (!graphics) return;
    const previous = graphics;
    clearMarks();
    graphics = null;
    previous.events.abort();
    previous.controls.dispose();
    for (const resource of [previous.sphere, ...Object.values(previous.materials)]) resource.dispose();
    previous.renderer.dispose();
    previous.renderer.domElement.remove();
    previous.renderer.forceContextLoss();
  }
  function unavailable() {
    releaseGraphics();
    container.dataset.renderer = "unavailable";
    stageNote.textContent = "3D is unavailable here. The level map shows the same scores.";
    retry.hidden = false;
    for (const button of presetButtons.values()) button.disabled = true;
  }
  function materialSet(colors) {
    const basic = (color, extra = {}) => new THREE.MeshBasicMaterial({ color, side: THREE.DoubleSide, ...extra });
    return {
      surface: basic(colors.surface, { transparent: true, opacity: 0.7, depthWrite: false }),
      ghost: basic(colors.surface, { transparent: true, opacity: 0.45, depthWrite: false }),
      zone: basic(colors.zone, { transparent: true, opacity: 0.85, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -1 }),
      ghostZone: basic(colors.zone, { transparent: true, opacity: 0.45, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -1 }),
      level: new THREE.MeshStandardMaterial({ color: colors.level, roughness: 0.3, metalness: 0.05 }),
      outside: new THREE.MeshStandardMaterial({ color: colors.outside, roughness: 0.3, metalness: 0.05 }),
      plain: new THREE.MeshStandardMaterial({ color: colors.plain, roughness: 0.3, metalness: 0.05 }),
      edge: new THREE.LineBasicMaterial({ color: colors.ink, transparent: true, opacity: 0.35 }),
      unreviewed: new THREE.LineDashedMaterial({ color: colors.ink, transparent: true, opacity: 0.35, dashSize: 0.18, gapSize: 0.14 }),
      grid: new THREE.LineBasicMaterial({ color: colors.line }),
      target: new THREE.LineBasicMaterial({ color: colors.ink }),
      trail: basic(colors.ink),
      faintTrail: basic(colors.ink, { transparent: true, opacity: 0.22 }),
    };
  }
  function startGraphics() {
    if (disposed) return;
    releaseGraphics();
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(30, 1.6, 0.1, 200);
      const controls = new OrbitControls(camera, renderer.domElement);
      controls.enableDamping = false;
      controls.enableZoom = false;
      controls.enablePan = false;
      controls.addEventListener("change", requestRender);
      const marks = new THREE.Group();
      scene.add(marks, new THREE.AmbientLight(0xffffff, 2.2));
      const light = new THREE.DirectionalLight(0xffffff, 2.6);
      light.position.set(-4, 10, 10);
      scene.add(light);
      graphics = { renderer, scene, camera, controls, marks, materials: materialSet(palette()), events: new AbortController(), pickable: [], dynamic: [], sphere: new THREE.SphereGeometry(0.13, 24, 16) };
      const events = { signal: graphics.events.signal };
      renderer.domElement.setAttribute("role", "img");
      renderer.domElement.setAttribute("aria-label", "Snapshots stacked by time, each plotting capability against upkeep burden. Exact scores are in the dimension list.");
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
      for (const button of presetButtons.values()) button.disabled = false;
      stageNote.textContent = stageStatus();
      setView(view);
      rebuild();
    } catch {
      if (!graphics) { renderer?.dispose(); renderer?.forceContextLoss(); }
      unavailable();
    }
  }
  function stageStatus() {
    const missing = dimensions.length - rows().length;
    const parts = [];
    if (timeline.length < 2) parts.push("One scan so far; earlier scans stack behind it.");
    else parts.push("Trails connect comparable source changes only. Evidence updates, new goal baselines and unknown or incompatible comparisons show separate snapshots.");
    if (missing) parts.push(`${missing} unknown ${missing === 1 ? "score is" : "scores are"} not positioned at zero.`);
    return parts.join(" ");
  }

  function renderDetail() {
    const row = selectedRow();
    detail.replaceChildren();
    if (!row) return;
    detail.append(element("h3", row.label, "dm-detail-title"));
    const values = element("dl", undefined, "dm-values");
    for (const [title, value] of [
      ["Capability", show(row.capability)], ["Upkeep burden", show(row.burden)],
      ["Minimum", score(row.capability_min) ? show(row.capability_min) : "Not set"],
      ["Ceiling", score(row.burden_max) ? show(row.burden_max) : "Not set"],
    ]) {
      const pair = element("div");
      pair.append(element("dt", title), element("dd", value));
      values.append(pair);
    }
    detail.append(values);
    const cg = capabilityGap(row), bg = burdenGap(row);
    if (cg !== null || bg !== null) {
      const parts = [cg === null ? "capability unknown" : cg ? `capability +${cg}` : null, bg === null ? "burden unknown" : bg ? `burden −${bg}` : null].filter(Boolean);
      const gap = element("p", parts.length ? `Gap: ${parts.join(" · ")}` : "Within both targets", "dm-gap-summary");
      gap.dataset.outside = String(parts.length > 0);
      detail.append(gap);
    }
    if (row.rationale) detail.append(element("p", row.rationale, "dm-rationale"));
    detail.append(element("p", `Confidence: capability ${row.capability_confidence || "unknown"} · burden ${row.burden_confidence || "unknown"}, ${basisLabel(row.burden_basis)}`, "dm-meta"));
    if (row.initiatives?.length) {
      const plans = element("div", undefined, "dm-plans");
      for (const item of row.initiatives) {
        const link = element("a", item.title, "dm-plan");
        link.href = `#initiative-${encodeURIComponent(item.id || "")}`;
        if (item.effect) link.title = item.effect;
        plans.append(link);
      }
      detail.append(plans);
    }
    if (row.recommendations?.length) {
      detail.append(element("h4", "Next steps"));
      detail.append(textList(row.recommendations.slice(0, 3)));
    }
    const evidence = element("details", undefined, "dm-evidence");
    evidence.append(element("summary", "Evidence"));
    if (row.evidence_references?.length) {
      evidence.append(textList(row.evidence_references.map((item) => `${item.path} · ${item.kind}`), "dm-paths"));
      if (row.evidence_reference_total > row.evidence_references.length) evidence.append(element("p", `+${row.evidence_reference_total - row.evidence_references.length} more in the full assessment`, "dm-note"));
    } else if (row.evidence_ids?.length) evidence.append(element("p", `${row.evidence_ids.length} cited records`, "dm-note"));
    if (row.burden_evidence) {
      const counts = row.burden_evidence;
      evidence.append(element("p", `Burden support: ${counts.source} source · ${counts.experience} experience · ${counts.matched_cost} matched cost · ${counts.partial_elapsed} partial timing`, "dm-note"));
    }
    if (row.confidence_notes?.length) evidence.append(textList(row.confidence_notes));
    if (row.burden_next_steps?.length) evidence.append(element("h4", "What would raise confidence"), textList(row.burden_next_steps));
    detail.append(evidence);
  }
  function textList(values, className) {
    const result = element("ul", undefined, className);
    for (const text of values) result.append(element("li", text));
    return result;
  }
  function axis(row, kind) {
    const isCapability = kind === "capability";
    const title = isCapability ? "Capability" : "Burden";
    const value = row[kind], target = row[isCapability ? "capability_min" : "burden_max"];
    const gap = isCapability ? capabilityGap(row) : burdenGap(row);
    const confidence = row[`${kind}_confidence`] || "unknown";
    const axisNode = element("span", undefined, `dm-axis dm-axis-${kind}`);
    const number = element("span", score(value) ? String(value) : "–", "dm-axis-number");
    number.setAttribute("aria-hidden", "true");
    axisNode.append(number, element("span", `${title} ${show(value)}`, "dm-axis-value dm-sr"));
    const vial = element("span", undefined, "dm-vial");
    vial.setAttribute("aria-hidden", "true");
    const inner = element("span", undefined, "dm-vial-scale");
    vial.append(inner);
    if (score(target)) {
      const zone = element("span", undefined, "dm-zone");
      zone.style.left = percent(along(kind, target));
      const tick = element("span", undefined, "dm-target");
      tick.dataset.value = String(target);
      tick.style.left = percent(along(kind, target));
      inner.append(zone, tick);
    }
    if (score(value)) {
      if (gap > 0) {
        const arrow = element("span", undefined, "dm-gap-arrow");
        arrow.style.left = percent(along(kind, value));
        arrow.style.width = percent(along(kind, target) - along(kind, value));
        inner.append(arrow);
      }
      const marker = element("span", undefined, "dm-current");
      marker.dataset.value = String(value);
      marker.dataset.confidence = confidence;
      if (!isCapability && row.burden_basis === "source_estimate") marker.dataset.estimate = "true";
      marker.style.left = percent(along(kind, value));
      inner.append(marker);
    } else {
      vial.classList.add("dm-vial-unknown");
      inner.append(element("span", "?", "dm-unknown"));
    }
    axisNode.append(vial);
    const gapText = !score(value) ? `${title} unknown` : gap === null ? "Target not set" : gap > 0 ? `${isCapability ? "Raise capability" : "Reduce burden"} by ${gap} ${gap === 1 ? "step" : "steps"}` : isCapability ? "Minimum met" : "Within ceiling";
    const gapLabel = element("span", gapText, "dm-axis-gap dm-sr");
    if (gap > 0) axisNode.dataset.outside = "true";
    axisNode.append(gapLabel, element("span", `Confidence: ${confidence}`, "dm-confidence dm-sr"));
    if (!isCapability) axisNode.append(element("span", basisLabel(row.burden_basis), "dm-basis dm-sr"));
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
    renderLevelMap();
    rebuild();
    if (notify && typeof onSelect === "function") onSelect(id);
  }
  function placeDetail() {
    // Rows expand in place; the map views keep the detail beside the picture.
    const selected = [...list.querySelectorAll("button[data-dimension]")].find((button) => button.dataset.dimension === selectedId);
    if (mode === "compare" && selected) selected.after(detail);
    else workspace.append(detail);
  }
  function pill(text, state) {
    const node = element("span", text, "dm-pill");
    if (state) node.dataset.state = state;
    return node;
  }
  function update(nextModel) {
    if (disposed) return;
    model = nextModel || {};
    dimensions = Array.isArray(model.dimensions) ? model.dimensions.slice(0, 8).filter((row) => row && typeof row.id === "string" && typeof row.label === "string") : [];
    timeline = Array.isArray(model.timeline) && model.timeline.length ? model.timeline.slice(-12) : [{ reviewed: true, date: null, scores: Object.fromEntries(dimensions.map((row) => [row.id, [row.capability, row.burden]])) }];
    const previous = selectedId;
    selector.replaceChildren();
    workspace.append(detail);
    list.replaceChildren();
    dimensions.forEach((row) => {
      const option = element("option", row.label);
      option.value = row.id;
      selector.append(option);
      const button = element("button", undefined, "dm-dimension");
      button.type = "button";
      button.dataset.dimension = row.id;
      const cited = row.evidence_ids?.length || 0;
      button.append(element("span", row.label, "dm-dimension-name"), axis(row, "capability"), axis(row, "burden"), element("span", cited ? `${cited} cited` : "None cited", "dm-cited"));
      list.append(button);
    });
    const anyTargets = dimensions.some((row) => score(row.capability_min) || score(row.burden_max));
    targetState.textContent = model.preview_targets ? "Unsaved target preview" : anyTargets ? "Saved targets" : "Targets not set";
    const known = rows().length, missing = dimensions.length - known;
    const pills = [];
    if (dimensions.some(hasGoal)) {
      pills.push(pill(`${dimensions.filter(level).length} of ${dimensions.length} level`, "level"));
      const below = dimensions.filter((row) => capabilityGap(row) > 0).length;
      const over = dimensions.filter((row) => burdenGap(row) > 0).length;
      if (below) pills.push(pill(`${below} below capability target`, "outside"));
      if (over) pills.push(pill(`${over} over burden ceiling`, "outside"));
    } else pills.push(pill(`${known} of ${dimensions.length} rated`), pill("Targets not set"));
    if (missing) pills.push(pill(`${missing} unknown`, "unknown"));
    summary.replaceChildren(...pills);
    status.textContent = model.preview_targets ? "Goal preview is unsaved." : "";
    status.hidden = !model.preview_targets;
    container.dataset.currentCount = String(known);
    container.dataset.goalCount = String(dimensions.filter(hasGoal).length);
    container.dataset.guideCount = String(dimensions.filter(needsImprovement).length);
    container.dataset.snapshotCount = String(timeline.length);
    if (graphics) stageNote.textContent = stageStatus();
    if (dimensions.length) select(dimensions.some((row) => row.id === previous) ? previous : dimensions[0].id);
    else {
      selectedId = null;
      delete container.dataset.selectedDimension;
      detail.replaceChildren();
      renderLevelMap();
      rebuild();
    }
  }
  const observer = new ResizeObserver(fit);
  observer.observe(stage);
  const changeTheme = () => {
    if (!graphics) return;
    for (const resource of Object.values(graphics.materials)) resource.dispose();
    graphics.materials = materialSet(palette());
    rebuild();
  };
  darkTheme.addEventListener("change", changeTheme);
  update(initialModel);
  setMode("compare");
  for (const [id, button] of presetButtons) button.setAttribute("aria-pressed", String(id === view));
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
      for (const name of ["renderer", "mode", "currentCount", "goalCount", "guideCount", "selectedDimension", "snapshotCount", "trailCount"]) delete container.dataset[name];
    },
  };
}
