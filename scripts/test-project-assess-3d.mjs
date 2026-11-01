#!/usr/bin/env node
/** Offline acceptance of comparison and optional Three.js reports; judgments are synthetic. */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(repo, "package.json"));
const { chromium, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const output = path.join(repo, ".artifacts");
await mkdir(output, { recursive: true });
const fixture = await mkdtemp(path.join(output, "pat-3d-fixture-"));
const python = String.raw`
import json, sys
from pathlib import Path
from project_assess.service import AssessmentService
from project_assess.web import create_server
from project_assess.rubric import DIMENSIONS

base=Path(sys.argv[1])
root=base/'synthetic-3d-<img src=x onerror=window.pwned=1>'
root.mkdir()
(root/'app.py').write_text("raise RuntimeError('Assessment must not execute this synthetic project')\n")
(root/'README.md').write_text('# Synthetic 3D acceptance fixture\nNot a real assessment.\n')
(root/'.env').write_text('PRIVATE_3D_SOURCE_MARKER=excluded-credential-material\n')
service=AssessmentService(base/'state', allowed_roots=[root])
snapshot=service.scan(root)
review=service.review_template(snapshot['id'])
review['coverage']['scope']='focused'
hostile="Synthetic UI judgment, not a real assessment. </script><script>window.pwned=1</script><img src=x onerror=window.pwned=1>"
scores={'security':(4,1),'testing':(2,4),'documentation':(3,2),
        'maintainability':(1,3),'delivery':(4,2),'operability':(None,4),
        'extensibility':(2,0),'performance':(1,3)}
for dimension,rating in review['ratings'].items():
    capability,burden=scores[dimension]
    rating.update(capability=capability,burden=burden,confidence='medium',
        burden_basis='source_estimate',burden_confidence='low',rationale=hostile,
        evidence_ids=[snapshot['evidence'][0]['id']],recommendations=[])
review['ratings']['documentation'].update(confidence='low',burden_confidence='medium')
context=review['project_context']
context['current'].update(milestone='personal_app',readiness='prototype',
    confidence='medium',rationale='Synthetic connected workflows, without runtime proof.',
    evidence_ids=[snapshot['evidence'][0]['id']])
context['intended'].update(milestone='personal_app',basis='user_stated',
    confidence='high',statement='Synthetic personal application destination. <img src=x onerror=window.contextPwned=1>',
    attribution='Synthetic owner statement for browser acceptance only.',
    evidence_ids=[],alternatives=[],limitations=['No real adoption or execution evidence.'])
context['alignment'].update(direction='rebalance',
    rationale='Reduce demonstrated change friction before expanding verification.',
    priorities=[
        {'dimension':'maintainability','direction':'simplify',
         'rationale':'Remove unnecessary change coupling first.','initiative_ids':[]},
        {'dimension':'testing','direction':'rebalance',
         'rationale':'Protect useful workflows with focused feedback next.','initiative_ids':[]}],
    deferred=['Commercial tenancy and external extension contracts.'])
saved=service.submit_review(snapshot['id'],review)
no_goals_export=service.export_report(snapshot['id'])
targets={dimension:{'capability_min':2,'burden_max':2} for dimension in DIMENSIONS}
targets['security']={'capability_min':2,'burden_max':3}
targets['testing']={'capability_min':4,'burden_max':2}
targets['documentation']={'capability_min':3,'burden_max':2}
targets['maintainability']={'capability_min':3,'burden_max':2}
targets['delivery']={'capability_min':3,'burden_max':2}
service.set_targets(snapshot['project_id'],targets,0)
export=service.export_report(snapshot['id'])
with create_server(service) as server:
    print(json.dumps({'origin':server.origin,'assessment_id':snapshot['id'],
        'review_id':saved['id'],'project_id':snapshot['project_id'],
        'root':str(root),'html':export['html'],'no_goals_html':no_goals_export['html'],
        'targets':targets}),flush=True)
    server.serve_forever()
`;
const child = spawn(path.join(repo, ".venv/bin/python"), ["-u", "-c", python, fixture], {
  cwd: repo, env: { ...process.env, PYTHONPATH: path.join(repo, "src") },
  stdio: ["ignore", "pipe", "pipe"],
});
let stderr = "";
child.stderr.on("data", (data) => { stderr += data; });
const lines = createInterface({ input: child.stdout });
const launch = Promise.race([
  once(lines, "line").then(([line]) => JSON.parse(line)),
  once(child, "exit").then(([code]) => { throw new Error(`3D fixture exited ${code}: ${stderr}`); }),
  new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error(`3D fixture startup timeout: ${stderr}`)), 15000); timer.unref(); }),
]);
const digest = (buffer) => createHash("sha256").update(buffer).digest("hex");
const settle = (page) => page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
async function accessibility(page, name) {
  const result = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(result.violations.map((v) => ({ id: v.id, targets: v.nodes.map((n) => n.target) })), [], name);
}
async function assertImages(page, selector) {
  await expect(page.locator(selector)).toHaveCount(9);
  await expect.poll(() => page.locator(selector).evaluateAll((images) => images.every((image) => image.complete && image.naturalWidth > 0))).toBe(true);
}
async function assertProjectContext(page) {
  const section = page.locator('section[aria-labelledby="project-context-heading"]');
  await expect(section.locator(".context-summary article").first()).toContainText("Personal application · Prototype");
  await expect(section.locator(".context-summary article").last()).toContainText("Personal application");
  await expect(section.locator(".context-summary article").last()).toContainText("User-stated");
  await expect(section).toContainText("Synthetic owner statement for browser acceptance only.");
  await expect(section).toContainText("Commercial tenancy and external extension contracts.");
  const priorities = section.locator(".context-priorities li");
  await expect(priorities).toHaveCount(2);
  await expect(priorities.nth(0)).toContainText("Maintainability · Reduce unnecessary burden");
  await expect(priorities.nth(1)).toContainText("Testing · Strengthen and simplify");
  await expect(section).toContainText("<img src=x onerror=window.contextPwned=1>");
  await expect(section.locator("img")).toHaveCount(0);
  assert.equal(await page.evaluate(() => window.contextPwned), undefined);
}
async function assertInspectorPlacement(page, dimension) {
  const map = page.locator("#dimension-map");
  await expect(map).toHaveAttribute("data-selected-dimension", dimension);
  await expect.poll(() => map.evaluate((node, id) => {
    const detail = node.querySelector(".dm-detail");
    const selected = node.querySelector(`.dm-dimension[data-dimension="${id}"]`);
    return matchMedia("(max-width: 940px)").matches && node.dataset.mode === "compare"
      ? selected.nextElementSibling === detail
      : detail.parentElement.classList.contains("dm-workspace");
  }, dimension), { message: "inspector must stay beside desktop exploration or immediately after the selected mobile row" }).toBe(true);
}
async function assertComparison(page, { guides = "4", fresh = true } = {}) {
  const map = page.locator("#dimension-map");
  await expect(map).toHaveAttribute("data-mode", "compare");
  await expect(map.getByRole("button", { name: "Compare dimensions", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(map.getByRole("button", { name: "Explore in 3D", exact: true })).toHaveAttribute("aria-pressed", "false");
  if (fresh) await expect(map.locator("canvas")).toHaveCount(0);
  await expect(map.locator(".dm-dimension")).toHaveCount(8);
  await expect(map).toHaveAttribute("data-current-count", "7");
  await expect(map).toHaveAttribute("data-goal-count", "8");
  await expect(map).toHaveAttribute("data-guide-count", guides);
  await expect(map.locator(".dm-summary")).toContainText(`${guides === "4" ? 3 : 2} of 7 capabilities below minimum`);
  await expect(map.locator(".dm-summary")).toContainText(`${guides} of 8 burdens above ceiling`);
  await expect(map.locator(".dm-summary")).toContainText("1 of 8 dimensions have unknown scores");
  await expect(map.locator(".dm-axis-capability .dm-current")).toHaveCount(7);
  await expect(map.locator(".dm-axis-burden .dm-current")).toHaveCount(8);
  await expect(map.locator(".dm-axis-capability .dm-target")).toHaveCount(8);
  await expect(map.locator(".dm-axis-burden .dm-target")).toHaveCount(8);
  const security = map.locator('.dm-dimension[data-dimension="security"]');
  await expect(security.locator(".dm-axis-capability")).toContainText("4 / 5");
  await expect(security.locator(".dm-axis-capability")).toContainText("medium");
  await expect(security.locator(".dm-axis-burden")).toContainText("low");
  await expect(security.locator(".dm-axis-capability .dm-axis-gap")).toHaveText("Minimum met");
  await expect(security.locator(".dm-axis-capability .dm-current")).toHaveAttribute("data-value", "4");
  assert.equal(await security.locator(".dm-axis-capability .dm-current").evaluate((mark) => mark.style.left), "80%");
  await expect(security.locator(".dm-axis-capability .dm-target")).toHaveAttribute("data-value", "2");
  assert.equal(await security.locator(".dm-axis-capability .dm-target").evaluate((mark) => mark.style.left), "40%");
  const documentation = map.locator('.dm-dimension[data-dimension="documentation"]');
  await expect(documentation.locator(".dm-axis-capability")).toContainText("low");
  await expect(documentation.locator(".dm-axis-burden")).toContainText("medium");
  const operability = map.locator('.dm-dimension[data-dimension="operability"]');
  await expect(operability.locator(".dm-axis-capability")).toContainText("Unknown");
  await expect(operability.locator(".dm-axis-capability .dm-current")).toHaveCount(0);
  await expect(operability.locator(".dm-axis-burden")).toContainText("4 / 5");
  await expect(operability.locator(".dm-axis-burden .dm-current")).toHaveCount(1);
  await expect(operability.locator(".dm-axis-burden .dm-axis-gap")).toHaveText("Reduce burden by 2 steps");
  await operability.click();
  await expect(map.locator(".dm-gap-summary")).toContainText("Goal distance: capability unknown, burden −2 rubric steps");
  await assertInspectorPlacement(page, "operability");
  const extensibility = map.locator('.dm-dimension[data-dimension="extensibility"]');
  await expect(extensibility.locator(".dm-axis-burden")).toContainText("0 / 5");
  await expect(extensibility.locator(".dm-axis-burden .dm-current")).toHaveCount(1);
  await expect(extensibility.locator(".dm-axis-burden .dm-current")).toHaveAttribute("data-value", "0");
  assert.equal(await extensibility.locator(".dm-axis-burden .dm-current").evaluate((mark) => mark.style.left), "0%");
  await extensibility.focus();
  await page.keyboard.press("Enter");
  await expect(map).toHaveAttribute("data-selected-dimension", "extensibility");
  await assertInspectorPlacement(page, "extensibility");
  await expect(map.locator(".dm-rationale")).toContainText("</script><script>window.pwned=1</script>");
  assert.equal(await page.evaluate(() => window.pwned), undefined);
}
async function explore3d(page) {
  const map = page.locator("#dimension-map");
  await map.getByRole("button", { name: "Explore in 3D", exact: true }).click();
  await expect(map).toHaveAttribute("data-mode", "3d");
  await expect(map.getByRole("button", { name: "Explore in 3D", exact: true })).toHaveAttribute("aria-pressed", "true");
}
async function assertMap(page) {
  const map = page.locator("#dimension-map");
  await expect(map).toHaveAttribute("data-renderer", "webgl");
  await expect(map).toHaveAttribute("data-current-count", "7");
  await expect(map).toHaveAttribute("data-goal-count", "8");
  await expect(map).toHaveAttribute("data-guide-count", "4");
  await expect(map.locator("canvas")).toHaveCount(1);
  await expect(map.locator(".dm-dimension")).toHaveCount(8);
  const renderer = await map.locator("canvas").evaluate((canvas) => {
    const gl = canvas.getContext("webgl2");
    return gl && gl.getParameter(gl.VERSION);
  });
  assert.match(renderer, /WebGL 2/, "graph must use a real WebGL renderer");
  await map.getByRole("combobox", { name: "Inspect dimension", exact: true }).selectOption("security");
  await expect(map.locator(".dm-detail")).toContainText("Within both targets");
  await expect(map.locator(".dm-detail")).toContainText("4 / 5");
  await expect(map.locator(".dm-detail")).toContainText("1 / 5");
  await map.getByRole("combobox", { name: "Inspect dimension", exact: true }).selectOption("operability");
  await expect(map.locator(".dm-detail")).toContainText("Unknown");
  await expect(map.locator(".dm-detail")).toContainText("4 / 5");
  await expect(map.locator(".dm-gap-summary")).toContainText("Goal distance: capability unknown, burden −2 rubric steps");
  await expect(map.locator(".dm-status")).toContainText("not positioned at zero");
  await map.getByRole("combobox", { name: "Inspect dimension", exact: true }).selectOption("security");
  await map.getByRole("button", { name: "Compare dimensions", exact: true }).click();
  await map.locator(".dm-dimension[data-dimension=testing]").focus();
  await expect(map.locator(".dm-dimension[data-dimension=testing]")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(map).toHaveAttribute("data-selected-dimension", "testing");
  await expect(map.locator(".dm-detail")).toContainText("capability +2, burden −2");
  await expect(map.locator(".dm-rationale")).toContainText("</script><script>window.pwned=1</script>");
  assert.equal(await page.evaluate(() => window.pwned), undefined);
  await explore3d(page);
  await map.getByRole("button", { name: "3D overview", exact: true }).click();
  await settle(page);
  const canvas = map.locator("canvas");
  const original = digest(await canvas.screenshot());
  await map.getByRole("button", { name: "Capability view", exact: true }).click();
  await settle(page);
  const front = digest(await canvas.screenshot());
  assert.notEqual(front, original, "capability preset must change actual rendered geometry");
  await map.getByRole("button", { name: "Burden view", exact: true }).click();
  await settle(page);
  assert.notEqual(digest(await canvas.screenshot()), front, "burden preset must change actual rendered geometry");
  await map.getByRole("button", { name: "Reset view", exact: true }).click();
  await settle(page);
  const beforeDrag = digest(await canvas.screenshot());
  const box = await canvas.boundingBox();
  await page.mouse.move(box.x + box.width * 0.6, box.y + box.height * 0.5);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * 0.3, box.y + box.height * 0.65, { steps: 8 });
  await page.mouse.up();
  await settle(page);
  const afterDrag = digest(await canvas.screenshot());
  assert.notEqual(afterDrag, beforeDrag, "orbit drag must change rendered geometry");
  const selectedProjection = () => map.locator(".dm-label-selected").evaluate((item) => ({
    left: parseFloat(item.style.left), top: parseFloat(item.style.top),
  }));
  const exploredProjection = await selectedProjection();
  await map.getByRole("button", { name: "Compare dimensions", exact: true }).click();
  await expect(map).toHaveAttribute("data-selected-dimension", "testing");
  await assertInspectorPlacement(page, "testing");
  await explore3d(page);
  await expect(map).toHaveAttribute("data-selected-dimension", "testing");
  await assertInspectorPlacement(page, "testing");
  await settle(page);
  const restoredProjection = await selectedProjection();
  for (const axis of ["left", "top"]) assert(Math.abs(restoredProjection[axis] - exploredProjection[axis]) < 0.5,
    "switching comparison and 3D must preserve the explored camera projection");
  await expect(map.getByRole("button", { name: "3D overview", exact: true })).toHaveAttribute("aria-pressed", "true");
}

let browser;
try {
  const data = await launch;
  browser = await chromium.launch({ headless: true, args: ["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"] });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  await page.goto(data.origin);
  await assertProjectContext(page);
  await assertImages(page, "#badges img");
  await assertComparison(page);
  await accessibility(page, "live comparison desktop accessibility");
  await page.locator("#dimension-map").locator("..").screenshot({ path: path.join(output, "pat-compare-desktop.png") });
  for (const colorScheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    await page.setViewportSize({ width: 320, height: 780 });
    await assertInspectorPlacement(page, "extensibility");
    await expect.poll(() => overflow(page)).toBe(false);
    await accessibility(page, `live comparison mobile ${colorScheme} accessibility`);
    await page.locator("#dimension-map").locator("..").screenshot({ path: path.join(output, `pat-compare-mobile-${colorScheme}.png`) });
  }
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 1280, height: 1000 });
  await explore3d(page);
  await assertMap(page);
  const badgeDownload = page.waitForEvent("download");
  await page.locator("#badges a").first().click();
  const badge = await badgeDownload;
  const badgePath = path.join(fixture, "downloaded-summary.svg");
  await badge.saveAs(badgePath);
  const svg = await readFile(badgePath, "utf8");
  assert(svg.includes(data.assessment_id) && svg.includes(data.review_id));
  assert(!svg.includes(data.root) && !svg.includes("PRIVATE_3D_SOURCE_MARKER"));
  const reportUrl = `${data.origin}/api/report?assessment_id=${data.assessment_id}`;
  const reportBefore = await (await page.request.get(reportUrl)).json();
  const historyBefore = await (await page.request.get(`${data.origin}/api/history?project_id=${data.project_id}`)).json();
  await page.locator("#testing-capability_min").fill("2");
  await page.locator("#testing-burden_max").fill("4");
  await expect(page.locator("#dimension-map .dm-status")).toContainText("preview is unsaved");
  await expect(page.locator("#dimension-map")).toHaveAttribute("data-guide-count", "3");
  const testingPreview = page.locator('#dimension-map .dm-dimension[data-dimension="testing"]');
  await expect(testingPreview.locator(".dm-axis-capability .dm-target")).toHaveAttribute("data-value", "2");
  await expect(testingPreview.locator(".dm-axis-burden .dm-target")).toHaveAttribute("data-value", "4");
  await expect(testingPreview.locator(".dm-axis-capability .dm-axis-gap")).toHaveText("Minimum met");
  await expect(testingPreview.locator(".dm-axis-burden .dm-axis-gap")).toHaveText("Within ceiling");
  const unsavedReport = await (await page.request.get(reportUrl)).json();
  assert.deepEqual(unsavedReport.review.ratings, reportBefore.review.ratings);
  assert.deepEqual(unsavedReport.badges, reportBefore.badges);
  assert.deepEqual(unsavedReport.goals, reportBefore.goals, "preview must not persist target changes");
  assert.deepEqual(await (await page.request.get(`${data.origin}/api/history?project_id=${data.project_id}`)).json(), historyBefore);
  await page.locator("#save").click();
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 2");
  const savedReport = await (await page.request.get(reportUrl)).json();
  assert.equal(savedReport.goals.revision, 2);
  assert.deepEqual(savedReport.assessment, reportBefore.assessment);
  assert.deepEqual(savedReport.review.ratings, reportBefore.review.ratings);
  assert.deepEqual(savedReport.review.project_context, reportBefore.review.project_context);
  assert.deepEqual(savedReport.badges, reportBefore.badges);
  await page.reload();
  await assertProjectContext(page);
  await assertComparison(page, { guides: "3" });
  await explore3d(page);
  await expect(page.locator("#dimension-map")).toHaveAttribute("data-renderer", "webgl");
  await settle(page);
  await page.locator("#badges").screenshot({ path: path.join(output, "pat-3d-badges.png") });
  await page.locator("#dimension-map").locator("..").screenshot({ path: path.join(output, "pat-3d-desktop.png") });
  const htmlDownload = page.waitForEvent("download");
  await page.locator("#download-report").click();
  const downloaded = await htmlDownload;
  const downloadedPath = path.join(fixture, "downloaded-report.html");
  await downloaded.saveAs(downloadedPath);
  assert((await readFile(downloadedPath, "utf8")).includes(data.assessment_id));
  await accessibility(page, "live 3D desktop accessibility");
  for (const colorScheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    await page.setViewportSize({ width: 320, height: 780 });
    await expect.poll(() => overflow(page)).toBe(false);
    await accessibility(page, `live 3D mobile ${colorScheme} accessibility`);
  }
  await page.locator("#dimension-map").locator("..").screenshot({ path: path.join(output, "pat-3d-mobile.png") });
  assert.deepEqual(errors, []);
  await context.close();

  const offline = await browser.newContext({ viewport: { width: 1280, height: 1000 }, colorScheme: "light" });
  const external = [];
  await offline.route(/^https?:\/\//, (route) => { external.push(route.request().url()); return route.abort(); });
  const standalone = await offline.newPage();
  standalone.on("pageerror", (error) => errors.push(String(error)));
  await standalone.goto(pathToFileURL(data.html).href);
  await assertProjectContext(standalone);
  await assertImages(standalone, ".badges img");
  await assertComparison(standalone);
  await accessibility(standalone, "offline comparison report accessibility");
  await standalone.locator("#dimension-map").locator("..").screenshot({ path: path.join(output, "pat-compare-offline.png") });
  await explore3d(standalone);
  await assertMap(standalone);
  await expect(standalone.locator(".dm-dimension")).toHaveCount(8);
  await expect(standalone.locator("body")).toContainText("Synthetic UI judgment");
  assert.equal(await standalone.evaluate(() => window.pwned), undefined);
  assert.deepEqual(external, [], "offline export must not request remote scripts, fonts or data");
  await accessibility(standalone, "offline 3D report accessibility");
  await standalone.locator("#dimension-map").locator("..").screenshot({ path: path.join(output, "pat-3d-offline.png") });
  await standalone.setViewportSize({ width: 320, height: 780 });
  await standalone.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await expect.poll(() => overflow(standalone)).toBe(false);
  await accessibility(standalone, "offline 3D mobile accessibility");
  await standalone.goto(pathToFileURL(data.no_goals_html).href);
  const noGoalsMap = standalone.locator("#dimension-map");
  await expect(noGoalsMap).toHaveAttribute("data-mode", "compare");
  await expect(noGoalsMap).toHaveAttribute("data-goal-count", "0");
  await expect(noGoalsMap.locator(".dm-target")).toHaveCount(0);
  await expect(noGoalsMap.locator(".dm-axis-capability .dm-axis-gap").first()).toHaveText("Target not set");
  await expect(noGoalsMap.locator(".dm-axis-burden .dm-axis-gap").first()).toHaveText("Target not set");
  await expect(noGoalsMap.locator(".dm-axis-capability .dm-current")).toHaveCount(7);
  await expect(noGoalsMap.locator(".dm-axis-burden .dm-current")).toHaveCount(8);
  await expect.poll(() => overflow(standalone)).toBe(false);
  await accessibility(standalone, "offline no-goals comparison accessibility");
  await offline.close();

  const fallback = await browser.newContext({ viewport: { width: 320, height: 780 } });
  await fallback.addInitScript(() => {
    const original = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(type, ...args) {
      return String(type).includes("webgl") ? null : original.call(this, type, ...args);
    };
  });
  const noWebgl = await fallback.newPage();
  await noWebgl.goto(pathToFileURL(downloadedPath).href);
  await assertComparison(noWebgl, { guides: "3" });
  await accessibility(noWebgl, "offline comparison without WebGL accessibility");
  await explore3d(noWebgl);
  await expect(noWebgl.locator("#dimension-map")).toHaveAttribute("data-renderer", "unavailable");
  await expect(noWebgl.locator("#dimension-map .dm-dimension")).toHaveCount(8);
  await expect(noWebgl.locator("#dimension-map canvas")).toHaveCount(0);
  await noWebgl.getByRole("combobox", { name: "Inspect dimension", exact: true }).selectOption("operability");
  await expect(noWebgl.locator(".dm-detail")).toContainText("Unknown");
  await expect(noWebgl.locator(".dm-detail")).toContainText("4 / 5");
  await expect(noWebgl.locator("#dimension-map")).toHaveAttribute("data-current-count", "7");
  await expect(noWebgl.locator("#dimension-map")).toHaveAttribute("data-guide-count", "3");
  await assertImages(noWebgl, ".badges img");
  await expect.poll(() => overflow(noWebgl)).toBe(false);
  await accessibility(noWebgl, "offline no-WebGL fallback accessibility");
  await noWebgl.locator("#dimension-map").locator("..").screenshot({ path: path.join(output, "pat-3d-fallback.png") });
  await noWebgl.goto(data.origin);
  await assertComparison(noWebgl, { guides: "3" });
  await explore3d(noWebgl);
  await expect(noWebgl.locator("#dimension-map")).toHaveAttribute("data-renderer", "unavailable");
  await expect(noWebgl.locator("#dimension-map .dm-dimension")).toHaveCount(8);
  await expect(noWebgl.locator("#dimension-map")).toHaveAttribute("data-current-count", "7");
  await assertImages(noWebgl, "#badges img");
  await expect(noWebgl.locator("#ratings .rating")).toHaveCount(8);
  await accessibility(noWebgl, "live no-WebGL fallback accessibility");
  await fallback.close();
  assert.deepEqual(errors, []);
  console.log("PAT comparison/3D acceptance passed: aligned independent scores/goals/confidence, true zero and partial unknown axes, no-goals state, lazy WebGL, presets/orbit/keyboard, nine bound badges, goal preview/save separation, hostile content, offline export, no-WebGL comparison, mobile themes/reduced motion and accessibility.");
} finally {
  await browser?.close();
  lines.close();
  const exited = child.exitCode !== null || child.signalCode !== null ? Promise.resolve() : once(child, "exit");
  child.kill("SIGTERM");
  await exited.catch(() => {});
  await rm(fixture, { recursive: true, force: true });
}
