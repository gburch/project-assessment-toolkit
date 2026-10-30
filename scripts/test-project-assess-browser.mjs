#!/usr/bin/env node
/** Offline browser acceptance against the real service and loopback server. */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(repo, "package.json"));
const { chromium, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;
const output = path.join(repo, ".artifacts");
await mkdir(output, { recursive: true });
const fixture = await mkdtemp(path.join(output, "project-assess-browser-"));
const python = String.raw`
import json, sys
from pathlib import Path
from threading import Thread
from project_assess.service import AssessmentService
from project_assess.web import create_server

base = Path(sys.argv[1])
root = base / 'fixture-<img src=x onerror=window.pwned=1>'
root.mkdir()
(root / 'app.py').write_text("""def add(a, b):
    return a + b
""")
(root / 'architecture.py').write_text("""from typing import Protocol
from app import add

class Calculator(Protocol):
    def add(self, a: int, b: int) -> int: ...

def forward_add(a, b):
    return add(a, b)
""")
(root / 'README.md').write_text("""# Fixture
<img src=x onerror=window.pwned=1>
""")
(root / 'scroll-evidence.md').write_text('# Keyboard scrolling fixture\n' +
    '\n'.join(f'Evidence line {index}' for index in range(80)))

def synthetic_review(service, snapshot, burden, unknown_operability=False):
    review = service.review_template(snapshot['id'])
    for dimension, rating in review['ratings'].items():
        rating.update(capability=2, burden=burden, confidence='medium',
            burden_basis='source_estimate', burden_confidence='medium',
            rationale='Synthetic browser fixture judgment; not a real project assessment.',
            evidence_ids=[snapshot['evidence'][0]['id']], recommendations=[])
        if dimension == 'operability' and unknown_operability:
            rating.update(capability=None, burden=None)
    return review

class FixtureService(AssessmentService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scans = {}

    def scan(self, project_root, reports=None):
        key = str(Path(project_root).resolve())
        count = self.scans.get(key, 0)
        snapshot = super().scan(project_root, reports)
        review = synthetic_review(self, snapshot, 4 if count == 0 else 1,
            unknown_operability=key == str(root) and count == 0)
        self.submit_review(snapshot['id'], review)
        self.scans[key] = count + 1
        return snapshot

service = FixtureService(base / 'state')
service.scan(root)
second_root = base / 'second-project'
second_root.mkdir()
(second_root / 'app.py').write_text('value = 1')
second = service.scan(second_root)
service.set_targets(second['project_id'], None, 0, profile='internal-service')
def commands():
    for line in sys.stdin:
        command = line.strip()
        if command not in {'review-complete', 'rereview'}:
            continue
        project = next(project for project in service.list_projects() if project['root'] == str(root))
        assessment_id = project['latest_assessment_id']
        snapshot = service.get_report(assessment_id)['assessment']
        review = synthetic_review(service, snapshot, 4 if service.scans[str(root)] == 1 else 1)
        if command == 'rereview':
            review['ratings']['testing']['capability'] = 1
            review['ratings']['security'].update(burden_basis='observed', burden_confidence='high')
        service.submit_review(assessment_id, review)
        print(json.dumps({'command': command}), flush=True)
Thread(target=commands, daemon=True).start()
with create_server(service) as server:
    print(json.dumps({'origin': server.origin, 'root': str(root)}), flush=True)
    server.serve_forever()
`;
const child = spawn(path.join(repo, ".venv/bin/python"), ["-u", "-c", python, fixture], {
  cwd: repo, env: { ...process.env, PYTHONPATH: path.join(repo, "src") }, stdio: ["pipe", "pipe", "pipe"]
});
let stderr = "";
child.stderr.on("data", (data) => { stderr += data; });
const lines = createInterface({ input: child.stdout });
const launch = Promise.race([
  once(lines, "line").then(([line]) => JSON.parse(line)),
  once(child, "exit").then(([code]) => { throw new Error(`Fixture exited ${code}: ${stderr}`); }),
  new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error(`Fixture startup timed out: ${stderr}`)), 15000); timer.unref(); })
]);
async function fixtureCommand(command) {
  const reply = once(lines, "line", { signal: AbortSignal.timeout(15000) });
  child.stdin.write(`${command}\n`);
  const [line] = await reply;
  assert.equal(JSON.parse(line).command, command);
}
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
async function holdResponse(page, pattern, errorResponse = false) {
  const entered = deferred();
  const release = deferred();
  const finished = deferred();
  let used = false;
  const handler = async (route) => {
    if (used) return route.fallback();
    used = true;
    const response = errorResponse ? null : await route.fetch();
    entered.resolve(response);
    await release.promise;
    const completed = page.waitForEvent("requestfinished", (request) => request === route.request());
    await route.fulfill(errorResponse ? {
      status: 409, contentType: "application/json", body: JSON.stringify({ error: "Synthetic delayed conflict" })
    } : { response });
    await completed;
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(resolve)));
    finished.resolve();
  };
  await page.route(pattern, handler);
  return {
    entered: entered.promise,
    async release() {
      release.resolve();
      await finished.promise;
      await page.unroute(pattern, handler);
    }
  };
}
async function checkProjectSwitches(page, origin) {
  const projects = await (await page.request.get(`${origin}/api/projects`)).json();
  assert.equal(projects.length, 2);
  const first = projects.find((project) => project.name.startsWith("fixture-"));
  const second = projects.find((project) => project.name === "second-project");
  const beforeSecond = (await (await page.request.get(`${origin}/api/report?assessment_id=${second.latest_assessment_id}`)).json()).goals;
  const writes = [];
  const recordWrite = (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname === "/api/targets") writes.push(request.postDataJSON());
  };
  page.on("request", recordWrite);

  // A new selection must not submit the previous project's still-visible draft.
  await page.locator("#testing-capability_min").fill("3");
  const loadingSecond = await holdResponse(page, `**/api/report?assessment_id=${second.latest_assessment_id}`);
  await page.selectOption("#project", second.id);
  await loadingSecond.entered;
  await expect(page.locator("#profile")).toBeDisabled();
  await expect(page.locator("#testing-capability_min")).toBeDisabled();
  await expect(page.locator("#save")).toBeDisabled();
  await page.evaluate(() => document.getElementById("goal-form").requestSubmit());
  assert.equal(writes.length, 0);
  await page.selectOption("#project", first.id);
  await expect(page.locator("#source")).toContainText(first.root);
  await expect(page.locator("#profile")).toBeEnabled();
  await loadingSecond.release();
  await expect(page.locator("#source")).toContainText(first.root);

  // A saved A response arriving while B is selected must not repaint B's goals.
  await page.locator("#testing-capability_min").fill("3");
  const savingFirst = await holdResponse(page, "**/api/targets");
  await page.click("#save");
  await savingFirst.entered;
  await expect(page.locator("#profile")).toBeDisabled();
  await page.selectOption("#project", second.id);
  await expect(page.locator("#source")).toContainText(second.root);
  await expect(page.locator("#profile")).toBeEnabled();
  await savingFirst.release();
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 1");
  await expect(page.locator("#testing-capability_min")).toHaveValue("2");

  // Returning to A creates a fresh context even though its project ID is the same.
  await page.selectOption("#project", first.id);
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 2");
  await page.locator("#testing-capability_min").fill("4");
  const switchingBack = await holdResponse(page, "**/api/targets");
  await page.click("#save");
  await switchingBack.entered;
  await page.selectOption("#project", second.id);
  await expect(page.locator("#source")).toContainText(second.root);
  await page.selectOption("#project", first.id);
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 3");
  await page.locator("#testing-capability_min").fill("5");
  await switchingBack.release();
  await expect(page.locator("#testing-capability_min")).toHaveValue("5");
  await expect(page.locator("#goal-state")).toHaveText("Unsaved targets");

  // Late errors from A must not appear in B's successfully loaded report.
  const failedFirst = await holdResponse(page, "**/api/targets", true);
  await page.click("#save");
  await failedFirst.entered;
  await page.selectOption("#project", second.id);
  await expect(page.locator("#source")).toContainText(second.root);
  await failedFirst.release();
  await expect(page.locator("#error")).toBeHidden();
  await expect(page.locator("#testing-capability_min")).toHaveValue("2");
  assert.equal(writes.length, 3);
  const afterSecond = (await (await page.request.get(`${origin}/api/report?assessment_id=${second.latest_assessment_id}`)).json()).goals;
  assert.deepEqual(afterSecond, beforeSecond, "switching projects must never write another project's goals");
  await page.selectOption("#project", first.id);
  await expect(page.locator("#source")).toContainText(first.root);
  await expect(page.locator("#profile")).toBeEnabled();
  await page.locator("#testing-capability_min").fill("5");
  const currentFailure = await holdResponse(page, "**/api/targets", true);
  await page.click("#save");
  await currentFailure.entered;
  await currentFailure.release();
  await expect(page.locator("#error")).toContainText("Synthetic delayed conflict");
  await expect(page.locator("#testing-capability_min")).toHaveValue("5");
  await expect(page.locator("#save")).toBeEnabled();
  await page.click("#save");
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 4");
  await expect(page.locator("#error")).toBeHidden();
  assert.equal(writes.length, 5);
  assert(writes.every((write) => write.project_id === first.id), "all target writes must remain bound to their submitted project");
  page.off("request", recordWrite);

  // Scanning A while viewing B must refresh A's cached snapshot without repainting B.
  const priorAssessment = (await (await page.request.get(`${origin}/api/projects`)).json())
    .find((project) => project.id === first.id).latest_assessment_id;
  await writeFile(path.join(first.root, "after_scan.py"), "value = 2\n");
  const scanningFirst = await holdResponse(page, "**/api/scan");
  await page.click("#rescan");
  const scanSnapshot = await (await scanningFirst.entered).json();
  assert.notEqual(scanSnapshot.id, priorAssessment);
  await page.selectOption("#project", second.id);
  await expect(page.locator("#source")).toContainText(second.root);
  await expect(page.locator("#profile")).toBeEnabled();
  await scanningFirst.release();
  await expect(page.locator("#source")).toContainText(second.root);
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 1");
  await page.selectOption("#project", first.id);
  await expect(page.locator("#status")).toContainText(scanSnapshot.id);
  await expect(page.locator("#evidence")).toContainText("after_scan.py");
  await expect(page.locator("#profile")).toBeEnabled();
}
function ratingCard(page, title) {
  return page.locator("#ratings .rating").filter({ has: page.getByRole("heading", { name: title, exact: true }) });
}
async function checkLegacyTargets(page, origin, frameworkProfile) {
  const projects = await (await page.request.get(`${origin}/api/projects`)).json();
  const project = projects.find((item) => item.name.startsWith("fixture-"));
  const reportUrl = `${origin}/api/report?assessment_id=${project.latest_assessment_id}`;
  const original = await (await page.request.get(reportUrl)).json();
  const legacy = structuredClone(original);
  delete legacy.goals.targets.extensibility;
  delete legacy.review.ratings.extensibility;
  legacy.assessment.rubric_version = "3";
  legacy.review.rubric_version = "3";
  legacy.progress.missing_targets = ["extensibility"];
  legacy.progress.dimensions.extensibility = { capability_gap: null, burden_gap: null };
  const handler = (route) => route.fulfill({ json: legacy });
  const writes = [];
  const recordWrite = (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname === "/api/targets") writes.push(request.postDataJSON());
  };
  page.on("request", recordWrite);
  await page.route(reportUrl, handler);
  try {
    await page.reload();
    await expect(page.locator("#goal-state")).toHaveText("Saved goals need targets for Extensibility");
    await expect(ratingCard(page, "Extensibility")).toContainText("Unknown");
    await expect(page.locator("#extensibility-capability_min")).toHaveAttribute("aria-valuetext", "Not set");
    await expect(page.locator("#extensibility-burden_max")).toHaveAttribute("aria-valuetext", "Not set");
    await expect(page.locator("#save")).toBeDisabled();
    await page.locator("#testing-capability_min").fill("3");
    await expect(page.locator("#goal-state")).toHaveText("Saved goals need targets for Extensibility");
    await expect(page.locator("#save")).toBeDisabled();
    await page.evaluate(() => document.getElementById("goal-form").requestSubmit());
    assert.equal(writes.length, 0, "legacy targets must not generate automatic goal writes");
    await expect(page.locator("#extensibility-capability_min")).toHaveAttribute("type", "number");
    await expect(page.locator("#extensibility-capability_min")).toHaveValue("");
    await expect(page.locator("#extensibility-burden_max")).toHaveValue("");
    await page.locator("#extensibility-capability_min").focus();
    await page.keyboard.press("0");
    await expect(page.locator("#extensibility-capability_min")).toHaveValue("0");
    await expect(page.locator("#save")).toBeDisabled();
    await page.locator("#extensibility-burden_max").focus();
    await page.keyboard.press("5");
    await expect(page.locator("#extensibility-burden_max")).toHaveValue("5");
    await expect(page.locator("#goal-state")).toHaveText("Unsaved targets");
    await expect(page.locator("#save")).toBeEnabled();
    await page.locator("#extensibility-burden_max").fill("");
    await expect(page.locator("#extensibility-burden_max")).toHaveAttribute("aria-valuetext", "Not set");
    await expect(page.locator("#save")).toBeDisabled();
    await page.locator("#extensibility-burden_max").fill("6");
    await expect(page.locator("#save")).toBeDisabled();
    await page.locator("#extensibility-burden_max").fill("5");
    await page.locator("#extensibility-capability_min").fill("-1");
    await expect(page.locator("#save")).toBeDisabled();
    await page.locator("#extensibility-capability_min").fill("2.5");
    await expect(page.locator("#save")).toBeDisabled();
    await page.locator("#extensibility-capability_min").fill("0");
    await expect(page.locator("#save")).toBeEnabled();
    await page.selectOption("#profile", frameworkProfile);
    await expect(page.locator("#extensibility-capability_min")).toHaveAttribute("type", "range");
    await expect(page.locator("#extensibility-burden_max")).toHaveAttribute("type", "range");
    await expect(page.locator("#extensibility-capability_min")).toHaveValue("4");
    await expect(page.locator("#extensibility-burden_max")).toHaveValue("2");
    await expect(page.locator("#maintainability-burden_max")).toHaveValue("2");
    await expect(page.locator("#save")).toBeEnabled();
    const after = await (await page.request.get(reportUrl)).json();
    assert.deepEqual(after.goals, original.goals, "legacy rendering and profile previews must not change goals or their baseline");
    assert.equal(writes.length, 0);
  } finally {
    await page.unroute(reportUrl, handler);
    page.off("request", recordWrite);
    await page.reload();
    await expect(page.locator("#goal-state")).toContainText(`Saved goal version ${original.goals.revision}`);
  }
}
let browser;
try {
  const { origin, root } = await launch;
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const rubric = await (await page.request.get(`${origin}/api/rubric`)).json();
  const dimensions = Object.keys(rubric.dimensions);
  const frameworkProfile = Object.entries(rubric.profiles).find(([, profile]) =>
    profile.targets.extensibility.capability_min === 4 && profile.targets.extensibility.burden_max === 2
  )?.[0];
  assert(frameworkProfile, "rubric must offer the framework profile");
  const improvementSteps = Object.values(rubric.profiles["local-experiment"].targets)
    .reduce((sum, target) => sum + Math.max(4 - target.burden_max, 0) - Math.max(1 - target.burden_max, 0), 0);
  await page.goto(origin);
  await expect(page.locator("#ratings .rating")).toHaveCount(dimensions.length);
  await expect(page.locator("#goal-state")).toContainText("No goals saved");
  await expect(page.locator("#save")).toBeDisabled();
  await expect(page.locator("#ratings")).toContainText("Unknown");
  await expect(ratingCard(page, "Security")).toContainText("Capability · medium confidence");
  await expect(ratingCard(page, "Security")).toContainText("Estimated from source · medium confidence");
  await expect(ratingCard(page, "Security")).toContainText("4 / 5");
  await expect(ratingCard(page, "Operability")).toContainText("Unknown");
  await expect(ratingCard(page, "Operability")).not.toContainText("Estimated from source");
  await expect(page.locator("#architecture-hints")).not.toHaveAttribute("open", "");
  await page.locator("#architecture-hints summary").click();
  await expect(page.locator("#architecture-hints")).toContainText("Forwarding functions: 1");
  await expect(page.locator("#architecture-hints")).toContainText("Abstract or protocol classes: 1");
  await expect(page.locator("#architecture-hints")).toContainText("never an automatic burden score");
  await expect(page.locator("#architecture-hints")).toContainText("1 candidate file");
  await expect(page.locator("#architecture-hints")).toContainText("architecture.py: 1 forwarding functions; 1 abstract or protocol classes");
  await expect(ratingCard(page, "Maintainability")).toContainText("4 / 5");

  assert.equal(await page.evaluate(() => window.pwned), undefined);
  assert.equal(await page.locator("main img").count(), 0, "hostile names must remain text");

  await fixtureCommand("review-complete");
  await page.reload();
  await expect(page.locator("#ratings")).not.toContainText("Unknown");
  await page.selectOption("#profile", frameworkProfile);
  await expect(page.locator("#extensibility-capability_min")).toHaveValue("4");
  await expect(page.locator("#extensibility-burden_max")).toHaveValue("2");
  await expect(page.locator("#maintainability-burden_max")).toHaveValue("2");
  await page.locator("#extensibility-capability_min").fill("3");
  await expect(page.locator("#profile")).toHaveValue("");
  const previewProjects = await (await page.request.get(`${origin}/api/projects`)).json();
  const previewProject = previewProjects.find((item) => item.name.startsWith("fixture-"));
  const previewReport = await (await page.request.get(`${origin}/api/report?assessment_id=${previewProject.latest_assessment_id}`)).json();
  assert.equal(previewReport.goals, null, "framework profile selection and lowering its target must not autosave");
  await page.selectOption("#profile", "local-experiment");
  await expect(page.locator("#goal-state")).toContainText("Unsaved");
  await expect(page.locator("#testing-capability_min")).toHaveValue("1");
  // Keyboard editing must modify only the target, not the observed score.
  await page.locator("#testing-capability_min").focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.locator("#testing-capability_min")).toHaveValue("2");
  await expect(ratingCard(page, "Testing")).toContainText("4 / 5");
  await page.click("#save");
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 1");
  await expect(page.locator("#progress-summary")).toContainText("New goal baseline");
  await page.reload();
  await expect(page.locator("#testing-capability_min")).toHaveValue("2");
  await expect(page.locator("#goal-state")).toContainText("Saved goal version 1");
  await expect(page.locator("#progress .progress-row").nth(1)).toContainText("Burden gap: 3 steps");

  await writeFile(path.join(root, "app.py"), "def add(a, b):\n    return a + b\n\ndef subtract(a, b):\n    return a - b\n");
  await page.click("#rescan");
  await expect(page.locator("#progress-summary")).toContainText("Source changed");
  await expect(page.locator("#progress-summary")).toContainText("Movement includes estimates or low-confidence ratings");
  await expect(page.locator("#progress .progress-row").nth(1)).toContainText("Burden gap: 0 steps");
  await expect(page.locator("#history")).toContainText("Goal change · new baseline");
  await expect(ratingCard(page, "Testing")).toContainText("1 / 5");
  await expect(page.locator("#progress-summary")).toContainText(`Engineering progress: +${improvementSteps} rubric steps`);
  await fixtureCommand("rereview");
  await page.reload();
  await expect(page.locator("#progress-summary")).toContainText("Re-rating a snapshot adds no engineering progress");
  await expect(ratingCard(page, "Security")).toContainText("Observed · high confidence");
  await expect(ratingCard(page, "Testing")).toContainText("Estimated from source · medium confidence");
  await expect(page.locator("#progress-summary")).toContainText(`Assessed movement from baseline: +${improvementSteps - 1} steps closer`);
  await expect(page.locator("#progress-summary")).toContainText(`Engineering progress: +${improvementSteps} rubric steps`);
  await page.locator("#history .event").filter({ hasText: "Source scan" }).last().getByRole("button").click();
  await expect(page.locator("#progress-summary")).toContainText("Progress uses the latest assessment");
  await page.locator("#history .event").filter({ hasText: "Source scan" }).first().getByRole("button").click();
  // The source's HTML is displayed as text in captured evidence.
  await expect(page.locator("#evidence")).toContainText("<img src=x onerror=window.pwned=1>");
  assert.equal(await page.evaluate(() => window.pwned), undefined);
  await checkLegacyTargets(page, origin, frameworkProfile);
  await checkProjectSwitches(page, origin);
  const accessibility = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(accessibility.violations.map((v) => ({ id: v.id, impact: v.impact, targets: v.nodes.map((node) => node.target) })), [], "desktop accessibility");
  await page.screenshot({ path: path.join(output, "project-assess-desktop.png"), fullPage: true });
  await page.setViewportSize({ width: 320, height: 900 });
  const noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  assert.equal(noOverflow, true, "320px layout must not overflow");
  await page.locator("#documentation-burden_max").focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.locator("#documentation-burden_max")).toHaveValue("2");
  await page.locator("#evidence-summary").click();
  const scrollingRecord = page.locator("#evidence details").filter({ has: page.getByText("scroll-evidence.md · documentation", { exact: true }) });
  await scrollingRecord.locator("summary").click();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "expanded evidence must fit mobile");
  const evidenceBlocks = scrollingRecord.locator("pre");
  const scrollableIndex = await evidenceBlocks.evaluateAll((elements) => elements.findIndex((element) => element.scrollHeight > element.clientHeight));
  assert(scrollableIndex >= 0, "fixture must exercise a vertically scrollable evidence block");
  const scrollableEvidence = evidenceBlocks.nth(scrollableIndex);
  await scrollableEvidence.focus();
  await expect(scrollableEvidence).toBeFocused();
  await page.keyboard.press("End");
  await expect.poll(() => scrollableEvidence.evaluate((element) => element.scrollTop), { message: "evidence must scroll with the keyboard" }).toBeGreaterThan(0);
  await page.getByText("Collected facts", { exact: true }).click();
  await page.locator("#facts").focus();
  await expect(page.locator("#facts")).toBeFocused();
  await page.keyboard.press("End");
  await expect.poll(() => page.locator("#facts").evaluate((element) => element.scrollTop), { message: "collected facts must scroll with the keyboard" }).toBeGreaterThan(0);
  const mobileAccessibility = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(mobileAccessibility.violations.map((v) => ({ id: v.id, impact: v.impact, targets: v.nodes.map((node) => node.target) })), [], "mobile accessibility");
  await page.screenshot({ path: path.join(output, "project-assess-mobile.png"), fullPage: true });
  assert.deepEqual(errors, [], "browser should not report JavaScript errors");
  console.log("PAT browser acceptance passed: goals, persistence, progress, project-switch races, hostile content, keyboard, mobile, accessibility.");
} finally {
  await browser?.close();
  lines.close();
  const exited = child.exitCode !== null || child.signalCode !== null ? Promise.resolve() : once(child, "exit");
  child.kill("SIGTERM");
  await exited.catch(() => {});
  await rm(fixture, { recursive: true, force: true });
}
