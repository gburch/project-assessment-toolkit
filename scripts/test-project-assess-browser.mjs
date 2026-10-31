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
from project_assess.badges import badge

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
(root / 'ecosystem.py').write_text('import sqlite3\n')
(root / 'package.json').write_text(json.dumps({'dependencies': {'fixture-lib': '1.0.0'}}))

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

    def scan(self, project_root, reports=None, **options):
        key = str(Path(project_root).resolve())
        count = self.scans.get(key, 0)
        snapshot = super().scan(project_root, reports, **options)
        review = synthetic_review(self, snapshot, 4 if count == 0 else 1,
            unknown_operability=key == str(root) and count == 0)
        self.submit_review(snapshot['id'], review)
        self.scans[key] = count + 1
        return snapshot

service = FixtureService(base / 'state')
initial = service.scan(root)
second_root = base / 'second-project'
second_root.mkdir()
(second_root / 'app.py').write_text('value = 1')
second = service.scan(second_root)
service.set_targets(second['project_id'], None, 0, profile='internal-service')
first_root = base / 'ui-first-project'
first_root.mkdir()
(first_root / 'app.py').write_text("raise AssertionError('Scans must not execute this project')\n")
(first_root / 'src').mkdir()
(first_root / 'src' / 'Feature.swift').write_text('func feature() { print("swift_context_marker") }\n')
(first_root / 'src' / 'Example.java').write_text('class Example { String value() { return "java_context_marker"; } }\n')
(first_root / 'src' / 'dead.py').write_text('\n'.join(
    f"def _unused{index}():\n    return {index}\n    print('never_called')\n" for index in range(25)))
(first_root / '.env').write_text('PRIVATE_UI_SCAN_MARKER=never-return-this-value\n')
forbidden_root = base / 'forbidden-project'
forbidden_root.mkdir()
first_service = AssessmentService(base / 'first-state', allowed_roots=[first_root, second_root])
badge_report = service.get_report(initial['id'])
badges = {'normal': badge(badge_report, 'maintainability')}
unknown = json.loads(json.dumps(badge_report))
unknown['review']['ratings']['maintainability'].update(capability=None, burden=None)
badges['unknown'] = badge(unknown, 'maintainability')
warning = json.loads(json.dumps(badge_report))
warning['assessment']['complete'] = False
warning['assessment']['findings'] = [{'severity': severity} for severity in ['critical', 'high'] for _ in range(100)]
badges['warning'] = badge(warning, 'maintainability')
def commands():
    for line in sys.stdin:
        command = line.strip()
        if command == 'change-context-source':
            (first_root / 'src' / 'dead.py').write_text("value = 'new_source_must_not_be_returned'\n")
            print(json.dumps({'command': command}), flush=True)
            continue
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
with create_server(service) as server, create_server(first_service) as first_server:
    Thread(target=first_server.serve_forever, daemon=True).start()
    print(json.dumps({'origin': server.origin, 'root': str(root),
        'first_origin': first_server.origin, 'first_root': str(first_root),
        'second_root': str(second_root), 'forbidden_root': str(forbidden_root), 'badges': badges}), flush=True)
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
  delete legacy.assessment.facts.ecosystem_fit;
  legacy.assessment.evidence = legacy.assessment.evidence.filter((entry) => entry.kind !== "ecosystem-analysis");
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
    await expect(page.locator("#ecosystem-fit")).toContainText("Not collected for this snapshot");
    await expect(page.getByRole("button", { name: "Inspect Ecosystem fit evidence" })).toHaveCount(0);
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
async function checkFirstScanAndReview(browser, info) {
  const origin = info.first_origin;
  const context = await browser.newContext({ viewport: { width: 320, height: 900 } });
  const page = await context.newPage();
  let dismissNext = false;
  page.on("dialog", (dialog) => dismissNext ? (dismissNext = false, dialog.dismiss()) : dialog.accept());
  const reviews = [];
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname === "/api/review") reviews.push(request.postDataJSON());
  });
  const projects = async () => (await page.request.get(`${origin}/api/projects`)).json();
  const history = async (id) => (await page.request.get(`${origin}/api/history?project_id=${id}`)).json();
  const submit = async (status) => {
    const response = page.waitForResponse((response) => response.url() === `${origin}/api/review` && response.request().method() === "POST");
    await page.getByRole("button", { name: "Submit review", exact: true }).click();
    const result = await response;
    assert.equal(result.status(), status);
    return result.json();
  };
  const scored = (template, snapshot, capability = 3) => {
    const result = structuredClone(template);
    Object.assign(result.ratings.testing, { capability, burden: 2, confidence: "medium", burden_basis: "source_estimate", burden_confidence: "low",
      rationale: "Synthetic browser review <img src=x onerror=window.reviewPwned=1>",
      evidence_ids: [snapshot.evidence.find((entry) => entry.kind === "python").id] });
    return result;
  };
  try {
    assert.deepEqual(await projects(), [], "first workflow must begin with no registered projects");
    await page.goto(origin);
    await expect(page.locator("#empty")).toBeVisible();
    await expect(page.locator("#scan")).toBeEnabled();
    await page.getByLabel("Project directory", { exact: true }).fill(info.forbidden_root);
    await page.getByRole("button", { name: "Scan project", exact: true }).click();
    await expect(page.locator("#error")).toContainText("outside configured allowed roots");
    assert.deepEqual(await projects(), []);
    await page.getByLabel("Project directory", { exact: true }).fill(info.first_root);
    const initialResponse = page.waitForResponse((response) => response.url() === `${origin}/api/scan` && response.request().method() === "POST");
    await page.locator("#scan-root").press("Enter");
    const initial = await (await initialResponse).json();
    await expect(page.locator("#status")).toContainText(initial.id);
    await expect(page.locator("#empty")).toBeHidden();
    await expect(page.locator("#ratings")).toContainText("Not reviewed");
    assert.equal((await page.request.get(`${origin}/api/report?assessment_id=${initial.id}`)).status(), 200);
    assert(!JSON.stringify(initial).includes("never-return-this-value"), "secret files must stay excluded");
    await page.locator("#review-editor summary").click();
    await page.getByRole("button", { name: "Load review template", exact: true }).click();
    await expect(page.locator("#review-state")).toContainText("Unsaved review template");
    const template = JSON.parse(await page.locator("#review-json").inputValue());
    assert.equal(template.assessment_id, initial.id);
    assert.equal(template.source_digest, initial.source.manifest_digest);
    assert(Object.values(template.ratings).every((rating) => rating.capability === null && rating.burden === null));
    await page.getByLabel("Import review JSON", { exact: true }).setInputFiles({ name: "large.json", mimeType: "application/json", buffer: Buffer.alloc(256 * 1024 + 1, 32) });
    await expect(page.locator("#error")).toContainText("at most 256 KiB");
    assert.deepEqual(JSON.parse(await page.locator("#review-json").inputValue()), template);
    const draft = scored(template, initial);
    await page.getByLabel("Import review JSON", { exact: true }).setInputFiles({ name: "review.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(draft)) });
    await expect(page.locator("#review-state")).toContainText("Imported JSON is unsaved");
    assert.equal((await history(initial.project_id)).reviews.length, 0, "import must not submit automatically");
    dismissNext = true;
    await page.getByRole("button", { name: "Scan again", exact: true }).click();
    assert.equal((await projects())[0].latest_assessment_id, initial.id, "declining discard keeps the snapshot and draft");
    assert.deepEqual(JSON.parse(await page.locator("#review-json").inputValue()), draft);
    const invalid = structuredClone(draft);
    invalid.ratings.testing.evidence_ids = ["foreign-evidence"];
    await page.locator("#review-json").fill(JSON.stringify(invalid));
    await submit(400);
    await expect(page.locator("#error")).toContainText("outside its captured snapshot");
    await expect(page.locator("#review-submit")).toBeEnabled();
    invalid.ratings.testing.evidence_ids = draft.ratings.testing.evidence_ids;
    invalid.source_digest = "wrong-source";
    await page.locator("#review-json").fill(JSON.stringify(invalid));
    await submit(409);
    await expect(page.locator("#error")).toContainText("identity does not match");
    const session = await (await page.request.get(`${origin}/api/session`)).json();
    const newerResponse = await page.request.post(`${origin}/api/scan`, { data: { project_id: initial.project_id }, headers: { Origin: origin, "X-Project-Assess-Token": session.token } });
    assert.equal(newerResponse.status(), 200);
    const newer = await newerResponse.json();
    await page.locator("#review-json").fill(JSON.stringify(draft));
    await submit(409);
    await expect(page.locator("#error")).toContainText("Assessment is stale");
    assert.equal((await history(initial.project_id)).reviews.length, 0);
    await page.reload();
    await expect(page.locator("#status")).toContainText(newer.id);
    await expect(page.locator("#review-json")).toHaveValue("");
    await page.locator("#review-editor summary").click();
    await page.getByRole("button", { name: "Load review template", exact: true }).click();
    await expect(page.locator("#review-state")).toContainText("Unsaved review template");
    const currentTemplate = JSON.parse(await page.locator("#review-json").inputValue());
    const current = scored(currentTemplate, newer);
    await page.locator("#review-json").fill(JSON.stringify(current));
    await page.selectOption("#profile", "local-experiment");
    await page.locator("#testing-capability_min").fill("2");
    const saved = await submit(200);
    await expect(page.locator("#review-state")).toContainText(saved.id);
    await expect(ratingCard(page, "Testing")).toContainText("3 / 5");
    await expect(ratingCard(page, "Testing")).toContainText("2 / 5");
    await expect(ratingCard(page, "Operability")).toContainText("Unknown");
    await expect(page.locator("#review-submit")).toBeDisabled();
    await expect(page.locator("#goal-state")).toContainText("Unsaved targets");
    await expect(page.locator("#testing-capability_min")).toHaveValue("2");
    assert.equal((await history(initial.project_id)).goals.length, 0);
    assert.equal(await page.evaluate(() => window.reviewPwned), undefined);
    assert.equal(await page.locator("main img").count(), 0);
    await page.screenshot({ path: path.join(output, "project-assess-first-review-mobile.png"), fullPage: true });
    await page.reload();
    await expect(ratingCard(page, "Testing")).toContainText("3 / 5");
    await expect(page.locator("#review-json")).toHaveValue("");
    await page.getByLabel("Project directory", { exact: true }).fill(info.second_root);
    await page.getByRole("button", { name: "Scan project", exact: true }).click();
    await expect(page.locator("#project-name")).toHaveText("second-project");
    const second = (await projects()).find((project) => project.name === "second-project");
    await page.selectOption("#project", initial.project_id);
    await expect(page.locator("#status")).toContainText(newer.id);
    await page.locator("#review-editor summary").click();
    const pendingTemplate = await holdResponse(page, `**/api/review-template?assessment_id=${newer.id}`);
    await page.getByRole("button", { name: "Load review template", exact: true }).click();
    await pendingTemplate.entered;
    await page.selectOption("#project", second.id);
    await expect(page.locator("#project-name")).toHaveText("second-project");
    await pendingTemplate.release();
    await expect(page.locator("#review-json")).toHaveValue("");
    await page.selectOption("#project", initial.project_id);
    await expect(page.locator("#status")).toContainText(newer.id);
    await page.locator("#review-editor summary").click();
    await page.locator("#review-json").fill(JSON.stringify(scored(currentTemplate, newer, 4)));
    const pendingReview = await holdResponse(page, "**/api/review");
    await page.getByRole("button", { name: "Submit review", exact: true }).click();
    await pendingReview.entered;
    await expect(page.locator("#review-json")).toBeDisabled();
    await page.selectOption("#project", second.id);
    await expect(page.locator("#project-name")).toHaveText("second-project");
    await page.selectOption("#project", initial.project_id);
    await expect(page.locator("#status")).toContainText(newer.id);
    await expect(ratingCard(page, "Testing")).toContainText("4 / 5");
    await page.locator("#review-editor summary").click();
    const returnedDraft = JSON.stringify({ ...current, findings: [] }, null, 2);
    await page.locator("#review-json").fill(returnedDraft);
    await pendingReview.release();
    await expect(page.locator("#review-json")).toHaveValue(returnedDraft);
    await expect(page.locator("#review-state")).toContainText("Unsaved review JSON");
    const pendingError = await holdResponse(page, "**/api/review", true);
    await page.getByRole("button", { name: "Submit review", exact: true }).click();
    await pendingError.entered;
    await page.selectOption("#project", second.id);
    await expect(page.locator("#project-name")).toHaveText("second-project");
    await pendingError.release();
    await expect(page.locator("#error")).toBeHidden();
    assert.equal((await history(second.id)).reviews.length, 0, "late review responses must not write to the selected project");
    assert(reviews.every((request) => request.assessment_id === request.review.assessment_id));
    await page.locator("#review-editor summary").click();
    const overflow = await page.evaluate(() => ({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
      elements: Array.from(document.querySelectorAll("main *")).map((element) => ({ tag: element.tagName, id: element.id, width: element.getBoundingClientRect().width, right: element.getBoundingClientRect().right })).filter((element) => element.right > innerWidth + 1) }));
    assert(overflow.scrollWidth <= overflow.width, `expanded review editor must fit mobile: ${JSON.stringify(overflow)}`);
    const accessibility = await new AxeBuilder({ page }).analyze();
    assert.deepEqual(accessibility.violations.map((violation) => ({ id: violation.id, targets: violation.nodes.map((node) => node.target) })), [], "first scan/review mobile accessibility");
    assert.deepEqual(errors, []);
  } finally {
    await context.close();
  }
}

async function checkBadgeText(browser, badges) {
  const page = await browser.newPage({ viewport: { width: 320, height: 220 } });
  try {
    for (const [name, svg] of Object.entries(badges)) {
      await page.setContent(svg);
      await page.evaluate(() => document.fonts.ready);
      const result = await page.locator("svg").evaluate((svg) => ({ width: svg.width.baseVal.value, height: svg.querySelector("rect").getBBox().height + 0.5,
        texts: Array.from(svg.querySelectorAll("text"), (element) => { const box = element.getBBox(); return { text: element.textContent, x: box.x, y: box.y, width: box.width, height: box.height }; }) }));
      assert.equal(result.width, 200);
      for (const text of result.texts) assert(text.x >= 0 && text.y >= 0 && text.x + text.width <= result.width && text.y + text.height <= result.height, `${name} badge text must fit: ${text.text}`);
      for (let i = 0; i < result.texts.length; i++) for (let j = i + 1; j < result.texts.length; j++) {
        const a = result.texts[i], b = result.texts[j];
        assert(!(Math.min(a.x + a.width, b.x + b.width) > Math.max(a.x, b.x) + 0.5 && Math.min(a.y + a.height, b.y + b.height) > Math.max(a.y, b.y) + 0.5), `${name} badge labels must not overlap`);
      }
      if (name === "unknown") assert.equal(result.texts.filter((text) => text.text === "?/5").length, 2);
      if (name === "warning") for (const text of ["Reported: 100 critical", "100 high", "Partial scan"]) assert(result.texts.some((row) => row.text === text));
    }
  } finally {
    await page.close();
  }
}

async function checkPlanningEvidence(browser, info) {
  const origin = info.first_origin;
  const context = await browser.newContext({ viewport: { width: 320, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("dialog", (dialog) => dialog.accept());
  try {
    const projects = await (await page.request.get(`${origin}/api/projects`)).json();
    const project = projects.find((entry) => entry.root === info.first_root);
    const other = projects.find((entry) => entry.id !== project.id);
    await page.goto(origin);
    await page.selectOption("#project", project.id);
    await expect(page.locator("#source")).toContainText(info.first_root);
    await expect(page.locator("#review-coverage")).toContainText("unexamined");
    await page.selectOption("#profile", "internal-service");
    await page.getByRole("button", { name: "Save goals", exact: true }).click();
    await expect(page.locator("#goal-state")).toContainText("Saved goal version");
    const report = await (await page.request.get(`${origin}/api/report?assessment_id=${project.latest_assessment_id}`)).json();
    const source = report.assessment.evidence.find((entry) => entry.path === "src/dead.py");
    const review = await (await page.request.get(`${origin}/api/review-template?assessment_id=${project.latest_assessment_id}`)).json();
    for (const rating of Object.values(review.ratings)) Object.assign(rating, {
      capability: 3, burden: 1, confidence: "medium", burden_basis: "source_estimate", burden_confidence: "low",
      rationale: "Synthetic full review, not an automatically calculated grade.", evidence_ids: [source.id], recommendations: ["Consolidate responsibility across the supported paths."]
    });
    const hostile = "<img src=x onerror=window.planPwned=1>";
    review.coverage = { schema_version: 1, scope: "whole_project", examined: [{ area: "Production lifecycle", evidence_ids: [source.id] }], unexamined: [{ area: "Provider recovery", reason: "No runtime receipt supplied" }], limitations: ["Source-only review"], validation: [{ check: "Provider recovery", status: "not_run", evidence_ids: [] }] };
    review.plan = { schema_version: 1, goal_revision: report.goals.revision, diagnosis: `Shared lifecycle ownership needs consolidation ${hostile}`, target_state: "One supported lifecycle across all entry points with source-linked failure verification", initiatives: [
      { id: "consolidate", title: "Consolidate lifecycle ownership", priority: "high", root_cause: "Ownership duplicated across callers", scope: "Every entry point, persisted transition and recovery caller", dimension_impacts: { maintainability: "Reduce coordinated edits", testing: "Protect shared public outcomes" }, evidence_ids: [source.id], acceptance: ["All supported callers preserve authority and recovery behavior"], burden_effect: "Replace duplicate upkeep; add no framework", depends_on: [], first_slice: "Move one path after agreeing the complete contract" },
      { id: "recovery", title: "Verify recovery guidance", priority: "medium", root_cause: "Guidance can drift from lifecycle ownership", scope: "Supported operator recovery workflows", dimension_impacts: { documentation: "Reliable recovery task" }, evidence_ids: [source.id], acceptance: ["A reader completes the recovery task"], burden_effect: "Maintain one canonical explanation", depends_on: ["consolidate"], first_slice: "Trace the documented recovery path" }
    ] };
    review.findings = [{ severity: "critical", title: "Synthetic critical finding remains visible despite met goals", evidence_ids: [source.id] }];
    await page.locator("#review-editor summary").click();
    await page.locator("#review-json").fill(JSON.stringify(review));
    await page.getByRole("button", { name: "Submit review", exact: true }).click();
    await expect(page.locator("#review-state")).toContainText("Saved review");
    await expect(page.locator("#plan-state")).toContainText("Plan is bound");
    await expect(page.locator("#plan-urgent")).toContainText("Synthetic critical finding");
    await expect(page.locator("#progress-summary")).toContainText("Remaining gap: 0");
    await expect(page.locator("#improvement-plan")).toContainText(hostile);
    await expect(page.locator("#improvement-plan")).toContainText("Every entry point, persisted transition and recovery caller");
    await expect(page.locator("#improvement-plan")).toContainText("Depends on: consolidate");
    const roadmap = await page.locator("#improvement-plan").textContent();
    assert(roadmap.indexOf("Full target state") < roadmap.indexOf("First implementation slice"));
    assert(roadmap.indexOf("Acceptance for the full outcome") < roadmap.indexOf("First implementation slice"));
    await page.locator("#review-coverage summary").click();
    await expect(page.locator("#review-coverage")).toContainText("Provider recovery: No runtime receipt supplied");
    const history = await (await page.request.get(`${origin}/api/history?project_id=${project.id}`)).json();
    await page.locator("#evidence-browser summary").first().click();
    await page.selectOption("#query-role", "production");
    await page.selectOption("#query-candidate", "unreachable_statement");
    await page.locator("#query-path").fill("src/dead.py");
    const hostileLead = async (route) => {
      const response = await route.fetch();
      const result = await response.json();
      result.items[0].metrics.caveat = hostile;
      await route.fulfill({ response, json: result });
    };
    await page.route("**/api/evidence-query?*", hostileLead);
    await page.getByRole("button", { name: "Query evidence", exact: true }).click();
    await expect(page.locator("#query-state")).toContainText("25 matching row(s)");
    const firstCount = await page.locator("#query-results > details").count();
    assert(firstCount > 0 && firstCount <= 20);
    const lead = page.locator("#query-results > details").first();
    await lead.locator("summary").click();
    await expect(lead).toContainText(hostile);
    const requested = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/source-context");
    await lead.getByRole("button", { name: "Read matching source context" }).click();
    assert.equal(new URL((await requested).url()).searchParams.get("evidence_id"), source.id);
    await expect(lead).toContainText("snapshot_matched_live_bytes");
    await expect(lead).toContainText("never_called");
    await page.unroute("**/api/evidence-query?*", hostileLead);
    await page.getByRole("button", { name: "Load more evidence" }).click();
    await expect.poll(() => page.locator("#query-results > details").count()).toBeGreaterThan(firstCount);
    await fixtureCommand("change-context-source");
    await lead.getByRole("button", { name: "Read matching source context" }).click();
    await expect(lead.locator(".context-result")).toContainText("changed since capture");
    await expect(lead.locator(".context-result")).not.toContainText("new_source_must_not_be_returned");
    await page.selectOption("#query-view", "snippets");
    await page.getByRole("button", { name: "Query evidence", exact: true }).click();
    await expect(page.locator("#query-state")).not.toContainText("Querying");
    await expect(page.locator("#query-results")).toContainText("never_called");
    const pending = await holdResponse(page, "**/api/evidence-query?*");
    await page.getByRole("button", { name: "Query evidence", exact: true }).click();
    await pending.entered;
    await page.selectOption("#project", other.id);
    await expect(page.locator("#source")).toContainText(info.second_root);
    await pending.release();
    await expect(page.locator("#query-results")).toBeEmpty();
    assert.deepEqual(await (await page.request.get(`${origin}/api/history?project_id=${project.id}`)).json(), history, "evidence/context queries must not mutate history");
    await page.selectOption("#project", project.id);
    await expect(page.locator("#plan-urgent")).toContainText("Synthetic critical finding");
    await page.locator("#plan-heading").locator("..").screenshot({ path: path.join(output, "project-assess-planning-mobile.png") });
    assert.equal(await page.evaluate(() => window.planPwned), undefined);
    assert.equal(await page.locator("#improvement-plan img, #query-results img").count(), 0);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "roadmap and evidence browser fit mobile");
    const accessibility = await new AxeBuilder({ page }).analyze();
    assert.deepEqual(accessibility.violations.map((violation) => ({ id: violation.id, targets: violation.nodes.map((node) => node.target) })), [], "roadmap/evidence mobile accessibility");
    assert.deepEqual(errors, []);
  } finally { await context.close(); }
}

async function checkAnalysisOptions(browser, info) {
  const origin = info.first_origin;
  const context = await browser.newContext({ viewport: { width: 320, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    const projects = await (await page.request.get(`${origin}/api/projects`)).json();
    const project = projects.find((entry) => entry.root === info.first_root);
    const other = projects.find((entry) => entry.id !== project.id);
    const previous = await (await page.request.get(`${origin}/api/report?assessment_id=${project.latest_assessment_id}`)).json();
    const goals = (await (await page.request.get(`${origin}/api/history?project_id=${project.id}`)).json()).goals;
    const vulture = (await (await page.request.get(`${origin}/api/analyzers`)).json()).find((entry) => entry.name === "vulture");
    await page.goto(origin);
    await page.selectOption("#project", project.id);
    await expect(page.locator("#status")).toContainText(project.latest_assessment_id);
    await expect(page.locator("#analysis-profile")).toHaveValue(previous.assessment.facts.collection.analysis_profile);
    await page.selectOption("#analysis-profile", "deep");
    await page.locator("#analyzer-vulture").focus();
    if (!(await page.locator("#analyzer-vulture").isChecked())) await page.keyboard.press("Space");
    await expect(page.locator("#analyzer-vulture")).toBeChecked();
    await expect(page.locator("#vulture-status")).toContainText(vulture.available ? `Vulture ${vulture.version} is available` : "Vulture is not installed");
    assert.deepEqual((await (await page.request.get(`${origin}/api/history?project_id=${project.id}`)).json()).goals, goals, "analysis selection must not save targets");
    const response = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/scan" && response.request().method() === "POST");
    await page.getByRole("button", { name: "Scan again", exact: true }).click();
    const completed = await response;
    assert.equal(completed.status(), 200);
    assert.deepEqual(completed.request().postDataJSON(), { project_id: project.id, analysis_profile: "deep", analyzers: ["vulture"] });
    const snapshot = await completed.json();
    await expect(page.locator("#status")).toContainText(snapshot.id);
    await expect(page.locator("#analysis-scope")).toContainText("Analysis: deep");
    await expect(page.locator("#analysis-scope")).toContainText("optional: vulture");
    assert.equal(snapshot.facts.collection.analysis_profile, "deep");
    assert.deepEqual(snapshot.facts.collection.analyzers, ["vulture"]);
    assert.equal(snapshot.facts.optional_analysis.vulture.status, vulture.available ? "complete" : "unavailable");
    assert.equal(snapshot.facts.optional_analysis.vulture.configuration.analysis_profile, "deep");
    const report = await (await page.request.get(`${origin}/api/report?assessment_id=${snapshot.id}`)).json();
    assert.deepEqual(report.goals, previous.goals, "a deeper scan must preserve selected goals and their baseline");
    assert.equal(report.review, null, "an optional analyzer must not manufacture ratings");
    await page.reload();
    await page.selectOption("#project", project.id);
    await expect(page.locator("#status")).toContainText(snapshot.id);
    await expect(page.locator("#analysis-profile")).toHaveValue("deep");
    await expect(page.locator("#analyzer-vulture")).toBeChecked();
    await expect(page.locator("#profile")).toHaveValue(previous.goals.profile);
    await page.locator("#evidence-browser summary").first().click();
    await page.selectOption("#query-view", "index");
    await page.selectOption("#query-kind", "source");
    await page.locator("#query-path").fill("Feature.swift");
    await page.getByRole("button", { name: "Query evidence", exact: true }).click();
    await expect(page.locator("#query-state")).toContainText("1 matching row(s)");
    const swift = page.locator("#query-results > details").first();
    await swift.locator("summary").click();
    await expect(swift).toContainText("src/Feature.swift");
    const contextRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/source-context");
    await swift.getByRole("button", { name: "Read matching source context" }).click();
    assert.equal(new URL((await contextRequest).url()).searchParams.get("evidence_id"), snapshot.evidence.find((entry) => entry.path === "src/Feature.swift").id);
    await expect(swift).toContainText("snapshot_matched_live_bytes");
    await expect(swift).toContainText("swift_context_marker");
    await page.selectOption("#project", other.id);
    await expect(page.locator("#status")).toContainText(other.latest_assessment_id);
    await expect(page.locator("#analysis-profile")).toHaveValue("standard");
    await expect(page.locator("#analyzer-vulture")).not.toBeChecked();
    await page.selectOption("#project", project.id);
    await expect(page.locator("#analysis-profile")).toHaveValue("deep");
    await expect(page.locator("#analyzer-vulture")).toBeChecked();
    assert.deepEqual((await (await page.request.get(`${origin}/api/history?project_id=${project.id}`)).json()).goals, goals);
    const hostileTitle = "Fixture <img src=x onerror=window.analyzerPwned=1>";
    await page.route("**/api/analyzers", async (route) => {
      const response = await route.fetch();
      const descriptors = await response.json();
      descriptors.push({ name: "fixture-analyzer", title: hostileTitle, version: null, available: false, optional: true, languages: ["python"] });
      await route.fulfill({ response, json: descriptors });
    });
    await page.reload();
    await page.selectOption("#project", project.id);
    await expect(page.locator("#status")).toContainText(snapshot.id);
    await expect(page.locator("#optional-analyzers input[data-analyzer]")).toHaveCount(2);
    await expect(page.locator("#optional-analyzers")).toContainText(hostileTitle);
    await page.locator("#analyzer-fixture-analyzer").check();
    const beforeInvalid = await (await page.request.get(`${origin}/api/history?project_id=${project.id}`)).json();
    const pending = await holdResponse(page, "**/api/scan");
    const pendingRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/scan" && request.method() === "POST");
    await page.getByRole("button", { name: "Scan again", exact: true }).click();
    const invalid = await pending.entered;
    assert.equal(invalid.status(), 400, "metadata alone must not register a backend analyzer");
    assert.deepEqual((await pendingRequest).postDataJSON().analyzers, ["vulture", "fixture-analyzer"], "scan payload must derive from all selected metadata checkboxes");
    await expect(page.locator("#analyzer-vulture")).toBeDisabled();
    await expect(page.locator("#analyzer-fixture-analyzer")).toBeDisabled();
    await pending.release();
    await expect(page.locator("#error")).toContainText("registered");
    await expect(page.locator("#analyzer-fixture-analyzer")).toBeEnabled();
    assert.deepEqual(await (await page.request.get(`${origin}/api/history?project_id=${project.id}`)).json(), beforeInvalid);
    await page.reload();
    await page.selectOption("#project", project.id);
    await expect(page.locator("#status")).toContainText(snapshot.id);
    await expect(page.locator("#analyzer-vulture")).toBeChecked();
    await expect(page.locator("#analyzer-fixture-analyzer")).not.toBeChecked();
    assert.equal(await page.locator("#optional-analyzers img").count(), 0);
    assert.equal(await page.evaluate(() => window.analyzerPwned), undefined);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "analysis options must fit mobile");
    const accessibility = await new AxeBuilder({ page }).analyze();
    assert.deepEqual(accessibility.violations.map((violation) => ({ id: violation.id, targets: violation.nodes.map((node) => node.target) })), [], "analysis options mobile keyboard/accessibility");
    assert.deepEqual(errors, []);
  } finally { await context.close(); }
}

let browser;
try {
  const info = await launch;
  const { origin, root } = info;
  browser = await chromium.launch({ headless: true });
  await checkBadgeText(browser, info.badges);
  await checkFirstScanAndReview(browser, info);
  await checkPlanningEvidence(browser, info);
  await checkAnalysisOptions(browser, info);
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  page.on("dialog", (dialog) => dialog.accept());
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
  // Exercise rendering defensively even if a captured/imported name is hostile.
  const hostileDependency = "<img src=x onerror=window.ecosystemPwned=1>";
  const hostileInventory = async (route) => {
    const response = await route.fetch();
    const report = await response.json();
    const record = report.assessment.evidence.find((entry) => entry.kind === "ecosystem-analysis");
    assert(record.stats.dependencies.length > 0, "fixture must capture a real dependency declaration");
    record.stats.dependencies[0].name = hostileDependency;
    await route.fulfill({ response, json: report });
  };
  await page.route("**/api/report?assessment_id=*", hostileInventory);
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
  await page.locator("#ecosystem-fit summary").click();
  await expect(page.locator("#ecosystem-fit")).toContainText("Dependency declarations: 1; syntax signals: 1");
  await expect(page.locator("#ecosystem-fit")).toContainText("not a fit rating or a migration recommendation");
  await page.getByRole("button", { name: "Inspect Ecosystem fit evidence" }).click();
  const ecosystemRecord = page.locator("#evidence details").filter({ has: page.getByText("<ecosystem-analysis> · ecosystem-analysis", { exact: true }) });
  await expect(ecosystemRecord).toHaveAttribute("open", "");
  await expect(ecosystemRecord).toContainText(hostileDependency);
  await expect(ecosystemRecord.locator("summary")).toBeFocused();
  assert.equal(await page.evaluate(() => window.ecosystemPwned), undefined);
  await page.unroute("**/api/report?assessment_id=*", hostileInventory);

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
  console.log("PAT browser acceptance passed: first scan/review, independent Deep/Vulture selection, shared roadmap/coverage/urgent findings, filtered evidence/pagination/source identity, stale responses, goals/progress, hostile content, keyboard/mobile/accessibility, badge text bounds.");
} finally {
  await browser?.close();
  lines.close();
  const exited = child.exitCode !== null || child.signalCode !== null ? Promise.resolve() : once(child, "exit");
  child.kill("SIGTERM");
  await exited.catch(() => {});
  await rm(fixture, { recursive: true, force: true });
}
