import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const { chromium } = process.env.PLAYWRIGHT_MODULE
  ? await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href)
  : await import("playwright");
const child = spawn(
  process.env.PYTHON || "python",
  ["run.py", "serve", "--port", "0"],
  { stdio: ["ignore", "pipe", "pipe"] },
);
let browser;
try {
  const base = await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Local server startup timeout")),
      20000,
    );
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`Server exited ${code}`));
    });
    child.stdout.on("data", (chunk) => {
      const match = chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+\//);
      if (match) {
        clearTimeout(timeout);
        resolve(match[0]);
      }
    });
  });
  browser = await chromium.launch({ headless: true });
  await mkdir("test-results", { recursive: true });
  const errors = [];
  async function waitText(page, id, value) {
    await page.waitForFunction(
      ({ id, value }) => document.getElementById(id).textContent === value,
      { id, value },
    );
  }
  async function assertLayout(page) {
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
      "Page horizontal overflow",
    );
    assert.equal(
      await page
        .locator("img")
        .evaluateAll((images) =>
          images.every((image) => image.complete && image.naturalWidth > 0),
        ),
      true,
      "Missing asset",
    );
  }
  for (const [name, width, height] of [
    ["desktop", 1440, 1000],
    ["mobile", 390, 844],
    ["compact", 360, 800],
  ]) {
    const context = await browser.newContext({
      viewport: { width, height },
      acceptDownloads: true,
    });
    const page = await context.newPage();
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("dialog", () => errors.push("Untrusted log executed a dialog"));
    page.on("request", (request) => {
      if (!request.url().startsWith(base) && !request.url().startsWith("blob:"))
        errors.push(`External request ${request.url()}`);
    });
    await page.goto(base);
    await waitText(page, "metric-alerts", "5");
    await page.locator("#status").filter({ hasText: "분석 완료" }).waitFor();
    assert.equal(await page.locator("#alert-list tbody tr").count(), 5);
    await assertLayout(page);
    await page.screenshot({ path: `test-results/${name}.png`, fullPage: true });
    await page.locator("#alert-list button").first().click();
    assert.equal(await page.locator("#detail").isVisible(), true);
    assert.match(
      await page.locator("#detail-content").textContent(),
      /일치한 근거/,
    );
    await page.locator("#search").fill("powershell");
    assert.equal(await page.locator("#alert-list tbody tr").count(), 3);
    await page.locator("#severity").selectOption("high");
    assert.equal(await page.locator("#alert-list tbody tr").count(), 1);
    await page.locator("#search").fill("");
    await page.locator("#severity").selectOption("");
    await page.locator("[data-view=timeline]").click();
    assert.equal(await page.locator("#timeline-list tbody tr").count(), 8);
    await page.locator("#timeline-list button").first().click();
    assert.match(
      await page.locator("#detail-content").textContent(),
      /process_guid/,
    );
    await page.locator("[data-view=processes]").click();
    assert.equal(await page.locator(".process-row").count(), 5);
    assert.equal(await page.locator(".process-row.depth-2").count(), 2);
    await page.screenshot({
      path: `test-results/${name}-tree.png`,
      fullPage: true,
    });
    await page.locator("[data-view=rules]").click();
    assert.equal(await page.locator(".rule-row").count(), 5);
    await page.locator("[data-view=validation]").click();
    await page.locator("#verification").filter({ hasText: "18/18" }).waitFor();
    await assertLayout(page);
    await page.screenshot({
      path: `test-results/${name}-validation.png`,
      fullPage: true,
    });
    await page
      .locator("#verification button")
      .filter({ hasText: "임시 경로 실행" })
      .click();
    await waitText(page, "metric-alerts", "1");
    await page.locator("#scenario").selectOption("normal-admin");
    await waitText(page, "metric-alerts", "2");
    await page.locator("[data-policy=tuned]").click();
    await waitText(page, "metric-suppressed", "2");
    assert.equal(await page.locator("#metric-alerts").textContent(), "0");
    await page.locator("#suppressed-summary").click();
    assert.equal(await page.locator("#suppressed-list button").count(), 2);
    await page.locator("#reset").click();
    await waitText(page, "metric-alerts", "5");
    await page.locator("#replay").evaluate((input) => {
      input.value = "3";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await waitText(page, "metric-events", "3");
    assert.equal(await page.locator("#metric-alerts").textContent(), "0");
    await page.locator("#step").click();
    await waitText(page, "metric-events", "4");
    assert.equal(await page.locator("#metric-alerts").textContent(), "2");
    await page.locator("#play").click();
    await page.waitForFunction(
      () => Number(document.getElementById("metric-events").textContent) >= 5,
    );
    await page.getByRole("button", { name: "일시 정지", exact: true }).click();
    await page.locator("#reset").click();
    await waitText(page, "metric-alerts", "5");
    await page.locator("#file").setInputFiles("samples/incident-chain.xml");
    await page
      .locator("#source-name")
      .filter({ hasText: "incident-chain.xml" })
      .waitFor();
    await page.locator("#status").filter({ hasText: "분석 완료" }).waitFor();
    assert.equal(await page.locator("#metric-alerts").textContent(), "5");
    const pending = page.waitForEvent("download");
    await page.locator("#export").click();
    const download = await pending;
    assert.equal(download.suggestedFilename(), "endpoint-lab-report.json");
    const filename = `test-results/${name}-report.json`;
    await download.saveAs(filename);
    const report = JSON.parse(await readFile(filename, "utf8"));
    assert.equal(report.lab_only, true);
    assert.equal(report.verdict, "indicators_only");
    assert.equal(report.input.format, "xml");
    const malicious = [
      {
        event_id: 1,
        timestamp: "2026-01-01T00:00:00Z",
        host: "lab-xss",
        process_guid: "00000000-0000-0000-0000-000000000001",
        image:
          "C:\\Users\\lab\\AppData\\Local\\Temp\\<img src=x onerror=alert(1)>.exe",
        command_line: "a\u202etxt",
      },
    ];
    await page
      .locator("#file")
      .setInputFiles({
        name: "untrusted.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify(malicious)),
      });
    await waitText(page, "metric-alerts", "1");
    assert.equal(await page.locator("#alert-list img").count(), 0);
    await page.locator("[data-view=timeline]").click();
    assert.match(await page.locator("#timeline-list").textContent(), /\\u202e/);
    assert.equal(await page.locator("#timeline-list img").count(), 0);
    await assertLayout(page);
    const many = Array.from({ length: 110 }, (_, index) => ({
      event_id: 1,
      timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      host: "lab-many",
      process_guid: `00000000-0000-0000-0000-${(index + 1).toString(16).padStart(12, "0")}`,
      image: "C:\\Program Files\\Lab\\browser.exe",
      record_id: index + 1,
    }));
    await page
      .locator("#file")
      .setInputFiles({
        name: "many.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify(many)),
      });
    await waitText(page, "metric-events", "110");
    assert.equal(await page.locator("#timeline-list tbody tr").count(), 50);
    await page.locator("#next").click();
    assert.equal(await page.locator("#page-position").textContent(), "2 / 3");
    await page.locator("#next").click();
    assert.equal(await page.locator("#timeline-list tbody tr").count(), 10);
    await context.close();
  }
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(base);
  await waitText(page, "metric-alerts", "5");
  let release, entered;
  const intercepted = new Promise((resolve) => {
    entered = resolve;
  });
  await page.route("**/api/analyze", async (route) => {
    entered();
    await new Promise((resolve) => {
      release = resolve;
    });
    await route.abort().catch(() => {});
  });
  await page
    .locator("#file")
    .setInputFiles({
      name: "cancel.json",
      mimeType: "application/json",
      buffer: Buffer.from("[]"),
    });
  await intercepted;
  await page.locator("#cancel").click();
  await page.locator("#status").filter({ hasText: "분석 취소됨" }).waitFor();
  assert.equal(await page.locator("#analysis").isVisible(), false);
  release();
  await page.unrouteAll({ behavior: "wait" });
  await page.locator("#reset").click();
  await waitText(page, "metric-alerts", "5");
  await context.close();
  assert.deepEqual(errors, []);
  console.log(
    "Browser checks passed: desktop/mobile/compact, alerts, evidence, tree, timeline, validation, tuning, replay, XML import, JSON export, XSS/bidi, pagination, cancellation.",
  );
} finally {
  await browser?.close();
  child.kill();
}
