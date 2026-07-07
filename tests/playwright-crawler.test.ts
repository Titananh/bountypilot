import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { crawlWithPlaywright } from "../src/engines/crawler/playwright-crawler.js";

const playwrightMock = vi.hoisted(() => ({
  launch: vi.fn(),
}));

vi.mock("playwright", () => ({
  chromium: {
    launch: playwrightMock.launch,
  },
}));

describe("crawlWithPlaywright evidence flags", () => {
  beforeEach(() => {
    playwrightMock.launch.mockReset();
    installPlaywrightMock();
  });

  it("does not write optional artifacts when evidence flags are disabled", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-flags-"));

    const result = await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      jobId: "job-disabled",
      evidence: {
        screenshots: false,
        har: false,
        consoleLogs: false,
        domSnapshot: false,
        browserTrace: false,
        video: false,
      },
    });

    expect(result.evidence).toEqual([]);
    expect(existsSync(path.join(root, "job-disabled", "127.0.0.1", "screenshot.png"))).toBe(false);
    expect(existsSync(path.join(root, "job-disabled", "127.0.0.1", "dom.html"))).toBe(false);
    expect(existsSync(path.join(root, "job-disabled", "127.0.0.1", "console.log"))).toBe(false);
  });

  it("creates HAR and browser trace artifacts when enabled", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-trace-"));

    const result = await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      jobId: "job-trace",
      evidence: {
        screenshots: false,
        har: true,
        consoleLogs: false,
        domSnapshot: false,
        browserTrace: true,
        video: "optional",
      },
    });

    expect(result.evidence.map((artifact) => artifact.kind).sort()).toEqual(["browser_trace", "har"]);
    for (const artifact of result.evidence) {
      expect(existsSync(artifact.path)).toBe(true);
    }
  });

  it("creates bounded request and response sample artifacts when enabled", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-samples-"));

    const result = await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      jobId: "job-samples",
      evidence: {
        screenshots: false,
        har: false,
        consoleLogs: false,
        domSnapshot: false,
        browserTrace: false,
        video: false,
        requestResponseSamples: true,
      },
    });

    expect(result.evidence.map((artifact) => artifact.kind).sort()).toEqual(["request_sample", "response_sample"]);
    const responseSample = result.evidence.find((artifact) => artifact.kind === "response_sample");
    expect(responseSample).toBeDefined();
    expect(readFileSync(responseSample!.path, "utf8")).toContain("mock response body");
  });
});

function installPlaywrightMock(): void {
  playwrightMock.launch.mockImplementation(async () => ({
    newContext: async (options: any) => makeContext(options),
    close: vi.fn(async () => undefined),
  }));
}

function makeContext(options: any): any {
  return {
    route: vi.fn(async () => undefined),
    tracing: {
      start: vi.fn(async () => undefined),
      stop: vi.fn(async ({ path: tracePath }: { path: string }) => {
        writeFileSync(tracePath, "trace", "utf8");
      }),
    },
    newPage: vi.fn(async () => ({
      on: vi.fn(),
      goto: vi.fn(async () => makeResponse()),
      title: vi.fn(async () => "Mock page"),
      content: vi.fn(async () => "<html><body>mock</body></html>"),
      screenshot: vi.fn(async ({ path: screenshotPath }: { path: string }) => {
        writeFileSync(screenshotPath, "screenshot", "utf8");
      }),
      $$eval: vi.fn(async () => ["http://127.0.0.1:8080/docs"]),
      video: vi.fn(() => undefined),
    })),
    close: vi.fn(async () => {
      if (options.recordHar?.path) {
        writeFileSync(options.recordHar.path, "{}", "utf8");
      }
    }),
  };
}

function makeResponse(): any {
  return {
    url: () => "http://127.0.0.1:8080/",
    status: () => 200,
    statusText: () => "OK",
    headers: () => ({ "content-type": "text/html; charset=utf-8" }),
    allHeaders: async () => ({ "content-type": "text/html; charset=utf-8" }),
    text: async () => "<html>mock response body</html>",
    request: () => ({
      url: () => "http://127.0.0.1:8080/",
      method: () => "GET",
      resourceType: () => "document",
      headers: () => ({ accept: "text/html" }),
      allHeaders: async () => ({ accept: "text/html" }),
      postData: () => null,
    }),
  };
}
