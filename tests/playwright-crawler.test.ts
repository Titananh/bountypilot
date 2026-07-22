import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { crawlWithPlaywright } from "../src/engines/crawler/playwright-crawler.js";

const playwrightMock = vi.hoisted(() => ({
  launch: vi.fn(),
  requests: [] as Array<{ url: string; method: string; resourceType: string }>,
  secretSamples: false,
  lastContext: undefined as any,
}));

vi.mock("playwright", () => ({
  chromium: {
    launch: playwrightMock.launch,
  },
}));

describe("crawlWithPlaywright evidence flags", () => {
  beforeEach(() => {
    playwrightMock.launch.mockReset();
    playwrightMock.requests = [
      { url: "http://127.0.0.1:8080/", method: "GET", resourceType: "document" },
    ];
    playwrightMock.secretSamples = false;
    playwrightMock.lastContext = undefined;
    installPlaywrightMock();
  });

  it("does not write optional artifacts when evidence flags are disabled", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-flags-"));

    const result = await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      jobId: "job-disabled",
      authorizeRequest: async ({ url }) => ({
        allowed: url.startsWith("http://127.0.0.1:8080"),
      }),
      onRequest: vi.fn(),
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

  it("sanitizes HAR and refuses binary trace/video artifacts", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-trace-"));

    const result = await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      jobId: "job-trace",
      authorizeRequest: async ({ url }) => ({
        allowed: url.startsWith("http://127.0.0.1:8080"),
      }),
      onRequest: vi.fn(),
      evidence: {
        screenshots: false,
        har: true,
        consoleLogs: false,
        domSnapshot: false,
        browserTrace: true,
        video: "optional",
      },
    });

    expect(result.evidence.map((artifact) => artifact.kind).sort()).toEqual(["har"]);
    for (const artifact of result.evidence) {
      expect(existsSync(artifact.path)).toBe(true);
    }
    expect(playwrightMock.lastContext.tracing.start).not.toHaveBeenCalled();
    expect(playwrightMock.lastContext.lastOptions.recordVideo).toBeUndefined();
  });

  it("creates bounded request and response sample artifacts when enabled", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-samples-"));

    const result = await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      jobId: "job-samples",
      authorizeRequest: async ({ url }) => ({
        allowed: url.startsWith("http://127.0.0.1:8080"),
      }),
      onRequest: vi.fn(),
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

  it("redacts browser request and response credentials before writing samples", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-redaction-"));
    playwrightMock.secretSamples = true;

    const result = await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      jobId: "job-redaction",
      authorizeRequest: async ({ url }) => ({ allowed: url.startsWith("http://127.0.0.1:8080") }),
      onRequest: vi.fn(),
      evidence: { screenshots: false, domSnapshot: false, consoleLogs: false, har: true, requestResponseSamples: true },
    });

    const requestSample = result.evidence.find((artifact) => artifact.kind === "request_sample");
    const responseSample = result.evidence.find((artifact) => artifact.kind === "response_sample");
    const harArtifact = result.evidence.find((artifact) => artifact.kind === "har");
    expect(requestSample).toBeDefined();
    expect(responseSample).toBeDefined();
    expect(harArtifact).toBeDefined();
    const requestText = readFileSync(requestSample!.path, "utf8");
    const responseText = readFileSync(responseSample!.path, "utf8");
    const harText = readFileSync(harArtifact!.path, "utf8");
    expect(requestText).not.toContain("request-secret");
    expect(requestText).not.toContain("request-cookie-secret");
    expect(responseText).not.toContain("response-secret");
    expect(responseText).not.toContain("server-secret");
    expect(responseText).not.toContain("body-secret");
    expect(harText).not.toContain("har-cookie-secret");
    expect(harText).not.toContain("har-token-secret");
    expect(harText).not.toContain("har-post-secret");
  });

  it("removes the complete evidence run directory after a crawl failure", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-failure-"));
    playwrightMock.launch.mockImplementationOnce(async () => ({
      newContext: async (options: any) => {
        const context = makeContext(options);
        context.newPage = vi.fn(async () => ({
          on: vi.fn(),
          goto: vi.fn(async () => {
            writeFileSync(path.join(root, "job-failure", "127.0.0.1", "raw-secret.txt"), "cookie=raw-secret", "utf8");
            throw new Error("mock navigation failure");
          }),
        }));
        playwrightMock.lastContext = context;
        return context;
      },
      close: vi.fn(async () => undefined),
    }));

    await expect(
      crawlWithPlaywright({
        url: "http://127.0.0.1:8080/",
        evidenceDir: root,
        jobId: "job-failure",
        authorizeRequest: async () => ({ allowed: true }),
        onRequest: vi.fn(),
        evidence: { screenshots: false, domSnapshot: false, consoleLogs: false, har: true },
      }),
    ).rejects.toThrow("mock navigation failure");
    expect(existsSync(path.join(root, "job-failure"))).toBe(false);
  });

  it("blocks unsafe HTTP methods before the authority hook and audits the block", async () => {
    playwrightMock.requests = [
      { url: "http://127.0.0.1:8080/write", method: "POST", resourceType: "fetch" },
    ];
    const authorizeRequest = vi.fn(async () => ({ allowed: true }));
    const onRequest = vi.fn();
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-method-"));

    await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      authorizeRequest,
      onRequest,
      evidence: { screenshots: false, domSnapshot: false, consoleLogs: false },
    });

    expect(authorizeRequest).not.toHaveBeenCalled();
    expect(onRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        allowed: false,
        transport: "http",
      }),
    );
  });

  it("uses an asynchronous authority hook for every safe request and blocks WebSockets", async () => {
    playwrightMock.requests = [
      { url: "http://127.0.0.1:8080/", method: "GET", resourceType: "document" },
      { url: "http://127.0.0.1:8080/head", method: "HEAD", resourceType: "fetch" },
      { url: "http://127.0.0.1:8080/options", method: "OPTIONS", resourceType: "fetch" },
    ];
    const calls: string[] = [];
    const authorizeRequest = vi.fn(async ({ method, url }) => {
      calls.push(`${method}:${url}`);
      await Promise.resolve();
      return { allowed: true, reason: "test authority" };
    });
    const onRequest = vi.fn();
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-crawler-boundary-"));

    await crawlWithPlaywright({
      url: "http://127.0.0.1:8080/",
      evidenceDir: root,
      authorizeRequest,
      onRequest,
      evidence: { screenshots: false, domSnapshot: false, consoleLogs: false },
    });

    expect(calls).toHaveLength(3);
    expect(playwrightMock.lastContext.routeWebSocket).toHaveBeenCalledWith("**/*", expect.any(Function));
    expect(playwrightMock.lastContext.lastOptions?.serviceWorkers).toBe("block");
    expect(playwrightMock.lastContext.lastOptions?.javaScriptEnabled).toBe(false);
    expect(playwrightMock.launch).toHaveBeenCalledWith(expect.objectContaining({
      args: expect.arrayContaining(["--disable-webrtc"]),
    }));

    const close = vi.fn(async () => undefined);
    await playwrightMock.lastContext.webSocketHandler({
      url: () => "wss://127.0.0.1:8080/socket",
      close,
    });
    expect(close).toHaveBeenCalledWith(expect.objectContaining({ code: 1008 }));
    expect(onRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        transport: "websocket",
        allowed: false,
      }),
    );
  });
});

function installPlaywrightMock(): void {
  playwrightMock.launch.mockImplementation(async () => ({
    newContext: async (options: any) => {
      const context = makeContext(options);
      playwrightMock.lastContext = context;
      return context;
    },
    close: vi.fn(async () => undefined),
  }));
}

function makeContext(options: any): any {
  const context: any = {
    lastOptions: options,
    routeHandler: undefined,
    webSocketHandler: undefined,
    route: vi.fn(async (_pattern: string, handler: any) => {
      context.routeHandler = handler;
    }),
    routeWebSocket: vi.fn(async (_pattern: string, handler: any) => {
      context.webSocketHandler = handler;
    }),
    tracing: {
      start: vi.fn(async () => undefined),
      stop: vi.fn(async ({ path: tracePath }: { path: string }) => {
        writeFileSync(tracePath, "trace", "utf8");
      }),
    },
    newPage: vi.fn(async () => ({
      on: vi.fn(),
      goto: vi.fn(async () => {
        for (const request of playwrightMock.requests) {
          const state = { continued: false, aborted: false };
          await context.routeHandler?.({
            request: () => ({
              url: () => request.url,
              method: () => request.method,
              resourceType: () => request.resourceType,
            }),
            url: () => request.url,
            method: () => request.method,
            resourceType: () => request.resourceType,
            continue: vi.fn(async () => {
              state.continued = true;
            }),
            abort: vi.fn(async () => {
              state.aborted = true;
            }),
          });
        }
        return makeResponse();
      }),
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
        writeFileSync(
          options.recordHar.path,
          playwrightMock.secretSamples
            ? JSON.stringify({
                log: {
                  entries: [{
                    request: {
                      headers: [{ name: "Cookie", value: "sid=har-cookie-secret" }],
                      queryString: [{ name: "token", value: "har-token-secret" }],
                      postData: { text: "password=har-post-secret" },
                    },
                  }],
                },
              })
            : "{}",
          "utf8",
        );
      }
    }),
  };
  return context;
}

function makeResponse(): any {
  const requestHeaders = playwrightMock.secretSamples
    ? {
        accept: "text/html",
        authorization: "Bearer request-secret",
        cookie: "session=request-cookie-secret",
      }
    : { accept: "text/html" };
  const responseHeaders = playwrightMock.secretSamples
    ? {
        "content-type": "text/plain",
        "set-cookie": "session=server-secret; HttpOnly",
        authorization: "Bearer response-secret",
      }
    : { "content-type": "text/html; charset=utf-8" };
  return {
    url: () => "http://127.0.0.1:8080/",
    status: () => 200,
    statusText: () => "OK",
    headers: () => responseHeaders,
    allHeaders: async () => responseHeaders,
    text: async () => (playwrightMock.secretSamples ? "authorization: bearer body-secret\n" : "<html>mock response body</html>"),
    request: () => ({
      url: () => "http://127.0.0.1:8080/",
      method: () => "GET",
      resourceType: () => "document",
      headers: () => requestHeaders,
      allHeaders: async () => requestHeaders,
      postData: () => null,
    }),
  };
}
