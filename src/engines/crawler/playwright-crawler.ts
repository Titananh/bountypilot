import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BrowserContextOptions } from "playwright";
import type { EvidenceArtifact } from "../../types.js";
import { nowIso } from "../../utils/time.js";

export interface PlaywrightCrawlResult {
  url: string;
  title: string;
  evidence: EvidenceArtifact[];
  links: string[];
}

export interface PlaywrightEvidenceOptions {
  screenshots?: boolean;
  har?: boolean;
  consoleLogs?: boolean;
  domSnapshot?: boolean;
  browserTrace?: boolean;
  video?: boolean | "optional";
  requestResponseSamples?: boolean;
}

const MAX_SAMPLE_BODY_CHARS = 80_000;

export async function crawlWithPlaywright(input: {
  url: string;
  evidenceDir: string;
  jobId?: string;
  evidence?: PlaywrightEvidenceOptions;
  allowUrl?: (url: string) => boolean;
  onRequest?: (event: { url: string; method: string; allowed: boolean }) => void;
}): Promise<PlaywrightCrawlResult> {
  const capture = normalizeEvidenceOptions(input.evidence);
  const safeName = new URL(input.url).hostname.replace(/[^a-z0-9.-]/gi, "_");
  const runDir = path.join(input.evidenceDir, input.jobId ?? `crawl-${Date.now()}`, safeName);
  mkdirSync(runDir, { recursive: true });
  const screenshotPath = path.join(runDir, "screenshot.png");
  const domPath = path.join(runDir, "dom.html");
  const consolePath = path.join(runDir, "console.log");
  const harPath = path.join(runDir, "network.har");
  const tracePath = path.join(runDir, "trace.zip");
  const requestSamplePath = path.join(runDir, "request-sample.json");
  const responseSamplePath = path.join(runDir, "response-sample.json");

  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ headless: true });
  const contextOptions: BrowserContextOptions = {
    userAgent: "BountyPilot/0.1 playwright-crawler",
  };
  if (capture.har) {
    contextOptions.recordHar = { path: harPath, mode: "minimal" };
  }
  if (capture.video) {
    contextOptions.recordVideo = { dir: runDir };
  }

  const context = await browser.newContext(contextOptions);
  let pageVideoPath: string | undefined;
  try {
    if (capture.browserTrace) {
      await context.tracing.start({
        screenshots: capture.screenshots,
        snapshots: capture.domSnapshot,
        sources: false,
      });
    }
    await context.route("**/*", async (route) => {
      const request = route.request();
      const requestUrl = request.url();
      const allowed = input.allowUrl?.(requestUrl) ?? true;
      input.onRequest?.({ url: requestUrl, method: request.method(), allowed });
      if (!allowed) {
        await route.abort("blockedbyclient");
        return;
      }
      await route.continue();
    });
    const consoleMessages: string[] = [];
    const page = await context.newPage();
    if (capture.consoleLogs) {
      page.on("console", (message) => {
        consoleMessages.push(`[${message.type()}] ${message.text()}`);
      });
    }

    const mainResponse = await page.goto(input.url, { waitUntil: "domcontentloaded", timeout: 30000 });
    const title = await page.title();
    if (capture.requestResponseSamples && mainResponse) {
      const request = mainResponse.request();
      writeFileSync(
        requestSamplePath,
        `${JSON.stringify(
          {
            url: request.url(),
            method: request.method(),
            resourceType: request.resourceType(),
            headers: await request.allHeaders().catch(() => request.headers()),
            postData: request.postData(),
          },
          null,
          2,
        )}\n`,
        "utf8",
      );
      writeFileSync(
        responseSamplePath,
        `${JSON.stringify(
          {
            url: mainResponse.url(),
            status: mainResponse.status(),
            statusText: mainResponse.statusText(),
            headers: await mainResponse.allHeaders().catch(() => mainResponse.headers()),
            body: await responseBodySample(mainResponse),
          },
          null,
          2,
        )}\n`,
        "utf8",
      );
    }

    if (capture.screenshots) {
      await page.screenshot({ path: screenshotPath, fullPage: true });
    }
    if (capture.domSnapshot) {
      writeFileSync(domPath, await page.content(), "utf8");
    }
    if (capture.consoleLogs) {
      writeFileSync(consolePath, consoleMessages.join("\n"), "utf8");
    }

    const links = await page.$$eval("a[href]", (elements) =>
      elements
        .map((element) => (element as HTMLAnchorElement).href)
        .filter(Boolean),
    );

    if (capture.video) {
      pageVideoPath = await page.video()?.path();
    }
    if (capture.browserTrace) {
      await context.tracing.stop({ path: tracePath });
    }
    await context.close();
    await browser.close();

    const createdAt = nowIso();
    const evidence: EvidenceArtifact[] = [];
    if (capture.screenshots) {
      evidence.push({
        id: `evidence-screenshot-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "screenshot",
        sourceUrl: input.url,
        path: screenshotPath,
        createdAt,
      });
    }
    if (capture.domSnapshot) {
      evidence.push({
        id: `evidence-dom-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "dom_snapshot",
        sourceUrl: input.url,
        path: domPath,
        createdAt,
      });
    }
    if (capture.consoleLogs) {
      evidence.push({
        id: `evidence-console-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "console_log",
        sourceUrl: input.url,
        path: consolePath,
        createdAt,
      });
    }
    if (capture.har && existsSync(harPath)) {
      evidence.push({
        id: `evidence-har-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "har",
        sourceUrl: input.url,
        path: harPath,
        createdAt,
      });
    }
    if (capture.requestResponseSamples && existsSync(requestSamplePath)) {
      evidence.push({
        id: `evidence-request-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "request_sample",
        sourceUrl: input.url,
        path: requestSamplePath,
        createdAt,
      });
    }
    if (capture.requestResponseSamples && existsSync(responseSamplePath)) {
      evidence.push({
        id: `evidence-response-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "response_sample",
        sourceUrl: input.url,
        path: responseSamplePath,
        createdAt,
      });
    }
    if (capture.browserTrace && existsSync(tracePath)) {
      evidence.push({
        id: `evidence-trace-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "browser_trace",
        sourceUrl: input.url,
        path: tracePath,
        createdAt,
      });
    }
    if (capture.video && pageVideoPath && existsSync(pageVideoPath)) {
      evidence.push({
        id: `evidence-video-${Date.now()}`,
        jobId: input.jobId,
        adapterName: "playwright",
        kind: "video",
        sourceUrl: input.url,
        path: pageVideoPath,
        createdAt,
      });
    }

    return {
      url: input.url,
      title,
      links,
      evidence,
    };
  } catch (error) {
    await context.close().catch(() => undefined);
    await browser.close().catch(() => undefined);
    throw error;
  }
}

function normalizeEvidenceOptions(options: PlaywrightEvidenceOptions | undefined): Required<PlaywrightEvidenceOptions> {
  return {
    screenshots: options?.screenshots ?? true,
    har: options?.har ?? false,
    consoleLogs: options?.consoleLogs ?? true,
    domSnapshot: options?.domSnapshot ?? true,
    browserTrace: options?.browserTrace ?? false,
    video: options?.video === true,
    requestResponseSamples: options?.requestResponseSamples ?? false,
  };
}

async function responseBodySample(response: {
  headers: () => Record<string, string>;
  text: () => Promise<string>;
}): Promise<{ captured: boolean; truncated?: boolean; text?: string; reason?: string }> {
  const headers = response.headers();
  const contentType = headers["content-type"] ?? headers["Content-Type"] ?? "";
  if (contentType && !/^(?:text\/|application\/(?:json|xml|javascript|x-www-form-urlencoded)\b)/i.test(contentType)) {
    return { captured: false, reason: `Skipped non-text content-type: ${contentType}` };
  }
  try {
    const text = await response.text();
    if (text.length > MAX_SAMPLE_BODY_CHARS) {
      return { captured: true, truncated: true, text: text.slice(0, MAX_SAMPLE_BODY_CHARS) };
    }
    return { captured: true, truncated: false, text };
  } catch (error) {
    return { captured: false, reason: error instanceof Error ? error.message : String(error) };
  }
}
