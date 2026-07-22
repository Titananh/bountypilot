import { existsSync, mkdirSync, readFileSync, rmSync, rmdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BrowserContextOptions } from "playwright";
import type { EvidenceArtifact } from "../../types.js";
import { nowIso } from "../../utils/time.js";
import { BountyPilotError } from "../../utils/errors.js";
import { isSensitiveHeaderName, maskSecrets, redactHttpHeaders } from "../../utils/secrets.js";
import { resolveNetworkTarget } from "../../core/http/network-address-policy.js";

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

export interface PlaywrightRequestAuthorityInput {
  url: string;
  method: string;
  resourceType: string;
}

export interface PlaywrightRequestAuthorityDecision {
  allowed: boolean;
  reason?: string;
}

export interface PlaywrightRequestAuditEvent extends PlaywrightRequestAuthorityInput {
  transport: "http" | "websocket";
  allowed: boolean;
  reason: string;
}

const MAX_SAMPLE_BODY_CHARS = 80_000;
const SAFE_BROWSER_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export async function crawlWithPlaywright(input: {
  url: string;
  evidenceDir: string;
  jobId?: string;
  evidence?: PlaywrightEvidenceOptions;
  /**
   * Mandatory asynchronous authority boundary for every safe HTTP request.
   * Callers are responsible for applying both current scope and rate-limit
   * authority before returning an allow decision.
   */
  authorizeRequest: (
    request: PlaywrightRequestAuthorityInput,
  ) => Promise<boolean | PlaywrightRequestAuthorityDecision>;
  /** Mandatory audit sink. It runs before an allowed request is continued. */
  onRequest: (event: PlaywrightRequestAuditEvent) => void | Promise<void>;
  /**
   * Optional lifecycle marker invoked only after authority and audit gates
   * pass, immediately before the first allowed request reaches the network.
   */
  beforeRequest?: (request: PlaywrightRequestAuthorityInput) => void | Promise<void>;
}): Promise<PlaywrightCrawlResult> {
  if (typeof input.authorizeRequest !== "function") {
    throw new BountyPilotError(
      "Playwright crawling requires an asynchronous per-request authority callback.",
      "PLAYWRIGHT_SCOPE_CONTEXT_REQUIRED",
    );
  }
  if (typeof input.onRequest !== "function") {
    throw new BountyPilotError(
      "Playwright crawling requires a per-request audit callback.",
      "PLAYWRIGHT_AUDIT_CONTEXT_REQUIRED",
    );
  }
  const capture = normalizeEvidenceOptions(input.evidence);
  const safeName = new URL(input.url).hostname.replace(/[^a-z0-9.-]/gi, "_");
  const initialHostname = new URL(input.url).hostname.toLowerCase();
  const runDir = path.join(input.evidenceDir, input.jobId ?? `crawl-${Date.now()}`, safeName);
  mkdirSync(runDir, { recursive: true });
  const screenshotPath = path.join(runDir, "screenshot.png");
  const domPath = path.join(runDir, "dom.html");
  const consolePath = path.join(runDir, "console.log");
  const harPath = path.join(runDir, "network.har");
  const tracePath = path.join(runDir, "trace.zip");
  const requestSamplePath = path.join(runDir, "request-sample.json");
  const responseSamplePath = path.join(runDir, "response-sample.json");

  let initialNetworkTarget;
  try {
    initialNetworkTarget = await resolveNetworkTarget(input.url);
  } catch (error) {
    rmSync(runDir, { recursive: true, force: true });
    throw error;
  }

  const { chromium } = await import("playwright");
    const browser = await chromium.launch({
      headless: true,
      // The crawler is an evidence collector, not a general browser. Disable
      // browser-side network primitives that do not pass through Playwright's
      // HTTP route hook (WebRTC/WebTransport/speculative preconnect).
      args: [
        "--disable-webrtc",
        "--dns-prefetch-disable",
        "--disable-background-networking",
        "--no-pings",
        "--disable-features=WebRtcHideLocalIpsWithMdns,WebTransport,SpeculativePreconnect,PrefetchPrivacyChanges",
        ...(initialNetworkTarget.explicitLocal
          ? []
          : [`--host-resolver-rules=MAP ${initialNetworkTarget.hostname} ${formatHostResolverAddress(initialNetworkTarget.address)}`]),
      ],
    });
    const contextOptions: BrowserContextOptions = {
      userAgent: "BountyPilot/0.2 playwright-crawler",
      serviceWorkers: "block",
      javaScriptEnabled: false,
    };
  if (capture.har) {
    contextOptions.recordHar = { path: harPath, mode: "minimal" };
  }
  // Video and tracing are intentionally disabled at this authority seam.
  // They can contain pixels, DOM snapshots, cookies, and request payloads
  // that cannot be reliably redacted after the fact (trace.zip is a binary
  // archive). Callers may still request them in a program profile, but the
  // production crawler never creates those raw artifacts.

  const context = await browser.newContext(contextOptions);
  let pageVideoPath: string | undefined;
  try {
    // browserTrace is normalized to false below; keep the branch absent from
    // the runtime path so a future Playwright default cannot re-enable raw
    // trace capture accidentally.
    await context.route("**/*", async (route) => {
      const request = route.request();
      const authorityInput: PlaywrightRequestAuthorityInput = {
        url: request.url(),
        method: request.method().toUpperCase(),
        resourceType: request.resourceType(),
      };
      let requestHostname: string;
      try {
        requestHostname = new URL(authorityInput.url).hostname.toLowerCase();
      } catch {
        await blockHttpRequest(route, input.onRequest, {
          ...authorityInput,
          transport: "http",
          allowed: false,
          reason: "Browser request URL is invalid",
        });
        return;
      }
      // Chromium receives a fixed host-resolver mapping for the initial
      // target. Do not allow a page to open a different hostname in the same
      // context: that would bypass the pinned mapping and make DNS rebinding
      // possible through an in-scope wildcard. The workflow can enqueue a
      // separate action for each authorized host.
      if (requestHostname !== initialHostname) {
        await blockHttpRequest(route, input.onRequest, {
          ...authorityInput,
          transport: "http",
          allowed: false,
          reason: "Browser subresource hostname differs from the pinned target host",
        });
        return;
      }
      if (!SAFE_BROWSER_METHODS.has(authorityInput.method)) {
        await blockHttpRequest(route, input.onRequest, {
          ...authorityInput,
          transport: "http",
          allowed: false,
          reason: `Browser request method ${authorityInput.method} is not allowed`,
        });
        return;
      }

      let decision: PlaywrightRequestAuthorityDecision;
      try {
        const pendingDecision = input.authorizeRequest(authorityInput);
        if (!isPromiseLike(pendingDecision)) throw requestAuthorityFailed();
        decision = normalizeAuthorityDecision(await pendingDecision);
      } catch {
        await blockHttpRequest(route, input.onRequest, {
          ...authorityInput,
          transport: "http",
          allowed: false,
          reason: "Browser request authority check failed",
        });
        throw requestAuthorityFailed();
      }

      const auditEvent: PlaywrightRequestAuditEvent = {
        ...authorityInput,
        transport: "http",
        allowed: decision.allowed,
        reason:
          decision.reason ??
          (decision.allowed
            ? "Request authorized by the per-request authority hook"
            : "Request blocked by the per-request authority hook"),
      };
      if (!decision.allowed) {
        await blockHttpRequest(route, input.onRequest, auditEvent);
        return;
      }

      try {
        await resolveNetworkTarget(authorityInput.url);
      } catch (error) {
        const reason = error instanceof BountyPilotError ? error.message : "Network address policy blocked request";
        await blockHttpRequest(route, input.onRequest, {
          ...auditEvent,
          allowed: false,
          reason,
        });
        return;
      }

      try {
        await input.onRequest(auditEvent);
        await input.beforeRequest?.(authorityInput);
      } catch {
        // An audit or lifecycle sink is part of the pre-effect authority
        // boundary. If it fails, abort the route and never continue it.
        await route.abort("blockedbyclient");
        throw requestAuthorityFailed();
      }
      await route.continue();
    });
    await context.routeWebSocket("**/*", async (webSocket) => {
      const auditEvent: PlaywrightRequestAuditEvent = {
        url: webSocket.url(),
        method: "WEBSOCKET",
        resourceType: "websocket",
        transport: "websocket",
        allowed: false,
        reason: "WebSocket connections are disabled for Playwright crawling",
      };
      try {
        await input.onRequest(auditEvent);
      } finally {
        // A routed WebSocket does not connect unless connectToServer() is
        // called. Closing it here keeps the block entirely pre-network.
        await webSocket.close({ code: 1008, reason: "Blocked by browser policy" });
      }
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
            headers: redactHttpHeaders(await request.allHeaders().catch(() => request.headers())),
            // Request bodies often contain credentials or CSRF material. Keep
            // only the fact that a body existed, never its contents.
            postData: request.postData() === null
              ? null
              : { captured: false, reason: "Request body omitted for secret safety" },
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
            headers: redactHttpHeaders(await mainResponse.allHeaders().catch(() => mainResponse.headers())),
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
      writeFileSync(domPath, maskSecrets(await page.content()), "utf8");
    }
    if (capture.consoleLogs) {
      writeFileSync(consolePath, maskSecrets(consoleMessages.join("\n")), "utf8");
    }

    const links = await page.$$eval("a[href]", (elements) =>
      elements
        .map((element) => (element as HTMLAnchorElement).href)
        .filter(Boolean),
    );

    // No trace/video is ever produced; see normalizeEvidenceOptions.
    await context.close();
    await browser.close();

    if (capture.har && existsSync(harPath)) {
      sanitizeHarFile(harPath);
    }

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

    return {
      url: input.url,
      title,
      links,
      evidence,
    };
  } catch (error) {
    await context.close().catch(() => undefined);
    await browser.close().catch(() => undefined);
    // A failed crawl must not leave an unregistered raw HAR/DOM/console file
    // in the evidence tree. Registered success artifacts are sanitized before
    // returning; failed runs are discarded as one unit.
    rmSync(runDir, { recursive: true, force: true });
    removeEmptyParentDirectories(runDir, path.resolve(input.evidenceDir));
    throw error;
  }
}

function normalizeEvidenceOptions(options: PlaywrightEvidenceOptions | undefined): Required<PlaywrightEvidenceOptions> {
  return {
    screenshots: options?.screenshots ?? true,
    har: options?.har ?? false,
    consoleLogs: options?.consoleLogs ?? true,
    domSnapshot: options?.domSnapshot ?? true,
    // Binary traces/videos can retain cookies, headers, and page pixels in a
    // form that cannot be proven safe by the local redaction pipeline.
    browserTrace: false,
    video: false,
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
    const text = maskSecrets(await response.text());
    if (text.length > MAX_SAMPLE_BODY_CHARS) {
      return { captured: true, truncated: true, text: text.slice(0, MAX_SAMPLE_BODY_CHARS) };
    }
    return { captured: true, truncated: false, text };
  } catch (error) {
    return { captured: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Sanitize a Playwright HAR after context.close() has flushed it. HAR is a
 * structured format, so plain-text regex masking alone is insufficient for
 * cookie arrays and header objects. If parsing or rewriting fails, fail closed
 * and let the crawl catch handler remove the entire run directory.
 */
function sanitizeHarFile(filePath: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
  } catch {
    throw new BountyPilotError("HAR evidence could not be safely redacted", "EVIDENCE_REDACTION_FAILED");
  }
  const sanitized = sanitizeHarValue(parsed);
  try {
    writeFileSync(filePath, `${JSON.stringify(sanitized, null, 2)}\n`, "utf8");
  } catch {
    throw new BountyPilotError("HAR evidence could not be safely rewritten", "EVIDENCE_REDACTION_FAILED");
  }
}

function sanitizeHarValue(value: unknown, key?: string): unknown {
  if (typeof value === "string") return maskSecrets(value);
  if (Array.isArray(value)) return value.map((item) => sanitizeHarValue(item, key));
  if (!value || typeof value !== "object") return value;

  const record = value as Record<string, unknown>;
  const entries = Object.entries(record).map(([entryKey, entryValue]) => {
    const normalized = entryKey.toLowerCase().replace(/[_-]/g, "");
    if (normalized === "postdata" || normalized === "requestbody") {
      return [entryKey, { captured: false, reason: "Request body omitted for secret safety" }];
    }
    if (normalized === "headers" || normalized === "requestheaders" || normalized === "responseheaders") {
      return [entryKey, sanitizeHarHeaders(entryValue)];
    }
    if (normalized === "cookies" || normalized === "requestcookies" || normalized === "responsecookies") {
      return [entryKey, sanitizeHarCookies(entryValue)];
    }
    if (normalized === "querystring" || normalized === "params" || normalized === "formparams") {
      return [entryKey, sanitizeHarNameValuePairs(entryValue)];
    }
    if (/^(?:authorization|cookie|setcookie|token|secret|password|csrf|xsrf|session|jwt)$/i.test(normalized)) {
      return [entryKey, "[REDACTED]"];
    }
    return [entryKey, sanitizeHarValue(entryValue, entryKey)];
  });
  return Object.fromEntries(entries);
}

function sanitizeHarHeaders(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (!item || typeof item !== "object") return sanitizeHarValue(item);
      const header = item as Record<string, unknown>;
      const name = typeof header.name === "string" ? header.name : "";
      return {
        ...header,
        value: isSensitiveHeaderName(name)
          ? "[REDACTED]"
          : maskSecrets(typeof header.value === "string" ? header.value : String(header.value ?? "")),
      };
    });
  }
  if (value && typeof value === "object") {
    return redactHttpHeaders(
      Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([name, headerValue]) => [name, String(headerValue ?? "")]),
      ),
    );
  }
  return sanitizeHarValue(value);
}

function sanitizeHarCookies(value: unknown): unknown {
  if (!Array.isArray(value)) return sanitizeHarValue(value);
  return value.map((item) => {
    if (!item || typeof item !== "object") return sanitizeHarValue(item);
    const cookie = item as Record<string, unknown>;
    return {
      ...cookie,
      ...(Object.prototype.hasOwnProperty.call(cookie, "value") ? { value: "[REDACTED]" } : {}),
      ...(Object.prototype.hasOwnProperty.call(cookie, "name") ? { name: maskSecrets(String(cookie.name)) } : {}),
    };
  });
}

function sanitizeHarNameValuePairs(value: unknown): unknown {
  if (!Array.isArray(value)) return sanitizeHarValue(value);
  return value.map((item) => {
    if (!item || typeof item !== "object") return sanitizeHarValue(item);
    const pair = item as Record<string, unknown>;
    const name = typeof pair.name === "string" ? pair.name : "";
    return {
      ...pair,
      ...(Object.prototype.hasOwnProperty.call(pair, "value")
        ? { value: isSensitiveHeaderName(name) || /(?:token|secret|password|session|csrf|xsrf|key|auth)/i.test(name)
          ? "[REDACTED]"
          : maskSecrets(String(pair.value ?? "")) }
        : {}),
    };
  });
}

function formatHostResolverAddress(address: string): string {
  return address.includes(":") ? `[${address}]` : address;
}

function removeEmptyParentDirectories(startPath: string, stopPath: string): void {
  const boundary = path.resolve(stopPath);
  let current = path.resolve(path.dirname(startPath));
  while (current !== boundary && current.startsWith(`${boundary}${path.sep}`)) {
    try {
      // Remove only an empty directory; a sibling host/run is never touched.
      rmdirSync(current);
    } catch {
      break;
    }
    current = path.dirname(current);
  }
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

function normalizeAuthorityDecision(
  value: boolean | PlaywrightRequestAuthorityDecision,
): PlaywrightRequestAuthorityDecision {
  if (typeof value === "boolean") return { allowed: value };
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.allowed !== "boolean" ||
    (value.reason !== undefined && typeof value.reason !== "string")
  ) {
    throw requestAuthorityFailed();
  }
  return {
    allowed: value.allowed,
    ...(value.reason !== undefined ? { reason: value.reason } : {}),
  };
}

async function blockHttpRequest(
  route: { abort: (errorCode?: string) => Promise<void> },
  audit: (event: PlaywrightRequestAuditEvent) => void | Promise<void>,
  event: PlaywrightRequestAuditEvent,
): Promise<void> {
  try {
    await audit(event);
  } finally {
    await route.abort("blockedbyclient");
  }
}

function requestAuthorityFailed(): BountyPilotError {
  return new BountyPilotError(
    "Playwright request authority could not be established.",
    "PLAYWRIGHT_REQUEST_AUTHORITY_FAILED",
  );
}
