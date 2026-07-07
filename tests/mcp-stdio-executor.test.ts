import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ActionQueue } from "../src/core/actions/action-queue.js";
import { ActionReviewStore } from "../src/core/actions/action-review-store.js";
import { PolicyGate } from "../src/core/policy/policy-gate.js";
import { RateLimiter } from "../src/core/rate-limit/rate-limiter.js";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import { ensureProgramWorkspace } from "../src/core/workspace.js";
import { JobManager } from "../src/core/jobs/job-manager.js";
import { WorkflowEventStore } from "../src/core/jobs/workflow-event-store.js";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { EvidenceStore } from "../src/stores/evidence-store.js";
import { FindingCandidateStore } from "../src/stores/finding-candidate-store.js";
import { FindingStore } from "../src/stores/finding-store.js";
import { CrawlGraphStore } from "../src/stores/crawl-graph-store.js";
import { McpStdioExecutor } from "../src/integrations/mcp/mcp-stdio-executor.js";
import { ActionExecutor } from "../src/workflows/action-executor.js";
import { createExecutableApprovalStore } from "../src/utils/local-process-policy.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import type { Runtime } from "../src/cli/runtime.js";

describe("McpStdioExecutor", () => {
  it("executes an explicitly enabled stdio MCP tool call", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-"));
    const serverScript = writeFakeMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-test", "safe", target);

    const result = await new McpStdioExecutor(runtime).executeCall({
      server: "playwright-mcp",
      tool: "browser_navigate",
      mode: "safe",
      target,
      arguments: { url: target },
      jobId: job.id,
    });

    expect(result.evidenceCreated).toBe(1);
    const artifact = runtime.evidence.list().find((item) => item.adapterName === "playwright_mcp");
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.execute).toBe(true);
    expect(content.commandSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(content.envKeys).not.toContain("PATH");
    expect(content.envKeys).not.toContain("HOME");
    expect(content.call.result.content[0].text).toContain("browser_navigate");
    expect(content.call.result.content[0].text).toContain(target);
  });

  it("captures bounded redacted MCP notification and progress stream events", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-events-"));
    const serverScript = writeEventfulMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-events-test", "safe", target);

    const result = await new McpStdioExecutor(runtime).executeCall({
      server: "playwright-mcp",
      tool: "browser_navigate",
      mode: "safe",
      target,
      arguments: { url: target },
      jobId: job.id,
    });

    expect(result.evidenceCreated).toBe(1);
    const artifact = runtime.evidence.list().find((item) => item.jobId === job.id);
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.streamEvents).toMatchObject({
      total: 5,
      captured: 5,
      dropped: 0,
      truncated: false,
    });
    expect(content.streamEvents.events.map((event: any) => event.kind)).toEqual(
      expect.arrayContaining(["response", "request", "log", "progress"]),
    );
    expect(content.streamEvents.events.map((event: any) => event.method)).toEqual(
      expect.arrayContaining(["notifications/message", "notifications/progress"]),
    );
    expect(JSON.stringify(content.streamEvents)).toContain("[REDACTED]");
    expect(JSON.stringify(content.streamEvents)).not.toContain("stream-secret");
    expect(runtime.events.list(job.id)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          phase: "mcp-stream",
          status: "completed",
          message: expect.stringContaining("MCP stream captured 5 stdout event"),
          metadata: expect.objectContaining({
            total: 5,
            methods: expect.arrayContaining(["notifications/message", "notifications/progress"]),
          }),
        }),
      ]),
    );
  });

  it("bounds and redacts noisy MCP stream transcripts", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-noisy-events-"));
    const serverScript = writeNoisyMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-noisy-events-test", "safe", target);

    const result = await new McpStdioExecutor(runtime).executeCall({
      server: "playwright-mcp",
      tool: "browser_navigate",
      mode: "safe",
      target,
      arguments: { url: target },
      jobId: job.id,
    });

    expect(result.evidenceCreated).toBe(1);
    const artifact = runtime.evidence.list().find((item) => item.jobId === job.id);
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.streamEvents.total).toBe(127);
    expect(content.streamEvents.captured).toBe(120);
    expect(content.streamEvents.dropped).toBe(7);
    expect(content.streamEvents.truncated).toBe(true);
    expect(content.streamEvents.events.every((event: any) => event.preview.length <= 2_048)).toBe(true);
    expect(content.streamEvents.events.some((event: any) => event.previewTruncated)).toBe(true);
    expect(JSON.stringify(content.streamEvents)).toContain("[REDACTED]");
    expect(JSON.stringify(content.streamEvents)).not.toContain("noisy-stream-secret");
  });

  it("executes a pinned MCP package entrypoint through an approved node executable", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-package-"));
    const serverScript = writeFakeMcpPackage(root, "fake-mcp-runner", "1.0.0", "dist/server.mjs");
    const runtime = createTestRuntime(root, serverScript, true, false, {
      package: "fake-mcp-runner",
      package_version: "1.0.0",
      entrypoint: "dist/server.mjs",
    });
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-package-test", "safe", target);

    const result = await new McpStdioExecutor(runtime).executeCall({
      server: "playwright-mcp",
      tool: "browser_navigate",
      mode: "safe",
      target,
      arguments: { url: target },
      jobId: job.id,
    });

    expect(result.evidenceCreated).toBe(1);
    const artifact = runtime.evidence.list().find((item) => item.adapterName === "playwright_mcp");
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.command).toBe(realpathSync.native(process.execPath));
    expect(content.package).toMatchObject({
      name: "fake-mcp-runner",
      version: "1.0.0",
      entrypoint: realpathSync.native(serverScript),
    });
    expect(content.package.entrypointSha256).toBe(sha256File(serverScript));
    expect(content.package.packageJsonSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(content.args[0]).toBe(realpathSync.native(serverScript));
    expect(content.call.result.content[0].text).toContain("browser_navigate");
  });

  it("refuses pinned MCP package entrypoints when the entrypoint hash drifts", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-package-drift-"));
    const serverScript = writeFakeMcpPackage(root, "fake-mcp-runner", "1.0.0", "dist/server.mjs");
    const runtime = createTestRuntime(root, serverScript, true, false, {
      package: "fake-mcp-runner",
      package_version: "1.0.0",
      entrypoint: "dist/server.mjs",
      entrypoint_sha256: sha256File(serverScript),
    });
    writeFileSync(serverScript, "console.log('changed');\n", "utf8");
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-package-drift-test", "safe", target);

    await expect(
      new McpStdioExecutor(runtime).executeCall({
        server: "playwright-mcp",
        tool: "browser_navigate",
        mode: "safe",
        target,
        arguments: { url: target },
        jobId: job.id,
      }),
    ).rejects.toMatchObject({ code: "PACKAGE_ENTRYPOINT_HASH_MISMATCH" });

    expect(runtime.evidence.list().filter((item) => item.jobId === job.id)).toHaveLength(0);
  });

  it("blocks MCP call arguments that override an in-scope target with an out-of-scope URL", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-scope-"));
    const serverScript = writeFakeMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-scope-test", "safe", target);

    await expect(
      new McpStdioExecutor(runtime).executeCall({
        server: "playwright-mcp",
        tool: "browser_navigate",
        mode: "safe",
        target,
        arguments: { url: "https://evil.example/" },
        jobId: job.id,
      }),
    ).rejects.toThrow("Target is not explicitly in scope");

    expect(runtime.evidence.list().filter((item) => item.jobId === job.id)).toHaveLength(0);
  });

  it("accepts scoped MCP snapshot postconditions with an in-scope current URL", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-snapshot-scope-"));
    const serverScript = writeFakeMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-snapshot-scope-test", "safe", target);

    const result = await new McpStdioExecutor(runtime).executeCall({
      server: "playwright-mcp",
      tool: "browser_snapshot",
      mode: "safe",
      target,
      jobId: job.id,
    });

    expect(result.evidenceCreated).toBe(1);
    const artifact = runtime.evidence.list().find((item) => item.jobId === job.id);
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.postcondition).toMatchObject({
      kind: "current_or_final_url_in_scope",
      ok: true,
      evidenceUsable: true,
      url: target,
    });
  });

  it("fails closed when an MCP snapshot postcondition leaves scope", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-snapshot-outscope-"));
    const serverScript = writeFakeMcpServer(root, "https://evil.example/");
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-snapshot-outscope-test", "safe", target);

    await expect(
      new McpStdioExecutor(runtime).executeCall({
        server: "playwright-mcp",
        tool: "browser_snapshot",
        mode: "safe",
        target,
        jobId: job.id,
      }),
    ).rejects.toMatchObject({ code: "MCP_POSTCONDITION_SCOPE_BLOCKED" });

    const artifacts = runtime.evidence.list().filter((item) => item.jobId === job.id);
    expect(artifacts).toHaveLength(1);
    const content = JSON.parse(readFileSync(artifacts[0]!.path, "utf8"));
    expect(content.postcondition).toMatchObject({
      kind: "current_or_final_url_in_scope",
      ok: false,
      evidenceUsable: false,
      code: "MCP_POSTCONDITION_SCOPE_BLOCKED",
      url: "https://evil.example/",
    });
  });

  it("runs queued approved MCP actions through ActionExecutor", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-action-"));
    const serverScript = writeFakeMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-action-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "playwright_mcp",
      actionType: "browser.navigate",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    const result = await new ActionExecutor(runtime).execute(action.id);

    expect(result.status).toBe("executed");
    expect(result.evidenceCreated).toBe(1);
    expect(runtime.actions.get(action.id)?.status).toBe("executed");
    expect(runtime.evidence.list().some((item) => item.path.includes(action.id))).toBe(true);
  });

  it("requires approval for direct MCP calls but runs approved queued MCP actions", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-approved-"));
    const serverScript = writeFakeMcpServer(root);
    const runtime = createTestRuntime(root, serverScript, true, true);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-approved-test", "safe", runtime.config.program);

    await expect(
      new McpStdioExecutor(runtime).executeCall({
        server: "windows-mcp",
        tool: "desktop_session_plan",
        mode: "safe",
        target,
        arguments: { target },
        jobId: job.id,
      }),
    ).rejects.toThrow("requires an approved queued action");

    expect(runtime.evidence.list().filter((item) => item.jobId === job.id)).toHaveLength(0);

    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "windows_mcp",
      actionType: "desktop.session.plan",
      target: runtime.config.program,
      riskLevel: "medium",
      requiresApproval: true,
    });
    runtime.actions.approve(action.id);

    const result = await new ActionExecutor(runtime).execute(action.id);

    expect(result.status).toBe("executed");
    expect(result.evidenceCreated).toBe(1);
    expect(runtime.actions.get(action.id)?.status).toBe("executed");
    const artifact = runtime.evidence.list().find((item) => item.path.includes(action.id));
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.actionId).toBe(action.id);
    expect(content.approvedAction).toBe(true);
    expect(content.target).toBeUndefined();
    expect(content.arguments).toEqual({ program: runtime.config.program });
    expect(content.validation.requiresApproval).toBe(true);
  });

  it("refuses MCP execution unless the integration opts in explicitly", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-disabled-"));
    const serverScript = writeFakeMcpServer(root);
    const runtime = createTestRuntime(root, serverScript, false);

    await expect(
      new McpStdioExecutor(runtime).executeCall({
        server: "playwright-mcp",
        tool: "browser_navigate",
        mode: "safe",
        target: "http://127.0.0.1:8080/",
        arguments: { url: "http://127.0.0.1:8080/" },
      }),
    ).rejects.toThrow("planning only");
  });

  it("fails closed on malformed MCP stdout frames", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-malformed-"));
    const serverScript = writeMalformedMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-malformed-test", "safe", target);

    await expect(
      new McpStdioExecutor(runtime).executeCall({
        server: "playwright-mcp",
        tool: "browser_navigate",
        mode: "safe",
        target,
        arguments: { url: target },
        jobId: job.id,
      }),
    ).rejects.toMatchObject({ code: "MCP_FRAME_INVALID" });

    const artifacts = runtime.evidence.list().filter((item) => item.jobId === job.id);
    expect(artifacts).toHaveLength(1);
    const content = JSON.parse(readFileSync(artifacts[0]!.path, "utf8"));
    expect(content.failure).toMatchObject({
      phase: "stdout_frame",
      code: "MCP_FRAME_INVALID",
      message: "MCP stdout frame contained malformed JSON",
      stdoutPreviewTruncated: false,
    });
    expect(content.failure.stdoutPreview).toContain("Content-Length: 9");
    expect(content.failure.stdoutPreview).toContain("{bad json");
    expect(content.call.error.message).toBe("MCP stdout frame contained malformed JSON");
  });

  it("fails closed on oversized MCP stdout frames", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-oversized-"));
    const serverScript = writeOversizedMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-oversized-test", "safe", target);

    await expect(
      new McpStdioExecutor(runtime).executeCall({
        server: "playwright-mcp",
        tool: "browser_navigate",
        mode: "safe",
        target,
        arguments: { url: target },
        jobId: job.id,
      }),
    ).rejects.toMatchObject({ code: "MCP_FRAME_TOO_LARGE" });

    const artifacts = runtime.evidence.list().filter((item) => item.jobId === job.id);
    expect(artifacts).toHaveLength(1);
    const content = JSON.parse(readFileSync(artifacts[0]!.path, "utf8"));
    expect(content.failure).toMatchObject({
      phase: "stdout_frame",
      code: "MCP_FRAME_TOO_LARGE",
      message: "MCP stdout frame exceeded the maximum size",
      stdoutPreviewTruncated: false,
    });
    expect(content.failure.stdoutPreview).toContain("Content-Length: 600000");
    expect(content.failure.stdoutPreview.length).toBeLessThanOrEqual(16_384);
    expect(content.call.error.message).toBe("MCP stdout frame exceeded the maximum size");
  });

  it("executes a multi-step MCP session in one stdio process", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-session-"));
    const serverScript = writeFakeMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-session-test", "safe", target);

    const result = await new McpStdioExecutor(runtime).executeSession({
      server: "playwright-mcp",
      mode: "safe",
      target,
      jobId: job.id,
      steps: [
        { tool: "browser_navigate", arguments: { url: target } },
        { tool: "browser_snapshot" },
      ],
    });

    expect(result.evidenceCreated).toBe(1);
    const artifact = runtime.evidence.list().find((item) => item.path.includes("mcp-session"));
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.steps).toHaveLength(2);
    expect(content.responses).toHaveLength(2);
    expect(content.responses.map((step: any) => step.tool)).toEqual(["browser_navigate", "browser_snapshot"]);
    expect(content.responses[1].postcondition).toMatchObject({
      kind: "current_or_final_url_in_scope",
      ok: true,
      evidenceUsable: true,
      url: target,
    });
  });

  it("captures session stream notifications with active step indexes", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mcp-session-events-"));
    const serverScript = writeEventfulMcpServer(root);
    const runtime = createTestRuntime(root, serverScript);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("mcp-session-events-test", "safe", target);

    const result = await new McpStdioExecutor(runtime).executeSession({
      server: "playwright-mcp",
      mode: "safe",
      target,
      jobId: job.id,
      steps: [
        { tool: "browser_navigate", arguments: { url: target } },
        { tool: "browser_snapshot" },
      ],
    });

    expect(result.evidenceCreated).toBe(1);
    const artifact = runtime.evidence.list().find((item) => item.path.includes("mcp-session"));
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.streamEvents.total).toBe(8);
    const progressEvents = content.streamEvents.events.filter((event: any) => event.kind === "progress");
    expect(progressEvents.map((event: any) => event.stepIndex)).toEqual([0, 1]);
    const requestEvents = content.streamEvents.events.filter((event: any) => event.kind === "request");
    expect(requestEvents.map((event: any) => event.stepIndex)).toEqual([0, 1]);
    expect(content.responses).toHaveLength(2);
  });
});

function writeFakeMcpServer(root: string, snapshotCurrentUrl?: string): string {
  const scriptPath = path.join(root, "fake-mcp-server.mjs");
  writeFileSync(scriptPath, fakeMcpServerSource(snapshotCurrentUrl), "utf8");
  return scriptPath;
}

function writeEventfulMcpServer(root: string): string {
  const scriptPath = path.join(root, "eventful-mcp-server.mjs");
  writeFileSync(scriptPath, eventfulMcpServerSource(), "utf8");
  return scriptPath;
}

function writeNoisyMcpServer(root: string): string {
  const scriptPath = path.join(root, "noisy-mcp-server.mjs");
  writeFileSync(scriptPath, noisyMcpServerSource(), "utf8");
  return scriptPath;
}

function writeFakeMcpPackage(root: string, packageName: string, version: string, entrypoint: string): string {
  const packageRoot = path.join(root, "node_modules", packageName);
  const scriptPath = path.join(packageRoot, ...entrypoint.split("/"));
  mkdirSync(path.dirname(scriptPath), { recursive: true });
  writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ name: packageName, version }), "utf8");
  writeFileSync(scriptPath, fakeMcpServerSource(), "utf8");
  return scriptPath;
}

function fakeMcpServerSource(snapshotCurrentUrl?: string): string {
  return `
const forcedSnapshotCurrentUrl = ${JSON.stringify(snapshotCurrentUrl)};
let buffer = Buffer.alloc(0);
function send(message) {
  const body = JSON.stringify(message);
  process.stdout.write(\`Content-Length: \${Buffer.byteLength(body, "utf8")}\\r\\n\\r\\n\${body}\`);
}
function contentLength(header) {
  const line = header.split(/\\r?\\n/).find((item) => item.toLowerCase().startsWith("content-length:"));
  return line ? Number(line.split(":")[1].trim()) : undefined;
}
process.stdin.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  while (true) {
    const headerEnd = buffer.indexOf("\\r\\n\\r\\n");
    if (headerEnd === -1) return;
    const header = buffer.slice(0, headerEnd).toString("utf8");
    const length = contentLength(header);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + length;
    if (buffer.length < bodyEnd) return;
    const message = JSON.parse(buffer.slice(bodyStart, bodyEnd).toString("utf8"));
    buffer = buffer.slice(bodyEnd);
    if (message.method === "initialize") {
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "fake-mcp", version: "0.0.1" }
        }
      });
    }
    if (message.method === "tools/call") {
      const tool = message.params.name;
      const args = message.params.arguments ?? {};
      const payload = { tool, arguments: args };
      if (tool === "browser_snapshot") {
        payload.currentUrl = forcedSnapshotCurrentUrl ?? args.currentUrl ?? args.current_url ?? args.finalUrl ?? args.final_url ?? args.pageUrl ?? args.page_url ?? args.url ?? args.target;
      }
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify(payload)
            }
          ],
          isError: false
        }
      });
    }
  }
});
`;
}

function eventfulMcpServerSource(): string {
  return `
let buffer = Buffer.alloc(0);
function send(message) {
  const body = JSON.stringify(message);
  process.stdout.write(\`Content-Length: \${Buffer.byteLength(body, "utf8")}\\r\\n\\r\\n\${body}\`);
}
function contentLength(header) {
  const line = header.split(/\\r?\\n/).find((item) => item.toLowerCase().startsWith("content-length:"));
  return line ? Number(line.split(":")[1].trim()) : undefined;
}
process.stdin.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  while (true) {
    const headerEnd = buffer.indexOf("\\r\\n\\r\\n");
    if (headerEnd === -1) return;
    const header = buffer.slice(0, headerEnd).toString("utf8");
    const length = contentLength(header);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + length;
    if (buffer.length < bodyEnd) return;
    const message = JSON.parse(buffer.slice(bodyStart, bodyEnd).toString("utf8"));
    buffer = buffer.slice(bodyEnd);
    if (message.method === "initialize") {
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "eventful-mcp", version: "0.0.1" }
        }
      });
      send({
        jsonrpc: "2.0",
        method: "notifications/message",
        params: { level: "info", logger: "eventful", token: "stream-secret", data: "initialized" }
      });
    }
    if (message.method === "tools/call") {
      const tool = message.params.name;
      const args = message.params.arguments ?? {};
      send({
        jsonrpc: "2.0",
        id: message.id,
        method: "roots/list",
        params: { token: "stream-secret" }
      });
      send({
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: { progress: 1, total: 1, token: "stream-secret", message: \`calling \${tool}\` }
      });
      const payload = { tool, arguments: args };
      if (tool === "browser_snapshot") {
        payload.currentUrl = args.url ?? args.target ?? "http://127.0.0.1:8080/";
      }
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify(payload)
            }
          ],
          isError: false
        }
      });
    }
  }
});
`;
}

function noisyMcpServerSource(): string {
  return `
let buffer = Buffer.alloc(0);
function send(message) {
  const body = JSON.stringify(message);
  process.stdout.write(\`Content-Length: \${Buffer.byteLength(body, "utf8")}\\r\\n\\r\\n\${body}\`);
}
function contentLength(header) {
  const line = header.split(/\\r?\\n/).find((item) => item.toLowerCase().startsWith("content-length:"));
  return line ? Number(line.split(":")[1].trim()) : undefined;
}
process.stdin.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  while (true) {
    const headerEnd = buffer.indexOf("\\r\\n\\r\\n");
    if (headerEnd === -1) return;
    const header = buffer.slice(0, headerEnd).toString("utf8");
    const length = contentLength(header);
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + length;
    if (buffer.length < bodyEnd) return;
    const message = JSON.parse(buffer.slice(bodyStart, bodyEnd).toString("utf8"));
    buffer = buffer.slice(bodyEnd);
    if (message.method === "initialize") {
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "noisy-mcp", version: "0.0.1" }
        }
      });
    }
    if (message.method === "tools/call") {
      for (let index = 0; index < 125; index += 1) {
        send({
          jsonrpc: "2.0",
          method: "notifications/message",
          params: {
            level: "info",
            token: "noisy-stream-secret",
            password: "noisy-stream-secret",
            data: "x".repeat(index === 0 ? 3000 : 16)
          }
        });
      }
      send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [{ type: "text", text: JSON.stringify({ tool: message.params.name, arguments: message.params.arguments ?? {} }) }],
          isError: false
        }
      });
    }
  }
});
`;
}

function writeMalformedMcpServer(root: string): string {
  const scriptPath = path.join(root, "malformed-mcp-server.mjs");
  writeFileSync(
    scriptPath,
    `
process.stdout.write("Content-Length: 9\\r\\n\\r\\n{bad json");
setInterval(() => {}, 1000);
`,
    "utf8",
  );
  return scriptPath;
}

function writeOversizedMcpServer(root: string): string {
  const scriptPath = path.join(root, "oversized-mcp-server.mjs");
  writeFileSync(
    scriptPath,
    `
process.stdout.write("Content-Length: 600000\\r\\n\\r\\n");
setInterval(() => {}, 1000);
`,
    "utf8",
  );
  return scriptPath;
}

function createTestRuntime(
  root: string,
  serverScript: string,
  allowExecute = true,
  withWindowsMcp = false,
  packageExecution?: {
    package: string;
    package_version: string;
    entrypoint: string;
    entrypoint_sha256?: string;
    package_json_sha256?: string;
  },
): Runtime {
  const config: ProgramConfig = {
    program: "mcp-executor-test",
    platform: "hackerone",
    in_scope: ["127.0.0.1"],
    out_of_scope: [],
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "100rps",
      browser_crawling: true,
      deep_safe_mode: true,
      require_human_approval_for_risky_actions: true,
    },
    accounts: {
      required: false,
      use_researcher_owned_test_accounts_only: true,
    },
    evidence: {
      screenshots: true,
      har: true,
      console_logs: true,
      dom_snapshot: true,
      video: "optional",
      browser_trace: true,
      desktop_screenshots: "optional",
      mask_secrets: true,
    },
    integrations: {
      playwright_mcp: {
        enabled: true,
        type: "mcp",
        transport: "stdio",
        ...(packageExecution
          ? {
              execution: {
                ...packageExecution,
                args: [],
                timeout_ms: 5_000,
              },
            }
          : {
              command: process.execPath,
              args: [serverScript],
              timeout_ms: 5_000,
            }),
        allow_execute: allowExecute,
        capabilities: ["browser.navigate", "browser.snapshot"],
      },
      ...(withWindowsMcp
        ? {
            windows_mcp: {
              enabled: true,
              type: "desktop",
              transport: "stdio",
              command: process.execPath,
              args: [serverScript],
              allow_execute: allowExecute,
              capabilities: ["desktop.session.plan"],
              timeout_ms: 5_000,
            },
          }
        : {}),
    },
  };
  const paths = ensureProgramWorkspace(config.program, root);
  const db = openBountyDatabase(paths.dbFile);
  const runtime: Runtime = {
    config,
    paths,
    db,
    scopeGuard: new ScopeGuard(config),
    policyGate: new PolicyGate(config.rules),
    rateLimiter: new RateLimiter(config.rules.rate_limit),
    candidates: new FindingCandidateStore(db),
    findings: new FindingStore(db),
    evidence: new EvidenceStore(db, paths.evidenceDir, { trustedArtifactRoots: [paths.reportsDir] }),
    crawlGraph: new CrawlGraphStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
  };
  if (allowExecute) {
    const approvals = createExecutableApprovalStore(paths.workspace.integrationsDir);
    approvals.approve({ integration: "playwright_mcp", command: process.execPath });
    if (withWindowsMcp) {
      approvals.approve({ integration: "windows_mcp", command: process.execPath });
    }
  }
  return runtime;
}

function sha256File(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}
