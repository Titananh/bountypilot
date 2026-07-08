import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, type SpawnOptionsWithoutStdio } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bountyCli = path.join(repoRoot, "dist", "cli", "index.js");
const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("CLI MCP call", () => {
  it("executes an explicitly enabled stdio MCP call and records evidence", async () => {
    const workspace = createWorkspace();
    const serverScript = writeFakeMcpServer(workspace);
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, programYaml(serverScript), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);
    expectCommand(await runCli(["integrations", "config", "playwright-mcp", "allow_execute=true"], workspace)).toExit(0);
    const approve = await runCli(
      ["integrations", "approve-executable", "playwright-mcp", "--command", process.execPath, "--json"],
      workspace,
    );
    expectCommand(approve).toExit(0);
    expect(JSON.parse(approve.stdout)).toMatchObject({ ok: true, integration: "playwright_mcp" });

    const result = await runCli(
      ["mcp", "call", "playwright-mcp", "browser_navigate", "--target", "http://127.0.0.1:8080/"],
      workspace,
    );
    expectCommand(result).toExit(0);
    expect(outputOf(result)).toContain("mcp call");
    expect(outputOf(result)).toContain("completed");

    const artifactPath = findFiles(path.join(workspace, ".bounty"), "mcp-result.json")[0];
    expect(artifactPath).toBeDefined();
    const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
    expect(artifact.execute).toBe(true);
    expect(artifact.server).toBe("playwright_mcp");
    expect(artifact.call.result.content[0].text).toContain("browser_navigate");
    expect(artifact.streamEvents.events.map((event: any) => event.method)).toEqual(
      expect.arrayContaining(["notifications/message", "notifications/progress"]),
    );
    expect(artifact.streamEvents.events.map((event: any) => event.kind)).toEqual(
      expect.arrayContaining(["log", "progress"]),
    );
    expect(JSON.stringify(artifact.streamEvents)).toContain("[REDACTED]");
    expect(JSON.stringify(artifact.streamEvents)).not.toContain("cli-stream-secret");

    const jsonResult = await runCli(
      ["mcp", "call", "playwright-mcp", "browser_navigate", "--target", "http://127.0.0.1:8080/", "--json"],
      workspace,
    );
    expectCommand(jsonResult).toExit(0);
    expect(jsonResult.stderr).toBe("");
    const parsedJsonResult = JSON.parse(jsonResult.stdout);
    expect(parsedJsonResult.ok).toBe(true);
    expect(parsedJsonResult.result.message).toContain("completed");

    const invalidArgPair = await runCli(
      ["mcp", "plan", "playwright-mcp", "browser_navigate", "--target", "http://127.0.0.1:8080/", "--arg", "=oops", "--json"],
      workspace,
    );
    expectCommand(invalidArgPair).toExit(1);
    expect(invalidArgPair.stderr).toBe("");
    expect(JSON.parse(invalidArgPair.stdout).error.code).toBe("ARG_PAIR_INVALID");

    const duplicateArgPair = await runCli(
      [
        "mcp",
        "plan",
        "playwright-mcp",
        "browser_navigate",
        "--target",
        "http://127.0.0.1:8080/",
        "--arg",
        "url=http://127.0.0.1:8080/",
        "url=http://127.0.0.1:8081/",
        "--json",
      ],
      workspace,
    );
    expectCommand(duplicateArgPair).toExit(1);
    expect(duplicateArgPair.stderr).toBe("");
    expect(JSON.parse(duplicateArgPair.stdout).error.code).toBe("ARG_PAIR_INVALID");

    const missingSteps = await runCli(["mcp", "session", "playwright-mcp", "--steps", path.join(workspace, "missing.json"), "--json"], workspace);
    expectCommand(missingSteps).toExit(1);
    expect(missingSteps.stderr).toBe("");
    expect(JSON.parse(missingSteps.stdout).error.code).toBe("MCP_STEPS_NOT_FOUND");

    const malformedStepsFile = path.join(workspace, "malformed-steps.json");
    writeFileSync(malformedStepsFile, "{", "utf8");
    const malformedSteps = await runCli(["mcp", "session", "playwright-mcp", "--steps", malformedStepsFile, "--json"], workspace);
    expectCommand(malformedSteps).toExit(1);
    expect(malformedSteps.stderr).toBe("");
    expect(JSON.parse(malformedSteps.stdout).error.code).toBe("MCP_STEPS_INVALID_JSON");

    const emptyStepsFile = path.join(workspace, "empty-steps.json");
    writeFileSync(emptyStepsFile, "[]", "utf8");
    const emptySteps = await runCli(["mcp", "session", "playwright-mcp", "--steps", emptyStepsFile, "--json"], workspace);
    expectCommand(emptySteps).toExit(1);
    expect(emptySteps.stderr).toBe("");
    expect(JSON.parse(emptySteps.stdout).error.code).toBe("MCP_STEPS_EMPTY");

    const tooManyStepsFile = path.join(workspace, "too-many-steps.json");
    writeFileSync(
      tooManyStepsFile,
      JSON.stringify({ steps: Array.from({ length: 101 }, () => ({ tool: "browser_snapshot" })) }),
      "utf8",
    );
    const tooManySteps = await runCli(["mcp", "session", "playwright-mcp", "--steps", tooManyStepsFile, "--json"], workspace);
    expectCommand(tooManySteps).toExit(1);
    expect(tooManySteps.stderr).toBe("");
    expect(JSON.parse(tooManySteps.stdout).error.code).toBe("MCP_STEPS_TOO_MANY");

    const stepsFile = path.join(workspace, "mcp-steps.json");
    writeFileSync(
      stepsFile,
      JSON.stringify(
        {
          steps: [
            { tool: "browser_navigate", arguments: { url: "http://127.0.0.1:8080/" } },
            { tool: "browser_snapshot" },
          ],
        },
        null,
        2,
      ),
      "utf8",
    );
    const session = await runCli(
      ["mcp", "session", "playwright-mcp", "--target", "http://127.0.0.1:8080/", "--steps", stepsFile],
      workspace,
    );
    expectCommand(session).toExit(0);
    expect(outputOf(session)).toContain("mcp session");
    expect(outputOf(session)).toContain("completed 2 steps");

    const sessionArtifactPath = findFiles(path.join(workspace, ".bounty"), "mcp-session.json")[0];
    expect(sessionArtifactPath).toBeDefined();
    const sessionArtifact = JSON.parse(readFileSync(sessionArtifactPath, "utf8"));
    expect(sessionArtifact.responses).toHaveLength(2);
    expect(sessionArtifact.streamEvents.events.map((event: any) => event.method)).toEqual(
      expect.arrayContaining(["notifications/message", "notifications/progress"]),
    );
    expect(JSON.stringify(sessionArtifact.streamEvents)).not.toContain("cli-stream-secret");

    const jsonSession = await runCli(
      ["mcp", "session", "playwright-mcp", "--target", "http://127.0.0.1:8080/", "--steps", stepsFile, "--json"],
      workspace,
    );
    expectCommand(jsonSession).toExit(0);
    expect(jsonSession.stderr).toBe("");
    const parsedJsonSession = JSON.parse(jsonSession.stdout);
    expect(parsedJsonSession.ok).toBe(true);
    expect(parsedJsonSession.steps).toHaveLength(2);
  }, 60_000);
});

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-cli-mcp-"));
  workspaces.push(workspace);
  return workspace;
}

function runCli(args: string[], cwd: string): Promise<CliResult> {
  return new Promise((resolve) => {
    const options: SpawnOptionsWithoutStdio = {
      cwd,
      env: {
        ...process.env,
        NO_COLOR: "1",
        NODE_NO_WARNINGS: "1",
      },
      windowsHide: true,
    };
    const child = spawn(process.execPath, [bountyCli, ...args], options);
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timeout = setTimeout(() => {
      settled = true;
      child.kill();
      resolve({ status: null, stdout, stderr, error: new Error(`CLI timed out: ${args.join(" ")}`) });
    }, 55_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ status: null, stdout, stderr, error });
    });
    child.on("close", (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ status, stdout, stderr });
    });
  });
}

function outputOf(result: CliResult): string {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function expectCommand(result: CliResult): { toExit(status: number): void } {
  return {
    toExit(status: number) {
      expect(result.error, outputOf(result)).toBeUndefined();
      expect(result.status, outputOf(result)).toBe(status);
    },
  };
}

function programYaml(serverScript: string): string {
  return `program: cli-mcp-call
platform: hackerone

in_scope:
  - "127.0.0.1"

out_of_scope: []

rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "100rps"
  browser_crawling: true
  deep_safe_mode: true
  require_human_approval_for_risky_actions: true

accounts:
  required: false
  use_researcher_owned_test_accounts_only: true

evidence:
  screenshots: true
  har: true
  console_logs: true
  dom_snapshot: true
  video: optional
  browser_trace: true
  desktop_screenshots: optional
  mask_secrets: true

integrations:
  playwright_mcp:
    enabled: true
    type: mcp
    transport: stdio
    command: ${yamlSingle(process.execPath)}
    args:
      - ${yamlSingle(serverScript)}
    allow_execute: true
    capabilities:
      - browser.navigate
      - browser.snapshot
    timeout_ms: 5000
`;
}

function yamlSingle(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function writeFakeMcpServer(root: string): string {
  const scriptPath = path.join(root, "fake-mcp-server.mjs");
  writeFileSync(
    scriptPath,
    `
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
      send({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "fake-mcp", version: "0.0.1" } } });
    }
    if (message.method === "tools/call") {
      const tool = message.params.name;
      const args = message.params.arguments ?? {};
      const payload = { tool, arguments: args };
      if (tool === "browser_snapshot") {
        payload.currentUrl = args.currentUrl ?? args.current_url ?? args.finalUrl ?? args.final_url ?? args.pageUrl ?? args.page_url ?? args.url ?? args.target;
      }
      send({ jsonrpc: "2.0", method: "notifications/message", params: { level: "info", data: \`running \${tool} token=cli-stream-secret\` } });
      send({ jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1, total: 2, token: "cli-stream-secret", message: \`calling \${tool}\` } });
      send({ jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text: JSON.stringify(payload) }], isError: false } });
    }
  }
});
`,
    "utf8",
  );
  return scriptPath;
}

function findFiles(root: string, suffix: string): string[] {
  if (!existsSync(root)) return [];
  const matches: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      matches.push(...findFiles(fullPath, suffix));
    } else if (entry.name.endsWith(suffix)) {
      matches.push(fullPath);
    }
  }
  return matches;
}
