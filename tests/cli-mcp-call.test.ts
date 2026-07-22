import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bountyCli = path.join(repoRoot, "dist", "cli", "index.js");
const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) rmSync(workspace, { recursive: true, force: true });
});

describe("CLI MCP handoff", () => {
  it("records a non-executing plan even when an integration is enabled", async () => {
    const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-cli-mcp-"));
    workspaces.push(workspace);
    const marker = path.join(workspace, "mcp-ran.txt");
    const serverScript = path.join(workspace, "server.mjs");
    writeFileSync(serverScript, `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(marker)}, "ran");`, "utf8");
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, programYaml(process.execPath, serverScript), "utf8");

    expect((await runCli(["init"], workspace)).status).toBe(0);
    expect((await runCli(["import", programFile], workspace)).status).toBe(0);
    expect((await runCli(["integrations", "config", "playwright-mcp", "allow_execute=true"], workspace)).status).toBe(0);
    expect((await runCli(["integrations", "approve-executable", "playwright-mcp", "--command", process.execPath, "--json"], workspace)).status).toBe(0);

    const result = await runCli([
      "mcp", "call", "playwright-mcp", "browser_navigate", "--target", "http://127.0.0.1:8080/", "--json",
    ], workspace);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    const payload = JSON.parse(result.stdout);
    expect(payload.ok).toBe(true);
    expect(payload.execute).toBe(false);
    expect(payload.status).toBe("completed");
    expect(payload.action.metadata).toMatchObject({ execute: false, planningOnly: true, handoffOnly: true });
    expect(existsSync(marker)).toBe(false);
    expect(existsSync(payload.artifact.path)).toBe(true);
    expect(JSON.parse(readFileSync(payload.artifact.path, "utf8")).execute).toBe(false);
  });
});

interface CliResult { status: number | null; stdout: string; stderr: string; error?: Error }

function runCli(args: string[], cwd: string): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bountyCli, ...args], {
      cwd,
      env: { ...process.env, NO_COLOR: "1", NODE_NO_WARNINGS: "1" },
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      resolve({ status: null, stdout, stderr, error: new Error(`CLI timed out: ${args.join(" ")}`) });
    }, 30_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
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

function programYaml(command: string, serverScript: string): string {
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
    command: ${yamlSingle(command)}
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
  return `'${value.replaceAll("'", "''")}'`;
}
