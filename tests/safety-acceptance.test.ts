import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bountyCli = path.join(repoRoot, "dist", "cli", "index.js");

const programYaml = `program: safety-acceptance
platform: hackerone

in_scope:
  - "*.safety.example"
  - "api.safety.example"

out_of_scope:
  - "staging.safety.example"
  - "*.internal.safety.example"
  - "169.254.169.254"

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

integrations: {}
`;

const localFailureProgramYaml = `program: safety-local-failure
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

integrations: {}
`;

const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("Safety acceptance", () => {
  it("blocks out-of-scope assets at the CLI boundary", () => {
    const workspace = prepareImportedWorkspace();

    const scopeTest = runCli(["scope", "test", "https://staging.safety.example"], workspace);
    expectCommand(scopeTest).toExit(2);
    expect(outputOf(scopeTest)).toContain("[blocked] Blocked by out_of_scope rule staging.safety.example");

    const dryRun = runCli(
      ["run", "https://staging.safety.example", "--dry-run", "--with", "safe-checks,playwright"],
      workspace,
    );
    expectCommand(dryRun).toExit(0);
    expect(outputOf(dryRun)).toContain("skipped scope rules");
    expect(outputOf(dryRun)).toContain("Blocked by out_of_scope rule staging.safety.example");

    const summary = readOnlyWorkflowSummary(workspace);
    expect(summary.seeds).toEqual([]);
    expect(summary.actionsPlanned).toBe(0);
    expect(summary.findingsCreated).toBe(0);
    expect(summary.skippedScopeRules).toEqual([
      "https://staging.safety.example (Blocked by out_of_scope rule staging.safety.example)",
    ]);
    expect(findFiles(path.join(workspace, ".bounty"), "safe-checks.json")).toEqual([]);
    expect(findFiles(path.join(workspace, ".bounty"), "crawl-graph.json")).toEqual([]);
  });

  it("rejects active dry-run components in passive mode", () => {
    const workspace = prepareImportedWorkspace();

    const dryRun = runCli(
      ["run", "api.safety.example", "--mode", "passive", "--dry-run", "--with", "safe-checks"],
      workspace,
    );
    expectCommand(dryRun).toExit(1);
    expect(outputOf(dryRun)).toContain("[error] [POLICY_BLOCKED]");
    expect(outputOf(dryRun)).toContain("Passive mode only allows non-invasive research and metadata actions");

    const summary = readOnlyWorkflowSummary(workspace);
    expect(summary.seeds).toEqual(["https://api.safety.example/"]);
    expect(summary.actionsPlanned).toBe(1);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "workflow",
          status: "failed",
          detail: "Passive mode only allows non-invasive research and metadata actions",
        }),
      ]),
    );
    expect(findFiles(path.join(workspace, ".bounty"), "safe-checks.json")).toEqual([]);
  });

  it("returns a failing exit code when a live workflow phase fails", () => {
    const workspace = prepareImportedWorkspace(localFailureProgramYaml);

    const run = runCli(["run", "http://127.0.0.1:1/", "--with", "safe-checks", "--json"], workspace);

    expectCommand(run).toExit(1);
    expect(run.stderr).toBe("");
    const parsed = JSON.parse(run.stdout);
    // The HTTP effect was marked dispatched before the connection failure, so
    // lifecycle truthfully retains an ambiguous paused outcome instead of
    // claiming a clean pre-dispatch failure.
    expect(parsed.summary.status).toBe("paused");
    expect(parsed.summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "safe-checks", status: "failed" }),
        expect.objectContaining({ name: "workflow", status: "failed" }),
      ]),
    );
  });
});

function prepareImportedWorkspace(yaml = programYaml): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-safety-"));
  workspaces.push(workspace);
  const programFile = path.join(workspace, "program.yml");
  writeFileSync(programFile, yaml, "utf8");
  expectCommand(runCli(["init"], workspace)).toExit(0);
  expectCommand(runCli(["import", programFile], workspace)).toExit(0);
  return workspace;
}

function runCli(args: string[], cwd: string): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [bountyCli, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 30_000,
    env: {
      ...process.env,
      NO_COLOR: "1",
      NODE_NO_WARNINGS: "1",
    },
  });
}

function outputOf(result: SpawnSyncReturns<string>): string {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function expectCommand(result: SpawnSyncReturns<string>): { toExit(status: number): void } {
  return {
    toExit(status: number) {
      expect(result.error, outputOf(result)).toBeUndefined();
      expect(result.status, outputOf(result)).toBe(status);
    },
  };
}

function readOnlyWorkflowSummary(workspace: string): Record<string, any> {
  const summaries = findFiles(path.join(workspace, ".bounty"), "workflow-summary.json");
  const finalSummary = summaries.find((summaryPath) =>
    summaryPath.includes(`${path.sep}evidence${path.sep}`),
  );
  expect(finalSummary, summaries.join("\n")).toBeDefined();
  return JSON.parse(readFileSync(finalSummary!, "utf8"));
}

function findFiles(root: string, fileName: string): string[] {
  if (!existsSync(root)) return [];
  const matches: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      matches.push(...findFiles(fullPath, fileName));
    } else if (entry.name === fileName || entry.name.endsWith(`-${fileName}`)) {
      matches.push(fullPath);
    }
  }
  return matches;
}
