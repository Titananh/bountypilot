import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bountyCli = path.join(repoRoot, "dist", "cli", "index.js");
const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("CLI skill commands", () => {
  it("lists, shows, validates, and exports the bundled skill", () => {
    const workspace = createWorkspace();

    const list = runCli(["skill", "list", "--json"], workspace);
    expectCommand(list).toExit(0);
    expect(JSON.parse(outputOf(list)).skills).toEqual(expect.arrayContaining([expect.objectContaining({ id: "bug-bounty-pilot" })]));

    const show = runCli(["skill", "show", "bug-bounty-pilot", "--json"], workspace);
    expectCommand(show).toExit(0);
    expect(JSON.parse(outputOf(show))).toMatchObject({
      ok: true,
      id: "bug-bounty-pilot",
      modes: expect.arrayContaining(["passive", "safe", "deep-safe", "lab-offensive"]),
    });

    const validate = runCli(["skill", "validate", "bug-bounty-pilot", "--json"], workspace);
    expectCommand(validate).toExit(0);
    expect(JSON.parse(outputOf(validate))).toMatchObject({ ok: true, id: "bug-bounty-pilot" });

    const output = path.join(workspace, ".bounty", "skills", "bug-bounty-pilot");
    const exported = runCli(["skill", "export", "bug-bounty-pilot", "--output", output, "--json"], workspace);
    expectCommand(exported).toExit(0);
    expect(JSON.parse(outputOf(exported))).toMatchObject({ ok: true, id: "bug-bounty-pilot", output });
    expect(existsSync(path.join(output, "SKILL.md"))).toBe(true);
  });

  it("runs passive skill workflow as dry-run against imported scope", () => {
    const workspace = createWorkspace();
    writeFileSync(path.join(workspace, "program.yml"), programYaml(), "utf8");
    expectCommand(runCli(["init"], workspace)).toExit(0);
    expectCommand(runCli(["import", "program.yml"], workspace)).toExit(0);

    const result = runCli(
      ["skill", "run", "bug-bounty-pilot", "https://skill.example", "--program", "skill-cli", "--mode", "passive", "--dry-run", "--json"],
      workspace,
    );

    expectCommand(result).toExit(0);
    const parsed = JSON.parse(outputOf(result));
    expect(parsed).toMatchObject({
      ok: true,
      skill: { id: "bug-bounty-pilot" },
      program: "skill-cli",
      mode: "passive",
      dryRun: true,
    });
    expect(parsed.recon.tools.map((tool: any) => tool.status)).toEqual(expect.arrayContaining(["planned"]));
    expect(readFileSync(path.join(workspace, ".bounty", "programs", "skill-cli", "program.yml"), "utf8")).toContain("skill-cli");
  }, 60_000);
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-cli-skill-"));
  workspaces.push(workspace);
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

function programYaml(): string {
  return `program: skill-cli
platform: hackerone

in_scope:
  - "skill.example"

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
}

