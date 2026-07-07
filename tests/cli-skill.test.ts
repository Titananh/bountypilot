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
      frontmatter: {
        name: "bug-bounty-pilot",
        description: expect.stringContaining("authorized scoped targets"),
      },
      agentMetadata: {
        interface: {
          display_name: "Bug Bounty Pilot",
          default_prompt: expect.stringContaining("$bug-bounty-pilot"),
        },
      },
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
    expect(existsSync(path.join(output, "agents", "openai.yaml"))).toBe(true);

    const bundlePath = path.join(workspace, "bug-bounty-pilot.skill.zip");
    const bundled = runCli(["skill", "bundle", "bug-bounty-pilot", "--output", bundlePath, "--json"], workspace);
    expectCommand(bundled).toExit(0);
    const parsedBundle = JSON.parse(outputOf(bundled));
    expect(parsedBundle).toMatchObject({
      ok: true,
      id: "bug-bounty-pilot",
      output: bundlePath,
      format: "zip",
      manifest: {
        schemaVersion: "bountypilot.skill.bundle.v1",
        id: "bug-bounty-pilot",
        validation: { failures: 0 },
      },
    });
    expect(parsedBundle.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(parsedBundle.manifest.files.map((file: any) => file.path)).toEqual(
      expect.arrayContaining(["SKILL.md", "agents/openai.yaml", "policy.yml", "workflow.yml"]),
    );
    const bundleBytes = readFileSync(bundlePath);
    expect(bundleBytes.subarray(0, 4).toString("latin1")).toBe("PK\u0003\u0004");
    expect(bundleBytes.toString("utf8")).toContain("bug-bounty-pilot/MANIFEST.bountypilot.json");

    const verified = runCli(["skill", "verify-bundle", bundlePath, "--json"], workspace);
    expectCommand(verified).toExit(0);
    expect(JSON.parse(outputOf(verified))).toMatchObject({
      ok: true,
      manifest: { id: "bug-bounty-pilot" },
      files: { expected: parsedBundle.files, verified: parsedBundle.files },
    });

    const tamperedPath = path.join(workspace, "bug-bounty-pilot-tampered.skill.zip");
    const tamperedBytes = Buffer.from(bundleBytes);
    const markerIndex = tamperedBytes.indexOf(Buffer.from("Bug Bounty Pilot Skill", "utf8"));
    expect(markerIndex).toBeGreaterThanOrEqual(0);
    tamperedBytes[markerIndex] = "b".charCodeAt(0);
    writeFileSync(tamperedPath, tamperedBytes);
    const tampered = runCli(["skill", "verify-bundle", tamperedPath, "--json"], workspace);
    expectCommand(tampered).toExit(1);
    expect(JSON.parse(outputOf(tampered))).toMatchObject({ ok: false });
  });

  it("scores bundled skill readiness across validation, bundle verification, and release gates", () => {
    const result = runCli(["skill", "score", "bug-bounty-pilot", "--json"], repoRoot);
    expectCommand(result).toExit(0);
    const parsed = JSON.parse(outputOf(result));
    expect(parsed).toMatchObject({
      ok: true,
      id: "bug-bounty-pilot",
      validation: { failures: [] },
      bundle: { ok: true },
      release: { ok: true },
    });
    expect(parsed.score).toBeGreaterThanOrEqual(90);
    expect(["ultimate", "ready_with_warnings"]).toContain(parsed.readiness);
    expect(parsed.nextSteps.length).toBeGreaterThan(0);
    if (parsed.warnings.some((warning: any) => warning.name === "github:origin")) {
      expect(parsed.nextSteps).toEqual(
        expect.arrayContaining([
          "bounty release publish-plan OWNER/REPO --write",
          "bounty release github-bootstrap OWNER/REPO --write",
          "winget install --id GitHub.cli -e",
          "brew install gh",
          "sudo apt-get update && sudo apt-get install -y gh",
          "gh --version",
          "gh auth status",
          "gh auth login",
          "gh repo create OWNER/REPO --public --source . --remote origin --push",
          "git push -u origin HEAD:main",
          "git tag v0.1.0",
          "git push origin v0.1.0",
          "bounty release publish-plan OWNER/REPO --branch main --tag v0.1.0 --write",
          "bounty release publish-status OWNER/REPO --branch main --tag v0.1.0 --online --actions --json",
          "bounty release publish-status OWNER/REPO --online --actions --json",
          "bugbounty release install-check --json",
          "bounty skill score bug-bounty-pilot --json",
        ]),
      );
    }

    const fakeGh = writeFakeGh(mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-fake-gh-")));
    const scoredForRepo = runCli(
      [
        "skill",
        "score",
        "bug-bounty-pilot",
        "--repo",
        "octo/bountypilot",
        "--gh-command",
        process.execPath,
        "--gh-command-arg",
        fakeGh,
        "--json",
      ],
      repoRoot,
    );
    expectCommand(scoredForRepo).toExit(0);
    const parsedForRepo = JSON.parse(outputOf(scoredForRepo));
    expect(parsedForRepo.github).toMatchObject({
      ok: false,
      repo: "octo/bountypilot",
      tag: "v0.1.0",
    });
    expect(parsedForRepo.score).toBeLessThan(97);
    expect(parsedForRepo.readiness).toBe("ready_with_warnings");
    expect(parsedForRepo.github.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "gh:version", status: "pass" }),
        expect.objectContaining({ name: "gh:auth", status: "pass" }),
        expect.objectContaining({ name: "git:origin", status: "fail" }),
      ]),
    );
    expect(parsedForRepo.nextSteps).toEqual(
      expect.arrayContaining([
        "bounty release github-bootstrap octo/bountypilot --write",
        "gh repo create octo/bountypilot --public --source . --remote origin --push",
        "git push -u origin HEAD:main",
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --json",
      ]),
    );
    expect(parsedForRepo.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "github:origin",
          message: "No origin remote configured. Add one with: git remote add origin https://github.com/octo/bountypilot.git",
        }),
        expect.objectContaining({ name: "git:origin" }),
        expect.objectContaining({ name: "git:origin-target" }),
        expect.objectContaining({ name: "git:local-tag" }),
      ]),
    );
    expect(parsedForRepo.release.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "github:origin",
          message: "No origin remote configured. Add one with: git remote add origin https://github.com/octo/bountypilot.git",
        }),
      ]),
    );
    expect(parsedForRepo.nextSteps.join("\n")).not.toContain("OWNER/REPO");
    expect(parsedForRepo.nextSteps).not.toContain("git remote add origin https://github.com/octo/bountypilot.git");
    expect(parsedForRepo.nextSteps).not.toContain("git push -u origin codex/bug-bounty-pilot-candidate-engine");
  }, 60_000);

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
    expect(parsed.nextCommands).toEqual(expect.arrayContaining([expect.stringContaining("--include-artifacts")]));
    expect(parsed.nextCommands.join("\n")).not.toContain("--include-evidence");
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

function writeFakeGh(root: string): string {
  const scriptPath = path.join(root, "fake-gh.mjs");
  writeFileSync(
    scriptPath,
    `const args = process.argv.slice(2);
if (args.includes("--version")) {
  console.log("gh version 2.0.0");
  process.exit(0);
}
if (args[0] === "auth" && args[1] === "status") {
  console.log("Logged in to github.com as bountypilot-test");
  process.exit(0);
}
console.error("unexpected fake gh args " + args.join(" "));
process.exit(1);
`,
    "utf8",
  );
  return scriptPath;
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
