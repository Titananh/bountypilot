import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
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
    expect(parsed.layers.local).toMatchObject({
      ok: true,
      ultimate: true,
      score: 100,
      readiness: "ultimate",
      blockers: [],
      warnings: [],
    });
    expect(parsed.publicReadiness).toMatchObject({
      ok: false,
      ultimate: false,
      score: parsed.layers.publish.score,
      readiness: parsed.layers.publish.readiness,
    });
    expect(parsed.publicReadiness.requirements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "publish:repo",
          status: "warn",
          commands: ["bounty skill score bug-bounty-pilot --repo OWNER/REPO --json"],
        }),
        expect.objectContaining({
          name: "github:origin",
          status: "warn",
          commands: expect.arrayContaining(["git remote add origin https://github.com/OWNER/REPO.git"]),
        }),
      ]),
    );
    expect(parsed.publicReadiness.missing).toEqual(expect.arrayContaining([expect.objectContaining({ name: "publish:repo" })]));
    expect(parsed.publicReadiness.fixPlan).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "repo",
          status: "pending",
          requirements: ["publish:repo"],
          commands: ["bounty skill score bug-bounty-pilot --repo OWNER/REPO --json"],
        }),
        expect.objectContaining({
          id: "origin",
          status: "pending",
          requirements: ["github:origin"],
          commands: expect.arrayContaining(["git push -u origin HEAD:main"]),
        }),
        expect.objectContaining({ id: "final-verify", status: "pending" }),
      ]),
    );
    expect(parsed.score).toBeGreaterThanOrEqual(90);
    expect(["ultimate", "ready_with_warnings"]).toContain(parsed.readiness);
    expect(parsed.nextSteps.length).toBeGreaterThan(0);
    const strictResult = runCli(["skill", "score", "bug-bounty-pilot", "--strict", "--json"], repoRoot);
    expectCommand(strictResult).toExit(parsed.ultimate ? 0 : 1);
    expect(JSON.parse(outputOf(strictResult)).ultimate).toBe(parsed.ultimate);
    if (parsed.warnings.some((warning: any) => warning.name === "github:origin")) {
      expect(parsed.nextSteps).toEqual(
        expect.arrayContaining([
          "bounty release publish-plan OWNER/REPO --write",
          "bounty release github-bootstrap OWNER/REPO --write",
          "bounty skill score bug-bounty-pilot --repo OWNER/REPO --write-public-plan .bounty/release/public-readiness.md --json",
          "winget install --id GitHub.cli -e",
          "brew install gh",
          "sudo apt-get update && sudo apt-get install -y gh",
          "gh --version",
          "gh auth status",
          "gh auth login",
          "gh repo create OWNER/REPO --public --source . --remote origin --push",
          "git push -u origin HEAD:main",
          "git tag -f v0.1.0 HEAD",
          "bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.1.0 --strict --json",
          "git push origin v0.1.0",
          "bounty release publish-plan OWNER/REPO --branch main --tag v0.1.0 --write",
          "bounty release publish-status OWNER/REPO --branch main --tag v0.1.0 --online --actions --json",
          "bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.1.0 --online --actions --strict --json",
          "bounty release public-gate OWNER/REPO --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
          "bounty release publish-status OWNER/REPO --online --actions --json",
          "bugbounty release install-check --json",
          "bounty skill score bug-bounty-pilot --json",
        ]),
      );
      expect(parsed.nextSteps.indexOf("git tag -f v0.1.0 HEAD")).toBeLessThan(
        parsed.nextSteps.indexOf("bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.1.0 --strict --json"),
      );
      expect(parsed.nextSteps.indexOf("bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.1.0 --strict --json")).toBeLessThan(
        parsed.nextSteps.indexOf("git push origin v0.1.0"),
      );
    }

    const fakeGh = writeFakeGh(mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-fake-gh-")));
    // Run the score against the real repo (needs package.json + skills/ + examples/),
    // but temporarily strip the real origin so the test sees `git:origin: fail` as expected.
    let realOrigin = "";
    try {
      realOrigin = execFileSync("git", ["remote", "get-url", "origin"], { cwd: repoRoot, encoding: "utf8" }).trim();
      if (realOrigin) execFileSync("git", ["remote", "remove", "origin"], { cwd: repoRoot });
    } catch {
      realOrigin = "";
    }
    let scoredForRepo;
    try {
      scoredForRepo = runCli(
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
    } finally {
      if (realOrigin) execFileSync("git", ["remote", "add", "origin", realOrigin], { cwd: repoRoot });
    }
    expectCommand(scoredForRepo).toExit(0);
    const parsedForRepo = JSON.parse(outputOf(scoredForRepo));
    expect(parsedForRepo.github).toMatchObject({
      ok: false,
      repo: "octo/bountypilot",
      tag: "v0.1.0",
    });
    expect(parsedForRepo.layers.local).toMatchObject({ ok: true, ultimate: true, score: 100, readiness: "ultimate" });
    expect(parsedForRepo.layers.publish).toMatchObject({ ok: true, ultimate: false, readiness: "ready_with_warnings" });
    expect(parsedForRepo.layers.publish.score).toBeLessThan(100);
    expect(parsedForRepo.publicReadiness.requirements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "publish:repo", status: "pass", message: "octo/bountypilot" }),
        expect.objectContaining({
          name: "git:origin",
          status: "fail",
          commands: expect.arrayContaining(["git remote add origin https://github.com/octo/bountypilot.git"]),
        }),
        expect.objectContaining({ name: "git:local-tag", commands: ["git tag -f v0.1.0 HEAD"] }),
        expect.objectContaining({
          name: "publish:public-branch",
          status: "warn",
          commands: expect.arrayContaining([
            "git push -u origin HEAD:main",
            "bounty release publish-status octo/bountypilot --branch main --tag v0.1.0 --online --actions --json",
          ]),
        }),
        expect.objectContaining({
          name: "publish:online",
          status: "warn",
          commands: ["bounty release publish-status octo/bountypilot --branch codex/bug-bounty-pilot-candidate-engine --tag v0.1.0 --online --json"],
        }),
        expect.objectContaining({
          name: "github:actions",
          status: "warn",
          commands: expect.arrayContaining(["gh run list --repo octo/bountypilot --limit 10"]),
        }),
      ]),
    );
    expect(parsedForRepo.publicReadiness.missing).toEqual(expect.arrayContaining([expect.objectContaining({ name: "git:origin" })]));
    expect(parsedForRepo.publicReadiness.fixPlan).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "github-cli", status: "pass", commands: [] }),
        expect.objectContaining({
          id: "origin",
          status: "pending",
          commands: expect.arrayContaining(["git push -u origin HEAD:codex/bug-bounty-pilot-candidate-engine"]),
        }),
        expect.objectContaining({ id: "tag" }),
        expect.objectContaining({
          id: "public-branch",
          status: "pending",
          commands: expect.arrayContaining(["git push -u origin HEAD:main"]),
        }),
        expect.objectContaining({
          id: "final-verify",
          status: "pending",
          commands: expect.arrayContaining([
            "bounty skill score bug-bounty-pilot --repo octo/bountypilot --online --actions --strict --json",
            "bounty release public-gate octo/bountypilot --branch codex/bug-bounty-pilot-candidate-engine --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
            "bounty release public-gate octo/bountypilot --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
          ]),
        }),
      ]),
    );
    const planWorkspace = createWorkspace();
    const publicPlanPath = path.join(planWorkspace, "public-readiness.md");
    const scoredWithPublicPlan = runCli(
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
        "--write-public-plan",
        publicPlanPath,
        "--json",
      ],
      repoRoot,
    );
    expectCommand(scoredWithPublicPlan).toExit(0);
    expect(JSON.parse(outputOf(scoredWithPublicPlan))).toMatchObject({
      publicReadinessPlanPath: publicPlanPath,
    });
    const publicPlan = readFileSync(publicPlanPath, "utf8");
    expect(publicPlan).toContain("# BountyPilot Public Readiness Plan");
    expect(publicPlan).toContain("## Ordered Fix Plan");
    expect(publicPlan).toContain("## Next Commands");
    expect(publicPlan).toContain("### Configure GitHub origin");
    expect(publicPlan).toContain("git remote add origin https://github.com/octo/bountypilot.git");
    expect(publicPlan).toContain("bounty skill score bug-bounty-pilot --repo octo/bountypilot --online --actions --strict --json");
    expect(publicPlan).toContain(
      "bounty release public-gate octo/bountypilot --branch codex/bug-bounty-pilot-candidate-engine --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(publicPlan).toContain(
      "bounty release public-gate octo/bountypilot --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(publicPlan).toContain("BountyPilot does not push, publish, or submit anything automatically.");
    expect(parsedForRepo.score).toBeLessThan(97);
    expect(parsedForRepo.readiness).toBe("ready_with_warnings");
    const strictForRepo = runCli(
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
        "--strict",
        "--json",
      ],
      repoRoot,
    );
    expectCommand(strictForRepo).toExit(1);
    expect(JSON.parse(outputOf(strictForRepo))).toMatchObject({
      ultimate: false,
      readiness: "ready_with_warnings",
    });
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
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --write-public-plan .bounty/release/public-readiness.md --json",
        "gh repo create octo/bountypilot --public --source . --remote origin --push",
        "git push -u origin HEAD:main",
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --online --actions --strict --json",
        "bounty release public-gate octo/bountypilot --branch codex/bug-bounty-pilot-candidate-engine --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
        "bounty release public-gate octo/bountypilot --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --json",
      ]),
    );
    // Strip real origin for the published-repo score so it does not skew
    // `git:origin` / `git:origin-target` expectations inside this case.
    let realOriginForPublished = "";
    try {
      realOriginForPublished = execFileSync("git", ["remote", "get-url", "origin"], { cwd: repoRoot, encoding: "utf8" }).trim();
      if (realOriginForPublished) execFileSync("git", ["remote", "remove", "origin"], { cwd: repoRoot });
    } catch {
      realOriginForPublished = "";
    }
    let scoredForPublishedRepo;
    try {
      scoredForPublishedRepo = runCli(
        [
          "skill",
          "score",
          "bug-bounty-pilot",
          "--repo",
          "octo/bountypilot",
          "--branch",
          "main",
          "--tag",
          "v0.1.0",
          "--online",
          "--actions",
          "--gh-command",
          process.execPath,
          "--gh-command-arg",
          fakeGh,
          "--json",
        ],
        repoRoot,
      );
    } finally {
      if (realOriginForPublished) execFileSync("git", ["remote", "add", "origin", realOriginForPublished], { cwd: repoRoot });
    }
    expectCommand(scoredForPublishedRepo).toExit(0);
    const parsedPublished = JSON.parse(outputOf(scoredForPublishedRepo));
    expect(parsedPublished.publish).toMatchObject({
      ok: false,
      repo: "octo/bountypilot",
      branch: "main",
      tag: "v0.1.0",
      online: true,
      actions: true,
    });
    expect(parsedPublished.layers.local).toMatchObject({ ok: true, ultimate: true, score: 100, readiness: "ultimate" });
    expect(parsedPublished.layers.publish).toMatchObject({ ok: true, ultimate: false, readiness: "ready_with_warnings" });
    expect(parsedPublished.publicReadiness.requirements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "publish:repo", status: "pass" }),
        expect.objectContaining({ name: "git:remote-branch", status: "fail", commands: ["git push -u origin HEAD:main"] }),
        expect.objectContaining({
          name: "github:actions:CI",
          status: "pass",
          commands: expect.arrayContaining(["bounty release publish-status octo/bountypilot --branch main --tag v0.1.0 --online --actions --json"]),
        }),
      ]),
    );
    expect(parsedPublished.publicReadiness.missing).toEqual(expect.arrayContaining([expect.objectContaining({ name: "git:remote-branch" })]));
    expect(parsedPublished.publicReadiness.fixPlan).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "branch", status: "pending", commands: ["git push -u origin HEAD:main"] }),
        expect.objectContaining({
          id: "final-verify",
          status: "pending",
          commands: expect.arrayContaining([
            "bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --online --actions --strict --json",
            "bounty release public-gate octo/bountypilot --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
          ]),
        }),
      ]),
    );
    expect(parsedPublished.publish.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "git:remote-branch", status: "fail" }),
        expect.objectContaining({ name: "github:actions:CI", status: "pass" }),
      ]),
    );
    const strictPublished = runCli(
      [
        "skill",
        "score",
        "bug-bounty-pilot",
        "--repo",
        "octo/bountypilot",
        "--branch",
        "main",
        "--tag",
        "v0.1.0",
        "--online",
        "--actions",
        "--strict",
        "--gh-command",
        process.execPath,
        "--gh-command-arg",
        fakeGh,
        "--json",
      ],
      repoRoot,
    );
    expectCommand(strictPublished).toExit(1);
    expect(JSON.parse(outputOf(strictPublished))).toMatchObject({
      ultimate: false,
      publish: { online: true, actions: true },
    });
    expect(parsedForRepo.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "github:origin",
          message: "No origin remote configured. Add one with: git remote add origin https://github.com/octo/bountypilot.git",
        }),
        expect.objectContaining({ name: "git:origin" }),
        expect.objectContaining({ name: "git:origin-target" }),
        expect.objectContaining({ name: "publish:public-branch" }),
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
if (args[0] === "run" && args[1] === "list") {
  const workflowIndex = args.indexOf("--workflow");
  const workflow = workflowIndex >= 0 ? args[workflowIndex + 1] : "CI";
  console.log(JSON.stringify([{ status: "completed", conclusion: "success", workflowName: workflow, url: "https://github.com/octo/bountypilot/actions/runs/1", headBranch: "main", event: "push" }]));
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
