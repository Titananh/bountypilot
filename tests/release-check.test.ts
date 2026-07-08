import { execFileSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { nodeEngineSupportsSqliteRuntime, runPackageReleaseCheck, runReleaseCheck } from "../src/core/release/release-check.js";
import { buildReleaseGithubBootstrap } from "../src/core/release/release-github-bootstrap.js";
import { buildReleaseInstallCheck } from "../src/core/release/release-install-check.js";
import { buildReleasePublishPlan, buildReleasePublishStatus } from "../src/core/release/release-publish-plan.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("release checks", () => {
  it("requires a Node runtime new enough for node:sqlite", () => {
    expect(nodeEngineSupportsSqliteRuntime(">=20")).toBe(false);
    expect(nodeEngineSupportsSqliteRuntime(">=22.12.0")).toBe(false);
    expect(nodeEngineSupportsSqliteRuntime(">=22.13.0")).toBe(true);
    expect(nodeEngineSupportsSqliteRuntime(">=24")).toBe(true);
  });

  it("fails malformed structured example files", () => {
    const root = writeReleaseFixture();
    writeFileSync(path.join(root, "examples", "mcp-steps.json"), "{bad json", "utf8");
    writeFileSync(path.join(root, "examples", "integrations.yml"), "integrations: [", "utf8");

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "examples/mcp-steps.json:json", status: "fail" }),
        expect.objectContaining({ name: "examples/integrations.yml:yaml", status: "fail" }),
      ]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails integration examples with invalid package hash pins", () => {
    const root = writeReleaseFixture();
    writeFileSync(
      path.join(root, "examples", "integrations.yml"),
      `integrations:
  playwright_mcp:
    enabled: false
    type: mcp
    transport: stdio
    execution:
      enabled: false
      package: "@playwright/mcp"
      package_version: "1.0.0"
      entrypoint: "cli.js"
      entrypoint_sha256: "not-a-sha"
    capabilities:
      - browser.navigate
`,
      "utf8",
    );

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "examples/integrations.yml:yaml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub release workflow is missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "workflows", "release.yml"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/workflows/release.yml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("warns when the source checkout has no GitHub origin remote", () => {
    const root = writeReleaseFixture();

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "github:origin", status: "warn" })]),
    );
    expect(result.ok).toBe(true);
  });

  it("passes when a GitHub origin remote is configured", () => {
    const root = writeReleaseFixture();
    execFileSync("git", ["init"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/owner/repo.git"], { cwd: root, stdio: "ignore" });

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "github:origin", status: "pass" })]),
    );
    expect(result.ok).toBe(true);
  });

  it("builds publish status for a clean GitHub checkout", () => {
    const root = writeReleaseFixture();
    execFileSync("git", ["init", "-b", "main"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "bountypilot@example.test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "BountyPilot Test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "fixture"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/owner/repo.git"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["tag", "v0.0.0"], { cwd: root, stdio: "ignore" });

    const result = buildReleasePublishStatus({ cwd: root, repo: "owner/repo", branch: "main", tag: "v0.0.0" });

    expect(result.ok).toBe(true);
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "git:origin-target", status: "pass" }),
        expect.objectContaining({ name: "git:working-tree", status: "pass" }),
        expect.objectContaining({ name: "publish:public-branch", status: "pass" }),
        expect.objectContaining({ name: "git:local-tag", status: "pass" }),
        expect.objectContaining({ name: "publish:online", status: "warn" }),
        expect.objectContaining({ name: "github:actions", status: "warn" }),
      ]),
    );
    expect(result.nextCommands).toContain("bounty release publish-status owner/repo --branch main --tag v0.0.0 --online --json");
    expect(result.nextCommands).toContain("bounty release publish-status owner/repo --branch main --tag v0.0.0 --online --actions --json");
    expect(result.install).toMatchObject({
      npm: "npm install -g github:owner/repo",
      npmPinned: "npm install -g github:owner/repo#main",
      shell: expect.stringContaining("BOUNTYPILOT_SOURCE=github:owner/repo#main"),
      powershell: expect.stringContaining('BOUNTYPILOT_SOURCE="github:owner/repo#main"'),
    });
    expect(result.installVerify).toEqual(
      expect.arrayContaining([
        "npm install -g github:owner/repo",
        "npm install -g github:owner/repo#main",
        "bugbounty release install-check --json",
        expect.stringContaining("BOUNTYPILOT_SOURCE=github:owner/repo#main"),
      ]),
    );
  }, 15_000);

  it("verifies an installed CLI command through the release install check", () => {
    const fakeCli = writeFakeInstalledBounty(mkdtempSync(path.join(os.tmpdir(), "bountypilot-fake-install-")));

    const result = buildReleaseInstallCheck({
      command: process.execPath,
      argsPrefix: [fakeCli],
    });

    expect(result.ok).toBe(true);
    expect(result.version).toBe("0.1.0");
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "command:version", status: "pass" }),
        expect.objectContaining({ name: "command:help", status: "pass" }),
        expect.objectContaining({ name: "skill:validate", status: "pass" }),
        expect.objectContaining({ name: "skill:metadata", status: "pass" }),
        expect.objectContaining({ name: "skill:score", status: "pass" }),
        expect.objectContaining({ name: "quickstart:fresh-user", status: "pass" }),
      ]),
    );
  });

  it("runs installed skill score from a global npm package root", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-global-install-"));
    try {
      const fakeGlobal = writeFakeGlobalInstalledBounty(root);

      const result = buildReleaseInstallCheck({
        command: fakeGlobal.command,
        cwd: root,
      });

      expect(result.ok).toBe(true);
      expect(result.checks).toEqual(expect.arrayContaining([expect.objectContaining({ name: "skill:score", status: "pass" })]));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("checks an installed runtime package without requiring source checkout files", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-installed-runtime-"));
    try {
      writeText(
        root,
        "package.json",
        JSON.stringify(
          {
            name: "bountypilot",
            version: "0.1.0",
            type: "module",
            license: "MIT",
            bin: {
              bugbounty: "dist/cli/index.js",
              bounty: "dist/cli/index.js",
            },
            engines: { node: ">=22.13.0" },
            scripts: {
              build: "tsc -p tsconfig.json",
              test: "vitest run",
              "test:package-bin": "vitest run --config vitest.package.config.ts",
              typecheck: "tsc -p tsconfig.json --noEmit",
              "verify:release": "node scripts/verify-release.mjs",
            },
          },
          null,
          2,
        ),
      );
      writeText(root, "README.md", "# BountyPilot\n");
      writeText(root, "dist/cli/index.js", "#!/usr/bin/env node\n");
      writeText(root, "examples/program.yml", "program: placeholder\n");
      writeText(root, "examples/local-program.yml", "program: local\n");
      writeText(root, "examples/local-lab-authorization.md", "authorized lab\n");
      writeText(root, "examples/safe-workflow.md", "# safe workflow\n");
      cpSync(path.join(repoRoot, "skills", "bug-bounty-pilot"), path.join(root, "skills", "bug-bounty-pilot"), { recursive: true });

      const result = runPackageReleaseCheck(root);

      expect(result.ok).toBe(true);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "compiled bin", status: "pass" }),
          expect.objectContaining({ name: "dist cli shebang", status: "pass" }),
          expect.objectContaining({ name: "skills/bug-bounty-pilot:valid", status: "pass" }),
        ]),
      );
      expect(result.checks).not.toEqual(expect.arrayContaining([expect.objectContaining({ name: ".github/workflows/release.yml" })]));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("warns when a publish plan targets a non-public branch", () => {
    const root = writeReleaseFixture();

    const plan = buildReleasePublishPlan({ cwd: root, repo: "owner/repo", branch: "codex/release-candidate", tag: "v0.0.0" });

    expect(plan.branch).toBe("codex/release-candidate");
    expect(plan.publicBranch).toBe("main");
    expect(plan.commands.localVerify).toContain("bounty skill score bug-bounty-pilot --repo owner/repo --json");
    expect(plan.commands.localVerify).toContain(
      "bounty skill score bug-bounty-pilot --repo owner/repo --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(plan.markdown).toContain("bounty skill score bug-bounty-pilot --repo owner/repo --json");
    expect(plan.markdown).toContain(
      "bounty skill score bug-bounty-pilot --repo owner/repo --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(plan.commands.actionsVerify).toContain(
      "bounty skill score bug-bounty-pilot --repo owner/repo --branch codex/release-candidate --tag v0.0.0 --online --actions --strict --json",
    );
    expect(plan.commands.actionsVerify).toContain(
      "bounty release public-gate owner/repo --branch codex/release-candidate --tag v0.0.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(plan.markdown).toContain(
      "bounty skill score bug-bounty-pilot --repo owner/repo --branch codex/release-candidate --tag v0.0.0 --online --actions --strict --json",
    );
    expect(plan.markdown).toContain(
      "bounty release public-gate owner/repo --branch codex/release-candidate --tag v0.0.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(plan.commands.release).toEqual([
      "git tag v0.0.0",
      "bounty skill score bug-bounty-pilot --repo owner/repo --branch codex/release-candidate --tag v0.0.0 --strict --json",
      "git push origin v0.0.0",
    ]);
    expect(plan.markdown).toContain(
      "bounty skill score bug-bounty-pilot --repo owner/repo --branch codex/release-candidate --tag v0.0.0 --strict --json",
    );
    expect(plan.commands.publicBranchVerify).toEqual([
      "git push -u origin HEAD:main",
      "bounty release publish-plan owner/repo --branch main --tag v0.0.0 --write",
      "bounty release publish-status owner/repo --branch main --tag v0.0.0 --online --actions --json",
    ]);
    expect(plan.markdown).toContain("Before announcing the default one-line install, push and verify the public branch too:");
  });

  it("adds public-branch verification commands when publish status targets a dev branch", () => {
    const root = writeReleaseFixture();
    execFileSync("git", ["init", "-b", "main"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "bountypilot@example.test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "BountyPilot Test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "fixture"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/owner/repo.git"], { cwd: root, stdio: "ignore" });

    const result = buildReleasePublishStatus({ cwd: root, repo: "owner/repo", branch: "codex/release-candidate", tag: "v0.0.0" });

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "publish:public-branch", status: "warn" })]),
    );
    expect(result.nextCommands).toContain("git push -u origin HEAD:main");
    expect(result.nextCommands).toContain("bounty release publish-plan owner/repo --branch main --tag v0.0.0 --write");
    expect(result.nextCommands).toContain("bounty release publish-status owner/repo --branch main --tag v0.0.0 --online --actions --json");
    expect(result.nextCommands).toContain(
      "bounty release public-gate owner/repo --branch codex/release-candidate --tag v0.0.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(result.nextCommands).toContain(
      "bounty skill score bug-bounty-pilot --repo owner/repo --write-public-plan .bounty/release/public-readiness.md --json",
    );
    expect(result.nextCommands.indexOf("git push -u origin HEAD:main")).toBeLessThan(result.nextCommands.indexOf("git push origin v0.0.0"));
    expect(result.nextCommands).toContain(
      "bounty skill score bug-bounty-pilot --repo owner/repo --branch codex/release-candidate --tag v0.0.0 --strict --json",
    );
    expect(result.nextCommands.indexOf("git tag v0.0.0")).toBeLessThan(
      result.nextCommands.indexOf("bounty skill score bug-bounty-pilot --repo owner/repo --branch codex/release-candidate --tag v0.0.0 --strict --json"),
    );
    expect(
      result.nextCommands.indexOf("bounty skill score bug-bounty-pilot --repo owner/repo --branch codex/release-candidate --tag v0.0.0 --strict --json"),
    ).toBeLessThan(result.nextCommands.indexOf("git push origin v0.0.0"));
  });

  it("verifies required GitHub Actions workflows through an injected gh command", () => {
    const root = writeReleaseFixture();
    const fakeGh = writeFakeGh(mkdtempSync(path.join(os.tmpdir(), "bountypilot-fake-gh-")));
    execFileSync("git", ["init", "-b", "main"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "bountypilot@example.test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "BountyPilot Test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "fixture"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/owner/repo.git"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["tag", "v0.0.0"], { cwd: root, stdio: "ignore" });

    const result = buildReleasePublishStatus({
      cwd: root,
      repo: "owner/repo",
      branch: "main",
      tag: "v0.0.0",
      actions: true,
      ghCommand: process.execPath,
      ghArgsPrefix: [fakeGh],
    });

    expect(result.ok).toBe(true);
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "github:actions:CI", status: "pass" }),
        expect.objectContaining({ name: "github:actions:Release", status: "pass" }),
        expect.objectContaining({ name: "github:actions:VM Lab Smoke", status: "pass" }),
        expect.objectContaining({ name: "github:actions:Real Tool VM Smoke", status: "pass" }),
      ]),
    );
    expect(result.nextCommands).not.toContain("gh run list --repo owner/repo --limit 10");
  });

  it("adds GitHub CLI install guidance when actions verification cannot find gh", () => {
    const root = writeReleaseFixture();
    execFileSync("git", ["init", "-b", "main"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "bountypilot@example.test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "BountyPilot Test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "fixture"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/owner/repo.git"], { cwd: root, stdio: "ignore" });

    const result = buildReleasePublishStatus({
      cwd: root,
      repo: "owner/repo",
      branch: "main",
      tag: "v0.0.0",
      actions: true,
      ghCommand: "bountypilot-missing-gh-command",
      timeoutMs: 500,
    });

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "github:actions-gh", status: "fail" })]),
    );
    expect(result.nextCommands).toEqual(expect.arrayContaining([
      "winget install --id GitHub.cli -e",
      "brew install gh",
      "sudo apt-get update && sudo apt-get install -y gh",
      "gh --version",
      "gh auth status",
      "gh auth login",
      "bounty skill score bug-bounty-pilot --repo owner/repo --write-public-plan .bounty/release/public-readiness.md --json",
      "bounty release publish-status owner/repo --branch main --tag v0.0.0 --online --actions --json",
    ]));
  });

  it("orders GitHub CLI setup before repo creation when origin is missing", () => {
    const root = writeReleaseFixture();
    execFileSync("git", ["init", "-b", "main"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "bountypilot@example.test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "BountyPilot Test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "fixture"], { cwd: root, stdio: "ignore" });

    const result = buildReleasePublishStatus({
      cwd: root,
      repo: "owner/repo",
      branch: "main",
      tag: "v0.0.0",
      actions: true,
      ghCommand: "bountypilot-missing-gh-command",
      timeoutMs: 500,
    });

    const installIndex = result.nextCommands.indexOf("winget install --id GitHub.cli -e");
    const authIndex = result.nextCommands.indexOf("gh auth login");
    const createIndex = result.nextCommands.indexOf("gh repo create owner/repo --public --source . --remote origin --push");
    expect(installIndex).toBeGreaterThanOrEqual(0);
    expect(authIndex).toBeGreaterThan(installIndex);
    expect(createIndex).toBeGreaterThan(authIndex);
    expect(result.nextCommands).not.toContain("git remote add origin https://github.com/owner/repo.git");
    expect(result.nextCommands).not.toContain("git push -u origin main");
  });

  it("prints shell-neutral commit commands for dirty release worktrees", () => {
    const root = writeReleaseFixture();
    const fakeGh = writeFakeGh(mkdtempSync(path.join(os.tmpdir(), "bountypilot-fake-gh-dirty-")));
    execFileSync("git", ["init", "-b", "main"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "bountypilot@example.test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "BountyPilot Test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "fixture"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["remote", "add", "origin", "https://github.com/owner/repo.git"], { cwd: root, stdio: "ignore" });
    writeFileSync(path.join(root, "README.md"), "# dirty release fixture\n", "utf8");

    const publishStatus = buildReleasePublishStatus({
      cwd: root,
      repo: "owner/repo",
      branch: "main",
      tag: "v0.0.0",
    });
    expect(publishStatus.nextCommands).toEqual(expect.arrayContaining(["git status --short", "git add .", "git commit -m \"Prepare BountyPilot release\""]));
    expect(publishStatus.nextCommands.join("\n")).not.toContain("git add . && git commit");

    const bootstrap = buildReleaseGithubBootstrap({
      cwd: root,
      repo: "owner/repo",
      branch: "main",
      tag: "v0.0.0",
      ghCommand: process.execPath,
      ghArgsPrefix: [fakeGh],
    });
    expect(bootstrap.nextCommands).toEqual(expect.arrayContaining(["git status --short", "git add .", "git commit -m \"Prepare BountyPilot release\""]));
    expect(bootstrap.nextCommands.join("\n")).not.toContain("git add . && git commit");
  });

  it("builds a GitHub bootstrap bundle with gh/auth probes and publish scripts", () => {
    const root = writeReleaseFixture();
    const fakeGh = writeFakeGh(mkdtempSync(path.join(os.tmpdir(), "bountypilot-fake-gh-bootstrap-")));
    const outputDir = path.join(root, "bootstrap-output");

    const result = buildReleaseGithubBootstrap({
      cwd: root,
      repo: "owner/repo",
      branch: "main",
      tag: "v0.0.0",
      ghCommand: process.execPath,
      ghArgsPrefix: [fakeGh],
      write: true,
      output: outputDir,
    });

    expect(result.ok).toBe(false);
    expect(result.gh.version.status).toBe("pass");
    expect(result.gh.auth.status).toBe("pass");
    expect(result.checks).toEqual(expect.arrayContaining([expect.objectContaining({ name: "git:origin", status: "fail" })]));
    expect(result.nextCommands).toContain("gh repo create owner/repo --public --source . --remote origin --push");
    expect(result.nextCommands).not.toContain("git remote add origin https://github.com/owner/repo.git");
    expect(result.nextCommands).not.toContain("git push -u origin main");
    expect(result.commands.verify).toContain("bugbounty release install-check --json");
    expect(result.outputFiles?.markdown).toBe(path.join(outputDir, "README.md"));
    expect(readFileSync(result.outputFiles!.markdown, "utf8")).toContain("## Local Verification");
    expect(readFileSync(result.outputFiles!.markdown, "utf8")).toContain("gh --version");
    expect(readFileSync(result.outputFiles!.markdown, "utf8")).toContain("bounty release verify-bundle .release --json");
    expect(readFileSync(result.outputFiles!.powershell, "utf8")).toContain("npm run verify:release");
    expect(readFileSync(result.outputFiles!.powershell, "utf8")).toContain("node dist/cli/index.js release verify-bundle .release --json");
    expect(readFileSync(result.outputFiles!.powershell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'owner/repo' --branch 'main' --tag 'v0.0.0' --json",
    );
    expect(readFileSync(result.outputFiles!.powershell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'owner/repo' --write-public-plan '.bounty/release/public-readiness.md' --json",
    );
    expect(readFileSync(result.outputFiles!.powershell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'owner/repo' --branch 'main' --tag 'v0.0.0' --strict --json",
    );
    expect(readFileSync(result.outputFiles!.powershell, "utf8")).toContain(
      "bounty release public-gate 'owner/repo' --branch 'main' --tag 'v0.0.0' --online --actions --install-check --write-public-plan '.bounty/release/public-readiness.md' --json",
    );
    expect(readFileSync(result.outputFiles!.shell, "utf8")).toContain("npm run verify:release");
    expect(readFileSync(result.outputFiles!.shell, "utf8")).toContain("node dist/cli/index.js release verify-bundle .release --json");
    expect(readFileSync(result.outputFiles!.shell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'owner/repo' --branch 'main' --tag 'v0.0.0' --json",
    );
    expect(readFileSync(result.outputFiles!.shell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'owner/repo' --write-public-plan '.bounty/release/public-readiness.md' --json",
    );
    expect(readFileSync(result.outputFiles!.shell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'owner/repo' --branch 'main' --tag 'v0.0.0' --strict --json",
    );
    expect(readFileSync(result.outputFiles!.shell, "utf8")).toContain(
      "bounty release public-gate 'owner/repo' --branch 'main' --tag 'v0.0.0' --online --actions --install-check --write-public-plan '.bounty/release/public-readiness.md' --json",
    );
  });

  it("orders GitHub CLI verification before bootstrap repo creation when gh is missing", () => {
    const root = writeReleaseFixture();

    const result = buildReleaseGithubBootstrap({
      cwd: root,
      repo: "owner/repo",
      branch: "main",
      tag: "v0.0.0",
      ghCommand: "bountypilot-missing-gh-command",
      timeoutMs: 500,
    });

    expect(result.nextCommands).toEqual(
      expect.arrayContaining([
        "winget install --id GitHub.cli -e",
        "brew install gh",
        "sudo apt-get update && sudo apt-get install -y gh",
        "gh --version",
        "gh auth status",
        "gh auth login",
        "gh repo create owner/repo --public --source . --remote origin --push",
      ]),
    );
    expect(result.nextCommands.indexOf("gh --version")).toBeGreaterThan(result.nextCommands.indexOf("winget install --id GitHub.cli -e"));
    expect(result.nextCommands.indexOf("gh auth status")).toBeGreaterThan(result.nextCommands.indexOf("gh --version"));
    expect(result.nextCommands.indexOf("gh auth login")).toBeGreaterThan(result.nextCommands.indexOf("gh auth status"));
    expect(result.nextCommands.indexOf("gh repo create owner/repo --public --source . --remote origin --push")).toBeGreaterThan(
      result.nextCommands.indexOf("gh auth login"),
    );
  });

  it("adds public branch push verification to GitHub bootstrap for non-public branches", () => {
    const root = writeReleaseFixture();
    const fakeGh = writeFakeGh(mkdtempSync(path.join(os.tmpdir(), "bountypilot-fake-gh-public-branch-")));

    const result = buildReleaseGithubBootstrap({
      cwd: root,
      repo: "owner/repo",
      branch: "codex/release-candidate",
      tag: "v0.0.0",
      ghCommand: process.execPath,
      ghArgsPrefix: [fakeGh],
    });

    expect(result.commands.verify).toEqual(
      expect.arrayContaining([
        "git push -u origin HEAD:main",
        "bounty release publish-plan owner/repo --branch main --tag v0.0.0 --write",
        "bounty release publish-status owner/repo --branch main --tag v0.0.0 --online --actions --json",
      ]),
    );
  });

  it("fails when generated release artifacts are tracked in source control", () => {
    const root = writeReleaseFixture();
    execFileSync("git", ["init"], { cwd: root, stdio: "ignore" });
    writeText(root, "artifacts/release/bug-bounty-pilot.skill.zip", "stale bundle");
    execFileSync("git", ["add", "artifacts/release/bug-bounty-pilot.skill.zip"], { cwd: root, stdio: "ignore" });

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "git:tracked-release-artifacts", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when installers do not support pinned GitHub refs", () => {
    const root = writeReleaseFixture();
    writeText(
      root,
      "scripts/install.sh",
      `#!/usr/bin/env bash
MIN_NODE_VERSION="22.13.0"
validate_source_spec() {
  local value="$1"
  if [[ "\${value}" =~ ^bountypilot(@[0-9A-Za-z._+-]+)?$ ]]; then return 0; fi
  if [[ "\${value}" =~ ^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then return 0; fi
  echo "Invalid BOUNTYPILOT_SOURCE: \${value}" >&2
  return 1
}
BOUNTYPILOT_INSTALL_DRY_RUN=1
npm install -g bountypilot
bugbounty skill validate bug-bounty-pilot --json
bugbounty release install-check --json
echo "Install verified: readiness score"
bugbounty skill score bug-bounty-pilot --json
`,
    );

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "scripts/install.sh:content:content",
          status: "fail",
          message: expect.stringContaining("github:OWNER/REPO#ref"),
        }),
      ]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub CodeQL workflow is missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "workflows", "codeql.yml"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/workflows/codeql.yml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub VM lab smoke workflow is missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "workflows", "vm-lab.yml"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/workflows/vm-lab.yml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub real tools smoke workflow is missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "workflows", "real-tools.yml"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/workflows/real-tools.yml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when public repository files are missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, "LICENSE"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "LICENSE", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when the GitHub source install prepare script is missing", () => {
    const root = writeReleaseFixture();
    const packageJsonPath = path.join(root, "package.json");
    const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
    delete packageJson.scripts.prepare;
    writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2), "utf8");

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "script:prepare", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub community templates are missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "pull_request_template.md"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/pull_request_template.md", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails malformed workflow summary examples", () => {
    const root = writeReleaseFixture();
    writeText(
      root,
      "examples/workflow-summary.json",
      JSON.stringify({ ...workflowSummaryExample(), checkpointVersion: 1 }, null, 2),
    );

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "examples/workflow-summary.json:json", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });
});

function writeReleaseFixture(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-release-check-"));
  writeText(
    root,
    "package.json",
    JSON.stringify(
      {
        name: "fixture",
        version: "0.0.0",
        type: "module",
        license: "MIT",
        files: ["dist", "examples", "skills"],
        bin: { bugbounty: "./dist/cli/index.js", bounty: "./dist/cli/index.js" },
        scripts: {
          clean: "echo clean",
          build: "echo build",
          test: "echo test",
          "test:smoke": "echo smoke",
          "test:external-tools": "echo external tools",
          "test:package-bin": "echo package",
          "test:vm-lab": "echo vm lab",
          "test:vm-real-tools": "echo vm real tools",
          typecheck: "echo typecheck",
          "release:check": "echo release",
          sbom: "echo sbom",
          "verify:release": "echo verify",
          prepare: "echo prepare",
          prepack: "echo prepack",
          dev: "echo dev",
        },
        engines: { node: ">=22.13.0" },
      },
      null,
      2,
    ),
  );
  writeText(root, "README.md", "# fixture\n");
  writeText(root, "tsconfig.json", "{}\n");
  writeText(root, "package-lock.json", "{}\n");
  writeText(root, "LICENSE", "MIT License\n");
  writeText(root, "SECURITY.md", "# Security\n");
  writeText(root, "CONTRIBUTING.md", "# Contributing\n");
  writeText(
    root,
    "scripts/install.sh",
    `#!/usr/bin/env bash
MIN_NODE_VERSION="22.13.0"
validate_source_spec() {
  local value="$1"
  if [[ "\${value}" =~ ^bountypilot(@[0-9A-Za-z._+-]+)?$ ]]; then
    return 0
  fi
  if [[ "\${value}" =~ ^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#[A-Za-z0-9._/@+-]+)?$ ]]; then
    return 0
  fi
  echo "Invalid BOUNTYPILOT_SOURCE: \${value}" >&2
  echo "Use bountypilot, bountypilot@<version>, github:OWNER/REPO, or github:OWNER/REPO#ref." >&2
  return 1
}
if [[ -n "\${BOUNTYPILOT_REF:-}" ]]; then
  echo "BOUNTYPILOT_REF=\${BOUNTYPILOT_REF}"
fi
if [[ "\${BOUNTYPILOT_INSTALL_DRY_RUN:-}" == "1" ]]; then
  echo "Dry run: npm install -g bountypilot"
  exit 0
fi
npm install -g bountypilot
bugbounty skill validate bug-bounty-pilot --json
bugbounty release install-check --json
echo "Install verified: readiness score"
bugbounty skill score bug-bounty-pilot --json
`,
  );
  writeText(
    root,
    "scripts/install.ps1",
    `$MinNodeVersion = [version]"22.13.0"
function Assert-BountyPilotSourceSpec {
  param([string]$Value)
  if ($Value -match '^bountypilot(@[0-9A-Za-z._+-]+)?$') { return }
  if ($Value -match '^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#[A-Za-z0-9._/@+-]+)?$') { return }
  Write-Error "Invalid BOUNTYPILOT_SOURCE: $Value. Use bountypilot, bountypilot@<version>, github:OWNER/REPO, or github:OWNER/REPO#ref."
}
if (-not [string]::IsNullOrWhiteSpace($env:BOUNTYPILOT_REF)) {
  Write-Host "BOUNTYPILOT_REF=$($env:BOUNTYPILOT_REF)"
}
if ($env:BOUNTYPILOT_INSTALL_DRY_RUN -eq "1") {
  Write-Host "Dry run: npm install -g bountypilot"
  exit 0
}
npm install -g bountypilot
if ($LASTEXITCODE -ne 0) { Write-Error "npm install failed" }
bugbounty skill validate bug-bounty-pilot --json
bugbounty release install-check --json
Write-Host "Install verified: readiness score"
bugbounty skill score bug-bounty-pilot --json
`,
  );
  writeText(
    root,
    "scripts/vm-real-tools-smoke.sh",
    `#!/usr/bin/env bash
BOUNTYPILOT_VM_REAL_TOOLS_INSTALL="\${BOUNTYPILOT_VM_REAL_TOOLS_INSTALL:-0}"
TARGET="http://127.0.0.1:8080/"
node dist/cli/index.js tools approve-executable httpx --command /home/runner/go/bin/httpx
node dist/cli/index.js tools approve-executable katana --command /home/runner/go/bin/katana
node dist/cli/index.js hunt recon "$TARGET" --profile web --live --tools httpx,katana
`,
  );
  writeText(
    root,
    ".github/workflows/ci.yml",
    `name: CI
on: [push]
jobs:
  verify:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: \${{ matrix.os }}
    steps:
      - run: npm ci
      - run: npm run verify:release
`,
  );
  writeText(
    root,
    ".github/workflows/release.yml",
    `name: Release
on:
  push:
    tags: ["v*"]
permissions:
  attestations: write
  contents: write
  id-token: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
      - run: npm run verify:release
      - run: node dist/cli/index.js release bundle --output .release --force --json
      - run: node dist/cli/index.js release verify-bundle .release --json
      - uses: actions/attest-build-provenance@v2
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            .release/bug-bounty-pilot.skill.zip
            .release/bountypilot-sbom.cdx.json
            .release/release-manifest.json
            .release/SHA256SUMS.txt
`,
  );
  writeText(
    root,
    ".github/workflows/codeql.yml",
    `name: CodeQL
jobs:
  analyze:
    steps:
      - uses: github/codeql-action/init@v3
        with:
          languages: javascript-typescript
          queries: security-extended
      - run: npm run build
`,
  );
  writeText(
    root,
    ".github/workflows/vm-lab.yml",
    `name: VM Lab Smoke
on:
  push:
    branches: [main]
  workflow_dispatch:
jobs:
  packaged-local-lab:
    name: Packaged CLI local lab smoke
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
      - run: npm run test:vm-lab
`,
  );
  writeText(
    root,
    ".github/workflows/real-tools.yml",
    `name: Real Tool VM Smoke
on:
  workflow_dispatch:
jobs:
  real-tool-recon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
      - run: npm run test:vm-real-tools
        env:
          BOUNTYPILOT_VM_REAL_TOOLS_INSTALL: "true"
`,
  );
  writeText(
    root,
    ".github/pull_request_template.md",
    "## Safety Checklist\n- [ ] No real target data\n- [ ] `npm run verify:release`\n",
  );
  writeText(
    root,
    ".github/dependabot.yml",
    "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n    open-pull-requests-limit: 5\n",
  );
  writeText(
    root,
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    "name: Bug report\nbody:\n  - type: markdown\n    attributes:\n      value: Safety confirmation secrets\n",
  );
  writeText(
    root,
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    "name: Feature request\nbody:\n  - type: markdown\n    attributes:\n      value: Safety mode scope, policy\n",
  );
  writeText(root, ".github/ISSUE_TEMPLATE/config.yml", "blank_issues_enabled: false\n");
  writeText(root, "dist/cli/index.js", "#!/usr/bin/env node\n");
  writeText(root, "examples/local-lab-authorization.md", "Authorized local lab.\n");
  writeText(root, "examples/program.yml", programYaml("fixture", false));
  writeText(root, "examples/local-program.yml", programYaml("fixture-local", true));
  writeText(root, "examples/integrations.yml", "integrations: {}\n");
  writeText(root, "examples/tool-registry.yml", "tools: []\n");
  writeText(root, "examples/safe-workflow.md", "# safe workflow\n");
  writeText(root, "examples/mcp-steps.json", JSON.stringify({ steps: [] }, null, 2));
  writeText(root, "examples/workflow-summary.json", JSON.stringify(workflowSummaryExample(), null, 2));
  writeText(root, "examples/sample-finding.json", JSON.stringify({ id: "finding", title: "Title", url: "https://example.com", status: "new", evidencePaths: [] }, null, 2));
  writeText(root, "examples/sample-evidence-manifest.json", JSON.stringify({ generatedAt: "2026-07-05T00:00:00.000Z", artifacts: [] }, null, 2));
  writeText(root, "examples/sample-report.md", "# report\n");
  writeText(root, "examples/evidence/finding-example-security-header/reproduction.md", "# reproduction\n");
  writeText(
    root,
    "examples/evidence/finding-example-security-header/safe-check-output.json",
    JSON.stringify({ target: "https://example.com", checks: [], safeTesting: true }, null, 2),
  );
  cpSync(path.join(repoRoot, "skills", "bug-bounty-pilot"), path.join(root, "skills", "bug-bounty-pilot"), { recursive: true });
  return root;
}

function workflowSummaryExample(): Record<string, unknown> {
  return {
    checkpointVersion: 2,
    jobId: "job-example",
    status: "completed",
    program: "fixture",
    mode: "safe",
    dryRun: false,
    draftReports: false,
    components: ["safe-checks"],
    seeds: ["https://example.com/"],
    skippedScopeRules: [],
    phases: [
      { name: "research-note", status: "skipped", detail: "already completed" },
      { name: "safe-checks", status: "completed", target: "https://example.com/", detail: "example.com: 0 candidates." },
    ],
    findingsCreated: 0,
    candidatesCreated: 0,
    evidenceCreated: 1,
    actionsPlanned: 1,
    actionCounts: {
      total: 1,
      pending: 0,
      approved: 0,
      executed: 1,
      blocked: 0,
      failed: 0,
    },
    reportsDrafted: 0,
    startedAt: "2026-07-05T00:00:00.000Z",
    updatedAt: "2026-07-05T00:01:00.000Z",
    resumeSkippedWork: [{ phase: "research-note" }],
  };
}

function writeText(root: string, relativePath: string, content: string): void {
  const filePath = path.join(root, relativePath);
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, content.endsWith("\n") ? content : `${content}\n`, "utf8");
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
  const workflow = args[args.indexOf("--workflow") + 1] || "unknown";
  console.log(JSON.stringify([{ status: "completed", conclusion: "success", workflowName: workflow, url: "https://github.com/owner/repo/actions/runs/1", headBranch: "main", event: "push" }]));
  process.exit(0);
}
console.error("unexpected gh args " + args.join(" "));
process.exit(1);
`,
    "utf8",
  );
  return scriptPath;
}

function writeFakeInstalledBounty(root: string): string {
  const scriptPath = path.join(root, "fake-bugbounty.mjs");
  writeFileSync(
    scriptPath,
    `const args = process.argv.slice(2);
if (args[0] === "--version") {
  console.log("0.1.0");
  process.exit(0);
}
if (args[0] === "--help") {
  console.log("BountyPilot safe, local-first, scoped bug bounty CLI");
  process.exit(0);
}
if (args.join(" ") === "skill validate bug-bounty-pilot --json") {
  console.log(JSON.stringify({ ok: true, checks: [{ name: "skill", status: "pass" }] }));
  process.exit(0);
}
if (args.join(" ") === "skill show bug-bounty-pilot --json") {
  console.log(JSON.stringify({
    ok: true,
    id: "bug-bounty-pilot",
    frontmatter: {
      name: "bug-bounty-pilot",
      description: "Safe local-first bug bounty workflow engine for authorized scoped targets."
    },
    agentMetadata: {
      interface: {
        display_name: "Bug Bounty Pilot",
        default_prompt: "Use $bug-bounty-pilot to plan a scoped workflow."
      }
    }
  }));
  process.exit(0);
}
if (args.join(" ") === "skill score bug-bounty-pilot --json") {
  console.log(JSON.stringify({
    ok: true,
    score: 97,
    readiness: "ready_with_warnings",
    validation: { failures: [] },
    bundle: { ok: true },
    release: { ok: true }
  }));
  process.exit(0);
}
if (args.join(" ") === "quickstart --json") {
  console.log(JSON.stringify({ status: "needs_review", workspace: { found: false }, nextCommands: ["bounty init --guided"] }));
  process.exit(0);
}
console.error("unexpected fake bugbounty args " + args.join(" "));
process.exit(1);
`,
    "utf8",
  );
  return scriptPath;
}

function writeFakeGlobalInstalledBounty(root: string): { command: string; packageRoot: string } {
  const prefix = path.join(root, "prefix");
  const packageRoot = path.join(prefix, "node_modules", "bountypilot");
  mkdirSync(packageRoot, { recursive: true });
  writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ name: "bountypilot", version: "0.1.0" }), "utf8");
  const scriptPath = path.join(root, "fake-global-bugbounty.mjs");
  writeFileSync(
    scriptPath,
    `const args = process.argv.slice(2);
const expectedPackageRoot = ${JSON.stringify(packageRoot)};
if (args[0] === "--version") {
  console.log("0.1.0");
  process.exit(0);
}
if (args[0] === "--help") {
  console.log("BountyPilot safe, local-first, scoped bug bounty CLI");
  process.exit(0);
}
if (args.join(" ") === "skill validate bug-bounty-pilot --json") {
  console.log(JSON.stringify({ ok: true, checks: [{ name: "skill", status: "pass" }] }));
  process.exit(0);
}
if (args.join(" ") === "skill show bug-bounty-pilot --json") {
  console.log(JSON.stringify({
    ok: true,
    frontmatter: { name: "bug-bounty-pilot" },
    agentMetadata: { interface: { default_prompt: "Use $bug-bounty-pilot to plan a scoped workflow." } }
  }));
  process.exit(0);
}
if (args.join(" ") === "skill score bug-bounty-pilot --json") {
  if (process.cwd() !== expectedPackageRoot) {
    console.error("skill score cwd was " + process.cwd());
    process.exit(1);
  }
  console.log(JSON.stringify({
    ok: true,
    score: 97,
    readiness: "ready_with_warnings",
    validation: { failures: [] },
    bundle: { ok: true },
    release: { ok: true }
  }));
  process.exit(0);
}
if (args.join(" ") === "quickstart --json") {
  console.log(JSON.stringify({ status: "needs_review", workspace: { found: false }, nextCommands: ["bounty init --guided"] }));
  process.exit(0);
}
console.error("unexpected fake global bugbounty args " + args.join(" "));
process.exit(1);
`,
    "utf8",
  );
  if (process.platform === "win32") {
    const command = path.join(prefix, "bugbounty.cmd");
    writeFileSync(command, `@echo off\r\n"${process.execPath}" "${scriptPath}" %*\r\n`, "utf8");
    return { command, packageRoot };
  }
  const command = path.join(prefix, "bugbounty");
  writeFileSync(command, `#!/usr/bin/env sh\nexec "${process.execPath}" "${scriptPath}" "$@"\n`, "utf8");
  chmodSync(command, 0o755);
  return { command, packageRoot };
}

function programYaml(program: string, lab: boolean): string {
  return `program: ${program}
platform: hackerone
in_scope:
  - example.com
out_of_scope: []
rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "1rps"
  browser_crawling: true
  deep_safe_mode: true
  lab_mode: ${lab ? "true" : "false"}
${lab ? "  lab_authorization_file: local-lab-authorization.md\n" : ""}  require_human_approval_for_risky_actions: true
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
