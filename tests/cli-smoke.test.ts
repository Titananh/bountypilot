import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bountyCli = path.join(repoRoot, "dist", "cli", "index.js");

const programYaml = `program: cli-smoke
platform: hackerone

in_scope:
  - "*.smoke.example"
  - "api.smoke.example"

out_of_scope:
  - "staging.smoke.example"
  - "*.internal.smoke.example"

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
  playwright:
    enabled: true
`;

const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("CLI smoke", () => {
  it("prints version as a successful informational command", () => {
    const workspace = createWorkspace();

    const version = runCli(["--version"], workspace);
    expectCommand(version).toExit(0);
    expect(version.stdout.trim()).toBe("0.1.0");
    expect(version.stderr).toBe("");
  });

  it("prints JSON envelopes for Commander usage errors when --json is requested", () => {
    const workspace = createWorkspace();

    const unknownCommand = runCli(["does-not-exist", "--json"], workspace);
    expectCommand(unknownCommand).toExit(1);
    expect(unknownCommand.stderr).toBe("");
    expect(JSON.parse(unknownCommand.stdout)).toMatchObject({
      ok: false,
      error: { code: "CLI_UNKNOWN_COMMAND" },
    });

    const missingArgument = runCli(["programs", "validate", "--json"], workspace);
    expectCommand(missingArgument).toExit(1);
    expect(missingArgument.stderr).toBe("");
    expect(JSON.parse(missingArgument.stdout)).toMatchObject({
      ok: false,
      error: { code: "CLI_MISSING_ARGUMENT" },
    });

    const unknownOption = runCli(["programs", "list", "--json", "--bogus"], workspace);
    expectCommand(unknownOption).toExit(1);
    expect(unknownOption.stderr).toBe("");
    expect(JSON.parse(unknownOption.stdout)).toMatchObject({
      ok: false,
      error: { code: "CLI_UNKNOWN_OPTION" },
    });
  });

  it("strips execution opt-ins from imported program files", () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(
      programFile,
      `program: imported-exec-optins
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
  crawl4ai:
    enabled: true
    type: crawler
    command: ${yamlSingle(process.execPath)}
    allow_execute: true
    execution:
      enabled: true
      command: ${yamlSingle(process.execPath)}
    capabilities:
      - crawler.fetch
`,
      "utf8",
    );

    expectCommand(runCli(["init"], workspace)).toExit(0);
    const imported = runCli(["import", programFile, "--json"], workspace);
    expectCommand(imported).toExit(0);
    expect(imported.stderr).toBe("");
    const parsedImport = JSON.parse(imported.stdout);
    expect(parsedImport.strippedExecutionOptIns).toEqual(
      expect.arrayContaining([
        { integration: "crawl4ai", field: "allow_execute" },
        { integration: "crawl4ai", field: "execution.enabled" },
      ]),
    );
    expect(parsedImport.config.integrations.crawl4ai.allow_execute).toBe(false);
    expect(parsedImport.config.integrations.crawl4ai.execution.enabled).toBe(false);

    const show = runCli(["programs", "show", "imported-exec-optins", "--json"], workspace);
    expectCommand(show).toExit(0);
    const saved = JSON.parse(show.stdout).config.integrations.crawl4ai;
    expect(saved.allow_execute).toBe(false);
    expect(saved.execution.enabled).toBe(false);
  });

  it("copies lab authorization files on import and allows local lab dry-runs", () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "local-program.yml");
    const authDir = path.join(workspace, "auth");
    mkdirSync(authDir, { recursive: true });
    writeFileSync(path.join(authDir, "lab.md"), "Authorized local lab owned by the researcher.\n", "utf8");
    writeFileSync(
      programFile,
      `program: imported-local-lab
platform: local
in_scope:
  - "127.0.0.1"
out_of_scope: []
rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "100rps"
  browser_crawling: true
  deep_safe_mode: true
  lab_mode: true
  lab_authorization_file: auth/lab.md
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
`,
      "utf8",
    );

    expectCommand(runCli(["init"], workspace)).toExit(0);
    const imported = runCli(["import", programFile, "--json"], workspace);
    expectCommand(imported).toExit(0);
    const payload = JSON.parse(imported.stdout);
    expect(payload.labAuthorizationFile).toContain(`${path.sep}auth${path.sep}lab.md`);
    expect(existsSync(path.join(workspace, ".bounty", "programs", "imported-local-lab", "auth", "lab.md"))).toBe(true);

    const dryRun = runCli(["-p", "imported-local-lab", "run", "127.0.0.1", "--mode", "lab-offensive", "--dry-run", "--json"], workspace);
    expectCommand(dryRun).toExit(0);
    expect(JSON.parse(dryRun.stdout).summary.mode).toBe("lab-offensive");
  }, 20_000);

  it("exercises help, doctor, scope, tools doctor, and run dry-run without external scanning", async () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, programYaml, "utf8");

    const help = runCli(["--help"], workspace);
    expectCommand(help).toExit(0);
    expect(outputOf(help)).toContain("BountyPilot safe, local-first");
    expect(outputOf(help)).toContain("doctor");
    expect(outputOf(help)).toContain("Common workflows");

    const quickstartFreshJson = runCli(["quickstart", "https://api.smoke.example", "--json"], workspace);
    expectCommand(quickstartFreshJson).toExit(0);
    expect(quickstartFreshJson.stderr).toBe("");
    const parsedFreshQuickstart = JSON.parse(quickstartFreshJson.stdout);
    expect(parsedFreshQuickstart.status).toBe("needs_review");
    expect(parsedFreshQuickstart.workspace.found).toBe(false);
    expect(parsedFreshQuickstart.sections.map((section: any) => section.id)).toEqual(
      expect.arrayContaining(["workspace", "providers", "arsenal", "hunt", "results"]),
    );

    const doctorBeforeInit = runCli(["doctor"], workspace);
    expectCommand(doctorBeforeInit).toExit(0);
    expect(outputOf(doctorBeforeInit)).toContain("workspace missing");
    expect(outputOf(doctorBeforeInit)).toContain("next commands");
    expect(outputOf(doctorBeforeInit)).toContain("$ bounty init");

    const guidedInitJson = runCli(["init", "--guided", "--program-file", programFile, "--json"], workspace);
    expectCommand(guidedInitJson).toExit(0);
    expect(guidedInitJson.stderr).toBe("");
    const parsedGuidedInit = JSON.parse(guidedInitJson.stdout);
    expect(parsedGuidedInit.guided).toBe(true);
    expect(parsedGuidedInit.import.program).toBe("cli-smoke");
    expect(parsedGuidedInit.doctor.programs.count).toBe(1);
    expect(parsedGuidedInit.nextCommands).toContain("bounty dashboard");

    const init = runCli(["init"], workspace);
    expectCommand(init).toExit(0);
    expect(outputOf(init)).toContain("workspace initialized");

    const initJson = runCli(["init", "--json"], workspace);
    expectCommand(initJson).toExit(0);
    expect(initJson.stderr).toBe("");
    expect(JSON.parse(initJson.stdout).ok).toBe(true);

    const imported = runCli(["import", programFile], workspace);
    expectCommand(imported).toExit(0);
    expect(outputOf(imported)).toContain("imported cli-smoke");

    const importJson = runCli(["import", programFile, "--json"], workspace);
    expectCommand(importJson).toExit(0);
    expect(importJson.stderr).toBe("");
    expect(JSON.parse(importJson.stdout).program).toBe("cli-smoke");

    const quickstartPath = path.join(workspace, "quickstart.md");
    const quickstartJson = runCli(
      ["quickstart", "https://api.smoke.example", "--profile", "web", "--write", "--output", quickstartPath, "--json"],
      workspace,
    );
    expectCommand(quickstartJson).toExit(0);
    expect(quickstartJson.stderr).toBe("");
    const parsedQuickstart = JSON.parse(quickstartJson.stdout);
    expect(parsedQuickstart.program.name).toBe("cli-smoke");
    expect(parsedQuickstart.target).toBe("https://api.smoke.example");
    expect(parsedQuickstart.huntDoctor.ok).toBe(true);
    expect(parsedQuickstart.outputPath).toBe(quickstartPath);
    expect(parsedQuickstart.nextCommands).toEqual(expect.arrayContaining(["bounty providers catalog"]));
    expect(existsSync(quickstartPath)).toBe(true);
    expect(readFileSync(quickstartPath, "utf8")).toContain("# BountyPilot Quickstart Runbook");

    const quickstartHuman = runCli(["quickstart", "https://api.smoke.example", "--profile", "web"], workspace);
    expectCommand(quickstartHuman).toExit(0);
    expect(outputOf(quickstartHuman)).toContain("quickstart");
    expect(outputOf(quickstartHuman)).toContain("Workspace And Scope");

    const programsList = runCli(["programs", "list"], workspace);
    expectCommand(programsList).toExit(0);
    expect(outputOf(programsList)).toContain("cli-smoke");
    expect(outputOf(programsList)).toContain("ready");

    const programsListJson = runCli(["programs", "list", "--json"], workspace);
    expectCommand(programsListJson).toExit(0);
    expect(outputOf(programsListJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(programsListJson)).programs[0].name).toBe("cli-smoke");

    const programsShowJson = runCli(["programs", "show", "cli-smoke", "--json"], workspace);
    expectCommand(programsShowJson).toExit(0);
    expect(outputOf(programsShowJson).trimStart().startsWith("{")).toBe(true);
    const parsedProgram = JSON.parse(outputOf(programsShowJson));
    expect(parsedProgram.config.program).toBe("cli-smoke");
    expect(parsedProgram.paths.programDir).toContain("cli-smoke");

    const programsValidateJson = runCli(["programs", "validate", programFile, "--json"], workspace);
    expectCommand(programsValidateJson).toExit(0);
    expect(outputOf(programsValidateJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(programsValidateJson)).ok).toBe(true);

    const doctorAfterInit = runCli(["doctor"], workspace);
    expectCommand(doctorAfterInit).toExit(0);
    expect(outputOf(doctorAfterInit)).toContain("workspace found");
    expect(outputOf(doctorAfterInit)).toContain("next commands");
    expect(outputOf(doctorAfterInit)).toContain("$ bounty dashboard");

    const releaseCheck = runCli(["release", "check", "--json"], repoRoot);
    expectCommand(releaseCheck).toExit(0);
    expect(outputOf(releaseCheck).trimStart().startsWith("{")).toBe(true);
    const parsedRelease = JSON.parse(outputOf(releaseCheck));
    expect(parsedRelease.ok).toBe(true);
    expect(parsedRelease.checks.length).toBeGreaterThan(0);

    const releaseBundleDir = path.join(workspace, "release-artifacts");
    const releaseBundle = runCli(["release", "bundle", "--output", releaseBundleDir, "--skip-sbom", "--json"], repoRoot);
    expectCommand(releaseBundle).toExit(0);
    expect(releaseBundle.stderr).toBe("");
    const parsedReleaseBundle = JSON.parse(releaseBundle.stdout);
    expect(parsedReleaseBundle).toMatchObject({
      ok: true,
      outputDir: releaseBundleDir,
      manifestPath: path.join(releaseBundleDir, "release-manifest.json"),
      checksumsPath: path.join(releaseBundleDir, "SHA256SUMS.txt"),
    });
    expect(parsedReleaseBundle.artifacts.map((artifact: { kind: string }) => artifact.kind)).toEqual(
      expect.arrayContaining(["npm-tarball", "skill-bundle", "manifest", "checksums"]),
    );
    expect(existsSync(path.join(releaseBundleDir, "release-manifest.json"))).toBe(true);
    expect(readFileSync(path.join(releaseBundleDir, "SHA256SUMS.txt"), "utf8")).toContain("bug-bounty-pilot.skill.zip");
    expect(readdirSync(releaseBundleDir).some((entry) => /^bountypilot-.*\.tgz$/.test(entry))).toBe(true);
    const releaseManifest = JSON.parse(readFileSync(path.join(releaseBundleDir, "release-manifest.json"), "utf8"));
    expect(releaseManifest.artifacts.every((artifact: { path: string }) => !path.isAbsolute(artifact.path))).toBe(true);

    const releaseBundleVerify = runCli(["release", "verify-bundle", releaseBundleDir, "--json"], repoRoot);
    expectCommand(releaseBundleVerify).toExit(0);
    expect(releaseBundleVerify.stderr).toBe("");
    const parsedReleaseBundleVerify = JSON.parse(releaseBundleVerify.stdout);
    expect(parsedReleaseBundleVerify).toMatchObject({
      ok: true,
      bundleDir: releaseBundleDir,
      files: { missing: [], mismatched: [], extra: [] },
    });
    expect(parsedReleaseBundleVerify.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "skill-bundle:verify", status: "pass" })]),
    );
    writeFileSync(path.join(releaseBundleDir, "unexpected.txt"), "tamper\n", "utf8");
    const tamperedReleaseBundleVerify = runCli(["release", "verify-bundle", releaseBundleDir, "--json"], repoRoot);
    expectCommand(tamperedReleaseBundleVerify).toExit(1);
    expect(JSON.parse(tamperedReleaseBundleVerify.stdout).files.extra).toContain("unexpected.txt");

    const publishPlanPath = path.join(workspace, "github-publish-plan.md");
    const publishPlan = runCli(
      [
        "release",
        "publish-plan",
        "octo/bountypilot",
        "--branch",
        "main",
        "--tag",
        "v0.1.0",
        "--write",
        "--output",
        publishPlanPath,
        "--json",
      ],
      repoRoot,
    );
    expectCommand(publishPlan).toExit(0);
    expect(publishPlan.stderr).toBe("");
    const parsedPublishPlan = JSON.parse(publishPlan.stdout);
    expect(parsedPublishPlan).toMatchObject({
      ok: true,
      repo: { slug: "octo/bountypilot", httpsRemote: "https://github.com/octo/bountypilot.git" },
      branch: "main",
      tag: "v0.1.0",
      outputPath: publishPlanPath,
      });
      expect(parsedPublishPlan.commands.remoteSetup.join("\n")).toContain("https://github.com/octo/bountypilot.git");
      expect(parsedPublishPlan.commands.githubCliPreflight).toEqual(["gh --version", "gh auth status", "gh auth login"]);
      expect(parsedPublishPlan.commands.repositoryCreate).toContain("gh repo create octo/bountypilot --public --source . --remote origin --push");
      expect(parsedPublishPlan.commands.postPushVerify).toContain("bounty release publish-status octo/bountypilot --branch main --tag v0.1.0 --online --json");
      expect(parsedPublishPlan.commands.actionsVerify).toContain("bounty release publish-status octo/bountypilot --branch main --tag v0.1.0 --online --actions --json");
      expect(parsedPublishPlan.commands.actionsVerify).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --online --actions --strict --json",
      );
      expect(parsedPublishPlan.commands.actionsVerify).toContain(
        "bounty release public-gate octo/bountypilot --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
      );
    expect(parsedPublishPlan.commands.actionsVerify).toContain("gh run list --repo octo/bountypilot --limit 10");
      expect(parsedPublishPlan.commands.localVerify).toContain("bounty skill score bug-bounty-pilot --repo octo/bountypilot --json");
      expect(parsedPublishPlan.commands.localVerify).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --write-public-plan .bounty/release/public-readiness.md --json",
      );
      expect(parsedPublishPlan.commands.localVerify).toContain("bounty release verify-bundle .release --json");
      expect(parsedPublishPlan.commands.release).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --strict --json",
      );
      expect(parsedPublishPlan.commands.installVerify.join("\n")).toContain("BOUNTYPILOT_INSTALL_DRY_RUN=1");
      expect(parsedPublishPlan.commands.installVerify).toContain("npm install -g github:octo/bountypilot#main");
      expect(parsedPublishPlan.install.npm).toBe("npm install -g github:octo/bountypilot");
      expect(parsedPublishPlan.install.npmPinned).toBe("npm install -g github:octo/bountypilot#main");
      expect(parsedPublishPlan.install.shell).toContain("BOUNTYPILOT_SOURCE=github:octo/bountypilot#main");
      expect(parsedPublishPlan.install.powershell).toContain('BOUNTYPILOT_SOURCE="github:octo/bountypilot#main"');
      expect(parsedPublishPlan.install.shellDryRun).toContain("BOUNTYPILOT_INSTALL_DRY_RUN=1");
      expect(parsedPublishPlan.install.shellDryRun).toContain("BOUNTYPILOT_SOURCE=github:octo/bountypilot#main");
      expect(parsedPublishPlan.install.powershellDryRun).toContain('BOUNTYPILOT_INSTALL_DRY_RUN="1"');
      expect(parsedPublishPlan.install.powershellDryRun).toContain('BOUNTYPILOT_SOURCE="github:octo/bountypilot#main"');
      expect(existsSync(publishPlanPath)).toBe(true);
      expect(readFileSync(publishPlanPath, "utf8")).toContain("bounty skill score bug-bounty-pilot --repo octo/bountypilot --json");
      expect(readFileSync(publishPlanPath, "utf8")).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --write-public-plan .bounty/release/public-readiness.md --json",
      );
      expect(readFileSync(publishPlanPath, "utf8")).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --strict --json",
      );
      expect(readFileSync(publishPlanPath, "utf8")).toContain("bounty release verify-bundle .release --json");
      expect(readFileSync(publishPlanPath, "utf8")).toContain("gh auth status");
      expect(readFileSync(publishPlanPath, "utf8")).toContain("gh auth login");
      expect(readFileSync(publishPlanPath, "utf8")).toContain("gh repo create octo/bountypilot");
      expect(readFileSync(publishPlanPath, "utf8")).toContain("npm install -g github:octo/bountypilot#main");
      expect(readFileSync(publishPlanPath, "utf8")).toContain("BOUNTYPILOT_SOURCE=github:octo/bountypilot#main");
      expect(readFileSync(publishPlanPath, "utf8")).toContain("bounty release publish-status octo/bountypilot --branch main --tag v0.1.0 --online --json");
      expect(readFileSync(publishPlanPath, "utf8")).toContain("bounty release publish-status octo/bountypilot --branch main --tag v0.1.0 --online --actions --json");
      expect(readFileSync(publishPlanPath, "utf8")).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --online --actions --strict --json",
      );
      expect(readFileSync(publishPlanPath, "utf8")).toContain(
        "bounty release public-gate octo/bountypilot --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
      );
    expect(readFileSync(publishPlanPath, "utf8")).toContain("Verify installer resolution");
    expect(readFileSync(publishPlanPath, "utf8")).toContain("git push origin v0.1.0");

    const publishPlanHuman = runCli(["release", "publish-plan", "octo/bountypilot", "--branch", "main", "--tag", "v0.1.0"], repoRoot);
    expectCommand(publishPlanHuman).toExit(0);
    expect(outputOf(publishPlanHuman)).toContain("github cli preflight");
    expect(outputOf(publishPlanHuman)).toContain("gh auth login");

    const fakeGh = writeFakeGh(mkdtempSync(path.join(os.tmpdir(), "bountypilot-cli-fake-gh-")));
    const bootstrapDir = path.join(workspace, "github-bootstrap");
    const bootstrap = runCli(
      [
        "release",
        "github-bootstrap",
        "octo/bountypilot",
        "--branch",
        "main",
        "--tag",
        "v0.1.0",
        "--gh-command",
        process.execPath,
        "--gh-command-arg",
        fakeGh,
        "--write",
        "--output",
        bootstrapDir,
        "--json",
      ],
      repoRoot,
    );
    expectCommand(bootstrap).toExit(0);
    expect(bootstrap.stderr).toBe("");
    const parsedGithubBootstrap = JSON.parse(bootstrap.stdout);
    expect(parsedGithubBootstrap.repo.slug).toBe("octo/bountypilot");
    expect(parsedGithubBootstrap.gh.version.status).toBe("pass");
    expect(parsedGithubBootstrap.gh.auth.status).toBe("pass");
    expect(parsedGithubBootstrap.commands.verify).toContain("bugbounty release install-check --json");
    expect(parsedGithubBootstrap.outputFiles.markdown).toBe(path.join(bootstrapDir, "README.md"));
    expect(readFileSync(parsedGithubBootstrap.outputFiles.markdown, "utf8")).toContain("## Local Verification");
    expect(readFileSync(parsedGithubBootstrap.outputFiles.powershell, "utf8")).toContain("npm run verify:release");
    expect(readFileSync(parsedGithubBootstrap.outputFiles.powershell, "utf8")).toContain("node dist/cli/index.js release verify-bundle .release --json");
    expect(readFileSync(parsedGithubBootstrap.outputFiles.powershell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'octo/bountypilot' --branch 'main' --tag 'v0.1.0' --json",
    );
    expect(readFileSync(parsedGithubBootstrap.outputFiles.powershell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'octo/bountypilot' --branch 'main' --tag 'v0.1.0' --strict --json",
    );
    expect(readFileSync(parsedGithubBootstrap.outputFiles.shell, "utf8")).toContain("npm run verify:release");
    expect(readFileSync(parsedGithubBootstrap.outputFiles.shell, "utf8")).toContain("node dist/cli/index.js release verify-bundle .release --json");
    expect(readFileSync(parsedGithubBootstrap.outputFiles.shell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'octo/bountypilot' --branch 'main' --tag 'v0.1.0' --json",
    );
    expect(readFileSync(parsedGithubBootstrap.outputFiles.shell, "utf8")).toContain(
      "node dist/cli/index.js skill score bug-bounty-pilot --repo 'octo/bountypilot' --branch 'main' --tag 'v0.1.0' --strict --json",
    );
    expect(readFileSync(parsedGithubBootstrap.outputFiles.shell, "utf8")).toContain("gh repo create 'octo/bountypilot'");

    const publishStatusPlanPath = path.join(workspace, "publish-status-public-readiness.md");
    const publishStatus = runCli(
      [
        "release",
        "publish-status",
        "octo/bountypilot",
        "--branch",
        "main",
        "--tag",
        "v0.1.0",
        "--write-public-plan",
        publishStatusPlanPath,
        "--json",
      ],
      repoRoot,
    );
    expectCommand(publishStatus).toExit(1);
    expect(publishStatus.stderr).toBe("");
    const parsedPublishStatus = JSON.parse(publishStatus.stdout);
    expect(parsedPublishStatus.ok).toBe(false);
    expect(parsedPublishStatus.publicReadinessPlanPath).toBe(publishStatusPlanPath);
    expect(readFileSync(publishStatusPlanPath, "utf8")).toContain("# BountyPilot Public Readiness Plan");
    expect(readFileSync(publishStatusPlanPath, "utf8")).toContain("octo/bountypilot");
    expect(parsedPublishStatus.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "release:check", status: "pass" }),
        expect.objectContaining({ name: "git:origin-target", status: "fail" }),
        expect.objectContaining({ name: "github:actions", status: "warn" }),
      ]),
      );
      expect(parsedPublishStatus.nextCommands.join("\n")).toMatch(/bounty release publish-plan octo\/bountypilot --write|git remote set-url origin https:\/\/github\.com\/octo\/bountypilot\.git/);
      expect(parsedPublishStatus.nextCommands).toContain("bounty release github-bootstrap octo/bountypilot --branch main --tag v0.1.0 --write");
      expect(parsedPublishStatus.nextCommands).toContain("gh auth login");
      expect(parsedPublishStatus.nextCommands).toContain("gh repo create octo/bountypilot --public --source . --remote origin --push");
      expect(parsedPublishStatus.nextCommands).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --write-public-plan .bounty/release/public-readiness.md --json",
      );
      expect(parsedPublishStatus.nextCommands).toContain(
        "bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --strict --json",
      );
      expect(parsedPublishStatus.nextCommands).toContain(
        "bounty release public-gate octo/bountypilot --branch main --tag v0.1.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json",
      );
      expect(parsedPublishStatus.nextCommands.indexOf("git tag -f v0.1.0 HEAD")).toBeLessThan(
        parsedPublishStatus.nextCommands.indexOf("bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --strict --json"),
      );
      expect(
        parsedPublishStatus.nextCommands.indexOf("bounty skill score bug-bounty-pilot --repo octo/bountypilot --branch main --tag v0.1.0 --strict --json"),
      ).toBeLessThan(parsedPublishStatus.nextCommands.indexOf("git push origin v0.1.0"));
      expect(parsedPublishStatus.install).toMatchObject({
        npm: "npm install -g github:octo/bountypilot",
        npmPinned: "npm install -g github:octo/bountypilot#main",
      });
      expect(parsedPublishStatus.installVerify).toContain("npm install -g github:octo/bountypilot#main");
      expect(parsedPublishStatus.installVerify).toContain("bugbounty release install-check --json");

      const publicGatePlanPath = path.join(workspace, "public-gate-readiness.md");
      const fakeInstalledCli = writeFakeInstalledBounty(mkdtempSync(path.join(os.tmpdir(), "bountypilot-cli-install-check-")));
      const publicGate = runCli(
        [
          "release",
          "public-gate",
          "octo/bountypilot",
          "--branch",
          "main",
          "--tag",
          "v0.1.0",
          "--write-public-plan",
          publicGatePlanPath,
          "--actions",
          "--gh-command",
          process.execPath,
          "--gh-command-arg",
          fakeGh,
          "--install-check",
          "--install-command",
          process.execPath,
          "--install-command-arg",
          fakeInstalledCli,
          "--json",
        ],
        repoRoot,
      );
      expectCommand(publicGate).toExit(1);
      expect(publicGate.stderr).toBe("");
      const parsedPublicGate = JSON.parse(publicGate.stdout);
      expect(parsedPublicGate.ok).toBe(false);
      expect(parsedPublicGate.ultimate).toBe(false);
      expect(parsedPublicGate.publicReadinessPlanPath).toBe(publicGatePlanPath);
      expect(parsedPublicGate.publishStatus.ok).toBe(false);
      expect(parsedPublicGate.skillScore.layers.local.ultimate).toBe(true);
      expect(parsedPublicGate.installCheck).toMatchObject({ ok: true, version: "0.1.0" });
      expect(parsedPublicGate.publishStatus.checks).toEqual(
        expect.arrayContaining([expect.objectContaining({ name: "github:actions:CI", status: "pass" })]),
      );
      expect(parsedPublicGate.publishStatus.checks).not.toEqual(
        expect.arrayContaining([expect.objectContaining({ name: "github:actions-gh", status: "fail" })]),
      );
      expect(parsedPublicGate.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "release:publish-status", status: "fail" }),
          expect.objectContaining({ name: "release:install-check", status: "pass" }),
          expect.objectContaining({ name: "skill:local", status: "pass" }),
          expect.objectContaining({ name: "skill:public-readiness", status: "fail" }),
        ]),
      );
      expect(parsedPublicGate.nextCommands).toContain("bugbounty release install-check --json");
      expect(readFileSync(publicGatePlanPath, "utf8")).toContain("# BountyPilot Public Readiness Plan");

      const installCheck = runCli(
        ["release", "install-check", "--command", process.execPath, "--command-arg", fakeInstalledCli, "--json"],
        repoRoot,
      );
      expectCommand(installCheck).toExit(0);
      const parsedInstallCheck = JSON.parse(installCheck.stdout);
      expect(parsedInstallCheck).toMatchObject({ ok: true, version: "0.1.0" });
      expect(parsedInstallCheck.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "command:version", status: "pass" }),
          expect.objectContaining({ name: "skill:validate", status: "pass" }),
          expect.objectContaining({ name: "skill:metadata", status: "pass" }),
          expect.objectContaining({ name: "skill:score", status: "pass" }),
          expect.objectContaining({ name: "quickstart:fresh-user", status: "pass" }),
        ]),
      );

      const deepDoctorJson = runCli(["doctor", "--deep", "--json"], repoRoot);
    expectCommand(deepDoctorJson).toExit(0);
    expect(outputOf(deepDoctorJson).trimStart().startsWith("{")).toBe(true);
    const parsedDeepDoctor = JSON.parse(outputOf(deepDoctorJson));
    expect(parsedDeepDoctor.ok).toBe(true);
    expect(parsedDeepDoctor.workspace.found).toBe(true);
    expect(parsedDeepDoctor.release.ok).toBe(true);
    expect(parsedDeepDoctor.checks).toEqual(expect.arrayContaining([expect.objectContaining({ name: "release", status: "pass" })]));
    expect(parsedDeepDoctor.nextCommands).toContain("bounty tools doctor");

    const deepDoctor = runCli(["doctor", "--deep"], repoRoot);
    expectCommand(deepDoctor).toExit(0);
    expect(outputOf(deepDoctor)).toContain("release checks passed");
    expect(outputOf(deepDoctor)).toContain("next commands");

    const betaReadinessJson = runCli(["beta", "readiness", "--json"], repoRoot);
    expectCommand(betaReadinessJson).toExit(0);
    expect(betaReadinessJson.stderr).toBe("");
    const parsedBetaReadiness = JSON.parse(betaReadinessJson.stdout);
    expect(parsedBetaReadiness.ok).toBe(true);
    expect(parsedBetaReadiness.score).toBeGreaterThan(0);
    expect(parsedBetaReadiness.release.ok).toBe(true);
    expect(parsedBetaReadiness.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "release_check", status: "pass" }),
        expect.objectContaining({ name: "package_bin", status: "pass" }),
      ]),
    );
    expect(parsedBetaReadiness.nextCommands).toContain("npm run verify:release");

    const betaReportPath = path.join(workspace, "beta-readiness.json");
    const betaReadinessWriteJson = runCli(["beta", "readiness", "--write", "--output", betaReportPath, "--json"], repoRoot);
    expectCommand(betaReadinessWriteJson).toExit(0);
    expect(betaReadinessWriteJson.stderr).toBe("");
    const parsedBetaReadinessWrite = JSON.parse(betaReadinessWriteJson.stdout);
    expect(parsedBetaReadinessWrite.reportPath).toBe(betaReportPath);
    expect(existsSync(betaReportPath)).toBe(true);
    expect(JSON.parse(readFileSync(betaReportPath, "utf8")).reportPath).toBe(betaReportPath);

    const betaChecklistJson = runCli(["beta", "checklist", "--json"], repoRoot);
    expectCommand(betaChecklistJson).toExit(0);
    expect(betaChecklistJson.stderr).toBe("");
    const parsedBetaChecklist = JSON.parse(betaChecklistJson.stdout);
    expect(parsedBetaChecklist.ok).toBe(true);
    expect(parsedBetaChecklist.score).toBe(parsedBetaReadiness.score);
    expect(parsedBetaChecklist.readiness.release.ok).toBe(true);
    expect(parsedBetaChecklist.markdown).toContain("# BountyPilot Beta Handoff Checklist");
    expect(parsedBetaChecklist.markdown).toContain("npm run verify:release");
    expect(parsedBetaChecklist.nextCommands).toContain("bounty beta checklist --write");

    const betaChecklistPath = path.join(workspace, "beta-checklist.md");
    const betaChecklistWriteJson = runCli(["beta", "checklist", "--write", "--output", betaChecklistPath, "--json"], repoRoot);
    expectCommand(betaChecklistWriteJson).toExit(0);
    expect(betaChecklistWriteJson.stderr).toBe("");
    const parsedBetaChecklistWrite = JSON.parse(betaChecklistWriteJson.stdout);
    expect(parsedBetaChecklistWrite.outputPath).toBe(betaChecklistPath);
    expect(existsSync(betaChecklistPath)).toBe(true);
    const betaChecklistMarkdown = readFileSync(betaChecklistPath, "utf8");
    expect(betaChecklistMarkdown).toContain("# BountyPilot Beta Handoff Checklist");
    expect(betaChecklistMarkdown).toContain("bounty lab e2e http://127.0.0.1:8080 --live --with safe-checks,js-analyzer");

    await allowVitestRpc();

    const scopeList = runCli(["scope", "list"], workspace);
    expectCommand(scopeList).toExit(0);
    expect(outputOf(scopeList)).toContain("api.smoke.example");
    expect(outputOf(scopeList)).toContain("staging.smoke.example");

    const scopeListJson = runCli(["scope", "list", "--json"], workspace);
    expectCommand(scopeListJson).toExit(0);
    expect(outputOf(scopeListJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(scopeListJson)).inScope).toContain("api.smoke.example");

    const scopeTest = runCli(["scope", "test", "https://api.smoke.example"], workspace);
    expectCommand(scopeTest).toExit(0);
    expect(outputOf(scopeTest)).toContain("[ok] Allowed by in_scope rule");
    expect(outputOf(scopeTest)).toContain("api.smoke.example");

    const scopeTestJson = runCli(["scope", "test", "https://api.smoke.example", "--json"], workspace);
    expectCommand(scopeTestJson).toExit(0);
    expect(outputOf(scopeTestJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(scopeTestJson)).allowed).toBe(true);

    const toolsDoctor = runCli(["tools", "doctor"], workspace);
    expectCommand(toolsDoctor).toExit(0);
    expect(outputOf(toolsDoctor)).toContain("playwright");
    expect(outputOf(toolsDoctor)).toContain("available");

    const toolsDoctorJson = runCli(["tools", "doctor", "--json"], workspace);
    expectCommand(toolsDoctorJson).toExit(0);
    expect(toolsDoctorJson.stderr).toBe("");
    expect(JSON.parse(toolsDoctorJson.stdout).tools[0].name).toBe("playwright");

    const providersCatalogJson = runCli(["providers", "catalog", "--json"], workspace);
    expectCommand(providersCatalogJson).toExit(0);
    expect(providersCatalogJson.stderr).toBe("");
    expect(JSON.parse(providersCatalogJson.stdout).providers.map((provider: any) => provider.id)).toEqual(expect.arrayContaining(["openai", "openrouter"]));

    const providerSecret = "sk-test-provider-secret";
    const providerConnectJson = runCli(["providers", "connect", "openai", "--api-key", providerSecret, "--model", "gpt-test", "--json"], workspace);
    expectCommand(providerConnectJson).toExit(0);
    expect(providerConnectJson.stderr).toBe("");
    expect(providerConnectJson.stdout).not.toContain(providerSecret);
    const parsedProviderConnect = JSON.parse(providerConnectJson.stdout);
    expect(parsedProviderConnect.provider).toMatchObject({
      id: "openai",
      status: "configured",
      auth: { type: "api_key", present: true },
      model: "gpt-test",
    });
    const providerAuthFile = path.join(workspace, ".bounty", "providers", "auth.json");
    expect(readFileSync(providerAuthFile, "utf8")).toContain(providerSecret);

    const providersListJson = runCli(["providers", "list", "--json"], workspace);
    expectCommand(providersListJson).toExit(0);
    expect(providersListJson.stderr).toBe("");
    expect(JSON.parse(providersListJson.stdout).providers[0].id).toBe("openai");

    const providerModelsJson = runCli(["providers", "models", "openai", "--json"], workspace);
    expectCommand(providerModelsJson).toExit(0);
    expect(providerModelsJson.stderr).toBe("");
    expect(JSON.parse(providerModelsJson.stdout).models).toEqual(expect.arrayContaining([expect.objectContaining({ model: "gpt-test", selected: true })]));

    const providerVerifyJson = runCli(["providers", "verify", "openai", "--json"], workspace);
    expectCommand(providerVerifyJson).toExit(0);
    expect(providerVerifyJson.stderr).toBe("");
    const parsedProviderVerify = JSON.parse(providerVerifyJson.stdout);
    expect(parsedProviderVerify.ok).toBe(true);
    expect(parsedProviderVerify.checks).toEqual(expect.arrayContaining([expect.objectContaining({ name: "auth", status: "pass" })]));

    const providerDoctor = runCli(["providers", "doctor"], workspace);
    expectCommand(providerDoctor).toExit(0);
    expect(outputOf(providerDoctor)).toContain("openai");
    expect(outputOf(providerDoctor)).toContain("configured");

    const huntProfilesJson = runCli(["hunt", "profiles", "--json"], workspace);
    expectCommand(huntProfilesJson).toExit(0);
    expect(huntProfilesJson.stderr).toBe("");
    expect(JSON.parse(huntProfilesJson.stdout).profiles.map((profile: any) => profile.id)).toEqual(expect.arrayContaining(["recon", "web", "validate"]));

    const huntDoctorJson = runCli(["hunt", "doctor", "https://api.smoke.example", "--profile", "web", "--json"], workspace);
    expectCommand(huntDoctorJson).toExit(0);
    expect(huntDoctorJson.stderr).toBe("");
    const parsedHuntDoctor = JSON.parse(huntDoctorJson.stdout);
    expect(parsedHuntDoctor.ok).toBe(true);
    expect(parsedHuntDoctor.checks).toEqual(expect.arrayContaining([expect.objectContaining({ name: "scope", status: "pass" })]));
    expect(parsedHuntDoctor.nextCommands).toContain("bounty arsenal bootstrap --write");

    const huntPlanPath = path.join(workspace, "hunt-plan.md");
    const huntPlanJson = runCli(["hunt", "plan", "https://api.smoke.example", "--profile", "web", "--write", "--output", huntPlanPath, "--json"], workspace);
    expectCommand(huntPlanJson).toExit(0);
    expect(huntPlanJson.stderr).toBe("");
    const parsedHuntPlan = JSON.parse(huntPlanJson.stdout);
    expect(parsedHuntPlan.ok).toBe(true);
    expect(parsedHuntPlan.profile.id).toBe("web");
    expect(parsedHuntPlan.validationGates.length).toBeGreaterThan(0);
    expect(existsSync(huntPlanPath)).toBe(true);
    expect(readFileSync(huntPlanPath, "utf8")).toContain("# BountyPilot Hunt Plan: web");

    const huntReconJson = runCli(["hunt", "recon", "https://api.smoke.example", "--profile", "web", "--dry-run", "--json"], workspace);
    expectCommand(huntReconJson).toExit(0);
    expect(huntReconJson.stderr).toBe("");
    const parsedHuntRecon = JSON.parse(huntReconJson.stdout);
    expect(parsedHuntRecon.ok).toBe(true);
    expect(parsedHuntRecon.tools.map((tool: any) => tool.tool)).toEqual(expect.arrayContaining(["subfinder", "httpx", "nuclei"]));
    expect(parsedHuntRecon.actionsPlanned).toBeGreaterThan(0);

    const huntPlaybookJson = runCli(["hunt", "playbook", "xss", "https://api.smoke.example/search?q=test", "--dry-run", "--json"], workspace);
    expectCommand(huntPlaybookJson).toExit(0);
    expect(huntPlaybookJson.stderr).toBe("");
    const parsedHuntPlaybook = JSON.parse(huntPlaybookJson.stdout);
    expect(parsedHuntPlaybook.bugClass).toBe("xss");
    expect(parsedHuntPlaybook.observations.length).toBeGreaterThanOrEqual(1);
    expect(parsedHuntPlaybook.findingsCreated).toHaveLength(0);

    const reconListJson = runCli(["recon", "list", "--kind", "parameter", "--job", parsedHuntPlaybook.jobId, "--json"], workspace);
    expectCommand(reconListJson).toExit(0);
    expect(reconListJson.stderr).toBe("");
    const parsedReconList = JSON.parse(reconListJson.stdout);
    expect(parsedReconList.counts.total).toBeGreaterThanOrEqual(1);
    expect(parsedReconList.observations[0].kind).toBe("parameter");

    const reconShowJson = runCli(["recon", "show", parsedReconList.observations[0].id, "--json"], workspace);
    expectCommand(reconShowJson).toExit(0);
    expect(reconShowJson.stderr).toBe("");
    const parsedReconShow = JSON.parse(reconShowJson.stdout);
    expect(parsedReconShow.observation.id).toBe(parsedReconList.observations[0].id);
    expect(parsedReconShow.nextCommands).toEqual(expect.arrayContaining([expect.stringContaining("bounty jobs timeline")]));

    await allowVitestRpc();

    const huntDryRunJson = runCli(["hunt", "run", "https://api.smoke.example", "--profile", "recon", "--dry-run", "--json"], workspace);
    expectCommand(huntDryRunJson).toExit(0);
    expect(huntDryRunJson.stderr).toBe("");
    const parsedHuntDryRun = JSON.parse(huntDryRunJson.stdout);
    expect(parsedHuntDryRun.ok).toBe(true);
    expect(parsedHuntDryRun.summary.dryRun).toBe(true);
    expect(parsedHuntDryRun.nextCommands).toContain(`bounty review --job ${parsedHuntDryRun.summary.jobId}`);

    const autopilotPlanPath = path.join(workspace, "autopilot-plan.md");
    const huntAutopilotJson = runCli(
      ["hunt", "autopilot", "https://api.smoke.example", "--profile", "recon", "--dry-run", "--write-plan", "--plan-output", autopilotPlanPath, "--json"],
      workspace,
    );
    expectCommand(huntAutopilotJson).toExit(0);
    expect(huntAutopilotJson.stderr).toBe("");
    const parsedHuntAutopilot = JSON.parse(huntAutopilotJson.stdout);
    expect(parsedHuntAutopilot.ok).toBe(true);
    expect(parsedHuntAutopilot.summary.dryRun).toBe(true);
    expect(parsedHuntAutopilot.plan.planPath).toBe(autopilotPlanPath);
    expect(existsSync(autopilotPlanPath)).toBe(true);
    expect(parsedHuntAutopilot.review.cockpit.checks.length).toBeGreaterThan(0);

    const arsenalProfilesJson = runCli(["arsenal", "profiles", "--json"], workspace);
    expectCommand(arsenalProfilesJson).toExit(0);
    expect(arsenalProfilesJson.stderr).toBe("");
    expect(JSON.parse(arsenalProfilesJson.stdout).tools.map((tool: any) => tool.name)).toEqual(expect.arrayContaining(["subfinder", "nuclei", "ffuf"]));

    const arsenalPath = path.join(workspace, "vm-arsenal.md");
    const arsenalVmJson = runCli(["arsenal", "vm", "--write", "--output", arsenalPath, "--json"], workspace);
    expectCommand(arsenalVmJson).toExit(0);
    expect(arsenalVmJson.stderr).toBe("");
    expect(JSON.parse(arsenalVmJson.stdout).tools.length).toBeGreaterThan(0);
    expect(existsSync(arsenalPath)).toBe(true);
    expect(readFileSync(arsenalPath, "utf8")).toContain("# BountyPilot VM Arsenal Plan");

    const bootstrapPath = path.join(workspace, "bootstrap.sh");
    const arsenalBootstrapJson = runCli(["arsenal", "bootstrap", "--level", "full", "--write", "--output", bootstrapPath, "--json"], workspace);
    expectCommand(arsenalBootstrapJson).toExit(0);
    expect(arsenalBootstrapJson.stderr).toBe("");
    const parsedBootstrap = JSON.parse(arsenalBootstrapJson.stdout);
    expect(parsedBootstrap.level).toBe("full");
    expect(existsSync(bootstrapPath)).toBe(true);
    const bootstrapScript = readFileSync(bootstrapPath, "utf8");
    expect(bootstrapScript).toContain("#!/usr/bin/env bash");
    expect(bootstrapScript).toContain("go install github.com/projectdiscovery/subfinder");
    expect(bootstrapScript).toContain("nuclei -update-templates");

    await allowVitestRpc();

    const toolsListJson = runCli(["tools", "list", "--json"], workspace);
    expectCommand(toolsListJson).toExit(0);
    expect(outputOf(toolsListJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(toolsListJson)).tools.length).toBeGreaterThan(0);

    const customRegistryPath = path.join(workspace, "tool-registry.yml");
    writeFileSync(customRegistryPath, customToolRegistryYaml(), "utf8");
    const customToolsListJson = runCli(["--tool-registry", customRegistryPath, "tools", "list", "--json"], workspace);
    expectCommand(customToolsListJson).toExit(0);
    expect(customToolsListJson.stderr).toBe("");
    const customTools = JSON.parse(customToolsListJson.stdout).tools;
    expect(customTools.map((tool: any) => tool.name)).toEqual(expect.arrayContaining(["playwright", "custom-local-tool"]));

    const toolsSearchJson = runCli(["tools", "search", "browser", "--json"], workspace);
    expectCommand(toolsSearchJson).toExit(0);
    expect(outputOf(toolsSearchJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(toolsSearchJson)).tools.length).toBeGreaterThan(0);

    const toolsInstall = runCli(["tools", "install", "playwright"], workspace);
    expectCommand(toolsInstall).toExit(0);
    expect(outputOf(toolsInstall)).toContain("install planning only");

    const toolsInstallJson = runCli(["tools", "install", "playwright", "--json"], workspace);
    expectCommand(toolsInstallJson).toExit(0);
    expect(toolsInstallJson.stderr).toBe("");
    const parsedToolsInstall = JSON.parse(toolsInstallJson.stdout);
    expect(parsedToolsInstall.tool).toBe("playwright");
    expect(parsedToolsInstall.execution).toBe("plan_only");

    const toolsUpdateJson = runCli(["tools", "update", "--json"], workspace);
    expectCommand(toolsUpdateJson).toExit(0);
    expect(toolsUpdateJson.stderr).toBe("");
    expect(JSON.parse(toolsUpdateJson.stdout).plans.length).toBeGreaterThan(0);

    const toolsApproveJson = runCli(["tools", "approve-executable", "subfinder", "--command", process.execPath, "--json"], workspace);
    expectCommand(toolsApproveJson).toExit(0);
    expect(toolsApproveJson.stderr).toBe("");
    const parsedToolApproval = JSON.parse(toolsApproveJson.stdout);
    expect(parsedToolApproval.tool).toBe("subfinder");
    expect(parsedToolApproval.approval.command).toBe(process.execPath);

    const toolsApprovedJson = runCli(["tools", "approved-executables", "subfinder", "--json"], workspace);
    expectCommand(toolsApprovedJson).toExit(0);
    expect(toolsApprovedJson.stderr).toBe("");
    expect(JSON.parse(toolsApprovedJson.stdout).approvals[0].command).toBe(process.execPath);

    const toolsDoctorAfterApprovalJson = runCli(["tools", "doctor", "--json"], workspace);
    expectCommand(toolsDoctorAfterApprovalJson).toExit(0);
    expect(toolsDoctorAfterApprovalJson.stderr).toBe("");
    const parsedToolsDoctor = JSON.parse(toolsDoctorAfterApprovalJson.stdout);
    expect(parsedToolsDoctor.tools.find((tool: any) => tool.name === "subfinder").approval.present).toBe(true);

    const toolsRun = runCli(
      ["tools", "run", "playwright", "--target", "api.smoke.example", "--action", "browser.navigate"],
      workspace,
    );
    expectCommand(toolsRun).toExit(0);
    expect(outputOf(toolsRun)).toContain("execute        false");

    const toolsRunJson = runCli(
      ["tools", "run", "playwright", "--target", "api.smoke.example", "--action", "browser.navigate", "--json"],
      workspace,
    );
    expectCommand(toolsRunJson).toExit(0);
    expect(toolsRunJson.stderr).toBe("");
    const parsedToolsRun = JSON.parse(toolsRunJson.stdout);
    expect(parsedToolsRun.execute).toBe(false);
    expect(parsedToolsRun.execution).toBe("planned_only");
    expect(parsedToolsRun.validation.allowed).toBe(true);

    const manualFindingJson = runCli(
      [
        "findings",
        "create",
        "--title",
        "Manual smoke finding",
        "--url",
        "https://api.smoke.example",
        "--note",
        "Local smoke evidence note.",
        "--json",
      ],
      workspace,
    );
    expectCommand(manualFindingJson).toExit(0);
    expect(manualFindingJson.stderr).toBe("");
    const parsedManualFinding = JSON.parse(manualFindingJson.stdout);
    const reportsScoreJson = runCli(["reports", "score", parsedManualFinding.finding.id, "--json"], workspace);
    expectCommand(reportsScoreJson).toExit(0);
    expect(reportsScoreJson.stderr).toBe("");
    const parsedReportsScore = JSON.parse(reportsScoreJson.stdout);
    expect(parsedReportsScore.findingId).toBe(parsedManualFinding.finding.id);
    expect(parsedReportsScore.score).toBeGreaterThanOrEqual(0);
    expect(parsedReportsScore.nextCommands).toEqual(expect.arrayContaining([expect.stringContaining("bounty reports review")]));

    const results = runCli(["results"], workspace);
    expectCommand(results).toExit(0);
    expect(outputOf(results)).toContain("Manual smoke finding");
    expect(outputOf(results)).toContain("next commands");

    const resultsJson = runCli(["results", "--json"], workspace);
    expectCommand(resultsJson).toExit(0);
    expect(resultsJson.stderr).toBe("");
    const parsedResults = JSON.parse(resultsJson.stdout);
    expect(parsedResults.status).toBe("needs_review");
    expect(parsedResults.totals.findingsConsidered).toBeGreaterThanOrEqual(1);
    expect(parsedResults.findings[0].id).toBe(parsedManualFinding.finding.id);
    expect(parsedResults.findings[0].nextCommands).toEqual(expect.arrayContaining([expect.stringContaining("bounty reports score")]));

    const readyOnlyResultsJson = runCli(["results", "--ready-only", "--json"], workspace);
    expectCommand(readyOnlyResultsJson).toExit(0);
    expect(readyOnlyResultsJson.stderr).toBe("");
    expect(JSON.parse(readyOnlyResultsJson.stdout).filters.readyOnly).toBe(true);

    await allowVitestRpc();

    const invalidWorkflowComponentJson = runCli(
      ["run", "api.smoke.example", "--dry-run", "--with", "safe-checks,does-not-exist", "--json"],
      workspace,
    );
    expectCommand(invalidWorkflowComponentJson).toExit(1);
    expect(invalidWorkflowComponentJson.stderr).toBe("");
    expect(JSON.parse(invalidWorkflowComponentJson.stdout).error.code).toBe("WORKFLOW_COMPONENT_INVALID");

    const emptyWorkflowComponentJson = runCli(
      ["run", "api.smoke.example", "--dry-run", "--with", ",", "--json"],
      workspace,
    );
    expectCommand(emptyWorkflowComponentJson).toExit(1);
    expect(emptyWorkflowComponentJson.stderr).toBe("");
    expect(JSON.parse(emptyWorkflowComponentJson.stdout).error.code).toBe("WORKFLOW_COMPONENTS_EMPTY");

    const integrationsListJson = runCli(["integrations", "list", "--json"], workspace);
    expectCommand(integrationsListJson).toExit(0);
    expect(integrationsListJson.stderr).toBe("");
    expect(JSON.parse(integrationsListJson.stdout).integrations.length).toBeGreaterThan(0);

    const configureNestedIntegrationJson = runCli(
      [
        "integrations",
        "config",
        "crawl4ai",
        "enabled=true",
        "type=crawler",
        "execution.enabled=true",
        "execution.package=fake-crawler",
        "execution.package_version=1.0.0",
        "execution.entrypoint=dist/cli.mjs",
        "execution.entrypoint_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "execution.package_json_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--json",
      ],
      workspace,
    );
    expectCommand(configureNestedIntegrationJson).toExit(0);
    expect(configureNestedIntegrationJson.stderr).toBe("");
    const parsedNestedIntegration = JSON.parse(configureNestedIntegrationJson.stdout);
    expect(parsedNestedIntegration.config.execution.enabled).toBe(true);
    expect(parsedNestedIntegration.config.execution.package).toBe("fake-crawler");
    expect(parsedNestedIntegration.config.execution.package_version).toBe("1.0.0");
    expect(parsedNestedIntegration.config.execution.entrypoint).toBe("dist/cli.mjs");
    expect(parsedNestedIntegration.config.execution.entrypoint_sha256).toBe(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    expect(parsedNestedIntegration.config.execution.package_json_sha256).toBe(
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    expect(parsedNestedIntegration.config["execution.enabled"]).toBeUndefined();

    const missingCrawlSetupCommand = runCli(["integrations", "setup", "crawl4ai", "--json"], workspace);
    expectCommand(missingCrawlSetupCommand).toExit(1);
    expect(missingCrawlSetupCommand.stderr).toBe("");
    expect(JSON.parse(missingCrawlSetupCommand.stdout).error.code).toBe("INTEGRATION_SETUP_COMMAND_REQUIRED");

    const crawlSetupJson = runCli(
      ["integrations", "setup", "crawl4ai", "--command", process.execPath, "--enable-execution", "--approve-executable", "--json"],
      workspace,
    );
    expectCommand(crawlSetupJson).toExit(0);
    expect(crawlSetupJson.stderr).toBe("");
    const parsedCrawlSetup = JSON.parse(crawlSetupJson.stdout);
    expect(parsedCrawlSetup.integration).toBe("crawl4ai");
    expect(parsedCrawlSetup.config).toMatchObject({
      enabled: true,
      type: "crawler",
      allow_execute: true,
      command: process.execPath,
      capabilities: ["crawler.fetch"],
    });
    expect(parsedCrawlSetup.approval.integration).toBe("crawl4ai");

    const capabilities = runCli(["integrations", "capabilities", "playwright-mcp"], workspace);
    expectCommand(capabilities).toExit(0);
    expect(outputOf(capabilities)).toContain("browser.navigate");

    const capabilitiesJson = runCli(["integrations", "capabilities", "playwright-mcp", "--json"], workspace);
    expectCommand(capabilitiesJson).toExit(0);
    expect(outputOf(capabilitiesJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(capabilitiesJson)).capabilities.length).toBeGreaterThan(0);

    const validateBeforeConfig = runCli(
      ["integrations", "validate", "playwright-mcp", "browser.navigate", "--target", "api.smoke.example"],
      workspace,
    );
    expectCommand(validateBeforeConfig).toExit(1);
    expect(outputOf(validateBeforeConfig)).toContain("[blocked]");

    writeFakePlaywrightMcpPackage(workspace);
    const setupMcpJson = runCli(
      ["integrations", "setup", "playwright-mcp", "--enable-execution", "--approve-executable", "--json"],
      workspace,
    );
    expectCommand(setupMcpJson).toExit(0);
    expect(setupMcpJson.stderr).toBe("");
    const parsedSetupMcp = JSON.parse(setupMcpJson.stdout);
    expect(parsedSetupMcp.integration).toBe("playwright_mcp");
    expect(parsedSetupMcp.config.execution).toMatchObject({
      enabled: true,
      package: "@playwright/mcp",
      package_version: "1.2.3",
      entrypoint: "cli.js",
    });
    expect(parsedSetupMcp.config.execution.entrypoint_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(parsedSetupMcp.config.execution.package_json_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(parsedSetupMcp.approval.integration).toBe("playwright_mcp");
    expect(parsedSetupMcp.nextCommands).toContain(
      "bounty mcp call playwright-mcp browser_navigate --target <in-scope-url> --arg url=<in-scope-url>",
    );

    const validateAfterConfig = runCli(
      ["integrations", "validate", "playwright-mcp", "browser.navigate", "--target", "api.smoke.example"],
      workspace,
    );
    expectCommand(validateAfterConfig).toExit(0);
    expect(outputOf(validateAfterConfig)).toContain("[ok] Allowed by policy");

    const validateAfterConfigJson = runCli(
      ["integrations", "validate", "playwright-mcp", "browser.navigate", "--target", "api.smoke.example", "--json"],
      workspace,
    );
    expectCommand(validateAfterConfigJson).toExit(0);
    expect(validateAfterConfigJson.stderr).toBe("");
    expect(JSON.parse(validateAfterConfigJson.stdout).validation.ok).toBe(true);

    const integrationShow = runCli(["integrations", "show", "playwright-mcp"], workspace);
    expectCommand(integrationShow).toExit(0);
    expect(outputOf(integrationShow)).toContain("configured");
    expect(outputOf(integrationShow)).toContain("browser.navigate");

    const integrationPreflight = runCli(
      ["integrations", "preflight", "playwright-mcp", "browser.navigate", "--target", "api.smoke.example"],
      workspace,
    );
    expectCommand(integrationPreflight).toExit(0);
    expect(outputOf(integrationPreflight)).toContain("execute        false");
    expect(outputOf(integrationPreflight)).toContain("Allowed by policy");

    const integrationVerifyJson = runCli(
      ["integrations", "verify", "playwright-mcp", "browser.navigate", "--target", "api.smoke.example", "--json"],
      workspace,
    );
    expectCommand(integrationVerifyJson).toExit(0);
    expect(integrationVerifyJson.stderr).toBe("");
    const parsedIntegrationVerify = JSON.parse(integrationVerifyJson.stdout);
    expect(parsedIntegrationVerify.status).toBe("pass");
    expect(parsedIntegrationVerify.execute).toBe(false);
    expect(parsedIntegrationVerify.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "scope", status: "pass" }),
        expect.objectContaining({ name: "policy", status: "pass" }),
        expect.objectContaining({ name: "executable_approval", status: "pass" }),
      ]),
    );

    const crawlIntegrationVerifyJson = runCli(
      ["integrations", "verify", "crawl4ai", "crawler.fetch", "--target", "api.smoke.example", "--json"],
      workspace,
    );
    expectCommand(crawlIntegrationVerifyJson).toExit(0);
    expect(crawlIntegrationVerifyJson.stderr).toBe("");
    expect(JSON.parse(crawlIntegrationVerifyJson.stdout).status).toBe("pass");

    const integrationVerify = runCli(
      ["integrations", "verify", "playwright-mcp", "browser.navigate", "--target", "api.smoke.example"],
      workspace,
    );
    expectCommand(integrationVerify).toExit(0);
    expect(outputOf(integrationVerify)).toContain("integrations verify");
    expect(outputOf(integrationVerify)).toContain("next commands");

    const integrationsDoctorJson = runCli(["integrations", "doctor", "--json"], workspace);
    expectCommand(integrationsDoctorJson).toExit(0);
    expect(integrationsDoctorJson.stderr).toBe("");
    const parsedIntegrationsDoctor = JSON.parse(integrationsDoctorJson.stdout);
    expect(parsedIntegrationsDoctor.integrations.length).toBeGreaterThan(0);
    expect(parsedIntegrationsDoctor.nextCommands).toContain(
      "bounty mcp call playwright-mcp browser_navigate --target <in-scope-url> --arg url=<in-scope-url>",
    );
    expect(parsedIntegrationsDoctor.nextCommands).toContain("bounty run <in-scope-host> --mode safe --with crawl4ai");

    const integrationsDoctor = runCli(["integrations", "doctor"], workspace);
    expectCommand(integrationsDoctor).toExit(0);
    expect(outputOf(integrationsDoctor)).toContain("next commands");
    expect(outputOf(integrationsDoctor)).toContain("$ bounty mcp call playwright-mcp");

    const mcpPlan = runCli(
      [
        "mcp",
        "plan",
        "playwright-mcp",
        "browser_navigate",
        "--target",
        "api.smoke.example",
        "--arg",
        "url=https://api.smoke.example/",
      ],
      workspace,
    );
    expectCommand(mcpPlan).toExit(0);
    expect(outputOf(mcpPlan)).toContain("execute        false");

    const mcpPlanJson = runCli(
      [
        "mcp",
        "plan",
        "playwright-mcp",
        "browser_navigate",
        "--target",
        "api.smoke.example",
        "--arg",
        "url=https://api.smoke.example/",
        "--json",
      ],
      workspace,
    );
    expectCommand(mcpPlanJson).toExit(0);
    expect(outputOf(mcpPlanJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(mcpPlanJson)).execute).toBe(false);

    const browserPlanJson = runCli(["browser", "api.smoke.example", "--json"], workspace);
    expectCommand(browserPlanJson).toExit(0);
    expect(browserPlanJson.stderr).toBe("");
    const parsedBrowserPlan = JSON.parse(browserPlanJson.stdout);
    expect(parsedBrowserPlan.ok).toBe(true);
    expect(parsedBrowserPlan.execute).toBe(false);
    expect(parsedBrowserPlan.plan.validation.ok).toBe(true);

    const mcpCrawlPlan = runCli(
      ["crawl", "api.smoke.example", "--engine", "playwright-mcp", "--mode", "safe"],
      workspace,
    );
    expectCommand(mcpCrawlPlan).toExit(0);
    expect(outputOf(mcpCrawlPlan)).toContain("execute        false");

    const mcpCrawlPlanJson = runCli(
      ["crawl", "api.smoke.example", "--engine", "playwright-mcp", "--mode", "safe", "--json"],
      workspace,
    );
    expectCommand(mcpCrawlPlanJson).toExit(0);
    expect(mcpCrawlPlanJson.stderr).toBe("");
    const parsedMcpCrawlPlan = JSON.parse(mcpCrawlPlanJson.stdout);
    expect(parsedMcpCrawlPlan.ok).toBe(true);
    expect(parsedMcpCrawlPlan.execute).toBe(false);
    expect(parsedMcpCrawlPlan.action.adapter).toBe("playwright_mcp");

    const configureDesktopMcpJson = runCli(
      [
        "integrations",
        "config",
        "windows-mcp",
        "enabled=true",
        "type=desktop",
        "transport=stdio",
        "command=npx",
        "capabilities=desktop.session.plan",
        "--json",
      ],
      workspace,
    );
    expectCommand(configureDesktopMcpJson).toExit(0);
    expect(configureDesktopMcpJson.stderr).toBe("");

    const desktopPlanJson = runCli(["desktop", "--json"], workspace);
    expectCommand(desktopPlanJson).toExit(0);
    expect(desktopPlanJson.stderr).toBe("");
    const parsedDesktopPlan = JSON.parse(desktopPlanJson.stdout);
    expect(parsedDesktopPlan.ok).toBe(true);
    expect(parsedDesktopPlan.execute).toBe(false);
    expect(parsedDesktopPlan.plan.validation.requiresApproval).toBe(true);

    const researchJson = runCli(["research", "--json"], workspace);
    expectCommand(researchJson).toExit(0);
    expect(researchJson.stderr).toBe("");
    expect(JSON.parse(researchJson.stdout).artifact.kind).toBe("research_note");

    const agentRunJson = runCli(["agent", "run", "--goal", "map safe next steps", "--json"], workspace);
    expectCommand(agentRunJson).toExit(0);
    expect(agentRunJson.stderr).toBe("");
    expect(JSON.parse(agentRunJson.stdout).artifact.kind).toBe("evidence_note");

    const agentPlanJson = runCli(["agent", "plan", "api.smoke.example", "--json"], workspace);
    expectCommand(agentPlanJson).toExit(0);
    expect(agentPlanJson.stderr).toBe("");
    expect(JSON.parse(agentPlanJson.stdout).enqueued).toBeGreaterThan(0);

    const dryRun = runCli(
      ["run", "api.smoke.example", "--dry-run", "--with", "safe-checks,js-analyzer,playwright,planner"],
      workspace,
    );
    expectCommand(dryRun).toExit(0);
    expect(outputOf(dryRun)).toContain("[planned] safe pipeline started");
    expect(outputOf(dryRun)).toContain("[ok] workflow finished");
    expect(outputOf(dryRun)).toContain("recent events");

    const summary = readOnlyWorkflowSummary(workspace);
    expect(outputOf(dryRun)).toContain("next commands");
    expect(outputOf(dryRun)).toContain(`bounty jobs show ${summary.jobId}`);
    expect(outputOf(dryRun)).toContain(`bounty jobs timeline ${summary.jobId}`);
    expect(outputOf(dryRun)).toContain("bounty dashboard");
    expect(summary.program).toBe("cli-smoke");
    expect(summary.seeds).toEqual(["https://api.smoke.example/"]);
    expect(summary.actionsPlanned).toBe(4);
    expect(summary.evidenceCreated).toBe(1);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "dry-run", status: "completed" }),
      ]),
    );

    await allowVitestRpc();

    const agentPlanFromJobJson = runCli(["agent", "plan", "api.smoke.example", "--from-job", summary.jobId, "--json"], workspace);
    expectCommand(agentPlanFromJobJson).toExit(0);
    expect(agentPlanFromJobJson.stderr).toBe("");
    const parsedAgentPlanFromJob = JSON.parse(agentPlanFromJobJson.stdout);
    expect(parsedAgentPlanFromJob.fromJobId).toBe(summary.jobId);
    expect(parsedAgentPlanFromJob.enqueued).toBe(0);
    expect(parsedAgentPlanFromJob.plannerLoop.iterations.some((iteration: any) => iteration.skippedExistingActions > 0)).toBe(true);
    expect(parsedAgentPlanFromJob.artifact.kind).toBe("tool_output");

    const jobEvidenceJson = runCli(["evidence", "--job", summary.jobId, "--json"], workspace);
    expectCommand(jobEvidenceJson).toExit(0);
    expect(jobEvidenceJson.stderr).toBe("");
    const parsedJobEvidence = JSON.parse(jobEvidenceJson.stdout);
    expect(parsedJobEvidence.jobId).toBe(summary.jobId);
    expect(parsedJobEvidence.evidence.length).toBeGreaterThanOrEqual(summary.evidenceCreated);
    expect(parsedJobEvidence.evidence.every((artifact: any) => artifact.jobId === summary.jobId)).toBe(true);

    const jobEvidenceManifestJson = runCli(["evidence", "--job", summary.jobId, "--manifest", "--json"], workspace);
    expectCommand(jobEvidenceManifestJson).toExit(0);
    expect(jobEvidenceManifestJson.stderr).toBe("");
    const parsedJobEvidenceManifest = JSON.parse(jobEvidenceManifestJson.stdout);
    expect(parsedJobEvidenceManifest.jobId).toBe(summary.jobId);
    expect(parsedJobEvidenceManifest.artifact.jobId).toBe(summary.jobId);

    const jobEvidenceVerifyJson = runCli(["evidence", "verify", "--job", summary.jobId, "--json"], workspace);
    expectCommand(jobEvidenceVerifyJson).toExit(0);
    expect(jobEvidenceVerifyJson.stderr).toBe("");
    const parsedJobEvidenceVerify = JSON.parse(jobEvidenceVerifyJson.stdout);
    expect(parsedJobEvidenceVerify.jobId).toBe(summary.jobId);
    expect(parsedJobEvidenceVerify.artifactCount).toBe(parsedJobEvidence.evidence.length + 1);

    const jobEvidenceVerifyParentOptionJson = runCli(["evidence", "--job", summary.jobId, "verify", "--json"], workspace);
    expectCommand(jobEvidenceVerifyParentOptionJson).toExit(0);
    expect(jobEvidenceVerifyParentOptionJson.stderr).toBe("");
    const parsedJobEvidenceVerifyParentOption = JSON.parse(jobEvidenceVerifyParentOptionJson.stdout);
    expect(parsedJobEvidenceVerifyParentOption.jobId).toBe(summary.jobId);
    expect(parsedJobEvidenceVerifyParentOption.artifactCount).toBe(parsedJobEvidenceVerify.artifactCount);

    const missingJobEvidenceJson = runCli(["evidence", "--job", "job-does-not-exist", "--json"], workspace);
    expectCommand(missingJobEvidenceJson).toExit(1);
    expect(missingJobEvidenceJson.stderr).toBe("");
    expect(JSON.parse(missingJobEvidenceJson.stdout).error.code).toBe("JOB_NOT_FOUND");

    await allowVitestRpc();

    const actionsListJson = runCli(["actions", "list", "--job", summary.jobId, "--json"], workspace);
    expectCommand(actionsListJson).toExit(0);
    expect(outputOf(actionsListJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(actionsListJson)).actions.length).toBe(summary.actionsPlanned);

    const invalidJobsLimitJson = runCli(["jobs", "list", "--limit", "-1", "--json"], workspace);
    expectCommand(invalidJobsLimitJson).toExit(1);
    expect(invalidJobsLimitJson.stderr).toBe("");
    expect(JSON.parse(invalidJobsLimitJson.stdout).error.code).toBe("CLI_INVALID_LIMIT");

    const jobShow = runCli(["jobs", "show", summary.jobId], workspace);
    expectCommand(jobShow).toExit(0);
    expect(outputOf(jobShow)).toContain("workflow checkpoint loaded");
    expect(outputOf(jobShow)).toContain(summary.jobId);
    expect(outputOf(jobShow)).toContain("dry-run");
    expect(outputOf(jobShow)).toContain("recent events");

    const jobWatch = runCli(["jobs", "watch", summary.jobId, "--iterations", "1", "--interval-ms", "1"], workspace);
    expectCommand(jobWatch).toExit(0);
    expect(outputOf(jobWatch)).toContain("jobs watch");
    expect(outputOf(jobWatch)).toContain("watch refresh 1");
    expect(outputOf(jobWatch)).toContain("next commands");

    const jobWatchJson = runCli(["jobs", "watch", summary.jobId, "--json"], workspace);
    expectCommand(jobWatchJson).toExit(0);
    expect(jobWatchJson.stderr).toBe("");
    expect(JSON.parse(jobWatchJson.stdout).terminal).toBe(true);

    const review = runCli(["review", "--job", summary.jobId], workspace);
    expectCommand(review).toExit(0);
    expect(outputOf(review)).toContain("job review ready");
    expect(outputOf(review)).toContain("health");
    expect(outputOf(review)).toContain("needs_review");
    expect(outputOf(review)).toContain("reports");
    expect(outputOf(review)).toContain("next commands");
    expect(outputOf(review)).toContain("$ bounty jobs show");
    expect(outputOf(review)).toContain(`bounty evidence verify --job ${summary.jobId}`);

    const reviewJson = runCli(["review", "--job", summary.jobId, "--json"], workspace);
    expectCommand(reviewJson).toExit(0);
    expect(reviewJson.stderr).toBe("");
    const parsedReviewJson = JSON.parse(reviewJson.stdout);
    expect(parsedReviewJson.job.id).toBe(summary.jobId);
    expect(parsedReviewJson.cockpit.status).toBe("needs_review");
    expect(parsedReviewJson.cockpit.phaseCounts.total).toBeGreaterThan(0);
    expect(parsedReviewJson.cockpit.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "workflow", status: "pass" }),
        expect.objectContaining({ name: "evidence", status: "pass" }),
        expect.objectContaining({ name: "findings", status: "warn" }),
      ]),
    );
    expect(parsedReviewJson.evidence.total).toBeGreaterThanOrEqual(summary.evidenceCreated);
    expect(parsedReviewJson.findings.total).toBe(0);
    expect(parsedReviewJson.nextCommands).toContain(`bounty actions review --job ${summary.jobId}`);

    const cockpit = runCli(["cockpit", "--job", summary.jobId], workspace);
    expectCommand(cockpit).toExit(0);
    expect(outputOf(cockpit)).toContain("cockpit refresh 1");
    expect(outputOf(cockpit)).toContain("job focus");
    expect(outputOf(cockpit)).toContain("providers/tools");
    expect(outputOf(cockpit)).toContain("next commands");

    const cockpitJson = runCli(["cockpit", "--job", summary.jobId, "--json"], workspace);
    expectCommand(cockpitJson).toExit(0);
    expect(cockpitJson.stderr).toBe("");
    const parsedCockpitJson = JSON.parse(cockpitJson.stdout);
    expect(parsedCockpitJson.workspace.program.name).toBe("cli-smoke");
    expect(parsedCockpitJson.jobReview.job.id).toBe(summary.jobId);
    expect(parsedCockpitJson.recon.workspace.total).toBeGreaterThan(0);
    expect(parsedCockpitJson.providers.configured).toBe(1);
    expect(parsedCockpitJson.tools.total).toBeGreaterThan(0);
    expect(parsedCockpitJson.checks).toEqual(expect.arrayContaining([expect.objectContaining({ name: "job" })]));
    expect(parsedCockpitJson.nextCommands).toContain(`bounty review --job ${summary.jobId}`);

    const cockpitWatchJson = runCli(["cockpit", "--watch", "--iterations", "1", "--interval-ms", "1", "--json"], workspace);
    expectCommand(cockpitWatchJson).toExit(0);
    expect(cockpitWatchJson.stderr).toBe("");
    const parsedCockpitWatchJson = JSON.parse(cockpitWatchJson.stdout);
    expect(parsedCockpitWatchJson.watch).toBe(true);
    expect(parsedCockpitWatchJson.iterations).toBe(1);
    expect(parsedCockpitWatchJson.latest.workspace.program.name).toBe("cli-smoke");

    const jobResultsJson = runCli(["results", "--job", summary.jobId, "--json"], workspace);
    expectCommand(jobResultsJson).toExit(0);
    expect(jobResultsJson.stderr).toBe("");
    const parsedJobResults = JSON.parse(jobResultsJson.stdout);
    expect(parsedJobResults.job.id).toBe(summary.jobId);
    expect(parsedJobResults.filters.jobId).toBe(summary.jobId);
    expect(parsedJobResults.nextCommands).toEqual(expect.arrayContaining([`bounty review --job ${summary.jobId}`]));

    await allowVitestRpc();

    const missingReviewJobJson = runCli(["review", "--job", "job-does-not-exist", "--json"], workspace);
    expectCommand(missingReviewJobJson).toExit(1);
    expect(missingReviewJobJson.stderr).toBe("");
    expect(JSON.parse(missingReviewJobJson.stdout).error.code).toBe("JOB_NOT_FOUND");

    const missingJobWatchJson = runCli(["jobs", "watch", "job-does-not-exist", "--json"], workspace);
    expectCommand(missingJobWatchJson).toExit(1);
    expect(missingJobWatchJson.stderr).toBe("");
    expect(JSON.parse(missingJobWatchJson.stdout).error.code).toBe("JOB_NOT_FOUND");

    const invalidJobWatchLimitJson = runCli(["jobs", "watch", summary.jobId, "--limit", "0", "--json"], workspace);
    expectCommand(invalidJobWatchLimitJson).toExit(1);
    expect(invalidJobWatchLimitJson.stderr).toBe("");
    expect(JSON.parse(invalidJobWatchLimitJson.stdout).error.code).toBe("CLI_INVALID_LIMIT");

    const jobShowJson = runCli(["jobs", "show", summary.jobId, "--json"], workspace);
    expectCommand(jobShowJson).toExit(0);
    expect(outputOf(jobShowJson).trimStart().startsWith("{")).toBe(true);
    expect(JSON.parse(outputOf(jobShowJson)).events.length).toBeGreaterThan(0);

    const missingJobJson = runCli(["jobs", "show", "job-does-not-exist", "--json"], workspace);
    expectCommand(missingJobJson).toExit(1);
    expect(missingJobJson.stderr).toBe("");
    expect(JSON.parse(missingJobJson.stdout)).toEqual({
      ok: false,
      error: {
        code: "JOB_NOT_FOUND",
        message: "Job not found: job-does-not-exist",
      },
    });

    const missingJobHuman = runCli(["jobs", "show", "job-does-not-exist"], workspace);
    expectCommand(missingJobHuman).toExit(1);
    expect(missingJobHuman.stdout).toBe("");
    expect(missingJobHuman.stderr).toContain("[error] [JOB_NOT_FOUND] Job not found: job-does-not-exist");

    const jobTimeline = runCli(["jobs", "timeline", summary.jobId], workspace);
    expectCommand(jobTimeline).toExit(0);
    expect(outputOf(jobTimeline)).toContain("workflow timeline");
    expect(outputOf(jobTimeline)).toContain("research-note");

    const jobTimelineJson = runCli(["jobs", "timeline", summary.jobId, "--json"], workspace);
    expectCommand(jobTimelineJson).toExit(0);
    expect(outputOf(jobTimelineJson).trimStart().startsWith("{")).toBe(true);
    const parsedTimeline = JSON.parse(outputOf(jobTimelineJson));
    expect(parsedTimeline.events.map((event: any) => event.phase)).toContain("dry-run");

    const invalidTimelineLimitJson = runCli(["jobs", "timeline", summary.jobId, "--limit", "abc", "--json"], workspace);
    expectCommand(invalidTimelineLimitJson).toExit(1);
    expect(invalidTimelineLimitJson.stderr).toBe("");
    expect(JSON.parse(invalidTimelineLimitJson.stdout).error.code).toBe("CLI_INVALID_LIMIT");

    const jobResume = runCli(["jobs", "resume", summary.jobId], workspace);
    expectCommand(jobResume).toExit(0);
    expect(outputOf(jobResume)).toContain("workflow already completed");
    expect(outputOf(jobResume)).toContain(summary.jobId);
    expect(outputOf(jobResume)).toContain("recent events");

    const jobResumeJson = runCli(["jobs", "resume", summary.jobId, "--json"], workspace);
    expectCommand(jobResumeJson).toExit(0);
    expect(jobResumeJson.stderr).toBe("");
    expect(outputOf(jobResumeJson).trimStart().startsWith("{")).toBe(true);
    const parsedJobResumeJson = JSON.parse(outputOf(jobResumeJson));
    expect(parsedJobResumeJson.summary.jobId).toBe(summary.jobId);
    expect(parsedJobResumeJson.summary.checkpointVersion).toBe(2);
    expect(parsedJobResumeJson.summary.resumeSkippedWork).toEqual([]);
    expect(parsedJobResumeJson.events.length).toBeGreaterThan(0);

    await allowVitestRpc();

    const conflictingJobResumeJson = runCli(["jobs", "resume", summary.jobId, "--dry-run", "--live", "--json"], workspace);
    expectCommand(conflictingJobResumeJson).toExit(1);
    expect(conflictingJobResumeJson.stderr).toBe("");
    expect(JSON.parse(conflictingJobResumeJson.stdout).error.code).toBe("RESUME_MODE_CONFLICT");

    const runApprovedMissingJobJson = runCli(["actions", "run-approved", "--job", "job-does-not-exist", "--json"], workspace);
    expectCommand(runApprovedMissingJobJson).toExit(1);
    expect(runApprovedMissingJobJson.stderr).toBe("");
    expect(JSON.parse(runApprovedMissingJobJson.stdout)).toEqual({
      ok: false,
      error: {
        code: "JOB_NOT_FOUND",
        message: "Job not found: job-does-not-exist",
      },
    });

    const missingActionExecuteJson = runCli(["actions", "execute", "action-does-not-exist", "--json"], workspace);
    expectCommand(missingActionExecuteJson).toExit(1);
    expect(missingActionExecuteJson.stderr).toBe("");
    expect(JSON.parse(missingActionExecuteJson.stdout)).toEqual({
      ok: false,
      error: {
        code: "ACTION_NOT_FOUND",
        message: "Action not found: action-does-not-exist",
      },
    });

    const invalidRunApprovedLimitJson = runCli(["actions", "run-approved", "--job", summary.jobId, "--limit", "1.5", "--json"], workspace);
    expectCommand(invalidRunApprovedLimitJson).toExit(1);
    expect(invalidRunApprovedLimitJson.stderr).toBe("");
    expect(JSON.parse(invalidRunApprovedLimitJson.stdout).error.code).toBe("CLI_INVALID_LIMIT");

    const legacyAuditLogPath = path.join(workspace, ".bounty", "programs", "cli-smoke", "jobs", summary.jobId, "audit.log");
    writeFileSync(
      legacyAuditLogPath,
      `${JSON.stringify({
        actionType: "legacy.audit",
        reason: "token=cli-audit-token-secret",
        metadata: { password: "cli-audit-password-secret" },
      })}\n`,
      { encoding: "utf8", flag: "a" },
    );

    const invalidAuditLimitJson = runCli(["audit", "list", "--job", summary.jobId, "--limit", "0", "--json"], workspace);
    expectCommand(invalidAuditLimitJson).toExit(1);
    expect(invalidAuditLimitJson.stderr).toBe("");
    expect(JSON.parse(invalidAuditLimitJson.stdout).error.code).toBe("CLI_INVALID_LIMIT");

    const missingAuditListJson = runCli(["audit", "list", "--job", "job-does-not-exist", "--json"], workspace);
    expectCommand(missingAuditListJson).toExit(1);
    expect(missingAuditListJson.stderr).toBe("");
    expect(JSON.parse(missingAuditListJson.stdout).error.code).toBe("JOB_NOT_FOUND");

    const missingAuditExportPath = path.join(workspace, "missing-audit-export.json");
    const missingAuditExportJson = runCli(
      ["audit", "export", "--job", "job-does-not-exist", "--output", missingAuditExportPath, "--json"],
      workspace,
    );
    expectCommand(missingAuditExportJson).toExit(1);
    expect(missingAuditExportJson.stderr).toBe("");
    expect(JSON.parse(missingAuditExportJson.stdout).error.code).toBe("JOB_NOT_FOUND");
    expect(existsSync(missingAuditExportPath)).toBe(false);

    const auditList = runCli(["audit", "list", "--job", summary.jobId], workspace);
    expectCommand(auditList).toExit(0);
    expect(outputOf(auditList)).toContain("workflow.start");
    expect(outputOf(auditList)).toContain("workflow.complete");
    expect(outputOf(auditList)).not.toContain("cli-audit-token-secret");

    const auditExportPath = path.join(workspace, "audit-export.json");
    const auditExport = runCli(["audit", "export", "--job", summary.jobId, "--output", auditExportPath], workspace);
    expectCommand(auditExport).toExit(0);
    const exportedAudit = JSON.parse(readFileSync(auditExportPath, "utf8"));
    expect(exportedAudit.jobId).toBe(summary.jobId);
    expect(exportedAudit.eventCount).toBeGreaterThan(0);
    expect(JSON.stringify(exportedAudit)).not.toContain("cli-audit-token-secret");
    expect(JSON.stringify(exportedAudit)).not.toContain("cli-audit-password-secret");

    const auditExportJson = runCli(["audit", "export", "--job", summary.jobId, "--json"], workspace);
    expectCommand(auditExportJson).toExit(0);
    expect(auditExportJson.stderr).toBe("");
    expect(JSON.parse(auditExportJson.stdout).eventCount).toBeGreaterThan(0);
    expect(auditExportJson.stdout).not.toContain("cli-audit-token-secret");
    expect(auditExportJson.stdout).not.toContain("cli-audit-password-secret");

    const dashboard = runCli(["dashboard"], workspace);
    expectCommand(dashboard).toExit(0);
    expect(outputOf(dashboard)).toContain("workspace summary ready");
    expect(outputOf(dashboard)).toContain("next actions");

    const dashboardJson = runCli(["dashboard", "--json"], workspace);
    expectCommand(dashboardJson).toExit(0);
    expect(outputOf(dashboardJson).trimStart().startsWith("{")).toBe(true);
    const parsedDashboard = JSON.parse(outputOf(dashboardJson));
    expect(parsedDashboard.program.name).toBe("cli-smoke");
    expect(parsedDashboard.actions.total).toBeGreaterThanOrEqual(4);
    expect(parsedDashboard.timeline.totalEvents).toBeGreaterThan(0);

    const exportedSummary = path.join(workspace, "workspace-summary.json");
    const exportSummary = runCli(["export", "summary", "--output", exportedSummary], workspace);
    expectCommand(exportSummary).toExit(0);
    expect(outputOf(exportSummary)).toContain("workspace summary exported");
    expect(JSON.parse(readFileSync(exportedSummary, "utf8")).program.name).toBe("cli-smoke");

    const exportSummaryJson = runCli(["export", "summary", "--json"], workspace);
    expectCommand(exportSummaryJson).toExit(0);
    expect(exportSummaryJson.stderr).toBe("");
    expect(JSON.parse(exportSummaryJson.stdout).program).toBe("cli-smoke");

    const bundleDir = path.join(workspace, "handoff-bundle");
    const exportBundle = runCli(
      ["export", "bundle", "--job", summary.jobId, "--output", bundleDir, "--include-artifacts", "--json"],
      workspace,
    );
    expectCommand(exportBundle).toExit(0);
    expect(outputOf(exportBundle).trimStart().startsWith("{")).toBe(true);
    const parsedBundle = JSON.parse(outputOf(exportBundle));
    expect(parsedBundle.outputDir).toBe(bundleDir);
    expect(parsedBundle.jobs).toHaveLength(1);
    expect(parsedBundle.artifactsCopied).toBeGreaterThan(0);
    expect(existsSync(path.join(bundleDir, "manifest.json"))).toBe(true);
    expect(existsSync(path.join(bundleDir, "workspace-summary.json"))).toBe(true);
    expect(existsSync(path.join(bundleDir, "jobs", summary.jobId, "timeline.json"))).toBe(true);
    expect(existsSync(path.join(bundleDir, "jobs", summary.jobId, "audit.json"))).toBe(true);
    expect(existsSync(path.join(bundleDir, "evidence-manifest.json"))).toBe(true);

    expect(findFiles(path.join(workspace, ".bounty"), "safe-checks.json")).toEqual([]);
    expect(findFiles(path.join(workspace, ".bounty"), "js-analysis.json")).toEqual([]);
    expect(findFiles(path.join(workspace, ".bounty"), "crawl-graph.json")).toEqual([]);
  }, 80_000);
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-cli-"));
  workspaces.push(workspace);
  return workspace;
}

function customToolRegistryYaml(): string {
  return `tools:
  - name: custom-local-tool
    category: local-helper
    description: Local helper used by CLI smoke tests.
    source: https://example.com/custom-local-tool
    version: "1.0.0"
    checksum: managed-by-test
    install:
      type: manual
    permissions:
      network: false
      filesystem_write: false
      destructive: false
      active_scanning: false
    safety:
      allowed_modes:
        - safe
      blocked_capabilities: []
    actions:
      - action_type: helper.inspect
        risk_level: low
        capabilities:
          - metadata_review
        state_changing: false
        destructive: false
        requires_approval: false
        network: false
        filesystem_write: false
`;
}

function writeFakePlaywrightMcpPackage(workspace: string): void {
  const packageRoot = path.join(workspace, "node_modules", "@playwright", "mcp");
  mkdirSync(packageRoot, { recursive: true });
  writeFileSync(
    path.join(packageRoot, "package.json"),
    JSON.stringify({ name: "@playwright/mcp", version: "1.2.3" }, null, 2),
    "utf8",
  );
  writeFileSync(path.join(packageRoot, "cli.js"), "console.log('fake playwright mcp');\n", "utf8");
}

function writeFakeInstalledBounty(root: string): string {
  mkdirSync(root, { recursive: true });
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

function writeFakeGh(root: string): string {
  mkdirSync(root, { recursive: true });
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

async function allowVitestRpc(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
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

function readOnlyWorkflowSummary(workspace: string): Record<string, any> {
  const summaries = findFiles(path.join(workspace, ".bounty"), "workflow-summary.json");
  const finalSummary = summaries
    .filter((summaryPath) => summaryPath.includes(`${path.sep}evidence${path.sep}`))
    .sort((left, right) => statSync(right).mtimeMs - statSync(left).mtimeMs)[0];
  expect(finalSummary, summaries.join("\n")).toBeDefined();
  return JSON.parse(readFileSync(finalSummary!, "utf8"));
}

function yamlSingle(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
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
