import { execFileSync } from "node:child_process";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { loadProgramFile } from "../config/config-loader.js";
import type { ProgramConfig } from "../config/program-schema.js";
import { IntegrationManager } from "../../integrations/integration-manager/integration-manager.js";
import { BUG_BOUNTY_PILOT_SKILL_ID, validateSkillDefinition } from "../../skills/skill-definition.js";

export type ReleaseCheckStatus = "pass" | "warn" | "fail";

export interface ReleaseCheckItem {
  name: string;
  status: ReleaseCheckStatus;
  message: string;
}

export interface ReleaseCheckResult {
  ok: boolean;
  generatedAt: string;
  cwd: string;
  packageName?: string;
  version?: string;
  checks: ReleaseCheckItem[];
}

const REQUIRED_SCRIPTS = [
  "clean",
  "build",
  "test",
  "test:smoke",
  "test:external-tools",
  "test:package-bin",
  "test:vm-lab",
  "test:vm-real-tools",
  "typecheck",
  "release:check",
  "sbom",
  "verify:release",
  "prepare",
  "prepack",
  "dev",
];
const REQUIRED_PACKAGE_FILES = ["dist", "examples", "skills"];
const FORBIDDEN_PACKAGE_FILES = ["src", "tests"];
const FORBIDDEN_TRACKED_RELEASE_ARTIFACTS = [
  /^artifacts\/release\//,
  /^\.release\//,
  /^bountypilot-[^/]+\.tgz$/,
  /^bug-bounty-pilot\.skill\.zip$/,
  /^bountypilot-sbom\.cdx\.json$/,
  /^release-manifest\.json$/,
  /^SHA256SUMS\.txt$/,
];
const REQUIRED_SKILL_FILES = [
  "skills/bug-bounty-pilot/SKILL.md",
  "skills/bug-bounty-pilot/policy.yml",
  "skills/bug-bounty-pilot/workflow.yml",
  "skills/bug-bounty-pilot/tool-registry.yml",
  "skills/bug-bounty-pilot/playbooks.yml",
  "skills/bug-bounty-pilot/vm-profile.yml",
];
const REQUIRED_EXAMPLES = [
  "examples/program.yml",
  "examples/local-program.yml",
  "examples/local-lab-authorization.md",
  "examples/integrations.yml",
  "examples/tool-registry.yml",
  "examples/safe-workflow.md",
  "examples/mcp-steps.json",
  "examples/workflow-summary.json",
  "examples/sample-finding.json",
  "examples/sample-evidence-manifest.json",
  "examples/sample-report.md",
  "examples/evidence/finding-example-security-header/reproduction.md",
  "examples/evidence/finding-example-security-header/safe-check-output.json",
];
const REQUIRED_PROGRAM_EXAMPLES = ["examples/program.yml", "examples/local-program.yml"];
const REQUIRED_PUBLIC_REPO_FILES = ["LICENSE", "SECURITY.md", "CONTRIBUTING.md"];
const REQUIRED_INSTALLER_FILES = [
  {
    name: "scripts/install.sh",
    snippets: [
      "MIN_NODE_VERSION=\"22.13.0\"",
      "validate_source_spec",
      "Invalid BOUNTYPILOT_SOURCE",
      "BOUNTYPILOT_INSTALL_DRY_RUN",
      "npm install -g",
      "skill validate bug-bounty-pilot",
    ],
  },
  {
    name: "scripts/install.ps1",
    snippets: [
      "$MinNodeVersion = [version]\"22.13.0\"",
      "Assert-BountyPilotSourceSpec",
      "Invalid BOUNTYPILOT_SOURCE",
      "BOUNTYPILOT_INSTALL_DRY_RUN",
      "$LASTEXITCODE",
      "npm install -g",
      "skill validate bug-bounty-pilot",
    ],
  },
];
const REQUIRED_RELEASE_SCRIPT_FILES = [
  {
    name: "scripts/vm-real-tools-smoke.sh",
    snippets: [
      "BOUNTYPILOT_VM_REAL_TOOLS_INSTALL",
      "http://127.0.0.1:",
      "tools approve-executable httpx",
      "tools approve-executable katana",
      "hunt recon",
      "--tools httpx,katana",
    ],
  },
];
const REQUIRED_GITHUB_COMMUNITY_FILES = [
  {
    name: ".github/pull_request_template.md",
    snippets: ["Safety Checklist", "npm run verify:release", "No real target data"],
  },
  {
    name: ".github/dependabot.yml",
    snippets: ["package-ecosystem: npm", "interval: weekly", "open-pull-requests-limit"],
  },
  {
    name: ".github/ISSUE_TEMPLATE/bug_report.yml",
    snippets: ["Bug report", "Safety confirmation", "secrets"],
  },
  {
    name: ".github/ISSUE_TEMPLATE/feature_request.yml",
    snippets: ["Feature request", "Safety mode", "scope, policy"],
  },
  {
    name: ".github/ISSUE_TEMPLATE/config.yml",
    snippets: ["blank_issues_enabled: false"],
  },
];
const REQUIRED_GITHUB_WORKFLOWS = [
  {
    name: ".github/workflows/ci.yml",
    snippets: ["ubuntu-latest", "windows-latest", "npm ci", "npm run verify:release"],
  },
  {
    name: ".github/workflows/release.yml",
    snippets: [
      "attestations: write",
      "id-token: write",
      "npm ci",
      "npm run verify:release",
      "release bundle --output .release --force --json",
      "release verify-bundle .release --json",
      "bug-bounty-pilot.skill.zip",
      "bountypilot-sbom.cdx.json",
      "release-manifest.json",
      "SHA256SUMS.txt",
      "actions/attest-build-provenance@v2",
      "softprops/action-gh-release",
    ],
  },
  {
    name: ".github/workflows/codeql.yml",
    snippets: ["github/codeql-action/init@v3", "javascript-typescript", "security-extended", "npm run build"],
  },
  {
    name: ".github/workflows/vm-lab.yml",
    snippets: ["ubuntu-latest", "npm ci", "npm run test:vm-lab", "Packaged CLI local lab smoke", "workflow_dispatch"],
  },
  {
    name: ".github/workflows/real-tools.yml",
    snippets: [
      "ubuntu-latest",
      "actions/setup-go@v5",
      "npm run test:vm-real-tools",
      "BOUNTYPILOT_VM_REAL_TOOLS_INSTALL",
      "workflow_dispatch",
    ],
  },
];
const MIN_NODE_SQLITE_RUNTIME: [number, number, number] = [22, 13, 0];

export function runReleaseCheck(cwd = process.cwd()): ReleaseCheckResult {
  const checks: ReleaseCheckItem[] = [];
  const packagePath = path.join(cwd, "package.json");
  const packageJson = readPackageJson(packagePath);

  checks.push(fileCheck("package.json", packagePath));
  checks.push(fileCheck("README.md", path.join(cwd, "README.md")));
  checks.push(fileCheck("tsconfig.json", path.join(cwd, "tsconfig.json")));
  checks.push(fileCheck("package-lock.json", path.join(cwd, "package-lock.json")));
  for (const publicFile of REQUIRED_PUBLIC_REPO_FILES) {
    checks.push(fileCheck(publicFile, path.join(cwd, publicFile)));
  }
  for (const workflow of REQUIRED_GITHUB_WORKFLOWS) {
    const workflowPath = path.join(cwd, workflow.name);
    checks.push(fileCheck(workflow.name, workflowPath));
    checks.push(workflowContentCheck(workflow.name, workflowPath, workflow.snippets));
  }
  checks.push(githubRemoteCheck(cwd));
  checks.push(trackedReleaseArtifactCheck(cwd));
  for (const communityFile of REQUIRED_GITHUB_COMMUNITY_FILES) {
    const communityPath = path.join(cwd, communityFile.name);
    checks.push(fileCheck(communityFile.name, communityPath));
    checks.push(workflowContentCheck(communityFile.name, communityPath, communityFile.snippets));
  }
  for (const installerFile of REQUIRED_INSTALLER_FILES) {
    const installerPath = path.join(cwd, installerFile.name);
    checks.push(fileCheck(installerFile.name, installerPath));
    checks.push(workflowContentCheck(`${installerFile.name}:content`, installerPath, installerFile.snippets));
  }
  for (const releaseScript of REQUIRED_RELEASE_SCRIPT_FILES) {
    const scriptPath = path.join(cwd, releaseScript.name);
    checks.push(fileCheck(releaseScript.name, scriptPath));
    checks.push(workflowContentCheck(`${releaseScript.name}:content`, scriptPath, releaseScript.snippets));
  }

  if (packageJson) {
    checks.push(packageFieldCheck("name", typeof packageJson.name === "string" && packageJson.name.length > 0));
    checks.push(packageFieldCheck("version", typeof packageJson.version === "string" && packageJson.version.length > 0));
    checks.push(packageFieldCheck("type=module", packageJson.type === "module"));
    checks.push(packageFieldCheck("license", typeof packageJson.license === "string" && packageJson.license.length > 0));
    const packageFiles = packageFilesFrom(packageJson.files);
    const missingPackageFiles = REQUIRED_PACKAGE_FILES.filter((entry) => !hasPackageFile(packageFiles, entry));
    checks.push({
      name: "package:files",
      status: packageFiles.length > 0 && missingPackageFiles.length === 0 ? "pass" : "fail",
      message:
        packageFiles.length > 0
          ? missingPackageFiles.length === 0
            ? packageFiles.join(", ")
            : `Missing publish entries: ${missingPackageFiles.join(", ")}`
          : "Add a files whitelist so npm pack contains the runtime package only",
    });
    const forbiddenPackageFiles = FORBIDDEN_PACKAGE_FILES.filter((entry) => hasPackageFile(packageFiles, entry));
    checks.push({
      name: "package:files excludes source/tests",
      status: forbiddenPackageFiles.length === 0 ? "pass" : "fail",
      message:
        forbiddenPackageFiles.length === 0
          ? "source and tests are excluded from the runtime package"
          : `Remove publish entries: ${forbiddenPackageFiles.join(", ")}`,
    });
    const binPath = typeof packageJson.bin?.bugbounty === "string" ? packageJson.bin.bugbounty : undefined;
    checks.push({
      name: "bin.bugbounty",
      status: binPath ? "pass" : "fail",
      message: binPath ? `bugbounty -> ${binPath}` : "package.json must expose bin.bugbounty",
    });
    const legacyBinPath = typeof packageJson.bin?.bounty === "string" ? packageJson.bin.bounty : undefined;
    checks.push({
      name: "bin.bounty",
      status: legacyBinPath ? "pass" : "warn",
      message: legacyBinPath ? `bounty -> ${legacyBinPath}` : "optional legacy alias bin.bounty is not configured",
    });
    if (binPath) {
      checks.push(fileCheck("compiled bin", path.resolve(cwd, binPath)));
    }
    for (const script of REQUIRED_SCRIPTS) {
      checks.push({
        name: `script:${script}`,
        status: typeof packageJson.scripts?.[script] === "string" ? "pass" : "fail",
        message:
          typeof packageJson.scripts?.[script] === "string"
            ? packageJson.scripts[script]
            : `Missing npm script ${script}`,
      });
    }
    const nodeEngine = packageJson.engines?.node;
    const nodeEngineOk = typeof nodeEngine === "string" && nodeEngineSupportsSqliteRuntime(nodeEngine);
    checks.push({
      name: "engines.node",
      status: nodeEngineOk ? "pass" : "fail",
      message: typeof nodeEngine === "string" ? nodeEngine : "Node engine is not declared; node:sqlite requires >=22.13.0",
    });
  }

  for (const example of REQUIRED_EXAMPLES) {
    checks.push(fileCheck(example, path.join(cwd, example)));
  }
  for (const skillFile of REQUIRED_SKILL_FILES) {
    checks.push(fileCheck(skillFile, path.join(cwd, skillFile)));
  }
  checks.push(skillPackageCheck(cwd));
  for (const example of REQUIRED_EXAMPLES) {
    checks.push(exampleContentCheck(example, path.join(cwd, example)));
  }
  for (const example of REQUIRED_PROGRAM_EXAMPLES) {
    checks.push(programExampleCheck(example, path.join(cwd, example)));
  }

  const distCli = path.join(cwd, "dist", "cli", "index.js");
  checks.push({
    name: "dist cli shebang",
    status: readText(distCli)?.startsWith("#!/usr/bin/env node") ? "pass" : "fail",
    message: "dist/cli/index.js should be built and executable by Node",
  });
  const staleDistPaths = ["dist/src", "dist/tests"].filter((entry) => existsSync(path.join(cwd, entry)));
  checks.push({
    name: "dist stale outputs",
    status: staleDistPaths.length === 0 ? "pass" : "fail",
    message:
      staleDistPaths.length === 0
        ? "dist contains only current build outputs"
        : `Run npm run clean && npm run build; found ${staleDistPaths.join(", ")}`,
  });

  return {
    ok: checks.every((check) => check.status !== "fail"),
    generatedAt: new Date().toISOString(),
    cwd,
    packageName: packageJson?.name,
    version: packageJson?.version,
    checks,
  };
}

function skillPackageCheck(cwd: string): ReleaseCheckItem {
  try {
    const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, cwd);
    const failures = result.checks.filter((check) => check.status === "fail");
    return {
      name: "skills/bug-bounty-pilot:valid",
      status: failures.length === 0 ? "pass" : "fail",
      message: failures.length === 0 ? `${result.checks.length} skill checks passed` : failures.map((check) => check.name).join(", "),
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { name: "skills/bug-bounty-pilot:valid", status: "fail", message: reason };
  }
}

export function nodeEngineSupportsSqliteRuntime(engine: string): boolean {
  const match = />=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(engine);
  if (!match) return false;
  const version: [number, number, number] = [
    Number(match[1]),
    Number(match[2] ?? 0),
    Number(match[3] ?? 0),
  ];
  return compareVersions(version, MIN_NODE_SQLITE_RUNTIME) >= 0;
}

function compareVersions(left: [number, number, number], right: [number, number, number]): number {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index];
    }
  }
  return 0;
}

function readPackageJson(filePath: string): Record<string, any> | undefined {
  try {
    return JSON.parse(readFileSync(filePath, "utf8")) as Record<string, any>;
  } catch {
    return undefined;
  }
}

function readText(filePath: string): string | undefined {
  try {
    return readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }
}

function fileCheck(name: string, filePath: string): ReleaseCheckItem {
  if (!existsSync(filePath)) {
    return { name, status: "fail", message: `Missing ${filePath}` };
  }
  try {
    accessSync(filePath, constants.R_OK);
    return { name, status: "pass", message: filePath };
  } catch {
    return { name, status: "fail", message: `Not readable: ${filePath}` };
  }
}

function githubRemoteCheck(cwd: string): ReleaseCheckItem {
  if (!existsSync(path.join(cwd, ".git"))) {
    return {
      name: "github:origin",
      status: "warn",
      message: "No .git directory found; packaged installs can ignore this, but source releases should be pushed to GitHub.",
    };
  }

  let remote = "";
  try {
    remote = execFileSync("git", ["remote", "get-url", "origin"], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2_000,
    }).trim();
  } catch {
    return {
      name: "github:origin",
      status: "warn",
      message: "No origin remote configured. Add one with: git remote add origin https://github.com/OWNER/REPO.git",
    };
  }

  if (!remote) {
    return {
      name: "github:origin",
      status: "warn",
      message: "Origin remote is empty. Add a GitHub remote before publishing a public release.",
    };
  }

  const githubRemote = /^(?:https:\/\/github\.com\/|git@github\.com:)[^/:\s]+\/[^/\s]+(?:\.git)?$/i.test(remote);
  return {
    name: "github:origin",
    status: githubRemote ? "pass" : "warn",
    message: githubRemote
      ? remote
      : `Origin remote is not a GitHub repository (${remote}). Public one-command installs expect a GitHub or npm release source.`,
  };
}

function trackedReleaseArtifactCheck(cwd: string): ReleaseCheckItem {
  if (!existsSync(path.join(cwd, ".git"))) {
    return {
      name: "git:tracked-release-artifacts",
      status: "pass",
      message: "not a git checkout; tracked release artifact check skipped",
    };
  }

  let output = "";
  try {
    output = execFileSync("git", ["ls-files"], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2_000,
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      name: "git:tracked-release-artifacts",
      status: "warn",
      message: `Could not inspect tracked release artifacts: ${reason}`,
    };
  }

  const tracked = output
    .split(/\r?\n/)
    .map((entry) => entry.trim().replaceAll("\\", "/"))
    .filter(Boolean);
  const offenders = tracked.filter((entry) => FORBIDDEN_TRACKED_RELEASE_ARTIFACTS.some((pattern) => pattern.test(entry)));
  return {
    name: "git:tracked-release-artifacts",
    status: offenders.length === 0 ? "pass" : "fail",
    message:
      offenders.length === 0
        ? "no generated release artifacts are tracked"
        : `Remove generated release artifacts from git: ${offenders.join(", ")}`,
  };
}

function programExampleCheck(name: string, filePath: string): ReleaseCheckItem {
  try {
    const loaded = loadProgramFile(filePath);
    return { name: `${name}:valid`, status: "pass", message: loaded.config.program };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { name: `${name}:valid`, status: "fail", message: reason };
  }
}

function exampleContentCheck(name: string, filePath: string): ReleaseCheckItem {
  if (name.endsWith(".json")) {
    return jsonExampleCheck(name, filePath);
  }
  if (name.endsWith(".yml") || name.endsWith(".yaml")) {
    return yamlExampleCheck(name, filePath);
  }
  return { name: `${name}:content`, status: "pass", message: "not structured data" };
}

function jsonExampleCheck(name: string, filePath: string): ReleaseCheckItem {
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
    const required = requiredJsonKeys(name);
    const missing = required.filter((key) => !hasOwnObjectKey(parsed, key));
    const nestedError = missing.length === 0 && name.endsWith("workflow-summary.json") ? workflowSummaryExampleCheck(parsed) : undefined;
    return {
      name: `${name}:json`,
      status: missing.length === 0 && !nestedError ? "pass" : "fail",
      message:
        missing.length > 0
          ? `Missing required keys: ${missing.join(", ")}`
          : nestedError ?? `valid JSON (${required.length} required keys)`,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { name: `${name}:json`, status: "fail", message: reason };
  }
}

function yamlExampleCheck(name: string, filePath: string): ReleaseCheckItem {
  try {
    const parsed = YAML.parse(readFileSync(filePath, "utf8")) as unknown;
    const required = requiredYamlKeys(name);
    const missing = required.filter((key) => !hasOwnObjectKey(parsed, key));
    if (missing.length === 0 && name.endsWith("integrations.yml")) {
      const integrationResult = integrationsExampleCheck(parsed);
      if (integrationResult) {
        return { name: `${name}:yaml`, status: "fail", message: integrationResult };
      }
    }
    return {
      name: `${name}:yaml`,
      status: missing.length === 0 ? "pass" : "fail",
      message: missing.length === 0 ? `valid YAML (${required.length} required keys)` : `Missing required keys: ${missing.join(", ")}`,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { name: `${name}:yaml`, status: "fail", message: reason };
  }
}

function integrationsExampleCheck(parsed: unknown): string | undefined {
  const integrations = (parsed as { integrations?: unknown }).integrations;
  if (!integrations || typeof integrations !== "object" || Array.isArray(integrations)) {
    return "integrations must be an object";
  }
  const manager = new IntegrationManager(exampleProgramConfig(integrations as Record<string, unknown>));
  const invalid = manager.listDetailed().filter((integration) => integration.configErrors.length > 0 || integration.unknownCapabilities.length > 0);
  if (invalid.length === 0) {
    return undefined;
  }
  return invalid
    .map((integration) => `${integration.name}: ${[...integration.configErrors, ...integration.unknownCapabilities].join("; ")}`)
    .join("; ");
}

function exampleProgramConfig(integrations: Record<string, unknown>): ProgramConfig {
  return {
    program: "release-example",
    platform: "hackerone",
    in_scope: ["example.com"],
    out_of_scope: [],
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "1rps",
      browser_crawling: true,
      deep_safe_mode: true,
      lab_mode: false,
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
    integrations,
  };
}

function requiredJsonKeys(name: string): string[] {
  if (name.endsWith("mcp-steps.json")) return ["steps"];
  if (name.endsWith("workflow-summary.json")) {
    return [
      "checkpointVersion",
      "jobId",
      "status",
      "program",
      "mode",
      "dryRun",
      "draftReports",
      "components",
      "seeds",
      "skippedScopeRules",
      "phases",
      "findingsCreated",
      "evidenceCreated",
      "actionsPlanned",
      "actionCounts",
      "reportsDrafted",
      "candidatesCreated",
      "startedAt",
      "updatedAt",
      "resumeSkippedWork",
    ];
  }
  if (name.endsWith("sample-finding.json")) return ["id", "title", "url", "status", "evidencePaths"];
  if (name.endsWith("sample-evidence-manifest.json")) return ["generatedAt", "artifacts"];
  if (name.endsWith("safe-check-output.json")) return ["target", "checks", "safeTesting"];
  return [];
}

function requiredYamlKeys(name: string): string[] {
  if (name.endsWith("program.yml") || name.endsWith("local-program.yml")) {
    return ["program", "platform", "in_scope", "rules", "evidence", "integrations"];
  }
  if (name.endsWith("integrations.yml")) return ["integrations"];
  if (name.endsWith("tool-registry.yml")) return ["tools"];
  return [];
}

function hasOwnObjectKey(value: unknown, key: string): boolean {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) && Object.hasOwn(value, key));
}

function workflowSummaryExampleCheck(parsed: unknown): string | undefined {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return "workflow summary must be an object";
  }
  const summary = parsed as Record<string, unknown>;
  if (summary.checkpointVersion !== 2) {
    return "checkpointVersion must be 2";
  }
  if (!Array.isArray(summary.phases) || !summary.phases.every(isWorkflowPhaseExample)) {
    return "phases must contain objects with string name/status/detail and optional string target";
  }
  if (!Array.isArray(summary.resumeSkippedWork) || !summary.resumeSkippedWork.every(isWorkflowSkippedWorkExample)) {
    return "resumeSkippedWork must contain objects with string phase and optional string target";
  }
  if (summary.plannerLoop !== undefined && !isPlannerLoopExample(summary.plannerLoop)) {
    return "plannerLoop must contain action and iteration arrays when present";
  }
  return undefined;
}

function isWorkflowPhaseExample(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const phase = value as Record<string, unknown>;
  return (
    typeof phase.name === "string" &&
    typeof phase.detail === "string" &&
    (phase.status === "completed" || phase.status === "failed" || phase.status === "skipped" || phase.status === "planned") &&
    (phase.target === undefined || typeof phase.target === "string")
  );
}

function isWorkflowSkippedWorkExample(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const skipped = value as Record<string, unknown>;
  return typeof skipped.phase === "string" && (skipped.target === undefined || typeof skipped.target === "string");
}

function isPlannerLoopExample(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const plannerLoop = value as Record<string, unknown>;
  return (
    Array.isArray(plannerLoop.actions) &&
    plannerLoop.actions.every(isPlannerLoopActionExample) &&
    Array.isArray(plannerLoop.iterations) &&
    plannerLoop.iterations.every(isPlannerLoopIterationExample) &&
    Boolean(plannerLoop.inputSummary && typeof plannerLoop.inputSummary === "object" && !Array.isArray(plannerLoop.inputSummary))
  );
}

function isPlannerLoopActionExample(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const action = value as Record<string, unknown>;
  return (
    typeof action.adapter === "string" &&
    typeof action.actionType === "string" &&
    typeof action.target === "string" &&
    (action.riskLevel === "low" || action.riskLevel === "medium" || action.riskLevel === "high") &&
    typeof action.requiresApproval === "boolean" &&
    typeof action.reason === "string" &&
    typeof action.score === "number" &&
    typeof action.iteration === "number" &&
    typeof action.dedupeKey === "string" &&
    typeof action.source === "string"
  );
}

function isPlannerLoopIterationExample(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const iteration = value as Record<string, unknown>;
  return (
    typeof iteration.index === "number" &&
    typeof iteration.label === "string" &&
    typeof iteration.candidates === "number" &&
    typeof iteration.selected === "number" &&
    typeof iteration.skippedDuplicates === "number" &&
    typeof iteration.skippedExistingActions === "number" &&
    typeof iteration.skippedFailedOrBlockedHistory === "number"
  );
}

function packageFieldCheck(name: string, passed: boolean): ReleaseCheckItem {
  return {
    name: `package:${name}`,
    status: passed ? "pass" : "fail",
    message: passed ? "ok" : `Invalid or missing package field ${name}`,
  };
}

function workflowContentCheck(name: string, filePath: string, requiredSnippets: string[]): ReleaseCheckItem {
  const text = readText(filePath);
  if (!text) {
    return { name: `${name}:content`, status: "fail", message: `Missing ${filePath}` };
  }
  const missing = requiredSnippets.filter((snippet) => !text.includes(snippet));
  return {
    name: `${name}:content`,
    status: missing.length === 0 ? "pass" : "fail",
    message:
      missing.length === 0
        ? `contains required release gates: ${requiredSnippets.join(", ")}`
        : `Missing required workflow content: ${missing.join(", ")}`,
  };
}

function packageFilesFrom(files: unknown): string[] {
  if (!Array.isArray(files)) return [];
  return files.filter((entry): entry is string => typeof entry === "string").map(normalizePackageFile);
}

function hasPackageFile(files: string[], expected: string): boolean {
  const normalizedExpected = normalizePackageFile(expected);
  return files.some((entry) => entry === normalizedExpected || entry.startsWith(`${normalizedExpected}/`));
}

function normalizePackageFile(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/$/, "");
}
