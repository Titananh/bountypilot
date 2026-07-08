import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { BountyPilotError } from "../../utils/errors.js";
import { runReleaseCheck, type ReleaseCheckResult } from "./release-check.js";

export interface GitHubRepoRef {
  owner: string;
  repo: string;
  slug: string;
  httpsRemote: string;
  sshRemote: string;
  webUrl: string;
}

export interface ReleasePublishPlanResult {
  ok: boolean;
  repo: GitHubRepoRef;
  branch: string;
  publicBranch: string;
  tag: string;
  remote: {
    preferred: "https" | "ssh";
    origin?: string;
    matchesTarget: boolean;
    addCommand: string;
    setUrlCommand: string;
  };
  releaseCheck: ReleaseCheckResult;
  install: {
    npm: string;
    npmPinned: string;
    shell: string;
    powershell: string;
    shellDryRun: string;
    powershellDryRun: string;
  };
  commands: {
    localVerify: string[];
    githubCliPreflight: string[];
    repositoryCreate: string[];
    remoteSetup: string[];
    postPushVerify: string[];
    actionsVerify: string[];
    installVerify: string[];
    release: string[];
    publicBranchVerify: string[];
  };
  urls: {
    repository: string;
    actions: string;
    releases: string;
    latestRelease: string;
  };
  markdown: string;
  outputPath?: string;
}

export interface BuildReleasePublishPlanInput {
  cwd?: string;
  repo: string;
  branch?: string;
  tag?: string;
  remote?: "https" | "ssh";
  write?: boolean;
  output?: string;
}

export interface ReleasePublishStatusCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

export interface ReleasePublishStatusResult {
  ok: boolean;
  repo: GitHubRepoRef;
  branch: string;
  publicBranch: string;
  tag: string;
  online: boolean;
  remote: ReleasePublishPlanResult["remote"];
  releaseCheck: ReleaseCheckResult;
  install: ReleasePublishPlanResult["install"];
  installVerify: string[];
  checks: ReleasePublishStatusCheck[];
  nextCommands: string[];
  urls: ReleasePublishPlanResult["urls"];
}

export interface BuildReleasePublishStatusInput {
  cwd?: string;
  repo: string;
  branch?: string;
  tag?: string;
  remote?: "https" | "ssh";
  online?: boolean;
  actions?: boolean;
  ghCommand?: string;
  ghArgsPrefix?: string[];
  timeoutMs?: number;
}

const GITHUB_CLI_INSTALL_COMMANDS = [
  "winget install --id GitHub.cli -e",
  "brew install gh",
  "sudo apt-get update && sudo apt-get install -y gh",
];

export function buildReleasePublishPlan(input: BuildReleasePublishPlanInput): ReleasePublishPlanResult {
  const cwd = input.cwd ?? process.cwd();
  const repo = parseGitHubRepo(input.repo);
  const packageJson = readPackageJson(cwd);
  const version = typeof packageJson.version === "string" && packageJson.version.trim() ? packageJson.version.trim() : "0.1.0";
  const branch = input.branch?.trim() || currentGitBranch(cwd) || "main";
  const publicBranch = "main";
  const tag = input.tag?.trim() || `v${version}`;
  const remotePreference = input.remote ?? "https";
  const targetRemote = remotePreference === "ssh" ? repo.sshRemote : repo.httpsRemote;
  const origin = currentOrigin(cwd);
  const releaseCheck = runReleaseCheck(cwd);
  const install = releaseInstallCommands(repo, branch);
  const commands = {
    localVerify: [
      "npm ci",
      "npm run verify:release",
      `bounty skill score bug-bounty-pilot --repo ${repo.slug} --json`,
      "bounty release bundle --output .release --force --json",
      "bounty release verify-bundle .release --json",
    ],
    githubCliPreflight: ["gh --version", "gh auth status", "gh auth login"],
    repositoryCreate: [`gh repo create ${repo.slug} --public --source . --remote origin --push`],
    remoteSetup: [
      origin ? `git remote set-url origin ${targetRemote}` : `git remote add origin ${targetRemote}`,
      `git push -u origin ${branch}`,
    ],
    postPushVerify: [`bounty release publish-status ${repo.slug} --branch ${branch} --tag ${tag} --online --json`],
    actionsVerify: [
      `bounty release publish-status ${repo.slug} --branch ${branch} --tag ${tag} --online --actions --json`,
      `gh run list --repo ${repo.slug} --limit 10`,
    ],
    installVerify: releaseInstallVerifyCommands(install),
    release: [
      `git tag ${tag}`,
      `bounty skill score bug-bounty-pilot --repo ${repo.slug} --branch ${branch} --tag ${tag} --strict --json`,
      `git push origin ${tag}`,
    ],
    publicBranchVerify:
      branch === publicBranch
        ? []
        : [
            `git push -u origin HEAD:${publicBranch}`,
            `bounty release publish-plan ${repo.slug} --branch ${publicBranch} --tag ${tag} --write`,
            `bounty release publish-status ${repo.slug} --branch ${publicBranch} --tag ${tag} --online --actions --json`,
          ],
  };
  const urls = {
    repository: repo.webUrl,
    actions: `${repo.webUrl}/actions`,
    releases: `${repo.webUrl}/releases`,
    latestRelease: `${repo.webUrl}/releases/latest`,
  };
  const resultWithoutMarkdown = {
    ok: releaseCheck.ok,
    repo,
    branch,
    publicBranch,
    tag,
    remote: {
      preferred: remotePreference,
      origin,
      matchesTarget: Boolean(origin) && sameRemote(origin!, targetRemote),
      addCommand: `git remote add origin ${targetRemote}`,
      setUrlCommand: `git remote set-url origin ${targetRemote}`,
    },
    releaseCheck,
    install,
    commands,
    urls,
  };
  const markdown = renderReleasePublishPlan(resultWithoutMarkdown);
  const outputPath = input.write ? writePublishPlan(cwd, input.output, markdown) : undefined;
  return {
    ...resultWithoutMarkdown,
    markdown,
    outputPath,
  };
}

export function buildReleasePublishStatus(input: BuildReleasePublishStatusInput): ReleasePublishStatusResult {
  const cwd = input.cwd ?? process.cwd();
  const repo = parseGitHubRepo(input.repo);
  const packageJson = readPackageJson(cwd);
  const version = typeof packageJson.version === "string" && packageJson.version.trim() ? packageJson.version.trim() : "0.1.0";
  const branch = input.branch?.trim() || currentGitBranch(cwd) || "main";
  const publicBranch = "main";
  const tag = input.tag?.trim() || `v${version}`;
  const remotePreference = input.remote ?? "https";
  const targetRemote = remotePreference === "ssh" ? repo.sshRemote : repo.httpsRemote;
  const origin = currentOrigin(cwd);
  const releaseCheck = runReleaseCheck(cwd);
  const install = releaseInstallCommands(repo, branch);
  const installVerify = releaseInstallVerifyCommands(install);
  const checks: ReleasePublishStatusCheck[] = [
    {
      name: "release:check",
      status: releaseCheck.ok ? "pass" : "fail",
      message: releaseCheck.ok ? `${releaseCheck.checks.length} release checks passed` : "Run npm run verify:release before publishing.",
    },
    origin
      ? { name: "git:origin", status: "pass", message: origin }
      : { name: "git:origin", status: "fail", message: "No origin remote configured." },
    origin && sameRemote(origin, targetRemote)
      ? { name: "git:origin-target", status: "pass", message: `origin matches ${targetRemote}` }
      : {
          name: "git:origin-target",
          status: "fail",
          message: origin ? `origin is ${origin}, expected ${targetRemote}` : `Set origin to ${targetRemote}`,
        },
    workingTreeStatus(cwd),
    currentBranchStatus(cwd, branch),
    publicBranchStatus(branch, publicBranch),
    localTagStatus(cwd, tag),
  ];

  if (input.online) {
    checks.push(remoteRefStatus(cwd, "git:remote-branch", `refs/heads/${branch}`, `Remote branch ${branch} is published.`, input.timeoutMs));
    checks.push(remoteRefStatus(cwd, "git:remote-tag", `refs/tags/${tag}`, `Remote tag ${tag} is published.`, input.timeoutMs, "warn"));
  } else {
    checks.push({
      name: "publish:online",
      status: "warn",
      message: "Online GitHub branch/tag checks were skipped. Re-run with --online after pushing.",
    });
  }
  if (input.actions) {
    checks.push(...githubActionsStatusChecks({
      repo: repo.slug,
      branch,
      ghCommand: input.ghCommand ?? "gh",
      ghArgsPrefix: input.ghArgsPrefix ?? [],
      timeoutMs: input.timeoutMs,
    }));
  } else {
    checks.push({
      name: "github:actions",
      status: "warn",
      message: "GitHub Actions checks were skipped. Re-run with --actions after pushing.",
    });
  }

  const remote = {
    preferred: remotePreference,
    origin,
    matchesTarget: Boolean(origin) && sameRemote(origin!, targetRemote),
    addCommand: `git remote add origin ${targetRemote}`,
    setUrlCommand: `git remote set-url origin ${targetRemote}`,
  };
  const urls = {
    repository: repo.webUrl,
    actions: `${repo.webUrl}/actions`,
    releases: `${repo.webUrl}/releases`,
    latestRelease: `${repo.webUrl}/releases/latest`,
  };
  return {
    ok: checks.every((check) => check.status !== "fail"),
    repo,
    branch,
    publicBranch,
    tag,
    online: Boolean(input.online),
    remote,
    releaseCheck,
    install,
    installVerify,
    checks,
    nextCommands: publishStatusNextCommands({
      repo,
      branch,
      publicBranch,
      tag,
      remote,
      checks,
      online: Boolean(input.online),
      actions: Boolean(input.actions),
    }),
    urls,
  };
}

function releaseInstallCommands(repo: GitHubRepoRef, branch: string): ReleasePublishPlanResult["install"] {
  return {
    npm: `npm install -g github:${repo.slug}`,
    npmPinned: `npm install -g github:${repo.slug}#${branch}`,
    shell: `curl -fsSL https://raw.githubusercontent.com/${repo.slug}/${branch}/scripts/install.sh | BOUNTYPILOT_SOURCE=github:${repo.slug} bash`,
    powershell: `$env:BOUNTYPILOT_SOURCE="github:${repo.slug}"; irm https://raw.githubusercontent.com/${repo.slug}/${branch}/scripts/install.ps1 | iex`,
    shellDryRun: `curl -fsSL https://raw.githubusercontent.com/${repo.slug}/${branch}/scripts/install.sh | BOUNTYPILOT_SOURCE=github:${repo.slug} BOUNTYPILOT_INSTALL_DRY_RUN=1 bash`,
    powershellDryRun: `$env:BOUNTYPILOT_SOURCE="github:${repo.slug}"; $env:BOUNTYPILOT_INSTALL_DRY_RUN="1"; irm https://raw.githubusercontent.com/${repo.slug}/${branch}/scripts/install.ps1 | iex`,
  };
}

function releaseInstallVerifyCommands(install: ReleasePublishPlanResult["install"]): string[] {
  return [install.npm, install.npmPinned, "bugbounty release install-check --json", install.shellDryRun, install.powershellDryRun];
}

export function parseGitHubRepo(value: string): GitHubRepoRef {
  const trimmed = value.trim();
  const normalized = trimmed
    .replace(/^https:\/\/github\.com\//i, "")
    .replace(/^git@github\.com:/i, "")
    .replace(/\.git$/i, "")
    .replace(/^\/+|\/+$/g, "");
  const parts = normalized.split("/");
  if (parts.length !== 2 || !/^[A-Za-z0-9_.-]+$/.test(parts[0]!) || !/^[A-Za-z0-9_.-]+$/.test(parts[1]!)) {
    throw new BountyPilotError("GitHub repo must be OWNER/REPO, https://github.com/OWNER/REPO, or git@github.com:OWNER/REPO.git.", "GITHUB_REPO_INVALID");
  }
  const owner = parts[0]!;
  const repo = parts[1]!;
  const slug = `${owner}/${repo}`;
  return {
    owner,
    repo,
    slug,
    httpsRemote: `https://github.com/${slug}.git`,
    sshRemote: `git@github.com:${slug}.git`,
    webUrl: `https://github.com/${slug}`,
  };
}

function renderReleasePublishPlan(input: Omit<ReleasePublishPlanResult, "markdown" | "outputPath">): string {
  const failures = input.releaseCheck.checks.filter((check) => check.status === "fail");
  const warnings = input.releaseCheck.checks.filter((check) => check.status === "warn");
  return `# BountyPilot GitHub Publish Plan

Repository: ${input.repo.slug}
Branch: ${input.branch}
Public branch: ${input.publicBranch}
Release tag: ${input.tag}
Preferred remote: ${input.remote.preferred}
Current origin: ${input.remote.origin ?? "not configured"}
Release check: ${input.releaseCheck.ok ? "pass" : "blocked"} (${input.releaseCheck.checks.length} checks, ${failures.length} failures, ${warnings.length} warnings)

## 1. Local Verification

\`\`\`bash
${input.commands.localVerify.join("\n")}
\`\`\`

## 2. GitHub CLI Preflight

If you want the one-command repository creation path, verify GitHub CLI is installed and authenticated. Run \`gh auth login\` when \`gh auth status\` reports no active session:

\`\`\`bash
${input.commands.githubCliPreflight.join("\n")}
\`\`\`

## 3. GitHub Remote

If GitHub CLI is installed and authenticated, this single command can create the public repository, set \`origin\`, and push the branch:

\`\`\`bash
${input.commands.repositoryCreate.join("\n")}
\`\`\`

If the repository already exists or GitHub CLI is unavailable, use the explicit remote setup:

\`\`\`bash
${input.commands.remoteSetup.join("\n")}
\`\`\`

Verify the pushed branch and release readiness:

\`\`\`bash
${input.commands.postPushVerify.join("\n")}
\`\`\`

Verify GitHub Actions before announcing the install command:

\`\`\`bash
${input.commands.actionsVerify.join("\n")}
\`\`\`

${input.commands.publicBranchVerify.length > 0 ? `Before announcing the default one-line install, push and verify the public branch too:

\`\`\`bash
${input.commands.publicBranchVerify.join("\n")}
\`\`\`
` : ""}

## 4. Install Commands For Users

Use the default-branch npm command after the repository default branch points at the released source. Use the branch-pinned npm command to verify this exact pushed branch before changing defaults or merging.

\`\`\`bash
${input.install.npm}
${input.install.npmPinned}
${input.install.shell}
\`\`\`

\`\`\`powershell
${input.install.powershell}
\`\`\`

Verify installer resolution without changing the global npm prefix:

\`\`\`bash
${input.install.shellDryRun}
\`\`\`

\`\`\`powershell
${input.install.powershellDryRun}
\`\`\`

## 5. Release Tag

\`\`\`bash
${input.commands.release.join("\n")}
\`\`\`

## 6. Links

- Repository: ${input.urls.repository}
- Actions: ${input.urls.actions}
- Releases: ${input.urls.releases}
- Latest release: ${input.urls.latestRelease}

## Notes

- Do not publish real target data, secrets, evidence from private programs, or authorization files.
- Run the VM lab and real-tool workflows in GitHub Actions before announcing the project publicly.
- The release workflow verifies and attaches the npm tarball, standalone skill ZIP, SBOM, release manifest, and SHA256SUMS to tagged releases.
`;
}

function writePublishPlan(cwd: string, output: string | undefined, markdown: string): string {
  const outputPath = path.resolve(cwd, output ?? path.join(".bounty", "release", "github-publish-plan.md"));
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, markdown, "utf8");
  return outputPath;
}

function readPackageJson(cwd: string): Record<string, unknown> {
  try {
    return JSON.parse(readFileSync(path.join(cwd, "package.json"), "utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function currentGitBranch(cwd: string): string | undefined {
  try {
    const branch = execFileSync("git", ["branch", "--show-current"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return branch || undefined;
  } catch {
    return undefined;
  }
}

function currentOrigin(cwd: string): string | undefined {
  if (!existsSync(path.join(cwd, ".git"))) return undefined;
  try {
    const origin = execFileSync("git", ["remote", "get-url", "origin"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return origin || undefined;
  } catch {
    return undefined;
  }
}

function workingTreeStatus(cwd: string): ReleasePublishStatusCheck {
  if (!existsSync(path.join(cwd, ".git"))) {
    return { name: "git:working-tree", status: "fail", message: "Not a git checkout." };
  }
  try {
    const status = execFileSync("git", ["status", "--porcelain"], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2_000,
    }).trim();
    return status
      ? { name: "git:working-tree", status: "fail", message: "Working tree has uncommitted changes." }
      : { name: "git:working-tree", status: "pass", message: "working tree clean" };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { name: "git:working-tree", status: "fail", message: `Could not inspect working tree: ${reason}` };
  }
}

function currentBranchStatus(cwd: string, expectedBranch: string): ReleasePublishStatusCheck {
  const branch = currentGitBranch(cwd);
  if (!branch) {
    return { name: "git:branch", status: "warn", message: `Could not determine current branch; expected ${expectedBranch}.` };
  }
  return branch === expectedBranch
    ? { name: "git:branch", status: "pass", message: branch }
    : { name: "git:branch", status: "warn", message: `Current branch is ${branch}; publish plan targets ${expectedBranch}.` };
}

function publicBranchStatus(branch: string, publicBranch: string): ReleasePublishStatusCheck {
  if (branch === publicBranch) {
    return { name: "publish:public-branch", status: "pass", message: `publishing from ${publicBranch}` };
  }
  return {
    name: "publish:public-branch",
    status: "warn",
    message: `Branch ${branch} is suitable for pre-release verification. Announce default install commands only after ${publicBranch} is pushed and verified.`,
  };
}

function localTagStatus(cwd: string, tag: string): ReleasePublishStatusCheck {
  if (!existsSync(path.join(cwd, ".git"))) {
    return { name: "git:local-tag", status: "warn", message: "Not a git checkout; local tag check skipped." };
  }
  try {
    execFileSync("git", ["rev-parse", "-q", "--verify", `refs/tags/${tag}`], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 2_000,
    });
    return { name: "git:local-tag", status: "pass", message: tag };
  } catch {
    return { name: "git:local-tag", status: "warn", message: `Local tag ${tag} has not been created yet.` };
  }
}

function remoteRefStatus(
  cwd: string,
  name: string,
  ref: string,
  passMessage: string,
  timeoutMs = 8_000,
  missingStatus: "warn" | "fail" = "fail",
): ReleasePublishStatusCheck {
  try {
    execFileSync("git", ["ls-remote", "--exit-code", "origin", ref], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "ignore", "pipe"],
      timeout: timeoutMs,
    });
    return { name, status: "pass", message: passMessage };
  } catch (error) {
    const reason = error instanceof Error ? error.message.split(/\r?\n/)[0] : String(error);
    return { name, status: missingStatus, message: `Could not verify ${ref} on origin: ${reason}` };
  }
}

interface GitHubActionsStatusInput {
  repo: string;
  branch: string;
  ghCommand: string;
  ghArgsPrefix: string[];
  timeoutMs?: number;
}

const REQUIRED_ACTION_WORKFLOWS = [
  { name: "CI", branchScoped: true },
  { name: "Release", branchScoped: false },
  { name: "VM Lab Smoke", branchScoped: true },
  { name: "Real Tool VM Smoke", branchScoped: true },
];

function githubActionsStatusChecks(input: GitHubActionsStatusInput): ReleasePublishStatusCheck[] {
  const ghAvailable = ghCliAvailable(input.ghCommand, input.ghArgsPrefix, input.timeoutMs);
  if (!ghAvailable.ok) {
    return [{ name: "github:actions-gh", status: "fail", message: ghAvailable.message }];
  }
  return REQUIRED_ACTION_WORKFLOWS.map((workflow) => {
    const args = [
      "run",
      "list",
      "--repo",
      input.repo,
      "--workflow",
      workflow.name,
      "--limit",
      "1",
      "--json",
      "status,conclusion,workflowName,url,headBranch,event",
    ];
    if (workflow.branchScoped) {
      args.splice(6, 0, "--branch", input.branch);
    }
    const run = ghJson<Array<Record<string, unknown>>>(input.ghCommand, input.ghArgsPrefix, args, input.timeoutMs);
    if (!run.ok) {
      return { name: `github:actions:${workflow.name}`, status: "fail", message: run.message };
    }
    const latest = Array.isArray(run.value) ? run.value[0] : undefined;
    if (!latest) {
      return { name: `github:actions:${workflow.name}`, status: "fail", message: `No GitHub Actions run found for workflow ${workflow.name}.` };
    }
    const status = typeof latest.status === "string" ? latest.status : "";
    const conclusion = typeof latest.conclusion === "string" ? latest.conclusion : "";
    const url = typeof latest.url === "string" ? latest.url : "";
    const passed = status === "completed" && conclusion === "success";
    return {
      name: `github:actions:${workflow.name}`,
      status: passed ? "pass" : "fail",
      message: passed ? `${workflow.name} succeeded${url ? `: ${url}` : ""}` : `${workflow.name} latest run is ${status}/${conclusion || "none"}${url ? `: ${url}` : ""}`,
    };
  });
}

function ghCliAvailable(ghCommand: string, ghArgsPrefix: string[], timeoutMs = 8_000): { ok: boolean; message: string } {
  try {
    execFileSync(ghCommand, [...ghArgsPrefix, "--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    });
    return { ok: true, message: "GitHub CLI is available." };
  } catch (error) {
    const reason = error instanceof Error ? error.message.split(/\r?\n/)[0] : String(error);
    return { ok: false, message: `GitHub CLI is not available or not authenticated: ${reason}` };
  }
}

function ghJson<T>(ghCommand: string, ghArgsPrefix: string[], args: string[], timeoutMs = 8_000): { ok: true; value: T } | { ok: false; message: string } {
  try {
    const output = execFileSync(ghCommand, [...ghArgsPrefix, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    });
    return { ok: true, value: JSON.parse(output) as T };
  } catch (error) {
    const reason = error instanceof Error ? error.message.split(/\r?\n/)[0] : String(error);
    return { ok: false, message: `GitHub CLI check failed: ${reason}` };
  }
}

function publishStatusNextCommands(input: {
  repo: GitHubRepoRef;
  branch: string;
  publicBranch: string;
  tag: string;
  remote: ReleasePublishStatusResult["remote"];
  checks: ReleasePublishStatusCheck[];
  online: boolean;
  actions: boolean;
}): string[] {
  const byName = new Map(input.checks.map((check) => [check.name, check]));
  const commands = new Set<string>();
  const originMissing = byName.get("git:origin")?.status === "fail";
  const githubActionsGhFailed = byName.get("github:actions-gh")?.status === "fail";
  if (byName.get("release:check")?.status === "fail") commands.add("npm run verify:release");
  if (byName.get("git:working-tree")?.status === "fail") {
    commands.add("git status --short");
    commands.add("git add .");
    commands.add("git commit -m \"Prepare BountyPilot release\"");
  }
  if (originMissing) {
    commands.add(`bounty release github-bootstrap ${input.repo.slug} --branch ${input.branch} --tag ${input.tag} --write`);
    commands.add(`bounty release publish-plan ${input.repo.slug} --write`);
    if (githubActionsGhFailed) {
      for (const command of GITHUB_CLI_INSTALL_COMMANDS) commands.add(command);
      commands.add("gh --version");
      commands.add("gh auth status");
    }
    commands.add("gh auth login");
    commands.add(`gh repo create ${input.repo.slug} --public --source . --remote origin --push`);
  }
  if (!originMissing && byName.get("git:origin-target")?.status === "fail") {
    commands.add(input.remote.origin ? input.remote.setUrlCommand : input.remote.addCommand);
  }
  if (byName.get("git:remote-branch")?.status === "fail") commands.add(`git push -u origin ${input.branch}`);
  if (byName.get("publish:public-branch")?.status === "warn") {
    commands.add(`git push -u origin HEAD:${input.publicBranch}`);
    commands.add(`bounty release publish-plan ${input.repo.slug} --branch ${input.publicBranch} --tag ${input.tag} --write`);
    commands.add(`bounty release publish-status ${input.repo.slug} --branch ${input.publicBranch} --tag ${input.tag} --online --actions --json`);
  }
  if (byName.get("git:local-tag")?.status === "warn") commands.add(`git tag ${input.tag}`);
  if (byName.get("git:remote-tag")?.status !== "pass") commands.add(`git push origin ${input.tag}`);
  if (!input.online) commands.add(`bounty release publish-status ${input.repo.slug} --branch ${input.branch} --tag ${input.tag} --online --json`);
  if (githubActionsGhFailed) {
    for (const command of GITHUB_CLI_INSTALL_COMMANDS) commands.add(command);
    commands.add("gh --version");
    commands.add("gh auth status");
    commands.add("gh auth login");
  }
  if (!input.actions || input.checks.some((check) => check.name.startsWith("github:actions") && check.status === "fail")) {
    commands.add(`bounty release publish-status ${input.repo.slug} --branch ${input.branch} --tag ${input.tag} --online --actions --json`);
    commands.add(`gh run list --repo ${input.repo.slug} --limit 10`);
  }
  return [...commands];
}

function sameRemote(left: string, right: string): boolean {
  return normalizeRemote(left) === normalizeRemote(right);
}

function normalizeRemote(value: string): string {
  return value
    .trim()
    .replace(/^https:\/\/github\.com\//i, "")
    .replace(/^git@github\.com:/i, "")
    .replace(/\.git$/i, "")
    .toLowerCase();
}
