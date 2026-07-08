import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  buildReleasePublishPlan,
  buildReleasePublishStatus,
  parseGitHubRepo,
  type GitHubRepoRef,
  type ReleasePublishPlanResult,
  type ReleasePublishStatusCheck,
} from "./release-publish-plan.js";

export interface ReleaseGithubBootstrapCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

export interface ReleaseGithubBootstrapResult {
  ok: boolean;
  repo: GitHubRepoRef;
  branch: string;
  publicBranch: string;
  tag: string;
  gh: {
    command: string;
    argsPrefix: string[];
    version: ReleaseGithubBootstrapCheck;
    auth: ReleaseGithubBootstrapCheck;
    install: {
      windows: string;
      macos: string;
      debian: string;
      docs: string;
    };
  };
  remote: ReleasePublishPlanResult["remote"];
  checks: ReleaseGithubBootstrapCheck[];
  commands: {
    installGh: string[];
    auth: string[];
    createRepository: string[];
    push: string[];
    tag: string[];
    verify: string[];
  };
  scripts: {
    powershell: string;
    shell: string;
  };
  nextCommands: string[];
  markdown: string;
  outputDir?: string;
  outputFiles?: {
    markdown: string;
    powershell: string;
    shell: string;
  };
}

export interface BuildReleaseGithubBootstrapInput {
  cwd?: string;
  repo: string;
  branch?: string;
  tag?: string;
  remote?: "https" | "ssh";
  ghCommand?: string;
  ghArgsPrefix?: string[];
  timeoutMs?: number;
  write?: boolean;
  output?: string;
}

const GH_INSTALL = {
  windows: "winget install --id GitHub.cli -e",
  macos: "brew install gh",
  debian: "sudo apt-get update && sudo apt-get install -y gh",
  docs: "https://cli.github.com/",
};

export function buildReleaseGithubBootstrap(input: BuildReleaseGithubBootstrapInput): ReleaseGithubBootstrapResult {
  const cwd = input.cwd ?? process.cwd();
  const repo = parseGitHubRepo(input.repo);
  const plan = buildReleasePublishPlan({
    cwd,
    repo: repo.slug,
    branch: input.branch,
    tag: input.tag,
    remote: input.remote,
  });
  const status = buildReleasePublishStatus({
    cwd,
    repo: repo.slug,
    branch: plan.branch,
    tag: plan.tag,
    remote: input.remote,
  });
  const ghCommand = input.ghCommand ?? "gh";
  const ghArgsPrefix = input.ghArgsPrefix ?? [];
  const ghVersion = probeGh({
    command: ghCommand,
    argsPrefix: ghArgsPrefix,
    args: ["--version"],
    name: "gh:version",
    passMessage: "GitHub CLI is installed.",
    failMessage: "GitHub CLI is missing. Install it before using one-command repository creation.",
    timeoutMs: input.timeoutMs,
  });
  const ghAuth =
    ghVersion.status === "pass"
      ? probeGh({
          command: ghCommand,
          argsPrefix: ghArgsPrefix,
          args: ["auth", "status"],
          name: "gh:auth",
          passMessage: "GitHub CLI is authenticated.",
          failMessage: "GitHub CLI is installed but not authenticated.",
          timeoutMs: input.timeoutMs,
        })
      : { name: "gh:auth", status: "fail" as const, message: "Skipped because GitHub CLI is not installed." };

  const commands = releaseGithubBootstrapCommands(plan);
  const scripts = {
    powershell: renderPowershellScript(plan),
    shell: renderShellScript(plan),
  };
  const checks = [
    releaseStatusCheck(status.checks, "release:check"),
    ghVersion,
    ghAuth,
    releaseStatusCheck(status.checks, "git:origin"),
    releaseStatusCheck(status.checks, "git:origin-target"),
    releaseStatusCheck(status.checks, "git:working-tree"),
    releaseStatusCheck(status.checks, "git:local-tag"),
  ];
  const nextCommands = nextCommandsForBootstrap({ checks, commands });
  const output = input.write ? writeBootstrapFiles(cwd, input.output, plan.repo.repo, scripts, renderMarkdown({ plan, ghVersion, ghAuth, commands, scripts })) : undefined;
  const markdown = output?.markdownText ?? renderMarkdown({ plan, ghVersion, ghAuth, commands, scripts });

  return {
    ok: checks.every((check) => check.status !== "fail"),
    repo,
    branch: plan.branch,
    publicBranch: plan.publicBranch,
    tag: plan.tag,
    gh: {
      command: ghCommand,
      argsPrefix: ghArgsPrefix,
      version: ghVersion,
      auth: ghAuth,
      install: GH_INSTALL,
    },
    remote: plan.remote,
    checks,
    commands,
    scripts,
    nextCommands,
    markdown,
    outputDir: output?.outputDir,
    outputFiles: output?.outputFiles,
  };
}

function releaseGithubBootstrapCommands(plan: ReleasePublishPlanResult): ReleaseGithubBootstrapResult["commands"] {
  return {
    installGh: [GH_INSTALL.windows, GH_INSTALL.macos, GH_INSTALL.debian],
    auth: ["gh auth status", "gh auth login"],
    createRepository: plan.commands.repositoryCreate,
    push: plan.commands.remoteSetup,
    tag: plan.commands.release,
    verify: [
      ...plan.commands.postPushVerify,
      ...plan.commands.actionsVerify,
      ...plan.commands.publicBranchVerify,
      ...plan.commands.installVerify,
    ],
  };
}

function probeGh(input: {
  command: string;
  argsPrefix: string[];
  args: string[];
  name: string;
  passMessage: string;
  failMessage: string;
  timeoutMs?: number;
}): ReleaseGithubBootstrapCheck {
  const result = spawnSync(input.command, [...input.argsPrefix, ...input.args], {
    encoding: "utf8",
    timeout: input.timeoutMs ?? 8_000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status === 0) {
    const firstLine = (result.stdout || result.stderr || "").split(/\r?\n/).find((line) => line.trim());
    return { name: input.name, status: "pass", message: firstLine?.trim() || input.passMessage };
  }
  const reason = result.error instanceof Error ? result.error.message : (result.stderr || result.stdout || "").split(/\r?\n/)[0];
  return { name: input.name, status: "fail", message: `${input.failMessage}${reason ? ` (${reason})` : ""}` };
}

function releaseStatusCheck(checks: ReleasePublishStatusCheck[], name: string): ReleaseGithubBootstrapCheck {
  const check = checks.find((candidate) => candidate.name === name);
  if (!check) return { name, status: "warn", message: "check was not available" };
  return check;
}

function nextCommandsForBootstrap(input: {
  checks: ReleaseGithubBootstrapCheck[];
  commands: ReleaseGithubBootstrapResult["commands"];
}): string[] {
  const byName = new Map(input.checks.map((check) => [check.name, check]));
  const commands = new Set<string>();
  const originMissing = byName.get("git:origin")?.status === "fail";
  if (byName.get("gh:version")?.status === "fail") {
    input.commands.installGh.forEach((command) => commands.add(command));
    commands.add("gh --version");
  }
  if (byName.get("gh:auth")?.status === "fail") {
    input.commands.auth.forEach((command) => commands.add(command));
  }
  if (byName.get("release:check")?.status === "fail") {
    commands.add("npm run verify:release");
  }
  if (byName.get("git:working-tree")?.status === "fail") {
    commands.add("git status --short");
    commands.add("git add .");
    commands.add("git commit -m \"Prepare BountyPilot release\"");
  }
  if (originMissing) {
    input.commands.createRepository.forEach((command) => commands.add(command));
  }
  if (!originMissing && byName.get("git:origin-target")?.status === "fail") {
    input.commands.push.forEach((command) => commands.add(command));
  }
  if (byName.get("git:local-tag")?.status === "warn") {
    input.commands.tag.forEach((command) => commands.add(command));
  }
  input.commands.verify.forEach((command) => commands.add(command));
  return [...commands];
}

function writeBootstrapFiles(
  cwd: string,
  output: string | undefined,
  repoName: string,
  scripts: ReleaseGithubBootstrapResult["scripts"],
  markdown: string,
): { outputDir: string; outputFiles: ReleaseGithubBootstrapResult["outputFiles"]; markdownText: string } {
  const outputDir = path.resolve(cwd, output ?? path.join(".bounty", "release", "github-bootstrap"));
  mkdirSync(outputDir, { recursive: true });
  const outputFiles = {
    markdown: path.join(outputDir, "README.md"),
    powershell: path.join(outputDir, `publish-${repoName}.ps1`),
    shell: path.join(outputDir, `publish-${repoName}.sh`),
  };
  writeFileSync(outputFiles.markdown, markdown, "utf8");
  writeFileSync(outputFiles.powershell, scripts.powershell, "utf8");
  writeFileSync(outputFiles.shell, scripts.shell, "utf8");
  return { outputDir, outputFiles, markdownText: markdown };
}

function renderMarkdown(input: {
  plan: ReleasePublishPlanResult;
  ghVersion: ReleaseGithubBootstrapCheck;
  ghAuth: ReleaseGithubBootstrapCheck;
  commands: ReleaseGithubBootstrapResult["commands"];
  scripts: ReleaseGithubBootstrapResult["scripts"];
}): string {
  return `# BountyPilot GitHub Bootstrap

Repository: ${input.plan.repo.slug}
Branch: ${input.plan.branch}
Tag: ${input.plan.tag}
Origin: ${input.plan.remote.origin ?? "not configured"}

## Status

- ${input.ghVersion.name}: ${input.ghVersion.status} - ${input.ghVersion.message}
- ${input.ghAuth.name}: ${input.ghAuth.status} - ${input.ghAuth.message}

## GitHub CLI

\`\`\`bash
${input.commands.installGh.join("\n")}
gh --version
${input.commands.auth.join("\n")}
\`\`\`

## Local Verification

The generated publish scripts run these checks before creating a repository, pushing a branch, or tagging a release:

\`\`\`bash
${input.plan.commands.localVerify.join("\n")}
\`\`\`

## Publish

\`\`\`bash
${input.commands.createRepository.join("\n")}
${input.commands.push.join("\n")}
${input.commands.tag.join("\n")}
${input.commands.verify.join("\n")}
\`\`\`

## PowerShell Script

\`\`\`powershell
${input.scripts.powershell}
\`\`\`

## Shell Script

\`\`\`bash
${input.scripts.shell}
\`\`\`
`;
}

function renderPowershellScript(plan: ReleasePublishPlanResult): string {
  const repo = quotePowerShell(plan.repo.slug);
  const branch = quotePowerShell(plan.branch);
  const tag = quotePowerShell(plan.tag);
  return `$ErrorActionPreference = "Stop"

npm run verify:release
node dist/cli/index.js release bundle --output .release --force --json
node dist/cli/index.js release verify-bundle .release --json
node dist/cli/index.js skill score bug-bounty-pilot --repo ${repo} --branch ${branch} --tag ${tag} --json

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  Write-Error "GitHub CLI is not installed. Install it with: ${GH_INSTALL.windows}"
}

gh auth status
if ($LASTEXITCODE -ne 0) {
  gh auth login
}

$origin = git remote get-url origin 2>$null
if (-not $origin) {
  gh repo create ${repo} --public --source . --remote origin --push
} else {
  git remote set-url origin ${quotePowerShell(plan.remote.preferred === "ssh" ? plan.repo.sshRemote : plan.repo.httpsRemote)}
  git push -u origin ${branch}
}

git rev-parse -q --verify "refs/tags/${plan.tag}" *> $null
if ($LASTEXITCODE -ne 0) {
  git tag ${tag}
}
git push origin ${tag}

bounty release publish-status ${repo} --branch ${branch} --tag ${tag} --online --actions --json
bugbounty release install-check --json
`;
}

function renderShellScript(plan: ReleasePublishPlanResult): string {
  const repo = quoteShell(plan.repo.slug);
  const branch = quoteShell(plan.branch);
  const tag = quoteShell(plan.tag);
  const targetRemote = quoteShell(plan.remote.preferred === "ssh" ? plan.repo.sshRemote : plan.repo.httpsRemote);
  return `#!/usr/bin/env bash
set -euo pipefail

npm run verify:release
node dist/cli/index.js release bundle --output .release --force --json
node dist/cli/index.js release verify-bundle .release --json
node dist/cli/index.js skill score bug-bounty-pilot --repo ${repo} --branch ${branch} --tag ${tag} --json

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI is not installed. Install it first: ${GH_INSTALL.docs}" >&2
  exit 1
fi

gh auth status || gh auth login

if ! git remote get-url origin >/dev/null 2>&1; then
  gh repo create ${repo} --public --source . --remote origin --push
else
  git remote set-url origin ${targetRemote}
  git push -u origin ${branch}
fi

if ! git rev-parse -q --verify "refs/tags/${plan.tag}" >/dev/null; then
  git tag ${tag}
fi
git push origin ${tag}

bounty release publish-status ${repo} --branch ${branch} --tag ${tag} --online --actions --json
bugbounty release install-check --json
`;
}

function quoteShell(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function quotePowerShell(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}
