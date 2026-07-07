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
    shell: string;
    powershell: string;
  };
  commands: {
    localVerify: string[];
    remoteSetup: string[];
    release: string[];
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

export function buildReleasePublishPlan(input: BuildReleasePublishPlanInput): ReleasePublishPlanResult {
  const cwd = input.cwd ?? process.cwd();
  const repo = parseGitHubRepo(input.repo);
  const packageJson = readPackageJson(cwd);
  const version = typeof packageJson.version === "string" && packageJson.version.trim() ? packageJson.version.trim() : "0.1.0";
  const branch = input.branch?.trim() || currentGitBranch(cwd) || "main";
  const tag = input.tag?.trim() || `v${version}`;
  const remotePreference = input.remote ?? "https";
  const targetRemote = remotePreference === "ssh" ? repo.sshRemote : repo.httpsRemote;
  const origin = currentOrigin(cwd);
  const releaseCheck = runReleaseCheck(cwd);
  const install = {
    npm: `npm install -g github:${repo.slug}`,
    shell: `curl -fsSL https://raw.githubusercontent.com/${repo.slug}/${branch}/scripts/install.sh | BOUNTYPILOT_SOURCE=github:${repo.slug} bash`,
    powershell: `$env:BOUNTYPILOT_SOURCE="github:${repo.slug}"; irm https://raw.githubusercontent.com/${repo.slug}/${branch}/scripts/install.ps1 | iex`,
  };
  const commands = {
    localVerify: [
      "npm ci",
      "npm run verify:release",
      "bounty skill score bug-bounty-pilot --json",
      "bounty release bundle --output .release --force --json",
    ],
    remoteSetup: [
      origin ? `git remote set-url origin ${targetRemote}` : `git remote add origin ${targetRemote}`,
      `git push -u origin ${branch}`,
    ],
    release: [`git tag ${tag}`, `git push origin ${tag}`],
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

function parseGitHubRepo(value: string): GitHubRepoRef {
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
Release tag: ${input.tag}
Preferred remote: ${input.remote.preferred}
Current origin: ${input.remote.origin ?? "not configured"}
Release check: ${input.releaseCheck.ok ? "pass" : "blocked"} (${input.releaseCheck.checks.length} checks, ${failures.length} failures, ${warnings.length} warnings)

## 1. Local Verification

\`\`\`bash
${input.commands.localVerify.join("\n")}
\`\`\`

## 2. GitHub Remote

\`\`\`bash
${input.commands.remoteSetup.join("\n")}
\`\`\`

## 3. Install Commands For Users

\`\`\`bash
${input.install.npm}
${input.install.shell}
\`\`\`

\`\`\`powershell
${input.install.powershell}
\`\`\`

## 4. Release Tag

\`\`\`bash
${input.commands.release.join("\n")}
\`\`\`

## 5. Links

- Repository: ${input.urls.repository}
- Actions: ${input.urls.actions}
- Releases: ${input.urls.releases}
- Latest release: ${input.urls.latestRelease}

## Notes

- Do not publish real target data, secrets, evidence from private programs, or authorization files.
- Run the VM lab and real-tool workflows in GitHub Actions before announcing the project publicly.
- The release workflow attaches the npm tarball, standalone skill ZIP, SBOM, and SHA256SUMS to tagged releases.
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
