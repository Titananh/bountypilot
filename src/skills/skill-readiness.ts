import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runPackageReleaseCheck } from "../core/release/release-check.js";
import { buildReleaseGithubBootstrap, type ReleaseGithubBootstrapCheck } from "../core/release/release-github-bootstrap.js";
import {
  BUG_BOUNTY_PILOT_SKILL_ID,
  bundleSkillDefinition,
  validateSkillDefinition,
  verifySkillBundle,
  type SkillBundleVerificationCheck,
  type SkillValidationCheck,
} from "./skill-definition.js";

export type SkillReadinessLevel = "ultimate" | "ready_with_warnings" | "blocked";

export interface SkillReadinessIssue {
  name: string;
  message: string;
}

export interface SkillReadinessResult {
  ok: boolean;
  ultimate: boolean;
  id: string;
  root: string;
  score: number;
  readiness: SkillReadinessLevel;
  blockers: SkillReadinessIssue[];
  warnings: SkillReadinessIssue[];
  nextSteps: string[];
  validation: {
    checks: number;
    failures: SkillReadinessIssue[];
    warnings: SkillReadinessIssue[];
  };
  bundle: {
    ok: boolean;
    files: number;
    bytes: number;
    sha256: string;
    checks: number;
    failures: SkillReadinessIssue[];
  };
  release: {
    ok: boolean;
    checks: number;
    failures: SkillReadinessIssue[];
    warnings: SkillReadinessIssue[];
  };
  github?: {
    ok: boolean;
    repo: string;
    branch: string;
    publicBranch: string;
    tag: string;
    origin?: string;
    checks: ReleaseGithubBootstrapCheck[];
    nextCommands: string[];
  };
}

const GITHUB_CLI_INSTALL_COMMANDS = [
  "winget install --id GitHub.cli -e",
  "brew install gh",
  "sudo apt-get update && sudo apt-get install -y gh",
];

export function scoreSkillReadiness(
  input: {
    id?: string;
    cwd?: string;
    generatedAt?: string;
    repo?: string;
    branch?: string;
    tag?: string;
    remote?: "https" | "ssh";
    ghCommand?: string;
    ghArgsPrefix?: string[];
    timeoutMs?: number;
  } = {},
): SkillReadinessResult {
  const cwd = input.cwd ?? process.cwd();
  const id = input.id ?? BUG_BOUNTY_PILOT_SKILL_ID;
  const validation = validateSkillDefinition(id, cwd);
  const validationFailures = issuesFor(validation.checks, "fail");
  const validationWarnings = issuesFor(validation.checks, "warn");
  const bundle = scoreSkillBundle({ id, cwd, generatedAt: input.generatedAt });
  const release = runPackageReleaseCheck(cwd);
  const github = input.repo
    ? buildReleaseGithubBootstrap({
        cwd,
        repo: input.repo,
        branch: input.branch,
        tag: input.tag,
        remote: input.remote,
        ghCommand: input.ghCommand,
        ghArgsPrefix: input.ghArgsPrefix,
        timeoutMs: input.timeoutMs,
      })
    : undefined;
  const releaseFailures = contextualizeReleaseIssues(issuesFor(release.checks, "fail"), github);
  const releaseWarnings = contextualizeReleaseIssues(issuesFor(release.checks, "warn"), github);
  const githubWarnings = github ? githubPreflightIssues(github) : [];
  const blockers = [...validationFailures, ...bundle.failures, ...releaseFailures];
  const warnings = dedupeIssues([...validationWarnings, ...releaseWarnings, ...githubWarnings]);
  const score = readinessScore({
    validationFailures: validationFailures.length,
    bundleFailures: bundle.failures.length,
    releaseFailures: releaseFailures.length,
    warnings: warnings.length,
  });
  const readiness: SkillReadinessLevel = blockers.length > 0 ? "blocked" : warnings.length > 0 ? "ready_with_warnings" : "ultimate";
  return {
    ok: blockers.length === 0,
    ultimate: blockers.length === 0 && warnings.length === 0 && score === 100,
    id,
    root: validation.root,
    score,
    readiness,
    blockers,
    warnings,
    nextSteps: readinessNextSteps({
      id,
      blockers,
      warnings,
      releaseTag: release.version ? `v${release.version}` : "v0.1.0",
      repoSlug: github?.repo.slug,
      githubNextCommands: github?.nextCommands,
    }),
    validation: {
      checks: validation.checks.length,
      failures: validationFailures,
      warnings: validationWarnings,
    },
    bundle,
    release: {
      ok: release.ok,
      checks: release.checks.length,
      failures: releaseFailures,
      warnings: releaseWarnings,
    },
    github: github
      ? {
          ok: github.ok,
          repo: github.repo.slug,
          branch: github.branch,
          publicBranch: github.publicBranch,
          tag: github.tag,
          origin: github.remote.origin,
          checks: github.checks,
          nextCommands: github.nextCommands,
        }
      : undefined,
  };
}

function contextualizeReleaseIssues(
  issues: SkillReadinessIssue[],
  github: ReturnType<typeof buildReleaseGithubBootstrap> | undefined,
): SkillReadinessIssue[] {
  if (!github) return issues;
  return issues.map((issue) => {
    if (issue.name !== "github:origin") return issue;
    return {
      ...issue,
      message: github.remote.origin
        ? `Origin is ${github.remote.origin}. Fix it with: ${github.remote.setUrlCommand}`
        : `No origin remote configured. Add one with: ${github.remote.addCommand}`,
    };
  });
}

function githubPreflightIssues(github: ReturnType<typeof buildReleaseGithubBootstrap>): SkillReadinessIssue[] {
  return github.checks
    .filter((check) => check.name !== "release:check")
    .filter((check) => check.status !== "pass")
    .map((check) => ({
      name: check.name,
      message: check.message,
    }));
}

function dedupeIssues(issues: SkillReadinessIssue[]): SkillReadinessIssue[] {
  const seen = new Set<string>();
  const deduped: SkillReadinessIssue[] = [];
  for (const issue of issues) {
    const key = `${issue.name}\n${issue.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(issue);
  }
  return deduped;
}

function scoreSkillBundle(input: { id: string; cwd: string; generatedAt?: string }): SkillReadinessResult["bundle"] {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-score-"));
  const output = path.join(tempRoot, `${input.id}.skill.zip`);
  try {
    const bundled = bundleSkillDefinition({
      id: input.id,
      cwd: input.cwd,
      output,
      generatedAt: input.generatedAt ?? new Date().toISOString(),
    });
    const verified = verifySkillBundle({ bundle: output, cwd: input.cwd });
    return {
      ok: verified.ok,
      files: bundled.files,
      bytes: bundled.bytes,
      sha256: bundled.sha256,
      checks: verified.checks.length,
      failures: issuesFor(verified.checks, "fail"),
    };
  } catch (error) {
    return {
      ok: false,
      files: 0,
      bytes: 0,
      sha256: "",
      checks: 1,
      failures: [
        {
          name: "skill:bundle",
          message: error instanceof Error ? error.message : String(error),
        },
      ],
    };
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

function readinessScore(input: {
  validationFailures: number;
  bundleFailures: number;
  releaseFailures: number;
  warnings: number;
}): number {
  const penalty =
    input.validationFailures * 12 +
    input.bundleFailures * 10 +
    input.releaseFailures * 8 +
    Math.min(input.warnings * 3, 15);
  return Math.max(0, Math.min(100, 100 - penalty));
}

function readinessNextSteps(input: {
  id: string;
  blockers: SkillReadinessIssue[];
  warnings: SkillReadinessIssue[];
  releaseTag: string;
  repoSlug?: string;
  githubNextCommands?: string[];
}): string[] {
  if (input.blockers.length === 0 && input.warnings.length === 0) {
    return [`bounty skill bundle ${input.id} --output ${input.id}.skill.zip`, "npm run verify:release"];
  }
  const steps = new Set<string>();
  if (input.blockers.some((issue) => issue.name.startsWith("skill") || issue.name.includes("policy") || issue.name.includes("workflow"))) {
    steps.add(`bounty skill validate ${input.id}`);
  }
  if (input.blockers.some((issue) => issue.name.includes("bundle") || issue.name.includes("manifest") || issue.name.startsWith("files:"))) {
    steps.add(`bounty skill bundle ${input.id} --output ${input.id}.skill.zip`);
    steps.add(`bounty skill verify-bundle ${input.id}.skill.zip`);
  }
  if (input.blockers.some((issue) => issue.name.startsWith("script:") || issue.name.includes("workflow") || issue.name.includes("package"))) {
    steps.add("npm run verify:release");
  }
  if (input.warnings.some((issue) => issue.name === "github:origin")) {
    const repo = input.repoSlug ?? "OWNER/REPO";
    steps.add(`bounty release github-bootstrap ${repo} --write`);
    steps.add(`bounty release publish-plan ${repo} --write`);
    if (!input.githubNextCommands) {
      GITHUB_CLI_INSTALL_COMMANDS.forEach((command) => steps.add(command));
      steps.add("gh --version");
      steps.add("gh auth status");
      steps.add("gh auth login");
      steps.add(`gh repo create ${repo} --public --source . --remote origin --push`);
      steps.add("git push -u origin HEAD:main");
      steps.add(`git tag ${input.releaseTag}`);
      steps.add(`bounty skill score ${input.id} --repo ${repo} --branch main --tag ${input.releaseTag} --strict --json`);
      steps.add(`git push origin ${input.releaseTag}`);
      steps.add(`bounty release publish-plan ${repo} --branch main --tag ${input.releaseTag} --write`);
      steps.add(`bounty release publish-status ${repo} --branch main --tag ${input.releaseTag} --online --actions --json`);
      steps.add(`bounty release publish-status ${repo} --online --actions --json`);
      steps.add("bugbounty release install-check --json");
    }
  }
  input.githubNextCommands?.forEach((command) => steps.add(command));
  if (steps.size > 0) {
    const repoArg = input.repoSlug ? ` --repo ${input.repoSlug}` : "";
    steps.add(`bounty skill score ${input.id}${repoArg} --json`);
  }
  if (steps.size === 0) {
    const repoArg = input.repoSlug ? ` --repo ${input.repoSlug}` : "";
    steps.add(`Review warnings, then rerun \`bounty skill score ${input.id}${repoArg} --json\`.`);
  }
  return [...steps];
}

function issuesFor<TStatus extends string>(
  checks: Array<SkillValidationCheck | SkillBundleVerificationCheck | { name: string; status: TStatus; message: string }>,
  status: TStatus,
): SkillReadinessIssue[] {
  return checks
    .filter((check) => check.status === status)
    .map((check) => ({
      name: check.name,
      message: check.message,
    }));
}
