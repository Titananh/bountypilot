import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runPackageReleaseCheck } from "../core/release/release-check.js";
import { buildReleaseGithubBootstrap, type ReleaseGithubBootstrapCheck } from "../core/release/release-github-bootstrap.js";
import { buildReleasePublishStatus, type ReleasePublishStatusCheck } from "../core/release/release-publish-plan.js";
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

export type SkillReadinessRequirementStatus = "pass" | "warn" | "fail";

export interface SkillReadinessRequirement extends SkillReadinessIssue {
  status: SkillReadinessRequirementStatus;
  commands: string[];
}

export type SkillReadinessFixPlanStepStatus = "pass" | "pending";

export interface SkillReadinessFixPlanStep {
  id: string;
  title: string;
  status: SkillReadinessFixPlanStepStatus;
  requirements: string[];
  commands: string[];
}

export interface SkillReadinessLayer {
  ok: boolean;
  ultimate: boolean;
  score: number;
  readiness: SkillReadinessLevel;
  blockers: SkillReadinessIssue[];
  warnings: SkillReadinessIssue[];
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
  layers: {
    local: SkillReadinessLayer;
    publish: SkillReadinessLayer;
  };
  publicReadiness: {
    ok: boolean;
    ultimate: boolean;
    score: number;
    readiness: SkillReadinessLevel;
    requirements: SkillReadinessRequirement[];
    missing: SkillReadinessRequirement[];
    fixPlan: SkillReadinessFixPlanStep[];
    nextCommands: string[];
  };
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
  publish?: {
    ok: boolean;
    repo: string;
    branch: string;
    publicBranch: string;
    tag: string;
    online: boolean;
    actions: boolean;
    checks: ReleasePublishStatusCheck[];
    nextCommands: string[];
  };
}

const GITHUB_CLI_INSTALL_COMMANDS = [
  "winget install --id GitHub.cli -e",
  "brew install gh",
  "sudo apt-get update && sudo apt-get install -y gh",
];

export function renderSkillReadinessPublicPlan(result: SkillReadinessResult): string {
  const missing = result.publicReadiness.missing;
  const lines = [
    "# BountyPilot Public Readiness Plan",
    "",
    `Skill: ${result.id}`,
    `Root: ${result.root}`,
    `Overall: ${result.score}/100 ${result.readiness}`,
    "",
    "## Layer Scores",
    "",
    markdownTable(
      ["Layer", "Score", "Readiness", "Ultimate", "Blockers", "Warnings"],
      [
        [
          "local",
          `${result.layers.local.score}/100`,
          result.layers.local.readiness,
          String(result.layers.local.ultimate),
          String(result.layers.local.blockers.length),
          String(result.layers.local.warnings.length),
        ],
        [
          "publish",
          `${result.layers.publish.score}/100`,
          result.layers.publish.readiness,
          String(result.layers.publish.ultimate),
          String(result.layers.publish.blockers.length),
          String(result.layers.publish.warnings.length),
        ],
      ],
    ),
    "",
    "## Public Readiness",
    "",
    markdownTable(
      ["Score", "Readiness", "Ultimate", "Missing"],
      [[`${result.publicReadiness.score}/100`, result.publicReadiness.readiness, String(result.publicReadiness.ultimate), String(missing.length)]],
    ),
    "",
    "## Missing Requirements",
    "",
    missing.length > 0
      ? markdownTable(
          ["Status", "Requirement", "Message"],
          missing.map((requirement) => [requirement.status, requirement.name, requirement.message]),
        )
      : "No missing public readiness requirements.",
    "",
    "## Ordered Fix Plan",
    "",
  ];

  for (const step of result.publicReadiness.fixPlan) {
    lines.push(`### ${step.title}`, "");
    lines.push(`- Status: ${step.status}`);
    lines.push(`- Requirements: ${step.requirements.length > 0 ? step.requirements.join(", ") : "none"}`);
    if (step.commands.length > 0) {
      lines.push("", commandBlock(step.commands));
    } else {
      lines.push("- Commands: none");
    }
    lines.push("");
  }

  lines.push("## Next Commands", "");
  if (result.publicReadiness.nextCommands.length > 0) {
    lines.push(commandBlock(result.publicReadiness.nextCommands), "");
  } else {
    lines.push("No final commands are required.", "");
  }

  lines.push(
    "## Safety Notes",
    "",
    "- This plan is local documentation only; BountyPilot does not push, publish, or submit anything automatically.",
    "- Do not include real target data, secrets, API keys, tokens, cookies, or private evidence in public GitHub artifacts.",
    "- Keep public testing claims tied to `bounty skill score ... --online --actions --strict --json` output from the target repository.",
    "",
  );

  return lines.join("\n");
}

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
    online?: boolean;
    actions?: boolean;
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
  const publish =
    input.repo && (input.online || input.actions)
      ? buildReleasePublishStatus({
          cwd,
          repo: input.repo,
          branch: input.branch,
          tag: input.tag,
          remote: input.remote,
          online: input.online,
          actions: input.actions,
          ghCommand: input.ghCommand,
          ghArgsPrefix: input.ghArgsPrefix,
          timeoutMs: input.timeoutMs,
        })
      : undefined;
  const releaseFailures = contextualizeReleaseIssues(issuesFor(release.checks, "fail"), github);
  const releaseWarnings = contextualizeReleaseIssues(issuesFor(release.checks, "warn"), github);
  const githubWarnings = github ? githubPreflightIssues(github) : [];
  const publishWarningsRaw = publish ? publishStatusIssues(publish) : [];
  const blockers = [...validationFailures, ...bundle.failures, ...releaseFailures];
  const warnings = dedupeIssues([...validationWarnings, ...releaseWarnings, ...githubWarnings, ...publishWarningsRaw]);
  const localBlockers = dedupeIssues([
    ...validationFailures,
    ...bundle.failures,
    ...releaseFailures.filter((issue) => !isPublishReadinessIssue(issue)),
  ]);
  const localWarnings = dedupeIssues([...validationWarnings, ...releaseWarnings.filter((issue) => !isPublishReadinessIssue(issue))]);
  const publishBlockers = dedupeIssues(releaseFailures.filter(isPublishReadinessIssue));
  const publishWarnings = dedupeIssues([...releaseWarnings.filter(isPublishReadinessIssue), ...githubWarnings, ...publishWarningsRaw]);
  const localLayer = readinessLayer({
    blockers: localBlockers,
    warnings: localWarnings,
    validationFailures: validationFailures.length,
    bundleFailures: bundle.failures.length,
    releaseFailures: releaseFailures.filter((issue) => !isPublishReadinessIssue(issue)).length,
  });
  const publishLayer = readinessLayer({
    blockers: publishBlockers,
    warnings: publishWarnings,
    validationFailures: 0,
    bundleFailures: 0,
    releaseFailures: publishBlockers.length,
  });
  const publicRequirements = buildPublicReadinessRequirements({
    id,
    repo: github?.repo.slug,
    github,
    publish,
    releaseWarnings,
    releaseTag: release.version ? `v${release.version}` : "v0.1.0",
  });
  const nextSteps = readinessNextSteps({
    id,
    blockers,
    warnings,
    releaseTag: release.version ? `v${release.version}` : "v0.1.0",
    releaseBranch: publish?.branch ?? github?.branch ?? "main",
    repoSlug: github?.repo.slug,
    githubNextCommands: github?.nextCommands,
    publishNextCommands: publish?.nextCommands,
  });
  const publicFixPlan = buildPublicReadinessFixPlan(publicRequirements, nextSteps);
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
    nextSteps,
    layers: {
      local: localLayer,
      publish: publishLayer,
    },
    publicReadiness: {
      ok: publishLayer.ultimate,
      ultimate: publishLayer.ultimate,
      score: publishLayer.score,
      readiness: publishLayer.readiness,
      requirements: publicRequirements,
      missing: publicRequirements.filter((requirement) => requirement.status !== "pass"),
      fixPlan: publicFixPlan,
      nextCommands: nextSteps,
    },
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
    publish: publish
      ? {
          ok: publish.ok,
          repo: publish.repo.slug,
          branch: publish.branch,
          publicBranch: publish.publicBranch,
          tag: publish.tag,
          online: publish.online,
          actions: Boolean(input.actions),
          checks: publish.checks,
          nextCommands: publish.nextCommands,
        }
      : undefined,
  };
}

function buildPublicReadinessRequirements(input: {
  id: string;
  repo?: string;
  github?: ReturnType<typeof buildReleaseGithubBootstrap>;
  publish?: ReturnType<typeof buildReleasePublishStatus>;
  releaseWarnings: SkillReadinessIssue[];
  releaseTag: string;
}): SkillReadinessRequirement[] {
  const context = publicReadinessCommandContext(input);
  const requirements: SkillReadinessRequirement[] = [
    input.repo
      ? requirementWithCommands({ name: "publish:repo", status: "pass", message: input.repo }, context)
      : requirementWithCommands(
          { name: "publish:repo", status: "warn", message: "Pass --repo OWNER/REPO to verify concrete GitHub public-readiness." },
          context,
        ),
  ];

  const releaseOriginWarning = input.releaseWarnings.find((issue) => issue.name === "github:origin");
  if (releaseOriginWarning) {
    requirements.push(requirementWithCommands({ status: "warn", ...releaseOriginWarning }, context));
  }

  if (input.github) {
    for (const check of input.github.checks) {
      if (check.name === "release:check") continue;
      requirements.push(requirementWithCommands({ name: check.name, status: check.status, message: check.message }, context));
    }
  }

  if (input.publish) {
    for (const check of input.publish.checks) {
      if (check.name === "release:check") continue;
      requirements.push(requirementWithCommands({ name: check.name, status: check.status, message: check.message }, context));
    }
  } else if (input.repo) {
    requirements.push(
      requirementWithCommands(
        {
          name: "publish:online",
          status: "warn",
          message: "Re-run with --online after pushing the public branch and tag.",
        },
        context,
      ),
    );
    requirements.push(
      requirementWithCommands(
        {
          name: "github:actions",
          status: "warn",
          message: "Re-run with --actions after GitHub Actions have completed.",
        },
        context,
      ),
    );
  }

  return mergeRequirements(requirements);
}

function buildPublicReadinessFixPlan(
  requirements: SkillReadinessRequirement[],
  finalCommands: string[],
): SkillReadinessFixPlanStep[] {
  const phaseSpecs: Array<{
    id: string;
    title: string;
    matches: (requirement: SkillReadinessRequirement) => boolean;
  }> = [
    {
      id: "repo",
      title: "Choose target GitHub repository",
      matches: (requirement) => requirement.name === "publish:repo",
    },
    {
      id: "github-cli",
      title: "Install and authenticate GitHub CLI",
      matches: (requirement) => requirement.name === "gh:version" || requirement.name === "gh:auth" || requirement.name === "github:actions-gh",
    },
    {
      id: "working-tree",
      title: "Commit local release changes",
      matches: (requirement) => requirement.name === "git:working-tree",
    },
    {
      id: "origin",
      title: "Configure GitHub origin",
      matches: (requirement) => requirement.name === "github:origin" || requirement.name === "git:origin" || requirement.name === "git:origin-target",
    },
    {
      id: "branch",
      title: "Push release branch",
      matches: (requirement) => requirement.name === "git:remote-branch",
    },
    {
      id: "public-branch",
      title: "Publish public install branch",
      matches: (requirement) => requirement.name === "publish:public-branch",
    },
    {
      id: "tag",
      title: "Create and push release tag",
      matches: (requirement) => requirement.name === "git:local-tag" || requirement.name === "git:remote-tag",
    },
    {
      id: "online",
      title: "Verify online refs",
      matches: (requirement) => requirement.name === "publish:online",
    },
    {
      id: "actions",
      title: "Verify required GitHub Actions",
      matches: (requirement) => requirement.name === "github:actions" || requirement.name.startsWith("github:actions:"),
    },
  ];

  const steps = phaseSpecs
    .map((phase): SkillReadinessFixPlanStep => {
      const matched = requirements.filter(phase.matches);
      const missing = matched.filter((requirement) => requirement.status !== "pass");
      return {
        id: phase.id,
        title: phase.title,
        status: missing.length > 0 ? "pending" : "pass",
        requirements: matched.map((requirement) => requirement.name),
        commands: missing.length > 0 ? uniqueCommands(missing.flatMap((requirement) => requirement.commands)) : [],
      };
    })
    .filter((step) => step.requirements.length > 0);

  const missingRequirements = requirements.filter((requirement) => requirement.status !== "pass");
  steps.push({
    id: "final-verify",
    title: "Verify public 100/100 readiness",
    status: missingRequirements.length > 0 ? "pending" : "pass",
    requirements: missingRequirements.map((requirement) => requirement.name),
    commands:
      missingRequirements.length > 0
        ? uniqueCommands(finalCommands.filter((command) => isFinalPublicVerificationCommand(command)))
        : [],
  });

  return steps;
}

function isFinalPublicVerificationCommand(command: string): boolean {
  return (
    /^bounty release publish-status .+ --online --actions --json$/.test(command) ||
    /^bounty release public-gate .+ --online --actions --install-check --write-public-plan \.bounty\/release\/public-readiness\.md --json$/.test(command) ||
    /^bounty skill score .+ --repo .+ --online --actions --strict --json$/.test(command) ||
    command === "bugbounty release install-check --json"
  );
}

interface PublicReadinessCommandContext {
  id: string;
  repo: string;
  branch: string;
  publicBranch: string;
  tag: string;
  addOriginCommand: string;
  setOriginCommand: string;
}

function publicReadinessCommandContext(input: {
  id: string;
  repo?: string;
  github?: ReturnType<typeof buildReleaseGithubBootstrap>;
  publish?: ReturnType<typeof buildReleasePublishStatus>;
  releaseTag: string;
}): PublicReadinessCommandContext {
  const repo = input.repo ?? "OWNER/REPO";
  const branch = input.publish?.branch ?? input.github?.branch ?? "main";
  const publicBranch = input.publish?.publicBranch ?? input.github?.publicBranch ?? "main";
  const tag = input.publish?.tag ?? input.github?.tag ?? input.releaseTag;
  const addOriginCommand = input.publish?.remote.addCommand ?? input.github?.remote.addCommand ?? `git remote add origin https://github.com/${repo}.git`;
  const setOriginCommand = input.publish?.remote.setUrlCommand ?? input.github?.remote.setUrlCommand ?? `git remote set-url origin https://github.com/${repo}.git`;
  return {
    id: input.id,
    repo,
    branch,
    publicBranch,
    tag,
    addOriginCommand,
    setOriginCommand,
  };
}

function requirementWithCommands(
  requirement: Omit<SkillReadinessRequirement, "commands">,
  context: PublicReadinessCommandContext,
): SkillReadinessRequirement {
  return {
    ...requirement,
    commands: remediationCommandsForRequirement(requirement.name, context),
  };
}

function remediationCommandsForRequirement(name: string, context: PublicReadinessCommandContext): string[] {
  if (name === "publish:repo") {
    return [`bounty skill score ${context.id} --repo ${context.repo} --json`];
  }
  if (name === "github:origin" || name === "git:origin") {
    return [
      `bounty release github-bootstrap ${context.repo} --branch ${context.branch} --tag ${context.tag} --write`,
      context.addOriginCommand,
      `git push -u origin HEAD:${context.branch}`,
    ];
  }
  if (name === "git:origin-target") {
    return [context.setOriginCommand];
  }
  if (name === "gh:version" || name === "github:actions-gh") {
    return [...GITHUB_CLI_INSTALL_COMMANDS, "gh --version", "gh auth status"];
  }
  if (name === "gh:auth") {
    return ["gh auth status", "gh auth login"];
  }
  if (name === "git:working-tree") {
    return ["git status --short", "git add .", 'git commit -m "Prepare BountyPilot release"'];
  }
  if (name === "git:local-tag") {
    return [`git tag ${context.tag}`];
  }
  if (name === "publish:public-branch") {
    return [
      `git push -u origin HEAD:${context.publicBranch}`,
      `bounty release publish-status ${context.repo} --branch ${context.publicBranch} --tag ${context.tag} --online --actions --json`,
    ];
  }
  if (name === "git:remote-branch") {
    return [`git push -u origin HEAD:${context.branch}`];
  }
  if (name === "git:remote-tag") {
    return [
      `bounty skill score ${context.id} --repo ${context.repo} --branch ${context.branch} --tag ${context.tag} --strict --json`,
      `git push origin ${context.tag}`,
    ];
  }
  if (name === "publish:online") {
    return [`bounty release publish-status ${context.repo} --branch ${context.branch} --tag ${context.tag} --online --json`];
  }
  if (name === "github:actions" || name.startsWith("github:actions:")) {
    return [
      `bounty release publish-status ${context.repo} --branch ${context.branch} --tag ${context.tag} --online --actions --json`,
      publicGateCommand(context.repo, context.branch, context.tag),
      `gh run list --repo ${context.repo} --limit 10`,
    ];
  }
  return [`bounty skill score ${context.id} --repo ${context.repo} --json`];
}

function uniqueCommands(commands: string[]): string[] {
  return [...new Set(commands.filter(Boolean))];
}

function markdownTable(headers: string[], rows: string[][]): string {
  const header = `| ${headers.map(markdownCell).join(" | ")} |`;
  const separator = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((row) => `| ${row.map(markdownCell).join(" | ")} |`);
  return [header, separator, ...body].join("\n");
}

function markdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
}

function commandBlock(commands: string[]): string {
  return ["```bash", ...commands, "```"].join("\n");
}

function mergeRequirements(requirements: SkillReadinessRequirement[]): SkillReadinessRequirement[] {
  const merged = new Map<string, SkillReadinessRequirement>();
  for (const requirement of requirements) {
    const existing = merged.get(requirement.name);
    if (!existing || requirementStatusRank(requirement.status) > requirementStatusRank(existing.status)) {
      merged.set(requirement.name, requirement);
    }
  }
  return [...merged.values()];
}

function requirementStatusRank(status: SkillReadinessRequirementStatus): number {
  if (status === "fail") return 2;
  if (status === "warn") return 1;
  return 0;
}

function readinessLayer(input: {
  blockers: SkillReadinessIssue[];
  warnings: SkillReadinessIssue[];
  validationFailures: number;
  bundleFailures: number;
  releaseFailures: number;
}): SkillReadinessLayer {
  const score = readinessScore({
    validationFailures: input.validationFailures,
    bundleFailures: input.bundleFailures,
    releaseFailures: input.releaseFailures,
    warnings: input.warnings.length,
  });
  const readiness: SkillReadinessLevel =
    input.blockers.length > 0 ? "blocked" : input.warnings.length > 0 ? "ready_with_warnings" : "ultimate";
  return {
    ok: input.blockers.length === 0,
    ultimate: input.blockers.length === 0 && input.warnings.length === 0 && score === 100,
    score,
    readiness,
    blockers: input.blockers,
    warnings: input.warnings,
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

function publishStatusIssues(publish: ReturnType<typeof buildReleasePublishStatus>): SkillReadinessIssue[] {
  return publish.checks
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
  releaseBranch: string;
  repoSlug?: string;
  githubNextCommands?: string[];
  publishNextCommands?: string[];
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
    steps.add(publicReadinessPlanCommand(input.id, repo));
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
      steps.add(`bounty skill score ${input.id} --repo ${repo} --branch main --tag ${input.releaseTag} --online --actions --strict --json`);
      steps.add(publicGateCommand(repo, "main", input.releaseTag));
      steps.add(`bounty release publish-status ${repo} --online --actions --json`);
      steps.add("bugbounty release install-check --json");
    }
  }
  input.githubNextCommands?.forEach((command) => steps.add(command));
  input.publishNextCommands?.forEach((command) => steps.add(command));
  if (steps.size > 0) {
    const repoArg = input.repoSlug ? ` --repo ${input.repoSlug}` : "";
    const repo = input.repoSlug ?? "OWNER/REPO";
    steps.add(publicReadinessPlanCommand(input.id, repo));
    if (input.repoSlug) {
      steps.add(`bounty skill score ${input.id}${repoArg} --online --actions --strict --json`);
      steps.add(publicGateCommand(repo, input.releaseBranch, input.releaseTag));
    }
    steps.add(`bounty skill score ${input.id}${repoArg} --json`);
  }
  if (steps.size === 0) {
    const repoArg = input.repoSlug ? ` --repo ${input.repoSlug}` : "";
    steps.add(`Review warnings, then rerun \`bounty skill score ${input.id}${repoArg} --json\`.`);
  }
  return [...steps];
}

function publicReadinessPlanCommand(id: string, repo: string): string {
  return `bounty skill score ${id} --repo ${repo} --write-public-plan .bounty/release/public-readiness.md --json`;
}

function publicGateCommand(repo: string, branch: string, tag: string): string {
  return `bounty release public-gate ${repo} --branch ${branch} --tag ${tag} --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json`;
}

function isPublishReadinessIssue(issue: SkillReadinessIssue): boolean {
  return (
    issue.name === "github:origin" ||
    issue.name.startsWith("gh:") ||
    issue.name.startsWith("github:") ||
    issue.name.startsWith("publish:") ||
    issue.name === "git:origin" ||
    issue.name === "git:origin-target" ||
    issue.name === "git:working-tree" ||
    issue.name === "git:local-tag" ||
    issue.name === "git:remote-branch" ||
    issue.name === "git:remote-tag" ||
    issue.name === "git:branch"
  );
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
