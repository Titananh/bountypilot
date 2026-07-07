import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runReleaseCheck } from "../core/release/release-check.js";
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
}

export function scoreSkillReadiness(input: { id?: string; cwd?: string; generatedAt?: string } = {}): SkillReadinessResult {
  const cwd = input.cwd ?? process.cwd();
  const id = input.id ?? BUG_BOUNTY_PILOT_SKILL_ID;
  const validation = validateSkillDefinition(id, cwd);
  const validationFailures = issuesFor(validation.checks, "fail");
  const validationWarnings = issuesFor(validation.checks, "warn");
  const bundle = scoreSkillBundle({ id, cwd, generatedAt: input.generatedAt });
  const release = runReleaseCheck(cwd);
  const releaseFailures = issuesFor(release.checks, "fail");
  const releaseWarnings = issuesFor(release.checks, "warn");
  const blockers = [...validationFailures, ...bundle.failures, ...releaseFailures];
  const warnings = [...validationWarnings, ...releaseWarnings];
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
    nextSteps: readinessNextSteps({ id, blockers, warnings, releaseTag: release.version ? `v${release.version}` : "v0.1.0" }),
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
  };
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
    steps.add("bounty release publish-plan OWNER/REPO --write");
    steps.add("gh --version");
    steps.add("gh auth status");
    steps.add("gh auth login");
    steps.add("gh repo create OWNER/REPO --public --source . --remote origin --push");
    steps.add("git remote add origin https://github.com/OWNER/REPO.git");
    steps.add("git push -u origin HEAD");
    steps.add(`git tag ${input.releaseTag}`);
    steps.add(`git push origin ${input.releaseTag}`);
    steps.add(`bounty release publish-plan OWNER/REPO --branch main --tag ${input.releaseTag} --write`);
    steps.add(`bounty release publish-status OWNER/REPO --branch main --tag ${input.releaseTag} --online --actions --json`);
    steps.add("bounty release publish-status OWNER/REPO --online --actions --json");
  }
  if (steps.size === 0) {
    steps.add("Review warnings, then rerun `bounty skill score bug-bounty-pilot`.");
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
