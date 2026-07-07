import type { HuntReconResult } from "../hunting/recon-engine.js";
import { runHuntRecon } from "../hunting/recon-engine.js";
import type { WorkflowEventRecord } from "../core/jobs/workflow-event-store.js";
import type { WorkflowSummary } from "../workflows/run-workflow.js";
import { WorkflowRunner } from "../workflows/run-workflow.js";
import type { ExecutionMode } from "../types.js";
import { BountyPilotError } from "../utils/errors.js";
import { createRuntime, type Runtime } from "../cli/runtime.js";
import {
  BUG_BOUNTY_PILOT_SKILL_ID,
  loadSkillDefinition,
  type SkillDefinition,
  type SkillRunMode,
  validateSkillDefinition,
  type SkillValidationResult,
} from "./skill-definition.js";

export interface SkillRunInput {
  id?: string;
  target: string;
  program?: string;
  mode: SkillRunMode;
  live?: boolean;
  dryRun?: boolean;
  withComponents?: string[];
  reviewRequired?: boolean;
  cwd?: string;
}

export interface SkillRunResult {
  ok: boolean;
  skill: {
    id: string;
    root: string;
  };
  program: string;
  target: string;
  mode: SkillRunMode;
  live: boolean;
  dryRun: boolean;
  validation: SkillValidationResult;
  recon?: HuntReconResult;
  summary?: WorkflowSummary;
  events: WorkflowEventRecord[];
  blockers: string[];
  warnings: string[];
  nextCommands: string[];
}

export async function runSkill(input: SkillRunInput): Promise<SkillRunResult> {
  const id = input.id ?? BUG_BOUNTY_PILOT_SKILL_ID;
  const validation = validateSkillDefinition(id, input.cwd ?? process.cwd());
  if (!validation.ok) {
    return blockedResult({
      input,
      validation,
      blockers: validation.checks.filter((check) => check.status === "fail").map((check) => `${check.name}: ${check.message}`),
    });
  }
  const skill = loadSkillDefinition(id, input.cwd ?? process.cwd());
  const live = input.live === true;
  const dryRun = input.dryRun === true || !live;
  if (input.live === true && input.dryRun === true) {
    throw new BountyPilotError("Use either --live or --dry-run, not both.", "SKILL_RUN_MODE_CONFLICT");
  }
  if (input.mode === "passive" && live) {
    throw new BountyPilotError("passive mode cannot use --live because it forbids active requests.", "SKILL_PASSIVE_LIVE_BLOCKED");
  }

  const runtime = createRuntime(input.program);
  const scoped = runtime.scopeGuard.assertAllowed(input.target);
  if (input.mode === "lab-offensive" && runtime.config.rules.lab_mode !== true) {
    throw new BountyPilotError(
      "lab-offensive mode requires rules.lab_mode=true and a local lab authorization file in the imported program.",
      "SKILL_LAB_MODE_REQUIRED",
    );
  }

  const warnings = skillWarnings(skill, input.mode, input.withComponents);
  if (input.reviewRequired) {
    warnings.push("review-required flag is advisory; approvals must still be granted through the action review store.");
  }

  if (input.mode === "passive") {
    const recon = await runHuntRecon(runtime, scoped.url, {
      profile: "passive",
      live: false,
    });
    return {
      ok: recon.ok,
      skill: { id: skill.id, root: skill.root },
      program: runtime.config.program,
      target: scoped.url,
      mode: input.mode,
      live: false,
      dryRun: true,
      validation,
      recon,
      events: runtime.events.list(recon.jobId),
      blockers: recon.ok ? [] : recon.tools.filter((tool) => tool.status === "blocked" || tool.status === "failed").map((tool) => `${tool.tool}: ${tool.message}`),
      warnings,
      nextCommands: skillNextCommands({ jobId: recon.jobId, mode: input.mode, recon }),
    };
  }

  const recon = await runHuntRecon(runtime, scoped.url, {
    profile: input.mode === "safe" ? "passive" : "web",
    live: input.mode === "safe" ? false : live,
  });
  const summary = await new WorkflowRunner(runtime).run({
    target: scoped.url,
    mode: input.mode as ExecutionMode,
    dryRun,
    draftReports: false,
    withComponents: input.withComponents && input.withComponents.length > 0 ? input.withComponents : defaultSkillComponents(input.mode),
  });
  const blockers = [
    ...recon.tools.filter((tool) => tool.status === "blocked" || tool.status === "failed").map((tool) => `${tool.tool}: ${tool.message}`),
    ...summary.phases.filter((phase) => phase.status === "failed").map((phase) => `${phase.name}: ${phase.detail}`),
  ];
  return {
    ok: blockers.length === 0 && summary.status !== "failed",
    skill: { id: skill.id, root: skill.root },
    program: runtime.config.program,
    target: scoped.url,
    mode: input.mode,
    live,
    dryRun,
    validation,
    recon,
    summary,
    events: runtime.events.list(summary.jobId),
    blockers,
    warnings,
    nextCommands: skillNextCommands({ jobId: summary.jobId, mode: input.mode, recon, summary }),
  };
}

function blockedResult(input: {
  input: SkillRunInput;
  validation: SkillValidationResult;
  blockers: string[];
}): SkillRunResult {
  return {
    ok: false,
    skill: { id: input.input.id ?? BUG_BOUNTY_PILOT_SKILL_ID, root: input.validation.root },
    program: input.input.program ?? "unknown",
    target: input.input.target,
    mode: input.input.mode,
    live: input.input.live === true,
    dryRun: input.input.dryRun === true || input.input.live !== true,
    validation: input.validation,
    events: [],
    blockers: input.blockers,
    warnings: [],
    nextCommands: [`bounty skill validate ${input.input.id ?? BUG_BOUNTY_PILOT_SKILL_ID}`],
  };
}

function defaultSkillComponents(mode: SkillRunMode): string[] {
  if (mode === "safe") {
    return ["d-research-skill", "safe-checks", "js-analyzer", "triage", "planner"];
  }
  if (mode === "deep-safe") {
    return ["d-research-skill", "safe-checks", "js-analyzer", "playwright", "triage", "planner"];
  }
  if (mode === "lab-offensive") {
    return ["safe-checks", "js-analyzer", "playwright", "triage", "planner"];
  }
  return ["planner"];
}

function skillWarnings(skill: SkillDefinition, mode: SkillRunMode, withComponents?: string[]): string[] {
  const warnings: string[] = [];
  const modePolicy = skill.policy.modes[mode];
  if (modePolicy.review_required_capabilities.length > 0) {
    warnings.push(`Mode ${mode} has review-required capabilities: ${modePolicy.review_required_capabilities.join(", ")}.`);
  }
  if (withComponents?.some((component) => ["crawl4ai", "playwright-mcp"].includes(component))) {
    warnings.push("MCP/crawler components remain policy-gated and planning-first unless explicitly enabled and approved.");
  }
  return warnings;
}

function skillNextCommands(input: {
  jobId: string;
  mode: SkillRunMode;
  recon?: HuntReconResult;
  summary?: WorkflowSummary;
}): string[] {
  const commands = [
    `bounty jobs show ${input.jobId}`,
    `bounty jobs timeline ${input.jobId}`,
    `bounty evidence manifest --job ${input.jobId}`,
  ];
  if (input.summary?.actionCounts.pending || input.recon?.tools.some((tool) => tool.status === "pending")) {
    commands.push(`bounty actions list --job ${input.jobId} --pending`);
  }
  if (input.mode !== "passive") {
    commands.push(`bounty reports score <candidate-id> --json`);
  }
  commands.push(`bounty export bundle --job ${input.jobId} --include-artifacts`);
  return commands;
}
