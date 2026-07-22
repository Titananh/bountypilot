import path from "node:path";
import { randomBytes } from "node:crypto";
import type { Command } from "commander";
import { ActionApprovalService } from "../core/actions/action-approval-service.js";
import { ActionLifecycle } from "../core/actions/action-lifecycle.js";
import { ActionQueue } from "../core/actions/action-queue.js";
import { ActionReviewStore } from "../core/actions/action-review-store.js";
import { createProductionActionAuthorityDependencies } from "../core/actions/production-action-authority.js";
import { AuditLogger } from "../core/audit/audit-logger.js";
import { loadWorkspaceProgram } from "../core/config/config-loader.js";
import type { ProgramConfig } from "../core/config/program-schema.js";
import { JobManager } from "../core/jobs/job-manager.js";
import { WorkflowEventStore } from "../core/jobs/workflow-event-store.js";
import { PolicyGate } from "../core/policy/policy-gate.js";
import { RateLimiter } from "../core/rate-limit/rate-limiter.js";
import { ScopeGuard } from "../core/scope/scope-guard.js";
import { ensureProgramWorkspace, type ProgramWorkspace } from "../core/workspace.js";
import { EvidenceStore } from "../stores/evidence-store.js";
import { FindingCandidateStore } from "../stores/finding-candidate-store.js";
import { FindingStore } from "../stores/finding-store.js";
import { openBountyDatabase, type BountyDatabase } from "../stores/db/database.js";
import { CrawlGraphStore } from "../stores/crawl-graph-store.js";
import { ReconObservationStore } from "../stores/recon-observation-store.js";
import type { ExecutionMode, RiskLevel } from "../types.js";
import { BountyPilotError } from "../utils/errors.js";
import * as ui from "./ui.js";

export interface Runtime {
  config: ProgramConfig;
  paths: ProgramWorkspace;
  db: BountyDatabase;
  scopeGuard: ScopeGuard;
  policyGate: PolicyGate;
  rateLimiter: RateLimiter;
  candidates: FindingCandidateStore;
  findings: FindingStore;
  evidence: EvidenceStore;
  crawlGraph: CrawlGraphStore;
  recon: ReconObservationStore;
  jobs: JobManager;
  events: WorkflowEventStore;
  actions: ActionQueue;
  reviews: ActionReviewStore;
  actionApproval: ActionApprovalService;
  actionLifecycle: ActionLifecycle;
}

export function getRootOptions(command: Command): { program?: string } {
  let current: Command | null = command;
  while (current.parent) {
    current = current.parent;
  }
  return current.opts<{ program?: string }>();
}

export function createRuntime(program?: string): Runtime {
  const loaded = loadWorkspaceProgram(process.cwd(), program);
  const paths = ensureProgramWorkspace(loaded.config.program, process.cwd());
  const db = openBountyDatabase(paths.dbFile);
  const authority = createProductionActionAuthorityDependencies({
    programFile: loaded.programFile,
  });
  const actionApproval = new ActionApprovalService(db, {
    ...authority,
    now: () => new Date(),
  });
  const actionLifecycle = new ActionLifecycle(db, {
    ...authority,
    now: () => new Date(),
    generateExecutionToken: () => randomBytes(32).toString("hex"),
  });
  return {
    config: loaded.config,
    paths,
    db,
    scopeGuard: new ScopeGuard(loaded.config),
    policyGate: new PolicyGate(loaded.config.rules),
    rateLimiter: new RateLimiter(loaded.config.rules.rate_limit),
    candidates: new FindingCandidateStore(db),
    findings: new FindingStore(db),
    evidence: new EvidenceStore(db, paths.evidenceDir, {
      maskSecrets: loaded.config.evidence.mask_secrets !== false,
      trustedArtifactRoots: [paths.reportsDir],
    }),
    crawlGraph: new CrawlGraphStore(db),
    recon: new ReconObservationStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
    actionApproval,
    actionLifecycle,
  };
}

export function modeFromOptions(value?: string): ExecutionMode {
  const mode = value ?? "safe";
  if (mode === "passive" || mode === "safe" || mode === "deep-safe" || mode === "lab-offensive") {
    return mode;
  }
  throw new BountyPilotError(`Unsupported mode: ${value}`, "MODE_INVALID");
}

export function createJobAuditLogger(paths: ProgramWorkspace, jobId: string): AuditLogger {
  return new AuditLogger(path.join(paths.jobsDir, jobId, "audit.log"));
}

export interface PlanAllowedActionInput {
  runtime: Runtime;
  audit: AuditLogger;
  jobId: string;
  adapter: string;
  actionType: string;
  target?: string;
  mode: ExecutionMode;
  riskLevel: RiskLevel;
  stateChanging?: boolean;
  destructive?: boolean;
  capability?: string;
  requiredForCompletion?: boolean;
  /**
   * Non-authoritative annotations for planning/handoff surfaces. Metadata is
   * persisted with the immutable action so review tooling can distinguish a
   * plan-only row from an effect-capable row; it never grants execution
   * authority.
   */
  metadata?: Record<string, unknown>;
}

export interface PlannedAllowedAction {
  allowed: boolean;
  action: import("../core/actions/action-queue.js").ActionRecord;
}

export async function planAllowedAction(input: PlanAllowedActionInput): Promise<boolean> {
  const result = await planAllowedActionWithRecord(input);
  return result.allowed;
}

export async function planAllowedActionWithRecord(input: PlanAllowedActionInput): Promise<PlannedAllowedAction> {
  const policy = input.runtime.policyGate.evaluate({
    mode: input.mode,
    actionType: input.actionType,
    target: input.target,
    riskLevel: input.riskLevel,
    stateChanging: input.stateChanging,
    destructive: input.destructive,
    capability: input.capability,
    labModeEnabled: input.runtime.config.rules.lab_mode === true,
  });

  input.audit.log({
    jobId: input.jobId,
    actionType: input.actionType,
    url: input.target,
    adapterName: input.adapter,
    policyDecision: policy.decision,
    reason: policy.reason,
  });

  if (policy.decision === "block") {
    input.runtime.actions.enqueue({
      jobId: input.jobId,
      adapter: input.adapter,
      actionType: input.actionType,
      target: input.target,
      riskLevel: input.riskLevel,
      requiresApproval: false,
      status: "blocked",
      requiredForCompletion: input.requiredForCompletion,
      metadata: input.metadata,
    });
    input.runtime.jobs.finalize(input.jobId);
    throw new BountyPilotError(policy.reason, "POLICY_BLOCKED");
  }

  const action = input.runtime.actions.enqueue({
    jobId: input.jobId,
    adapter: input.adapter,
    actionType: input.actionType,
    target: input.target,
    riskLevel: input.riskLevel,
    requiresApproval: policy.decision === "require_approval",
    requiredForCompletion: input.requiredForCompletion,
    metadata: input.metadata,
  });
  // Enqueuing into an existing terminal job must immediately re-derive its
  // authoritative tuple before an approval/claim attempt. JobManager.finalize
  // is the only path that may reopen it based on newly-required work.
  input.runtime.jobs.finalize(input.jobId);

  return { allowed: policy.decision === "allow", action };
}

export function printJson(value: unknown): void {
  ui.json(value);
}
