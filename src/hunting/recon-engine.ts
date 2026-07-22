import path from "node:path";
import type { Runtime } from "../cli/runtime.js";
import { createJobAuditLogger } from "../cli/runtime.js";
import type { JobRecord } from "../core/jobs/job-manager.js";
import type { WorkflowEventStatus } from "../core/jobs/workflow-event-store.js";
import { latestToolApproval } from "../integrations/tool-manager/tool-adapter-runner.js";
import { ToolManager } from "../integrations/tool-manager/tool-manager.js";
import { ActionExecutor } from "../workflows/action-executor.js";
import type {
  BugClass,
  EvidenceArtifact,
  ExecutionMode,
  PlaybookResult,
  ReconObservation,
  RiskLevel,
} from "../types.js";
import { BountyPilotError } from "../utils/errors.js";

export type HuntReconProfile = "passive" | "web";

export interface HuntReconOptions {
  profile: HuntReconProfile;
  live: boolean;
  tools?: string[];
}

export interface HuntReconToolResult {
  tool: string;
  actionType: string;
  status: "planned" | "pending" | "executed" | "skipped" | "blocked" | "failed";
  actionId?: string;
  approvalPresent: boolean;
  observations: number;
  evidencePath?: string;
  message: string;
}

export interface HuntReconResult {
  ok: boolean;
  profile: HuntReconProfile;
  target: string;
  live: boolean;
  jobId: string;
  mode: ExecutionMode;
  tools: HuntReconToolResult[];
  observations: ReconObservation[];
  evidence: EvidenceArtifact[];
  actionsPlanned: number;
  nextCommands: string[];
}

export const BUG_CLASSES: BugClass[] = ["xss", "ssrf", "idor", "graphql", "cors", "open-redirect", "js-secrets", "exposure"];

const PASSIVE_RECON_TOOLS = ["subfinder", "gau", "waybackurls"];
const WEB_RECON_TOOLS = ["subfinder", "gau", "waybackurls", "dnsx", "httpx", "katana", "nuclei", "ffuf", "dalfox"];
const REVIEW_REQUIRED_RECON_TOOLS = new Set(["nuclei", "ffuf", "dalfox", "naabu"]);

export async function runHuntRecon(runtime: Runtime, target: string, options: HuntReconOptions): Promise<HuntReconResult> {
  const scoped = runtime.scopeGuard.assertAllowed(target);
  const mode: ExecutionMode = options.profile === "web" ? "deep-safe" : "safe";
  const job = runtime.jobs.create("hunt-recon", mode, scoped.url);
  runtime.jobs.updateStatus(job.id, "running");
  runtime.events.record({
    jobId: job.id,
    phase: "hunt-recon",
    status: "running",
    message: `${options.profile} recon planning started; target effects are disabled.`,
    metadata: {
      target: scoped.url,
      requestedLive: options.live,
      planningOnly: true,
      targetEffectsExecuted: 0,
    },
  });

  const manager = new ToolManager();
  const selectedTools = normalizeToolSelection(options.tools, options.profile);
  const toolResults: HuntReconToolResult[] = [];
  const evidence: EvidenceArtifact[] = [];
  const observations: ReconObservation[] = [];
  const audit = createJobAuditLogger(runtime.paths, job.id);
  let actionsPlanned = 0;

  const planArtifact = runtime.evidence.writeTextArtifact({
    jobId: job.id,
    adapterName: "hunt-recon",
    kind: "research_note",
    sourceUrl: scoped.url,
    relativePath: path.join(job.id, "recon-plan.json"),
    content: `${JSON.stringify({
      target: scoped.url,
      profile: options.profile,
      live: options.live,
      planningOnly: true,
      targetEffectsAllowed: false,
      tools: selectedTools,
    }, null, 2)}\n`,
  });
  evidence.push(planArtifact);

  for (const toolName of selectedTools) {
    const tool = manager.get(toolName);
    if (!tool) {
      toolResults.push({
        tool: toolName,
        actionType: "unknown",
        status: "skipped",
        approvalPresent: false,
        observations: 0,
        message: "Tool is not in the trusted registry; no action was queued.",
      });
      continue;
    }

    const actionType = tool.actions[0]?.action_type;
    if (!actionType) {
      toolResults.push({
        tool: tool.name,
        actionType: "unknown",
        status: "skipped",
        approvalPresent: false,
        observations: 0,
        message: "Tool has no trusted action metadata; no action was queued.",
      });
      continue;
    }

    const validation = manager.validateRunPlan({
      tool: tool.name,
      mode,
      actionType,
      target: scoped.url,
      labModeEnabled: runtime.config.rules.lab_mode === true,
      programRules: runtime.config.rules,
    });
    const approvalPresent = Boolean(latestToolApproval(runtime, tool.name));
    const requiresApproval = validation.requiresApproval || REVIEW_REQUIRED_RECON_TOOLS.has(tool.name);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "tool-manager",
      actionType,
      target: scoped.url,
      riskLevel: validation.riskLevel ?? (tool.permissions.active_scanning ? "medium" : "low"),
      requiresApproval,
      // Recon is a planning-only surface. Even when the caller requested
      // `--live`, this module never dispatches a process; the queued row is a
      // handoff artifact and therefore must not hold the job in
      // approval_required forever.
      requiredForCompletion: false,
      metadata: {
        tool: tool.name,
        reconProfile: options.profile,
        requestedLive: options.live,
        planningOnly: true,
        handoffOnly: true,
      },
      status: validation.allowed ? "pending" : "blocked",
    });
    actionsPlanned += 1;

    audit.log({
      jobId: job.id,
      actionType,
      url: scoped.url,
      adapterName: tool.name,
      policyDecision: validation.allowed ? (requiresApproval ? "require_approval" : "allow") : "block",
      reason: validation.reasons.join("; ") || "Target effect was planned but not executed.",
      metadata: {
        actionId: action.id,
        approvalPresent,
        requestedLive: options.live,
        planningOnly: true,
      },
    });

    if (!validation.allowed) {
      toolResults.push({
        tool: tool.name,
        actionType,
        status: "blocked",
        actionId: action.id,
        approvalPresent,
        observations: 0,
        message: validation.reasons.join("; ") || "Tool action is blocked by policy.",
      });
      continue;
    }

    toolResults.push({
      tool: tool.name,
      actionType,
      status: "pending",
      actionId: action.id,
      approvalPresent,
      observations: 0,
      message: options.live
        ? "Live execution is disabled; the planning handoff remains pending for human review."
        : "Dry-run recorded the planning handoff as pending for human review.",
    });
  }

  const queueSummary = runtime.actions.summarize(job.id);
  const finalizedJob = runtime.jobs.finalize(job.id);
  runtime.events.record({
    jobId: job.id,
    phase: "hunt-recon",
    status: planningEventStatus(finalizedJob),
    message: reconPlanningMessage(finalizedJob, queueSummary.pending, queueSummary.blocked),
    metadata: {
      tools: toolResults,
      evidence: evidence.length,
      actionsPlanned,
      pendingActions: queueSummary.pending,
      blockedActions: queueSummary.blocked,
      jobStatus: finalizedJob.status,
      pauseReason: finalizedJob.pauseReason,
      reason: finalizedJob.pauseReason ?? "planning_complete",
      statusDetail: finalizedJob.statusDetail,
      requestedLive: options.live,
      planningOnly: true,
      targetEffectsExecuted: 0,
    },
  });

  return {
    ok: finalizedJob.status !== "failed",
    profile: options.profile,
    target: scoped.url,
    live: options.live,
    jobId: job.id,
    mode,
    tools: toolResults,
    observations,
    evidence,
    actionsPlanned,
    nextCommands: reconNextCommands(job.id),
  };
}

export async function runHuntPlaybook(runtime: Runtime, bugClass: BugClass, target: string, live: boolean): Promise<PlaybookResult> {
  if (!BUG_CLASSES.includes(bugClass)) {
    throw new BountyPilotError(`Unsupported playbook: ${bugClass}`, "HUNT_PLAYBOOK_UNKNOWN");
  }

  const scoped = runtime.scopeGuard.assertAllowed(target);
  const mode: ExecutionMode = "deep-safe";
  const job = runtime.jobs.create("hunt-playbook", mode, scoped.url);
  runtime.jobs.updateStatus(job.id, "running");
  runtime.events.record({
    jobId: job.id,
    phase: `playbook:${bugClass}`,
    status: "running",
    message: live
      ? `${bugClass} playbook planning started; only allowlisted low-risk built-ins may execute through the lifecycle.`
      : `${bugClass} playbook planning started; target effects are disabled.`,
    metadata: {
      bugClass,
      target: scoped.url,
      requestedLive: live,
      planningOnly: !live,
      targetEffectsAllowed: live,
      targetEffectsExecuted: 0,
    },
  });

  const evidence: EvidenceArtifact[] = [];
  const observations: ReconObservation[] = [];
  const audit = createJobAuditLogger(runtime.paths, job.id);
  let actionsPlanned = 0;
  const plannedActions: Array<{ actionId: string; adapter: string; riskLevel: RiskLevel; allowed: boolean }> = [];
  const executionErrors: string[] = [];
  let executedActions = 0;
  const actionSpecs = playbookActions(bugClass);

  const plan = runtime.evidence.writeTextArtifact({
    jobId: job.id,
    adapterName: "hunt-playbook",
    kind: "research_note",
    sourceUrl: scoped.url,
    relativePath: path.join(job.id, `${bugClass}-playbook-plan.json`),
    content: `${JSON.stringify({
      bugClass,
      target: scoped.url,
      live,
      planningOnly: !live,
      targetEffectsAllowed: live,
      handoffRequired: !live || actionSpecs.some((action) => action.adapter === "manual-validation" || action.requiresApproval === true),
      checks: playbookChecks(bugClass),
    }, null, 2)}\n`,
  });
  evidence.push(plan);

  for (const action of actionSpecs) {
    // Manual validation is always a handoff. In dry-run mode every row is a
    // plan-only handoff; only allowlisted low-risk built-ins in an explicit
    // live run participate in the required completion gate.
    const requiredForCompletion = live && action.adapter !== "manual-validation";
    const planningOnly = !requiredForCompletion;
    const decision = runtime.policyGate.evaluate({
      mode,
      actionType: action.actionType,
      target: scoped.url,
      riskLevel: action.riskLevel,
      capability: action.capability,
      requiresApprovalByDefault: action.requiresApproval,
      labModeEnabled: runtime.config.rules.lab_mode === true,
    });
    const queued = runtime.actions.enqueue({
      jobId: job.id,
      adapter: action.adapter,
      actionType: action.actionType,
      target: scoped.url,
      riskLevel: action.riskLevel,
      requiresApproval: decision.decision === "require_approval" || action.requiresApproval === true,
      requiredForCompletion,
      metadata: {
        bugClass,
        requestedLive: live,
        planningOnly,
        handoffOnly: planningOnly,
      },
      status: decision.decision === "block" ? "blocked" : "pending",
    });
    actionsPlanned += 1;
    plannedActions.push({
      actionId: queued.id,
      adapter: action.adapter,
      riskLevel: action.riskLevel,
      allowed: decision.decision === "allow",
    });

    audit.log({
      jobId: job.id,
      actionType: action.actionType,
      url: scoped.url,
      adapterName: action.adapter,
      policyDecision: decision.decision,
      reason: decision.reason,
      metadata: {
        actionId: queued.id,
        bugClass,
        requestedLive: live,
        planningOnly,
        handoffOnly: planningOnly,
      },
    });
  }

  // `--live` is an explicit user opt-in for the narrowly allowlisted,
  // non-destructive built-ins only. The executor revalidates scope, policy,
  // authority and lifecycle state immediately before dispatch. Manual
  // validation and every external/MCP adapter remain pending handoffs.
  if (live) {
    const executor = new ActionExecutor(runtime);
    for (const planned of plannedActions) {
      if (!planned.allowed || planned.riskLevel !== "low") continue;
      if (!new Set(["safe-checks", "js-analyzer", "playwright"]).has(planned.adapter)) continue;
      try {
        await executor.execute(planned.actionId);
        executedActions += 1;
      } catch (error) {
        executionErrors.push(`${planned.adapter}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  // Surface artifacts and findings produced by the authoritative executor,
  // while keeping the initial plan artifact in the returned evidence list.
  for (const artifact of runtime.evidence.list().filter((item) => item.jobId === job.id)) {
    if (!evidence.some((existing) => existing.id === artifact.id)) evidence.push(artifact);
  }
  const candidates = runtime.candidates.list({ jobId: job.id });
  const findings = runtime.findings.list().filter((finding) =>
    finding.evidencePaths.some((candidatePath) => candidatePath.includes(job.id)),
  );
  for (const candidate of candidates) {
    observations.push(runtime.recon.upsert({
      jobId: job.id,
      kind: "finding_candidate",
      value: candidate.title,
      sourceAdapter: "hunt-playbook",
      sourceUrl: candidate.url,
      scopeAllowed: true,
      confidence: candidate.confidence,
      riskHint: candidate.severityEstimate === "critical" || candidate.severityEstimate === "high" ? "medium" : "low",
      metadata: {
        bugClass,
        category: candidate.category,
        findingId: candidate.findingId,
        candidateId: candidate.id,
        planningOnly: false,
      },
    }));
  }

  observations.push(...recordStaticPlaybookObservations(runtime, job.id, bugClass, scoped.url));

  const queueSummary = runtime.actions.summarize(job.id);
  const finalizedJob = runtime.jobs.finalize(job.id);
  const paused = finalizedJob.status === "paused";
  const policyBlocked = finalizedJob.pauseReason === "policy_blocked";
  const queuedActions = runtime.actions.list(job.id);
  const handoffRequired = queuedActions.some(
    (action) =>
      action.metadata?.handoffOnly === true &&
      (action.status === "pending" || action.status === "approved" || action.status === "running"),
  );
  runtime.events.record({
    jobId: job.id,
    phase: `playbook:${bugClass}`,
    status: planningEventStatus(finalizedJob),
    message: playbookPlanningMessage(finalizedJob, live, queueSummary.pending, queueSummary.blocked, executedActions),
    metadata: {
      reason: finalizedJob.pauseReason ?? "planning_complete",
      jobStatus: finalizedJob.status,
      pauseReason: finalizedJob.pauseReason,
      statusDetail: finalizedJob.statusDetail,
      pendingActions: queueSummary.pending,
      blockedActions: queueSummary.blocked,
      observations: observations.length,
      candidates: candidates.length,
      findings: findings.length,
      evidence: evidence.length,
      bugClass,
      target: scoped.url,
      requestedLive: live,
      planningOnly: executedActions === 0,
      handoffRequired,
      targetEffectsExecuted: executedActions,
      executionErrors,
    },
  });

  return {
    ok: finalizedJob.status !== "failed",
    ...(paused ? { paused: true } : {}),
    bugClass,
    target: scoped.url,
    live,
    jobId: job.id,
    observations,
    candidatesCreated: candidates,
    findingsCreated: findings,
    evidence,
    actionsPlanned,
    actionsExecuted: executedActions,
    actionsPending: queueSummary.pending,
    actionsBlocked: queueSummary.blocked,
    nextCommands: policyBlocked
      ? playbookBlockedNextCommands(job.id)
      : playbookNextCommands(
          job.id,
          findings.map((finding) => finding.id),
          candidates.map((candidate) => candidate.id),
        ),
  };
}

function planningEventStatus(job: JobRecord): WorkflowEventStatus {
  if (job.pauseReason === "policy_blocked") return "blocked";
  if (job.status === "queued") return "planned";
  return job.status;
}

function reconPlanningMessage(job: JobRecord, pendingActions: number, blockedActions: number): string {
  if (job.pauseReason === "policy_blocked") {
    return `Recon planning failed closed: ${blockedActions} required action(s) are policy-blocked; no target effects were executed.`;
  }
  if (job.status === "paused") {
    return `Recon planning paused for human handoff (${job.pauseReason ?? "manual_review"}): ${pendingActions} action(s) remain queued; no target effects were executed.`;
  }
  if (job.status === "failed") {
    return "Recon planning failed closed; no target effects were executed.";
  }
  if (job.status === "completed") {
    return "Recon planning completed without required target actions; no target effects were executed.";
  }
  return "Recon planning remains active; no target effects were executed.";
}

function playbookPlanningMessage(
  job: JobRecord,
  live: boolean,
  pendingActions: number,
  blockedActions: number,
  executedActions = 0,
): string {
  if (job.pauseReason === "policy_blocked") {
    return executedActions > 0
      ? `Playbook is policy-blocked after ${executedActions} allowlisted non-destructive action(s) executed: ${blockedActions} required action(s) were denied.`
      : `Playbook is policy-blocked: ${blockedActions} required action(s) were denied; no target effects were executed.`;
  }
  if (job.status === "paused") {
    const requestKind = live ? "Live playbook" : "Playbook dry-run";
    return executedActions > 0
      ? `${requestKind} executed ${executedActions} allowlisted non-destructive action(s), then handed off for human review (${job.pauseReason ?? "manual_review"}): ${pendingActions} action(s) remain queued.`
      : `${requestKind} handed off for human review (${job.pauseReason ?? "manual_review"}): ${pendingActions} action(s) remain queued; no target effects were executed.`;
  }
  if (job.status === "failed") {
    return executedActions > 0
      ? `Playbook execution failed closed after ${executedActions} allowlisted action(s); review the lifecycle outcome.`
      : "Playbook planning failed closed; no target effects were executed.";
  }
  if (live) {
    return executedActions > 0
      ? `Playbook executed ${executedActions} allowlisted non-destructive action(s); remaining work is a human handoff.`
      : "Live playbook produced a plan only; no target effects were executed.";
  }
  return "Playbook dry-run planning finished; no target effects were executed.";
}

function normalizeToolSelection(tools: string[] | undefined, profile: HuntReconProfile): string[] {
  const defaults = profile === "web" ? WEB_RECON_TOOLS : PASSIVE_RECON_TOOLS;
  const selected = tools && tools.length > 0 ? tools : defaults;
  return [...new Set(selected.map((tool) => tool.trim().toLowerCase()).filter(Boolean))];
}

function reconNextCommands(jobId: string): string[] {
  return [
    `bounty review --job ${jobId}`,
    `bounty actions review --job ${jobId}`,
    `bounty jobs timeline ${jobId}`,
    `bounty evidence verify --job ${jobId}`,
  ];
}

function playbookNextCommands(jobId: string, findingIds: string[], candidateIds: string[] = []): string[] {
  return [
    `bounty review --job ${jobId}`,
    `bounty actions review --job ${jobId}`,
    `bounty evidence verify --job ${jobId}`,
    ...(candidateIds.length > 0 ? [`bounty findings candidates --job ${jobId}`] : []),
    ...candidateIds.flatMap((candidateId) => [
      `bounty findings candidate ${candidateId}`,
      `bounty reports score ${candidateId} --job ${jobId}`,
    ]),
    ...findingIds.flatMap((findingId) => [
      `bounty reports score ${findingId} --job ${jobId}`,
      `bounty reports review ${findingId} --job ${jobId}`,
    ]),
  ];
}

function playbookBlockedNextCommands(jobId: string): string[] {
  return [
    `bounty review --job ${jobId}`,
    `bounty evidence verify --job ${jobId}`,
  ];
}

function playbookChecks(bugClass: BugClass): string[] {
  const common = ["scope guard", "policy gate", "evidence threshold", "duplicate risk"];
  if (bugClass === "js-secrets") return [...common, "public JavaScript secret-like pattern review"];
  if (bugClass === "cors") return [...common, "CORS response header review"];
  if (bugClass === "exposure") return [...common, "safe exposure response review"];
  if (bugClass === "graphql") return [...common, "lab-gated GraphQL introspection review"];
  if (bugClass === "idor") return [...common, "lab-gated adjacent object authorization review"];
  if (bugClass === "ssrf") return [...common, "lab-gated server-side fetch review"];
  return [...common, "manual validation required before reporting"];
}

function playbookActions(bugClass: BugClass): Array<{
  adapter: string;
  actionType: string;
  riskLevel: RiskLevel;
  capability?: string;
  requiresApproval?: boolean;
}> {
  const actions: Array<{
    adapter: string;
    actionType: string;
    riskLevel: RiskLevel;
    capability?: string;
    requiresApproval?: boolean;
  }> = [
    { adapter: "safe-checks", actionType: "http.get", riskLevel: "low" },
  ];
  if (["xss", "idor", "js-secrets"].includes(bugClass)) {
    actions.push({ adapter: "js-analyzer", actionType: "http.get", riskLevel: "low" });
  }
  if (["xss", "ssrf", "idor"].includes(bugClass)) {
    actions.push({
      adapter: "manual-validation",
      actionType: "http.validate",
      riskLevel: "medium",
      capability: "exploit_validation",
      requiresApproval: true,
    });
  }
  if (bugClass === "graphql") {
    actions.push({
      adapter: "manual-validation",
      actionType: "graphql.introspect",
      riskLevel: "medium",
      capability: "exploit_validation",
      requiresApproval: true,
    });
  }
  return actions;
}

function recordStaticPlaybookObservations(
  runtime: Runtime,
  jobId: string,
  bugClass: BugClass,
  target: string,
): ReconObservation[] {
  const observations: ReconObservation[] = [];
  const url = new URL(target);
  for (const [name] of url.searchParams) {
    const kind = parameterKindFor(name, bugClass);
    if (!kind) continue;
    observations.push(runtime.recon.upsert({
      jobId,
      kind: "parameter",
      value: `${url.origin}${url.pathname}?${name}=`,
      sourceAdapter: "hunt-playbook",
      sourceUrl: target,
      scopeAllowed: true,
      confidence: "low",
      riskHint: "low",
      metadata: {
        bugClass,
        parameter: name,
        signal: kind,
        planningOnly: true,
      },
    }));
  }

  if (bugClass === "graphql" && /\/(?:graphql|gql)(?:[/?#]|$)/i.test(url.toString())) {
    observations.push(runtime.recon.upsert({
      jobId,
      kind: "endpoint",
      value: url.toString(),
      sourceAdapter: "hunt-playbook",
      sourceUrl: target,
      scopeAllowed: true,
      confidence: "medium",
      riskHint: "low",
      metadata: {
        bugClass,
        signal: "graphql_route",
        note: "GraphQL-looking route recorded from the target URL; validation requires human handoff.",
        planningOnly: true,
      },
    }));
  }

  return observations;
}

function parameterKindFor(name: string, bugClass: BugClass): string | undefined {
  const normalized = name.toLowerCase();
  if (bugClass === "open-redirect" && /^(next|url|redirect|redirect_uri|return|return_to|continue)$/i.test(normalized)) {
    return "redirect_parameter";
  }
  if (bugClass === "idor" && /^(id|user|account|org|tenant|file|order|invoice)(_?id)?$/i.test(normalized)) {
    return "object_identifier";
  }
  if (bugClass === "ssrf" && /^(url|uri|endpoint|callback|webhook|image|avatar|feed)$/i.test(normalized)) {
    return "server_fetch_parameter";
  }
  if (bugClass === "xss" && /^(q|query|search|s|name|message|return|next)$/i.test(normalized)) {
    return "reflected_input_parameter";
  }
  return undefined;
}
