import type { Runtime } from "../cli/runtime.js";
import { loadProgramFile } from "../core/config/config-loader.js";
import type { JobRecord } from "../core/jobs/job-manager.js";
import { buildProgramAuthoritySnapshot } from "../core/policy/program-authority-snapshot.js";
import { PolicyGate } from "../core/policy/policy-gate.js";
import { ScopeGuard } from "../core/scope/scope-guard.js";
import { BountyPilotError } from "../utils/errors.js";
import { WorkflowRunner, type WorkflowSummary } from "../workflows/run-workflow.js";
import {
  createMissionRecord,
  missionExecutionPlan,
  parseMissionReceipt,
  parseMissionRequest,
  type MissionReceiptV1,
  type MissionRecordV1,
  type MissionRequestV1,
} from "./mission-contract.js";

export type MissionAgentState = MissionReceiptV1["agentState"];
export type MissionJobReceipt = MissionReceiptV1["job"];
/** Absolute local workspace paths are intentionally excluded from Hermes output. */
export type MissionWorkflowReceipt = MissionReceiptV1["workflow"];
export type { MissionReceiptV1 } from "./mission-contract.js";

/**
 * Turns one typed Hermes request into exactly one local WorkflowRunner job.
 * Validation, authority materialization, and scope checks all happen before
 * the workflow is allowed to create any persistent job state.
 */
export class MissionRunner {
  constructor(private readonly runtime: Runtime) {}

  async run(input: unknown): Promise<MissionReceiptV1> {
    const request = parseMissionRequest(input);
    const plan = missionExecutionPlan(request.profile);
    const context = this.materializeCurrentContext(request);
    this.assertTargetAllowed(request, context.scopeGuard);
    this.assertPlanAllowed(request, plan, context.policyGate);

    const mission = createMissionRecord(request, context.authority);
    const workflow = await new WorkflowRunner(this.runtime).run({
      target: request.target,
      mode: plan.mode,
      withComponents: plan.components,
      dryRun: true,
      draftReports: false,
      mission,
    });

    const job = this.runtime.jobs.get(workflow.jobId);
    if (!job || job.type !== "mission" || workflow.mission?.missionDigest !== mission.missionDigest) {
      throw new BountyPilotError("Mission workflow did not produce its authoritative job record.", "MISSION_JOB_INVALID");
    }

    return parseMissionReceipt({
      accepted: job.status !== "failed",
      agentTerminal: true,
      agentState: missionAgentState(job),
      mission,
      job: missionJobReceipt(job),
      workflow: missionWorkflowReceipt(workflow),
      actionIds: this.runtime.actions.list(job.id).map((action) => action.id),
      nextCommands: missionNextCommands(request.program, job.id),
    });
  }

  private materializeCurrentContext(request: MissionRequestV1): {
    authority: MissionRecordV1["authority"];
    scopeGuard: ScopeGuard;
    policyGate: PolicyGate;
  } {
    const loaded = loadProgramFile(this.runtime.paths.programFile);
    if (
      request.program !== this.runtime.config.program ||
      request.program !== loaded.config.program
    ) {
      throw new BountyPilotError(
        "Mission program does not match the locally imported program.",
        "MISSION_PROGRAM_MISMATCH",
      );
    }

    const current = buildProgramAuthoritySnapshot({
      config: loaded.config,
      labAuthorization: loaded.labAuthorization,
    });

    let runtimeAuthority: ReturnType<typeof buildProgramAuthoritySnapshot>;
    try {
      runtimeAuthority = buildProgramAuthoritySnapshot({
        config: this.runtime.config,
        labAuthorization: loaded.labAuthorization,
      });
    } catch {
      throw staleRuntimeAuthority();
    }
    if (
      runtimeAuthority.scopeHash !== current.scopeHash ||
      runtimeAuthority.policyHash !== current.policyHash
    ) {
      throw staleRuntimeAuthority();
    }

    return {
      authority: { scopeHash: current.scopeHash, policyHash: current.policyHash },
      scopeGuard: new ScopeGuard(loaded.config),
      policyGate: new PolicyGate(loaded.config.rules),
    };
  }

  private assertTargetAllowed(request: MissionRequestV1, currentScopeGuard: ScopeGuard): void {
    if (!request.target) {
      return;
    }

    const currentResult = currentScopeGuard.test(request.target);
    const runtimeResult = this.runtime.scopeGuard.test(request.target);
    if (!currentResult.allowed || !runtimeResult.allowed) {
      throw new BountyPilotError(
        "Mission target is not allowed by the locally imported scope.",
        "MISSION_TARGET_OUT_OF_SCOPE",
      );
    }
    if (currentResult.url !== runtimeResult.url || currentResult.url !== request.target) {
      throw staleRuntimeAuthority();
    }
  }

  private assertPlanAllowed(
    request: MissionRequestV1,
    plan: ReturnType<typeof missionExecutionPlan>,
    currentPolicyGate: PolicyGate,
  ): void {
    for (const component of plan.components) {
      const actionType = MISSION_COMPONENT_ACTION_TYPES[component];
      if (!actionType) continue;
      const decision = currentPolicyGate.evaluate({
        mode: plan.mode,
        actionType,
        target: request.target,
        riskLevel: "low",
      });
      if (decision.decision === "block") {
        throw new BountyPilotError(
          "Mission plan is blocked by the current locally imported policy.",
          "MISSION_POLICY_BLOCKED",
        );
      }
    }
  }
}

export async function runMission(runtime: Runtime, input: unknown): Promise<MissionReceiptV1> {
  return new MissionRunner(runtime).run(input);
}

function missionAgentState(job: JobRecord): MissionAgentState {
  if (job.status === "failed") {
    return "blocked";
  }
  if (job.status === "completed") {
    return "human_handoff";
  }
  return "human_action_handoff";
}

function missionJobReceipt(job: JobRecord): MissionJobReceipt {
  return {
    id: job.id,
    type: "mission",
    status: job.status,
    pauseReason: job.pauseReason,
    statusDetail: job.statusDetail,
  };
}

function missionWorkflowReceipt(summary: WorkflowSummary): MissionWorkflowReceipt {
  const { checkpointPath: _checkpointPath, summaryPath: _summaryPath, ...receipt } = summary;
  return receipt as MissionWorkflowReceipt;
}

function missionNextCommands(program: string, jobId: string): string[] {
  const root = `bounty --program ${program}`;
  return [
    `${root} review --job ${jobId} --json`,
    `${root} actions list --job ${jobId} --json`,
    `${root} results --job ${jobId} --json`,
  ];
}

function staleRuntimeAuthority(): BountyPilotError {
  return new BountyPilotError(
    "Mission runtime authority is stale; recreate the local runtime and retry.",
    "MISSION_RUNTIME_AUTHORITY_STALE",
  );
}

const MISSION_COMPONENT_ACTION_TYPES: Readonly<Record<string, string>> = Object.freeze({
  "d-research-skill": "research.public",
  "safe-checks": "http.get",
  "js-analyzer": "http.get",
  playwright: "browser.navigate",
  planner: "agent.plan",
});
