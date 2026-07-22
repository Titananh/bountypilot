import { z } from "zod";
import { PROGRAM_NAME_PATTERN } from "../core/config/program-schema.js";
import type { ExecutionMode } from "../types.js";
import { sha256Canonical } from "../utils/canonical-json.js";
import { BountyPilotError } from "../utils/errors.js";

export const MISSION_REQUEST_SCHEMA_VERSION = "bountypilot/mission-request/v1" as const;
export const MISSION_RECORD_SCHEMA_VERSION = "bountypilot/mission-record/v1" as const;
export const MISSION_DIGEST_MATERIAL_SCHEMA_VERSION = "bountypilot/mission-digest-material/v1" as const;
export const MISSION_DIGEST_DOMAIN = "bountypilot/mission/v1" as const;

export const MissionGoalV1Schema = z.literal("local-report-draft");
export const MissionProfileV1Schema = z.enum(["recon", "web", "validate"]);
export const MissionSessionClassV1Schema = z.enum(["normal", "one-shot", "yolo", "approval-bypassed"]);

const MissionTargetV1Schema = z
  .string()
  .trim()
  .min(1)
  .max(2_048)
  .superRefine((value, context) => {
    if (/[\u0000-\u001F\u007F]/u.test(value)) {
      context.addIssue({ code: "custom", message: "Mission target contains control characters" });
      return;
    }

    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      context.addIssue({ code: "custom", message: "Mission target must be an absolute HTTP(S) URL" });
      return;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      context.addIssue({ code: "custom", message: "Mission target must use HTTP or HTTPS" });
    }
    if (parsed.username.length > 0 || parsed.password.length > 0) {
      context.addIssue({ code: "custom", message: "Mission target must not contain credentials" });
    }
  })
  .transform((value) => new URL(value).toString());

/**
 * The only request envelope accepted from Hermes. It intentionally has no
 * free-form prompt, raw argv, tool list, live flag, submission flag, or
 * caller-supplied scope/policy assertions.
 */
export const MissionRequestV1Schema = z
  .object({
    schemaVersion: z.literal(MISSION_REQUEST_SCHEMA_VERSION),
    origin: z.literal("hermes"),
    program: z.string().min(1).max(128).regex(PROGRAM_NAME_PATTERN),
    goal: MissionGoalV1Schema,
    profile: MissionProfileV1Schema,
    sessionClass: MissionSessionClassV1Schema,
    target: MissionTargetV1Schema.optional(),
    constraints: z
      .object({
        liveTargetEffects: z.literal(false),
        automaticSubmission: z.literal(false),
      })
      .strict(),
  })
  .strict();

export type MissionRequestV1 = z.infer<typeof MissionRequestV1Schema>;
export type MissionGoalV1 = MissionRequestV1["goal"];
export type MissionProfileV1 = MissionRequestV1["profile"];
export type MissionSessionClassV1 = MissionRequestV1["sessionClass"];

const LowercaseNonzeroHash64Schema = z
  .string()
  .regex(/^[0-9a-f]{64}$/u)
  .refine((value) => value !== "0".repeat(64), "Authority hash must not be all zeroes");

export const MissionAuthorityV1Schema = z
  .object({
    scopeHash: LowercaseNonzeroHash64Schema,
    policyHash: LowercaseNonzeroHash64Schema,
  })
  .strict();

export type MissionAuthorityV1 = z.infer<typeof MissionAuthorityV1Schema>;

export const MissionRecordV1Schema = z
  .object({
    schemaVersion: z.literal(MISSION_RECORD_SCHEMA_VERSION),
    request: MissionRequestV1Schema,
    missionDigest: LowercaseNonzeroHash64Schema,
    authority: MissionAuthorityV1Schema,
  })
  .strict()
  .superRefine((record, context) => {
    if (record.missionDigest !== computeMissionDigest(record.request, record.authority)) {
      context.addIssue({ code: "custom", message: "Mission record digest mismatch" });
    }
  });

export type MissionRecordV1 = z.infer<typeof MissionRecordV1Schema>;

const MissionJobStatusV1Schema = z.enum(["queued", "running", "paused", "failed", "completed"]);
const MissionPauseReasonV1Schema = z.enum([
  "approval_required",
  "execution_ready",
  "policy_drift",
  "policy_blocked",
  "reconciliation_required",
  "budget_exhausted",
  "manual_review",
]);

const MissionActionCountsV1Schema = z
  .object({
    total: z.number().int().nonnegative(),
    pending: z.number().int().nonnegative(),
    approved: z.number().int().nonnegative(),
    running: z.number().int().nonnegative(),
    executed: z.number().int().nonnegative(),
    blocked: z.number().int().nonnegative(),
    failed: z.number().int().nonnegative(),
    outcome_unknown: z.number().int().nonnegative(),
  })
  .strict();

const MissionWorkflowPhaseV1Schema = z
  .object({
    name: z.string(),
    status: z.enum(["completed", "failed", "skipped", "planned"]),
    detail: z.string(),
    target: MissionTargetV1Schema.optional(),
  })
  .strict();

const MissionWorkflowReceiptV1Schema = z
  .object({
    checkpointVersion: z.number().int().positive().optional(),
    jobId: z.string().min(1),
    status: MissionJobStatusV1Schema,
    program: z.string().min(1).max(128).regex(PROGRAM_NAME_PATTERN),
    target: MissionTargetV1Schema.optional(),
    mode: z.enum(["passive", "safe", "deep-safe"]),
    dryRun: z.literal(true),
    draftReports: z.literal(false),
    components: z.array(z.string()),
    seeds: z.array(MissionTargetV1Schema),
    skippedScopeRules: z.array(z.string()),
    phases: z.array(MissionWorkflowPhaseV1Schema),
    candidatesCreated: z.number().int().nonnegative(),
    findingsCreated: z.number().int().nonnegative(),
    evidenceCreated: z.number().int().nonnegative(),
    actionsPlanned: z.number().int().nonnegative(),
    actionCounts: MissionActionCountsV1Schema,
    reportsDrafted: z.literal(0),
    plannerCandidates: z
      .object({
        endpointCandidates: z.array(MissionTargetV1Schema),
        jsAssets: z.array(MissionTargetV1Schema),
      })
      .strict()
      .optional(),
    plannerLoop: z.never().optional(),
    startedAt: z.string().min(1),
    updatedAt: z.string().min(1),
    completedAt: z.string().min(1).optional(),
    failedAt: z.string().min(1).optional(),
    resumedFromJobId: z.string().min(1).optional(),
    resumeSkippedPhases: z.array(z.string()).optional(),
    resumeSkippedWork: z
      .array(
        z
          .object({
            phase: z.string(),
            target: MissionTargetV1Schema.optional(),
          })
          .strict(),
      )
      .optional(),
    mission: MissionRecordV1Schema,
  })
  .strict();

export const MissionReceiptV1Schema = z
  .object({
    accepted: z.boolean(),
    agentTerminal: z.literal(true),
    agentState: z.enum(["human_action_handoff", "human_handoff", "blocked"]),
    mission: MissionRecordV1Schema,
    job: z
      .object({
        id: z.string().min(1),
        type: z.literal("mission"),
        status: MissionJobStatusV1Schema,
        pauseReason: MissionPauseReasonV1Schema.nullable(),
        statusDetail: z.string().nullable(),
      })
      .strict(),
    workflow: MissionWorkflowReceiptV1Schema,
    actionIds: z.array(z.string().min(1)),
    nextCommands: z.array(z.string().min(1)).min(1),
  })
  .strict()
  .superRefine((receipt, context) => {
    if (receipt.workflow.jobId !== receipt.job.id) {
      context.addIssue({ code: "custom", message: "Receipt workflow/job id mismatch" });
    }
    if (
      receipt.workflow.mission.missionDigest !== receipt.mission.missionDigest ||
      receipt.workflow.status !== receipt.job.status
    ) {
      context.addIssue({ code: "custom", message: "Receipt mission or job status mismatch" });
    }
    const expectedAgentState = receipt.job.status === "failed"
      ? "blocked"
      : receipt.job.status === "completed"
        ? "human_handoff"
        : "human_action_handoff";
    if (receipt.agentState !== expectedAgentState || receipt.accepted !== (receipt.job.status !== "failed")) {
      context.addIssue({ code: "custom", message: "Receipt handoff state is inconsistent" });
    }
  });

export type MissionReceiptV1 = z.infer<typeof MissionReceiptV1Schema>;

export interface MissionExecutionPlan {
  mode: Exclude<ExecutionMode, "lab-offensive">;
  components: string[];
}

const MISSION_PROFILE_PLANS = {
  recon: {
    mode: "safe",
    components: ["d-research-skill", "safe-checks", "js-analyzer", "planner"],
  },
  web: {
    mode: "deep-safe",
    components: ["d-research-skill", "safe-checks", "js-analyzer", "playwright", "planner", "triage"],
  },
  validate: {
    mode: "safe",
    components: ["safe-checks", "js-analyzer", "triage"],
  },
} as const satisfies Readonly<
  Record<MissionProfileV1, { mode: Exclude<ExecutionMode, "lab-offensive">; components: readonly string[] }>
>;

export function parseMissionRequest(input: unknown): MissionRequestV1 {
  const parsed = MissionRequestV1Schema.safeParse(input);
  if (!parsed.success) {
    throw new BountyPilotError(
      "Mission request does not match bountypilot/mission-request/v1.",
      "MISSION_REQUEST_INVALID",
    );
  }
  return parsed.data;
}

export function missionExecutionPlan(profile: MissionProfileV1): MissionExecutionPlan {
  const plan = MISSION_PROFILE_PLANS[profile];
  return { mode: plan.mode, components: [...plan.components] };
}

export function computeMissionDigest(requestInput: unknown, authorityInput: unknown): string {
  const request = parseMissionRequest(requestInput);
  const authority = parseMissionAuthority(authorityInput);
  return sha256Canonical(
    {
      schemaVersion: MISSION_DIGEST_MATERIAL_SCHEMA_VERSION,
      request,
      authority,
    },
    MISSION_DIGEST_DOMAIN,
  );
}

export function createMissionRecord(requestInput: unknown, authorityInput: unknown): MissionRecordV1 {
  const request = parseMissionRequest(requestInput);
  const authority = parseMissionAuthority(authorityInput);
  return {
    schemaVersion: MISSION_RECORD_SCHEMA_VERSION,
    request,
    missionDigest: computeMissionDigest(request, authority),
    authority,
  };
}

export function parseMissionRecord(input: unknown): MissionRecordV1 {
  const parsed = MissionRecordV1Schema.safeParse(input);
  if (!parsed.success) {
    throw invalidMissionRecord();
  }
  const expectedDigest = computeMissionDigest(parsed.data.request, parsed.data.authority);
  if (parsed.data.missionDigest !== expectedDigest) {
    throw invalidMissionRecord();
  }
  return parsed.data;
}

export function parseMissionReceipt(input: unknown): MissionReceiptV1 {
  const parsed = MissionReceiptV1Schema.safeParse(input);
  if (!parsed.success) {
    throw new BountyPilotError("Mission receipt violates its public safety contract.", "MISSION_RECEIPT_INVALID");
  }
  return parsed.data;
}

export function isMissionRecordV1(input: unknown): input is MissionRecordV1 {
  try {
    parseMissionRecord(input);
    return true;
  } catch {
    return false;
  }
}

function parseMissionAuthority(input: unknown): MissionAuthorityV1 {
  const parsed = MissionAuthorityV1Schema.safeParse(input);
  if (!parsed.success) {
    throw new BountyPilotError("Mission authority hashes are malformed.", "MISSION_AUTHORITY_INVALID");
  }
  return parsed.data;
}

function invalidMissionRecord(): BountyPilotError {
  return new BountyPilotError("Mission record is malformed or has an invalid digest.", "MISSION_RECORD_INVALID");
}
