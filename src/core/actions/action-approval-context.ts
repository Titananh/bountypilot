// P0.2 Packet 0 — Action binding and approval context.
//
// The action binding is the deterministic projection of an
// `ActionRecord` plus its `JobRecord`, the original `PolicyAction`, the
// resolved `AdapterCapabilityMetadata`, the normalized target, the
// policy decision, and the closed `SafeIntegrationExecutionPolicy`.
// Approval reviewers, the executor, and the audit log all compute the
// same binding from the same input and compare hashes, so a single
// change in any bound field invalidates the approval.
//
// Hash contract:
//
//   actionHash  = SHA256( "bountypilot/action-binding/v1" || 0x00 ||
//                         canonicalJson(ActionBinding) )
//   contextHash = SHA256( "bountypilot/approval-context/v1" || 0x00 ||
//                         canonicalJson({ scopeHash, policyHash,
//                         actionHash }) )
//
// The projection is intentionally narrow:
//   * mutable queue status and timestamps are never bound;
//   * raw metadata is never stored on the binding; only its SHA-256
//     digest is bound, so the binding does not leak adapter internals;
//   * the safe integration projection is whitelisted; command, args,
//     endpoint, headers, options, and any other passthrough fields
//     that could carry credentials or absolute paths are dropped;
//   * entrypoints must be a normalized safe relative identifier
//     (no absolute paths, no `..` escape); any allowed SHA-256 field
//     must be a 64-character lowercase hex digest.

import { createHash } from "node:crypto";
import type { ExecutionMode, PolicyDecision, RiskLevel } from "../../types.js";
import type { ActionRecord } from "../actions/action-queue.js";
import type { JobRecord } from "../jobs/job-manager.js";
import type { AdapterCapabilityMetadata } from "../../integrations/adapters/adapter.js";
import { canonicalize, sha256Canonical } from "../../utils/canonical-json.js";
import { BountyPilotError } from "../../utils/errors.js";

export const ACTION_BINDING_SCHEMA_VERSION = "action-binding/v1";
export const ACTION_SEMANTICS_VERSION = "action/v1";
export const ACTION_HASH_DOMAIN = "bountypilot/action-binding/v1";
export const CONTEXT_HASH_DOMAIN = "bountypilot/approval-context/v1";

const EXECUTION_MODE_VALUES: ReadonlySet<string> = new Set([
  "passive",
  "safe",
  "deep-safe",
  "lab-offensive",
]);
const RISK_LEVEL_VALUES: ReadonlySet<string> = new Set(["low", "medium", "high"]);
const POLICY_DECISION_VALUES: ReadonlySet<string> = new Set([
  "allow",
  "block",
  "require_approval",
]);

export interface PolicyActionInput {
  mode: ExecutionMode;
  actionType: string;
  target?: string;
  riskLevel?: RiskLevel;
  stateChanging?: boolean;
  destructive?: boolean;
  capability?: string;
  requiresApprovalByDefault?: boolean;
  labModeEnabled?: boolean;
}

export interface SafeIntegrationExecutionPolicy {
  name: string;
  type: string;
  enabled: boolean;
  allowExecute: boolean;
  transport: string | null;
  launcherSha256: string;
  endpointSha256: string | null;
  package: string | null;
  packageVersion: string | null;
  entrypoint: string | null;
  entrypointSha256: string | null;
  packageJsonSha256: string | null;
  timeoutMs: number;
  capabilities: string[];
  blockedCapabilities: string[];
}

export interface CapabilityEnforcementInput extends Partial<AdapterCapabilityMetadata> {
  id: string;
  actionType: string;
  riskLevel: RiskLevel;
  allowedModes: ExecutionMode[];
  // The optional fields are kept for callers that pass a full
  // `AdapterCapabilityMetadata`. They are whitelisted/omitted by
  // `buildActionBinding` according to the snapshot contract.
  title?: string;
  description?: string;
  produces?: string[];
}

export interface ActionBindingInput {
  action: ActionRecord;
  job: JobRecord;
  normalizedTarget: string | null;
  requiredForCompletion: boolean;
  policyAction: PolicyActionInput;
  capabilityEnforcement: CapabilityEnforcementInput;
  policyDecision: PolicyDecision;
  integrationExecutionPolicy: SafeIntegrationExecutionPolicy | null;
}

export interface ActionBinding {
  schemaVersion: typeof ACTION_BINDING_SCHEMA_VERSION;
  semanticsVersion: typeof ACTION_SEMANTICS_VERSION;
  action: {
    id: string;
    jobId: string;
    adapter: string;
    actionType: string;
    target: string | null;
    normalizedTarget: string | null;
    riskLevel: RiskLevel;
    requiresApproval: boolean;
    requiredForCompletion: boolean;
  };
  job: {
    mode: ExecutionMode;
    target: string | null;
  };
  policyAction: {
    mode: ExecutionMode;
    actionType: string;
    target: string | null;
    riskLevel: RiskLevel | null;
    stateChanging: boolean | null;
    destructive: boolean | null;
    capability: string | null;
    requiresApprovalByDefault: boolean | null;
    labModeEnabled: boolean | null;
  };
  capabilityEnforcement: {
    id: string;
    actionType: string;
    riskLevel: RiskLevel;
    allowedModes: ExecutionMode[];
    requiresTarget: boolean | null;
    requiresScope: boolean | null;
    stateChanging: boolean | null;
    destructive: boolean | null;
    requiresApprovalByDefault: boolean | null;
    blockedByDefault: boolean | null;
    scopedPostcondition: "current_or_final_url_in_scope" | null;
    mcpTools: string[];
  };
  metadataSha256: string;
  policyDecision: PolicyDecision;
  integrationExecutionPolicy: SafeIntegrationExecutionPolicy | null;
}

export interface ContextHashInput {
  scopeHash: string;
  policyHash: string;
  actionHash: string;
}

export function buildActionBinding(input: ActionBindingInput): ActionBinding {
  assertActionBindingInput(input);
  return {
    schemaVersion: ACTION_BINDING_SCHEMA_VERSION,
    semanticsVersion: ACTION_SEMANTICS_VERSION,
    action: projectAction(input),
    job: projectJob(input.job),
    policyAction: projectPolicyAction(input.policyAction),
    capabilityEnforcement: projectCapabilityEnforcement(input.capabilityEnforcement),
    metadataSha256: computeMetadataSha256(input.action.metadata),
    policyDecision: input.policyDecision,
    integrationExecutionPolicy: projectIntegrationExecutionPolicy(input.integrationExecutionPolicy),
  };
}

export function computeActionHash(binding: ActionBinding): string {
  return sha256Canonical(binding, ACTION_HASH_DOMAIN);
}

export function computeContextHash(input: ContextHashInput): string {
  for (const [field, value] of [
    ["scopeHash", input.scopeHash],
    ["policyHash", input.policyHash],
    ["actionHash", input.actionHash],
  ] as const) {
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
      throw new BountyPilotError(
        `Context hash field ${field} must be a 64-character lowercase hex digest`,
        "AUTHORITY_HASH_INVALID",
      );
    }
  }
  return sha256Canonical(
    { scopeHash: input.scopeHash, policyHash: input.policyHash, actionHash: input.actionHash },
    CONTEXT_HASH_DOMAIN,
  );
}

function projectAction(input: ActionBindingInput): ActionBinding["action"] {
  return {
    id: input.action.id,
    jobId: input.action.jobId as string,
    adapter: input.action.adapter,
    actionType: input.action.actionType,
    target: input.action.target ?? null,
    normalizedTarget: input.normalizedTarget,
    riskLevel: input.action.riskLevel,
    requiresApproval: input.action.requiresApproval,
    requiredForCompletion: input.requiredForCompletion,
  };
}

function projectJob(job: JobRecord): ActionBinding["job"] {
  return {
    mode: job.mode,
    target: job.target ?? null,
  };
}

function projectPolicyAction(policyAction: PolicyActionInput): ActionBinding["policyAction"] {
  return {
    mode: policyAction.mode,
    actionType: policyAction.actionType,
    target: policyAction.target ?? null,
    riskLevel: policyAction.riskLevel ?? null,
    stateChanging: policyAction.stateChanging ?? null,
    destructive: policyAction.destructive ?? null,
    capability: policyAction.capability ?? null,
    requiresApprovalByDefault: policyAction.requiresApprovalByDefault ?? null,
    labModeEnabled: policyAction.labModeEnabled ?? null,
  };
}

function projectCapabilityEnforcement(
  enforcement: CapabilityEnforcementInput,
): ActionBinding["capabilityEnforcement"] {
  return {
    id: enforcement.id,
    actionType: enforcement.actionType,
    riskLevel: enforcement.riskLevel,
    allowedModes: normalizeExecutionModes(enforcement.allowedModes),
    requiresTarget: enforcement.requiresTarget ?? null,
    requiresScope: enforcement.requiresScope ?? null,
    stateChanging: enforcement.stateChanging ?? null,
    destructive: enforcement.destructive ?? null,
    requiresApprovalByDefault: enforcement.requiresApprovalByDefault ?? null,
    blockedByDefault: enforcement.blockedByDefault ?? null,
    scopedPostcondition: enforcement.scopedPostcondition ?? null,
    mcpTools: normalizeStringArray(enforcement.mcpTools),
  };
}

function projectIntegrationExecutionPolicy(
  policy: SafeIntegrationExecutionPolicy | null,
): SafeIntegrationExecutionPolicy | null {
  if (policy === null) return null;
  const normalizedEntrypoint = assertSafeIntegrationExecutionPolicy(policy);
  return {
    name: policy.name,
    type: policy.type,
    enabled: policy.enabled,
    allowExecute: policy.allowExecute,
    transport: policy.transport,
    launcherSha256: policy.launcherSha256,
    endpointSha256: policy.endpointSha256,
    package: policy.package,
    packageVersion: policy.packageVersion,
    entrypoint: normalizedEntrypoint,
    entrypointSha256: policy.entrypointSha256,
    packageJsonSha256: policy.packageJsonSha256,
    timeoutMs: policy.timeoutMs,
    capabilities: normalizeStringArray(policy.capabilities),
    blockedCapabilities: normalizeStringArray(policy.blockedCapabilities),
  };
}

function computeMetadataSha256(metadata: Record<string, unknown> | undefined): string {
  const source = metadata ?? {};
  const canonical = canonicalize(source);
  return createHash("sha256").update(canonical).digest("hex");
}

function normalizeStringArray(values: readonly string[] | undefined): string[] {
  if (!Array.isArray(values)) return [];
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") {
      throw new BountyPilotError(
        "Set-like projection arrays must contain only strings",
        "ACTION_BINDING_INVALID",
      );
    }
    const trimmed = value.trim();
    if (trimmed.length === 0) continue;
    seen.add(trimmed);
  }
  return [...seen].sort();
}

function normalizeExecutionModes(values: readonly ExecutionMode[] | undefined): ExecutionMode[] {
  const normalized = normalizeStringArray(values);
  for (const mode of normalized) {
    if (!EXECUTION_MODE_VALUES.has(mode)) {
      throw new BountyPilotError(
        "Capability enforcement contains an unsupported execution mode",
        "ACTION_BINDING_INVALID",
      );
    }
  }
  return normalized as ExecutionMode[];
}

function assertActionBindingInput(input: ActionBindingInput): void {
  if (!input || !input.action || !input.job) {
    throw new BountyPilotError(
      "Action binding input must include an action and a job",
      "ACTION_BINDING_INVALID",
    );
  }
  if (typeof input.action.id !== "string" || input.action.id.length === 0) {
    throw new BountyPilotError(
      "Action binding input must include an action id",
      "ACTION_BINDING_INVALID",
    );
  }
  if (typeof input.action.jobId !== "string" || input.action.jobId.length === 0) {
    throw new BountyPilotError(
      "Action binding input must include a concrete action.jobId referencing the job.id",
      "ACTION_BINDING_INVALID",
    );
  }
  if (typeof input.job.id !== "string" || input.job.id.length === 0) {
    throw new BountyPilotError(
      "Action binding input must include a concrete job.id",
      "ACTION_BINDING_INVALID",
    );
  }
  if (input.action.jobId !== input.job.id) {
    throw new BountyPilotError(
      "Action binding input action.jobId must equal job.id",
      "ACTION_BINDING_INVALID",
    );
  }
  if (
    !input.capabilityEnforcement ||
    typeof input.capabilityEnforcement.id !== "string" ||
    input.capabilityEnforcement.id.length === 0
  ) {
    throw new BountyPilotError(
      "Action binding input must include a capabilityEnforcement identifier",
      "ACTION_BINDING_INVALID",
    );
  }
  if (!input.policyAction || typeof input.policyAction.mode !== "string") {
    throw new BountyPilotError(
      "Action binding input must include a policyAction with an execution mode",
      "ACTION_BINDING_INVALID",
    );
  }
  if (
    !EXECUTION_MODE_VALUES.has(input.job.mode) ||
    !EXECUTION_MODE_VALUES.has(input.policyAction.mode)
  ) {
    throw new BountyPilotError(
      "Action binding input contains an unsupported execution mode",
      "ACTION_BINDING_INVALID",
    );
  }
  if (
    !RISK_LEVEL_VALUES.has(input.action.riskLevel) ||
    !RISK_LEVEL_VALUES.has(input.capabilityEnforcement.riskLevel) ||
    (input.policyAction.riskLevel !== undefined &&
      !RISK_LEVEL_VALUES.has(input.policyAction.riskLevel))
  ) {
    throw new BountyPilotError(
      "Action binding input contains an unsupported risk level",
      "ACTION_BINDING_INVALID",
    );
  }
  if (!POLICY_DECISION_VALUES.has(input.policyDecision)) {
    throw new BountyPilotError(
      "Action binding input contains an unsupported policy decision",
      "ACTION_BINDING_INVALID",
    );
  }
}

function assertSafeIntegrationExecutionPolicy(policy: SafeIntegrationExecutionPolicy): string | null {
  assertLowercaseHex64("launcherSha256", policy.launcherSha256, true);
  assertLowercaseHex64("endpointSha256", policy.endpointSha256, false);
  assertLowercaseHex64("entrypointSha256", policy.entrypointSha256, false);
  assertLowercaseHex64("packageJsonSha256", policy.packageJsonSha256, false);
  if (policy.entrypoint === null) return null;
  if (typeof policy.entrypoint !== "string" || policy.entrypoint.length === 0) {
    throw new BountyPilotError(
      "Safe integration entrypoint must be a non-empty string or null",
      "INTEGRATION_EXECUTION_POLICY_INVALID",
    );
  }
  const normalized = normalizeSafeEntrypoint(policy.entrypoint);
  if (normalized.length === 0) {
    throw new BountyPilotError(
      "Safe integration entrypoint is empty after normalization",
      "INTEGRATION_EXECUTION_POLICY_INVALID",
    );
  }
  if (/[\u0000-\u001F\u007F]/.test(normalized)) {
    throw new BountyPilotError(
      "Safe integration entrypoint must not contain control characters",
      "INTEGRATION_EXECUTION_POLICY_INVALID",
    );
  }
  if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized)) {
    throw new BountyPilotError(
      "Safe integration entrypoint must be a safe relative identifier",
      "INTEGRATION_EXECUTION_POLICY_INVALID",
    );
  }
  if (normalized.includes(":")) {
    throw new BountyPilotError(
      "Safe integration entrypoint must not contain a Windows drive or alternate data stream separator",
      "INTEGRATION_EXECUTION_POLICY_INVALID",
    );
  }
  const segments = normalized.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === "." || segment === "..") {
      throw new BountyPilotError(
        "Safe integration entrypoint must not contain empty, '.', or '..' segments",
        "INTEGRATION_EXECUTION_POLICY_INVALID",
      );
    }
  }
  return normalized;
}

function normalizeSafeEntrypoint(value: string): string {
  // Windows-style entrypoints written as `.\dist\cli.js` are common in
  // audit artifacts; canonicalize them to the POSIX relative form so
  // the resulting actionHash is identical to the forward-slash
  // canonical form. We strip leading `./` segments after the
  // backslash conversion so that a chain of redundant prefixes (e.g.
  // `././dist/cli.js`) still reduces to `dist/cli.js`, but internal
  // `./` and `..` segments are preserved and rejected by the segment
  // check below.
  let normalized = value.replaceAll("\\", "/");
  while (normalized.startsWith("./")) {
    normalized = normalized.slice(2);
  }
  return normalized;
}

function assertLowercaseHex64(field: string, value: string | null, required: boolean): void {
  if (value === null) {
    if (required) {
      throw new BountyPilotError(
        `Safe integration ${field} is required`,
        "INTEGRATION_EXECUTION_POLICY_INVALID",
      );
    }
    return;
  }
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new BountyPilotError(
      `Safe integration ${field} must be a 64-character lowercase hex digest`,
      "INTEGRATION_EXECUTION_POLICY_INVALID",
    );
  }
}
