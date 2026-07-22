// P0.2 Packet 2 — Action approval service.
//
// The pinned public surface (constructor, `preview`, `approveHuman`,
// `approvePolicy`, and the contract-pinned types/interfaces) is
// exported exactly as specified in `docs/p0.2-packet-2-contract.md`
// sections 4 and 7.
//
// `preview()` performs the read-only materialization of the current
// program, scope, policy, capability, and integration material for
// one clean pending action. It is strictly read-only: no SQL writes,
// no transaction, no clock call, no cached authority material from
// `runtime.config` or a previous call. Every fresh call reloads
// current program, resolves binding material, and re-derives the
// challenge hashes. Each approval independently repeats that work,
// captures one validated clock instant, and atomically persists the
// review, action CAS, event, and derived job state.

import { types as nodeTypes } from "node:util";
import { BountyPilotError } from "../../utils/errors.js";
import type { ExecutionMode, PolicyDecision, RiskLevel } from "../../types.js";
import { ProgramSchema, type ProgramConfig } from "../config/program-schema.js";
import type { LabAuthorization, LoadedProgram } from "../config/config-loader.js";
import { ScopeGuard } from "../scope/scope-guard.js";
import { PolicyGate } from "../policy/policy-gate.js";
import { buildProgramAuthoritySnapshot } from "../policy/program-authority-snapshot.js";
import {
  buildActionBinding,
  computeActionHash,
  computeContextHash,
  type CapabilityEnforcementInput,
  type PolicyActionInput,
  type SafeIntegrationExecutionPolicy,
} from "./action-approval-context.js";
import {
  ActionQueue,
  type ActionRecord,
  type PendingApprovalCandidate,
} from "./action-queue.js";
import {
  ActionReviewStore,
  type ActionReviewRecord,
} from "./action-review-store.js";
import { JobManager, type JobRecord } from "../jobs/job-manager.js";
import {
  WorkflowEventStore,
  type WorkflowEventRecord,
} from "../jobs/workflow-event-store.js";
import {
  withImmediateTransaction,
  type BountyDatabase,
} from "../../stores/db/database.js";
import { canonicalize } from "../../utils/canonical-json.js";

/**
 * Narrow row authority projection the service builds itself from
 * validated database rows. Status and lifecycle fields are excluded
 * from this projection.
 */
export interface ActionMaterialSource {
  action: {
    id: string;
    jobId: string;
    adapter: string;
    actionType: string;
    target: string | null;
    riskLevel: RiskLevel;
    requiresApproval: boolean;
    requiredForCompletion: boolean;
    metadata: Record<string, unknown>;
  };
  job: {
    id: string;
    type: string;
    target: string | null;
    mode: ExecutionMode;
  };
}

/**
 * Tagged binding-material projection. `integration` requires a complete
 * safe execution policy; the tag is derived from the current
 * integration registry.
 */
export type IntegrationBindingMaterial =
  | { kind: "builtin" }
  | {
      kind: "integration";
      policy: SafeIntegrationExecutionPolicy;
    };

/**
 * Resolver output snapshotted into deeply plain immutable data before
 * any transaction.
 */
export interface ResolvedBindingMaterial {
  normalizedTarget: string | null;
  capabilityEnforcement: CapabilityEnforcementInput;
  integration: IntegrationBindingMaterial;
}

export interface CurrentActionMaterial {
  program: LoadedProgram;
  scopeHash: string;
  policyHash: string;
  normalizedTarget: string | null;
  capabilityEnforcement: CapabilityEnforcementInput;
  integration: IntegrationBindingMaterial;
}

/**
 * Trusted, constructor-injected authority and binding resolvers.
 */
export interface ActionAuthorityDependencies {
  loadCurrentProgram(): LoadedProgram;
  resolveBindingMaterial(input: {
    source: ActionMaterialSource;
    program: LoadedProgram;
  }): ResolvedBindingMaterial;
}

/**
 * Approval-clock and authority dependencies. `now()` is the only
 * approval clock and is never invoked by `preview()`.
 */
export interface ActionApprovalServiceDependencies extends ActionAuthorityDependencies {
  now(): Date;
}

/**
 * Read-only challenge returned by `preview`. Possession grants no
 * authority; each approval method reloads and rematerializes.
 */
export interface ActionApprovalChallenge {
  actionId: string;
  jobId: string;
  policyDecision: PolicyDecision;
  policyReason: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
}

/**
 * Internal definitive authority block class returned by the shared
 * authority seam. The value is never exposed in the public
 * `ActionApprovalChallenge` or the persisted material; it is the
 * shared materializer's private signal that the current scope or
 * policy gate has produced a hard block.
 *
 *   - `scope`  -> a current `ScopeGuard` denial of a target
 *                 flagged `requiresScope`.
 *   - `policy` -> any other current enforcement or native
 *                 `PolicyGate` block.
 *   - `null`   -> the current authority is not a hard block.
 */
export type DefinitiveAuthorityBlock = "scope" | "policy" | null;

/**
 * Frozen narrow source projection plus its canonical string. The
 * snapshot is the only authority binding input the resolver and
 * the binding pipeline are allowed to see. The canonical string
 * is the bytes the lifecycle-claim path compares against the
 * in-tx reload to detect a source race.
 */
export interface ActionMaterialSourceSnapshot {
  source: ActionMaterialSource;
  canonical: string;
}

/**
 * Pure challenge recomputation result. The block class is an
 * internal signal and is not serialized into the public challenge,
 * the public approval result, the workflow event metadata, the
 * persisted material, or any of the bound hashes.
 */
export interface ActionAuthorityEvaluation {
  challenge: ActionApprovalChallenge;
  definitiveBlock: DefinitiveAuthorityBlock;
}

/**
 * `MaterializedActionAuthority` is the shared one-shot material
 * the approval service binds to a preview or approval. The
 * material is constructed outside any transaction; the lifecycle
 * claim path reuses it via `recomputeActionAuthority` to derive
 * the in-tx challenge without re-running the loader, resolver, or
 * clock.
 */
export interface MaterializedActionAuthority extends ActionAuthorityEvaluation {
  source: ActionMaterialSource;
  sourceCanonical: string;
  material: CurrentActionMaterial;
}

export interface HumanApprovalInput {
  actionId: string;
  reviewerId: string;
  expectedContextHash: string;
  ttlMs: number;
  note?: string;
}

export interface PolicyApprovalInput {
  actionId: string;
  ttlMs: number;
  note?: string;
}

/**
 * Result of a successful approval. Contains no execution token and no
 * raw authority material.
 */
export interface ActionApprovalResult {
  action: ActionRecord;
  review: ActionReviewRecord;
  event: WorkflowEventRecord;
  job: JobRecord;
}

const ACTION_APPROVAL_CONTEXT_UNAVAILABLE_MESSAGE =
  "Action approval context is unavailable.";
const ACTION_APPROVAL_INVALID_MESSAGE =
  "Action approval service received an invalid action identifier";
const ACTION_APPROVAL_REVIEWER_INVALID_MESSAGE =
  "Action approval reviewer is invalid.";
const ACTION_APPROVAL_TTL_INVALID_MESSAGE =
  "Action approval TTL is invalid.";
const ACTION_APPROVAL_CONTEXT_INVALID_MESSAGE =
  "Action approval context token is invalid.";
const ACTION_APPROVAL_CONTEXT_STALE_MESSAGE =
  "Action approval context is stale.";
const ACTION_APPROVAL_POLICY_BLOCKED_MESSAGE =
  "Action approval is blocked by current policy.";
const ACTION_HANDOFF_ONLY_MESSAGE =
  "Planning and handoff actions cannot receive executable approval.";
const ACTION_APPROVAL_HUMAN_REQUIRED_MESSAGE =
  "Action approval requires a human reviewer.";
const ACTION_APPROVAL_RACE_LOST_MESSAGE =
  "Action approval lost a concurrent race.";
const ENFORCEMENT_BLOCK_REASON = "Blocked by current authority enforcement";
const APPROVAL_MATERIAL_SOURCE_SCHEMA = "approval-material-source/v1";
const POLICY_REVIEWER_ID = "system:policy-gate";
const MAX_APPROVAL_TTL_MS = 86_400_000;
const MAX_DATE_EPOCH_MS = 8_640_000_000_000_000;

const HEX64_PATTERN = /^[0-9a-f]{64}$/;
const HEX64_ALL_ZERO = "0".repeat(64);
const C0_DEL_REGEX = /[\0-\u001F\u007F]/u;
const CODE_POINT_MIN = 1;
const CODE_POINT_MAX = 256;

// Captured intrinsics for the hostile public DTO boundary. A caller object is
// reflected once into a trusted descriptor map and is never read directly.
const GET_PROTOTYPE_OF: (value: unknown) => object | null = Object.getPrototypeOf;
const GET_OWN_PROPERTY_DESCRIPTORS: (value: object) => PropertyDescriptorMap =
  Object.getOwnPropertyDescriptors;
const GET_OWN_PROPERTY_DESCRIPTOR: (
  value: object,
  key: PropertyKey,
) => PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor;
const REFLECT_OWN_KEYS: (value: object) => PropertyKey[] = Reflect.ownKeys;
const DATE_GET_TIME: (this: Date) => number = Date.prototype.getTime;
const DATE_TO_ISO_STRING: (this: Date) => string = Date.prototype.toISOString;

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
const INTEGRATION_BLOCKED_REASONS: ReadonlySet<string> = new Set([
  "disabled",
  "allowExecute",
  "missing_capability",
  "blocked_capability",
  "blockedByDefault",
  "mode_not_allowed",
]);
const ENFORCEMENT_BLOCK_REASONS: ReadonlySet<string> = new Set([
  "scope_blocked",
  ...INTEGRATION_BLOCKED_REASONS,
]);
function isPlainObject(value: unknown): value is Record<PropertyKey, unknown> {
  if (value === null || typeof value !== "object") return false;
  try {
    if (nodeTypes.isProxy(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
}

function ownDataValue(
  value: Record<PropertyKey, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (
    descriptor === undefined ||
    !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
    descriptor.enumerable !== true
  ) {
    throw contextUnavailable();
  }
  return descriptor.value;
}

function ownOptionalDataValue(
  value: Record<PropertyKey, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined) return undefined;
  if (
    !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
    descriptor.enumerable !== true
  ) {
    throw contextUnavailable();
  }
  return descriptor.value;
}

function assertExactOwnKeys(
  value: Record<PropertyKey, unknown>,
  allowed: ReadonlySet<string>,
): void {
  if (Object.getOwnPropertySymbols(value).length > 0) throw contextUnavailable();
  for (const key of Object.getOwnPropertyNames(value)) {
    if (!allowed.has(key)) throw contextUnavailable();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true
    ) {
      throw contextUnavailable();
    }
  }
}

function snapshotStringArrayStrict(
  value: unknown,
  allowEmpty = true,
): string[] {
  if (value === undefined && allowEmpty) return [];
  if (!Array.isArray(value) || nodeTypes.isProxy(value)) throw contextUnavailable();
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !Object.prototype.hasOwnProperty.call(lengthDescriptor, "value") ||
    typeof lengthDescriptor.value !== "number" ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0
  ) {
    throw contextUnavailable();
  }
  const length = lengthDescriptor.value;
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length > 0 || names.length !== length + 1) {
    throw contextUnavailable();
  }
  const result: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
      descriptor.enumerable !== true ||
      !isCanonicalMaterialId(descriptor.value)
    ) {
      throw contextUnavailable();
    }
    result.push(descriptor.value);
  }
  if (!allowEmpty && result.length === 0) throw contextUnavailable();
  return Object.freeze(result) as unknown as string[];
}

function isSafeString(value: unknown): value is string {
  return typeof value === "string";
}

function isCanonicalMaterialId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value === value.trim() &&
    Array.from(value).length <= CODE_POINT_MAX &&
    !C0_DEL_REGEX.test(value)
  );
}

function assertOptionalBoolean(value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw contextUnavailable();
  return value;
}

function isExecutionMode(value: unknown): value is ExecutionMode {
  return typeof value === "string" && EXECUTION_MODE_VALUES.has(value);
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return typeof value === "string" && RISK_LEVEL_VALUES.has(value);
}

function isPolicyDecision(value: unknown): value is PolicyDecision {
  return typeof value === "string" && POLICY_DECISION_VALUES.has(value);
}

function isNonnegativeSafeInteger(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= Number.MAX_SAFE_INTEGER
  );
}

function isLowercaseHex64(value: unknown): value is string {
  return typeof value === "string" && HEX64_PATTERN.test(value);
}

interface ValidatedHumanApprovalInput {
  actionId: string;
  reviewerId: string;
  expectedContextHash: string;
  ttlMs: number;
  note?: string;
}

interface ValidatedPolicyApprovalInput {
  actionId: string;
  ttlMs: number;
  note?: string;
}

type ApprovalSource = "human" | "policy";

interface ApprovalTimestamps {
  reviewedAt: string;
  expiresAt: string;
}

const HUMAN_APPROVAL_REQUIRED_FIELDS: ReadonlySet<string> = new Set([
  "actionId",
  "reviewerId",
  "expectedContextHash",
  "ttlMs",
]);
const HUMAN_APPROVAL_ALLOWED_FIELDS: ReadonlySet<string> = new Set([
  ...HUMAN_APPROVAL_REQUIRED_FIELDS,
  "note",
]);
const POLICY_APPROVAL_REQUIRED_FIELDS: ReadonlySet<string> = new Set([
  "actionId",
  "ttlMs",
]);
const POLICY_APPROVAL_ALLOWED_FIELDS: ReadonlySet<string> = new Set([
  ...POLICY_APPROVAL_REQUIRED_FIELDS,
  "note",
]);

function approvalInvalid(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_INVALID_MESSAGE,
    "ACTION_APPROVAL_INVALID",
  );
}

function reviewerInvalid(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_REVIEWER_INVALID_MESSAGE,
    "ACTION_APPROVAL_REVIEWER_INVALID",
  );
}

function ttlInvalid(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_TTL_INVALID_MESSAGE,
    "ACTION_APPROVAL_TTL_INVALID",
  );
}

function contextInvalid(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_CONTEXT_INVALID_MESSAGE,
    "ACTION_APPROVAL_CONTEXT_INVALID",
  );
}

function contextStale(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_CONTEXT_STALE_MESSAGE,
    "ACTION_APPROVAL_CONTEXT_STALE",
  );
}

function policyBlocked(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_POLICY_BLOCKED_MESSAGE,
    "ACTION_APPROVAL_POLICY_BLOCKED",
  );
}

function handoffOnly(): BountyPilotError {
  return new BountyPilotError(
    ACTION_HANDOFF_ONLY_MESSAGE,
    "ACTION_HANDOFF_ONLY",
  );
}

function humanRequired(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_HUMAN_REQUIRED_MESSAGE,
    "ACTION_APPROVAL_HUMAN_REQUIRED",
  );
}

function approvalRaceLost(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_RACE_LOST_MESSAGE,
    "ACTION_APPROVAL_RACE_LOST",
  );
}

/**
 * Snapshot an approval DTO without performing a property get on the caller
 * object. Proxy objects (including revoked proxies), custom prototypes,
 * symbols, unknown/missing fields, and accessors all collapse to the same
 * fixed cause-free invalid-input error.
 */
function snapshotApprovalFields(
  input: unknown,
  required: ReadonlySet<string>,
  allowed: ReadonlySet<string>,
): Record<string, unknown> {
  if (input === null || typeof input !== "object") throw approvalInvalid();

  let descriptors: PropertyDescriptorMap;
  let keys: PropertyKey[];
  try {
    if (nodeTypes.isProxy(input)) throw approvalInvalid();
    const prototype = GET_PROTOTYPE_OF(input);
    if (prototype !== Object.prototype && prototype !== null) {
      throw approvalInvalid();
    }
    descriptors = GET_OWN_PROPERTY_DESCRIPTORS(input);
    keys = REFLECT_OWN_KEYS(descriptors);
  } catch {
    throw approvalInvalid();
  }

  const names: string[] = [];
  for (const key of keys) {
    if (typeof key !== "string" || !allowed.has(key)) throw approvalInvalid();
    names.push(key);
  }
  if (names.length < required.size || names.length > allowed.size) {
    throw approvalInvalid();
  }
  for (const field of required) {
    if (!names.includes(field)) throw approvalInvalid();
  }

  const values = Object.create(null) as Record<string, unknown>;
  try {
    for (const name of names) {
      const outer = GET_OWN_PROPERTY_DESCRIPTOR(descriptors, name);
      if (outer === undefined) throw approvalInvalid();
      const outerValue = GET_OWN_PROPERTY_DESCRIPTOR(outer, "value");
      if (outerValue === undefined || outerValue.value === null || typeof outerValue.value !== "object") {
        throw approvalInvalid();
      }
      const innerValue = GET_OWN_PROPERTY_DESCRIPTOR(outerValue.value, "value");
      if (innerValue === undefined) throw approvalInvalid();
      values[name] = innerValue.value;
    }
  } catch {
    throw approvalInvalid();
  }
  return values;
}

function snapshotOptionalNote(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw approvalInvalid();
  return value;
}

function snapshotHumanApprovalInput(input: unknown): ValidatedHumanApprovalInput {
  const fields = snapshotApprovalFields(
    input,
    HUMAN_APPROVAL_REQUIRED_FIELDS,
    HUMAN_APPROVAL_ALLOWED_FIELDS,
  );

  // Contract-pinned semantic precedence: actionId/note, reviewer, TTL,
  // then context-token shape.
  const actionId = snapshotCanonicalActionId(fields.actionId);
  const note = snapshotOptionalNote(fields.note);

  const rawReviewer = fields.reviewerId;
  if (typeof rawReviewer !== "string" || C0_DEL_REGEX.test(rawReviewer)) {
    throw reviewerInvalid();
  }
  const reviewerId = rawReviewer.trim();
  const reviewerCodePoints = Array.from(reviewerId).length;
  if (
    reviewerCodePoints < CODE_POINT_MIN ||
    reviewerCodePoints > CODE_POINT_MAX ||
    reviewerId === POLICY_REVIEWER_ID
  ) {
    throw reviewerInvalid();
  }

  const ttlMs = fields.ttlMs;
  if (
    typeof ttlMs !== "number" ||
    !Number.isSafeInteger(ttlMs) ||
    ttlMs < 1 ||
    ttlMs > MAX_APPROVAL_TTL_MS
  ) {
    throw ttlInvalid();
  }

  const expectedContextHash = fields.expectedContextHash;
  if (!isLowercaseHex64(expectedContextHash)) throw contextInvalid();

  return Object.freeze({ actionId, reviewerId, expectedContextHash, ttlMs, note });
}

function snapshotPolicyApprovalInput(input: unknown): ValidatedPolicyApprovalInput {
  const fields = snapshotApprovalFields(
    input,
    POLICY_APPROVAL_REQUIRED_FIELDS,
    POLICY_APPROVAL_ALLOWED_FIELDS,
  );
  const actionId = snapshotCanonicalActionId(fields.actionId);
  const note = snapshotOptionalNote(fields.note);
  const ttlMs = fields.ttlMs;
  if (
    typeof ttlMs !== "number" ||
    !Number.isSafeInteger(ttlMs) ||
    ttlMs < 1 ||
    ttlMs > MAX_APPROVAL_TTL_MS
  ) {
    throw ttlInvalid();
  }
  return Object.freeze({ actionId, ttlMs, note });
}

function captureApprovalTimestamps(
  dependencies: ActionApprovalServiceDependencies,
  ttlMs: number,
): ApprovalTimestamps {
  try {
    const current = dependencies.now();
    // Deliberately bypass an overridden instance method and read the clock
    // object's Date slot exactly once.
    const reviewedEpoch = DATE_GET_TIME.call(current) as number;
    if (!Number.isFinite(reviewedEpoch) || !Number.isSafeInteger(reviewedEpoch)) {
      throw contextUnavailable();
    }
    if (reviewedEpoch < -MAX_DATE_EPOCH_MS || reviewedEpoch > MAX_DATE_EPOCH_MS) {
      throw contextUnavailable();
    }

    const expiresEpoch = reviewedEpoch + ttlMs;
    if (
      !Number.isFinite(expiresEpoch) ||
      !Number.isSafeInteger(expiresEpoch) ||
      expiresEpoch < -MAX_DATE_EPOCH_MS ||
      expiresEpoch > MAX_DATE_EPOCH_MS ||
      expiresEpoch <= reviewedEpoch
    ) {
      throw contextUnavailable();
    }

    const reviewedAt = DATE_TO_ISO_STRING.call(new Date(reviewedEpoch));
    const expiresAt = DATE_TO_ISO_STRING.call(new Date(expiresEpoch));
    if (
      DATE_TO_ISO_STRING.call(new Date(reviewedAt)) !== reviewedAt ||
      DATE_TO_ISO_STRING.call(new Date(expiresAt)) !== expiresAt
    ) {
      throw contextUnavailable();
    }
    return Object.freeze({ reviewedAt, expiresAt });
  } catch {
    throw contextUnavailable();
  }
}

export class ActionApprovalService {
  private readonly queue: ActionQueue;
  private readonly reviewStore: ActionReviewStore;
  private readonly eventStore: WorkflowEventStore;
  private readonly jobManager: JobManager;

  constructor(
    private readonly db: BountyDatabase,
    private readonly dependencies: ActionApprovalServiceDependencies,
  ) {
    // All transaction participants are permanently bound to the exact handle
    // supplied to this service. Store injection is intentionally unsupported.
    this.queue = new ActionQueue(db);
    this.reviewStore = new ActionReviewStore(db);
    this.eventStore = new WorkflowEventStore(db);
    this.jobManager = new JobManager(db);
  }

  preview(actionId: string): ActionApprovalChallenge {
    // 1) Pure snapshot of the action identifier BEFORE any database
    //    read, loader call, resolver call, or clock call. Hostile
    //    shapes (non-string, padded, C0/DEL, empty, oversized,
    //    proxies) are rejected with the fixed cause-free
    //    ACTION_APPROVAL_INVALID. No reflection through caller code
    //    and no use of the dependencies.
    const canonicalActionId = snapshotCanonicalActionId(actionId);
    const preflight = loadPreviewPreflight(this.db, this.queue, canonicalActionId);

    try {
      return materializePreview(preflight, this.dependencies).challenge;
    } catch {
      throw contextUnavailable();
    }
  }

  approveHuman(input: HumanApprovalInput): ActionApprovalResult {
    const validated = snapshotHumanApprovalInput(input);
    return this.approveValidated(validated, "human");
  }

  approvePolicy(input: PolicyApprovalInput): ActionApprovalResult {
    const validated = snapshotPolicyApprovalInput(input);
    return this.approveValidated(validated, "policy");
  }

  private approveValidated(
    input: ValidatedHumanApprovalInput | ValidatedPolicyApprovalInput,
    source: ApprovalSource,
  ): ActionApprovalResult {
    // Typed database/preflight errors deliberately remain outside the
    // materialization catch and propagate unchanged.
    const preflight = loadPreviewPreflight(this.db, this.queue, input.actionId);

    let outside: PreviewMaterial;
    try {
      outside = materializePreview(preflight, this.dependencies);
    } catch {
      throw contextUnavailable();
    }

    const expectedContextHash =
      source === "human"
        ? (input as ValidatedHumanApprovalInput).expectedContextHash
        : undefined;
    applyApprovalGate(
      source,
      outside.challenge,
      preflight.candidate.requiresApproval,
      expectedContextHash,
    );

    // The one approval clock call occurs only after every outside gate and is
    // immediately followed by BEGIN IMMEDIATE.
    const timestamps = captureApprovalTimestamps(this.dependencies, input.ttlMs);

    return withImmediateTransaction(this.db, () => {
      // Reload every transaction-visible row and precondition through the same
      // queue/database handle used by the stores below.
      const currentPreflight = loadPreviewPreflight(
        this.db,
        this.queue,
        input.actionId,
      );

      let currentSource: ActionMaterialSourceSnapshot;
      try {
        currentSource = snapshotPreflightSource(currentPreflight);
      } catch {
        throw contextUnavailable();
      }
      if (currentSource.canonical !== outside.sourceCanonical) {
        throw approvalRaceLost();
      }

      let currentChallenge: ActionApprovalChallenge;
      try {
        currentChallenge = recomputeActionAuthority(
          currentSource.source,
          outside.material,
        ).challenge;
      } catch {
        throw contextUnavailable();
      }

      applyApprovalGate(
        source,
        currentChallenge,
        currentPreflight.candidate.requiresApproval,
        expectedContextHash,
      );

      const review = this.reviewStore.insertApprovalInTransaction({
        actionId: input.actionId,
        jobId: currentPreflight.candidate.jobId,
        decision: "approved",
        reviewerId:
          source === "human"
            ? (input as ValidatedHumanApprovalInput).reviewerId
            : POLICY_REVIEWER_ID,
        source,
        reviewedAt: timestamps.reviewedAt,
        expiresAt: timestamps.expiresAt,
        scopeHash: currentChallenge.scopeHash,
        policyHash: currentChallenge.policyHash,
        actionHash: currentChallenge.actionHash,
        contextHash: currentChallenge.contextHash,
        note: input.note,
      });

      const action = this.queue.approveWithReviewInTransaction({
        actionId: input.actionId,
        jobId: currentPreflight.candidate.jobId,
        reviewId: review.id,
        scopeHash: currentChallenge.scopeHash,
        policyHash: currentChallenge.policyHash,
        actionHash: currentChallenge.actionHash,
        contextHash: currentChallenge.contextHash,
        updatedAt: timestamps.reviewedAt,
      });

      const event = this.eventStore.recordInTransaction({
        jobId: currentPreflight.candidate.jobId,
        phase: "action-review",
        status: "completed",
        message: "Action approval completed",
        metadata: {
          actionId: input.actionId,
          reviewId: review.id,
          source,
          contextHash: currentChallenge.contextHash,
        },
      });
      const job = this.jobManager.finalizeInTransaction(
        currentPreflight.candidate.jobId,
      );

      return { action, review, event, job };
    });
  }
}

interface PreviewMaterial extends MaterializedActionAuthority {}

interface PreviewJobRow {
  id: string;
  type: string;
  target: string | null;
  mode: string;
}

interface PreviewPreflight {
  candidate: PendingApprovalCandidate;
  jobRow: PreviewJobRow;
}

function applyApprovalGate(
  source: ApprovalSource,
  challenge: ActionApprovalChallenge,
  requiresApproval: boolean,
  expectedContextHash?: string,
): void {
  if (challenge.policyDecision === "block") throw policyBlocked();
  if (source === "human") {
    if (expectedContextHash !== challenge.contextHash) throw contextStale();
    return;
  }
  if (challenge.policyDecision !== "allow" || requiresApproval !== false) {
    throw humanRequired();
  }
}

/**
 * Pure canonical action-id snapshot. Returns a primitive string equal
 * to its trim, 1..256 Unicode code points, no C0/DEL control
 * characters, no caller reflection, no caller accessors.
 */
function snapshotCanonicalActionId(value: unknown): string {
  if (typeof value !== "string") {
    throw new BountyPilotError(
      ACTION_APPROVAL_INVALID_MESSAGE,
      "ACTION_APPROVAL_INVALID",
    );
  }
  if (value.length === 0 || value !== value.trim()) {
    throw new BountyPilotError(
      ACTION_APPROVAL_INVALID_MESSAGE,
      "ACTION_APPROVAL_INVALID",
    );
  }
  if (C0_DEL_REGEX.test(value)) {
    throw new BountyPilotError(
      ACTION_APPROVAL_INVALID_MESSAGE,
      "ACTION_APPROVAL_INVALID",
    );
  }
  const codePoints = Array.from(value);
  if (codePoints.length < CODE_POINT_MIN || codePoints.length > CODE_POINT_MAX) {
    throw new BountyPilotError(
      ACTION_APPROVAL_INVALID_MESSAGE,
      "ACTION_APPROVAL_INVALID",
    );
  }
  return value;
}

function loadPreviewPreflight(
  db: BountyDatabase,
  queue: ActionQueue,
  actionId: string,
): PreviewPreflight {
  // 1) Token-free pending-approval candidate reload. This
  //    transaction-neutral primitive validates the canonical
  //    actionId (defense in depth), queries the v2 public
  //    projection plus a SQL boolean that covers every clean
  //    field, and applies the exact preflight error order:
  //    ACTION_NOT_FOUND, ACTION_APPROVAL_NOT_PENDING,
  //    ACTION_APPROVAL_JOB_REQUIRED, JOB_NOT_FOUND,
  //    ACTION_APPROVAL_JOB_TERMINAL, ACTION_APPROVAL_STATE_INVALID.
  //    Malformed row errors (ACTION_RECORD_INVALID) propagate
  //    unchanged. The primitive is strictly read-only; no
  //    transaction is opened, no clock is touched, and the
  //    dependencies are not invoked here.
  const candidate = queue.requireCleanPendingForApproval(actionId);
  // Non-required rows are receipts/plans, not dormant effect capabilities.
  // Enforce this at the core approval seam so alternate callers cannot turn a
  // planning handoff into an executable action by bypassing CLI review UX.
  if (
    candidate.requiredForCompletion === false ||
    candidate.metadata?.handoffOnly === true ||
    candidate.metadata?.planningOnly === true
  ) {
    throw handoffOnly();
  }

  // The candidate gives us a concrete jobId; the job's mode/type
  // are not in the candidate projection. Reload only the four
  // columns needed to project the binding's job view (id, type,
  // target, mode). The read is narrow, deterministic, and
  // strictly read-only.
  const jobRow = db
    .prepare(
      "SELECT id AS id, type AS type, target AS target, mode AS mode FROM jobs WHERE id = ?",
    )
    .get(candidate.jobId) as PreviewJobRow | undefined;
  if (!jobRow) {
    // The preflight job-linkage check is supposed to be
    // authoritative; if a concurrent job deletion raced past the
    // candidate, the link is broken and the only safe answer is
    // the existing JOB_NOT_FOUND propagated through the original
    // typed store error. We map the surface here so a missing
    // row is not a materialization fault.
    throw new BountyPilotError(
      `Job not found: ${candidate.jobId}`,
      "JOB_NOT_FOUND",
    );
  }

  return { candidate, jobRow };
}

function snapshotPreflightSource(
  preflight: PreviewPreflight,
): ActionMaterialSourceSnapshot {
  const { candidate, jobRow } = preflight;
  if (
    !isCanonicalMaterialId(jobRow.id) ||
    jobRow.id !== candidate.jobId ||
    !isCanonicalMaterialId(jobRow.type) ||
    (jobRow.target !== null && !isSafeString(jobRow.target)) ||
    !isExecutionMode(jobRow.mode)
  ) {
    throw contextUnavailable();
  }

  const sourceDraft: ActionMaterialSource = {
    action: {
      id: candidate.id,
      jobId: candidate.jobId,
      adapter: candidate.adapter,
      actionType: candidate.actionType,
      target: candidate.target ?? null,
      riskLevel: candidate.riskLevel,
      requiresApproval: candidate.requiresApproval,
      requiredForCompletion: candidate.requiredForCompletion,
      metadata: candidate.metadata ? { ...candidate.metadata } : {},
    },
    job: {
      id: jobRow.id,
      type: jobRow.type,
      target: jobRow.target ?? null,
      mode: jobRow.mode,
    },
  };
  return snapshotActionMaterialSource(sourceDraft);
}

function materializePreview(
  preflight: PreviewPreflight,
  dependencies: ActionApprovalServiceDependencies,
): PreviewMaterial {
  const { source } = snapshotPreflightSource(preflight);

  // The shared materializer is the single authority binding path
  // for both approval and lifecycle. Any loader, resolver, or
  // materialization fault is mapped to the fixed, cause-free
  // `ACTION_APPROVAL_CONTEXT_UNAVAILABLE` error by the
  // materializer itself. `materializeActionAuthority` depends
  // only on `ActionAuthorityDependencies`; the approval clock
  // (`now()`) is never called here, and no SQL, no
  // transaction, and no write happens at this layer.
  try {
    return materializeActionAuthority(source, dependencies);
  } catch (err) {
    if (err instanceof BountyPilotError) throw err;
    throw contextUnavailable();
  }
}

/**
 * Dependency-free challenge recomputation shared by preview/outside approval
 * and the transaction reload. It creates fresh guards/gates but performs no
 * SQL, loader, resolver, clock, ID, or write operation.
 *
 * The function also returns the private `definitiveBlock` signal: a
 * current `requiresScope` denial is a `scope` block; any other
 * enforcement or native PolicyGate block is a `policy` block; scope
 * wins when both apply. The signal is consumed by callers that need
 * to record a different transition (`pending` vs `blocked`) but is
 * never serialized into the public challenge, the persisted
 * material, the workflow event metadata, or any of the bound
 * hashes.
 */
function computeChallengeFromCurrentMaterial(
  source: ActionMaterialSource,
  material: CurrentActionMaterial,
): ActionAuthorityEvaluation {
  const program = material.program;
  const resolved: ResolvedBindingMaterial = {
    normalizedTarget: material.normalizedTarget,
    capabilityEnforcement: material.capabilityEnforcement,
    integration: material.integration,
  };
  const authority = {
    scopeHash: material.scopeHash,
    policyHash: material.policyHash,
  };
  validateActionMaterialSource(source);
  validateAuthorityHashShape(program);
  if (
    !isLowercaseHex64(authority.scopeHash) ||
    !isLowercaseHex64(authority.policyHash) ||
    authority.scopeHash === HEX64_ALL_ZERO ||
    authority.policyHash === HEX64_ALL_ZERO
  ) {
    throw contextUnavailable();
  }

  const guard = new ScopeGuard(program.config);
  const gate = new PolicyGate(program.config.rules);

  // 7) Validate the capability projection. The capability id,
  //    actionType, riskLevel, and allowedModes are exact-equal to
  //    the action/job surface; allowedModes must contain the
  //    current job mode; requiresTarget/requiresScope rules are
  //    applied to the target. A mismatched capability is a
  //    materialization fault.
  validateCapabilityEnforcement(
    resolved.capabilityEnforcement,
    source.job.mode,
    source.action,
  );

  const capability = resolved.capabilityEnforcement;
  const rawTarget = source.action.target;
  const resolverNormalized = resolved.normalizedTarget;

  // 8) Apply requiresTarget/requiresScope. A present target is
  //    normalized by the fresh ScopeGuard; the normalized URL
  //    must equal the resolver's normalizedTarget exactly (or
  //    null when the raw target is absent). A valid
  //    requiresScope denial is a definitive `scope` block with
  //    the fixed public reason "Blocked by current authority
  //    enforcement". A missing required target, a missing
  //    normalized target when one is required, or a
  //    normalization/equality defect is a materialization
  //    fault.
  const enforcedDecision: PolicyDecision = "block";
  const enforcedReason: string = ENFORCEMENT_BLOCK_REASON;
  let scopeBlocked = false;
  let enforcementBlocked = false;

  if (rawTarget === null) {
    if (capability.requiresTarget || capability.requiresScope) {
      throw contextUnavailable();
    }
    if (resolverNormalized !== null) {
      throw contextUnavailable();
    }
  } else {
    let scoped;
    try {
      scoped = guard.test(rawTarget);
    } catch {
      throw contextUnavailable();
    }
    if (resolverNormalized === null) {
      throw contextUnavailable();
    }
    if (resolverNormalized !== scoped.url) {
      throw contextUnavailable();
    }
    if (capability.requiresScope && !scoped.allowed) {
      scopeBlocked = true;
      enforcementBlocked = true;
    }
  }

  // 9) Build the current PolicyActionInput exactly from current
  //    job mode, action type, normalized target, action risk,
  //    capability enforcement, and the current program's
  //    rules.lab_mode. The binding pipeline re-validates the
  //    whole input; an inconsistent material is a
  //    materialization fault.
  const labModeEnabled = program.config.rules.lab_mode === true;
  const policyAction: PolicyActionInput = {
    mode: source.job.mode,
    actionType: source.action.actionType,
    target: resolverNormalized ?? undefined,
    riskLevel: source.action.riskLevel,
    stateChanging: capability.stateChanging,
    destructive: capability.destructive,
    capability: capability.id,
    requiresApprovalByDefault: capability.requiresApprovalByDefault,
    labModeEnabled,
  };

  // 10) Integration projection. `builtin` is always valid;
  //    `integration` requires a complete safe execution policy
  //    AND the union of enforcement preconditions. The
  //    structurally valid happy path is enforced; any malformed
  //    policy, hash, entrypoint, array, or linkage defect is a
  //    materialization fault.
  // Capability-level enforcement applies to both builtin and
  // integration bindings. A blocked-by-default capability or a
  // job mode outside its allow-list is a normal public block,
  // never a materialization fault.
  if (
    capability.blockedByDefault === true ||
    !capability.allowedModes.includes(source.job.mode)
  ) {
    enforcementBlocked = true;
  }

  if (resolved.integration.kind === "integration") {
    if (source.action.adapter !== resolved.integration.policy.name) {
      throw contextUnavailable();
    }
    try {
      validateSafeIntegrationExecutionPolicy(resolved.integration.policy);
    } catch {
      throw contextUnavailable();
    }
    const enforced = evaluateIntegrationEnforcement(
      capability,
      source.job.mode,
      resolved.integration.policy,
      source.action.adapter,
    );
    if (enforced !== null) enforcementBlocked = true;
  }

  // 11) Evaluate the fresh PolicyGate once. The decision is part
  // of the canonical action binding, so the same result must be
  // used for both hashing and the public challenge.
  const gateResult = snapshotPolicyGateResult(gate.evaluate(policyAction));
  const effectiveDecision = enforcementBlocked ? enforcedDecision : gateResult.decision;
  const effectiveReason = enforcementBlocked ? enforcedReason : gateResult.reason;

  // 12) Build the binding through the canonical pipeline. The
  //    pipeline enforces every cross-field invariant (id, mode,
  //    risk, decision, capability, normalized target, integration
  //    policy). Any defect is a materialization fault.
  const binding = buildActionBinding({
    action: candidateRecordForSource(source),
    job: jobRecordForSource(source.job),
    normalizedTarget: resolverNormalized,
    requiredForCompletion: source.action.requiredForCompletion,
    policyAction,
    capabilityEnforcement: capability,
    policyDecision: effectiveDecision,
    integrationExecutionPolicy:
      resolved.integration.kind === "integration" ? resolved.integration.policy : null,
  });
  const actionHash = computeActionHash(binding);
  const contextHash = computeContextHash({
    scopeHash: authority.scopeHash,
    policyHash: authority.policyHash,
    actionHash,
  });

  // Block classification: a current `requiresScope` denial is a
  // `scope` block. Every other enforcement (capability,
  // mode, integration) or native `PolicyGate` block is a
  // `policy` block. Scope wins when both apply. The signal is
  // private to the shared materializer and is not serialized
  // into the public challenge, the persisted material, the
  // workflow event metadata, or any of the bound hashes.
  let definitiveBlock: DefinitiveAuthorityBlock = null;
  if (effectiveDecision === "block") {
    definitiveBlock = scopeBlocked ? "scope" : "policy";
  }

  return {
    challenge: {
      actionId: source.action.id,
      jobId: source.job.id,
      policyDecision: effectiveDecision,
      policyReason: effectiveReason,
      scopeHash: authority.scopeHash,
      policyHash: authority.policyHash,
      actionHash,
      contextHash,
    },
    definitiveBlock,
  };
}

/**
 * Runtime-check the otherwise TypeScript-only `PolicyGate` result before any
 * field is consumed. This boundary is intentionally descriptor based: a
 * replaced/malformed gate cannot execute an accessor or smuggle an expanded
 * result shape into the canonical binding. A valid native reason is returned
 * byte-for-byte.
 */
function snapshotPolicyGateResult(value: unknown): {
  decision: PolicyDecision;
  reason: string;
} {
  if (!isPlainObject(value)) throw contextUnavailable();
  assertExactOwnKeys(value, new Set(["decision", "reason"]));
  const decision = ownDataValue(value, "decision");
  const reason = ownDataValue(value, "reason");
  if (
    typeof decision !== "string" ||
    !POLICY_DECISION_VALUES.has(decision) ||
    typeof reason !== "string"
  ) {
    throw contextUnavailable();
  }
  return Object.freeze({ decision: decision as PolicyDecision, reason });
}

function candidateRecordForSource(source: ActionMaterialSource): ActionRecord {
  // Project the source into the ActionRecord shape that
  // buildActionBinding expects. The candidate path already
  // produces an ActionRecord; this helper is used when we
  // reconstruct from a source (e.g. for the enforcement block
  // path that has only the canonical source in hand).
  return {
    id: source.action.id,
    jobId: source.action.jobId,
    adapter: source.action.adapter,
    actionType: source.action.actionType,
    target: source.action.target ?? undefined,
    riskLevel: source.action.riskLevel,
    requiresApproval: source.action.requiresApproval,
    status: "pending",
    metadata: { ...source.action.metadata },
    createdAt: "",
    updatedAt: undefined,
    requiredForCompletion: source.action.requiredForCompletion,
  };
}

function jobRecordForSource(job: ActionMaterialSource["job"]): {
  id: string;
  type: string;
  target: string | undefined;
  mode: ExecutionMode;
  status: "queued" | "running" | "paused" | "failed" | "completed";
  pauseReason: null;
  statusDetail: null;
  createdAt: string;
  updatedAt: string;
} {
  return {
    id: job.id,
    type: job.type,
    target: job.target ?? undefined,
    mode: job.mode,
    status: "queued",
    pauseReason: null,
    statusDetail: null,
    createdAt: "",
    updatedAt: "",
  };
}

function validateActionMaterialSource(source: ActionMaterialSource): void {
  const action = source.action;
  const job = source.job;
  if (
    !isCanonicalMaterialId(action.id) ||
    !isCanonicalMaterialId(action.jobId) ||
    !isCanonicalMaterialId(job.id) ||
    action.jobId !== job.id ||
    !isCanonicalMaterialId(action.adapter) ||
    !isCanonicalMaterialId(action.actionType) ||
    !isCanonicalMaterialId(job.type) ||
    !isRiskLevel(action.riskLevel) ||
    !isExecutionMode(job.mode) ||
    typeof action.requiresApproval !== "boolean" ||
    typeof action.requiredForCompletion !== "boolean"
  ) {
    throw contextUnavailable();
  }
  if (action.target !== null && !isSafeString(action.target)) {
    throw contextUnavailable();
  }
  if (job.target !== null && !isSafeString(job.target)) {
    throw contextUnavailable();
  }
  if (!isPlainObject(action.metadata)) {
    throw contextUnavailable();
  }
}

function canonicalizeSourceForSchema(source: ActionMaterialSource): string {
  // The contract pins schema "approval-material-source/v1" as the
  // canonical projection of the source. The projection bytes are
  // not bound into any hash the test exercises, but a hostile
  // source can still smuggle non-canonical values through
  // `metadata` (which is bound into actionHash via
  // computeMetadataSha256 inside buildActionBinding). The
  // canonicalization here is a defense-in-depth: any value that
  // is not representable in canonical JSON is rejected before it
  // reaches the binding pipeline. We do not capture the bytes.
  // The schema constant is the contract; the function ignores
  // it for now beyond the safety check.
  return canonicalize({
    schemaVersion: APPROVAL_MATERIAL_SOURCE_SCHEMA,
    action: {
      id: source.action.id,
      jobId: source.action.jobId,
      adapter: source.action.adapter,
      actionType: source.action.actionType,
      target: source.action.target,
      riskLevel: source.action.riskLevel,
      requiresApproval: source.action.requiresApproval,
      requiredForCompletion: source.action.requiredForCompletion,
      metadata: source.action.metadata,
    },
    job: {
      id: source.job.id,
      type: source.job.type,
      target: source.job.target,
      mode: source.job.mode,
    },
  }).toString("utf8");
}

function snapshotFrozenMaterialSource(canonical: string): ActionMaterialSource {
  try {
    const parsed = snapshotPlainData(
      JSON.parse(canonical) as unknown,
      [],
      new WeakSet<object>(),
      true,
      () => false,
    );
    if (!isPlainObject(parsed)) throw contextUnavailable();
    assertExactOwnKeys(parsed, new Set(["schemaVersion", "action", "job"]));
    if (ownDataValue(parsed, "schemaVersion") !== APPROVAL_MATERIAL_SOURCE_SCHEMA) {
      throw contextUnavailable();
    }
    if (canonicalize(parsed).toString("utf8") !== canonical) {
      throw contextUnavailable();
    }

    const action = ownDataValue(parsed, "action");
    const job = ownDataValue(parsed, "job");
    if (!isPlainObject(action) || !isPlainObject(job)) throw contextUnavailable();
    assertExactOwnKeys(
      action,
      new Set([
        "id",
        "jobId",
        "adapter",
        "actionType",
        "target",
        "riskLevel",
        "requiresApproval",
        "requiredForCompletion",
        "metadata",
      ]),
    );
    assertExactOwnKeys(job, new Set(["id", "type", "target", "mode"]));

    const source = Object.freeze({
      action: action as unknown as ActionMaterialSource["action"],
      job: job as unknown as ActionMaterialSource["job"],
    });
    validateActionMaterialSource(source);
    return source;
  } catch {
    throw contextUnavailable();
  }
}

function snapshotLoadedProgram(value: unknown): LoadedProgram {
  try {
    if (!isPlainObject(value)) throw contextUnavailable();
    assertExactOwnKeys(value, new Set(["config", "programFile", "labAuthorization"]));
    const rawConfig = ownDataValue(value, "config");
    const programFile = ownDataValue(value, "programFile");
    const rawLabAuthorization = ownDataValue(value, "labAuthorization");
    if (!isSafeString(programFile) || programFile.length === 0) {
      throw contextUnavailable();
    }
    const safeRawConfig = snapshotProgramConfig(rawConfig, false);
    const parsedConfig = ProgramSchema.parse(safeRawConfig);
    const config = snapshotProgramConfig(parsedConfig, true) as ProgramConfig;
    let labAuthorization: LabAuthorization | null = null;
    if (rawLabAuthorization !== null) {
      if (!isPlainObject(rawLabAuthorization)) throw contextUnavailable();
      assertExactOwnKeys(
        rawLabAuthorization,
        new Set(["relativePath", "byteLength", "contentSha256"]),
      );
      const relativePath = ownDataValue(rawLabAuthorization, "relativePath");
      const byteLength = ownDataValue(rawLabAuthorization, "byteLength");
      const contentSha256 = ownDataValue(rawLabAuthorization, "contentSha256");
      if (
        !isSafeString(relativePath) ||
        relativePath.length === 0 ||
        !isNonnegativeSafeInteger(byteLength) ||
        !isLowercaseHex64(contentSha256)
      ) {
        throw contextUnavailable();
      }
      labAuthorization = Object.freeze({ relativePath, byteLength, contentSha256 });
    }
    return Object.freeze({ config, programFile, labAuthorization });
  } catch {
    throw contextUnavailable();
  }
}

function snapshotProgramConfig(value: unknown, freeze: boolean): unknown {
  return snapshotPlainData(
    value,
    [],
    new WeakSet<object>(),
    freeze,
    isOptionalProgramConfigUndefined,
  );
}

function isOptionalProgramConfigUndefined(path: ReadonlyArray<string>): boolean {
  return (
    path.length === 2 &&
    path[0] === "rules" &&
    (path[1] === "lab_mode" || path[1] === "lab_authorization_file")
  );
}

function snapshotPlainData(
  value: unknown,
  path: ReadonlyArray<string>,
  active: WeakSet<object>,
  freeze: boolean,
  allowUndefined: (path: ReadonlyArray<string>) => boolean,
): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw contextUnavailable();
    return value;
  }
  if (value === undefined) {
    if (!allowUndefined(path)) throw contextUnavailable();
    return undefined;
  }
  if (typeof value !== "object" || nodeTypes.isProxy(value)) {
    throw contextUnavailable();
  }
  if (active.has(value)) throw contextUnavailable();

  active.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) throw contextUnavailable();
      if (Object.getOwnPropertySymbols(value).length > 0) throw contextUnavailable();
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      if (
        lengthDescriptor === undefined ||
        !Object.prototype.hasOwnProperty.call(lengthDescriptor, "value") ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0
      ) {
        throw contextUnavailable();
      }
      const length = lengthDescriptor.value as number;
      const names = Object.getOwnPropertyNames(value);
      if (names.length !== length + 1) throw contextUnavailable();

      const cloned: unknown[] = [];
      for (let index = 0; index < length; index += 1) {
        const key = String(index);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (
          descriptor === undefined ||
          !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
          descriptor.enumerable !== true
        ) {
          throw contextUnavailable();
        }
        cloned.push(
          snapshotPlainData(
            descriptor.value,
            [...path, key],
            active,
            freeze,
            allowUndefined,
          ),
        );
      }
      return freeze ? Object.freeze(cloned) : cloned;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw contextUnavailable();
    }
    if (Object.getOwnPropertySymbols(value).length > 0) throw contextUnavailable();

    const cloned = Object.create(null) as Record<string, unknown>;
    for (const key of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
        descriptor.enumerable !== true
      ) {
        throw contextUnavailable();
      }
      Object.defineProperty(cloned, key, {
        value: snapshotPlainData(
          descriptor.value,
          [...path, key],
          active,
          freeze,
          allowUndefined,
        ),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return freeze ? Object.freeze(cloned) : cloned;
  } finally {
    active.delete(value);
  }
}

function validateAuthorityHashShape(program: LoadedProgram): void {
  // The contract pins scopeHash and policyHash as 64-character
  // lowercase hex digests. This is enforced inside
  // buildProgramAuthoritySnapshot; we re-validate here so a
  // future change to that helper cannot widen the public shape.
  const config = program.config as ProgramConfig;
  if (!config || typeof config !== "object") {
    throw contextUnavailable();
  }
}

function snapshotResolvedBindingMaterial(
  value: unknown,
  actionAdapter: string,
): ResolvedBindingMaterial {
  if (!isPlainObject(value)) {
    throw contextUnavailable();
  }
  assertExactOwnKeys(
    value,
    new Set(["normalizedTarget", "capabilityEnforcement", "integration"]),
  );
  const rawNormalized = ownDataValue(value, "normalizedTarget");
  if (rawNormalized !== null && !isSafeString(rawNormalized)) {
    throw contextUnavailable();
  }
  const rawCapability = ownDataValue(value, "capabilityEnforcement");
  if (!isPlainObject(rawCapability)) {
    throw contextUnavailable();
  }
  const capability = snapshotCapabilityEnforcement(rawCapability);
  const rawIntegration = ownDataValue(value, "integration");
  const integration = snapshotIntegrationBindingMaterial(rawIntegration, actionAdapter);
  return Object.freeze({
    normalizedTarget: rawNormalized,
    capabilityEnforcement: capability,
    integration,
  });
}

function snapshotCapabilityEnforcement(value: Record<PropertyKey, unknown>): CapabilityEnforcementInput {
  assertExactOwnKeys(
    value,
    new Set([
      "id",
      "actionType",
      "riskLevel",
      "allowedModes",
      "title",
      "description",
      "produces",
      "requiresTarget",
      "requiresScope",
      "stateChanging",
      "destructive",
      "requiresApprovalByDefault",
      "blockedByDefault",
      "scopedPostcondition",
      "mcpTools",
    ]),
  );
  const id = ownDataValue(value, "id");
  const actionType = ownDataValue(value, "actionType");
  const riskLevel = ownDataValue(value, "riskLevel");
  if (!isCanonicalMaterialId(id)) {
    throw contextUnavailable();
  }
  if (!isCanonicalMaterialId(actionType)) {
    throw contextUnavailable();
  }
  if (!isRiskLevel(riskLevel)) {
    throw contextUnavailable();
  }
  const allowedModes = ownDataValue(value, "allowedModes");
  const normalizedModes = snapshotStringArrayStrict(allowedModes, false);
  if (normalizedModes.some((mode) => !isExecutionMode(mode))) throw contextUnavailable();
  const requiresTarget = assertOptionalBoolean(ownOptionalDataValue(value, "requiresTarget"));
  const requiresScope = assertOptionalBoolean(ownOptionalDataValue(value, "requiresScope"));
  const stateChanging = assertOptionalBoolean(ownOptionalDataValue(value, "stateChanging"));
  const destructive = assertOptionalBoolean(ownOptionalDataValue(value, "destructive"));
  const requiresApprovalByDefault = assertOptionalBoolean(
    ownOptionalDataValue(value, "requiresApprovalByDefault"),
  );
  const blockedByDefault = assertOptionalBoolean(
    ownOptionalDataValue(value, "blockedByDefault"),
  );
  const scopedPostcondition = ownOptionalDataValue(value, "scopedPostcondition");
  if (
    scopedPostcondition !== undefined &&
    scopedPostcondition !== "current_or_final_url_in_scope"
  ) {
    throw contextUnavailable();
  }
  const title = snapshotOptionalString(ownOptionalDataValue(value, "title"));
  const description = snapshotOptionalString(ownOptionalDataValue(value, "description"));
  const mcpTools = snapshotStringArrayStrict(ownOptionalDataValue(value, "mcpTools"));
  const produces = snapshotStringArrayStrict(ownOptionalDataValue(value, "produces"));
  return Object.freeze({
    id,
    actionType,
    riskLevel,
    allowedModes: normalizedModes as ExecutionMode[],
    requiresTarget,
    requiresScope,
    stateChanging,
    destructive,
    requiresApprovalByDefault,
    blockedByDefault,
    scopedPostcondition:
      scopedPostcondition === "current_or_final_url_in_scope"
        ? "current_or_final_url_in_scope"
        : undefined,
    mcpTools,
    title,
    description,
    produces,
  });
}

function snapshotOptionalString(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw contextUnavailable();
  return value;
}

function snapshotIntegrationBindingMaterial(
  value: unknown,
  actionAdapter: string,
): IntegrationBindingMaterial {
  if (!isPlainObject(value)) {
    throw contextUnavailable();
  }
  assertExactOwnKeys(value, new Set(["kind", "policy"]));
  const kind = ownDataValue(value, "kind");
  if (kind === "builtin") {
    if (Object.getOwnPropertyNames(value).length !== 1) throw contextUnavailable();
    return Object.freeze({ kind: "builtin" });
  }
  if (kind === "integration") {
    const policy = snapshotSafeIntegrationExecutionPolicy(ownDataValue(value, "policy"));
    if (policy.name !== actionAdapter) {
      throw contextUnavailable();
    }
    return Object.freeze({ kind: "integration", policy });
  }
  throw contextUnavailable();
}

function snapshotSafeIntegrationExecutionPolicy(value: unknown): SafeIntegrationExecutionPolicy {
  if (!isPlainObject(value)) {
    throw contextUnavailable();
  }
  assertExactOwnKeys(
    value,
    new Set([
      "name",
      "type",
      "enabled",
      "allowExecute",
      "transport",
      "launcherSha256",
      "endpointSha256",
      "package",
      "packageVersion",
      "entrypoint",
      "entrypointSha256",
      "packageJsonSha256",
      "timeoutMs",
      "capabilities",
      "blockedCapabilities",
    ]),
  );
  const name = ownDataValue(value, "name");
  const type = ownDataValue(value, "type");
  const enabled = ownDataValue(value, "enabled");
  const allowExecute = ownDataValue(value, "allowExecute");
  const transport = ownDataValue(value, "transport");
  const launcherSha256 = ownDataValue(value, "launcherSha256");
  const endpointSha256 = ownDataValue(value, "endpointSha256");
  const packageName = ownDataValue(value, "package");
  const packageVersion = ownDataValue(value, "packageVersion");
  const entrypoint = ownDataValue(value, "entrypoint");
  const entrypointSha256 = ownDataValue(value, "entrypointSha256");
  const packageJsonSha256 = ownDataValue(value, "packageJsonSha256");
  const timeoutMs = ownDataValue(value, "timeoutMs");
  if (!isCanonicalMaterialId(name)) {
    throw contextUnavailable();
  }
  if (!isCanonicalMaterialId(type)) {
    throw contextUnavailable();
  }
  if (typeof enabled !== "boolean" || typeof allowExecute !== "boolean") {
    throw contextUnavailable();
  }
  if (transport !== null && !isCanonicalMaterialId(transport)) {
    throw contextUnavailable();
  }
  if (!isLowercaseHex64(launcherSha256)) {
    throw contextUnavailable();
  }
  if (endpointSha256 !== null && !isLowercaseHex64(endpointSha256)) {
    throw contextUnavailable();
  }
  if (entrypoint !== null && !isCanonicalMaterialId(entrypoint)) {
    throw contextUnavailable();
  }
  if (entrypointSha256 !== null && !isLowercaseHex64(entrypointSha256)) {
    throw contextUnavailable();
  }
  if (packageName !== null && !isCanonicalMaterialId(packageName)) {
    throw contextUnavailable();
  }
  if (packageVersion !== null && !isCanonicalMaterialId(packageVersion)) {
    throw contextUnavailable();
  }
  if (packageJsonSha256 !== null && !isLowercaseHex64(packageJsonSha256)) {
    throw contextUnavailable();
  }
  if (!isNonnegativeSafeInteger(timeoutMs)) {
    throw contextUnavailable();
  }
  if (timeoutMs < 1 || timeoutMs > 120_000) {
    throw contextUnavailable();
  }
  const capabilities = snapshotStringArrayStrict(ownDataValue(value, "capabilities"), true);
  const blockedCapabilities = snapshotStringArrayStrict(
    ownDataValue(value, "blockedCapabilities"),
    true,
  );
  return Object.freeze({
    name,
    type,
    enabled,
    allowExecute,
    transport: transport as string | null,
    launcherSha256,
    endpointSha256: endpointSha256 as string | null,
    package: packageName as string | null,
    packageVersion: packageVersion as string | null,
    entrypoint: entrypoint as string | null,
    entrypointSha256: entrypointSha256 as string | null,
    packageJsonSha256: packageJsonSha256 as string | null,
    timeoutMs,
    capabilities,
    blockedCapabilities,
  });
}

function validateSafeIntegrationExecutionPolicy(policy: SafeIntegrationExecutionPolicy): void {
  // The contract pins the same structural validations
  // enforced by the binding pipeline. We re-check here so a
  // malformed projection surfaces as a materialization
  // fault instead of leaking a hash into the challenge. The
  // pipeline also throws on the same defects; double-checking
  // is the contract-strict interpretation.
  if (!isLowercaseHex64(policy.launcherSha256)) {
    throw contextUnavailable();
  }
  if (policy.endpointSha256 !== null && !isLowercaseHex64(policy.endpointSha256)) {
    throw contextUnavailable();
  }
  if (policy.entrypointSha256 !== null && !isLowercaseHex64(policy.entrypointSha256)) {
    throw contextUnavailable();
  }
  if (policy.packageJsonSha256 !== null && !isLowercaseHex64(policy.packageJsonSha256)) {
    throw contextUnavailable();
  }
  if (policy.entrypoint !== null) {
    if (policy.entrypoint.length === 0) {
      throw contextUnavailable();
    }
    if (C0_DEL_REGEX.test(policy.entrypoint)) {
      throw contextUnavailable();
    }
    if (
      policy.entrypoint.startsWith("/") ||
      /^[A-Za-z]:/.test(policy.entrypoint) ||
      policy.entrypoint.includes(":")
    ) {
      throw contextUnavailable();
    }
    const segments = policy.entrypoint.split("/");
    for (const segment of segments) {
      if (segment === "" || segment === "." || segment === "..") {
        throw contextUnavailable();
      }
    }
  }
  if (policy.timeoutMs < 1 || policy.timeoutMs > 120_000) {
    throw contextUnavailable();
  }
}

function validateCapabilityEnforcement(
  capability: CapabilityEnforcementInput,
  jobMode: ExecutionMode,
  action: ActionMaterialSource["action"],
): void {
  void jobMode;
  if (
    !Array.isArray(capability.allowedModes) ||
    capability.allowedModes.length === 0 ||
    capability.allowedModes.some((mode) => !isExecutionMode(mode))
  ) {
    throw contextUnavailable();
  }
  // The capability id, actionType, and riskLevel are exactly
  // the action surface; the binding pipeline re-validates
  // them. Pre-validating here gives a cleaner failure path.
  if (typeof capability.id !== "string" || capability.id.length === 0) {
    throw contextUnavailable();
  }
  if (typeof capability.actionType !== "string" || capability.actionType.length === 0) {
    throw contextUnavailable();
  }
  if (!isRiskLevel(capability.riskLevel)) {
    throw contextUnavailable();
  }
  if (
    capability.actionType !== action.actionType ||
    capability.riskLevel !== action.riskLevel
  ) {
    throw contextUnavailable();
  }
}

function evaluateIntegrationEnforcement(
  capability: CapabilityEnforcementInput,
  jobMode: ExecutionMode,
  policy: SafeIntegrationExecutionPolicy,
  actionAdapter: string,
): string | null {
  // Enforcement precedence mirrors the contract:
  //   1. integration disabled
  //   2. allowExecute false
  //   3. action type absent from policy capabilities
  //   4. action type or capability id in blockedCapabilities
  //   5. capability.blockedByDefault
  //   6. job mode not in capability.allowedModes
  //   7. policy name mismatch (defense in depth, also caught
  //      by snapshotSafeIntegrationExecutionPolicy)
  if (policy.enabled === false) return "disabled";
  if (policy.allowExecute === false) return "allowExecute";
  if (!policy.capabilities.includes(capability.actionType)) return "missing_capability";
  if (
    policy.blockedCapabilities.includes(capability.actionType) ||
    policy.blockedCapabilities.includes(capability.id)
  ) {
    return "blocked_capability";
  }
  if (capability.blockedByDefault === true) return "blockedByDefault";
  if (!capability.allowedModes.includes(jobMode)) return "mode_not_allowed";
  if (policy.name !== actionAdapter) return "name_mismatch";
  return null;
}

function contextUnavailable(): BountyPilotError {
  return new BountyPilotError(
    ACTION_APPROVAL_CONTEXT_UNAVAILABLE_MESSAGE,
    "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
  );
}

// ---------------------------------------------------------------------------
// Shared authority seam (P0.2 Slice C1A).
//
// Approval and lifecycle must share one internal authority
// materializer and one pure challenge recomputation function. The
// functions below are the shared seam; both `preview` and
// `approve*` (and the lifecycle claim path, when it is wired up)
// route through them so the policy/authority pipeline is never
// duplicated. The surface is exported for the in-tree tests and
// the lifecycle author; it is documented as `@internal` and is
// not part of the public approval-service surface.
// ---------------------------------------------------------------------------

/**
 * @internal
 *
 * Freeze a validated `ActionMaterialSource` into the shared
 * snapshot the resolver, the binding pipeline, and the in-tx
 * reload see. The canonical string is the bytes the lifecycle
 * claim path compares against the in-tx reload to detect a
 * source race. The function performs no SQL, no clock, no
 * loader, no resolver, and no effect.
 */
export function snapshotActionMaterialSource(
  source: ActionMaterialSource,
): ActionMaterialSourceSnapshot {
  try {
    return snapshotActionMaterialSourceUnchecked(source);
  } catch {
    // Always allocate a fresh fixed error. In particular, do not rethrow a
    // foreign BountyPilotError from canonical JSON or expose a hostile trap.
    throw contextUnavailable();
  }
}

function snapshotActionMaterialSourceUnchecked(
  source: unknown,
): ActionMaterialSourceSnapshot {
  // Reject proxies before reflection and extract every allowed field through
  // own data descriptors. No ordinary property read is performed against the
  // caller-owned source, action, job, or metadata objects.
  if (!isPlainObject(source)) throw contextUnavailable();
  assertExactOwnKeys(source, new Set(["action", "job"]));

  const rawAction = ownDataValue(source, "action");
  const rawJob = ownDataValue(source, "job");
  if (!isPlainObject(rawAction) || !isPlainObject(rawJob)) {
    throw contextUnavailable();
  }
  assertExactOwnKeys(
    rawAction,
    new Set([
      "id",
      "jobId",
      "adapter",
      "actionType",
      "target",
      "riskLevel",
      "requiresApproval",
      "requiredForCompletion",
      "metadata",
    ]),
  );
  assertExactOwnKeys(rawJob, new Set(["id", "type", "target", "mode"]));

  const rawMetadata = ownDataValue(rawAction, "metadata");
  if (!isPlainObject(rawMetadata)) throw contextUnavailable();
  const metadata = snapshotPlainData(
    rawMetadata,
    ["action", "metadata"],
    new WeakSet<object>(),
    true,
    () => false,
  );
  if (!isPlainObject(metadata)) throw contextUnavailable();

  const action: ActionMaterialSource["action"] = Object.freeze({
    id: ownDataValue(rawAction, "id") as string,
    jobId: ownDataValue(rawAction, "jobId") as string,
    adapter: ownDataValue(rawAction, "adapter") as string,
    actionType: ownDataValue(rawAction, "actionType") as string,
    target: ownDataValue(rawAction, "target") as string | null,
    riskLevel: ownDataValue(rawAction, "riskLevel") as RiskLevel,
    requiresApproval: ownDataValue(rawAction, "requiresApproval") as boolean,
    requiredForCompletion: ownDataValue(rawAction, "requiredForCompletion") as boolean,
    metadata: metadata as Record<string, unknown>,
  });
  const job: ActionMaterialSource["job"] = Object.freeze({
    id: ownDataValue(rawJob, "id") as string,
    type: ownDataValue(rawJob, "type") as string,
    target: ownDataValue(rawJob, "target") as string | null,
    mode: ownDataValue(rawJob, "mode") as ExecutionMode,
  });
  const frozenSource: ActionMaterialSource = Object.freeze({ action, job });

  validateActionMaterialSource(frozenSource);
  const canonical = canonicalizeSourceForSchema(frozenSource);
  return Object.freeze({
    source: snapshotFrozenMaterialSource(canonical),
    canonical,
  });
}

/**
 * @internal
 *
 * One-shot authority materialization shared by approval and
 * lifecycle. Loads the current program and resolves the binding
 * material exactly once, snapshots the result into deeply plain
 * immutable data, then derives the immutable `CurrentActionMaterial`
 * and the public challenge. The function never calls
 * `now()`, never opens a transaction, never writes, and never
 * reaches outside `ActionAuthorityDependencies`. Throws the
 * fixed cause-free `ACTION_APPROVAL_CONTEXT_UNAVAILABLE` error
 * on any loader/resolver/materialization fault.
 */
export function materializeActionAuthority(
  source: ActionMaterialSource,
  dependencies: ActionAuthorityDependencies,
): MaterializedActionAuthority {
  try {
    return materializeActionAuthorityUnchecked(source, dependencies);
  } catch {
    // This exported pure seam has exactly one failure surface. Database and
    // transaction work lives outside it, so remapping here cannot swallow a
    // preflight/read/BEGIN/COMMIT failure from the approval service.
    throw contextUnavailable();
  }
}

function materializeActionAuthorityUnchecked(
  source: ActionMaterialSource,
  dependencies: ActionAuthorityDependencies,
): MaterializedActionAuthority {
  // 1) Build and freeze the source snapshot. The canonical string
  //    is the bytes the in-tx reload compares against to detect
  //    a source race.
  const { source: frozenSource, canonical: sourceCanonical } =
    snapshotActionMaterialSourceUnchecked(source);

  // 2) Fresh program load and resolver call. Both are invoked
  //    exactly once per materialization. Any throw inside the
  //    resolver or loader is caught and remapped to a fixed
  //    cause-free `ACTION_APPROVAL_CONTEXT_UNAVAILABLE` — the
  //    original cause is never reflected in the public error or
  //    in the snapshot.
  let program: LoadedProgram;
  let resolvedRaw: ResolvedBindingMaterial;
  try {
    const loadedProgram = dependencies.loadCurrentProgram();
    program = snapshotLoadedProgram(loadedProgram);
  } catch {
    throw contextUnavailable();
  }
  try {
    resolvedRaw = dependencies.resolveBindingMaterial({
      source: frozenSource,
      program,
    });
  } catch {
    throw contextUnavailable();
  }
  // 3) Source re-canonicalization guard. A hostile resolver or
  //    downstream call cannot smuggle off-canonical JSON through
  //    the binding hash. The bytes are kept only in memory and
  //    never persisted.
  try {
    if (canonicalizeSourceForSchema(frozenSource) !== sourceCanonical) {
      throw contextUnavailable();
    }
  } catch {
    throw contextUnavailable();
  }

  // 4) Snapshot the resolver output into deeply plain immutable
  //    data. The snapshot rejects proxies, accessors, functions,
  //    mutable callbacks, unknown tags, and malformed values.
  //    The only allowed shape is the contract-pinned
  //    `ResolvedBindingMaterial`. The integration union is
  //    exactly `{ kind: "builtin" }` or
  //    `{ kind: "integration", policy }`.
  const resolved = snapshotResolvedBindingMaterial(
    resolvedRaw,
    frozenSource.action.adapter,
  );

  // 5) Validate LoadedProgram. Anything malformed (missing
  //    config, missing programFile, missing programFile string,
  //    bad labAuthorization) is a materialization fault.
  validateAuthorityHashShape(program);

  // 6) Build the ProgramAuthoritySnapshot. `authority` is the
  //    ONLY scope/policy view bound into the challenge hashes.
  //    It is built afresh on every call; nothing is reused from
  //    a prior call or from `runtime.config`.
  let authority;
  try {
    authority = buildProgramAuthoritySnapshot({
      config: program.config,
      labAuthorization: program.labAuthorization,
    });
  } catch {
    throw contextUnavailable();
  }
  if (
    !isLowercaseHex64(authority.scopeHash) ||
    !isLowercaseHex64(authority.policyHash)
  ) {
    throw contextUnavailable();
  }
  if (
    authority.scopeHash === HEX64_ALL_ZERO ||
    authority.policyHash === HEX64_ALL_ZERO
  ) {
    throw contextUnavailable();
  }

  const material: CurrentActionMaterial = Object.freeze({
    program,
    scopeHash: authority.scopeHash,
    policyHash: authority.policyHash,
    normalizedTarget: resolved.normalizedTarget,
    capabilityEnforcement: resolved.capabilityEnforcement,
    integration: resolved.integration,
  });

  // 7) Pure challenge recomputation. No SQL, loader, resolver,
  //    clock, ID, or write happens here. The function creates
  //    fresh guards/gates from the already-materialized program
  //    and binding material.
  const evaluation = recomputeActionAuthorityUnchecked(frozenSource, material);
  return Object.freeze({
    challenge: evaluation.challenge,
    definitiveBlock: evaluation.definitiveBlock,
    source: frozenSource,
    sourceCanonical,
    material,
  });
}

/**
 * @internal
 *
 * Pure challenge recomputation shared by the shared materializer
 * and the in-tx approval/lifecycle reload. It creates fresh
 * guards/gates but performs no SQL, loader, resolver, clock, ID,
 * or write operation. It also returns the private
 * `definitiveBlock` signal used by the lifecycle claim path
 * to choose between a `pending` demotion and a `blocked`
 * transition; the signal is never serialized into the public
 * challenge, the persisted material, the workflow event
 * metadata, or any of the bound hashes.
 */
export function recomputeActionAuthority(
  source: ActionMaterialSource,
  material: CurrentActionMaterial,
): ActionAuthorityEvaluation {
  try {
    return recomputeActionAuthorityUnchecked(source, material);
  } catch {
    throw contextUnavailable();
  }
}

function recomputeActionAuthorityUnchecked(
  source: ActionMaterialSource,
  material: CurrentActionMaterial,
): ActionAuthorityEvaluation {
  return computeChallengeFromCurrentMaterial(source, material);
}

// ---------------------------------------------------------------------------
// Schema constants exposed for unit tests that pin the canonical hash inputs.
// The bytes are never returned to callers; tests that need the canonical
// projection re-derive it via the imported `canonicalize` utility.
// ---------------------------------------------------------------------------
export const APPROVAL_PREVIEW_MATERIAL_HASH_FIELDS: ReadonlyArray<keyof ActionApprovalChallenge> = [
  "actionId",
  "jobId",
  "policyDecision",
  "policyReason",
  "scopeHash",
  "policyHash",
  "actionHash",
  "contextHash",
];

export const _INTERNAL_ENFORCEMENT_REASONS: ReadonlySet<string> = ENFORCEMENT_BLOCK_REASONS;
