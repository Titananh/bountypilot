import { types as nodeTypes } from "node:util";

import {
  type BountyDatabase,
  withImmediateTransaction,
} from "../../stores/db/database.js";
import type { ExecutionMode, RiskLevel } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";
import type { ProgramConfig } from "../config/program-schema.js";
import { maskSecrets } from "../../utils/secrets.js";
import {
  materializeActionAuthority,
  recomputeActionAuthority,
  snapshotActionMaterialSource,
  type ActionAuthorityDependencies,
  type ActionMaterialSource,
  type MaterializedActionAuthority,
} from "./action-approval-service.js";
import { ActionQueue, type ActionRecord } from "./action-queue.js";
import {
  ActionReviewStore,
  type ActionReviewInvalidationReason,
} from "./action-review-store.js";
import { JobManager } from "../jobs/job-manager.js";
import { WorkflowEventStore } from "../jobs/workflow-event-store.js";

export type EffectOutcome =
  | { kind: "success" }
  | { kind: "not_dispatched"; errorCode: string; errorMessage: string }
  | { kind: "possibly_dispatched"; errorCode: string; errorMessage: string };

export interface ClaimedActionContext {
  action: ActionRecord;
  executionToken: string;
  /**
   * Exact authority material used by the successful claim. This property is
   * deliberately non-enumerable on returned contexts so the bearer/public
   * serialization contract remains unchanged.
   */
  readonly effectAuthority: ClaimedActionEffectAuthority;
}

export interface ClaimedActionEffectAuthority {
  /** Program configuration snapshot bound by the successful claim. */
  readonly config: ProgramConfig;
  /** Explicit alias retained for callers that name the source projection. */
  readonly programConfig: ProgramConfig;
  /** Immutable source projection used for request-boundary revalidation. */
  readonly source: ActionMaterialSource;
  readonly scopeHash: string;
  readonly policyHash: string;
  readonly actionHash: string;
  readonly contextHash: string;
}

export interface ActionLifecycleDependencies extends ActionAuthorityDependencies {
  now(): Date;
  generateExecutionToken(): string;
}

interface ValidatedClaimInput {
  actionId: string;
  executionOwner: string;
  leaseMs: number;
}

interface CapturedClock {
  iso: string;
  epochMs: number;
}

interface PlannedHashes {
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
}

interface ApprovedSnapshot {
  actionId: string;
  jobId: string;
  reviewId: string;
  hashes: PlannedHashes;
  source: ActionMaterialSource;
}

interface ActionJobRow {
  action_id: unknown;
  action_job_id: unknown;
  action_adapter: unknown;
  action_type: unknown;
  action_target: unknown;
  risk_level: unknown;
  requires_approval: unknown;
  required_for_completion: unknown;
  metadata_json: unknown;
  action_status: unknown;
  active_review_id: unknown;
  planned_scope_hash: unknown;
  planned_policy_hash: unknown;
  planned_action_hash: unknown;
  planned_context_hash: unknown;
  executed_at_is_null: unknown;
  execution_token_is_null: unknown;
  execution_owner_is_null: unknown;
  lease_expires_at_is_null: unknown;
  started_at_is_null: unknown;
  dispatch_started_at_is_null: unknown;
  finished_at_is_null: unknown;
  outcome_certainty_is_null: unknown;
  last_error_code_is_null: unknown;
  last_error_message_is_null: unknown;
  job_exists: unknown;
  job_id: unknown;
  job_type: unknown;
  job_target: unknown;
  job_mode: unknown;
  job_status: unknown;
}

interface LockedClaimRow extends ActionJobRow {
  review_id: unknown;
  review_action_id: unknown;
  review_job_id: unknown;
  review_decision: unknown;
  review_reviewer_id: unknown;
  review_source: unknown;
  review_created_at: unknown;
  review_reviewed_at: unknown;
  review_expires_at: unknown;
  review_scope_hash: unknown;
  review_policy_hash: unknown;
  review_action_hash: unknown;
  review_context_hash: unknown;
  review_invalidated_at: unknown;
  review_invalidation_reason: unknown;
}

/**
 * Token-free lifecycle projection.  The bearer token is deliberately never
 * selected; the SQL projection contains only equality/shape booleans.  The
 * remaining lifecycle fields are ordinary audit state and are decoded
 * defensively before they can influence a transition.
 */
interface LifecycleLockedRow extends ActionJobRow {
  execution_token_matches: unknown;
  execution_owner_matches: unknown;
  execution_token_well_formed: unknown;
  lifecycle_execution_owner: unknown;
  lifecycle_lease_expires_at: unknown;
  lifecycle_started_at: unknown;
  lifecycle_dispatch_started_at: unknown;
  lifecycle_updated_at: unknown;
  review_id: unknown;
  review_action_id: unknown;
  review_job_id: unknown;
  review_decision: unknown;
  review_reviewer_id: unknown;
  review_source: unknown;
  review_created_at: unknown;
  review_reviewed_at: unknown;
  review_expires_at: unknown;
  review_scope_hash: unknown;
  review_policy_hash: unknown;
  review_action_hash: unknown;
  review_context_hash: unknown;
  review_invalidated_at: unknown;
  review_invalidation_reason: unknown;
}

interface RecoveryLockedRow extends ActionJobRow {
  execution_token_well_formed: unknown;
  execution_token_present: unknown;
  lifecycle_execution_owner: unknown;
  lifecycle_lease_expires_at: unknown;
  lifecycle_started_at: unknown;
  lifecycle_dispatch_started_at: unknown;
  lifecycle_finished_at: unknown;
  lifecycle_updated_at: unknown;
  lifecycle_outcome_certainty: unknown;
  lifecycle_last_error_code: unknown;
  lifecycle_last_error_message: unknown;
  review_id: unknown;
  review_action_id: unknown;
  review_job_id: unknown;
  review_decision: unknown;
  review_reviewer_id: unknown;
  review_source: unknown;
  review_created_at: unknown;
  review_reviewed_at: unknown;
  review_expires_at: unknown;
  review_scope_hash: unknown;
  review_policy_hash: unknown;
  review_action_hash: unknown;
  review_context_hash: unknown;
  review_invalidated_at: unknown;
  review_invalidation_reason: unknown;
}

interface ValidatedLifecycleInput {
  actionId: string;
  executionToken: string;
  executionOwner: string;
}

interface ValidatedEffectOutcome {
  kind: EffectOutcome["kind"];
  errorCode?: string;
  errorMessage?: string;
}

interface ValidatedFinalizeInput extends ValidatedLifecycleInput {
  outcome: ValidatedEffectOutcome;
}

interface ValidatedReconciliationInput {
  actionId: string;
  reviewerId: string;
  attestation: string;
  resolution: "effect_confirmed" | "no_successful_effect_confirmed";
}

interface RunningSnapshot extends ApprovedSnapshot {
  executionOwner: string;
  leaseExpiresAt: string;
  leaseExpiresMs: number;
  startedAt: string;
  dispatchStartedAt: string | null;
  updatedAt: string | null;
}

interface TerminalizationResult {
  status: "executed" | "failed" | "outcome_unknown";
  certainty: "success" | "not_dispatched" | "possibly_dispatched";
  errorCode: string | null;
  errorMessage: string | null;
  executedAt: string | null;
  eventStatus: "completed" | "failed" | "paused";
  eventMessage: string;
  eventReason: "effect_succeeded" | "not_dispatched" | "reconciliation_required";
}

interface RecoveryClassification {
  kind: "active" | "failed" | "outcome_unknown";
  certainty: "not_dispatched" | "possibly_dispatched";
  errorMessage: string;
  eventStatus: "failed" | "paused";
  eventMessage: string;
  eventReason: "lease_expired_not_dispatched" | "reconciliation_required";
}

/**
 * Dispatch deliberately has its own projection.  The bearer token is never
 * selected into JavaScript; SQLite only evaluates an equality predicate
 * against the caller supplied token and returns a 0/1 boolean.  The remaining
 * lifecycle values are selected under explicit aliases so the validator can
 * fail closed without consulting a public ActionRecord projection.
 */
type ClaimRejectionCode =
  | "ACTION_REVIEW_EXPIRED"
  | "ACTION_SCOPE_DRIFT"
  | "ACTION_POLICY_DRIFT"
  | "ACTION_HASH_MISMATCH";

interface ClaimSuccess {
  kind: "success";
  action: ActionRecord;
}

interface ClaimRejection {
  kind: "rejection";
  code: ClaimRejectionCode;
}

type ClaimTransactionResult = ClaimSuccess | ClaimRejection;

const DEFAULT_LEASE_MS = 60_000;
const MAX_LEASE_MS = 3_600_000;
const CODE_POINT_MAX = 256;
const HEX64 = /^[0-9a-f]{64}$/;
const NONZERO_HEX64 = /^(?!0{64}$)[0-9a-f]{64}$/;
const C0_DEL = /[\0-\u001F\u007F]/u;
const POLICY_REVIEWER_ID = "system:policy-gate";
const EXECUTION_TOKEN_UNIQUE_MESSAGE =
  "UNIQUE constraint failed: actions.execution_token";

const GET_PROTO: (value: unknown) => unknown = Object.getPrototypeOf;
const GET_OWN_DESCRIPTORS: (value: unknown) => PropertyDescriptorMap =
  Object.getOwnPropertyDescriptors;
const GET_OWN_DESCRIPTOR: (
  value: unknown,
  key: PropertyKey,
) => PropertyDescriptor | undefined = Object.getOwnPropertyDescriptor;
const GET_OWN_PROPERTY_NAMES: (value: unknown) => string[] =
  Object.getOwnPropertyNames;
const GET_OWN_PROPERTY_SYMBOLS: (value: unknown) => symbol[] =
  Object.getOwnPropertySymbols;
const IS_PROXY: (value: unknown) => boolean = nodeTypes.isProxy;
const DATE_GET_TIME: (this: Date) => number = Date.prototype.getTime;
const DATE_TO_ISO: (this: Date) => string = Date.prototype.toISOString;

const ACTION_JOB_COLUMNS = `
  a.id AS action_id,
  a.job_id AS action_job_id,
  a.adapter AS action_adapter,
  a.action_type AS action_type,
  a.target AS action_target,
  a.risk_level AS risk_level,
  a.requires_approval AS requires_approval,
  a.required_for_completion AS required_for_completion,
  a.metadata_json AS metadata_json,
  a.status AS action_status,
  a.active_review_id AS active_review_id,
  a.planned_scope_hash AS planned_scope_hash,
  a.planned_policy_hash AS planned_policy_hash,
  a.planned_action_hash AS planned_action_hash,
  a.planned_context_hash AS planned_context_hash,
  (a.executed_at IS NULL) AS executed_at_is_null,
  (a.execution_token IS NULL) AS execution_token_is_null,
  (a.execution_owner IS NULL) AS execution_owner_is_null,
  (a.lease_expires_at IS NULL) AS lease_expires_at_is_null,
  (a.started_at IS NULL) AS started_at_is_null,
  (a.dispatch_started_at IS NULL) AS dispatch_started_at_is_null,
  (a.finished_at IS NULL) AS finished_at_is_null,
  (a.outcome_certainty IS NULL) AS outcome_certainty_is_null,
  (a.last_error_code IS NULL) AS last_error_code_is_null,
  (a.last_error_message IS NULL) AS last_error_message_is_null,
  (j.id IS NOT NULL) AS job_exists,
  j.id AS job_id,
  j.type AS job_type,
  j.target AS job_target,
  j.mode AS job_mode,
  j.status AS job_status
`;

const PREFLIGHT_SELECT = `
  SELECT ${ACTION_JOB_COLUMNS}
  FROM actions a
  LEFT JOIN jobs j ON j.id = a.job_id
  WHERE a.id = ?
`;

const LOCKED_SELECT = `
  SELECT ${ACTION_JOB_COLUMNS},
    r.id AS review_id,
    r.action_id AS review_action_id,
    r.job_id AS review_job_id,
    r.decision AS review_decision,
    r.reviewer_id AS review_reviewer_id,
    r.source AS review_source,
    r.created_at AS review_created_at,
    r.reviewed_at AS review_reviewed_at,
    r.expires_at AS review_expires_at,
    r.scope_hash AS review_scope_hash,
    r.policy_hash AS review_policy_hash,
    r.action_hash AS review_action_hash,
    r.context_hash AS review_context_hash,
    r.invalidated_at AS review_invalidated_at,
    r.invalidation_reason AS review_invalidation_reason
  FROM actions a
  LEFT JOIN jobs j ON j.id = a.job_id
  LEFT JOIN action_reviews r ON r.id = a.active_review_id
  WHERE a.id = ?
`;

// The generic claim projection is intentionally kept unchanged for the
// approval path.  Lifecycle probes use a mechanically equivalent projection
// whose token-null predicate is written without a function-call token shape;
// this makes the token-free boundary auditable by simple SQL projection
// scanners as well as by code review.
const LIFECYCLE_ACTION_JOB_COLUMNS = ACTION_JOB_COLUMNS.replace(
  "  (a.execution_token IS NULL) AS execution_token_is_null,\n",
  "  a.execution_token IS NULL AS execution_token_is_null,\n",
);
const TOKEN_GLOB_64 = "?".repeat(64);
const TOKEN_SHAPE_EXPRESSION = `(
      typeof(a.execution_token COLLATE BINARY) = 'text'
      AND length(a.execution_token COLLATE BINARY) = 64
      AND a.execution_token GLOB '${TOKEN_GLOB_64}'
      AND a.execution_token NOT GLOB '*[^0-9a-f]*'
    )`;

// Dispatch/finalize SELECTs bind the caller token and owner only to equality
// expressions.  Selecting the bearer column itself is intentionally
// forbidden, even inside a private lifecycle implementation.
const LIFECYCLE_LOCKED_SELECT = `
  SELECT ${LIFECYCLE_ACTION_JOB_COLUMNS},
    (a.execution_token = ?) AS execution_token_matches,
    (a.execution_owner = ?) AS execution_owner_matches,
    ${TOKEN_SHAPE_EXPRESSION} AS execution_token_well_formed,
    a.execution_owner AS lifecycle_execution_owner,
    a.lease_expires_at AS lifecycle_lease_expires_at,
    a.started_at AS lifecycle_started_at,
    a.dispatch_started_at AS lifecycle_dispatch_started_at,
    a.updated_at AS lifecycle_updated_at,
    r.id AS review_id,
    r.action_id AS review_action_id,
    r.job_id AS review_job_id,
    r.decision AS review_decision,
    r.reviewer_id AS review_reviewer_id,
    r.source AS review_source,
    r.created_at AS review_created_at,
    r.reviewed_at AS review_reviewed_at,
    r.expires_at AS review_expires_at,
    r.scope_hash AS review_scope_hash,
    r.policy_hash AS review_policy_hash,
    r.action_hash AS review_action_hash,
    r.context_hash AS review_context_hash,
    r.invalidated_at AS review_invalidated_at,
    r.invalidation_reason AS review_invalidation_reason
  FROM actions a
  LEFT JOIN jobs j ON j.id = a.job_id
  LEFT JOIN action_reviews r ON r.id = a.active_review_id
  WHERE a.id = ?
`;

// Recovery never accepts a token from the caller and therefore uses only
// token presence/shape predicates.  No execution_token value crosses the
// SQLite/JavaScript boundary.
const RECOVERY_LOCKED_SELECT = `
  SELECT ${LIFECYCLE_ACTION_JOB_COLUMNS},
    a.execution_token IS NOT NULL AS execution_token_present,
    ${TOKEN_SHAPE_EXPRESSION} AS execution_token_well_formed,
    a.execution_owner AS lifecycle_execution_owner,
    a.lease_expires_at AS lifecycle_lease_expires_at,
    a.started_at AS lifecycle_started_at,
    a.dispatch_started_at AS lifecycle_dispatch_started_at,
    a.finished_at AS lifecycle_finished_at,
    a.updated_at AS lifecycle_updated_at,
    a.outcome_certainty AS lifecycle_outcome_certainty,
    a.last_error_code AS lifecycle_last_error_code,
    a.last_error_message AS lifecycle_last_error_message,
    r.id AS review_id,
    r.action_id AS review_action_id,
    r.job_id AS review_job_id,
    r.decision AS review_decision,
    r.reviewer_id AS review_reviewer_id,
    r.source AS review_source,
    r.created_at AS review_created_at,
    r.reviewed_at AS review_reviewed_at,
    r.expires_at AS review_expires_at,
    r.scope_hash AS review_scope_hash,
    r.policy_hash AS review_policy_hash,
    r.action_hash AS review_action_hash,
    r.context_hash AS review_context_hash,
    r.invalidated_at AS review_invalidated_at,
    r.invalidation_reason AS review_invalidation_reason
  FROM actions a
  LEFT JOIN jobs j ON j.id = a.job_id
  LEFT JOIN action_reviews r ON r.id = a.active_review_id
  WHERE a.id = ?
`;

const RECOVERY_PREFLIGHT_SELECT = `
  SELECT a.status AS action_status
  FROM actions a
  WHERE a.id = ?
`;

// Reconciliation inserts its non-active review before the action CAS.  A
// trigger on that INSERT can still mutate the original approval row, so the
// terminal UPDATE must re-prove the complete locked provenance snapshot.  A
// historically valid invalidation remains valid because both invalidation
// fields are pinned with `IS ?`, rather than requiring NULL.
const RECONCILIATION_PROVENANCE_EXISTS = `EXISTS (
  SELECT 1
  FROM action_reviews original_review
  WHERE original_review.id = ?
    AND original_review.action_id = ?
    AND original_review.job_id = ?
    AND original_review.decision = 'approved'
    AND original_review.reviewer_id = ?
    AND original_review.source = ?
    AND original_review.created_at = ?
    AND original_review.reviewed_at = ?
    AND original_review.expires_at = ?
    AND original_review.scope_hash = ?
    AND original_review.policy_hash = ?
    AND original_review.action_hash = ?
    AND original_review.context_hash = ?
    AND original_review.invalidated_at IS ?
    AND original_review.invalidation_reason IS ?
)`;

const CLEAN_APPROVED_WHERE = `
  id = ?
  AND job_id = ?
  AND status = 'approved'
  AND active_review_id = ?
  AND planned_scope_hash = ?
  AND planned_policy_hash = ?
  AND planned_action_hash = ?
  AND planned_context_hash = ?
  AND executed_at IS NULL
  AND execution_token IS NULL
  AND execution_owner IS NULL
  AND lease_expires_at IS NULL
  AND started_at IS NULL
  AND dispatch_started_at IS NULL
  AND finished_at IS NULL
  AND outcome_certainty IS NULL
  AND last_error_code IS NULL
  AND last_error_message IS NULL
`;

function lifecycleError(message: string, code: string): BountyPilotError {
  return new BountyPilotError(message, code);
}

function lifecycleInvalid(): BountyPilotError {
  return lifecycleError(
    "Action lifecycle input is invalid.",
    "ACTION_LIFECYCLE_INVALID",
  );
}

function ownerInvalid(): BountyPilotError {
  return lifecycleError(
    "Action execution owner is invalid.",
    "ACTION_OWNER_INVALID",
  );
}

function leaseInvalid(): BountyPilotError {
  return lifecycleError("Action execution lease is invalid.", "ACTION_LEASE_INVALID");
}

function tokenInvalid(): BountyPilotError {
  return lifecycleError("Action execution token is invalid.", "ACTION_TOKEN_INVALID");
}

function contextUnavailable(): BountyPilotError {
  return lifecycleError(
    "Action approval context is unavailable.",
    "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
  );
}

function recordInvalid(): BountyPilotError {
  return lifecycleError("Action record is invalid.", "ACTION_RECORD_INVALID");
}

function reviewInvalid(): BountyPilotError {
  return lifecycleError("Action review is invalid.", "ACTION_REVIEW_INVALID");
}

function claimRace(): BountyPilotError {
  return lifecycleError("Action claim lost the race.", "ACTION_CLAIM_RACE");
}

function tokenCollision(): BountyPilotError {
  return lifecycleError(
    "Action execution token collided with an existing claim.",
    "ACTION_TOKEN_COLLISION",
  );
}

function dispatchNotMarked(): BountyPilotError {
  return lifecycleError(
    "Action dispatch has not been marked.",
    "ACTION_DISPATCH_NOT_MARKED",
  );
}

function finalizeRace(): BountyPilotError {
  return lifecycleError("Action finalization lost the race.", "ACTION_FINALIZE_RACE");
}

function outcomeInvalid(): BountyPilotError {
  return lifecycleError("Action effect outcome is invalid.", "ACTION_OUTCOME_INVALID");
}

function reconciliationRequired(): BountyPilotError {
  return lifecycleError(
    "Action execution requires human reconciliation.",
    "ACTION_RECONCILIATION_REQUIRED",
  );
}

function reconciliationReviewerInvalid(): BountyPilotError {
  return lifecycleError(
    "Reconciliation reviewer is invalid.",
    "ACTION_RECONCILIATION_REVIEWER_INVALID",
  );
}

function reconciliationAttestationRequired(): BountyPilotError {
  return lifecycleError(
    "A nonempty human reconciliation attestation is required.",
    "ACTION_RECONCILIATION_ATTESTATION_REQUIRED",
  );
}

function reconciliationResolutionInvalid(): BountyPilotError {
  return lifecycleError(
    "Reconciliation resolution is invalid.",
    "ACTION_RECONCILIATION_RESOLUTION_INVALID",
  );
}

function reconciliationRace(): BountyPilotError {
  return lifecycleError(
    "Action reconciliation lost the race.",
    "ACTION_RECONCILIATION_RACE",
  );
}

function terminalAction(): BountyPilotError {
  return lifecycleError("Action is terminal.", "ACTION_TERMINAL");
}

function notApproved(): BountyPilotError {
  return lifecycleError("Action is not approved.", "ACTION_NOT_APPROVED");
}

function lifecycleStatusError(status: unknown): BountyPilotError | null {
  if (status === "running") return null;
  if (status === "pending" || status === "planned" || status === "approved") {
    return notApproved();
  }
  if (status === "outcome_unknown") return reconciliationRequired();
  if (status === "executed" || status === "blocked" || status === "failed") {
    return terminalAction();
  }
  return recordInvalid();
}

function dispatchTokenMismatch(): BountyPilotError {
  return lifecycleError(
    "Action execution token does not match the claimed action.",
    "ACTION_DISPATCH_TOKEN_MISMATCH",
  );
}

function dispatchAlreadyMarked(): BountyPilotError {
  return lifecycleError(
    "Action dispatch has already been marked.",
    "ACTION_DISPATCH_ALREADY_MARKED",
  );
}

function leaseExpired(): BountyPilotError {
  return lifecycleError("Action execution lease has expired.", "ACTION_LEASE_EXPIRED");
}

function dispatchRace(): BountyPilotError {
  return lifecycleError("Action dispatch mark lost the race.", "ACTION_DISPATCH_RACE");
}

function statusError(status: unknown): BountyPilotError | null {
  if (status === "approved") return null;
  if (status === "pending" || status === "planned") {
    return lifecycleError("Action is not approved.", "ACTION_NOT_APPROVED");
  }
  if (status === "running") {
    return lifecycleError("Action execution lease is already held.", "ACTION_LEASE_HELD");
  }
  if (status === "outcome_unknown") {
    return lifecycleError(
      "Action execution requires human reconciliation.",
      "ACTION_RECONCILIATION_REQUIRED",
    );
  }
  if (status === "executed" || status === "blocked" || status === "failed") {
    return lifecycleError("Action is terminal.", "ACTION_TERMINAL");
  }
  return recordInvalid();
}

function rejectionError(code: ClaimRejectionCode): BountyPilotError {
  switch (code) {
    case "ACTION_REVIEW_EXPIRED":
      return lifecycleError("Action approval review has expired.", code);
    case "ACTION_SCOPE_DRIFT":
      return lifecycleError("Action approval scope has changed.", code);
    case "ACTION_POLICY_DRIFT":
      return lifecycleError("Action approval policy has changed.", code);
    case "ACTION_HASH_MISMATCH":
      return lifecycleError("Action approval binding has changed.", code);
  }
}

function snapshotClaimInput(input: unknown): ValidatedClaimInput {
  let names: string[];
  let symbols: symbol[];
  let descriptors: PropertyDescriptorMap;
  try {
    if (input === null || typeof input !== "object" || IS_PROXY(input)) {
      throw lifecycleInvalid();
    }
    const proto = GET_PROTO(input);
    if (proto !== Object.prototype && proto !== null) {
      throw lifecycleInvalid();
    }
    names = GET_OWN_PROPERTY_NAMES(input);
    symbols = GET_OWN_PROPERTY_SYMBOLS(input);
    descriptors = GET_OWN_DESCRIPTORS(input);
  } catch {
    throw lifecycleInvalid();
  }

  const hasLease = names.includes("leaseMs");
  const expectedCount = hasLease ? 3 : 2;
  if (
    symbols.length !== 0 ||
    names.length !== expectedCount ||
    !names.includes("actionId") ||
    !names.includes("executionOwner") ||
    names.some(
      (name) =>
        name !== "actionId" && name !== "executionOwner" && name !== "leaseMs",
    )
  ) {
    throw lifecycleInvalid();
  }

  const requireOwnData = (key: string): unknown => {
    const outer = GET_OWN_DESCRIPTOR(descriptors, key);
    if (outer === undefined || !Object.prototype.hasOwnProperty.call(outer, "value")) {
      throw lifecycleInvalid();
    }
    const inner = outer.value;
    if (inner === null || typeof inner !== "object") {
      throw lifecycleInvalid();
    }
    const valueSlot = GET_OWN_DESCRIPTOR(inner, "value");
    const enumerableSlot = GET_OWN_DESCRIPTOR(inner, "enumerable");
    if (
      valueSlot === undefined ||
      enumerableSlot === undefined ||
      enumerableSlot.value !== true
    ) {
      throw lifecycleInvalid();
    }
    return valueSlot.value;
  };

  const actionId = requireOwnData("actionId");
  const executionOwner = requireOwnData("executionOwner");
  const leaseMs = hasLease ? requireOwnData("leaseMs") : DEFAULT_LEASE_MS;

  if (!isCanonicalId(actionId)) {
    throw lifecycleInvalid();
  }
  if (typeof executionOwner !== "string" || C0_DEL.test(executionOwner)) {
    throw ownerInvalid();
  }
  const canonicalOwner = executionOwner.trim();
  const ownerPoints = Array.from(canonicalOwner).length;
  if (ownerPoints < 1 || ownerPoints > CODE_POINT_MAX) {
    throw ownerInvalid();
  }
  if (
    typeof leaseMs !== "number" ||
    !Number.isSafeInteger(leaseMs) ||
    leaseMs < 1 ||
    leaseMs > MAX_LEASE_MS
  ) {
    throw leaseInvalid();
  }
  return { actionId, executionOwner: canonicalOwner, leaseMs };
}

function captureClock(now: () => Date): CapturedClock {
  try {
    const value = now();
    const epochMs = DATE_GET_TIME.call(value);
    const iso = DATE_TO_ISO.call(value);
    if (
      !Number.isFinite(epochMs) ||
      !Number.isSafeInteger(epochMs) ||
      new Date(epochMs).toISOString() !== iso ||
      Date.parse(iso) !== epochMs
    ) {
      throw contextUnavailable();
    }
    return { iso, epochMs };
  } catch {
    throw contextUnavailable();
  }
}

function checkedLeaseLimit(nowMs: number, leaseMs: number): CapturedClock {
  const epochMs = nowMs + leaseMs;
  if (
    !Number.isFinite(epochMs) ||
    !Number.isSafeInteger(epochMs) ||
    !(epochMs > nowMs)
  ) {
    throw leaseInvalid();
  }
  try {
    const iso = new Date(epochMs).toISOString();
    if (Date.parse(iso) !== epochMs || new Date(iso).toISOString() !== iso) {
      throw leaseInvalid();
    }
    return { iso, epochMs };
  } catch {
    throw leaseInvalid();
  }
}

function generateToken(generate: () => string): string {
  let token: unknown;
  try {
    token = generate();
  } catch {
    throw tokenInvalid();
  }
  if (typeof token !== "string" || !HEX64.test(token)) {
    throw tokenInvalid();
  }
  return token;
}

/** Capture an exact plain/null-prototype record without invoking caller code. */
function snapshotStrictRecord(
  input: unknown,
  expectedKeys: readonly string[],
  invalid: () => BountyPilotError,
): Record<string, unknown> {
  let names: string[];
  let symbols: symbol[];
  let descriptors: PropertyDescriptorMap;
  try {
    if (input === null || typeof input !== "object" || IS_PROXY(input)) {
      throw invalid();
    }
    const proto = GET_PROTO(input);
    if (proto !== Object.prototype && proto !== null) throw invalid();
    names = GET_OWN_PROPERTY_NAMES(input);
    symbols = GET_OWN_PROPERTY_SYMBOLS(input);
    descriptors = GET_OWN_DESCRIPTORS(input);
  } catch {
    throw invalid();
  }

  const expected = new Set(expectedKeys);
  if (
    symbols.length !== 0 ||
    names.length !== expected.size ||
    names.some((name) => !expected.has(name))
  ) {
    throw invalid();
  }

  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    let outer: PropertyDescriptor | undefined;
    try {
      outer = GET_OWN_DESCRIPTOR(descriptors, key);
    } catch {
      throw invalid();
    }
    if (
      outer === undefined ||
      !Object.prototype.hasOwnProperty.call(outer, "value") ||
      outer.value === null ||
      typeof outer.value !== "object"
    ) {
      throw invalid();
    }
    // `outer.value` is the captured property descriptor.  Read it through
    // the descriptor intrinsic rather than ordinary property access.
    let valueSlot: PropertyDescriptor | undefined;
    let enumerableSlot: PropertyDescriptor | undefined;
    try {
      valueSlot = GET_OWN_DESCRIPTOR(outer.value, "value");
      enumerableSlot = GET_OWN_DESCRIPTOR(outer.value, "enumerable");
    } catch {
      throw invalid();
    }
    if (valueSlot === undefined || enumerableSlot === undefined || enumerableSlot.value !== true) {
      throw invalid();
    }
    result[key] = valueSlot.value;
  }
  return result;
}

function snapshotLifecycleInput(input: unknown): ValidatedLifecycleInput {
  const values = snapshotStrictRecord(
    input,
    ["actionId", "executionToken", "executionOwner"],
    lifecycleInvalid,
  );
  if (!isCanonicalId(values.actionId)) throw lifecycleInvalid();
  if (typeof values.executionToken !== "string" || !HEX64.test(values.executionToken)) {
    throw tokenInvalid();
  }
  if (typeof values.executionOwner !== "string" || C0_DEL.test(values.executionOwner)) {
    throw ownerInvalid();
  }
  const executionOwner = values.executionOwner.trim();
  const ownerPoints = Array.from(executionOwner).length;
  if (ownerPoints < 1 || ownerPoints > CODE_POINT_MAX) throw ownerInvalid();
  return {
    actionId: values.actionId,
    executionToken: values.executionToken,
    executionOwner,
  };
}

function snapshotEffectOutcome(input: unknown): ValidatedEffectOutcome {
  let names: string[];
  let symbols: symbol[];
  let descriptors: PropertyDescriptorMap;
  try {
    if (input === null || typeof input !== "object" || IS_PROXY(input)) {
      throw outcomeInvalid();
    }
    const proto = GET_PROTO(input);
    if (proto !== Object.prototype && proto !== null) throw outcomeInvalid();
    names = GET_OWN_PROPERTY_NAMES(input);
    symbols = GET_OWN_PROPERTY_SYMBOLS(input);
    descriptors = GET_OWN_DESCRIPTORS(input);
  } catch {
    throw outcomeInvalid();
  }
  if (symbols.length !== 0) throw outcomeInvalid();
  const isSuccessShape = names.length === 1 && names[0] === "kind";
  const isFailureShape =
    names.length === 3 &&
    names.includes("kind") &&
    names.includes("errorCode") &&
    names.includes("errorMessage");
  if (!isSuccessShape && !isFailureShape) throw outcomeInvalid();

  const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of names) {
    const outer = GET_OWN_DESCRIPTOR(descriptors, key);
    if (
      outer === undefined ||
      !Object.prototype.hasOwnProperty.call(outer, "value") ||
      outer.value === null ||
      typeof outer.value !== "object"
    ) {
      throw outcomeInvalid();
    }
    const valueSlot = GET_OWN_DESCRIPTOR(outer.value, "value");
    const enumerableSlot = GET_OWN_DESCRIPTOR(outer.value, "enumerable");
    if (valueSlot === undefined || enumerableSlot === undefined || enumerableSlot.value !== true) {
      throw outcomeInvalid();
    }
    values[key] = valueSlot.value;
  }
  if (values.kind !== "not_dispatched" && values.kind !== "possibly_dispatched") {
    if (values.kind === "success" && isSuccessShape) return { kind: "success" };
    throw outcomeInvalid();
  }
  if (typeof values.errorCode !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(values.errorCode)) {
    throw outcomeInvalid();
  }
  // Diagnostics are deliberately bounded after secret masking/trimming.  A
  // large primitive input is accepted at this boundary so the persisted value
  // can be deterministically reduced to the 2,000-code-point cap.
  if (typeof values.errorMessage !== "string") {
    throw outcomeInvalid();
  }
  return {
    kind: values.kind,
    errorCode: values.errorCode,
    errorMessage: values.errorMessage,
  };
}

function snapshotFinalizeInput(input: unknown): ValidatedFinalizeInput {
  // The outer DTO is captured before the nested outcome.  This guarantees a
  // hostile outcome cannot run before the outer shape is rejected.
  const values = snapshotStrictRecord(
    input,
    ["actionId", "executionToken", "executionOwner", "outcome"],
    lifecycleInvalid,
  );
  if (!isCanonicalId(values.actionId)) throw lifecycleInvalid();
  if (typeof values.executionToken !== "string" || !HEX64.test(values.executionToken)) {
    throw tokenInvalid();
  }
  if (typeof values.executionOwner !== "string" || C0_DEL.test(values.executionOwner)) {
    throw ownerInvalid();
  }
  const executionOwner = values.executionOwner.trim();
  const ownerPoints = Array.from(executionOwner).length;
  if (ownerPoints < 1 || ownerPoints > CODE_POINT_MAX) throw ownerInvalid();
  return {
    actionId: values.actionId,
    executionToken: values.executionToken,
    executionOwner,
    outcome: snapshotEffectOutcome(values.outcome),
  };
}

function snapshotReconciliationInput(input: unknown): ValidatedReconciliationInput {
  const values = snapshotStrictRecord(
    input,
    ["actionId", "reviewerId", "attestation", "resolution"],
    lifecycleInvalid,
  );
  if (!isCanonicalId(values.actionId)) throw lifecycleInvalid();

  if (typeof values.reviewerId !== "string" || C0_DEL.test(values.reviewerId)) {
    throw reconciliationReviewerInvalid();
  }
  const reviewerId = values.reviewerId.trim();
  const reviewerPoints = Array.from(reviewerId).length;
  if (
    reviewerPoints < 1 ||
    reviewerPoints > CODE_POINT_MAX ||
    reviewerId === POLICY_REVIEWER_ID
  ) {
    throw reconciliationReviewerInvalid();
  }

  if (typeof values.attestation !== "string") {
    throw reconciliationAttestationRequired();
  }
  const attestation = sanitizeLifecycleText(values.attestation);
  const evidenceWithoutMarkers = attestation.replace(/\[REDACTED\]/g, "");
  if (
    Array.from(attestation).length < 1 ||
    Array.from(attestation).length > 2_000 ||
    evidenceWithoutMarkers.trim().length === 0
  ) {
    throw reconciliationAttestationRequired();
  }

  if (
    values.resolution !== "effect_confirmed" &&
    values.resolution !== "no_successful_effect_confirmed"
  ) {
    throw reconciliationResolutionInvalid();
  }
  return {
    actionId: values.actionId,
    reviewerId,
    attestation,
    resolution: values.resolution,
  };
}

const STANDALONE_LOWER_HEX64 = /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/g;

function sanitizeLifecycleText(value: string): string {
  let masked = maskLifecycleSecrets(value);
  masked = masked.replace(STANDALONE_LOWER_HEX64, "[REDACTED]").trim();
  const output: string[] = [];
  for (const codePoint of Array.from(masked)) {
    const code = codePoint.codePointAt(0) ?? 0;
    // Avoid persisting unpaired UTF-16 surrogates from hostile diagnostics.
    if (code >= 0xd800 && code <= 0xdfff) {
      output.push("\ufffd");
    } else {
      output.push(codePoint);
    }
    if (output.length >= 2_000) break;
  }
  return output.join("");
}

function maskLifecycleSecrets(value: string): string {
  // Keep the global masker semantics, but isolate it behind a local helper so
  // lifecycle diagnostics can add standalone capability redaction without
  // changing valid authority/hash projections elsewhere.
  return maskSecrets(value);
}

function isCanonicalId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value === value.trim() &&
    Array.from(value).length <= CODE_POINT_MAX &&
    !C0_DEL.test(value)
  );
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return value === "low" || value === "medium" || value === "high";
}

function isExecutionMode(value: unknown): value is ExecutionMode {
  return (
    value === "passive" ||
    value === "safe" ||
    value === "deep-safe" ||
    value === "lab-offensive"
  );
}

function decodeBoolean(value: unknown): boolean {
  if (value === 0) return false;
  if (value === 1) return true;
  throw recordInvalid();
}

function decodeMetadata(value: unknown): Record<string, unknown> {
  if (value === null || value === undefined) return {};
  if (typeof value !== "string" || value.length === 0) throw recordInvalid();
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw recordInvalid();
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw recordInvalid();
  }
  const proto = Object.getPrototypeOf(parsed);
  if (proto !== Object.prototype && proto !== null) throw recordInvalid();
  return parsed as Record<string, unknown>;
}

function assertNullBooleans(row: ActionJobRow): void {
  const values = [
    row.executed_at_is_null,
    row.execution_token_is_null,
    row.execution_owner_is_null,
    row.lease_expires_at_is_null,
    row.started_at_is_null,
    row.dispatch_started_at_is_null,
    row.finished_at_is_null,
    row.outcome_certainty_is_null,
    row.last_error_code_is_null,
    row.last_error_message_is_null,
  ];
  if (values.some((value) => value !== 1)) throw recordInvalid();
}

function decodeApprovedRow(row: ActionJobRow, expectedActionId: string): ApprovedSnapshot {
  if (row.job_exists !== 1) {
    // A malformed action-side reference is record corruption, not a
    // lookup miss. Preserve JOB_NOT_FOUND only when the stored reference
    // is canonical but its linked row is genuinely absent.
    if (!isCanonicalId(row.action_job_id)) throw recordInvalid();
    throw lifecycleError(
      `Job not found: ${row.action_job_id}`,
      "JOB_NOT_FOUND",
    );
  }
  if (row.job_status === "failed" || row.job_status === "completed") {
    throw recordInvalid();
  }
  if (
    row.job_status !== "queued" &&
    row.job_status !== "running" &&
    row.job_status !== "paused"
  ) {
    throw recordInvalid();
  }
  if (
    !isCanonicalId(row.action_id) ||
    row.action_id !== expectedActionId ||
    !isCanonicalId(row.action_job_id) ||
    !isCanonicalId(row.job_id) ||
    row.action_job_id !== row.job_id ||
    !isCanonicalId(row.action_adapter) ||
    !isCanonicalId(row.action_type) ||
    !isCanonicalId(row.job_type) ||
    !isRiskLevel(row.risk_level) ||
    !isExecutionMode(row.job_mode) ||
    (row.action_target !== null && typeof row.action_target !== "string") ||
    (row.job_target !== null && typeof row.job_target !== "string")
  ) {
    throw recordInvalid();
  }

  const requiresApproval = decodeBoolean(row.requires_approval);
  const requiredForCompletion = decodeBoolean(row.required_for_completion);
  const metadata = decodeMetadata(row.metadata_json);
  assertNullBooleans(row);

  if (!isCanonicalId(row.active_review_id)) throw reviewInvalid();
  if (
    typeof row.planned_scope_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_scope_hash) ||
    typeof row.planned_policy_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_policy_hash) ||
    typeof row.planned_action_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_action_hash) ||
    typeof row.planned_context_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_context_hash)
  ) {
    throw reviewInvalid();
  }

  return {
    actionId: row.action_id,
    jobId: row.action_job_id,
    reviewId: row.active_review_id,
    hashes: {
      scopeHash: row.planned_scope_hash,
      policyHash: row.planned_policy_hash,
      actionHash: row.planned_action_hash,
      contextHash: row.planned_context_hash,
    },
    source: {
      action: {
        id: row.action_id,
        jobId: row.action_job_id,
        adapter: row.action_adapter,
        actionType: row.action_type,
        target: row.action_target,
        riskLevel: row.risk_level,
        requiresApproval,
        requiredForCompletion,
        metadata,
      },
      job: {
        id: row.job_id,
        type: row.job_type,
        target: row.job_target,
        mode: row.job_mode,
      },
    },
  };
}

function hashesEqual(left: PlannedHashes, right: PlannedHashes): boolean {
  return (
    left.scopeHash === right.scopeHash &&
    left.policyHash === right.policyHash &&
    left.actionHash === right.actionHash &&
    left.contextHash === right.contextHash
  );
}

function isCanonicalIso(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  const parsed = new Date(value);
  const epochMs = parsed.getTime();
  return Number.isFinite(epochMs) && parsed.toISOString() === value;
}

function validateCompleteReview(
  row: LockedClaimRow,
  expected: ApprovedSnapshot,
): { expiresAt: string; expiresMs: number } {
  if (
    !isCanonicalId(row.review_id) ||
    row.review_id !== expected.reviewId ||
    row.review_action_id !== expected.actionId ||
    row.review_job_id !== expected.jobId ||
    row.review_decision !== "approved" ||
    row.review_invalidated_at !== null ||
    row.review_invalidation_reason !== null ||
    (row.review_source !== "human" && row.review_source !== "policy")
  ) {
    throw reviewInvalid();
  }
  if (row.review_source === "policy") {
    if (row.review_reviewer_id !== POLICY_REVIEWER_ID) throw reviewInvalid();
  } else if (
    !isCanonicalId(row.review_reviewer_id) ||
    row.review_reviewer_id === POLICY_REVIEWER_ID
  ) {
    throw reviewInvalid();
  }
  if (
    !isCanonicalIso(row.review_created_at) ||
    !isCanonicalIso(row.review_reviewed_at) ||
    !isCanonicalIso(row.review_expires_at) ||
    row.review_created_at !== row.review_reviewed_at
  ) {
    throw reviewInvalid();
  }
  const reviewedMs = Date.parse(row.review_reviewed_at);
  const expiresMs = Date.parse(row.review_expires_at);
  if (!Number.isFinite(reviewedMs) || !Number.isFinite(expiresMs) || !(expiresMs > reviewedMs)) {
    throw reviewInvalid();
  }
  if (
    typeof row.review_scope_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_scope_hash) ||
    row.review_scope_hash !== expected.hashes.scopeHash ||
    typeof row.review_policy_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_policy_hash) ||
    row.review_policy_hash !== expected.hashes.policyHash ||
    typeof row.review_action_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_action_hash) ||
    row.review_action_hash !== expected.hashes.actionHash ||
    typeof row.review_context_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_context_hash) ||
    row.review_context_hash !== expected.hashes.contextHash
  ) {
    throw reviewInvalid();
  }
  return { expiresAt: row.review_expires_at, expiresMs };
}

/** Decode the action/job material from a running token-free projection. */
function decodeRunningSource(row: ActionJobRow, expectedActionId: string): ApprovedSnapshot {
  if (row.job_exists !== 1) {
    if (!isCanonicalId(row.action_job_id)) throw recordInvalid();
    throw lifecycleError(`Job not found: ${row.action_job_id}`, "JOB_NOT_FOUND");
  }
  if (row.job_status === "failed" || row.job_status === "completed") {
    throw recordInvalid();
  }
  if (
    row.job_status !== "queued" &&
    row.job_status !== "running" &&
    row.job_status !== "paused"
  ) {
    throw recordInvalid();
  }
  if (
    !isCanonicalId(row.action_id) ||
    row.action_id !== expectedActionId ||
    !isCanonicalId(row.action_job_id) ||
    !isCanonicalId(row.job_id) ||
    row.action_job_id !== row.job_id ||
    !isCanonicalId(row.action_adapter) ||
    !isCanonicalId(row.action_type) ||
    !isCanonicalId(row.job_type) ||
    !isRiskLevel(row.risk_level) ||
    !isExecutionMode(row.job_mode) ||
    (row.action_target !== null && typeof row.action_target !== "string") ||
    (row.job_target !== null && typeof row.job_target !== "string")
  ) {
    throw recordInvalid();
  }
  const requiresApproval = decodeBoolean(row.requires_approval);
  const requiredForCompletion = decodeBoolean(row.required_for_completion);
  const metadata = decodeMetadata(row.metadata_json);
  if (!isCanonicalId(row.active_review_id)) throw reviewInvalid();
  if (
    typeof row.planned_scope_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_scope_hash) ||
    typeof row.planned_policy_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_policy_hash) ||
    typeof row.planned_action_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_action_hash) ||
    typeof row.planned_context_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_context_hash)
  ) {
    throw reviewInvalid();
  }
  return {
    actionId: row.action_id,
    jobId: row.action_job_id,
    reviewId: row.active_review_id,
    hashes: {
      scopeHash: row.planned_scope_hash,
      policyHash: row.planned_policy_hash,
      actionHash: row.planned_action_hash,
      contextHash: row.planned_context_hash,
    },
    source: {
      action: {
        id: row.action_id,
        jobId: row.action_job_id,
        adapter: row.action_adapter,
        actionType: row.action_type,
        target: row.action_target,
        riskLevel: row.risk_level,
        requiresApproval,
        requiredForCompletion,
        metadata,
      },
      job: {
        id: row.job_id,
        type: row.job_type,
        target: row.job_target,
        mode: row.job_mode,
      },
    },
  };
}

/**
 * Decode provenance for reconciliation.  Unlike claim/finalize, this path
 * may inspect an already-completed/failed job when the action was explicitly
 * non-required; that job state does not authorize an effect and therefore is
 * safe historical context.  Required actions retain the stricter active-job
 * relationship so a corrupted completion cannot be silently reconciled.
 */
function decodeReconciliationSource(
  row: RecoveryLockedRow,
  expectedActionId: string,
): ApprovedSnapshot {
  if (row.job_exists !== 1) {
    if (!isCanonicalId(row.action_job_id)) throw recordInvalid();
    throw lifecycleError(`Job not found: ${row.action_job_id}`, "JOB_NOT_FOUND");
  }
  if (
    row.job_status !== "queued" &&
    row.job_status !== "running" &&
    row.job_status !== "paused" &&
    row.job_status !== "completed" &&
    row.job_status !== "failed"
  ) {
    throw recordInvalid();
  }
  if (
    !isCanonicalId(row.action_id) ||
    row.action_id !== expectedActionId ||
    !isCanonicalId(row.action_job_id) ||
    !isCanonicalId(row.job_id) ||
    row.action_job_id !== row.job_id ||
    !isCanonicalId(row.action_adapter) ||
    !isCanonicalId(row.action_type) ||
    !isCanonicalId(row.job_type) ||
    !isRiskLevel(row.risk_level) ||
    !isExecutionMode(row.job_mode) ||
    (row.action_target !== null && typeof row.action_target !== "string") ||
    (row.job_target !== null && typeof row.job_target !== "string")
  ) {
    throw recordInvalid();
  }

  const requiresApproval = decodeBoolean(row.requires_approval);
  const requiredForCompletion = decodeBoolean(row.required_for_completion);
  // A required action cannot have a terminal job while it is still carrying
  // an outcome-unknown action.  A non-required action is deliberately allowed
  // to coexist with a completed/failed job (the completion gate ignores it).
  if (
    requiredForCompletion &&
    (row.job_status === "completed" || row.job_status === "failed")
  ) {
    throw recordInvalid();
  }
  const metadata = decodeMetadata(row.metadata_json);
  if (!isCanonicalId(row.active_review_id)) throw reviewInvalid();
  if (
    typeof row.planned_scope_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_scope_hash) ||
    typeof row.planned_policy_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_policy_hash) ||
    typeof row.planned_action_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_action_hash) ||
    typeof row.planned_context_hash !== "string" ||
    !NONZERO_HEX64.test(row.planned_context_hash)
  ) {
    throw reviewInvalid();
  }
  return {
    actionId: row.action_id,
    jobId: row.action_job_id,
    reviewId: row.active_review_id,
    hashes: {
      scopeHash: row.planned_scope_hash,
      policyHash: row.planned_policy_hash,
      actionHash: row.planned_action_hash,
      contextHash: row.planned_context_hash,
    },
    source: {
      action: {
        id: row.action_id,
        jobId: row.action_job_id,
        adapter: row.action_adapter,
        actionType: row.action_type,
        target: row.action_target,
        riskLevel: row.risk_level,
        requiresApproval,
        requiredForCompletion,
        metadata,
      },
      job: {
        id: row.job_id,
        type: row.job_type,
        target: row.job_target,
        mode: row.job_mode,
      },
    },
  };
}

const RECONCILIATION_INVALIDATION_REASONS: ReadonlySet<string> = new Set([
  "review_expired",
  "scope_drift",
  "policy_drift",
  "action_hash_mismatch",
  "context_hash_mismatch",
  "scope_blocked",
  "policy_blocked",
]);

/** Validate the original approval as historical provenance, not authority. */
function validateReconciliationReview(
  row: RecoveryLockedRow,
  expected: ApprovedSnapshot,
): void {
  if (
    !isCanonicalId(row.review_id) ||
    row.review_id !== expected.reviewId ||
    row.review_action_id !== expected.actionId ||
    row.review_job_id !== expected.jobId ||
    row.review_decision !== "approved" ||
    (row.review_source !== "human" && row.review_source !== "policy")
  ) {
    throw reviewInvalid();
  }
  if (row.review_source === "policy") {
    if (row.review_reviewer_id !== POLICY_REVIEWER_ID) throw reviewInvalid();
  } else if (
    !isCanonicalId(row.review_reviewer_id) ||
    row.review_reviewer_id === POLICY_REVIEWER_ID
  ) {
    throw reviewInvalid();
  }
  if (
    !isCanonicalIso(row.review_created_at) ||
    !isCanonicalIso(row.review_reviewed_at) ||
    !isCanonicalIso(row.review_expires_at) ||
    row.review_created_at !== row.review_reviewed_at
  ) {
    throw reviewInvalid();
  }
  const reviewedMs = Date.parse(row.review_reviewed_at);
  const expiresMs = Date.parse(row.review_expires_at);
  if (!Number.isSafeInteger(reviewedMs) || !Number.isSafeInteger(expiresMs) || expiresMs <= reviewedMs) {
    throw reviewInvalid();
  }
  // A historical invalidation is accepted only when both fields are a
  // structurally valid pair.  A half-populated or unknown reason is storage
  // corruption, not evidence.
  if (row.review_invalidated_at === null && row.review_invalidation_reason === null) {
    // still a valid provenance row
  } else if (
    !isCanonicalIso(row.review_invalidated_at) ||
    typeof row.review_invalidation_reason !== "string" ||
    !RECONCILIATION_INVALIDATION_REASONS.has(row.review_invalidation_reason)
  ) {
    throw reviewInvalid();
  }
  if (
    typeof row.review_scope_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_scope_hash) ||
    row.review_scope_hash !== expected.hashes.scopeHash ||
    typeof row.review_policy_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_policy_hash) ||
    row.review_policy_hash !== expected.hashes.policyHash ||
    typeof row.review_action_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_action_hash) ||
    row.review_action_hash !== expected.hashes.actionHash ||
    typeof row.review_context_hash !== "string" ||
    !NONZERO_HEX64.test(row.review_context_hash) ||
    row.review_context_hash !== expected.hashes.contextHash
  ) {
    throw reviewInvalid();
  }
}

function validateReconciliationLifecycleRow(
  row: RecoveryLockedRow,
  expectedActionId: string,
): ApprovedSnapshot {
  // Reconciliation can only consume a finalized ambiguity.  The token is
  // expected to have been cleared by finalize; any bearer left in storage is
  // a malformed lifecycle record and is never selected into JavaScript.
  if (
    sqlTrue(row.execution_token_present) ||
    sqlTrue(row.execution_token_well_formed) ||
    row.execution_token_is_null !== 1 ||
    row.execution_owner_is_null !== 1 ||
    row.lease_expires_at_is_null !== 1 ||
    row.executed_at_is_null !== 1 ||
    row.finished_at_is_null !== 0 ||
    row.outcome_certainty_is_null !== 0 ||
    row.lifecycle_execution_owner !== null ||
    row.lifecycle_lease_expires_at !== null
  ) {
    throw recordInvalid();
  }
  // Start/dispatch values are deliberately *not* required to be canonical:
  // expired-lease recovery may have converted a malformed running row into an
  // outcome_unknown record precisely because dispatch provenance could not be
  // proven.  Reconciliation resolves that ambiguity and preserves those raw
  // audit slots.  They are still pinned byte-for-byte by the terminal CAS.
  if (!isCanonicalIso(row.lifecycle_finished_at)) throw recordInvalid();
  if (!isCanonicalIso(row.lifecycle_updated_at)) throw recordInvalid();

  if (row.lifecycle_outcome_certainty !== "possibly_dispatched") {
    throw recordInvalid();
  }
  if (
    typeof row.lifecycle_last_error_code !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(row.lifecycle_last_error_code)
  ) {
    throw recordInvalid();
  }
  if (typeof row.lifecycle_last_error_message !== "string") {
    throw recordInvalid();
  }
  const sanitizedDiagnostic = sanitizeLifecycleText(row.lifecycle_last_error_message);
  if (
    sanitizedDiagnostic !== row.lifecycle_last_error_message ||
    Array.from(sanitizedDiagnostic).length > 2_000
  ) {
    throw recordInvalid();
  }

  const source = decodeReconciliationSource(row, expectedActionId);
  validateReconciliationReview(row, source);
  return source;
}

function validateRunningLifecycleRow(
  row: LifecycleLockedRow,
  expectedActionId: string,
  input: ValidatedLifecycleInput,
  nowMs: number,
): RunningSnapshot {
  if (row.execution_token_matches !== 1 && row.execution_token_matches !== 1n) {
    throw dispatchTokenMismatch();
  }
  // Token shape is checked after equality so a malformed/missing stored value
  // cannot be reflected through JavaScript, while a valid caller token still
  // receives the stable mismatch code.
  if (row.execution_token_well_formed !== 1 && row.execution_token_well_formed !== 1n) {
    throw dispatchTokenMismatch();
  }
  if (
    row.execution_owner_matches !== 1 &&
    row.execution_owner_matches !== 1n
  ) {
    throw ownerInvalid();
  }
  if (
    typeof row.lifecycle_execution_owner !== "string" ||
    C0_DEL.test(row.lifecycle_execution_owner) ||
    row.lifecycle_execution_owner !== input.executionOwner ||
    row.lifecycle_execution_owner.trim() !== row.lifecycle_execution_owner
  ) {
    throw ownerInvalid();
  }

  if (
    row.executed_at_is_null !== 1 ||
    row.execution_token_is_null !== 0 ||
    row.execution_owner_is_null !== 0 ||
    row.lease_expires_at_is_null !== 0 ||
    row.started_at_is_null !== 0 ||
    row.finished_at_is_null !== 1 ||
    row.outcome_certainty_is_null !== 1 ||
    row.last_error_code_is_null !== 1 ||
    row.last_error_message_is_null !== 1
  ) {
    throw recordInvalid();
  }

  const source = decodeRunningSource(row, expectedActionId);
  const leaseExpiresAt = row.lifecycle_lease_expires_at;
  if (!isCanonicalIso(leaseExpiresAt)) throw leaseInvalid();
  const leaseExpiresMs = Date.parse(leaseExpiresAt);
  if (!Number.isFinite(leaseExpiresMs) || !Number.isSafeInteger(leaseExpiresMs)) {
    throw leaseInvalid();
  }
  if (!isCanonicalIso(row.lifecycle_started_at)) throw leaseInvalid();
  const startedAt = row.lifecycle_started_at;
  const startedMs = Date.parse(startedAt);
  if (!Number.isSafeInteger(startedMs) || startedMs > nowMs || leaseExpiresMs <= startedMs) {
    throw leaseInvalid();
  }
  const review = validateCompleteReview(row, source);
  if (leaseExpiresMs > review.expiresMs) throw leaseInvalid();
  if (review.expiresMs <= nowMs || leaseExpiresMs <= nowMs) throw leaseExpired();

  let dispatchStartedAt: string | null;
  if (row.lifecycle_dispatch_started_at === null) {
    dispatchStartedAt = null;
    if (row.dispatch_started_at_is_null !== 1) throw recordInvalid();
  } else {
    if (
      row.dispatch_started_at_is_null !== 0 ||
      !isCanonicalIso(row.lifecycle_dispatch_started_at)
    ) {
      throw recordInvalid();
    }
    const markerMs = Date.parse(row.lifecycle_dispatch_started_at);
    if (
      !Number.isSafeInteger(markerMs) ||
      markerMs < startedMs ||
      markerMs > nowMs ||
      markerMs >= leaseExpiresMs
    ) {
      throw recordInvalid();
    }
    dispatchStartedAt = row.lifecycle_dispatch_started_at;
  }

  let updatedAt: string | null;
  if (row.lifecycle_updated_at === null || row.lifecycle_updated_at === undefined) {
    updatedAt = null;
  } else if (isCanonicalIso(row.lifecycle_updated_at)) {
    const updatedMs = Date.parse(row.lifecycle_updated_at);
    if (!Number.isSafeInteger(updatedMs) || updatedMs < startedMs || updatedMs > nowMs) {
      throw recordInvalid();
    }
    updatedAt = row.lifecycle_updated_at;
  } else {
    throw recordInvalid();
  }
  return {
    ...source,
    executionOwner: row.lifecycle_execution_owner,
    leaseExpiresAt,
    leaseExpiresMs,
    startedAt,
    dispatchStartedAt,
    updatedAt,
  };
}

function sqlTrue(value: unknown): boolean {
  return value === 1 || value === 1n;
}

function terminalizationForOutcome(
  outcome: ValidatedEffectOutcome,
  hasDispatchMarker: boolean,
): TerminalizationResult {
  if (outcome.kind === "success") {
    if (!hasDispatchMarker) throw dispatchNotMarked();
    return {
      status: "executed",
      certainty: "success",
      errorCode: null,
      errorMessage: null,
      executedAt: null, // filled with the captured terminal clock by caller
      eventStatus: "completed",
      eventMessage: "Action execution completed",
      eventReason: "effect_succeeded",
    };
  }

  const sanitized = sanitizeLifecycleText(outcome.errorMessage ?? "");
  if (outcome.kind === "not_dispatched" && !hasDispatchMarker) {
    return {
      status: "failed",
      certainty: "not_dispatched",
      errorCode: outcome.errorCode ?? null,
      errorMessage: sanitized,
      executedAt: null,
      eventStatus: "failed",
      eventMessage: "Action execution failed",
      eventReason: "not_dispatched",
    };
  }
  return {
    status: "outcome_unknown",
    certainty: "possibly_dispatched",
    errorCode: outcome.errorCode ?? null,
    errorMessage: sanitized,
    executedAt: null,
    eventStatus: "paused",
    eventMessage: "Action execution outcome is unknown",
    eventReason: "reconciliation_required",
  };
}

function isCanonicalLifecycleOwner(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value === value.trim() &&
    !C0_DEL.test(value) &&
    Array.from(value).length >= 1 &&
    Array.from(value).length <= CODE_POINT_MAX
  );
}

function classifyRecoveryRow(
  row: RecoveryLockedRow,
  actionId: string,
  nowMs: number,
): RecoveryClassification {
  const rawLease = row.lifecycle_lease_expires_at;
  const leaseIsCanonical = isCanonicalIso(rawLease);
  const leaseMs = leaseIsCanonical ? Date.parse(rawLease) : Number.NaN;
  if (leaseIsCanonical && Number.isSafeInteger(leaseMs) && leaseMs > nowMs) {
    return {
      kind: "active",
      certainty: "possibly_dispatched",
      errorMessage: "",
      eventStatus: "paused",
      eventMessage: "",
      eventReason: "reconciliation_required",
    };
  }

  let provenanceValid = false;
  try {
    const source = decodeRunningSource(row, actionId);
    validateCompleteReview(row, source);
    provenanceValid = true;
  } catch {
    provenanceValid = false;
  }
  const cleanPreDispatch =
    leaseIsCanonical &&
    Number.isSafeInteger(leaseMs) &&
    leaseMs <= nowMs &&
    sqlTrue(row.execution_token_present) &&
    sqlTrue(row.execution_token_well_formed) &&
    isCanonicalLifecycleOwner(row.lifecycle_execution_owner) &&
    isCanonicalIso(row.lifecycle_started_at) &&
    row.lifecycle_dispatch_started_at === null &&
    row.executed_at_is_null === 1 &&
    row.finished_at_is_null === 1 &&
    row.outcome_certainty_is_null === 1 &&
    row.last_error_code_is_null === 1 &&
    row.last_error_message_is_null === 1 &&
    provenanceValid;

  if (cleanPreDispatch) {
    return {
      kind: "failed",
      certainty: "not_dispatched",
      errorMessage: "Expired action lease recovered before dispatch",
      eventStatus: "failed",
      eventMessage: "Expired action lease recovered before dispatch",
      eventReason: "lease_expired_not_dispatched",
    };
  }
  return {
    kind: "outcome_unknown",
    certainty: "possibly_dispatched",
    errorMessage: "Expired action lease requires reconciliation",
    eventStatus: "paused",
    eventMessage: "Expired action lease requires reconciliation",
    eventReason: "reconciliation_required",
  };
}

function changedExactlyOnce(changes: number | bigint): boolean {
  return changes === 1 || changes === 1n;
}

function isTokenUniqueCollision(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.message === EXECUTION_TOKEN_UNIQUE_MESSAGE
  );
}

function materialRace(
  row: LockedClaimRow,
  outside: ApprovedSnapshot,
  materialized: MaterializedActionAuthority,
): { locked: ApprovedSnapshot; definitiveBlock: "scope" | "policy" | null; hashes: PlannedHashes } {
  if (row.action_status !== "approved") throw claimRace();
  let locked: ApprovedSnapshot;
  try {
    locked = decodeApprovedRow(row, outside.actionId);
  } catch {
    throw claimRace();
  }
  if (
    locked.jobId !== outside.jobId ||
    locked.reviewId !== outside.reviewId ||
    !hashesEqual(locked.hashes, outside.hashes)
  ) {
    throw claimRace();
  }

  let sourceSnapshot;
  try {
    sourceSnapshot = snapshotActionMaterialSource(locked.source);
  } catch {
    throw claimRace();
  }
  if (sourceSnapshot.canonical !== materialized.sourceCanonical) throw claimRace();
  const evaluation = recomputeActionAuthority(
    sourceSnapshot.source,
    materialized.material,
  );
  return {
    locked,
    definitiveBlock: evaluation.definitiveBlock,
    hashes: {
      scopeHash: evaluation.challenge.scopeHash,
      policyHash: evaluation.challenge.policyHash,
      actionHash: evaluation.challenge.actionHash,
      contextHash: evaluation.challenge.contextHash,
    },
  };
}

export class ActionLifecycle {
  private readonly actionQueue: ActionQueue;
  private readonly reviewStore: ActionReviewStore;
  private readonly eventStore: WorkflowEventStore;
  private readonly jobManager: JobManager;

  constructor(
    private readonly db: BountyDatabase,
    private readonly dependencies: ActionLifecycleDependencies,
  ) {
    this.actionQueue = new ActionQueue(db);
    this.reviewStore = new ActionReviewStore(db);
    this.eventStore = new WorkflowEventStore(db);
    this.jobManager = new JobManager(db);
  }

  claim(input: {
    actionId: string;
    executionOwner: string;
    leaseMs?: number;
  }): ClaimedActionContext {
    const validated = snapshotClaimInput(input);
    const preflightRow = this.db
      .prepare(PREFLIGHT_SELECT)
      .get(validated.actionId) as ActionJobRow | undefined;
    if (!preflightRow) {
      throw lifecycleError(
        `Action not found: ${validated.actionId}`,
        "ACTION_NOT_FOUND",
      );
    }
    const currentStatusError = statusError(preflightRow.action_status);
    if (currentStatusError) throw currentStatusError;

    const preflight = decodeApprovedRow(preflightRow, validated.actionId);
    const materialized = materializeActionAuthority(
      preflight.source,
      this.dependencies,
    );
    const now = captureClock(() => this.dependencies.now());
    const leaseLimit = checkedLeaseLimit(now.epochMs, validated.leaseMs);
    const executionToken = generateToken(() =>
      this.dependencies.generateExecutionToken(),
    );

    const transactionResult = withImmediateTransaction<ClaimTransactionResult>(
      this.db,
      () => {
        const row = this.db
          .prepare(LOCKED_SELECT)
          .get(validated.actionId) as LockedClaimRow | undefined;
        if (!row) throw claimRace();

        const current = materialRace(row, preflight, materialized);
        if (current.definitiveBlock !== null) {
          const reason: ActionReviewInvalidationReason =
            current.definitiveBlock === "scope" ? "scope_blocked" : "policy_blocked";
          this.reviewStore.invalidateApprovalInTransaction({
            reviewId: preflight.reviewId,
            actionId: preflight.actionId,
            jobId: preflight.jobId,
            invalidatedAt: now.iso,
            invalidationReason: reason,
          });
          this.repairApprovedAction(preflight, "blocked", now.iso);
          this.eventStore.recordInTransaction({
            jobId: preflight.jobId,
            phase: "action-review",
            status: "blocked",
            message: "Action approval blocked by current authority",
            metadata: {
              actionId: preflight.actionId,
              reviewId: preflight.reviewId,
              reasonCode: reason,
            },
          });
          this.jobManager.finalizeInTransaction(preflight.jobId);
          return {
            kind: "rejection",
            code:
              current.definitiveBlock === "scope"
                ? "ACTION_SCOPE_DRIFT"
                : "ACTION_POLICY_DRIFT",
          };
        }

        const review = validateCompleteReview(row, preflight);
        let rejection:
          | {
              code: ClaimRejectionCode;
              reason: ActionReviewInvalidationReason;
            }
          | undefined;
        if (review.expiresMs <= now.epochMs) {
          rejection = {
            code: "ACTION_REVIEW_EXPIRED",
            reason: "review_expired",
          };
        } else if (current.hashes.scopeHash !== preflight.hashes.scopeHash) {
          rejection = { code: "ACTION_SCOPE_DRIFT", reason: "scope_drift" };
        } else if (current.hashes.policyHash !== preflight.hashes.policyHash) {
          rejection = { code: "ACTION_POLICY_DRIFT", reason: "policy_drift" };
        } else if (current.hashes.actionHash !== preflight.hashes.actionHash) {
          rejection = {
            code: "ACTION_HASH_MISMATCH",
            reason: "action_hash_mismatch",
          };
        } else if (current.hashes.contextHash !== preflight.hashes.contextHash) {
          rejection = {
            code: "ACTION_HASH_MISMATCH",
            reason: "context_hash_mismatch",
          };
        }

        if (rejection) {
          const reviewChanges = this.reviewStore.invalidateApprovalInTransaction({
            reviewId: preflight.reviewId,
            actionId: preflight.actionId,
            jobId: preflight.jobId,
            invalidatedAt: now.iso,
            invalidationReason: rejection.reason,
          });
          if (reviewChanges.changes !== 1) throw claimRace();
          this.repairApprovedAction(preflight, "pending", now.iso);
          this.eventStore.recordInTransaction({
            jobId: preflight.jobId,
            phase: "action-review",
            status: "paused",
            message: "Action approval invalidated",
            metadata: {
              actionId: preflight.actionId,
              reviewId: preflight.reviewId,
              reasonCode: rejection.reason,
            },
          });
          this.jobManager.finalizeInTransaction(preflight.jobId);
          return { kind: "rejection", code: rejection.code };
        }

        const leaseExpiresMs = Math.min(leaseLimit.epochMs, review.expiresMs);
        if (!Number.isSafeInteger(leaseExpiresMs) || !(leaseExpiresMs > now.epochMs)) {
          throw leaseInvalid();
        }
        let leaseExpiresAt: string;
        try {
          leaseExpiresAt = new Date(leaseExpiresMs).toISOString();
          if (Date.parse(leaseExpiresAt) !== leaseExpiresMs) throw leaseInvalid();
        } catch {
          throw leaseInvalid();
        }

        let cas;
        try {
          cas = this.db
            .prepare(
              `UPDATE actions
               SET status = 'running',
                   execution_token = ?,
                   execution_owner = ?,
                   lease_expires_at = ?,
                   started_at = ?,
                   updated_at = ?
               WHERE ${CLEAN_APPROVED_WHERE}`,
            )
            .run(
              executionToken,
              validated.executionOwner,
              leaseExpiresAt,
              now.iso,
              now.iso,
              preflight.actionId,
              preflight.jobId,
              preflight.reviewId,
              preflight.hashes.scopeHash,
              preflight.hashes.policyHash,
              preflight.hashes.actionHash,
              preflight.hashes.contextHash,
            );
        } catch (error) {
          if (isTokenUniqueCollision(error)) throw tokenCollision();
          throw error;
        }
        if (!changedExactlyOnce(cas.changes)) throw claimRace();

        this.eventStore.recordInTransaction({
          jobId: preflight.jobId,
          phase: "action-execution",
          status: "running",
          message: "Action execution claimed",
          metadata: {
            actionId: preflight.actionId,
            reviewId: preflight.reviewId,
            reasonCode: "execution_claimed",
            contextHash: preflight.hashes.contextHash,
          },
        });
        this.jobManager.finalizeInTransaction(preflight.jobId);
        const action = this.actionQueue.get(preflight.actionId);
        if (!action || action.status !== "running") throw recordInvalid();
        return { kind: "success", action };
      },
    );

    if (transactionResult.kind === "rejection") {
      throw rejectionError(transactionResult.code);
    }
    const claimed: ClaimedActionContext = {
      action: transactionResult.action,
      executionToken,
    } as ClaimedActionContext;
    Object.defineProperty(claimed, "effectAuthority", {
      value: Object.freeze({
        config: materialized.material.program.config,
        programConfig: materialized.material.program.config,
        source: materialized.source,
        scopeHash: materialized.material.scopeHash,
        policyHash: materialized.material.policyHash,
        actionHash: materialized.challenge.actionHash,
        contextHash: materialized.challenge.contextHash,
      }),
      enumerable: false,
      writable: false,
      configurable: false,
    });
    return claimed;
  }

  markDispatch(_input: {
    actionId: string;
    executionToken: string;
    executionOwner: string;
  }): { dispatchStartedAt: string } {
    const input = snapshotLifecycleInput(_input);
    // Capture exactly one lifecycle clock before BEGIN.  No SQL, loader,
    // resolver, token generation, or effect is reached when the clock is
    // unavailable or malformed.
    const now = captureClock(() => this.dependencies.now());

    return withImmediateTransaction(this.db, () => {
      const row = this.db
        .prepare(LIFECYCLE_LOCKED_SELECT)
        .get(input.executionToken, input.executionOwner, input.actionId) as
        | LifecycleLockedRow
        | undefined;
      if (!row) {
        throw lifecycleError(`Action not found: ${input.actionId}`, "ACTION_NOT_FOUND");
      }
      const statusFailure = lifecycleStatusError(row.action_status);
      if (statusFailure) throw statusFailure;

      // Marker presence is deliberately checked before token/owner/lease or
      // review expiry.  Once a dispatch permit was issued, callers never get
      // a second permit, even if the row subsequently becomes stale.
      if (row.lifecycle_dispatch_started_at !== null) {
        throw dispatchAlreadyMarked();
      }

      const running = validateRunningLifecycleRow(
        row,
        input.actionId,
        input,
        now.epochMs,
      );

      const cas = this.db
        .prepare(
          `UPDATE actions
           SET dispatch_started_at = ?, updated_at = ?
           WHERE id = ?
             AND status = 'running'
             AND execution_token = ?
             AND execution_owner = ?
             AND lease_expires_at = ?
             AND dispatch_started_at IS NULL`,
        )
        .run(
          now.iso,
          now.iso,
          running.actionId,
          input.executionToken,
          input.executionOwner,
          running.leaseExpiresAt,
        );
      if (!changedExactlyOnce(cas.changes)) throw dispatchRace();
      return { dispatchStartedAt: now.iso };
    });
  }

  /**
   * Revalidate an already-marked dispatch before every later target request.
   * This issues no second permit and performs no writes; it only proves that
   * the same token/owner still holds a live lease backed by an unexpired review
   * and a non-terminal job.
   */
  assertDispatchActive(_input: {
    actionId: string;
    executionToken: string;
    executionOwner: string;
  }): { dispatchStartedAt: string } {
    const input = snapshotLifecycleInput(_input);
    const now = captureClock(() => this.dependencies.now());

    return withImmediateTransaction(this.db, () => {
      const row = this.db
        .prepare(LIFECYCLE_LOCKED_SELECT)
        .get(input.executionToken, input.executionOwner, input.actionId) as
        | LifecycleLockedRow
        | undefined;
      if (!row) {
        throw lifecycleError(`Action not found: ${input.actionId}`, "ACTION_NOT_FOUND");
      }
      const statusFailure = lifecycleStatusError(row.action_status);
      if (statusFailure) throw statusFailure;
      const running = validateRunningLifecycleRow(
        row,
        input.actionId,
        input,
        now.epochMs,
      );
      if (running.dispatchStartedAt === null) throw dispatchNotMarked();
      return { dispatchStartedAt: running.dispatchStartedAt };
    });
  }

  finalize(_input: {
    actionId: string;
    executionToken: string;
    executionOwner: string;
    outcome: EffectOutcome;
  }): ActionRecord {
    const input = snapshotFinalizeInput(_input);
    const now = captureClock(() => this.dependencies.now());

    return withImmediateTransaction(this.db, () => {
      const row = this.db
        .prepare(LIFECYCLE_LOCKED_SELECT)
        .get(input.executionToken, input.executionOwner, input.actionId) as
        | LifecycleLockedRow
        | undefined;
      if (!row) {
        throw lifecycleError(`Action not found: ${input.actionId}`, "ACTION_NOT_FOUND");
      }
      const statusFailure = lifecycleStatusError(row.action_status);
      if (statusFailure) throw statusFailure;

      const running = validateRunningLifecycleRow(
        row,
        input.actionId,
        input,
        now.epochMs,
      );
      const terminal = terminalizationForOutcome(
        input.outcome,
        running.dispatchStartedAt !== null,
      );
      const executedAt = terminal.status === "executed" ? now.iso : null;

      const cas = this.db
        .prepare(
          `UPDATE actions
           SET status = ?,
               executed_at = ?,
               execution_token = NULL,
               execution_owner = NULL,
               lease_expires_at = NULL,
               finished_at = ?,
               updated_at = ?,
               outcome_certainty = ?,
               last_error_code = ?,
               last_error_message = ?
           WHERE id = ?
             AND status = 'running'
             AND execution_token = ?
             AND execution_owner = ?
             AND lease_expires_at = ?`,
        )
        .run(
          terminal.status,
          executedAt,
          now.iso,
          now.iso,
          terminal.certainty,
          terminal.errorCode,
          terminal.errorMessage,
          running.actionId,
          input.executionToken,
          input.executionOwner,
          running.leaseExpiresAt,
        );
      if (!changedExactlyOnce(cas.changes)) throw finalizeRace();

      this.eventStore.recordInTransaction({
        jobId: running.jobId,
        phase: "action-execution",
        status: terminal.eventStatus,
        message: terminal.eventMessage,
        metadata: {
          actionId: running.actionId,
          status: terminal.status,
          outcomeCertainty: terminal.certainty,
          reasonCode: terminal.eventReason,
        },
      });
      this.jobManager.finalizeInTransaction(running.jobId);
      const action = this.actionQueue.get(running.actionId);
      if (!action || action.status !== terminal.status) throw recordInvalid();
      return action;
    });
  }

  recoverExpiredLease(
    _actionId: string,
  ):
    | { kind: "active" | "not_running" }
    | { kind: "recovered"; status: "failed" | "outcome_unknown" } {
    if (!isCanonicalId(_actionId)) throw lifecycleInvalid();
    const preflight = this.db
      .prepare(RECOVERY_PREFLIGHT_SELECT)
      .get(_actionId) as { action_status: unknown } | undefined;
    if (!preflight) {
      throw lifecycleError(`Action not found: ${_actionId}`, "ACTION_NOT_FOUND");
    }
    if (preflight.action_status !== "running") {
      if (
        preflight.action_status === "pending" ||
        preflight.action_status === "planned" ||
        preflight.action_status === "approved" ||
        preflight.action_status === "executed" ||
        preflight.action_status === "blocked" ||
        preflight.action_status === "failed" ||
        preflight.action_status === "outcome_unknown"
      ) {
        return { kind: "not_running" };
      }
      throw recordInvalid();
    }

    const now = captureClock(() => this.dependencies.now());
    return withImmediateTransaction(this.db, () => {
      const row = this.db
        .prepare(RECOVERY_LOCKED_SELECT)
        .get(_actionId) as RecoveryLockedRow | undefined;
      if (!row) {
        throw lifecycleError(`Action not found: ${_actionId}`, "ACTION_NOT_FOUND");
      }
      if (row.action_status !== "running") {
        if (
          row.action_status === "pending" ||
          row.action_status === "planned" ||
          row.action_status === "approved" ||
          row.action_status === "executed" ||
          row.action_status === "blocked" ||
          row.action_status === "failed" ||
          row.action_status === "outcome_unknown"
        ) {
          return { kind: "not_running" as const };
        }
        throw recordInvalid();
      }

      const classification = classifyRecoveryRow(row, _actionId, now.epochMs);
      if (classification.kind === "active") return { kind: "active" as const };

      // Establish the minimum concrete job/link projection before any write.
      // Review defects remain an ambiguity signal, but a missing/malformed
      // action-to-job link cannot be terminalized into an orphan audit row.
      const source = decodeRunningSource(row, _actionId);

      const observedTokenShape = `(
        execution_token = CAST(execution_token AS TEXT)
        AND execution_token GLOB '${TOKEN_GLOB_64}'
        AND execution_token NOT GLOB '*[^0-9a-f]*'
      )`;
      const tokenPresencePredicate = sqlTrue(row.execution_token_present)
        ? "execution_token IS NOT NULL"
        : "execution_token IS NULL";
      const tokenShapePredicate = sqlTrue(row.execution_token_well_formed)
        ? observedTokenShape
        : `(execution_token IS NULL OR NOT ${observedTokenShape})`;

      const cas = this.db
        .prepare(
          `UPDATE actions
           SET status = ?,
               execution_token = NULL,
               execution_owner = NULL,
               lease_expires_at = NULL,
               finished_at = ?,
               updated_at = ?,
               outcome_certainty = ?,
             last_error_code = 'ACTION_LEASE_EXPIRED',
             last_error_message = ?
           WHERE id = ?
             AND status = 'running'
             AND ${tokenPresencePredicate}
             AND ${tokenShapePredicate}
             AND job_id = ?
             AND active_review_id = ?
             AND planned_scope_hash = ?
             AND planned_policy_hash = ?
             AND planned_action_hash = ?
             AND planned_context_hash = ?
             AND execution_owner IS ?
             AND lease_expires_at IS ?
             AND started_at IS ?
             AND dispatch_started_at IS ?
             AND updated_at IS ?`,
        )
        .run(
          classification.kind,
          now.iso,
          now.iso,
          classification.certainty,
          classification.errorMessage,
          _actionId,
          source.jobId,
          source.reviewId,
          source.hashes.scopeHash,
          source.hashes.policyHash,
          source.hashes.actionHash,
          source.hashes.contextHash,
          row.lifecycle_execution_owner as never,
          row.lifecycle_lease_expires_at as never,
          row.lifecycle_started_at as never,
          row.lifecycle_dispatch_started_at as never,
          row.lifecycle_updated_at as never,
        );
      if (!changedExactlyOnce(cas.changes)) throw finalizeRace();

      this.eventStore.recordInTransaction({
        jobId: source.jobId,
        phase: "action-recovery",
        status: classification.eventStatus,
        message: classification.eventMessage,
        metadata: {
          actionId: _actionId,
          status: classification.kind,
          outcomeCertainty: classification.certainty,
          reasonCode: classification.eventReason,
        },
      });
      this.jobManager.finalizeInTransaction(source.jobId);
      return {
        kind: "recovered" as const,
        status: classification.kind,
      };
    });
  }

  reconcileOutcome(_input: {
    actionId: string;
    reviewerId: string;
    attestation: string;
    resolution: "effect_confirmed" | "no_successful_effect_confirmed";
  }): {
    action: ActionRecord;
    reconciliationReviewId: string;
    status: "executed" | "failed";
  } {
    // Capture the exact caller DTO before SQL, clocks, transaction state, or
    // any generated identifier.  The snapshot also performs deterministic
    // attestation redaction, including standalone bearer-like hex strings.
    const input = snapshotReconciliationInput(_input);

    // Token-free status preflight deliberately selects only the action status.
    // This establishes the public precedence and lets non-unknown states fail
    // without invoking the injected clock or any transaction/write path.
    const preflight = this.db
      .prepare(RECOVERY_PREFLIGHT_SELECT)
      .get(input.actionId) as { action_status: unknown } | undefined;
    if (!preflight) {
      throw lifecycleError(`Action not found: ${input.actionId}`, "ACTION_NOT_FOUND");
    }
    const preflightStatus = preflight.action_status;
    if (preflightStatus !== "outcome_unknown") {
      if (
        preflightStatus === "pending" ||
        preflightStatus === "planned" ||
        preflightStatus === "approved"
      ) {
        throw notApproved();
      }
      if (preflightStatus === "running") {
        throw lifecycleError("Action execution lease is already held.", "ACTION_LEASE_HELD");
      }
      if (
        preflightStatus === "executed" ||
        preflightStatus === "blocked" ||
        preflightStatus === "failed"
      ) {
        throw terminalAction();
      }
      throw recordInvalid();
    }

    // Exactly one lifecycle clock capture, after the pure boundary and before
    // BEGIN IMMEDIATE.  The timestamp is reused for the reconciliation review
    // and action terminal CAS; dependency failures are fixed and cause-free.
    const now = captureClock(() => this.dependencies.now());

    return withImmediateTransaction(this.db, () => {
      const row = this.db
        .prepare(RECOVERY_LOCKED_SELECT)
        .get(input.actionId) as RecoveryLockedRow | undefined;

      // The outside preflight observed outcome_unknown.  Any disappearance or
      // status change inside the transaction is an exact CAS race, not a new
      // caller-status classification.
      if (!row || row.action_status !== "outcome_unknown") {
        throw reconciliationRace();
      }

      const source = validateReconciliationLifecycleRow(row, input.actionId);

      const review = this.reviewStore.insertReconciliationInTransaction({
        actionId: source.actionId,
        jobId: source.jobId,
        decision: input.resolution === "effect_confirmed" ? "executed" : "failed",
        reviewerId: input.reviewerId,
        reviewedAt: now.iso,
        scopeHash: source.hashes.scopeHash,
        policyHash: source.hashes.policyHash,
        actionHash: source.hashes.actionHash,
        contextHash: source.hashes.contextHash,
        note: input.attestation,
      });

      const effectConfirmed = input.resolution === "effect_confirmed";
      const cas = effectConfirmed
        ? this.db
            .prepare(
              `UPDATE actions
               SET status = 'executed',
                   executed_at = ?,
                   outcome_certainty = 'success',
                   last_error_code = NULL,
                   last_error_message = NULL,
                   updated_at = ?
               WHERE id = ?
                 AND status = 'outcome_unknown'
                 AND job_id = ?
                 AND executed_at IS NULL
                 AND execution_token IS NULL
                 AND execution_owner IS NULL
                 AND lease_expires_at IS NULL
                 AND active_review_id = ?
                 AND planned_scope_hash = ?
                 AND planned_policy_hash = ?
                 AND planned_action_hash = ?
                 AND planned_context_hash = ?
                 AND started_at IS ?
                 AND dispatch_started_at IS ?
                 AND finished_at IS ?
                 AND updated_at IS ?
                 AND outcome_certainty IS ?
                 AND last_error_code IS ?
                 AND last_error_message IS ?
                 AND ${RECONCILIATION_PROVENANCE_EXISTS}`,
            )
            .run(
              now.iso,
              now.iso,
              source.actionId,
              source.jobId,
              source.reviewId,
              source.hashes.scopeHash,
              source.hashes.policyHash,
              source.hashes.actionHash,
              source.hashes.contextHash,
              row.lifecycle_started_at as never,
              row.lifecycle_dispatch_started_at as never,
              row.lifecycle_finished_at as never,
              row.lifecycle_updated_at as never,
              row.lifecycle_outcome_certainty as never,
              row.lifecycle_last_error_code as never,
              row.lifecycle_last_error_message as never,
              row.review_id as never,
              row.review_action_id as never,
              row.review_job_id as never,
              row.review_reviewer_id as never,
              row.review_source as never,
              row.review_created_at as never,
              row.review_reviewed_at as never,
              row.review_expires_at as never,
              row.review_scope_hash as never,
              row.review_policy_hash as never,
              row.review_action_hash as never,
              row.review_context_hash as never,
              row.review_invalidated_at as never,
              row.review_invalidation_reason as never,
            )
        : this.db
            .prepare(
              `UPDATE actions
               SET status = 'failed',
                   executed_at = NULL,
                   outcome_certainty = 'possibly_dispatched',
                   updated_at = ?
               WHERE id = ?
                 AND status = 'outcome_unknown'
                 AND job_id = ?
                 AND executed_at IS NULL
                 AND execution_token IS NULL
                 AND execution_owner IS NULL
                 AND lease_expires_at IS NULL
                 AND active_review_id = ?
                 AND planned_scope_hash = ?
                 AND planned_policy_hash = ?
                 AND planned_action_hash = ?
                 AND planned_context_hash = ?
                 AND started_at IS ?
                 AND dispatch_started_at IS ?
                 AND finished_at IS ?
                 AND updated_at IS ?
                 AND outcome_certainty IS ?
                 AND last_error_code IS ?
                 AND last_error_message IS ?
                 AND ${RECONCILIATION_PROVENANCE_EXISTS}`,
            )
            .run(
              now.iso,
              source.actionId,
              source.jobId,
              source.reviewId,
              source.hashes.scopeHash,
              source.hashes.policyHash,
              source.hashes.actionHash,
              source.hashes.contextHash,
              row.lifecycle_started_at as never,
              row.lifecycle_dispatch_started_at as never,
              row.lifecycle_finished_at as never,
              row.lifecycle_updated_at as never,
              row.lifecycle_outcome_certainty as never,
              row.lifecycle_last_error_code as never,
              row.lifecycle_last_error_message as never,
              row.review_id as never,
              row.review_action_id as never,
              row.review_job_id as never,
              row.review_reviewer_id as never,
              row.review_source as never,
              row.review_created_at as never,
              row.review_reviewed_at as never,
              row.review_expires_at as never,
              row.review_scope_hash as never,
              row.review_policy_hash as never,
              row.review_action_hash as never,
              row.review_context_hash as never,
              row.review_invalidated_at as never,
              row.review_invalidation_reason as never,
            );

      if (!changedExactlyOnce(cas.changes)) throw reconciliationRace();

      const status = effectConfirmed ? "executed" : "failed";
      this.eventStore.recordInTransaction({
        jobId: source.jobId,
        phase: "action-reconciliation",
        status: effectConfirmed ? "completed" : "failed",
        message: "Action outcome reconciled",
        metadata: {
          actionId: source.actionId,
          reconciliationReviewId: review.id,
          resolution: input.resolution,
          status,
        },
      });
      this.jobManager.finalizeInTransaction(source.jobId);
      const action = this.actionQueue.get(source.actionId);
      if (!action || action.status !== status) throw recordInvalid();
      return {
        action,
        reconciliationReviewId: review.id,
        status,
      };
    });
  }

  private repairApprovedAction(
    snapshot: ApprovedSnapshot,
    status: "pending" | "blocked",
    updatedAt: string,
  ): void {
    const result = this.db
      .prepare(
        `UPDATE actions
         SET status = ?,
             active_review_id = NULL,
             planned_scope_hash = NULL,
             planned_policy_hash = NULL,
             planned_action_hash = NULL,
             planned_context_hash = NULL,
             updated_at = ?
         WHERE ${CLEAN_APPROVED_WHERE}`,
      )
      .run(
        status,
        updatedAt,
        snapshot.actionId,
        snapshot.jobId,
        snapshot.reviewId,
        snapshot.hashes.scopeHash,
        snapshot.hashes.policyHash,
        snapshot.hashes.actionHash,
        snapshot.hashes.contextHash,
      );
    if (!changedExactlyOnce(result.changes)) throw claimRace();
  }
}
