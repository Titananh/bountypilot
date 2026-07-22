// P0.2 Packet 2 (Slice B1) — ActionQueue storage primitive.
//
// Strict public decoding, token-free projection, pending-approval
// candidate reload, and the in-transaction approval CAS primitive.
//
// All public decoding is fail-closed:
//   - requires_approval: raw 0 -> false, raw 1 -> true; any other
//     stored value (including REAL 1.5, non-numeric TEXT, BLOB, or
//     any non-0/1 integer) throws a fixed cause-free
//     ACTION_RECORD_INVALID. No truthiness coercion is permitted.
//   - metadata_json: SQL NULL or absent -> undefined; every other
//     value must be a non-empty string that parses to a non-null,
//     non-array plain object. Any storage/type/parse/shape defect
//     throws a fixed cause-free ACTION_RECORD_INVALID.
//
// The token-free public projection SELECTs the v2 columns by name
// and never selects execution_token; the bearer capability cannot
// leak into a returned ActionRecord or its JSON form. The active
// review row is left-joined with explicit aliases so approved rows
// can be structurally validated without any secret material
// (review.note and action.execution_token are NEVER selected).
//
// requireCleanPendingForApproval is transaction-neutral: it never
// begins, commits, or rolls back. It reloads the action and its
// linked job on every call and applies the exact preflight error
// order required by the contract. The 15 SQL-null clean fields,
// including execution_token IS NULL, are computed in SQL so the
// bearer value is never selected, materialized, or returned.
//
// approveWithReviewInTransaction is a strict in-tx primitive.
// The first executable operation is the tracked-tx guard
// (hasImmediateTransaction); outside the tracked tx it throws
// fixed cause-free ACTION_QUEUE_TRANSACTION_REQUIRED before
// reflecting on the caller DTO. Inside the tx it snapshots a
// non-null plain/null-prototype input with exactly the pinned own
// data fields, rejecting accessors, hostile reflection, symbol
// fields, Proxy objects (including revoked Proxy via
// node:util/types.isProxy), and unknown own fields. It performs
// exactly one UPDATE actions with the full clean-state predicate
// and the stable-review EXISTS check; changes !== 1 is a hard
// ACTION_APPROVAL_RACE_LOST with no retry.

import { types as utilTypes } from "node:util";

import type { BountyDatabase } from "../../stores/db/database.js";
import { hasImmediateTransaction } from "../../stores/db/database.js";
import type { RiskLevel } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";
import { createId } from "../../utils/ids.js";
import { maskSecrets, maskSecretsDeep } from "../../utils/secrets.js";
import { nowIso } from "../../utils/time.js";

export type ActionStatus =
  | "pending"
  | "approved"
  | "running"
  | "executed"
  | "blocked"
  | "failed"
  | "outcome_unknown";

export type OutcomeCertainty = "success" | "not_dispatched" | "possibly_dispatched";

type StoredActionStatus = ActionStatus | "planned";

export interface ActionQueueSummary {
  total: number;
  pending: number;
  approved: number;
  running: number;
  executed: number;
  blocked: number;
  failed: number;
  outcome_unknown: number;
}

export interface ActionRecord {
  id: string;
  jobId?: string;
  adapter: string;
  actionType: string;
  target?: string;
  riskLevel: RiskLevel;
  requiresApproval: boolean;
  status: ActionStatus;
  metadata?: Record<string, unknown>;
  createdAt: string;
  executedAt?: string;
  updatedAt?: string;
  requiredForCompletion: boolean;
  activeReviewId?: string;
  plannedScopeHash?: string;
  plannedPolicyHash?: string;
  plannedActionHash?: string;
  plannedContextHash?: string;
  executionOwner?: string;
  leaseExpiresAt?: string;
  startedAt?: string;
  dispatchStartedAt?: string;
  finishedAt?: string;
  outcomeCertainty?: OutcomeCertainty;
  lastErrorCode?: string;
  lastErrorMessage?: string;
  supersedesActionId?: string;
}

export interface EnqueueActionInput {
  jobId?: string;
  adapter: string;
  actionType: string;
  target?: string;
  riskLevel: RiskLevel;
  requiresApproval: boolean;
  metadata?: Record<string, unknown>;
  status?: Extract<ActionStatus, "pending" | "approved" | "blocked" | "failed">;
  requiredForCompletion?: boolean;
  supersedesActionId?: string;
}

// Token-free narrowed record returned by requireCleanPendingForApproval.
export type PendingApprovalCandidate = ActionRecord & {
  jobId: string;
  status: "pending";
};

export interface ApproveActionWithReviewInput {
  actionId: string;
  jobId: string;
  reviewId: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
  updatedAt: string;
}

// One shared explicit public column projection for get/list. Every
// ActionRow field is named explicitly. execution_token is NEVER
// selected so it cannot leak into the public record or its JSON.
// The active review, when present, is left-joined with explicit
// aliases so approved rows can be structurally validated without
// any secret material. Per Slice B1 hardening we also include
// review.created_at and review.invalidation_reason; review.note
// and action.execution_token are NEVER selected.
const ACTION_PUBLIC_COLUMNS = [
  "a.id AS id",
  "a.job_id AS job_id",
  "a.adapter AS adapter",
  "a.action_type AS action_type",
  "a.target AS target",
  "a.risk_level AS risk_level",
  "a.requires_approval AS requires_approval",
  "a.status AS status",
  "a.metadata_json AS metadata_json",
  "a.created_at AS created_at",
  "a.executed_at AS executed_at",
  "a.updated_at AS updated_at",
  "a.required_for_completion AS required_for_completion",
  "a.active_review_id AS active_review_id",
  "a.planned_scope_hash AS planned_scope_hash",
  "a.planned_policy_hash AS planned_policy_hash",
  "a.planned_action_hash AS planned_action_hash",
  "a.planned_context_hash AS planned_context_hash",
  "a.execution_owner AS execution_owner",
  "a.lease_expires_at AS lease_expires_at",
  "a.started_at AS started_at",
  "a.dispatch_started_at AS dispatch_started_at",
  "a.finished_at AS finished_at",
  "a.outcome_certainty AS outcome_certainty",
  "a.last_error_code AS last_error_code",
  "a.last_error_message AS last_error_message",
  "a.supersedes_action_id AS supersedes_action_id",
  "r.id AS review_id",
  "r.action_id AS review_action_id",
  "r.job_id AS review_job_id",
  "r.decision AS review_decision",
  "r.reviewer_id AS review_reviewer_id",
  "r.source AS review_source",
  "r.created_at AS review_created_at",
  "r.reviewed_at AS review_reviewed_at",
  "r.expires_at AS review_expires_at",
  "r.scope_hash AS review_scope_hash",
  "r.policy_hash AS review_policy_hash",
  "r.action_hash AS review_action_hash",
  "r.context_hash AS review_context_hash",
  "r.invalidated_at AS review_invalidated_at",
  "r.invalidation_reason AS review_invalidation_reason",
].join(", ");

const ACTION_PUBLIC_SELECT = `SELECT ${ACTION_PUBLIC_COLUMNS} FROM actions a LEFT JOIN action_reviews r ON r.id = a.active_review_id`;

// The token-free pending-approval candidate projection. Identical
// public columns but augmented with a SQL boolean that covers
// every clean field. execution_token IS NULL is computed ONLY in
// SQL so the bearer value is never selected, materialized in
// JavaScript, or returned to the caller.
const CANDIDATE_CLEAN_BOOLEAN = `
  a.executed_at IS NULL
  AND a.active_review_id IS NULL
  AND a.planned_scope_hash IS NULL
  AND a.planned_policy_hash IS NULL
  AND a.planned_action_hash IS NULL
  AND a.planned_context_hash IS NULL
  AND a.execution_token IS NULL
  AND a.execution_owner IS NULL
  AND a.lease_expires_at IS NULL
  AND a.started_at IS NULL
  AND a.dispatch_started_at IS NULL
  AND a.finished_at IS NULL
  AND a.outcome_certainty IS NULL
  AND a.last_error_code IS NULL
  AND a.last_error_message IS NULL
`;

const CANDIDATE_SELECT = `
  SELECT ${ACTION_PUBLIC_COLUMNS}, (${CANDIDATE_CLEAN_BOOLEAN}) AS is_clean
  FROM actions a LEFT JOIN action_reviews r ON r.id = a.active_review_id
`;

// Fixed generic error messages. The contract forbids echoing raw
// data, parser cause, error.message, or input data in any error
// message. Every hostile-input or storage-decode failure path uses
// one of these constants verbatim.
const INVALID_APPROVAL_MESSAGE = "ActionQueue.approveWithReviewInTransaction requires a strict tracked-tx input";
const INVALID_CANDIDATE_ID_MESSAGE = "ActionQueue.requireCleanPendingForApproval received an invalid action identifier";
const INVALID_INPUT_MESSAGE = "ActionQueue.approveWithReviewInTransaction input is invalid";
const RECORD_INVALID_MESSAGE = "Action record is invalid";
const METADATA_INVALID_MESSAGE = "Action record has invalid metadata_json storage";
const REQUIRES_APPROVAL_INVALID_MESSAGE =
  "Action record has invalid requires_approval value (expected 0 or 1)";

const ACTION_QUEUE_TRANSACTION_REQUIRED_MESSAGE =
  "ActionQueue.approveWithReviewInTransaction requires an active withImmediateTransaction on the same handle";

// Sentinel policy reviewer ID per contract §6.
const POLICY_REVIEWER_ID = "system:policy-gate";

// 1..256 Unicode code points per the v2 review contract.
const CODE_POINT_MIN = 1;
const CODE_POINT_MAX = 256;

// Module-level lexical constants captured at module evaluation
// time. The hardened input validator uses these intrinsics
// instead of fresh dot-syntax references so a hostile
// global/import cannot redirect them at runtime.
const GET_PROTO: (value: unknown) => unknown = Object.getPrototypeOf;
const GET_OWN_DESCRIPTORS: (value: unknown) => PropertyDescriptorMap = Object.getOwnPropertyDescriptors;
const GET_OWN_DESCRIPTOR: (value: unknown, key: PropertyKey) => PropertyDescriptor | undefined =
  Object.getOwnPropertyDescriptor;
const GET_OWN_PROPERTY_NAMES: (value: unknown) => string[] = Object.getOwnPropertyNames;
const GET_OWN_PROPERTY_SYMBOLS: (value: unknown) => symbol[] = Object.getOwnPropertySymbols;
const IS_PROXY: (value: unknown) => boolean = utilTypes.isProxy;

const HEX64_PATTERN = /^[0-9a-f]{64}$/;
const HEX64_ALL_ZERO = "0".repeat(64);
const C0_DEL_REGEX = /[\0-\u001F\u007F]/u;

export class ActionQueue {
  constructor(private readonly db: BountyDatabase) {}

  enqueue(input: EnqueueActionInput): ActionRecord {
    if (input.status === "approved") {
      throw new BountyPilotError(
        "Direct approved status is forbidden; use the action approval service.",
        "ACTION_APPROVAL_SERVICE_REQUIRED",
      );
    }
    const status: ActionStatus = input.status ?? "pending";
    const requiredForCompletion = input.requiredForCompletion ?? true;
    const createdAt = nowIso();
    const action: ActionRecord = {
      id: createId("action"),
      jobId: input.jobId,
      adapter: input.adapter,
      actionType: input.actionType,
      target: input.target,
      riskLevel: input.riskLevel,
      requiresApproval: input.requiresApproval,
      status,
      metadata: input.metadata,
      createdAt,
      updatedAt: createdAt,
      requiredForCompletion,
      supersedesActionId: input.supersedesActionId,
    };

    this.db
      .prepare(
        `INSERT INTO actions (
          id, job_id, adapter, action_type, target, risk_level, requires_approval, status, metadata_json, created_at, executed_at,
          updated_at, supersedes_action_id, required_for_completion
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        action.id,
        action.jobId ?? null,
        action.adapter,
        action.actionType,
        action.target ?? null,
        action.riskLevel,
        action.requiresApproval ? 1 : 0,
        action.status,
        action.metadata ? JSON.stringify(action.metadata) : null,
        action.createdAt,
        null,
        createdAt,
        action.supersedesActionId ?? null,
        action.requiredForCompletion ? 1 : 0,
      );

    return action;
  }

  markExecuted(id: string): ActionRecord {
    // The durable lifecycle owns claim, approval expiry, dispatch marking and
    // outcome finalization. Keeping this legacy mutator callable would let a
    // caller bypass every one of those guards with a single status update.
    if (!this.db.prepare("SELECT 1 FROM actions WHERE id = ?").get(id)) {
      throw new BountyPilotError(`Action not found: ${id}`, "ACTION_NOT_FOUND");
    }
    throw new BountyPilotError(
      "Action execution must be performed by the action lifecycle service.",
      "ACTION_LIFECYCLE_SERVICE_REQUIRED",
    );
  }

  approve(id: string): ActionRecord {
    const row = this.db.prepare("SELECT 1 FROM actions WHERE id = ?").get(id) as unknown;
    if (!row) {
      throw new BountyPilotError(`Action not found: ${id}`, "ACTION_NOT_FOUND");
    }
    throw new BountyPilotError(
      "Action approval must be performed by the action approval service.",
      "ACTION_APPROVAL_SERVICE_REQUIRED",
    );
  }

  block(id: string): ActionRecord {
    const action = this.requireAction(id);
    if (action.status === "blocked") {
      return action;
    }
    assertTransition(action, "blocked");
    this.db.prepare("UPDATE actions SET status = ? WHERE id = ?").run("blocked", id);
    return { ...action, status: "blocked" };
  }

  fail(id: string): ActionRecord {
    const action = this.requireAction(id);
    if (action.status === "failed") {
      return action;
    }
    assertTransition(action, "failed");
    this.db.prepare("UPDATE actions SET status = ? WHERE id = ?").run("failed", id);
    return { ...action, status: "failed" };
  }

  get(id: string): ActionRecord | undefined {
    const row = this.db
      .prepare(`${ACTION_PUBLIC_SELECT} WHERE a.id = ?`)
      .get(id) as unknown as ActionRow | undefined;
    return row ? rowToAction(row) : undefined;
  }

  list(jobId?: string): ActionRecord[] {
    const statement =
      jobId !== undefined
        ? this.db.prepare(
            `${ACTION_PUBLIC_SELECT} WHERE a.job_id = ? ORDER BY a.created_at DESC`,
          )
        : this.db.prepare(`${ACTION_PUBLIC_SELECT} ORDER BY a.created_at DESC`);
    const rows = (jobId !== undefined ? statement.all(jobId) : statement.all()) as unknown as ActionRow[];
    return rows.map(rowToAction);
  }

  listByStatus(status: ActionStatus, jobId?: string): ActionRecord[] {
    return this.list(jobId).filter((action) => action.status === status);
  }

  summarize(jobId?: string): ActionQueueSummary {
    const summary: ActionQueueSummary = {
      total: 0,
      pending: 0,
      approved: 0,
      running: 0,
      executed: 0,
      blocked: 0,
      failed: 0,
      outcome_unknown: 0,
    };
    for (const action of this.list(jobId)) {
      summary.total += 1;
      // Defensive: if a future status lands in the summary keys, it
      // is incremented safely; unknown keys do not throw.
      if (Object.prototype.hasOwnProperty.call(summary, action.status)) {
        (summary as unknown as Record<string, number>)[action.status] += 1;
      }
    }
    return summary;
  }

  /**
   * Transaction-neutral, token-free candidate reload.
   *
   * Validates the canonical action identifier, queries the v2
   * public projection plus a SQL boolean that covers every clean
   * field, and applies the exact preflight error order required by
   * contract §7. The 15 SQL-null clean fields, including
   * execution_token IS NULL, are computed ONLY in SQL — the bearer
   * value is never selected, materialized in JavaScript, or
   * returned.
   *
   * The final CAS performed by approveWithReviewInTransaction
   * repeats every clean-state predicate, so this reload is not
   * the concurrency boundary. The method is intended for use
   * both by ActionApprovalService.preview() and inside the
   * tracked approval transaction.
   */
  requireCleanPendingForApproval(actionId: string): PendingApprovalCandidate {
    // 1) Canonical action identifier validation BEFORE any SQL.
    // The rule is: primitive string equal to its trim, 1..256
    // Unicode code points, no C0/DEL control characters.
    assertCanonicalId(actionId, INVALID_CANDIDATE_ID_MESSAGE);

    // 2) Candidate query. The projection is the same token-free
    // public column list used by get/list, augmented with a SQL
    // boolean that materializes the clean predicate. The
    // boolean is computed entirely in SQL so the bearer
    // execution_token value is never selected, materialized in
    // JavaScript, or returned.
    const row = this.db
      .prepare(`${CANDIDATE_SELECT} WHERE a.id = ?`)
      .get(actionId) as unknown as
      | (ActionRow & { is_clean: number | null | undefined })
      | undefined;

    // 3) Preflight error order: missing action -> ACTION_NOT_FOUND.
    if (!row) {
      throw new BountyPilotError(`Action not found: ${actionId}`, "ACTION_NOT_FOUND");
    }

    // 4) Preflight error order: raw status not exactly pending
    // (including the compatibility-only raw "planned" value) ->
    // ACTION_APPROVAL_NOT_PENDING. The comparison is on the raw
    // stored value so a `planned` row fails the same way it
    // would for any other non-pending status, even though
    // generic reads normalize it to "pending".
    if (row.status !== "pending") {
      throw new BountyPilotError(
        "Action is not pending",
        "ACTION_APPROVAL_NOT_PENDING",
      );
    }

    // 5) Preflight error order: null/trim-empty jobId ->
    // ACTION_APPROVAL_JOB_REQUIRED. The jobId is required to be
    // a concrete, nonempty string for the rest of preflight to
    // run.
    if (typeof row.job_id !== "string" || row.job_id.trim().length === 0) {
      throw new BountyPilotError(
        "Pending action has no jobId",
        "ACTION_APPROVAL_JOB_REQUIRED",
      );
    }

    // 6) Preflight error order: missing job row -> existing
    // JOB_NOT_FOUND. A referenced jobId whose value is not
    // present in the jobs table fails closed with the existing
    // typed store error, which the candidate propagates
    // unchanged. Only the columns required to determine
    // terminal status are selected; the job projection is
    // deliberately narrow so no extra data is materialized.
    const jobRow = this.db
      .prepare("SELECT status FROM jobs WHERE id = ?")
      .get(row.job_id) as { status: string } | undefined;
    if (!jobRow) {
      throw new BountyPilotError(`Job not found: ${row.job_id}`, "JOB_NOT_FOUND");
    }

    // 7) Preflight error order: job status failed | completed
    // -> ACTION_APPROVAL_JOB_TERMINAL. Any other value (queued,
    // running, paused, or an unrecognized status) is
    // fail-closed via the existing typed store error path so
    // malformed/unknown job rows never become a hidden
    // approval. The status column is validated only against
    // the contract-pinned terminal pair; non-terminal values
    // are accepted as valid job lifecycle states.
    if (jobRow.status === "failed" || jobRow.status === "completed") {
      throw new BountyPilotError(
        "Job is in a terminal state",
        "ACTION_APPROVAL_JOB_TERMINAL",
      );
    }
    if (jobRow.status !== "queued" && jobRow.status !== "running" && jobRow.status !== "paused") {
      // An unknown job status is a store-corruption signal and
      // must propagate as ACTION_RECORD_INVALID per §10.
      throw new BountyPilotError(
        "Action record has an unknown stored status",
        "ACTION_RECORD_INVALID",
      );
    }

    // 8) Preflight error order: dirty SQL state ->
    // ACTION_APPROVAL_STATE_INVALID. The is_clean boolean was
    // computed in SQL over all 15 clean fields including
    // execution_token IS NULL; a 0 / false / null result
    // indicates that at least one field is non-null. The
    // bearer value itself is never inspected; the only data
    // that crosses the SQL boundary is the boolean.
    if (!row.is_clean) {
      throw new BountyPilotError(
        "Action is not in a clean pending state",
        "ACTION_APPROVAL_STATE_INVALID",
      );
    }

    // 9) Strict row decoding. The row passed every preflight
    // gate; rowToAction is the same strict decoder used by
    // get/list and may fail closed with ACTION_RECORD_INVALID
    // for any storage/type/parse/shape defect (corrupted
    // requires_approval, malformed metadata_json, unknown
    // required_for_completion, unknown outcome_certainty,
    // unknown stored status, structurally invalid approved
    // review). The candidate projection is structurally
    // identical to the public projection; the only addition
    // is the SQL clean boolean, which rowToAction ignores.
    const decoded = rowToAction(row);
    // Type narrowing for the return type. The decode + status
    // preflight already guarantee jobId is a concrete string
    // and status is "pending".
    return {
      ...decoded,
      jobId: row.job_id,
      status: "pending",
    };
  }

  /**
   * In-transaction primitive that performs the single CAS
   * pending -> approved with the complete active review linkage.
   *
   * First executable operation: hasImmediateTransaction(this.db).
   * Outside the tracked transaction it throws fixed cause-free
   * ACTION_QUEUE_TRANSACTION_REQUIRED before any input reflection
   * or SQL.
   *
   * Inside the transaction it snapshots a non-null
   * plain/null-prototype input with exactly the pinned own data
   * fields and rejects accessors, hostile reflection, symbol
   * fields, Proxy objects, custom prototypes, and unknown own
   * fields. It validates actionId/jobId/reviewId/updatedAt and
   * the four hashes, selects the exact review authorization
   * columns (never note), and validates the visible review.
   *
   * It then performs exactly one UPDATE actions with the full
   * clean-state predicate and the stable-review EXISTS check;
   * changes !== 1 is a hard ACTION_APPROVAL_RACE_LOST. The
   * primitive reloads through the public token-free projection
   * and returns that action. An impossible missing post-update
   * row is ACTION_RECORD_INVALID.
   */
  approveWithReviewInTransaction(input: ApproveActionWithReviewInput): ActionRecord {
    // 1) Pure guard-state read on the EXACT handle. No SQL, no
    //    DatabaseSync.isTransaction, no input reflection.
    if (!hasImmediateTransaction(this.db)) {
      throw new BountyPilotError(
        ACTION_QUEUE_TRANSACTION_REQUIRED_MESSAGE,
        "ACTION_QUEUE_TRANSACTION_REQUIRED",
      );
    }

    // 2) Snapshot the caller DTO without invoking caller code.
    //    Every input field is read from the captured descriptor
    //    map; the input reference is never read again. Any
    //    exception from the reflection sequence (revoked Proxy,
    //    throwing traps, exotic prototypes, accessor
    //    conversions) collapses to the same fixed cause-free
    //    ACTION_APPROVAL_INVALID. Cause, error.message, and
    //    input data are never echoed.
    const validated = validateApproveInput(input);

    // 3) Fetch the exact review row by id and validate every
    //    authorization column against the input. The
    //    projection deliberately omits `note`; the bearer
    //    execution_token was never selected by the candidate
    //    projection so it cannot leak here either. Missing
    //    or malformed linkage is fixed ACTION_APPROVAL_INVALID.
    const review = loadAuthorizationReview(this.db, validated.reviewId);

    // 4) Validate review/action/job linkage, decision,
    //    invalidation nulls, source/reviewer link, canonical
    //    timestamps, and the four-hash equality to the input.
    if (review.action_id !== validated.actionId) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.job_id !== validated.jobId) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.decision !== "approved") {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.invalidated_at !== null) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.invalidation_reason !== null) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.source !== "human" && review.source !== "policy") {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    // Canonical reviewer (trim + 1..256 code points + no C0/DEL)
    // is enforced by the input snapshot for actionId/jobId/reviewId.
    // The reviewer_id comes from the visible review row itself and
    // is validated here for human reviews BEFORE any UPDATE is
    // prepared. The existing requireCanonicalReviewer helper is
    // reused inside a try/catch that maps any defect (non-string,
    // padded, empty, over-length, or C0/DEL byte) to the fixed
    // cause-free ACTION_APPROVAL_INVALID. Policy reviews remain
    // exact-equal to POLICY_REVIEWER_ID; the source/reviewer link
    // rules below are unchanged.
    if (review.source === "policy") {
      if (review.reviewer_id !== POLICY_REVIEWER_ID) {
        throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
      }
    } else {
      try {
        requireCanonicalReviewer(review.reviewer_id, "review.reviewer_id");
      } catch {
        throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
      }
      if (review.reviewer_id === POLICY_REVIEWER_ID) {
        throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
      }
    }
    // Canonical timestamps: stored created_at MUST equal
    // reviewed_at (per §6 insert contract) and BOTH must equal
    // input.updatedAt byte-for-byte. expires_at must round-trip
    // through toISOString and be strictly later than
    // reviewed_at by parsed epoch milliseconds. The three
    // stored timestamps must each round-trip exactly through
    // Date#toISOString BEFORE the UPDATE is prepared, so a
    // parseable-but-noncanonical stored value (e.g. a missing
    // millisecond fraction) fails closed. The existing
    // requireIsoRoundTrip helper is reused inside a try/catch
    // that maps any defect to the fixed cause-free
    // ACTION_APPROVAL_INVALID.
    try {
      requireIsoRoundTrip(review.created_at, "review.created_at");
      requireIsoRoundTrip(review.reviewed_at, "review.reviewed_at");
      requireIsoRoundTrip(review.expires_at, "review.expires_at");
    } catch {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.created_at !== review.reviewed_at) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.reviewed_at !== validated.updatedAt) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    const reviewedMs = Date.parse(review.reviewed_at);
    if (!Number.isFinite(reviewedMs)) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    const expiresMs = Date.parse(review.expires_at);
    if (!Number.isFinite(expiresMs) || !(expiresMs > reviewedMs)) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.expires_at === review.reviewed_at) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.scope_hash !== validated.scopeHash) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.policy_hash !== validated.policyHash) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.action_hash !== validated.actionHash) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (review.context_hash !== validated.contextHash) {
      throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
    }

    // 5) The single CAS. WHERE repeats the exact action id and
    //    job id, status = pending, all 15 IS NULL clean
    //    predicates, and the stable-review EXISTS with the same
    //    exact review fields, hashes, timestamps, source,
    //    reviewer, and invalidation nulls. The SET clause
    //    updates ONLY status = approved, active_review_id, the
    //    four planned hashes, and updated_at; every other
    //    column is left unchanged. The review row is read here
    //    for equality but never UPDATEd by this primitive.
    const cas = this.db
      .prepare(
        `UPDATE actions AS a
         SET status = 'approved',
             active_review_id = ?,
             planned_scope_hash = ?,
             planned_policy_hash = ?,
             planned_action_hash = ?,
             planned_context_hash = ?,
             updated_at = ?
         WHERE a.id = ?
           AND a.job_id = ?
           AND a.status = 'pending'
           AND a.executed_at IS NULL
           AND a.active_review_id IS NULL
           AND a.planned_scope_hash IS NULL
           AND a.planned_policy_hash IS NULL
           AND a.planned_action_hash IS NULL
           AND a.planned_context_hash IS NULL
           AND a.execution_token IS NULL
           AND a.execution_owner IS NULL
           AND a.lease_expires_at IS NULL
           AND a.started_at IS NULL
           AND a.dispatch_started_at IS NULL
           AND a.finished_at IS NULL
           AND a.outcome_certainty IS NULL
           AND a.last_error_code IS NULL
           AND a.last_error_message IS NULL
           AND EXISTS (
             SELECT 1 FROM action_reviews r
             WHERE r.id = ?
               AND r.action_id = a.id
               AND r.job_id = a.job_id
               AND r.decision = 'approved'
               AND r.invalidated_at IS NULL
               AND r.invalidation_reason IS NULL
               AND r.created_at = r.reviewed_at
               AND r.reviewed_at = ?
               AND r.expires_at > r.reviewed_at
               AND r.source = ?
               AND r.reviewer_id = ?
               AND r.scope_hash = ?
               AND r.policy_hash = ?
               AND r.action_hash = ?
               AND r.context_hash = ?
           )`,
      )
      .run(
        validated.reviewId,
        validated.scopeHash,
        validated.policyHash,
        validated.actionHash,
        validated.contextHash,
        validated.updatedAt,
        validated.actionId,
        validated.jobId,
        validated.reviewId,
        validated.updatedAt,
        review.source,
        review.reviewer_id,
        validated.scopeHash,
        validated.policyHash,
        validated.actionHash,
        validated.contextHash,
      );

    // 6) changes !== 1 is a hard ACTION_APPROVAL_RACE_LOST.
    //    No retry, no idempotent-success branch, no second
    //    SELECT. The transaction is left to roll back via the
    //    caller's withImmediateTransaction guard on the
    //    surrounding throw.
    if (cas.changes !== 1) {
      throw new BountyPilotError(
        "Action approval CAS lost the race",
        "ACTION_APPROVAL_RACE_LOST",
      );
    }

    // 7) Reload through the public token-free projection and
    //    return the action. An impossible missing post-update
    //    row is ACTION_RECORD_INVALID.
    const reloaded = this.get(validated.actionId);
    if (!reloaded) {
      throw new BountyPilotError(RECORD_INVALID_MESSAGE, "ACTION_RECORD_INVALID");
    }
    return reloaded;
  }

  private requireAction(id: string): ActionRecord {
    const action = this.get(id);
    if (!action) {
      throw new BountyPilotError(`Action not found: ${id}`, "ACTION_NOT_FOUND");
    }
    return action;
  }
}

// ---------------------------------------------------------------------------
// Validators and helpers
// ---------------------------------------------------------------------------

interface ActionRow {
  id: string;
  job_id?: string | null;
  adapter: string;
  action_type: string;
  target?: string | null;
  risk_level: RiskLevel;
  requires_approval: unknown;
  status: StoredActionStatus;
  metadata_json?: string | null;
  created_at: string;
  executed_at?: string | null;
  updated_at?: string | null;
  required_for_completion: 0 | 1 | number;
  active_review_id?: string | null;
  planned_scope_hash?: string | null;
  planned_policy_hash?: string | null;
  planned_action_hash?: string | null;
  planned_context_hash?: string | null;
  execution_owner?: string | null;
  lease_expires_at?: string | null;
  started_at?: string | null;
  dispatch_started_at?: string | null;
  finished_at?: string | null;
  outcome_certainty?: string | null;
  last_error_code?: string | null;
  last_error_message?: string | null;
  supersedes_action_id?: string | null;
  review_id?: string | null;
  review_action_id?: string | null;
  review_job_id?: string | null;
  review_decision?: string | null;
  review_reviewer_id?: string | null;
  review_source?: string | null;
  review_created_at?: string | null;
  review_reviewed_at?: string | null;
  review_expires_at?: string | null;
  review_scope_hash?: string | null;
  review_policy_hash?: string | null;
  review_action_hash?: string | null;
  review_context_hash?: string | null;
  review_invalidated_at?: string | null;
  review_invalidation_reason?: string | null;
}

interface AuthorizationReviewRow {
  id: string;
  action_id: string;
  job_id: string;
  decision: string;
  reviewer_id: string;
  source: string;
  created_at: string;
  reviewed_at: string;
  expires_at: string;
  scope_hash: string;
  policy_hash: string;
  action_hash: string;
  context_hash: string;
  invalidated_at: string | null;
  invalidation_reason: string | null;
}

function rowToAction(row: ActionRow): ActionRecord {
  const status = normalizeStatus(row.status);
  if (status === "approved") {
    assertApprovedRowStructurallyValid(row);
  }
  const requiredForCompletion = decodeRequiredForCompletion(row.required_for_completion);
  const updatedAt = row.updated_at ?? row.executed_at ?? row.created_at;
  const lastErrorCode = row.last_error_code == null ? undefined : maskSecrets(row.last_error_code);
  const lastErrorMessage = row.last_error_message == null ? undefined : maskSecrets(row.last_error_message);
  return {
    id: row.id,
    jobId: row.job_id ?? undefined,
    adapter: row.adapter,
    actionType: row.action_type,
    target: row.target ?? undefined,
    riskLevel: row.risk_level,
    requiresApproval: decodeRequiresApproval(row.requires_approval),
    status,
    metadata: parseMetadata(row.metadata_json),
    createdAt: row.created_at,
    executedAt: row.executed_at ?? undefined,
    updatedAt,
    requiredForCompletion,
    activeReviewId: row.active_review_id ?? undefined,
    plannedScopeHash: row.planned_scope_hash ?? undefined,
    plannedPolicyHash: row.planned_policy_hash ?? undefined,
    plannedActionHash: row.planned_action_hash ?? undefined,
    plannedContextHash: row.planned_context_hash ?? undefined,
    executionOwner: row.execution_owner ?? undefined,
    leaseExpiresAt: row.lease_expires_at ?? undefined,
    startedAt: row.started_at ?? undefined,
    dispatchStartedAt: row.dispatch_started_at ?? undefined,
    finishedAt: row.finished_at ?? undefined,
    outcomeCertainty: decodeOutcomeCertainty(row.outcome_certainty),
    lastErrorCode,
    lastErrorMessage,
    supersedesActionId: row.supersedes_action_id ?? undefined,
  };
}

function assertApprovedRowStructurallyValid(row: ActionRow): void {
  try {
    requireTrimNonempty(row.job_id, "action.job_id");
    requireTrimNonempty(row.active_review_id, "action.active_review_id");
    requireTrimNonempty(row.review_id, "review.id");
    if (row.active_review_id !== row.review_id) {
      throwInvalid();
    }
    if (row.review_action_id !== row.id) {
      throwInvalid();
    }
    requireTrimNonempty(row.review_job_id, "review.job_id");
    if (row.review_job_id !== row.job_id) {
      throwInvalid();
    }
    if (row.review_decision !== "approved") {
      throwInvalid();
    }
    if (row.review_invalidated_at !== null) {
      throwInvalid();
    }
    if (row.review_invalidation_reason !== null) {
      throwInvalid();
    }
    if (row.review_source !== "human" && row.review_source !== "policy") {
      throwInvalid();
    }
    requireCanonicalReviewer(row.review_reviewer_id, "review.reviewer_id");
    if (row.review_source === "policy") {
      if (row.review_reviewer_id !== "system:policy-gate") {
        throwInvalid();
      }
    } else {
      if (row.review_reviewer_id === "system:policy-gate") {
        throwInvalid();
      }
    }
    requireIsoRoundTrip(row.review_created_at, "review.created_at");
    requireIsoRoundTrip(row.review_reviewed_at, "review.reviewed_at");
    requireIsoRoundTrip(row.review_expires_at, "review.expires_at");
    if (row.review_created_at !== row.review_reviewed_at) {
      throwInvalid();
    }
    const reviewedMs = Date.parse(row.review_reviewed_at as string);
    const expiresMs = Date.parse(row.review_expires_at as string);
    if (!(expiresMs > reviewedMs)) {
      throwInvalid();
    }
    requireHexHash64(row.review_scope_hash, "review.scope_hash");
    requireHexHash64(row.review_policy_hash, "review.policy_hash");
    requireHexHash64(row.review_action_hash, "review.action_hash");
    requireHexHash64(row.review_context_hash, "review.context_hash");
    requireHexHash64(row.planned_scope_hash, "action.planned_scope_hash");
    requireHexHash64(row.planned_policy_hash, "action.planned_policy_hash");
    requireHexHash64(row.planned_action_hash, "action.planned_action_hash");
    requireHexHash64(row.planned_context_hash, "action.planned_context_hash");
    if (row.review_scope_hash !== row.planned_scope_hash) throwInvalid();
    if (row.review_policy_hash !== row.planned_policy_hash) throwInvalid();
    if (row.review_action_hash !== row.planned_action_hash) throwInvalid();
    if (row.review_context_hash !== row.planned_context_hash) throwInvalid();
  } catch {
    throw new BountyPilotError(
      "Approved action row failed structural review validation.",
      "ACTION_APPROVAL_INVALID",
    );
  }
}

function throwInvalid(): never {
  throw new Error("ACTION_APPROVAL_INVALID");
}

function requireTrimNonempty(value: unknown, _field: string): asserts value is string {
  if (typeof value !== "string") {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  if (value.trim().length === 0) {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
}

function requireCanonicalReviewer(value: unknown, _field: string): asserts value is string {
  if (typeof value !== "string") {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  if (value !== value.trim()) {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  const codePoints = Array.from(value);
  if (codePoints.length < CODE_POINT_MIN || codePoints.length > CODE_POINT_MAX) {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  for (const cp of codePoints) {
    const code = cp.codePointAt(0);
    if (code === undefined) {
      throw new Error("ACTION_APPROVAL_INVALID");
    }
    if (code < 0x20 || code === 0x7f) {
      throw new Error("ACTION_APPROVAL_INVALID");
    }
  }
}

function requireIsoRoundTrip(value: unknown, _field: string): asserts value is string {
  if (typeof value !== "string") {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  if (parsed.toISOString() !== value) {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
}

function requireHexHash64(value: unknown, _field: string): asserts value is string {
  if (typeof value !== "string") {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  if (!HEX64_PATTERN.test(value)) {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
  if (value === HEX64_ALL_ZERO) {
    throw new Error("ACTION_APPROVAL_INVALID");
  }
}

function parseMetadata(value?: string | null): Record<string, unknown> | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new BountyPilotError(METADATA_INVALID_MESSAGE, "ACTION_RECORD_INVALID");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new BountyPilotError(METADATA_INVALID_MESSAGE, "ACTION_RECORD_INVALID");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BountyPilotError(METADATA_INVALID_MESSAGE, "ACTION_RECORD_INVALID");
  }
  // Public action reads must remain safe even when a legacy row or a direct
  // database write placed secret-bearing values in metadata_json.  Authority
  // materialization uses its own locked raw projection, so masking the public
  // projection cannot change approval hashes or execution semantics.
  return maskSecretsDeep(parsed as Record<string, unknown>);
}

function normalizeStatus(status: StoredActionStatus): ActionStatus {
  if (status === "planned") {
    return "pending";
  }
  switch (status) {
    case "pending":
    case "approved":
    case "running":
    case "executed":
    case "blocked":
    case "failed":
    case "outcome_unknown":
      return status;
    default:
      throw new BountyPilotError(
        "Action record has an unknown stored status.",
        "ACTION_RECORD_INVALID",
      );
  }
}

function decodeRequiredForCompletion(value: unknown): boolean {
  if (value === 0) {
    return false;
  }
  if (value === 1) {
    return true;
  }
  throw new BountyPilotError(
    "Action record has invalid required_for_completion value (expected 0 or 1)",
    "ACTION_RECORD_INVALID",
  );
}

// Strict requires_approval decoder. Only raw numeric integer 0
// (false) and raw numeric integer 1 (true) are valid. Any other
// value — integer 2, integer -1, REAL 1.5, non-numeric TEXT, BLOB,
// etc. — throws fixed cause-free ACTION_RECORD_INVALID.
function decodeRequiresApproval(value: unknown): boolean {
  // node:sqlite returns integer columns as JS numbers. The
  // strict rule is: must be exactly the primitive number 0
  // or the primitive number 1. Every other storage class,
  // including non-integer numbers (REAL 1.5), non-numeric
  // strings, and bigint, fails closed. Truthiness coercion
  // is forbidden.
  if (value === 0) {
    return false;
  }
  if (value === 1) {
    return true;
  }
  throw new BountyPilotError(REQUIRES_APPROVAL_INVALID_MESSAGE, "ACTION_RECORD_INVALID");
}

function decodeOutcomeCertainty(value?: string | null): OutcomeCertainty | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (value === "success" || value === "not_dispatched" || value === "possibly_dispatched") {
    return value;
  }
  // An unknown stored value is a record corruption signal.
  throw new BountyPilotError(
    "Action record has an unknown outcome_certainty.",
    "ACTION_RECORD_INVALID",
  );
}

// ---------------------------------------------------------------------------
// Canonical-ID validation (used by requireCleanPendingForApproval and the
// approveWithReviewInTransaction input snapshot).
// ---------------------------------------------------------------------------

function assertCanonicalId(value: unknown, message: string): asserts value is string {
  if (typeof value !== "string") {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  if (value !== value.trim()) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  if (value.length === 0) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  // C0/DEL must be rejected on the RAW value so trim-removable
  // controls at the boundaries are not silently stripped.
  if (C0_DEL_REGEX.test(value)) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  const codePoints = Array.from(value);
  if (codePoints.length < CODE_POINT_MIN || codePoints.length > CODE_POINT_MAX) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
}

function assertCanonicalIsoTimestamp(value: unknown, message: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  if (parsed.toISOString() !== value) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
}

function assertNonzeroHex64(value: unknown, message: string): asserts value is string {
  if (typeof value !== "string") {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  if (!HEX64_PATTERN.test(value)) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
  if (value === HEX64_ALL_ZERO) {
    throw new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
  }
}

// ---------------------------------------------------------------------------
// Hostile-input snapshot for approveWithReviewInTransaction.
//
// The reflection sequence uses the captured module-level
// intrinsics only. The caller-supplied `input` is read once to
// capture the descriptor map; thereafter every field read goes
// through the captured Object.getOwnPropertyDescriptor on the
// map. Any exception raised by getPrototypeOf, getOwnPropertyDescriptors,
// getOwnPropertyDescriptor, or the descriptor conversion itself
// collapses to the same fixed cause-free ACTION_APPROVAL_INVALID.
// Cause, error.message, and input data are never echoed.
// ---------------------------------------------------------------------------

type ReadResult =
  | { kind: "ABSENT" }
  | { kind: "ACCESSOR" }
  | { kind: "DATA"; value: unknown };

function readField(
  map: PropertyDescriptorMap,
  key: PropertyKey,
  getDescriptor: (value: unknown, k: PropertyKey) => PropertyDescriptor | undefined,
): ReadResult {
  // Layer 1: outer descriptor for the map entry.
  const outer = getDescriptor(map, key);
  if (outer === undefined) {
    return { kind: "ABSENT" };
  }
  // Acquire outer's own `value` slot via the captured intrinsic.
  const outerValueSlot = getDescriptor(outer, "value");
  if (outerValueSlot === undefined) {
    return { kind: "ACCESSOR" };
  }
  const inner = outerValueSlot.value;
  if (inner === null || typeof inner !== "object") {
    return { kind: "ABSENT" };
  }
  // Layer 2: acquire the inner descriptor's own `value` slot.
  const innerValueSlot = getDescriptor(inner, "value");
  if (innerValueSlot === undefined) {
    return { kind: "ACCESSOR" };
  }
  return { kind: "DATA", value: innerValueSlot.value };
}

interface ValidatedApproveInput {
  actionId: string;
  jobId: string;
  reviewId: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
  updatedAt: string;
}

function validateApproveInput(input: unknown): ValidatedApproveInput {
  // Every reflection step is wrapped; ANY exception becomes
  // the same fixed cause-free ACTION_APPROVAL_INVALID.
  let proto: unknown;
  let ownNames: string[];
  let ownSymbols: symbol[];
  try {
    if (input === null || typeof input !== "object") {
      throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    // node:util/types.isProxy is true for both active and
    // revoked Proxies. The check happens BEFORE any
    // reflection so the primitive never enters a hostile
    // get/has/ownKeys trap.
    if (IS_PROXY(input)) {
      throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    proto = GET_PROTO(input);
    if (proto !== Object.prototype && proto !== null) {
      throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    // Capture both string and symbol own keys BEFORE reading
    // descriptors. A hostile DTO that smuggles a symbol own
    // property is detected by GET_OWN_PROPERTY_SYMBOLS.
    ownNames = GET_OWN_PROPERTY_NAMES(input);
    ownSymbols = GET_OWN_PROPERTY_SYMBOLS(input);
  } catch (err) {
    if (err instanceof BountyPilotError) {
      throw err;
    }
    throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
  }

  // Reject any own symbol keys. A plain-object DTO may not
  // smuggle extra symbol own fields, even when the eight
  // expected string fields are all present.
  if (ownSymbols.length !== 0) {
    throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
  }

  // The descriptor map captures the data-vs-accessor shape
  // of every own string key. We acquire the map AFTER the
  // proxy and own-name checks; the only reflection on the
  // input from this point onward is through the captured
  // map and the captured GET_OWN_DESCRIPTOR intrinsic.
  let descriptorMap: PropertyDescriptorMap;
  try {
    descriptorMap = GET_OWN_DESCRIPTORS(input);
  } catch {
    throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
  }

  // The exact eight own string keys must be present. The
  // ownNames list is the trusted string-only key inventory
  // of the input; any deviation from the expected set is a
  // hostile DTO.
  if (ownNames.length !== 8) {
    throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
  }
  const expectedKeys = [
    "actionId",
    "jobId",
    "reviewId",
    "scopeHash",
    "policyHash",
    "actionHash",
    "contextHash",
    "updatedAt",
  ];
  const present = new Set<string>(ownNames);
  for (const expected of expectedKeys) {
    if (!present.has(expected)) {
      throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
  }
  for (const key of ownNames) {
    if (!expectedKeys.includes(key)) {
      throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
  }

  // The exact eight own data fields. Each is required to
  // be present as an own data descriptor. Accessors are
  // rejected. The descriptor map is an ordinary Object, so
  // we must read its own entries with the captured
  // GET_OWN_DESCRIPTOR rather than with dot/bracket syntax
  // (which would consult the prototype chain).
  function requireOwnData(key: PropertyKey): unknown {
    const r = readField(descriptorMap, key, GET_OWN_DESCRIPTOR);
    if (r.kind === "ABSENT") {
      throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    if (r.kind === "ACCESSOR") {
      throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
    }
    return r.value;
  }

  const actionIdRaw = requireOwnData("actionId");
  const jobIdRaw = requireOwnData("jobId");
  const reviewIdRaw = requireOwnData("reviewId");
  const scopeHashRaw = requireOwnData("scopeHash");
  const policyHashRaw = requireOwnData("policyHash");
  const actionHashRaw = requireOwnData("actionHash");
  const contextHashRaw = requireOwnData("contextHash");
  const updatedAtRaw = requireOwnData("updatedAt");

  // ID fields: must be a primitive string equal to its
  // trim, 1..256 Unicode code points, no C0/DEL. Use the
  // canonical-ID validator with the same fixed message;
  // any defect is fixed cause-free ACTION_APPROVAL_INVALID.
  try {
    assertCanonicalId(actionIdRaw, INVALID_INPUT_MESSAGE);
    assertCanonicalId(jobIdRaw, INVALID_INPUT_MESSAGE);
    assertCanonicalId(reviewIdRaw, INVALID_INPUT_MESSAGE);
  } catch (err) {
    if (err instanceof BountyPilotError) {
      throw err;
    }
    throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
  }
  // Narrowed to string after assertCanonicalId.
  const actionId = actionIdRaw as string;
  const jobId = jobIdRaw as string;
  const reviewId = reviewIdRaw as string;

  // Hashes: must be 64 lowercase hex characters and not
  // the all-zero sentinel.
  try {
    assertNonzeroHex64(scopeHashRaw, INVALID_INPUT_MESSAGE);
    assertNonzeroHex64(policyHashRaw, INVALID_INPUT_MESSAGE);
    assertNonzeroHex64(actionHashRaw, INVALID_INPUT_MESSAGE);
    assertNonzeroHex64(contextHashRaw, INVALID_INPUT_MESSAGE);
  } catch (err) {
    if (err instanceof BountyPilotError) {
      throw err;
    }
    throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
  }
  const scopeHash = scopeHashRaw as string;
  const policyHash = policyHashRaw as string;
  const actionHash = actionHashRaw as string;
  const contextHash = contextHashRaw as string;

  // updatedAt: must parse finite and round-trip exactly
  // through toISOString. The CAS writes this exact value
  // into actions.updated_at, so a non-canonical string
  // would silently desynchronize the persisted state from
  // the contract invariant.
  try {
    assertCanonicalIsoTimestamp(updatedAtRaw, INVALID_INPUT_MESSAGE);
  } catch (err) {
    if (err instanceof BountyPilotError) {
      throw err;
    }
    throw new BountyPilotError(INVALID_INPUT_MESSAGE, "ACTION_APPROVAL_INVALID");
  }
  const updatedAt = updatedAtRaw as string;

  return {
    actionId,
    jobId,
    reviewId,
    scopeHash,
    policyHash,
    actionHash,
    contextHash,
    updatedAt,
  };
}

// Load the exact review authorization columns. The query
// intentionally OMITS `note` and never references
// `actions.execution_token`. A missing row is fixed
// ACTION_APPROVAL_INVALID (linkage by id mismatch with the
// input reviewId).
const AUTHORIZATION_REVIEW_SELECT = `
  SELECT id, action_id, job_id, decision, reviewer_id, source,
         created_at, reviewed_at, expires_at,
         scope_hash, policy_hash, action_hash, context_hash,
         invalidated_at, invalidation_reason
  FROM action_reviews
  WHERE id = ?
`;

function loadAuthorizationReview(db: BountyDatabase, reviewId: string): AuthorizationReviewRow {
  const row = db
    .prepare(AUTHORIZATION_REVIEW_SELECT)
    .get(reviewId) as AuthorizationReviewRow | undefined;
  if (!row) {
    throw new BountyPilotError(INVALID_APPROVAL_MESSAGE, "ACTION_APPROVAL_INVALID");
  }
  return row;
}

// ---------------------------------------------------------------------------
// Status transition guard (legacy enqueue/block/fail/markExecuted).
// ---------------------------------------------------------------------------

function assertTransition(action: ActionRecord, next: ActionStatus): void {
  const allowed = isTransitionAllowed(action.status, next);
  if (!allowed) {
    throw new BountyPilotError(
      `Cannot transition action ${action.id} from ${action.status} to ${next}`,
      "ACTION_INVALID_TRANSITION",
    );
  }
}

function isTransitionAllowed(current: ActionStatus, next: ActionStatus): boolean {
  if (current === next) {
    return true;
  }
  if (current === "pending") {
    return next === "approved" || next === "blocked" || next === "failed";
  }
  if (current === "approved") {
    return next === "executed" || next === "blocked" || next === "failed";
  }
  return false;
}
