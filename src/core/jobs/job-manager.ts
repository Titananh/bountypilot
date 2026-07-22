import type { BountyDatabase } from "../../stores/db/database.js";
import { hasImmediateTransaction, withImmediateTransaction } from "../../stores/db/migrations.js";
import type { ExecutionMode } from "../../types.js";
import { canonicalize } from "../../utils/canonical-json.js";
import { BountyPilotError } from "../../utils/errors.js";
import { createId } from "../../utils/ids.js";
import { nowIso } from "../../utils/time.js";

export type JobStatus = "queued" | "running" | "paused" | "failed" | "completed";

export type PauseReason =
  | "approval_required"
  | "execution_ready"
  | "policy_drift"
  | "policy_blocked"
  | "reconciliation_required"
  | "budget_exhausted"
  | "manual_review";

export interface RequiredActionCounts {
  approved: number;
  blocked: number;
  executed: number;
  failed: number;
  outcome_unknown: number;
  pending: number;
  running: number;
}

interface ActionStatusAggregation extends RequiredActionCounts {
  total: number;
  optionalRunning: number;
  optionalOutcomeUnknown: number;
}

export interface JobRecord {
  id: string;
  type: string;
  target?: string;
  mode: ExecutionMode;
  status: JobStatus;
  pauseReason: PauseReason | null;
  statusDetail: string | null;
  createdAt: string;
  updatedAt: string;
}

const COUNT_KEYS_ORDER: ReadonlyArray<keyof RequiredActionCounts> = [
  "approved",
  "blocked",
  "executed",
  "failed",
  "outcome_unknown",
  "pending",
  "running",
];

type CountedStatus = keyof RequiredActionCounts;

const RECOGNIZED_ACTION_STATUSES: ReadonlyArray<CountedStatus> = [
  "approved",
  "blocked",
  "executed",
  "failed",
  "outcome_unknown",
  "pending",
  "running",
];

const JOB_FINALIZE_WRITE_FAILED_MESSAGE = "job finalization write did not affect exactly one row";
const JOB_FINALIZE_WRITE_FAILED_CODE = "JOB_FINALIZE_WRITE_FAILED";

export class JobManager {
  constructor(private readonly db: BountyDatabase) {}

  create(type: string, mode: ExecutionMode, target?: string): JobRecord {
    const now = nowIso();
    const job: JobRecord = {
      id: createId("job"),
      type,
      target,
      mode,
      status: "queued",
      pauseReason: null,
      statusDetail: null,
      createdAt: now,
      updatedAt: now,
    };
    this.db
      .prepare(
        "INSERT INTO jobs (id, type, target, mode, status, pause_reason, status_detail, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        job.id,
        job.type,
        job.target ?? null,
        job.mode,
        job.status,
        job.pauseReason,
        job.statusDetail,
        job.createdAt,
        job.updatedAt,
      );
    return job;
  }

  updateStatus(id: string, status: JobStatus): JobRecord {
    // Completion branch: must precede the legacy same-status
    // shortcut. It owns its own immediate transaction, reloads the
    // job and counts WITHIN that transaction, and rejects with
    // JOB_COMPLETION_BLOCKED before any write when any required
    // action is not executed. A stale preseeded completed job
    // with a pending required action must still throw and remain
    // byte-identical (no UPDATE issued).
    if (status === "completed") {
      return withImmediateTransaction(this.db, () => {
        const job = this.get(id);
        if (!job) {
          throw new BountyPilotError(`Job not found: ${id}`, "JOB_NOT_FOUND");
        }
        const counts = this.aggregateRequiredActionCountsInTransaction(id);
        const hasOutstandingRequired =
          counts.total > 0 && counts.executed < counts.total;
        const hasSafetyCriticalOptional =
          counts.optionalRunning > 0 || counts.optionalOutcomeUnknown > 0;
        if (hasOutstandingRequired || hasSafetyCriticalOptional) {
          throw new BountyPilotError(
            hasSafetyCriticalOptional
              ? `Cannot complete job ${id}: a non-required action is running or requires reconciliation.`
              : `Cannot complete job ${id}: ${counts.total - counts.executed} required action(s) are not executed.`,
            "JOB_COMPLETION_BLOCKED",
          );
        }
        // Zero required or all required executed: apply the same
        // finalization primitive. Never call public finalize from
        // inside a transaction.
        return this.finalizeInTransaction(id);
      });
    }

    const job = this.requireJob(id);
    if (job.status === status) {
      return job;
    }
    assertJobTransition(job, status);
    const updatedAt = nowIso();
    this.db.prepare("UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?").run(status, updatedAt, id);
    return { ...job, status, updatedAt };
  }

  resume(id: string): JobRecord {
    return this.updateStatus(id, "running");
  }

  get(id: string): JobRecord | undefined {
    const row = this.db
      .prepare(`${SELECT_JOB_PUBLIC_COLUMNS} WHERE id = ?`)
      .get(id) as unknown as JobRow | undefined;
    return row ? rowToJob(row) : undefined;
  }

  list(limit = 50): JobRecord[] {
    const rows = this.db
      .prepare(`${SELECT_JOB_PUBLIC_COLUMNS} ORDER BY created_at DESC LIMIT ?`)
      .all(limit) as unknown as JobRow[];
    return rows.map(rowToJob);
  }

  /**
   * Public transaction-owning wrapper. Inside the immediate
   * transaction it delegates to `finalizeInTransaction`, which is
   * the in-tx primitive. If the caller is already inside a
   * tracked transaction, the nested call would raise
   * `DB_TRANSACTION_NESTED` and the original error is preserved
   * (never swallowed).
   */
  finalize(id: string): JobRecord {
    return withImmediateTransaction(this.db, () => this.finalizeInTransaction(id));
  }

  /**
   * In-transaction primitive. Must be called inside a tracked
   * `withImmediateTransaction` scope. The first executable guard
   * is the transaction check: if there is no active immediate
   * transaction on this handle, throws `JOB_TRANSACTION_REQUIRED`
   * BEFORE any SQL is issued. Then reloads the exact job (or
   * preserves `JOB_NOT_FOUND`) and derives the tuple from the
   * required actions scoped to this exact job under the caller
   * transaction. Required-action counts are aggregated
   * strictly-validated (0|1), while non-required running and
   * outcome_unknown rows contribute only to the safety tuple. Tuple idempotence: if the
   * persisted (status, pauseReason, statusDetail) already equal
   * the derived tuple, the reloaded record is returned with no
   * UPDATE and the existing `updated_at` is preserved; otherwise
   * exactly one UPDATE is issued for (status, pause_reason,
   * status_detail, updated_at) and the updated record is returned.
   * No IDs, targets, metadata, execution_token, errors, or
   * review data are selected.
   */
  finalizeInTransaction(id: string): JobRecord {
    if (!hasImmediateTransaction(this.db)) {
      throw new BountyPilotError(
        `finalizeInTransaction requires an active immediate transaction on the same database handle`,
        "JOB_TRANSACTION_REQUIRED",
      );
    }

    const job = this.get(id);
    if (!job) {
      throw new BountyPilotError(`Job not found: ${id}`, "JOB_NOT_FOUND");
    }

    const counts = this.aggregateRequiredActionCountsInTransaction(id);
    const { status: derivedStatus, pauseReason: derivedPauseReason } = deriveTuple(counts);
    const derivedStatusDetail = serializeStatusDetail(counts);

    if (
      job.status === derivedStatus &&
      job.pauseReason === derivedPauseReason &&
      job.statusDetail === derivedStatusDetail
    ) {
      return job;
    }

    const updatedAt = nowIso();
    const result = this.db
      .prepare(
        "UPDATE jobs SET status = ?, pause_reason = ?, status_detail = ?, updated_at = ? WHERE id = ?",
      )
      .run(derivedStatus, derivedPauseReason, derivedStatusDetail, updatedAt, id);
    // A BEFORE UPDATE trigger can silently suppress the write via
    // RAISE(IGNORE). Do not return a fabricated updated record in
    // that case: a lifecycle caller relies on this primitive to
    // make the terminal action, event, and derived job tuple
    // atomic. Accept number and bigint representations of the
    // one-row RunResult only; every other count fails closed.
    if (result.changes !== 1 && result.changes !== 1n) {
      throw new BountyPilotError(
        JOB_FINALIZE_WRITE_FAILED_MESSAGE,
        JOB_FINALIZE_WRITE_FAILED_CODE,
      );
    }
    return { ...job, status: derivedStatus, pauseReason: derivedPauseReason, statusDetail: derivedStatusDetail, updatedAt };
  }

  /**
   * Aggregate required-action counts for one job under the caller
   * transaction. Reads ONLY the columns required to derive the
   * tuple (no ids, targets, metadata, execution_token, errors, or
   * review data), scoped strictly to the exact job_id. The result
   * is grouped by (required_for_completion, status) with COUNT(*)
   * computed per group; that bounded, server-side aggregation
   * replaces the previous per-row materialization.
   *
   * Validation, all of which throws a fixed-message
   * ACTION_RECORD_INVALID (never echoing raw data):
   *   - `required_for_completion` is strictly 0 or 1.
   *   - For `required_for_completion = 0`, pending/approved/terminal
   *     groups remain excluded. `running` and `outcome_unknown` are
   *     tracked separately so an active or ambiguous effect cannot be
   *     hidden behind job completion.
   *   - For `required_for_completion = 1` the status MUST be one
   *     of the seven recognized counted statuses; any other
   *     string fails closed.
   *   - The grouped COUNT(*) is a positive safe integer.
   *   - Accumulating `count` into the per-status bucket and into
   *     `total` is guarded against safe-integer overflow
   *     (Number.isSafeInteger). Any overflow fails closed.
   */
  private aggregateRequiredActionCountsInTransaction(id: string): ActionStatusAggregation {
    const counts: RequiredActionCounts = {
      approved: 0,
      blocked: 0,
      executed: 0,
      failed: 0,
      outcome_unknown: 0,
      pending: 0,
      running: 0,
    };
    let total = 0;
    let optionalRunning = 0;
    let optionalOutcomeUnknown = 0;
    const groups = this.db
      .prepare(
        "SELECT required_for_completion AS required_for_completion, status AS status, COUNT(*) AS count FROM actions WHERE job_id = ? GROUP BY required_for_completion, status",
      )
      .all(id) as Array<{ required_for_completion: unknown; status: unknown; count: unknown }>;
    for (const group of groups) {
      const required = group.required_for_completion;
      if (required !== 0 && required !== 1) {
        throw new BountyPilotError(
          "Action record has invalid required_for_completion value (expected 0 or 1)",
          "ACTION_RECORD_INVALID",
        );
      }
      if (required === 0) {
        // Non-required pending/approved/terminal rows remain excluded from
        // completion. Once an effect is running or its outcome is uncertain,
        // however, the job must not hide that safety-critical state.
        if (group.status === "running") {
          optionalRunning = addCount(optionalRunning, decodeGroupedCount(group.count));
        } else if (group.status === "outcome_unknown") {
          optionalOutcomeUnknown = addCount(optionalOutcomeUnknown, decodeGroupedCount(group.count));
        }
        continue;
      }
      const status = group.status;
      if (typeof status !== "string" || !isCountedStatus(status)) {
        throw new BountyPilotError(
          "Action record has an unknown stored status.",
          "ACTION_RECORD_INVALID",
        );
      }
      // Group cardinality must be a positive safe integer. The DB
      // returns COUNT(*) as a number; reject anything that is not
      // a finite, safe, strictly positive integer so a corrupted
      // or hostile value cannot poison the precedence derivation.
      const groupCount = decodeGroupedCount(group.count);
      // Accumulate the per-status bucket with a safe-integer
      // overflow guard. Adding two safe integers may exceed
      // Number.MAX_SAFE_INTEGER; reject that case fail-closed
      // rather than producing a silently-wrapped count.
      counts[status] = addCount(counts[status], groupCount);
      // Same overflow guard for the running total.
      total = addCount(total, groupCount);
    }
    return { ...counts, total, optionalRunning, optionalOutcomeUnknown };
  }

  private requireJob(id: string): JobRecord {
    const job = this.get(id);
    if (!job) {
      throw new BountyPilotError(`Job not found: ${id}`, "JOB_NOT_FOUND");
    }
    return job;
  }
}

const JOB_PUBLIC_COLUMNS = [
  "id AS id",
  "type AS type",
  "target AS target",
  "mode AS mode",
  "status AS status",
  "pause_reason AS pause_reason",
  "status_detail AS status_detail",
  "created_at AS created_at",
  "updated_at AS updated_at",
].join(", ");

const SELECT_JOB_PUBLIC_COLUMNS = `SELECT ${JOB_PUBLIC_COLUMNS} FROM jobs`;

interface JobRow {
  id: string;
  type: string;
  target?: string | null;
  mode: ExecutionMode;
  status: JobStatus;
  pause_reason: string | null;
  status_detail: string | null;
  created_at: string;
  updated_at: string;
}

function rowToJob(row: JobRow): JobRecord {
  return {
    id: row.id,
    type: row.type,
    target: row.target ?? undefined,
    mode: row.mode,
    status: row.status,
    pauseReason: decodePauseReason(row.pause_reason),
    statusDetail: row.status_detail,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const PAUSE_REASON_VALUES: ReadonlySet<PauseReason> = new Set<PauseReason>([
  "approval_required",
  "execution_ready",
  "policy_drift",
  "policy_blocked",
  "reconciliation_required",
  "budget_exhausted",
  "manual_review",
]);

// Fixed generic message. The stored value is intentionally NOT
// interpolated: this is a record-corruption signal, and echoing the
// raw bytes would leak attacker-controlled data through the public
// error message and through structured logs. Every other (non-null,
// non-recognized) stored pause_reason throws ACTION_RECORD_INVALID
// via this function so that rowToJob -> get/list AND
// finalizeInTransaction -> finalize fail closed BEFORE any write
// (the finalizer calls get(id) first, so the throw happens before
// the idempotence check and before the UPDATE).
const INVALID_PAUSE_REASON_MESSAGE = "jobs.pause_reason has an unrecognized stored value";

function decodePauseReason(value: string | null): PauseReason | null {
  if (value === null) {
    return null;
  }
  if (PAUSE_REASON_VALUES.has(value as PauseReason)) {
    return value as PauseReason;
  }
  // Any non-null stored value that is not one of the seven exact
  // PauseReason literals is a record-corruption signal. Do not
  // normalize, heal, echo, or silently hide it. Fail closed.
  throw new BountyPilotError(INVALID_PAUSE_REASON_MESSAGE, "ACTION_RECORD_INVALID");
}

function deriveTuple(counts: ActionStatusAggregation): {
  status: JobStatus;
  pauseReason: PauseReason | null;
} {
  // Precedence: outcome_unknown > running > blocked|failed >
  // pending > approved > all-executed/zero-required.
  // Executed and inactive non-required rows never outrank blockers; zero
  // required completes only when no optional effect is active/uncertain.
  if (counts.outcome_unknown > 0 || counts.optionalOutcomeUnknown > 0) {
    return { status: "paused", pauseReason: "reconciliation_required" };
  }
  if (counts.running > 0 || counts.optionalRunning > 0) {
    return { status: "running", pauseReason: null };
  }
  if (counts.blocked > 0 || counts.failed > 0) {
    return { status: "failed", pauseReason: counts.blocked > 0 ? "policy_blocked" : null };
  }
  if (counts.pending > 0) {
    return { status: "paused", pauseReason: "approval_required" };
  }
  if (counts.approved > 0) {
    return { status: "paused", pauseReason: "execution_ready" };
  }
  return { status: "completed", pauseReason: null };
}

function serializeStatusDetail(counts: ActionStatusAggregation): string {
  // Pin the exact key order to COUNT_KEYS_ORDER so the canonical
  // JSON is byte-stable. Only the seven integer counters; no raw
  // rows, no secrets, no extra keys.
  const requiredActionCounts: Record<string, number> = {};
  for (const key of COUNT_KEYS_ORDER) {
    requiredActionCounts[key] = counts[key];
  }
  const payload: {
    schemaVersion: number;
    requiredActionCounts: Record<string, number>;
    safetyCriticalOptionalActionCounts?: { running: number; outcome_unknown: number };
  } = {
    schemaVersion: 1,
    requiredActionCounts,
  };
  if (counts.optionalRunning > 0 || counts.optionalOutcomeUnknown > 0) {
    payload.safetyCriticalOptionalActionCounts = {
      running: counts.optionalRunning,
      outcome_unknown: counts.optionalOutcomeUnknown,
    };
  }
  return canonicalize(payload).toString("utf8");
}

function decodeGroupedCount(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    throw new BountyPilotError(
      "Action record has an invalid grouped count.",
      "ACTION_RECORD_INVALID",
    );
  }
  return value;
}

function addCount(current: number, increment: number): number {
  const next = current + increment;
  if (!Number.isSafeInteger(next) || next > Number.MAX_SAFE_INTEGER) {
    throw new BountyPilotError(
      "Action record count overflow.",
      "ACTION_RECORD_INVALID",
    );
  }
  return next;
}

function isCountedStatus(value: string): value is CountedStatus {
  for (const candidate of RECOGNIZED_ACTION_STATUSES) {
    if (candidate === value) {
      return true;
    }
  }
  return false;
}

function assertJobTransition(job: JobRecord, next: JobStatus): void {
  if (isJobTransitionAllowed(job.status, next)) {
    return;
  }
  throw new BountyPilotError(`Cannot transition job ${job.id} from ${job.status} to ${next}`, "JOB_INVALID_TRANSITION");
}

function isJobTransitionAllowed(current: JobStatus, next: JobStatus): boolean {
  if (current === next) {
    return true;
  }
  if (current === "queued") {
    return next === "running" || next === "paused" || next === "failed" || next === "completed";
  }
  if (current === "running") {
    return next === "paused" || next === "failed" || next === "completed";
  }
  if (current === "paused") {
    return next === "running" || next === "failed" || next === "completed";
  }
  return false;
}
