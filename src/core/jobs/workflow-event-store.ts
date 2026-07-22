import type { BountyDatabase } from "../../stores/db/database.js";
import { hasImmediateTransaction, withImmediateTransaction } from "../../stores/db/database.js";
import { BountyPilotError } from "../../utils/errors.js";
import { createId } from "../../utils/ids.js";
import { maskSecrets, maskSecretsDeep } from "../../utils/secrets.js";
import { nowIso } from "../../utils/time.js";

export type WorkflowEventStatus =
  | "running"
  | "completed"
  | "failed"
  | "skipped"
  | "planned"
  | "blocked"
  | "paused";

export interface WorkflowEventRecord {
  id: string;
  jobId: string;
  sequence: number;
  phase: string;
  status: WorkflowEventStatus;
  message: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface WorkflowEventInput {
  jobId: string;
  phase: string;
  status: WorkflowEventStatus;
  message: string;
  metadata?: Record<string, unknown>;
}

const CODE_TRANSACTION_REQUIRED = "WORKFLOW_EVENT_TRANSACTION_REQUIRED";
const CODE_SEQUENCE_CONFLICT = "WORKFLOW_EVENT_SEQUENCE_CONFLICT";
const CODE_WRITE_FAILED = "WORKFLOW_EVENT_WRITE_FAILED";
const MESSAGE_WRITE_FAILED = "workflow event write did not affect exactly one row";

export class WorkflowEventStore {
  constructor(private readonly db: BountyDatabase) {}

  /**
   * Public transaction-owning wrapper. Allocates a fresh sequence
   * per job (MAX(sequence)+1), masks message and metadata, and
   * INSERTs exactly once under a tracked BEGIN IMMEDIATE. The
   * wrapper never retries; a UNIQUE(job_id, sequence) conflict
   * surfaces as WORKFLOW_EVENT_SEQUENCE_CONFLICT and rolls back
   * the caller's transaction.
   */
  record(input: WorkflowEventInput): WorkflowEventRecord {
    return withImmediateTransaction(this.db, () => this.recordInTransaction(input));
  }

  /**
   * In-tx primitive. Requires that a tracked
   * `withImmediateTransaction` is already active on `this.db` for
   * the SAME handle (per-handle, not global). Under that
   * transaction, computes MAX(sequence)+1 for the job, masks
   * message and metadata, and INSERTs exactly once. Returns the
   * masked record. Never begins, commits, or rolls back.
   */
  recordInTransaction(input: WorkflowEventInput): WorkflowEventRecord {
    if (!hasImmediateTransaction(this.db)) {
      throw new BountyPilotError(
        "recordInTransaction requires an active withImmediateTransaction on the same database handle",
        CODE_TRANSACTION_REQUIRED,
      );
    }

    const maskedMessage = maskSecrets(input.message);
    const maskedMetadata = input.metadata ? maskSecretsDeep(input.metadata) : undefined;

    const event: WorkflowEventRecord = {
      id: createId("event"),
      jobId: input.jobId,
      sequence: this.nextSequence(input.jobId),
      phase: input.phase,
      status: input.status,
      message: maskedMessage,
      metadata: maskedMetadata,
      createdAt: nowIso(),
    };

    try {
      const result = this.db
        .prepare(
          `INSERT INTO workflow_events (
            id, job_id, sequence, phase, status, message, metadata_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          event.id,
          event.jobId,
          event.sequence,
          event.phase,
          event.status,
          event.message,
          event.metadata ? JSON.stringify(event.metadata) : null,
          event.createdAt,
        );
      // A BEFORE INSERT trigger can use RAISE(IGNORE), in which
      // case SQLite reports success but persists no row. Treat
      // every result other than exactly one affected row as a
      // hard, fixed-message failure so the owning transaction
      // rolls back any earlier lifecycle writes. Some node:sqlite
      // configurations expose RunResult.changes as bigint.
      if (result.changes !== 1 && result.changes !== 1n) {
        throw new BountyPilotError(MESSAGE_WRITE_FAILED, CODE_WRITE_FAILED);
      }
    } catch (err) {
      if (isUniqueSequenceConflict(err)) {
        throw new BountyPilotError(
          "workflow event sequence conflict",
          CODE_SEQUENCE_CONFLICT,
        );
      }
      throw err;
    }

    return event;
  }

  list(jobId: string, limit = 100): WorkflowEventRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM workflow_events WHERE job_id = ? ORDER BY sequence DESC LIMIT ?")
      .all(jobId, limit) as unknown as WorkflowEventRow[];
    return rows.map(rowToEvent).reverse();
  }

  recent(limit = 25): WorkflowEventRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM workflow_events ORDER BY created_at DESC, sequence DESC LIMIT ?")
      .all(limit) as unknown as WorkflowEventRow[];
    return rows.map(rowToEvent);
  }

  count(jobId?: string): number {
    if (jobId) {
      const row = this.db.prepare("SELECT COUNT(*) AS count FROM workflow_events WHERE job_id = ?").get(jobId) as
        | CountRow
        | undefined;
      return Number(row?.count ?? 0);
    }
    const row = this.db.prepare("SELECT COUNT(*) AS count FROM workflow_events").get() as CountRow | undefined;
    return Number(row?.count ?? 0);
  }

  private nextSequence(jobId: string): number {
    const row = this.db
      .prepare("SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence FROM workflow_events WHERE job_id = ?")
      .get(jobId) as SequenceRow | undefined;
    return Number(row?.sequence ?? 1);
  }
}

interface WorkflowEventRow {
  id: string;
  job_id: string;
  sequence: number;
  phase: string;
  status: WorkflowEventStatus;
  message: string;
  metadata_json?: string | null;
  created_at: string;
}

interface SequenceRow {
  sequence: number;
}

interface CountRow {
  count: number;
}

function rowToEvent(row: WorkflowEventRow): WorkflowEventRecord {
  return {
    id: row.id,
    jobId: row.job_id,
    sequence: row.sequence,
    phase: row.phase,
    status: row.status,
    message: maskSecrets(row.message),
    metadata: maskParsedMetadata(parseMetadata(row.metadata_json)),
    createdAt: row.created_at,
  };
}

function parseMetadata(value?: string | null): Record<string, unknown> | undefined {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function maskParsedMetadata(value: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  return value ? maskSecretsDeep(value) : undefined;
}

/**
 * Exact diagnostic match for the SQLite composite-index UNIQUE
 * violation on workflow_events.(job_id, sequence). Accepts
 * only an Error-like object whose trimmed message matches
 *   "UNIQUE constraint failed: workflow_events.job_id, workflow_events.sequence"
 * (case-insensitive, with optional whitespace around the comma
 * between the two column names). This exact table + both-column
 * shape is sufficient to exclude unrelated NOT NULL, CHECK,
 * PRIMARY KEY, and other UNIQUE-index errors: a NOT NULL
 * violation on workflow_events.status, a UNIQUE violation on a
 * different column, or a constraint failure on a different
 * table all produce a different message and will not match.
 * The check does not depend on the SQLite `code` / `errno`
 * fields because node:sqlite may surface the error as a plain
 * Error with only a `message`.
 */
function isUniqueSequenceConflict(err: unknown): boolean {
  if (!err || typeof err !== "object") {
    return false;
  }
  const message = typeof (err as { message?: unknown }).message === "string"
    ? ((err as { message: string }).message).trim()
    : "";
  // Exact composite-index UNIQUE-violation message, case
  // insensitive, with optional whitespace around the comma
  // between the two column names.
  return /^UNIQUE constraint failed:\s*workflow_events\.job_id\s*,\s*workflow_events\.sequence\s*$/i.test(message);
}
