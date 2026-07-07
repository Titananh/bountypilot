import type { BountyDatabase } from "../../stores/db/database.js";
import { createId } from "../../utils/ids.js";
import { maskSecrets, maskSecretsDeep } from "../../utils/secrets.js";
import { nowIso } from "../../utils/time.js";

export type WorkflowEventStatus = "running" | "completed" | "failed" | "skipped" | "planned" | "blocked";

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

export class WorkflowEventStore {
  constructor(private readonly db: BountyDatabase) {}

  record(input: WorkflowEventInput): WorkflowEventRecord {
    const event: WorkflowEventRecord = {
      id: createId("event"),
      jobId: input.jobId,
      sequence: this.nextSequence(input.jobId),
      phase: input.phase,
      status: input.status,
      message: maskSecrets(input.message),
      metadata: input.metadata ? maskSecretsDeep(input.metadata) : undefined,
      createdAt: nowIso(),
    };
    this.db
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
