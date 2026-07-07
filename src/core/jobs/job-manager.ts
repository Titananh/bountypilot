import type { BountyDatabase } from "../../stores/db/database.js";
import type { ExecutionMode } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";
import { createId } from "../../utils/ids.js";
import { nowIso } from "../../utils/time.js";

export type JobStatus = "queued" | "running" | "paused" | "failed" | "completed";

export interface JobRecord {
  id: string;
  type: string;
  target?: string;
  mode: ExecutionMode;
  status: JobStatus;
  createdAt: string;
  updatedAt: string;
}

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
      createdAt: now,
      updatedAt: now,
    };
    this.db
      .prepare("INSERT INTO jobs (id, type, target, mode, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(job.id, job.type, job.target ?? null, job.mode, job.status, job.createdAt, job.updatedAt);
    return job;
  }

  updateStatus(id: string, status: JobStatus): JobRecord {
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
    const row = this.db.prepare("SELECT * FROM jobs WHERE id = ?").get(id) as unknown as JobRow | undefined;
    return row ? rowToJob(row) : undefined;
  }

  list(limit = 50): JobRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?")
      .all(limit) as unknown as JobRow[];
    return rows.map(rowToJob);
  }

  private requireJob(id: string): JobRecord {
    const job = this.get(id);
    if (!job) {
      throw new BountyPilotError(`Job not found: ${id}`, "JOB_NOT_FOUND");
    }
    return job;
  }
}

interface JobRow {
  id: string;
  type: string;
  target?: string | null;
  mode: ExecutionMode;
  status: JobStatus;
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
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
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
