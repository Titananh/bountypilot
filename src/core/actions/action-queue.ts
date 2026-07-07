import type { BountyDatabase } from "../../stores/db/database.js";
import type { RiskLevel } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";
import { createId } from "../../utils/ids.js";
import { nowIso } from "../../utils/time.js";

export type ActionStatus = "pending" | "approved" | "executed" | "blocked" | "failed";
type StoredActionStatus = ActionStatus | "planned";

export interface ActionQueueSummary {
  total: number;
  pending: number;
  approved: number;
  executed: number;
  blocked: number;
  failed: number;
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
}

export class ActionQueue {
  constructor(private readonly db: BountyDatabase) {}

  enqueue(input: EnqueueActionInput): ActionRecord {
    const status = input.status ?? (input.requiresApproval ? "pending" : "approved");
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
      createdAt: nowIso(),
    };

    this.db
      .prepare(
        `INSERT INTO actions (
          id, job_id, adapter, action_type, target, risk_level, requires_approval, status, metadata_json, created_at, executed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      );

    return action;
  }

  markExecuted(id: string): ActionRecord {
    const action = this.requireAction(id);
    if (action.status === "executed") {
      return action;
    }
    assertTransition(action, "executed");
    const executedAt = nowIso();
    this.db
      .prepare("UPDATE actions SET status = ?, executed_at = ? WHERE id = ?")
      .run("executed", executedAt, id);
    return { ...action, status: "executed", executedAt };
  }

  approve(id: string): ActionRecord {
    const action = this.requireAction(id);
    if (action.status === "approved") {
      return action;
    }
    assertTransition(action, "approved");
    this.db.prepare("UPDATE actions SET status = ? WHERE id = ?").run("approved", id);
    return { ...action, status: "approved" };
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
    const row = this.db.prepare("SELECT * FROM actions WHERE id = ?").get(id) as unknown as ActionRow | undefined;
    return row ? rowToAction(row) : undefined;
  }

  list(jobId?: string): ActionRecord[] {
    const statement = jobId
      ? this.db.prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY created_at DESC")
      : this.db.prepare("SELECT * FROM actions ORDER BY created_at DESC");
    const rows = (jobId ? statement.all(jobId) : statement.all()) as unknown as ActionRow[];
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
      executed: 0,
      blocked: 0,
      failed: 0,
    };
    for (const action of this.list(jobId)) {
      summary.total += 1;
      summary[action.status] += 1;
    }
    return summary;
  }

  private requireAction(id: string): ActionRecord {
    const action = this.get(id);
    if (!action) {
      throw new BountyPilotError(`Action not found: ${id}`, "ACTION_NOT_FOUND");
    }
    return action;
  }
}

interface ActionRow {
  id: string;
  job_id?: string | null;
  adapter: string;
  action_type: string;
  target?: string | null;
  risk_level: RiskLevel;
  requires_approval: 0 | 1;
  status: StoredActionStatus;
  metadata_json?: string | null;
  created_at: string;
  executed_at?: string | null;
}

function rowToAction(row: ActionRow): ActionRecord {
  return {
    id: row.id,
    jobId: row.job_id ?? undefined,
    adapter: row.adapter,
    actionType: row.action_type,
    target: row.target ?? undefined,
    riskLevel: row.risk_level,
    requiresApproval: row.requires_approval === 1,
    status: normalizeStatus(row.status),
    metadata: parseMetadata(row.metadata_json),
    createdAt: row.created_at,
    executedAt: row.executed_at ?? undefined,
  };
}

function parseMetadata(value?: string | null): Record<string, unknown> | undefined {
  if (!value) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function normalizeStatus(status: StoredActionStatus): ActionStatus {
  return status === "planned" ? "pending" : status;
}

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
