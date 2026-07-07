import type { BountyDatabase } from "../../stores/db/database.js";
import { createId } from "../../utils/ids.js";
import { maskSecrets } from "../../utils/secrets.js";
import { nowIso } from "../../utils/time.js";

export type ActionReviewDecision = "approved" | "blocked";

export interface ActionReviewRecord {
  id: string;
  actionId: string;
  jobId?: string;
  decision: ActionReviewDecision;
  note?: string;
  createdAt: string;
}

export interface NewActionReviewInput {
  actionId: string;
  jobId?: string;
  decision: ActionReviewDecision;
  note?: string;
}

export class ActionReviewStore {
  constructor(private readonly db: BountyDatabase) {}

  record(input: NewActionReviewInput): ActionReviewRecord {
    const review: ActionReviewRecord = {
      id: createId("review"),
      actionId: input.actionId,
      jobId: input.jobId,
      decision: input.decision,
      note: input.note ? maskSecrets(input.note.trim()) || undefined : undefined,
      createdAt: nowIso(),
    };
    this.db
      .prepare(
        `INSERT INTO action_reviews (
          id, action_id, job_id, decision, note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(review.id, review.actionId, review.jobId ?? null, review.decision, review.note ?? null, review.createdAt);
    return review;
  }

  listForAction(actionId: string): ActionReviewRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM action_reviews WHERE action_id = ? ORDER BY created_at ASC")
      .all(actionId) as unknown as ActionReviewRow[];
    return rows.map(rowToReview);
  }

  listForJob(jobId: string): ActionReviewRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM action_reviews WHERE job_id = ? ORDER BY created_at ASC")
      .all(jobId) as unknown as ActionReviewRow[];
    return rows.map(rowToReview);
  }

  list(limit = 100): ActionReviewRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM action_reviews ORDER BY created_at DESC LIMIT ?")
      .all(limit) as unknown as ActionReviewRow[];
    return rows.map(rowToReview);
  }
}

interface ActionReviewRow {
  id: string;
  action_id: string;
  job_id?: string | null;
  decision: ActionReviewDecision;
  note?: string | null;
  created_at: string;
}

function rowToReview(row: ActionReviewRow): ActionReviewRecord {
  return {
    id: row.id,
    actionId: row.action_id,
    jobId: row.job_id ?? undefined,
    decision: row.decision,
    note: row.note ? maskSecrets(row.note) : undefined,
    createdAt: row.created_at,
  };
}
