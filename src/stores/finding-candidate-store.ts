import { createHash } from "node:crypto";
import type { BountyDatabase } from "./db/database.js";
import type {
  Confidence,
  DuplicateRisk,
  FindingCandidate,
  FindingCandidateReportability,
  FindingCandidateStatus,
  SeverityEstimate,
} from "../types.js";
import { createId } from "../utils/ids.js";
import { nowIso } from "../utils/time.js";

export interface NewFindingCandidateInput {
  id?: string;
  jobId?: string;
  title: string;
  asset: string;
  url: string;
  category: string;
  severityEstimate: SeverityEstimate;
  confidence: Confidence;
  status: FindingCandidateStatus;
  evidenceIds?: string[];
  observationIds?: string[];
  findingId?: string;
  falsePositiveRisk: DuplicateRisk;
  duplicateRisk: DuplicateRisk;
  reportability: FindingCandidateReportability;
  reasoningSummary: string;
  nextManualSteps?: string[];
  fingerprint?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface FindingCandidateListOptions {
  jobId?: string;
  status?: FindingCandidateStatus;
  reportability?: FindingCandidateReportability;
  findingId?: string;
  limit?: number;
}

export class FindingCandidateStore {
  constructor(private readonly db: BountyDatabase) {}

  create(input: NewFindingCandidateInput): FindingCandidate {
    const now = nowIso();
    const fingerprint = input.fingerprint ?? candidateFingerprint(input);
    const candidate: FindingCandidate = {
      id: input.id ?? createCandidateId(),
      jobId: input.jobId,
      title: input.title,
      asset: input.asset,
      url: input.url,
      category: input.category,
      severityEstimate: input.severityEstimate,
      confidence: input.confidence,
      status: input.status,
      evidenceIds: uniqueStrings(input.evidenceIds ?? []),
      observationIds: uniqueStrings(input.observationIds ?? []),
      findingId: input.findingId,
      falsePositiveRisk: input.falsePositiveRisk,
      duplicateRisk: input.duplicateRisk,
      reportability: input.reportability,
      reasoningSummary: input.reasoningSummary,
      nextManualSteps: uniqueStrings(input.nextManualSteps ?? []),
      fingerprint,
      createdAt: input.createdAt ?? now,
      updatedAt: input.updatedAt ?? now,
    };

    this.db
      .prepare(
        `INSERT INTO finding_candidates (
          id, job_id, title, asset, url, category, severity_estimate, confidence, status,
          evidence_ids, observation_ids, finding_id, false_positive_risk, duplicate_risk,
          reportability, reasoning_summary, next_manual_steps, fingerprint, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
          job_id = COALESCE(excluded.job_id, finding_candidates.job_id),
          title = excluded.title,
          asset = excluded.asset,
          url = excluded.url,
          category = excluded.category,
          severity_estimate = excluded.severity_estimate,
          confidence = excluded.confidence,
          status = excluded.status,
          evidence_ids = excluded.evidence_ids,
          observation_ids = excluded.observation_ids,
          finding_id = COALESCE(excluded.finding_id, finding_candidates.finding_id),
          false_positive_risk = excluded.false_positive_risk,
          duplicate_risk = excluded.duplicate_risk,
          reportability = excluded.reportability,
          reasoning_summary = excluded.reasoning_summary,
          next_manual_steps = excluded.next_manual_steps,
          updated_at = excluded.updated_at`,
      )
      .run(
        candidate.id,
        candidate.jobId ?? null,
        candidate.title,
        candidate.asset,
        candidate.url,
        candidate.category,
        candidate.severityEstimate,
        candidate.confidence,
        candidate.status,
        JSON.stringify(candidate.evidenceIds),
        JSON.stringify(candidate.observationIds),
        candidate.findingId ?? null,
        candidate.falsePositiveRisk,
        candidate.duplicateRisk,
        candidate.reportability,
        candidate.reasoningSummary,
        JSON.stringify(candidate.nextManualSteps),
        candidate.fingerprint,
        candidate.createdAt,
        candidate.updatedAt,
      );

    return this.getByFingerprint(fingerprint) ?? candidate;
  }

  list(options: FindingCandidateListOptions = {}): FindingCandidate[] {
    const clauses: string[] = [];
    const values: Array<string | number> = [];
    if (options.jobId) {
      clauses.push("job_id = ?");
      values.push(options.jobId);
    }
    if (options.status) {
      clauses.push("status = ?");
      values.push(options.status);
    }
    if (options.reportability) {
      clauses.push("reportability = ?");
      values.push(options.reportability);
    }
    if (options.findingId) {
      clauses.push("finding_id = ?");
      values.push(options.findingId);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    const limit = Math.max(1, Math.min(Math.floor(options.limit ?? 500), 5000));
    const rows = this.db
      .prepare(`SELECT * FROM finding_candidates ${where} ORDER BY updated_at DESC LIMIT ?`)
      .all(...values, limit) as unknown as FindingCandidateRow[];
    return rows.map(rowToCandidate);
  }

  get(id: string): FindingCandidate | undefined {
    const row = this.db.prepare("SELECT * FROM finding_candidates WHERE id = ?").get(id) as FindingCandidateRow | undefined;
    return row ? rowToCandidate(row) : undefined;
  }

  getByFingerprint(fingerprint: string): FindingCandidate | undefined {
    const row = this.db
      .prepare("SELECT * FROM finding_candidates WHERE fingerprint = ?")
      .get(fingerprint) as FindingCandidateRow | undefined;
    return row ? rowToCandidate(row) : undefined;
  }

  updateStatus(
    id: string,
    status: FindingCandidateStatus,
    reportability?: FindingCandidateReportability,
  ): FindingCandidate | undefined {
    const existing = this.get(id);
    if (!existing) return undefined;
    const updatedAt = nowIso();
    this.db
      .prepare("UPDATE finding_candidates SET status = ?, reportability = ?, updated_at = ? WHERE id = ?")
      .run(status, reportability ?? existing.reportability, updatedAt, id);
    return this.get(id);
  }

  linkFinding(id: string, findingId: string): FindingCandidate | undefined {
    const existing = this.get(id);
    if (!existing) return undefined;
    const updatedAt = nowIso();
    this.db
      .prepare("UPDATE finding_candidates SET finding_id = ?, status = ?, updated_at = ? WHERE id = ?")
      .run(findingId, "promoted", updatedAt, id);
    return this.get(id);
  }

  linkEvidence(id: string, evidenceId: string): FindingCandidate | undefined {
    const existing = this.get(id);
    if (!existing) return undefined;
    const evidenceIds = uniqueStrings([...existing.evidenceIds, evidenceId]);
    const updatedAt = nowIso();
    this.db
      .prepare("UPDATE finding_candidates SET evidence_ids = ?, updated_at = ? WHERE id = ?")
      .run(JSON.stringify(evidenceIds), updatedAt, id);
    return this.get(id);
  }

  updateReadiness(
    id: string,
    input: Pick<FindingCandidate, "status" | "reportability" | "reasoningSummary" | "nextManualSteps" | "falsePositiveRisk" | "duplicateRisk">,
  ): FindingCandidate | undefined {
    if (!this.get(id)) return undefined;
    const updatedAt = nowIso();
    this.db
      .prepare(
        `UPDATE finding_candidates
         SET status = ?, reportability = ?, false_positive_risk = ?, duplicate_risk = ?,
             reasoning_summary = ?, next_manual_steps = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        input.status,
        input.reportability,
        input.falsePositiveRisk,
        input.duplicateRisk,
        input.reasoningSummary,
        JSON.stringify(uniqueStrings(input.nextManualSteps)),
        updatedAt,
        id,
      );
    return this.get(id);
  }
}

interface FindingCandidateRow {
  id: string;
  job_id?: string | null;
  title: string;
  asset: string;
  url: string;
  category: string;
  severity_estimate: SeverityEstimate;
  confidence: Confidence;
  status: FindingCandidateStatus;
  evidence_ids: string;
  observation_ids: string;
  finding_id?: string | null;
  false_positive_risk: DuplicateRisk;
  duplicate_risk: DuplicateRisk;
  reportability: FindingCandidateReportability;
  reasoning_summary: string;
  next_manual_steps: string;
  fingerprint: string;
  created_at: string;
  updated_at: string;
}

function rowToCandidate(row: FindingCandidateRow): FindingCandidate {
  return {
    id: row.id,
    jobId: row.job_id ?? undefined,
    title: row.title,
    asset: row.asset,
    url: row.url,
    category: row.category,
    severityEstimate: row.severity_estimate,
    confidence: row.confidence,
    status: row.status,
    evidenceIds: parseStringArray(row.evidence_ids),
    observationIds: parseStringArray(row.observation_ids),
    findingId: row.finding_id ?? undefined,
    falsePositiveRisk: row.false_positive_risk,
    duplicateRisk: row.duplicate_risk,
    reportability: row.reportability,
    reasoningSummary: row.reasoning_summary,
    nextManualSteps: parseStringArray(row.next_manual_steps),
    fingerprint: row.fingerprint,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function candidateFingerprint(input: Pick<NewFindingCandidateInput, "jobId" | "title" | "asset" | "url" | "category">): string {
  return createHash("sha256")
    .update([input.jobId ?? "", input.url, input.asset, input.category, input.title].map((item) => item.trim().toLowerCase()).join("\n"))
    .digest("hex");
}

function parseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? uniqueStrings(parsed.filter((item): item is string => typeof item === "string" && item.length > 0)) : [];
  } catch {
    return [];
  }
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function createCandidateId(): string {
  return createId("cand").replace(/^cand-/, "cand_");
}
