import type { BountyDatabase } from "./db/database.js";
import type { NormalizedFinding } from "../types.js";
import { createId } from "../utils/ids.js";
import { nowIso } from "../utils/time.js";

export type NewFindingInput = Omit<NormalizedFinding, "id" | "createdAt" | "updatedAt"> & {
  id?: string;
  createdAt?: string;
  updatedAt?: string;
};

export class FindingStore {
  constructor(private readonly db: BountyDatabase) {}

  create(input: NewFindingInput): NormalizedFinding {
    const now = nowIso();
    const finding: NormalizedFinding = {
      id: input.id ?? createId("finding"),
      title: input.title,
      asset: input.asset,
      url: input.url,
      category: input.category,
      severityEstimate: input.severityEstimate,
      confidence: input.confidence,
      status: input.status,
      evidencePaths: input.evidencePaths,
      rawOutputPath: input.rawOutputPath,
      remediation: input.remediation,
      duplicateRisk: input.duplicateRisk,
      reportabilityScore: input.reportabilityScore,
      createdAt: input.createdAt ?? now,
      updatedAt: input.updatedAt ?? now,
    };

    this.db
      .prepare(
        `INSERT INTO findings (
          id, title, asset, url, category, severity_estimate, confidence, status,
          evidence_paths, raw_output_path, remediation, duplicate_risk, reportability_score, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        finding.id,
        finding.title,
        finding.asset,
        finding.url,
        finding.category,
        finding.severityEstimate,
        finding.confidence,
        finding.status,
        JSON.stringify(finding.evidencePaths),
        finding.rawOutputPath ?? null,
        finding.remediation ?? null,
        finding.duplicateRisk,
        finding.reportabilityScore,
        finding.createdAt,
        finding.updatedAt,
      );

    return finding;
  }

  list(): NormalizedFinding[] {
    const rows = this.db.prepare("SELECT * FROM findings ORDER BY created_at DESC").all() as unknown as FindingRow[];
    return rows.map(rowToFinding);
  }

  get(id: string): NormalizedFinding | undefined {
    const row = this.db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as FindingRow | undefined;
    return row ? rowToFinding(row) : undefined;
  }

  updateStatus(id: string, status: NormalizedFinding["status"]): void {
    this.db
      .prepare("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?")
      .run(status, nowIso(), id);
  }

  linkEvidencePath(id: string, evidencePath: string): NormalizedFinding {
    const finding = this.get(id);
    if (!finding) {
      throw new Error(`Finding not found: ${id}`);
    }
    const evidencePaths = [...new Set([...finding.evidencePaths, evidencePath].filter((item) => item.length > 0))];
    const updatedAt = nowIso();
    this.db
      .prepare("UPDATE findings SET evidence_paths = ?, updated_at = ? WHERE id = ?")
      .run(JSON.stringify(evidencePaths), updatedAt, id);
    return { ...finding, evidencePaths, updatedAt };
  }
}

interface FindingRow {
  id: string;
  title: string;
  asset: string;
  url: string;
  category: string;
  severity_estimate: NormalizedFinding["severityEstimate"];
  confidence: NormalizedFinding["confidence"];
  status: NormalizedFinding["status"];
  evidence_paths: string;
  raw_output_path?: string | null;
  remediation?: string | null;
  duplicate_risk: NormalizedFinding["duplicateRisk"];
  reportability_score: number;
  created_at: string;
  updated_at: string;
}

function rowToFinding(row: FindingRow): NormalizedFinding {
  return {
    id: row.id,
    title: row.title,
    asset: row.asset,
    url: row.url,
    category: row.category,
    severityEstimate: row.severity_estimate,
    confidence: row.confidence,
    status: row.status,
    evidencePaths: parseEvidencePaths(row.evidence_paths),
    rawOutputPath: row.raw_output_path ?? undefined,
    remediation: row.remediation ?? undefined,
    duplicateRisk: row.duplicate_risk,
    reportabilityScore: row.reportability_score,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function parseEvidencePaths(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
  } catch {
    return [];
  }
}
