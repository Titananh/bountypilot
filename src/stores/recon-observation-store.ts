import { createHash } from "node:crypto";
import type { BountyDatabase } from "./db/database.js";
import type { Confidence, ReconObservation, ReconObservationKind, RiskLevel } from "../types.js";
import { createId } from "../utils/ids.js";
import { nowIso } from "../utils/time.js";

export interface NewReconObservationInput {
  jobId?: string;
  kind: ReconObservationKind;
  value: string;
  normalizedValue?: string;
  sourceAdapter: string;
  sourceUrl?: string;
  scopeAllowed: boolean;
  confidence: Confidence;
  riskHint?: RiskLevel;
  metadata?: Record<string, unknown>;
  fingerprint?: string;
}

export interface ReconObservationListOptions {
  jobId?: string;
  kind?: ReconObservationKind;
  sourceAdapter?: string;
  scopeAllowed?: boolean;
  limit?: number;
}

export class ReconObservationStore {
  constructor(private readonly db: BountyDatabase) {}

  upsert(input: NewReconObservationInput): ReconObservation {
    const now = nowIso();
    const normalizedValue = input.normalizedValue ?? normalizeObservationValue(input.kind, input.value);
    const fingerprint = input.fingerprint ?? observationFingerprint({
      kind: input.kind,
      normalizedValue,
      sourceAdapter: input.sourceAdapter,
      sourceUrl: input.sourceUrl,
    });
    const id = createId("recon");
    const metadata = input.metadata ?? {};

    this.db
      .prepare(
        `INSERT INTO recon_observations (
          id, job_id, kind, value, normalized_value, source_adapter, source_url,
          scope_allowed, confidence, risk_hint, metadata_json, fingerprint, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
          job_id = COALESCE(excluded.job_id, recon_observations.job_id),
          value = excluded.value,
          source_url = COALESCE(excluded.source_url, recon_observations.source_url),
          scope_allowed = excluded.scope_allowed,
          confidence = excluded.confidence,
          risk_hint = excluded.risk_hint,
          metadata_json = excluded.metadata_json,
          last_seen_at = excluded.last_seen_at`,
      )
      .run(
        id,
        input.jobId ?? null,
        input.kind,
        input.value,
        normalizedValue,
        input.sourceAdapter,
        input.sourceUrl ?? null,
        input.scopeAllowed ? 1 : 0,
        input.confidence,
        input.riskHint ?? null,
        JSON.stringify(metadata),
        fingerprint,
        now,
        now,
      );

    return this.getByFingerprint(fingerprint) ?? {
      id,
      jobId: input.jobId,
      kind: input.kind,
      value: input.value,
      normalizedValue,
      sourceAdapter: input.sourceAdapter,
      sourceUrl: input.sourceUrl,
      scopeAllowed: input.scopeAllowed,
      confidence: input.confidence,
      riskHint: input.riskHint,
      metadata,
      fingerprint,
      firstSeenAt: now,
      lastSeenAt: now,
    };
  }

  list(options: ReconObservationListOptions = {}): ReconObservation[] {
    const clauses: string[] = [];
    const values: Array<string | number> = [];
    if (options.jobId) {
      clauses.push("job_id = ?");
      values.push(options.jobId);
    }
    if (options.kind) {
      clauses.push("kind = ?");
      values.push(options.kind);
    }
    if (options.sourceAdapter) {
      clauses.push("source_adapter = ?");
      values.push(options.sourceAdapter);
    }
    if (options.scopeAllowed !== undefined) {
      clauses.push("scope_allowed = ?");
      values.push(options.scopeAllowed ? 1 : 0);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    const limit = Math.max(1, Math.min(Math.floor(options.limit ?? 500), 5000));
    const rows = this.db
      .prepare(`SELECT * FROM recon_observations ${where} ORDER BY last_seen_at DESC LIMIT ?`)
      .all(...values, limit) as unknown as ReconObservationRow[];
    return rows.map(rowToObservation);
  }

  getByFingerprint(fingerprint: string): ReconObservation | undefined {
    const row = this.db
      .prepare("SELECT * FROM recon_observations WHERE fingerprint = ?")
      .get(fingerprint) as unknown as ReconObservationRow | undefined;
    return row ? rowToObservation(row) : undefined;
  }

  get(idOrFingerprint: string): ReconObservation | undefined {
    const row = this.db
      .prepare("SELECT * FROM recon_observations WHERE id = ? OR fingerprint = ?")
      .get(idOrFingerprint, idOrFingerprint) as unknown as ReconObservationRow | undefined;
    return row ? rowToObservation(row) : undefined;
  }
}

interface ReconObservationRow {
  id: string;
  job_id?: string | null;
  kind: ReconObservationKind;
  value: string;
  normalized_value: string;
  source_adapter: string;
  source_url?: string | null;
  scope_allowed: 0 | 1;
  confidence: Confidence;
  risk_hint?: RiskLevel | null;
  metadata_json: string;
  fingerprint: string;
  first_seen_at: string;
  last_seen_at: string;
}

function rowToObservation(row: ReconObservationRow): ReconObservation {
  return {
    id: row.id,
    jobId: row.job_id ?? undefined,
    kind: row.kind,
    value: row.value,
    normalizedValue: row.normalized_value,
    sourceAdapter: row.source_adapter,
    sourceUrl: row.source_url ?? undefined,
    scopeAllowed: row.scope_allowed === 1,
    confidence: row.confidence,
    riskHint: row.risk_hint ?? undefined,
    metadata: parseMetadata(row.metadata_json),
    fingerprint: row.fingerprint,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
  };
}

export function normalizeObservationValue(kind: ReconObservationKind, value: string): string {
  const trimmed = value.trim();
  if (kind === "host") {
    return trimmed.toLowerCase().replace(/^\*\./, "");
  }
  try {
    const url = new URL(trimmed.startsWith("//") ? `https:${trimmed}` : trimmed);
    url.hash = "";
    url.hostname = url.hostname.toLowerCase();
    url.searchParams.sort();
    return url.toString();
  } catch {
    return trimmed.toLowerCase();
  }
}

export function observationFingerprint(input: {
  kind: ReconObservationKind;
  normalizedValue: string;
  sourceAdapter: string;
  sourceUrl?: string;
}): string {
  return createHash("sha256")
    .update([input.kind, input.normalizedValue, input.sourceAdapter, input.sourceUrl ?? ""].join("\n"))
    .digest("hex");
}

function parseMetadata(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}
