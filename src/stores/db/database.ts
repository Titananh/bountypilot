import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export type BountyDatabase = DatabaseSync;

export function openBountyDatabase(dbFile: string): BountyDatabase {
  mkdirSync(path.dirname(dbFile), { recursive: true });
  const db = new DatabaseSync(dbFile);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA foreign_keys = ON;
  `);
  ensureSchema(db);
  return db;
}

export function ensureSchema(db: BountyDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      asset TEXT NOT NULL,
      url TEXT NOT NULL,
      category TEXT NOT NULL,
      severity_estimate TEXT NOT NULL,
      confidence TEXT NOT NULL,
      status TEXT NOT NULL,
      evidence_paths TEXT NOT NULL,
      raw_output_path TEXT,
      remediation TEXT,
      duplicate_risk TEXT NOT NULL,
      reportability_score INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence_artifacts (
      id TEXT PRIMARY KEY,
      finding_id TEXT,
      job_id TEXT,
      adapter_name TEXT NOT NULL,
      kind TEXT NOT NULL,
      source_url TEXT,
      path TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS finding_candidates (
      id TEXT PRIMARY KEY,
      job_id TEXT,
      title TEXT NOT NULL,
      asset TEXT NOT NULL,
      url TEXT NOT NULL,
      category TEXT NOT NULL,
      severity_estimate TEXT NOT NULL,
      confidence TEXT NOT NULL,
      status TEXT NOT NULL,
      evidence_ids TEXT NOT NULL,
      observation_ids TEXT NOT NULL,
      finding_id TEXT,
      false_positive_risk TEXT NOT NULL,
      duplicate_risk TEXT NOT NULL,
      reportability TEXT NOT NULL,
      reasoning_summary TEXT NOT NULL,
      next_manual_steps TEXT NOT NULL,
      fingerprint TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_finding_candidates_job_id
      ON finding_candidates (job_id, updated_at);

    CREATE INDEX IF NOT EXISTS idx_finding_candidates_status
      ON finding_candidates (status, updated_at);

    CREATE INDEX IF NOT EXISTS idx_finding_candidates_reportability
      ON finding_candidates (reportability, updated_at);

    CREATE INDEX IF NOT EXISTS idx_finding_candidates_finding_id
      ON finding_candidates (finding_id);

    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      target TEXT,
      mode TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS actions (
      id TEXT PRIMARY KEY,
      job_id TEXT,
      adapter TEXT NOT NULL,
      action_type TEXT NOT NULL,
      target TEXT,
      risk_level TEXT NOT NULL,
      requires_approval INTEGER NOT NULL,
      status TEXT NOT NULL,
      metadata_json TEXT,
      created_at TEXT NOT NULL,
      executed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS recon_observations (
      id TEXT PRIMARY KEY,
      job_id TEXT,
      kind TEXT NOT NULL,
      value TEXT NOT NULL,
      normalized_value TEXT NOT NULL,
      source_adapter TEXT NOT NULL,
      source_url TEXT,
      scope_allowed INTEGER NOT NULL,
      confidence TEXT NOT NULL,
      risk_hint TEXT,
      metadata_json TEXT NOT NULL,
      fingerprint TEXT NOT NULL UNIQUE,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_recon_observations_job_id
      ON recon_observations (job_id, last_seen_at);

    CREATE INDEX IF NOT EXISTS idx_recon_observations_kind
      ON recon_observations (kind, last_seen_at);

    CREATE INDEX IF NOT EXISTS idx_recon_observations_source_adapter
      ON recon_observations (source_adapter, last_seen_at);

    CREATE TABLE IF NOT EXISTS action_reviews (
      id TEXT PRIMARY KEY,
      action_id TEXT NOT NULL,
      job_id TEXT,
      decision TEXT NOT NULL,
      note TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_action_reviews_action_id
      ON action_reviews (action_id, created_at);

    CREATE INDEX IF NOT EXISTS idx_action_reviews_job_id
      ON action_reviews (job_id, created_at);

    CREATE TABLE IF NOT EXISTS crawl_pages (
      url TEXT PRIMARY KEY,
      title TEXT,
      status INTEGER,
      content_hash TEXT,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS crawl_edges (
      id TEXT PRIMARY KEY,
      from_url TEXT NOT NULL,
      to_url TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS workflow_events (
      id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      phase TEXT NOT NULL,
      status TEXT NOT NULL,
      message TEXT NOT NULL,
      metadata_json TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_workflow_events_job_sequence
      ON workflow_events (job_id, sequence);

    CREATE INDEX IF NOT EXISTS idx_workflow_events_created_at
      ON workflow_events (created_at);
  `);
  ensureColumn(db, "actions", "metadata_json", "TEXT");
}

function ensureColumn(db: BountyDatabase, table: string, column: string, definition: string): void {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (rows.some((row) => row.name === column)) {
    return;
  }
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
