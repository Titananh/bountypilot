// P0.2 Packet 1 — db-migrations.test.ts
// Intentionally RED until runMigrations / CURRENT_SCHEMA_VERSION ship in
// src/stores/db/database.ts. Touches only local temp SQLite files.
//
// PART 1 (this file) proves three contracts from
// docs/p0.2-action-approval-execution-packets.md §7 Packet 1:
//   1. fresh DB reaches CURRENT_SCHEMA_VERSION with exact v2 schema/PRAGMAs
//      and zero migration audit events;
//   2. unversioned legacy rows upgrade without loss: planned and incomplete
//      approved demote to pending, no fake review is fabricated, executed/
//      blocked/failed stay terminal, stale execution/lease/dispatch/finish/
//      outcome fields clear on demoted actions, updated_at is backfilled;
//   3. duplicate workflow_events (job_id, sequence) is deterministically
//      resequenced 1..N by (created_at, id); sequences for an unaffected job
//      stay byte-for-byte identical; a follow-up duplicate insert is rejected.
//
// PART 2 (TODO at the bottom) covers the remaining Packet 1 contracts.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { Worker } from "node:worker_threads";
import * as ts from "typescript";
import type { BountyDatabase } from "../src/stores/db/database.js";
import * as dbApi from "../src/stores/db/database.js";
import { BountyPilotError } from "../src/utils/errors.js";

// Local helper: assert that a sync call throws a BountyPilotError with the
// expected code, and return the error for further inspection. Used by
// contract-8 fail-closed checks.
//
// FIX 1: If the callback unexpectedly returns a DatabaseSync-like object,
// close that returned handle before failing. This prevents Windows EPERM/temp-dir
// leaks while APIs are intentionally missing in RED state.
function expectBountyError(fn: () => unknown, code: string): BountyPilotError {
  let captured: unknown;
  let returnedHandle: unknown;
  try {
    returnedHandle = fn();
  } catch (err) {
    captured = err;
  }
  // If fn() unexpectedly returned a DatabaseSync-like object, close it before failing.
  if (returnedHandle && typeof returnedHandle === "object" && "close" in returnedHandle) {
    try {
      (returnedHandle as { close: () => void }).close();
    } catch {
      /* best-effort close */
    }
  }
  expect(captured, "expected BountyPilotError to be thrown").toBeInstanceOf(BountyPilotError);
  const err = captured as BountyPilotError;
  expect(err.code).toBe(code);
  return err;
}

const openBountyDatabase = (dbApi as any).openBountyDatabase as (dbFile: string) => BountyDatabase;
const runMigrations = (dbApi as any).runMigrations as (
  db: BountyDatabase,
  opts?: { faultInjector?: (checkpoint: string) => void },
) => void;
const CURRENT_SCHEMA_VERSION = (dbApi as any).CURRENT_SCHEMA_VERSION as number;

// --- temp + cleanup helpers ---------------------------------------------

function makeTempDir(): string {
  return mkdtempSync(path.join(tmpdir(), "bountypilot-mig-"));
}

function cleanupDb(dbFile: string): void {
  for (const suffix of ["", "-wal", "-shm", "-journal"]) {
    const p = dbFile + suffix;
    if (existsSync(p)) {
      try {
        unlinkSync(p);
      } catch {
        /* best-effort */
      }
    }
  }
}

// --- SQLite schema/query helpers ----------------------------------------

interface ColumnRow {
  name: string;
  type: string;
  notnull: number;
  dflt_value: string | null;
  pk: number;
}

interface IndexRow {
  name: string;
  sql: string | null;
}

function columnsOf(db: BountyDatabase, table: string): ColumnRow[] {
  return db.prepare(`PRAGMA table_info(${table})`).all() as unknown as ColumnRow[];
}

function schemaObjects(db: BountyDatabase): IndexRow[] {
  return db.prepare(
    "SELECT name, sql FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY name ASC",
  ).all() as unknown as IndexRow[];
}

function userVersion(db: BountyDatabase): number {
  return (db.prepare("PRAGMA user_version").get() as { user_version: number }).user_version;
}

function journalMode(db: BountyDatabase): string {
  return (db.prepare("PRAGMA journal_mode").get() as { journal_mode: string }).journal_mode;
}

function busyTimeout(db: BountyDatabase): number {
  return (db.prepare("PRAGMA busy_timeout").get() as { timeout: number }).timeout;
}

function foreignKeys(db: BountyDatabase): number {
  return (db.prepare("PRAGMA foreign_keys").get() as { foreign_keys: number }).foreign_keys;
}

function indexSql(db: BountyDatabase, name: string): string | null {
  const row = db.prepare("SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?").get(name) as
    | { sql: string | null }
    | undefined;
  return row ? row.sql : null;
}

function actionIndexes(db: BountyDatabase): IndexRow[] {
  return db.prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'index' AND tbl_name = 'actions'").all() as unknown as IndexRow[];
}

interface IndexListRow {
  name: string;
  unique: number;
  partial: number;
  origin: string;
}

function listTableIndexes(db: BountyDatabase, table: string): IndexListRow[] {
  return db.prepare(`PRAGMA index_list(${table})`).all() as unknown as IndexListRow[];
}

function indexColumnNames(db: BountyDatabase, indexName: string): string[] {
  const rows = db.prepare(`PRAGMA index_info(${indexName})`).all() as Array<{ name: string }>;
  return rows.map((r) => r.name);
}

interface TableIndexContract {
  name: string;
  unique: number;
  partial: number;
  origin: string;
  columns: string[];
}

function tableIndexContracts(db: BountyDatabase, table: string): TableIndexContract[] {
  return listTableIndexes(db, table)
    .map((index) => ({
      name: index.name,
      unique: index.unique,
      partial: index.partial,
      origin: index.origin,
      columns: indexColumnNames(db, index.name),
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

function findUniqueIndexWithColumns(
  db: BountyDatabase,
  table: string,
  expectedCols: string[],
): { name: string; cols: string[] } | null {
  for (const meta of listTableIndexes(db, table)) {
    if (meta.unique !== 1 || meta.partial !== 0) continue;
    const cols = indexColumnNames(db, meta.name);
    if (cols.length === expectedCols.length && cols.every((c, i) => c === expectedCols[i])) {
      return { name: meta.name, cols };
    }
  }
  return null;
}

function findPartialUniqueIndexWithColumns(
  db: BountyDatabase,
  table: string,
  expectedCols: string[],
): { name: string; cols: string[] } | null {
  for (const meta of listTableIndexes(db, table)) {
    if (meta.unique !== 1 || meta.partial !== 1) continue;
    const cols = indexColumnNames(db, meta.name);
    if (cols.length === expectedCols.length && cols.every((c, i) => c === expectedCols[i])) {
      return { name: meta.name, cols };
    }
  }
  return null;
}

// --- untouched-table snapshot helpers -----------------------------------
//
// The migration must not alter any row in legacy product tables that
// have no P0.2 schema change: findings, evidence_artifacts, finding_candidates,
// recon_observations, crawl_pages, crawl_edges. These helpers capture a
// full-row deep-equal snapshot so a second open cannot silently mutate
// data, and so a corrupted migration is caught.

function fullRows(db: BountyDatabase, table: string, orderBy: string): Record<string, unknown>[] {
  return db.prepare(`SELECT * FROM ${table} ORDER BY ${orderBy} ASC`).all() as Record<string, unknown>[];
}

const LEGACY_JOB_COLUMNS = ["id", "type", "target", "mode", "status", "created_at", "updated_at"] as const;
const LEGACY_ACTION_COLUMNS = [
  "id",
  "job_id",
  "adapter",
  "action_type",
  "target",
  "risk_level",
  "requires_approval",
  "status",
  "metadata_json",
  "created_at",
  "executed_at",
] as const;
const LEGACY_REVIEW_COLUMNS = ["id", "action_id", "job_id", "decision", "note", "created_at"] as const;
const LEGACY_WORKFLOW_COLUMNS = [
  "id",
  "job_id",
  "sequence",
  "phase",
  "status",
  "message",
  "metadata_json",
  "created_at",
] as const;

function projectedRows(
  db: BountyDatabase,
  table: string,
  columns: readonly string[],
  orderBy: string,
): Array<Record<string, unknown>> {
  return db
    .prepare(`SELECT ${columns.join(", ")} FROM ${table} ORDER BY ${orderBy} ASC`)
    .all() as Array<Record<string, unknown>>;
}

// --- legacy fixture builders --------------------------------------------
//
// These DDLs are a byte-for-byte mirror of the current
// src/stores/db/database.ts `ensureSchema` body (with `IF NOT EXISTS`
// stripped) so an unversioned legacy DB built by the tests starts from
// the real production baseline, not a hand-trimmed subset.

const LEGACY_FINDINGS_DDL = `
  CREATE TABLE findings (
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
`;

const LEGACY_EVIDENCE_ARTIFACTS_DDL = `
  CREATE TABLE evidence_artifacts (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    job_id TEXT,
    adapter_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_url TEXT,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`;

const LEGACY_FINDING_CANDIDATES_DDL = `
  CREATE TABLE finding_candidates (
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
  CREATE INDEX idx_finding_candidates_job_id ON finding_candidates (job_id, updated_at);
  CREATE INDEX idx_finding_candidates_status ON finding_candidates (status, updated_at);
  CREATE INDEX idx_finding_candidates_reportability ON finding_candidates (reportability, updated_at);
  CREATE INDEX idx_finding_candidates_finding_id ON finding_candidates (finding_id);
`;

const LEGACY_JOBS_DDL = `
  CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    target TEXT,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`;

const LEGACY_ACTIONS_DDL = `
  CREATE TABLE actions (
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
`;

const LEGACY_RECON_OBSERVATIONS_DDL = `
  CREATE TABLE recon_observations (
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
  CREATE INDEX idx_recon_observations_job_id ON recon_observations (job_id, last_seen_at);
  CREATE INDEX idx_recon_observations_kind ON recon_observations (kind, last_seen_at);
  CREATE INDEX idx_recon_observations_source_adapter ON recon_observations (source_adapter, last_seen_at);
`;

const LEGACY_ACTION_REVIEWS_DDL = `
  CREATE TABLE action_reviews (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    job_id TEXT,
    decision TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX idx_action_reviews_action_id ON action_reviews (action_id, created_at);
  CREATE INDEX idx_action_reviews_job_id ON action_reviews (job_id, created_at);
`;

const LEGACY_CRAWL_PAGES_DDL = `
  CREATE TABLE crawl_pages (
    url TEXT PRIMARY KEY,
    title TEXT,
    status INTEGER,
    content_hash TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
  );
`;

const LEGACY_CRAWL_EDGES_DDL = `
  CREATE TABLE crawl_edges (
    id TEXT PRIMARY KEY,
    from_url TEXT NOT NULL,
    to_url TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`;

const LEGACY_WORKFLOW_DDL = `
  CREATE TABLE workflow_events (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    phase TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata_json TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX idx_workflow_events_job_sequence ON workflow_events (job_id, sequence);
  CREATE INDEX idx_workflow_events_created_at ON workflow_events (created_at);
`;

export interface LegacyFixture {
  jobIds: { dup: string; clean: string; cleanFar: string };
  actionIds: {
    planned: string;
    approved: string;
    executed: string;
    blocked: string;
    failed: string;
    pending: string;
  };
  reviewIds: { approved: string };
  workflow: Array<{ id: string; jobId: string; sequence: number; createdAt: string }>;
  findingIds: string[];
  evidenceArtifactIds: string[];
  findingCandidateIds: string[];
  reconObservationIds: string[];
  crawlPageUrls: string[];
  crawlEdgeIds: string[];
}

function buildLegacyDatabase(dbFile: string): void {
  mkdirSync(path.dirname(dbFile), { recursive: true });
  const db = new DatabaseSync(dbFile);
  try {
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
    `);
    db.exec(LEGACY_FINDINGS_DDL);
    db.exec(LEGACY_EVIDENCE_ARTIFACTS_DDL);
    db.exec(LEGACY_FINDING_CANDIDATES_DDL);
    db.exec(LEGACY_JOBS_DDL);
    db.exec(LEGACY_ACTIONS_DDL);
    db.exec(LEGACY_RECON_OBSERVATIONS_DDL);
    db.exec(LEGACY_ACTION_REVIEWS_DDL);
    db.exec(LEGACY_CRAWL_PAGES_DDL);
    db.exec(LEGACY_CRAWL_EDGES_DDL);
    db.exec(LEGACY_WORKFLOW_DDL);
  } finally {
    db.close();
  }
}

function seedLegacyDatabase(dbFile: string): LegacyFixture {
  const db = new DatabaseSync(dbFile);
  try {
    const now = "2026-01-01T00:00:00.000Z";
    const jobDup = "job-dup";
    const jobClean = "job-clean";
    const jobCleanFar = "job-far";

    // --- jobs ---
    const insertJob = db.prepare(
      `INSERT INTO jobs (id, type, target, mode, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    insertJob.run(jobDup, "hunt", "https://dup.example", "live", "paused", now, now);
    insertJob.run(jobClean, "hunt", "https://clean.example", "live", "running", now, now);
    insertJob.run(jobCleanFar, "hunt", "https://far.example", "live", "completed", now, now);

    // --- actions ---
    const insertAction = db.prepare(
      `INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at, executed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const a = {
      planned: "act-planned",
      approved: "act-approved",
      executed: "act-executed",
      blocked: "act-blocked",
      failed: "act-failed",
      pending: "act-pending",
    } as const;
    insertAction.run(a.planned, jobDup, "http", "GET", "https://dup.example/x", "low", 0, "planned", now, null);
    insertAction.run(a.approved, jobDup, "http", "POST", "https://dup.example/y", "high", 1, "approved", now, null);
    insertAction.run(a.executed, jobDup, "http", "GET", "https://dup.example/z", "low", 0, "executed", now, now);
    insertAction.run(a.blocked, jobClean, "http", "GET", "https://clean.example/x", "medium", 0, "blocked", now, null);
    insertAction.run(a.failed, jobClean, "http", "GET", "https://clean.example/y", "high", 1, "failed", now, null);
    insertAction.run(a.pending, jobClean, "http", "GET", "https://clean.example/z", "low", 0, "pending", now, null);

    // --- action_reviews (one legacy row) ---
    const revApproved = "rev-approved-1";
    db.prepare(
      `INSERT INTO action_reviews (id, action_id, job_id, decision, note, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(revApproved, a.approved, jobDup, "approved", "legacy row, no reviewer/hashes", now);

    // --- workflow_events: dup job has duplicate sequences that force the
    // migration to resequence deterministically. The two duplicate rows
    // share the SAME created_at so the id tie-break is the only thing
    // that can produce a stable order.
    //
    // FIX 2: Insert lexical id D2 BEFORE D1 (D2 first in insertion order).
    // D3 has the earliest timestamp despite legacy sequence=2. The required
    // final order is therefore D3, D1, D2. This distinguishes (created_at,id)
    // from insertion order, id-only, and sequence-first implementations.
    const SHARED_TS = "2026-01-01T00:00:01.000Z";
    const workflow: Array<{ id: string; jobId: string; sequence: number; createdAt: string }> = [
      { id: "we-D-2", jobId: jobDup, sequence: 1, createdAt: SHARED_TS }, // Inserted first; lexically after D1.
      { id: "we-D-1", jobId: jobDup, sequence: 1, createdAt: SHARED_TS }, // Inserted second; lexically before D2.
      { id: "we-D-3", jobId: jobDup, sequence: 2, createdAt: "2025-12-31T23:59:59.000Z" },
      { id: "we-C-1", jobId: jobClean, sequence: 1, createdAt: "2026-01-01T00:00:04.000Z" },
      { id: "we-C-2", jobId: jobClean, sequence: 2, createdAt: "2026-01-01T00:00:05.000Z" },
      { id: "we-F-1", jobId: jobCleanFar, sequence: 5, createdAt: "2026-01-01T00:00:06.000Z" },
      { id: "we-F-2", jobId: jobCleanFar, sequence: 10, createdAt: "2026-01-01T00:00:07.000Z" },
    ];
    const insertWe = db.prepare(
      `INSERT INTO workflow_events (id, job_id, sequence, phase, status, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const w of workflow) {
      insertWe.run(w.id, w.jobId, w.sequence, "recon", "completed", "ok", w.createdAt);
    }

    // --- findings ---
    const findingIds = ["find-1", "find-2"];
    const insertFinding = db.prepare(
      `INSERT INTO findings (id, title, asset, url, category, severity_estimate, confidence, status, evidence_paths, duplicate_risk, reportability_score, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const fid of findingIds) {
      insertFinding.run(
        fid,
        "smoke",
        `${fid}.example`,
        `https://${fid}.example`,
        "xss",
        "low",
        "low",
        "open",
        "[]",
        "low",
        0,
        now,
        now,
      );
    }

    // --- evidence_artifacts ---
    const evidenceArtifactIds = ["ev-1", "ev-2"];
    const insertEvidence = db.prepare(
      `INSERT INTO evidence_artifacts (id, finding_id, job_id, adapter_name, kind, source_url, path, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    insertEvidence.run("ev-1", "find-1", jobDup, "http", "html", "https://dup.example/x", "/tmp/ev-1.html", now);
    insertEvidence.run("ev-2", "find-2", jobClean, "http", "html", "https://clean.example/x", "/tmp/ev-2.html", now);

    // --- finding_candidates (UNIQUE on fingerprint) ---
    const findingCandidateIds = ["fc-1", "fc-2"];
    const insertFc = db.prepare(
      `INSERT INTO finding_candidates (id, job_id, title, asset, url, category, severity_estimate, confidence, status, evidence_ids, observation_ids, finding_id, false_positive_risk, duplicate_risk, reportability, reasoning_summary, next_manual_steps, fingerprint, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    insertFc.run(
      "fc-1",
      jobDup,
      "cand xss 1",
      "fc-1.example",
      "https://fc-1.example",
      "xss",
      "low",
      "low",
      "open",
      '["ev-1"]',
      '[]',
      null,
      "low",
      "low",
      "low",
      "ok",
      "manual verify",
      "fc1-fingerprint",
      now,
      now,
    );
    insertFc.run(
      "fc-2",
      jobClean,
      "cand xss 2",
      "fc-2.example",
      "https://fc-2.example",
      "xss",
      "low",
      "low",
      "open",
      '["ev-2"]',
      '[]',
      "find-2",
      "low",
      "low",
      "low",
      "ok",
      "manual verify",
      "fc2-fingerprint",
      now,
      now,
    );

    // --- recon_observations (UNIQUE on fingerprint) ---
    const reconObservationIds = ["ro-1", "ro-2"];
    const insertRo = db.prepare(
      `INSERT INTO recon_observations (id, job_id, kind, value, normalized_value, source_adapter, source_url, scope_allowed, confidence, risk_hint, metadata_json, fingerprint, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    insertRo.run(
      "ro-1",
      jobDup,
      "url",
      "https://dup.example/",
      "https://dup.example/",
      "http",
      "https://dup.example/",
      1,
      "high",
      "low",
      "{}",
      "ro1-fingerprint",
      now,
      now,
    );
    insertRo.run(
      "ro-2",
      jobClean,
      "header",
      "x-frame-options: deny",
      "x-frame-options: deny",
      "http",
      "https://clean.example/",
      1,
      "high",
      "low",
      "{}",
      "ro2-fingerprint",
      now,
      now,
    );

    // --- crawl_pages ---
    const crawlPageUrls = [
      "https://dup.example/",
      "https://clean.example/",
    ];
    const insertCp = db.prepare(
      `INSERT INTO crawl_pages (url, title, status, content_hash, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)`,
    );
    insertCp.run("https://dup.example/", "Dup Home", 200, "dup-content-hash", now, now);
    insertCp.run("https://clean.example/", "Clean Home", 200, "clean-content-hash", now, now);

    // --- crawl_edges ---
    const crawlEdgeIds = ["edge-1", "edge-2"];
    const insertCe = db.prepare(
      `INSERT INTO crawl_edges (id, from_url, to_url, created_at) VALUES (?, ?, ?, ?)`,
    );
    insertCe.run("edge-1", "https://dup.example/", "https://dup.example/x", now);
    insertCe.run("edge-2", "https://clean.example/", "https://clean.example/x", now);

    return {
      jobIds: { dup: jobDup, clean: jobClean, cleanFar: jobCleanFar },
      actionIds: a,
      reviewIds: { approved: revApproved },
      workflow,
      findingIds,
      evidenceArtifactIds,
      findingCandidateIds,
      reconObservationIds,
      crawlPageUrls,
      crawlEdgeIds,
    };
  } finally {
    db.close();
  }
}

// --- expected v2 schema fingerprints ------------------------------------
//
// docs/p0.2-action-approval-execution-packets.md §4 declares every additive
// P0.2 column. The contract is exact: all added columns are TEXT and
// nullable with NULL default, except `actions.required_for_completion`
// which is INTEGER NOT NULL with semantic default 1.
//
// SQLite preserves declared type spelling. Case and surrounding whitespace
// are irrelevant, but the Packet 1 contract deliberately rejects affinity
// lookalikes such as TEXT(255): the additive DDL must declare TEXT/INTEGER.

function normalizeType(t: string): string {
  return t.trim().toUpperCase();
}

function normalizeDefault(d: string | null): string {
  if (d === null) return "";
  let s = d.trim();
  // Strip enclosing parentheses.
  if (s.startsWith("(") && s.endsWith(")")) s = s.slice(1, -1).trim();
  // Strip enclosing quotes for string defaults.
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith("\"") && s.endsWith("\""))) {
    s = s.slice(1, -1);
  }
  return s;
}

function assertColumn(
  cols: ColumnRow[],
  table: string,
  col: string,
  expectedType: "TEXT" | "INTEGER",
  opts: { notNull: boolean; defaultNumeric?: number } = { notNull: false },
): void {
  const row = cols.find((c) => c.name === col);
  expect(row, `${table}.${col} present`).toBeTruthy();
  expect(normalizeType(row!.type), `${table}.${col} type`).toBe(expectedType);
  if (expectedType === "TEXT") {
    expect(row!.notnull, `${table}.${col} nullable`).toBe(opts.notNull ? 1 : 0);
  } else {
    expect(row!.notnull, `${table}.${col} notnull flag`).toBe(opts.notNull ? 1 : 0);
  }
  if (opts.defaultNumeric !== undefined) {
    const n = Number(normalizeDefault(row!.dflt_value));
    expect(Number.isFinite(n), `${table}.${col} default is numeric`).toBe(true);
    expect(n, `${table}.${col} default equals ${opts.defaultNumeric}`).toBe(opts.defaultNumeric);
  } else {
    const semanticNullDefault =
      row!.dflt_value === null || normalizeDefault(row!.dflt_value).toUpperCase() === "NULL";
    expect(semanticNullDefault, `${table}.${col} default is semantically NULL`).toBe(true);
  }
}

// Per docs §4.1–§4.3: every additive column is TEXT, nullable, NULL default.
const ACTIONS_V2_COLUMNS = [
  "updated_at",
  "active_review_id",
  "planned_scope_hash",
  "planned_policy_hash",
  "planned_action_hash",
  "planned_context_hash",
  "execution_token",
  "execution_owner",
  "lease_expires_at",
  "started_at",
  "dispatch_started_at",
  "finished_at",
  "outcome_certainty",
  "last_error_code",
  "last_error_message",
  "supersedes_action_id",
] as const;

// §4.1: required_for_completion is the only INTEGER NOT NULL DEFAULT 1.
const ACTION_REVIEWS_V2_COLUMNS = [
  "reviewer_id",
  "source",
  "reviewed_at",
  "expires_at",
  "scope_hash",
  "policy_hash",
  "action_hash",
  "context_hash",
  "invalidated_at",
  "invalidation_reason",
] as const;

const JOBS_V2_COLUMNS = ["pause_reason", "status_detail"] as const;

// =========================================================================
// PART 1 tests
// =========================================================================

describe("P0.2 Packet 1 — fresh DB reaches v2 schema with no migration audit event", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "fresh.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("sets user_version to CURRENT_SCHEMA_VERSION, records both migrations, and preserves PRAGMAs", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      expect(CURRENT_SCHEMA_VERSION).toBe(2);
      expect(userVersion(db)).toBe(CURRENT_SCHEMA_VERSION);

      const mig = db.prepare("SELECT version FROM schema_migrations ORDER BY version ASC").all() as Array<{
        version: number;
      }>;
      expect(mig.map((r) => r.version)).toEqual([1, 2]);

      expect(journalMode(db).toLowerCase()).toBe("wal");
      expect(busyTimeout(db)).toBe(5000);
      expect(foreignKeys(db)).toBe(1);

      // Zero migration audit event on a fresh DB (no legacy data changed).
      const audit = (db.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'").get() as {
        n: number;
      });
      expect(audit.n).toBe(0);
    } finally {
      db.close();
    }
  });

  it("adds every section-4 additive column with exact type and nullability", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      const actionsCols = columnsOf(db, "actions");
      // §4.1: every additive column is TEXT nullable with NULL default,
      // except required_for_completion which is INTEGER NOT NULL DEFAULT 1.
      for (const col of ACTIONS_V2_COLUMNS) {
        assertColumn(actionsCols, "actions", col, "TEXT", { notNull: false });
      }
      assertColumn(actionsCols, "actions", "required_for_completion", "INTEGER", {
        notNull: true,
        defaultNumeric: 1,
      });

      const reviewCols = columnsOf(db, "action_reviews");
      for (const col of ACTION_REVIEWS_V2_COLUMNS) {
        assertColumn(reviewCols, "action_reviews", col, "TEXT", { notNull: false });
      }

      const jobCols = columnsOf(db, "jobs");
      for (const col of JOBS_V2_COLUMNS) {
        assertColumn(jobCols, "jobs", col, "TEXT", { notNull: false });
      }
    } finally {
      db.close();
    }
  });

  it("workflow_events(job_id, sequence) becomes UNIQUE and actions.execution_token gains a partial unique index", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      // PRAGMA-based lookup so the test does not pin a specific index name.
      const weIdx = findUniqueIndexWithColumns(db, "workflow_events", ["job_id", "sequence"]);
      expect(weIdx, "workflow_events unique (job_id, sequence) index").toBeTruthy();

      // Find a unique partial index on actions with ordered columns [execution_token].
      const tokenIdx = findPartialUniqueIndexWithColumns(db, "actions", ["execution_token"]);
      expect(tokenIdx, "actions partial unique (execution_token) index").toBeTruthy();

      // Behavioral duplicate probe: two non-NULL tokens collide.
      db.prepare(
        "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run("act-token-1", null, "http", "GET", "https://t1.example", "low", 0, "pending", "2026-01-01T00:00:00.000Z");
      db.prepare("UPDATE actions SET execution_token = ? WHERE id = ?").run("token-A", "act-token-1");
      let threw = false;
      try {
        db.prepare(
          "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at, execution_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run("act-token-2", null, "http", "GET", "https://t2.example", "low", 0, "pending", "2026-01-01T00:00:00.000Z", "token-B");
        db.prepare("UPDATE actions SET execution_token = ? WHERE id = ?").run("token-A", "act-token-2");
      } catch {
        threw = true;
      }
      expect(threw, "duplicate non-NULL execution_token must be rejected").toBe(true);
    } finally {
      db.close();
    }
  });
});

describe("P0.2 Packet 1 — unversioned legacy DB upgrade preserves rows and demotes cleanly", () => {
  let tempDir: string;
  let dbFile: string;
  let fixture: LegacyFixture;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "legacy.db");
    buildLegacyDatabase(dbFile);
    fixture = seedLegacyDatabase(dbFile);
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("demotes planned and incomplete-approved, keeps executed/blocked/failed terminal, never fabricates a review", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      const allActions = db.prepare("SELECT id, status FROM actions ORDER BY id ASC").all() as Array<{
        id: string;
        status: string;
      }>;
      expect(allActions.length).toBe(6);
      expect(allActions.map((r) => r.id).sort()).toEqual(
        [
          fixture.actionIds.planned,
          fixture.actionIds.approved,
          fixture.actionIds.executed,
          fixture.actionIds.blocked,
          fixture.actionIds.failed,
          fixture.actionIds.pending,
        ].sort(),
      );

      // planned -> pending
      expect(allActions.find((r) => r.id === fixture.actionIds.planned)!.status).toBe("pending");

      // approved without complete active review/hash binding -> pending.
      const approved = db.prepare(
        "SELECT status, active_review_id, updated_at FROM actions WHERE id = ?",
      ).get(fixture.actionIds.approved) as {
        status: string;
        active_review_id: string | null;
        updated_at: string | null;
      };
      expect(approved.status).toBe("pending");
      expect(approved.active_review_id).toBeNull();
      expect(approved.updated_at).toBeTruthy();

      // No fake review is fabricated. The legacy review row stays on disk as
      // immutable history with invalidated_at NULL; active-ness is proved
      // only by the action's active_review_id being NULL after demotion.
      const reviewRow = db
        .prepare(
          "SELECT id, invalidated_at FROM action_reviews WHERE id = ?",
        )
        .get(fixture.reviewIds.approved) as { id: string; invalidated_at: string | null } | undefined;
      expect(reviewRow).toBeTruthy();
      expect(reviewRow!.id).toBe(fixture.reviewIds.approved);
      expect(reviewRow!.invalidated_at).toBeNull();

      // FIX 3: For the legacy action review after migration, query and assert
      // every newly added field is NULL: reviewer_id, source, reviewed_at,
      // expires_at, scope_hash, policy_hash, action_hash, context_hash,
      // invalidated_at, invalidation_reason. No fake review binding/data.
      const NEW_REVIEW_COLS = [
        "reviewer_id",
        "source",
        "reviewed_at",
        "expires_at",
        "scope_hash",
        "policy_hash",
        "action_hash",
        "context_hash",
        "invalidated_at",
        "invalidation_reason",
      ] as const;
      const legacyReviewFields = db
        .prepare(`SELECT ${NEW_REVIEW_COLS.join(", ")} FROM action_reviews WHERE id = ?`)
        .get(fixture.reviewIds.approved) as Record<(typeof NEW_REVIEW_COLS)[number], string | null>;
      for (const col of NEW_REVIEW_COLS) {
        expect(legacyReviewFields[col], `legacy review.${col} must be NULL after demotion`).toBeNull();
      }

      // Terminal statuses preserved verbatim.
      const byId = new Map(allActions.map((r) => [r.id, r.status]));
      expect(byId.get(fixture.actionIds.executed)).toBe("executed");
      expect(byId.get(fixture.actionIds.blocked)).toBe("blocked");
      expect(byId.get(fixture.actionIds.failed)).toBe("failed");
      expect(byId.get(fixture.actionIds.pending)).toBe("pending");

      // FIX 6: Assert every migrated legacy action has required_for_completion=1.
      const reqComplete = db.prepare("SELECT id, required_for_completion FROM actions ORDER BY id ASC").all() as Array<{
        id: string;
        required_for_completion: number;
      }>;
      expect(reqComplete.length).toBe(6);
      for (const row of reqComplete) {
        expect(row.required_for_completion, `action ${row.id} required_for_completion must be 1`).toBe(1);
      }

      // Every demoted action gets an updated_at.
      const demotedUpdated = db.prepare(
        "SELECT updated_at FROM actions WHERE id IN (?, ?)",
      ).all(fixture.actionIds.planned, fixture.actionIds.approved) as Array<{ updated_at: string | null }>;
      for (const r of demotedUpdated) {
        expect(r.updated_at, "demoted action has updated_at").toBeTruthy();
      }
    } finally {
      db.close();
    }
  });

  it("preserves every row of untouched legacy product tables byte-for-byte across migration", () => {
    // Capture pre-migration full rows from a fresh raw sqlite handle so
    // we can compare against post-migration state.
    const pre = new DatabaseSync(dbFile);
    let findingsPre: unknown[];
    let evidencePre: unknown[];
    let findingCandidatesPre: unknown[];
    let reconPre: unknown[];
    let crawlPagesPre: unknown[];
    let crawlEdgesPre: unknown[];
    let jobsPre: Array<Record<string, unknown>>;
    let actionsPre: Array<Record<string, unknown>>;
    let reviewsPre: Array<Record<string, unknown>>;
    let workflowPre: Array<Record<string, unknown>>;
    try {
      findingsPre = fullRows(pre, "findings", "id");
      evidencePre = fullRows(pre, "evidence_artifacts", "id");
      findingCandidatesPre = fullRows(pre, "finding_candidates", "id");
      reconPre = fullRows(pre, "recon_observations", "id");
      crawlPagesPre = fullRows(pre, "crawl_pages", "url");
      crawlEdgesPre = fullRows(pre, "crawl_edges", "id");
      jobsPre = projectedRows(pre, "jobs", LEGACY_JOB_COLUMNS, "id");
      actionsPre = projectedRows(pre, "actions", LEGACY_ACTION_COLUMNS, "id");
      reviewsPre = projectedRows(pre, "action_reviews", LEGACY_REVIEW_COLUMNS, "id");
      workflowPre = projectedRows(pre, "workflow_events", LEGACY_WORKFLOW_COLUMNS, "id");
    } finally {
      pre.close();
    }

    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);
      expect(fullRows(db, "findings", "id")).toEqual(findingsPre);
      expect(fullRows(db, "evidence_artifacts", "id")).toEqual(evidencePre);
      expect(fullRows(db, "finding_candidates", "id")).toEqual(findingCandidatesPre);
      expect(fullRows(db, "recon_observations", "id")).toEqual(reconPre);
      expect(fullRows(db, "crawl_pages", "url")).toEqual(crawlPagesPre);
      expect(fullRows(db, "crawl_edges", "id")).toEqual(crawlEdgesPre);

      expect(projectedRows(db, "jobs", LEGACY_JOB_COLUMNS, "id")).toEqual(jobsPre);
      expect(projectedRows(db, "action_reviews", LEGACY_REVIEW_COLUMNS, "id")).toEqual(reviewsPre);

      const expectedActions = actionsPre.map((row) => ({
        ...row,
        status:
          row.id === fixture.actionIds.planned || row.id === fixture.actionIds.approved
            ? "pending"
            : row.status,
      }));
      expect(projectedRows(db, "actions", LEGACY_ACTION_COLUMNS, "id")).toEqual(expectedActions);

      const expectedWorkflow = workflowPre.map((row) => ({ ...row }));
      const affected = expectedWorkflow
        .filter((row) => row.job_id === fixture.jobIds.dup)
        .sort((left, right) => {
          const byTime = String(left.created_at).localeCompare(String(right.created_at));
          return byTime !== 0 ? byTime : String(left.id).localeCompare(String(right.id));
        });
      affected.forEach((row, index) => {
        row.sequence = index + 1;
      });
      expectedWorkflow.sort((left, right) => String(left.id).localeCompare(String(right.id)));
      const productWorkflow = db
        .prepare(
          `SELECT ${LEGACY_WORKFLOW_COLUMNS.join(", ")} FROM workflow_events WHERE phase != 'migration' ORDER BY id ASC`,
        )
        .all() as Array<Record<string, unknown>>;
      expect(productWorkflow).toEqual(expectedWorkflow);
    } finally {
      db.close();
    }
  });
});

describe("P0.2 Packet 1 — openBountyDatabase runs migrations implicitly on fresh and legacy DBs", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "implicit.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("fresh DB opened via openBountyDatabase alone reaches v2 with the required additive schema", () => {
    // No explicit runMigrations call: openBountyDatabase must drive the
    // v1 → v2 migration implicitly so production callers never have to
    // call runMigrations by hand.
    const db = openBountyDatabase(dbFile);
    try {
      expect(userVersion(db)).toBe(CURRENT_SCHEMA_VERSION);
      const mig = (db
        .prepare("SELECT version FROM schema_migrations ORDER BY version ASC")
        .all() as Array<{ version: number }>).map((r) => r.version);
      expect(mig).toEqual([1, 2]);
      const actionsCols = columnsOf(db, "actions").map((c) => c.name);
      for (const col of ACTIONS_V2_COLUMNS) {
        expect(actionsCols, `actions.${col} present after openBountyDatabase`).toContain(col);
      }
      expect(actionsCols).toContain("required_for_completion");
      const audit = (db
        .prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'")
        .get() as { n: number }).n;
      expect(audit).toBe(0);
    } finally {
      db.close();
    }
  });

  it("legacy DB opened via openBountyDatabase alone reaches v2 and demotes planned/incomplete-approved", () => {
    buildLegacyDatabase(dbFile);
    const seeded = seedLegacyDatabase(dbFile);

    const db = openBountyDatabase(dbFile);
    try {
      expect(userVersion(db)).toBe(CURRENT_SCHEMA_VERSION);
      const statuses = (db
        .prepare("SELECT id, status FROM actions ORDER BY id ASC")
        .all() as Array<{ id: string; status: string }>);
      const byId = new Map(statuses.map((r) => [r.id, r.status]));
      // planned -> pending, incomplete approved -> pending, terminal
      // statuses preserved byte-for-byte. The migration ran implicitly
      // inside openBountyDatabase, so the caller never has to call
      // runMigrations by hand.
      expect(byId.get(seeded.actionIds.planned)).toBe("pending");
      expect(byId.get(seeded.actionIds.approved)).toBe("pending");
      expect(byId.get(seeded.actionIds.executed)).toBe("executed");
      expect(byId.get(seeded.actionIds.blocked)).toBe("blocked");
      expect(byId.get(seeded.actionIds.failed)).toBe("failed");
      expect(byId.get(seeded.actionIds.pending)).toBe("pending");
    } finally {
      db.close();
    }
  });

  it("recovers an older unversioned actions table that predates metadata_json", () => {
    buildLegacyDatabase(dbFile);
    const raw = new DatabaseSync(dbFile);
    try {
      raw.exec("ALTER TABLE actions DROP COLUMN metadata_json");
    } finally {
      raw.close();
    }
    const seeded = seedLegacyDatabase(dbFile);

    const db = openBountyDatabase(dbFile);
    try {
      expect(userVersion(db)).toBe(2);
      const metadataColumn = columnsOf(db, "actions").find((column) => column.name === "metadata_json");
      expect(metadataColumn).toBeTruthy();
      expect(normalizeType(metadataColumn!.type)).toBe("TEXT");
      expect(metadataColumn!.notnull).toBe(0);
      expect(metadataColumn!.dflt_value).toBeNull();
      const rows = db
        .prepare("SELECT id, metadata_json FROM actions ORDER BY id ASC")
        .all() as Array<{ id: string; metadata_json: string | null }>;
      expect(rows.map((row) => row.id).sort()).toEqual(Object.values(seeded.actionIds).sort());
      expect(rows.every((row) => row.metadata_json === null)).toBe(true);
    } finally {
      db.close();
    }
  });
});

describe("P0.2 Packet 1 — schema_migrations exact column contract", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "schemamig.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  // FIX 5: Exact schema_migrations contract: the only columns are version,
  // name, applied_at in order; version has declared type INTEGER and pk=1;
  // name is TEXT NOT NULL and has a unique index/constraint; applied_at is
  // TEXT NOT NULL; no extra columns. Extend the PRAGMA column row type with
  // pk if needed.
  it("schema_migrations has exactly version, name, applied_at with correct types/indexes", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      const cols = columnsOf(db, "schema_migrations");
      expect(cols.map((column) => column.name)).toEqual(["version", "name", "applied_at"]);
      expect(normalizeType(cols[0].type)).toBe("INTEGER");
      expect(cols[0].pk).toBe(1);
      expect(cols[0].dflt_value).toBeNull();
      expect(cols[1].pk).toBe(0);
      expect(normalizeType(cols[1].type)).toBe("TEXT");
      expect(cols[1].notnull).toBe(1);
      expect(cols[1].dflt_value).toBeNull();
      expect(cols[2].pk).toBe(0);
      expect(normalizeType(cols[2].type)).toBe("TEXT");
      expect(cols[2].notnull).toBe(1);
      expect(cols[2].dflt_value).toBeNull();

      // Verify unique index on name.
      const indexes = listTableIndexes(db, "schema_migrations");
      const nameIndex = indexes.find((idx) => {
        const columns = indexColumnNames(db, idx.name);
        return idx.unique === 1 && idx.partial === 0 && columns.length === 1 && columns[0] === "name";
      });
      expect(nameIndex, "unique index on name column").toBeTruthy();

      // Verify data is present and has expected rows.
      const rows = db.prepare("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC").all() as Array<{
        version: number;
        name: string;
        applied_at: string;
      }>;
      expect(rows.length).toBe(2);
      expect(rows[0].version).toBe(1);
      expect(rows[0].name).toBe("legacy_baseline");
      expect(rows[1].version).toBe(2);
    } finally {
      db.close();
    }
  });
});

describe("P0.2 Packet 1 — workflow_events deterministic resequence", () => {
  let tempDir: string;
  let dbFile: string;
  let fixture: LegacyFixture;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "reseq.db");
    buildLegacyDatabase(dbFile);
    fixture = seedLegacyDatabase(dbFile);
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("only the affected job is resequenced 1..N by (created_at, id); other jobs keep every column byte-identical", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      // Affected job: original sequences [1,1,2] must become [1,2,3] in
      // deterministic (created_at, id) order. Both duplicates share the
      // SAME created_at, so the id tie-break is the only thing that
      // produces a stable order among D1/D2, while D3 proves created_at is
      // evaluated before the legacy sequence.
      //
      // FIX 2: The seeded order was D2 then D1 (although D1 sorts first), but
      // after migration sorted by (created_at, id) lexicographically, it
      // MUST be D3, D1, D2. This catches implementations that rely on legacy
      // sequence, id-only ordering, or insertion order.
      const dup = db.prepare(
        "SELECT id, sequence FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC, id ASC",
      ).all(fixture.jobIds.dup) as Array<{ id: string; sequence: number }>;
      expect(dup.length).toBe(3);
      const dupBySeq = [...dup].sort((a, b) => a.sequence - b.sequence);
      expect(dupBySeq.map((r) => r.sequence)).toEqual([1, 2, 3]);
      expect(dupBySeq.map((r) => r.id)).toEqual(["we-D-3", "we-D-1", "we-D-2"]);

      // Unaffected jobs: every column is byte-for-byte identical to
      // what was seeded. Comparing only id/sequence is not enough to
      // catch a silent migration that rewrites messages or status.
      const WORKFLOW_ALL_COLS = [
        "id",
        "job_id",
        "sequence",
        "phase",
        "status",
        "message",
        "metadata_json",
        "created_at",
      ] as const;
      const clean = db
        .prepare(
          `SELECT ${WORKFLOW_ALL_COLS.join(", ")} FROM workflow_events WHERE job_id = ? ORDER BY id ASC`,
        )
        .all(fixture.jobIds.clean) as Array<Record<(typeof WORKFLOW_ALL_COLS)[number], unknown>>;
      expect(clean.map((r) => r.sequence)).toEqual([1, 2]);
      expect(clean.map((r) => r.id)).toEqual(["we-C-1", "we-C-2"]);
      const cleanSeeded = fixture.workflow
        .filter((w) => w.jobId === fixture.jobIds.clean)
        .map((w) => ({
          id: w.id,
          job_id: w.jobId,
          sequence: w.sequence,
          phase: "recon",
          status: "completed",
          message: "ok",
          metadata_json: null,
          created_at: w.createdAt,
        }));
      expect(clean).toEqual(cleanSeeded);

      const cleanFar = db
        .prepare(
          `SELECT ${WORKFLOW_ALL_COLS.join(", ")} FROM workflow_events WHERE job_id = ? ORDER BY id ASC`,
        )
        .all(fixture.jobIds.cleanFar) as Array<Record<(typeof WORKFLOW_ALL_COLS)[number], unknown>>;
      expect(cleanFar.map((r) => r.sequence)).toEqual([5, 10]);
      expect(cleanFar.map((r) => r.id)).toEqual(["we-F-1", "we-F-2"]);
      const cleanFarSeeded = fixture.workflow
        .filter((w) => w.jobId === fixture.jobIds.cleanFar)
        .map((w) => ({
          id: w.id,
          job_id: w.jobId,
          sequence: w.sequence,
          phase: "recon",
          status: "completed",
          message: "ok",
          metadata_json: null,
          created_at: w.createdAt,
        }));
      expect(cleanFar).toEqual(cleanFarSeeded);

      // Original event rows are preserved: every seeded id still resolves,
      // and rows whose phase is not 'migration' still match the seeded set
      // (migration audit rows are asserted separately in contract-5).
      const origIds = new Set(fixture.workflow.map((w) => w.id));
      const present = db
        .prepare("SELECT id FROM workflow_events WHERE id IN (?, ?, ?, ?, ?, ?, ?)")
        .all(...(Array.from(origIds) as string[])) as Array<{ id: string }>;
      expect(present.map((r) => r.id).sort()).toEqual(Array.from(origIds).sort());

      const seededCount = (db
        .prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase != 'migration'")
        .get() as { n: number }).n;
      expect(seededCount).toBe(fixture.workflow.length);
    } finally {
      db.close();
    }
  });

  it("rejects a follow-up duplicate (job_id, sequence) insert after the unique index is in place", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      const insertDup = db.prepare(
        `INSERT INTO workflow_events (id, job_id, sequence, phase, status, message, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      );

      let threw = false;
      try {
        insertDup.run(
          "we-dup-after",
          fixture.jobIds.dup,
          1,
          "recon",
          "completed",
          "ok",
          "2026-01-01T00:00:50.000Z",
        );
      } catch {
        threw = true;
      }
      expect(threw).toBe(true);

      // Same sequence is still allowed in a different job (uniqueness is scoped
      // to the pair). Use cleanFar, which does not already use sequence 1.
      const beforeFar = (db.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(
        fixture.jobIds.cleanFar,
      ) as { n: number }).n;
      db.prepare(
        `INSERT INTO workflow_events (id, job_id, sequence, phase, status, message, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        "we-cross-1",
        fixture.jobIds.cleanFar,
        1,
        "recon",
        "completed",
        "ok",
        "2026-01-01T00:01:00.000Z",
      );
      const afterFar = (db.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(
        fixture.jobIds.cleanFar,
      ) as { n: number }).n;
      expect(afterFar - beforeFar).toBe(1);
      expect(afterFar).toBe(3);
    } finally {
      db.close();
    }
  });
});

// =========================================================================
// PART 2 — contract tests
// =========================================================================

// SHA-256 lowercase 64-hex helper. Uses node:crypto so the test does not
// need a vendored implementation. These are synthetic, content-fixed
// digests; they only need to be valid lowercase 64-hex and to match
// between the action and review rows in the same fixture.
function hex64(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

interface PartialUpgradeFixture {
  jobId: string;
  actionId: string;
  reviewId: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
  // Second action: approved in legacy, partial-upgrade columns added but
  // binding is INCOMPLETE. We seed real non-null stale values into every
  // P0.2 column that the migration must clear on demotion.
  staleActionId: string;
  staleValues: {
    execution_token: string;
    execution_owner: string;
    lease_expires_at: string;
    started_at: string;
    dispatch_started_at: string;
    finished_at: string;
    outcome_certainty: string;
    planned_scope_hash: string;
    planned_policy_hash: string;
    planned_action_hash: string;
    planned_context_hash: string;
    active_review_id: string;
  };
}

function buildPartialUpgradeDatabase(dbFile: string): void {
  buildLegacyDatabase(dbFile);
}

function seedPartialUpgradeDatabase(dbFile: string): PartialUpgradeFixture {
  const db = new DatabaseSync(dbFile);
  try {
    const now = "2026-01-01T00:00:00.000Z";
    const jobId = "job-partial";
    const actionId = "act-partial";
    const reviewId = "rev-partial";
    const staleActionId = "act-partial-stale";

    // Seed job + two approved actions in the legacy v1-only shape.
    db.prepare(
      `INSERT INTO jobs (id, type, target, mode, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(jobId, "hunt", "https://partial.example", "live", "paused", now, now);
    db.prepare(
      `INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at, executed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(actionId, jobId, "http", "POST", "https://partial.example/x", "high", 1, "approved", now, null);
    db.prepare(
      `INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at, executed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(staleActionId, jobId, "http", "POST", "https://partial.example/y", "high", 1, "approved", now, null);

    // Simulate a prior partial upgrade: ALTER-ADD the columns needed for a
    // complete binding AND the execution/lease/dispatch/finish/outcome/hash
    // fields. No schema_migrations row, no new indexes.
    db.exec(`
      ALTER TABLE actions ADD COLUMN active_review_id TEXT;
      ALTER TABLE actions ADD COLUMN planned_scope_hash TEXT;
      ALTER TABLE actions ADD COLUMN planned_policy_hash TEXT;
      ALTER TABLE actions ADD COLUMN planned_action_hash TEXT;
      ALTER TABLE actions ADD COLUMN planned_context_hash TEXT;
      ALTER TABLE actions ADD COLUMN execution_token TEXT;
      ALTER TABLE actions ADD COLUMN execution_owner TEXT;
      ALTER TABLE actions ADD COLUMN lease_expires_at TEXT;
      ALTER TABLE actions ADD COLUMN started_at TEXT;
      ALTER TABLE actions ADD COLUMN dispatch_started_at TEXT;
      ALTER TABLE actions ADD COLUMN finished_at TEXT;
      ALTER TABLE actions ADD COLUMN outcome_certainty TEXT;
      ALTER TABLE action_reviews ADD COLUMN reviewer_id TEXT;
      ALTER TABLE action_reviews ADD COLUMN source TEXT;
      ALTER TABLE action_reviews ADD COLUMN reviewed_at TEXT;
      ALTER TABLE action_reviews ADD COLUMN expires_at TEXT;
      ALTER TABLE action_reviews ADD COLUMN scope_hash TEXT;
      ALTER TABLE action_reviews ADD COLUMN policy_hash TEXT;
      ALTER TABLE action_reviews ADD COLUMN action_hash TEXT;
      ALTER TABLE action_reviews ADD COLUMN context_hash TEXT;
      ALTER TABLE action_reviews ADD COLUMN invalidated_at TEXT;
      ALTER TABLE action_reviews ADD COLUMN invalidation_reason TEXT;
    `);

    // ---- Action 1: complete binding stays approved ----
    const scopeHash = hex64("scope:partial");
    const policyHash = hex64("policy:partial");
    const actionHash = hex64("action:partial");
    const contextHash = hex64("context:partial");

    db.prepare(
      `INSERT INTO action_reviews (id, action_id, job_id, decision, note, created_at,
        reviewer_id, source, reviewed_at, expires_at, scope_hash, policy_hash, action_hash, context_hash,
        invalidated_at, invalidation_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
    ).run(
      reviewId,
      actionId,
      jobId,
      "approved",
      "partially upgraded legacy row",
      now,
      "alice@example",
      "human",
      now,
      // Deliberately old but structurally present: schema migration validates
      // binding shape only. Runtime approval code, not a migration tied to the
      // current wall clock, owns TTL expiry/invalidation.
      "2000-01-01T00:00:00.000Z",
      scopeHash,
      policyHash,
      actionHash,
      contextHash,
    );

    db.prepare(
      `UPDATE actions SET active_review_id = ?, planned_scope_hash = ?, planned_policy_hash = ?,
        planned_action_hash = ?, planned_context_hash = ? WHERE id = ?`,
    ).run(reviewId, scopeHash, policyHash, actionHash, contextHash, actionId);

    // ---- Action 2: INCOMPLETE binding, real non-null stale values ----
    // The hashes on this action do NOT match any review row, so the
    // binding is incomplete and the migration must demote this row to
    // pending and clear every P0.2 field. We also seed a non-null
    // active_review_id to confirm it is cleared.
    const staleValues = {
      execution_token: "stale-token-do-not-keep",
      execution_owner: "stale-owner",
      lease_expires_at: "2099-12-31T23:59:59.000Z",
      started_at: "2026-01-01T00:00:01.000Z",
      dispatch_started_at: "2026-01-01T00:00:02.000Z",
      finished_at: "2026-01-01T00:00:03.000Z",
      outcome_certainty: "possibly_dispatched",
      planned_scope_hash: hex64("stale:scope"),
      planned_policy_hash: hex64("stale:policy"),
      planned_action_hash: hex64("stale:action"),
      planned_context_hash: hex64("stale:context"),
      active_review_id: "stale-review-id-no-such-row",
    };
    db.prepare(
      `UPDATE actions SET
        active_review_id = ?,
        planned_scope_hash = ?,
        planned_policy_hash = ?,
        planned_action_hash = ?,
        planned_context_hash = ?,
        execution_token = ?,
        execution_owner = ?,
        lease_expires_at = ?,
        started_at = ?,
        dispatch_started_at = ?,
        finished_at = ?,
        outcome_certainty = ?
       WHERE id = ?`,
    ).run(
      staleValues.active_review_id,
      staleValues.planned_scope_hash,
      staleValues.planned_policy_hash,
      staleValues.planned_action_hash,
      staleValues.planned_context_hash,
      staleValues.execution_token,
      staleValues.execution_owner,
      staleValues.lease_expires_at,
      staleValues.started_at,
      staleValues.dispatch_started_at,
      staleValues.finished_at,
      staleValues.outcome_certainty,
      staleActionId,
    );

    return {
      jobId,
      actionId,
      reviewId,
      scopeHash,
      policyHash,
      actionHash,
      contextHash,
      staleActionId,
      staleValues,
    };
  } finally {
    db.close();
  }
}

const INVALID_COMPLETE_BINDING_MUTATIONS = [
  ["review decision is not approved", "UPDATE action_reviews SET decision = 'rejected' WHERE id = ?"],
  ["review is already invalidated", "UPDATE action_reviews SET invalidated_at = '2026-01-01T00:00:01.000Z' WHERE id = ?"],
  ["reviewer identity is absent", "UPDATE action_reviews SET reviewer_id = NULL WHERE id = ?"],
  ["review source is absent", "UPDATE action_reviews SET source = NULL WHERE id = ?"],
  ["review source is outside the human/policy protocol", "UPDATE action_reviews SET source = 'robot' WHERE id = ?"],
  ["reviewed timestamp is absent", "UPDATE action_reviews SET reviewed_at = NULL WHERE id = ?"],
  ["expiry timestamp is absent", "UPDATE action_reviews SET expires_at = NULL WHERE id = ?"],
  ["review points at another action", "UPDATE action_reviews SET action_id = 'act-partial-stale' WHERE id = ?"],
  ["review points at another job", "UPDATE action_reviews SET job_id = 'job-other' WHERE id = ?"],
  ["scope hash differs", `UPDATE action_reviews SET scope_hash = '${hex64("scope:mismatch")}' WHERE id = ?`],
  ["policy hash differs", `UPDATE action_reviews SET policy_hash = '${hex64("policy:mismatch")}' WHERE id = ?`],
  ["action hash differs", `UPDATE action_reviews SET action_hash = '${hex64("action:mismatch")}' WHERE id = ?`],
  ["one binding hash differs", `UPDATE action_reviews SET context_hash = '${hex64("context:mismatch")}' WHERE id = ?`],
] as const;

describe("P0.2 Packet 1 — partial-upgrade approved row with complete binding stays approved", () => {
  let tempDir: string;
  let dbFile: string;
  let partial: PartialUpgradeFixture;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "partial.db");
    buildPartialUpgradeDatabase(dbFile);
    partial = seedPartialUpgradeDatabase(dbFile);
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("keeps the action approved with the original active review after migration", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      const action = db
        .prepare(
          "SELECT status, active_review_id, updated_at FROM actions WHERE id = ?",
        )
        .get(partial.actionId) as {
          status: string;
          active_review_id: string | null;
          updated_at: string | null;
        };
      expect(action.status).toBe("approved");
      expect(action.active_review_id).toBe(partial.reviewId);

      // FIX 4: For the complete partial-upgrade binding, query and assert
      // planned_scope_hash, planned_policy_hash, planned_action_hash, and
      // planned_context_hash are all preserved exactly, alongside
      // status/active_review_id/updated_at as already required.
      const PLANNED_HASH_COLS = [
        "planned_scope_hash",
        "planned_policy_hash",
        "planned_action_hash",
        "planned_context_hash",
      ] as const;
      const actionWithHashes = db
        .prepare(`SELECT status, active_review_id, updated_at, ${PLANNED_HASH_COLS.join(", ")} FROM actions WHERE id = ?`)
        .get(partial.actionId) as {
          status: string;
          active_review_id: string | null;
          updated_at: string | null;
        } & Record<(typeof PLANNED_HASH_COLS)[number], string | null>;
      expect(actionWithHashes.status).toBe("approved");
      expect(actionWithHashes.active_review_id).toBe(partial.reviewId);
      // A structurally complete approval is not a normalization target; the
      // migration must not invent a timestamp solely because the new nullable
      // column was added.
      expect(actionWithHashes.updated_at).toBeNull();
      expect(actionWithHashes.planned_scope_hash).toBe(partial.scopeHash);
      expect(actionWithHashes.planned_policy_hash).toBe(partial.policyHash);
      expect(actionWithHashes.planned_action_hash).toBe(partial.actionHash);
      expect(actionWithHashes.planned_context_hash).toBe(partial.contextHash);

      // Review row is unchanged: hashes match, invalidated_at still NULL,
      // reviewer/source/reviewed/expires preserved.
      const review = db
        .prepare(
          `SELECT id, decision, reviewer_id, source, reviewed_at, expires_at,
             scope_hash, policy_hash, action_hash, context_hash, invalidated_at
           FROM action_reviews WHERE id = ?`,
        )
        .get(partial.reviewId) as {
          id: string;
          decision: string;
          reviewer_id: string;
          source: string;
          reviewed_at: string;
          expires_at: string;
          scope_hash: string;
          policy_hash: string;
          action_hash: string;
          context_hash: string;
          invalidated_at: string | null;
        };
      expect(review.decision).toBe("approved");
      expect(review.reviewer_id).toBe("alice@example");
      expect(review.source).toBe("human");
      expect(review.reviewed_at).toBeTruthy();
      expect(review.expires_at).toBe("2000-01-01T00:00:00.000Z");
      expect(review.invalidated_at).toBeNull();
      expect(review.scope_hash).toBe(partial.scopeHash);
      expect(review.policy_hash).toBe(partial.policyHash);
      expect(review.action_hash).toBe(partial.actionHash);
      expect(review.context_hash).toBe(partial.contextHash);
    } finally {
      db.close();
    }
  });

  it("demotes the incomplete-binding action to pending and clears every P0.2 field actually seeded; the complete-binding action is untouched", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      // ---- Incomplete action must be pending with every seeded stale
      // P0.2 field cleared to NULL. The migration must not infer an
      // active review from the (stale) active_review_id pointer.
      const STALE_COLS = [
        "active_review_id",
        "execution_token",
        "execution_owner",
        "lease_expires_at",
        "started_at",
        "dispatch_started_at",
        "finished_at",
        "outcome_certainty",
        "planned_scope_hash",
        "planned_policy_hash",
        "planned_action_hash",
        "planned_context_hash",
      ] as const;
      const stale = db
        .prepare(`SELECT status, ${STALE_COLS.join(", ")} FROM actions WHERE id = ?`)
        .get(partial.staleActionId) as { status: string } & Record<(typeof STALE_COLS)[number], string | null>;
      expect(stale.status).toBe("pending");
      for (const col of STALE_COLS) {
        expect(stale[col], `stale ${col} cleared`).toBeNull();
      }
      // No review row must exist that points at the stale action with
      // a complete binding; the migration must not have fabricated one.
      const fabReview = db
        .prepare(
          "SELECT 1 AS hit FROM action_reviews WHERE action_id = ? AND invalidated_at IS NULL",
        )
        .get(partial.staleActionId) as { hit: number } | undefined;
      expect(fabReview).toBeUndefined();

      // ---- Complete action must still be approved with its real active
      // review pointer; the second action's demotion must not have
      // touched it.
      const ok = db
        .prepare(
          "SELECT status, active_review_id FROM actions WHERE id = ?",
        )
        .get(partial.actionId) as { status: string; active_review_id: string | null };
      expect(ok.status).toBe("approved");
      expect(ok.active_review_id).toBe(partial.reviewId);

      const okReview = db
        .prepare(
          `SELECT decision, invalidated_at, scope_hash, policy_hash, action_hash, context_hash
           FROM action_reviews WHERE id = ?`,
        )
        .get(partial.reviewId) as {
          decision: string;
          invalidated_at: string | null;
          scope_hash: string;
          policy_hash: string;
          action_hash: string;
          context_hash: string;
        };
      expect(okReview.decision).toBe("approved");
      expect(okReview.invalidated_at).toBeNull();
      expect(okReview.scope_hash).toBe(partial.scopeHash);
      expect(okReview.policy_hash).toBe(partial.policyHash);
      expect(okReview.action_hash).toBe(partial.actionHash);
      expect(okReview.context_hash).toBe(partial.contextHash);
    } finally {
      db.close();
    }
  });

  it.each(INVALID_COMPLETE_BINDING_MUTATIONS)(
    "demotes an otherwise complete approved action when %s",
    (_label, mutationSql) => {
      const raw = new DatabaseSync(dbFile);
      let reviewBefore: Record<string, unknown>;
      try {
        raw.prepare(mutationSql).run(partial.reviewId);
        raw
          .prepare(
            `UPDATE actions SET execution_token = 'invalid-review-token', execution_owner = 'invalid-review-owner',
              lease_expires_at = '2099-12-31T23:59:59.000Z', started_at = '2026-01-01T00:00:01.000Z',
              dispatch_started_at = '2026-01-01T00:00:02.000Z', finished_at = '2026-01-01T00:00:03.000Z',
              outcome_certainty = 'possibly_dispatched' WHERE id = ?`,
          )
          .run(partial.actionId);
        reviewBefore = raw.prepare("SELECT * FROM action_reviews WHERE id = ?").get(partial.reviewId) as Record<
          string,
          unknown
        >;
      } finally {
        raw.close();
      }

      const db = openBountyDatabase(dbFile);
      try {
        runMigrations(db);
        const action = db
          .prepare(
            `SELECT status, active_review_id, updated_at,
              planned_scope_hash, planned_policy_hash, planned_action_hash, planned_context_hash,
              execution_token, execution_owner, lease_expires_at, started_at,
              dispatch_started_at, finished_at, outcome_certainty
             FROM actions WHERE id = ?`,
          )
          .get(partial.actionId) as Record<string, string | null>;
        expect(action.status).toBe("pending");
        expect(action.updated_at).toBeTruthy();
        for (const field of [
          "active_review_id",
          "planned_scope_hash",
          "planned_policy_hash",
          "planned_action_hash",
          "planned_context_hash",
          "execution_token",
          "execution_owner",
          "lease_expires_at",
          "started_at",
          "dispatch_started_at",
          "finished_at",
          "outcome_certainty",
        ]) {
          expect(action[field], `${field} cleared for invalid binding`).toBeNull();
        }
        const reviewAfter = db.prepare("SELECT * FROM action_reviews WHERE id = ?").get(partial.reviewId) as Record<
          string,
          unknown
        >;
        expect(reviewAfter).toEqual(reviewBefore);
      } finally {
        db.close();
      }
    },
  );
});

describe("P0.2 Packet 1 — migration audit semantic contract", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "audit-semantic.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  interface AuditWorkflowRow {
    id: string;
    job_id: string;
    sequence: number;
    phase: string;
    status: string;
    message: string;
    metadata_json: string | null;
    created_at: string;
  }

  function auditRows(db: BountyDatabase): AuditWorkflowRow[] {
    return db
      .prepare("SELECT * FROM workflow_events WHERE phase = 'migration' ORDER BY id ASC")
      .all() as unknown as AuditWorkflowRow[];
  }

  function fullV1State(db: BountyDatabase): Record<string, unknown> {
    return {
      userVersion: userVersion(db),
      schema: schemaObjects(db),
      history: db.prepare("SELECT * FROM schema_migrations ORDER BY version ASC").all(),
      findings: fullRows(db, "findings", "id"),
      evidenceArtifacts: fullRows(db, "evidence_artifacts", "id"),
      findingCandidates: fullRows(db, "finding_candidates", "id"),
      jobs: fullRows(db, "jobs", "id"),
      actions: fullRows(db, "actions", "id"),
      reconObservations: fullRows(db, "recon_observations", "id"),
      actionReviews: fullRows(db, "action_reviews", "id"),
      crawlPages: fullRows(db, "crawl_pages", "url"),
      crawlEdges: fullRows(db, "crawl_edges", "id"),
      workflowEvents: fullRows(db, "workflow_events", "id"),
    };
  }

  // The kind and schema version are fixed protocol identifiers. Count-key
  // spelling remains implementation-neutral, but there must be exactly three
  // aggregate integer counters and no other metadata values.
  it("legacy change yields exactly one migration audit with strict metadata contract", () => {
    buildLegacyDatabase(dbFile);
    const fixture = seedLegacyDatabase(dbFile);

    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);
      const rows = auditRows(db);
      expect(rows).toHaveLength(1);
      const row = rows[0];
      const realJobIds = new Set(Object.values(fixture.jobIds));

      expect(row.id).toBe("migration-v2-audit");
      expect(row.job_id).toBe("__bountypilot_migrations__");
      expect(realJobIds.has(row.job_id), "audit must use a reserved non-product job id").toBe(false);
      expect(row.sequence).toBe(1);
      expect(row.phase).toBe("migration");
      expect(row.status).toBe("completed");
      expect(row.message).toBe("P0.2 migration applied");
      expect(Number.isFinite(Date.parse(row.created_at))).toBe(true);

      const fixtureIdentifiers = [
        ...Object.values(fixture.jobIds),
        ...Object.values(fixture.actionIds),
        ...Object.values(fixture.reviewIds),
        ...fixture.findingIds,
        ...fixture.evidenceArtifactIds,
        ...fixture.findingCandidateIds,
        ...fixture.reconObservationIds,
        ...fixture.crawlPageUrls,
        ...fixture.crawlEdgeIds,
      ];
      for (const identifier of fixtureIdentifiers) {
        expect(row.message, `audit message leaked fixture identifier ${identifier}`).not.toContain(identifier);
      }

      expect(row.metadata_json).not.toBeNull();
      expect(row.metadata_json!.length).toBeLessThan(512);
      const parsed = JSON.parse(row.metadata_json!) as unknown;
      expect(parsed).not.toBeNull();
      expect(Array.isArray(parsed)).toBe(false);
      expect(typeof parsed).toBe("object");
      const meta = parsed as Record<string, unknown>;
      expect(meta.kind).toBe("p0_2_migration_audit");
      expect(meta.migrationVersion).toBe(2);

      const remainingKeys = Object.keys(meta).filter(
        (key) => key !== "kind" && key !== "migrationVersion",
      );
      expect(remainingKeys).toHaveLength(3);
      const countValues: number[] = [];
      for (const key of remainingKeys) {
        expect(key).toMatch(/^[A-Za-z][A-Za-z0-9_]{0,63}$/);
        const value = meta[key];
        expect(typeof value, `metadata.${key} must be a number`).toBe("number");
        expect(Number.isInteger(value), `metadata.${key} must be an integer`).toBe(true);
        expect(value as number, `metadata.${key} must be nonnegative`).toBeGreaterThanOrEqual(0);
        countValues.push(value as number);
      }
      expect(countValues.sort((a, b) => a - b)).toEqual([1, 1, 1]);

      // Explicit canaries cover partial target/path/hash/secret fragments, not
      // merely full fixture IDs. They must not appear anywhere in the stored
      // audit row (id, reserved job id, message, metadata keys, or values).
      const serializedAudit = JSON.stringify(row).toLowerCase();
      for (const canary of [
        "dup.example",
        "/tmp/ev-1.html",
        "dup-content-hash",
        "clean-content-hash",
        "legacy row",
        "token-a",
        "scope_hash",
        "policy_hash",
        "action_hash",
        "context_hash",
      ]) {
        expect(serializedAudit, `audit leaked canary ${canary}`).not.toContain(canary);
      }
    } finally {
      db.close();
    }
  });

  it.each([
    {
      label: "the fixed audit id is occupied by a product event",
      id: "migration-v2-audit",
      jobId: "job-clean",
      sequence: 99,
    },
    {
      label: "the reserved audit job/sequence slot is occupied by a product event",
      id: "legacy-reserved-audit-slot",
      jobId: "__bountypilot_migrations__",
      sequence: 1,
    },
    {
      label: "the reserved audit job namespace is occupied outside sequence one",
      id: "legacy-reserved-audit-namespace",
      jobId: "__bountypilot_migrations__",
      sequence: 5,
    },
  ])("fails closed without replacing or ignoring data when $label", ({ id, jobId, sequence }) => {
    buildLegacyDatabase(dbFile);
    seedLegacyDatabase(dbFile);

    const seed = new DatabaseSync(dbFile);
    let before!: Record<string, unknown>;
    try {
      seed.exec(`
        CREATE TABLE schema_migrations (
          version INTEGER PRIMARY KEY,
          name TEXT NOT NULL UNIQUE,
          applied_at TEXT NOT NULL
        );
        INSERT INTO schema_migrations (version, name, applied_at)
        VALUES (1, 'legacy_baseline', '2026-01-01T00:00:00.000Z');
        PRAGMA user_version = 1;
      `);
      seed.prepare(
        `INSERT INTO workflow_events
          (id, job_id, sequence, phase, status, message, metadata_json, created_at)
         VALUES (?, ?, ?, 'recon', 'completed', 'legacy product event: preserve exactly', ?, ?)`,
      ).run(id, jobId, sequence, JSON.stringify({ product: true, secretCanary: "do-not-overwrite" }), "2026-01-02T00:00:00.000Z");
      before = fullV1State(seed);
    } finally {
      seed.close();
    }

    expectBountyError(() => openBountyDatabase(dbFile), "DB_SCHEMA_STATE_INVALID");

    const verify = new DatabaseSync(dbFile);
    try {
      verify.exec("PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
      expect(fullV1State(verify)).toEqual(before);
      expect(userVersion(verify)).toBe(1);
      expect(
        verify.prepare("SELECT version, name FROM schema_migrations ORDER BY version ASC").all(),
      ).toEqual([{ version: 1, name: "legacy_baseline" }]);
      for (const column of ACTIONS_V2_COLUMNS) {
        expect(columnsOf(verify, "actions").map((candidate) => candidate.name)).not.toContain(column);
      }
      expect(findUniqueIndexWithColumns(verify, "workflow_events", ["job_id", "sequence"])).toBeNull();
      expect(findPartialUniqueIndexWithColumns(verify, "actions", ["execution_token"])).toBeNull();
      expect(auditRows(verify)).toEqual([]);
    } finally {
      verify.close();
    }
  });

  it("reopen yields exact same audit row with no duplication", () => {
    buildLegacyDatabase(dbFile);
    seedLegacyDatabase(dbFile);

    const first = openBountyDatabase(dbFile);
    let firstAudit: AuditWorkflowRow;
    try {
      runMigrations(first);
      const rows = auditRows(first);
      expect(rows).toHaveLength(1);
      firstAudit = rows[0];
    } finally {
      first.close();
    }

    const second = openBountyDatabase(dbFile);
    try {
      runMigrations(second);
      const rows = auditRows(second);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toEqual(firstAudit);
    } finally {
      second.close();
    }
  });

  it("fresh DB yields zero migration audit events", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);
      const audit = db.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'").get() as { n: number };
      expect(audit.n).toBe(0);
    } finally {
      db.close();
    }
  });
});

describe("P0.2 Packet 1 — reopen idempotency", () => {
  let tempDir: string;
  let dbFile: string;
  let legacyFixture: LegacyFixture;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "idem.db");
    buildLegacyDatabase(dbFile);
    legacyFixture = seedLegacyDatabase(dbFile);
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  interface Snapshot {
    userVersion: number;
    schema: IndexRow[];
    migrations: Array<{ version: number; name: string; applied_at: string }>;
    // Full rows for every product table, in deterministic order. So a
    // second open cannot silently mutate data without being caught.
    actionRows: Array<Record<string, unknown>>;
    reviewRows: Array<Record<string, unknown>>;
    findingRows: Array<Record<string, unknown>>;
    evidenceRows: Array<Record<string, unknown>>;
    findingCandidateRows: Array<Record<string, unknown>>;
    reconRows: Array<Record<string, unknown>>;
    crawlPageRows: Array<Record<string, unknown>>;
    crawlEdgeRows: Array<Record<string, unknown>>;
    jobRows: Array<Record<string, unknown>>;
    // FIX 7: Include EVERY workflow_events row including the full
    // migration/audit row, not a filtered subset plus count. The second
    // open must deep-equal the first so audit id/message/metadata/created_at
    // cannot mutate or duplicate.
    workflowRows: Array<Record<string, unknown>>;
    indexNames: string[];
    auditCount: number;
  }

  function snapshot(db: BountyDatabase): Snapshot {
    return {
      userVersion: userVersion(db),
      schema: schemaObjects(db),
      migrations: db
        .prepare("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC")
        .all() as Array<{ version: number; name: string; applied_at: string }>,
      actionRows: db.prepare("SELECT * FROM actions ORDER BY id ASC").all() as Array<Record<string, unknown>>,
      reviewRows: db
        .prepare("SELECT * FROM action_reviews ORDER BY id ASC")
        .all() as Array<Record<string, unknown>>,
      findingRows: db.prepare("SELECT * FROM findings ORDER BY id ASC").all() as Array<Record<string, unknown>>,
      evidenceRows: db
        .prepare("SELECT * FROM evidence_artifacts ORDER BY id ASC")
        .all() as Array<Record<string, unknown>>,
      findingCandidateRows: db
        .prepare("SELECT * FROM finding_candidates ORDER BY id ASC")
        .all() as Array<Record<string, unknown>>,
      reconRows: db
        .prepare("SELECT * FROM recon_observations ORDER BY id ASC")
        .all() as Array<Record<string, unknown>>,
      crawlPageRows: db.prepare("SELECT * FROM crawl_pages ORDER BY url ASC").all() as Array<Record<string, unknown>>,
      crawlEdgeRows: db
        .prepare("SELECT * FROM crawl_edges ORDER BY id ASC")
        .all() as Array<Record<string, unknown>>,
      jobRows: db.prepare("SELECT * FROM jobs ORDER BY id ASC").all() as Array<Record<string, unknown>>,
      // FIX 7: Include ALL workflow_events rows, not filtered.
      workflowRows: db.prepare("SELECT * FROM workflow_events ORDER BY id ASC").all() as Array<Record<string, unknown>>,
      indexNames: schemaObjects(db)
        .filter((o) => /^CREATE\s+(UNIQUE\s+)?INDEX/i.test(o.sql ?? ""))
        .map((o) => o.name)
        .sort(),
      auditCount: (db
        .prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'")
        .get() as { n: number }).n,
    };
  }

  it("two opens of the same migrated DB produce deep-equal snapshots with no duplicate audit row", () => {
    const first = openBountyDatabase(dbFile);
    let snap1: Snapshot;
    try {
      runMigrations(first);
      snap1 = snapshot(first);
    } finally {
      first.close();
    }

    const second = openBountyDatabase(dbFile);
    let snap2: Snapshot;
    try {
      runMigrations(second);
      snap2 = snapshot(second);
    } finally {
      second.close();
    }

    expect(snap2).toEqual(snap1);
    expect(snap2.auditCount).toBe(1);
    expect(snap2.userVersion).toBe(CURRENT_SCHEMA_VERSION);
    expect(snap2.migrations.map((r) => r.version)).toEqual([1, 2]);
    expect(snap2.actionRows.length).toBe(6);
    expect(snap2.reviewRows.length).toBe(1);
    expect(snap2.findingRows.map((r) => r.id).sort()).toEqual(legacyFixture.findingIds.slice().sort());
    // FIX 7: The workflow rows must include the migration audit row.
    expect(snap2.workflowRows.length).toBe(legacyFixture.workflow.length + 1);
  });
});

describe("P0.2 Packet 1 — concurrent migration runners serialize before reading state", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "concurrent-migrations.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("two blocked runners apply each migration checkpoint exactly once in total", async () => {
    const blocker = new DatabaseSync(dbFile);
    blocker.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; BEGIN IMMEDIATE;");
    let lockHeld = true;
    const barrier = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    const moduleUrl = new URL("../src/stores/db/database.ts", import.meta.url).href;
    const workerSource = `
      const { parentPort, workerData } = require('node:worker_threads');
      const { DatabaseSync } = require('node:sqlite');
      const { tsImport } = require('tsx/esm/api');
      const barrier = new Int32Array(workerData.barrier);
      const send = (payload) => parentPort.postMessage(payload);
      function waitForStart() {
        const deadline = Date.now() + 5000;
        while (Atomics.load(barrier, 0) !== 1) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) throw new Error('migration start barrier timeout');
          Atomics.wait(barrier, 0, 0, Math.min(50, remaining));
        }
      }
      let db;
      (async () => {
        try {
          const { runMigrations } = await tsImport(workerData.moduleUrl, workerData.parentUrl);
          db = new DatabaseSync(workerData.dbFile);
          db.exec('PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
          let beginImmediateAttempted = false;
          const instrumentedDb = new Proxy(db, {
            get(target, property) {
              if (property === 'exec') {
                return (sql) => {
                  const statement = String(sql);
                  const isBeginImmediate = /(?:^|;)\\s*BEGIN\\s+IMMEDIATE\\b/i.test(statement);
                  const beforeBegin = !beginImmediateAttempted;
                  if (isBeginImmediate) beginImmediateAttempted = true;
                  send({ kind: 'sql', operation: 'exec', sql: statement, beforeBegin, isBeginImmediate });
                  return target.exec(statement);
                };
              }
              if (property === 'prepare') {
                return (sql) => {
                  const statement = String(sql);
                  send({
                    kind: 'sql',
                    operation: 'prepare',
                    sql: statement,
                    beforeBegin: !beginImmediateAttempted,
                    isBeginImmediate: false,
                  });
                  return target.prepare(statement);
                };
              }
              const value = Reflect.get(target, property, target);
              return typeof value === 'function' ? value.bind(target) : value;
            },
          });
          send({ kind: 'ready' });
          waitForStart();
          send({ kind: 'attempting' });
          if (typeof runMigrations !== 'function') throw new Error('runMigrations missing');
          runMigrations(instrumentedDb, {
            faultInjector: (checkpoint) => send({ kind: 'checkpoint', checkpoint }),
          });
          send({ kind: 'done' });
        } catch (error) {
          send({ kind: 'worker-error', message: error && error.message ? error.message : String(error) });
          process.exitCode = 1;
        } finally {
          if (db) {
            try { db.close(); } catch (_) { /* best effort */ }
          }
        }
      })();
    `;
    type WorkerMessage = {
      kind: string;
      checkpoint?: string;
      message?: string;
      operation?: "exec" | "prepare";
      sql?: string;
      beforeBegin?: boolean;
      isBeginImmediate?: boolean;
    };
    const states = [
      { messages: [] as WorkerMessage[], exitCode: null as number | null, error: null as string | null },
      { messages: [] as WorkerMessage[], exitCode: null as number | null, error: null as string | null },
    ];
    const workers = states.map((state) => {
      const worker = new Worker(workerSource, {
        eval: true,
        workerData: { barrier, dbFile, moduleUrl, parentUrl: import.meta.url },
      });
      worker.on("message", (message: WorkerMessage) => {
        state.messages.push(message);
        if (message.kind === "worker-error") state.error = message.message ?? "worker-error";
      });
      worker.on("error", (error) => {
        state.error = error.message;
      });
      worker.on("exit", (code) => {
        state.exitCode = code;
      });
      return worker;
    });
    const waitUntil = async (predicate: () => boolean, label: string, timeoutMs = 6000): Promise<void> => {
      const deadline = Date.now() + timeoutMs;
      while (!predicate()) {
        if (Date.now() >= deadline) throw new Error(`timeout waiting for ${label}`);
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    };

    try {
      await waitUntil(
        () => states.every((state) => state.messages.some((message) => message.kind === "ready")),
        "migration workers ready",
      );
      const view = new Int32Array(barrier);
      Atomics.store(view, 0, 1);
      Atomics.notify(view, 0, Infinity);
      await waitUntil(
        () => states.every((state) => state.messages.some((message) => message.kind === "attempting")),
        "both migration attempts",
      );

      // The proxy reports SQL immediately before invoking SQLite. Waiting for
      // both BEGIN IMMEDIATE attempts proves both workers have reached the
      // write-lock boundary and are synchronously blocked by `blocker`; this
      // is a deterministic barrier, not a scheduling delay.
      await waitUntil(
        () =>
          states.every((state) =>
            state.messages.some((message) => message.kind === "sql" && message.isBeginImmediate),
          ) || states.some((state) => state.error !== null || state.exitCode !== null),
        "both BEGIN IMMEDIATE attempts",
      );

      expect(
        states.some((state) => state.error !== null || state.exitCode !== null),
        `workers must reach BEGIN IMMEDIATE before either exits: ${JSON.stringify(states)}`,
      ).toBe(false);

      // No schema/history/version read or mutation may occur before the first
      // lock attempt. Harmless connection PRAGMAs were deliberately configured
      // before installing the proxy.
      const preLockSql = states.flatMap((state, workerIndex) =>
        state.messages
          .filter(
            (message) =>
              message.kind === "sql" && message.beforeBegin && !message.isBeginImmediate,
          )
          .map((message) => ({ workerIndex, operation: message.operation, sql: message.sql })),
      );
      expect(preLockSql).toEqual([]);

      blocker.exec("COMMIT");
      lockHeld = false;

      await waitUntil(() => states.every((state) => state.exitCode !== null), "migration workers exit", 10000);
      expect(states.map((state) => state.exitCode)).toEqual([0, 0]);
      expect(states.map((state) => state.error)).toEqual([null, null]);
      const checkpoints = states
        .flatMap((state) => state.messages)
        .filter((message) => message.kind === "checkpoint")
        .map((message) => message.checkpoint)
        .sort();
      expect(checkpoints).toEqual(["v1:after-user-version", "v2:after-user-version"]);
    } finally {
      if (lockHeld) {
        try {
          blocker.exec("ROLLBACK");
        } catch {
          // best effort cleanup
        }
      }
      try {
        blocker.close();
      } catch {
        // best effort cleanup
      }
      await Promise.all(workers.map(async (worker) => {
        try {
          await worker.terminate();
        } catch {
          // best effort cleanup
        }
      }));
    }

    // Verify through raw SQLite so this assertion cannot repair an incomplete
    // result by running openBountyDatabase a third time.
    const verify = new DatabaseSync(dbFile);
    try {
      verify.exec("PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
      expect(userVersion(verify)).toBe(2);
      const history = verify
        .prepare("SELECT version, name FROM schema_migrations ORDER BY version ASC")
        .all() as Array<{ version: number; name: string }>;
      expect(history.map((row) => row.version)).toEqual([1, 2]);
      expect(history[0].name).toBe("legacy_baseline");
      expect(history[1].name).toMatch(/^[A-Za-z0-9._:-]{1,80}$/);
      expect(
        (verify.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'").get() as { n: number }).n,
      ).toBe(0);
    } finally {
      verify.close();
    }
  }, 20000);
});

describe("P0.2 Packet 1 — v1 baseline is exact and atomic", () => {
  let tempDir: string;
  let dbFile: string;
  let referenceFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "v1-fault.db");
    referenceFile = path.join(tempDir, "v1-reference.db");
    buildLegacyDatabase(referenceFile);
  });
  afterEach(() => {
    cleanupDb(dbFile);
    cleanupDb(referenceFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("exposes the complete baseline only inside v1, then rolls DDL/history/user_version back together", () => {
    const reference = new DatabaseSync(referenceFile);
    const db = new DatabaseSync(dbFile);
    db.exec("PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
    const productTables = [
      "findings",
      "evidence_artifacts",
      "finding_candidates",
      "jobs",
      "actions",
      "recon_observations",
      "action_reviews",
      "crawl_pages",
      "crawl_edges",
      "workflow_events",
    ];
    const expectedIndexes = [
      "idx_finding_candidates_job_id",
      "idx_finding_candidates_status",
      "idx_finding_candidates_reportability",
      "idx_finding_candidates_finding_id",
      "idx_recon_observations_job_id",
      "idx_recon_observations_kind",
      "idx_recon_observations_source_adapter",
      "idx_action_reviews_action_id",
      "idx_action_reviews_job_id",
      "idx_workflow_events_job_sequence",
      "idx_workflow_events_created_at",
    ].sort();
    const sentinel = new Error("BTP-MIG-FAULT-V1-AFTER-USER-VERSION");
    let hit = false;
    let thrown: unknown;
    try {
      try {
        runMigrations(db, {
          faultInjector: (checkpoint) => {
            if (checkpoint !== "v1:after-user-version") return;
            hit = true;
            expect(userVersion(db)).toBe(1);
            const history = db
              .prepare("SELECT version, name FROM schema_migrations ORDER BY version ASC")
              .all() as Array<{ version: number; name: string }>;
            expect(history).toEqual([{ version: 1, name: "legacy_baseline" }]);
            const tables = (
              db
                .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
                .all() as Array<{ name: string }>
            ).map((row) => row.name);
            expect(tables).toEqual([...productTables, "schema_migrations"].sort());
            for (const table of productTables) {
              expect(columnsOf(db, table), `v1 ${table} must match the legacy baseline`).toEqual(
                columnsOf(reference, table),
              );
              expect(
                tableIndexContracts(db, table),
                `v1 ${table} indexes and PRIMARY/UNIQUE constraints must match the legacy baseline`,
              ).toEqual(tableIndexContracts(reference, table));
            }
            const indexes = (
              db
                .prepare("SELECT name FROM sqlite_schema WHERE type = 'index' AND name NOT LIKE 'sqlite_%' ORDER BY name")
                .all() as Array<{ name: string }>
            ).map((row) => row.name);
            expect(indexes).toEqual(expectedIndexes);
            throw sentinel;
          },
        });
      } catch (error) {
        thrown = error;
      }
      expect(hit).toBe(true);
      expect(thrown).toBe(sentinel);
      expect(userVersion(db)).toBe(0);
      const remainingObjects = db
        .prepare(
          "SELECT name FROM sqlite_schema WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .all() as Array<{ name: string }>;
      expect(remainingObjects).toEqual([]);
    } finally {
      reference.close();
      db.close();
    }

    const clean = openBountyDatabase(dbFile);
    try {
      expect(userVersion(clean)).toBe(2);
      expect(
        (clean.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'").get() as { n: number }).n,
      ).toBe(0);
    } finally {
      clean.close();
    }
  });

  it("adds legacy actions.metadata_json inside v1 and rolls that repair back with a v1 fault", () => {
    buildLegacyDatabase(dbFile);
    const strip = new DatabaseSync(dbFile);
    try {
      strip.exec("ALTER TABLE actions DROP COLUMN metadata_json");
    } finally {
      strip.close();
    }
    const fixture = seedLegacyDatabase(dbFile);

    const db = new DatabaseSync(dbFile);
    db.exec("PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
    const columnsBeforeMetadata = LEGACY_ACTION_COLUMNS.filter((column) => column !== "metadata_json");
    const rowsBefore = projectedRows(db, "actions", columnsBeforeMetadata, "id");
    const sentinel = new Error("BTP-MIG-FAULT-V1-METADATA-REPAIR");
    let hit = false;
    let thrown: unknown;
    try {
      try {
        runMigrations(db, {
          faultInjector: (checkpoint) => {
            if (checkpoint !== "v1:after-user-version") return;
            hit = true;
            expect(userVersion(db)).toBe(1);
            expect(
              db.prepare("SELECT version, name FROM schema_migrations ORDER BY version ASC").all(),
            ).toEqual([{ version: 1, name: "legacy_baseline" }]);
            const metadata = columnsOf(db, "actions").find((column) => column.name === "metadata_json");
            expect(metadata).toBeTruthy();
            expect(normalizeType(metadata!.type)).toBe("TEXT");
            expect(metadata!.notnull).toBe(0);
            expect(
              metadata!.dflt_value === null || normalizeDefault(metadata!.dflt_value).toUpperCase() === "NULL",
            ).toBe(true);
            const repairedRows = db
              .prepare("SELECT id, metadata_json FROM actions ORDER BY id ASC")
              .all() as Array<{ id: string; metadata_json: string | null }>;
            expect(repairedRows.map((row) => row.id).sort()).toEqual(Object.values(fixture.actionIds).sort());
            expect(repairedRows.every((row) => row.metadata_json === null)).toBe(true);
            throw sentinel;
          },
        });
      } catch (error) {
        thrown = error;
      }

      expect(hit).toBe(true);
      expect(thrown).toBe(sentinel);
      expect(userVersion(db)).toBe(0);
      expect(columnsOf(db, "actions").map((column) => column.name)).not.toContain("metadata_json");
      expect(
        db.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'").get(),
      ).toBeUndefined();
      expect(projectedRows(db, "actions", columnsBeforeMetadata, "id")).toEqual(rowsBefore);
    } finally {
      db.close();
    }

    const clean = openBountyDatabase(dbFile);
    try {
      expect(userVersion(clean)).toBe(2);
      const repairedRows = clean
        .prepare("SELECT id, metadata_json FROM actions ORDER BY id ASC")
        .all() as Array<{ id: string; metadata_json: string | null }>;
      expect(repairedRows.map((row) => row.id).sort()).toEqual(Object.values(fixture.actionIds).sort());
      expect(repairedRows.every((row) => row.metadata_json === null)).toBe(true);
    } finally {
      clean.close();
    }
  });
});

describe("P0.2 Packet 1 — fault injection at v2:after-user-version rolls back to v1", () => {
  let tempDir: string;
  let dbFile: string;
  let legacyFixture: LegacyFixture;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "fault.db");
    buildLegacyDatabase(dbFile);
    legacyFixture = seedLegacyDatabase(dbFile);
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  function openRawWithPragmas(file: string): BountyDatabase {
    const db = new DatabaseSync(file);
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
    `);
    return db;
  }

  function productSnapshot(db: BountyDatabase): Record<string, Array<Record<string, unknown>>> {
    return {
      findings: fullRows(db, "findings", "id"),
      evidence_artifacts: fullRows(db, "evidence_artifacts", "id"),
      finding_candidates: fullRows(db, "finding_candidates", "id"),
      jobs: fullRows(db, "jobs", "id"),
      actions: fullRows(db, "actions", "id"),
      recon_observations: fullRows(db, "recon_observations", "id"),
      action_reviews: fullRows(db, "action_reviews", "id"),
      crawl_pages: fullRows(db, "crawl_pages", "url"),
      crawl_edges: fullRows(db, "crawl_edges", "id"),
      workflow_events: fullRows(db, "workflow_events", "id"),
    };
  }

  it("injected sentinel at v2:after-user-version leaves DB at v1 with no v2 columns/indexes/audit; clean rerun reaches v2", () => {
    const SENTINEL = "BTP-MIG-FAULT-V2-AFTER-USER-VERSION";
    let hit = "";

    const first = openRawWithPragmas(dbFile);
    const before = productSnapshot(first);
    try {
      let threw: unknown;
      try {
        runMigrations(first, {
          faultInjector: (checkpoint) => {
            hit = checkpoint;
            if (checkpoint === "v2:after-user-version") {
              // The seam is meaningful only after every v2 DDL/data/index/
              // audit/history/version mutation is visible on this handle and
              // while the encompassing transaction is still open.
              expect(userVersion(first)).toBe(2);
              const history = first
                .prepare("SELECT version FROM schema_migrations ORDER BY version ASC")
                .all() as Array<{ version: number }>;
              expect(history.map((row) => row.version)).toEqual([1, 2]);
              const actionColumns = columnsOf(first, "actions");
              for (const column of ACTIONS_V2_COLUMNS) {
                assertColumn(actionColumns, "actions", column, "TEXT", { notNull: false });
              }
              assertColumn(actionColumns, "actions", "required_for_completion", "INTEGER", {
                notNull: true,
                defaultNumeric: 1,
              });
              const reviewColumns = columnsOf(first, "action_reviews");
              for (const column of ACTION_REVIEWS_V2_COLUMNS) {
                assertColumn(reviewColumns, "action_reviews", column, "TEXT", { notNull: false });
              }
              const jobColumns = columnsOf(first, "jobs");
              for (const column of JOBS_V2_COLUMNS) {
                assertColumn(jobColumns, "jobs", column, "TEXT", { notNull: false });
              }
              expect(findUniqueIndexWithColumns(first, "workflow_events", ["job_id", "sequence"])).not.toBeNull();
              expect(findPartialUniqueIndexWithColumns(first, "actions", ["execution_token"])).not.toBeNull();
              const statuses = first
                .prepare("SELECT id, status FROM actions WHERE id IN (?, ?) ORDER BY id ASC")
                .all(legacyFixture.actionIds.planned, legacyFixture.actionIds.approved) as Array<{
                id: string;
                status: string;
              }>;
              expect(statuses.every((row) => row.status === "pending")).toBe(true);
              const resequenced = first
                .prepare("SELECT id, sequence FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
                .all(legacyFixture.jobIds.dup) as Array<{ id: string; sequence: number }>;
              expect(resequenced).toEqual([
                { id: "we-D-3", sequence: 1 },
                { id: "we-D-1", sequence: 2 },
                { id: "we-D-2", sequence: 3 },
              ]);
              expect(
                (first.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'").get() as {
                  n: number;
                }).n,
              ).toBe(1);
              throw new Error(SENTINEL);
            }
          },
        });
      } catch (err) {
        threw = err;
      }
      expect(threw, "fault injector must propagate").toBeInstanceOf(Error);
      expect((threw as Error).message).toBe(SENTINEL);
      expect(hit).toBe("v2:after-user-version");

      // DB rolled back to v1.
      expect(userVersion(first)).toBe(1);

      // Only v1 migration row recorded.
      const mig = first
        .prepare("SELECT version FROM schema_migrations ORDER BY version ASC")
        .all() as Array<{ version: number }>;
      expect(mig.map((r) => r.version)).toEqual([1]);

      // No v2 actions columns.
      const actionCols = columnsOf(first, "actions").map((c) => c.name);
      for (const col of ACTIONS_V2_COLUMNS) {
        expect(actionCols, `legacy actions.${col} absent`).not.toContain(col);
      }
      const jobCols = columnsOf(first, "jobs").map((c) => c.name);
      for (const col of JOBS_V2_COLUMNS) {
        expect(jobCols, `legacy jobs.${col} absent`).not.toContain(col);
      }
      const reviewCols = columnsOf(first, "action_reviews").map((c) => c.name);
      for (const col of ACTION_REVIEWS_V2_COLUMNS) {
        expect(reviewCols, `legacy action_reviews.${col} absent`).not.toContain(col);
      }

      // Old non-unique workflow index is still present (no v2 unique
      // conversion). We assert the legacy index name and that no
      // unique index over (job_id, sequence) exists yet.
      const weSql = indexSql(first, "idx_workflow_events_job_sequence") ?? "";
      expect(weSql).toBeTruthy();
      expect(weSql).not.toMatch(/UNIQUE/i);
      const weUnique = findUniqueIndexWithColumns(first, "workflow_events", ["job_id", "sequence"]);
      expect(weUnique, "no workflow_events unique (job_id, sequence) index after rollback").toBeNull();
      const tokenIdx = findPartialUniqueIndexWithColumns(first, "actions", ["execution_token"]);
      expect(tokenIdx, "no actions partial unique (execution_token) index after rollback").toBeNull();

      // Zero migration audit event was written.
      const audit = (first
        .prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'")
        .get() as { n: number });
      expect(audit.n).toBe(0);

      // Legacy statuses and duplicate sequences are exactly as seeded.
      const statuses = (first
        .prepare("SELECT id, status FROM actions ORDER BY id ASC")
        .all() as Array<{ id: string; status: string }>);
      const expectedStatuses: Record<string, string> = {
        [legacyFixture.actionIds.planned]: "planned",
        [legacyFixture.actionIds.approved]: "approved",
        [legacyFixture.actionIds.executed]: "executed",
        [legacyFixture.actionIds.blocked]: "blocked",
        [legacyFixture.actionIds.failed]: "failed",
        [legacyFixture.actionIds.pending]: "pending",
      };
      expect(statuses.length).toBe(6);
      for (const row of statuses) {
        expect(row.status, `legacy status preserved for ${row.id}`).toBe(expectedStatuses[row.id]);
      }

      const dupSeqs = (first
        .prepare("SELECT sequence FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC, id ASC")
        .all(legacyFixture.jobIds.dup) as Array<{ sequence: number }>).map((r) => r.sequence);
      expect(dupSeqs).toEqual([1, 1, 2]);
      expect(productSnapshot(first)).toEqual(before);
    } finally {
      first.close();
    }

    // Clean open on the same file must reach v2 with no fault.
    const second = openBountyDatabase(dbFile);
    try {
      runMigrations(second);
      expect(userVersion(second)).toBe(CURRENT_SCHEMA_VERSION);
      const mig = (second
        .prepare("SELECT version FROM schema_migrations ORDER BY version ASC")
        .all() as Array<{ version: number }>).map((r) => r.version);
      expect(mig).toEqual([1, 2]);
      const audit = (second
        .prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE phase = 'migration'")
        .get() as { n: number }).n;
      expect(audit).toBe(1);
    } finally {
      second.close();
    }
  });
});

describe("P0.2 Packet 1 — unsupported / inconsistent schema state fails closed", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "failclosed.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  function rawWithPragmas(file: string): BountyDatabase {
    const db = new DatabaseSync(file);
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
    `);
    return db;
  }

  function seedFullyMigratedDatabase(): void {
    buildLegacyDatabase(dbFile);
    seedLegacyDatabase(dbFile);
    const seed = openBountyDatabase(dbFile);
    try {
      runMigrations(seed);
      expect(userVersion(seed)).toBe(2);
    } finally {
      seed.close();
    }
  }

  function migratedStateSnapshot(db: BountyDatabase): Record<string, unknown> {
    return {
      userVersion: userVersion(db),
      schema: schemaObjects(db),
      history: db.prepare("SELECT * FROM schema_migrations ORDER BY version ASC").all(),
      findings: fullRows(db, "findings", "id"),
      evidenceArtifacts: fullRows(db, "evidence_artifacts", "id"),
      findingCandidates: fullRows(db, "finding_candidates", "id"),
      jobs: fullRows(db, "jobs", "id"),
      actions: fullRows(db, "actions", "id"),
      reconObservations: fullRows(db, "recon_observations", "id"),
      actionReviews: fullRows(db, "action_reviews", "id"),
      crawlPages: fullRows(db, "crawl_pages", "url"),
      crawlEdges: fullRows(db, "crawl_edges", "id"),
      workflowEvents: fullRows(db, "workflow_events", "id"),
    };
  }

  it("future user_version is rejected with DB_SCHEMA_VERSION_UNSUPPORTED and no writes", () => {
    const SENTINEL_TABLE = "btp_future_user_version_marker";
    const SENTINEL_ROW = "keep-me";
    const FUTURE_VERSION = 99;

    let beforeState!: Record<string, unknown>;
    const raw = rawWithPragmas(dbFile);
    try {
      raw.exec(`CREATE TABLE ${SENTINEL_TABLE} (id TEXT PRIMARY KEY, note TEXT)`);
      raw.prepare(`INSERT INTO ${SENTINEL_TABLE} (id, note) VALUES (?, ?)`).run(SENTINEL_ROW, "alive");
      raw.exec(`PRAGMA user_version = ${FUTURE_VERSION}`);
      beforeState = {
        userVersion: userVersion(raw),
        schema: raw
          .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type ASC, name ASC")
          .all(),
        sentinelRows: raw.prepare(`SELECT * FROM ${SENTINEL_TABLE} ORDER BY id ASC`).all(),
      };
    } finally {
      raw.close();
    }

    const err = expectBountyError(() => openBountyDatabase(dbFile), "DB_SCHEMA_VERSION_UNSUPPORTED");
    expect(err.message).toBeTruthy();

    // Open with raw sqlite and deep-compare every pre-existing schema object
    // (including sqlite_autoindex entries) plus all sentinel rows. Product
    // DDL created before rejection cannot hide behind a shallow canary check.
    const verify = rawWithPragmas(dbFile);
    try {
      expect({
        userVersion: userVersion(verify),
        schema: verify
          .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type ASC, name ASC")
          .all(),
        sentinelRows: verify.prepare(`SELECT * FROM ${SENTINEL_TABLE} ORDER BY id ASC`).all(),
      }).toEqual(beforeState);
    } finally {
      verify.close();
    }
  });

  it("inconsistent user_version / schema_migrations state is rejected with DB_SCHEMA_STATE_INVALID", () => {
    seedFullyMigratedDatabase();

    // Tamper: delete the v2 schema_migrations row while keeping user_version
    // at 2. This simulates inconsistent state from a partial external write.
    const tamper = rawWithPragmas(dbFile);
    try {
      const before = (tamper
        .prepare("SELECT COUNT(*) AS n FROM schema_migrations")
        .get() as { n: number }).n;
      expect(before).toBe(2);
      tamper.prepare("DELETE FROM schema_migrations WHERE version = 2").run();
      expect(userVersion(tamper)).toBe(CURRENT_SCHEMA_VERSION);
    } finally {
      tamper.close();
    }

    // Snapshot schema/data before reopen, so we can assert no further
    // changes are made on the fail-closed reopen.
    const snapBefore = rawWithPragmas(dbFile);
    let beforeState: Record<string, unknown>;
    try {
      beforeState = migratedStateSnapshot(snapBefore);
    } finally {
      snapBefore.close();
    }

    expectBountyError(() => openBountyDatabase(dbFile), "DB_SCHEMA_STATE_INVALID");

    // Reopen with raw sqlite: no further schema/data/migration-row change.
    const verify = rawWithPragmas(dbFile);
    try {
      expect(migratedStateSnapshot(verify)).toEqual(beforeState);
    } finally {
      verify.close();
    }
  });

  it.each([
    ["v1 history row is missing but v2 remains", 2, "DELETE FROM schema_migrations WHERE version = 1"],
    ["the pinned v1 migration name is changed", 2, "UPDATE schema_migrations SET name = 'tampered' WHERE version = 1"],
    [
      "the registered v2 migration name is changed",
      2,
      "UPDATE schema_migrations SET name = name || '__externally_tampered__' WHERE version = 2",
    ],
    ["history is ahead of user_version", 1, "PRAGMA user_version = 1"],
    [
      "history contains an extra future migration row",
      2,
      "INSERT INTO schema_migrations (version, name, applied_at) VALUES (3, 'future_external', '2099-01-01T00:00:00.000Z')",
    ],
  ])("rejects %s without mutating any state", (_label, expectedUserVersion, tamperSql) => {
    seedFullyMigratedDatabase();
    const tamper = rawWithPragmas(dbFile);
    let beforeState: Record<string, unknown>;
    try {
      tamper.exec(tamperSql);
      expect(userVersion(tamper)).toBe(expectedUserVersion);
      beforeState = migratedStateSnapshot(tamper);
    } finally {
      tamper.close();
    }

    expectBountyError(() => openBountyDatabase(dbFile), "DB_SCHEMA_STATE_INVALID");

    const verify = rawWithPragmas(dbFile);
    try {
      expect(migratedStateSnapshot(verify)).toEqual(beforeState);
    } finally {
      verify.close();
    }
  });
});

// =========================================================================
// PART 2 — remaining contract tests (TODO)
// =========================================================================

// FIX 9: Partial-unique execution_token contract. Introspect a unique partial
// index whose only column is execution_token and whose normalized SQL predicate
// is WHERE execution_token IS NOT NULL. Behavior: two NULL tokens succeed;
// two distinct non-null tokens succeed; duplicate non-null insert fails with
// SQLite constraint errcode 2067; original token owner/row is unchanged and
// duplicate row is absent.
describe("P0.2 Packet 1 — partial-unique execution_token contract", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "token-unique.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("allows many NULL tokens, rejects duplicate non-NULL tokens", () => {
    const db = openBountyDatabase(dbFile);
    try {
      runMigrations(db);

      const tokenIndex = findPartialUniqueIndexWithColumns(db, "actions", ["execution_token"]);
      expect(tokenIndex, "actions must have a one-column partial unique token index").not.toBeNull();
      const normalizedIndexSql = (indexSql(db, tokenIndex!.name) ?? "")
        .replace(/["`\[\]]/g, "")
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase();
      const whereParts = normalizedIndexSql.split(" where ");
      expect(whereParts).toHaveLength(2);
      expect(whereParts[1]).toBe("execution_token is not null");

      // Insert first action with NULL token (default).
      db.prepare(
        "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run("act-null-1", null, "http", "GET", "https://null1.example", "low", 0, "pending", "2026-01-01T00:00:00.000Z");

      // Insert second action with NULL token.
      db.prepare(
        "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run("act-null-2", null, "http", "GET", "https://null2.example", "low", 0, "pending", "2026-01-01T00:00:00.000Z");

      // Two NULL tokens should succeed.
      const nullCount = (db.prepare("SELECT COUNT(*) AS n FROM actions WHERE execution_token IS NULL").get() as { n: number }).n;
      expect(nullCount).toBe(2);

      // Insert first action with non-NULL token.
      db.prepare(
        "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at, execution_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run("act-token-a", null, "http", "GET", "https://token-a.example", "low", 0, "pending", "2026-01-01T00:00:00.000Z", "token-A");

      // Insert second action with different non-NULL token.
      db.prepare(
        "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at, execution_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run("act-token-b", null, "http", "GET", "https://token-b.example", "low", 0, "pending", "2026-01-01T00:00:00.000Z", "token-B");

      // Two distinct non-NULL tokens should succeed.
      const tokenCount = (db.prepare("SELECT COUNT(*) AS n FROM actions WHERE execution_token IS NOT NULL").get() as { n: number }).n;
      expect(tokenCount).toBe(2);

      // Attempt to insert duplicate non-NULL token.
      let thrown: unknown;
      try {
        db.prepare(
          "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, created_at, execution_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run("act-token-c", null, "http", "GET", "https://token-c.example", "low", 0, "pending", "2026-01-01T00:00:00.000Z", "token-A");
      } catch (error: unknown) {
        thrown = error;
      }
      expect(thrown, "duplicate non-NULL execution_token must be rejected").toBeInstanceOf(Error);
      expect((thrown as Error & { errcode?: number }).errcode).toBe(2067);

      // Both successful token owners remain byte-for-byte bound to their
      // original values; the failed statement creates no row.
      const owners = db
        .prepare(
          "SELECT id, execution_token FROM actions WHERE id IN ('act-token-a', 'act-token-b') ORDER BY id ASC",
        )
        .all() as Array<{ id: string; execution_token: string }>;
      expect(owners).toEqual([
        { id: "act-token-a", execution_token: "token-A" },
        { id: "act-token-b", execution_token: "token-B" },
      ]);

      // Duplicate row is absent.
      const dupExists = db.prepare("SELECT 1 AS hit FROM actions WHERE id = ?").get("act-token-c") as { hit: number } | undefined;
      expect(dupExists).toBeUndefined();
    } finally {
      db.close();
    }
  });
});

// FIX 10: TypeScript-AST import/boundary/synchronous-source contract scanning
// src/stores/db/database.ts plus src/stores/db/migrations.ts and/or recursively
// src/stores/db/migrations/**. Missing required migration source is an
// intentional RED assertion, not a fixture crash. Detect static imports,
// export-from declarations, literal dynamic import calls, and literal require
// calls; reject nonliteral dynamic import/require. Resolve relative imports
// and allow them only when the resolved source stays under src/stores/db/** or
// src/utils/**. Forbid network/process/worker/IPC/MCP/adapter dependencies
// including node:http, node:https, node:http2, node:net, node:dgram, node:dns,
// node:child_process, node:worker_threads, undici, got, axios, playwright,
// puppeteer, electron and obvious IPC/MCP packages. Use AST nodes, not
// substring scans of comments/string prose. Also reject any AST identifier or
// property named isTransaction, every AwaitExpression, every async function,
// and every fetch call. Avoid false positives from ordinary words such as
// internet in comments. Import TypeScript from the project dependency.
describe("P0.2 Packet 1 — TypeScript AST import/boundary contract", () => {
  let tempDir: string;
  let dbFile: string;
  beforeEach(() => {
    tempDir = makeTempDir();
    dbFile = path.join(tempDir, "ast-import.db");
  });
  afterEach(() => {
    cleanupDb(dbFile);
    rmSync(tempDir, { recursive: true, force: true });
  });

  function scanFileForViolations(
    filePath: string,
    discoveredDependencies: Set<string> = new Set<string>(),
  ): string[] {
    const violations: string[] = [];

    // Read the source file.
    let sourceFile: ts.SourceFile;
    try {
      const sourceText = readFileSync(filePath, "utf8");
      sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true);
    } catch {
      // If file doesn't exist, we'll handle it below.
      return [`FILE_NOT_FOUND: ${filePath}`];
    }

    // Forbidden imports/modules.
    const FORBIDDEN_MODULES = new Set([
      "node:http",
      "node:https",
      "node:http2",
      "node:net",
      "node:dgram",
      "node:dns",
      "node:tls",
      "node:process",
      "node:module",
      "node:vm",
      "node:child_process",
      "node:worker_threads",
      "http",
      "https",
      "http2",
      "net",
      "dgram",
      "dns",
      "tls",
      "process",
      "module",
      "vm",
      "child_process",
      "worker_threads",
      "undici",
      "got",
      "axios",
      "playwright",
      "puppeteer",
      "electron",
      // MCP/IPC adapters.
      "@modelcontextprotocol/server",
      "@modelcontextprotocol/sdk",
      "@modelcontextprotocol",
      "mcp-sdk",
      "mcp",
      "node-ipc",
      "@achrinza/node-ipc",
      "ipc",
      "adapter",
    ]);
    const ALLOWED_EXTERNAL_MODULES = new Set([
      "node:crypto",
      "node:fs",
      "node:path",
      "node:sqlite",
    ]);

    // Helper to resolve relative imports.
    function resolveRelative(specifier: string, basePath: string): string {
      if (!specifier.startsWith(".")) return specifier;
      let resolved = path.resolve(path.dirname(basePath), specifier);
      // Add .ts or .js extension if missing.
      if (!resolved.endsWith(".ts") && !resolved.endsWith(".js")) {
        if (existsSync(resolved + ".ts")) resolved += ".ts";
        else if (existsSync(resolved + ".js")) resolved += ".js";
      }
      return resolved;
    }

    function existingTypeScriptSource(resolvedSpecifier: string): string | null {
      const extension = path.extname(resolvedSpecifier).toLowerCase();
      const withoutJsExtension = [".js", ".mjs", ".cjs"].includes(extension)
        ? resolvedSpecifier.slice(0, -extension.length)
        : resolvedSpecifier;
      const candidates = [
        resolvedSpecifier,
        `${withoutJsExtension}.ts`,
        `${withoutJsExtension}.tsx`,
        path.join(withoutJsExtension, "index.ts"),
        path.join(withoutJsExtension, "index.tsx"),
      ];
      for (const candidate of [...new Set(candidates)]) {
        if (existsSync(candidate) && statSync(candidate).isFile()) {
          return path.resolve(candidate);
        }
      }
      return null;
    }

    // Check if a path is allowed (must be under src/stores/db or src/utils).
    function isAllowedPath(candidate: string): boolean {
      const resolved = path.resolve(candidate);
      return [path.resolve("src/stores/db"), path.resolve("src/utils")].some((root) => {
        const relative = path.relative(root, resolved);
        return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
      });
    }

    function checkSpecifier(spec: string, kind: string): void {
      const normalized = spec.toLowerCase();
      if (spec.startsWith(".")) {
        const resolved = resolveRelative(spec, filePath);
        if (!isAllowedPath(resolved)) {
          violations.push(`ESCAPED_${kind}: ${spec} resolves to ${resolved}`);
          return;
        }
        const dependency = existingTypeScriptSource(resolved);
        if (!dependency) {
          violations.push(`UNRESOLVED_${kind}: ${spec} from ${filePath}`);
          return;
        }
        discoveredDependencies.add(dependency);
        return;
      }
      for (const forbidden of FORBIDDEN_MODULES) {
        if (normalized === forbidden || normalized.startsWith(`${forbidden}/`)) {
          violations.push(`FORBIDDEN_${kind}: ${spec} in ${filePath}`);
          return;
        }
      }
      if (!ALLOWED_EXTERNAL_MODULES.has(normalized)) {
        violations.push(`UNAPPROVED_EXTERNAL_${kind}: ${spec} in ${filePath}`);
      }
    }

    // Walk the AST.
    function visit(node: ts.Node): void {
      // Check ImportDeclaration (static imports).
      if (ts.isImportDeclaration(node)) {
        const moduleSpec = node.moduleSpecifier;
        if (ts.isStringLiteral(moduleSpec)) {
          const spec = moduleSpec.text;
          checkSpecifier(spec, "IMPORT");
        }
      }

      // Check ExportDeclaration with named exports (export { ... } from "...").
      if (ts.isExportDeclaration(node)) {
        if (node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
          const spec = node.moduleSpecifier.text;
          checkSpecifier(spec, "EXPORT_FROM");
        }
      }

      if (
        ts.isImportEqualsDeclaration(node) &&
        ts.isExternalModuleReference(node.moduleReference) &&
        node.moduleReference.expression
      ) {
        const expression = node.moduleReference.expression;
        if (ts.isStringLiteralLike(expression)) {
          checkSpecifier(expression.text, "IMPORT_EQUALS");
        } else {
          violations.push(`NONLITERAL_IMPORT_EQUALS: in ${filePath}`);
        }
      }

      // Check for literal dynamic import() calls.
      // TypeScript represents import() as a CallExpression whose expression
      // node has SyntaxKind.ImportKeyword (it is not an Identifier).
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        if (node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0])) {
          const spec = (node.arguments[0] as ts.StringLiteral).text;
          checkSpecifier(spec, "DYNAMIC_IMPORT");
        } else {
          // Non-literal dynamic imports are forbidden.
          violations.push(`NONLITERAL_DYNAMIC_IMPORT: in ${filePath}`);
        }
      }

      // Check for literal require() calls.
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
        if (node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0])) {
          const spec = (node.arguments[0] as ts.StringLiteral).text;
          checkSpecifier(spec, "REQUIRE");
        } else {
          // Non-literal require is forbidden.
          violations.push(`NONLITERAL_REQUIRE: in ${filePath}`);
        }
      }

      // Check for isTransaction identifier or property.
      if (ts.isIdentifier(node) && node.text === "isTransaction") {
        violations.push(`FORBIDDEN_IDENTIFIER: isTransaction in ${filePath}`);
      }
      if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.name) && node.name.text === "isTransaction") {
        violations.push(`FORBIDDEN_PROPERTY: isTransaction in ${filePath}`);
      }
      if (
        ts.isElementAccessExpression(node) &&
        node.argumentExpression &&
        ts.isStringLiteralLike(node.argumentExpression) &&
        node.argumentExpression.text === "isTransaction"
      ) {
        violations.push(`FORBIDDEN_ELEMENT_ACCESS: isTransaction in ${filePath}`);
      }

      if (
        ts.isIdentifier(node) &&
        ["fetch", "eval", "Function", "WebSocket", "process", "require", "getBuiltinModule"].includes(node.text)
      ) {
        violations.push(`FORBIDDEN_RUNTIME_GLOBAL: ${node.text} in ${filePath}`);
      }
      if (
        ts.isElementAccessExpression(node) &&
        node.argumentExpression &&
        ts.isStringLiteralLike(node.argumentExpression) &&
        ["fetch", "eval", "Function", "WebSocket", "process", "require", "getBuiltinModule"].includes(
          node.argumentExpression.text,
        )
      ) {
        violations.push(`FORBIDDEN_RUNTIME_ELEMENT: ${node.argumentExpression.text} in ${filePath}`);
      }

      // Check for AwaitExpression.
      if (ts.isAwaitExpression(node)) {
        violations.push(`FORBIDDEN_AWAIT: await expression in ${filePath}`);
      }
      if (ts.isForOfStatement(node) && node.awaitModifier) {
        violations.push(`FORBIDDEN_FOR_AWAIT: in ${filePath}`);
      }

      // Check for async functions.
      if (
        ts.isFunctionLike(node) &&
        ts.canHaveModifiers(node) &&
        ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
      ) {
        violations.push(`FORBIDDEN_ASYNC_FUNCTION: async function in ${filePath}`);
      }

      // Check for fetch calls (direct calls to fetch).
      if (ts.isCallExpression(node)) {
        const expr = node.expression;
        if (
          (ts.isIdentifier(expr) && expr.text === "fetch") ||
          (ts.isPropertyAccessExpression(expr) && expr.name.text === "fetch")
        ) {
          violations.push(`FORBIDDEN_FETCH: fetch call in ${filePath}`);
        }
        if (
          (ts.isPropertyAccessExpression(expr) && expr.name.text === "require") ||
          (ts.isElementAccessExpression(expr) &&
            expr.argumentExpression &&
            ts.isStringLiteralLike(expr.argumentExpression) &&
            ["fetch", "require", "getBuiltinModule"].includes(expr.argumentExpression.text)) ||
          (ts.isIdentifier(expr) && ["eval", "Function"].includes(expr.text)) ||
          (ts.isPropertyAccessExpression(expr) && expr.name.text === "getBuiltinModule")
        ) {
          violations.push(`FORBIDDEN_DYNAMIC_RUNTIME_CALL: ${expr.getText(sourceFile)} in ${filePath}`);
        }
      }
      if (
        ts.isNewExpression(node) &&
        ts.isIdentifier(node.expression) &&
        ["Function", "WebSocket"].includes(node.expression.text)
      ) {
        violations.push(`FORBIDDEN_DYNAMIC_RUNTIME_NEW: ${node.expression.text} in ${filePath}`);
      }

      ts.forEachChild(node, visit);
    }

    visit(sourceFile);
    return violations;
  }

  function collectTypeScriptFiles(directory: string): string[] {
    const files: string[] = [];
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const candidate = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        files.push(...collectTypeScriptFiles(candidate));
      } else if (
        entry.isFile() &&
        (candidate.endsWith(".ts") || candidate.endsWith(".tsx")) &&
        statSync(candidate).isFile()
      ) {
        files.push(path.resolve(candidate));
      }
    }
    return files.sort();
  }

  it("database.ts has no forbidden imports/AST patterns; migrations source presence is a RED assertion", () => {
    const dbModulePath = path.resolve("src/stores/db/database.ts");
    const violations: string[] = [];

    // Check if migrations.ts or migrations/ exists.
    const migrationsPath = path.resolve("src/stores/db/migrations.ts");
    const migrationsDir = path.resolve("src/stores/db/migrations");
    const migrationSources: string[] = [];
    if (existsSync(migrationsPath) && statSync(migrationsPath).isFile()) {
      migrationSources.push(migrationsPath);
    }
    if (existsSync(migrationsDir) && statSync(migrationsDir).isDirectory()) {
      migrationSources.push(...collectTypeScriptFiles(migrationsDir));
    }

    if (migrationSources.length === 0) {
      // FIX 10: Missing required migration source is an intentional RED assertion.
      violations.push("MISSING_MIGRATION_SOURCE: src/stores/db/migrations.ts or src/stores/db/migrations/ does not exist");
    }

    // Scan every executable migration root plus its complete relative import
    // closure. This prevents an allowed-looking utility import from hiding a
    // child_process/network dependency one file deeper.
    const queue = [dbModulePath, ...migrationSources].map((source) => path.resolve(source));
    const visited = new Set<string>();
    while (queue.length > 0) {
      const source = queue.shift()!;
      if (visited.has(source)) continue;
      visited.add(source);
      const dependencies = new Set<string>();
      violations.push(...scanFileForViolations(source, dependencies));
      for (const dependency of [...dependencies].sort()) {
        if (!visited.has(dependency)) queue.push(dependency);
      }
    }

    expect(violations, `AST violations found: ${violations.join("; ")}`).toEqual([]);
  });
});
