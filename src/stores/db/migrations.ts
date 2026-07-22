import { DatabaseSync } from "node:sqlite";
import { BountyPilotError } from "../../utils/errors.js";

export const CURRENT_SCHEMA_VERSION = 2;

const MIGRATION_V1 = "legacy_baseline";
const MIGRATION_V2 = "p0_2_action_lifecycle";

const CODE_TRANSACTION_NESTED = "DB_TRANSACTION_NESTED";
const CODE_TRANSACTION_THENABLE = "DB_TRANSACTION_THENABLE";
const CODE_TRANSACTION_ROLLBACK_FAILED = "DB_TRANSACTION_ROLLBACK_FAILED";
const CODE_SCHEMA_VERSION_UNSUPPORTED = "DB_SCHEMA_VERSION_UNSUPPORTED";
const CODE_SCHEMA_STATE_INVALID = "DB_SCHEMA_STATE_INVALID";

type BountyDatabase = DatabaseSync;

export type MigrationFaultInjector = (checkpoint: string) => void;

export interface RunMigrationsOptions {
  readonly faultInjector?: MigrationFaultInjector;
}

const guardHandles = new WeakSet<BountyDatabase>();

/**
 * Pure read of the SAME module-private WeakSet that
 * `withImmediateTransaction` uses. No SQL is issued, no
 * DatabaseSync.isTransaction is consulted, and the transaction
 * cleanup semantics of `withImmediateTransaction` are not
 * altered. Callers can probe whether a tracked transaction is
 * already active on the given handle.
 */
export function hasImmediateTransaction(db: BountyDatabase): boolean {
  return guardHandles.has(db);
}

export function withImmediateTransaction<T>(
  db: BountyDatabase,
  fn: () => T,
): T {
  if (guardHandles.has(db)) {
    throw new BountyPilotError(
      "withImmediateTransaction cannot nest on the same database handle",
      CODE_TRANSACTION_NESTED,
    );
  }

  guardHandles.add(db);

  try {
    db.exec("BEGIN IMMEDIATE");
  } catch (beginErr) {
    guardHandles.delete(db);
    throw beginErr;
  }

  let result: T;
  try {
    result = fn();
  } catch (cbErr) {
    let rollbackErr: unknown = null;
    try {
      db.exec("ROLLBACK");
    } catch (re) {
      rollbackErr = re;
    }
    guardHandles.delete(db);
    if (rollbackErr) {
      throw new BountyPilotError(
        `transaction rollback failed: ${(rollbackErr as Error).message ?? String(rollbackErr)}`,
        CODE_TRANSACTION_ROLLBACK_FAILED,
      );
    }
    throw cbErr;
  }

  let thenable: boolean;
  try {
    thenable = isThenable(result);
  } catch (inspectErr) {
    let rollbackErr: unknown = null;
    try {
      db.exec("ROLLBACK");
    } catch (re) {
      rollbackErr = re;
    }
    guardHandles.delete(db);
    if (rollbackErr) {
      throw new BountyPilotError(
        `transaction rollback failed after thenable inspection error: ${(rollbackErr as Error).message ?? String(rollbackErr)}`,
        CODE_TRANSACTION_ROLLBACK_FAILED,
      );
    }
    throw inspectErr;
  }

  if (thenable) {
    let rollbackErr: unknown = null;
    try {
      db.exec("ROLLBACK");
    } catch (re) {
      rollbackErr = re;
    }
    guardHandles.delete(db);
    if (rollbackErr) {
      throw new BountyPilotError(
        `transaction rollback failed after thenable detection: ${(rollbackErr as Error).message ?? String(rollbackErr)}`,
        CODE_TRANSACTION_ROLLBACK_FAILED,
      );
    }
    throw new BountyPilotError(
      "withImmediateTransaction callback returned a Promise or thenable; only synchronous callbacks are supported",
      CODE_TRANSACTION_THENABLE,
    );
  }

  try {
    db.exec("COMMIT");
  } catch (commitErr) {
    let rollbackErr: unknown = null;
    try {
      db.exec("ROLLBACK");
    } catch (re) {
      rollbackErr = re;
    }
    guardHandles.delete(db);
    if (rollbackErr) {
      throw new BountyPilotError(
        `transaction rollback failed: ${(rollbackErr as Error).message ?? String(rollbackErr)}`,
        CODE_TRANSACTION_ROLLBACK_FAILED,
      );
    }
    throw commitErr;
  }

  guardHandles.delete(db);
  return result;
}

function isThenable(value: unknown): boolean {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value !== "object" && typeof value !== "function") {
    return false;
  }
  const then = (value as { then?: unknown }).then;
  return typeof then === "function";
}

interface MigrationStep {
  readonly version: number;
  readonly name: string;
  readonly faultCheckpoint: string;
  apply: (db: BountyDatabase) => void;
}

function applyV1(db: BountyDatabase): void {
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

  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      applied_at TEXT NOT NULL
    );
  `);

  ensureColumn(db, "actions", "metadata_json", "TEXT");
}

function applyV2SchemaColumns(db: BountyDatabase): void {
  ensureColumn(db, "actions", "updated_at", "TEXT");
  ensureColumn(db, "actions", "active_review_id", "TEXT");
  ensureColumn(db, "actions", "planned_scope_hash", "TEXT");
  ensureColumn(db, "actions", "planned_policy_hash", "TEXT");
  ensureColumn(db, "actions", "planned_action_hash", "TEXT");
  ensureColumn(db, "actions", "planned_context_hash", "TEXT");
  ensureColumn(db, "actions", "execution_token", "TEXT");
  ensureColumn(db, "actions", "execution_owner", "TEXT");
  ensureColumn(db, "actions", "lease_expires_at", "TEXT");
  ensureColumn(db, "actions", "started_at", "TEXT");
  ensureColumn(db, "actions", "dispatch_started_at", "TEXT");
  ensureColumn(db, "actions", "finished_at", "TEXT");
  ensureColumn(db, "actions", "outcome_certainty", "TEXT");
  ensureColumn(db, "actions", "last_error_code", "TEXT");
  ensureColumn(db, "actions", "last_error_message", "TEXT");
  ensureColumn(db, "actions", "supersedes_action_id", "TEXT");
  ensureColumn(db, "actions", "required_for_completion", "INTEGER NOT NULL DEFAULT 1");

  ensureColumn(db, "action_reviews", "reviewer_id", "TEXT");
  ensureColumn(db, "action_reviews", "source", "TEXT");
  ensureColumn(db, "action_reviews", "reviewed_at", "TEXT");
  ensureColumn(db, "action_reviews", "expires_at", "TEXT");
  ensureColumn(db, "action_reviews", "scope_hash", "TEXT");
  ensureColumn(db, "action_reviews", "policy_hash", "TEXT");
  ensureColumn(db, "action_reviews", "action_hash", "TEXT");
  ensureColumn(db, "action_reviews", "context_hash", "TEXT");
  ensureColumn(db, "action_reviews", "invalidated_at", "TEXT");
  ensureColumn(db, "action_reviews", "invalidation_reason", "TEXT");

  ensureColumn(db, "jobs", "pause_reason", "TEXT");
  ensureColumn(db, "jobs", "status_detail", "TEXT");
}

interface ActionNormalizationCounts {
  readonly plannedActionsNormalized: number;
  readonly approvedActionsDemoted: number;
}

const NORMALIZE_ACTION_RESET_SET = `
  status = 'pending',
  updated_at = COALESCE(updated_at, created_at),
  active_review_id = NULL,
  planned_scope_hash = NULL,
  planned_policy_hash = NULL,
  planned_action_hash = NULL,
  planned_context_hash = NULL,
  execution_token = NULL,
  execution_owner = NULL,
  lease_expires_at = NULL,
  started_at = NULL,
  dispatch_started_at = NULL,
  finished_at = NULL,
  outcome_certainty = NULL,
  last_error_code = NULL,
  last_error_message = NULL
`;

const STRUCTURALLY_COMPLETE_REVIEW_PREDICATE = `
  SELECT 1 FROM action_reviews r
  WHERE r.id = a.active_review_id
    AND r.action_id = a.id
    AND (r.job_id IS a.job_id)
    AND r.decision = 'approved'
    AND r.invalidated_at IS NULL
    AND r.reviewer_id IS NOT NULL AND r.reviewer_id != ''
    AND r.reviewed_at IS NOT NULL AND r.reviewed_at != ''
    AND r.expires_at IS NOT NULL AND r.expires_at != ''
    AND r.source IN ('human', 'policy')
    AND r.scope_hash IS NOT NULL AND r.scope_hash = a.planned_scope_hash
    AND r.policy_hash IS NOT NULL AND r.policy_hash = a.planned_policy_hash
    AND r.action_hash IS NOT NULL AND r.action_hash = a.planned_action_hash
    AND r.context_hash IS NOT NULL AND r.context_hash = a.planned_context_hash
`;

function countActionNormalizations(db: BountyDatabase): ActionNormalizationCounts {
  const plannedRow = db
    .prepare("SELECT COUNT(*) AS c FROM actions WHERE status = 'planned'")
    .get() as { c: number };
  const approvedRow = db
    .prepare(
      `SELECT COUNT(*) AS c FROM actions AS a
       WHERE a.status = 'approved'
         AND NOT EXISTS (${STRUCTURALLY_COMPLETE_REVIEW_PREDICATE})`,
    )
    .get() as { c: number };
  return {
    plannedActionsNormalized: plannedRow.c,
    approvedActionsDemoted: approvedRow.c,
  };
}

function normalizeLegacyActions(db: BountyDatabase): ActionNormalizationCounts {
  const counts = countActionNormalizations(db);

  db
    .prepare(
      `UPDATE actions AS a
       SET ${NORMALIZE_ACTION_RESET_SET}
       WHERE a.status = 'planned'`,
    )
    .run();

  db
    .prepare(
      `UPDATE actions AS a
       SET ${NORMALIZE_ACTION_RESET_SET}
       WHERE a.status = 'approved'
         AND NOT EXISTS (${STRUCTURALLY_COMPLETE_REVIEW_PREDICATE})`,
    )
    .run();

  return counts;
}

function duplicateWorkflowJobIds(db: BountyDatabase): string[] {
  const rows = db
    .prepare(
      "SELECT job_id FROM workflow_events GROUP BY job_id HAVING COUNT(*) <> COUNT(DISTINCT sequence) ORDER BY job_id",
    )
    .all() as Array<{ job_id: string }>;
  return rows.map((row) => row.job_id);
}

function resequenceDuplicateWorkflowJobs(
  db: BountyDatabase,
  jobIds: readonly string[],
): number {
  const loadStmt = db.prepare(
    "SELECT id, sequence FROM workflow_events WHERE job_id = ? ORDER BY created_at ASC, id ASC",
  );
  const minStmt = db.prepare(
    "SELECT MIN(sequence) AS min_seq FROM workflow_events WHERE job_id = ?",
  );
  const tempUpdateStmt = db.prepare(
    "UPDATE workflow_events SET sequence = ? WHERE id = ? AND job_id = ?",
  );
  const finalUpdateStmt = db.prepare(
    "UPDATE workflow_events SET sequence = ? WHERE id = ? AND job_id = ?",
  );

  for (const jobId of jobIds) {
    const rows = loadStmt.all(jobId) as Array<{ id: string; sequence: number }>;
    if (rows.length === 0) {
      continue;
    }
    const minRow = minStmt.get(jobId) as { min_seq: number | null };
    const minSeq = minRow.min_seq;
    if (minSeq === null) {
      continue;
    }
    const rowCount = rows.length;
    const tempStart = minSeq - rowCount - 1;

    for (let i = 0; i < rowCount; i++) {
      tempUpdateStmt.run(tempStart + i, rows[i].id, jobId);
    }
    for (let i = 0; i < rowCount; i++) {
      finalUpdateStmt.run(i + 1, rows[i].id, jobId);
    }
  }

  return jobIds.length;
}

function createV2UniqueIndexes(db: BountyDatabase): void {
  db.exec("DROP INDEX IF EXISTS idx_workflow_events_job_sequence");
  db.exec(
    "CREATE UNIQUE INDEX idx_workflow_events_job_sequence ON workflow_events (job_id, sequence)",
  );
  db.exec("DROP INDEX IF EXISTS idx_actions_execution_token_unique");
  db.exec(
    "CREATE UNIQUE INDEX idx_actions_execution_token_unique ON actions (execution_token) WHERE execution_token IS NOT NULL",
  );
}

function assertNoV2AuditCollision(db: BountyDatabase): void {
  const collision = db
    .prepare(
      `SELECT 1 AS hit FROM workflow_events
       WHERE id = ?
          OR job_id = ?
       LIMIT 1`,
    )
    .get(
      "migration-v2-audit",
      "__bountypilot_migrations__",
    ) as { hit: number } | undefined;
  if (collision !== undefined) {
    throw new BountyPilotError(
      "schema state invalid: v2 migration audit row already exists",
      CODE_SCHEMA_STATE_INVALID,
    );
  }
}

function insertV2MigrationAudit(
  db: BountyDatabase,
  counts: ActionNormalizationCounts,
  workflowJobsResequenced: number,
): void {
  const metadata = {
    kind: "p0_2_migration_audit",
    migrationVersion: 2,
    plannedActionsNormalized: counts.plannedActionsNormalized,
    approvedActionsDemoted: counts.approvedActionsDemoted,
    workflowJobsResequenced,
  };
  db.prepare(
    `INSERT INTO workflow_events
       (id, job_id, sequence, phase, status, message, metadata_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    "migration-v2-audit",
    "__bountypilot_migrations__",
    1,
    "migration",
    "completed",
    "P0.2 migration applied",
    JSON.stringify(metadata),
    new Date().toISOString(),
  );
}

function applyV2DataAndIndexes(db: BountyDatabase): void {
  const preCounts = countActionNormalizations(db);
  const duplicateJobIds = duplicateWorkflowJobIds(db);
  const totalChanges =
    preCounts.plannedActionsNormalized +
    preCounts.approvedActionsDemoted +
    duplicateJobIds.length;

  if (totalChanges > 0) {
    assertNoV2AuditCollision(db);
  }

  const counts = normalizeLegacyActions(db);
  resequenceDuplicateWorkflowJobs(db, duplicateJobIds);
  createV2UniqueIndexes(db);

  if (totalChanges > 0) {
    insertV2MigrationAudit(db, counts, duplicateJobIds.length);
  }
}

function applyV2(db: BountyDatabase): void {
  applyV2SchemaColumns(db);
  applyV2DataAndIndexes(db);
}

const MIGRATIONS: readonly MigrationStep[] = [
  { version: 1, name: MIGRATION_V1, faultCheckpoint: "v1:after-user-version", apply: applyV1 },
  { version: 2, name: MIGRATION_V2, faultCheckpoint: "v2:after-user-version", apply: applyV2 },
];

function ensureColumn(db: BountyDatabase, table: string, column: string, definition: string): void {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (rows.some((row) => row.name === column)) {
    return;
  }
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

function ensureSchemaMigrations(db: BountyDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      applied_at TEXT NOT NULL
    );
  `);
}

function readUserVersion(db: BountyDatabase): number {
  const row = db.prepare("PRAGMA user_version").get() as { user_version: number } | undefined;
  return row?.user_version ?? 0;
}

function writeUserVersion(db: BountyDatabase, version: number): void {
  db.exec(`PRAGMA user_version = ${version}`);
}

function recordMigration(db: BountyDatabase, version: number, name: string, appliedAt: string): void {
  db.prepare(
    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
  ).run(version, name, appliedAt);
}

function listHistory(db: BountyDatabase): Array<{ version: number; name: string; applied_at: string }> {
  return db
    .prepare("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC")
    .all() as Array<{ version: number; name: string; applied_at: string }>;
}

function isoTimestamp(): string {
  return new Date().toISOString();
}

function expectedNameFor(version: number): string | undefined {
  for (const step of MIGRATIONS) {
    if (step.version === version) {
      return step.name;
    }
  }
  return undefined;
}

function lockedValidate(db: BountyDatabase): number {
  ensureSchemaMigrations(db);

  const userVersion = readUserVersion(db);

  if (userVersion > CURRENT_SCHEMA_VERSION) {
    throw new BountyPilotError(
      `database schema version ${userVersion} is newer than supported ${CURRENT_SCHEMA_VERSION}`,
      CODE_SCHEMA_VERSION_UNSUPPORTED,
    );
  }

  const history = listHistory(db);
  const historyVersions = history.map((h) => h.version);

  if (userVersion !== historyVersions.length) {
    throw new BountyPilotError(
      `schema state invalid: user_version=${userVersion} history count=${historyVersions.length}`,
      CODE_SCHEMA_STATE_INVALID,
    );
  }

  for (let i = 0; i < historyVersions.length; i++) {
    if (historyVersions[i] !== i + 1) {
      throw new BountyPilotError(
        `schema state invalid: history has unexpected version ${historyVersions[i]} at position ${i}`,
        CODE_SCHEMA_STATE_INVALID,
      );
    }
  }

  for (const h of history) {
    const expected = expectedNameFor(h.version);
    if (expected === undefined) {
      throw new BountyPilotError(
        `schema state invalid: unknown migration version ${h.version} in history`,
        CODE_SCHEMA_STATE_INVALID,
      );
    }
    if (expected !== h.name) {
      throw new BountyPilotError(
        `schema state invalid: migration ${h.version} name mismatch (expected ${expected}, got ${h.name})`,
        CODE_SCHEMA_STATE_INVALID,
      );
    }
  }

  return userVersion;
}

export function runMigrations(db: BountyDatabase, opts: RunMigrationsOptions = {}): void {
  const faultInjector = opts.faultInjector;

  while (true) {
    let nextStep: MigrationStep | undefined;
    let applied = false;

    db.exec("BEGIN IMMEDIATE");
    try {
      const currentVersion = lockedValidate(db);
      if (currentVersion === CURRENT_SCHEMA_VERSION) {
        db.exec("COMMIT");
        return;
      }

      const nextVersion = currentVersion + 1;
      nextStep = MIGRATIONS.find((s) => s.version === nextVersion);
      if (!nextStep) {
        throw new BountyPilotError(
          `schema state invalid: no migration registered for version ${nextVersion}`,
          CODE_SCHEMA_STATE_INVALID,
        );
      }

      nextStep.apply(db);
      recordMigration(db, nextStep.version, nextStep.name, isoTimestamp());
      writeUserVersion(db, nextStep.version);

      if (faultInjector) {
        faultInjector(nextStep.faultCheckpoint);
      }

      db.exec("COMMIT");
      applied = true;
    } catch (err) {
      if (!applied) {
        try {
          db.exec("ROLLBACK");
        } catch {
          throw err;
        }
      }
      throw err;
    }
  }
}
