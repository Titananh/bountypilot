import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  CURRENT_SCHEMA_VERSION,
  hasImmediateTransaction,
  runMigrations,
  withImmediateTransaction,
  type RunMigrationsOptions,
  type MigrationFaultInjector,
} from "./migrations.js";

export type BountyDatabase = DatabaseSync;

export { CURRENT_SCHEMA_VERSION, hasImmediateTransaction, runMigrations, withImmediateTransaction };
export type { RunMigrationsOptions, MigrationFaultInjector };

export function openBountyDatabase(dbFile: string): BountyDatabase {
  mkdirSync(path.dirname(dbFile), { recursive: true });
  const db = new DatabaseSync(dbFile);
  try {
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
    `);
    runMigrations(db);
  } catch (err) {
    try {
      db.close();
    } catch {
      // best-effort close, rethrow original error
    }
    throw err;
  }
  return db;
}

export function ensureSchema(db: BountyDatabase): void {
  runMigrations(db);
}
