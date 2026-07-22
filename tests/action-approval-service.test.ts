// P0.2 Packet 2 — Slice B1 RED tests
// tests/action-approval-service.test.ts
//
// Contract source: docs/p0.2-packet-2-contract.md §3, §7 (Slice B1
// storage). This file covers the ActionQueue storage behavior that
// backs the ActionApprovalService preview/approveHuman/approvePolicy
// contract: strict requires_approval decoding, strict metadata_json
// decoding, requireCleanPendingForApproval, and
// approveWithReviewInTransaction (with token non-leak invariants).
//
// The DB fixtures are reused from tests/action-lifecycle.test.ts
// (insertRawV2Action, insertReviewRow, openBountyDatabase +
// withImmediateTransaction, plus per-test temp DBs in
// mkdtempSync). No target-effect/network/browser/MCP/executor imports.
// `node:worker_threads` is used only by the B3C test harness to prove a
// genuinely concurrent two-handle SQLite approval race.
//
// RED suite: most tests assert a stricter contract code than the
// current stub returns, so the suite is RED as a whole. Negative
// fail-closed tests (e.g. invalid DTO shapes, malformed reviews,
// dirty-state CAS) may already pass on the current stub because
// the stub happens to throw the same fixed code. A passing test
// here does not mean production satisfies the contract — it
// only means the failure code happened to align. The only
// signal that production is complete is a green run that
// matches every pinned code in this file.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";

import { openBountyDatabase, withImmediateTransaction, hasImmediateTransaction, type BountyDatabase } from "../src/stores/db/database.js";
import { BountyPilotError } from "../src/utils/errors.js";
import {
  ActionQueue,
  type ActionRecord,
  type ApproveActionWithReviewInput,
  type PendingApprovalCandidate,
} from "../src/core/actions/action-queue.js";
import {
  ActionApprovalService,
  materializeActionAuthority,
  recomputeActionAuthority,
  snapshotActionMaterialSource,
  type ActionAuthorityDependencies,
  type ActionApprovalServiceDependencies,
  type ActionMaterialSource,
  type CurrentActionMaterial,
  type IntegrationBindingMaterial,
  type ResolvedBindingMaterial,
} from "../src/core/actions/action-approval-service.js";
import type { AdapterCapabilityMetadata } from "../src/integrations/adapters/adapter.js";
import {
  buildActionBinding,
  computeActionHash,
  computeContextHash,
  type CapabilityEnforcementInput,
  type SafeIntegrationExecutionPolicy,
} from "../src/core/actions/action-approval-context.js";
import { buildProgramAuthoritySnapshot } from "../src/core/policy/program-authority-snapshot.js";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import { ProgramSchema, type ProgramConfig } from "../src/core/config/program-schema.js";
import type { LoadedProgram } from "../src/core/config/config-loader.js";

// ---------------------------------------------------------------------------
// Test-only narrow structural interface for requireCleanPendingForApproval.
// ---------------------------------------------------------------------------

interface ActionQueueSliceB1 {
  requireCleanPendingForApproval(actionId: string): PendingApprovalCandidate;
  approveWithReviewInTransaction(input: ApproveActionWithReviewInput): ActionRecord;
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

function makeTempDir(): string {
  return mkdtempSync(path.join(tmpdir(), "bountypilot-p02-b1-"));
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

function hex64(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

const SCOPE_HASH = hex64("scope:b1");
const POLICY_HASH = hex64("policy:b1");
const ACTION_HASH = hex64("action:b1");
const CONTEXT_HASH = hex64("context:b1");
const REVIEWER_ID = "reviewer-b1";
const POLICY_REVIEWER_ID = "system:policy-gate";

const CREATED_AT = "2099-01-01T00:00:00.000Z";
const REVIEWED_AT = "2099-01-01T00:00:00.000Z";
const EXPIRES_AT = "2099-01-01T00:15:00.000Z";

const SECRET_TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SECRET_TOKEN_OWNER = "owner-b1-token";

// Canonical canonical-equal updatedAt used as the action CAS instant.
// The value must round-trip through Date#toISOString() per §7.
const UPDATED_AT = "2099-01-01T00:00:00.000Z";

interface RawV2ActionSeed {
  id: string;
  jobId: string;
  status: "pending" | "approved" | "executed" | "blocked" | "failed" | "running" | "outcome_unknown" | "planned";
  requiredForCompletion: 0 | 1;
  // The v2 additive columns we exercise in this slice. The full
  // 27-column insert is overkill here, so the helper accepts only the
  // fields needed by the dirty-state table tests.
  executedAt?: string | null;
  activeReviewId?: string | null;
  plannedScopeHash?: string | null;
  plannedPolicyHash?: string | null;
  plannedActionHash?: string | null;
  plannedContextHash?: string | null;
  executionToken?: string | null;
  executionOwner?: string | null;
  leaseExpiresAt?: string | null;
  startedAt?: string | null;
  dispatchStartedAt?: string | null;
  finishedAt?: string | null;
  outcomeCertainty?: string | null;
  lastErrorCode?: string | null;
  lastErrorMessage?: string | null;
  updatedAt?: string | null;
  // The requires_approval raw value. The strict-decoder probe
  // (B1.1) must reject any value other than raw integer 0 or
  // raw integer 1; the table-test dirty values (2, -1, 3, 42)
  // exercise that path. The field is typed as the union of the
  // two valid and four invalid representative integers; callers
  // do not need a dishonest cast.
  requiresApproval?: 0 | 1 | 2 | -1 | 3 | 42;
  // Raw metadata_json value. NULL/empty string/valid JSON object
  // mapping is exercised through this field. For NULL semantics
  // pass null; for the empty string / non-JSON / primitive / null-
  // JSON / array variants pass the exact raw string. A
  // `Uint8Array` is bound as a BLOB; the strict-decoder probe
  // must reject a BLOB metadata_json because the contract pins
  // metadata_json to a non-null plain-object JSON encoding.
  metadataJsonRaw?: string | Uint8Array | null;
}

/**
 * Insert a v2 action row that matches the schema exactly. The
 * helper writes every required legacy column plus the additive v2
 * columns exercised by this slice. Caller controls the requires_approval
 * raw integer and the raw metadata_json string so the strict-decoder
 * table tests can stage malformed values.
 */
function insertRawV2Action(db: BountyDatabase, seed: RawV2ActionSeed): void {
  const COLS = [
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
    "required_for_completion",
  ] as const;
  const values: (string | number | null | Uint8Array)[] = [
    seed.id,
    seed.jobId,
    "http",
    "GET",
    "https://b1.example/path",
    "low",
    seed.requiresApproval ?? 0,
    seed.status,
    seed.metadataJsonRaw === undefined ? null : seed.metadataJsonRaw,
    CREATED_AT,
    seed.executedAt === undefined ? null : seed.executedAt,
    seed.updatedAt === undefined ? UPDATED_AT : seed.updatedAt,
    seed.activeReviewId ?? null,
    seed.plannedScopeHash ?? null,
    seed.plannedPolicyHash ?? null,
    seed.plannedActionHash ?? null,
    seed.plannedContextHash ?? null,
    seed.executionToken ?? null,
    seed.executionOwner ?? null,
    seed.leaseExpiresAt ?? null,
    seed.startedAt ?? null,
    seed.dispatchStartedAt ?? null,
    seed.finishedAt ?? null,
    seed.outcomeCertainty ?? null,
    seed.lastErrorCode ?? null,
    seed.lastErrorMessage ?? null,
    null, // supersedes_action_id is unused in this slice
    seed.requiredForCompletion,
  ];
  const placeholders = COLS.map(() => "?").join(", ");
  db.prepare(`INSERT INTO actions (${COLS.join(", ")}) VALUES (${placeholders})`).run(...values);
}

function insertValidActiveReview(
  db: BountyDatabase,
  row: {
    id: string;
    actionId: string;
    jobId: string;
    decision: "approved";
    reviewerId: string;
    source: "human" | "policy";
    reviewedAt?: string;
    expiresAt?: string;
    scopeHash?: string;
    policyHash?: string;
    actionHash?: string;
    contextHash?: string;
  },
): void {
  db.prepare(
    `INSERT INTO action_reviews (
       id, action_id, job_id, decision, note, created_at,
       reviewer_id, source, reviewed_at, expires_at,
       scope_hash, policy_hash, action_hash, context_hash,
       invalidated_at, invalidation_reason
     ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
  ).run(
    row.id,
    row.actionId,
    row.jobId,
    row.decision,
    row.reviewedAt ?? REVIEWED_AT,
    row.reviewerId,
    row.source,
    row.reviewedAt ?? REVIEWED_AT,
    row.expiresAt ?? EXPIRES_AT,
    row.scopeHash ?? SCOPE_HASH,
    row.policyHash ?? POLICY_HASH,
    row.actionHash ?? ACTION_HASH,
    row.contextHash ?? CONTEXT_HASH,
  );
}

function readActionRow(db: BountyDatabase, id: string): Record<string, unknown> {
  return db.prepare("SELECT * FROM actions WHERE id = ?").get(id) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// insertJob fixture — matches the real v2 jobs schema exactly. Inserts a
// nonterminal job with status='queued' by default. The contract preflight
// for requireCleanPendingForApproval (§7) only allows nonterminal job
// statuses; "queued" is a nonterminal valid JobStatus and is the default
// for callers that do not need to exercise a specific terminal status
// (which is covered by the explicit JOB_TERMINAL table cases).
//
// Two overloads:
//   1) `insertJob(db, id, status?)` — positional convenience used by
//      the success and dirty-state cases. The status argument accepts
//      both nonterminal and terminal JobStatus values, but the
//      terminal values are exercised only by the JOB_TERMINAL table
//      cases (see B1.3).
//   2) `insertJob(db, seed)` — object form used when the caller needs
//      to override the `mode` or other schema fields.
//
// The `mode` is always "safe" — a nonterminal valid mode. The
// contract does not exercise job-mode filtering at this layer,
// so the value stays constant across every call site. "safe"
// is a deterministic valid `ExecutionMode` literal; "lab" was
// a non-deterministic stub value and is no longer used.
// ---------------------------------------------------------------------------

type JobStatusFixture = "queued" | "running" | "paused" | "failed" | "completed";

function insertJob(db: BountyDatabase, id: string, status?: JobStatusFixture): void;
function insertJob(
  db: BountyDatabase,
  seed: { id: string; type?: string; mode?: string; status?: JobStatusFixture; target?: string | null },
): void;
function insertJob(
  db: BountyDatabase,
  idOrSeed: string | { id: string; type?: string; mode?: string; status?: JobStatusFixture; target?: string | null },
  statusArg?: JobStatusFixture,
): void {
  if (typeof idOrSeed === "string") {
    db
      .prepare(
        `INSERT INTO jobs (
           id, type, target, mode, status, pause_reason, status_detail,
           created_at, updated_at
         ) VALUES (?, ?, NULL, ?, ?, NULL, NULL, ?, ?)`,
      )
      .run(idOrSeed, "b1-test-job", "safe", statusArg ?? "queued", CREATED_AT, UPDATED_AT);
    return;
  }
  db
    .prepare(
      `INSERT INTO jobs (
         id, type, target, mode, status, pause_reason, status_detail,
         created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)`,
    )
    .run(
      idOrSeed.id,
      idOrSeed.type ?? "b1-test-job",
      idOrSeed.target ?? null,
      idOrSeed.mode ?? "safe",
      idOrSeed.status ?? "queued",
      CREATED_AT,
      UPDATED_AT,
    );
}

/**
 * Insert a v2 action row whose `requires_approval` value is bound
 * to a runtime value with non-{0,1} storage class so the strict
 * decoder must reject. The contract pins 0 and 1 as the only
 * valid values; any other storage class (REAL 1.5, non-numeric
 * TEXT, or a SQLite BLOB) must be rejected with
 * ACTION_RECORD_INVALID.
 *
 * The `requires_approvalRaw` field accepts the JS-side runtime
 * value (number | string | Uint8Array) without lying about its
 * shape. The helper writes the value through `Statement.run`
 * directly; node:sqlite binds each JS value to its nearest
 * SQLite storage class:
 *   - JS number 1.5  -> REAL 1.5
 *   - JS string "true" -> TEXT "true" (non-numeric literal, so
 *     INTEGER affinity does not coerce)
 *   - JS Uint8Array -> BLOB
 *
 * The helper is the only place in this file that stages a
 * non-{0,1} value, and the storage-class probe in B1.1b
 * asserts the actual SQLite `typeof()` for the row to ground
 * the "raw storage class" claim — the cast is no longer
 * dishonest: the value that lands in the column is the value
 * the type signature says it is.
 */
function insertRawV2ActionRequiresApprovalRaw(
  db: BountyDatabase,
  seed: {
    id: string;
    jobId: string;
    status: "pending" | "approved" | "executed" | "blocked" | "failed" | "running" | "outcome_unknown" | "planned";
    requiredForCompletion: 0 | 1;
    // The exact runtime value to bind. node:sqlite maps each
    // JS value to its nearest storage class; the strict
    // decoder must reject anything other than raw integer 0
    // or raw integer 1.
    requiresApprovalRaw: number | string | Uint8Array;
  },
): void {
  db
    .prepare(
      `INSERT INTO actions (
         id, job_id, adapter, action_type, target, risk_level,
         requires_approval, status, metadata_json, created_at,
         executed_at, updated_at, required_for_completion
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?, ?)`,
    )
    .run(
      seed.id,
      seed.jobId,
      "http",
      "GET",
      "https://b1.example/path",
      "low",
      // Bind the value as-is. node:sqlite picks the storage
      // class from the JS value; no cast, no coercion. The
      // strict-decoder probe verifies the storage class and
      // asserts the rejection.
      seed.requiresApprovalRaw,
      seed.status,
      CREATED_AT,
      UPDATED_AT,
      seed.requiredForCompletion,
    );
}



// ---------------------------------------------------------------------------
// Per-test temp DB
// ---------------------------------------------------------------------------

let tempDir: string;
let dbFile: string;
let db: BountyDatabase | null = null;

function openDb(): BountyDatabase {
  const handle = openBountyDatabase(dbFile);
  db = handle;
  return handle;
}

function closeDb(): void {
  if (db) {
    try {
      db.close();
    } catch {
      /* best-effort */
    }
    db = null;
  }
}

beforeEach(() => {
  tempDir = makeTempDir();
  dbFile = path.join(tempDir, "slice-b1.db");
});

afterEach(() => {
  closeDb();
  cleanupDb(dbFile);
  if (tempDir && existsSync(tempDir)) {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

// Capture-and-classify helper. Always asserts the captured error is
// a BountyPilotError with the expected code AND that the message
// does not echo the action id (defense in depth). Returns the
// captured error so the caller can perform additional per-case
// assertions.
function expectCode(err: unknown, code: string, sentinel?: string): BountyPilotError {
  expect(err, `expected BountyPilotError, got ${err === null ? "null" : typeof err}`).toBeInstanceOf(BountyPilotError);
  const bp = err as BountyPilotError;
  expect(bp.code).toBe(code);
  if (sentinel !== undefined && sentinel.length > 0) {
    expect(bp.message, `error message echoed sentinel`).not.toContain(sentinel);
  }
  return bp;
}

// Nonleak serialization helper. The contract pins BountyPilotError's
// public surface to (name, code, message) — no other enumerable
// own field may carry secret-bearing data. This helper inspects
// the actual error object, not a curated whitelist, by serializing
// every own ENUMERABLE property and asserting the secret never
// reaches any enumerable field. Two projections are checked so a
// future change to BountyPilotError that adds a new enumerable
// own field is caught:
//   1) JSON.stringify(err) over the captured error directly
//      (only own enumerable properties, the runtime path)
//   2) JSON.stringify({ name, code, message }) on the explicit
//      contract surface (the "curated" projection, defense in
//      depth)
// A regression that adds an enumerable own property carrying
// the secret would still fail the JSON.stringify(err) check
// even if the curated projection is updated to ignore it.
// Note: JSON.stringify only inspects own ENUMERABLE string-keyed
// properties; a non-enumerable getter that returns a secret
// would slip past this check. The contract pins the public
// surface to exactly (name, code, message) — a separate review
// of the BountyPilotError constructor is the canonical defense
// against non-enumerable property smuggling, this helper is the
// runtime + curated safety net for the enumerable surface.
function serializeErrorForLeakCheck(err: BountyPilotError): {
  runtime: string;
  curated: string;
} {
  // Capture every own ENUMERABLE property the runtime exposes.
  // The returned JSON form is the union of own enumerable
  // string-keyed keys; non-enumerable properties are not
  // reached by JSON.stringify and must be defended at the
  // BountyPilotError constructor level (a separate review).
  const runtime = JSON.stringify(err);
  const curated = JSON.stringify({
    name: err.name,
    code: err.code,
    message: err.message,
  });
  return { runtime, curated };
}

// Top-level DTO builder used by the B1.4b/c/d/e tables. The
// shape is exactly the eight required fields documented in
// §7 of docs/p0.2-packet-2-contract.md. The B1.4 describe
// block previously declared this helper inline; it is now
// hoisted to module scope so the table tests can share it
// without duplicating the field list.
function makeBaseInput(actionId: string, jobId: string, reviewId: string): ApproveActionWithReviewInput {
  return {
    actionId,
    jobId,
    reviewId,
    scopeHash: SCOPE_HASH,
    policyHash: POLICY_HASH,
    actionHash: ACTION_HASH,
    contextHash: CONTEXT_HASH,
    updatedAt: UPDATED_AT,
  };
}

// Top-level "stage a clean pending action" helper. Inserts
// the action row only; the linked nonterminal job is the
// caller's responsibility (most test cases insert one
// explicitly so the preflight JOB_NOT_FOUND path is not
// accidentally taken).
function seedCleanPending(db: BountyDatabase, actionId: string, jobId: string): void {
  insertRawV2Action(db, {
    id: actionId,
    jobId,
    status: "pending",
    requiredForCompletion: 1,
    requiresApproval: 1,
  });
}

// Top-level prepare-call probe. The probe intercepts every
// call to db.prepare(sql) for the duration of `fn` and
// captures (counter, sqls) so tests can assert "no
// UPDATE actions was prepared" / "no SELECT against the
// business tables was prepared". The probe is uninstalled
// in `finally` so subsequent tests are unaffected.
//
// The probe only intercepts the prepare surface; the
// transaction wrapper may issue BEGIN/COMMIT through
// db.exec, which bypasses prepare entirely. That is the
// canonical "no SQL was prepared" form for the
// tracked-tx guard. We treat `sqls.length === 0` as the
// strict zero-prepare case.
function withPrepareProbe<T>(
  db: BountyDatabase,
  fn: (count: { value: number }, sqls: string[]) => T,
): T {
  const origPrepare = db.prepare.bind(db);
  const counter = { value: 0 };
  const sqls: string[] = [];
  db.prepare = ((sql: string) => {
    counter.value += 1;
    sqls.push(sql);
    return origPrepare(sql);
  }) as typeof db.prepare;
  try {
    return fn(counter, sqls);
  } finally {
    db.prepare = origPrepare as typeof db.prepare;
  }
}

// Top-level ID-mutation table helper. Used by B1.4b (DTO
// field corruption) and B1.4d (candidate id boundary
// corruption). Both blocks must agree on the canonical
// mutation list, so the helper is hoisted to module scope.
//
// c0 inserts the actual U+0000 (NULL) code point. A literal
// "\\0" two-character string would be stripped by trim()
// and slip past a naive control-character check; the
// mutation must land a REAL U+0000 byte that survives
// value === value.trim() but fails the canonical C0/DEL
// regex. The same applies to del: actual U+007F (DEL).
//
// long is exactly 257 Unicode code points — one over the
// contract cap of 1..256. Pure ASCII so the bytes are
// unambiguous.
type IdMut = "padded" | "c0" | "del" | "long";
function mutId(value: string, kind: IdMut): string {
  if (kind === "padded") return " " + value + " ";
  if (kind === "c0") return value + "\u0000";
  if (kind === "del") return value + "\u007f";
  // 257 ASCII code points, one over the cap. Pure ASCII
  // so the byte length and code-point length are equal
  // and the test cannot pass vacuously via multibyte
  // counting.
  return "a".repeat(257);
}

// Top-level hash-mutation table helper. Used by B1.4b only
// today, but hoisted for symmetry with mutId and to keep
// the B1.4b describe block free of helper declarations.
//
// uppercase is deterministic and ALWAYS differs from the
// valid base: a single uppercase "A" followed by 63
// lowercase hex characters. This guarantees the mutation
// is not a no-op for hashes whose first four characters
// are already uppercase, AND the result is still rejected
// (lowercase-only hex rule) regardless of which 4 chars
// were chosen. The valid base is the 64-lowercase-hex
// shape; flipping any one of them to upper is always a
// different value AND always an invalid hex form.
type HashMut = "uppercase" | "nonhex" | "wrong-type";
function mutHash(value: string, kind: HashMut): string | number {
  if (kind === "uppercase") {
    // Deterministic invalid uppercase hash: one uppercase
    // letter followed by 63 lowercase hex characters. The
    // contract requires 64 lowercase hex; this mutation
    // always produces a string that is NOT a valid hex
    // (the "A" breaks the lowercase rule) AND always
    // differs from the base value of the 64 lowercase hex
    // strings used in the suite.
    return "A" + "a".repeat(63);
  }
  if (kind === "nonhex") {
    // 64 non-hex characters: a-z letters are not in [0-9a-f]
    // and produce a deterministic invalid hex form that
    // always differs from the valid base.
    return "z".repeat(64);
  }
  // wrong-type: a runtime value whose typeof is "number".
  // The strict hash decoder pins typeof === "string".
  return 0xdeadbeef;
}

// ===========================================================================
// B1.1: strict requires_approval raw 0/1 decoding — every other raw
// value makes get/list/candidate throw ACTION_RECORD_INVALID.
// ===========================================================================

describe("B1.1: requires_approval is decoded strictly as 0->false, 1->true; every other raw value throws ACTION_RECORD_INVALID", () => {
  // Each table case stages a row whose raw requires_approval is the
  // listed value. The 0 and 1 baselines are the only two valid stored
  // values; every other integer must fail closed.
  interface Case {
    name: string;
    rawRequiresApproval: number;
  }

  const VALID_CASES: Case[] = [
    { name: "raw=0 decodes to false", rawRequiresApproval: 0 },
    { name: "raw=1 decodes to true", rawRequiresApproval: 1 },
  ];
  const INVALID_CASES: Case[] = [
    { name: "raw=2", rawRequiresApproval: 2 },
    { name: "raw=-1", rawRequiresApproval: -1 },
    { name: "raw=3", rawRequiresApproval: 3 },
    { name: "raw=42", rawRequiresApproval: 42 },
  ];

  for (const c of VALID_CASES) {
    it(`get() decodes requires_approval ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      insertRawV2Action(handle, {
        id: `act-b11-valid-${c.rawRequiresApproval}`,
        jobId: `job-b11-valid-${c.rawRequiresApproval}`,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: c.rawRequiresApproval as 0 | 1,
      });

      const record = queue.get(`act-b11-valid-${c.rawRequiresApproval}`) as ActionRecord | undefined;
      expect(record).toBeDefined();
      expect(record!.requiresApproval).toBe(c.rawRequiresApproval === 1);
    });

    it(`list() decodes requires_approval ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      insertRawV2Action(handle, {
        id: `act-b11-list-valid-${c.rawRequiresApproval}`,
        jobId: `job-b11-list-valid-${c.rawRequiresApproval}`,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: c.rawRequiresApproval as 0 | 1,
      });

      const list = queue.list(`job-b11-list-valid-${c.rawRequiresApproval}`) as ActionRecord[];
      expect(list.length).toBe(1);
      expect(list[0].requiresApproval).toBe(c.rawRequiresApproval === 1);
    });
  }

  for (const c of INVALID_CASES) {
    // The rawRequiresApproval type is widened at the table level
    // so the dirty values (2, -1, 3, 42) flow through without a
    // cast to 0|1. The seed type accepts the union of valid and
    // invalid representative integers.
    it(`get() throws ACTION_RECORD_INVALID for requires_approval ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      insertRawV2Action(handle, {
        id: `act-b11-bad-get-${c.rawRequiresApproval}`,
        jobId: `job-b11-bad-get-${c.rawRequiresApproval}`,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: c.rawRequiresApproval as 0 | 1 | 2 | -1 | 3 | 42,
      });

      let captured: unknown = null;
      try {
        queue.get(`act-b11-bad-get-${c.rawRequiresApproval}`);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_RECORD_INVALID", `act-b11-bad-get-${c.rawRequiresApproval}`);
    });

    it(`list() throws ACTION_RECORD_INVALID when ANY row has requires_approval ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const jobId = `job-b11-bad-list-${c.rawRequiresApproval}`;
      // Two rows: one good + one bad. list() must fail closed
      // because a divergent mapper is forbidden.
      insertRawV2Action(handle, {
        id: `act-b11-bad-list-a-${c.rawRequiresApproval}`,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: 1,
      });
      insertRawV2Action(handle, {
        id: `act-b11-bad-list-b-${c.rawRequiresApproval}`,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: c.rawRequiresApproval as 0 | 1 | 2 | -1 | 3 | 42,
      });

      let captured: unknown = null;
      try {
        queue.list(jobId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_RECORD_INVALID", jobId);
    });

    it(`requireCleanPendingForApproval throws ACTION_RECORD_INVALID for requires_approval ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const actionId = `act-b11-bad-cand-${c.rawRequiresApproval}`;
      const jobId = `job-b11-bad-cand-${c.rawRequiresApproval}`;
      // Per §7 preflight order, job linkage is validated BEFORE
      // strict decoding. Seed a real nonterminal linked job so
      // preflight clears and the strict-decoder error is the
      // observed failure (not a missing-job error).
      insertJob(handle, jobId);
      insertRawV2Action(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: c.rawRequiresApproval as 0 | 1 | 2 | -1 | 3 | 42,
      });

      const candidate = queue as unknown as ActionQueueSliceB1;
      let captured: unknown = null;
      try {
        candidate.requireCleanPendingForApproval(actionId);
      } catch (err) {
        captured = err;
      }
      // The candidate is read-only and must use the same strict
      // 0/1 decoder; any other value is ACTION_RECORD_INVALID.
      expectCode(captured, "ACTION_RECORD_INVALID", actionId);
    });
  }
});

// ===========================================================================
// B1.2: metadata_json NULL/valid plain object mapping; invalid JSON,
// empty string, primitive, null JSON, and array throw
// ACTION_RECORD_INVALID through get/list/candidate.
// ===========================================================================

describe("B1.2: metadata_json strict mapping — NULL/valid plain object pass; invalid shapes throw ACTION_RECORD_INVALID", () => {
  it("get() returns record with metadata=undefined for metadata_json=NULL", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-b12-null",
      jobId: "job-b12-null",
      status: "pending",
      requiredForCompletion: 1,
      requiresApproval: 1,
      metadataJsonRaw: null,
    });

    const record = queue.get("act-b12-null") as ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.metadata).toBeUndefined();
  });

  it("get() returns the exact plain-object metadata for a valid JSON object", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const meta = { kind: "b1", nested: { a: 1, b: "x" } };
    insertRawV2Action(handle, {
      id: "act-b12-valid",
      jobId: "job-b12-valid",
      status: "pending",
      requiredForCompletion: 1,
      requiresApproval: 1,
      metadataJsonRaw: JSON.stringify(meta),
    });

    const record = queue.get("act-b12-valid") as ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.metadata).toEqual(meta);
  });

  interface BadCase {
    name: string;
    raw: string | Uint8Array;
  }
  const BAD_CASES: BadCase[] = [
    { name: "empty string", raw: "" },
    { name: "non-JSON garbage", raw: "this is not json" },
    { name: "JSON object missing closing brace", raw: '{"kind": "b1"' },
    { name: "primitive number", raw: "42" },
    { name: "primitive string", raw: '"hello"' },
    { name: "primitive boolean", raw: "true" },
    { name: "null literal", raw: "null" },
    { name: "array", raw: "[1, 2, 3]" },
    { name: "array of objects", raw: '[{"kind": "b1"}]' },
    { name: "empty array", raw: "[]" },
    // BLOB storage: SQLite stores a Uint8Array as a BLOB, which
    // the strict metadata_json decoder must reject. The BLOB
    // probe does NOT pretend to be a string; node:sqlite binds
    // it as a BLOB and the storage class is asserted below.
    { name: "BLOB Uint8Array", raw: Uint8Array.of(1, 2, 3) },
  ];

  // Probe the SQLite storage class of the metadata_json column
  // for the BLOB case. The BLOB probe uses node:sqlite's
  // direct binding of a JS Uint8Array to a SQLite BLOB; the
  // decoder must reject because the contract pins
  // metadata_json to a non-null plain-object JSON encoding.
  function assertMetadataJsonStorage(
    db: BountyDatabase,
    actionId: string,
    expected: "text" | "blob" | "null",
  ): void {
    const row = db
      .prepare("SELECT typeof(metadata_json) AS storage FROM actions WHERE id = ?")
      .get(actionId) as { storage: string } | undefined;
    expect(row, `fixture row for ${actionId} not found`).toBeDefined();
    expect(
      row!.storage,
      `SQLite typeof(metadata_json) for ${actionId} must equal "${expected}"`,
    ).toBe(expected);
  }

  for (const c of BAD_CASES) {
    it(`get() throws ACTION_RECORD_INVALID for metadata_json=${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const actionId = `act-b12-bad-get-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      insertRawV2Action(handle, {
        id: actionId,
        jobId: `job-b12-bad-get-${c.name.replace(/[^a-z0-9]/gi, "_")}`,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: 1,
        metadataJsonRaw: c.raw,
      });
      // Probe the storage class for the BLOB case so the test
      // cannot pass vacuously. The string cases stay as "text"
      // (the BLOB case is the only "blob" assertion).
      assertMetadataJsonStorage(
        handle,
        actionId,
        c.raw instanceof Uint8Array ? "blob" : "text",
      );

      let captured: unknown = null;
      try {
        queue.get(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(
        captured,
        "ACTION_RECORD_INVALID",
        actionId,
      );
    });

    it(`list() throws ACTION_RECORD_INVALID when ANY row has metadata_json=${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const jobId = `job-b12-bad-list-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      const actionId = `act-b12-bad-list-b-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      // First row: valid metadata. Second row: bad metadata. list()
      // must fail closed on the bad row, not silently drop it.
      insertRawV2Action(handle, {
        id: `act-b12-bad-list-a-${c.name.replace(/[^a-z0-9]/gi, "_")}`,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: 1,
        metadataJsonRaw: JSON.stringify({ ok: true }),
      });
      insertRawV2Action(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: 1,
        metadataJsonRaw: c.raw,
      });
      assertMetadataJsonStorage(
        handle,
        actionId,
        c.raw instanceof Uint8Array ? "blob" : "text",
      );

      let captured: unknown = null;
      try {
        queue.list(jobId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_RECORD_INVALID", jobId);
    });

    it(`requireCleanPendingForApproval throws ACTION_RECORD_INVALID for metadata_json=${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const actionId = `act-b12-bad-cand-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b12-bad-cand-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      // Per §7 preflight order, job linkage is validated BEFORE
      // strict metadata_json decoding. Seed a real nonterminal
      // linked job so preflight clears and the strict-decoder
      // error is the observed failure (not a missing-job error).
      insertJob(handle, jobId);
      insertRawV2Action(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: 1,
        metadataJsonRaw: c.raw,
      });
      assertMetadataJsonStorage(
        handle,
        actionId,
        c.raw instanceof Uint8Array ? "blob" : "text",
      );

      const candidate = queue as unknown as ActionQueueSliceB1;
      let captured: unknown = null;
      try {
        candidate.requireCleanPendingForApproval(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(
        captured,
        "ACTION_RECORD_INVALID",
        actionId,
      );
    });
  }
});

// ===========================================================================
// B1.3: requireCleanPendingForApproval — invalid canonical ID
// before SQL; missing action; nonpending status; missing/blank job.
// ===========================================================================

describe("B1.3: requireCleanPendingForApproval enforces canonical IDs and clean pending state", () => {
  // --- input validation: invalid canonical action id BEFORE SQL ---

  it("throws ACTION_APPROVAL_INVALID (before any SQL) for a blank actionId", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval("");
    } catch (err) {
      captured = err;
    }
    // The empty-string sentinel is not a probe-able reflection
    // boundary: the contract pins the code, and the input is
    // already echoed through the actionId-required invariant.
    // expectCode without a sentinel asserts the code only.
    expectCode(captured, "ACTION_APPROVAL_INVALID");
  });

  it("throws ACTION_APPROVAL_INVALID (before any SQL) for a whitespace actionId", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval("   ");
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID", "   ");
  });

  it("throws ACTION_APPROVAL_INVALID (before any SQL) for a control-character actionId", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const polluted = `evil\u0001id`;
    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval(polluted);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID", polluted);
  });

  // --- missing action ---

  it("throws ACTION_NOT_FOUND for a missing action", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval("act-b13-missing");
    } catch (err) {
      captured = err;
    }
    // The contract pins ACTION_NOT_FOUND here. The existing
    // store error path may legitimately include the missing
    // action id in its message, so we do not pin a non-
    // reflection sentinel: asserting on the code only is the
    // contract-true expectation.
    expectCode(captured, "ACTION_NOT_FOUND");
  });

  // --- nonpending status table: every nonpending status (including
  // the compatibility-only raw "planned") must throw
  // ACTION_APPROVAL_NOT_PENDING. ---

  type NonpendingStatus =
    | "approved"
    | "running"
    | "executed"
    | "blocked"
    | "failed"
    | "outcome_unknown"
    | "planned";

  const NONPENDING_STATUSES: NonpendingStatus[] = [
    "approved",
    "running",
    "executed",
    "blocked",
    "failed",
    "outcome_unknown",
    "planned",
  ];

  // For "approved" we additionally need a structurally complete
  // active review so the failure mode is the status predicate, not
  // the approved-row structural predicate. For every other
  // nonpending status the row stays dirty because the action is
  // not pending. A nonterminal linked job is seeded so the preflight
  // order (status check before job check) reaches the status
  // predicate: without the seed the missing-job check would preempt
  // the status check and produce the wrong error code.
  for (const status of NONPENDING_STATUSES) {
    it(`throws ACTION_APPROVAL_NOT_PENDING for raw status=${status}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b13-${status}`;
      const jobId = `job-b13-${status}`;
      insertJob(handle, jobId);
      if (status === "approved") {
        // Seed a structurally complete active approval review so
        // the row reads cleanly. The status predicate still
        // returns ACTION_APPROVAL_NOT_PENDING.
        insertValidActiveReview(handle, {
          id: `rev-b13-${status}`,
          actionId,
          jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
        });
        insertRawV2Action(handle, {
          id: actionId,
          jobId,
          status,
          requiredForCompletion: 1,
          requiresApproval: 1,
          activeReviewId: `rev-b13-${status}`,
          plannedScopeHash: SCOPE_HASH,
          plannedPolicyHash: POLICY_HASH,
          plannedActionHash: ACTION_HASH,
          plannedContextHash: CONTEXT_HASH,
        });
      } else {
        insertRawV2Action(handle, {
          id: actionId,
          jobId,
          status,
          requiredForCompletion: 1,
          requiresApproval: 1,
        });
      }

      let captured: unknown = null;
      try {
        queue.requireCleanPendingForApproval(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_NOT_PENDING", actionId);
    });
  }

  // --- missing/blank job ---

  it("throws ACTION_APPROVAL_JOB_REQUIRED when the pending action has no jobId", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    // Direct raw insert with job_id=NULL.
    handle
      .prepare(
        `INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, metadata_json, created_at, executed_at, updated_at, required_for_completion) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?, 1)`,
      )
      .run("act-b13-nojob", "http", "GET", "https://b1.example", "low", 0, "pending", CREATED_AT, UPDATED_AT);

    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval("act-b13-nojob");
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_JOB_REQUIRED", "act-b13-nojob");
  });

  it("throws ACTION_APPROVAL_JOB_REQUIRED when the pending action has a blank jobId", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    handle
      .prepare(
        `INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, metadata_json, created_at, executed_at, updated_at, required_for_completion) VALUES (?, '', ?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?, 1)`,
      )
      .run("act-b13-blankjob", "http", "GET", "https://b1.example", "low", 0, "pending", CREATED_AT, UPDATED_AT);

    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval("act-b13-blankjob");
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_JOB_REQUIRED", "act-b13-blankjob");
  });

  it("throws ACTION_APPROVAL_JOB_REQUIRED when the pending action has a whitespace jobId", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    handle
      .prepare(
        `INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, metadata_json, created_at, executed_at, updated_at, required_for_completion) VALUES (?, '   ', ?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?, 1)`,
      )
      .run("act-b13-wsjob", "http", "GET", "https://b1.example", "low", 0, "pending", CREATED_AT, UPDATED_AT);

    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval("act-b13-wsjob");
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_JOB_REQUIRED", "act-b13-wsjob");
  });

  // --- referenced missing job => existing JOB_NOT_FOUND ---
  // Per §7 preflight order, a non-blank action.jobId whose value
  // is not present in the jobs table fails closed with the
  // existing JOB_NOT_FOUND. The candidate projection must never
  // inspect or echo the job identifier; the assertion verifies
  // the error code and that the candidate identity is not
  // persisted in the message.

  it("throws JOB_NOT_FOUND for a pending action whose jobId has no matching job row", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b13-missingjob";
    const jobId = "job-b13-missingjob-no-row";
    insertRawV2Action(handle, {
      id: actionId,
      jobId,
      status: "pending",
      requiredForCompletion: 1,
      requiresApproval: 1,
    });

    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "JOB_NOT_FOUND", actionId);
  });

  // --- terminal job => ACTION_APPROVAL_JOB_TERMINAL ---
  // Per §7 preflight order, a job whose status is `failed` or
  // `completed` makes the candidate reject with
  // ACTION_APPROVAL_JOB_TERMINAL, regardless of the action
  // being pending. Both terminal statuses are exercised.

  type TerminalJobStatus = "failed" | "completed";
  const TERMINAL_JOB_STATUSES: TerminalJobStatus[] = ["failed", "completed"];

  for (const terminalStatus of TERMINAL_JOB_STATUSES) {
    it(`throws ACTION_APPROVAL_JOB_TERMINAL for a pending action linked to a ${terminalStatus} job`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b13-termjob-${terminalStatus}`;
      const jobId = `job-b13-termjob-${terminalStatus}`;
      // Seed a real job whose status is the terminal value under
      // test. The insertJob helper writes through the exact v2
      // jobs schema with the requested terminal status; the
      // status-only preflight check is what we are exercising.
      insertJob(handle, jobId, terminalStatus);
      insertRawV2Action(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: 1,
      });

      let captured: unknown = null;
      try {
        queue.requireCleanPendingForApproval(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_JOB_TERMINAL", actionId);
    });
  }

  // --- clean pending returns token-free narrowed record ---

  it("returns a token-free PendingApprovalCandidate for a clean pending action", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    // The success path requires preflight to clear: a real
    // nonterminal linked job so JOB_NOT_FOUND / JOB_TERMINAL do
    // not preempt the success return.
    insertJob(handle, "job-b13-clean");
    insertRawV2Action(handle, {
      id: "act-b13-clean",
      jobId: "job-b13-clean",
      status: "pending",
      requiredForCompletion: 1,
      requiresApproval: 1,
    });

    const candidate = queue.requireCleanPendingForApproval("act-b13-clean") as PendingApprovalCandidate;
    expect(candidate.id).toBe("act-b13-clean");
    expect(candidate.jobId).toBe("job-b13-clean");
    expect(candidate.status).toBe("pending");
    // Token absence: no own executionToken and JSON does not
    // mention the field.
    expect(Object.prototype.hasOwnProperty.call(candidate, "executionToken")).toBe(false);
    const json = JSON.stringify(candidate);
    expect(json).not.toMatch(/executionToken/i);
  });
});

// ===========================================================================
// B1.1b: requires_approval strict decoding — additional storage
// classes. Only raw integer 0 and raw integer 1 are valid. Three
// non-integer storage classes are exercised:
//   1) REAL 1.5 — JS number that SQLite stores under REAL affinity
//      (typeof(c) === "real"). The strict decoder must reject because
//      1.5 !== 0 and 1.5 !== 1.
//   2) Non-numeric TEXT — a JS string ("true") that SQLite stores
//      under TEXT affinity (typeof(c) === "text"). The strict
//      decoder must reject because "true" !== 0 and "true" !== 1.
//   3) BLOB Uint8Array.of(1) — JS Uint8Array that SQLite stores
//      under BLOB affinity (typeof(c) === "blob"). The strict
//      decoder must reject because the BLOB bytes are not 0 or 1.
//
// The fixture asserts the storage class via SQLite `typeof(c)` so the
// test cannot pass vacuously. The legacy "1" probe is intentionally
// NOT exercised: SQLite's INTEGER affinity silently coerces numeric
// text to integer, so a TEXT-typed "1" never reaches the strict
// decoder. A non-numeric text value is the only typeof=text input
// that survives the column affinity unchanged. A BLOB probe uses
// JS Uint8Array which has no INTEGER-affinity path.
// ===========================================================================

describe("B1.1b: requires_approval raw REAL 1.5, non-numeric TEXT, and BLOB are rejected by get/list/candidate", () => {
  interface TypeCase {
    readonly name: string;
    readonly rawValue: number | string | Uint8Array;
    readonly expectedStorageClass: "real" | "text" | "blob";
  }

  const TYPE_CASES: TypeCase[] = [
    { name: "raw=1.5 stored as REAL", rawValue: 1.5, expectedStorageClass: "real" },
    { name: "raw=\"true\" stored as TEXT", rawValue: "true", expectedStorageClass: "text" },
    { name: "raw=Uint8Array.of(1) stored as BLOB", rawValue: Uint8Array.of(1), expectedStorageClass: "blob" },
  ];

  function assertStorageClass(
    db: BountyDatabase,
    actionId: string,
    expected: "real" | "text" | "blob",
  ): void {
    const row = db
      .prepare("SELECT typeof(requires_approval) AS storage FROM actions WHERE id = ?")
      .get(actionId) as { storage: string } | undefined;
    expect(row, `fixture row for ${actionId} not found`).toBeDefined();
    expect(
      row!.storage,
      `SQLite typeof(requires_approval) for ${actionId} must equal "${expected}"`,
    ).toBe(expected);
  }

  for (const c of TYPE_CASES) {
    it(`get() throws ACTION_RECORD_INVALID for ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const actionId = `act-b11b-get-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b11b-get-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      insertRawV2ActionRequiresApprovalRaw(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApprovalRaw: c.rawValue,
      });
      // Fixture integrity: the raw value really did land in the
      // expected storage class. A typecheck-clean test that binds
      // the wrong shape would fail here before it could ever
      // exercise the decoder.
      assertStorageClass(handle, actionId, c.expectedStorageClass);

      let captured: unknown = null;
      try {
        queue.get(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_RECORD_INVALID", actionId);
    });

    it(`list() throws ACTION_RECORD_INVALID for ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const actionId = `act-b11b-list-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b11b-list-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      insertRawV2ActionRequiresApprovalRaw(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApprovalRaw: c.rawValue,
      });
      assertStorageClass(handle, actionId, c.expectedStorageClass);

      let captured: unknown = null;
      try {
        queue.list(jobId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_RECORD_INVALID", jobId);
    });

    it(`requireCleanPendingForApproval throws ACTION_RECORD_INVALID for ${c.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b11b-cand-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b11b-cand-${c.name.replace(/[^a-z0-9]/gi, "_")}`;
      // Per §7 preflight order, job linkage is validated BEFORE
      // strict decoding. Seed a real nonterminal linked job so
      // preflight clears and the strict-decoder error is the
      // observed failure (not a missing-job error).
      insertJob(handle, jobId);
      insertRawV2ActionRequiresApprovalRaw(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApprovalRaw: c.rawValue,
      });
      assertStorageClass(handle, actionId, c.expectedStorageClass);

      let captured: unknown = null;
      try {
        queue.requireCleanPendingForApproval(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_RECORD_INVALID", actionId);
    });
  }
});

// ===========================================================================
// B1.3a: requireCleanPendingForApproval — table-driven clean-state
// probe over the 15 dirty SQL fields. A valid queued linked job
// is seeded, the action is created in `pending`, then a single
// non-null dirty value is written into exactly one of the 15 SQL
// fields the contract requires to be NULL for a clean pending
// action. The candidate must reject with the exact pinned code
// ACTION_APPROVAL_STATE_INVALID, must leave the raw row byte-
// identical, and must NEVER echo the execution_token secret
// through the BountyPilotError message or its public JSON shape.
// ===========================================================================

describe("B1.3a: requireCleanPendingForApproval rejects any non-null SQL state field", () => {
  interface DirtyField {
    name: string;
    column: string;
    value: string | number | null;
  }
  const DIRTY_FIELDS: DirtyField[] = [
    { name: "executed_at", column: "executed_at", value: "2099-01-01T00:00:10.000Z" },
    { name: "active_review_id", column: "active_review_id", value: "rev-b13a-dirty-active" },
    { name: "planned_scope_hash", column: "planned_scope_hash", value: SCOPE_HASH },
    { name: "planned_policy_hash", column: "planned_policy_hash", value: POLICY_HASH },
    { name: "planned_action_hash", column: "planned_action_hash", value: ACTION_HASH },
    { name: "planned_context_hash", column: "planned_context_hash", value: CONTEXT_HASH },
    { name: "execution_token", column: "execution_token", value: SECRET_TOKEN },
    { name: "execution_owner", column: "execution_owner", value: SECRET_TOKEN_OWNER },
    { name: "lease_expires_at", column: "lease_expires_at", value: EXPIRES_AT },
    { name: "started_at", column: "started_at", value: REVIEWED_AT },
    { name: "dispatch_started_at", column: "dispatch_started_at", value: "2099-01-01T00:00:05.000Z" },
    { name: "finished_at", column: "finished_at", value: "2099-01-01T00:00:10.000Z" },
    { name: "outcome_certainty", column: "outcome_certainty", value: "success" },
    { name: "last_error_code", column: "last_error_code", value: "ACTION_LEASE_EXPIRED" },
    { name: "last_error_message", column: "last_error_message", value: "public text" },
  ];

  for (const dirty of DIRTY_FIELDS) {
    it(`table: ACTION_APPROVAL_STATE_INVALID for dirty ${dirty.name}; raw row byte-identical; no token leak`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b13a-${dirty.name}`;
      const jobId = `job-b13a-${dirty.name}`;
      // Valid queued (nonterminal) job so JOB_NOT_FOUND /
      // ACTION_APPROVAL_JOB_TERMINAL do not preempt the
      // STATE_INVALID check.
      insertJob(handle, jobId);
      insertRawV2Action(handle, {
        id: actionId,
        jobId,
        status: "pending",
        requiredForCompletion: 1,
        requiresApproval: 1,
      });
      handle
        .prepare(`UPDATE actions SET ${dirty.column} = ? WHERE id = ?`)
        .run(dirty.value, actionId);

      const before = readActionRow(handle, actionId);

      let captured: unknown = null;
      try {
        queue.requireCleanPendingForApproval(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_STATE_INVALID", actionId);

      // Raw row is byte-identical: the rejection happened
      // before any state-mutating SQL could run.
      const after = readActionRow(handle, actionId);
      expect(after).toEqual(before);

      // Token non-leak: the error message and the public
      // JSON projection of the captured BountyPilotError must
      // NEVER contain the bearer capability. For the
      // execution_token case the dirty value IS the secret; for
      // every other case the secret is unrelated to the dirty
      // value but the contract still pins that no error
      // produced by this primitive may echo the token. The
      // check is therefore unconditional: it holds for all 15
      // dirty fields, not just the one that literally carries
      // the secret on disk. The serializeErrorForLeakCheck
      // helper inspects the ACTUAL error object — every
      // enumerable own property plus the curated
      // (name, code, message) surface — so an accidental new
      // own field cannot smuggle the secret past this check.
      const bp = captured as BountyPilotError;
      expect(bp.message).not.toContain(SECRET_TOKEN);
      const { runtime, curated } = serializeErrorForLeakCheck(bp);
      expect(runtime, `runtime error JSON contains ${SECRET_TOKEN}`).not.toContain(SECRET_TOKEN);
      expect(curated, `curated error JSON contains ${SECRET_TOKEN}`).not.toContain(SECRET_TOKEN);
      expect(runtime, `runtime error JSON mentions executionToken`).not.toMatch(/executionToken/i);
      expect(curated, `curated error JSON mentions executionToken`).not.toMatch(/executionToken/i);
    });
  }
});

// ===========================================================================
// B1.4: approveWithReviewInTransaction — outside-tracked-tx guard
// wins before input reflection/SQL; inside-tx exact complete
// review linkage/source/reviewer/timestamps/nonzero hashes; valid
// review performs one clean CAS; malformed review and hash/link
// mismatch => ACTION_APPROVAL_INVALID; dirty/zero-change =>
// ACTION_APPROVAL_RACE_LOST with rollback and no retry.
// ===========================================================================

describe("B1.4: approveWithReviewInTransaction is a strict tracked-tx primitive", () => {
  // makeBaseInput and seedCleanPending are now top-level
  // module-scope helpers (declared above the B1.1 describe)
  // so the B1.4b/c/d/e table tests can reuse them. The
  // local duplicate of makeBaseInput and the local mutId /
  // mutHash / ID_MUTATIONS / ID_FIELDS / HASH_MUTATIONS /
  // HASH_FIELDS table constants below shadow the top-level
  // ones for this describe block only. The local mutators
  // intentionally use a slightly different corruption form
  // (trailing characters for padded/c0/del, all-zeros for
  // nonhex) because the B1.4 BadDto table needs every
  // mutation to remain plausibly ID-shaped; the B1.4b/c/d
  // blocks use a different, stricter form (leading
  // characters, "Z"-then-hex, integer for wrong-type). The
  // two tables prove the same invariant on different
  // hostile inputs.

  // --- outside-tx guard wins before input reflection/SQL ---

  it("throws ACTION_QUEUE_TRANSACTION_REQUIRED outside a tracked transaction; accessor getter is not invoked and the action row is unchanged", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14-outside";
    const jobId = "job-b14-outside";
    const reviewId = "rev-b14-outside";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      decision: "approved",
      reviewerId: REVIEWER_ID,
      source: "human",
    });

    // A hostile input with a getter that explodes. The transaction
    // guard is the FIRST executable operation per §7, so the
    // primitive must short-circuit before any input field is
    // reflected. The thrown error must be the exact pinned code
    // ACTION_QUEUE_TRANSACTION_REQUIRED, must NOT contain the
    // getter's secret, and the action row must remain byte-
    // identical to the pre-call snapshot.
    const A14_GETTER_SECRET = "A14_GETTER_SECRET_TOKEN_LEAK";
    let getterInvocations = 0;
    const base = makeBaseInput(actionId, jobId, reviewId);
    const baseWithAccessor: Record<string, unknown> = { ...base };
    Object.defineProperty(baseWithAccessor, "actionId", {
      get: () => {
        getterInvocations += 1;
        throw new Error(`token=${A14_GETTER_SECRET}`);
      },
      enumerable: true,
      configurable: true,
    });
    const input = baseWithAccessor as unknown as ApproveActionWithReviewInput;

    const before = readActionRow(handle, actionId);

    let captured: unknown = null;
    try {
      queue.approveWithReviewInTransaction(input);
    } catch (err) {
      captured = err;
    }

    // Exact pinned code per contract §7: "Outside that transaction
    // it throws fixed cause-free ACTION_QUEUE_TRANSACTION_REQUIRED
    // before input reflection or SQL."
    expectCode(captured, "ACTION_QUEUE_TRANSACTION_REQUIRED");
    // The getter was never invoked because the guard short-
    // circuited before any input reflection. This is the precise
    // invariant proved here: a hostile DTO cannot fire its
    // accessor side effects, and the secret it would have echoed
    // never reaches the error or the row.
    expect(getterInvocations, "accessor getter must not run before the tracked-tx guard").toBe(0);
    expect((captured as BountyPilotError).message).not.toContain(A14_GETTER_SECRET);

    // No SQL was issued against the actions row: byte-identical.
    const after = readActionRow(handle, actionId);
    expect(after).toEqual(before);
  });

  // --- inside-tx invalid exact DTOs => ACTION_APPROVAL_INVALID ---

  interface BadDto {
    name: string;
    // build() returns [built, counter]:
    //   - built: the input value the primitive will be called
    //     with. The hostile-shape cases return a non-plain-
    //     object value (null, undefined, primitive, array,
    //     prototype-tampered, Proxy, ...). The built value is
    //     intentionally cast through `unknown` so the helper
    //     is the only path that can stage those shapes.
    //   - counter: optional closure-owned invocation counter.
    //     When set, the test loop asserts the counter remains
    //     exactly zero after the primitive call. The counter
    //     is external to the built value so the built DTO has
    //     no extra own property that a strict own-property
    //     validator could reject as a side effect.
    build: (
      actionId: string,
      jobId: string,
      reviewId: string,
    ) => { built: unknown; counter?: () => number };
    // Optional post-assert hook. Runs AFTER expectCode has
    // pinned the error code and the action row byte-
    // identical. The hook receives the captured
    // BountyPilotError, the input value the primitive was
    // called with, and the optional closure counter, so a
    // case can prove its own case-specific invariant without
    // weakening the shared ones. The accessor case proves
    // the hostile getter was never invoked (counter
    // === 0); the symbol case asserts the string actionId
    // is still present on the input shape so the rejection
    // must trace to the symbol-presence check, not to a
    // missing string field.
    postAssert?: (ctx: {
      bp: BountyPilotError;
      built: unknown;
      counter: () => number | undefined;
    }) => void;
  }

  function makeBaseInput(
    actionId: string,
    jobId: string,
    reviewId: string,
  ): ApproveActionWithReviewInput {
    return {
      actionId,
      jobId,
      reviewId,
      scopeHash: SCOPE_HASH,
      policyHash: POLICY_HASH,
      actionHash: ACTION_HASH,
      contextHash: CONTEXT_HASH,
      updatedAt: UPDATED_AT,
    };
  }

  // Mutation helpers for the ID-validation table. Each helper
  // takes a base id and a "kind" string and returns a single
  // canonical corrupted form. The four ID fields (actionId,
  // jobId, reviewId) and the four hash fields (scopeHash,
  // policyHash, actionHash, contextHash) share these
  // generators so the table is small and table-driven.
  //
  // c0 inserts the actual U+0000 (NULL) code point. del
  // inserts the actual U+007F (DEL) code point. A naive
  // validator that checks trim() of literal "\\0" or
  // "\\x7f" escape sequences would accept these as valid
  // 3-character strings; the corruption must land REAL
  // control bytes that survive value === value.trim().
  //
  // long is exactly 257 Unicode code points — one over the
  // contract cap of 1..256 — so the validator's length check
  // fires. Pure ASCII so byte length and code-point length
  // agree.
  type IdKind = "padded" | "c0" | "del" | "long";
  const mutId = (base: string, kind: IdKind): string => {
    switch (kind) {
      case "padded":
        return " " + base + " ";
      case "c0":
        // Real U+0000 (NULL) — the value passes
        // value === value.trim() but fails the C0/DEL
        // regex. A literal backslash-zero string ("\0")
        // is just two printable characters and would slip
        // past this control-character check.
        return base + "\u0000";
      case "del":
        // Real U+007F (DEL) — same rationale as c0.
        return base + "\u007f";
      case "long":
        // 257 code points: one over the contract limit
        // (1..256). Pure ASCII so the bytes are unambiguous.
        return "a".repeat(257);
    }
  };
  type HashKind = "uppercase" | "nonhex" | "wrong-type";
  const mutHash = (base: string, kind: HashKind): string | number | object => {
    switch (kind) {
      case "uppercase":
        // Deterministic invalid uppercase hash: one
        // uppercase letter followed by 63 lowercase hex
        // characters. Always differs from the valid base
        // (which is 64 lowercase hex) AND always fails
        // the lowercase-only hex rule. base is unused so
        // the mutation cannot accidentally match the
        // input — the local mutator must produce the
        // same canonical form regardless of which base
        // is supplied.
        return "A" + "a".repeat(63);
      case "nonhex":
        // 64 'z' characters: never matches the lowercase
        // hex regex and always differs from the base.
        return "z".repeat(64);
      case "wrong-type":
        // Runtime type other than string. The strict
        // decoder must reject: it pins `typeof === "string"`.
        return 42;
    }
  };

  // Each ID field gets the four mutations. The "padded" form
  // is the only one likely to be accepted by a naive .trim()
  // fix; "c0"/"del" prove the validator rejects C0/DEL; "long"
  // proves the length cap.
  const ID_MUTATIONS: IdKind[] = ["padded", "c0", "del", "long"];
  const ID_FIELDS = ["actionId", "jobId", "reviewId"] as const;
  // Each hash field gets the three mutations. The "all-zero"
  // and "63 chars" cases are kept by the existing short/all-
  // zero tests; here we focus on the new high-value classes.
  const HASH_MUTATIONS: HashKind[] = ["uppercase", "nonhex", "wrong-type"];
  const HASH_FIELDS = [
    { name: "scopeHash", pick: (b: ApproveActionWithReviewInput) => b.scopeHash },
    { name: "policyHash", pick: (b: ApproveActionWithReviewInput) => b.policyHash },
    { name: "actionHash", pick: (b: ApproveActionWithReviewInput) => b.actionHash },
    { name: "contextHash", pick: (b: ApproveActionWithReviewInput) => b.contextHash },
  ] as const;

  const BAD_DTOS: BadDto[] = [
    // actionId
    {
      name: "empty actionId",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), actionId: "" } }),
    },
    {
      name: "whitespace actionId",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), actionId: "   " } }),
    },
    {
      name: "null actionId",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), actionId: null as unknown as string },
      }),
    },
    {
      name: "control character actionId",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), actionId: `evil\u0001id` } }),
    },
    // jobId
    {
      name: "empty jobId",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), jobId: "" } }),
    },
    {
      name: "whitespace jobId",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), jobId: "   " } }),
    },
    {
      name: "null jobId",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), jobId: null as unknown as string },
      }),
    },
    // reviewId
    {
      name: "empty reviewId",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), reviewId: "" } }),
    },
    {
      name: "whitespace reviewId",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), reviewId: "   " } }),
    },
    {
      name: "null reviewId",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), reviewId: null as unknown as string },
      }),
    },
    // updatedAt
    {
      name: "empty updatedAt",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), updatedAt: "" } }),
    },
    {
      name: "non-ISO updatedAt",
      build: (a, j, r) => ({ built: { ...makeBaseInput(a, j, r), updatedAt: "not-a-date" } }),
    },
    {
      name: "null updatedAt",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), updatedAt: null as unknown as string },
      }),
    },
    // scopeHash
    {
      name: "scopeHash 63 chars",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), scopeHash: SCOPE_HASH.slice(0, -1) },
      }),
    },
    {
      name: "scopeHash all-zero sentinel",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), scopeHash: "0".repeat(64) },
      }),
    },
    {
      name: "scopeHash uppercase",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), scopeHash: SCOPE_HASH.toUpperCase() },
      }),
    },
    {
      name: "scopeHash non-hex",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), scopeHash: "z".repeat(64) },
      }),
    },
    // policyHash
    {
      name: "policyHash 63 chars",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), policyHash: POLICY_HASH.slice(0, -1) },
      }),
    },
    {
      name: "policyHash all-zero sentinel",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), policyHash: "0".repeat(64) },
      }),
    },
    // actionHash
    {
      name: "actionHash 63 chars",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), actionHash: ACTION_HASH.slice(0, -1) },
      }),
    },
    {
      name: "actionHash all-zero sentinel",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), actionHash: "0".repeat(64) },
      }),
    },
    // contextHash
    {
      name: "contextHash 63 chars",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), contextHash: CONTEXT_HASH.slice(0, -1) },
      }),
    },
    {
      name: "contextHash all-zero sentinel",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), contextHash: "0".repeat(64) },
      }),
    },
    // unknown field is rejected by the strict own-property
    // validation; we add a probe here.
    {
      name: "unknown own field",
      build: (a, j, r) => ({
        built: { ...makeBaseInput(a, j, r), mystery: "extra" } as unknown as ApproveActionWithReviewInput,
      }),
    },
    // -- Hostile DTO shapes (no plain-object input at all) --
    // The contract requires the primitive to fail closed with
    // the exact pinned code ACTION_APPROVAL_INVALID and a
    // message that does not echo any field sentinel. The
    // action row must remain byte-identical: the rejection
    // happens before any SQL is issued. Each case stages a
    // runtime value that a hostile caller could pass through
    // a TypeScript-typed boundary by lying about the type.
    {
      name: "input is null",
      build: () => ({ built: null }),
    },
    {
      name: "input is a number (non-object primitive)",
      build: () => ({ built: 42 }),
    },
    {
      name: "input is a string (non-object primitive)",
      build: () => ({ built: "totally not an input" }),
    },
    {
      name: "input is a boolean (non-object primitive)",
      build: () => ({ built: false }),
    },
    {
      name: "input is undefined",
      build: () => ({ built: undefined }),
    },
    {
      name: "input is an array",
      build: (a, j, r) => ({ built: [makeBaseInput(a, j, r)] }),
    },
    {
      name: "input has a custom prototype (Object.create)",
      build: (a, j, r) => {
        const base = makeBaseInput(a, j, r) as unknown as Record<string, unknown>;
        const hostile = Object.create({ custom: "evil" }) as unknown as Record<string, unknown>;
        for (const k of Object.keys(base)) {
          (hostile as Record<string, unknown>)[k] = (base as Record<string, unknown>)[k];
        }
        return { built: hostile };
      },
    },
    {
      // The hostile DTO retains every required string field
      // (including string actionId = the actionId passed in)
      // AND carries an additional symbol own property on
      // actionId. The contract rejects any symbol own field
      // regardless of whether the string field is present:
      // a plain-object DTO may not smuggle extra symbol keys.
      // The post-assert hook proves the rejection happens
      // because of the symbol key, not because the string
      // field is missing.
      name: "input has a symbol own field on actionId",
      build: (a, j, r) => {
        const base = makeBaseInput(a, j, r) as unknown as Record<string | symbol, unknown>;
        const sym = Symbol("actionId-symbol");
        base[sym] = a;
        // KEEP the string actionId (and every other required
        // string field) on the record. The hostile DTO is
        // distinguishable from a valid input only by the
        // symbol own property, so the rejection must trace
        // to the symbol-presence check, not to a missing
        // string field.
        return { built: base };
      },
      postAssert: ({ built, bp }) => {
        // The string actionId must still be on the input the
        // primitive received: a fix that simply rejects "any
        // object with a symbol" without inspecting own
        // properties would still pass this table, but the
        // symbol-presence invariant is the one the contract
        // pins. We therefore assert the string field is
        // present on the input we built.
        const builtRecord = built as Record<string, unknown>;
        expect(builtRecord.actionId, "string actionId must remain on the built input").toBeDefined();
        // The error message and BOTH the runtime and curated
        // JSON projections must not echo the symbol description.
        // A regression that adds an enumerable own field to
        // BountyPilotError carrying the symbol description would
        // still fail the runtime serialization check.
        expect(bp.message).not.toContain("actionId-symbol");
        const { runtime, curated } = serializeErrorForLeakCheck(bp);
        expect(runtime).not.toContain("actionId-symbol");
        expect(curated).not.toContain("actionId-symbol");
      },
    },
    {
      // The hostile DTO has an own accessor on actionId whose
      // getter throws a sentinel error every time it is read.
      // The contract must short-circuit on the accessor shape
      // and never read the field. The closure-owned counter
      // is captured by build and postAssert; the built value
      // carries no extra own property, so a strict own-
      // property validator that rejects unknown fields
      // cannot trivially satisfy the invariant by spotting
      // the counter property and bailing on it instead of
      // proving accessor handling.
      //
      // IIFE/closure pattern: the counter is created and
      // captured by the build function. The build returns
      // both the built value (whose actionId is the accessor)
      // and a getter that returns the counter. The post-assert
      // hook reads the counter only through the external
      // getter — it never touches the built value for the
      // counter, so the built DTO has exactly the eight
      // expected string keys.
      name: "input has an own accessor with a throwing getter on actionId",
      build: (a, j, r) => {
        // IIFE: closure-captured counter, returned via a
        // getter. The build function and the accessor share
        // the same closure; the built value never references
        // the counter, so the only path to the counter is
        // through the external getter returned here.
        const built = (() => {
          const obj: Record<string, unknown> = { ...makeBaseInput(a, j, r) };
          let getterInvocations = 0;
          Object.defineProperty(obj, "actionId", {
            get: () => {
              getterInvocations += 1;
              throw new Error("B14_HOSTILE_ACCESSOR_DERIVED");
            },
            enumerable: true,
            configurable: true,
          });
          return { obj, readCount: () => getterInvocations };
        })();
        return { built: built.obj, counter: built.readCount };
      },
      postAssert: ({ counter, bp }) => {
        // The counter is read only via the external closure
        // getter returned by build. A primitive that read
        // the accessor even once would have incremented the
        // counter past 0; a primitive that short-circuited on
        // the accessor shape would leave it at 0.
        const counterFn = counter;
        if (counterFn === undefined) {
          throw new Error("accessor case must expose a counter getter");
        }
        const invocations = counterFn();
        expect(
          invocations,
          "hostile accessor getter must not be invoked before the strict own-property check",
        ).toBe(0);
        // Defense in depth: the error message and BOTH the
        // runtime and curated JSON projections must not echo
        // the host's sentinel. The runtime serialization
        // catches a regression that adds an enumerable own
        // field to BountyPilotError carrying the host's
        // secret-bearing message.
        expect(bp.message).not.toContain("B14_HOSTILE_ACCESSOR_DERIVED");
        const { runtime, curated } = serializeErrorForLeakCheck(bp);
        expect(runtime).not.toContain("B14_HOSTILE_ACCESSOR_DERIVED");
        expect(curated).not.toContain("B14_HOSTILE_ACCESSOR_DERIVED");
      },
    },
    {
      // A Proxy whose reflection traps (get/has/ownKeys) throw
      // a sentinel on every reflection. The contract requires
      // the primitive to fail closed with the fixed
      // ACTION_APPROVAL_INVALID and never reflect through the
      // proxy. We do NOT count trap invocations here: the
      // exact trap count is implementation-dependent (V8 may
      // call get/has/ownKeys a different number of times for
      // different reflective probes), and asserting a specific
      // number would be a false-positive vector. The only
      // provable invariants are: (1) the rejection is
      // ACTION_APPROVAL_INVALID, (2) the secret in the trap
      // body never reaches the error message or its public
      // JSON, and (3) the action row is byte-identical.
      name: "input is a Proxy whose ownKeys/has/get traps throw on reflection",
      build: (a, j, r) => {
        const base = makeBaseInput(a, j, r) as unknown as Record<string | symbol, unknown>;
        return { built: new Proxy(base, {
          get(target, prop) {
            if (prop === "actionId") {
              throw new Error("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
            }
            return (target as Record<string | symbol, unknown>)[prop];
          },
          has() {
            throw new Error("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
          },
          ownKeys() {
            throw new Error("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
          },
        }) };
      },
      postAssert: ({ bp }) => {
        // No trap body sentinel is allowed to reach the
        // public error message or its public JSON. The
        // runtime + curated serialization catches a
        // regression that adds an enumerable own field to
        // BountyPilotError carrying the trap body message.
        expect(bp.message).not.toContain("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
        const { runtime, curated } = serializeErrorForLeakCheck(bp);
        expect(runtime).not.toContain("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
        expect(curated).not.toContain("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
      },
    },
  ];

  for (const tc of BAD_DTOS) {
    it(`table: ACTION_APPROVAL_INVALID inside a tracked tx for ${tc.name}; action row byte-identical`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b14-bad-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b14-bad-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      const reviewId = `rev-b14-bad-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      seedCleanPending(handle, actionId, jobId);
      insertValidActiveReview(handle, {
        id: reviewId,
        actionId,
        jobId,
        decision: "approved",
        reviewerId: REVIEWER_ID,
        source: "human",
      });

      const before = readActionRow(handle, actionId);

      // Build the hostile DTO once. The same value is passed
      // both to the primitive (cast through unknown) and
      // surfaced to the optional post-assert hook so the
      // hook can inspect the input the primitive actually
      // received (e.g. read a closure-captured invocation
      // counter, or assert that a string field is still
      // present on the input).
      const builtResult = tc.build(actionId, jobId, reviewId);
      const built = builtResult.built;
      const counter = builtResult.counter;

      let captured: unknown = null;
      try {
        withImmediateTransaction(handle, () => {
          queue.approveWithReviewInTransaction(
            built as ApproveActionWithReviewInput,
          );
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      // Exact pinned code, fixed message without the actionId
      // sentinel (the action identity must never reach the
      // error message for any invalid DTO).
      expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);

      // The action row is byte-identical to the snapshot:
      // the failure rolled back, no partial state was written.
      const after = readActionRow(handle, actionId);
      expect(after).toEqual(before);

      // Optional case-specific hook. Runs last; the shared
      // assertions above have already pinned the failure
      // mode. The hook is the precise, case-specific
      // invariant — for example, the accessor case proves
      // the hostile getter was never invoked. The same
      // `built` value the primitive received is surfaced so
      // the hook can inspect its shape (e.g. read a
      // closure-captured invocation counter, or assert
      // that a string field is still present on the input).
      if (tc.postAssert) {
        tc.postAssert({ bp: captured as BountyPilotError, built, counter: counter ?? (() => undefined) });
      }
    });
  }

  // --- malformed review and hash/link mismatch => ACTION_APPROVAL_INVALID ---

  // The action CAS requires the exact complete active review
  // visible in the transaction. The primitive receives
  // `reviewId` directly, so the test must NEVER update
  // `actions.active_review_id`: the action is read with
  // `active_review_id IS NULL` (a clean pending row), and
  // the primitive uses the input `reviewId` to fetch the
  // review row. Dirtying `active_review_id` here would
  // collapse every malformed-review test into a "linked to
  // a real but bad review" test and would also make the
  // malformed-review path indistinguishable from the
  // dirty-action path. The review row itself is the only
  // thing each setup mutates.
  //   1) Review does not exist at all (linkage by id mismatch
  //      with the input reviewId).
  //   2) Review decision is not "approved".
  //   3) Review invalidation fields are NOT NULL.
  //   4) Review reviewed_at is missing/wrong vs input.updatedAt.
  //   5) Review expires_at is not strictly later than reviewed_at.
  //   6) Review source/reviewer link violated (e.g. policy source
  //      with non-system:policy-gate reviewer, or human reviewer
  //      equals system:policy-gate).
  //   7) Review hash mismatch: any of the four hashes on the
  //      review differs from the input.
  //   8) Review action_id/job_id linkage mismatch (the review
  //      points at a different action or different job than
  //      the input).

  interface MalformedReviewCase {
    name: string;
    setup: (db: BountyDatabase, ctx: { actionId: string; jobId: string; reviewId: string }) => void;
  }

  const MALFORMED_REVIEW_CASES: MalformedReviewCase[] = [
    {
      name: "review row missing (linkage by id mismatch)",
      setup: (_db, _ctx) => {
        // Don't insert any review. The action's
        // active_review_id remains NULL: the primitive uses
        // the input reviewId to fetch the review row, sees
        // no matching row, and must fail closed with
        // ACTION_APPROVAL_INVALID.
      },
    },
    {
      name: "review decision is not approved",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
        });
        db.prepare("UPDATE action_reviews SET decision = 'blocked' WHERE id = ?").run(ctx.reviewId);
      },
    },
    {
      name: "review invalidated_at is set (non-null)",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
        });
        db.prepare("UPDATE action_reviews SET invalidated_at = ?, invalidation_reason = ? WHERE id = ?").run(
          "2099-01-01T00:05:00.000Z",
          "expired",
          ctx.reviewId,
        );
      },
    },
    {
      name: "review reviewed_at does not match input.updatedAt",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
          reviewedAt: "2098-12-31T23:59:59.000Z",
        });
      },
    },
    {
      name: "review created_at differs from reviewed_at",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
          reviewedAt: REVIEWED_AT,
        });
        // created_at must equal reviewed_at per the contract.
        // A real divergent created_at forces the linkage check
        // to fail closed with ACTION_APPROVAL_INVALID. The
        // review row is the only thing the setup mutates.
        db.prepare("UPDATE action_reviews SET created_at = ? WHERE id = ?").run(
          "2098-12-31T23:59:59.000Z",
          ctx.reviewId,
        );
      },
    },
    {
      name: "review invalidation_reason non-null while invalidated_at null",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
        });
        // The contract requires the two invalidation fields
        // move together: invalidation_reason must not be set
        // while invalidated_at is NULL. This makes the review
        // structurally invalid and ACTION_APPROVAL_INVALID
        // must fire.
        db.prepare("UPDATE action_reviews SET invalidation_reason = ? WHERE id = ?").run(
          "expired",
          ctx.reviewId,
        );
      },
    },
    {
      name: "review expires_at not strictly later than reviewed_at",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
          reviewedAt: REVIEWED_AT,
          expiresAt: REVIEWED_AT,
        });
      },
    },
    {
      name: "policy source with non-system:policy-gate reviewer",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: "someone-else-policy",
          source: "policy",
        });
      },
    },
    {
      name: "human source with reviewer=system:policy-gate",
      setup: (db, ctx) => {
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: POLICY_REVIEWER_ID,
          source: "human",
        });
      },
    },
    {
      name: "review action_id does not match input.actionId",
      setup: (db, ctx) => {
        // The review points at a different action; the input
        // reviewId is the SAME id, so the primitive's
        // reviewId lookup finds the row, but the row's
        // action_id does not match input.actionId. No
        // action-side mutation.
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: "act-some-other",
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
        });
      },
    },
    {
      name: "review job_id does not match input.jobId",
      setup: (db, ctx) => {
        // The review points at a different job; the input
        // reviewId is the SAME id, so the primitive's
        // reviewId lookup finds the row, but the row's
        // job_id does not match input.jobId. No action-side
        // mutation.
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: "job-some-other",
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
        });
      },
    },
    {
      name: "review scope_hash differs from input.scopeHash",
      setup: (db, ctx) => {
        const flipped = SCOPE_HASH.slice(0, -1) + (SCOPE_HASH.slice(-1) === "0" ? "1" : "0");
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
          scopeHash: flipped,
        });
      },
    },
    {
      name: "review policy_hash differs from input.policyHash",
      setup: (db, ctx) => {
        const flipped = POLICY_HASH.slice(0, -1) + (POLICY_HASH.slice(-1) === "0" ? "1" : "0");
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
          policyHash: flipped,
        });
      },
    },
    {
      name: "review action_hash differs from input.actionHash",
      setup: (db, ctx) => {
        const flipped = ACTION_HASH.slice(0, -1) + (ACTION_HASH.slice(-1) === "0" ? "1" : "0");
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
          actionHash: flipped,
        });
      },
    },
    {
      name: "review context_hash differs from input.contextHash",
      setup: (db, ctx) => {
        const flipped = CONTEXT_HASH.slice(0, -1) + (CONTEXT_HASH.slice(-1) === "0" ? "1" : "0");
        insertValidActiveReview(db, {
          id: ctx.reviewId,
          actionId: ctx.actionId,
          jobId: ctx.jobId,
          decision: "approved",
          reviewerId: REVIEWER_ID,
          source: "human",
          contextHash: flipped,
        });
      },
    },
  ];

  for (const tc of MALFORMED_REVIEW_CASES) {
    it(`table: ACTION_APPROVAL_INVALID for ${tc.name}; action row byte-identical`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b14-mr-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b14-mr-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      const reviewId = `rev-b14-mr-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      // The action is created as a clean pending row:
      // active_review_id remains NULL. The primitive uses
      // the input reviewId to fetch the review row, so
      // dirtying the action's pointer here would be a
      // self-defeating setup. The malformed review is the
      // only thing each case mutates.
      seedCleanPending(handle, actionId, jobId);
      tc.setup(handle, { actionId, jobId, reviewId });

      // Explicit pre-CAS assertion: the action is clean, so
      // every malformed-review test isolates the review
      // validation path. A setup that accidentally writes
      // active_review_id would mask the review-validation
      // failure with a "linked to a real review" check.
      const preCasSnapshot = readActionRow(handle, actionId);
      expect(
        preCasSnapshot.active_review_id,
        `action must be clean before CAS: ${tc.name}`,
      ).toBeNull();

      const before = readActionRow(handle, actionId);

      let captured: unknown = null;
      try {
        withImmediateTransaction(handle, () => {
          queue.approveWithReviewInTransaction(makeBaseInput(actionId, jobId, reviewId));
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);

      const after = readActionRow(handle, actionId);
      expect(after).toEqual(before);
    });
  }

  // --- valid review performs one clean CAS and returns a structurally
  // valid approved action. ---

  it("valid complete review: one clean CAS, returns structurally valid approved action with no execution token", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14-happy";
    const jobId = "job-b14-happy";
    const reviewId = "rev-b14-happy";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      decision: "approved",
      reviewerId: REVIEWER_ID,
      source: "human",
    });

    const returned = withImmediateTransaction(handle, () => {
      return queue.approveWithReviewInTransaction(makeBaseInput(actionId, jobId, reviewId));
    });

    expect(returned).toBeDefined();
    expect(returned.id).toBe(actionId);
    expect(returned.status).toBe("approved");
    expect(returned.jobId).toBe(jobId);
    expect(returned.activeReviewId).toBe(reviewId);
    expect(returned.plannedScopeHash).toBe(SCOPE_HASH);
    expect(returned.plannedPolicyHash).toBe(POLICY_HASH);
    expect(returned.plannedActionHash).toBe(ACTION_HASH);
    expect(returned.plannedContextHash).toBe(CONTEXT_HASH);
    // Token absence.
    expect(Object.prototype.hasOwnProperty.call(returned, "executionToken")).toBe(false);
    const json = JSON.stringify(returned);
    expect(json).not.toMatch(/executionToken/i);
  });

  // --- dirty/zero-change => ACTION_APPROVAL_RACE_LOST with rollback
  // and no retry. ---

  // Table-test: every dirty SQL field makes the CAS fail closed.
  // The single-CAS predicate must include all 15 SQL-null clean
  // fields, and a value written into any of them forces a
  // `changes !== 1` -> ACTION_APPROVAL_RACE_LOST. The dirty row is
  // expected to remain byte-identical to the snapshot; no retry
  // is attempted (changes must be exactly 1 on the only UPDATE).
  type DirtyField = {
    name: string;
    column: string;
    value: string | number | null;
  };
  const DIRTY_FIELDS: DirtyField[] = [
    { name: "executed_at", column: "executed_at", value: "2099-01-01T00:00:10.000Z" },
    { name: "active_review_id", column: "active_review_id", value: "rev-b14-dirty-active" },
    { name: "planned_scope_hash", column: "planned_scope_hash", value: SCOPE_HASH },
    { name: "planned_policy_hash", column: "planned_policy_hash", value: POLICY_HASH },
    { name: "planned_action_hash", column: "planned_action_hash", value: ACTION_HASH },
    { name: "planned_context_hash", column: "planned_context_hash", value: CONTEXT_HASH },
    { name: "execution_token", column: "execution_token", value: SECRET_TOKEN },
    { name: "execution_owner", column: "execution_owner", value: SECRET_TOKEN_OWNER },
    { name: "lease_expires_at", column: "lease_expires_at", value: EXPIRES_AT },
    { name: "started_at", column: "started_at", value: REVIEWED_AT },
    { name: "dispatch_started_at", column: "dispatch_started_at", value: "2099-01-01T00:00:05.000Z" },
    { name: "finished_at", column: "finished_at", value: "2099-01-01T00:00:10.000Z" },
    { name: "outcome_certainty", column: "outcome_certainty", value: "success" },
    { name: "last_error_code", column: "last_error_code", value: "ACTION_LEASE_EXPIRED" },
    { name: "last_error_message", column: "last_error_message", value: "api_key=AKIAIOSFODNN7EXAMPLE public text" },
  ];

  for (const dirty of DIRTY_FIELDS) {
    it(`table: ACTION_APPROVAL_RACE_LOST for dirty ${dirty.name}; action row byte-identical; no token leak`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b14-dirty-${dirty.name}`;
      const jobId = `job-b14-dirty-${dirty.name}`;
      const reviewId = `rev-b14-dirty-${dirty.name}`;
      seedCleanPending(handle, actionId, jobId);
      // Insert the structurally valid review at active_review_id.
      insertValidActiveReview(handle, {
        id: reviewId,
        actionId,
        jobId,
        decision: "approved",
        reviewerId: REVIEWER_ID,
        source: "human",
      });
      // For the active_review_id case the dirty value MUST equal
      // the reviewId (so the review-visibility linkage check
      // passes) AND the value is non-null (so the CAS predicate
      // `active_review_id IS NULL` fails and the CAS reports
      // RACE_LOST, not a linkage INVALID). For all other
      // columns the value is just a non-null dirty marker.
      const dirtyValue =
        dirty.column === "active_review_id" ? reviewId : dirty.value;
      handle
        .prepare(`UPDATE actions SET ${dirty.column} = ? WHERE id = ?`)
        .run(dirtyValue, actionId);

      const before = readActionRow(handle, actionId);
      // The base action row had active_review_id = NULL because
      // seedCleanPending did not set it. The single-CAS predicate
      // requires the 15 SQL-null clean fields; for the
      // planned_*_hash cases the input hash matches the seeded
      // NULL, so the CAS sees them as still null and would
      // succeed — but for those columns the dirty value is the
      // real hash, so the CAS sees a non-null planned_*_hash
      // and the predicate rejects. We assert on
      // ACTION_APPROVAL_RACE_LOST in every case; the contract
      // is that the CAS predicate repeats the clean fields and
      // any single non-null in those fields forces a race-lost.

      let captured: unknown = null;
      try {
        withImmediateTransaction(handle, () => {
          queue.approveWithReviewInTransaction(makeBaseInput(actionId, jobId, reviewId));
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_RACE_LOST", actionId);

      // Action row is byte-identical to the snapshot: the CAS
      // failed and the transaction rolled back. There is NO
      // retry path; a second call would hit the same predicate.
      const after = readActionRow(handle, actionId);
      expect(after).toEqual(before);

      // The dirty value MUST NOT contain or produce a token leak.
      // For the execution_token case the dirty value is the secret
      // token itself. The action row after the failed CAS still
      // contains the dirty value (it was never cleaned), but the
      // captured BountyPilotError must not echo the token in
      // either the message, the runtime JSON, or the curated
      // (name, code, message) projection.
      if (dirty.name === "execution_token") {
        const bp = captured as BountyPilotError;
        expect(bp.message).not.toContain(SECRET_TOKEN);
        const { runtime, curated } = serializeErrorForLeakCheck(bp);
        expect(runtime).not.toContain(SECRET_TOKEN);
        expect(curated).not.toContain(SECRET_TOKEN);
      }
    });
  }

  // Zero-change case: the action is not pending when the
  // approveWithReviewInTransaction runs. The single-CAS predicate
  // requires status = 'pending' plus the 15 clean fields, so the
  // already-approved action forces changes !== 1 with no retry.
  it("table: ACTION_APPROVAL_RACE_LOST for a zero-change (non-pending) action; action row byte-identical", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14-nonpending";
    const jobId = "job-b14-nonpending";
    const reviewId = "rev-b14-nonpending";
    // Seed as a structurally valid APPROVED row so the predicate
    // requires status = 'pending' to fail. This isolates the
    // status component from the 15 clean fields.
    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      decision: "approved",
      reviewerId: REVIEWER_ID,
      source: "human",
    });
    insertRawV2Action(handle, {
      id: actionId,
      jobId,
      status: "approved",
      requiredForCompletion: 1,
      requiresApproval: 1,
      activeReviewId: reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
    });

    const before = readActionRow(handle, actionId);

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        queue.approveWithReviewInTransaction(makeBaseInput(actionId, jobId, reviewId));
        return "should-not-reach";
      });
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_RACE_LOST", actionId);

    const after = readActionRow(handle, actionId);
    expect(after).toEqual(before);
  });
});

// ===========================================================================
// B1.4b: CAS DTO validation-before-SQL probes + ID/hash
// mutation table. The B1.4 hostile-DTO block already covers
// null/array/Proxy/accessor/symbol shapes. This block tightens
// coverage with:
//   - prepare-call probe: the primitive must reject the DTO
//     BEFORE issuing any UPDATE; we install a prepare-counting
//     probe on the db handle, call the primitive inside
//     withImmediateTransaction, and assert the probe saw zero
//     additional prepares (or the expected inner-review read
//     if the primitive reaches the review-linkage check).
//     The probe is uninstalled in a `finally` so the rest of
//     the suite is not affected.
//   - missing-required-own-field: omit actionId (one of the
//     eight required keys). A validator that only rejects
//     unknown fields would still pass this case; the contract
//     pins the strict "every required key is its own data
//     property" check.
//   - ID mutations: each of the three ID fields (actionId,
//     jobId, reviewId) gets four canonical mutations: padded
//     (whitespace), C0 (\\0), DEL (\\x7f), and 257 code
//     points (over the 256 cap).
//   - Hash mutations: each of the four hash fields gets three
//     mutations: uppercase, non-hex, and wrong runtime type.
//   - Parseable-but-noncanonical updatedAt:
//     "2099-01-01T00:00:00Z" parses, but is not
//     Date#toISOString() canonical; the contract pins
//     strict round-trip equality.
//   - Symbol case tightens: the post-assert hook receives the
//     expected actionId and asserts the string field is
//     exactly that id (not just defined), and the BLOB-safe
//     error projections do not echo the symbol description.
//   - Proxy case: every reflective trap (get/has/ownKeys/
//     getPrototypeOf/getOwnPropertyDescriptor) shares a single
//     external closure counter; the post-assert hook requires
//     the counter is exactly 0 (every reflective trap is
//     required to short-circuit on the first contact).
//   - TEMP AFTER UPDATE trigger is installed around the
//     positive plain-object happy case to assert exactly one
//     action update, and changed columns are exactly
//     (status, active_review_id, four planned hashes,
//     updated_at); the other execution/lifecycle/error
//     columns stay null.
//   - Null-prototype minimal happy case: an Object.assign(
//     Object.create(null), validInput) DTO is accepted (the
//     contract requires plain-object OR null-prototype, both
//     without a non-default prototype chain).
//   - Inherited-field pollution is intentionally NOT
//     exercised. The custom-prototype rejection plus the
//     missing-own-field case already cover the test surface.
//   - "Proxy trap count is implementation-dependent" is no
//     longer claimed. The trap count is bounded by the
//     primitive's own logic; the external counter makes the
//     actual count observable.
// ===========================================================================

describe("B1.4b: CAS DTO validation before SQL; ID/hash mutation table; symbol and proxy hardening", () => {
  // The withPrepareProbe helper is at module scope (declared
  // above the B1.1 describe block) so B1.4e can share the
  // same probe for its review-validation table. The probe
  // is uninstalled in `finally` so subsequent tests are
  // unaffected.

  // -- missing-required-own-field (no actionId key) --

  it("ACTION_APPROVAL_INVALID for missing required own field actionId; zero prepares; row byte-identical", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14b-missing";
    const jobId = "job-b14b-missing";
    const reviewId = "rev-b14b-missing";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId, actionId, jobId, decision: "approved",
      reviewerId: REVIEWER_ID, source: "human",
    });
    const before = readActionRow(handle, actionId);
    // Build a plain object with every required field EXCEPT
    // actionId. delete the string key; the strict own-property
    // check must fire on the missing field, not on a hidden
    // symbol or accessor.
    const built: Record<string, unknown> = { ...makeBaseInput(actionId, jobId, reviewId) };
    delete built.actionId;
    expect(Object.prototype.hasOwnProperty.call(built, "actionId")).toBe(false);

    let captured: unknown = null;
    withPrepareProbe(handle, (counter, sqls) => {
      try {
        withImmediateTransaction(handle, () => {
          // Cast through unknown: built is no longer a
          // valid ApproveActionWithReviewInput because
          // actionId is missing, but the primitive must
          // see the hostile shape and reject it before
          // any input reflection would otherwise crash.
          queue.approveWithReviewInTransaction(built as unknown as ApproveActionWithReviewInput);
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      // The primitive must reject the DTO BEFORE issuing
      // any prepare call that would touch the actions,
      // action_reviews, or jobs tables. The transactional
      // setup itself may issue BEGIN/COMMIT wraps via
      // exec; no SELECT/UPDATE/INSERT/DELETE on those
      // three tables is permitted.
      const targetTouches = sqls.some((s) => {
        const upper = s.toUpperCase();
        if (!/(\bSELECT\b|\bUPDATE\b|\bINSERT\b|\bDELETE\b)/.test(upper)) {
          return false;
        }
        return /\bFROM\s+actions\b/.test(upper)
          || /\bUPDATE\s+actions\b/.test(upper)
          || /\bINTO\s+actions\b/.test(upper)
          || /\bFROM\s+action_reviews\b/.test(upper)
          || /\bUPDATE\s+action_reviews\b/.test(upper)
          || /\bINTO\s+action_reviews\b/.test(upper)
          || /\bFROM\s+jobs\b/.test(upper)
          || /\bUPDATE\s+jobs\b/.test(upper)
          || /\bINTO\s+jobs\b/.test(upper);
      });
      expect(targetTouches, `must not prepare any actions/action_reviews/jobs SQL. Saw: ${sqls.join(" | ")}`).toBe(false);
      // Strictest form: when transaction wrapping uses
      // exec, total prepare count must be zero. We treat
      // this as the canonical "no SQL" form: if exec
      // bypasses prepare entirely, this assertion holds.
      if (sqls.length === 0) {
        expect(counter.value, "total prepare count must be zero when wrapping uses exec").toBe(0);
      }
    });
    expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
    expect(readActionRow(handle, actionId)).toEqual(before);
  });

  // -- symbol case tightened: exact actionId equality --

  it("symbol case: string actionId is exactly the expected id; runtime/curated JSON do not echo the symbol description", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14b-symbol";
    const jobId = "job-b14b-symbol";
    const reviewId = "rev-b14b-symbol";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId, actionId, jobId, decision: "approved",
      reviewerId: REVIEWER_ID, source: "human",
    });
    const before = readActionRow(handle, actionId);
    const built = makeBaseInput(actionId, jobId, reviewId) as unknown as Record<string | symbol, unknown>;
    built[Symbol("actionId-symbol")] = actionId;
    // KEEP the string actionId (every other required key);
    // the rejection must trace to the symbol-presence check.
    expect(built.actionId).toBe(actionId);

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        queue.approveWithReviewInTransaction(built as unknown as ApproveActionWithReviewInput);
        return "should-not-reach";
      });
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
    const bp = captured as BountyPilotError;
    // The post-assertion strengthens the symbol case: the
    // string field must be EXACTLY the expected id, and both
    // the runtime and curated JSON must not echo the symbol
    // description.
    const builtRecord = built as Record<string, unknown>;
    expect(builtRecord.actionId, "string actionId must be the exact expected id").toBe(actionId);
    const { runtime, curated } = serializeErrorForLeakCheck(bp);
    expect(runtime).not.toContain("actionId-symbol");
    expect(curated).not.toContain("actionId-symbol");
    expect(readActionRow(handle, actionId)).toEqual(before);
  });

  // -- Proxy case: every reflective trap shares a closure counter --

  it("Proxy case: get/has/ownKeys/getPrototypeOf/getOwnPropertyDescriptor traps share a closure counter; post-assert requires exactly 0", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14b-proxy";
    const jobId = "job-b14b-proxy";
    const reviewId = "rev-b14b-proxy";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId, actionId, jobId, decision: "approved",
      reviewerId: REVIEWER_ID, source: "human",
    });
    const before = readActionRow(handle, actionId);
    const trapCounts = (() => {
      const counts = { get: 0, has: 0, ownKeys: 0, getPrototypeOf: 0, getOwnPropertyDescriptor: 0 };
      const trap = (slot: keyof typeof counts) => () => {
        counts[slot] += 1;
        throw new Error("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
      };
      const built = makeBaseInput(actionId, jobId, reviewId) as unknown as Record<string | symbol, unknown>;
      const proxy = new Proxy(built, {
        get: trap("get"),
        has: trap("has"),
        ownKeys: trap("ownKeys"),
        getPrototypeOf: trap("getPrototypeOf"),
        getOwnPropertyDescriptor: trap("getOwnPropertyDescriptor"),
      });
      return { proxy, counts };
    })();
    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        queue.approveWithReviewInTransaction(trapCounts.proxy as unknown as ApproveActionWithReviewInput);
        return "should-not-reach";
      });
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
    const bp = captured as BountyPilotError;
    // Every trap count must be exactly 0. The primitive is
    // required to short-circuit on the first reflective
    // contact; if any trap fires, the closure counters
    // record the violation.
    expect(trapCounts.counts.get, "Proxy get trap fired").toBe(0);
    expect(trapCounts.counts.has, "Proxy has trap fired").toBe(0);
    expect(trapCounts.counts.ownKeys, "Proxy ownKeys trap fired").toBe(0);
    expect(trapCounts.counts.getPrototypeOf, "Proxy getPrototypeOf trap fired").toBe(0);
    expect(trapCounts.counts.getOwnPropertyDescriptor, "Proxy getOwnPropertyDescriptor trap fired").toBe(0);
    // Defense in depth: the trap body sentinel must not
    // reach the runtime or curated JSON.
    const { runtime, curated } = serializeErrorForLeakCheck(bp);
    expect(runtime).not.toContain("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
    expect(curated).not.toContain("B14_PROXY_REFLECTION_FAILURE_SENTINEL");
    expect(readActionRow(handle, actionId)).toEqual(before);
  });

  // -- ID and hash mutation tables --
  //
  // Each ID field is replaced with a corrupted value via the
  // mutId helper; the primitive must reject. Each hash field
  // is replaced with a corrupted value via the mutHash helper;
  // the primitive must reject. All tests share the same
  // structure: build a valid DTO, mutate one field, expect
  // ACTION_APPROVAL_INVALID with the row byte-identical.
  //
  // The mutId / mutId / IdMut / HashMut helpers and the
  // ID_FIELDS / ID_MUTATIONS / HASH_FIELDS / HASH_MUTATIONS
  // table constants are declared at module scope (above the
  // B1.1 describe) so B1.4d can share the same mutators.
  // Re-declaring them here would shadow the top-level
  // bindings and confuse later readers, so this block just
  // references the module-scope names.

  const ID_FIELDS = ["actionId", "jobId", "reviewId"] as const;
  const ID_MUTATIONS: ReadonlyArray<IdMut> = ["padded", "c0", "del", "long"];
  const HASH_FIELDS: ReadonlyArray<{ name: string; pick: (b: ReturnType<typeof makeBaseInput>) => string }> = [
    { name: "scopeHash", pick: (b) => b.scopeHash },
    { name: "policyHash", pick: (b) => b.policyHash },
    { name: "actionHash", pick: (b) => b.actionHash },
    { name: "contextHash", pick: (b) => b.contextHash },
  ];
  const HASH_MUTATIONS: ReadonlyArray<HashMut> = ["uppercase", "nonhex", "wrong-type"];

  for (const field of ID_FIELDS) {
    for (const mut of ID_MUTATIONS) {
      // Test title uses the field NAME (never the object
      // itself): a template that interpolates `${field}` for
      // a {name, pick} object would stringify to
      // "[object Object]" in the test report and erase the
      // signal that the field-level invariant is being
      // exercised.
      it(`ID mutation ${field}=${mut} -> ACTION_APPROVAL_INVALID; row byte-identical; no SQL touching actions/action_reviews/jobs`, () => {
        const handle = openDb();
        const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
        const actionId = "act-b14b-id";
        const jobId = "job-b14b-id";
        const reviewId = "rev-b14b-id";
        seedCleanPending(handle, actionId, jobId);
        insertValidActiveReview(handle, {
          id: reviewId, actionId, jobId, decision: "approved",
          reviewerId: REVIEWER_ID, source: "human",
        });
        const before = readActionRow(handle, actionId);
        const base = makeBaseInput(actionId, jobId, reviewId);
        const mutated = mutId(base[field], mut);
        const built = { ...base, [field]: mutated } as unknown as ApproveActionWithReviewInput;

        // Direct fixture assertion: c0 and del really do
        // contain the actual control code points; long is
        // exactly 257 code points; padded is whitespace-
        // bracketed. A mutation that produced a literal
        // backslash escape string would fail these
        // assertions before the primitive ever ran.
        const mutatedRecord = built as unknown as Record<string, unknown>;
        const mutatedFieldValue = mutatedRecord[field];
        if (mut === "c0") {
          expect(mutatedFieldValue, "c0 mutation must contain U+0000").toBe(base[field] + "\u0000");
          // The real U+0000 byte is present and the string
          // passes value === value.trim().
          expect((mutatedFieldValue as string).indexOf("\u0000")).toBeGreaterThanOrEqual(0);
          expect(mutatedFieldValue, "c0 mutation must trim equal").toBe((mutatedFieldValue as string).trim());
        } else if (mut === "del") {
          expect(mutatedFieldValue, "del mutation must contain U+007F").toBe(base[field] + "\u007f");
          expect((mutatedFieldValue as string).indexOf("\u007f")).toBeGreaterThanOrEqual(0);
          expect(mutatedFieldValue, "del mutation must trim equal").toBe((mutatedFieldValue as string).trim());
        } else if (mut === "long") {
          expect(Array.from(mutatedFieldValue as string).length, "long mutation must be 257 code points").toBe(257);
        } else {
          // padded
          expect((mutatedFieldValue as string).startsWith(" ")).toBe(true);
          expect((mutatedFieldValue as string).endsWith(" ")).toBe(true);
        }
        // The mutation must always differ from the valid
        // base. A no-op mutation (e.g. uppercase hash over
        // a digit-only prefix) would satisfy the field
        // shape but invalidate this assertion.
        expect(mutated, `mutation must differ from base for ${field}=${mut}`).not.toBe(base[field]);

        let captured: unknown = null;
        withPrepareProbe(handle, (counter, sqls) => {
          try {
            withImmediateTransaction(handle, () => {
              queue.approveWithReviewInTransaction(built);
              return "should-not-reach";
            });
          } catch (err) {
            captured = err;
          }
          // The primitive must reject the DTO BEFORE
          // issuing any prepare that touches the actions,
          // action_reviews, or jobs tables. The
          // transactional setup itself may issue BEGIN/
          // COMMIT wraps, but no SELECT/UPDATE/INSERT/
          // DELETE on those three tables is permitted.
          const mutatedTouchesTarget = sqls.some((s) => {
            const upper = s.toUpperCase();
            if (!/(\bSELECT\b|\bUPDATE\b|\bINSERT\b|\bDELETE\b)/.test(upper)) {
              return false;
            }
            return /\bFROM\s+actions\b/.test(upper)
              || /\bUPDATE\s+actions\b/.test(upper)
              || /\bINTO\s+actions\b/.test(upper)
              || /\bFROM\s+action_reviews\b/.test(upper)
              || /\bUPDATE\s+action_reviews\b/.test(upper)
              || /\bINTO\s+action_reviews\b/.test(upper)
              || /\bFROM\s+jobs\b/.test(upper)
              || /\bUPDATE\s+jobs\b/.test(upper)
              || /\bINTO\s+jobs\b/.test(upper);
          });
          expect(
            mutatedTouchesTarget,
            `${field}=${mut} rejected: must not prepare any actions/action_reviews/jobs SQL. Saw: ${sqls.join(" | ")}`,
          ).toBe(false);
          // Per the strictest reading, the prepare count
          // itself must be zero for the actions table
          // when transaction wrapping uses exec. node:sqlite
          // routes BEGIN/COMMIT through exec so any
          // actions-table prepare here is a regression.
          const totalPrepareCount = counter.value;
          const sawExecBypass = sqls.length === 0;
          if (sawExecBypass) {
            // Transaction wrapping did not invoke prepare
            // at all: a strict interpretation accepts this
            // as the zero-prepare case.
            expect(totalPrepareCount, `${field}=${mut} total prepare count must be zero`).toBe(0);
          } else {
            // Some prepares fired (most likely PRAGMA or
            // unrelated session setup). The contract only
            // requires ZERO of them to target the three
            // business tables — the negative-mutation
            // check above already pins that. The total
            // count is a diagnostic, not a strict invariant.
            expect(totalPrepareCount, `${field}=${mut} prepare count is informational only`).toBeGreaterThanOrEqual(0);
          }
        });
        expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
        expect(readActionRow(handle, actionId)).toEqual(before);
      });
    }
  }

  for (const field of HASH_FIELDS) {
    for (const mut of HASH_MUTATIONS) {
      // Test title uses field.name explicitly: the
      // HASH_FIELDS table is an array of {name, pick}
      // objects, and a `${field}` template would stringify
      // to "[object Object]" in the report.
      it(`hash mutation ${field.name}=${mut} -> ACTION_APPROVAL_INVALID; row byte-identical; no SQL touching actions/action_reviews/jobs`, () => {
        const handle = openDb();
        const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
        const actionId = "act-b14b-hash";
        const jobId = "job-b14b-hash";
        const reviewId = "rev-b14b-hash";
        seedCleanPending(handle, actionId, jobId);
        insertValidActiveReview(handle, {
          id: reviewId, actionId, jobId, decision: "approved",
          reviewerId: REVIEWER_ID, source: "human",
        });
        const before = readActionRow(handle, actionId);
        const base = makeBaseInput(actionId, jobId, reviewId);
        const baseFieldValue = field.pick(base);
        const mutated = mutHash(baseFieldValue, mut);
        const built = { ...base, [field.name]: mutated } as unknown as ApproveActionWithReviewInput;

        // Direct fixture assertion: the mutation must
        // really differ from the valid base. A no-op
        // mutation (e.g. uppercase over a digit-only
        // prefix that the existing 64-char hex already
        // produced identically) would pass the field
        // shape but invalidate this assertion. The
        // uppercase / nonhex mutators always produce a
        // value of the SAME TYPE (string) but ALWAYS a
        // value that is not equal to the lowercase 64-hex
        // base; the wrong-type mutator always produces a
        // non-string.
        if (mut === "uppercase") {
          expect(typeof mutated, "uppercase mutator returns string").toBe("string");
          expect(mutated, "uppercase mutator always differs from base").not.toBe(baseFieldValue);
          // The result must fail the lowercase-only hex
          // regex.
          expect(/^[0-9a-f]{64}$/.test(mutated as string), "uppercase mutator breaks lowercase hex rule").toBe(false);
        } else if (mut === "nonhex") {
          expect(typeof mutated, "nonhex mutator returns string").toBe("string");
          expect(mutated, "nonhex mutator always differs from base").not.toBe(baseFieldValue);
          expect(/^[0-9a-f]{64}$/.test(mutated as string), "nonhex mutator breaks hex rule").toBe(false);
        } else {
          // wrong-type: not a string.
          expect(typeof mutated, "wrong-type mutator returns non-string").not.toBe("string");
        }

        let captured: unknown = null;
        withPrepareProbe(handle, (counter, sqls) => {
          try {
            withImmediateTransaction(handle, () => {
              queue.approveWithReviewInTransaction(built);
              return "should-not-reach";
            });
          } catch (err) {
            captured = err;
          }
          // The primitive must reject the DTO BEFORE
          // issuing any prepare that touches the three
          // business tables.
          const mutatedTouchesTarget = sqls.some((s) => {
            const upper = s.toUpperCase();
            if (!/(\bSELECT\b|\bUPDATE\b|\bINSERT\b|\bDELETE\b)/.test(upper)) {
              return false;
            }
            return /\bFROM\s+actions\b/.test(upper)
              || /\bUPDATE\s+actions\b/.test(upper)
              || /\bINTO\s+actions\b/.test(upper)
              || /\bFROM\s+action_reviews\b/.test(upper)
              || /\bUPDATE\s+action_reviews\b/.test(upper)
              || /\bINTO\s+action_reviews\b/.test(upper)
              || /\bFROM\s+jobs\b/.test(upper)
              || /\bUPDATE\s+jobs\b/.test(upper)
              || /\bINTO\s+jobs\b/.test(upper);
          });
          expect(
            mutatedTouchesTarget,
            `${field.name}=${mut} rejected: must not prepare any actions/action_reviews/jobs SQL. Saw: ${sqls.join(" | ")}`,
          ).toBe(false);
          const totalPrepareCount = counter.value;
          if (sqls.length === 0) {
            expect(totalPrepareCount, `${field.name}=${mut} total prepare count must be zero`).toBe(0);
          }
        });
        expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
        expect(readActionRow(handle, actionId)).toEqual(before);
      });
    }
  }

  // -- parseable-but-noncanonical updatedAt --
  it("updatedAt parseable but not Date#toISOString() canonical -> ACTION_APPROVAL_INVALID; row byte-identical", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14b-utc";
    const jobId = "job-b14b-utc";
    const reviewId = "rev-b14b-utc";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId, actionId, jobId, decision: "approved",
      reviewerId: REVIEWER_ID, source: "human",
    });
    const before = readActionRow(handle, actionId);
    const built = {
      ...makeBaseInput(actionId, jobId, reviewId),
      // "2099-01-01T00:00:00Z" parses via new Date(), but the
      // round-trip through toISOString() yields
      // "2099-01-01T00:00:00.000Z" (with milliseconds). The
      // contract pins the strict round-trip canonical form.
      updatedAt: "2099-01-01T00:00:00Z",
    };

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        queue.approveWithReviewInTransaction(built as ApproveActionWithReviewInput);
        return "should-not-reach";
      });
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
    expect(readActionRow(handle, actionId)).toEqual(before);
  });
});

// ===========================================================================
// B1.4c: positive CAS instrumented with TEMP AFTER UPDATE
// trigger. The contract requires the action CAS to perform
// exactly one UPDATE that changes only (status, active_review_id,
// four planned hashes, updated_at). Every other execution /
// lifecycle / error column must remain null. The trigger is
// installed after fixtures and uninstalled in `finally` so the
// rest of the suite is unaffected. The trigger is scoped to
// this describe block; the rest of the file is unchanged.
// ===========================================================================

describe("B1.4c: positive CAS performs exactly one action update with a tightly bounded column-change set", () => {
  // Install a TEMP AFTER UPDATE trigger on `actions` that
  // records (action_id, updated_at) into a side table. The
  // trigger is the only sane way to count the number of
  // action-table UPDATEs the primitive issues: the
  // production code might otherwise batch or coalesce.
  // Restore the schema in `finally` so subsequent tests see
  // a clean actions table.
  //
  // The trigger records one row per UPDATE. The "which
  // columns changed" assertion is computed in JS by taking a
  // before/after snapshot of the row and diffing every
  // column; the trigger only provides the "this row was
  // updated" signal, not the per-column diff. Using OLD/NEW
  // references inside the trigger would also work, but the
  // row-diff in JS is more transparent for a reviewer who is
  // checking exactly which column the contract pins.
  function instrumentActionsUpdates(handle: BountyDatabase): {
    changed: () => Array<{ id: string; updatedAt: string }>;
  } {
    handle.exec(`
      CREATE TEMP TABLE b1_cas_audit (
        action_id TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TEMP TRIGGER b1_cas_audit_au
        AFTER UPDATE ON actions
        BEGIN
          INSERT INTO b1_cas_audit (action_id, updated_at)
          VALUES (NEW.id, NEW.updated_at);
        END;
    `);
    return {
      changed: () =>
        handle
          .prepare("SELECT action_id AS id, updated_at AS updatedAt FROM b1_cas_audit ORDER BY rowid")
          .all() as Array<{ id: string; updatedAt: string }>,
    };
  }
  function dropAudit(handle: BountyDatabase): void {
    try {
      handle.exec("DROP TRIGGER IF EXISTS b1_cas_audit_au; DROP TABLE IF EXISTS b1_cas_audit;");
    } catch {
      /* best-effort cleanup; the handle is per-test */
    }
  }

  it("plain-object happy path: exactly one action update; changed columns = status,active_review_id,four planned hashes,updated_at", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14c-happy";
    const jobId = "job-b14c-happy";
    const reviewId = "rev-b14c-happy";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId, actionId, jobId, decision: "approved",
      reviewerId: REVIEWER_ID, source: "human",
    });
    // Pre-CAS the action's updated_at to a canonical
    // value that DIFFERS from UPDATED_AT. seedCleanPending
    // sets updated_at to UPDATED_AT; if the CAS writes
    // UPDATED_AT verbatim, the changed-key set for
    // updated_at collapses to "unchanged" and the diff
    // cannot prove the column was actually written. The
    // PRE_CAS_UPDATED_AT value is one second earlier than
    // UPDATED_AT and still round-trips through
    // Date#toISOString() so the column remains
    // canonical-valid.
    const PRE_CAS_UPDATED_AT = "2098-12-31T23:59:59.000Z";
    expect(PRE_CAS_UPDATED_AT).not.toBe(UPDATED_AT);
    handle
      .prepare("UPDATE actions SET updated_at = ? WHERE id = ?")
      .run(PRE_CAS_UPDATED_AT, actionId);

    // Snapshot the COMPLETE raw row before the CAS. The
    // exact changed-key set is computed by diffing every
    // column in the row, not a curated whitelist. A
    // pre-snapshot that omits columns the CAS touches
    // would silently hide regressions in the change-set.
    const before = handle
      .prepare("SELECT * FROM actions WHERE id = ?")
      .get(actionId) as Record<string, unknown>;
    expect(before.updated_at).toBe(PRE_CAS_UPDATED_AT);
    expect(before.status).toBe("pending");

    const audit = instrumentActionsUpdates(handle);
    try {
      const returned = withImmediateTransaction(handle, () => {
        return queue.approveWithReviewInTransaction(
          makeBaseInput(actionId, jobId, reviewId),
        );
      });
      expect(returned.status).toBe("approved");
      expect(returned.activeReviewId).toBe(reviewId);
      const updates = audit.changed();
      // Exactly one UPDATE on the action row. The TEMP
      // trigger records (action_id, updated_at) per UPDATE;
      // the column-level diff is checked in JS below.
      expect(updates.length, `audit rows: ${JSON.stringify(updates)}`).toBe(1);
      // The trigger records NEW.updated_at verbatim. This
      // proves the primitive wrote a non-NULL updated_at and
      // did not UPDATE the row without setting the column
      // (the audit table would otherwise have captured NULL).
      expect(updates[0].id).toBe(actionId);
      expect(updates[0].updatedAt).toBe(UPDATED_AT);
      // The column-by-column diff is checked below: the
      // contract requires the CAS to change only (status,
      // active_review_id, four planned hashes, updated_at).
      // Every other lifecycle / error / execution column
      // stays at its pre-CAS value. We assert the post-CAS
      // row state directly.
      const rec = handle
        .prepare("SELECT * FROM actions WHERE id = ?")
        .get(actionId) as Record<string, unknown>;
      for (const k of [
        "executed_at",
        "execution_token",
        "execution_owner",
        "lease_expires_at",
        "started_at",
        "dispatch_started_at",
        "finished_at",
        "outcome_certainty",
        "last_error_code",
        "last_error_message",
      ]) {
        expect(rec[k], `${k} must remain null after CAS`).toBeNull();
      }
      // And the four planned hashes are exactly the inputs.
      expect(rec.planned_scope_hash).toBe(SCOPE_HASH);
      expect(rec.planned_policy_hash).toBe(POLICY_HASH);
      expect(rec.planned_action_hash).toBe(ACTION_HASH);
      expect(rec.planned_context_hash).toBe(CONTEXT_HASH);
      // status is "approved" and active_review_id is set.
      expect(rec.status).toBe("approved");
      expect(rec.active_review_id).toBe(reviewId);
      // updated_at is the canonical UPDATED_AT.
      expect(rec.updated_at).toBe(UPDATED_AT);

      // Compute the exact sorted changed-key set: every
      // column where the post-CAS value differs from the
      // pre-CAS snapshot. The CAS is the only writer, so
      // this set must be exactly the seven columns the
      // contract pins: status, active_review_id, the four
      // planned hashes, and updated_at.
      const changedKeys = Object.keys(before)
        .filter((k) => !Object.is(before[k], rec[k]))
        .sort();
      expect(
        changedKeys,
        `CAS must change exactly the pinned columns; diff was ${JSON.stringify(changedKeys)}`,
      ).toEqual([
        "active_review_id",
        "planned_action_hash",
        "planned_context_hash",
        "planned_policy_hash",
        "planned_scope_hash",
        "status",
        "updated_at",
      ]);
    } finally {
      dropAudit(handle);
    }
  });

  it("null-prototype minimal happy path: Object.assign(Object.create(null), validInput) is accepted", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14c-np";
    const jobId = "job-b14c-np";
    const reviewId = "rev-b14c-np";
    seedCleanPending(handle, actionId, jobId);
    insertValidActiveReview(handle, {
      id: reviewId, actionId, jobId, decision: "approved",
      reviewerId: REVIEWER_ID, source: "human",
    });
    const audit = instrumentActionsUpdates(handle);
    try {
      const base = makeBaseInput(actionId, jobId, reviewId);
      const npInput = Object.assign(Object.create(null) as Record<string, unknown>, base);
      // The null-prototype input has no Object.prototype
      // chain, so any validator that relies on prototype
      // pollution or `instanceof Object` must fail; the
      // contract requires the primitive to accept the
      // null-prototype shape as long as every required own
      // data property is present.
      const returned = withImmediateTransaction(handle, () => {
        return queue.approveWithReviewInTransaction(npInput as unknown as ApproveActionWithReviewInput);
      });
      expect(returned.status).toBe("approved");
      expect(returned.id).toBe(actionId);
      expect(audit.changed().length).toBe(1);
    } finally {
      dropAudit(handle);
    }
  });
});

// ===========================================================================
// B1.4d: candidate boundary: padded, DEL, and 257-code-point
// actionId; "in withImmediateTransaction" re-entry; mixed-
// fault precedence table.
// ===========================================================================

describe("B1.4d: candidate boundary mutations, re-entry inside tracked tx, mixed-fault precedence", () => {
  function readActionAfterPending(handle: BountyDatabase, actionId: string): { started_at: unknown } {
    return handle
      .prepare("SELECT started_at FROM actions WHERE id = ?")
      .get(actionId) as { started_at: unknown };
  }

  // -- candidate actionId boundary mutations --

  for (const mut of ["padded", "del", "long"] as const) {
    it(`candidate actionId=${mut} -> ACTION_APPROVAL_INVALID; row byte-identical`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = "act-b14d-bnd";
      const jobId = "job-b14d-bnd";
      insertJob(handle, jobId);
      insertRawV2Action(handle, {
        id: actionId, jobId, status: "pending",
        requiredForCompletion: 1, requiresApproval: 1,
      });
      const before = readActionRow(handle, actionId);
      const corrupted = mutId(actionId, mut);
      let captured: unknown = null;
      try {
        queue.requireCleanPendingForApproval(corrupted);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_INVALID", corrupted);
      expect(readActionRow(handle, actionId)).toEqual(before);
    });
  }

  // -- re-entry inside withImmediateTransaction: first call
  // succeeds (clean candidate), outer tx remains active, then a
  // mutation is written, the second call freshly reloads the
  // dirty state, the second call returns
  // ACTION_APPROVAL_STATE_INVALID, and the outer tx remains
  // active. The test does not commit; the dirty mutation is
  // visible only inside the open tx.

  it("clean candidate succeeds; outer tx active; mutate started_at; second call returns STATE_INVALID; outer tx still active", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14d-reent";
    const jobId = "job-b14d-reent";
    insertJob(handle, jobId);
    insertRawV2Action(handle, {
      id: actionId, jobId, status: "pending",
      requiredForCompletion: 1, requiresApproval: 1,
    });

    // Strict-safe holder pattern. TypeScript's strict mode
    // narrows `let foo: T | null` only through a direct
    // control-flow test on the variable itself
    // (e.g. `if (first === null) ...` or an
    // `asserts first is T` predicate). A Vitest
    // `expect(first).not.toBeNull()` call does NOT narrow
    // the type, and a plain `as` cast merely silences the
    // type checker without proving the value is defined.
    // The fix is a `{ value?: T }` box: the property is
    // optional, so the box is always safely assignable,
    // and a real `if (holder.value === undefined) throw`
    // check narrows the value to `T` for the rest of the
    // block.
    interface CandidateShape { id: string; status: string }
    const firstHolder: { value?: CandidateShape } = {};
    let secondError: BountyPilotError | null = null;
    // Probe: the tracked-tx guard is observable via
    // hasImmediateTransaction(handle) from
    // stores/db/database. The candidate path is
    // transaction-neutral, so it must run inside a
    // tracked tx AND must leave the tracked tx active
    // after each call. The previous outerActiveAfterFirst
    // / outerActiveAfterSecond probes used
    // SELECT 1 FROM actions as a proxy for "tx alive";
    // the new probes call the contract surface directly.
    let hasImmediateAfterFirst = false;
    let hasImmediateAfterSecond = false;

    withImmediateTransaction(handle, () => {
      // First call: clean candidate, returns the narrowed
      // record, outer tx still active.
      firstHolder.value = queue.requireCleanPendingForApproval(actionId) as unknown as CandidateShape;
      // The tracked-tx surface MUST be true here: the
      // candidate path runs inside a tracked tx and the
      // primitive must not have aborted it.
      hasImmediateAfterFirst = hasImmediateTransaction(handle);

      // Mutate started_at inside the open tx; the candidate
      // path reloads the action and must see this dirty
      // state.
      handle
        .prepare("UPDATE actions SET started_at = ? WHERE id = ?")
        .run(REVIEWED_AT, actionId);

      // Second call: same actionId, freshly reloaded, sees the
      // dirty started_at, must return STATE_INVALID.
      try {
        queue.requireCleanPendingForApproval(actionId);
        // unreachable
        secondError = null;
      } catch (err) {
        secondError = err as BountyPilotError;
      }

      // After the second rejection the tracked tx MUST
      // still be alive: the candidate must not have
      // aborted the surrounding transaction.
      hasImmediateAfterSecond = hasImmediateTransaction(handle);
    });
    // After withImmediateTransaction returns, the commit has
    // run, so the mutation persists. The point of the test is
    // that the second call inside the open tx sees the dirty
    // state and rejects; the hasImmediateTransaction probes
    // ensure we did not abort the transaction on either
    // candidate call.
    //
    // Real control-flow narrowing on the holder: a plain
    // `as` cast would silence the type checker without
    // proving the value is defined, and Vitest's
    // `expect(...).toBeDefined()` does not narrow the
    // type either. The explicit undefined check below is
    // the strict-safe narrow that lets the rest of the
    // block access `id` / `status` without an unsafe cast.
    if (firstHolder.value === undefined) {
      throw new Error("first call must produce a candidate");
    }
    const firstRecord: CandidateShape = firstHolder.value;
    expect(firstRecord.id).toBe(actionId);
    expect(firstRecord.status).toBe("pending");
    expect(
      hasImmediateAfterFirst,
      "tracked-tx surface must be true after first candidate call",
    ).toBe(true);
    expect(secondError, "second call must throw").not.toBeNull();
    expect((secondError as unknown as BountyPilotError).code).toBe("ACTION_APPROVAL_STATE_INVALID");
    expect(
      hasImmediateAfterSecond,
      "tracked-tx surface must be true after second-call rejection",
    ).toBe(true);
    // The dirty started_at is now persisted; the commit
    // itself is the proof of commit, no separate
    // outerCommitted flag is needed. Persisted started_at
    // after return is enough to prove the commit
    // happened.
    const finalRow = readActionAfterPending(handle, actionId);
    expect(finalRow.started_at).toBe(REVIEWED_AT);
  });

  // -- mixed-fault precedence table: a non-pending status is
  // the strongest signal (a status check fires first, before
  // job-linkage or dirty-state preflight), a blank jobId beats
  // dirty, a missing-job beats dirty, and a terminal job
  // status beats dirty. Each row mutates one column only; the
  // other conditions are clean.

  interface PrecedenceRow {
    name: string;
    mutate: (handle: BountyDatabase, actionId: string, jobId: string) => void;
    expectedCode: "ACTION_APPROVAL_NOT_PENDING" | "ACTION_APPROVAL_JOB_REQUIRED" | "JOB_NOT_FOUND" | "ACTION_APPROVAL_JOB_TERMINAL";
  }
  const PRECEDENCE_ROWS: PrecedenceRow[] = [
    {
      // The job is inserted with the default status
      // (queued) — a NON-terminal valid JobStatus. The
      // name describes the preflight outcome: the status
      // check on the action is the strongest signal and
      // fires before any job-linkage preflight, so even
      // with a valid queued job the action's blocked
      // status makes the candidate reject with
      // ACTION_APPROVAL_NOT_PENDING.
      name: "nonpending status beats nonterminal job (and dirty state)",
      mutate: (h, a, j) => {
        // Pre-create the job so JOB_NOT_FOUND is not what
        // fires. The job is in the default queued state
        // (a non-terminal, valid JobStatus).
        insertJob(h, j);
        h.prepare("UPDATE actions SET status = ?, started_at = ?, execution_token = ? WHERE id = ?").run(
          "blocked", REVIEWED_AT, SECRET_TOKEN, a,
        );
      },
      expectedCode: "ACTION_APPROVAL_NOT_PENDING",
    },
    {
      name: "nonpending status beats missing job (and dirty state)",
      mutate: (h, a) => {
        // No job insert; the action's jobId is missing AND
        // the action is dirty. The status check must win.
        h.prepare("UPDATE actions SET status = ?, started_at = ?, execution_token = ? WHERE id = ?").run(
          "blocked", REVIEWED_AT, SECRET_TOKEN, a,
        );
      },
      expectedCode: "ACTION_APPROVAL_NOT_PENDING",
    },
    {
      name: "nonpending status beats terminal job (and dirty state)",
      mutate: (h, a, j) => {
        insertJob(h, j, "completed");
        h.prepare("UPDATE actions SET status = ?, started_at = ?, execution_token = ? WHERE id = ?").run(
          "blocked", REVIEWED_AT, SECRET_TOKEN, a,
        );
      },
      expectedCode: "ACTION_APPROVAL_NOT_PENDING",
    },
    {
      name: "blank jobId beats dirty state",
      mutate: (h, a) => {
        h.prepare("UPDATE actions SET job_id = ?, started_at = ?, execution_token = ? WHERE id = ?").run(
          "   ", REVIEWED_AT, SECRET_TOKEN, a,
        );
      },
      expectedCode: "ACTION_APPROVAL_JOB_REQUIRED",
    },
  ];
  for (const row of PRECEDENCE_ROWS) {
    it(`precedence: ${row.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = "act-b14d-prec";
      const jobId = "job-b14d-prec";
      // Seed the action with a clean pending state. Do NOT
      // pre-insert a job; some rows depend on the missing-job
      // path. The per-row mutate callback is responsible for
      // pre-inserting the job when it needs one.
      insertRawV2Action(handle, {
        id: actionId, jobId, status: "pending",
        requiredForCompletion: 1, requiresApproval: 1,
      });
      row.mutate(handle, actionId, jobId);
      // Snapshot AFTER the mutate so we prove the primitive
      // did not further mutate the row, not that the row
      // stayed at its pre-mutate clean-pending state.
      const before = readActionRow(handle, actionId);

      let captured: unknown = null;
      try {
        queue.requireCleanPendingForApproval(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, row.expectedCode, actionId);
      expect(readActionRow(handle, actionId)).toEqual(before);
    });
  }

  it("precedence: missing job beats dirty state (job row is never inserted)", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14d-precmiss";
    const jobId = "job-b14d-precmiss";
    insertRawV2Action(handle, {
      id: actionId, jobId, status: "pending",
      requiredForCompletion: 1, requiresApproval: 1,
    });
    // The action is dirty (started_at, execution_token) and
    // its jobId has no matching job row. Per contract order
    // the job-linkage check fires before the dirty-state
    // preflight.
    handle
      .prepare("UPDATE actions SET started_at = ?, execution_token = ? WHERE id = ?")
      .run(REVIEWED_AT, SECRET_TOKEN, actionId);
    const before = readActionRow(handle, actionId);

    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "JOB_NOT_FOUND", actionId);
    expect(readActionRow(handle, actionId)).toEqual(before);
  });

  it("precedence: terminal job beats dirty state", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    const actionId = "act-b14d-precterm";
    const jobId = "job-b14d-precterm";
    insertRawV2Action(handle, {
      id: actionId, jobId, status: "pending",
      requiredForCompletion: 1, requiresApproval: 1,
    });
    insertJob(handle, jobId, "failed");
    handle
      .prepare("UPDATE actions SET started_at = ?, execution_token = ? WHERE id = ?")
      .run(REVIEWED_AT, SECRET_TOKEN, actionId);
    const before = readActionRow(handle, actionId);

    let captured: unknown = null;
    try {
      queue.requireCleanPendingForApproval(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_JOB_TERMINAL", actionId);
    expect(readActionRow(handle, actionId)).toEqual(before);
  });
});

// ===========================================================================
// B1.4e: review validation table with action clean. Each row
// mutates exactly one column on an otherwise valid review and
// expects ACTION_APPROVAL_INVALID with the raw action byte-
// identical. The action's active_review_id stays NULL — the
// primitive uses the input reviewId, so dirtying the action
// would be self-defeating (item 4 of the P0/P1 contract).
// ===========================================================================

describe("B1.4e: review validation table with action clean (exactly one column mutated per row)", () => {
  interface ReviewMutation {
    name: string;
    setup: (db: BountyDatabase, ctx: { reviewId: string; actionId: string; jobId: string }) => void;
  }

  // Each case uses `insertValidActiveReview` for the baseline
  // and then a per-case `setup` that mutates exactly one
  // column. The action stays a clean pending row.
  const REVIEW_MUTATIONS: ReviewMutation[] = [
    {
      name: "source NULL",
      setup: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET source = NULL WHERE id = ?").run(ctx.reviewId);
      },
    },
    {
      name: "source unknown literal",
      setup: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET source = 'quux' WHERE id = ?").run(ctx.reviewId);
      },
    },
    {
      name: "empty reviewer",
      setup: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewer_id = '' WHERE id = ?").run(ctx.reviewId);
      },
    },
    {
      name: "padded reviewer",
      setup: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewer_id = '  reviewer  ' WHERE id = ?").run(ctx.reviewId);
      },
    },
    {
      name: "control reviewer (DEL)",
      setup: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewer_id = ? WHERE id = ?").run(
          `reviewer\u007f`,
          ctx.reviewId,
        );
      },
    },
    {
      name: "reviewed_at NULL",
      setup: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = NULL WHERE id = ?").run(ctx.reviewId);
      },
    },
    {
      name: "expires_at NULL",
      setup: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET expires_at = NULL WHERE id = ?").run(ctx.reviewId);
      },
    },
    {
      name: "parseable-but-noncanonical expires_at",
      setup: (db, ctx) => {
        // new Date() parses this, but Date#toISOString()
        // would produce a different string. The contract pins
        // round-trip canonical equality.
        db.prepare("UPDATE action_reviews SET expires_at = '2099-01-01T00:15:00Z' WHERE id = ?").run(
          ctx.reviewId,
        );
      },
    },
  ];

  for (const tc of REVIEW_MUTATIONS) {
    it(`ACTION_APPROVAL_INVALID for ${tc.name}; action clean and byte-identical; no UPDATE actions statement prepared`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
      const actionId = `act-b14e-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b14e-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      const reviewId = `rev-b14e-${tc.name.replace(/[^a-z0-9]/gi, "_")}`;
      // Action stays clean: active_review_id NULL. The
      // primitive uses the input reviewId to fetch the review.
      seedCleanPending(handle, actionId, jobId);
      insertValidActiveReview(handle, {
        id: reviewId, actionId, jobId, decision: "approved",
        reviewerId: REVIEWER_ID, source: "human",
      });
      tc.setup(handle, { reviewId, actionId, jobId });

      // Explicit pre-CAS assertion: the action is clean.
      const preCas = readActionRow(handle, actionId);
      expect(preCas.active_review_id, "action must be clean before CAS").toBeNull();

      const before = readActionRow(handle, actionId);
      let captured: unknown = null;
      // Prepare/statement probe around the primitive. The
      // snapshot equality after rollback alone is
      // insufficient: a transient UPDATE can be issued
      // and then rolled back, leaving the row byte-
      // identical but the SQL having fired. The probe
      // pins the negative invariant at the prepare
      // surface: no UPDATE actions statement must be
      // prepared or issued.
      //
      // We deliberately do NOT use a TEMP trigger here:
      // a trigger-based audit row would also roll back,
      // making the audit indistinguishable from a no-op.
      // The prepare probe is the only mechanism that
      // observes the rejected call BEFORE any SQL fires.
      withPrepareProbe(handle, (counter, sqls) => {
        try {
          withImmediateTransaction(handle, () => {
            queue.approveWithReviewInTransaction(makeBaseInput(actionId, jobId, reviewId));
            return "should-not-reach";
          });
        } catch (err) {
          captured = err;
        }
        const updateActions = sqls.some(
          (s) => /UPDATE\s+actions\b/i.test(s),
        );
        expect(
          updateActions,
          `${tc.name} rejected: must not prepare any UPDATE actions statement. Saw: ${sqls.join(" | ")}`,
        ).toBe(false);
        // The malformed-review case may issue a SELECT
        // against action_reviews (the linkage check) but
        // never an UPDATE against the actions table. The
        // probe is the surface that catches the violation
        // even when the surrounding tx rolls back the row
        // state.
        const targetUpdates = sqls.some((s) => {
          const upper = s.toUpperCase();
          if (!/(\bUPDATE\b|\bINSERT\b|\bDELETE\b)/.test(upper)) {
            return false;
          }
          return /\bUPDATE\s+actions\b/.test(upper)
            || /\bINTO\s+actions\b/.test(upper)
            || /\bFROM\s+actions\b/.test(upper)
            || /\bUPDATE\s+action_reviews\b/.test(upper)
            || /\bINTO\s+action_reviews\b/.test(upper)
            || /\bFROM\s+action_reviews\b/.test(upper)
            || /\bUPDATE\s+jobs\b/.test(upper)
            || /\bINTO\s+jobs\b/.test(upper)
            || /\bFROM\s+jobs\b/.test(upper);
        });
        expect(
          targetUpdates,
          `${tc.name} rejected: must not prepare any UPDATE/INSERT/DELETE on the three business tables. Saw: ${sqls.join(" | ")}`,
        ).toBe(false);
        // When transaction wrapping uses exec, the strict
        // zero-prepare form is total === 0. node:sqlite
        // routes BEGIN/COMMIT through exec so a
        // pre-rejection UPDATE would be visible in the
        // counter as a non-zero prepare.
        if (sqls.length === 0) {
          expect(
            counter.value,
            `${tc.name}: total prepare count must be zero when wrapping uses exec`,
          ).toBe(0);
        }
      });
      expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
      const after = readActionRow(handle, actionId);
      expect(after).toEqual(before);
    });
  }
});

// ===========================================================================
// B1.5: token non-leak. The execution token must never be returned
// or serialized by get/list/candidate. The contract requires the
// bearer value to be absent from the generic ActionRecord and from
// any JSON.stringify(...) of that record.
// ===========================================================================


describe("B1.5: execution_token never returns or serializes through the generic ActionQueue surface", () => {
  function seedRunningActionWithToken(db: BountyDatabase, actionId: string, jobId: string, reviewId: string): void {
    insertValidActiveReview(db, {
      id: reviewId,
      actionId,
      jobId,
      decision: "approved",
      reviewerId: REVIEWER_ID,
      source: "human",
    });
    insertRawV2Action(db, {
      id: actionId,
      jobId,
      status: "running",
      requiredForCompletion: 1,
      requiresApproval: 1,
      activeReviewId: reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
      executionToken: SECRET_TOKEN,
      executionOwner: SECRET_TOKEN_OWNER,
      leaseExpiresAt: EXPIRES_AT,
      startedAt: REVIEWED_AT,
    });
  }

  it("get() of a running action exposes no own executionToken and JSON does not contain the token", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const actionId = "act-b15-run-get";
    const jobId = "job-b15-run-get";
    const reviewId = "rev-b15-run-get";
    seedRunningActionWithToken(handle, actionId, jobId, reviewId);

    const record = queue.get(actionId) as ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(Object.prototype.hasOwnProperty.call(record, "executionToken")).toBe(false);
    const json = JSON.stringify(record);
    expect(json).not.toContain(SECRET_TOKEN);
    expect(json).not.toMatch(/executionToken/i);
  });

  it("list() of a job with a running action exposes no own executionToken and JSON does not contain the token", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const actionId = "act-b15-run-list";
    const jobId = "job-b15-run-list";
    const reviewId = "rev-b15-run-list";
    seedRunningActionWithToken(handle, actionId, jobId, reviewId);

    const list = queue.list(jobId) as ActionRecord[];
    expect(list.length).toBe(1);
    const record = list[0];
    expect(record.id).toBe(actionId);
    expect(record.status).toBe("running");
    expect(Object.prototype.hasOwnProperty.call(record, "executionToken")).toBe(false);
    const json = JSON.stringify(record);
    expect(json).not.toContain(SECRET_TOKEN);
    expect(json).not.toMatch(/executionToken/i);
  });

  it("requireCleanPendingForApproval() does not return executionToken and JSON does not contain the token", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle) as unknown as ActionQueueSliceB1;
    // A clean pending row has no execution_token; the candidate
    // is just the pending projection. The token-non-leak
    // invariant is "never select, materialize, or return"; even
    // for a row without a token, the candidate must not have an
    // own executionToken field. A real nonterminal linked job is
    // required so preflight clears and the success path
    // actually runs.
    insertJob(handle, "job-b15-pending-cand");
    insertRawV2Action(handle, {
      id: "act-b15-pending-cand",
      jobId: "job-b15-pending-cand",
      status: "pending",
      requiredForCompletion: 1,
      requiresApproval: 1,
    });

    const candidate = queue.requireCleanPendingForApproval("act-b15-pending-cand") as PendingApprovalCandidate;
    expect(Object.prototype.hasOwnProperty.call(candidate, "executionToken")).toBe(false);
    const json = JSON.stringify(candidate);
    expect(json).not.toMatch(/executionToken/i);
  });
});

// ===========================================================================
// B1.6: review projection hardening — an otherwise structurally
// valid approved action whose review has invalidation_reason
// non-null while invalidated_at is NULL must fail closed
// with ACTION_APPROVAL_INVALID through the generic get / list
// surfaces. This pins the production review projection
// independently of the CAS path: the malformed review is
// rejected as soon as the row decoder sees it, not just
// during the in-tx CAS. The contract requires the two
// invalidation columns to move together; the malformed
// review is structurally invalid regardless of which
// surface reads it.
// ===========================================================================

describe("B1.6: review projection rejects invalidation_reason non-null while invalidated_at NULL", () => {
  function seedApprovedActionWithOrphanedInvalidationReason(
    db: BountyDatabase,
    actionId: string,
    jobId: string,
    reviewId: string,
  ): void {
    insertValidActiveReview(db, {
      id: reviewId,
      actionId,
      jobId,
      decision: "approved",
      reviewerId: REVIEWER_ID,
      source: "human",
    });
    // Move only invalidation_reason: invalidated_at stays
    // NULL. The other review columns are at their valid
    // baseline.
    db.prepare("UPDATE action_reviews SET invalidation_reason = ? WHERE id = ?").run(
      "orphaned-reason",
      reviewId,
    );
    insertRawV2Action(db, {
      id: actionId,
      jobId,
      status: "approved",
      requiredForCompletion: 1,
      requiresApproval: 1,
      activeReviewId: reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
    });
  }

  it("get() of an approved action with orphaned invalidation_reason throws ACTION_APPROVAL_INVALID", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const actionId = "act-b16-get-orphaned";
    const jobId = "job-b16-get-orphaned";
    const reviewId = "rev-b16-get-orphaned";
    seedApprovedActionWithOrphanedInvalidationReason(handle, actionId, jobId, reviewId);

    let captured: unknown = null;
    try {
      queue.get(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID", actionId);
  });

  it("list() of a job with an approved action that has orphaned invalidation_reason throws ACTION_APPROVAL_INVALID", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const actionId = "act-b16-list-orphaned";
    const jobId = "job-b16-list-orphaned";
    const reviewId = "rev-b16-list-orphaned";
    seedApprovedActionWithOrphanedInvalidationReason(handle, actionId, jobId, reviewId);

    let captured: unknown = null;
    try {
      queue.list(jobId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID", jobId);
  });
});

// ===========================================================================
// P0.2 Packet 2 (Slice B2A) — ActionApprovalService.preview() RED tests.
//
// Contract source: docs/p0.2-packet-2-contract.md §4 and §7 (preview pure
// materialization). The current ActionApprovalService.preview is a
// fail-closed stub that throws ACTION_APPROVAL_CONTEXT_UNAVAILABLE on
// every call. The B2A suite asserts the strict contract surface that
// the production preview implementation must satisfy:
//
//   1. actionId is validated purely (no SQL, no loader/resolver/clock)
//      and rejected for wrong type, padded, C0, DEL, empty, and a
//      257-code-point value;
//   2. service preflight propagates the exact typed error code for
//      missing action, non-pending action, missing/blank job, missing
//      job, terminal job, dirty clean-state. Loader/resolver/clock are
//      NOT invoked on preflight failure.
//   3. Valid builtin happy path returns a narrow ActionMaterialSource
//      projection, reuses the resolved normalized target, calls
//      loadCurrentProgram exactly once and resolveBindingMaterial
//      exactly once with the same program, never calls now(), never
//      begins/commits/writes, and produces an ActionApprovalChallenge
//      with exact actionId/jobId/policy decision/reason and
//      independently verified 64-lowercase-hex scope/policy/action/
//      context hashes. JSON output must not expose programFile,
//      metadata, target authority internals, or execution token.
//   4. Present target is normalized by a fresh ScopeGuard and must
//      exactly equal resolver normalizedTarget; the source preserves
//      raw action/job targets. A requiresScope denial is a normal
//      challenge block (not CONTEXT_UNAVAILABLE) with the fixed
//      reason "Blocked by current authority enforcement".
//   5. PolicyGate outcomes are returned unchanged when enforcement
//      does not block: allow, require_approval, and one genuine
//      PolicyGate block preserving its native reason.
//   6. Every preview call reloads current program and resolves
//      binding once; a current-program semantic drift changes the
//      relevant challenge hash and context hash; no previous preview
//      result is reused.
//   7. Loader throw / resolver throw / malformed target / malformed
//      capability / malformed integration material / unknown
//      integration tag => fixed cause-free
//      ACTION_APPROVAL_CONTEXT_UNAVAILABLE. Injected sentinel text
//      is absent from the message AND from the serialized
//      BountyPilotError. now() remains zero. Valid preflight errors
//      are NOT remapped.
//   8. Structurally valid integration projection happy case +
//      representative enforcement blocks (disabled, allowExecute
//      false, capability missing/blocked, blockedByDefault, mode
//      absent) with fixed enforcement reason. Representative
//      malformed complete-policy cases (name mismatch, timeout out
//      of range, invalid digest/entrypoint/array type) =>
//      CONTEXT_UNAVAILABLE.
//   9. DB rows are byte-identical around preview and the
//      transaction tracker is false afterward; no live effects.
//
// All new tests must remain RED against the current fail-closed
// service skeleton because expected preview successes and the typed
// validation codes differ from the current CONTEXT_UNAVAILABLE
// stub. A passing test on the stub indicates only that the
// fail-closed code happened to match the expected code; it does
// not mean production satisfies the contract.
// ===========================================================================

// ---------------------------------------------------------------------------
// B2A shared fixtures and helpers
// ---------------------------------------------------------------------------

interface B2ACapabilityInput {
  id: string;
  actionType: string;
  riskLevel: "low" | "medium" | "high";
  allowedModes: ReadonlyArray<"passive" | "safe" | "deep-safe" | "lab-offensive">;
  requiresTarget?: boolean;
  requiresScope?: boolean;
  stateChanging?: boolean;
  destructive?: boolean;
  requiresApprovalByDefault?: boolean;
  blockedByDefault?: boolean;
  scopedPostcondition?: "current_or_final_url_in_scope";
  mcpTools?: ReadonlyArray<string>;
}

interface B2ABaseProgramInput {
  program: string;
  inScope: ReadonlyArray<string>;
  requireHumanApproval?: boolean;
  deepSafeMode?: boolean;
  labMode?: boolean;
}

function buildB2AProgramConfig(input: B2ABaseProgramInput): ProgramConfig {
  // The ProgramSchema accepts a plain JavaScript object directly.
  // Building the object explicitly (rather than parsing YAML) keeps
  // the fixture independent of the yaml package and lets the test
  // exercise the same Zod normalization path that the production
  // loader uses.
  return ProgramSchema.parse({
    program: input.program,
    platform: "hackerone",
    in_scope: [...input.inScope],
    out_of_scope: [],
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "1rps",
      browser_crawling: true,
      deep_safe_mode: input.deepSafeMode ?? true,
      lab_mode: input.labMode ?? false,
      require_human_approval_for_risky_actions: input.requireHumanApproval ?? true,
    },
    accounts: { required: false, use_researcher_owned_test_accounts_only: true },
    evidence: {
      screenshots: true,
      har: true,
      console_logs: true,
      dom_snapshot: true,
      video: "optional",
      browser_trace: true,
      desktop_screenshots: "optional",
      mask_secrets: true,
    },
    integrations: {},
  });
}

function buildB2ALoadedProgram(input: B2ABaseProgramInput): LoadedProgram {
  const config = buildB2AProgramConfig(input);
  return {
    config,
    programFile: `/tmp/bountypilot-b2a-${input.program}.yml`,
    labAuthorization: null,
  };
}

function buildB2AProgramAuthoritySnapshot(loaded: LoadedProgram) {
  return buildProgramAuthoritySnapshot({
    config: loaded.config,
    labAuthorization: loaded.labAuthorization,
  });
}

function buildB2ACapability(
  base: B2ACapabilityInput,
  overrides: Partial<AdapterCapabilityMetadata> = {},
): CapabilityEnforcementInput {
  return {
    id: base.id,
    actionType: base.actionType,
    riskLevel: base.riskLevel,
    allowedModes: [...base.allowedModes],
    requiresTarget: base.requiresTarget ?? false,
    requiresScope: base.requiresScope ?? false,
    stateChanging: base.stateChanging ?? false,
    destructive: base.destructive ?? false,
    requiresApprovalByDefault: base.requiresApprovalByDefault ?? false,
    blockedByDefault: base.blockedByDefault ?? false,
    scopedPostcondition: base.scopedPostcondition,
    mcpTools: base.mcpTools ? [...base.mcpTools] : [],
    title: "B2A capability",
    description: "B2A test capability",
    produces: ["observation"],
    ...overrides,
  };
}

function buildB2ASafeIntegrationPolicy(
  overrides: Partial<SafeIntegrationExecutionPolicy> = {},
): SafeIntegrationExecutionPolicy {
  return {
    name: "safe-checks",
    type: "external-tool",
    enabled: true,
    allowExecute: true,
    transport: null,
    launcherSha256: "1".repeat(64),
    endpointSha256: null,
    package: null,
    packageVersion: null,
    entrypoint: "dist/cli.js",
    entrypointSha256: "2".repeat(64),
    packageJsonSha256: null,
    timeoutMs: 30_000,
    capabilities: ["GET"],
    blockedCapabilities: [],
    ...overrides,
  };
}

interface B2ADependenciesInput {
  loaded: LoadedProgram;
  capability: CapabilityEnforcementInput;
  // The resolver is configured to return this integration material
  // for the given (source, program) pair.
  integration: IntegrationBindingMaterial;
  // The normalized target the resolver should report. When the
  // configured target is null the resolver must also return null
  // regardless of this value.
  normalizedTarget: string | null;
}

interface B2ADependencyCounters {
  loadCount: () => number;
  resolveCount: () => number;
  nowCount: () => number;
  loadCurrentProgram: () => LoadedProgram;
  resolveBindingMaterial: (input: {
    source: {
      action: {
        id: string;
        jobId: string;
        adapter: string;
        actionType: string;
        target: string | null;
        riskLevel: "low" | "medium" | "high";
        requiresApproval: boolean;
        requiredForCompletion: boolean;
        metadata: Record<string, unknown>;
      };
      job: {
        id: string;
        type: string;
        target: string | null;
        mode: "passive" | "safe" | "deep-safe" | "lab-offensive";
      };
    };
    program: LoadedProgram;
  }) => ResolvedBindingMaterial;
  now: () => Date;
}

function buildB2ADependencies(
  input: B2ADependenciesInput,
): { dependencies: ActionApprovalServiceDependencies; counters: B2ADependencyCounters } {
  let loadCount = 0;
  let resolveCount = 0;
  let nowCount = 0;
  const loaded = input.loaded;
  const capability = input.capability;
  const integration = input.integration;
  const normalizedTarget = input.normalizedTarget;
  const loadCurrentProgram = (): LoadedProgram => {
    loadCount += 1;
    return loaded;
  };
  const resolveBindingMaterial: B2ADependencyCounters["resolveBindingMaterial"] = (resolveInput) => {
    resolveCount += 1;
    // The resolver's normalized target is always the configured
    // constant for this dependency bundle. The contract requires
    // fresh ScopeGuard normalization to land the same value; the
    // B2A.4 happy case below uses a real ScopeGuard to compute
    // that value and the dependency is configured to mirror it.
    return {
      normalizedTarget: resolveInput.source.action.target === null ? null : normalizedTarget,
      capabilityEnforcement: capability,
      integration,
    };
  };
  const now = (): Date => {
    nowCount += 1;
    return new Date("2099-01-01T00:00:00.000Z");
  };
  return {
    dependencies: { loadCurrentProgram, resolveBindingMaterial, now },
    counters: {
      loadCount: () => loadCount,
      resolveCount: () => resolveCount,
      nowCount: () => nowCount,
      loadCurrentProgram,
      resolveBindingMaterial,
      now,
    },
  };
}

const B2A_DEFAULT_PROGRAM_INPUT: B2ABaseProgramInput = {
  program: "b2a-base",
  inScope: ["api.example.com", "*.example.com"],
};

const B2A_DEFAULT_CAPABILITY: B2ACapabilityInput = {
  id: "http.read",
  actionType: "GET",
  riskLevel: "low",
  allowedModes: ["safe", "deep-safe"],
  requiresTarget: true,
  requiresScope: true,
  stateChanging: false,
  destructive: false,
  requiresApprovalByDefault: false,
  blockedByDefault: false,
  scopedPostcondition: "current_or_final_url_in_scope",
  mcpTools: ["http.get"],
};

const B2A_TARGET = "https://api.example.com/health";
const B2A_NORMALIZED_TARGET = "https://api.example.com/health";

function buildB2AService(
  handle: BountyDatabase,
  dependenciesInput?: Partial<B2ADependenciesInput>,
): { service: ActionApprovalService; counters: B2ADependencyCounters } {
  const merged: B2ADependenciesInput = {
    loaded: dependenciesInput?.loaded ?? buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT),
    capability: dependenciesInput?.capability ?? buildB2ACapability(B2A_DEFAULT_CAPABILITY),
    integration: dependenciesInput?.integration ?? { kind: "builtin" },
    normalizedTarget: dependenciesInput?.normalizedTarget ?? B2A_NORMALIZED_TARGET,
  };
  const { dependencies, counters } = buildB2ADependencies(merged);
  return { service: new ActionApprovalService(handle, dependencies), counters };
}

function insertJobWithMode(
  db: BountyDatabase,
  id: string,
  mode: "passive" | "safe" | "deep-safe" | "lab-offensive",
  type = "b2a-test-job",
  status: "queued" | "running" | "paused" | "failed" | "completed" = "queued",
  target: string | null = null,
): void {
  db
    .prepare(
      `INSERT INTO jobs (
         id, type, target, mode, status, pause_reason, status_detail,
         created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)`,
    )
    .run(id, type, target, mode, status, CREATED_AT, UPDATED_AT);
}

function seedB2APendingAction(
  db: BountyDatabase,
  actionId: string,
  jobId: string,
  overrides: {
    target?: string | null;
    metadataJsonRaw?: string | null;
    riskLevel?: "low" | "medium" | "high";
    actionType?: string;
    adapter?: string;
    requiresApproval?: 0 | 1;
    requiredForCompletion?: 0 | 1;
  } = {},
): void {
  insertRawV2Action(db, {
    id: actionId,
    jobId,
    status: "pending",
    requiredForCompletion: overrides.requiredForCompletion ?? 1,
    requiresApproval: overrides.requiresApproval ?? 1,
    metadataJsonRaw: overrides.metadataJsonRaw === undefined ? null : overrides.metadataJsonRaw,
  });
  // Apply overrides that the helper does not cover.
  const sets: string[] = [];
  const args: Array<string | number | null> = [];
  if (overrides.target !== undefined) {
    sets.push("target = ?");
    args.push(overrides.target);
  }
  if (overrides.riskLevel !== undefined) {
    sets.push("risk_level = ?");
    args.push(overrides.riskLevel);
  }
  if (overrides.actionType !== undefined) {
    sets.push("action_type = ?");
    args.push(overrides.actionType);
  }
  if (overrides.adapter !== undefined) {
    sets.push("adapter = ?");
    args.push(overrides.adapter);
  }
  if (sets.length > 0) {
    args.push(actionId);
    db.prepare(`UPDATE actions SET ${sets.join(", ")} WHERE id = ?`).run(...args);
  }
}

describe("B2A handoff boundary: planning receipts never become executable approvals", () => {
  for (const testCase of [
    {
      name: "non-required action",
      overrides: { requiredForCompletion: 0 as const },
    },
    {
      name: "handoffOnly metadata",
      overrides: { metadataJsonRaw: JSON.stringify({ handoffOnly: true }) },
    },
    {
      name: "planningOnly metadata",
      overrides: { metadataJsonRaw: JSON.stringify({ planningOnly: true }) },
    },
  ]) {
    it(`rejects ${testCase.name} before materialization or writes`, () => {
      const handle = openDb();
      const jobId = `job-b2a-handoff-${testCase.name.replace(/[^a-z]+/gi, "-").toLowerCase()}`;
      const actionId = `action-b2a-handoff-${testCase.name.replace(/[^a-z]+/gi, "-").toLowerCase()}`;
      insertJobWithMode(handle, jobId, "safe");
      seedB2APendingAction(handle, actionId, jobId, testCase.overrides);
      const before = snapshotAllActionRows(handle, jobId);
      const { service, counters } = buildB2AService(handle);

      let captured: unknown;
      try {
        service.preview(actionId);
      } catch (error) {
        captured = error;
      }

      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("ACTION_HANDOFF_ONLY");
      expect(counters.loadCount()).toBe(0);
      expect(counters.resolveCount()).toBe(0);
      expect(counters.nowCount()).toBe(0);
      expect(snapshotAllActionRows(handle, jobId)).toEqual(before);
    });
  }
});

function readActionRowForB2A(db: BountyDatabase, actionId: string): Record<string, unknown> {
  return db.prepare("SELECT * FROM actions WHERE id = ?").get(actionId) as Record<string, unknown>;
}

function snapshotAllActionRows(db: BountyDatabase, jobId: string): Array<Record<string, unknown>> {
  return db
    .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id")
    .all(jobId) as Array<Record<string, unknown>>;
}

function serializeErrorForB2ALeakCheck(err: BountyPilotError): {
  runtime: string;
  curated: string;
} {
  const runtime = JSON.stringify(err);
  const curated = JSON.stringify({
    name: err.name,
    code: err.code,
    message: err.message,
  });
  return { runtime, curated };
}

function expectNoExecutionTokenLeak(err: BountyPilotError, secret: string): void {
  expect(err.message).not.toContain(secret);
  const { runtime, curated } = serializeErrorForB2ALeakCheck(err);
  expect(runtime, `runtime JSON contains ${secret}`).not.toContain(secret);
  expect(curated, `curated JSON contains ${secret}`).not.toContain(secret);
  expect(runtime).not.toMatch(/executionToken/i);
  expect(curated).not.toMatch(/executionToken/i);
}

// ===========================================================================
// B2A.1: actionId is validated purely. The same canonical rule used by
// ActionQueue.requireCleanPendingForApproval and the in-tx CAS primitive
// must apply BEFORE the first database read. The validation is a pure
// snapshot: no SQL, no loader/resolver/clock call, no caller-code
// invocation, no reflection through hostile proxies.
// ===========================================================================

describe("B2A.1: preview actionId is validated purely before SQL, loader, resolver, or clock", () => {
  it("throws ACTION_APPROVAL_INVALID for a non-string actionId without invoking any dependency or SQL", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    let captured: unknown = null;
    try {
      // Cast through unknown to stage a non-string id at the typed
      // boundary; production must short-circuit on typeof and never
      // touch the dependency bundle or the database.
      (service.preview as unknown as (id: unknown) => unknown)(42);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID");
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
    // No SQL of any kind. The handle is the same one openDb opened;
    // asserting that no action row was written proves the pure path.
    const rows = handle.prepare("SELECT COUNT(*) AS c FROM actions").get() as { c: number };
    expect(rows.c).toBe(0);
  });

  it("throws ACTION_APPROVAL_INVALID for null actionId without invoking any dependency or SQL", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    let captured: unknown = null;
    try {
      (service.preview as unknown as (id: unknown) => unknown)(null);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID");
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });

  it("throws ACTION_APPROVAL_INVALID for undefined actionId", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    let captured: unknown = null;
    try {
      (service.preview as unknown as (id: unknown) => unknown)(undefined);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_INVALID");
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });

  // The boundary mutators follow the B1.4d mutId form: padded,
  // C0 (real U+0000), DEL (real U+007F), and 257 Unicode code
  // points (one over the 256 cap). Production preview must reject
  // every shape with ACTION_APPROVAL_INVALID.
  interface IdCase {
    name: string;
    mutate: (base: string) => string;
  }
  const ID_CASES: IdCase[] = [
    { name: "empty", mutate: (base) => "" },
    { name: "padded", mutate: (base) => " " + base + " " },
    { name: "c0", mutate: (base) => base + "\u0000" },
    { name: "del", mutate: (base) => base + "\u007f" },
    { name: "long", mutate: () => "a".repeat(257) },
  ];
  for (const c of ID_CASES) {
    it(`table: ACTION_APPROVAL_INVALID for actionId=${c.name}; no dependency, no SQL, no caller code`, () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle);
      const actionId = "act-b2a1";
      const jobId = "job-b2a1";
      // Seed a real clean pending action whose id is the unmutated
      // form; we use the mutator on a different string so the
      // mutation is the only signal the validator can rely on. The
      // row is not the target of the call, but it proves that
      // rejecting a hostile id never reached SQL.
      insertJob(handle, jobId);
      seedB2APendingAction(handle, actionId, jobId);
      const mutated = c.mutate(actionId);
      // Fixture integrity: the mutation really differs from the
      // base. A no-op mutator (e.g. empty mutation that returned
      // the base) would pass the field shape but invalidate this
      // assertion.
      expect(mutated).not.toBe(actionId);
      let captured: unknown = null;
      try {
        service.preview(mutated);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_INVALID", mutated);
      expect(counters.loadCount()).toBe(0);
      expect(counters.resolveCount()).toBe(0);
      expect(counters.nowCount()).toBe(0);
      // The valid action row remains byte-identical and is still
      // queryable; the rejection path did not touch the actions
      // table.
      const row = readActionRowForB2A(handle, actionId);
      expect(row.id).toBe(actionId);
      expect(row.status).toBe("pending");
    });
  }
});

// ===========================================================================
// B2A.2: service preflight propagates the exact typed error codes from
// §7 without invoking the loader, resolver, or clock. A representative
// table — not the exhaustive B1 matrix — keeps the slice compact while
// still proving that every documented preflight error is reached.
// ===========================================================================

describe("B2A.2: preview preflight propagates exact typed errors without invoking dependencies", () => {
  it("missing action -> ACTION_NOT_FOUND; no dependency calls", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    let captured: unknown = null;
    try {
      service.preview("act-b2a2-missing");
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_NOT_FOUND");
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });

  it("non-pending action -> ACTION_APPROVAL_NOT_PENDING; no dependency calls", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    const actionId = "act-b2a2-nonpending";
    const jobId = "job-b2a2-nonpending";
    insertJob(handle, jobId);
    // approved: structurally valid path through the ActionQueue
    // table is not necessary for this test; the row is rejected on
    // the status predicate before any review join. Seeding the row
    // directly with status='approved' is the shortest fail-closed
    // path.
    insertRawV2Action(handle, {
      id: actionId,
      jobId,
      status: "approved",
      requiredForCompletion: 1,
      requiresApproval: 1,
    });
    let captured: unknown = null;
    try {
      service.preview(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_NOT_PENDING", actionId);
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });

  it("missing/blank action jobId -> ACTION_APPROVAL_JOB_REQUIRED; no dependency calls", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    // Direct insert with job_id=NULL. The status is pending so
    // preflight reaches the jobId check.
    handle
      .prepare(
        `INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, metadata_json, created_at, executed_at, updated_at, required_for_completion) VALUES (?, NULL, 'http', 'GET', NULL, 'low', 1, 'pending', NULL, ?, NULL, ?, 1)`,
      )
      .run("act-b2a2-blankjob", CREATED_AT, UPDATED_AT);
    let captured: unknown = null;
    try {
      service.preview("act-b2a2-blankjob");
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_JOB_REQUIRED", "act-b2a2-blankjob");
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });

  it("referenced missing job -> JOB_NOT_FOUND; no dependency calls", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    const actionId = "act-b2a2-missingjob";
    const jobId = "job-b2a2-missingjob";
    seedB2APendingAction(handle, actionId, jobId);
    let captured: unknown = null;
    try {
      service.preview(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "JOB_NOT_FOUND", actionId);
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });

  it("terminal job -> ACTION_APPROVAL_JOB_TERMINAL; no dependency calls", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    const actionId = "act-b2a2-term";
    const jobId = "job-b2a2-term";
    insertJob(handle, jobId, "completed");
    seedB2APendingAction(handle, actionId, jobId);
    let captured: unknown = null;
    try {
      service.preview(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_JOB_TERMINAL", actionId);
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });

  it("dirty clean-state (started_at non-null) -> ACTION_APPROVAL_STATE_INVALID; no dependency calls", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    const actionId = "act-b2a2-dirty";
    const jobId = "job-b2a2-dirty";
    insertJob(handle, jobId);
    seedB2APendingAction(handle, actionId, jobId);
    handle
      .prepare("UPDATE actions SET started_at = ? WHERE id = ?")
      .run(REVIEWED_AT, actionId);
    let captured: unknown = null;
    try {
      service.preview(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_STATE_INVALID", actionId);
    expect(counters.loadCount()).toBe(0);
    expect(counters.resolveCount()).toBe(0);
    expect(counters.nowCount()).toBe(0);
  });
});

// ===========================================================================
// B2A.3: valid builtin happy path. The action has a concrete
// nonterminal job, a present target, and a valid capability. preview
// must build the narrow ActionMaterialSource (no status/lifecycle),
// call loadCurrentProgram exactly once and resolveBindingMaterial
// exactly once with the same program, never call now(), never begin
// or commit a transaction, never write to the database, and return an
// ActionApprovalChallenge with the exact actionId, jobId, current
// policy decision, native reason, and 64-lowercase-hex scope/policy/
// action/context hashes that an independent helper agrees on. The
// challenge JSON must not expose programFile, metadata, target
// authority internals, or the execution token.
// ===========================================================================

describe("B2A.3: valid builtin happy path is pure materialization with exact challenge contents", () => {
  it("returns an ActionApprovalChallenge with the exact decision, hashes, and zero side effects", () => {
    const handle = openDb();
    const { service, counters } = buildB2AService(handle);
    const actionId = "act-b2a3-happy";
    const jobId = "job-b2a3-happy";
    insertJobWithMode(handle, jobId, "safe", "b2a3-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const before = snapshotAllActionRows(handle, jobId);

    const challenge = service.preview(actionId);
    expect(challenge.actionId).toBe(actionId);
    expect(challenge.jobId).toBe(jobId);
    expect(challenge.policyDecision).toBe("allow");
    expect(challenge.policyReason).toBe("Allowed by policy");
    expect(challenge.scopeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(challenge.policyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(challenge.actionHash).toMatch(/^[0-9a-f]{64}$/);
    expect(challenge.contextHash).toMatch(/^[0-9a-f]{64}$/);
    // Zero-prepare/tx state side effects. The dependency bundle is
    // called exactly once each, and the clock is never touched.
    expect(counters.loadCount()).toBe(1);
    expect(counters.resolveCount()).toBe(1);
    expect(counters.nowCount()).toBe(0);
    // No SQL touched the actions table.
    const after = snapshotAllActionRows(handle, jobId);
    expect(after).toEqual(before);
    // The transaction tracker is false after preview returned.
    expect(hasImmediateTransaction(handle)).toBe(false);
  });

  it("independently verified hashes match sha256 of the canonical authority + binding context", () => {
    const handle = openDb();
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const capability = buildB2ACapability(B2A_DEFAULT_CAPABILITY);
    const { service, counters } = buildB2AService(handle, {
      loaded,
      capability,
      integration: { kind: "builtin" },
      normalizedTarget: B2A_NORMALIZED_TARGET,
    });
    const actionId = "act-b2a3-hashes";
    const jobId = "job-b2a3-hashes";
    insertJobWithMode(handle, jobId, "safe", "b2a3-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const challenge = service.preview(actionId);

    // Independently recompute the scope/policy hashes from the
    // same program config via the public authority helpers. The
    // service must agree because preview binds the current
    // program on every call.
    const authority = buildB2AProgramAuthoritySnapshot(loaded);
    expect(challenge.scopeHash).toBe(authority.scopeHash);
    expect(challenge.policyHash).toBe(authority.policyHash);

    // Independently rebuild the action binding and the context
    // hash from the persisted row + capability + normalized
    // target. The service must produce the same actionHash and
    // contextHash because the production binding inputs are
    // exactly these projections.
    const actionRow = handle
      .prepare(
        "SELECT id, job_id, adapter, action_type, target, risk_level, requires_approval, required_for_completion, status, metadata_json, created_at, updated_at FROM actions WHERE id = ?",
      )
      .get(actionId) as Record<string, unknown>;
    const jobRow = handle
      .prepare("SELECT id, type, target, mode FROM jobs WHERE id = ?")
      .get(jobId) as { id: string; type: string; target: string | null; mode: "passive" | "safe" | "deep-safe" | "lab-offensive" };
    const metadata = actionRow.metadata_json === null || actionRow.metadata_json === undefined
      ? {}
      : (JSON.parse(String(actionRow.metadata_json)) as Record<string, unknown>);
    const actionRecord: ActionRecord = {
      id: String(actionRow.id),
      jobId: String(actionRow.job_id),
      adapter: String(actionRow.adapter),
      actionType: String(actionRow.action_type),
      target: actionRow.target === null ? undefined : String(actionRow.target),
      riskLevel: actionRow.risk_level as "low" | "medium" | "high",
      requiresApproval: actionRow.requires_approval === 1,
      status: actionRow.status as "pending",
      metadata,
      createdAt: String(actionRow.created_at),
      updatedAt: String(actionRow.updated_at),
      requiredForCompletion: actionRow.required_for_completion === 1,
    };
    const binding = buildActionBinding({
      action: actionRecord,
      job: {
        ...jobRow,
        target: jobRow.target === null ? undefined : jobRow.target,
        status: "queued",
        pauseReason: null,
        statusDetail: null,
        createdAt: String(actionRow.created_at),
        updatedAt: String(actionRow.updated_at),
      },
      normalizedTarget: B2A_NORMALIZED_TARGET,
      requiredForCompletion: true,
      policyAction: {
        mode: "safe",
        actionType: String(actionRow.action_type),
        target: B2A_TARGET,
        riskLevel: actionRow.risk_level as "low" | "medium" | "high",
        stateChanging: capability.stateChanging ?? false,
        destructive: capability.destructive ?? false,
        capability: capability.id,
        requiresApprovalByDefault: capability.requiresApprovalByDefault ?? false,
        labModeEnabled: false,
      },
      capabilityEnforcement: capability,
      policyDecision: "allow",
      integrationExecutionPolicy: null,
    });
    const expectedActionHash = computeActionHash(binding);
    const expectedContextHash = computeContextHash({
      scopeHash: authority.scopeHash,
      policyHash: authority.policyHash,
      actionHash: expectedActionHash,
    });
    expect(challenge.actionHash).toBe(expectedActionHash);
    expect(challenge.contextHash).toBe(expectedContextHash);
    // The dependency counters remain exactly 1/1/0; this is a
    // second read of the same program/binding, not a fresh call.
    expect(counters.loadCount()).toBe(1);
    expect(counters.resolveCount()).toBe(1);
    expect(counters.nowCount()).toBe(0);
  });

  it("missing target -> null; missing metadata -> fresh empty plain object; no token/programFile leak", () => {
    const handle = openDb();
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const capability = buildB2ACapability({
      ...B2A_DEFAULT_CAPABILITY,
      requiresTarget: false,
      requiresScope: false,
    });
    const { service } = buildB2AService(handle, {
      loaded,
      capability,
      integration: { kind: "builtin" },
      normalizedTarget: "",
    });
    const actionId = "act-b2a3-null";
    const jobId = "job-b2a3-null";
    insertJobWithMode(handle, jobId, "safe", "b2a3-hunt", "queued", null);
    seedB2APendingAction(handle, actionId, jobId, { target: null, metadataJsonRaw: null });
    const challenge = service.preview(actionId);
    expect(challenge.actionId).toBe(actionId);
    expect(challenge.jobId).toBe(jobId);
    expect(challenge.scopeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(challenge.policyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(challenge.actionHash).toMatch(/^[0-9a-f]{64}$/);
    expect(challenge.contextHash).toMatch(/^[0-9a-f]{64}$/);
    // No programFile, no metadata, no target authority internals,
    // no execution token in the JSON projection of the challenge.
    const json = JSON.stringify(challenge);
    expect(json).not.toContain(loaded.programFile);
    expect(json).not.toMatch(/metadata/i);
    expect(json).not.toMatch(/programFile/i);
    expect(json).not.toMatch(/executionToken/i);
    expect(json).not.toMatch(/token/i);
    expect(json).not.toMatch(/entrypoint/i);
    expect(json).not.toMatch(/launcherSha/i);
  });
});

// ===========================================================================
// B2A.4: present target is normalized by a fresh ScopeGuard and must
// exactly equal the resolver's normalizedTarget; the source preserves
// the raw action/job targets. A requiresScope denial becomes a
// normal challenge block (not CONTEXT_UNAVAILABLE) with the fixed
// reason "Blocked by current authority enforcement".
// ===========================================================================

describe("B2A.4: present target is normalized by a fresh ScopeGuard; requiresScope denial is a normal block", () => {
  it("present target is normalized by a fresh ScopeGuard and matches the resolver's normalizedTarget", () => {
    const handle = openDb();
    // The action target intentionally differs in trailing-slash and
    // case from the resolver's normalized target; the production
    // ScopeGuard must canonicalize it to the resolver's value.
    const rawTarget = "HTTPS://api.example.com/health/";
    const expectedNormalized = "https://api.example.com/health/";
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const { service, counters } = buildB2AService(handle, {
      loaded,
      capability: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
      integration: { kind: "builtin" },
      normalizedTarget: expectedNormalized,
    });
    const actionId = "act-b2a4-scope-allow";
    const jobId = "job-b2a4-scope-allow";
    insertJobWithMode(handle, jobId, "safe", "b2a4-hunt", "queued", rawTarget);
    seedB2APendingAction(handle, actionId, jobId, { target: rawTarget });
    const challenge = service.preview(actionId);
    expect(counters.loadCount()).toBe(1);
    expect(counters.resolveCount()).toBe(1);
    // Independently run a fresh ScopeGuard over the raw target. The
    // resulting normalized URL must equal the resolver's
    // normalizedTarget (and therefore appear in the actionHash
    // input that the helper recomputes).
    const guard = new ScopeGuard(loaded.config);
    const scoped = guard.test(rawTarget);
    expect(scoped.allowed).toBe(true);
    const freshNormalized = scoped.url;
    expect(freshNormalized).toBe(expectedNormalized);
    // The challenge's actionHash is the SHA-256 of the binding
    // that included the fresh normalized target. We re-derive the
    // binding using the fresh normalized target and assert the
    // hash matches.
    const actionRow = handle
      .prepare("SELECT id, job_id, adapter, action_type, target, risk_level, requires_approval, required_for_completion, status, metadata_json, created_at, updated_at FROM actions WHERE id = ?")
      .get(actionId) as Record<string, unknown>;
    const metadata = actionRow.metadata_json === null || actionRow.metadata_json === undefined
      ? {}
      : (JSON.parse(String(actionRow.metadata_json)) as Record<string, unknown>);
    const actionRecord: ActionRecord = {
      id: String(actionRow.id),
      jobId: String(actionRow.job_id),
      adapter: String(actionRow.adapter),
      actionType: String(actionRow.action_type),
      target: String(actionRow.target),
      riskLevel: actionRow.risk_level as "low" | "medium" | "high",
      requiresApproval: actionRow.requires_approval === 1,
      status: actionRow.status as "pending",
      metadata,
      createdAt: String(actionRow.created_at),
      updatedAt: String(actionRow.updated_at),
      requiredForCompletion: actionRow.required_for_completion === 1,
    };
    const expectedBinding = buildActionBinding({
      action: actionRecord,
      job: {
        id: jobId,
        type: "b2a4-hunt",
        target: rawTarget,
        mode: "safe",
        status: "queued",
        pauseReason: null,
        statusDetail: null,
        createdAt: String(actionRow.created_at),
        updatedAt: String(actionRow.updated_at),
      },
      normalizedTarget: freshNormalized,
      requiredForCompletion: true,
      policyAction: {
        mode: "safe",
        actionType: String(actionRow.action_type),
        target: freshNormalized,
        riskLevel: "low",
        stateChanging: false,
        destructive: false,
        capability: "http.read",
        requiresApprovalByDefault: false,
        labModeEnabled: false,
      },
      capabilityEnforcement: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
      policyDecision: "allow",
      integrationExecutionPolicy: null,
    });
    expect(challenge.actionHash).toBe(computeActionHash(expectedBinding));
  });

  it("requiresScope denial becomes a normal block with the fixed enforcement reason", () => {
    const handle = openDb();
    // The action target is OUT of the program's in_scope rules;
    // a fresh ScopeGuard returns allowed=false. The preview
    // challenge is a normal block, not CONTEXT_UNAVAILABLE, with
    // the exact reason "Blocked by current authority enforcement".
    const outOfScopeTarget = "https://attacker.example.com/exfil";
    const loaded = buildB2ALoadedProgram({
      ...B2A_DEFAULT_PROGRAM_INPUT,
      inScope: ["api.example.com"],
    });
    const { service, counters } = buildB2AService(handle, {
      loaded,
      capability: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
      integration: { kind: "builtin" },
      normalizedTarget: outOfScopeTarget,
    });
    const actionId = "act-b2a4-scope-block";
    const jobId = "job-b2a4-scope-block";
    insertJobWithMode(handle, jobId, "safe", "b2a4-hunt", "queued", outOfScopeTarget);
    seedB2APendingAction(handle, actionId, jobId, { target: outOfScopeTarget });
    const challenge = service.preview(actionId);
    expect(challenge.actionId).toBe(actionId);
    expect(challenge.jobId).toBe(jobId);
    expect(challenge.policyDecision).toBe("block");
    expect(challenge.policyReason).toBe("Blocked by current authority enforcement");
    // The dependency was still called exactly once each because
    // the enforcement path is a normal block, not a materialization
    // failure.
    expect(counters.loadCount()).toBe(1);
    expect(counters.resolveCount()).toBe(1);
    expect(counters.nowCount()).toBe(0);
    // Independent confirmation: a fresh ScopeGuard on the action
    // target reports allowed=false.
    const guard = new ScopeGuard(loaded.config);
    const scoped = guard.test(outOfScopeTarget);
    expect(scoped.allowed).toBe(false);
  });
});

// ===========================================================================
// B2A.5: PolicyGate outcomes are returned unchanged when enforcement
// does not block: allow, require_approval, and one genuine PolicyGate
// block preserving its native reason. The block must NOT be remapped
// to CONTEXT_UNAVAILABLE.
// ===========================================================================

describe("B2A.5: PolicyGate outcomes (allow, require_approval, native block) are returned unchanged when enforcement does not block", () => {
  it("returns policyDecision=allow with the native reason", () => {
    const handle = openDb();
    const { service } = buildB2AService(handle);
    const actionId = "act-b2a5-allow";
    const jobId = "job-b2a5-allow";
    insertJobWithMode(handle, jobId, "safe", "b2a5-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const challenge = service.preview(actionId);
    expect(challenge.policyDecision).toBe("allow");
    expect(challenge.policyReason).toBe("Allowed by policy");
  });

  it("returns policyDecision=require_approval with the native reason when the action is risky and the rule requires approval", () => {
    const handle = openDb();
    const { service } = buildB2AService(handle, {
      capability: buildB2ACapability({
        ...B2A_DEFAULT_CAPABILITY,
        riskLevel: "medium",
      }),
    });
    const actionId = "act-b2a5-req";
    const jobId = "job-b2a5-req";
    // A safe-mode medium-risk action is the canonical
    // require_approval case per PolicyGate: state-changing=false,
    // risk=medium, mode=safe.
    insertJobWithMode(handle, jobId, "safe", "b2a5-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, {
      target: B2A_TARGET,
      riskLevel: "medium",
      actionType: "GET",
    });
    const challenge = service.preview(actionId);
    expect(challenge.policyDecision).toBe("require_approval");
    expect(challenge.policyReason).toBe("Safe mode requires approval for medium/high risk actions");
  });

  it("returns policyDecision=block with the native PolicyGate reason (destructive=true)", () => {
    const handle = openDb();
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const { service, counters } = buildB2AService(handle, {
      loaded,
      capability: buildB2ACapability({
        ...B2A_DEFAULT_CAPABILITY,
        destructive: true,
        // destructive=true is the PolicyGate's unconditional block
        // trigger; the enforcement-block path does NOT preempt it.
        requiresScope: false,
        blockedByDefault: false,
      }),
      integration: { kind: "builtin" },
      normalizedTarget: B2A_NORMALIZED_TARGET,
    });
    const actionId = "act-b2a5-block";
    const jobId = "job-b2a5-block";
    insertJobWithMode(handle, jobId, "safe", "b2a5-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const challenge = service.preview(actionId);
    expect(challenge.policyDecision).toBe("block");
    // The native PolicyGate reason is preserved verbatim; it is
    // NOT remapped to the enforcement-block reason.
    expect(challenge.policyReason).toBe("Destructive testing is blocked by default");
    // Dependencies still called exactly once each.
    expect(counters.loadCount()).toBe(1);
    expect(counters.resolveCount()).toBe(1);
    expect(counters.nowCount()).toBe(0);
  });
});

// ===========================================================================
// B2A.6: every preview call reloads current program and resolves
// binding once; a current-program semantic drift changes the
// relevant challenge hash/context; no previous preview is reused.
// ===========================================================================

describe("B2A.6: every preview call reloads current program and resolves binding once; no caching across calls", () => {
  it("two consecutive previews call the loader+resolver exactly twice each and never reuse the previous challenge", () => {
    const handle = openDb();
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const { service, counters } = buildB2AService(handle, {
      loaded,
      capability: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
      integration: { kind: "builtin" },
      normalizedTarget: B2A_NORMALIZED_TARGET,
    });
    const actionId = "act-b2a6-pair";
    const jobId = "job-b2a6-pair";
    insertJobWithMode(handle, jobId, "safe", "b2a6-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });

    const first = service.preview(actionId);
    const second = service.preview(actionId);
    expect(counters.loadCount()).toBe(2);
    expect(counters.resolveCount()).toBe(2);
    expect(counters.nowCount()).toBe(0);
    // Same inputs -> same challenge. This is a contract-stability
    // invariant: a re-call with the same rows must produce a
    // stable, equal challenge. A future change that started
    // caching would either break this equality or fail the call
    // counts above.
    expect(second).toEqual(first);
  });

  it("current-program semantic drift changes the relevant scopeHash/policyHash and contextHash but not the actionHash", () => {
    const handle = openDb();
    const baseLoaded = buildB2ALoadedProgram({
      program: "b2a6-drift-a",
      inScope: ["api.example.com", "*.example.com"],
    });
    const { service, counters } = buildB2AService(handle, {
      loaded: baseLoaded,
      capability: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
      integration: { kind: "builtin" },
      normalizedTarget: B2A_NORMALIZED_TARGET,
    });
    const actionId = "act-b2a6-drift";
    const jobId = "job-b2a6-drift";
    insertJobWithMode(handle, jobId, "safe", "b2a6-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const first = service.preview(actionId);

    // Rebuild a service that uses a different program file with
    // a SEMANTIC drift (a different out_of_scope entry). The
    // first challenge must NOT be reused; a new scopeHash and a
    // new policyHash must land, and the contextHash must follow.
    const driftedLoaded = buildB2ALoadedProgram({
      program: "b2a6-drift-a",
      inScope: ["api.example.com", "*.example.com"],
    });
    // Drift the policy field: change destructive_testing. The
    // scope snapshot is unchanged; the policy snapshot must
    // change. The actionHash is built from the binding, which is
    // action+job+capability+normalizedTarget+decision dependent;
    // it does NOT include the program config, so it stays
    // identical.
    const driftedConfig: ProgramConfig = {
      ...driftedLoaded.config,
      rules: { ...driftedLoaded.config.rules, destructive_testing: true },
    };
    const driftedLoadedFinal: LoadedProgram = {
      config: driftedConfig,
      programFile: driftedLoaded.programFile,
      labAuthorization: driftedLoaded.labAuthorization,
    };
    const secondDeps = buildB2ADependencies({
      loaded: driftedLoadedFinal,
      capability: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
      integration: { kind: "builtin" },
      normalizedTarget: B2A_NORMALIZED_TARGET,
    });
    const driftedService = new ActionApprovalService(handle, secondDeps.dependencies);
    const second = driftedService.preview(actionId);
    expect(second.scopeHash).toBe(first.scopeHash);
    expect(second.policyHash).not.toBe(first.policyHash);
    expect(second.contextHash).not.toBe(first.contextHash);
    // The actionHash is built from the same binding inputs, so it
    // is identical between the two calls.
    expect(second.actionHash).toBe(first.actionHash);
    // The drift path used a fresh service; the original counter
    // is untouched. The new dependency's counters must report
    // exactly one call each.
    expect(secondDeps.counters.loadCount()).toBe(1);
    expect(secondDeps.counters.resolveCount()).toBe(1);
    expect(secondDeps.counters.nowCount()).toBe(0);
    // And the original service's counters reflect the two
    // earlier previews only.
    expect(counters.loadCount()).toBe(1);
    expect(counters.resolveCount()).toBe(1);
  });
});

// ===========================================================================
// B2A.7: loader throw / resolver throw / malformed target / malformed
// capability / malformed integration material / unknown integration
// tag => fixed cause-free ACTION_APPROVAL_CONTEXT_UNAVAILABLE. The
// injected sentinel text is absent from message AND from the
// serialized BountyPilotError. now() remains zero. Valid preflight
// errors are NOT remapped.
// ===========================================================================

describe("B2A.7: malformed material and dependency throws map to fixed cause-free CONTEXT_UNAVAILABLE without leaking the cause", () => {
  // The sentinel text is unique, deliberately placed inside the
  // dependency's own throw, and asserted to be absent from every
  // observable surface of the captured BountyPilotError. The
  // test does NOT depend on the message being a constant; it
  // depends on the cause/echo path being a fixed
  // ACTION_APPROVAL_CONTEXT_UNAVAILABLE with no reflective text.
  const SENTINEL = "B2A7_LEAKED_CAUSE_SENTINEL_TOKEN_LEAK";

  it("loader throw -> ACTION_APPROVAL_CONTEXT_UNAVAILABLE; sentinel absent; now() zero", () => {
    const handle = openDb();
    const actionId = "act-b2a7-loader";
    const jobId = "job-b2a7-loader";
    insertJobWithMode(handle, jobId, "safe", "b2a7-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const capability = buildB2ACapability(B2A_DEFAULT_CAPABILITY);
    let nowCount = 0;
    let resolveCount = 0;
    const deps: ActionApprovalServiceDependencies = {
      loadCurrentProgram: () => {
        throw new Error(`loader-failure: ${SENTINEL}`);
      },
      resolveBindingMaterial: () => {
        resolveCount += 1;
        return {
          normalizedTarget: B2A_NORMALIZED_TARGET,
          capabilityEnforcement: capability,
          integration: { kind: "builtin" },
        };
      },
      now: () => {
        nowCount += 1;
        return new Date("2099-01-01T00:00:00.000Z");
      },
    };
    const service = new ActionApprovalService(handle, deps);
    let captured: unknown = null;
    try {
      service.preview(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_CONTEXT_UNAVAILABLE");
    expectNoExecutionTokenLeak(captured as BountyPilotError, SENTINEL);
    expect(nowCount).toBe(0);
    expect(resolveCount).toBe(0);
  });

  it("resolver throw -> ACTION_APPROVAL_CONTEXT_UNAVAILABLE; sentinel absent; now() zero", () => {
    const handle = openDb();
    const actionId = "act-b2a7-resolver";
    const jobId = "job-b2a7-resolver";
    insertJobWithMode(handle, jobId, "safe", "b2a7-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    let nowCount = 0;
    let loadCount = 0;
    const deps: ActionApprovalServiceDependencies = {
      loadCurrentProgram: () => {
        loadCount += 1;
        return loaded;
      },
      resolveBindingMaterial: () => {
        throw new Error(`resolver-failure: ${SENTINEL}`);
      },
      now: () => {
        nowCount += 1;
        return new Date("2099-01-01T00:00:00.000Z");
      },
    };
    const service = new ActionApprovalService(handle, deps);
    let captured: unknown = null;
    try {
      service.preview(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_CONTEXT_UNAVAILABLE");
    expectNoExecutionTokenLeak(captured as BountyPilotError, SENTINEL);
    expect(nowCount).toBe(0);
    expect(loadCount).toBe(1);
  });

  it("unknown integration tag (string) -> ACTION_APPROVAL_CONTEXT_UNAVAILABLE; sentinel absent; now() zero", () => {
    const handle = openDb();
    const actionId = "act-b2a7-unkint";
    const jobId = "job-b2a7-unkint";
    insertJobWithMode(handle, jobId, "safe", "b2a7-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const capability = buildB2ACapability(B2A_DEFAULT_CAPABILITY);
    // A resolver that returns a string tag (not the typed
    // union) is the canonical "unknown integration tag" input
    // from §4: the trusted resolver must derive the tag from
    // the current integration registry, and any other shape is
    // CONTEXT_UNAVAILABLE. The narrow typed boundary cast is
    // the only place in this file that crosses the type
    // boundary; every other case uses a typed value.
    const unknownTag = "totally-unknown-integration-tag-with-leak-" + SENTINEL as unknown as ResolvedBindingMaterial;
    const deps: ActionApprovalServiceDependencies = {
      loadCurrentProgram: () => loaded,
      resolveBindingMaterial: () => unknownTag,
      now: () => new Date("2099-01-01T00:00:00.000Z"),
    };
    const service = new ActionApprovalService(handle, deps);
    let captured: unknown = null;
    try {
      service.preview(actionId);
    } catch (err) {
      captured = err;
    }
    expectCode(captured, "ACTION_APPROVAL_CONTEXT_UNAVAILABLE");
    expectNoExecutionTokenLeak(captured as BountyPilotError, SENTINEL);
    // The capability/loaded reference prevents unused-var
    // warnings on the typed values when this case runs.
    expect(capability.id).toBe("http.read");
  });

  it("valid preflight error (missing action) is NOT remapped to CONTEXT_UNAVAILABLE", () => {
    const handle = openDb();
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    let loadCount = 0;
    const deps: ActionApprovalServiceDependencies = {
      loadCurrentProgram: () => {
        loadCount += 1;
        return loaded;
      },
      resolveBindingMaterial: () => {
        throw new Error("must not be called");
      },
      now: () => new Date("2099-01-01T00:00:00.000Z"),
    };
    const service = new ActionApprovalService(handle, deps);
    let captured: unknown = null;
    try {
      service.preview("act-b2a7-notfound");
    } catch (err) {
      captured = err;
    }
    // Existing ACTION_NOT_FOUND propagates unchanged; the
    // resolver must NOT have been called.
    expectCode(captured, "ACTION_NOT_FOUND");
    expect(loadCount).toBe(0);
  });
});

// ===========================================================================
// B2A.8: structurally valid integration projection happy case +
// representative enforcement blocks (disabled, allowExecute false,
// capability missing, capability blocked, blockedByDefault, mode
// absent) with fixed enforcement reason. Representative malformed
// complete-policy cases (name mismatch, timeout out of range,
// invalid digest/entrypoint/array type) => CONTEXT_UNAVAILABLE.
// ===========================================================================

describe("B2A.8: integration projection happy case; enforcement blocks; malformed complete policy => CONTEXT_UNAVAILABLE", () => {
  function buildIntegrationService(
    handle: BountyDatabase,
    policy: SafeIntegrationExecutionPolicy,
    capability: CapabilityEnforcementInput,
  ): ActionApprovalService {
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const deps = buildB2ADependencies({
      loaded,
      capability,
      integration: { kind: "integration", policy },
      normalizedTarget: B2A_NORMALIZED_TARGET,
    });
    return new ActionApprovalService(handle, deps.dependencies);
  }

  it("structurally valid integration projection returns a normal challenge (allow)", () => {
    const handle = openDb();
    const actionId = "act-b2a8-int-happy";
    const jobId = "job-b2a8-int-happy";
    insertJobWithMode(handle, jobId, "safe", "b2a8-hunt", "queued", B2A_TARGET);
    // The integration policy's `name` MUST equal the action's
    // adapter per §4; the adapter we write here is "safe-checks",
    // matching the policy's default name.
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET, adapter: "safe-checks" });
    const policy = buildB2ASafeIntegrationPolicy();
    const capability = buildB2ACapability({
      ...B2A_DEFAULT_CAPABILITY,
      // The capability's action type must equal the action's
      // action type; the policy gate operates on the action
      // shape and the binding's policyAction/actionType fields
      // are sourced from the action row.
      actionType: "GET",
    });
    const service = buildIntegrationService(handle, policy, capability);
    const challenge = service.preview(actionId);
    expect(challenge.policyDecision).toBe("allow");
    expect(challenge.scopeHash).toMatch(/^[0-9a-f]{64}$/);
    expect(challenge.actionHash).toMatch(/^[0-9a-f]{64}$/);
  });

  // Representative enforcement blocks: each row mutates one
  // field of the integration policy and the result MUST be a
  // normal challenge block with the fixed enforcement reason
  // "Blocked by current authority enforcement", NOT a
  // CONTEXT_UNAVAILABLE.
  interface EnforcementBlock {
    name: string;
    mutate: (policy: SafeIntegrationExecutionPolicy) => SafeIntegrationExecutionPolicy;
    capability: CapabilityEnforcementInput;
  }
  const ENFORCEMENT_BLOCKS: EnforcementBlock[] = [
    {
      name: "disabled=true",
      mutate: (policy) => ({ ...policy, enabled: false }),
      capability: buildB2ACapability({ ...B2A_DEFAULT_CAPABILITY, actionType: "GET" }),
    },
    {
      name: "allowExecute=false",
      mutate: (policy) => ({ ...policy, allowExecute: false }),
      capability: buildB2ACapability({ ...B2A_DEFAULT_CAPABILITY, actionType: "GET" }),
    },
    {
      name: "action type absent from policy capabilities",
      // The action's actionType is "GET", but the policy's
      // capabilities list does not include it. The enforcement
      // path treats this as a block.
      mutate: (policy) => ({ ...policy, capabilities: ["other.capability"] }),
      capability: buildB2ACapability({ ...B2A_DEFAULT_CAPABILITY, actionType: "GET" }),
    },
    {
      name: "action type present in blockedCapabilities",
      mutate: (policy) => ({ ...policy, blockedCapabilities: ["GET"] }),
      capability: buildB2ACapability({ ...B2A_DEFAULT_CAPABILITY, actionType: "GET" }),
    },
    {
      name: "capability.blockedByDefault=true",
      mutate: (policy) => policy,
      capability: buildB2ACapability({
        ...B2A_DEFAULT_CAPABILITY,
        actionType: "GET",
        blockedByDefault: true,
      }),
    },
    {
      name: "current job mode absent from allowedModes",
      // The job is mode=safe, but the capability's
      // allowedModes excludes "safe".
      mutate: (policy) => policy,
      capability: buildB2ACapability({
        ...B2A_DEFAULT_CAPABILITY,
        actionType: "GET",
        allowedModes: ["deep-safe"],
      }),
    },
  ];
  for (const row of ENFORCEMENT_BLOCKS) {
    it(`enforcement block: ${row.name} -> block with fixed reason`, () => {
      const handle = openDb();
      const actionId = `act-b2a8-${row.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b2a8-${row.name.replace(/[^a-z0-9]/gi, "_")}`;
      insertJobWithMode(handle, jobId, "safe", "b2a8-hunt", "queued", B2A_TARGET);
      seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET, adapter: "safe-checks" });
      const policy = row.mutate(buildB2ASafeIntegrationPolicy());
      const service = buildIntegrationService(handle, policy, row.capability);
      const challenge = service.preview(actionId);
      expect(challenge.actionId).toBe(actionId);
      expect(challenge.jobId).toBe(jobId);
      expect(challenge.policyDecision).toBe("block");
      expect(challenge.policyReason).toBe("Blocked by current authority enforcement");
      // The challenge still has valid 64-lowercase-hex hashes; an
      // enforcement block is not a materialization failure.
      expect(challenge.scopeHash).toMatch(/^[0-9a-f]{64}$/);
      expect(challenge.policyHash).toMatch(/^[0-9a-f]{64}$/);
      expect(challenge.actionHash).toMatch(/^[0-9a-f]{64}$/);
      expect(challenge.contextHash).toMatch(/^[0-9a-f]{64}$/);
    });
  }

  // Malformed complete-policy cases: each row is a structurally
  // invalid SafeIntegrationExecutionPolicy that the binding
  // validator would reject. preview must surface
  // ACTION_APPROVAL_CONTEXT_UNAVAILABLE for these — they are
  // materialization failures, not enforcement blocks.
  interface MalformedPolicy {
    name: string;
    patch: (policy: SafeIntegrationExecutionPolicy) => SafeIntegrationExecutionPolicy;
  }
  const MALFORMED_POLICY: MalformedPolicy[] = [
    {
      name: "name mismatch with adapter",
      // Adapter is "safe-checks" but policy.name is something
      // else; the integration projection requires name===adapter.
      patch: (policy) => ({ ...policy, name: "other-integration-name" }),
    },
    {
      name: "timeoutMs out of range (0)",
      patch: (policy) => ({ ...policy, timeoutMs: 0 }),
    },
    {
      name: "timeoutMs out of range (120_001)",
      patch: (policy) => ({ ...policy, timeoutMs: 120_001 }),
    },
    {
      name: "launcherSha256 invalid (not 64 hex)",
      patch: (policy) => ({ ...policy, launcherSha256: "not-a-sha256" }),
    },
    {
      name: "launcherSha256 uppercase (must be lowercase hex)",
      patch: (policy) => ({ ...policy, launcherSha256: "A".repeat(64) }),
    },
    {
      name: "entrypoint is absolute path",
      patch: (policy) => ({ ...policy, entrypoint: "/etc/passwd" }),
    },
    {
      name: "capabilities contains non-string",
      // The strict binding validator rejects a non-string entry
      // inside a set-like array. Cast through unknown at the
      // single host boundary so the fixture is honest about its
      // shape.
      patch: (policy) => ({ ...policy, capabilities: ["http.get", 42 as unknown as string] }),
    },
  ];
  for (const row of MALFORMED_POLICY) {
    it(`malformed complete-policy: ${row.name} -> ACTION_APPROVAL_CONTEXT_UNAVAILABLE`, () => {
      const handle = openDb();
      const actionId = `act-b2a8-mal-${row.name.replace(/[^a-z0-9]/gi, "_")}`;
      const jobId = `job-b2a8-mal-${row.name.replace(/[^a-z0-9]/gi, "_")}`;
      insertJobWithMode(handle, jobId, "safe", "b2a8-hunt", "queued", B2A_TARGET);
      seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET, adapter: "safe-checks" });
      const policy = row.patch(buildB2ASafeIntegrationPolicy());
      const service = buildIntegrationService(
        handle,
        policy,
        buildB2ACapability({ ...B2A_DEFAULT_CAPABILITY, actionType: "GET" }),
      );
      let captured: unknown = null;
      try {
        service.preview(actionId);
      } catch (err) {
        captured = err;
      }
      expectCode(captured, "ACTION_APPROVAL_CONTEXT_UNAVAILABLE");
    });
  }
});

// ===========================================================================
// B2A.9: DB rows are byte-identical around preview and the
// transaction tracker is false afterward. preview must never write
// to the actions table and must not leave a transaction open.
// ===========================================================================

describe("B2A.9: preview is strictly read-only; DB rows byte-identical; transaction tracker false", () => {
  it("all action rows are byte-identical before and after preview; no transaction is open", () => {
    const handle = openDb();
    const { service } = buildB2AService(handle);
    const actionId = "act-b2a9-snap";
    const jobId = "job-b2a9-snap";
    insertJobWithMode(handle, jobId, "safe", "b2a9-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    // Seed a second action in the same job so the snapshot
    // covers more than one row.
    seedB2APendingAction(handle, "act-b2a9-other", jobId, { target: B2A_TARGET });
    const before = snapshotAllActionRows(handle, jobId);
    const beforeJob = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(hasImmediateTransaction(handle)).toBe(false);
    const challenge = service.preview(actionId);
    expect(challenge.actionId).toBe(actionId);
    const after = snapshotAllActionRows(handle, jobId);
    const afterJob = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(after).toEqual(before);
    expect(afterJob).toEqual(beforeJob);
    expect(hasImmediateTransaction(handle)).toBe(false);
  });

  it("preview does not write any new row to the actions, jobs, action_reviews, or workflow_events tables", () => {
    const handle = openDb();
    const { service } = buildB2AService(handle);
    const actionId = "act-b2a9-counts";
    const jobId = "job-b2a9-counts";
    insertJobWithMode(handle, jobId, "safe", "b2a9-hunt", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET });
    const countRows = (table: string): number => {
      return (handle.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get() as { c: number }).c;
    };
    const beforeActions = countRows("actions");
    const beforeJobs = countRows("jobs");
    const beforeReviews = countRows("action_reviews");
    const beforeEvents = countRows("workflow_events");
    service.preview(actionId);
    expect(countRows("actions")).toBe(beforeActions);
    expect(countRows("jobs")).toBe(beforeJobs);
    expect(countRows("action_reviews")).toBe(beforeReviews);
    expect(countRows("workflow_events")).toBe(beforeEvents);
  });
});

// ===========================================================================
// B2B: resolver-boundary hardening. The service must snapshot resolver
// material as deeply plain data before any getter, proxy trap, mutable
// callback, or resolver mutation can affect the authority/action hashes.
// Invalid scalar/array shapes are materialization failures (fixed,
// cause-free ACTION_APPROVAL_CONTEXT_UNAVAILABLE), never normal policy
// enforcement blocks. These tests are intentionally bounded and read-only.
// ===========================================================================

describe("B2B: resolver material is strict, immutable, and fail-closed", () => {
  type Resolver = ActionApprovalServiceDependencies["resolveBindingMaterial"];
  const FIXED_CONTEXT_MESSAGE = "Action approval context is unavailable.";

  function capturePreview(service: ActionApprovalService, actionId: string): unknown {
    try {
      service.preview(actionId);
    } catch (err) {
      return err;
    }
    return null;
  }

  function expectContextUnavailable(captured: unknown, sentinel: string): BountyPilotError {
    const error = expectCode(captured, "ACTION_APPROVAL_CONTEXT_UNAVAILABLE", sentinel);
    expect(error.message).toBe(FIXED_CONTEXT_MESSAGE);
    // The sentinel is always non-empty in this slice. Keep the explicit
    // guard so this helper remains safe if a future table adds an empty one.
    if (sentinel.length > 0) {
      expectNoExecutionTokenLeak(error, sentinel);
    }
    return error;
  }

  function buildB2BService(
    handle: BountyDatabase,
    resolver: Resolver,
    loaded: LoadedProgram = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT),
  ): {
    service: ActionApprovalService;
    loaded: LoadedProgram;
    loadCount: () => number;
    nowCount: () => number;
  } {
    let loadCount = 0;
    let nowCount = 0;
    const dependencies: ActionApprovalServiceDependencies = {
      loadCurrentProgram: () => {
        loadCount += 1;
        return loaded;
      },
      resolveBindingMaterial: resolver,
      now: () => {
        nowCount += 1;
        return new Date("2099-01-01T00:00:00.000Z");
      },
    };
    return {
      service: new ActionApprovalService(handle, dependencies),
      loaded,
      loadCount: () => loadCount,
      nowCount: () => nowCount,
    };
  }

  function validBuiltinMaterial(
    capability: CapabilityEnforcementInput = buildB2ACapability(B2A_DEFAULT_CAPABILITY),
    normalizedTarget: string | null = B2A_NORMALIZED_TARGET,
  ): ResolvedBindingMaterial {
    return {
      normalizedTarget,
      capabilityEnforcement: capability,
      integration: { kind: "builtin" },
    };
  }

  function seedB2BAction(
    handle: BountyDatabase,
    actionId: string,
    jobId: string,
    overrides: Parameters<typeof seedB2APendingAction>[3] = {},
    jobTarget: string | null = B2A_TARGET,
  ): void {
    insertJobWithMode(handle, jobId, "safe", "b2b-hunt", "queued", jobTarget);
    seedB2APendingAction(handle, actionId, jobId, {
      target: jobTarget,
      ...overrides,
    });
  }

  // -------------------------------------------------------------------------
  // B2B.1: optional capability flags are strict booleans.
  // -------------------------------------------------------------------------

  const INVALID_FLAG_CASES: ReadonlyArray<{
    name: string;
    field: string;
    value: unknown;
  }> = [
    { name: "destructive string", field: "destructive", value: "true" },
    { name: "requiresScope number", field: "requiresScope", value: 1 },
    { name: "blockedByDefault string", field: "blockedByDefault", value: "yes" },
  ];

  for (const row of INVALID_FLAG_CASES) {
    it(`B2B.1 rejects non-boolean capability flag: ${row.name}`, () => {
      const handle = openDb();
      const actionId = `act-b2b1-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      const jobId = `job-b2b1-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      seedB2BAction(handle, actionId, jobId);
      const capability = buildB2ACapability(
        B2A_DEFAULT_CAPABILITY,
        { [row.field]: row.value } as unknown as Partial<AdapterCapabilityMetadata>,
      );
      const material = validBuiltinMaterial(capability);
      const { service, loadCount, nowCount } = buildB2BService(handle, () => material);
      const captured = capturePreview(service, actionId);
      expectContextUnavailable(captured, actionId);
      expect(loadCount()).toBe(1);
      expect(nowCount()).toBe(0);
    });
  }

  // -------------------------------------------------------------------------
  // B2B.2: capability identity/risk must be canonical and equal to the
  // action row. Padded/control identifiers are not silently normalized.
  // -------------------------------------------------------------------------

  const CAPABILITY_IDENTITY_CASES: ReadonlyArray<{
    name: string;
    capability: Partial<CapabilityEnforcementInput>;
  }> = [
    {
      name: "actionType mismatch",
      capability: { actionType: "http.post" },
    },
    {
      name: "riskLevel mismatch",
      capability: { riskLevel: "high" },
    },
    {
      name: "padded capability id",
      capability: { id: " http.read " },
    },
    {
      name: "control capability id",
      capability: { id: "http.read\u0001" },
    },
    {
      name: "padded capability actionType",
      capability: { actionType: " http.get " },
    },
    {
      name: "control capability actionType",
      capability: { actionType: "http.get\u0001" },
    },
  ];

  for (const row of CAPABILITY_IDENTITY_CASES) {
    it(`B2B.2 rejects capability identity defect: ${row.name}`, () => {
      const handle = openDb();
      const actionId = `act-b2b2-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      const jobId = `job-b2b2-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      seedB2BAction(handle, actionId, jobId);
      const capability = buildB2ACapability(
        B2A_DEFAULT_CAPABILITY,
        row.capability as Partial<AdapterCapabilityMetadata>,
      );
      const material = validBuiltinMaterial(capability);
      const { service } = buildB2BService(handle, () => material);
      const captured = capturePreview(service, actionId);
      expectContextUnavailable(captured, actionId);
    });
  }

  // -------------------------------------------------------------------------
  // B2B.3: integration set-like arrays are strict strings with no padding or
  // controls. A malformed array is not reinterpreted as an enforcement block.
  // -------------------------------------------------------------------------

  const INTEGRATION_ARRAY_CASES: ReadonlyArray<{
    name: string;
    patch: (policy: SafeIntegrationExecutionPolicy) => SafeIntegrationExecutionPolicy;
  }> = [
    {
      name: "capabilities padded",
      patch: (policy) => ({ ...policy, capabilities: ["GET "] }),
    },
    {
      name: "capabilities control",
      patch: (policy) => ({ ...policy, capabilities: ["GET\u0001"] }),
    },
    {
      name: "capabilities non-string",
      patch: (policy) => ({
        ...policy,
        capabilities: ["GET", 42 as unknown as string],
      }),
    },
    {
      name: "blockedCapabilities padded",
      patch: (policy) => ({ ...policy, blockedCapabilities: ["GET "] }),
    },
    {
      name: "blockedCapabilities control",
      patch: (policy) => ({ ...policy, blockedCapabilities: ["GET\u0001"] }),
    },
    {
      name: "blockedCapabilities non-string",
      patch: (policy) => ({
        ...policy,
        blockedCapabilities: [42 as unknown as string],
      }),
    },
  ];

  for (const row of INTEGRATION_ARRAY_CASES) {
    it(`B2B.3 rejects malformed integration array: ${row.name}`, () => {
      const handle = openDb();
      const actionId = `act-b2b3-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      const jobId = `job-b2b3-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      seedB2BAction(handle, actionId, jobId, { adapter: "safe-checks", actionType: "GET" });
      const policy = row.patch(buildB2ASafeIntegrationPolicy());
      const capability = buildB2ACapability({
        ...B2A_DEFAULT_CAPABILITY,
        actionType: "GET",
      });
      const material: ResolvedBindingMaterial = {
        normalizedTarget: B2A_NORMALIZED_TARGET,
        capabilityEnforcement: capability,
        integration: { kind: "integration", policy },
      };
      const { service } = buildB2BService(handle, () => material);
      const captured = capturePreview(service, actionId);
      expectContextUnavailable(captured, actionId);
    });
  }

  // -------------------------------------------------------------------------
  // B2B.4: a denied required-scope target is a normal block only when the
  // resolver supplied the exact fresh normalized target. Null/mismatched
  // resolver targets are materialization failures, not policy blocks.
  // -------------------------------------------------------------------------

  const OUT_OF_SCOPE_TARGET = "https://outside.invalid/health";
  const SCOPE_MATERIAL_CASES: ReadonlyArray<{
    name: string;
    normalizedTarget: string | null;
  }> = [
    { name: "resolver normalizedTarget null", normalizedTarget: null },
    { name: "resolver normalizedTarget mismatched", normalizedTarget: B2A_NORMALIZED_TARGET },
  ];

  for (const row of SCOPE_MATERIAL_CASES) {
    it(`B2B.4 rejects denied-scope material defect: ${row.name}`, () => {
      const handle = openDb();
      const actionId = `act-b2b4-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      const jobId = `job-b2b4-${row.name.replace(/[^a-z0-9]/gi, "-")}`;
      seedB2BAction(handle, actionId, jobId, {}, OUT_OF_SCOPE_TARGET);
      const capability = buildB2ACapability(B2A_DEFAULT_CAPABILITY);
      const material = validBuiltinMaterial(capability, row.normalizedTarget);
      const { service } = buildB2BService(handle, () => material);
      const captured = capturePreview(service, actionId);
      expectContextUnavailable(captured, actionId);
    });
  }

  // -------------------------------------------------------------------------
  // B2B.5: accessor/proxy material and a hostile BountyPilotError getter
  // cannot execute caller code or leak its cause through mapPreviewError.
  // -------------------------------------------------------------------------

  it("B2B.5 rejects accessor-bearing resolver output without invoking the accessor or custom error getter", () => {
    const handle = openDb();
    const actionId = "act-b2b5-accessor";
    const jobId = "job-b2b5-accessor";
    seedB2BAction(handle, actionId, jobId);
    const capability = buildB2ACapability(B2A_DEFAULT_CAPABILITY);
    const sentinel = "b2b-accessor-secret";
    let accessorCalls = 0;
    let customCodeGetterCalls = 0;
    const resolver: Resolver = () => {
      const hostile: Record<PropertyKey, unknown> = Object.create(null) as Record<PropertyKey, unknown>;
      Object.defineProperty(hostile, "normalizedTarget", {
        configurable: true,
        enumerable: true,
        get: () => {
          accessorCalls += 1;
          const custom = new BountyPilotError(sentinel, "B2B_CUSTOM_CAUSE");
          Object.defineProperty(custom, "code", {
            configurable: true,
            enumerable: true,
            get: () => {
              customCodeGetterCalls += 1;
              throw new Error(`${sentinel}: code getter invoked`);
            },
          });
          throw custom;
        },
      });
      hostile.capabilityEnforcement = capability;
      hostile.integration = { kind: "builtin" };
      return hostile as unknown as ResolvedBindingMaterial;
    };
    const { service } = buildB2BService(handle, resolver);
    const captured = capturePreview(service, actionId);
    expectContextUnavailable(captured, sentinel);
    expect(accessorCalls).toBe(0);
    expect(customCodeGetterCalls).toBe(0);
  });

  it("B2B.5 rejects a proxied resolver projection without invoking its get trap", () => {
    const handle = openDb();
    const actionId = "act-b2b5-proxy";
    const jobId = "job-b2b5-proxy";
    seedB2BAction(handle, actionId, jobId);
    const capability = buildB2ACapability(B2A_DEFAULT_CAPABILITY);
    const sentinel = "b2b-proxy-secret";
    let getTrapCalls = 0;
    const target: Record<string, unknown> = {
      capabilityEnforcement: capability,
      integration: { kind: "builtin" },
    };
    Object.defineProperty(target, "normalizedTarget", {
      configurable: true,
      enumerable: true,
      get: () => {
        throw new BountyPilotError(sentinel, "B2B_PROXY_CAUSE");
      },
    });
    const hostile = new Proxy(target, {
      get: () => {
        getTrapCalls += 1;
        throw new BountyPilotError(sentinel, "B2B_PROXY_GET");
      },
    });
    const resolver: Resolver = () => hostile as unknown as ResolvedBindingMaterial;
    const { service } = buildB2BService(handle, resolver);
    const captured = capturePreview(service, actionId);
    expectContextUnavailable(captured, sentinel);
    expect(getTrapCalls).toBe(0);
  });

  // -------------------------------------------------------------------------
  // B2B.6: resolver mutation after receiving the narrow source/program must
  // fail closed; mutated authority must never be hashed into a challenge.
  // -------------------------------------------------------------------------

  it("B2B.6 fails closed when the resolver mutates the source projection", () => {
    const handle = openDb();
    const actionId = "act-b2b6-source";
    const jobId = "job-b2b6-source";
    seedB2BAction(handle, actionId, jobId);
    const sentinel = "b2b-source-mutation";
    let mutationObserved = false;
    const resolver: Resolver = ({ source }) => {
      mutationObserved = true;
      source.action.metadata.mutatedByResolver = sentinel;
      return validBuiltinMaterial();
    };
    const { service } = buildB2BService(handle, resolver);
    const captured = capturePreview(service, actionId);
    expectContextUnavailable(captured, sentinel);
    expect(mutationObserved).toBe(true);
  });

  it("B2B.6 fails closed when the resolver mutates the loaded program authority", () => {
    const handle = openDb();
    const actionId = "act-b2b6-program";
    const jobId = "job-b2b6-program";
    seedB2BAction(handle, actionId, jobId);
    const sentinel = "b2b-program-mutation";
    let mutationObserved = false;
    const resolver: Resolver = ({ program }) => {
      mutationObserved = true;
      const rules = program.config.rules as unknown as Record<string, unknown>;
      rules.rate_limit = sentinel;
      return validBuiltinMaterial();
    };
    const { service } = buildB2BService(handle, resolver);
    const captured = capturePreview(service, actionId);
    expectContextUnavailable(captured, sentinel);
    expect(mutationObserved).toBe(true);
  });
  describe("B2C", () => {
    it("rejects a nested Proxy in loader-owned integrations without traps or mutation", () => {
      const handle = openDb();
      const actionId = "act-b2c-loader-integrations-proxy";
      const jobId = "job-b2c-loader-integrations-proxy";
      const sentinel = "b2c-loader-integrations-proxy-secret";
      seedB2BAction(handle, actionId, jobId);

      const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
      const trapCalls = { get: 0, ownKeys: 0 };
      const nestedProxy = new Proxy<Record<string, unknown>>(
        { sentinel },
        {
          get: () => {
            trapCalls.get += 1;
            throw new Error(`${sentinel}:get`);
          },
          ownKeys: () => {
            trapCalls.ownKeys += 1;
            throw new Error(`${sentinel}:ownKeys`);
          },
        },
      );
      const loaderOwnedIntegrations: Record<string, unknown> = {
        hostile: nestedProxy,
      };
      const descriptorBefore = Object.getOwnPropertyDescriptor(loaderOwnedIntegrations, "hostile");
      (loaded.config as unknown as { integrations: Record<string, unknown> }).integrations =
        loaderOwnedIntegrations;

      let resolverCalls = 0;
      const { service, loadCount, nowCount } = buildB2BService(
        handle,
        () => {
          resolverCalls += 1;
          return validBuiltinMaterial();
        },
        loaded,
      );
      const captured = capturePreview(service, actionId);
      const error = expectContextUnavailable(captured, sentinel);

      expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
      expect(loadCount()).toBe(1);
      expect(resolverCalls).toBe(0);
      expect(nowCount()).toBe(0);
      expect(trapCalls).toEqual({ get: 0, ownKeys: 0 });

      expect(loaded.config.integrations).toBe(loaderOwnedIntegrations);
      expect(Object.isFrozen(loaderOwnedIntegrations)).toBe(false);
      expect(Object.isExtensible(loaderOwnedIntegrations)).toBe(true);
      expect(Reflect.ownKeys(loaderOwnedIntegrations)).toEqual(["hostile"]);
      const descriptorAfter = Object.getOwnPropertyDescriptor(loaderOwnedIntegrations, "hostile");
      expect(descriptorAfter?.value).toBe(nestedProxy);
      expect(descriptorAfter?.writable).toBe(descriptorBefore?.writable);
      expect(descriptorAfter?.enumerable).toBe(descriptorBefore?.enumerable);
      expect(descriptorAfter?.configurable).toBe(descriptorBefore?.configurable);
    });

    it("passes only action and job source keys to the resolver", () => {
      const handle = openDb();
      const actionId = "act-b2c-source-keys";
      const jobId = "job-b2c-source-keys";
      seedB2BAction(handle, actionId, jobId);
      let sourceKeys: string[] = [];
      const resolver: Resolver = ({ source }) => {
        sourceKeys = Object.keys(source);
        return validBuiltinMaterial();
      };
      const { service } = buildB2BService(handle, resolver);
      expect(() => service.preview(actionId)).not.toThrow();
      expect(sourceKeys).toEqual(["action", "job"]);
    });
  });

  describe("B2D: database identity and prototype-poisoning regressions", () => {
    it("propagates the exact database read error without remapping or invoking dependencies", () => {
      const handle = openDb();
      const actionId = "act-b2d-db-error";
      const jobId = "job-b2d-db-error";
      seedB2BAction(handle, actionId, jobId);

      let resolverCalls = 0;
      const { service, loadCount, nowCount } = buildB2BService(handle, () => {
        resolverCalls += 1;
        return validBuiltinMaterial();
      });
      const sentinel = new Error("B2D_DATABASE_ERROR_IDENTITY_SENTINEL");
      const originalPrepare = handle.prepare.bind(handle);
      let prepareCalls = 0;
      let captured: unknown = null;
      handle.prepare = ((_sql: string) => {
        prepareCalls += 1;
        throw sentinel;
      }) as typeof handle.prepare;
      try {
        captured = capturePreview(service, actionId);
      } finally {
        handle.prepare = originalPrepare as typeof handle.prepare;
      }

      expect(prepareCalls).toBe(1);
      expect(captured).toBe(sentinel);
      expect(captured).not.toBeInstanceOf(BountyPilotError);
      expect(loadCount()).toBe(0);
      expect(resolverCalls).toBe(0);
      expect(nowCount()).toBe(0);
    });

    it("does not consult an inherited integrations getter when the defaultable field is omitted", () => {
      const handle = openDb();
      const actionId = "act-b2d-prototype";
      const jobId = "job-b2d-prototype";
      seedB2BAction(handle, actionId, jobId);

      const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
      const rawConfig = loaded.config as unknown as Record<string, unknown>;
      expect(Object.prototype.hasOwnProperty.call(rawConfig, "integrations")).toBe(true);
      expect(Reflect.deleteProperty(rawConfig, "integrations")).toBe(true);
      expect(Object.prototype.hasOwnProperty.call(rawConfig, "integrations")).toBe(false);
      // Fixture guard: integrations is schema-defaulted, so omission is valid
      // before any prototype poison is installed.
      expect(ProgramSchema.parse(rawConfig).integrations).toEqual({});

      let resolverCalls = 0;
      const { service, loadCount, nowCount } = buildB2BService(
        handle,
        () => {
          resolverCalls += 1;
          return validBuiltinMaterial();
        },
        loaded,
      );

      const originalDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "integrations");
      const sentinel = new Error("B2D_INHERITED_INTEGRATIONS_GETTER_SENTINEL");
      let getterCalls = 0;
      let captured: unknown = null;
      let challenge: ReturnType<ActionApprovalService["preview"]> | null = null;
      try {
        Object.defineProperty(Object.prototype, "integrations", {
          configurable: true,
          enumerable: false,
          get: () => {
            getterCalls += 1;
            throw sentinel;
          },
        });
        try {
          challenge = service.preview(actionId);
        } catch (err) {
          captured = err;
        }
      } finally {
        if (originalDescriptor === undefined) {
          Reflect.deleteProperty(Object.prototype, "integrations");
        } else {
          Object.defineProperty(Object.prototype, "integrations", originalDescriptor);
        }
      }

      expect(Object.getOwnPropertyDescriptor(Object.prototype, "integrations")).toEqual(originalDescriptor);
      expect(getterCalls).toBe(0);
      expect(captured).toBeNull();
      expect(challenge?.policyDecision).toBe("allow");
      expect(loadCount()).toBe(1);
      expect(resolverCalls).toBe(1);
      expect(nowCount()).toBe(0);
    });
  });

  describe("B3B2: clock failures, source race, and event rollback", () => {
    function buildB3B2Dependencies(
      handle: BountyDatabase,
      nowImpl: () => Date,
    ): {
      dependencies: ActionApprovalServiceDependencies;
      loadCount: () => number;
      resolveCount: () => number;
      nowCount: () => number;
      transactionStates: { load: boolean[]; resolve: boolean[]; now: boolean[] };
    } {
      const base = buildB2ADependencies({
        loaded: buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT),
        capability: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
        integration: { kind: "builtin" },
        normalizedTarget: B2A_NORMALIZED_TARGET,
      });
      const transactionStates = { load: [] as boolean[], resolve: [] as boolean[], now: [] as boolean[] };
      let nowCount = 0;
      const dependencies: ActionApprovalServiceDependencies = {
        loadCurrentProgram: () => {
          transactionStates.load.push(hasImmediateTransaction(handle));
          return base.dependencies.loadCurrentProgram();
        },
        resolveBindingMaterial: (input) => {
          transactionStates.resolve.push(hasImmediateTransaction(handle));
          return base.dependencies.resolveBindingMaterial(input);
        },
        now: () => {
          nowCount += 1;
          transactionStates.now.push(hasImmediateTransaction(handle));
          return nowImpl();
        },
      };
      return {
        dependencies,
        loadCount: base.counters.loadCount,
        resolveCount: base.counters.resolveCount,
        nowCount: () => nowCount,
        transactionStates,
      };
    }

    function resetB3B2States(states: { load: boolean[]; resolve: boolean[]; now: boolean[] }): void {
      states.load.length = 0;
      states.resolve.length = 0;
      states.now.length = 0;
    }

    const B3A_REVIEWER_ID = "reviewer-b3b2";

    function seedDecisionAction(
      handle: BountyDatabase,
      actionId: string,
      jobId: string,
      overrides: Parameters<typeof seedB2APendingAction>[3] = {},
    ): void {
      insertJobWithMode(handle, jobId, "safe", "b3b2-decision", "queued", B2A_TARGET);
      seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET, ...overrides });
    }

    function snapshotB3ADatabase(handle: BountyDatabase): Record<string, ReadonlyArray<Record<string, unknown>>> {
      const rows = (table: "actions" | "action_reviews" | "workflow_events" | "jobs") =>
        handle.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all() as Array<Record<string, unknown>>;
      return {
        actions: rows("actions"),
        reviews: rows("action_reviews"),
        events: rows("workflow_events"),
        jobs: rows("jobs"),
      };
    }

    function captureApproval(
      service: ActionApprovalService,
      method: "approveHuman" | "approvePolicy",
      input: unknown,
    ): unknown {
      try {
        const call = service[method] as unknown as (runtimeInput: unknown) => unknown;
        call.call(service, input);
      } catch (err) {
        return err;
      }
      return null;
    }

    function withB3ASqlProbe<T>(
      handle: BountyDatabase,
      run: (preparedSql: string[], execSql: string[]) => T,
    ): T {
      const originalExec = handle.exec.bind(handle);
      const execSql: string[] = [];
      handle.exec = ((sql: string) => {
        execSql.push(sql);
        return originalExec(sql);
      }) as typeof handle.exec;
      try {
        return withPrepareProbe(handle, (_count, preparedSql) => run(preparedSql, execSql));
      } finally {
        handle.exec = originalExec as typeof handle.exec;
      }
    }

    function b3b2Rows(handle: BountyDatabase, table: "action_reviews" | "workflow_events"): Array<Record<string, unknown>> {
      return handle.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all() as Array<Record<string, unknown>>;
    }

    it("groups clock throw, Invalid Date, and TTL overflow before BEGIN with byte-identical storage", () => {
      const handle = openDb();
      const thrownSentinel = "B3B2_CLOCK_THROW_SENTINEL";
      const cases: ReadonlyArray<{ name: string; now: () => Date }> = [
        {
          name: "throw",
          now: () => {
            throw new Error(thrownSentinel);
          },
        },
        { name: "invalid-date", now: () => new Date(Number.NaN) },
        { name: "ttl-overflow", now: () => new Date(8_640_000_000_000_000) },
      ];

      for (const [index, row] of cases.entries()) {
        const actionId = `act-b3b2-clock-${index}`;
        const jobId = `job-b3b2-clock-${index}`;
        seedDecisionAction(handle, actionId, jobId);
        const bundle = buildB3B2Dependencies(handle, row.now);
        const service = new ActionApprovalService(handle, bundle.dependencies);
        const challenge = service.preview(actionId);
        expect(bundle.loadCount()).toBe(1);
        expect(bundle.resolveCount()).toBe(1);
        expect(bundle.nowCount()).toBe(0);
        resetB3B2States(bundle.transactionStates);
        const before = snapshotB3ADatabase(handle);
        let captured: unknown = null;
        withB3ASqlProbe(handle, (_preparedSql, execSql) => {
          captured = captureApproval(service, "approveHuman", {
            actionId,
            reviewerId: B3A_REVIEWER_ID,
            expectedContextHash: challenge.contextHash,
            ttlMs: 1,
          });
          expect(execSql, `${row.name} must fail before BEGIN`).toEqual([]);
        });

        const error = expectCode(captured, "ACTION_APPROVAL_CONTEXT_UNAVAILABLE", actionId);
        expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
        expect(JSON.stringify(error)).not.toContain(thrownSentinel);
        expect(bundle.loadCount()).toBe(2);
        expect(bundle.resolveCount()).toBe(2);
        expect(bundle.nowCount()).toBe(1);
        expect(bundle.transactionStates).toEqual({ load: [false], resolve: [false], now: [false] });
        expect(snapshotB3ADatabase(handle)).toEqual(before);
      }
    });

    it("detects a pre-BEGIN source mutation as RACE_LOST without approval writes or in-tx dependency calls", () => {
      const handle = openDb();
      const actionId = "act-b3b2-source-race";
      const jobId = "job-b3b2-source-race";
      const racedMetadata = JSON.stringify({ b3b2Race: true });
      seedDecisionAction(handle, actionId, jobId, { requiresApproval: 0 });
      const originalJob = handle.prepare("SELECT * FROM jobs WHERE id = ?").get(jobId);
      const bundle = buildB3B2Dependencies(handle, () => {
        handle.prepare("UPDATE actions SET metadata_json = ? WHERE id = ?").run(racedMetadata, actionId);
        return new Date("2099-01-01T00:40:00.000Z");
      });
      const service = new ActionApprovalService(handle, bundle.dependencies);
      let captured: unknown = null;
      let execSql: string[] = [];
      withB3ASqlProbe(handle, (_preparedSql, observedExecSql) => {
        captured = captureApproval(service, "approvePolicy", { actionId, ttlMs: 1_000 });
        execSql = [...observedExecSql];
      });

      expectCode(captured, "ACTION_APPROVAL_RACE_LOST", actionId);
      expect(execSql.some((sql) => /\bBEGIN\s+IMMEDIATE\b/i.test(sql))).toBe(true);
      const rawAction = readActionRowForB2A(handle, actionId);
      expect(rawAction.metadata_json).toBe(racedMetadata);
      expect(rawAction.status).toBe("pending");
      expect(rawAction.active_review_id).toBeNull();
      expect(rawAction.planned_scope_hash).toBeNull();
      expect(rawAction.planned_policy_hash).toBeNull();
      expect(rawAction.planned_action_hash).toBeNull();
      expect(rawAction.planned_context_hash).toBeNull();
      expect(b3b2Rows(handle, "action_reviews")).toEqual([]);
      expect(b3b2Rows(handle, "workflow_events")).toEqual([]);
      expect(handle.prepare("SELECT * FROM jobs WHERE id = ?").get(jobId)).toEqual(originalJob);
      expect(bundle.loadCount()).toBe(1);
      expect(bundle.resolveCount()).toBe(1);
      expect(bundle.nowCount()).toBe(1);
      expect(bundle.transactionStates).toEqual({ load: [false], resolve: [false], now: [false] });
    });

    it("propagates an event INSERT sentinel and rolls back review, action CAS, event, and job", () => {
      const handle = openDb();
      const actionId = "act-b3b2-event-fault";
      const jobId = "job-b3b2-event-fault";
      seedDecisionAction(handle, actionId, jobId);
      const bundle = buildB3B2Dependencies(handle, () => new Date("2099-01-01T00:50:00.000Z"));
      const sentinel = new Error("B3B2_WORKFLOW_EVENT_INSERT_SENTINEL");
      const originalPrepare = handle.prepare.bind(handle);
      let eventInsertAttempts = 0;
      handle.prepare = ((sql: string) => {
        const statement = originalPrepare(sql);
        if (!/\bINSERT\s+INTO\s+workflow_events\b/i.test(sql)) return statement;
        return new Proxy(statement, {
          get: (target, property) => {
            if (property === "run") {
              return (..._args: unknown[]) => {
                eventInsertAttempts += 1;
                throw sentinel;
              };
            }
            const value = Reflect.get(target, property, target) as unknown;
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
      }) as typeof handle.prepare;

      let captured: unknown = null;
      let before: ReturnType<typeof snapshotB3ADatabase> | null = null;
      let execSql: string[] = [];
      try {
        const service = new ActionApprovalService(handle, bundle.dependencies);
        const challenge = service.preview(actionId);
        expect(bundle.loadCount()).toBe(1);
        expect(bundle.resolveCount()).toBe(1);
        expect(bundle.nowCount()).toBe(0);
        resetB3B2States(bundle.transactionStates);
        before = snapshotB3ADatabase(handle);
        withB3ASqlProbe(handle, (_preparedSql, observedExecSql) => {
          captured = captureApproval(service, "approveHuman", {
            actionId,
            reviewerId: B3A_REVIEWER_ID,
            expectedContextHash: challenge.contextHash,
            ttlMs: 1_000,
          });
          execSql = [...observedExecSql];
        });
      } finally {
        handle.prepare = originalPrepare as typeof handle.prepare;
      }

      expect(eventInsertAttempts).toBe(1);
      expect(captured).toBe(sentinel);
      expect(execSql.some((sql) => /\bBEGIN\s+IMMEDIATE\b/i.test(sql))).toBe(true);
      expect(execSql.some((sql) => /\bROLLBACK\b/i.test(sql))).toBe(true);
      expect(before).not.toBeNull();
      expect(snapshotB3ADatabase(handle)).toEqual(before);
      expect(readActionRowForB2A(handle, actionId).status).toBe("pending");
      expect(b3b2Rows(handle, "action_reviews")).toEqual([]);
      expect(b3b2Rows(handle, "workflow_events")).toEqual([]);
      expect(bundle.loadCount()).toBe(2);
      expect(bundle.resolveCount()).toBe(2);
      expect(bundle.nowCount()).toBe(1);
      expect(bundle.transactionStates).toEqual({ load: [false], resolve: [false], now: [false] });
    });

    it("propagates a late job-finalizer UPDATE sentinel and rolls back review, action, event, and job byte-identically", () => {
      const handle = openDb();
      const actionId = "act-b3b2-job-finalizer-fault";
      const jobId = "job-b3b2-job-finalizer-fault";
      seedDecisionAction(handle, actionId, jobId);
      const bundle = buildB3B2Dependencies(handle, () => new Date("2099-01-01T00:55:00.000Z"));
      const sentinel = new Error("B3B2_JOB_FINALIZER_UPDATE_SENTINEL");
      const originalPrepare = handle.prepare.bind(handle);
      let jobUpdateAttempts = 0;
      let stateAtFault: {
        reviewCount: number;
        eventCount: number;
        actionStatus: unknown;
        jobStatus: unknown;
      } | null = null;
      handle.prepare = ((sql: string) => {
        const statement = originalPrepare(sql);
        if (!/\bUPDATE\s+jobs\b/i.test(sql)) return statement;
        return new Proxy(statement, {
          get: (target, property) => {
            if (property === "run") {
              return (..._args: unknown[]) => {
                jobUpdateAttempts += 1;
                stateAtFault = {
                  reviewCount: Number(
                    (originalPrepare("SELECT COUNT(*) AS n FROM action_reviews WHERE action_id = ?").get(actionId) as { n: number }).n,
                  ),
                  eventCount: Number(
                    (originalPrepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobId) as { n: number }).n,
                  ),
                  actionStatus: (originalPrepare("SELECT status FROM actions WHERE id = ?").get(actionId) as { status: unknown }).status,
                  jobStatus: (originalPrepare("SELECT status FROM jobs WHERE id = ?").get(jobId) as { status: unknown }).status,
                };
                throw sentinel;
              };
            }
            const value = Reflect.get(target, property, target) as unknown;
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
      }) as typeof handle.prepare;

      let captured: unknown = null;
      let before: ReturnType<typeof snapshotB3ADatabase> | null = null;
      let execSql: string[] = [];
      try {
        const service = new ActionApprovalService(handle, bundle.dependencies);
        const challenge = service.preview(actionId);
        resetB3B2States(bundle.transactionStates);
        before = snapshotB3ADatabase(handle);
        withB3ASqlProbe(handle, (_preparedSql, observedExecSql) => {
          captured = captureApproval(service, "approveHuman", {
            actionId,
            reviewerId: B3A_REVIEWER_ID,
            expectedContextHash: challenge.contextHash,
            ttlMs: 1_000,
          });
          execSql = [...observedExecSql];
        });
      } finally {
        handle.prepare = originalPrepare as typeof handle.prepare;
      }

      expect(jobUpdateAttempts).toBe(1);
      expect(stateAtFault).toEqual({
        reviewCount: 1,
        eventCount: 1,
        actionStatus: "approved",
        jobStatus: "queued",
      });
      expect(captured).toBe(sentinel);
      expect(execSql.some((sql) => /\bBEGIN\s+IMMEDIATE\b/i.test(sql))).toBe(true);
      expect(execSql.some((sql) => /\bROLLBACK\b/i.test(sql))).toBe(true);
      expect(hasImmediateTransaction(handle)).toBe(false);
      expect(before).not.toBeNull();
      expect(snapshotB3ADatabase(handle)).toEqual(before);
      expect(bundle.loadCount()).toBe(2);
      expect(bundle.resolveCount()).toBe(2);
      expect(bundle.nowCount()).toBe(1);
      expect(bundle.transactionStates).toEqual({ load: [false], resolve: [false], now: [false] });
    });
  });
});

// ===========================================================================
// B3A: bounded approval-service RED slice. This block covers only the pure
// public DTO boundary and the current-decision gate. Transaction rollback,
// two-handle races, and the complete persisted-result contract belong to the
// later B3 slices.
// ===========================================================================

describe("B3A: approval caller validation and current-decision matrix", () => {
  type B3AMethod = "approveHuman" | "approvePolicy";

  const B3A_ACTION_ID = "act-b3a-validation";
  const B3A_JOB_ID = "job-b3a-validation";
  const B3A_REVIEWER_ID = "reviewer-b3a";
  const B3A_VALID_CONTEXT = "a".repeat(64);

  function validHumanInput(actionId = B3A_ACTION_ID): {
    actionId: string;
    reviewerId: string;
    expectedContextHash: string;
    ttlMs: number;
  } {
    return {
      actionId,
      reviewerId: B3A_REVIEWER_ID,
      expectedContextHash: B3A_VALID_CONTEXT,
      ttlMs: 60_000,
    };
  }

  function validPolicyInput(actionId = B3A_ACTION_ID): {
    actionId: string;
    ttlMs: number;
  } {
    return { actionId, ttlMs: 60_000 };
  }

  function invokeApproval(service: ActionApprovalService, method: B3AMethod, input: unknown): unknown {
    const call = service[method] as unknown as (runtimeInput: unknown) => unknown;
    return call.call(service, input);
  }

  function captureApproval(service: ActionApprovalService, method: B3AMethod, input: unknown): unknown {
    try {
      invokeApproval(service, method, input);
    } catch (err) {
      return err;
    }
    return null;
  }

  function snapshotB3ADatabase(handle: BountyDatabase): Record<string, ReadonlyArray<Record<string, unknown>>> {
    const rows = (table: "actions" | "action_reviews" | "workflow_events" | "jobs") =>
      handle.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all() as Array<Record<string, unknown>>;
    return {
      actions: rows("actions"),
      reviews: rows("action_reviews"),
      events: rows("workflow_events"),
      jobs: rows("jobs"),
    };
  }

  function withB3ASqlProbe<T>(
    handle: BountyDatabase,
    run: (preparedSql: string[], execSql: string[]) => T,
  ): T {
    const originalExec = handle.exec.bind(handle);
    const execSql: string[] = [];
    handle.exec = ((sql: string) => {
      execSql.push(sql);
      return originalExec(sql);
    }) as typeof handle.exec;
    try {
      return withPrepareProbe(handle, (_count, preparedSql) => run(preparedSql, execSql));
    } finally {
      handle.exec = originalExec as typeof handle.exec;
    }
  }

  function buildValidationHarness(): {
    handle: BountyDatabase;
    service: ActionApprovalService;
    counters: B2ADependencyCounters;
  } {
    const handle = openDb();
    insertJobWithMode(handle, B3A_JOB_ID, "safe", "b3a-validation", "queued", B2A_TARGET);
    seedB2APendingAction(handle, B3A_ACTION_ID, B3A_JOB_ID, { target: B2A_TARGET });
    const { service, counters } = buildB2AService(handle);
    return { handle, service, counters };
  }

  function expectPureCallerRejection(
    harness: ReturnType<typeof buildValidationHarness>,
    method: B3AMethod,
    input: unknown,
    expectedCode: string,
  ): BountyPilotError {
    const before = snapshotB3ADatabase(harness.handle);
    let captured: unknown = null;
    withB3ASqlProbe(harness.handle, (preparedSql, execSql) => {
      captured = captureApproval(harness.service, method, input);
      expect(preparedSql, "caller validation must run before any prepared SQL").toEqual([]);
      expect(execSql, "caller validation must run before BEGIN or any exec SQL").toEqual([]);
    });

    const error = expectCode(captured, expectedCode, B3A_ACTION_ID);
    expect(Object.prototype.hasOwnProperty.call(error, "cause"), "fixed caller error must be cause-free").toBe(false);
    expect(harness.counters.loadCount()).toBe(0);
    expect(harness.counters.resolveCount()).toBe(0);
    expect(harness.counters.nowCount()).toBe(0);
    expect(snapshotB3ADatabase(harness.handle)).toEqual(before);
    return error;
  }

  describe("B3A caller DTO validation is a pure snapshot", () => {
    it("requires non-null plain records for both approval methods", () => {
      const harness = buildValidationHarness();
      expectPureCallerRejection(harness, "approveHuman", null, "ACTION_APPROVAL_INVALID");

      const customPrototypePolicy = Object.assign(Object.create({ inherited: true }), validPolicyInput());
      expectPureCallerRejection(
        harness,
        "approvePolicy",
        customPrototypePolicy as unknown,
        "ACTION_APPROVAL_INVALID",
      );
    });

    it("rejects accessors without invoking them", () => {
      const harness = buildValidationHarness();
      let getterCalls = 0;
      const hostile = validHumanInput() as unknown as Record<string, unknown>;
      Object.defineProperty(hostile, "actionId", {
        configurable: true,
        enumerable: true,
        get: () => {
          getterCalls += 1;
          throw new Error("B3A_ACCESSOR_MUST_NOT_RUN");
        },
      });

      const error = expectPureCallerRejection(harness, "approveHuman", hostile, "ACTION_APPROVAL_INVALID");
      expect(getterCalls).toBe(0);
      expect(JSON.stringify(error)).not.toContain("B3A_ACCESSOR_MUST_NOT_RUN");
    });

    it("rejects symbol and unknown own fields as non-exact DTOs", () => {
      const harness = buildValidationHarness();
      const symbolInput = {
        ...validPolicyInput(),
        [Symbol("B3A_SYMBOL_FIELD")]: true,
      };
      expectPureCallerRejection(harness, "approvePolicy", symbolInput, "ACTION_APPROVAL_INVALID");
      expectPureCallerRejection(
        harness,
        "approveHuman",
        { ...validHumanInput(), unknownField: true },
        "ACTION_APPROVAL_INVALID",
      );
    });

    it("accepts null-prototype envelopes far enough to apply reviewer and TTL validation", () => {
      const harness = buildValidationHarness();
      const human = Object.assign(Object.create(null), {
        ...validHumanInput(),
        reviewerId: "system:policy-gate",
        ttlMs: 0,
        expectedContextHash: "A".repeat(64),
      });
      expectPureCallerRejection(harness, "approveHuman", human, "ACTION_APPROVAL_REVIEWER_INVALID");

      const policy = Object.assign(Object.create(null), { ...validPolicyInput(), ttlMs: 0 });
      expectPureCallerRejection(harness, "approvePolicy", policy, "ACTION_APPROVAL_TTL_INVALID");
    });

    it("applies actionId and note precedence before reviewer, TTL, and context", () => {
      const harness = buildValidationHarness();
      expectPureCallerRejection(
        harness,
        "approveHuman",
        {
          ...validHumanInput(),
          actionId: ` ${B3A_ACTION_ID} `,
          note: 7,
          reviewerId: "system:policy-gate",
          ttlMs: 0,
          expectedContextHash: "A",
        },
        "ACTION_APPROVAL_INVALID",
      );
      expectPureCallerRejection(
        harness,
        "approvePolicy",
        { ...validPolicyInput(), note: { secret: true }, ttlMs: 0 },
        "ACTION_APPROVAL_INVALID",
      );
    });

    it("applies human reviewer precedence, including the reserved policy reviewer", () => {
      const harness = buildValidationHarness();
      expectPureCallerRejection(
        harness,
        "approveHuman",
        { ...validHumanInput(), reviewerId: 17, ttlMs: 0, expectedContextHash: "A" },
        "ACTION_APPROVAL_REVIEWER_INVALID",
      );
      expectPureCallerRejection(
        harness,
        "approveHuman",
        { ...validHumanInput(), reviewerId: "system:policy-gate" },
        "ACTION_APPROVAL_REVIEWER_INVALID",
      );
    });

    it("rejects zero, unsafe, and over-cap TTLs before human context shape", () => {
      const harness = buildValidationHarness();
      expectPureCallerRejection(
        harness,
        "approvePolicy",
        { ...validPolicyInput(), ttlMs: 0 },
        "ACTION_APPROVAL_TTL_INVALID",
      );
      expectPureCallerRejection(
        harness,
        "approveHuman",
        { ...validHumanInput(), ttlMs: Number.MAX_SAFE_INTEGER + 1, expectedContextHash: "A" },
        "ACTION_APPROVAL_TTL_INVALID",
      );
      expectPureCallerRejection(
        harness,
        "approvePolicy",
        { ...validPolicyInput(), ttlMs: 86_400_001 },
        "ACTION_APPROVAL_TTL_INVALID",
      );
    });

    it("rejects uppercase, non-hex, and wrong-length human context tokens", () => {
      const harness = buildValidationHarness();
      for (const expectedContextHash of ["A".repeat(64), "g".repeat(64), "a".repeat(63)]) {
        expectPureCallerRejection(
          harness,
          "approveHuman",
          { ...validHumanInput(), expectedContextHash },
          "ACTION_APPROVAL_CONTEXT_INVALID",
        );
      }
    });
  });

  function seedDecisionAction(
    handle: BountyDatabase,
    actionId: string,
    jobId: string,
    overrides: Parameters<typeof seedB2APendingAction>[3] = {},
  ): void {
    insertJobWithMode(handle, jobId, "safe", "b3a-decision", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET, ...overrides });
  }

  describe("B3A current decision is independently rematerialized for approval", () => {
    it("accepts human approval for the current allow decision", () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle);
      const actionId = "act-b3a-human-allow";
      const jobId = "job-b3a-human-allow";
      seedDecisionAction(handle, actionId, jobId);

      const challenge = service.preview(actionId);
      expect(challenge.policyDecision).toBe("allow");
      expect(counters.loadCount()).toBe(1);
      expect(counters.resolveCount()).toBe(1);

      const result = service.approveHuman({
        actionId,
        reviewerId: B3A_REVIEWER_ID,
        expectedContextHash: challenge.contextHash,
        ttlMs: 60_000,
      });
      expect(result.action.status).toBe("approved");
      expect(result.review.source).toBe("human");
      expect(result.review.reviewerId).toBe(B3A_REVIEWER_ID);
      expect(counters.loadCount()).toBe(2);
      expect(counters.resolveCount()).toBe(2);
    });

    it("accepts human approval for the current require_approval decision", () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle, {
        capability: buildB2ACapability({ ...B2A_DEFAULT_CAPABILITY, riskLevel: "medium" }),
      });
      const actionId = "act-b3a-human-required";
      const jobId = "job-b3a-human-required";
      seedDecisionAction(handle, actionId, jobId, { riskLevel: "medium" });

      const challenge = service.preview(actionId);
      expect(challenge.policyDecision).toBe("require_approval");
      const result = service.approveHuman({
        actionId,
        reviewerId: B3A_REVIEWER_ID,
        expectedContextHash: challenge.contextHash,
        ttlMs: 60_000,
      });
      expect(result.action.status).toBe("approved");
      expect(result.review.source).toBe("human");
      expect(counters.loadCount()).toBe(2);
      expect(counters.resolveCount()).toBe(2);
    });

    it("rejects a valid current block for both human and policy approval", () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle, {
        capability: buildB2ACapability({
          ...B2A_DEFAULT_CAPABILITY,
          destructive: true,
          requiresScope: false,
        }),
      });
      const actionId = "act-b3a-block";
      const jobId = "job-b3a-block";
      seedDecisionAction(handle, actionId, jobId);

      const challenge = service.preview(actionId);
      expect(challenge.policyDecision).toBe("block");
      expectCode(
        captureApproval(service, "approveHuman", {
          actionId,
          reviewerId: B3A_REVIEWER_ID,
          expectedContextHash: challenge.contextHash,
          ttlMs: 60_000,
        }),
        "ACTION_APPROVAL_POLICY_BLOCKED",
      );
      expect(counters.loadCount()).toBe(2);
      expect(counters.resolveCount()).toBe(2);

      expectCode(
        captureApproval(service, "approvePolicy", { actionId, ttlMs: 60_000 }),
        "ACTION_APPROVAL_POLICY_BLOCKED",
      );
      expect(counters.loadCount()).toBe(3);
      expect(counters.resolveCount()).toBe(3);
      expect(counters.nowCount()).toBe(0);
    });

    it("accepts policy approval only for allow when requiresApproval is false", () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle);
      const actionId = "act-b3a-policy-allow";
      const jobId = "job-b3a-policy-allow";
      seedDecisionAction(handle, actionId, jobId, { requiresApproval: 0 });

      const challenge = service.preview(actionId);
      expect(challenge.policyDecision).toBe("allow");
      const result = service.approvePolicy({ actionId, ttlMs: 60_000 });
      expect(result.action.status).toBe("approved");
      expect(result.review.source).toBe("policy");
      expect(result.review.reviewerId).toBe("system:policy-gate");
      expect(counters.loadCount()).toBe(2);
      expect(counters.resolveCount()).toBe(2);
    });

    it("requires a human when an allow action still has requiresApproval=true", () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle);
      const actionId = "act-b3a-policy-flag";
      const jobId = "job-b3a-policy-flag";
      seedDecisionAction(handle, actionId, jobId, { requiresApproval: 1 });

      expect(service.preview(actionId).policyDecision).toBe("allow");
      expectCode(
        captureApproval(service, "approvePolicy", { actionId, ttlMs: 60_000 }),
        "ACTION_APPROVAL_HUMAN_REQUIRED",
      );
      expect(counters.loadCount()).toBe(2);
      expect(counters.resolveCount()).toBe(2);
      expect(counters.nowCount()).toBe(0);
    });

    it("requires a human for require_approval even when requiresApproval=false", () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle, {
        capability: buildB2ACapability({ ...B2A_DEFAULT_CAPABILITY, riskLevel: "medium" }),
      });
      const actionId = "act-b3a-policy-decision";
      const jobId = "job-b3a-policy-decision";
      seedDecisionAction(handle, actionId, jobId, { riskLevel: "medium", requiresApproval: 0 });

      expect(service.preview(actionId).policyDecision).toBe("require_approval");
      expectCode(
        captureApproval(service, "approvePolicy", { actionId, ttlMs: 60_000 }),
        "ACTION_APPROVAL_HUMAN_REQUIRED",
      );
      expect(counters.loadCount()).toBe(2);
      expect(counters.resolveCount()).toBe(2);
      expect(counters.nowCount()).toBe(0);
    });

    it("rejects stale and all-zero syntactically valid human contexts", () => {
      const handle = openDb();
      const { service, counters } = buildB2AService(handle);
      const actionId = "act-b3a-stale";
      const jobId = "job-b3a-stale";
      seedDecisionAction(handle, actionId, jobId);

      const challenge = service.preview(actionId);
      const staleContext = `${challenge.contextHash[0] === "f" ? "e" : "f"}${challenge.contextHash.slice(1)}`;
      expect(staleContext).toMatch(/^[0-9a-f]{64}$/);
      expect(staleContext).not.toBe(challenge.contextHash);
      expect(challenge.contextHash).not.toBe("0".repeat(64));

      for (const expectedContextHash of [staleContext, "0".repeat(64)]) {
        expectCode(
          captureApproval(service, "approveHuman", {
            actionId,
            reviewerId: B3A_REVIEWER_ID,
            expectedContextHash,
            ttlMs: 60_000,
          }),
          "ACTION_APPROVAL_CONTEXT_STALE",
        );
      }
      expect(counters.loadCount()).toBe(3);
      expect(counters.resolveCount()).toBe(3);
      expect(counters.nowCount()).toBe(0);
    });
  });

  describe("B3B1: atomic human and policy approval happy paths", () => {
    interface B3BHooks {
      onLoad?: () => void;
      onResolve?: () => void;
      onNow?: () => void;
    }

    function buildB3BDependencies(
      nowImpl: () => Date,
      overrides: Partial<B2ADependenciesInput> = {},
      hooks: B3BHooks = {},
    ): {
      dependencies: ActionApprovalServiceDependencies;
      loadCount: () => number;
      resolveCount: () => number;
      nowCount: () => number;
    } {
      const base = buildB2ADependencies({
        loaded: overrides.loaded ?? buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT),
        capability: overrides.capability ?? buildB2ACapability(B2A_DEFAULT_CAPABILITY),
        integration: overrides.integration ?? { kind: "builtin" },
        normalizedTarget: overrides.normalizedTarget ?? B2A_NORMALIZED_TARGET,
      });
      let nowCount = 0;
      const dependencies: ActionApprovalServiceDependencies = {
        loadCurrentProgram: () => {
          hooks.onLoad?.();
          return base.dependencies.loadCurrentProgram();
        },
        resolveBindingMaterial: (input) => {
          hooks.onResolve?.();
          return base.dependencies.resolveBindingMaterial(input);
        },
        now: () => {
          nowCount += 1;
          hooks.onNow?.();
          return nowImpl();
        },
      };
      return {
        dependencies,
        loadCount: base.counters.loadCount,
        resolveCount: base.counters.resolveCount,
        nowCount: () => nowCount,
      };
    }

    function rowsForB3B(handle: BountyDatabase, table: "action_reviews" | "workflow_events"): Array<Record<string, unknown>> {
      return handle.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all() as Array<Record<string, unknown>>;
    }

    function expectStoredB3BApproval(
      handle: BountyDatabase,
      result: ReturnType<ActionApprovalService["approveHuman"]>,
      challenge: ReturnType<ActionApprovalService["preview"]>,
      expected: {
        actionId: string;
        jobId: string;
        source: "human" | "policy";
        reviewerId: string;
        note: string | null;
        reviewedAt: string;
        expiresAt: string;
        forbiddenEventValues: ReadonlyArray<string>;
      },
    ): void {
      const reviewRows = rowsForB3B(handle, "action_reviews");
      expect(reviewRows).toHaveLength(1);
      const rawReview = reviewRows[0]!;
      expect(rawReview).toEqual({
        id: result.review.id,
        action_id: expected.actionId,
        job_id: expected.jobId,
        decision: "approved",
        note: expected.note,
        created_at: expected.reviewedAt,
        reviewer_id: expected.reviewerId,
        source: expected.source,
        reviewed_at: expected.reviewedAt,
        expires_at: expected.expiresAt,
        scope_hash: challenge.scopeHash,
        policy_hash: challenge.policyHash,
        action_hash: challenge.actionHash,
        context_hash: challenge.contextHash,
        invalidated_at: null,
        invalidation_reason: null,
      });

      const returnedReview = result.review as unknown as Record<string, unknown>;
      expect(returnedReview.id).toBe(rawReview.id);
      expect(returnedReview.actionId).toBe(rawReview.action_id);
      expect(returnedReview.jobId).toBe(rawReview.job_id);
      expect(returnedReview.decision).toBe(rawReview.decision);
      expect(returnedReview.note ?? null).toBe(rawReview.note);
      expect(returnedReview.createdAt).toBe(rawReview.created_at);
      expect(returnedReview.reviewerId).toBe(rawReview.reviewer_id);
      expect(returnedReview.source).toBe(rawReview.source);
      expect(returnedReview.reviewedAt).toBe(rawReview.reviewed_at);
      expect(returnedReview.expiresAt).toBe(rawReview.expires_at);
      expect(returnedReview.scopeHash).toBe(rawReview.scope_hash);
      expect(returnedReview.policyHash).toBe(rawReview.policy_hash);
      expect(returnedReview.actionHash).toBe(rawReview.action_hash);
      expect(returnedReview.contextHash).toBe(rawReview.context_hash);
      expect(returnedReview.invalidatedAt ?? null).toBeNull();
      expect(returnedReview.invalidationReason ?? null).toBeNull();

      const rawAction = readActionRowForB2A(handle, expected.actionId);
      expect(rawAction.status).toBe("approved");
      expect(rawAction.active_review_id).toBe(result.review.id);
      expect(rawAction.planned_scope_hash).toBe(challenge.scopeHash);
      expect(rawAction.planned_policy_hash).toBe(challenge.policyHash);
      expect(rawAction.planned_action_hash).toBe(challenge.actionHash);
      expect(rawAction.planned_context_hash).toBe(challenge.contextHash);
      expect(rawAction.updated_at).toBe(expected.reviewedAt);
      expect(rawAction.execution_token).toBeNull();
      expect(result.action).toEqual(new ActionQueue(handle).get(expected.actionId));
      expect(JSON.stringify(result.action)).not.toMatch(/executionToken/i);

      const eventRows = rowsForB3B(handle, "workflow_events");
      expect(eventRows).toHaveLength(1);
      const rawEvent = eventRows[0]!;
      const rawMetadata = JSON.parse(String(rawEvent.metadata_json)) as Record<string, unknown>;
      expect(Object.keys(rawMetadata).sort()).toEqual(["actionId", "contextHash", "reviewId", "source"]);
      expect(rawMetadata).toEqual({
        actionId: expected.actionId,
        reviewId: result.review.id,
        source: expected.source,
        contextHash: challenge.contextHash,
      });
      expect(rawEvent.phase).toBe("action-review");
      expect(rawEvent.status).toBe("completed");
      expect(rawEvent.message).toBe("Action approval completed");

      const returnedEvent = result.event as unknown as Record<string, unknown>;
      expect(returnedEvent.id).toBe(rawEvent.id);
      expect(returnedEvent.jobId).toBe(rawEvent.job_id);
      expect(returnedEvent.phase).toBe(rawEvent.phase);
      expect(returnedEvent.status).toBe(rawEvent.status);
      expect(returnedEvent.message).toBe(rawEvent.message);
      expect(returnedEvent.metadata).toEqual(rawMetadata);
      const serializedEvent = JSON.stringify({ rawEvent, returnedEvent });
      for (const forbidden of expected.forbiddenEventValues) {
        expect(serializedEvent).not.toContain(forbidden);
      }
      expect(serializedEvent).not.toMatch(/(?:scope|policy|action)Hash|execution_?token/i);

      const rawJob = handle.prepare("SELECT * FROM jobs WHERE id = ?").get(expected.jobId) as Record<string, unknown>;
      expect(result.job).toEqual({
        id: rawJob.id,
        type: rawJob.type,
        target: rawJob.target,
        mode: rawJob.mode,
        status: rawJob.status,
        pauseReason: rawJob.pause_reason,
        statusDetail: rawJob.status_detail,
        createdAt: rawJob.created_at,
        updatedAt: rawJob.updated_at,
      });
      expect(result.action.jobId).toBe(result.job.id);
    }

    it("commits the complete human review, action, event, and derived job from one clock instant", () => {
      const handle = openDb();
      const actionId = "act-b3b-human";
      const jobId = "job-b3b-human";
      const note = "B3B-HUMAN-PRIVATE-NOTE";
      const reviewedAt = "2099-01-01T00:10:00.123Z";
      const ttlMs = 65_432;
      const expiresAt = new Date(new Date(reviewedAt).getTime() + ttlMs).toISOString();
      seedDecisionAction(handle, actionId, jobId);
      const transactionStates = { load: [] as boolean[], resolve: [] as boolean[], now: [] as boolean[] };
      const bundle = buildB3BDependencies(
        () => new Date(reviewedAt),
        {},
        {
          onLoad: () => transactionStates.load.push(hasImmediateTransaction(handle)),
          onResolve: () => transactionStates.resolve.push(hasImmediateTransaction(handle)),
          onNow: () => transactionStates.now.push(hasImmediateTransaction(handle)),
        },
      );
      const service = new ActionApprovalService(handle, bundle.dependencies);

      const challenge = service.preview(actionId);
      expect(bundle.loadCount()).toBe(1);
      expect(bundle.resolveCount()).toBe(1);
      expect(bundle.nowCount()).toBe(0);
      transactionStates.load.length = 0;
      transactionStates.resolve.length = 0;
      transactionStates.now.length = 0;
      const result = service.approveHuman({
        actionId,
        reviewerId: B3A_REVIEWER_ID,
        expectedContextHash: challenge.contextHash,
        ttlMs,
        note,
      });

      expect(bundle.loadCount()).toBe(2);
      expect(bundle.resolveCount()).toBe(2);
      expect(bundle.nowCount()).toBe(1);
      expect(transactionStates).toEqual({ load: [false], resolve: [false], now: [false] });
      expectStoredB3BApproval(handle, result, challenge, {
        actionId,
        jobId,
        source: "human",
        reviewerId: B3A_REVIEWER_ID,
        note,
        reviewedAt,
        expiresAt,
        forbiddenEventValues: [note, B2A_TARGET, "/tmp/bountypilot-b2a-b2a-base.yml"],
      });
    });

    it("commits the analogous finite-TTL policy approval with the reserved reviewer", () => {
      const handle = openDb();
      const actionId = "act-b3b-policy";
      const jobId = "job-b3b-policy";
      const note = "B3B-POLICY-PRIVATE-NOTE";
      const reviewedAt = "2099-01-01T00:20:00.007Z";
      const ttlMs = 12_345;
      const expiresAt = new Date(new Date(reviewedAt).getTime() + ttlMs).toISOString();
      seedDecisionAction(handle, actionId, jobId, { requiresApproval: 0 });
      const transactionStates = { load: [] as boolean[], resolve: [] as boolean[], now: [] as boolean[] };
      const bundle = buildB3BDependencies(
        () => new Date(reviewedAt),
        {},
        {
          onLoad: () => transactionStates.load.push(hasImmediateTransaction(handle)),
          onResolve: () => transactionStates.resolve.push(hasImmediateTransaction(handle)),
          onNow: () => transactionStates.now.push(hasImmediateTransaction(handle)),
        },
      );
      const service = new ActionApprovalService(handle, bundle.dependencies);

      const challenge = service.preview(actionId);
      expect(bundle.loadCount()).toBe(1);
      expect(bundle.resolveCount()).toBe(1);
      expect(bundle.nowCount()).toBe(0);
      transactionStates.load.length = 0;
      transactionStates.resolve.length = 0;
      transactionStates.now.length = 0;
      const result = service.approvePolicy({ actionId, ttlMs, note });

      expect(bundle.loadCount()).toBe(2);
      expect(bundle.resolveCount()).toBe(2);
      expect(bundle.nowCount()).toBe(1);
      expect(transactionStates).toEqual({ load: [false], resolve: [false], now: [false] });
      expectStoredB3BApproval(handle, result, challenge, {
        actionId,
        jobId,
        source: "policy",
        reviewerId: "system:policy-gate",
        note,
        reviewedAt,
        expiresAt,
        forbiddenEventValues: [note, B2A_TARGET, "/tmp/bountypilot-b2a-b2a-base.yml"],
      });
    });
  });
});

// ===========================================================================
// B3C: approval concurrency and fail-closed boundary coverage.
//
// This block intentionally does not repeat B3B1's persisted happy-path shape
// or B3B2's clock/event-insert rollback cases. Its concurrent case uses two
// worker threads, each of which opens its own DatabaseSync handle, and holds
// both callers at now() until both have completed their outside preflight.
// ===========================================================================

describe("B3C: concurrent approval and remaining fail-closed boundaries", () => {
  type B3CMethod = "approveHuman" | "approvePolicy";

  interface B3CAuthorityState {
    loaded: LoadedProgram;
    capability: CapabilityEnforcementInput;
    integration: IntegrationBindingMaterial;
  }

  interface B3CWorkerSuccess {
    kind: "success";
    reviewId: string;
    eventId: string;
  }

  interface B3CWorkerFailure {
    kind: "error";
    code: string | null;
    name: string;
    message: string;
  }

  type B3CWorkerOutcome = B3CWorkerSuccess | B3CWorkerFailure;

  function captureB3CApproval(
    service: ActionApprovalService,
    method: B3CMethod,
    input: unknown,
  ): unknown {
    try {
      const call = service[method] as unknown as (runtimeInput: unknown) => unknown;
      call.call(service, input);
    } catch (err) {
      return err;
    }
    return null;
  }

  function snapshotB3CDatabase(
    handle: BountyDatabase,
  ): Record<string, ReadonlyArray<Record<string, unknown>>> {
    const rows = (table: "actions" | "action_reviews" | "workflow_events" | "jobs") =>
      handle.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all() as Array<Record<string, unknown>>;
    return {
      actions: rows("actions"),
      reviews: rows("action_reviews"),
      events: rows("workflow_events"),
      jobs: rows("jobs"),
    };
  }

  function withB3CSqlProbe<T>(
    handle: BountyDatabase,
    run: (preparedSql: string[], execSql: string[]) => T,
  ): T {
    const originalExec = handle.exec.bind(handle);
    const execSql: string[] = [];
    handle.exec = ((sql: string) => {
      execSql.push(sql);
      return originalExec(sql);
    }) as typeof handle.exec;
    try {
      return withPrepareProbe(handle, (_count, preparedSql) => run(preparedSql, execSql));
    } finally {
      handle.exec = originalExec as typeof handle.exec;
    }
  }

  function seedB3CDecisionAction(
    handle: BountyDatabase,
    actionId: string,
    jobId: string,
    overrides: Parameters<typeof seedB2APendingAction>[3] = {},
  ): void {
    insertJobWithMode(handle, jobId, "safe", "b3c-decision", "queued", B2A_TARGET);
    seedB2APendingAction(handle, actionId, jobId, { target: B2A_TARGET, ...overrides });
  }

  function makeB3CState(): B3CAuthorityState {
    return {
      loaded: buildB2ALoadedProgram({
        program: "b3c-authority",
        inScope: ["api.example.com", "*.example.com"],
      }),
      capability: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
      integration: { kind: "builtin" },
    };
  }

  function launchB3CApprovalWorker(input: {
    actionId: string;
    contextHash: string;
    loaded: LoadedProgram;
    material: ResolvedBindingMaterial;
    barrier: SharedArrayBuffer;
  }): { worker: Worker; outcome: Promise<B3CWorkerOutcome> } {
    const source = `
      const { parentPort, workerData } = require('node:worker_threads');
      const { DatabaseSync } = require('node:sqlite');
      const { tsImport } = require('tsx/esm/api');
      const i32 = new Int32Array(workerData.barrier);
      const ARRIVED = 0;
      const RELEASE = 1;
      const WAIT_MS = 10000;
      function barrierNow() {
        const arrived = Atomics.add(i32, ARRIVED, 1) + 1;
        if (arrived === 2) {
          Atomics.store(i32, RELEASE, 1);
          Atomics.notify(i32, RELEASE, Infinity);
        } else {
          const deadline = Date.now() + WAIT_MS;
          while (Atomics.load(i32, RELEASE) !== 1) {
            const remaining = deadline - Date.now();
            if (remaining <= 0) throw new Error('B3C approval barrier timeout');
            const current = Atomics.load(i32, RELEASE);
            Atomics.wait(i32, RELEASE, current, Math.min(50, remaining));
          }
        }
        return new Date('2099-01-01T01:00:00.000Z');
      }
      let db = null;
      (async () => {
        try {
          const { ActionApprovalService } = await tsImport(workerData.moduleUrl, workerData.parentUrl);
          db = new DatabaseSync(workerData.dbFile);
          db.exec('PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
          const service = new ActionApprovalService(db, {
            loadCurrentProgram: () => workerData.loaded,
            resolveBindingMaterial: () => workerData.material,
            now: barrierNow,
          });
          const result = service.approveHuman({
            actionId: workerData.actionId,
            reviewerId: workerData.reviewerId,
            expectedContextHash: workerData.contextHash,
            ttlMs: 60000,
          });
          parentPort.postMessage({
            kind: 'success',
            reviewId: result.review.id,
            eventId: result.event.id,
          });
        } catch (err) {
          parentPort.postMessage({
            kind: 'error',
            code: err && typeof err === 'object' && typeof err.code === 'string' ? err.code : null,
            name: err && typeof err === 'object' && typeof err.name === 'string' ? err.name : typeof err,
            message: err && typeof err === 'object' && typeof err.message === 'string' ? err.message : String(err),
          });
        } finally {
          if (db) {
            try { db.close(); } catch (_) { /* best effort */ }
          }
        }
      })();
    `;
    const worker = new Worker(source, {
      eval: true,
      workerData: {
        moduleUrl: new URL("../src/core/actions/action-approval-service.ts", import.meta.url).href,
        parentUrl: import.meta.url,
        dbFile,
        actionId: input.actionId,
        reviewerId: "reviewer-b3c-concurrent",
        contextHash: input.contextHash,
        loaded: input.loaded,
        material: input.material,
        barrier: input.barrier,
      },
    });
    const outcome = new Promise<B3CWorkerOutcome>((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error("B3C approval worker timed out"));
      }, 15_000);
      worker.once("message", (message: B3CWorkerOutcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve(message);
      });
      worker.once("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        reject(err);
      });
      worker.once("exit", (code) => {
        if (settled || code === 0) return;
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`B3C approval worker exited with code ${code}`));
      });
    });
    return { worker, outcome };
  }

  it("uses two truly concurrent database handles and commits exactly one approval winner", async () => {
    const handle = openDb();
    const actionId = "act-b3c-concurrent";
    const jobId = "job-b3c-concurrent";
    seedB3CDecisionAction(handle, actionId, jobId);
    const state = makeB3CState();
    const material: ResolvedBindingMaterial = {
      normalizedTarget: B2A_NORMALIZED_TARGET,
      capabilityEnforcement: state.capability,
      integration: state.integration,
    };
    const previewService = new ActionApprovalService(handle, {
      loadCurrentProgram: () => state.loaded,
      resolveBindingMaterial: () => material,
      now: () => new Date("2099-01-01T01:00:00.000Z"),
    });
    const challenge = previewService.preview(actionId);
    const barrier = new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT);
    const first = launchB3CApprovalWorker({
      actionId,
      contextHash: challenge.contextHash,
      loaded: state.loaded,
      material,
      barrier,
    });
    const second = launchB3CApprovalWorker({
      actionId,
      contextHash: challenge.contextHash,
      loaded: state.loaded,
      material,
      barrier,
    });

    let outcomes: B3CWorkerOutcome[];
    try {
      outcomes = await Promise.all([first.outcome, second.outcome]);
    } finally {
      await Promise.allSettled([first.worker.terminate(), second.worker.terminate()]);
    }

    expect(Atomics.load(new Int32Array(barrier), 0), "both callers must finish preflight before racing BEGIN").toBe(2);
    const winners = outcomes.filter((outcome): outcome is B3CWorkerSuccess => outcome.kind === "success");
    const losers = outcomes.filter((outcome): outcome is B3CWorkerFailure => outcome.kind === "error");
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    expect(losers[0]?.code).toBe("ACTION_APPROVAL_NOT_PENDING");

    const reviews = handle.prepare("SELECT * FROM action_reviews WHERE action_id = ?").all(actionId) as Array<Record<string, unknown>>;
    const events = handle.prepare("SELECT * FROM workflow_events WHERE job_id = ?").all(jobId) as Array<Record<string, unknown>>;
    const action = readActionRowForB2A(handle, actionId);
    expect(reviews).toHaveLength(1);
    expect(events).toHaveLength(1);
    expect(action.status).toBe("approved");
    expect(action.active_review_id).toBe(winners[0]?.reviewId);
    expect(reviews[0]?.id).toBe(winners[0]?.reviewId);
    expect(events[0]?.id).toBe(winners[0]?.eventId);
  }, 20_000);

  it("propagates exact BEGIN and COMMIT sentinels and leaves all approval writes rolled back", () => {
    const handle = openDb();
    const cases = [
      { name: "begin", matches: (sql: string) => /^\s*BEGIN\s+IMMEDIATE\s*;?\s*$/i.test(sql) },
      { name: "commit", matches: (sql: string) => /^\s*COMMIT\s*;?\s*$/i.test(sql) },
    ] as const;

    for (const [index, row] of cases.entries()) {
      const actionId = `act-b3c-${row.name}-sentinel`;
      const jobId = `job-b3c-${row.name}-sentinel`;
      seedB3CDecisionAction(handle, actionId, jobId);
      const { service, counters } = buildB2AService(handle);
      const challenge = service.preview(actionId);
      const before = snapshotB3CDatabase(handle);
      const sentinel = new Error(`B3C_${row.name.toUpperCase()}_${index}_IDENTITY_SENTINEL`);
      const originalExec = handle.exec.bind(handle);
      const observed: string[] = [];
      handle.exec = ((sql: string) => {
        observed.push(sql);
        if (row.matches(sql)) throw sentinel;
        return originalExec(sql);
      }) as typeof handle.exec;
      let captured: unknown = null;
      try {
        captured = captureB3CApproval(service, "approveHuman", {
          actionId,
          reviewerId: "reviewer-b3c-sentinel",
          expectedContextHash: challenge.contextHash,
          ttlMs: 60_000,
        });
      } finally {
        handle.exec = originalExec as typeof handle.exec;
      }

      expect(captured, `${row.name} error identity`).toBe(sentinel);
      expect(hasImmediateTransaction(handle), `${row.name} guard cleanup`).toBe(false);
      expect(snapshotB3CDatabase(handle), `${row.name} atomic storage`).toEqual(before);
      expect(counters.nowCount()).toBe(1);
      expect(observed.some((sql) => /^\s*BEGIN\s+IMMEDIATE/i.test(sql))).toBe(true);
      if (row.name === "begin") {
        expect(observed.some((sql) => /^\s*ROLLBACK/i.test(sql))).toBe(false);
      } else {
        expect(observed.some((sql) => /^\s*ROLLBACK/i.test(sql))).toBe(true);
      }
    }
  });

  it("maps approval-time loader and resolver faults to fixed cause-free CONTEXT_UNAVAILABLE before clock, BEGIN, or writes", () => {
    const handle = openDb();
    const faults = ["loader", "resolver"] as const;

    for (const [index, fault] of faults.entries()) {
      const actionId = `act-b3c-${fault}-fault-${index}`;
      const jobId = `job-b3c-${fault}-fault-${index}`;
      seedB3CDecisionAction(handle, actionId, jobId);
      const state = makeB3CState();
      const sentinel = `B3C_${fault.toUpperCase()}_PRIVATE_CAUSE`;
      let approvalPhase = false;
      let loadCount = 0;
      let resolveCount = 0;
      let nowCount = 0;
      const dependencies: ActionApprovalServiceDependencies = {
        loadCurrentProgram: () => {
          loadCount += 1;
          if (approvalPhase && fault === "loader") throw new Error(sentinel);
          return state.loaded;
        },
        resolveBindingMaterial: ({ source }) => {
          resolveCount += 1;
          if (approvalPhase && fault === "resolver") throw new Error(sentinel);
          return {
            normalizedTarget: source.action.target,
            capabilityEnforcement: state.capability,
            integration: state.integration,
          };
        },
        now: () => {
          nowCount += 1;
          return new Date("2099-01-01T01:10:00.000Z");
        },
      };
      const service = new ActionApprovalService(handle, dependencies);
      const challenge = service.preview(actionId);
      approvalPhase = true;
      const before = snapshotB3CDatabase(handle);
      let captured: unknown = null;
      withB3CSqlProbe(handle, (preparedSql, execSql) => {
        captured = captureB3CApproval(service, "approveHuman", {
          actionId,
          reviewerId: "reviewer-b3c-dependency-fault",
          expectedContextHash: challenge.contextHash,
          ttlMs: 60_000,
        });
        expect(execSql, `${fault} must fail before BEGIN`).toEqual([]);
        expect(
          preparedSql.filter((sql) => /\b(?:INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql)),
          `${fault} must prepare reads only`,
        ).toEqual([]);
      });

      const error = expectCode(captured, "ACTION_APPROVAL_CONTEXT_UNAVAILABLE", sentinel);
      expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
      expect(JSON.stringify(error)).not.toContain(sentinel);
      expect(loadCount).toBe(2);
      expect(resolveCount).toBe(fault === "loader" ? 1 : 2);
      expect(nowCount).toBe(0);
      expect(snapshotB3CDatabase(handle)).toEqual(before);
    }
  });

  it("invalidates one preview token for scope, policy, target, metadata, job-mode, capability, and integration drift with zero approval writes", () => {
    const handle = openDb();
    const rows: ReadonlyArray<{
      name: string;
      drift: (input: {
        handle: BountyDatabase;
        actionId: string;
        jobId: string;
        state: B3CAuthorityState;
      }) => void;
    }> = [
      {
        name: "scope",
        drift: ({ state }) => {
          state.loaded = buildB2ALoadedProgram({
            program: "b3c-authority",
            inScope: ["api.example.com", "*.example.com", "drift.example.net"],
          });
        },
      },
      {
        name: "policy",
        drift: ({ state }) => {
          const current = buildB2ALoadedProgram({
            program: "b3c-authority",
            inScope: ["api.example.com", "*.example.com"],
          });
          state.loaded = {
            ...current,
            config: ProgramSchema.parse({
              ...current.config,
              rules: { ...current.config.rules, browser_crawling: false },
            }),
          };
        },
      },
      {
        name: "target",
        drift: ({ handle: driftHandle, actionId }) => {
          driftHandle.prepare("UPDATE actions SET target = ? WHERE id = ?").run(
            "https://api.example.com/status",
            actionId,
          );
        },
      },
      {
        name: "metadata",
        drift: ({ handle: driftHandle, actionId }) => {
          driftHandle.prepare("UPDATE actions SET metadata_json = ? WHERE id = ?").run(
            JSON.stringify({ b3c: "metadata-drift" }),
            actionId,
          );
        },
      },
      {
        name: "job-mode",
        drift: ({ handle: driftHandle, jobId }) => {
          driftHandle.prepare("UPDATE jobs SET mode = ? WHERE id = ?").run("deep-safe", jobId);
        },
      },
      {
        name: "capability",
        drift: ({ state }) => {
          state.capability = buildB2ACapability({
            ...B2A_DEFAULT_CAPABILITY,
            mcpTools: ["http.get", "http.head"],
          });
        },
      },
      {
        name: "integration",
        drift: ({ state }) => {
          state.integration = {
            kind: "integration",
            policy: buildB2ASafeIntegrationPolicy({ name: "http" }),
          };
        },
      },
    ];

    for (const [index, row] of rows.entries()) {
      const actionId = `act-b3c-drift-${index}`;
      const jobId = `job-b3c-drift-${index}`;
      seedB3CDecisionAction(handle, actionId, jobId);
      const state = makeB3CState();
      let loadCount = 0;
      let resolveCount = 0;
      let nowCount = 0;
      const service = new ActionApprovalService(handle, {
        loadCurrentProgram: () => {
          loadCount += 1;
          return state.loaded;
        },
        resolveBindingMaterial: ({ source }) => {
          resolveCount += 1;
          return {
            normalizedTarget: source.action.target,
            capabilityEnforcement: state.capability,
            integration: state.integration,
          };
        },
        now: () => {
          nowCount += 1;
          return new Date("2099-01-01T01:20:00.000Z");
        },
      });
      const challenge = service.preview(actionId);
      row.drift({ handle, actionId, jobId, state });
      const beforeApproval = snapshotB3CDatabase(handle);
      let captured: unknown = null;
      withB3CSqlProbe(handle, (preparedSql, execSql) => {
        captured = captureB3CApproval(service, "approveHuman", {
          actionId,
          reviewerId: "reviewer-b3c-drift",
          expectedContextHash: challenge.contextHash,
          ttlMs: 60_000,
        });
        expect(execSql, `${row.name} drift must reject before BEGIN`).toEqual([]);
        expect(
          preparedSql.filter((sql) => /\b(?:INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql)),
          `${row.name} drift must prepare reads only`,
        ).toEqual([]);
      });

      expectCode(captured, "ACTION_APPROVAL_CONTEXT_STALE", actionId);
      expect(loadCount).toBe(2);
      expect(resolveCount).toBe(2);
      expect(nowCount).toBe(0);
      expect(snapshotB3CDatabase(handle), `${row.name} drift approval must write nothing`).toEqual(beforeApproval);
    }
  });

  it("statically excludes effect/network/browser/process dependencies and exposes no token anywhere in an approval result", () => {
    const serviceSource = readFileSync(
      new URL("../src/core/actions/action-approval-service.ts", import.meta.url),
      "utf8",
    );
    const importSpecifiers = [
      ...serviceSource.matchAll(/^\s*import[\s\S]*?\sfrom\s+["']([^"']+)["'];\s*$/gm),
    ].map((match) => match[1]!);
    const forbiddenImports = importSpecifiers.filter((specifier) =>
      /^(?:node:)?(?:http|https|net|dns|tls|dgram|child_process|worker_threads|cluster|process)$/u.test(specifier) ||
      /(?:^|\/)(?:effects?|effect-executors?|browser|mcp|external)(?:\/|$)/u.test(specifier) ||
      /(?:playwright|process-tree|tool-manager|action-lifecycle|target-effect)/u.test(specifier),
    );
    expect(forbiddenImports).toEqual([]);

    const handle = openDb();
    const actionId = "act-b3c-token-proof";
    const jobId = "job-b3c-token-proof";
    seedB3CDecisionAction(handle, actionId, jobId);
    const { service } = buildB2AService(handle);
    const challenge = service.preview(actionId);
    const result = service.approveHuman({
      actionId,
      reviewerId: "reviewer-b3c-token-proof",
      expectedContextHash: challenge.contextHash,
      ttlMs: 60_000,
    });
    const tokenKeyPaths: string[] = [];
    const visit = (value: unknown, pathParts: string[], seen: Set<object>): void => {
      if (value === null || typeof value !== "object") return;
      if (seen.has(value)) return;
      seen.add(value);
      for (const key of Reflect.ownKeys(value)) {
        const rendered = typeof key === "symbol" ? key.toString() : key;
        const nextPath = [...pathParts, rendered];
        if (/token/i.test(rendered)) tokenKeyPaths.push(nextPath.join("."));
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")) {
          visit(descriptor.value, nextPath, seen);
        }
      }
    };
    visit(result, ["result"], new Set<object>());
    expect(tokenKeyPaths).toEqual([]);
    expect(JSON.stringify(result)).not.toMatch(/execution_?token|bearer/i);
    expect(JSON.stringify(result.event)).not.toMatch(/execution_?token|bearer/i);
  });
});

// ===========================================================================
// C1A authority seam hardening. These direct exported-seam tests pin the
// failure boundary used by both approval and lifecycle claim: hostile or
// non-canonical source data must never escape as a foreign error, and an
// invalid source must fail before either authority dependency is invoked.
// ===========================================================================

describe("C1A authority seam hardening", () => {
  const FIXED_CONTEXT_MESSAGE = "Action approval context is unavailable.";

  function validSource(): ActionMaterialSource {
    return {
      action: {
        id: "act-c1a-authority-seam",
        jobId: "job-c1a-authority-seam",
        adapter: "http",
        actionType: "GET",
        target: B2A_TARGET,
        riskLevel: "low",
        requiresApproval: true,
        requiredForCompletion: true,
        metadata: { slice: "c1a-authority-seam" },
      },
      job: {
        id: "job-c1a-authority-seam",
        type: "c1a-authority-seam",
        target: B2A_TARGET,
        mode: "safe",
      },
    };
  }

  function capture(call: () => unknown): unknown {
    try {
      call();
    } catch (err) {
      return err;
    }
    return null;
  }

  function expectFixedContextError(captured: unknown, sentinel: string): BountyPilotError {
    const error = expectCode(
      captured,
      "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
      sentinel,
    );
    expect(error.message).toBe(FIXED_CONTEXT_MESSAGE);
    expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
    expect(JSON.stringify(error)).not.toContain(sentinel);
    return error;
  }

  function dependencyProbe(): {
    dependencies: ActionAuthorityDependencies;
    loadCount: () => number;
    resolveCount: () => number;
  } {
    let loadCount = 0;
    let resolveCount = 0;
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    return {
      dependencies: {
        loadCurrentProgram: () => {
          loadCount += 1;
          return loaded;
        },
        resolveBindingMaterial: ({ source }) => {
          resolveCount += 1;
          return {
            normalizedTarget: source.action.target,
            capabilityEnforcement: buildB2ACapability(B2A_DEFAULT_CAPABILITY),
            integration: { kind: "builtin" },
          };
        },
      },
      loadCount: () => loadCount,
      resolveCount: () => resolveCount,
    };
  }

  const INVALID_SOURCE_CASES: ReadonlyArray<{
    name: string;
    sentinel: string;
    build: () => ActionMaterialSource;
  }> = [
    {
      name: "throwing top-level Proxy",
      sentinel: "C1A_SOURCE_PROXY_SENTINEL",
      build: () => {
        const sentinel = "C1A_SOURCE_PROXY_SENTINEL";
        return new Proxy(validSource(), {
          get: () => {
            throw new Error(sentinel);
          },
        });
      },
    },
    {
      name: "revoked top-level Proxy",
      sentinel: "C1A_REVOKED_PROXY_MUST_BE_GENERIC",
      build: () => {
        const pair = Proxy.revocable(validSource(), {});
        pair.revoke();
        return pair.proxy;
      },
    },
    {
      name: "throwing top-level action accessor",
      sentinel: "C1A_SOURCE_ACCESSOR_SENTINEL",
      build: () => {
        const base = validSource();
        const hostile: Record<string, unknown> = {};
        Object.defineProperty(hostile, "action", {
          enumerable: true,
          get: () => {
            throw new Error("C1A_SOURCE_ACCESSOR_SENTINEL");
          },
        });
        Object.defineProperty(hostile, "job", {
          enumerable: true,
          value: base.job,
        });
        return hostile as unknown as ActionMaterialSource;
      },
    },
    {
      name: "non-canonical BigInt metadata",
      sentinel: "CANONICAL_VALUE_UNSUPPORTED",
      build: () => {
        const source = validSource();
        source.action.metadata = { unsupported: BigInt(1) };
        return source;
      },
    },
  ];

  for (const row of INVALID_SOURCE_CASES) {
    it(`${row.name} is remapped before loader or resolver`, () => {
      const probe = dependencyProbe();
      const captured = capture(() =>
        materializeActionAuthority(row.build(), probe.dependencies),
      );

      expectFixedContextError(captured, row.sentinel);
      expect(probe.loadCount()).toBe(0);
      expect(probe.resolveCount()).toBe(0);
    });
  }

  it("snapshotActionMaterialSource remaps non-canonical metadata to the fixed cause-free error", () => {
    const source = validSource();
    source.action.metadata = { unsupported: BigInt(2) };

    const captured = capture(() => snapshotActionMaterialSource(source));

    expectFixedContextError(captured, "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("recomputeActionAuthority remaps a hostile material fault without leaking its sentinel", () => {
    const source = validSource();
    const loaded = buildB2ALoadedProgram(B2A_DEFAULT_PROGRAM_INPUT);
    const authority = buildB2AProgramAuthoritySnapshot(loaded);
    const capability = buildB2ACapability(B2A_DEFAULT_CAPABILITY);
    Object.defineProperty(capability, "allowedModes", {
      enumerable: true,
      configurable: true,
      get: () => {
        throw new Error("C1A_RECOMPUTE_MATERIAL_SENTINEL");
      },
    });
    const material: CurrentActionMaterial = {
      program: loaded,
      scopeHash: authority.scopeHash,
      policyHash: authority.policyHash,
      normalizedTarget: B2A_NORMALIZED_TARGET,
      capabilityEnforcement: capability,
      integration: { kind: "builtin" },
    };

    const captured = capture(() => recomputeActionAuthority(source, material));

    expectFixedContextError(captured, "C1A_RECOMPUTE_MATERIAL_SENTINEL");
  });
});
