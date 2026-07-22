// P0.2 Packet 2 — Slice A RED tests
// tests/action-lifecycle.test.ts
//
// Contract source: docs/p0.2-packet-2-contract.md §1–6, §9, §11 (Slice A).
//
// Scope of THIS FILE (Slice A — storage, fail-closed state, transaction
// composition, and finalizer precedence):
//   A1. enqueue with requiresApproval=false defaults to "pending", not "approved".
//   A2. enqueue with caller-supplied status="approved" throws
//       ACTION_APPROVAL_SERVICE_REQUIRED and inserts zero rows (runtime
//       probe is type-safe even if a future TS input narrows out "approved").
//   A3. ActionQueue.approve preserves ACTION_NOT_FOUND for missing id, but
//       every existing action status (pending, structurally-valid approved,
//       running, executed, blocked, failed, outcome_unknown) is rejected
//       with ACTION_APPROVAL_SERVICE_REQUIRED and the row is preserved.
//   A4. A raw v2 action row is mapped to a generic ActionRecord that
//       exposes every v2 field: requiredForCompletion (decoded strictly
//       as 1->true and 0->false, with any other stored value failing
//       ACTION_RECORD_INVALID), activeReviewId, the four planned hashes,
//       executionOwner, lease/start/dispatch/finish timestamps, outcome
//       certainty, redacted lastErrorCode/lastErrorMessage (with positive
//       [REDACTED] and preserved public text), updatedAt, supersedesActionId,
//       and the legacy executedAt terminal timestamp. The generic
//       ActionRecord has no OWN "executionToken" property and
//       JSON.stringify(...) never contains the token value, for both
//       get() and list().
//   A5. A malformed v2 "approved" row whose active review is NOT
//       structurally complete makes both ActionQueue.get and .list fail
//       closed with ACTION_APPROVAL_INVALID. Structural validation starts
//       from a valid human or policy approved row and breaks each
//       predicate component (null/missing active review, action mismatch,
//       job mismatch, wrong decision, invalidated, blank reviewer,
//       null/blank reviewedAt, null/blank expiresAt, invalid source,
//       policy reviewer not system:policy-gate, human reviewer equal
//       system:policy-gate, and null/mismatched scope/policy/action/
//       context hashes on either side). Far-future structural fixtures
//       only; live-clock expiry is lifecycle/claim scope.
//   A6. ActionReviewStore.complete approval in-transaction primitive
//       requires an active transaction; inside withImmediateTransaction it
//       persists reviewer/source/reviewedAt/expiresAt and all four hashes
//       exactly; no public helper may begin a nested transaction.
//   A7. WorkflowEventStore.recordInTransaction requires an active
//       transaction; inside withImmediateTransaction two appends allocate
//       exact sequences, and raw SQL proves message/metadata were redacted
//       before persistence. The public record() wrapper, called inside an
//       outer transaction, raises DB_TRANSACTION_NESTED after it becomes
//       transaction-owning.
//   A8. JobManager finalizer table-test pins mixed required-state
//       precedence (outcome_unknown > running > blocked|failed > pending >
//       approved > all-executed/zero-required). Non-required rows are
//       ignored. Direct updateStatus(id, "completed") with a required
//       pending action throws JOB_COMPLETION_BLOCKED. pauseReason/
//       statusDetail mapping is asserted and no execution token leaks into
//       statusDetail.
//
// Constraints honored:
//   - only the test file is created or modified;
//   - production modules are imported only for production code that
//     ALREADY exists today;
//   - action-approval-service.ts and action-lifecycle.ts are NOT
//     statically imported (they do not exist yet);
//   - every future method on existing classes is reached through a narrow
//     local structural interface and cast so the test file transpiles,
//     and every assertion fails at the intended runtime check;
//   - fixtures are local temp-file SQLite, deterministic; the
//     concurrency test uses bounded local liveness polling only
//     (Atomics.wait + short setTimeout polling for parent-phase
//     timeouts) — no network, no credentials, no protected paths;
//   - raw v2 inserts match the v2 schema exactly;
//   - assertions are not weakened.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
// Worker is needed by the A7 true-concurrency test; the Worker
// thread reuses the proven CommonJS + require('tsx/esm/api') pattern
// from tests/db-transactions.test.ts.
import { Worker } from "node:worker_threads";

import { openBountyDatabase, withImmediateTransaction, type BountyDatabase } from "../src/stores/db/database.js";
import { BountyPilotError } from "../src/utils/errors.js";
import { ActionQueue, type ActionRecord, type EnqueueActionInput } from "../src/core/actions/action-queue.js";
import { ActionReviewStore, type ActionReviewRecord } from "../src/core/actions/action-review-store.js";
import { JobManager, type JobRecord, type JobStatus } from "../src/core/jobs/job-manager.js";
import { WorkflowEventStore, type WorkflowEventInput, type WorkflowEventRecord } from "../src/core/jobs/workflow-event-store.js";
import {
  ActionApprovalService,
  type ActionApprovalServiceDependencies,
  type ActionMaterialSource,
  type ResolvedBindingMaterial,
} from "../src/core/actions/action-approval-service.js";
import {
  ActionLifecycle,
  type ActionLifecycleDependencies,
  type ClaimedActionContext,
} from "../src/core/actions/action-lifecycle.js";
import type { CapabilityEnforcementInput } from "../src/core/actions/action-approval-context.js";
import { ProgramSchema } from "../src/core/config/program-schema.js";
import type { LoadedProgram } from "../src/core/config/config-loader.js";

// ---------------------------------------------------------------------------
// Future public API surface that does NOT exist yet (Slice A pinned names).
//
// These narrow structural interfaces exist so this test file TRANSPIES today
// even though the production code that satisfies them has not been written
// yet. Every test casts the existing production class to one of these
// interfaces and exercises the pinned method; if the method is missing,
// the test fails at the call site with a "X is not a function" TypeError
// (which is the desired RED signal) — never at the fixture / schema layer.
// ---------------------------------------------------------------------------

// Correct test-only future public API for CompleteApprovalReviewInput.
// Per contract §6:
//   - NO caller-controlled `id`: the store generates the trusted
//     `review-...` ID. A runtime cast that supplies an `id` must be
//     rejected with ACTION_APPROVAL_INVALID and zero writes.
//   - actionId and jobId are required concrete nonempty strings.
//   - decision is exactly "approved".
//   - reviewerId is required, source is "human" | "policy".
//   - reviewedAt and expiresAt are required canonical ISO-8601 UTC
//     strings; expiresAt must be strictly later than reviewedAt.
//   - all four hash fields are required, nonzero 64 lowercase hex.
//   - note is optional; the store trims and redacts it before write
//     and redacts again on read.
// This type does NOT widen the production ActionReviewStore surface;
// production's own CompleteApprovalReviewInput may have any shape.
// The narrow local types below exist only so strict TS compiles the
// test file today without weakening assertions.
interface CompleteApprovalReviewInput {
  actionId: string;
  jobId: string;
  decision: "approved";
  reviewerId: string;
  source: "human" | "policy";
  reviewedAt: string;
  expiresAt: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
  note?: string;
}

interface ActionReviewStoreSliceA {
  insertApprovalInTransaction(input: CompleteApprovalReviewInput): V2ActionReviewRecord;
}

// V2ActionReviewRecord mirrors the v2 review contract. Production's
// ActionReviewRecord is narrower; the test casts through this so every
// v2 field assertion has a target. Built with Omit<...> so the type
// only widens fields that already exist (decision is narrowed to
// "approved"; v2 fields are added). On a successful insert the
// invalidation fields are OPTIONAL STRINGS (undefined on a fresh
// record) while the raw SQL columns are NULL — these are two
// different representations of the same invariant.
interface V2ActionReviewRecord extends Omit<ActionReviewRecord, "decision"> {
  decision: "approved";
  reviewerId: string;
  source: "human" | "policy";
  reviewedAt: string;
  expiresAt: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
  // On a successful insert, invalidation fields are absent
  // (undefined) on the public record. Raw SQL columns are NULL.
  invalidatedAt?: string;
  invalidationReason?: string;
  createdAt: string;
}

interface WorkflowEventStoreSliceA {
  recordInTransaction(input: WorkflowEventInput): WorkflowEventRecord;
}

interface JobManagerSliceA {
  finalize(jobId: string): FutureJobRecord;
  finalizeInTransaction(jobId: string): FutureJobRecord;
}

// Local test-only RequiredActionCounts mirror of the contract §9
// shape. Production has not exported this interface yet; declaring
// it here keeps the test file strict-TS compilable without
// touching production.
interface RequiredActionCounts {
  approved: number;
  blocked: number;
  executed: number;
  failed: number;
  outcome_unknown: number;
  pending: number;
  running: number;
}

// Local test-only FutureJobRecord mirror of the finalizer return
// shape. Production's JobRecord does not yet carry
// pauseReason/statusDetail; declaring it here keeps the test file
// strict-TS compilable without touching production.
interface FutureJobRecord extends Omit<JobRecord, "status"> {
  status: "queued" | "running" | "paused" | "failed" | "completed";
  pauseReason: PauseReason | null;
  statusDetail: string | null;
}

type PauseReason =
  | "approval_required"
  | "execution_ready"
  | "policy_drift"
  | "policy_blocked"
  | "reconciliation_required"
  | "budget_exhausted"
  | "manual_review";

interface JobStatusDetail {
  pauseReason: PauseReason | null;
  statusDetail: string | null;
}

// Future ActionStatus includes "running" and "outcome_unknown" per §3.
// The legacy ActionStatus type does not, so cast through this union.
type FutureActionStatus =
  | "pending"
  | "approved"
  | "running"
  | "executed"
  | "blocked"
  | "failed"
  | "outcome_unknown";

// V2 ActionRecord (per §3). Production's ActionRecord is narrower; the
// tests cast through this so every v2 field assertion has a target.
// Built with Omit<...> so the type only widens fields that already
// exist (status is replaced with the future union; v2 fields are
// added). Production's narrower ActionRecord must not silently break
// the cast.
interface V2ActionRecord extends Omit<ActionRecord, "status"> {
  status: FutureActionStatus;
  requiredForCompletion: boolean;
  activeReviewId?: string;
  plannedScopeHash?: string;
  plannedPolicyHash?: string;
  plannedActionHash?: string;
  plannedContextHash?: string;
  executionOwner?: string;
  leaseExpiresAt?: string;
  startedAt?: string;
  dispatchStartedAt?: string;
  finishedAt?: string;
  outcomeCertainty?: "success" | "not_dispatched" | "possibly_dispatched";
  lastErrorCode?: string;
  lastErrorMessage?: string;
  updatedAt?: string;
  supersedesActionId?: string;
}

// Future EnqueueActionInput that still includes "approved" so the
// explicit approved probe remains runtime-valid even if production
// narrows the type. Cast through unknown to call enqueue().
interface FutureEnqueueActionInput {
  jobId?: string;
  adapter: string;
  actionType: string;
  target?: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  requiresApproval: boolean;
  metadata?: Record<string, unknown>;
  status?: "pending" | "approved" | "blocked" | "failed";
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeTempDir(): string {
  return mkdtempSync(path.join(tmpdir(), "bountypilot-p02-sliceA-"));
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

const SCOPE_HASH = hex64("scope:slice-a");
const POLICY_HASH = hex64("policy:slice-a");
const ACTION_HASH = hex64("action:slice-a");
const CONTEXT_HASH = hex64("context:slice-a");
const REVIEWER_ID = "reviewer-slice-a";
const POLICY_REVIEWER_ID = "system:policy-gate";
const REVIEW_NOTE = "slice-a review note";
// Far-future canonical timestamps: structural read validation does not
// exercise the live clock (claim/lifecycle scope). Legacy terminal
// timestamps are likewise exercised with a 2099 date.
const CREATED_AT = "2099-01-01T00:00:00.000Z";
const REVIEWED_AT = "2099-01-01T00:00:00.000Z";
const EXPIRES_AT = "2099-01-01T00:15:00.000Z";
const DISPATCHED_AT = "2099-01-01T00:00:05.000Z";
const FINISHED_AT = "2099-01-01T00:00:10.000Z";
const UPDATED_AT = "2099-01-01T00:00:10.000Z";
const SECRET_TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SECRET_IN_METADATA = "Bearer abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SECRET_LAST_ERROR_MESSAGE = "api_key=AKIAIOSFODNN7EXAMPLE slice-a public text";
const REDACTED_LAST_ERROR_MESSAGE = "api_key=[REDACTED] slice-a public text";

interface RawV2ActionSeed {
  id: string;
  jobId: string;
  status: "pending" | "approved" | "executed" | "blocked" | "failed" | "running" | "outcome_unknown";
  requiredForCompletion: 0 | 1;
  // Optional v2 lifecycle columns; if omitted they are inserted as NULL.
  // explicit null is preserved (used by the legacy updatedAt fallback).
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
  supersedesActionId?: string | null;
}

/**
 * Insert a v2 action row that matches the v2 schema exactly (legacy
 * columns + every v2 additive column including supersedes_action_id).
 * Caller controls the lifecycle values so RED tests can stage
 * "approved" rows that fail the structurally-complete predicate, rows
 * that satisfy it, and rows with execution tokens that the generic
 * ActionRecord must NOT expose.
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
  const values: (string | number | null)[] = [
    seed.id,
    seed.jobId,
    "http",
    "GET",
    "https://slice-a.example/path",
    "low",
    0,
    seed.status,
    null,
    CREATED_AT,
    // executed_at: explicit null is preserved; omitted = NULL.
    seed.executedAt === undefined ? null : seed.executedAt,
    // updatedAt: preserve an explicit null; undefined => default.
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
    seed.supersedesActionId ?? null,
    seed.requiredForCompletion,
  ];
  const placeholders = COLS.map(() => "?").join(", ");
  db.prepare(`INSERT INTO actions (${COLS.join(", ")}) VALUES (${placeholders})`).run(...values);
}

/**
 * Insert a structurally valid active approval review. Caller controls
 * the binding fields so the structural-validation table can break one
 * predicate component at a time from a known-good baseline.
 */
function insertValidActiveReview(
  db: BountyDatabase,
  row: {
    id: string;
    actionId: string;
    jobId: string;
    source: "human" | "policy";
    reviewerId: string;
    reviewedAt?: string;
    expiresAt?: string;
    note?: string;
  },
): void {
  insertReviewRow(db, {
    id: row.id,
    actionId: row.actionId,
    jobId: row.jobId,
    decision: "approved",
    reviewerId: row.reviewerId,
    source: row.source,
    reviewedAt: row.reviewedAt ?? REVIEWED_AT,
    expiresAt: row.expiresAt ?? EXPIRES_AT,
    scopeHash: SCOPE_HASH,
    policyHash: POLICY_HASH,
    actionHash: ACTION_HASH,
    contextHash: CONTEXT_HASH,
    note: row.note ?? REVIEW_NOTE,
  });
}

function insertReviewRow(
  db: BountyDatabase,
  row: {
    id: string;
    actionId: string;
    jobId: string;
    decision: "approved" | "blocked" | "executed" | "failed";
    reviewerId: string;
    source: "human" | "policy";
    reviewedAt: string;
    expiresAt: string;
    scopeHash: string;
    policyHash: string;
    actionHash: string;
    contextHash: string;
    note?: string;
    invalidatedAt?: string | null;
  },
): void {
  db.prepare(
    `INSERT INTO action_reviews (
       id, action_id, job_id, decision, note, created_at,
       reviewer_id, source, reviewed_at, expires_at,
       scope_hash, policy_hash, action_hash, context_hash,
       invalidated_at, invalidation_reason
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
  ).run(
    row.id,
    row.actionId,
    row.jobId,
    row.decision,
    row.note ?? null,
    row.reviewedAt,
    row.reviewerId,
    row.source,
    row.reviewedAt,
    row.expiresAt,
    row.scopeHash,
    row.policyHash,
    row.actionHash,
    row.contextHash,
    row.invalidatedAt ?? null,
  );
}

function readActionRow(db: BountyDatabase, id: string): Record<string, unknown> {
  return db.prepare("SELECT * FROM actions WHERE id = ?").get(id) as Record<string, unknown>;
}

function readJobRow(db: BountyDatabase, id: string): Record<string, unknown> {
  return db.prepare("SELECT * FROM jobs WHERE id = ?").get(id) as Record<string, unknown>;
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
  dbFile = path.join(tempDir, "slice-a.db");
});

afterEach(() => {
  closeDb();
  cleanupDb(dbFile);
  if (tempDir && existsSync(tempDir)) {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// A1: enqueue with requiresApproval=false defaults to "pending", not "approved".
// ---------------------------------------------------------------------------

describe("P0.2 Packet 2 Slice A — ActionQueue.enqueue fails closed on default and explicit approved", () => {
  it("A1: low-risk enqueue (requiresApproval=false) defaults to pending, not approved", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const action = queue.enqueue({
      jobId: "job-a1",
      adapter: "http",
      actionType: "GET",
      target: "https://slice-a.example/a1",
      riskLevel: "low",
      requiresApproval: false,
    });

    // Returned record: status must be pending.
    expect(action.status).toBe("pending");

    // Persisted row: status must be pending; the raw SQL column must also
    // say "pending" so callers reading through a future read API cannot
    // observe a phantom approved row.
    const row = readActionRow(handle, action.id) as { status: string };
    expect(row.status).toBe("pending");

    // Re-read via the public get() surface — same answer.
    const fetched = queue.get(action.id);
    expect(fetched).toBeDefined();
    expect(fetched!.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// A2: enqueue({ status: "approved" }) must be rejected and insert no row.
// ---------------------------------------------------------------------------

describe("A2: caller-supplied status='approved' is rejected and inserts zero rows", () => {
  it("throws ACTION_APPROVAL_SERVICE_REQUIRED and never inserts an action row", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM actions").get() as { n: number }).n;

    // The probe must remain valid at runtime even if a future TS
    // input type narrows out "approved". Build a structurally
    // permissive payload and cast through unknown to enqueue().
    const probeInput: FutureEnqueueActionInput = {
      jobId: "job-a2",
      adapter: "http",
      actionType: "GET",
      target: "https://slice-a.example/a2",
      riskLevel: "low",
      requiresApproval: false,
      status: "approved",
    };
    const input = probeInput as unknown as EnqueueActionInput;

    let captured: unknown = null;
    try {
      queue.enqueue(input);
    } catch (err) {
      captured = err;
    }
    expect(captured, "expected BountyPilotError").toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_SERVICE_REQUIRED");

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM actions").get() as { n: number }).n;
    expect(after).toBe(before);

    // Stronger: no row with target == a2 was ever persisted.
    const matching = handle
      .prepare("SELECT COUNT(*) AS n FROM actions WHERE target = ?")
      .get("https://slice-a.example/a2") as { n: number };
    expect(matching.n).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// A3: ActionQueue.approve preserves ACTION_NOT_FOUND for missing id and
//     rejects an existing pending action with ACTION_APPROVAL_SERVICE_REQUIRED
//     without ever flipping the status to approved.
// ---------------------------------------------------------------------------

describe("A3: ActionQueue.approve preserves ACTION_NOT_FOUND and rejects every existing action status", () => {
  it("approve(missing) throws ACTION_NOT_FOUND, not ACTION_APPROVAL_SERVICE_REQUIRED", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);

    let captured: unknown = null;
    try {
      queue.approve("act-does-not-exist");
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_NOT_FOUND");
  });

  it("approve(existing pending) throws ACTION_APPROVAL_SERVICE_REQUIRED and the row stays pending", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const enqueued = queue.enqueue({
      jobId: "job-a3-pending",
      adapter: "http",
      actionType: "GET",
      target: "https://slice-a.example/a3-pending",
      riskLevel: "high",
      requiresApproval: true,
    });
    expect(enqueued.status).toBe("pending");

    let captured: unknown = null;
    try {
      queue.approve(enqueued.id);
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_SERVICE_REQUIRED");

    const row = readActionRow(handle, enqueued.id) as { status: string };
    expect(row.status).toBe("pending");
  });

  interface StatusSeed {
    name: string;
    actionId: string;
    jobId: string;
    status: FutureActionStatus;
    needsReview: boolean;
    invalidated?: boolean;
    source?: "human" | "policy";
    reviewerId?: string;
  }

  // Each seed is a LIFECYCLE-VALID row. Per Slice A §6 retention
  // semantics:
  //   - approved/running/executed/failed/outcome_unknown all RETAIN
  //     the original active approval review (active_review_id set)
  //     and all four planned hashes.
  //   - blocked ALSO retains the original approval pointer and the
  //     four planned hashes, but the underlying review row is
  //     invalidated with a canonical invalidated_at and a nonempty
  //     invalidation_reason. Blocked execution columns stay clean
  //     (no finishedAt, no outcome, no lastError*).
  // All other states keep the pointer/hashes too; only blocked
  // invalidates the review.
  const STATUS_SEEDS: StatusSeed[] = [
    // "pending" is covered by the dedicated approve(existing pending)
    // test above.
    { name: "valid-approved",  actionId: "act-a3-approve", jobId: "job-a3-approve", status: "approved",        needsReview: true,  source: "human", reviewerId: REVIEWER_ID },
    { name: "running",         actionId: "act-a3-running", jobId: "job-a3-running", status: "running",         needsReview: true,  source: "human", reviewerId: REVIEWER_ID },
    { name: "executed",        actionId: "act-a3-exec",    jobId: "job-a3-exec",    status: "executed",        needsReview: true,  source: "human", reviewerId: REVIEWER_ID },
    { name: "blocked",         actionId: "act-a3-blocked", jobId: "job-a3-blocked", status: "blocked",         needsReview: true,  invalidated: true, source: "human", reviewerId: REVIEWER_ID },
    { name: "failed",          actionId: "act-a3-failed",  jobId: "job-a3-failed",  status: "failed",          needsReview: true,  source: "human", reviewerId: REVIEWER_ID },
    { name: "outcome_unknown", actionId: "act-a3-unknown", jobId: "job-a3-unknown", status: "outcome_unknown", needsReview: true,  source: "human", reviewerId: REVIEWER_ID },
  ];

  // Canonical invalidation timestamp used by the blocked seed.
  const INVALIDATED_AT = "2099-01-01T00:00:01.000Z";
  const INVALIDATION_REASON = "policy_blocked_at_claim";

  for (const seed of STATUS_SEEDS) {
    it(`approve(${seed.name}) throws ACTION_APPROVAL_SERVICE_REQUIRED and the row is byte-identical (zero mutation)`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      const reviewId = `rev-a3-${seed.name}`;

      // Seed the original active approval review pointer + the four
      // planned hashes for every state. The blocked case keeps the
      // pointer/hashes on the action but invalidates the review row.
      if (seed.needsReview) {
        insertValidActiveReview(handle, {
          id: reviewId,
          actionId: seed.actionId,
          jobId: seed.jobId,
          source: seed.source!,
          reviewerId: seed.reviewerId!,
        });
        if (seed.invalidated) {
          handle
            .prepare("UPDATE action_reviews SET invalidated_at = ?, invalidation_reason = ? WHERE id = ?")
            .run(INVALIDATED_AT, INVALIDATION_REASON, reviewId);
        }
      }

      const baseSeed: RawV2ActionSeed = {
        id: seed.actionId,
        jobId: seed.jobId,
        status: seed.status,
        requiredForCompletion: 1,
        // approved/running/executed/failed/outcome_unknown and
        // blocked all retain the original approval pointer and
        // the four planned hashes on the action.
        activeReviewId: seed.needsReview ? reviewId : null,
        plannedScopeHash: seed.needsReview ? SCOPE_HASH : null,
        plannedPolicyHash: seed.needsReview ? POLICY_HASH : null,
        plannedActionHash: seed.needsReview ? ACTION_HASH : null,
        plannedContextHash: seed.needsReview ? CONTEXT_HASH : null,
      };

      // Lifecycle-valid lifecycle columns per state. Every column
      // set here is one that a row in that state can legitimately
      // have; nothing is invented.
      if (seed.status === "approved") {
        // approved-but-not-yet-running: no execution columns.
        baseSeed.startedAt = null;
        baseSeed.finishedAt = null;
        baseSeed.outcomeCertainty = null;
        baseSeed.lastErrorCode = null;
        baseSeed.lastErrorMessage = null;
        baseSeed.executedAt = null;
      } else if (seed.status === "running") {
        baseSeed.executionToken = SECRET_TOKEN;
        baseSeed.executionOwner = "owner-a3-running";
        baseSeed.leaseExpiresAt = EXPIRES_AT;
        baseSeed.startedAt = REVIEWED_AT;
        baseSeed.dispatchStartedAt = null;
        baseSeed.finishedAt = null;
        baseSeed.outcomeCertainty = null;
        baseSeed.lastErrorCode = null;
        baseSeed.lastErrorMessage = null;
        baseSeed.executedAt = null;
      } else if (seed.status === "executed") {
        // Terminalization cleared the bearer capability columns.
        baseSeed.executionToken = null;
        baseSeed.executionOwner = null;
        baseSeed.leaseExpiresAt = null;
        baseSeed.startedAt = REVIEWED_AT;
        baseSeed.dispatchStartedAt = DISPATCHED_AT;
        baseSeed.finishedAt = FINISHED_AT;
        baseSeed.outcomeCertainty = "success";
        baseSeed.lastErrorCode = null;
        baseSeed.lastErrorMessage = null;
        baseSeed.executedAt = FINISHED_AT;
      } else if (seed.status === "blocked") {
        // Blocked retains the approval pointer + planned hashes on
        // the action, but the underlying review is invalidated.
        // No execution columns: blocked is not a finished execution
        // and has no error to report (the review carries the reason).
        baseSeed.executionToken = null;
        baseSeed.executionOwner = null;
        baseSeed.leaseExpiresAt = null;
        baseSeed.startedAt = null;
        baseSeed.dispatchStartedAt = null;
        baseSeed.finishedAt = null;
        baseSeed.outcomeCertainty = null;
        baseSeed.lastErrorCode = null;
        baseSeed.lastErrorMessage = null;
        baseSeed.executedAt = null;
      } else if (seed.status === "failed") {
        // failed/not_dispatched: NO dispatch marker, NO executed_at.
        baseSeed.executionToken = null;
        baseSeed.executionOwner = null;
        baseSeed.leaseExpiresAt = null;
        baseSeed.startedAt = REVIEWED_AT;
        baseSeed.dispatchStartedAt = null;
        baseSeed.finishedAt = FINISHED_AT;
        baseSeed.outcomeCertainty = "not_dispatched";
        baseSeed.lastErrorCode = "ACTION_LEASE_EXPIRED";
        baseSeed.lastErrorMessage = SECRET_LAST_ERROR_MESSAGE;
        baseSeed.executedAt = null;
      } else if (seed.status === "outcome_unknown") {
        baseSeed.executionToken = null;
        baseSeed.executionOwner = null;
        baseSeed.leaseExpiresAt = null;
        baseSeed.startedAt = REVIEWED_AT;
        baseSeed.dispatchStartedAt = DISPATCHED_AT;
        baseSeed.finishedAt = FINISHED_AT;
        baseSeed.outcomeCertainty = "possibly_dispatched";
        baseSeed.lastErrorCode = "ACTION_FINALIZE_RACE";
        baseSeed.lastErrorMessage = SECRET_LAST_ERROR_MESSAGE;
        baseSeed.executedAt = null;
      }

      insertRawV2Action(handle, baseSeed);

      // Snapshot action + every review row BEFORE the reject.
      const beforeAction = readActionRow(handle, seed.actionId);
      const beforeReviews = handle
        .prepare("SELECT * FROM action_reviews ORDER BY id ASC")
        .all() as Array<Record<string, unknown>>;
      const beforeReviewCount = beforeReviews.length;

      let captured: unknown = null;
      try {
        queue.approve(seed.actionId);
      } catch (err) {
        captured = err;
      }
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_SERVICE_REQUIRED");

      // Deep equality on the action row, byte-identical. This
      // proves the rejection caused ZERO mutation, not just
      // status-preservation.
      const afterAction = readActionRow(handle, seed.actionId);
      expect(afterAction).toEqual(beforeAction);

      // Review rows: same count and same identity.
      const afterReviews = handle
        .prepare("SELECT * FROM action_reviews ORDER BY id ASC")
        .all() as Array<Record<string, unknown>>;
      expect(afterReviews.length).toBe(beforeReviewCount);
      expect(afterReviews).toEqual(beforeReviews);
    });
  }
});

// ---------------------------------------------------------------------------
// A4: raw v2 action row -> generic ActionRecord maps requiredForCompletion
//     and the v2 lifecycle audit fields, but has no OWN executionToken
//     property and JSON.stringify(...) must not contain the token value.
// ---------------------------------------------------------------------------

describe("A4: generic ActionRecord maps every v2 field but never exposes the execution token", () => {
  it("requiredForCompletion: 1 -> true", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-rfc-1",
      jobId: "job-a4-rfc-1",
      status: "pending",
      requiredForCompletion: 1,
    });

    const record = queue.get("act-a4-rfc-1") as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.requiredForCompletion).toBe(true);
  });

  it("requiredForCompletion: 0 -> false", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-rfc-0",
      jobId: "job-a4-rfc-0",
      status: "pending",
      requiredForCompletion: 0,
    });

    const record = queue.get("act-a4-rfc-0") as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.requiredForCompletion).toBe(false);
  });

  it("requiredForCompletion: 2 (invalid stored value) -> get() throws ACTION_RECORD_INVALID", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-rfc-bad",
      jobId: "job-a4-rfc-bad",
      status: "pending",
      // SQLite accepts any INTEGER; the production read model must
      // fail closed on anything other than 0 or 1.
      requiredForCompletion: 2 as unknown as 0 | 1,
    });

    let captured: unknown = null;
    try {
      queue.get("act-a4-rfc-bad");
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_RECORD_INVALID");
  });

  it("list() decodes requiredForCompletion: 0 -> false", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-rfc-list-0",
      jobId: "job-a4-rfc-list-0",
      status: "pending",
      requiredForCompletion: 0,
    });

    const list = queue.list("job-a4-rfc-list-0") as V2ActionRecord[];
    expect(list.length).toBe(1);
    expect(list[0].requiredForCompletion).toBe(false);
  });

  it("list() decodes requiredForCompletion: 1 -> true", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-rfc-list-1",
      jobId: "job-a4-rfc-list-1",
      status: "pending",
      requiredForCompletion: 1,
    });

    const list = queue.list("job-a4-rfc-list-1") as V2ActionRecord[];
    expect(list.length).toBe(1);
    expect(list[0].requiredForCompletion).toBe(true);
  });

  it("list() throws ACTION_RECORD_INVALID when ANY row has requiredForCompletion=2 (list cannot use a divergent mapper)", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-rfc-list-bad-a",
      jobId: "job-a4-rfc-list-bad",
      status: "pending",
      requiredForCompletion: 1,
    });
    insertRawV2Action(handle, {
      id: "act-a4-rfc-list-bad-b",
      jobId: "job-a4-rfc-list-bad",
      status: "pending",
      requiredForCompletion: 2 as unknown as 0 | 1,
    });

    let captured: unknown = null;
    try {
      queue.list("job-a4-rfc-list-bad");
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_RECORD_INVALID");
  });

  it("executed terminal action preserves the legacy executedAt timestamp", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-exec",
      jobId: "job-a4-exec",
      status: "executed",
      requiredForCompletion: 1,
    });
    handle
      .prepare("UPDATE actions SET executed_at = ? WHERE id = ?")
      .run(FINISHED_AT, "act-a4-exec");

    const record = queue.get("act-a4-exec") as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.status).toBe("executed");
    expect(record!.executedAt).toBe(FINISHED_AT);
  });

  it("running action with execution token: no own executionToken on get, JSON never contains the token", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const jobId = "job-a4-running";
    const actionId = "act-a4-running";
    const reviewId = "rev-a4-running";

    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      source: "human",
      reviewerId: REVIEWER_ID,
    });
    insertRawV2Action(handle, {
      id: actionId,
      jobId,
      status: "running",
      requiredForCompletion: 1,
      activeReviewId: reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
      executionToken: SECRET_TOKEN,
      executionOwner: "owner-a4-running",
      leaseExpiresAt: EXPIRES_AT,
      startedAt: REVIEWED_AT,
      // Deliberately NO finishedAt: a still-running action must not
      // have a finished_at. Split from the legacy terminal case above.
    });

    const record = queue.get(actionId) as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    // Contract: a generic ActionRecord has no own "executionToken".
    expect(Object.prototype.hasOwnProperty.call(record, "executionToken")).toBe(false);
    const json = JSON.stringify(record);
    expect(json).not.toContain(SECRET_TOKEN);
    expect(json).not.toMatch(/executionToken/i);
  });

  it("list() of a job containing a running action also never exposes the execution token", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const jobId = "job-a4-list";
    const actionId = "act-a4-list";
    const reviewId = "rev-a4-list";

    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      source: "human",
      reviewerId: REVIEWER_ID,
    });
    insertRawV2Action(handle, {
      id: actionId,
      jobId,
      status: "running",
      requiredForCompletion: 1,
      activeReviewId: reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
      executionToken: SECRET_TOKEN,
      executionOwner: "owner-a4-list",
      leaseExpiresAt: EXPIRES_AT,
      startedAt: REVIEWED_AT,
    });

    const list = queue.list(jobId) as V2ActionRecord[];
    // Strengthen: exact length=1, exact id, every non-secret
    // running field mapped, requiredForCompletion true.
    expect(list.length).toBe(1);
    const rec = list[0];
    expect(rec.id).toBe(actionId);
    expect(rec.status).toBe("running");
    expect(rec.requiredForCompletion).toBe(true);
    expect(rec.activeReviewId).toBe(reviewId);
    expect(rec.plannedScopeHash).toBe(SCOPE_HASH);
    expect(rec.plannedPolicyHash).toBe(POLICY_HASH);
    expect(rec.plannedActionHash).toBe(ACTION_HASH);
    expect(rec.plannedContextHash).toBe(CONTEXT_HASH);
    expect(rec.executionOwner).toBe("owner-a4-list");
    expect(rec.leaseExpiresAt).toBe(EXPIRES_AT);
    expect(rec.startedAt).toBe(REVIEWED_AT);

    // Token exclusion via hasOwnProperty + JSON, never direct access.
    expect(Object.prototype.hasOwnProperty.call(rec, "executionToken")).toBe(false);
    const json = JSON.stringify(rec);
    expect(json).not.toContain(SECRET_TOKEN);
    expect(json).not.toMatch(/executionToken/i);
  });

  it("lastErrorCode + redacted lastErrorMessage on a FAILED/NOT_DISPATCHED terminal row", () => {
    // A failed terminal row keeps audit fields (started/finished,
    // outcome=not_dispatched, lastError*) but the bearer capability
    // columns (token/owner/lease) AND the dispatch marker AND
    // executed_at are absent. Redaction is read-time and preserves
    // public text.
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-err",
      jobId: "job-a4-err",
      status: "failed",
      requiredForCompletion: 1,
      startedAt: REVIEWED_AT,
      finishedAt: FINISHED_AT,
      outcomeCertainty: "not_dispatched",
      lastErrorCode: "ACTION_LEASE_EXPIRED",
      lastErrorMessage: SECRET_LAST_ERROR_MESSAGE,
      // Explicit updatedAt null for the legacy fallback.
      updatedAt: null,
    });

    const record = queue.get("act-a4-err") as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.status).toBe("failed");
    expect(record!.lastErrorCode).toBe("ACTION_LEASE_EXPIRED");
    expect(record!.lastErrorMessage).toBe(REDACTED_LAST_ERROR_MESSAGE);
    expect(record!.lastErrorMessage).toContain("[REDACTED]");
    expect(record!.lastErrorMessage).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(record!.lastErrorMessage).toContain("slice-a public text");
    // Failed terminal: dispatch marker absent.
    expect(record!.dispatchStartedAt).toBeUndefined();
    // Bearer capability columns absent on a failed row.
    expect(Object.prototype.hasOwnProperty.call(record, "executionToken")).toBe(false);
    // executedAt absent on a failed row (failure is not a successful execution).
    expect(record!.executedAt).toBeUndefined();
  });

  it("supersedesActionId is exposed on the v2 record (pending)", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-supersedes",
      jobId: "job-a4-supersedes",
      status: "pending",
      requiredForCompletion: 1,
      supersedesActionId: "act-a4-old",
    });

    const record = queue.get("act-a4-supersedes") as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.supersedesActionId).toBe("act-a4-old");
  });

  it("updatedAt is exposed on the v2 record (pending)", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-updated",
      jobId: "job-a4-updated",
      status: "pending",
      requiredForCompletion: 1,
      updatedAt: UPDATED_AT,
    });

    const record = queue.get("act-a4-updated") as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.updatedAt).toBe(UPDATED_AT);
  });

  it("RUNNING lifecycle row: active review + hashes + token + owner + lease + startedAt + dispatchStartedAt; no terminal fields", () => {
    // A running row is mid-execution. It carries the bearer
    // capability, lease, startedAt, and (optionally) dispatchStartedAt
    // but must NOT carry finishedAt, outcome, lastError*, or
    // executedAt — those belong to terminal rows.
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const jobId = "job-a4-running-lifecycle";
    const actionId = "act-a4-running-lifecycle";
    const reviewId = "rev-a4-running-lifecycle";

    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      source: "human",
      reviewerId: REVIEWER_ID,
    });
    insertRawV2Action(handle, {
      id: actionId,
      jobId,
      status: "running",
      requiredForCompletion: 1,
      activeReviewId: reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
      executionToken: SECRET_TOKEN,
      executionOwner: "owner-a4-running",
      leaseExpiresAt: EXPIRES_AT,
      startedAt: REVIEWED_AT,
      dispatchStartedAt: DISPATCHED_AT,
    });

    const record = queue.get(actionId) as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.status).toBe("running");
    expect(record!.requiredForCompletion).toBe(true);
    expect(record!.activeReviewId).toBe(reviewId);
    expect(record!.plannedScopeHash).toBe(SCOPE_HASH);
    expect(record!.plannedPolicyHash).toBe(POLICY_HASH);
    expect(record!.plannedActionHash).toBe(ACTION_HASH);
    expect(record!.plannedContextHash).toBe(CONTEXT_HASH);
    expect(record!.executionOwner).toBe("owner-a4-running");
    expect(record!.leaseExpiresAt).toBe(EXPIRES_AT);
    expect(record!.startedAt).toBe(REVIEWED_AT);
    expect(record!.dispatchStartedAt).toBe(DISPATCHED_AT);

    // Terminal fields are explicitly absent on a running row.
    expect(record!.finishedAt).toBeUndefined();
    expect(record!.outcomeCertainty).toBeUndefined();
    expect(record!.lastErrorCode).toBeUndefined();
    expect(record!.lastErrorMessage).toBeUndefined();
    expect(record!.executedAt).toBeUndefined();

    // Token exclusion holds — proved by absence, never by reading
    // the field. V2ActionRecord has no executionToken property.
    expect(Object.prototype.hasOwnProperty.call(record, "executionToken")).toBe(false);
    const json = JSON.stringify(record);
    expect(json).not.toContain(SECRET_TOKEN);
    expect(json).not.toMatch(/executionToken/i);
  });

  it("EXECUTED/SUCCESS terminal row: active review + hashes retained, token/owner/lease cleared, started/dispatch/finished + executedAt, updatedAt + supersedes asserted", () => {
    // After finalize(success) the bearer capability columns are
    // cleared but the approval pointer, planned hashes, and audit
    // timestamps are retained. The legacy executedAt is preserved
    // alongside the new finishedAt.
    const handle = openDb();
    const queue = new ActionQueue(handle);
    const jobId = "job-a4-executed-lifecycle";
    const actionId = "act-a4-executed-lifecycle";
    const reviewId = "rev-a4-executed-lifecycle";

    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      source: "human",
      reviewerId: REVIEWER_ID,
    });
    insertRawV2Action(handle, {
      id: actionId,
      jobId,
      status: "executed",
      requiredForCompletion: 1,
      activeReviewId: reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
      startedAt: REVIEWED_AT,
      dispatchStartedAt: DISPATCHED_AT,
      finishedAt: FINISHED_AT,
      outcomeCertainty: "success",
      updatedAt: UPDATED_AT,
      supersedesActionId: "act-a4-old",
    });
    handle
      .prepare("UPDATE actions SET executed_at = ? WHERE id = ?")
      .run(FINISHED_AT, actionId);

    const record = queue.get(actionId) as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.status).toBe("executed");
    expect(record!.requiredForCompletion).toBe(true);
    expect(record!.activeReviewId).toBe(reviewId);
    expect(record!.plannedScopeHash).toBe(SCOPE_HASH);
    expect(record!.plannedPolicyHash).toBe(POLICY_HASH);
    expect(record!.plannedActionHash).toBe(ACTION_HASH);
    expect(record!.plannedContextHash).toBe(CONTEXT_HASH);
    expect(record!.startedAt).toBe(REVIEWED_AT);
    expect(record!.dispatchStartedAt).toBe(DISPATCHED_AT);
    expect(record!.finishedAt).toBe(FINISHED_AT);
    expect(record!.outcomeCertainty).toBe("success");
    expect(record!.updatedAt).toBe(UPDATED_AT);
    expect(record!.supersedesActionId).toBe("act-a4-old");
    expect(record!.executedAt).toBe(FINISHED_AT);

    // Bearer capability columns cleared on terminalization.
    expect(Object.prototype.hasOwnProperty.call(record, "executionToken")).toBe(false);
    expect(record!.executionOwner).toBeUndefined();
    expect(record!.leaseExpiresAt).toBeUndefined();
    // Errors absent on success.
    expect(record!.lastErrorCode).toBeUndefined();
    expect(record!.lastErrorMessage).toBeUndefined();
  });

  it("legacy terminal updatedAt fallback: raw updated_at NULL + executed_at non-null -> public updatedAt equals executedAt", () => {
    // Legacy rows written before v2 may have updated_at NULL and a
    // non-null executed_at. The read model must surface executedAt
    // as updatedAt so callers can rely on updatedAt alone for
    // terminal timestamps.
    const handle = openDb();
    const queue = new ActionQueue(handle);
    insertRawV2Action(handle, {
      id: "act-a4-legacy-updated",
      jobId: "job-a4-legacy-updated",
      status: "executed",
      requiredForCompletion: 1,
      // Explicit raw null on updated_at — do NOT use the default.
      updatedAt: null,
    });
    handle
      .prepare("UPDATE actions SET executed_at = ? WHERE id = ?")
      .run(FINISHED_AT, "act-a4-legacy-updated");

    const record = queue.get("act-a4-legacy-updated") as V2ActionRecord | undefined;
    expect(record).toBeDefined();
    expect(record!.executedAt).toBe(FINISHED_AT);
    expect(record!.updatedAt).toBe(FINISHED_AT);
    // createdAt preservation: legacy rows must still expose the
    // original createdAt.
    expect(record!.createdAt).toBe(CREATED_AT);
  });
});

// ---------------------------------------------------------------------------
// A5: malformed v2 "approved" row (no structurally complete active review)
//     must make get() and list() fail closed with ACTION_APPROVAL_INVALID.
// ---------------------------------------------------------------------------

describe("A5: malformed approved row makes get and list fail closed with ACTION_APPROVAL_INVALID", () => {
  // Seed a structurally valid approved action+review so each broken
  // variant has a known-good baseline. Uses far-future timestamps:
  // structural read validation does not exercise the live clock.
  function seedValidApproved(
    handle: BountyDatabase,
    opts: { jobId: string; actionId: string; reviewId: string; source: "human" | "policy"; reviewerId: string },
  ): void {
    insertValidActiveReview(handle, {
      id: opts.reviewId,
      actionId: opts.actionId,
      jobId: opts.jobId,
      source: opts.source,
      reviewerId: opts.reviewerId,
    });
    insertRawV2Action(handle, {
      id: opts.actionId,
      jobId: opts.jobId,
      status: "approved",
      requiredForCompletion: 1,
      activeReviewId: opts.reviewId,
      plannedScopeHash: SCOPE_HASH,
      plannedPolicyHash: POLICY_HASH,
      plannedActionHash: ACTION_HASH,
      plannedContextHash: CONTEXT_HASH,
    });
  }

  it("valid HUMAN approved row: get() and list() return a record with requiredForCompletion + activeReviewId + all four planned hashes", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    seedValidApproved(handle, {
      jobId: "job-a5-valid-human",
      actionId: "act-a5-valid-human",
      reviewId: "rev-a5-valid-human",
      source: "human",
      reviewerId: REVIEWER_ID,
    });

    const got = queue.get("act-a5-valid-human") as V2ActionRecord | undefined;
    expect(got).toBeDefined();
    expect(got!.status).toBe("approved");
    expect(got!.requiredForCompletion).toBe(true);
    expect(got!.activeReviewId).toBe("rev-a5-valid-human");
    expect(got!.plannedScopeHash).toBe(SCOPE_HASH);
    expect(got!.plannedPolicyHash).toBe(POLICY_HASH);
    expect(got!.plannedActionHash).toBe(ACTION_HASH);
    expect(got!.plannedContextHash).toBe(CONTEXT_HASH);

    const listed = queue.list("job-a5-valid-human") as V2ActionRecord[];
    expect(listed.length).toBe(1);
    const rec = listed[0];
    expect(rec.id).toBe("act-a5-valid-human");
    expect(rec.status).toBe("approved");
    expect(rec.requiredForCompletion).toBe(true);
    expect(rec.activeReviewId).toBe("rev-a5-valid-human");
    expect(rec.plannedScopeHash).toBe(SCOPE_HASH);
    expect(rec.plannedPolicyHash).toBe(POLICY_HASH);
    expect(rec.plannedActionHash).toBe(ACTION_HASH);
    expect(rec.plannedContextHash).toBe(CONTEXT_HASH);
  });

  it("valid POLICY approved row: get() and list() return a record with requiredForCompletion + activeReviewId + all four planned hashes", () => {
    const handle = openDb();
    const queue = new ActionQueue(handle);
    seedValidApproved(handle, {
      jobId: "job-a5-valid-policy",
      actionId: "act-a5-valid-policy",
      reviewId: "rev-a5-valid-policy",
      source: "policy",
      reviewerId: POLICY_REVIEWER_ID,
    });

    const got = queue.get("act-a5-valid-policy") as V2ActionRecord | undefined;
    expect(got).toBeDefined();
    expect(got!.status).toBe("approved");
    expect(got!.requiredForCompletion).toBe(true);
    expect(got!.activeReviewId).toBe("rev-a5-valid-policy");
    expect(got!.plannedScopeHash).toBe(SCOPE_HASH);
    expect(got!.plannedPolicyHash).toBe(POLICY_HASH);
    expect(got!.plannedActionHash).toBe(ACTION_HASH);
    expect(got!.plannedContextHash).toBe(CONTEXT_HASH);

    const listed = queue.list("job-a5-valid-policy") as V2ActionRecord[];
    expect(listed.length).toBe(1);
    const rec = listed[0];
    expect(rec.id).toBe("act-a5-valid-policy");
    expect(rec.status).toBe("approved");
    expect(rec.requiredForCompletion).toBe(true);
    expect(rec.activeReviewId).toBe("rev-a5-valid-policy");
    expect(rec.plannedScopeHash).toBe(SCOPE_HASH);
    expect(rec.plannedPolicyHash).toBe(POLICY_HASH);
    expect(rec.plannedActionHash).toBe(ACTION_HASH);
    expect(rec.plannedContextHash).toBe(CONTEXT_HASH);
  });

  // Each broken variant describes one structural mutation. The base
  // human-approved seed is used; the action's planned hashes and
  // active_review_id are adjusted as needed.
  type Mutation = (db: BountyDatabase, ctx: { actionId: string; reviewId: string; jobId: string }) => void;

  interface BrokenVariant {
    name: string;
    mutate: Mutation;
    // Optional override: when the variant mutates the action or
    // review's job_id, list() must be called with that exact job.
    // Defaults to baseJob. Used by the whitespace-job and
    // null-review-job variants below.
    listJobId?: string;
  }

  // The 4 hash columns on either side. We need to break both "null on
  // action" and "mismatched value" for each.
  const hashColumns: ReadonlyArray<"scope" | "policy" | "action" | "context"> = ["scope", "policy", "action", "context"];
  const HASH_BY_COLUMN: Record<"scope" | "policy" | "action" | "context", string> = {
    scope: SCOPE_HASH,
    policy: POLICY_HASH,
    action: ACTION_HASH,
    context: CONTEXT_HASH,
  };
  const PLANNED_BY_COLUMN: Record<"scope" | "policy" | "action" | "context", string> = {
    scope: "planned_scope_hash",
    policy: "planned_policy_hash",
    action: "planned_action_hash",
    context: "planned_context_hash",
  };
  const REVIEW_BY_COLUMN: Record<"scope" | "policy" | "action" | "context", string> = {
    scope: "scope_hash",
    policy: "policy_hash",
    action: "action_hash",
    context: "context_hash",
  };

  const baseJob = "job-a5-broken";
  const baseAction = "act-a5-broken";
  const baseReview = "rev-a5-broken";

  function freshSeedValidApproved(handle: BountyDatabase): void {
    // Each test variant uses a unique job/action/review id so the
    // variants do not collide. We pass ids in via ctx and rely on
    // the caller to open a fresh handle per test (it() does).
    seedValidApproved(handle, {
      jobId: baseJob,
      actionId: baseAction,
      reviewId: baseReview,
      source: "human",
      reviewerId: REVIEWER_ID,
    });
  }

  const BROKEN_VARIANTS: BrokenVariant[] = [
    { name: "null active review", mutate: (db, ctx) => {
        db.prepare("UPDATE actions SET active_review_id = NULL WHERE id = ?").run(ctx.actionId);
      } },
    { name: "missing review (active_review_id points to nonexistent row)", mutate: (db, ctx) => {
        db.prepare("UPDATE actions SET active_review_id = 'rev-does-not-exist' WHERE id = ?").run(ctx.actionId);
      } },
    { name: "action mismatch (review.action_id != action.id)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET action_id = 'act-some-other' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "job mismatch (review.job_id != action.job_id)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET job_id = 'job-some-other' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "wrong decision (decision='blocked')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET decision = 'blocked' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "wrong decision (decision='executed')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET decision = 'executed' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "wrong decision (decision='failed')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET decision = 'failed' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "invalidated review (invalidated_at set)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET invalidated_at = '2099-01-01T00:05:00.000Z', invalidation_reason = 'expired' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "empty reviewer (reviewer_id='')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewer_id = '' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "null reviewer (reviewer_id=NULL)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewer_id = NULL WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "missing/empty reviewedAt (reviewed_at='')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = '' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "null reviewedAt (reviewed_at=NULL)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = NULL WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "missing/empty expiresAt (expires_at='')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET expires_at = '' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "null expiresAt (expires_at=NULL)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET expires_at = NULL WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "invalid source (source='invalid')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET source = 'invalid' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "policy reviewer not system:policy-gate", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET source = 'policy', reviewer_id = 'someone-else' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "human reviewer equal system:policy-gate", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET source = 'human', reviewer_id = ? WHERE id = ?").run(POLICY_REVIEWER_ID, ctx.reviewId);
      } },
    // Whitespace-only human reviewer.
    { name: "whitespace-only human reviewer (reviewer_id='   ')", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewer_id = '   ' WHERE id = ?").run(ctx.reviewId);
      } },
    // Reviewer containing a control character (0x01).
    { name: "reviewer with control character (reviewer_id includes 0x01)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewer_id = ? WHERE id = ?").run(`evil\u0001reviewer`, ctx.reviewId);
      } },
    // source = NULL.
    { name: "null source (source=NULL)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET source = NULL WHERE id = ?").run(ctx.reviewId);
      } },
  ];

  // Malformed-but-same-length hash variants for each of the four
  // hash columns, applied to BOTH the action side and the review
  // side. Values are still 64 chars where applicable; the defect is
  // wrong length, uppercase, non-hex, or 64-zero.
  const MALFORMED_HASH_VALUES: ReadonlyArray<{ kind: string; value: string }> = [
    { kind: "wrong length (63 hex)", value: hex64("bad-len-63").slice(0, -1) },
    { kind: "wrong length (65 hex)", value: hex64("bad-len-65") + "0" },
    { kind: "uppercase hex", value: SCOPE_HASH.toUpperCase() },
    { kind: "non-hex (contains 'z')", value: "z".repeat(64) },
    { kind: "64 all-zero lowercase hex", value: "0".repeat(64) },
  ];

  for (const col of hashColumns) {
    BROKEN_VARIANTS.push({
      name: `null ${col} hash on action (planned_${col}_hash = NULL)`,
      mutate: (db, ctx) => {
        db.prepare(`UPDATE actions SET ${PLANNED_BY_COLUMN[col]} = NULL WHERE id = ?`).run(ctx.actionId);
      },
    });
    BROKEN_VARIANTS.push({
      name: `null ${col} hash on review (${REVIEW_BY_COLUMN[col]} = NULL)`,
      mutate: (db, ctx) => {
        db.prepare(`UPDATE action_reviews SET ${REVIEW_BY_COLUMN[col]} = NULL WHERE id = ?`).run(ctx.reviewId);
      },
    });
    // Mismatch on the ACTION side: planned_*_hash differs from the
    // review's stored value. The new value is a valid 64-lowercase
    // hex that is NOT equal to the review's hash.
    BROKEN_VARIANTS.push({
      name: `mismatched ${col} hash on ACTION (planned differs from review; both still 64-hex)`,
      mutate: (db, ctx) => {
        // Build a 64-hex value that is definitely not the review's
        // stored value: flip the last hex char.
        const reviewVal = HASH_BY_COLUMN[col];
        const flipped = reviewVal.slice(0, -1) + (reviewVal.slice(-1) === "0" ? "1" : "0");
        db.prepare(`UPDATE actions SET ${PLANNED_BY_COLUMN[col]} = ? WHERE id = ?`).run(flipped, ctx.actionId);
      },
    });
    // Mismatch on the REVIEW side: review hash differs from the
    // action's planned_*_hash. The new value is a valid 64-hex that
    // is NOT equal to the action's planned hash.
    BROKEN_VARIANTS.push({
      name: `mismatched ${col} hash on REVIEW (review differs from planned; both still 64-hex)`,
      mutate: (db, ctx) => {
        const plannedVal = HASH_BY_COLUMN[col];
        const flipped = plannedVal.slice(0, -1) + (plannedVal.slice(-1) === "0" ? "1" : "0");
        db.prepare(`UPDATE action_reviews SET ${REVIEW_BY_COLUMN[col]} = ? WHERE id = ?`).run(flipped, ctx.reviewId);
      },
    });

    for (const bad of MALFORMED_HASH_VALUES) {
      // Matching-but-malformed: the SAME malformed value is written
      // to BOTH actions.planned_*_hash and action_reviews.*_hash.
      // The structural predicate must reject this on shape (wrong
      // length / uppercase / non-hex / all-zero) alone, not merely
      // on a mismatch between the two sides.
      BROKEN_VARIANTS.push({
        name: `matching-but-malformed ${col} hash on BOTH action and review (${bad.kind})`,
        mutate: (db, ctx) => {
          db.prepare(`UPDATE actions SET ${PLANNED_BY_COLUMN[col]} = ? WHERE id = ?`).run(bad.value, ctx.actionId);
          db.prepare(`UPDATE action_reviews SET ${REVIEW_BY_COLUMN[col]} = ? WHERE id = ?`).run(bad.value, ctx.reviewId);
        },
      });
    }
  }

  // Noncanonical timestamps: parseable-but-noncanonical + truly
  // invalid + boundary ordering. Structural validation does not
  // depend on the live clock; canonical ISO-8601 UTC formatting
  // itself is pinned.
  const NONCANONICAL_REVIEWED_AT = "2099-01-01T00:00:00Z"; // missing milliseconds
  const NONCANONICAL_EXPIRES_AT = "2099-01-01T00:15:00Z"; // missing milliseconds
  BROKEN_VARIANTS.push(
    { name: "noncanonical reviewed_at (parseable but missing '.000' milliseconds)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = ? WHERE id = ?").run(NONCANONICAL_REVIEWED_AT, ctx.reviewId);
      } },
    { name: "noncanonical expires_at (parseable but missing '.000' milliseconds)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET expires_at = ? WHERE id = ?").run(NONCANONICAL_EXPIRES_AT, ctx.reviewId);
      } },
    { name: "noncanonical reviewed_at and expires_at (both missing milliseconds, still parseable)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = ?, expires_at = ? WHERE id = ?").run(NONCANONICAL_REVIEWED_AT, NONCANONICAL_EXPIRES_AT, ctx.reviewId);
      } },
    { name: "noncanonical reviewed_at (not ISO-8601)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = 'not-a-date' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "noncanonical expires_at (not ISO-8601)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET expires_at = '2099-13-99T99:99:99.999Z' WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "expires_at == reviewed_at (boundary, must be strictly later)", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = ?, expires_at = ? WHERE id = ?").run(REVIEWED_AT, REVIEWED_AT, ctx.reviewId);
      } },
    { name: "expires_at earlier than reviewed_at", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET reviewed_at = ?, expires_at = ? WHERE id = ?").run("2099-01-01T00:15:00.000Z", "2099-01-01T00:00:00.000Z", ctx.reviewId);
      } },
  );

  // Concrete job validation: both sides carry a whitespace job_id
  // (single space). The list test must call list() with that
  // EXACT whitespace job — not the base job — to exercise the
  // structural predicate on the real row.
  const WHITESPACE_JOB = " ";
  BROKEN_VARIANTS.push({
    name: "whitespace-only job_id on both action and review (list uses exact whitespace job)",
    mutate: (db, ctx) => {
      db.prepare("UPDATE actions SET job_id = ? WHERE id = ?").run(WHITESPACE_JOB, ctx.actionId);
      db.prepare("UPDATE action_reviews SET job_id = ? WHERE id = ?").run(WHITESPACE_JOB, ctx.reviewId);
    },
    listJobId: WHITESPACE_JOB,
  });

  // Matched empty-string job_id: BOTH action and review carry
  // job_id = ''. list() must be called with the exact empty string
  // (not the base job) to exercise the predicate on the real row.
  BROKEN_VARIANTS.push({
    name: "matched empty-string job_id on both action and review (list uses exact empty string)",
    mutate: (db, ctx) => {
      db.prepare("UPDATE actions SET job_id = '' WHERE id = ?").run(ctx.actionId);
      db.prepare("UPDATE action_reviews SET job_id = '' WHERE id = ?").run(ctx.reviewId);
    },
    listJobId: "",
  });

  // Null/blank review job: review's job_id is NULL (or '') while the
  // action keeps a real job. The action is still selectable, so
  // list() is called with baseJob and both get/list must fail.
  BROKEN_VARIANTS.push(
    { name: "null review.job_id while action.job_id is real", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET job_id = NULL WHERE id = ?").run(ctx.reviewId);
      } },
    { name: "blank review.job_id ('') while action.job_id is real", mutate: (db, ctx) => {
        db.prepare("UPDATE action_reviews SET job_id = '' WHERE id = ?").run(ctx.reviewId);
      } },
  );

  for (const variant of BROKEN_VARIANTS) {
    const listJob = variant.listJobId ?? baseJob;

    it(`get() throws ACTION_APPROVAL_INVALID for broken: ${variant.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      freshSeedValidApproved(handle);
      variant.mutate(handle, { actionId: baseAction, reviewId: baseReview, jobId: baseJob });

      let captured: unknown = null;
      try {
        queue.get(baseAction);
      } catch (err) {
        captured = err;
      }
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_INVALID");
    });

    it(`list() throws ACTION_APPROVAL_INVALID for broken: ${variant.name}`, () => {
      const handle = openDb();
      const queue = new ActionQueue(handle);
      freshSeedValidApproved(handle);
      variant.mutate(handle, { actionId: baseAction, reviewId: baseReview, jobId: baseJob });

      let captured: unknown = null;
      try {
        queue.list(listJob);
      } catch (err) {
        captured = err;
      }
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_INVALID");
    });
  }
});

// ---------------------------------------------------------------------------
// A6: ActionReviewStore.insertApprovalInTransaction — in-transaction primitive
//     that requires an active transaction, persists every required field
//     exactly, and never begins a nested transaction of its own.
// ---------------------------------------------------------------------------

describe("A6: ActionReviewStore.insertApprovalInTransaction is an in-tx primitive with full v2 validation", () => {
  // Secrets used in the A6 suite. The note carries a secret that must
  // never reach persisted columns or returned records.
  const A6_NOTE_PUBLIC_PREFIX = "public-prefix";
  const A6_NOTE_PUBLIC_SUFFIX = "public-suffix";
  const A6_NOTE_SECRET = "SUPERSECRET";
  const A6_SECRET_NOTE = `${A6_NOTE_PUBLIC_PREFIX} api_key=${A6_NOTE_SECRET} ${A6_NOTE_PUBLIC_SUFFIX}`;
  // Exact redacted note: write-time + read-time masking must produce
  // this canonical form (preserve public prefix/suffix, replace the
  // api_key=VALUE assignment with api_key=[REDACTED]).
  const A6_REDACTED_NOTE = `${A6_NOTE_PUBLIC_PREFIX} api_key=[REDACTED] ${A6_NOTE_PUBLIC_SUFFIX}`;

  // Store-generated review ID prefix per the project convention.
  const REVIEW_ID_PATTERN = /^review-/;

  // Caller-controlled probe value used to assert the store REJECTS a
  // runtime-cast caller-supplied id. Per Slice A contract, an own id
  // property on the public input is rejected with
  // ACTION_APPROVAL_INVALID and zero writes.
  const CALLER_SUPPLIED_ID = "caller-controlled-rev";
  const SOMEONE_ELSE_POLICY_REVIEWER = "someone-else";

  // Reviewer with 257 code points (one above the 1..256 cap). Use
  // ASCII so length === code points for the rejection test.
  const A6_REVIEWER_257 = "a".repeat(257);

  // Reviewer with EXACTLY 256 Unicode code points, but each code
  // point is an emoji that is a surrogate pair in UTF-16. An
  // incorrect `string.length` (UTF-16 code units) check would see
  // 512, not 256, and would reject this valid boundary input. The
  // store must count code points, not code units.
  const A6_EMOJI_256 = "\u{1F600}".repeat(256); // 256 grinning-face code points, 512 UTF-16 code units

  // Canonical form expected after read-back: must round-trip exactly
  // through Date.toISOString(). A value produced by
  // new Date().toISOString() is used so the round-trip is provable.
  const A6_CANONICAL_REVIEWED_AT = new Date("2099-01-01T00:00:00.000Z").toISOString();
  const A6_CANONICAL_EXPIRES_AT = new Date("2099-01-01T00:15:00.000Z").toISOString();

  // Parseable-but-noncanonical timestamp variants (missing the
  // `.000` millisecond suffix). Canonical formatting is pinned.
  const A6_NONCANONICAL_REVIEWED_AT = "2099-01-01T00:00:00Z";
  const A6_NONCANONICAL_EXPIRES_AT = "2099-01-01T00:15:00Z";

  // Read-back probe: a fresh secret-bearing note we overwrite into
  // the row directly via SQL after a valid insert. listForAction
  // must mask the secret on read while preserving public text.
  const A6_RUNTIME_SECRET_NOTE = "runtime-public-prefix api_key=RUNTIME_SECRET runtime-public-suffix";

  function buildValidHumanBase(actionId: string, jobId: string): CompleteApprovalReviewInput {
    return {
      actionId,
      jobId,
      decision: "approved",
      // Surrounding whitespace must be trimmed and persisted canonically.
      reviewerId: `   ${REVIEWER_ID}   `,
      source: "human",
      reviewedAt: A6_CANONICAL_REVIEWED_AT,
      expiresAt: A6_CANONICAL_EXPIRES_AT,
      scopeHash: SCOPE_HASH,
      policyHash: POLICY_HASH,
      actionHash: ACTION_HASH,
      contextHash: CONTEXT_HASH,
      note: A6_SECRET_NOTE,
    };
  }

  function buildValidPolicyBase(actionId: string, jobId: string): CompleteApprovalReviewInput {
    return {
      actionId,
      jobId,
      decision: "approved",
      // Policy reviewer must be EXACTLY system:policy-gate.
      reviewerId: POLICY_REVIEWER_ID,
      source: "policy",
      reviewedAt: A6_CANONICAL_REVIEWED_AT,
      expiresAt: A6_CANONICAL_EXPIRES_AT,
      scopeHash: SCOPE_HASH,
      policyHash: POLICY_HASH,
      actionHash: ACTION_HASH,
      contextHash: CONTEXT_HASH,
    };
  }

  // A6-scoped safe descriptor save/restore helper for Object.prototype
  // mutations. Scoped to A6 (defined inside the A6 describe block) so
  // it cannot leak into other suites. The helper:
  //   - saves the EXACT current own-property descriptor of each named
  //     field on Object.prototype (or "ABSENT" if the field does not
  //     currently exist as an own property);
  //   - installs the caller-supplied descriptors;
  //   - runs `body()`;
  //   - in finally, restores absent properties via
  //     Reflect.deleteProperty and existing properties via
  //     Object.defineProperty, in the REVERSE order of installation.
  // No global state survives the call.
  const a6WithPrototypeDescriptors = (
    fieldDescriptors: Record<string, PropertyDescriptor>,
    body: () => void,
  ): void => {
    const proto = Object.prototype;
    const saved: Array<{ field: string; value: PropertyDescriptor | "ABSENT" }> = [];
    for (const field of Object.keys(fieldDescriptors)) {
      const existing = Object.getOwnPropertyDescriptor(proto, field);
      saved.push({ field, value: existing === undefined ? "ABSENT" : existing });
    }
    try {
      for (const [field, desc] of Object.entries(fieldDescriptors)) {
        Object.defineProperty(proto, field, desc);
      }
      body();
    } finally {
      for (let i = saved.length - 1; i >= 0; i--) {
        const { field, value } = saved[i]!;
        if (value === "ABSENT") {
          Reflect.deleteProperty(proto, field);
        } else {
          Object.defineProperty(proto, field, value);
        }
      }
    }
  };

  // Single source of truth for every v2 public field on a successful
  // insert. Used to assert BOTH the returned record and the
  // listForAction record. The same shape works for human and policy
  // happy paths.
  interface V2FieldExpectation {
    actionId: string;
    jobId: string;
    reviewerId: string;
    source: "human" | "policy";
    // Exact redacted note form to assert on the public record.
    // `undefined` means the public record must NOT expose a note at all.
    expectNote: string | undefined;
  }

  // Asserts every v2 public field on a returned OR listForAction
  // record. `label` distinguishes "returned" from "listed" in the
  // failure messages so a regression points at the right surface.
  function assertEveryV2PublicField(
    rec: V2ActionReviewRecord,
    exp: V2FieldExpectation,
    label: "returned" | "listed",
  ): void {
    // ID is project-generated: must match the review- prefix.
    expect(typeof rec.id, `${label}.id is a string`).toBe("string");
    expect(rec.id, `${label}.id project-generated prefix`).toMatch(REVIEW_ID_PATTERN);
    // ID linkage.
    expect(rec.actionId).toBe(exp.actionId);
    expect(rec.jobId).toBe(exp.jobId);
    // Decision is exactly "approved".
    expect(rec.decision).toBe("approved");
    // Reviewer + source.
    expect(rec.reviewerId).toBe(exp.reviewerId);
    expect(rec.source).toBe(exp.source);
    // Timestamps: round-trip via Date.toISOString() and equal the
    // canonical form. createdAt === reviewedAt.
    expect(new Date(rec.reviewedAt).toISOString(), `${label}.reviewedAt round-trip`).toBe(A6_CANONICAL_REVIEWED_AT);
    expect(rec.reviewedAt, `${label}.reviewedAt canonical`).toBe(A6_CANONICAL_REVIEWED_AT);
    expect(new Date(rec.expiresAt).toISOString(), `${label}.expiresAt round-trip`).toBe(A6_CANONICAL_EXPIRES_AT);
    expect(rec.expiresAt, `${label}.expiresAt canonical`).toBe(A6_CANONICAL_EXPIRES_AT);
    // createdAt is canonical, equal to reviewedAt.
    expect(rec.createdAt, `${label}.createdAt canonical`).toBe(A6_CANONICAL_REVIEWED_AT);
    expect(rec.createdAt, `${label}.createdAt === reviewedAt`).toBe(rec.reviewedAt);
    // Four hashes.
    expect(rec.scopeHash).toBe(SCOPE_HASH);
    expect(rec.policyHash).toBe(POLICY_HASH);
    expect(rec.actionHash).toBe(ACTION_HASH);
    expect(rec.contextHash).toBe(CONTEXT_HASH);
    // Invalidation fields are absent (undefined) on a fresh record.
    expect(rec.invalidatedAt, `${label}.invalidatedAt absent`).toBeUndefined();
    expect(rec.invalidationReason, `${label}.invalidationReason absent`).toBeUndefined();
    // Note.
    if (exp.expectNote === undefined) {
      expect(rec.note, `${label}.note absent`).toBeUndefined();
    } else {
      expect(rec.note, `${label}.note exact redacted form`).toBe(exp.expectNote);
    }
  }

  // Asserts every column on the raw SQL row returned by SELECT *.
  // `expectedRawNote` is the exact redacted form (string) when a
  // note is expected, or null when the row's note column must be
  // NULL (e.g. policy happy path).
  function assertEveryRawSqlField(
    row: Record<string, unknown>,
    exp: V2FieldExpectation,
    expectedRawNote: string | null,
  ): void {
    // ID matches the project-generated prefix.
    expect(typeof row.id).toBe("string");
    expect((row.id as string).length).toBeGreaterThan(0);
    expect((row.id as string).match(REVIEW_ID_PATTERN)).not.toBeNull();
    // Linkage.
    expect(row.action_id).toBe(exp.actionId);
    expect(row.job_id).toBe(exp.jobId);
    // Decision.
    expect(row.decision).toBe("approved");
    // Reviewer + source.
    expect(row.reviewer_id).toBe(exp.reviewerId);
    expect(row.source).toBe(exp.source);
    // Timestamps: round-trip exact.
    expect(row.reviewed_at).toBe(A6_CANONICAL_REVIEWED_AT);
    expect(row.expires_at).toBe(A6_CANONICAL_EXPIRES_AT);
    expect(row.created_at).toBe(A6_CANONICAL_REVIEWED_AT);
    // created_at === reviewed_at on disk.
    expect(row.created_at).toBe(row.reviewed_at);
    // Four hashes.
    expect(row.scope_hash).toBe(SCOPE_HASH);
    expect(row.policy_hash).toBe(POLICY_HASH);
    expect(row.action_hash).toBe(ACTION_HASH);
    expect(row.context_hash).toBe(CONTEXT_HASH);
    // Invalidation: NULL on a fresh row.
    expect(row.invalidated_at).toBeNull();
    expect(row.invalidation_reason).toBeNull();
    // Raw note: NULL when no note is expected; the redacted form
    // when one is.
    if (expectedRawNote === null) {
      expect(row.note).toBeNull();
    } else {
      expect(row.note).toBe(expectedRawNote);
    }
  }

  // A6.1: outside-tx guard + zero rows.
  it("throws ACTION_REVIEW_TRANSACTION_REQUIRED outside a transaction and writes zero rows", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    let captured: unknown = null;
    try {
      store.insertApprovalInTransaction(buildValidHumanBase("act-a6-1", "job-a6-1"));
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_REVIEW_TRANSACTION_REQUIRED");

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // A6.2: human happy path.
  it("human happy path: project-generated /review-/ ID, every v2 field asserted on returned, listForAction, and raw SELECT *", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const actionId = "act-a6-human";
    const jobId = "job-a6-human";
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const result = withImmediateTransaction(handle, () => {
      return (store as ActionReviewStoreSliceA).insertApprovalInTransaction(buildValidHumanBase(actionId, jobId));
    });

    expect(result).toBeDefined();

    // Reused expectation: human, trimmed reviewer, exact redacted note.
    const exp: V2FieldExpectation = {
      actionId,
      jobId,
      reviewerId: REVIEWER_ID,
      source: "human",
      expectNote: A6_REDACTED_NOTE,
    };
    // Every returned field.
    assertEveryV2PublicField(result, exp, "returned");
    // No secret leaks into the returned note.
    expect(result.note!).not.toContain(A6_NOTE_SECRET);

    // Raw SELECT * proves every column.
    const rows = handle
      .prepare("SELECT * FROM action_reviews WHERE action_id = ?")
      .all(actionId) as Array<Record<string, unknown>>;
    expect(rows.length).toBe(1);
    const row = rows[0];
    expect(row.id).toBe(result.id);
    assertEveryRawSqlField(row, exp, A6_REDACTED_NOTE);
    // Raw row's note: must not contain the secret.
    expect(row.note as string).not.toContain(A6_NOTE_SECRET);

    // listForAction: every field, including note redaction.
    const listed = (store as unknown as { listForAction(actionId: string): V2ActionReviewRecord[] }).listForAction(actionId);
    expect(listed.length).toBe(1);
    assertEveryV2PublicField(listed[0], exp, "listed");
    expect(listed[0].note!).not.toContain(A6_NOTE_SECRET);

    // Total action_reviews count grew by exactly one.
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before + 1);
  });

  // A6.3: policy happy path requires reviewer exactly system:policy-gate.
  it("policy happy path: reviewer=system:policy-gate, every v2 field asserted on returned, listForAction, and raw SELECT *", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const actionId = "act-a6-policy";
    const jobId = "job-a6-policy";

    const result = withImmediateTransaction(handle, () => {
      return (store as ActionReviewStoreSliceA).insertApprovalInTransaction(buildValidPolicyBase(actionId, jobId));
    });

    expect(result).toBeDefined();

    const exp: V2FieldExpectation = {
      actionId,
      jobId,
      reviewerId: POLICY_REVIEWER_ID,
      source: "policy",
      // No note was supplied; the public record must NOT expose one.
      expectNote: undefined,
    };
    // Returned: every field.
    assertEveryV2PublicField(result, exp, "returned");

    // Raw SELECT *.
    const row = handle
      .prepare("SELECT * FROM action_reviews WHERE id = ?")
      .get(result.id) as Record<string, unknown>;
    expect(row).toBeDefined();
    assertEveryRawSqlField(row, exp, null);
    // Policy path carries NO note.
    expect(row.note).toBeNull();

    // listForAction: every field, including absence of note.
    const listed = (store as unknown as { listForAction(actionId: string): V2ActionReviewRecord[] }).listForAction(actionId);
    expect(listed.length).toBe(1);
    assertEveryV2PublicField(listed[0], exp, "listed");
  });

  // A6.4: read-time defense. After a valid insert, raw SQL overwrites
  // the note with a fresh secret-bearing string. listForAction must
  // mask the secret on read while preserving public text.
  it("read-time defense: raw SQL overwrite of note is masked by listForAction", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const actionId = "act-a6-read";
    const jobId = "job-a6-read";

    const result = withImmediateTransaction(handle, () => {
      return (store as ActionReviewStoreSliceA).insertApprovalInTransaction(buildValidHumanBase(actionId, jobId));
    });

    // Overwrite the note directly via SQL to simulate a row that
    // somehow got a secret-bearing note past write-time masking
    // (e.g. via a legacy path or direct DB access). The read API
    // must still mask.
    handle
      .prepare("UPDATE action_reviews SET note = ? WHERE id = ?")
      .run(A6_RUNTIME_SECRET_NOTE, result.id);

    // Raw note still contains the secret on disk — that is the
    // threat model the read-time defense is designed to handle.
    const rawAfter = handle
      .prepare("SELECT note FROM action_reviews WHERE id = ?")
      .get(result.id) as { note: string };
    expect(rawAfter.note).toContain("RUNTIME_SECRET");

    const listed = (store as unknown as { listForAction(actionId: string): V2ActionReviewRecord[] }).listForAction(actionId);
    expect(listed.length).toBe(1);
    const note = listed[0].note;
    expect(note).toBeDefined();
    expect(note!).toContain("[REDACTED]");
    expect(note!).not.toContain("RUNTIME_SECRET");
    expect(note!).toContain("runtime-public-prefix");
    expect(note!).toContain("runtime-public-suffix");
  });

  // A6.5: invalid input table. Each row is invoked inside a fresh
  // withImmediateTransaction. Expected: ACTION_APPROVAL_INVALID and
  // ZERO action_reviews rows written for the action.
  type InvalidCase = {
    name: string;
    override: (base: CompleteApprovalReviewInput) => CompleteApprovalReviewInput;
    expectedIdProbe?: boolean; // when true, the case passes a caller id
  };

  const INVALID_CASES: InvalidCase[] = [
    // Caller-controlled ID is rejected.
    { name: "caller-supplied id (id is not part of the public input)", expectedIdProbe: true,
      override: (b) => ({ ...b }) },
    // Required string fields: empty / whitespace / null.
    { name: "empty actionId", override: (b) => ({ ...b, actionId: "" }) },
    { name: "whitespace actionId", override: (b) => ({ ...b, actionId: "   " }) },
    { name: "null actionId", override: (b) => ({ ...b, actionId: null as unknown as string }) },
    { name: "empty jobId", override: (b) => ({ ...b, jobId: "" }) },
    { name: "whitespace jobId", override: (b) => ({ ...b, jobId: "   " }) },
    { name: "null jobId", override: (b) => ({ ...b, jobId: null as unknown as string }) },
    // Decision must be exactly "approved" (runtime cast).
    { name: "decision='blocked'", override: (b) => ({ ...b, decision: "blocked" as unknown as "approved" }) },
    { name: "decision='executed'", override: (b) => ({ ...b, decision: "executed" as unknown as "approved" }) },
    { name: "decision='failed'", override: (b) => ({ ...b, decision: "failed" as unknown as "approved" }) },
    { name: "decision=null", override: (b) => ({ ...b, decision: null as unknown as "approved" }) },
    // Source.
    { name: "source='invalid'", override: (b) => ({ ...b, source: "invalid" as unknown as "human" }) },
    { name: "source=null", override: (b) => ({ ...b, source: null as unknown as "human" }) },
    // Human reviewer: empty / whitespace / null / control / DEL / overlong / system:policy-gate.
    { name: "human reviewer empty", override: (b) => ({ ...b, reviewerId: "" }) },
    { name: "human reviewer whitespace", override: (b) => ({ ...b, reviewerId: "   " }) },
    { name: "human reviewer null", override: (b) => ({ ...b, reviewerId: null as unknown as string }) },
    { name: "human reviewer contains U+0000", override: (b) => ({ ...b, reviewerId: `evil\u0000reviewer` }) },
    { name: "human reviewer contains U+0001 (control)", override: (b) => ({ ...b, reviewerId: `evil\u0001reviewer` }) },
    { name: "human reviewer contains U+001F (control)", override: (b) => ({ ...b, reviewerId: `evil\u001freviewer` }) },
    { name: "human reviewer contains U+007F (DEL)", override: (b) => ({ ...b, reviewerId: `evil\u007freviewer` }) },
    { name: "human reviewer 257 code points (over length cap)", override: (b) => ({ ...b, reviewerId: A6_REVIEWER_257 }) },
    { name: "human reviewer equals system:policy-gate", override: (b) => ({ ...b, reviewerId: POLICY_REVIEWER_ID }) },
    // Policy reviewer: must be exactly system:policy-gate.
    { name: "policy reviewer not system:policy-gate", override: (b) => ({ ...b, source: "policy", reviewerId: SOMEONE_ELSE_POLICY_REVIEWER }) },
    // Timestamps: canonical round-trip + ordering + parseable-but-noncanonical.
    { name: "reviewedAt empty", override: (b) => ({ ...b, reviewedAt: "" }) },
    { name: "reviewedAt null", override: (b) => ({ ...b, reviewedAt: null as unknown as string }) },
    { name: "reviewedAt not ISO-8601", override: (b) => ({ ...b, reviewedAt: "not-a-date" }) },
    { name: "reviewedAt parseable but missing '.000' milliseconds (noncanonical)", override: (b) => ({ ...b, reviewedAt: A6_NONCANONICAL_REVIEWED_AT }) },
    { name: "expiresAt empty", override: (b) => ({ ...b, expiresAt: "" }) },
    { name: "expiresAt null", override: (b) => ({ ...b, expiresAt: null as unknown as string }) },
    { name: "expiresAt not ISO-8601", override: (b) => ({ ...b, expiresAt: "2099-13-99T99:99:99.999Z" }) },
    { name: "expiresAt parseable but missing '.000' milliseconds (noncanonical)", override: (b) => ({ ...b, expiresAt: A6_NONCANONICAL_EXPIRES_AT }) },
    { name: "expiresAt == reviewedAt (boundary)", override: (b) => ({ ...b, reviewedAt: A6_CANONICAL_REVIEWED_AT, expiresAt: A6_CANONICAL_REVIEWED_AT }) },
    { name: "expiresAt earlier than reviewedAt", override: (b) => ({ ...b, reviewedAt: A6_CANONICAL_EXPIRES_AT, expiresAt: A6_CANONICAL_REVIEWED_AT }) },
  ];

  // Per-hash field invalid cases. Applied to each of the four hash
  // columns; the test iterates so the table stays compact.
  const HASH_COLUMN_NAMES: ReadonlyArray<"scope" | "policy" | "action" | "context"> = ["scope", "policy", "action", "context"];
  const HASH_FIELD_BY_COLUMN: Record<"scope" | "policy" | "action" | "context", "scopeHash" | "policyHash" | "actionHash" | "contextHash"> = {
    scope: "scopeHash",
    policy: "policyHash",
    action: "actionHash",
    context: "contextHash",
  };
  const HASH_VALUE_BY_COLUMN: Record<"scope" | "policy" | "action" | "context", string> = {
    scope: SCOPE_HASH,
    policy: POLICY_HASH,
    action: ACTION_HASH,
    context: CONTEXT_HASH,
  };

  for (const col of HASH_COLUMN_NAMES) {
    const field = HASH_FIELD_BY_COLUMN[col];
    const valid = HASH_VALUE_BY_COLUMN[col];
    INVALID_CASES.push(
      { name: `${col} hash undefined`, override: (b) => ({ ...b, [field]: undefined as unknown as string }) },
      { name: `${col} hash null`, override: (b) => ({ ...b, [field]: null as unknown as string }) },
      { name: `${col} hash 63 chars`, override: (b) => ({ ...b, [field]: valid.slice(0, -1) }) },
      { name: `${col} hash 65 chars`, override: (b) => ({ ...b, [field]: valid + "0" }) },
      { name: `${col} hash uppercase hex`, override: (b) => ({ ...b, [field]: valid.toUpperCase() }) },
      { name: `${col} hash non-hex (contains 'z')`, override: (b) => ({ ...b, [field]: "z".repeat(64) }) },
      { name: `${col} hash 64 all-zero lowercase hex`, override: (b) => ({ ...b, [field]: "0".repeat(64) }) },
    );
  }

  for (const tc of INVALID_CASES) {
    it(`table: ACTION_APPROVAL_INVALID and zero writes for ${tc.name}`, () => {
      const handle = openDb();
      const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
      // Snapshot the TOTAL action_reviews count, not a count by
      // actionId, because several invalid inputs null/malform
      // actionId and counting by it would be undefined.
      const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

      const base: CompleteApprovalReviewInput = tc.expectedIdProbe
        ? // For the caller-id probe, attach a caller-controlled id at
          // runtime via an object spread so the strict public type is
          // not altered.
          ({ ...buildValidHumanBase("act-a6-invalid", "job-a6-invalid"), id: CALLER_SUPPLIED_ID } as unknown as CompleteApprovalReviewInput)
        : buildValidHumanBase("act-a6-invalid", "job-a6-invalid");
      const overridden = tc.override(base);

      let captured: unknown = null;
      try {
        withImmediateTransaction(handle, () => {
          (store as ActionReviewStoreSliceA).insertApprovalInTransaction(overridden);
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_INVALID");

      // Zero writes overall: the invalid insert must not have
      // persisted anything anywhere.
      const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
      expect(after).toBe(before);
    });
  }

  // A6.6: caller rollback. A valid insert inside withImmediateTransaction
  // followed by a thrown sentinel must roll back the review.
  it("caller rollback removes a successfully inserted review and rethrows the sentinel", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const actionId = "act-a6-rollback";
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const SENTINEL = new Error("force-rollback");
    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        (store as ActionReviewStoreSliceA).insertApprovalInTransaction(buildValidHumanBase(actionId, "job-a6-rollback"));
        throw SENTINEL;
      });
    } catch (err) {
      captured = err;
    }
    // The sentinel escapes the transaction helper verbatim.
    expect(captured).toBe(SENTINEL);

    // Zero rows persisted overall.
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // A6.7: composition proof. A SIMPLE caller-owned withImmediateTransaction
  // containing exactly one valid insert and returning the inserted
  // record. No explicit nested withImmediateTransaction call, no
  // nested-rejected probes, no outerThrew bookkeeping. If the
  // primitive tries to own a transaction (by calling
  // withImmediateTransaction itself), the test naturally fails: the
  // returned record's existence and every-v2-field correctness prove
  // composition.
  it("composition: one valid insert inside caller-owned withImmediateTransaction returns the inserted record", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const actionId = "act-a6-compose";
    const jobId = "job-a6-compose";

    const returned = withImmediateTransaction(handle, () => {
      return (store as ActionReviewStoreSliceA).insertApprovalInTransaction(buildValidHumanBase(actionId, jobId));
    });

    // The insert succeeded inside the caller's transaction; the
    // primitive did not begin a nested transaction (otherwise the
    // outer withImmediateTransaction would have rolled back and
    // the returned record would not exist on disk).
    expect(returned).toBeDefined();
    expect(returned.id).toMatch(REVIEW_ID_PATTERN);
    expect(returned.actionId).toBe(actionId);
    expect(returned.jobId).toBe(jobId);
    expect(returned.decision).toBe("approved");
    expect(returned.reviewerId).toBe(REVIEWER_ID);
    expect(returned.source).toBe("human");

    // The row is on disk under the generated ID.
    const row = handle
      .prepare("SELECT * FROM action_reviews WHERE id = ?")
      .get(returned.id) as Record<string, unknown>;
    expect(row).toBeDefined();
    expect(row.action_id).toBe(actionId);
    expect(row.reviewer_id).toBe(REVIEWER_ID);
  });

  // A6.8: positive boundary — human reviewer of exactly 256 Unicode
  // code points (each a surrogate-pair emoji). An incorrect
  // UTF-16 .length check would see 512 and reject this valid input.
  it("positive boundary: trimmed human reviewer of exactly 256 Unicode code points (surrogate-pair emoji) is accepted", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const actionId = "act-a6-boundary-256";
    const jobId = "job-a6-boundary-256";
    // Sanity: 256 code points, 512 UTF-16 code units. If the store
    // counts code units instead of code points, this input is
    // rejected as 512 (over the 256 cap).
    const codePointLen = Array.from(A6_EMOJI_256).length;
    const utf16Len = A6_EMOJI_256.length;
    expect(codePointLen).toBe(256);
    expect(utf16Len).toBe(512);
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const result = withImmediateTransaction(handle, () => {
      return (store as ActionReviewStoreSliceA).insertApprovalInTransaction({
        actionId,
        jobId,
        decision: "approved",
        // Surrounding spaces must be trimmed; the canonical
        // persisted reviewer is the 256-emoji string with no
        // surrounding spaces.
        reviewerId: `   ${A6_EMOJI_256}   `,
        source: "human",
        reviewedAt: A6_CANONICAL_REVIEWED_AT,
        expiresAt: A6_CANONICAL_EXPIRES_AT,
        scopeHash: SCOPE_HASH,
        policyHash: POLICY_HASH,
        actionHash: ACTION_HASH,
        contextHash: CONTEXT_HASH,
      });
    });

    expect(result).toBeDefined();
    // The persisted reviewer is the trimmed canonical 256-emoji.
    expect(result.reviewerId).toBe(A6_EMOJI_256);
    expect(result.reviewerId.length).toBe(512); // UTF-16 code units
    expect(Array.from(result.reviewerId).length).toBe(256); // code points

    // Raw row mirrors the canonical persisted form.
    const row = handle
      .prepare("SELECT reviewer_id FROM action_reviews WHERE id = ?")
      .get(result.id) as { reviewer_id: string };
    expect(row.reviewer_id).toBe(A6_EMOJI_256);
    expect(row.reviewer_id.length).toBe(512);
    expect(Array.from(row.reviewer_id).length).toBe(256);

    // listForAction returns the same canonical reviewer.
    const listed = (store as unknown as { listForAction(actionId: string): V2ActionReviewRecord[] }).listForAction(actionId);
    expect(listed.length).toBe(1);
    expect(listed[0].reviewerId).toBe(A6_EMOJI_256);

    // Exactly one row was persisted.
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before + 1);
  });

  // A6.9 (hardening RED): trim-removable C0 controls (U+0009 TAB,
  //   U+000A LF, U+000B VT, U+000C FF, U+000D CR) at the leading
  //   and/or trailing positions of a human reviewerId are rejected
  //   even though String.prototype.trim removes them. Current
  //   production trims these characters and then runs its C0 regex
  //   on the TRIMMED value, so the raw input is accepted. The
  //   hardened contract inspects the raw input.
  it("hardening: trim-removable C0 controls at leading/trailing reviewerId positions are rejected", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    type Shape = "leading" | "trailing" | "both";
    interface Row {
      name: string;
      char: string;
      shape: Shape;
    }
    // Five trim-removable C0 controls, each exercised in at least
    // one leading and one trailing position. U+0009 TAB is also
    // exercised in BOTH positions to prove the rule applies to
    // either side independently.
    const ROWS: Row[] = [
      { name: "U+0009 TAB leading",  char: "\u0009", shape: "leading"  },
      { name: "U+0009 TAB trailing", char: "\u0009", shape: "trailing" },
      { name: "U+0009 TAB both",     char: "\u0009", shape: "both"     },
      { name: "U+000A LF leading",   char: "\u000A", shape: "leading"  },
      { name: "U+000A LF trailing",  char: "\u000A", shape: "trailing" },
      { name: "U+000B VT leading",   char: "\u000B", shape: "leading"  },
      { name: "U+000B VT trailing",  char: "\u000B", shape: "trailing" },
      { name: "U+000C FF leading",   char: "\u000C", shape: "leading"  },
      { name: "U+000C FF trailing",  char: "\u000C", shape: "trailing" },
      { name: "U+000D CR leading",   char: "\u000D", shape: "leading"  },
      { name: "U+000D CR trailing",  char: "\u000D", shape: "trailing" },
    ];

    for (const row of ROWS) {
      const polluted =
        row.shape === "leading"
          ? `${row.char}${REVIEWER_ID}`
          : row.shape === "trailing"
            ? `${REVIEWER_ID}${row.char}`
            : `${row.char}${REVIEWER_ID}${row.char}`;
      const base = buildValidHumanBase("act-a6-hardening-c0", "job-a6-hardening-c0");
      const input: CompleteApprovalReviewInput = { ...base, reviewerId: polluted };

      let captured: unknown = null;
      try {
        withImmediateTransaction(handle, () => {
          (store as ActionReviewStoreSliceA).insertApprovalInTransaction(input);
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      expect(captured, `case ${row.name} must throw`).toBeInstanceOf(BountyPilotError);
      expect(
        (captured as BountyPilotError).code,
        `case ${row.name} code`,
      ).toBe("ACTION_APPROVAL_INVALID");
    }

    // Zero writes overall — every row was rejected.
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // A6.10 (hardening RED): source=policy with reviewerId that
  //   trims to the exact policy literal but carries leading/
  //   trailing spaces or trim-removable C0 controls is rejected.
  //   The exact literal comparison must be done on the RAW input,
  //   not on the trimmed input. Current production trims first
  //   and then compares, so it accepts all of these.
  it("hardening: source=policy with reviewerId padded by spaces or C0 trim-controls is rejected", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const CASES: Array<{ name: string; reviewerId: string }> = [
      { name: "space-padded system:policy-gate", reviewerId: " system:policy-gate " },
      { name: "tab-wrapped system:policy-gate",   reviewerId: "\u0009system:policy-gate\u0009" },
      { name: "lf-wrapped system:policy-gate",    reviewerId: "\u000Asystem:policy-gate\u000A" },
    ];

    for (const c of CASES) {
      const base = buildValidPolicyBase("act-a6-hardening-policy", "job-a6-hardening-policy");
      const input: CompleteApprovalReviewInput = { ...base, reviewerId: c.reviewerId };

      let captured: unknown = null;
      try {
        withImmediateTransaction(handle, () => {
          (store as ActionReviewStoreSliceA).insertApprovalInTransaction(input);
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      expect(captured, `case ${c.name} must throw`).toBeInstanceOf(BountyPilotError);
      expect(
        (captured as BountyPilotError).code,
        `case ${c.name} code`,
      ).toBe("ACTION_APPROVAL_INVALID");
    }

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // A6.11 (hardening RED): chronologically backwards extended-year
  //   timestamps are rejected. reviewedAt in year 10000 and
  //   expiresAt in year 9999 are chronologically inverted, but
  //   the current naive string-based ordering (which compares
  //   ASCII '+' (0x2B) < '9' (0x39) at the first character)
  //   misreads the order and accepts the pair. The hardened
  //   contract compares by parsed Date value, not by string.
  it("hardening: chronologically backwards extended-year timestamps are rejected", () => {
    const reviewedAt = "+010000-01-01T00:00:00.000Z"; // year 10000
    const expiresAt  = "9999-12-31T23:59:59.999Z";    // year 9999

    // Prove both strings individually round-trip through
    // Date#toISOString() before invoking the store. This is a
    // sanity check that the timestamps are canonical on any
    // conforming runtime; the RED assertion is below.
    expect(new Date(reviewedAt).toISOString()).toBe(reviewedAt);
    expect(new Date(expiresAt).toISOString()).toBe(expiresAt);
    // Sanity: chronologically reviewedAt > expiresAt.
    expect(new Date(reviewedAt).getTime()).toBeGreaterThan(new Date(expiresAt).getTime());

    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const base = buildValidHumanBase("act-a6-hardening-backwards", "job-a6-hardening-backwards");
    const input: CompleteApprovalReviewInput = { ...base, reviewedAt, expiresAt };

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        (store as ActionReviewStoreSliceA).insertApprovalInTransaction(input);
        return "should-not-reach";
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_INVALID");

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // A6.12 (hardening RED): positive extended-year crossing
  //   succeeds and the EXACT supplied strings round-trip through
  //   to the persisted row. reviewedAt in year 9999 and expiresAt
  //   in year 10000 are chronologically correct, but the current
  //   naive string compare rejects the pair because '+' (0x2B) is
  //   less than '9' (0x39) at the first character. The hardened
  //   contract accepts the pair.
  it("hardening: positive extended-year crossing (year 9999 -> year 10000) is accepted and persisted exactly", () => {
    const reviewedAt = "9999-12-31T23:59:59.999Z";    // year 9999
    const expiresAt  = "+010000-01-01T00:00:00.000Z"; // year 10000

    // Prove both strings individually round-trip through
    // Date#toISOString() before invoking the store.
    expect(new Date(reviewedAt).toISOString()).toBe(reviewedAt);
    expect(new Date(expiresAt).toISOString()).toBe(expiresAt);
    // Sanity: chronologically reviewedAt < expiresAt.
    expect(new Date(reviewedAt).getTime()).toBeLessThan(new Date(expiresAt).getTime());

    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const actionId = "act-a6-hardening-crossing";
    const jobId    = "job-a6-hardening-crossing";
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const result = withImmediateTransaction(handle, () => {
      return (store as ActionReviewStoreSliceA).insertApprovalInTransaction({
        ...buildValidHumanBase(actionId, jobId),
        reviewedAt,
        expiresAt,
      });
    });

    // Returned record: the EXACT strings round-trip.
    expect(result.reviewedAt).toBe(reviewedAt);
    expect(result.expiresAt).toBe(expiresAt);

    // Raw row: the EXACT strings persist.
    const row = handle
      .prepare("SELECT reviewed_at, expires_at FROM action_reviews WHERE id = ?")
      .get(result.id) as { reviewed_at: string; expires_at: string };
    expect(row).toBeDefined();
    expect(row.reviewed_at).toBe(reviewedAt);
    expect(row.expires_at).toBe(expiresAt);

    // Exactly one row was written.
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before + 1);
  });

  // A6.13 (hardening RED): prototype pollution cannot supply the
  //   required DTO fields. Every required field is temporarily
  //   installed on Object.prototype as a configurable,
  //   non-enumerable VALUE property; the caller then invokes
  //   insertApprovalInTransaction with an empty own-properties
  //   object. The hardened validator must ignore prototype-chain
  //   values and reject the call. Uses the a6WithPrototypeDescriptors
  //   helper for safe save/restore — no global state leaks into
  //   other tests.
  it("hardening: prototype pollution of required DTO fields is rejected with zero writes", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    // Every required DTO field that the validator reads. Note is
    // optional and therefore not required; we leave it absent.
    const FIELD_VALUES: Record<string, unknown> = {
      actionId: "act-a6-hardening-proto",
      jobId: "job-a6-hardening-proto",
      decision: "approved",
      reviewerId: REVIEWER_ID,
      source: "human",
      reviewedAt: A6_CANONICAL_REVIEWED_AT,
      expiresAt: A6_CANONICAL_EXPIRES_AT,
      scopeHash: SCOPE_HASH,
      policyHash: POLICY_HASH,
      actionHash: ACTION_HASH,
      contextHash: CONTEXT_HASH,
    };
    const fieldDescriptors: Record<string, PropertyDescriptor> = {};
    for (const [field, val] of Object.entries(FIELD_VALUES)) {
      fieldDescriptors[field] = {
        value: val,
        writable: true,
        enumerable: false,
        configurable: true,
      };
    }

    a6WithPrototypeDescriptors(fieldDescriptors, () => {
      // Empty own-properties object. Runtime-cast to the public
      // input type because strict TS does not allow it directly.
      const polluted = {} as unknown as CompleteApprovalReviewInput;
      let captured: unknown = null;
      try {
        withImmediateTransaction(handle, () => {
          (store as ActionReviewStoreSliceA).insertApprovalInTransaction(polluted);
          return "should-not-reach";
        });
      } catch (err) {
        captured = err;
      }
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_INVALID");
    });

    // After the helper returns, Object.prototype is restored. A
    // fresh plain {} must NOT expose any of the required fields
    // via the prototype chain.
    const fresh = {} as Record<string, unknown>;
    for (const field of Object.keys(FIELD_VALUES)) {
      expect(fresh[field], `prototype field ${field} restored`).toBeUndefined();
    }

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // A6.14 (hardening RED): an inherited Object.prototype.id alone
  //   must NOT count as a caller-supplied own id. The hardened
  //   validator must consult own properties only. Current
  //   production uses the `in` operator, which walks the
  //   prototype chain, and therefore rejects the otherwise-valid
  //   input. Uses the a6WithPrototypeDescriptors helper for safe
  //   save/restore.
  it("hardening: inherited Object.prototype.id does not count as caller-supplied own id", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    a6WithPrototypeDescriptors(
      {
        // Configurable, non-enumerable, writable, plain value.
        id: { value: "proto-inherited-id", writable: true, enumerable: false, configurable: true },
      },
      () => {
        // Otherwise own-property valid base — NO own id.
        const base = buildValidHumanBase("act-a6-hardening-proto-id", "job-a6-hardening-proto-id");
        expect(Object.prototype.hasOwnProperty.call(base, "id")).toBe(false);
        expect("id" in base).toBe(true); // inherited only

        const result = withImmediateTransaction(handle, () => {
          return (store as ActionReviewStoreSliceA).insertApprovalInTransaction(base);
        });

        expect(result).toBeDefined();
        expect(result.id).toMatch(REVIEW_ID_PATTERN);
        expect(result.actionId).toBe("act-a6-hardening-proto-id");

        const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
        expect(after).toBe(before + 1);
      },
    );

    // After the helper returns, Object.prototype.id is restored
    // to its prior state (absent on a normal runtime).
    const fresh = {} as Record<string, unknown>;
    expect(fresh.id).toBeUndefined();
  });

  // A6.15 (hardening RED): accessor DTO fields are rejected
  //   WITHOUT invoking the getter. The hardened validator must
  //   inspect own-property descriptors, not trigger getters. The
  //   getter throws a secret-bearing error; the validator must
  //   convert that into a secret-free BountyPilotError and never
  //   call the getter at all.
  it("hardening: accessor DTO field (reviewerId) is rejected without invoking the getter", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const A6_GETTER_SECRET = "A6_GETTER_SECRET";
    let getterCalls = 0;
    const base = buildValidHumanBase("act-a6-hardening-accessor", "job-a6-hardening-accessor");
    // Replace reviewerId on a valid own-property object with an
    // enumerable configurable accessor whose getter increments a
    // counter and throws a secret-bearing error. The hardened
    // validator must never call this getter.
    const baseWithAccessor: Record<string, unknown> = { ...base };
    Object.defineProperty(baseWithAccessor, "reviewerId", {
      get: () => {
        getterCalls += 1;
        throw new Error(`token=${A6_GETTER_SECRET}`);
      },
      enumerable: true,
      configurable: true,
    });
    const input = baseWithAccessor as unknown as CompleteApprovalReviewInput;

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        (store as ActionReviewStoreSliceA).insertApprovalInTransaction(input);
        return "should-not-reach";
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_INVALID");
    // Secret must not leak into the captured error message.
    expect((captured as BountyPilotError).message).not.toContain(A6_GETTER_SECRET);
    // Getter was never invoked.
    expect(getterCalls).toBe(0);

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // A6.16 (hardening RED): a Proxy whose getPrototypeOf trap
  //   throws a secret-bearing error must be mapped to a
  //   secret-free BountyPilotError ACTION_APPROVAL_INVALID. The
  //   hardened validator must not let a hostile prototype trap
  //   leak through with the secret in the error message.
  it("hardening: Proxy with throwing getPrototypeOf trap is mapped to secret-free ACTION_APPROVAL_INVALID", () => {
    const handle = openDb();
    const store = new ActionReviewStore(handle) as unknown as ActionReviewStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;

    const A6_PROXY_SECRET = "A6_PROXY_SECRET";
    const base = buildValidHumanBase("act-a6-hardening-proxy", "job-a6-hardening-proxy");
    // Wrap the valid base in a Proxy whose getPrototypeOf trap
    // throws a secret-bearing error. All other traps delegate to
    // the underlying target.
    const proxyTarget: Record<string, unknown> = { ...base };
    let getPrototypeOfTrapCalls = 0;
    const proxy = new Proxy(proxyTarget, {
      getPrototypeOf(): object | null {
        getPrototypeOfTrapCalls += 1;
        throw new Error(`token=${A6_PROXY_SECRET}`);
      },
    });
    const input = proxy as unknown as CompleteApprovalReviewInput;

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        (store as ActionReviewStoreSliceA).insertApprovalInTransaction(input);
        return "should-not-reach";
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("ACTION_APPROVAL_INVALID");
    // Secret must not leak into the captured error message.
    expect((captured as BountyPilotError).message).not.toContain(A6_PROXY_SECRET);
    // A Proxy is rejected by the trusted isProxy discriminator before any
    // reflection. Catching and remapping a fired hostile trap is insufficient.
    expect(getPrototypeOfTrapCalls).toBe(0);

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM action_reviews").get() as { n: number }).n;
    expect(after).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// A7: WorkflowEventStore — in-tx primitive, exact sequence allocation,
//     write/read-time redaction, public record() owns a transaction,
//     deterministic unique-sequence collision mapped to
//     WORKFLOW_EVENT_SEQUENCE_CONFLICT (no retry), and two real
//     Worker threads each calling the public record() produce exact
//     monotonic sequences [1,2] on a shared temp DB. The
//     concurrency proof uses a third blocker DB handle holding a
//     raw BEGIN IMMEDIATE plus a per-worker Proxy that intercepts
//     only exec("BEGIN IMMEDIATE") to prove BOTH workers reached
//     the transaction-owning boundary before COMMIT.
// ---------------------------------------------------------------------------

describe("A7: WorkflowEventStore in-tx primitive + public record() owns a transaction", () => {
  // A7 describe-scope constants. The Worker concurrency test uses
  // these as the vitest test-level timeout (third it() argument),
  // so the constant must be visible at describe scope, not inside
  // the it() callback.
  const A7_TEST_TIMEOUT_MS = 60_000;

  // Reused probe secrets: every event MUST be masked on write AND
  // re-masked on read. The public text + non-secret metadata fields
  // must survive both passes.
  const A7_SECRET_VALUE = "AKIAIOSFODNN7EXAMPLE";
  const A7_SECRET_VALUE_2 = "hunter2-secret";
  const A7_PUBLIC_PREFIX = "a7-public-prefix";
  const A7_PUBLIC_SUFFIX = "a7-public-suffix";
  const A7_MESSAGE = `${A7_PUBLIC_PREFIX} api_key=${A7_SECRET_VALUE} ${A7_PUBLIC_SUFFIX}`;
  const A7_MESSAGE_2 = `${A7_PUBLIC_PREFIX} password=${A7_SECRET_VALUE_2} ${A7_PUBLIC_SUFFIX}`;
  const A7_REDACTED_MESSAGE = `${A7_PUBLIC_PREFIX} api_key=[REDACTED] ${A7_PUBLIC_SUFFIX}`;
  const A7_REDACTED_MESSAGE_2 = `${A7_PUBLIC_PREFIX} password=[REDACTED] ${A7_PUBLIC_SUFFIX}`;
  const A7_METADATA = {
    token: SECRET_IN_METADATA,
    publicField: "a7-public-meta",
    inner: { password: A7_SECRET_VALUE_2, keep: "a7-keep" },
  };
  // Event 2 metadata carries a password= secret so the list/read
  // redaction loop has a real basis to assert `[REDACTED]`.
  const A7_METADATA_2 = {
    kind: "a7-second",
    publicField: "a7-second-public",
    password: A7_SECRET_VALUE_2,
    note: "a7-second-note",
  };

  // ---- Shared A7 helpers ---------------------------------------------

  // A worker source that wraps its DatabaseSync handle in a Proxy.
  // The Proxy binds every native method/iterator to the real target;
  // it intercepts ONLY exec("BEGIN IMMEDIATE"). On interception
  // the worker:
  //   a) increments its own begin-call counter, marks its own
  //      at-boundary slot and waits the peer's at-boundary slot;
  //   b) waits blockerHeld=1;
  //   c) marks its own forwardReady slot and notifies the parent
  //      (this proves the call is parked just before the native
  //      exec while the blocker is still held);
  //   d) waits forwardGrant=1;
  //   e) immediately calls target.exec(sql).
  // The only correctness barrier is a busy Atomics.wait on
  // SharedArrayBuffer int32 cells. Polling timeouts on the parent
  // are liveness observation only, not ordering.
  function a7ProxyWorkerSource(
    a7_WORKER_START_TIMEOUT_MS: number,
    a7_WORKER_PEER_TIMEOUT_MS: number,
    a7_WORKER_BLOCKER_TIMEOUT_MS: number,
    a7_WORKER_GRANT_TIMEOUT_MS: number,
  ): string {
    return `
      const { parentPort, workerData } = require('node:worker_threads');
      const { DatabaseSync } = require('node:sqlite');
      const { tsImport } = require('tsx/esm/api');
      const sab = workerData.sab;
      const i32 = new Int32Array(sab);
      const JOB_ID = workerData.jobId;
      const DB_PATH = workerData.dbPath;
      const ROLE = workerData.role;
      const READY_OFFSET = workerData.readyOffset;
      const START_OFFSET = 2;
      const MY_AT_BOUNDARY_OFFSET = workerData.atBoundaryOffset;
      const OTHER_AT_BOUNDARY_OFFSET = workerData.otherAtBoundaryOffset;
      const MY_FORWARD_READY_OFFSET = workerData.forwardReadyOffset;
      const MY_BEGIN_COUNT_OFFSET = workerData.beginCountOffset;
      const BLOCKER_HELD_OFFSET = 5;
      const BEGIN_FORWARD_GRANTED_OFFSET = 6;
      function send(payload) { parentPort.postMessage(payload); }
      function waitValue(offset, value, label, timeoutMs) {
        const deadline = Date.now() + timeoutMs;
        while (Atomics.load(i32, offset) !== value) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) {
            throw new Error('a7 worker ' + ROLE + ' barrier timeout: ' + label + ' offset=' + offset + ' want=' + value + ' got=' + Atomics.load(i32, offset));
          }
          const cur = Atomics.load(i32, offset);
          const rc = Atomics.wait(i32, offset, cur, Math.min(50, remaining));
          if (rc === 'timed-out' && Date.now() >= deadline) {
            throw new Error('a7 worker ' + ROLE + ' barrier timeout: ' + label + ' offset=' + offset + ' want=' + value + ' got=' + Atomics.load(i32, offset));
          }
        }
      }
      // Use DatabaseSync directly — the test does not need the
      // production wrapper to obtain a handle. The parent has
      // already opened and migrated the file in WAL mode; do NOT
      // re-issue PRAGMA journal_mode here (concurrent writers
      // toggling WAL can serialize on a writer lock and stall
      // startup).
      const realDb = new DatabaseSync(DB_PATH);
      realDb.exec('PRAGMA busy_timeout = 5000;');
      realDb.exec('PRAGMA foreign_keys = ON;');
      // Increment my begin-call counter so the parent can verify
      // exactly one BEGIN IMMEDIATE per worker fired through the proxy.
      function incBeginCount() {
        return Atomics.add(i32, MY_BEGIN_COUNT_OFFSET, 1) + 1;
      }
      const proxiedDb = new Proxy(realDb, {
        get(target, prop, receiver) {
          if (prop === 'exec') {
            return function proxiedExec(sql) {
              const trimmed = String(sql).trim().replace(/;\\s*$/, '').replace(/\\s+/g, ' ').toUpperCase();
              if (trimmed === 'BEGIN IMMEDIATE') {
                // (a) increment my begin-call counter, mark at-boundary,
                // notify the parent, wait the peer's at-boundary slot.
                const myCount = incBeginCount();
                if (myCount !== 1) {
                  throw new Error('a7 worker ' + ROLE + ' BEGIN IMMEDIATE called ' + myCount + ' times (wrapper should pass through exactly once)');
                }
                Atomics.store(i32, MY_AT_BOUNDARY_OFFSET, 1);
                Atomics.notify(i32, MY_AT_BOUNDARY_OFFSET, Infinity);
                waitValue(OTHER_AT_BOUNDARY_OFFSET, 1, 'wait for peer at-boundary', ${a7_WORKER_PEER_TIMEOUT_MS});
                // (b) wait for the parent's blocker-hold slot.
                waitValue(BLOCKER_HELD_OFFSET, 1, 'wait for parent blocker-hold', ${a7_WORKER_BLOCKER_TIMEOUT_MS});
                // (c) mark my forwardReady slot and notify the parent.
                // The native exec is still NOT called — the call is
                // parked on the still-held blocker.
                Atomics.store(i32, MY_FORWARD_READY_OFFSET, 1);
                Atomics.notify(i32, MY_FORWARD_READY_OFFSET, Infinity);
                // (d) wait for the parent's begin-forward-grant slot,
                // which is set ONLY after the blocker has been COMMITTED.
                waitValue(BEGIN_FORWARD_GRANTED_OFFSET, 1, 'wait for parent begin-forward-grant', ${a7_WORKER_GRANT_TIMEOUT_MS});
                // (e) forward the exec to the real target.
                return target.exec(sql);
              }
              return target.exec(sql);
            };
          }
          const v = Reflect.get(target, prop, target);
          if (typeof v === 'function') return v.bind(target);
          return v;
        },
      });
      let db = null;
      (async () => {
        try {
          const storeMod = await tsImport(workerData.storeUrl, workerData.parentUrl);
          const { WorkflowEventStore } = storeMod;
          if (typeof WorkflowEventStore !== 'function') throw new Error('WorkflowEventStore missing');
          db = new WorkflowEventStore(proxiedDb);
          // Mark this worker as ready, notify parent.
          Atomics.store(i32, READY_OFFSET, 1);
          Atomics.notify(i32, READY_OFFSET, Infinity);
          send({ kind: 'ready', value: 1 });
          // Wait for parent's start signal.
          waitValue(START_OFFSET, 1, 'wait for start', ${a7_WORKER_START_TIMEOUT_MS});
          // Public record() — transaction-owning. The wrapper's exec
          // proxy will catch the BEGIN IMMEDIATE and park on the
          // parent-controlled barrier chain.
          const rec = db.record({
            jobId: JOB_ID,
            phase: 'phase-conc-' + ROLE,
            status: 'running',
            message: 'conc-msg-' + ROLE,
          });
          send({ kind: 'result', value: rec.sequence });
        } catch (err) {
          const message = err && err.message ? err.message : String(err);
          send({ kind: 'worker-error', value: 0, message });
          throw err;
        } finally {
          if (db) { try { db.close?.(); } catch (_) { /* ignore */ } }
          try { realDb.close(); } catch (_) { /* ignore */ }
        }
      })().catch(() => { process.exitCode = 1; });
    `;
  }

  // ---- 1) recordInTransaction outside a tracked transaction =>
  // WORKFLOW_EVENT_TRANSACTION_REQUIRED and total count unchanged.
  it("recordInTransaction outside a transaction throws WORKFLOW_EVENT_TRANSACTION_REQUIRED and writes zero rows", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;

    let captured: unknown = null;
    try {
      events.recordInTransaction({
        jobId: "job-a7-1",
        phase: "test",
        status: "running",
        message: "hello",
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("WORKFLOW_EVENT_TRANSACTION_REQUIRED");

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // ---- 1a) Raw manual BEGIN IMMEDIATE on the SAME handle (NOT
  // through withImmediateTransaction) must still make
  // recordInTransaction reject with WORKFLOW_EVENT_TRANSACTION_REQUIRED
  // and zero event rows. The raw tx is rolled back in finally. This
  // rejects implementations that rely on DatabaseSync.isTransaction
  // or a process-global boolean.
  it("recordInTransaction rejects a raw/manual BEGIN IMMEDIATE opened directly on the same handle", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA;
    const jobId = "job-a7-1a";
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;

    let rawBegun = false;
    let captured: unknown = null;
    try {
      // Raw manual BEGIN IMMEDIATE — NOT through withImmediateTransaction.
      handle.exec("BEGIN IMMEDIATE");
      rawBegun = true;
      try {
        events.recordInTransaction({
          jobId,
          phase: "phase-raw",
          status: "running",
          message: "should-be-rejected",
        });
      } catch (err) {
        captured = err;
      }
    } finally {
      // Always rollback the raw tx so the handle is clean for the
      // afterEach close.
      try {
        handle.exec("ROLLBACK");
      } catch {
        /* best-effort rollback; the tx may already have been rolled back */
      }
    }
    expect(rawBegun, "raw BEGIN IMMEDIATE must have executed").toBe(true);
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("WORKFLOW_EVENT_TRANSACTION_REQUIRED");

    const after = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    expect(after).toBe(before);
    const jobCount = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobId) as { n: number }).n;
    expect(jobCount).toBe(0);
  });

  // ---- 1b) A tracked withImmediateTransaction on handle A does
  // NOT authorize a store bound to a separate handle B. Both
  // handles point at the SAME file DB, and recordInTransaction on
  // handle B must still reject with WORKFLOW_EVENT_TRANSACTION_REQUIRED
  // and write zero rows for jobIdB on either handle, while the
  // A-side sanity event intentionally persists. Rejects
  // implementations that use DatabaseSync.isTransaction or a
  // process-global boolean.
  it("tracked tx on handle A does not authorize a store on a separate handle B", () => {
    const handleA = openDb();
    const handleB = openBountyDatabase(dbFile);
    const eventsA = new WorkflowEventStore(handleA) as unknown as WorkflowEventStoreSliceA;
    const eventsB = new WorkflowEventStore(handleB) as unknown as WorkflowEventStoreSliceA;
    const jobIdA = "job-a7-1b-A";
    const jobIdB = "job-a7-1b-B";
    const beforeA = (handleA.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    const beforeB = (handleB.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;

    let captured: unknown = null;
    let jobCountB: number = -1;
    let afterA: number = -1;
    let jobCountA: number = -1;
    let jobCountAOnA: number = -1;
    let afterB: number = -1;
    try {
      withImmediateTransaction(handleA, () => {
        // Tracked tx is active on A. recordInTransaction on B
        // (a separate handle) must still be rejected because the
        // production guard is per-handle, not global.
        try {
          eventsB.recordInTransaction({
            jobId: jobIdB,
            phase: "phase-B",
            status: "running",
            message: "B-rejected",
          });
        } catch (err) {
          captured = err;
        }
        // Also confirm the A store CAN be reached inside its own
        // tracked tx (sanity check for the harness).
        eventsA.recordInTransaction({
          jobId: jobIdA,
          phase: "phase-A",
          status: "running",
          message: "A-ok",
        });
      });
      // Capture B-side state while handleB is still open.
      jobCountB = (handleB.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobIdB) as { n: number }).n;
      afterB = (handleB.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    } finally {
      // Close handleB last; B-side queries have already been captured.
      try { handleB.close(); } catch (_) { /* ignore */ }
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("WORKFLOW_EVENT_TRANSACTION_REQUIRED");

    // B is queried before close: ZERO rows for jobIdB on either
    // handle (per-handle guard is not a process-global boolean).
    // The A sanity event intentionally persists on BOTH handles'
    // visible count (beforeB + 1 on B; beforeA + 1 on A) — that
    // is the harness sanity check, not a guard violation.
    expect(jobCountB).toBe(0);
    expect(afterB).toBe(beforeB + 1);

    // A is still open: A's per-job B count is zero, A's per-job A
    // count is exactly one, and A's total count grew by one.
    jobCountA = (handleA.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobIdB) as { n: number }).n;
    jobCountAOnA = (handleA.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobIdA) as { n: number }).n;
    afterA = (handleA.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    expect(jobCountA).toBe(0);
    expect(jobCountAOnA).toBe(1);
    expect(afterA).toBe(beforeA + 1);
  });

  // ---- 2) Inside one caller transaction, two appends allocate
  // exact sequences [1,2], generated IDs, all fields, and write/raw/list
  // redaction while public text + non-secret metadata survive.
  it("inside withImmediateTransaction two appends allocate sequences [1,2] with full redaction", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA;
    const jobId = "job-a7-2";

    const results: WorkflowEventRecord[] = [];
    withImmediateTransaction(handle, () => {
      results.push(
        events.recordInTransaction({
          jobId,
          phase: "phase-1",
          status: "running",
          message: A7_MESSAGE,
          metadata: A7_METADATA,
        }),
      );
      results.push(
        events.recordInTransaction({
          jobId,
          phase: "phase-2",
          status: "completed",
          message: A7_MESSAGE_2,
          metadata: A7_METADATA_2,
        }),
      );
    });

    // The store returns exactly the two records we appended, in
    // the order we appended them.
    expect(results.length).toBe(2);

    // Per-record returned-field assertions.
    const [r0, r1] = results;

    // Exact sequences 1,2.
    expect(r0.sequence).toBe(1);
    expect(r1.sequence).toBe(2);

    // Generated IDs match the project event- prefix.
    expect(typeof r0.id).toBe("string");
    expect(r0.id.length).toBeGreaterThan(0);
    expect(r0.id).toMatch(/^event-/);
    expect(typeof r1.id).toBe("string");
    expect(r1.id.length).toBeGreaterThan(0);
    expect(r1.id).toMatch(/^event-/);
    expect(r0.id).not.toBe(r1.id);

    // Linkage, phase, status, message.
    expect(r0.jobId).toBe(jobId);
    expect(r0.phase).toBe("phase-1");
    expect(r0.status).toBe("running");
    expect(r0.message).toBe(A7_REDACTED_MESSAGE);

    expect(r1.jobId).toBe(jobId);
    expect(r1.phase).toBe("phase-2");
    expect(r1.status).toBe("completed");
    expect(r1.message).toBe(A7_REDACTED_MESSAGE_2);

    // createdAt round-trips through Date.toISOString() and equals
    // the canonical form.
    expect(new Date(r0.createdAt).toISOString()).toBe(r0.createdAt);
    expect(new Date(r1.createdAt).toISOString()).toBe(r1.createdAt);
    // createdAt is a parseable canonical ISO-8601 UTC string.
    expect(typeof r0.createdAt).toBe("string");
    expect(r0.createdAt.endsWith("Z")).toBe(true);
    expect(r1.createdAt.endsWith("Z")).toBe(true);

    // Returned metadata: public fields survive, secrets do not.
    expect(r0.metadata).toBeDefined();
    const r0Meta = r0.metadata as Record<string, unknown>;
    expect(r0Meta.publicField).toBe("a7-public-meta");
    expect(r0Meta.token).toBe("[REDACTED]");
    const r0MetaInner = r0Meta.inner as Record<string, unknown>;
    expect(r0MetaInner.password).toBe("[REDACTED]");
    expect(r0MetaInner.keep).toBe("a7-keep");

    expect(r1.metadata).toBeDefined();
    const r1Meta = r1.metadata as Record<string, unknown>;
    expect(r1Meta.kind).toBe("a7-second");
    expect(r1Meta.publicField).toBe("a7-second-public");
    expect(r1Meta.note).toBe("a7-second-note");
    expect(r1Meta.password).toBe("[REDACTED]");

    // Literal [REDACTED] is present in both redacted messages and
    // both redacted metadata payloads; no original secret survives
    // in any returned value.
    expect(r0.message).toContain("[REDACTED]");
    expect(r1.message).toContain("[REDACTED]");
    expect(JSON.stringify(r0.metadata)).toContain("[REDACTED]");
    expect(JSON.stringify(r1.metadata)).toContain("[REDACTED]");
    expect(r0.message).not.toContain(A7_SECRET_VALUE);
    expect(r1.message).not.toContain(A7_SECRET_VALUE_2);
    expect(JSON.stringify(r0.metadata)).not.toContain(A7_SECRET_VALUE_2);
    expect(JSON.stringify(r0.metadata)).not.toContain(SECRET_IN_METADATA);
    expect(JSON.stringify(r1.metadata)).not.toContain(A7_SECRET_VALUE_2);

    // Raw SELECT *: exact per-row assertions (no tautological
    // expect(row.sequence).toBe(row.sequence)).
    const rows = handle
      .prepare("SELECT * FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
      .all(jobId) as Array<Record<string, unknown>>;
    expect(rows.length).toBe(2);
    expect(rows[0].sequence).toBe(1);
    expect(rows[1].sequence).toBe(2);

    // Row 0 raw fields.
    expect(typeof rows[0].id).toBe("string");
    expect(rows[0].id).toMatch(/^event-/);
    expect(rows[0].id).toBe(r0.id);
    expect(rows[0].job_id).toBe(jobId);
    expect(rows[0].phase).toBe("phase-1");
    expect(rows[0].status).toBe("running");
    expect(rows[0].message).toBe(A7_REDACTED_MESSAGE);
    expect(typeof rows[0].created_at).toBe("string");
    expect(rows[0].created_at).toBe(r0.createdAt);
    expect(new Date(rows[0].created_at as string).toISOString()).toBe(rows[0].created_at);
    // metadata_json is non-null valid JSON, parsed and redacted.
    expect(rows[0].metadata_json).not.toBeNull();
    const rawMeta0 = JSON.parse(rows[0].metadata_json as string) as Record<string, unknown>;
    expect(rawMeta0.publicField).toBe("a7-public-meta");
    expect(rawMeta0.token).toBe("[REDACTED]");
    const rawMeta0Inner = rawMeta0.inner as Record<string, unknown>;
    expect(rawMeta0Inner.password).toBe("[REDACTED]");
    expect(rawMeta0Inner.keep).toBe("a7-keep");
    expect(JSON.stringify(rawMeta0)).not.toContain(SECRET_IN_METADATA);
    expect(JSON.stringify(rawMeta0)).not.toContain(A7_SECRET_VALUE_2);

    // Row 1 raw fields.
    expect(typeof rows[1].id).toBe("string");
    expect(rows[1].id).toMatch(/^event-/);
    expect(rows[1].id).toBe(r1.id);
    expect(rows[1].job_id).toBe(jobId);
    expect(rows[1].phase).toBe("phase-2");
    expect(rows[1].status).toBe("completed");
    expect(rows[1].message).toBe(A7_REDACTED_MESSAGE_2);
    expect(typeof rows[1].created_at).toBe("string");
    expect(rows[1].created_at).toBe(r1.createdAt);
    expect(new Date(rows[1].created_at as string).toISOString()).toBe(rows[1].created_at);
    expect(rows[1].metadata_json).not.toBeNull();
    const rawMeta1 = JSON.parse(rows[1].metadata_json as string) as Record<string, unknown>;
    expect(rawMeta1.kind).toBe("a7-second");
    expect(rawMeta1.publicField).toBe("a7-second-public");
    expect(rawMeta1.note).toBe("a7-second-note");
    expect(rawMeta1.password).toBe("[REDACTED]");
    expect(JSON.stringify(rawMeta1)).not.toContain(A7_SECRET_VALUE_2);

    // list(jobId) re-masks the message + metadata. Field-by-field
    // assertions against returned + raw values, not only generic
    // no-secret checks.
    const listed = (events as unknown as { list(jobId: string, limit?: number): WorkflowEventRecord[] }).list(jobId, 10);
    expect(listed.length).toBe(2);
    expect(listed[0].sequence).toBe(1);
    expect(listed[1].sequence).toBe(2);
    // Listed record 0 matches returned r0 and raw row 0 field-by-field.
    expect(listed[0].id).toBe(r0.id);
    expect(listed[0].id).toBe(rows[0].id);
    expect(listed[0].jobId).toBe(jobId);
    expect(listed[0].phase).toBe("phase-1");
    expect(listed[0].status).toBe("running");
    expect(listed[0].message).toBe(A7_REDACTED_MESSAGE);
    expect(listed[0].createdAt).toBe(r0.createdAt);
    expect(listed[0].createdAt).toBe(rows[0].created_at);
    const listedMeta0 = listed[0].metadata as Record<string, unknown>;
    expect(listedMeta0.publicField).toBe("a7-public-meta");
    expect(listedMeta0.token).toBe("[REDACTED]");
    const listedMeta0Inner = listedMeta0.inner as Record<string, unknown>;
    expect(listedMeta0Inner.password).toBe("[REDACTED]");
    expect(listedMeta0Inner.keep).toBe("a7-keep");
    expect(JSON.stringify(listed[0].metadata)).not.toContain(SECRET_IN_METADATA);
    expect(JSON.stringify(listed[0].metadata)).not.toContain(A7_SECRET_VALUE_2);

    // Listed record 1 matches returned r1 and raw row 1.
    expect(listed[1].id).toBe(r1.id);
    expect(listed[1].id).toBe(rows[1].id);
    expect(listed[1].jobId).toBe(jobId);
    expect(listed[1].phase).toBe("phase-2");
    expect(listed[1].status).toBe("completed");
    expect(listed[1].message).toBe(A7_REDACTED_MESSAGE_2);
    expect(listed[1].createdAt).toBe(r1.createdAt);
    expect(listed[1].createdAt).toBe(rows[1].created_at);
    const listedMeta1 = listed[1].metadata as Record<string, unknown>;
    expect(listedMeta1.kind).toBe("a7-second");
    expect(listedMeta1.publicField).toBe("a7-second-public");
    expect(listedMeta1.note).toBe("a7-second-note");
    expect(listedMeta1.password).toBe("[REDACTED]");
    expect(JSON.stringify(listed[1].metadata)).not.toContain(A7_SECRET_VALUE_2);

    // Public text + non-secret metadata fields survive every pass.
    expect(r0.message).toContain(A7_PUBLIC_PREFIX);
    expect(r0.message).toContain(A7_PUBLIC_SUFFIX);
    expect(r1.message).toContain(A7_PUBLIC_PREFIX);
    expect(r1.message).toContain(A7_PUBLIC_SUFFIX);
    expect(rawMeta0.publicField).toBe("a7-public-meta");
    expect(rawMeta1.publicField).toBe("a7-second-public");
    expect(rawMeta1.note).toBe("a7-second-note");
  });

  // ---- 2b) PUBLIC record() success with secret-bearing message
  // AND nested metadata. Returned, raw SELECT row, and list()
  // are already redacted at write time. The raw DB column must
  // contain no original secret. This is distinct from read-time
  // defense (test 3): we prove the write path itself is masked.
  it("public record() write-time redaction: returned, raw, and list are all masked immediately", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA & {
      record(input: WorkflowEventInput): WorkflowEventRecord;
    };
    const jobId = "job-a7-2b";

    const returned = events.record({
      jobId,
      phase: "phase-write",
      status: "running",
      message: A7_MESSAGE,
      metadata: A7_METADATA,
    });

    // 1) Returned record is masked.
    expect(returned.message).toBe(A7_REDACTED_MESSAGE);
    expect(returned.message).not.toContain(A7_SECRET_VALUE);
    const retMeta = returned.metadata as Record<string, unknown>;
    expect(retMeta.token).toBe("[REDACTED]");
    expect(retMeta.publicField).toBe("a7-public-meta");
    const retInner = retMeta.inner as Record<string, unknown>;
    expect(retInner.password).toBe("[REDACTED]");
    expect(retInner.keep).toBe("a7-keep");
    expect(JSON.stringify(returned.metadata)).not.toContain(SECRET_IN_METADATA);
    expect(JSON.stringify(returned.metadata)).not.toContain(A7_SECRET_VALUE_2);

    // 2) Raw DB row is masked (write-time, not read-time).
    const rawRow = handle
      .prepare("SELECT message, metadata_json FROM workflow_events WHERE id = ?")
      .get(returned.id) as { message: string; metadata_json: string | null };
    expect(rawRow.message).toBe(A7_REDACTED_MESSAGE);
    expect(rawRow.message).not.toContain(A7_SECRET_VALUE);
    expect(rawRow.metadata_json).not.toBeNull();
    const rawMetaParsed = JSON.parse(rawRow.metadata_json as string) as Record<string, unknown>;
    expect(rawMetaParsed.token).toBe("[REDACTED]");
    expect(rawMetaParsed.publicField).toBe("a7-public-meta");
    const rawInner = rawMetaParsed.inner as Record<string, unknown>;
    expect(rawInner.password).toBe("[REDACTED]");
    expect(rawInner.keep).toBe("a7-keep");
    expect(JSON.stringify(rawRow.metadata_json)).not.toContain(SECRET_IN_METADATA);
    expect(JSON.stringify(rawRow.metadata_json)).not.toContain(A7_SECRET_VALUE_2);

    // 3) list(jobId) is also masked (defense at read time on top
    // of write-time masking; both must produce the same redacted
    // shape).
    const listed = (events as unknown as { list(jobId: string, limit?: number): WorkflowEventRecord[] }).list(jobId, 10);
    expect(listed.length).toBe(1);
    expect(listed[0].message).toBe(A7_REDACTED_MESSAGE);
    expect(listed[0].message).not.toContain(A7_SECRET_VALUE);
    const listMeta = listed[0].metadata as Record<string, unknown>;
    expect(listMeta.token).toBe("[REDACTED]");
    expect(JSON.stringify(listed[0].metadata)).not.toContain(SECRET_IN_METADATA);
    expect(JSON.stringify(listed[0].metadata)).not.toContain(A7_SECRET_VALUE_2);
  });

  // ---- 3) Read-time defense. After a valid event, raw SQL overwrites
  // message + metadata_json with fresh secrets; list(jobId) must mask
  // them and preserve public text/fields.
  it("read-time defense: raw SQL overwrite of message + metadata is masked by list(jobId)", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA;
    const jobId = "job-a7-3";
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;

    const result = withImmediateTransaction(handle, () => {
      return events.recordInTransaction({
        jobId,
        phase: "phase-read",
        status: "running",
        message: A7_MESSAGE,
        metadata: { publicField: "a3-public" },
      });
    });

    expect(result).toBeDefined();
    // Fresh secret-bearing values injected via raw SQL to simulate a
    // row that got past write-time masking (legacy path / direct DB
    // access). list(jobId) must still mask on read.
    const runtimeMessage = "runtime-public api_key=RUNTIME_SECRET_KEY runtime-public-suffix";
    const runtimeMeta = JSON.stringify({
      token: "Bearer RUNTIME_BEARER_TOKEN",
      password: "RUNTIME_PASSWORD",
      keep: "runtime-keep",
    });
    handle
      .prepare("UPDATE workflow_events SET message = ?, metadata_json = ? WHERE id = ?")
      .run(runtimeMessage, runtimeMeta, result.id);

    // The threat model: the raw row holds the fresh secrets on disk.
    const rawAfter = handle
      .prepare("SELECT message, metadata_json FROM workflow_events WHERE id = ?")
      .get(result.id) as { message: string; metadata_json: string | null };
    expect(rawAfter.message).toContain("RUNTIME_SECRET_KEY");
    expect(rawAfter.metadata_json).toContain("RUNTIME_BEARER_TOKEN");

    const listed = (events as unknown as { list(jobId: string, limit?: number): WorkflowEventRecord[] }).list(jobId, 10);
    expect(listed.length).toBe(1);
    const rec = listed[0];
    expect(rec.message).toContain("[REDACTED]");
    expect(rec.message).not.toContain("RUNTIME_SECRET_KEY");
    expect(rec.message).toContain("runtime-public");
    expect(rec.message).toContain("runtime-public-suffix");
    expect(JSON.stringify(rec.metadata)).toContain("[REDACTED]");
    expect(JSON.stringify(rec.metadata)).not.toContain("RUNTIME_BEARER_TOKEN");
    expect(JSON.stringify(rec.metadata)).not.toContain("RUNTIME_PASSWORD");
    expect(JSON.stringify(rec.metadata)).toContain("runtime-keep");

    // No phantom rows beyond the original insert.
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    expect(after).toBe(before + 1);
  });

  // ---- 4) Caller rollback: a valid recordInTransaction then a thrown
  // sentinel escapes the helper; both TOTAL and per-job count are
  // unchanged.
  it("caller rollback removes a successfully recorded event and rethrows the sentinel", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA;
    const jobId = "job-a7-4";
    const beforeTotal = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    const beforeJob = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobId) as { n: number }).n;

    const SENTINEL = new Error("force-rollback-a7");
    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        events.recordInTransaction({
          jobId,
          phase: "phase-rollback",
          status: "running",
          message: "will-be-rolled-back",
        });
        throw SENTINEL;
      });
    } catch (err) {
      captured = err;
    }
    // The sentinel escapes the transaction helper verbatim.
    expect(captured).toBe(SENTINEL);

    // Zero rows persisted overall AND for the job.
    const afterTotal = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    const afterJob = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobId) as { n: number }).n;
    expect(afterTotal).toBe(beforeTotal);
    expect(afterJob).toBe(beforeJob);
  });

  // ---- 5) Deterministic unique-sequence collision + no retry. Uses
  // DatabaseSync.function as a UDF counter that throws if invoked >1
  // (exposing any retry), plus a TEMP BEFORE INSERT trigger on this
  // handle. The public record() wrapper must map the collision to
  // WORKFLOW_EVENT_SEQUENCE_CONFLICT and never retry.
  it("deterministic unique-sequence collision: trigger forces a UNIQUE(job_id,sequence) failure; record() maps to WORKFLOW_EVENT_SEQUENCE_CONFLICT with counter exactly 1 and zero rows", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA & {
      record(input: WorkflowEventInput): WorkflowEventRecord;
    };

    // A JS counter UDF bound to this handle only. The function
    // throws if invoked more than once: any retry by the wrapper
    // would raise the second-call guard.
    let counter = 0;
    handle.function("a7_counter", () => {
      counter += 1;
      if (counter > 1) {
        throw new Error(`UDF invoked ${counter} times — wrapper retried`);
      }
      return counter;
    });

    // TEMP BEFORE INSERT trigger on workflow_events for THIS handle.
    handle.exec(`
      CREATE TEMP TRIGGER a7_force_seq_collision
      BEFORE INSERT ON workflow_events
      FOR EACH ROW
      WHEN NEW.phase = 'force-conflict'
      BEGIN
        SELECT a7_counter();
        INSERT INTO workflow_events
          (id, job_id, sequence, phase, status, message, metadata_json, created_at)
        VALUES
          ('sentinel-' || NEW.id, NEW.job_id, NEW.sequence, 'sentinel', 'completed', '', NULL, NEW.created_at);
      END;
    `);

    const before = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;

    let captured: unknown = null;
    try {
      // PUBLIC record() must be transaction-owning. The wrapper
      // begins, computes sequence, fires the trigger, sees the
      // collision, and must map to WORKFLOW_EVENT_SEQUENCE_CONFLICT
      // without retrying.
      events.record({
        jobId: "job-a7-5",
        phase: "force-conflict",
        status: "running",
        message: "trigger-collision",
      });
    } catch (err) {
      captured = err;
    }
    // The wrapper MUST throw the pinned code, not a generic SQLite
    // error. The UDF ran exactly once (any retry would have raised
    // the second-call guard).
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("WORKFLOW_EVENT_SEQUENCE_CONFLICT");
    expect(counter).toBe(1);

    // After the wrapper rolls back its own transaction, neither the
    // outer insert nor the sentinel pre-insert survives.
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // ---- 6) Public record() inside an outer withImmediateTransaction
  // => DB_TRANSACTION_NESTED + zero rows persisted.
  it("the public record() wrapper, called inside an outer transaction, raises DB_TRANSACTION_NESTED", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA & {
      record(input: WorkflowEventInput): WorkflowEventRecord;
    };

    const jobId = "job-a7-6";
    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        events.record({
          jobId,
          phase: "phase-nested",
          status: "running",
          message: "inside-outer-tx",
        });
        return "outer-ok";
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("DB_TRANSACTION_NESTED");

    // The outer transaction rolled back, so the inner event never
    // persisted.
    const count = (handle.prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?").get(jobId) as { n: number }).n;
    expect(count).toBe(0);
  });

  // ---- 7) TRUE concurrency with deterministic boundary proof.
  // Two real Worker threads, each on its own node:sqlite
  // DatabaseSync handle (not openBountyDatabase — the test
  // deliberately uses the raw node:sqlite constructor so the
  // Proxy can intercept the exec("BEGIN IMMEDIATE") call before
  // any production wrapper layer sees it) to the same temp DB,
  // each calling PUBLIC WorkflowEventStore.record() once for the
  // same job. Each worker wraps its DB in a Proxy that
  // intercepts ONLY exec("BEGIN IMMEDIATE"). The parent holds a
  // third blocker DB handle with a raw BEGIN IMMEDIATE so both
  // workers are proven to have entered the BEGIN path before
  // COMMIT. Workers synchronize via Atomics on a SharedArrayBuffer.
  // There is no sleep-based ordering — only Atomics barriers. The
  // parent polling timeouts are liveness observation.
  it("two real Workers with proxy+blocker: exact sequences [1,2] with no error and no sleep-based ordering", async () => {
    const a7_PARENT_PHASE_TIMEOUT_MS = 10_000;
    // Worker waits MUST exceed the corresponding parent phase
    // timeout so a parent-side timeout always fires first and the
    // failing parent error is the one observed.
    const a7_WORKER_START_TIMEOUT_MS = 25_000;
    const a7_WORKER_PEER_TIMEOUT_MS = 30_000;
    const a7_WORKER_BLOCKER_TIMEOUT_MS = 30_000;
    const a7_WORKER_GRANT_TIMEOUT_MS = 30_000;

    // SharedArrayBuffer layout (int32 cells):
    //   0  ready_a
    //   1  ready_b
    //   2  start (1 = released)
    //   3  at_boundary_a
    //   4  at_boundary_b
    //   5  blocker_held (1 = parent holds raw BEGIN IMMEDIATE)
    //   6  begin_forward_granted (1 = parent set this ONLY after
    //      COMMITing the blocker; workers may then call target.exec)
    //   7  begin_count_a
    //   8  begin_count_b
    //   9  forward_ready_a (1 = worker A parked just before
    //      target.exec while the blocker is still held)
    //  10  forward_ready_b (1 = worker B parked just before
    //      target.exec while the blocker is still held)
    const sab = new SharedArrayBuffer(11 * Int32Array.BYTES_PER_ELEMENT);
    const i32 = new Int32Array(sab);
    // Initial state.
    i32[2] = 0; // start
    i32[5] = 0; // blocker_held
    i32[6] = 0; // begin_forward_granted

    // Close the per-test handle so the workers can open the same
    // file exclusively.
    const handle = openDb();
    handle.close();
    db = null;

    const jobId = "job-a7-conc";

    const moduleUrl = new URL("../src/core/jobs/workflow-event-store.ts", import.meta.url).href;

    const source = a7ProxyWorkerSource(
      a7_WORKER_START_TIMEOUT_MS,
      a7_WORKER_PEER_TIMEOUT_MS,
      a7_WORKER_BLOCKER_TIMEOUT_MS,
      a7_WORKER_GRANT_TIMEOUT_MS,
    );

    interface ConcMsg { kind: "ready" | "result" | "worker-error"; value: number; message?: string }
    interface ConcOutcome {
      a: ConcMsg[];
      b: ConcMsg[];
      aError: string | null;
      bError: string | null;
      aExitCode: number | null;
      bExitCode: number | null;
    }

    function runWorkers(): Promise<ConcOutcome> {
      return new Promise<ConcOutcome>((resolve, reject) => {
        let a: Worker | null = null;
        let b: Worker | null = null;
        const outcome: ConcOutcome = {
          a: [], b: [],
          aError: null, bError: null,
          aExitCode: null, bExitCode: null,
        };
        const wire = (worker: Worker, bucket: ConcMsg[], key: "a" | "b") => {
          worker.on("message", (msg: ConcMsg) => {
            if (msg.kind === "worker-error") {
              if (key === "a") outcome.aError = String(msg.message ?? "worker-error");
              else outcome.bError = String(msg.message ?? "worker-error");
              return;
            }
            bucket.push({ kind: msg.kind, value: Number(msg.value) });
          });
          worker.on("error", (err) => {
            if (key === "a") outcome.aError = err.message;
            else outcome.bError = err.message;
          });
          worker.on("exit", (code) => {
            if (key === "a") outcome.aExitCode = code;
            else outcome.bExitCode = code;
          });
        };
        const teardown = async () => {
          if (a) { try { await a.terminate(); } catch (_) { /* ignore */ } a = null; }
          if (b) { try { await b.terminate(); } catch (_) { /* ignore */ } b = null; }
        };
        try {
          a = new Worker(source, {
            eval: true,
            workerData: {
              sab,
              jobId,
              dbPath: dbFile,
              role: "a",
              storeUrl: moduleUrl,
              parentUrl: import.meta.url,
              readyOffset: 0,
              atBoundaryOffset: 3,
              otherAtBoundaryOffset: 4,
              forwardReadyOffset: 9,
              beginCountOffset: 7,
            },
          });
          wire(a, outcome.a, "a");
          b = new Worker(source, {
            eval: true,
            workerData: {
              sab,
              jobId,
              dbPath: dbFile,
              role: "b",
              storeUrl: moduleUrl,
              parentUrl: import.meta.url,
              readyOffset: 1,
              atBoundaryOffset: 4,
              otherAtBoundaryOffset: 3,
              forwardReadyOffset: 10,
              beginCountOffset: 8,
            },
          });
          wire(b, outcome.b, "b");
        } catch (err) {
          void teardown().then(() => reject(err), () => reject(err));
          return;
        }
        // waitForReady fails EARLY with a diagnostic if either
        // worker reported an error or exited before both became
        // ready. Do not hide startup failures behind a generic
        // timeout.
        const waitForReady = async () => {
          const start = Date.now();
          while (Date.now() - start < a7_PARENT_PHASE_TIMEOUT_MS) {
            if (Atomics.load(i32, 0) === 1 && Atomics.load(i32, 1) === 1) return;
            if (outcome.aError !== null || outcome.bError !== null) {
              throw new Error(
                `a7 worker startup error (ready not reached); aErr=${outcome.aError ?? "<none>"} bErr=${outcome.bError ?? "<none>"}`,
              );
            }
            if (outcome.aExitCode !== null || outcome.bExitCode !== null) {
              throw new Error(
                `a7 worker exited before READY; aExit=${outcome.aExitCode} bExit=${outcome.bExitCode}`,
              );
            }
            await new Promise((r) => setTimeout(r, 10));
          }
          throw new Error(
            `timeout waiting for proxy+blocker workers ready; aErr=${outcome.aError ?? "<none>"} bErr=${outcome.bError ?? "<none>"} aExit=${outcome.aExitCode} bExit=${outcome.bExitCode}`,
          );
        };
        // waitForAtBoundary and waitForForwardReady run while the
        // third blocker handle may still hold a raw BEGIN IMMEDIATE.
        // They MUST NOT call teardown() — terminating workers while
        // a transaction is open on a shared file can wedge the file
        // and break the blocker's ROLLBACK. They detect premature
        // result/error/exit and throw; the outer try/finally is
        // responsible for ROLLBACK/close and worker teardown on
        // failure.
        const failFast = (label: string) => {
          if (outcome.a.some((m) => m.kind === "result") || outcome.b.some((m) => m.kind === "result")) {
            throw new Error(`${label}: workers must not have returned any result yet`);
          }
          if (outcome.aError !== null || outcome.bError !== null) {
            throw new Error(`${label}: workers must not have errored; aErr=${outcome.aError} bErr=${outcome.bError}`);
          }
          if (outcome.aExitCode !== null || outcome.bExitCode !== null) {
            throw new Error(`${label}: workers must not have exited`);
          }
        };
        const waitForAtBoundary = async () => {
          const start = Date.now();
          while (Date.now() - start < a7_PARENT_PHASE_TIMEOUT_MS) {
            if (Atomics.load(i32, 3) === 1 && Atomics.load(i32, 4) === 1) return;
            failFast("at-boundary");
            await new Promise((r) => setTimeout(r, 10));
          }
          throw new Error("timeout waiting for both workers at proxy boundary");
        };
        const waitForForwardReady = async () => {
          const start = Date.now();
          while (Date.now() - start < a7_PARENT_PHASE_TIMEOUT_MS) {
            if (Atomics.load(i32, 9) === 1 && Atomics.load(i32, 10) === 1) return;
            failFast("forward-ready");
            await new Promise((r) => setTimeout(r, 10));
          }
          throw new Error("timeout waiting for both workers at forward-ready slot");
        };
        const waitForExit = async () => {
          const start = Date.now();
          while (Date.now() - start < a7_PARENT_PHASE_TIMEOUT_MS) {
            if (outcome.aExitCode !== null && outcome.bExitCode !== null) return;
            await new Promise((r) => setTimeout(r, 10));
          }
          await teardown();
          throw new Error("timeout waiting for workers exit");
        };
        (async () => {
          try {
            await waitForReady();
            // Open a third blocker DB handle and acquire a raw
            // BEGIN IMMEDIATE so the workers are guaranteed to
            // contend at the transaction-owning boundary.
            const blocker = openBountyDatabase(dbFile);
            let blockerCommitted = false;
            try {
              blocker.exec("BEGIN IMMEDIATE");
              Atomics.store(i32, 5, 1); // blocker_held
              Atomics.notify(i32, 5, Infinity);
              // Both workers have finished their start-wait and are
              // about to call public record(). Release start. The
              // workers will run their per-handle BEGIN through the
              // proxy and park at the barrier.
              Atomics.store(i32, 2, 1); // start
              Atomics.notify(i32, 2, Infinity);
              // waitForAtBoundary proves both workers reached the
              // BEGIN IMMEDIATE interception and waited peer +
              // blocker — i.e. they would otherwise hold a writer
              // lock.
              await waitForAtBoundary();
              // At-boundary invariant assertions.
              const countA = Atomics.load(i32, 7);
              const countB = Atomics.load(i32, 8);
              if (countA !== 1 || countB !== 1) {
                throw new Error(`at-boundary: begin counts must be exactly 1 each; got A=${countA} B=${countB}`);
              }
              // waitForForwardReady proves both workers reached the
              // forward-ready slot — i.e. the call is parked just
              // before target.exec("BEGIN IMMEDIATE") while the
              // blocker is still holding the writer lock.
              await waitForForwardReady();
              if (Atomics.load(i32, 9) !== 1 || Atomics.load(i32, 10) !== 1) {
                throw new Error(`forward-ready: forward-ready flags must both be 1; got A=${Atomics.load(i32, 9)} B=${Atomics.load(i32, 10)}`);
              }
              // Commit the blocker FIRST, set blockerCommitted, then
              // (still inside the try, after COMMIT) grant workers.
              // On any failure path the finally below ROLLBACKs the
              // blocker and closes it, leaving the workers parked on
              // an unreleased grant — at which point the outer catch
              // calls teardown.
              blocker.exec("COMMIT");
              blockerCommitted = true;
              Atomics.store(i32, 6, 1); // begin_forward_granted
              Atomics.notify(i32, 6, Infinity);
            } finally {
              if (!blockerCommitted) {
                try { blocker.exec("ROLLBACK"); } catch (_) { /* ignore */ }
              }
              try { blocker.close(); } catch (_) { /* ignore */ }
            }
            await waitForExit();
            if (outcome.aExitCode !== 0 || outcome.bExitCode !== 0) {
              throw new Error(
                `worker exit codes a=${outcome.aExitCode} b=${outcome.bExitCode} aErr=${outcome.aError ?? "<none>"} bErr=${outcome.bError ?? "<none>"}`,
              );
            }
            resolve(outcome);
          } catch (err) {
            await teardown();
            reject(err);
          }
        })();
      });
    }

    const outcome = await runWorkers();
    expect(outcome.aError).toBeNull();
    expect(outcome.bError).toBeNull();
    // Each worker fired BEGIN IMMEDIATE through the proxy exactly once.
    expect(Atomics.load(i32, 7)).toBe(1);
    expect(Atomics.load(i32, 8)).toBe(1);
    // Both workers parked at forward-ready before target.exec.
    expect(Atomics.load(i32, 9)).toBe(1);
    expect(Atomics.load(i32, 10)).toBe(1);
    // Exactly one result per worker.
    expect(outcome.a.filter((m) => m.kind === "result").length).toBe(1);
    expect(outcome.b.filter((m) => m.kind === "result").length).toBe(1);
    const seqA = outcome.a.find((m) => m.kind === "result")?.value;
    const seqB = outcome.b.find((m) => m.kind === "result")?.value;
    expect(seqA).toBeDefined();
    expect(seqB).toBeDefined();
    const sequences = [seqA!, seqB!].sort((x, y) => x - y);
    expect(sequences).toEqual([1, 2]);

    // Final DB: exactly two distinct rows for the job with sequences [1,2].
    const verify = openBountyDatabase(dbFile);
    try {
      const countRow = verify
        .prepare("SELECT COUNT(*) AS c, COUNT(DISTINCT sequence) AS d FROM workflow_events WHERE job_id = ?")
        .get(jobId) as { c: number; d: number };
      expect(countRow.c).toBe(2);
      expect(countRow.d).toBe(2);
      const seqs = (verify
        .prepare("SELECT sequence FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
        .all(jobId) as Array<{ sequence: number }>).map((r) => r.sequence);
      expect(seqs).toEqual([1, 2]);
    } finally {
      try { verify.close(); } catch (_) { /* ignore */ }
    }
  }, A7_TEST_TIMEOUT_MS);

  // ---- 8) Collision cleanup/recovery. SELF-CONTAINED — this test
  // installs its own UDF counter + TEMP trigger and forces a unique
  // collision on its own handle. It does NOT depend on test 5's
  // handle state (each test opens a fresh handle in beforeEach).
  // After the forced collision and rollback, the raw row count for
  // the job must be exactly 0, then a normal PUBLIC record() must
  // succeed with sequence 1. The successful second record proves
  // the production transaction/WeakSet guard state was cleaned up
  // — the TEMP trigger and UDF remain installed on this handle
  // (TEMP objects are scoped to the connection, not the
  // transaction), but their WHEN predicate (NEW.phase =
  // 'force-recover-conflict') does not match the normal phase
  // 'phase-recover', so the trigger is a no-op for the recovery
  // write. Close and reopen the DB; the row persists.
  it("after unique-collision rollback: a normal public record() on the same store/handle returns sequence 1 and persists across close/reopen", () => {
    const handle = openDb();
    const events = new WorkflowEventStore(handle) as unknown as WorkflowEventStoreSliceA & {
      record(input: WorkflowEventInput): WorkflowEventRecord;
    };

    // A UDF counter + TEMP trigger that will be installed on this
    // handle. After the trigger fires once and the wrapper rolls
    // back, a normal record() must succeed and produce sequence 1.
    let counter = 0;
    handle.function("a7_recover_counter", () => {
      counter += 1;
      if (counter > 1) {
        throw new Error(`recovery UDF invoked ${counter} times — wrapper retried after collision`);
      }
      return counter;
    });
    handle.exec(`
      CREATE TEMP TRIGGER a7_recover_force_collision
      BEFORE INSERT ON workflow_events
      FOR EACH ROW
      WHEN NEW.phase = 'force-recover-conflict'
      BEGIN
        SELECT a7_recover_counter();
        INSERT INTO workflow_events
          (id, job_id, sequence, phase, status, message, metadata_json, created_at)
        VALUES
          ('sentinel-' || NEW.id, NEW.job_id, NEW.sequence, 'sentinel', 'completed', '', NULL, NEW.created_at);
      END;
    `);

    const jobId = "job-a7-recover";
    // First record: must collide and roll back.
    let captured: unknown = null;
    try {
      events.record({
        jobId,
        phase: "force-recover-conflict",
        status: "running",
        message: "first-collision",
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("WORKFLOW_EVENT_SEQUENCE_CONFLICT");
    expect(counter).toBe(1);

    // After the forced collision the wrapper rolled back its own
    // transaction: the raw row count for this job on this handle
    // must be exactly 0 (no phantom row from the wrapper, no
    // sentinel row from the trigger, no committed event).
    const jobCountAfterCollision = (handle
      .prepare("SELECT COUNT(*) AS n FROM workflow_events WHERE job_id = ?")
      .get(jobId) as { n: number }).n;
    expect(jobCountAfterCollision).toBe(0);

    // Second record on the same store/handle: must succeed with
    // sequence 1, proving the guard was cleaned up and the wrapper
    // did not leave the handle in a poisoned state.
    const normalReturned = events.record({
      jobId,
      phase: "phase-recover",
      status: "running",
      message: "after-recovery",
    });
    expect(normalReturned).toBeDefined();
    expect(normalReturned.sequence).toBe(1);
    expect(normalReturned.jobId).toBe(jobId);
    expect(normalReturned.phase).toBe("phase-recover");

    // Verify the recovery row is in the DB and list returns it.
    const listed = (events as unknown as { list(jobId: string, limit?: number): WorkflowEventRecord[] }).list(jobId, 10);
    expect(listed.length).toBe(1);
    expect(listed[0].sequence).toBe(1);
    expect(listed[0].phase).toBe("phase-recover");

    // Close the handle and reopen: the recovery row must persist.
    handle.close();
    db = null;
    const reopened = openBountyDatabase(dbFile);
    try {
      const persisted = reopened
        .prepare("SELECT id, sequence, phase FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
        .all(jobId) as Array<{ id: string; sequence: number; phase: string }>;
      expect(persisted.length).toBe(1);
      expect(persisted[0].sequence).toBe(1);
      expect(persisted[0].phase).toBe("phase-recover");
      expect(persisted[0].id).toBe(normalReturned.id);
    } finally {
      try { reopened.close(); } catch (_) { /* ignore */ }
    }
  });
});

// ---------------------------------------------------------------------------
// A8: JobManager finalizer — in-tx primitive that derives a job's
//     status/pauseReason/statusDetail from its required actions, plus
//     the public finalize() wrapper that owns a transaction. The
//     21 unordered distinct-pairs table pins the precedence
//     derivation from the contract §9: outcome_unknown first, then
//     running, then blocked|failed, then pending, then approved,
//     then all-executed/zero-required. The statusDetail JSON is
//     count-only and has a fixed key order.
// ---------------------------------------------------------------------------

describe("P0.2 Packet 2 Slice A — JobManager finalize / finalizeInTransaction", () => {
  // The finalizer is a NEW public method on JobManager; the test
  // exercises it through a narrow structural interface so the test
  // file transpiles before the production method ships.
  type SliceAJobManager = JobManager & JobManagerSliceA;

  // Canonical far-future 2099 timestamps used by every finalizer
  // fixture. The finalizer must not depend on the live clock, and
  // these dates are far enough in the future to never be live.
  const A8_JOB_CREATED_AT = "2099-01-01T00:00:00.000Z";
  const A8_REVIEWED_AT = "2099-01-01T00:00:00.000Z";
  const A8_EXPIRES_AT = "2099-01-01T00:15:00.000Z";
  const A8_INVALIDATED_AT = "2099-01-01T00:00:01.000Z";
  const A8_INVALIDATION_REASON = "policy_blocked_at_claim";
  const A8_FUTURE_LEASE = "2099-01-01T00:05:00.000Z";
  const A8_STARTED_AT = "2099-01-01T00:00:00.000Z";
  const A8_DISPATCHED_AT = "2099-01-01T00:00:05.000Z";
  const A8_FINISHED_AT = "2099-01-01T00:00:10.000Z";
  const A8_EXECUTED_AT = "2099-01-01T00:00:10.000Z";
  const A8_TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const A8_TOKEN_OWNER = "owner-a8";

  // Per-status required-action shape. Production reads only what a
  // row in that state can legitimately have. Each function returns a
  // raw seed that goes through insertRawV2Action. The action_id and
  // review_id are caller-supplied so the per-pair seed can stay
  // self-describing.
  interface StatusSeed {
    actionId: string;
    reviewId: string;
    status:
      | "pending"
      | "approved"
      | "running"
      | "executed"
      | "blocked"
      | "failed"
      | "outcome_unknown";
  }

  function seedJobWithInitialRow(handle: BountyDatabase, jobId: string): void {
    // Insert the job with a fixed test-owned id and a fixed initial
    // raw row. The finalizer must derive the tuple from the actions
    // and overwrite this initial row; the initial row is used only
    // as a "before" snapshot for the rollback / guard tests.
    handle
      .prepare(
        "INSERT INTO jobs (id, type, target, mode, status, created_at, updated_at, pause_reason, status_detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        jobId,
        "hunt",
        "https://slice-a.example/jobs/" + jobId,
        "safe",
        "running",
        A8_JOB_CREATED_AT,
        A8_JOB_CREATED_AT,
        null,
        null,
      );
  }

  function seedValidReviewFor(
    handle: BountyDatabase,
    jobId: string,
    actionId: string,
    reviewId: string,
  ): void {
    insertValidActiveReview(handle, {
      id: reviewId,
      actionId,
      jobId,
      source: "human",
      reviewerId: REVIEWER_ID,
      reviewedAt: A8_REVIEWED_AT,
      expiresAt: A8_EXPIRES_AT,
    });
  }

  function seedLifecycleValidAction(
    handle: BountyDatabase,
    jobId: string,
    seed: StatusSeed,
    requiredForCompletion: 0 | 1 = 1,
  ): void {
    // The ACTUAL seeded jobId is passed in explicitly. The function
    // never invents a jobId; both the review row and the action row
    // link to this exact id. This is enforced by the fixture
    // integrity assertion `assertA8FixtureLinkage` below.
    if (seed.status !== "pending") {
      seedValidReviewFor(handle, jobId, seed.actionId, seed.reviewId);
      if (seed.status === "blocked") {
        handle
          .prepare("UPDATE action_reviews SET invalidated_at = ?, invalidation_reason = ? WHERE id = ?")
          .run(A8_INVALIDATED_AT, A8_INVALIDATION_REASON, seed.reviewId);
      }
    }

    const base: RawV2ActionSeed = {
      id: seed.actionId,
      jobId,
      status: seed.status,
      requiredForCompletion,
      activeReviewId: seed.status === "pending" ? null : seed.reviewId,
      plannedScopeHash: seed.status === "pending" ? null : SCOPE_HASH,
      plannedPolicyHash: seed.status === "pending" ? null : POLICY_HASH,
      plannedActionHash: seed.status === "pending" ? null : ACTION_HASH,
      plannedContextHash: seed.status === "pending" ? null : CONTEXT_HASH,
    };

    // Per-status lifecycle columns.
    if (seed.status === "pending") {
      base.executionToken = null;
      base.executionOwner = null;
      base.leaseExpiresAt = null;
      base.startedAt = null;
      base.dispatchStartedAt = null;
      base.finishedAt = null;
      base.outcomeCertainty = null;
      base.lastErrorCode = null;
      base.lastErrorMessage = null;
      base.executedAt = null;
    } else if (seed.status === "approved") {
      base.executionToken = null;
      base.executionOwner = null;
      base.leaseExpiresAt = null;
      base.startedAt = null;
      base.dispatchStartedAt = null;
      base.finishedAt = null;
      base.outcomeCertainty = null;
      base.lastErrorCode = null;
      base.lastErrorMessage = null;
      base.executedAt = null;
    } else if (seed.status === "running") {
      base.executionToken = A8_TOKEN;
      base.executionOwner = A8_TOKEN_OWNER;
      base.leaseExpiresAt = A8_FUTURE_LEASE;
      base.startedAt = A8_STARTED_AT;
      base.dispatchStartedAt = null;
      base.finishedAt = null;
      base.outcomeCertainty = null;
      base.lastErrorCode = null;
      base.lastErrorMessage = null;
      base.executedAt = null;
    } else if (seed.status === "executed") {
      // Terminalization cleared the bearer capability columns.
      base.executionToken = null;
      base.executionOwner = null;
      base.leaseExpiresAt = null;
      base.startedAt = A8_STARTED_AT;
      base.dispatchStartedAt = A8_DISPATCHED_AT;
      base.finishedAt = A8_FINISHED_AT;
      base.outcomeCertainty = "success";
      base.lastErrorCode = null;
      base.lastErrorMessage = null;
      base.executedAt = A8_EXECUTED_AT;
    } else if (seed.status === "blocked") {
      // Blocked retains the approval pointer + planned hashes on the
      // action, but the underlying review is invalidated. No
      // execution columns: blocked is not a finished execution and
      // carries no error (the review carries the reason).
      base.executionToken = null;
      base.executionOwner = null;
      base.leaseExpiresAt = null;
      base.startedAt = null;
      base.dispatchStartedAt = null;
      base.finishedAt = null;
      base.outcomeCertainty = null;
      base.lastErrorCode = null;
      base.lastErrorMessage = null;
      base.executedAt = null;
    } else if (seed.status === "failed") {
      // failed/not_dispatched: NO dispatch marker, NO executed_at.
      base.executionToken = null;
      base.executionOwner = null;
      base.leaseExpiresAt = null;
      base.startedAt = A8_STARTED_AT;
      base.dispatchStartedAt = null;
      base.finishedAt = A8_FINISHED_AT;
      base.outcomeCertainty = "not_dispatched";
      base.lastErrorCode = "ACTION_LEASE_EXPIRED";
      base.lastErrorMessage = SECRET_LAST_ERROR_MESSAGE;
      base.executedAt = null;
    } else if (seed.status === "outcome_unknown") {
      base.executionToken = null;
      base.executionOwner = null;
      base.leaseExpiresAt = null;
      base.startedAt = A8_STARTED_AT;
      base.dispatchStartedAt = A8_DISPATCHED_AT;
      base.finishedAt = A8_FINISHED_AT;
      base.outcomeCertainty = "possibly_dispatched";
      base.lastErrorCode = "ACTION_FINALIZE_RACE";
      base.lastErrorMessage = SECRET_LAST_ERROR_MESSAGE;
      base.executedAt = null;
    }

    insertRawV2Action(handle, base);
  }

  // Fixture-integrity assertion: every expected A8 action has
  // action_queue.job_id (actions.job_id) exactly equal to the actual
  // seeded jobId, and the total count matches. This catches future
  // invented-ID regressions (e.g. the helper accidentally
  // stringifies actionId into jobId). It does NOT query a
  // fabricated id. The caller passes the exact set of expected
  // action ids and (optionally) the exact set of expected review
  // ids for non-pending actions, so the assertion is independent
  // of any particular review-id naming convention.
  function assertA8FixtureLinkage(
    handle: BountyDatabase,
    jobId: string,
    expectedActionIds: ReadonlyArray<string>,
    expectedReviewIds: ReadonlyArray<string> = [],
  ): void {
    const actual = handle
      .prepare("SELECT id, job_id FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(jobId) as Array<{ id: string; job_id: string }>;
    // Every row's job_id MUST equal the actual jobId; the query
    // already filters by it, but assert it again on each row so a
    // future bug that inserts the wrong id is caught here.
    for (const row of actual) {
      expect(row.job_id, `action ${row.id} linked to wrong job_id`).toBe(jobId);
    }
    const actualIds = actual.map((r) => r.id).sort();
    const expectedSorted = [...expectedActionIds].sort();
    expect(actualIds).toEqual(expectedSorted);

    if (expectedReviewIds.length > 0) {
      const placeholders = expectedReviewIds.map(() => "?").join(", ");
      const reviews = handle
        .prepare(`SELECT id, job_id, action_id FROM action_reviews WHERE id IN (${placeholders})`)
        .all(...expectedReviewIds) as Array<{ id: string; job_id: string; action_id: string }>;
      expect(reviews.length, "review row count mismatch").toBe(expectedReviewIds.length);
      for (const row of reviews) {
        expect(row.job_id, `review ${row.id} linked to wrong job_id`).toBe(jobId);
        // The action_id on the review must match an action we just
        // seeded, not an invented id.
        expect(expectedActionIds, `review ${row.id} has unexpected action_id`).toContain(row.action_id);
      }
    }
  }

  // The seven required-action count keys must appear in this exact
  // order with no whitespace and no extra keys. `requiredActionCounts`
  // is the first top-level key, then `schemaVersion`. This mirrors
  // the contract §9 canonical count-only JSON.
  const A8_COUNT_KEYS_ORDER: ReadonlyArray<keyof RequiredActionCounts> = [
    "approved",
    "blocked",
    "executed",
    "failed",
    "outcome_unknown",
    "pending",
    "running",
  ];

  function expectedStatusDetail(
    counts: RequiredActionCounts,
  ): string {
    const obj: Record<string, unknown> = {};
    obj.requiredActionCounts = counts;
    obj.schemaVersion = 1;
    // Compact: no whitespace, key order = insertion order in modern
    // V8 (preserved for string keys, non-numeric). Production must
    // emit the same compact string via canonicalize(...).toString.
    return JSON.stringify(obj);
  }

  function deriveFromSeeds(
    seeds: StatusSeed[],
  ): { status: "queued" | "running" | "paused" | "failed" | "completed"; pauseReason: PauseReason | null; counts: RequiredActionCounts } {
    const counts: RequiredActionCounts = {
      approved: 0,
      blocked: 0,
      executed: 0,
      failed: 0,
      outcome_unknown: 0,
      pending: 0,
      running: 0,
    };
    for (const s of seeds) {
      counts[s.status] += 1;
    }
    let status: "queued" | "running" | "paused" | "failed" | "completed";
    let pauseReason: PauseReason | null;
    if (counts.outcome_unknown > 0) {
      status = "paused";
      pauseReason = "reconciliation_required";
    } else if (counts.running > 0) {
      status = "running";
      pauseReason = null;
    } else if (counts.blocked > 0 || counts.failed > 0) {
      status = "failed";
      // Contract: A failed job uses policy_blocked when at least
      // one required action is blocked, and null when the failing
      // set contains only failed.
      pauseReason = counts.blocked > 0 ? "policy_blocked" : null;
    } else if (counts.pending > 0) {
      status = "paused";
      pauseReason = "approval_required";
    } else if (counts.approved > 0) {
      status = "paused";
      pauseReason = "execution_ready";
    } else {
      // All required executed (or zero required) => completed.
      status = "completed";
      pauseReason = null;
    }
    return { status, pauseReason, counts };
  }

  // Small A8-local helpers for the new Slice 4b-1 tests.

  // A fresh RequiredActionCounts with every key zero. Used to build
  // the per-status "only that status" expected count object.
  function zeroCounts(): RequiredActionCounts {
    return {
      approved: 0,
      blocked: 0,
      executed: 0,
      failed: 0,
      outcome_unknown: 0,
      pending: 0,
      running: 0,
    };
  }

  // The actual review ids that the StatusSeed[] will produce, in
  // seed order, with the pending status filtered out (pending has
  // no review row). This guarantees the test does NOT derive a
  // review id from the action id by string convention — it uses
  // the exact ids declared on the seeds.
  function expectedReviewIds(seeds: StatusSeed[]): string[] {
    const out: string[] = [];
    for (const s of seeds) {
      if (s.status !== "pending") out.push(s.reviewId);
    }
    return out;
  }

  // Assertion helper: returned FutureJobRecord AND raw jobs row
  // must agree on status, pause_reason, status_detail; the parsed
  // JSON must have exactly the seven count keys in the pinned order
  // with no extra keys.
  function assertReturnedAndRawJob(
    returned: FutureJobRecord,
    handle: BountyDatabase,
    jobId: string,
    expectedStatus: "queued" | "running" | "paused" | "failed" | "completed",
    expectedPauseReason: PauseReason | null,
    expectedCounts: RequiredActionCounts,
  ): void {
    // Returned record fields.
    expect(returned.id).toBe(jobId);
    expect(returned.status).toBe(expectedStatus);
    expect(returned.pauseReason).toBe(expectedPauseReason);
    expect(returned.statusDetail).toBe(expectedStatusDetail(expectedCounts));

    // Raw jobs row.
    const raw = handle
      .prepare("SELECT id, status, pause_reason, status_detail FROM jobs WHERE id = ?")
      .get(jobId) as { id: string; status: string; pause_reason: string | null; status_detail: string | null };
    expect(raw.id).toBe(jobId);
    expect(raw.status).toBe(expectedStatus);
    expect(raw.pause_reason).toBe(expectedPauseReason);
    expect(raw.status_detail).toBe(expectedStatusDetail(expectedCounts));

    // Parsed JSON: exactly the seven count keys, exact order, no
    // extra keys, no whitespace.
    const expected = expectedStatusDetail(expectedCounts);
    expect(raw.status_detail).toBe(expected);
    const parsed = JSON.parse(raw.status_detail as string) as Record<string, unknown>;
    const topLevelKeys = Object.keys(parsed);
    expect(topLevelKeys).toEqual(["requiredActionCounts", "schemaVersion"]);
    const rac = parsed.requiredActionCounts as Record<string, unknown>;
    expect(Object.keys(rac)).toEqual([...A8_COUNT_KEYS_ORDER]);
    expect(parsed.schemaVersion).toBe(1);
    for (const key of A8_COUNT_KEYS_ORDER) {
      expect(rac[key]).toBe(expectedCounts[key]);
    }
  }

  // The seven statuses used by the 21-pair table.
  const ALL_STATUSES: ReadonlyArray<StatusSeed["status"]> = [
    "outcome_unknown",
    "running",
    "blocked",
    "failed",
    "pending",
    "approved",
    "executed",
  ];

  // 1) finalizeInTransaction outside a tracked transaction =>
  // JOB_TRANSACTION_REQUIRED and full raw job row unchanged.
  it("finalizeInTransaction outside a transaction throws JOB_TRANSACTION_REQUIRED and the raw jobs row is byte-identical", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-out";
    seedJobWithInitialRow(handle, jobId);

    const before = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    const beforeActions = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(`job-a8-out`) as Array<Record<string, unknown>>;

    let captured: unknown = null;
    try {
      (jobMgr as unknown as {
        finalizeInTransaction(jobId: string): FutureJobRecord;
      }).finalizeInTransaction(jobId);
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("JOB_TRANSACTION_REQUIRED");

    // Full raw row byte-identical, every action row byte-identical.
    const after = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(after).toEqual(before);
    const afterActions = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(`job-a8-out`) as Array<Record<string, unknown>>;
    expect(afterActions).toEqual(beforeActions);
  });

  // 2) finalizeInTransaction inside a caller transaction commits
  // the derived tuple and returns it.
  it("finalizeInTransaction inside a caller transaction commits and returns the derived tuple", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-inside";
    const seedA: StatusSeed = { actionId: "a-pending", reviewId: "rev-a-pending", status: "pending" };
    const seedB: StatusSeed = { actionId: "a-executed", reviewId: "rev-a-executed", status: "executed" };
    seedJobWithInitialRow(handle, jobId);
    seedLifecycleValidAction(handle, jobId, seedA);
    seedLifecycleValidAction(handle, jobId, seedB);

    // Fixture-integrity: every action row links to the real jobId,
    // and every expected review row is also linked to the real jobId.
    assertA8FixtureLinkage(handle, jobId, [seedA.actionId, seedB.actionId], [seedB.reviewId]);

    const derived = deriveFromSeeds([seedA, seedB]);
    expect(derived.status).toBe("paused");
    expect(derived.pauseReason).toBe("approval_required");

    const returned = withImmediateTransaction(handle, () => {
      return (jobMgr as unknown as {
        finalizeInTransaction(jobId: string): FutureJobRecord;
      }).finalizeInTransaction(jobId);
    });

    assertReturnedAndRawJob(
      returned,
      handle,
      jobId,
      derived.status,
      derived.pauseReason,
      derived.counts,
    );
  });

  // 3) Caller rollback after finalizeInTransaction + a thrown
  // sentinel restores the full raw job row and rethrows the
  // sentinel.
  it("caller rollback after finalizeInTransaction restores the full raw job row and rethrows the sentinel", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-rollback";
    const seed: StatusSeed = { actionId: "a-pending", reviewId: "rev-a-pending", status: "pending" };
    seedJobWithInitialRow(handle, jobId);
    seedLifecycleValidAction(handle, jobId, seed);
    assertA8FixtureLinkage(handle, jobId, [seed.actionId]);

    const before = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    const beforeActions = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(jobId) as Array<Record<string, unknown>>;

    const SENTINEL = new Error("force-job-rollback");
    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        (jobMgr as unknown as {
          finalizeInTransaction(jobId: string): FutureJobRecord;
        }).finalizeInTransaction(jobId);
        throw SENTINEL;
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBe(SENTINEL);

    // The full raw job row is byte-identical to the snapshot.
    const after = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(after).toEqual(before);
    // Every action row is byte-identical to the snapshot.
    const afterActions = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(jobId) as Array<Record<string, unknown>>;
    expect(afterActions).toEqual(beforeActions);
  });

  // 4) Public finalize() called inside an outer withImmediateTransaction
  // => DB_TRANSACTION_NESTED and the full raw job row unchanged.
  // Hardened: install a handle-local NONTHROWING UDF counter plus
  // a TEMP BEFORE UPDATE trigger on the jobs table scoped to
  // job-a8-nest. The counter MUST be 0 after the
  // DB_TRANSACTION_NESTED, proving the guard failed BEFORE any
  // write was issued. The counter is JS-side and is NOT rolled
  // back by SQLite (a transaction rollback only undoes the row
  // change, not the side effect of running the trigger's SELECT
  // a8_nest_counter() expression). So if production ever issues
  // an UPDATE on the jobs row before raising DB_TRANSACTION_NESTED,
  // the trigger fires, the UDF runs, counter becomes 1, and
  // the assertion fails — regardless of whether the outer
  // transaction later rolls back. The counter is nonthrowing on
  // purpose: a throwing UDF could mask DB_TRANSACTION_NESTED by
  // surfacing its own error first.
  it("public finalize() inside an outer transaction raises DB_TRANSACTION_NESTED; the raw jobs row is unchanged and the UPDATE trigger never fired", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-nest";
    const seed: StatusSeed = { actionId: "a-pending", reviewId: "rev-a-pending", status: "pending" };
    seedJobWithInitialRow(handle, jobId);
    seedLifecycleValidAction(handle, jobId, seed);
    assertA8FixtureLinkage(handle, jobId, [seed.actionId]);

    // Handle-local NONTHROWING UDF counter. Increments per call;
    // never throws so it cannot mask DB_TRANSACTION_NESTED.
    let counter = 0;
    handle.function("a8_nest_counter", () => {
      counter += 1;
      return counter;
    });
    // TEMP BEFORE UPDATE trigger on jobs, scoped to the single
    // target job id. If production runs an UPDATE on the jobs
    // row before raising DB_TRANSACTION_NESTED, the trigger
    // fires and the counter becomes 1.
    handle.exec(`
      CREATE TEMP TRIGGER a8_nest_jobs_update_count
      BEFORE UPDATE ON jobs
      FOR EACH ROW
      WHEN NEW.id = 'job-a8-nest'
      BEGIN
        SELECT a8_nest_counter();
      END;
    `);

    const before = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
        return "outer-ok";
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("DB_TRANSACTION_NESTED");

    // The outer transaction rolled back; the raw row is unchanged.
    const after = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(after).toEqual(before);

    // Fail-before-write probe: the BEFORE UPDATE trigger never
    // fired, so the handle-local UDF counter is still 0. This
    // proves production raised DB_TRANSACTION_NESTED without
    // issuing an UPDATE on the jobs row. The counter is JS-side
    // and is NOT affected by the outer rollback, so this is a
    // hard probe of "did production issue an UPDATE?".
    expect(counter, "a8_nest_counter must remain 0; production issued an UPDATE on jobs before raising DB_TRANSACTION_NESTED").toBe(0);
  });

  // 5) Generate ALL 21 unordered distinct pairs from
  // [outcome_unknown, running, blocked, failed, pending, approved,
  // executed]. For every pair, seed two required lifecycle-valid
  // actions, call PUBLIC finalize(), and assert returned+raw exact
  // tuple and exact counts.
  function buildPairs(): Array<[StatusSeed["status"], StatusSeed["status"]]> {
    const out: Array<[StatusSeed["status"], StatusSeed["status"]]> = [];
    for (let i = 0; i < ALL_STATUSES.length; i++) {
      for (let j = i + 1; j < ALL_STATUSES.length; j++) {
        out.push([ALL_STATUSES[i], ALL_STATUSES[j]]);
      }
    }
    return out;
  }

  const ALL_PAIRS = buildPairs();
  // Sanity: C(7,2) = 21 unordered distinct pairs. This is a hard
  // literal so the test will fail if a status is removed or added
  // (the formula would silently shrink, hiding the regression).
  const EXPECTED_PAIR_COUNT = 21;

  for (const pair of ALL_PAIRS) {
    const [statusA, statusB] = pair;
    const name = `pair (${statusA}, ${statusB})`;
    it(`public finalize() derivation for ${name}`, () => {
      const handle = openDb();
      const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
      const jobId = `job-a8-pair-${statusA}-${statusB}`;
      seedJobWithInitialRow(handle, jobId);
      const seedA: StatusSeed = {
        actionId: `a-${statusA}`,
        reviewId: `rev-${statusA}-${statusA}`,
        status: statusA,
      };
      const seedB: StatusSeed = {
        actionId: `a-${statusB}`,
        reviewId: `rev-${statusB}-${statusB}`,
        status: statusB,
      };
      seedLifecycleValidAction(handle, jobId, seedA);
      seedLifecycleValidAction(handle, jobId, seedB);

      // Fixture-integrity: every action row links to the real jobId,
      // and every non-pending review row is also linked to the real jobId.
      const expectedReviewIds: string[] = [];
      if (statusA !== "pending") expectedReviewIds.push(seedA.reviewId);
      if (statusB !== "pending") expectedReviewIds.push(seedB.reviewId);
      assertA8FixtureLinkage(handle, jobId, [seedA.actionId, seedB.actionId], expectedReviewIds);

      const derived = deriveFromSeeds([seedA, seedB]);

      const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
      assertReturnedAndRawJob(
        returned,
        handle,
        jobId,
        derived.status,
        derived.pauseReason,
        derived.counts,
      );
    });
  }

  it("the 21-pair table covers every unordered pair exactly once and the precedence universe has exactly seven ordered statuses", () => {
    // The precedence universe is exactly seven statuses, in this
    // exact order, with no extras. A future regression that
    // removes/renames/adds a status must be caught here.
    expect([...ALL_STATUSES]).toEqual([
      "outcome_unknown",
      "running",
      "blocked",
      "failed",
      "pending",
      "approved",
      "executed",
    ]);
    expect(ALL_STATUSES.length).toBe(7);

    // Cross-check the table generator produced 21 unique entries.
    expect(ALL_PAIRS.length).toBe(EXPECTED_PAIR_COUNT);
    expect(EXPECTED_PAIR_COUNT).toBe(21);
    const seen = new Set<string>();
    for (const [a, b] of ALL_PAIRS) {
      const key = [a, b].sort().join("|");
      expect(seen.has(key), `duplicate pair: ${a},${b}`).toBe(false);
      seen.add(key);
    }
    expect(seen.size).toBe(EXPECTED_PAIR_COUNT);
    // The pinned must-include pairs.
    const mustInclude = [
      ["blocked", "failed"],
      ["pending", "approved"],
    ] as const;
    for (const [a, b] of mustInclude) {
      const key = [a, b].sort().join("|");
      expect(seen.has(key), `must-include pair missing: ${a},${b}`).toBe(true);
    }
  });

  // 6) finalize missing job preserves JOB_NOT_FOUND; finalizeInTransaction
  // missing job inside a tracked transaction also preserves JOB_NOT_FOUND.
  it("finalize(missing) throws JOB_NOT_FOUND and writes no jobs row", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number }).n;

    let captured: unknown = null;
    try {
      (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize("job-a8-missing");
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("JOB_NOT_FOUND");
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  it("finalizeInTransaction(missing) inside a tracked transaction throws JOB_NOT_FOUND and writes no jobs row", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const before = (handle.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number }).n;

    let captured: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        (jobMgr as unknown as {
          finalizeInTransaction(jobId: string): FutureJobRecord;
        }).finalizeInTransaction("job-a8-missing-inside");
        return "outer-ok";
      });
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("JOB_NOT_FOUND");
    const after = (handle.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number }).n;
    expect(after).toBe(before);
  });

  // ---- Slice 4b-1: coverage for counts, non-required exclusion,
  // job isolation, completion base cases, and in-tx visibility ----

  // Repeated-status cardinality table: for EACH of the seven
  // statuses, seed THREE required lifecycle-valid actions of that
  // same status with unique exact IDs/review IDs, finalize, and
  // assert the derived tuple plus exact canonical counts with
  // that status = 3 and every other count = 0. This catches
  // boolean-presence instead of COUNT for every status.
  // Per-status execution-token suffixes: the v2 schema enforces
  // UNIQUE(execution_token) and Packet 2 requires every execution
  // token to be exactly 64 lowercase hex. The three "running"
  // actions (which all carry an execution_token) therefore use
  // three distinct 64-hex tokens derived from A8_TOKEN. Each
  // variant replaces the LAST 2 hex chars of A8_TOKEN with one
  // of 01 / 02 / 03; the first 62 chars are preserved, so the
  // result is exactly 64 lowercase hex and uniqueness is
  // guaranteed by the 2-hex suffix.
  const A8_TOKEN_SUFFIX = ["01", "02", "03"] as const;
  // Pre-build the three distinct 64-hex tokens from A8_TOKEN.
  const A8_TOKEN_RUNNING_VARIANTS: readonly string[] = A8_TOKEN_SUFFIX.map(
    (s) => A8_TOKEN.slice(0, 62) + s,
  );
  for (const target of ALL_STATUSES) {
    it(`repeated-status cardinality: three required "${target}" actions => that count = 3, every other count = 0`, () => {
      const handle = openDb();
      const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
      const jobId = `job-a8-card-${target}`;
      seedJobWithInitialRow(handle, jobId);

      // Three required lifecycle-valid actions of the same status,
      // each with a unique exact actionId/reviewId. The "running"
      // case uses unique execution tokens (the three A8_TOKEN
      // variants that replace the last 2 hex chars with 01/02/03)
      // to satisfy the v2 schema's UNIQUE(execution_token)
      // constraint while keeping every token exactly 64 lowercase
      // hex characters.
      const seeds: StatusSeed[] = [0, 1, 2].map((i) => ({
        actionId: `a-${target}-${i + 1}`,
        reviewId: `rev-${target}-${i + 1}`,
        status: target,
      }));
      for (let i = 0; i < seeds.length; i++) {
        const s = seeds[i];
        seedLifecycleValidAction(handle, jobId, s);
        // If the seed was "running", overwrite the execution_token
        // to a unique 64-hex value (the helper used the global
        // A8_TOKEN for all three, which collides on the UNIQUE
        // index). Each variant is exactly 64 lowercase hex chars.
        if (target === "running") {
          handle
            .prepare("UPDATE actions SET execution_token = ? WHERE id = ?")
            .run(A8_TOKEN_RUNNING_VARIANTS[i], s.actionId);
        }
      }

      // Fixture-integrity: every action and every non-pending review
      // row links to the real jobId.
      assertA8FixtureLinkage(
        handle,
        jobId,
        seeds.map((s) => s.actionId),
        expectedReviewIds(seeds),
      );

      const expectedCounts: RequiredActionCounts = zeroCounts();
      expectedCounts[target] = 3;
      const derived = deriveFromSeeds(seeds);

      const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
      assertReturnedAndRawJob(returned, handle, jobId, derived.status, derived.pauseReason, expectedCounts);
    });
  }

  // Non-required rows do not block completion unless an effect is actively
  // running or its outcome is unknown. Those two safety-critical states must
  // remain visible even though the required-action counters stay unchanged.
  for (const nonReqStatus of ALL_STATUSES) {
    it(`non-required exclusion: one required executed + one non-required "${nonReqStatus}" => completed, executed=1, all others=0`, () => {
      const handle = openDb();
      const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
      const jobId = `job-a8-nonreq-${nonReqStatus}`;
      seedJobWithInitialRow(handle, jobId);

      const requiredExecuted: StatusSeed = {
        actionId: "a-required-executed",
        reviewId: "rev-required-executed",
        status: "executed",
      };
      const nonRequired: StatusSeed = {
        actionId: `a-nonreq-${nonReqStatus}`,
        reviewId: `rev-nonreq-${nonReqStatus}`,
        status: nonReqStatus,
      };
      // required = 1 (default).
      seedLifecycleValidAction(handle, jobId, requiredExecuted);
      // Non-required = 0.
      seedLifecycleValidAction(handle, jobId, nonRequired, 0);

      assertA8FixtureLinkage(
        handle,
        jobId,
        [requiredExecuted.actionId, nonRequired.actionId],
        expectedReviewIds([requiredExecuted, nonRequired]),
      );

      // Counts must include ONLY the required executed action.
      const expectedCounts: RequiredActionCounts = zeroCounts();
      expectedCounts.executed = 1;

      const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
      if (nonReqStatus === "running" || nonReqStatus === "outcome_unknown") {
        const expectedStatus = nonReqStatus === "running" ? "running" : "paused";
        const expectedPauseReason = nonReqStatus === "running" ? null : "reconciliation_required";
        expect(returned.status).toBe(expectedStatus);
        expect(returned.pauseReason).toBe(expectedPauseReason);
        const parsedDetail = JSON.parse(returned.statusDetail as string) as {
          requiredActionCounts: RequiredActionCounts;
          safetyCriticalOptionalActionCounts: { running: number; outcome_unknown: number };
          schemaVersion: number;
        };
        expect(parsedDetail.requiredActionCounts).toEqual(expectedCounts);
        expect(parsedDetail.safetyCriticalOptionalActionCounts).toEqual({
          running: nonReqStatus === "running" ? 1 : 0,
          outcome_unknown: nonReqStatus === "outcome_unknown" ? 1 : 0,
        });
        expect(parsedDetail.schemaVersion).toBe(1);
        const rawJob = handle.prepare("SELECT status, pause_reason, status_detail FROM jobs WHERE id = ?").get(jobId) as {
          status: string;
          pause_reason: string | null;
          status_detail: string;
        };
        expect(rawJob.status).toBe(expectedStatus);
        expect(rawJob.pause_reason).toBe(expectedPauseReason);
        expect(rawJob.status_detail).toBe(returned.statusDetail);
      } else {
        assertReturnedAndRawJob(returned, handle, jobId, "completed", null, expectedCounts);
      }

      // Defensive: the non-required row's status has no influence on
      // the derived tuple even when the non-required status itself
      // would otherwise be terminal/active (e.g. executed). The
      // executed-count stays exactly 1, not 2.
      const raw = handle
        .prepare("SELECT status_detail FROM jobs WHERE id = ?")
        .get(jobId) as { status_detail: string | null };
      const parsed = JSON.parse(raw.status_detail as string) as { requiredActionCounts: Record<string, number> };
      expect(parsed.requiredActionCounts.executed).toBe(1);
      for (const key of A8_COUNT_KEYS_ORDER) {
        if (key === "executed") continue;
        expect(parsed.requiredActionCounts[key], `non-required ${nonReqStatus} leaked into count for key ${key}`).toBe(0);
      }
    });
  }

  // Job scoping: target job has one required executed. A separate
  // decoy job in the same DB has required outcome_unknown (and
  // optionally another running/pending). Finalize only the target;
  // it must be completed with executed=1 only; the decoy's full
  // raw job row + action rows remain unchanged. Catches unscoped
  // / global aggregation.
  it("job scoping: finalizing the target job does not touch a decoy job with required outcome_unknown", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const targetJobId = "job-a8-scope-target";
    const decoyJobId = "job-a8-scope-decoy";
    seedJobWithInitialRow(handle, targetJobId);
    seedJobWithInitialRow(handle, decoyJobId);

    const targetExecuted: StatusSeed = {
      actionId: "a-target-executed",
      reviewId: "rev-target-executed",
      status: "executed",
    };
    const decoyOutcomeUnknown: StatusSeed = {
      actionId: "a-decoy-ou",
      reviewId: "rev-decoy-ou",
      status: "outcome_unknown",
    };
    const decoyRunning: StatusSeed = {
      actionId: "a-decoy-running",
      reviewId: "rev-decoy-running",
      status: "running",
    };
    seedLifecycleValidAction(handle, targetJobId, targetExecuted);
    seedLifecycleValidAction(handle, decoyJobId, decoyOutcomeUnknown);
    seedLifecycleValidAction(handle, decoyJobId, decoyRunning);

    assertA8FixtureLinkage(handle, targetJobId, [targetExecuted.actionId], expectedReviewIds([targetExecuted]));
    assertA8FixtureLinkage(
      handle,
      decoyJobId,
      [decoyOutcomeUnknown.actionId, decoyRunning.actionId],
      expectedReviewIds([decoyOutcomeUnknown, decoyRunning]),
    );

    // Snapshot the decoy full raw job row and every decoy action row
    // BEFORE finalizing the target.
    const decoyBefore = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(decoyJobId) as Record<string, unknown>;
    const decoyActionsBefore = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(decoyJobId) as Array<Record<string, unknown>>;

    const targetExpected: RequiredActionCounts = zeroCounts();
    targetExpected.executed = 1;
    const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(targetJobId);
    assertReturnedAndRawJob(returned, handle, targetJobId, "completed", null, targetExpected);

    // The decoy's full raw job row AND every decoy action row are
    // byte-identical to the pre-snapshot. No global aggregation.
    const decoyAfter = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(decoyJobId) as Record<string, unknown>;
    expect(decoyAfter, "decoy raw jobs row mutated").toEqual(decoyBefore);
    const decoyActionsAfter = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(decoyJobId) as Array<Record<string, unknown>>;
    expect(decoyActionsAfter, "decoy action rows mutated").toEqual(decoyActionsBefore);
  });

  // Base completion/cardinality: public finalize on
  // zero-required/no-action job => completed/null with all seven
  // counts zero. Public finalize with TWO required executed
  // actions => completed/null with executed = 2. Both returned
  // and raw exact canonical detail.
  it("base completion: zero-required/no-action job => completed, all seven counts = 0", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-zero";
    seedJobWithInitialRow(handle, jobId);
    assertA8FixtureLinkage(handle, jobId, []);

    const expectedCounts: RequiredActionCounts = zeroCounts();
    const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
    assertReturnedAndRawJob(returned, handle, jobId, "completed", null, expectedCounts);
  });

  it("base cardinality: two required executed actions => completed, executed = 2, all others = 0", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-two-executed";
    seedJobWithInitialRow(handle, jobId);

    const seeds: StatusSeed[] = [
      { actionId: "a-exec-1", reviewId: "rev-exec-1", status: "executed" },
      { actionId: "a-exec-2", reviewId: "rev-exec-2", status: "executed" },
    ];
    for (const s of seeds) seedLifecycleValidAction(handle, jobId, s);
    assertA8FixtureLinkage(
      handle,
      jobId,
      seeds.map((s) => s.actionId),
      expectedReviewIds(seeds),
    );

    const expectedCounts: RequiredActionCounts = zeroCounts();
    expectedCounts.executed = 2;
    const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
    assertReturnedAndRawJob(returned, handle, jobId, "completed", null, expectedCounts);
  });

  // Same-transaction visibility: seed job before transaction,
  // inside one withImmediateTransaction insert at least one
  // required lifecycle-valid action using the A8 helper, assert
  // linkage in that transaction, then call finalizeInTransaction.
  // Commit and assert exact returned/raw tuple/counts. Proves
  // finalizeInTransaction derives from rows written earlier in
  // the same caller transaction.
  it("in-tx visibility: finalizeInTransaction sees a required action inserted earlier in the same caller transaction", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-intx-vis";
    seedJobWithInitialRow(handle, jobId);

    const seed: StatusSeed = {
      actionId: "a-intx-executed",
      reviewId: "rev-intx-executed",
      status: "executed",
    };

    const returned = withImmediateTransaction(handle, () => {
      seedLifecycleValidAction(handle, jobId, seed);
      // Linkage assertion must run inside the same transaction so
      // the test proves the in-tx insert is visible to the
      // finalizer, not just visible to a later reader.
      assertA8FixtureLinkage(handle, jobId, [seed.actionId], expectedReviewIds([seed]));
      return (jobMgr as unknown as {
        finalizeInTransaction(jobId: string): FutureJobRecord;
      }).finalizeInTransaction(jobId);
    });

    const expectedCounts: RequiredActionCounts = zeroCounts();
    expectedCounts.executed = 1;
    assertReturnedAndRawJob(returned, handle, jobId, "completed", null, expectedCounts);
  });

  // ---- Slice 4b-2a: direct-completion guard, finalize idempotence,
  // and fail-before-write hardening ----

  // Cast helper for updateStatus — same pattern as finalize.
  type UpdateStatusFn = (jobId: string, status: "queued" | "running" | "paused" | "failed" | "completed") => FutureJobRecord;

  // Narrow structural interface for JobManager.get / .list. The
  // get/list mapper test casts the production JobManager to this
  // interface so the test file strict-TS compiles before the
  // future get/list surfaces ship.
  interface GetListSlice {
    get(jobId: string): FutureJobRecord;
    list(limit: number): FutureJobRecord[];
  }

  // 1) JOB_COMPLETION_BLOCKED table: for each of the required
  // NON-executed statuses (pending, approved, running, blocked,
  // failed, outcome_unknown), seed one lifecycle-valid REQUIRED
  // action on an initially running target job; call real
  // JobManager.updateStatus(jobId, "completed"); require
  // BountyPilotError code JOB_COMPLETION_BLOCKED; snapshot the
  // full raw job row, all target action rows, and all target
  // review rows must remain byte-identical.
  // Hardened with a handle-local NONTHROWING UDF counter + TEMP
  // BEFORE UPDATE ON jobs trigger scoped to this test's actual
  // jobId: the counter is JS-side and is NOT rolled back by
  // SQLite, so a non-zero counter is a hard probe that production
  // issued an UPDATE on the jobs row before raising
  // JOB_COMPLETION_BLOCKED. Review snapshots are full
  // job-scoped SELECT * FROM action_reviews (not just the
  // expected review ids) so a sneaky INSERT/DELETE on reviews
  // cannot hide. Fresh DB per test allows fixed UDF/trigger
  // names; the WHEN clause uses the actual job id.
  for (const target of ["pending", "approved", "running", "blocked", "failed", "outcome_unknown"] as const) {
    it(`JOB_COMPLETION_BLOCKED: one required "${target}" action blocks updateStatus(completed); job+actions+reviews byte-identical and no jobs UPDATE issued`, () => {
      const handle = openDb();
      const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
      const jobId = `job-a8-block-${target}`;
      seedJobWithInitialRow(handle, jobId);

      // Seed one required lifecycle-valid action in the target
      // status. The "running" case uses the existing A8_TOKEN,
      // which is already exactly 64 lowercase hex. Every blocker
      // case opens a fresh DB, so the token is unique within that
      // DB and the v2 UNIQUE(execution_token) constraint is
      // satisfied without any post-seed UPDATE.
      const seed: StatusSeed = {
        actionId: `a-block-${target}`,
        reviewId: `rev-block-${target}`,
        status: target,
      };
      seedLifecycleValidAction(handle, jobId, seed);
      assertA8FixtureLinkage(
        handle,
        jobId,
        [seed.actionId],
        expectedReviewIds([seed]),
      );

      // Snapshot the full raw job row, every action row, and
      // every review row (FULL job-scoped SELECT * — not just the
      // expected review ids — so a sneaky INSERT/DELETE on
      // reviews cannot hide).
      const beforeJob = handle
        .prepare("SELECT * FROM jobs WHERE id = ?")
        .get(jobId) as Record<string, unknown>;
      const beforeActions = handle
        .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
        .all(jobId) as Array<Record<string, unknown>>;
      const beforeReviews = handle
        .prepare("SELECT * FROM action_reviews WHERE job_id = ? ORDER BY id ASC")
        .all(jobId) as Array<Record<string, unknown>>;

      // Handle-local NONTHROWING UDF counter (the actual job id
      // is interpolated into the trigger WHEN clause — not into
      // the UDF/trigger name, so the UDF/trigger names stay
      // fixed across tests). The counter is JS-side and is NOT
      // rolled back by SQLite, so counter > 0 is a hard probe
      // that production issued an UPDATE on the jobs row before
      // raising JOB_COMPLETION_BLOCKED.
      let blockCounter = 0;
      handle.function("a8_block_counter", () => {
        blockCounter += 1;
        return blockCounter;
      });
      handle.exec(`
        CREATE TEMP TRIGGER a8_block_jobs_update_count
        BEFORE UPDATE ON jobs
        FOR EACH ROW
        WHEN NEW.id = '${jobId}'
        BEGIN
          SELECT a8_block_counter();
        END;
      `);

      let captured: unknown = null;
      try {
        (jobMgr as unknown as { updateStatus: UpdateStatusFn }).updateStatus(jobId, "completed");
      } catch (err) {
        captured = err;
      }
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("JOB_COMPLETION_BLOCKED");

      // Full raw job row byte-identical to snapshot.
      const afterJob = handle
        .prepare("SELECT * FROM jobs WHERE id = ?")
        .get(jobId) as Record<string, unknown>;
      expect(afterJob, "raw jobs row mutated by updateStatus(completed)").toEqual(beforeJob);

      // Every action row byte-identical.
      const afterActions = handle
        .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
        .all(jobId) as Array<Record<string, unknown>>;
      expect(afterActions, "action rows mutated by updateStatus(completed)").toEqual(beforeActions);

      // Every review row byte-identical (full job-scoped SELECT *).
      const afterReviews = handle
        .prepare("SELECT * FROM action_reviews WHERE job_id = ? ORDER BY id ASC")
        .all(jobId) as Array<Record<string, unknown>>;
      expect(afterReviews, "review rows mutated by updateStatus(completed)").toEqual(beforeReviews);

      // Fail-before-write probe: the BEFORE UPDATE trigger never
      // fired, so the handle-local UDF counter is still 0. This
      // proves production raised JOB_COMPLETION_BLOCKED without
      // issuing any UPDATE on the jobs row.
      expect(
        blockCounter,
        "a8_block_counter must remain 0; production issued an UPDATE on jobs before raising JOB_COMPLETION_BLOCKED",
      ).toBe(0);
    });
  }

  for (const target of ["running", "outcome_unknown"] as const) {
    it(`JOB_COMPLETION_BLOCKED: safety-critical non-required ${target} action cannot be hidden by direct completion`, () => {
      const handle = openDb();
      const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
      const jobId = `job-a8-optional-active-${target}`;
      seedJobWithInitialRow(handle, jobId);
      const seed: StatusSeed = {
        actionId: `a-optional-active-${target}`,
        reviewId: `rev-optional-active-${target}`,
        status: target,
      };
      seedLifecycleValidAction(handle, jobId, seed, 0);
      const beforeJob = handle.prepare("SELECT * FROM jobs WHERE id = ?").get(jobId);
      const beforeActions = handle.prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id").all(jobId);

      let captured: unknown;
      try {
        (jobMgr as unknown as { updateStatus: UpdateStatusFn }).updateStatus(jobId, "completed");
      } catch (error) {
        captured = error;
      }

      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe("JOB_COMPLETION_BLOCKED");
      expect(handle.prepare("SELECT * FROM jobs WHERE id = ?").get(jobId)).toEqual(beforeJob);
      expect(handle.prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id").all(jobId)).toEqual(beforeActions);
    });
  }

  // 2) Same-status bypass: raw-preseed the job to status
  // "completed" with a required pending action;
  // updateStatus("completed") must still throw
  // JOB_COMPLETION_BLOCKED; the full raw job row and all target
  // action rows must remain byte-identical.
  // Hardened: install an analogous nonthrowing UDF + TEMP BEFORE
  // UPDATE ON jobs trigger only AFTER the deliberate stale setup
  // UPDATE and the snapshot, scoped to job-a8-same-bypass. The
  // counter is JS-side and is NOT rolled back by SQLite, so
  // counter > 0 is a hard probe that production issued an UPDATE
  // on the jobs row before raising JOB_COMPLETION_BLOCKED.
  // Review snapshots are full job-scoped SELECT *.
  it("JOB_COMPLETION_BLOCKED same-status bypass: raw-preseed status=completed + required pending action; updateStatus(completed) still blocked; no jobs UPDATE issued", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-same-bypass";
    seedJobWithInitialRow(handle, jobId);
    const seed: StatusSeed = { actionId: "a-bypass-pending", reviewId: "rev-bypass-pending", status: "pending" };
    seedLifecycleValidAction(handle, jobId, seed);
    assertA8FixtureLinkage(handle, jobId, [seed.actionId]);

    // Structurally-coherent raw-preseed: set status="completed",
    // pause_reason=NULL, status_detail to the canonical
    // zeroCounts() detail, and a distinctive updated_at. The job
    // is now DELIBERATELY STALE: status=completed but a required
    // pending action exists, so the completion guard MUST still
    // block the next updateStatus("completed") call.
    const A8_BYPASS_DISTINCT_UPDATED_AT = "2099-12-31T23:59:59.999Z";
    const bypassExpectedDetail = expectedStatusDetail(zeroCounts());
    handle
      .prepare(
        "UPDATE jobs SET status = ?, pause_reason = ?, status_detail = ?, updated_at = ? WHERE id = ?",
      )
      .run("completed", null, bypassExpectedDetail, A8_BYPASS_DISTINCT_UPDATED_AT, jobId);

    // Snapshot AFTER the setup UPDATE so the snapshot reflects
    // the deliberate stale state. Full job-scoped SELECT * on
    // reviews so a sneaky INSERT/DELETE on reviews cannot hide.
    const beforeJob = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    const beforeActions = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(jobId) as Array<Record<string, unknown>>;
    const beforeReviews = handle
      .prepare("SELECT * FROM action_reviews WHERE job_id = ? ORDER BY id ASC")
      .all(jobId) as Array<Record<string, unknown>>;

    // Handle-local NONTHROWING UDF counter installed ONLY AFTER
    // the deliberate stale setup UPDATE and the snapshot, so
    // the setup UPDATE itself does not increment the counter.
    // The counter is JS-side and is NOT rolled back by SQLite,
    // so counter > 0 after JOB_COMPLETION_BLOCKED is a hard probe
    // that production issued an UPDATE on the jobs row before
    // raising JOB_COMPLETION_BLOCKED.
    let bypassCounter = 0;
    handle.function("a8_bypass_counter", () => {
      bypassCounter += 1;
      return bypassCounter;
    });
    handle.exec(`
      CREATE TEMP TRIGGER a8_bypass_jobs_update_count
      BEFORE UPDATE ON jobs
      FOR EACH ROW
      WHEN NEW.id = 'job-a8-same-bypass'
      BEGIN
        SELECT a8_bypass_counter();
      END;
    `);

    let captured: unknown = null;
    try {
      (jobMgr as unknown as { updateStatus: UpdateStatusFn }).updateStatus(jobId, "completed");
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(BountyPilotError);
    expect((captured as BountyPilotError).code).toBe("JOB_COMPLETION_BLOCKED");

    // The raw-preseed distinct updated_at must still be there —
    // updateStatus must not have touched the row.
    const afterJob = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(afterJob).toEqual(beforeJob);
    const afterActions = handle
      .prepare("SELECT * FROM actions WHERE job_id = ? ORDER BY id ASC")
      .all(jobId) as Array<Record<string, unknown>>;
    expect(afterActions).toEqual(beforeActions);

    // Every review row byte-identical (full job-scoped SELECT *).
    const afterReviews = handle
      .prepare("SELECT * FROM action_reviews WHERE job_id = ? ORDER BY id ASC")
      .all(jobId) as Array<Record<string, unknown>>;
    expect(afterReviews, "review rows mutated by updateStatus(completed)").toEqual(beforeReviews);

    // Fail-before-write probe: the BEFORE UPDATE trigger never
    // fired, so the handle-local UDF counter is still 0. This
    // proves production raised JOB_COMPLETION_BLOCKED without
    // issuing any UPDATE on the jobs row.
    expect(
      bypassCounter,
      "a8_bypass_counter must remain 0; production issued an UPDATE on jobs before raising JOB_COMPLETION_BLOCKED",
    ).toBe(0);
  });

  // 3) Direct completion happy paths: updateStatus(completed) on
  // (a) zero-required/no-action job and (b) two required
  // executed actions. Both must complete THROUGH finalization
  // and the returned + raw must be exact
  // completed / null / canonical seven-key counts. Uses
  // assertReturnedAndRawJob.
  it("direct completion happy path: zero-required/no-action job => updateStatus(completed) finalizes to completed with all counts 0", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-direct-zero";
    seedJobWithInitialRow(handle, jobId);
    assertA8FixtureLinkage(handle, jobId, []);

    const expectedCounts: RequiredActionCounts = zeroCounts();
    const returned = (jobMgr as unknown as { updateStatus: UpdateStatusFn }).updateStatus(jobId, "completed");
    assertReturnedAndRawJob(returned, handle, jobId, "completed", null, expectedCounts);
  });

  it("direct completion happy path: two required executed actions => updateStatus(completed) finalizes to completed with executed=2", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-direct-two";
    seedJobWithInitialRow(handle, jobId);

    const seeds: StatusSeed[] = [
      { actionId: "a-direct-exec-1", reviewId: "rev-direct-exec-1", status: "executed" },
      { actionId: "a-direct-exec-2", reviewId: "rev-direct-exec-2", status: "executed" },
    ];
    for (const s of seeds) seedLifecycleValidAction(handle, jobId, s);
    assertA8FixtureLinkage(
      handle,
      jobId,
      seeds.map((s) => s.actionId),
      expectedReviewIds(seeds),
    );

    const expectedCounts: RequiredActionCounts = zeroCounts();
    expectedCounts.executed = 2;
    const returned = (jobMgr as unknown as { updateStatus: UpdateStatusFn }).updateStatus(jobId, "completed");
    assertReturnedAndRawJob(returned, handle, jobId, "completed", null, expectedCounts);
  });

  // 4) Public finalize idempotence: seed a required pending
  // action. Raw-preseed the job row to the already-derived
  // paused / approval_required / exact expectedStatusDetail
  // tuple with a fixed distinctive updated_at. Snapshot the full
  // SELECT * from jobs. Finalize returns the exact tuple but the
  // complete raw job row INCLUDING updated_at remains
  // byte-identical. Strengthened: a handle-local NONTHROWING
  // counter UDF + TEMP BEFORE UPDATE ON jobs trigger scoped to
  // job-a8-finalize-idem proves no same-value UPDATE was issued
  // (any UPDATE — even one that sets NEW.updated_at to the same
  // value — would still fire the trigger and increment the
  // counter). The counter is JS-side and is NOT rolled back by
  // any SQLite transaction, so it is a hard probe of "did
  // production issue an UPDATE on this row?"
  it("public finalize idempotence: raw-preseed already-derived paused/approval_required tuple; finalize returns the same tuple, leaves the raw row byte-identical, and never issues a same-value UPDATE", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-finalize-idem";
    seedJobWithInitialRow(handle, jobId);
    const seed: StatusSeed = { actionId: "a-idem-pending", reviewId: "rev-idem-pending", status: "pending" };
    seedLifecycleValidAction(handle, jobId, seed);
    assertA8FixtureLinkage(handle, jobId, [seed.actionId]);

    // Build the expected tuple for one required pending action.
    const expectedCounts: RequiredActionCounts = zeroCounts();
    expectedCounts.pending = 1;
    const expectedStatusDetailStr = expectedStatusDetail(expectedCounts);

    // Raw-preseed the job row to the already-derived tuple with a
    // distinctive fixed updated_at. The finalize() call must NOT
    // re-write this row — not even with the same values.
    const A8_IDEM_DISTINCT_UPDATED_AT = "2099-06-15T12:34:56.789Z";
    handle
      .prepare(
        "UPDATE jobs SET status = ?, pause_reason = ?, status_detail = ?, updated_at = ? WHERE id = ?",
      )
      .run("paused", "approval_required", expectedStatusDetailStr, A8_IDEM_DISTINCT_UPDATED_AT, jobId);

    // Handle-local NONTHROWING counter UDF. Any UPDATE on the
    // target jobs row (even a same-value UPDATE) fires the
    // trigger and increments the counter. The counter is JS-side
    // and is NOT rolled back by SQLite, so counter > 0 is a hard
    // probe that production issued an UPDATE.
    let idemCounter = 0;
    handle.function("a8_idem_counter", () => {
      idemCounter += 1;
      return idemCounter;
    });
    // TEMP BEFORE UPDATE trigger on jobs, scoped to the single
    // target job id.
    handle.exec(`
      CREATE TEMP TRIGGER a8_idem_jobs_update_count
      BEFORE UPDATE ON jobs
      FOR EACH ROW
      WHEN NEW.id = 'job-a8-finalize-idem'
      BEGIN
        SELECT a8_idem_counter();
      END;
    `);

    // Snapshot the full SELECT * row AFTER setup.
    const before = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;

    const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);

    // Returned tuple must match the pre-seeded derived tuple.
    expect(returned.id).toBe(jobId);
    expect(returned.status).toBe("paused");
    expect(returned.pauseReason).toBe("approval_required");
    expect(returned.statusDetail).toBe(expectedStatusDetailStr);
    // Returned updatedAt must equal the sentinel — production
    // did not rewrite updated_at.
    expect(returned.updatedAt).toBe(A8_IDEM_DISTINCT_UPDATED_AT);

    // Fail-before-write probe: the BEFORE UPDATE trigger never
    // fired, so the handle-local UDF counter is still 0. This
    // proves production raised the idempotent tuple WITHOUT
    // issuing any UPDATE on the jobs row, even a same-value one.
    expect(idemCounter, "a8_idem_counter must remain 0; production issued an UPDATE on jobs despite idempotent tuple").toBe(0);

    // The complete raw jobs row must remain byte-identical,
    // INCLUDING the distinctive updated_at. Production must not
    // rewrite the row when the derived tuple matches what is
    // already there.
    const after = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(after, "raw jobs row was rewritten by finalize despite idempotent tuple").toEqual(before);
    expect(after.updated_at).toBe(A8_IDEM_DISTINCT_UPDATED_AT);
  });

  // ---- Slice 4b-2b: get/list mapper + non-vacuous
  // status_detail secret non-leak ----

  // (1) get/list mapper after finalization. In one fresh DB seed
  // TWO jobs: job P has one required lifecycle-valid pending
  // action; job Z has zero actions. Finalize both via public
  // finalize. Then call real JobManager.get for both and list(50);
  // find list entries BY ID (do not rely on order because
  // created_at ties). Assert get and list records each have own
  // properties pauseReason and statusDetail, and exact values:
  // P paused/approval_required/canonical pending=1, Z
  // completed/null/canonical all-zero. Assert linkage with actual
  // IDs. Cast future surfaces through unknown for strict compile.
  it("get/list mapper after finalization: P (1 required pending) and Z (zero actions) => P paused/approval_required, Z completed/null; get and list records have own pauseReason + statusDetail", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobIdP = "job-a8-map-p";
    const jobIdZ = "job-a8-map-z";
    seedJobWithInitialRow(handle, jobIdP);
    seedJobWithInitialRow(handle, jobIdZ);

    // Job P: one required lifecycle-valid pending action.
    const seedP: StatusSeed = { actionId: "a-map-pending", reviewId: "rev-map-pending", status: "pending" };
    seedLifecycleValidAction(handle, jobIdP, seedP);
    // Job Z: zero actions.
    assertA8FixtureLinkage(handle, jobIdP, [seedP.actionId]);
    assertA8FixtureLinkage(handle, jobIdZ, []);

    // Finalize both jobs via public finalize (own transaction).
    const pExpectedCounts: RequiredActionCounts = zeroCounts();
    pExpectedCounts.pending = 1;
    const zExpectedCounts: RequiredActionCounts = zeroCounts();
    const pReturned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobIdP);
    const zReturned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobIdZ);
    assertReturnedAndRawJob(pReturned, handle, jobIdP, "paused", "approval_required", pExpectedCounts);
    assertReturnedAndRawJob(zReturned, handle, jobIdZ, "completed", null, zExpectedCounts);

    // Cast helper for get/list — narrow structural interface so the
    // test file strict-TS compiles before production ships the
    // future get/list surfaces.
    const getList = jobMgr as unknown as GetListSlice;

    // get(P) and get(Z): each has own pauseReason + statusDetail
    // with the exact values pinned above.
    const pGet = getList.get(jobIdP);
    expect(pGet.id).toBe(jobIdP);
    expect(Object.prototype.hasOwnProperty.call(pGet, "pauseReason")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(pGet, "statusDetail")).toBe(true);
    expect(pGet.status).toBe("paused");
    expect(pGet.pauseReason).toBe("approval_required");
    expect(pGet.statusDetail).toBe(expectedStatusDetail(pExpectedCounts));

    const zGet = getList.get(jobIdZ);
    expect(zGet.id).toBe(jobIdZ);
    expect(Object.prototype.hasOwnProperty.call(zGet, "pauseReason")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(zGet, "statusDetail")).toBe(true);
    expect(zGet.status).toBe("completed");
    expect(zGet.pauseReason).toBeNull();
    expect(zGet.statusDetail).toBe(expectedStatusDetail(zExpectedCounts));

    // list(50): find each entry BY ID (created_at ties mean order
    // is not guaranteed).
    const list = getList.list(50);
    expect(list.length).toBe(2);
    const pFromList = list.find((r) => r.id === jobIdP);
    const zFromList = list.find((r) => r.id === jobIdZ);
    expect(pFromList, "list(50) missing P job").toBeDefined();
    expect(zFromList, "list(50) missing Z job").toBeDefined();
    if (!pFromList || !zFromList) return; // narrow for the type checker

    // P list entry: own pauseReason + statusDetail, exact values.
    expect(Object.prototype.hasOwnProperty.call(pFromList, "pauseReason")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(pFromList, "statusDetail")).toBe(true);
    expect(pFromList.status).toBe("paused");
    expect(pFromList.pauseReason).toBe("approval_required");
    expect(pFromList.statusDetail).toBe(expectedStatusDetail(pExpectedCounts));

    // Z list entry: own pauseReason + statusDetail, exact values.
    expect(Object.prototype.hasOwnProperty.call(zFromList, "pauseReason")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(zFromList, "statusDetail")).toBe(true);
    expect(zFromList.status).toBe("completed");
    expect(zFromList.pauseReason).toBeNull();
    expect(zFromList.statusDetail).toBe(expectedStatusDetail(zExpectedCounts));

    // Linkage with actual IDs: the list entry IDs are the actual
    // seeded job IDs, not invented values.
    expect(pFromList.id).toBe(jobIdP);
    expect(zFromList.id).toBe(jobIdZ);
  });

  // (2) non-vacuous status_detail secret non-leak. One target
  // job has ONE required running action plus ONE non-required
  // failed action, both lifecycle-valid. After seeding, raw-
  // update action target and metadata_json with unique secret
  // strings, update a linked action_review.note with a unique
  // secret note; failed row already carries
  // SECRET_LAST_ERROR_MESSAGE and required running row carries
  // A8_TOKEN/A8_TOKEN_OWNER. Query raw action/review rows FIRST
  // and assert each forbidden value really exists (token exactly
  // 64 lowercase hex, target secret, metadata secret, review
  // note, last-error secret, both action IDs). Finalize; expected
  // tuple running/null and counts only running=1, every other
  // count=0. Use assertReturnedAndRawJob and then assert BOTH
  // returned.statusDetail and raw jobs.status_detail equal
  // expectedStatusDetail and contain none of: token, owner,
  // either action ID, target secret, metadata secret, review-
  // note secret, SECRET_LAST_ERROR_MESSAGE. Non-required failed
  // must not affect decision/counts.
  it("non-vacuous status_detail secret non-leak: required running + non-required failed secrets must not appear in returned or raw statusDetail", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8-secrets";

    seedJobWithInitialRow(handle, jobId);

    // Required running action.
    const runningSeed: StatusSeed = {
      actionId: "a-secrets-running",
      reviewId: "rev-secrets-running",
      status: "running",
    };
    seedLifecycleValidAction(handle, jobId, runningSeed);

    // Non-required failed action.
    const failedSeed: StatusSeed = {
      actionId: "a-secrets-failed",
      reviewId: "rev-secrets-failed",
      status: "failed",
    };
    seedLifecycleValidAction(handle, jobId, failedSeed, 0);

    assertA8FixtureLinkage(
      handle,
      jobId,
      [runningSeed.actionId, failedSeed.actionId],
      expectedReviewIds([runningSeed, failedSeed]),
    );

    // Unique secret strings. Each one MUST appear in the raw row
    // before finalization so the non-vacuous probe is real.
    const A8_SECRET_TARGET = "https://secret-target.example/A8_TARGET_SECRET";
    const A8_SECRET_METADATA = "A8_METADATA_SECRET_value_to_leak";
    const A8_SECRET_REVIEW_NOTE = "A8_REVIEW_NOTE_SECRET_value_to_leak";

    // Raw-update action target and metadata_json with the unique
    // secret strings.
    handle
      .prepare("UPDATE actions SET target = ?, metadata_json = ? WHERE id IN (?, ?)")
      .run(A8_SECRET_TARGET, JSON.stringify({ secret: A8_SECRET_METADATA }), runningSeed.actionId, failedSeed.actionId);

    // Update both linked action_review.note with the unique
    // secret note. Both reviews are non-pending (running + failed
    // both have a review), so both rows are present.
    handle
      .prepare("UPDATE action_reviews SET note = ? WHERE id IN (?, ?)")
      .run(A8_SECRET_REVIEW_NOTE, runningSeed.reviewId, failedSeed.reviewId);

    // Pre-finalization raw-row assertion: each forbidden value
    // really exists in the DB so the non-leak assertion is
    // non-vacuous.
    const runningRow = handle
      .prepare("SELECT execution_token, execution_owner, target, metadata_json FROM actions WHERE id = ?")
      .get(runningSeed.actionId) as {
        execution_token: string | null;
        execution_owner: string | null;
        target: string;
        metadata_json: string | null;
      };
    expect(runningRow.execution_token).toBe(A8_TOKEN);
    expect(runningRow.execution_token).toMatch(/^[0-9a-f]{64}$/);
    expect(runningRow.execution_owner).toBe(A8_TOKEN_OWNER);
    expect(runningRow.target).toBe(A8_SECRET_TARGET);
    expect(runningRow.metadata_json).not.toBeNull();
    expect(runningRow.metadata_json).toContain(A8_SECRET_METADATA);

    const failedRow = handle
      .prepare("SELECT last_error_message, target, metadata_json FROM actions WHERE id = ?")
      .get(failedSeed.actionId) as {
        last_error_message: string | null;
        target: string;
        metadata_json: string | null;
      };
    expect(failedRow.last_error_message).toBe(SECRET_LAST_ERROR_MESSAGE);
    expect(failedRow.target).toBe(A8_SECRET_TARGET);
    expect(failedRow.metadata_json).not.toBeNull();
    expect(failedRow.metadata_json).toContain(A8_SECRET_METADATA);

    const reviewRow = handle
      .prepare("SELECT note FROM action_reviews WHERE id = ?")
      .get(runningSeed.reviewId) as { note: string | null };
    expect(reviewRow.note).toBe(A8_SECRET_REVIEW_NOTE);

    // Finalize. Expected tuple: running / pauseReason null /
    // counts only running=1 (non-required failed is excluded).
    const expectedCounts: RequiredActionCounts = zeroCounts();
    expectedCounts.running = 1;
    const returned = (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
    assertReturnedAndRawJob(returned, handle, jobId, "running", null, expectedCounts);

    // Non-leak probe: BOTH returned.statusDetail and raw
    // jobs.status_detail must equal the canonical expectedStatusDetail
    // and must contain none of the forbidden secrets / IDs /
    // token / owner.
    const rawAfter = handle
      .prepare("SELECT status_detail FROM jobs WHERE id = ?")
      .get(jobId) as { status_detail: string | null };
    expect(rawAfter.status_detail).toBe(expectedStatusDetail(expectedCounts));

    const forbiddenStrings: string[] = [
      A8_TOKEN,
      A8_TOKEN_OWNER,
      runningSeed.actionId,
      failedSeed.actionId,
      A8_SECRET_TARGET,
      A8_SECRET_METADATA,
      A8_SECRET_REVIEW_NOTE,
      SECRET_LAST_ERROR_MESSAGE,
    ];
    for (const s of forbiddenStrings) {
      expect(returned.statusDetail).not.toContain(s);
      expect(rawAfter.status_detail).not.toContain(s);
    }
  });

  // A8 P1 regression (RED): a non-null jobs.pause_reason outside the
  // recognized set is not idempotent and must fail closed. finalize
  // / get / list must EACH throw ACTION_RECORD_INVALID with a fixed
  // message that does not echo the marker. After finalize throws,
  // the full raw jobs row must be byte-identical to the snapshot.
  it("A8 P1 regression: zero-action job with otherwise-derived completed tuple but corrupt pause_reason => finalize/get/list all throw ACTION_RECORD_INVALID; full raw jobs row byte-identical", () => {
    const handle = openDb();
    const jobMgr = new JobManager(handle) as unknown as SliceAJobManager;
    const jobId = "job-a8p1-corrupt-pause-reason";
    const A8P1_MARKER = "A8P1_PRIVATE_MARKER_DO_NOT_ECHO";
    const A8P1_CORRUPT_VALUE = `${A8P1_MARKER}_not_a_recognized_pause_reason_${A8P1_MARKER}`;
    const A8P1_SENTINEL_UPDATED_AT = "2099-07-15T12:34:56.789Z";
    const a8p1ExpectedZeroDetail = expectedStatusDetail(zeroCounts());

    // Seed: zero-action job whose raw tuple is otherwise the exact
    // derived completed tuple, then overwrite pause_reason with an
    // invalid non-null value, then snapshot the FULL raw row.
    seedJobWithInitialRow(handle, jobId);
    handle
      .prepare("UPDATE jobs SET status = ?, pause_reason = ?, status_detail = ?, updated_at = ? WHERE id = ?")
      .run("completed", null, a8p1ExpectedZeroDetail, A8P1_SENTINEL_UPDATED_AT, jobId);
    handle
      .prepare("UPDATE jobs SET pause_reason = ? WHERE id = ?")
      .run(A8P1_CORRUPT_VALUE, jobId);
    const before = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(before.pause_reason).toBe(A8P1_CORRUPT_VALUE);

    // finalize: must throw ACTION_RECORD_INVALID; message must not
    // contain the marker. (KEEP current production RED here.)
    let finalizeCaptured: unknown = null;
    try {
      (jobMgr as unknown as { finalize(jobId: string): FutureJobRecord }).finalize(jobId);
    } catch (err) { finalizeCaptured = err; }
    expect(finalizeCaptured).toBeInstanceOf(BountyPilotError);
    expect((finalizeCaptured as BountyPilotError).code).toBe("ACTION_RECORD_INVALID");
    expect((finalizeCaptured as BountyPilotError).message).not.toContain(A8P1_MARKER);

    // After finalize throws, the full raw jobs row is byte-identical
    // to the snapshot — no UPDATE issued, no column overwritten. No
    // redundant per-column probes after the full equality check.
    const after = handle
      .prepare("SELECT * FROM jobs WHERE id = ?")
      .get(jobId) as Record<string, unknown>;
    expect(after).toEqual(before);

    // get and list must EACH throw ACTION_RECORD_INVALID with a
    // marker-free message. No else branch where they may return.
    const getList = jobMgr as unknown as GetListSlice;
    let getCaptured: unknown = null;
    try { getList.get(jobId); } catch (err) { getCaptured = err; }
    expect(getCaptured).toBeInstanceOf(BountyPilotError);
    expect((getCaptured as BountyPilotError).code).toBe("ACTION_RECORD_INVALID");
    expect((getCaptured as BountyPilotError).message).not.toContain(A8P1_MARKER);

    let listCaptured: unknown = null;
    try { getList.list(50); } catch (err) { listCaptured = err; }
    expect(listCaptured).toBeInstanceOf(BountyPilotError);
    expect((listCaptured as BountyPilotError).code).toBe("ACTION_RECORD_INVALID");
    expect((listCaptured as BountyPilotError).message).not.toContain(A8P1_MARKER);
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C1A - ActionLifecycle.claim RED contract
// ===========================================================================

const C1A_REVIEWED_AT = "2099-01-01T00:00:00.000Z";
const C1A_CLAIMED_AT = "2099-01-01T00:01:00.000Z";
const C1A_TOKEN = "a".repeat(64);
const C1A_TARGET = "https://slice-a.example/path";

function buildC1AAuthorityDependencies(): Pick<
  ActionLifecycleDependencies,
  "loadCurrentProgram" | "resolveBindingMaterial"
> {
  const loaded: LoadedProgram = {
    config: ProgramSchema.parse({
      program: "c1a-program",
      platform: "hackerone",
      in_scope: ["slice-a.example", "*.slice-a.example"],
      out_of_scope: [],
      rules: {
        automated_scanning: "limited",
        destructive_testing: false,
        rate_limit: "1rps",
        browser_crawling: true,
        deep_safe_mode: true,
        lab_mode: false,
        require_human_approval_for_risky_actions: true,
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
    }),
    programFile: "/tmp/bountypilot-c1a.yml",
    labAuthorization: null,
  };
  const capability: CapabilityEnforcementInput = {
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
    mcpTools: [],
    title: "C1A HTTP read",
    description: "C1A inert test capability",
    produces: ["observation"],
  };
  return {
    loadCurrentProgram: () => loaded,
    resolveBindingMaterial: ({ source }): ResolvedBindingMaterial => ({
      normalizedTarget: source.action.target,
      capabilityEnforcement: capability,
      integration: { kind: "builtin" },
    }),
  };
}

function seedC1AApprovedAction(
  handle: BountyDatabase,
  suffix: string,
  approvalTtlMs = 15 * 60_000,
): {
  actionId: string;
  jobId: string;
  reviewId: string;
  authority: Pick<ActionLifecycleDependencies, "loadCurrentProgram" | "resolveBindingMaterial">;
} {
  const authority = buildC1AAuthorityDependencies();
  const job = new JobManager(handle).create("c1a-job", "safe", C1A_TARGET);
  const pending = new ActionQueue(handle).enqueue({
    jobId: job.id,
    adapter: "http",
    actionType: "GET",
    target: C1A_TARGET,
    riskLevel: "low",
    requiresApproval: true,
    requiredForCompletion: true,
    metadata: { fixture: suffix },
  });
  const approval = new ActionApprovalService(handle, {
    ...authority,
    now: () => new Date(C1A_REVIEWED_AT),
  });
  const challenge = approval.preview(pending.id);
  const result = approval.approveHuman({
    actionId: pending.id,
    reviewerId: `researcher-${suffix}`,
    expectedContextHash: challenge.contextHash,
    ttlMs: approvalTtlMs,
  });
  expect(result.action.status).toBe("approved");
  return { actionId: pending.id, jobId: job.id, reviewId: result.review.id, authority };
}

function captureC1AError(run: () => unknown): BountyPilotError {
  let captured: unknown;
  try {
    run();
  } catch (error) {
    captured = error;
  }
  expect(captured).toBeInstanceOf(BountyPilotError);
  return captured as BountyPilotError;
}

describe("C1A claim: caller boundary and raw status precedence", () => {
  it("C1A claim validates a plain exact DTO, canonical owner, and lease bounds before SQL/dependencies", () => {
    const handle = openDb();
    const unavailable = () => { throw new Error("C1A dependency must not run"); };
    const lifecycle = new ActionLifecycle(handle, {
      loadCurrentProgram: unavailable,
      resolveBindingMaterial: unavailable,
      now: unavailable,
      generateExecutionToken: unavailable,
    } as unknown as ActionLifecycleDependencies);
    const accessor: Record<string, unknown> = {
      actionId: "action-c1a-accessor",
      executionOwner: "owner",
    };
    Object.defineProperty(accessor, "leaseMs", { get: unavailable, enumerable: true });
    const proxy = new Proxy(
      { actionId: "action-c1a-proxy", executionOwner: "owner" },
      { get: unavailable },
    );
    const invalidCases: Array<{ input: unknown; code: string }> = [
      { input: null, code: "ACTION_LIFECYCLE_INVALID" },
      { input: [], code: "ACTION_LIFECYCLE_INVALID" },
      { input: proxy, code: "ACTION_LIFECYCLE_INVALID" },
      { input: accessor, code: "ACTION_LIFECYCLE_INVALID" },
      { input: { actionId: " padded", executionOwner: "owner" }, code: "ACTION_LIFECYCLE_INVALID" },
      { input: { actionId: "action-c1a", executionOwner: "" }, code: "ACTION_OWNER_INVALID" },
      { input: { actionId: "action-c1a", executionOwner: "bad\nowner" }, code: "ACTION_OWNER_INVALID" },
      { input: { actionId: "action-c1a", executionOwner: "owner", leaseMs: 0 }, code: "ACTION_LEASE_INVALID" },
      { input: { actionId: "action-c1a", executionOwner: "owner", leaseMs: 3_600_001 }, code: "ACTION_LEASE_INVALID" },
      { input: { actionId: "action-c1a", executionOwner: "owner", leaseMs: 1.5 }, code: "ACTION_LEASE_INVALID" },
      { input: { actionId: "action-c1a", executionOwner: "owner", leaseMs: undefined }, code: "ACTION_LEASE_INVALID" },
      { input: { actionId: "action-c1a", executionOwner: "owner", extra: true }, code: "ACTION_LIFECYCLE_INVALID" },
    ];
    for (const testCase of invalidCases) {
      const error = captureC1AError(() => lifecycle.claim(testCase.input as never));
      expect(error.code).toBe(testCase.code);
      expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
    }
  });

  it("C1A claim applies raw status precedence without authority, clock, token, or writes", () => {
    const handle = openDb();
    let dependencyCalls = 0;
    const unavailable = () => {
      dependencyCalls += 1;
      throw new Error("C1A dependency must not run");
    };
    const lifecycle = new ActionLifecycle(handle, {
      loadCurrentProgram: unavailable,
      resolveBindingMaterial: unavailable,
      now: unavailable,
      generateExecutionToken: unavailable,
    } as unknown as ActionLifecycleDependencies);
    const rows: Array<{ status: string; expected: string }> = [
      { status: "pending", expected: "ACTION_NOT_APPROVED" },
      { status: "planned", expected: "ACTION_NOT_APPROVED" },
      { status: "running", expected: "ACTION_LEASE_HELD" },
      { status: "outcome_unknown", expected: "ACTION_RECONCILIATION_REQUIRED" },
      { status: "executed", expected: "ACTION_TERMINAL" },
      { status: "blocked", expected: "ACTION_TERMINAL" },
      { status: "failed", expected: "ACTION_TERMINAL" },
      { status: "corrupt-status", expected: "ACTION_RECORD_INVALID" },
    ];
    for (const [index, row] of rows.entries()) {
      const actionId = `action-c1a-status-${index}`;
      insertRawV2Action(handle, {
        id: actionId,
        jobId: `job-c1a-status-${index}`,
        status: "pending",
        requiredForCompletion: 1,
      });
      if (row.status !== "pending") {
        handle.prepare("UPDATE actions SET status = ? WHERE id = ?").run(row.status, actionId);
      }
      const before = readActionRow(handle, actionId);
      const error = captureC1AError(() =>
        lifecycle.claim({ actionId, executionOwner: "worker-c1a" }),
      );
      expect(error.code, row.status).toBe(row.expected);
      expect(readActionRow(handle, actionId)).toEqual(before);
    }
    expect(dependencyCalls).toBe(0);
  });
});

describe("C1A claim: approval-bound happy path and fail-closed dependencies", () => {
  it("C1A claim atomically returns a nested token context, persists running state, records the exact safe event, and finalizes the job", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "happy");
    let tokenCalls = 0;
    const lifecycle = new ActionLifecycle(handle, {
      ...seeded.authority,
      now: () => new Date(C1A_CLAIMED_AT),
      generateExecutionToken: () => {
        tokenCalls += 1;
        return C1A_TOKEN;
      },
    });
    const claimed: ClaimedActionContext = lifecycle.claim({
      actionId: seeded.actionId,
      executionOwner: "  c1a-worker  ",
      leaseMs: 120_000,
    });
    expect(tokenCalls).toBe(1);
    expect(Object.keys(claimed).sort()).toEqual(["action", "executionToken"]);
    expect(Object.prototype.propertyIsEnumerable.call(claimed, "effectAuthority")).toBe(false);
    expect(claimed.effectAuthority.programConfig.program).toBe("c1a-program");
    expect(claimed.executionToken).toBe(C1A_TOKEN);
    expect(claimed.action.id).toBe(seeded.actionId);
    expect(claimed.action.status).toBe("running");
    expect(claimed.action.executionOwner).toBe("c1a-worker");
    expect(Object.prototype.hasOwnProperty.call(claimed.action, "executionToken")).toBe(false);
    expect(JSON.stringify(claimed.action)).not.toContain(C1A_TOKEN);

    const raw = readActionRow(handle, seeded.actionId);
    expect(raw.status).toBe("running");
    expect(raw.execution_token).toBe(C1A_TOKEN);
    expect(raw.execution_owner).toBe("c1a-worker");
    expect(raw.started_at).toBe(C1A_CLAIMED_AT);
    expect(raw.updated_at).toBe(C1A_CLAIMED_AT);
    expect(raw.lease_expires_at).toBe("2099-01-01T00:03:00.000Z");
    expect(raw.dispatch_started_at).toBeNull();
    expect(raw.finished_at).toBeNull();
    expect(raw.outcome_certainty).toBeNull();

    const events = new WorkflowEventStore(handle).list(seeded.jobId);
    const event = events.at(-1);
    expect(event).toMatchObject({
      phase: "action-execution",
      status: "running",
      message: "Action execution claimed",
      metadata: {
        actionId: seeded.actionId,
        reviewId: seeded.reviewId,
        reasonCode: "execution_claimed",
        contextHash: claimed.action.plannedContextHash,
      },
    });
    expect(Object.keys(event?.metadata ?? {}).sort()).toEqual(
      ["actionId", "contextHash", "reasonCode", "reviewId"].sort(),
    );
    expect(JSON.stringify(event)).not.toContain(C1A_TOKEN);
    const job = new JobManager(handle).get(seeded.jobId);
    expect(job?.status).toBe("running");
    expect(job?.pauseReason).toBeNull();
  });

  it("C1A claim maps invalid clocks and token faults to fixed cause-free errors with no writes", () => {
    const handle = openDb();
    const cases: Array<{ name: string; now: () => Date; token: () => string; expected: string }> = [
      {
        name: "clock throws",
        now: () => { throw new Error("private-clock-secret"); },
        token: () => C1A_TOKEN,
        expected: "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
      },
      {
        name: "invalid Date",
        now: () => new Date(Number.NaN),
        token: () => C1A_TOKEN,
        expected: "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
      },
      {
        name: "token throws",
        now: () => new Date(C1A_CLAIMED_AT),
        token: () => { throw new Error("private-token-secret"); },
        expected: "ACTION_TOKEN_INVALID",
      },
      {
        name: "token malformed",
        now: () => new Date(C1A_CLAIMED_AT),
        token: () => "A".repeat(64),
        expected: "ACTION_TOKEN_INVALID",
      },
    ];
    for (const [index, testCase] of cases.entries()) {
      const seeded = seedC1AApprovedAction(handle, `fault-${index}`);
      const beforeAction = readActionRow(handle, seeded.actionId);
      const beforeReview = handle
        .prepare("SELECT * FROM action_reviews WHERE id = ?")
        .get(seeded.reviewId) as Record<string, unknown>;
      const beforeEvents = new WorkflowEventStore(handle).count(seeded.jobId);
      const lifecycle = new ActionLifecycle(handle, {
        ...seeded.authority,
        now: testCase.now,
        generateExecutionToken: testCase.token,
      });
      const error = captureC1AError(() =>
        lifecycle.claim({ actionId: seeded.actionId, executionOwner: "worker-c1a" }),
      );
      expect(error.code, testCase.name).toBe(testCase.expected);
      expect(error.message).not.toContain("private-");
      expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
      expect(readActionRow(handle, seeded.actionId)).toEqual(beforeAction);
      expect(
        handle.prepare("SELECT * FROM action_reviews WHERE id = ?").get(seeded.reviewId),
      ).toEqual(beforeReview);
      expect(new WorkflowEventStore(handle).count(seeded.jobId)).toBe(beforeEvents);
    }
  });

  it("C1A claim treats review expiry equality as expired, commits invalidation/demotion/event/job, then throws", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "expiry", 60_000);
    const lifecycle = new ActionLifecycle(handle, {
      ...seeded.authority,
      now: () => new Date(C1A_CLAIMED_AT),
      generateExecutionToken: () => C1A_TOKEN,
    });
    const error = captureC1AError(() =>
      lifecycle.claim({ actionId: seeded.actionId, executionOwner: "worker-c1a" }),
    );
    expect(error.code).toBe("ACTION_REVIEW_EXPIRED");
    expect(error.message).not.toContain(C1A_TOKEN);

    const review = handle
      .prepare("SELECT invalidated_at, invalidation_reason FROM action_reviews WHERE id = ?")
      .get(seeded.reviewId) as Record<string, unknown>;
    expect(review).toEqual({
      invalidated_at: C1A_CLAIMED_AT,
      invalidation_reason: "review_expired",
    });
    const raw = readActionRow(handle, seeded.actionId);
    expect(raw.status).toBe("pending");
    expect(raw.active_review_id).toBeNull();
    expect(raw.planned_scope_hash).toBeNull();
    expect(raw.planned_policy_hash).toBeNull();
    expect(raw.planned_action_hash).toBeNull();
    expect(raw.planned_context_hash).toBeNull();
    expect(raw.execution_token).toBeNull();

    const event = new WorkflowEventStore(handle).list(seeded.jobId).at(-1);
    expect(event).toMatchObject({
      phase: "action-review",
      status: "paused",
      message: "Action approval invalidated",
      metadata: {
        actionId: seeded.actionId,
        reviewId: seeded.reviewId,
        reasonCode: "review_expired",
      },
    });
    expect(Object.keys(event?.metadata ?? {}).sort()).toEqual(
      ["actionId", "reasonCode", "reviewId"].sort(),
    );
    const job = new JobManager(handle).get(seeded.jobId);
    expect(job?.status).toBe("paused");
    expect(job?.pauseReason).toBe("approval_required");
  });

  it("C1A claim lifecycle module has no effect/network/browser/process imports", () => {
    const source = readFileSync(
      new URL("../src/core/actions/action-lifecycle.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toMatch(
      /(?:from|import\s*\()\s*["'](?:node:(?:child_process|cluster|dgram|dns|http|https|net|tls)|playwright|puppeteer|.*(?:executor|adapter-runner|browser|mcp|effect|network).*)["']/i,
    );
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C1B-A - invalidation primitive + claim boundaries
// ===========================================================================

const C1B_INVALIDATED_AT = "2099-01-01T00:01:00.000Z";
const C1B_ZERO_TOKEN = "0".repeat(64);

const C1B_FIXED_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  ACTION_APPROVAL_CONTEXT_UNAVAILABLE: "Action approval context is unavailable.",
  ACTION_CLAIM_RACE: "Action claim lost the race.",
  ACTION_HASH_MISMATCH: "Action approval binding has changed.",
  ACTION_POLICY_DRIFT: "Action approval policy has changed.",
  ACTION_RECORD_INVALID: "Action record is invalid.",
  ACTION_REVIEW_EXPIRED: "Action approval review has expired.",
  ACTION_REVIEW_INVALID: "Action review is invalid.",
  ACTION_SCOPE_DRIFT: "Action approval scope has changed.",
  ACTION_TOKEN_COLLISION: "Action execution token collided with an existing claim.",
  ACTION_TOKEN_INVALID: "Action execution token is invalid.",
});

function expectC1BError(
  run: () => unknown,
  code: keyof typeof C1B_FIXED_MESSAGES,
): BountyPilotError {
  const error = captureC1AError(run);
  expect(error.code).toBe(code);
  expect(error.message).toBe(C1B_FIXED_MESSAGES[code]);
  expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
  return error;
}

function c1bRawState(
  handle: BountyDatabase,
  seeded: ReturnType<typeof seedC1AApprovedAction>,
): {
  action: Record<string, unknown>;
  review: Record<string, unknown> | undefined;
  job: Record<string, unknown>;
  events: WorkflowEventRecord[];
} {
  return {
    action: readActionRow(handle, seeded.actionId),
    review: handle
      .prepare("SELECT * FROM action_reviews WHERE id = ?")
      .get(seeded.reviewId) as Record<string, unknown> | undefined,
    job: readJobRow(handle, seeded.jobId),
    events: new WorkflowEventStore(handle).list(seeded.jobId),
  };
}

describe("C1B-A ActionReviewStore.invalidateApprovalInTransaction", () => {
  it("checks the exact tracked handle before reflecting over a hostile Proxy", () => {
    const handleA = openDb();
    const handleB = openBountyDatabase(dbFile);
    const storeA = new ActionReviewStore(handleA);
    const storeB = new ActionReviewStore(handleB);
    const privateMarker = "C1B_PRIVATE_PROXY_TRAP";
    let trapCalls = 0;
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          trapCalls += 1;
          throw new Error(privateMarker);
        },
        ownKeys: () => {
          trapCalls += 1;
          throw new Error(privateMarker);
        },
        getOwnPropertyDescriptor: () => {
          trapCalls += 1;
          throw new Error(privateMarker);
        },
      },
    );

    const assertGuard = (run: () => unknown): void => {
      const error = captureC1AError(run);
      expect(error.code).toBe("ACTION_REVIEW_TRANSACTION_REQUIRED");
      expect(error.message).toBe(
        "ActionReviewStore.invalidateApprovalInTransaction requires an active withImmediateTransaction on the same handle",
      );
      expect(error.message).not.toContain(privateMarker);
      expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
    };

    try {
      assertGuard(() =>
        storeA.invalidateApprovalInTransaction(hostile as never),
      );
      withImmediateTransaction(handleA, () => {
        assertGuard(() =>
          storeB.invalidateApprovalInTransaction(hostile as never),
        );
      });
      expect(trapCalls).toBe(0);
    } finally {
      handleB.close();
    }
  });

  it("rejects non-exact DTOs and non-allowlisted reasons cause-free before any UPDATE", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "invalidate-invalid");
    const store = new ActionReviewStore(handle);
    const valid = {
      reviewId: seeded.reviewId,
      actionId: seeded.actionId,
      jobId: seeded.jobId,
      invalidatedAt: C1B_INVALIDATED_AT,
      invalidationReason: "scope_drift",
    } as const;
    const accessor = { ...valid } as Record<string, unknown>;
    Object.defineProperty(accessor, "invalidationReason", {
      enumerable: true,
      get: () => {
        throw new Error("C1B_PRIVATE_ACCESSOR");
      },
    });
    const withSymbol = { ...valid } as Record<PropertyKey, unknown>;
    withSymbol[Symbol("c1b")] = true;
    const invalidInputs: unknown[] = [
      null,
      [],
      { ...valid, extra: true },
      {
        reviewId: valid.reviewId,
        actionId: valid.actionId,
        jobId: valid.jobId,
        invalidatedAt: valid.invalidatedAt,
      },
      { ...valid, reviewId: ` ${valid.reviewId}` },
      { ...valid, invalidatedAt: "2099-01-01T00:01:00Z" },
      { ...valid, invalidationReason: "expired" },
      Object.assign(Object.create({ inherited: true }), valid),
      accessor,
      withSymbol,
    ];
    const before = handle
      .prepare("SELECT * FROM action_reviews WHERE id = ?")
      .get(seeded.reviewId) as Record<string, unknown>;

    withImmediateTransaction(handle, () => {
      for (const input of invalidInputs) {
        const error = captureC1AError(() =>
          store.invalidateApprovalInTransaction(input as never),
        );
        expect(error.code).toBe("ACTION_APPROVAL_INVALID");
        expect(error.message).toBe("Action review invalidation input is invalid.");
        expect(error.message).not.toContain("C1B_PRIVATE");
        expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
      }
    });

    expect(
      handle.prepare("SELECT * FROM action_reviews WHERE id = ?").get(seeded.reviewId),
    ).toEqual(before);
  });

  it("accepts an exact null-prototype DTO, returns a frozen one-row result, and issues only a narrow UPDATE", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "invalidate-one");
    const store = new ActionReviewStore(handle);
    const input = Object.assign(Object.create(null), {
      reviewId: seeded.reviewId,
      actionId: seeded.actionId,
      jobId: seeded.jobId,
      invalidatedAt: C1B_INVALIDATED_AT,
      invalidationReason: "context_hash_mismatch",
    });
    const originalPrepare = handle.prepare.bind(handle);
    const preparedSql: string[] = [];
    Object.defineProperty(handle, "prepare", {
      configurable: true,
      value: ((sql: string) => {
        preparedSql.push(sql);
        return originalPrepare(sql);
      }) as BountyDatabase["prepare"],
    });

    let result: Readonly<{ changes: 0 | 1 }> | undefined;
    try {
      result = withImmediateTransaction(handle, () =>
        store.invalidateApprovalInTransaction(input as never),
      );
    } finally {
      delete (handle as unknown as Record<string, unknown>).prepare;
    }

    expect(result).toEqual({ changes: 1 });
    expect(Object.keys(result ?? {})).toEqual(["changes"]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(preparedSql).toHaveLength(1);
    const sql = preparedSql[0] ?? "";
    expect(sql).toMatch(/^\s*UPDATE\s+action_reviews\b/i);
    expect(sql).toMatch(/\bid\s*=\s*\?/i);
    expect(sql).toMatch(/\baction_id\s*=\s*\?/i);
    expect(sql).toMatch(/\bjob_id\s*=\s*\?/i);
    expect(sql).toMatch(/invalidated_at\s+IS\s+NULL/i);
    expect(sql).toMatch(/invalidation_reason\s+IS\s+NULL/i);
    expect(sql).not.toMatch(/\bSELECT\b|\bRETURNING\b|\bnote\b|execution_token|\btoken\b/i);
    expect(
      originalPrepare(
        "SELECT invalidated_at, invalidation_reason FROM action_reviews WHERE id = ?",
      ).get(seeded.reviewId),
    ).toEqual({
      invalidated_at: C1B_INVALIDATED_AT,
      invalidation_reason: "context_hash_mismatch",
    });
  });

  it("returns frozen zero for missing, mismatched, or already-invalidated rows and still invalidates a matching malformed decision", () => {
    const handle = openDb();
    const missing = seedC1AApprovedAction(handle, "invalidate-missing");
    const mismatch = seedC1AApprovedAction(handle, "invalidate-mismatch");
    const prior = seedC1AApprovedAction(handle, "invalidate-prior");
    const malformed = seedC1AApprovedAction(handle, "invalidate-decision");
    handle
      .prepare(
        "UPDATE action_reviews SET invalidated_at = ?, invalidation_reason = ? WHERE id = ?",
      )
      .run(C1B_INVALIDATED_AT, "review_expired", prior.reviewId);
    handle
      .prepare("UPDATE action_reviews SET decision = 'blocked' WHERE id = ?")
      .run(malformed.reviewId);
    const store = new ActionReviewStore(handle);

    const results = withImmediateTransaction(handle, () => [
      store.invalidateApprovalInTransaction({
        reviewId: "review-c1b-does-not-exist",
        actionId: missing.actionId,
        jobId: missing.jobId,
        invalidatedAt: C1B_INVALIDATED_AT,
        invalidationReason: "review_expired",
      }),
      store.invalidateApprovalInTransaction({
        reviewId: mismatch.reviewId,
        actionId: mismatch.actionId,
        jobId: `${mismatch.jobId}-wrong`,
        invalidatedAt: C1B_INVALIDATED_AT,
        invalidationReason: "policy_drift",
      }),
      store.invalidateApprovalInTransaction({
        reviewId: prior.reviewId,
        actionId: prior.actionId,
        jobId: prior.jobId,
        invalidatedAt: "2099-01-01T00:02:00.000Z",
        invalidationReason: "scope_blocked",
      }),
      store.invalidateApprovalInTransaction({
        reviewId: malformed.reviewId,
        actionId: malformed.actionId,
        jobId: malformed.jobId,
        invalidatedAt: C1B_INVALIDATED_AT,
        invalidationReason: "policy_blocked",
      }),
    ]);

    expect(results.map((result) => result.changes)).toEqual([0, 0, 0, 1]);
    expect(results.every((result) => Object.isFrozen(result))).toBe(true);
    expect(
      handle
        .prepare("SELECT decision, invalidated_at, invalidation_reason FROM action_reviews WHERE id = ?")
        .get(malformed.reviewId),
    ).toEqual({
      decision: "blocked",
      invalidated_at: C1B_INVALIDATED_AT,
      invalidation_reason: "policy_blocked",
    });
  });

  it("leaves invalidation ownership with the caller transaction so rollback restores the row", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "invalidate-rollback");
    const store = new ActionReviewStore(handle);
    const sentinel = new Error("C1B_ROLLBACK_SENTINEL");
    let captured: unknown;

    try {
      withImmediateTransaction(handle, () => {
        const result = store.invalidateApprovalInTransaction({
          reviewId: seeded.reviewId,
          actionId: seeded.actionId,
          jobId: seeded.jobId,
          invalidatedAt: C1B_INVALIDATED_AT,
          invalidationReason: "action_hash_mismatch",
        });
        expect(result).toEqual({ changes: 1 });
        expect(
          handle
            .prepare("SELECT invalidated_at FROM action_reviews WHERE id = ?")
            .get(seeded.reviewId),
        ).toEqual({ invalidated_at: C1B_INVALIDATED_AT });
        throw sentinel;
      });
    } catch (error) {
      captured = error;
    }

    expect(captured).toBe(sentinel);
    expect(
      handle
        .prepare("SELECT invalidated_at, invalidation_reason FROM action_reviews WHERE id = ?")
        .get(seeded.reviewId),
    ).toEqual({ invalidated_at: null, invalidation_reason: null });
  });
});

describe("C1B-A claim: exact dependency pipeline, lease cap, and token boundary", () => {
  it("calls load-resolve-now-token exactly once in order, caps the lease to review expiry, and accepts an all-zero token", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "pipeline", 90_000);
    const order: string[] = [];
    const calls = { load: 0, resolve: 0, now: 0, token: 0 };
    const lifecycle = new ActionLifecycle(handle, {
      loadCurrentProgram: () => {
        calls.load += 1;
        order.push("load");
        return seeded.authority.loadCurrentProgram();
      },
      resolveBindingMaterial: (input) => {
        calls.resolve += 1;
        order.push("resolve");
        return seeded.authority.resolveBindingMaterial(input);
      },
      now: () => {
        calls.now += 1;
        order.push("now");
        return new Date(C1A_CLAIMED_AT);
      },
      generateExecutionToken: () => {
        calls.token += 1;
        order.push("token");
        return C1B_ZERO_TOKEN;
      },
    });

    const claimed = lifecycle.claim({
      actionId: seeded.actionId,
      executionOwner: "c1b-worker",
      leaseMs: 120_000,
    });

    expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expect(order).toEqual(["load", "resolve", "now", "token"]);
    expect(claimed.executionToken).toBe(C1B_ZERO_TOKEN);
    expect(readActionRow(handle, seeded.actionId)).toMatchObject({
      status: "running",
      execution_token: C1B_ZERO_TOKEN,
      lease_expires_at: "2099-01-01T00:01:30.000Z",
    });

    const publicValues = [
      claimed.action,
      new ActionQueue(handle).get(seeded.actionId),
      new WorkflowEventStore(handle).list(seeded.jobId),
      new JobManager(handle).get(seeded.jobId),
      new ActionReviewStore(handle).listForAction(seeded.actionId),
    ];
    for (const value of publicValues) {
      expect(JSON.stringify(value)).not.toContain(C1B_ZERO_TOKEN);
    }
    expect(Object.prototype.hasOwnProperty.call(claimed.action, "executionToken")).toBe(false);
  });
});

type C1BPreflightMutation = {
  name: string;
  expected: "ACTION_RECORD_INVALID" | "ACTION_REVIEW_INVALID";
  mutate(
    handle: BountyDatabase,
    seeded: ReturnType<typeof seedC1AApprovedAction>,
  ): void;
};

const C1B_PREFLIGHT_CASES: readonly C1BPreflightMutation[] = [
  {
    name: "malformed null action job reference",
    expected: "ACTION_RECORD_INVALID",
    mutate: (handle, seeded) => {
      handle.exec("PRAGMA foreign_keys = OFF");
      handle.prepare("UPDATE actions SET job_id = NULL WHERE id = ?").run(seeded.actionId);
      handle.exec("PRAGMA foreign_keys = ON");
    },
  },
  {
    name: "invalid job mode",
    expected: "ACTION_RECORD_INVALID",
    mutate: (handle, seeded) => {
      handle.prepare("UPDATE jobs SET mode = 'c1b-invalid' WHERE id = ?").run(seeded.jobId);
    },
  },
  {
    name: "dirty action execution state",
    expected: "ACTION_RECORD_INVALID",
    mutate: (handle, seeded) => {
      handle.prepare("UPDATE actions SET execution_owner = 'orphan-owner' WHERE id = ?").run(seeded.actionId);
    },
  },
  {
    name: "missing active review link",
    expected: "ACTION_REVIEW_INVALID",
    mutate: (handle, seeded) => {
      handle.prepare("UPDATE actions SET active_review_id = NULL WHERE id = ?").run(seeded.actionId);
    },
  },
  {
    name: "all-zero planned review hash",
    expected: "ACTION_REVIEW_INVALID",
    mutate: (handle, seeded) => {
      handle
        .prepare("UPDATE actions SET planned_scope_hash = ? WHERE id = ?")
        .run("0".repeat(64), seeded.actionId);
    },
  },
  {
    name: "non-record action metadata",
    expected: "ACTION_RECORD_INVALID",
    mutate: (handle, seeded) => {
      handle.prepare("UPDATE actions SET metadata_json = '[]' WHERE id = ?").run(seeded.actionId);
    },
  },
];

describe("C1B-A claim: preflight and dependency fault boundaries", () => {
  it.each(C1B_PREFLIGHT_CASES)(
    "rejects $name before authority, clock, or token generation",
    ({ expected, mutate }) => {
      const handle = openDb();
      const seeded = seedC1AApprovedAction(handle, `preflight-${expected}-${Math.random()}`);
      mutate(handle, seeded);
      const before = c1bRawState(handle, seeded);
      const calls = { load: 0, resolve: 0, now: 0, token: 0 };
      const unavailable = (stage: keyof typeof calls): never => {
        calls[stage] += 1;
        throw new Error(`C1B_PRIVATE_UNEXPECTED_${stage}`);
      };
      const lifecycle = new ActionLifecycle(handle, {
        loadCurrentProgram: () => unavailable("load"),
        resolveBindingMaterial: () => unavailable("resolve"),
        now: () => unavailable("now"),
        generateExecutionToken: () => unavailable("token"),
      } as unknown as ActionLifecycleDependencies);

      const error = expectC1BError(
        () => lifecycle.claim({ actionId: seeded.actionId, executionOwner: "c1b-worker" }),
        expected,
      );
      expect(error.message).not.toContain("C1B_PRIVATE");
      expect(calls).toEqual({ load: 0, resolve: 0, now: 0, token: 0 });
      expect(c1bRawState(handle, seeded)).toEqual(before);
    },
  );

  const dependencyFaults = [
    {
      stage: "load",
      expectedCode: "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
      expectedCalls: { load: 1, resolve: 0, now: 0, token: 0 },
    },
    {
      stage: "resolve",
      expectedCode: "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
      expectedCalls: { load: 1, resolve: 1, now: 0, token: 0 },
    },
    {
      stage: "now",
      expectedCode: "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
      expectedCalls: { load: 1, resolve: 1, now: 1, token: 0 },
    },
    {
      stage: "token",
      expectedCode: "ACTION_TOKEN_INVALID",
      expectedCalls: { load: 1, resolve: 1, now: 1, token: 1 },
    },
  ] as const;

  it.each(dependencyFaults)(
    "maps a $stage fault cause-free with exact call counts and zero writes",
    ({ stage, expectedCode, expectedCalls }) => {
      const handle = openDb();
      const seeded = seedC1AApprovedAction(handle, `dependency-${stage}`);
      const before = c1bRawState(handle, seeded);
      const calls = { load: 0, resolve: 0, now: 0, token: 0 };
      const fail = (current: keyof typeof calls): void => {
        calls[current] += 1;
        if (current === stage) throw new Error(`C1B_PRIVATE_${stage}_FAULT`);
      };
      const lifecycle = new ActionLifecycle(handle, {
        loadCurrentProgram: () => {
          fail("load");
          return seeded.authority.loadCurrentProgram();
        },
        resolveBindingMaterial: (input) => {
          fail("resolve");
          return seeded.authority.resolveBindingMaterial(input);
        },
        now: () => {
          fail("now");
          return new Date(C1A_CLAIMED_AT);
        },
        generateExecutionToken: () => {
          fail("token");
          return C1A_TOKEN;
        },
      });

      const error = expectC1BError(
        () => lifecycle.claim({ actionId: seeded.actionId, executionOwner: "c1b-worker" }),
        expectedCode,
      );
      expect(error.message).not.toContain("C1B_PRIVATE");
      expect(calls).toEqual(expectedCalls);
      expect(c1bRawState(handle, seeded)).toEqual(before);
    },
  );
});

const C1B_LOCKED_REVIEW_CASES = [
  {
    name: "missing review",
    mutate: (
      handle: BountyDatabase,
      seeded: ReturnType<typeof seedC1AApprovedAction>,
    ): void => {
      handle.exec("PRAGMA foreign_keys = OFF");
      handle.prepare("DELETE FROM action_reviews WHERE id = ?").run(seeded.reviewId);
      handle.exec("PRAGMA foreign_keys = ON");
    },
  },
  {
    name: "malformed review decision",
    mutate: (
      handle: BountyDatabase,
      seeded: ReturnType<typeof seedC1AApprovedAction>,
    ): void => {
      handle.prepare("UPDATE action_reviews SET decision = 'failed' WHERE id = ?").run(seeded.reviewId);
    },
  },
  {
    name: "malformed human reviewer",
    mutate: (
      handle: BountyDatabase,
      seeded: ReturnType<typeof seedC1AApprovedAction>,
    ): void => {
      handle.prepare("UPDATE action_reviews SET reviewer_id = '' WHERE id = ?").run(seeded.reviewId);
    },
  },
] as const;

describe("C1B-A claim: locked review and token-collision rollback", () => {
  it.each(C1B_LOCKED_REVIEW_CASES)(
    "consumes exactly one local token for a $name but persists and emits nothing",
    ({ name, mutate }) => {
      const handle = openDb();
      const seeded = seedC1AApprovedAction(handle, `locked-${name}`);
      mutate(handle, seeded);
      const before = c1bRawState(handle, seeded);
      const calls = { load: 0, resolve: 0, now: 0, token: 0 };
      const generatedToken = "b".repeat(64);
      const lifecycle = new ActionLifecycle(handle, {
        loadCurrentProgram: () => {
          calls.load += 1;
          return seeded.authority.loadCurrentProgram();
        },
        resolveBindingMaterial: (input) => {
          calls.resolve += 1;
          return seeded.authority.resolveBindingMaterial(input);
        },
        now: () => {
          calls.now += 1;
          return new Date(C1A_CLAIMED_AT);
        },
        generateExecutionToken: () => {
          calls.token += 1;
          return generatedToken;
        },
      });

      const error = expectC1BError(
        () => lifecycle.claim({ actionId: seeded.actionId, executionOwner: "c1b-worker" }),
        "ACTION_REVIEW_INVALID",
      );
      expect(error.message).not.toContain(generatedToken);
      expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
      expect(c1bRawState(handle, seeded)).toEqual(before);
    },
  );

  it("maps a real unique execution-token collision once and rolls back the whole claim", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "token-collision");
    const collisionToken = "c".repeat(64);
    insertRawV2Action(handle, {
      id: "action-c1b-token-holder",
      jobId: "job-c1b-token-holder",
      status: "running",
      requiredForCompletion: 0,
      executionToken: collisionToken,
      executionOwner: "existing-worker",
      leaseExpiresAt: "2099-01-01T00:10:00.000Z",
      startedAt: C1A_REVIEWED_AT,
    });
    const before = c1bRawState(handle, seeded);
    const holderBefore = readActionRow(handle, "action-c1b-token-holder");
    let tokenCalls = 0;
    const lifecycle = new ActionLifecycle(handle, {
      ...seeded.authority,
      now: () => new Date(C1A_CLAIMED_AT),
      generateExecutionToken: () => {
        tokenCalls += 1;
        return collisionToken;
      },
    });

    const error = expectC1BError(
      () => lifecycle.claim({ actionId: seeded.actionId, executionOwner: "c1b-worker" }),
      "ACTION_TOKEN_COLLISION",
    );
    expect(error.message).not.toContain(collisionToken);
    expect(tokenCalls).toBe(1);
    expect(c1bRawState(handle, seeded)).toEqual(before);
    expect(readActionRow(handle, "action-c1b-token-holder")).toEqual(holderBefore);
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C1B-B - committed claim rejection + exact CAS races
// ===========================================================================

type C1BBCallCounts = {
  load: number;
  resolve: number;
  now: number;
  token: number;
};

type C1BBDependencyOverrides = {
  load?(loaded: LoadedProgram): LoadedProgram;
  resolve?(resolved: ResolvedBindingMaterial): ResolvedBindingMaterial;
  beforeToken?(): void;
};

function buildC1BBClaimDependencies(
  seeded: ReturnType<typeof seedC1AApprovedAction>,
  token: string,
  overrides: C1BBDependencyOverrides = {},
): { dependencies: ActionLifecycleDependencies; calls: C1BBCallCounts } {
  const calls: C1BBCallCounts = { load: 0, resolve: 0, now: 0, token: 0 };
  return {
    calls,
    dependencies: {
      loadCurrentProgram: () => {
        calls.load += 1;
        const loaded = seeded.authority.loadCurrentProgram();
        return overrides.load ? overrides.load(loaded) : loaded;
      },
      resolveBindingMaterial: (input) => {
        calls.resolve += 1;
        const resolved = seeded.authority.resolveBindingMaterial(input);
        return overrides.resolve ? overrides.resolve(resolved) : resolved;
      },
      now: () => {
        calls.now += 1;
        return new Date(C1A_CLAIMED_AT);
      },
      generateExecutionToken: () => {
        calls.token += 1;
        overrides.beforeToken?.();
        return token;
      },
    },
  };
}

function c1bbProgramWith(
  loaded: LoadedProgram,
  patch: { inScope?: string[]; rateLimit?: string },
): LoadedProgram {
  return {
    ...loaded,
    config: ProgramSchema.parse({
      ...loaded.config,
      in_scope: patch.inScope ?? loaded.config.in_scope,
      rules: {
        ...loaded.config.rules,
        ...(patch.rateLimit === undefined ? {} : { rate_limit: patch.rateLimit }),
      },
    }),
  };
}

function c1bbStatusDetail(status: "pending" | "blocked"): string {
  return JSON.stringify({
    requiredActionCounts: {
      approved: 0,
      blocked: status === "blocked" ? 1 : 0,
      executed: 0,
      failed: 0,
      outcome_unknown: 0,
      pending: status === "pending" ? 1 : 0,
      running: 0,
    },
    schemaVersion: 1,
  });
}

function expectC1BBCommittedRepair(input: {
  handle: BountyDatabase;
  seeded: ReturnType<typeof seedC1AApprovedAction>;
  before: ReturnType<typeof c1bRawState>;
  status: "pending" | "blocked";
  reason:
    | "scope_drift"
    | "policy_drift"
    | "action_hash_mismatch"
    | "context_hash_mismatch"
    | "scope_blocked"
    | "policy_blocked";
}): void {
  const { handle, seeded, before, status, reason } = input;
  expect(readActionRow(handle, seeded.actionId)).toEqual({
    ...before.action,
    status,
    active_review_id: null,
    planned_scope_hash: null,
    planned_policy_hash: null,
    planned_action_hash: null,
    planned_context_hash: null,
    updated_at: C1A_CLAIMED_AT,
  });

  const review = handle
    .prepare("SELECT * FROM action_reviews WHERE id = ?")
    .get(seeded.reviewId) as Record<string, unknown> | undefined;
  if (before.review === undefined) {
    expect(review).toBeUndefined();
  } else {
    expect(review).toEqual({
      ...before.review,
      invalidated_at: C1A_CLAIMED_AT,
      invalidation_reason: reason,
    });
  }

  const events = new WorkflowEventStore(handle).list(seeded.jobId);
  expect(events).toHaveLength(before.events.length + 1);
  expect(events.slice(0, -1)).toEqual(before.events);
  expect(events.at(-1)).toEqual({
    id: expect.any(String),
    jobId: seeded.jobId,
    sequence: (before.events.at(-1)?.sequence ?? 0) + 1,
    phase: "action-review",
    status: status === "blocked" ? "blocked" : "paused",
    message:
      status === "blocked"
        ? "Action approval blocked by current authority"
        : "Action approval invalidated",
    metadata: {
      actionId: seeded.actionId,
      reviewId: seeded.reviewId,
      reasonCode: reason,
    },
    createdAt: expect.stringMatching(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    ),
  });
  expect(Object.keys(events.at(-1)?.metadata ?? {}).sort()).toEqual(
    ["actionId", "reasonCode", "reviewId"].sort(),
  );

  expect(readJobRow(handle, seeded.jobId)).toEqual({
    ...before.job,
    status: status === "blocked" ? "failed" : "paused",
    pause_reason: status === "blocked" ? "policy_blocked" : "approval_required",
    status_detail: c1bbStatusDetail(status),
    updated_at: expect.stringMatching(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    ),
  });
}

function expectC1BBTokenAbsent(
  handle: BountyDatabase,
  seeded: ReturnType<typeof seedC1AApprovedAction>,
  token: string,
  error: BountyPilotError,
): void {
  expect(error.message).not.toContain(token);
  expect(String(error)).not.toContain(token);
  const publicAndRawState = [
    readActionRow(handle, seeded.actionId),
    handle.prepare("SELECT * FROM action_reviews WHERE action_id = ?").all(seeded.actionId),
    new ActionQueue(handle).get(seeded.actionId),
    new ActionReviewStore(handle).listForAction(seeded.actionId),
    new WorkflowEventStore(handle).list(seeded.jobId),
    new JobManager(handle).get(seeded.jobId),
  ];
  for (const value of publicAndRawState) {
    expect(JSON.stringify(value)).not.toContain(token);
  }
}

function c1bbLoseActionCas(
  handle: BountyDatabase,
  kind: "success" | "repair",
  onLoss?: () => void,
): { restore(): void; hits(): number } {
  const originalPrepare = handle.prepare.bind(handle);
  let hitCount = 0;
  Object.defineProperty(handle, "prepare", {
    configurable: true,
    value: ((sql: string) => {
      const isTarget =
        kind === "success"
          ? /UPDATE\s+actions\s+SET\s+status\s*=\s*'running'/i.test(sql)
          : /UPDATE\s+actions\s+SET\s+status\s*=\s*\?/i.test(sql);
      if (!isTarget) return originalPrepare(sql);
      hitCount += 1;
      onLoss?.();
      return {
        run: () => ({ changes: 0, lastInsertRowid: 0 }),
      } as unknown as ReturnType<BountyDatabase["prepare"]>;
    }) as BountyDatabase["prepare"],
  });
  return {
    restore: () => {
      delete (handle as unknown as Record<string, unknown>).prepare;
    },
    hits: () => hitCount,
  };
}

describe("C1B-B claim: current authority block precedes locked review validation", () => {
  it("commits a scope block and invalidates the matching review even when its decision is malformed", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bb-scope-block-malformed");
    handle
      .prepare("UPDATE action_reviews SET decision = 'failed' WHERE id = ?")
      .run(seeded.reviewId);
    const before = c1bRawState(handle, seeded);
    const token = "d".repeat(64);
    const { dependencies, calls } = buildC1BBClaimDependencies(seeded, token, {
      load: (loaded) => c1bbProgramWith(loaded, { inScope: ["elsewhere.example"] }),
    });

    const error = expectC1BError(
      () =>
        new ActionLifecycle(handle, dependencies).claim({
          actionId: seeded.actionId,
          executionOwner: "c1bb-worker",
        }),
      "ACTION_SCOPE_DRIFT",
    );

    expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expectC1BBCommittedRepair({
      handle,
      seeded,
      before,
      status: "blocked",
      reason: "scope_blocked",
    });
    expectC1BBTokenAbsent(handle, seeded, token, error);
  });

  it("commits a policy block even when the linked active review row is missing", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bb-policy-block-missing");
    handle.exec("PRAGMA foreign_keys = OFF");
    handle.prepare("DELETE FROM action_reviews WHERE id = ?").run(seeded.reviewId);
    handle.exec("PRAGMA foreign_keys = ON");
    const before = c1bRawState(handle, seeded);
    expect(before.review).toBeUndefined();
    const token = "e".repeat(64);
    const { dependencies, calls } = buildC1BBClaimDependencies(seeded, token, {
      resolve: (resolved) => ({
        ...resolved,
        capabilityEnforcement: {
          ...resolved.capabilityEnforcement,
          blockedByDefault: true,
        },
      }),
    });

    const error = expectC1BError(
      () =>
        new ActionLifecycle(handle, dependencies).claim({
          actionId: seeded.actionId,
          executionOwner: "c1bb-worker",
        }),
      "ACTION_POLICY_DRIFT",
    );

    expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expectC1BBCommittedRepair({
      handle,
      seeded,
      before,
      status: "blocked",
      reason: "policy_blocked",
    });
    expectC1BBTokenAbsent(handle, seeded, token, error);
  });
});

const C1BB_DRIFT_CASES = [
  {
    kind: "scope",
    code: "ACTION_SCOPE_DRIFT",
    reason: "scope_drift",
    token: "1".repeat(64),
  },
  {
    kind: "policy",
    code: "ACTION_POLICY_DRIFT",
    reason: "policy_drift",
    token: "2".repeat(64),
  },
  {
    kind: "action",
    code: "ACTION_HASH_MISMATCH",
    reason: "action_hash_mismatch",
    token: "3".repeat(64),
  },
  {
    kind: "context",
    code: "ACTION_HASH_MISMATCH",
    reason: "context_hash_mismatch",
    token: "4".repeat(64),
  },
] as const;

describe("C1B-B claim: committed scope, policy, action, and context drift", () => {
  it.each(C1BB_DRIFT_CASES)(
    "commits the exact $kind drift invalidation before throwing $code",
    ({ kind, code, reason, token }) => {
      const handle = openDb();
      const seeded = seedC1AApprovedAction(handle, `c1bb-${kind}-drift`);
      const overrides: C1BBDependencyOverrides = {};
      if (kind === "scope") {
        overrides.load = (loaded) =>
          c1bbProgramWith(loaded, {
            inScope: [...loaded.config.in_scope, "unrelated.example"],
          });
      } else if (kind === "policy") {
        overrides.load = (loaded) => c1bbProgramWith(loaded, { rateLimit: "2rps" });
      } else if (kind === "action") {
        overrides.resolve = (resolved) => ({
          ...resolved,
          capabilityEnforcement: {
            ...resolved.capabilityEnforcement,
            mcpTools: ["c1bb.inert"],
          },
        });
      } else {
        const staleContextHash = hex64("c1bb-independent-context-drift");
        handle
          .prepare("UPDATE actions SET planned_context_hash = ? WHERE id = ?")
          .run(staleContextHash, seeded.actionId);
        handle
          .prepare("UPDATE action_reviews SET context_hash = ? WHERE id = ?")
          .run(staleContextHash, seeded.reviewId);
      }
      const before = c1bRawState(handle, seeded);
      const { dependencies, calls } = buildC1BBClaimDependencies(
        seeded,
        token,
        overrides,
      );

      const error = expectC1BError(
        () =>
          new ActionLifecycle(handle, dependencies).claim({
            actionId: seeded.actionId,
            executionOwner: "c1bb-worker",
          }),
        code,
      );

      expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
      expectC1BBCommittedRepair({
        handle,
        seeded,
        before,
        status: "pending",
        reason,
      });
      expectC1BBTokenAbsent(handle, seeded, token, error);
    },
  );
});

describe("C1B-B claim: source and action-CAS races", () => {
  it("maps an in-window source canonical mismatch to ACTION_CLAIM_RACE with no lifecycle writes", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bb-source-race");
    const before = c1bRawState(handle, seeded);
    const token = "5".repeat(64);
    const racedMetadata = JSON.stringify({ fixture: "c1bb-source-race", raced: true });
    let injectedAction: Record<string, unknown> | undefined;
    const { dependencies, calls } = buildC1BBClaimDependencies(seeded, token, {
      beforeToken: () => {
        handle
          .prepare("UPDATE actions SET metadata_json = ? WHERE id = ?")
          .run(racedMetadata, seeded.actionId);
        injectedAction = readActionRow(handle, seeded.actionId);
      },
    });

    const error = expectC1BError(
      () =>
        new ActionLifecycle(handle, dependencies).claim({
          actionId: seeded.actionId,
          executionOwner: "c1bb-worker",
        }),
      "ACTION_CLAIM_RACE",
    );

    expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expect(injectedAction).toEqual({ ...before.action, metadata_json: racedMetadata });
    expect(c1bRawState(handle, seeded)).toEqual({
      action: injectedAction,
      review: before.review,
      job: before.job,
      events: before.events,
    });
    expectC1BBTokenAbsent(handle, seeded, token, error);
  });

  it("maps a lost successful claim CAS to ACTION_CLAIM_RACE and rolls back without emitting the token", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bb-success-cas-loss");
    const before = c1bRawState(handle, seeded);
    const token = "6".repeat(64);
    const { dependencies, calls } = buildC1BBClaimDependencies(seeded, token);
    const cas = c1bbLoseActionCas(handle, "success");
    let error: BountyPilotError;
    try {
      error = expectC1BError(
        () =>
          new ActionLifecycle(handle, dependencies).claim({
            actionId: seeded.actionId,
            executionOwner: "c1bb-worker",
          }),
        "ACTION_CLAIM_RACE",
      );
    } finally {
      cas.restore();
    }

    expect(cas.hits()).toBe(1);
    expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expect(c1bRawState(handle, seeded)).toEqual(before);
    expectC1BBTokenAbsent(handle, seeded, token, error!);
  });

  it("rolls back a preceding expiry invalidation when the repair CAS loses", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bb-expiry-cas-loss", 60_000);
    const before = c1bRawState(handle, seeded);
    const token = "7".repeat(64);
    const { dependencies, calls } = buildC1BBClaimDependencies(seeded, token);
    const directPrepare = handle.prepare.bind(handle);
    let invalidationSeenBeforeCas: Record<string, unknown> | undefined;
    const cas = c1bbLoseActionCas(handle, "repair", () => {
      invalidationSeenBeforeCas = directPrepare(
        "SELECT invalidated_at, invalidation_reason FROM action_reviews WHERE id = ?",
      ).get(seeded.reviewId) as Record<string, unknown>;
    });
    let error: BountyPilotError;
    try {
      error = expectC1BError(
        () =>
          new ActionLifecycle(handle, dependencies).claim({
            actionId: seeded.actionId,
            executionOwner: "c1bb-worker",
          }),
        "ACTION_CLAIM_RACE",
      );
    } finally {
      cas.restore();
    }

    expect(cas.hits()).toBe(1);
    expect(invalidationSeenBeforeCas).toEqual({
      invalidated_at: C1A_CLAIMED_AT,
      invalidation_reason: "review_expired",
    });
    expect(calls).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expect(c1bRawState(handle, seeded)).toEqual(before);
    expectC1BBTokenAbsent(handle, seeded, token, error!);
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C1B-C - expiry-repair fault atomicity
// ===========================================================================

function c1bcRawRows(
  handle: BountyDatabase,
  seeded: ReturnType<typeof seedC1AApprovedAction>,
): {
  action: Record<string, unknown>;
  review: Record<string, unknown> | undefined;
  job: Record<string, unknown>;
  events: Array<Record<string, unknown>>;
} {
  return {
    action: readActionRow(handle, seeded.actionId),
    review: handle
      .prepare("SELECT * FROM action_reviews WHERE id = ?")
      .get(seeded.reviewId) as Record<string, unknown> | undefined,
    job: readJobRow(handle, seeded.jobId),
    events: handle
      .prepare("SELECT * FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
      .all(seeded.jobId) as Array<Record<string, unknown>>,
  };
}

function c1bcFaultingPrepareProxy(
  handle: BountyDatabase,
  matches: (sql: string) => boolean,
  fault: Error,
  onHit: () => void,
): BountyDatabase {
  return new Proxy(handle, {
    get(target, property): unknown {
      if (property === "prepare") {
        return (sql: string) => {
          if (matches(sql)) {
            onHit();
            throw fault;
          }
          return target.prepare(sql);
        };
      }
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === "function"
        ? (value as (...args: unknown[]) => unknown).bind(target)
        : value;
    },
  }) as BountyDatabase;
}

describe("C1B-C claim: expiry-repair faults are atomic and preserve the primary error", () => {
  it("propagates a real workflow-event sequence conflict instead of ACTION_REVIEW_EXPIRED and rolls back every repair row", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bc-event-conflict", 60_000);
    const before = c1bcRawRows(handle, seeded);
    const token = "8".repeat(64);
    let insertAttempts = 0;
    handle.function("c1bc_event_insert_counter", () => {
      insertAttempts += 1;
      return insertAttempts;
    });
    handle.exec(`
      CREATE TEMP TRIGGER c1bc_force_event_sequence_conflict
      BEFORE INSERT ON workflow_events
      FOR EACH ROW
      WHEN NEW.phase = 'action-review'
      BEGIN
        SELECT c1bc_event_insert_counter();
        INSERT INTO workflow_events
          (id, job_id, sequence, phase, status, message, metadata_json, created_at)
        VALUES
          ('c1bc-sentinel-' || NEW.id, NEW.job_id, NEW.sequence,
           'c1bc-sentinel', 'completed', '', NULL, NEW.created_at);
      END;
    `);

    const error = captureC1AError(() =>
      new ActionLifecycle(handle, {
        ...seeded.authority,
        now: () => new Date(C1A_CLAIMED_AT),
        generateExecutionToken: () => token,
      }).claim({ actionId: seeded.actionId, executionOwner: "c1bc-worker" }),
    );

    expect(error.code).toBe("WORKFLOW_EVENT_SEQUENCE_CONFLICT");
    expect(error.code).not.toBe("ACTION_REVIEW_EXPIRED");
    expect(insertAttempts).toBe(1);
    const after = c1bcRawRows(handle, seeded);
    expect(after).toEqual(before);
    expect(JSON.stringify(after)).not.toContain(token);
    expect(String(error)).not.toContain(token);
  });

  it.each([
    {
      stage: "SELECT",
      matches: (sql: string) => /\bFROM\s+jobs\s+WHERE\s+id\s*=\s*\?/i.test(sql),
    },
    {
      stage: "UPDATE",
      matches: (sql: string) =>
        /UPDATE\s+jobs\s+SET\s+status\s*=\s*\?\s*,\s*pause_reason\s*=\s*\?\s*,\s*status_detail\s*=\s*\?/i.test(
          sql,
        ),
    },
  ])(
    "propagates the exact JobManager $stage database fault and rolls back review, action, event, and job writes",
    ({ stage, matches }) => {
      const handle = openDb();
      const seeded = seedC1AApprovedAction(handle, `c1bc-job-${stage.toLowerCase()}`, 60_000);
      const before = c1bcRawRows(handle, seeded);
      const token = stage === "SELECT" ? "9".repeat(64) : "a".repeat(64);
      const fault = new Error(`C1BC_JOB_${stage}_DB_FAULT`);
      let hits = 0;
      const faultingDb = c1bcFaultingPrepareProxy(
        handle,
        matches,
        fault,
        () => {
          hits += 1;
        },
      );
      let captured: unknown;
      try {
        new ActionLifecycle(faultingDb, {
          ...seeded.authority,
          now: () => new Date(C1A_CLAIMED_AT),
          generateExecutionToken: () => token,
        }).claim({ actionId: seeded.actionId, executionOwner: "c1bc-worker" });
      } catch (error) {
        captured = error;
      }

      expect(captured).toBe(fault);
      expect(hits).toBe(1);
      const after = c1bcRawRows(handle, seeded);
      expect(after).toEqual(before);
      expect(JSON.stringify(after)).not.toContain(token);
      expect(String(captured)).not.toContain(token);
    },
  );

  it("lets an exact COMMIT sentinel win over ACTION_REVIEW_EXPIRED, forwards ROLLBACK, and leaves no partial rows or token", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bc-commit", 60_000);
    const before = c1bcRawRows(handle, seeded);
    const token = "b".repeat(64);
    const commitSentinel = new Error("C1BC_COMMIT_SENTINEL");
    const seen: string[] = [];
    const forwarded: string[] = [];
    const commitFaultDb = new Proxy(handle, {
      get(target, property): unknown {
        if (property === "exec") {
          return (sql: string): void => {
            const command = sql.trim().toUpperCase();
            seen.push(command);
            if (command === "COMMIT") throw commitSentinel;
            forwarded.push(command);
            target.exec(sql);
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    }) as BountyDatabase;
    let captured: unknown;
    try {
      new ActionLifecycle(commitFaultDb, {
        ...seeded.authority,
        now: () => new Date(C1A_CLAIMED_AT),
        generateExecutionToken: () => token,
      }).claim({ actionId: seeded.actionId, executionOwner: "c1bc-worker" });
    } catch (error) {
      captured = error;
    }

    expect(captured).toBe(commitSentinel);
    expect(seen).toEqual(["BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"]);
    expect(forwarded).toEqual(["BEGIN IMMEDIATE", "ROLLBACK"]);
    const after = c1bcRawRows(handle, seeded);
    expect(after).toEqual(before);
    expect(JSON.stringify(after)).not.toContain(token);
    expect(String(captured)).not.toContain(token);
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C1B-D - true two-handle claim race
// ===========================================================================

describe("C1B-D claim: two independent handles observe approved then race", () => {
  const C1BD_TEST_TIMEOUT_MS = 30_000;
  const C1BD_WORKER_BARRIER_TIMEOUT_MS = 15_000;
  const C1BD_OWNER_A = "c1bd-owner-a";
  const C1BD_OWNER_B = "c1bd-owner-b";
  const C1BD_TOKEN_A = "d".repeat(64);
  const C1BD_TOKEN_B = "e".repeat(64);

  type C1BDCounts = {
    load: number;
    resolve: number;
    now: number;
    token: number;
  };

  type C1BDWorkerSuccess = {
    kind: "success";
    role: "a" | "b";
    owner: string;
    token: string;
    executionToken: string;
    actionStatus: string;
    actionOwner: string | null;
    actionJson: string;
    counts: C1BDCounts;
  };

  type C1BDWorkerError = {
    kind: "error";
    role: "a" | "b";
    owner: string;
    token: string;
    code: string | null;
    name: string;
    message: string;
    errorSerialization: string;
    errorString: string;
    counts: C1BDCounts;
  };

  type C1BDWorkerOutcome = C1BDWorkerSuccess | C1BDWorkerError;

  function launchC1BDWorker(input: {
    role: "a" | "b";
    actionId: string;
    jobId: string;
    dbPath: string;
    loaded: LoadedProgram;
    material: ResolvedBindingMaterial;
    barrier: SharedArrayBuffer;
    barrierArrivalOffset: number;
    barrierReleaseOffset: number;
    countOffsets: { load: number; resolve: number; now: number; token: number };
    owner: string;
    token: string;
  }): { worker: Worker; outcome: Promise<C1BDWorkerOutcome> } {
    // Keep this worker source CommonJS and load the TypeScript module through
    // tsx, matching the proven A7/B3C worker harnesses in this file and the
    // approval-service test. The resolver barrier is reached only after the
    // lifecycle has loaded and materialized the approved action authority.
    const source = `
      const { parentPort, workerData } = require('node:worker_threads');
      const { DatabaseSync } = require('node:sqlite');
      const { tsImport } = require('tsx/esm/api');
      const i32 = new Int32Array(workerData.barrier);
      const ARRIVAL = workerData.barrierArrivalOffset;
      const RELEASE = workerData.barrierReleaseOffset;
      const WAIT_MS = workerData.barrierTimeoutMs;
      const COUNT_OFFSETS = workerData.countOffsets;
      const counts = { load: 0, resolve: 0, now: 0, token: 0 };

      function waitForPeerAfterMaterialization() {
        const arrived = Atomics.add(i32, ARRIVAL, 1) + 1;
        if (arrived === 2) {
          Atomics.store(i32, RELEASE, 1);
          Atomics.notify(i32, RELEASE, Infinity);
          return;
        }
        const deadline = Date.now() + WAIT_MS;
        while (Atomics.load(i32, RELEASE) !== 1) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) throw new Error('C1BD authority barrier timeout');
          const current = Atomics.load(i32, RELEASE);
          Atomics.wait(i32, RELEASE, current, Math.min(50, remaining));
        }
      }

      let db = null;
      let payload;
      (async () => {
        try {
          const { ActionLifecycle } = await tsImport(workerData.moduleUrl, workerData.parentUrl);
          db = new DatabaseSync(workerData.dbPath);
          db.exec('PRAGMA busy_timeout = 10000;');
          db.exec('PRAGMA foreign_keys = ON;');
          const lifecycle = new ActionLifecycle(db, {
            loadCurrentProgram: () => {
              counts.load += 1;
              Atomics.add(i32, COUNT_OFFSETS.load, 1);
              return workerData.loaded;
            },
            resolveBindingMaterial: () => {
              counts.resolve += 1;
              Atomics.add(i32, COUNT_OFFSETS.resolve, 1);
              // This is the synchronization point: both workers have
              // completed approved-row preflight and authority materialization
              // before either can enter the claim transaction.
              waitForPeerAfterMaterialization();
              return workerData.material;
            },
            now: () => {
              counts.now += 1;
              Atomics.add(i32, COUNT_OFFSETS.now, 1);
              return new Date(workerData.nowIso);
            },
            generateExecutionToken: () => {
              counts.token += 1;
              Atomics.add(i32, COUNT_OFFSETS.token, 1);
              return workerData.token;
            },
          });

          const result = lifecycle.claim({
            actionId: workerData.actionId,
            executionOwner: workerData.owner,
          });
          payload = {
            kind: 'success',
            role: workerData.role,
            owner: workerData.owner,
            token: workerData.token,
            executionToken: result.executionToken,
            actionStatus: result.action.status,
            actionOwner: result.action.executionOwner || null,
            actionJson: JSON.stringify(result.action),
            counts,
          };
        } catch (err) {
          const isObject = err !== null && typeof err === 'object';
          const code = isObject && typeof err.code === 'string' ? err.code : null;
          const name = isObject && typeof err.name === 'string' ? err.name : typeof err;
          const message = isObject && typeof err.message === 'string' ? err.message : String(err);
          let errorSerialization;
          try {
            errorSerialization = JSON.stringify(err);
          } catch (_) {
            errorSerialization = undefined;
          }
          if (typeof errorSerialization !== 'string') errorSerialization = String(err);
          payload = {
            kind: 'error',
            role: workerData.role,
            owner: workerData.owner,
            token: workerData.token,
            code,
            name,
            message,
            // Preserve the production error's own JSON and string forms so
            // the parent can prove the loser bearer token is absent from both.
            errorSerialization,
            errorString: String(err),
            counts,
          };
        } finally {
          if (db) {
            try { db.close(); } catch (_) { /* best effort */ }
          }
        }
        parentPort.postMessage(payload);
      })();
    `;

    const worker = new Worker(source, {
      eval: true,
      workerData: {
        moduleUrl: new URL("../src/core/actions/action-lifecycle.ts", import.meta.url).href,
        parentUrl: import.meta.url,
        dbPath: input.dbPath,
        actionId: input.actionId,
        jobId: input.jobId,
        role: input.role,
        loaded: input.loaded,
        material: input.material,
        barrier: input.barrier,
        barrierArrivalOffset: input.barrierArrivalOffset,
        barrierReleaseOffset: input.barrierReleaseOffset,
        barrierTimeoutMs: C1BD_WORKER_BARRIER_TIMEOUT_MS,
        countOffsets: input.countOffsets,
        owner: input.owner,
        token: input.token,
        nowIso: C1A_CLAIMED_AT,
      },
    });

    const outcome = new Promise<C1BDWorkerOutcome>((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error(`C1BD ${input.role} worker timed out`));
      }, C1BD_TEST_TIMEOUT_MS - 5_000);
      worker.once("message", (message: C1BDWorkerOutcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve(message);
      });
      worker.once("error", (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        reject(error);
      });
      worker.once("exit", (code) => {
        if (settled || code === 0) return;
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`C1BD ${input.role} worker exited with code ${code}`));
      });
    });
    return { worker, outcome };
  }

  it("commits exactly one winner while the other handle reports ACTION_CLAIM_RACE", async () => {
    // Seed one approved action and its active review on the parent handle.
    // The default 15-minute approval TTL remains valid at C1A_CLAIMED_AT.
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "c1bd-two-handle-race");
    const seededAction = new ActionQueue(handle).get(seeded.actionId);
    const seededJob = new JobManager(handle).get(seeded.jobId);
    if (!seededAction || !seededJob || !seededAction.jobId) {
      throw new Error("C1BD fixture failed to seed action/job");
    }
    const source: ActionMaterialSource = {
      action: {
        id: seededAction.id,
        jobId: seededAction.jobId,
        adapter: seededAction.adapter,
        actionType: seededAction.actionType,
        target: seededAction.target ?? null,
        riskLevel: seededAction.riskLevel,
        requiresApproval: seededAction.requiresApproval,
        requiredForCompletion: seededAction.requiredForCompletion,
        metadata: seededAction.metadata ?? {},
      },
      job: {
        id: seededJob.id,
        type: seededJob.type,
        target: seededJob.target ?? null,
        mode: seededJob.mode,
      },
    };
    const loaded = seeded.authority.loadCurrentProgram();
    const material = seeded.authority.resolveBindingMaterial({ source, program: loaded });

    // No parent handle may remain open while the workers race. This also
    // makes it explicit that each worker owns an independent DatabaseSync
    // connection to the same file.
    handle.close();
    db = null;

    // Shared cells: 0/1 are the post-materialization barrier; 2..9 are
    // per-worker dependency counters (load, resolve, now, token).
    const barrier = new SharedArrayBuffer(10 * Int32Array.BYTES_PER_ELEMENT);
    const i32 = new Int32Array(barrier);
    const first = launchC1BDWorker({
      role: "a",
      actionId: seeded.actionId,
      jobId: seeded.jobId,
      dbPath: dbFile,
      loaded,
      material,
      barrier,
      barrierArrivalOffset: 0,
      barrierReleaseOffset: 1,
      countOffsets: { load: 2, resolve: 3, now: 4, token: 5 },
      owner: C1BD_OWNER_A,
      token: C1BD_TOKEN_A,
    });
    const second = launchC1BDWorker({
      role: "b",
      actionId: seeded.actionId,
      jobId: seeded.jobId,
      dbPath: dbFile,
      loaded,
      material,
      barrier,
      barrierArrivalOffset: 0,
      barrierReleaseOffset: 1,
      countOffsets: { load: 6, resolve: 7, now: 8, token: 9 },
      owner: C1BD_OWNER_B,
      token: C1BD_TOKEN_B,
    });

    let outcomes: C1BDWorkerOutcome[];
    try {
      outcomes = await Promise.all([first.outcome, second.outcome]);
    } finally {
      // Workers close their handles before posting the outcome; terminate is
      // still awaited so no native connection survives into verification or
      // the per-test cleanup hook.
      await Promise.allSettled([first.worker.terminate(), second.worker.terminate()]);
    }

    expect(Atomics.load(i32, 0), "both workers must pass approved materialization").toBe(2);
    expect(Atomics.load(i32, 1), "the post-materialization barrier must release").toBe(1);
    expect(outcomes).toHaveLength(2);
    const winners = outcomes.filter(
      (outcome): outcome is C1BDWorkerSuccess => outcome.kind === "success",
    );
    const losers = outcomes.filter(
      (outcome): outcome is C1BDWorkerError => outcome.kind === "error",
    );
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    const winner = winners[0]!;
    const loser = losers[0]!;
    expect(loser.code).toBe("ACTION_CLAIM_RACE");
    expect(loser.code).not.toBe("ACTION_LEASE_HELD");
    expect(winner.owner).not.toBe(loser.owner);
    expect(winner.token).not.toBe(loser.token);
    expect(winner.executionToken).toBe(winner.token);
    expect(winner.actionStatus).toBe("running");
    expect(winner.actionOwner).toBe(winner.owner);
    expect(JSON.parse(winner.actionJson)).toMatchObject({
      status: "running",
      executionOwner: winner.owner,
    });
    expect(winner.actionJson).not.toContain(winner.token);
    expect(winner.actionJson).not.toContain(loser.token);

    // Each independent caller gets exactly one authority load, resolver,
    // clock, and token. The offset assertions are independent of the wire
    // outcome and prove no retry path was taken.
    expect(winner.counts).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expect(loser.counts).toEqual({ load: 1, resolve: 1, now: 1, token: 1 });
    expect(Atomics.load(i32, 2)).toBe(1);
    expect(Atomics.load(i32, 3)).toBe(1);
    expect(Atomics.load(i32, 4)).toBe(1);
    expect(Atomics.load(i32, 5)).toBe(1);
    expect(Atomics.load(i32, 6)).toBe(1);
    expect(Atomics.load(i32, 7)).toBe(1);
    expect(Atomics.load(i32, 8)).toBe(1);
    expect(Atomics.load(i32, 9)).toBe(1);

    const verify = openBountyDatabase(dbFile);
    try {
      const rawAction = readActionRow(verify, seeded.actionId);
      expect(rawAction).toMatchObject({
        status: "running",
        execution_token: winner.token,
        execution_owner: winner.owner,
        active_review_id: seeded.reviewId,
      });
      expect(rawAction.execution_token).not.toBe(loser.token);

      // Exactly one running event was emitted by the winner. Approval events
      // may also exist, so the running-status filter is intentional.
      const runningRawEvents = verify
        .prepare("SELECT * FROM workflow_events WHERE job_id = ? AND status = 'running'")
        .all(seeded.jobId) as Array<Record<string, unknown>>;
      expect(runningRawEvents).toHaveLength(1);
      expect(runningRawEvents[0]).toMatchObject({
        phase: "action-execution",
        status: "running",
      });
      const publicEvents = new WorkflowEventStore(verify).list(seeded.jobId);
      const publicRunningEvents = publicEvents.filter((event) => event.status === "running");
      expect(publicRunningEvents).toHaveLength(1);
      expect(publicRunningEvents[0]).toMatchObject({
        phase: "action-execution",
        status: "running",
        metadata: {
          actionId: seeded.actionId,
          reviewId: seeded.reviewId,
          reasonCode: "execution_claimed",
        },
      });
      expect(Object.keys(publicRunningEvents[0]?.metadata ?? {}).sort()).toEqual(
        ["actionId", "contextHash", "reasonCode", "reviewId"].sort(),
      );

      const rawJob = readJobRow(verify, seeded.jobId);
      expect(rawJob.status).toBe("running");
      expect(rawJob.pause_reason).toBeNull();
      const publicJob = new JobManager(verify).get(seeded.jobId);
      expect(publicJob?.status).toBe("running");
      expect(publicJob?.pauseReason).toBeNull();

      // The losing transaction rolled back completely: the original review
      // remains active, approved, uninvalidated, and hash-bound to the action.
      const rawReview = verify
        .prepare("SELECT * FROM action_reviews WHERE id = ?")
        .get(seeded.reviewId) as Record<string, unknown>;
      expect(rawReview).toMatchObject({
        id: seeded.reviewId,
        action_id: seeded.actionId,
        job_id: seeded.jobId,
        decision: "approved",
        reviewer_id: "researcher-c1bd-two-handle-race",
        source: "human",
        reviewed_at: C1A_REVIEWED_AT,
        expires_at: EXPIRES_AT,
        invalidated_at: null,
        invalidation_reason: null,
      });
      expect(rawReview.created_at).toBe(C1A_REVIEWED_AT);
      expect(Date.parse(String(rawReview.expires_at))).toBeGreaterThan(
        Date.parse(String(rawReview.reviewed_at)),
      );
      expect(rawReview.scope_hash).toBe(rawAction.planned_scope_hash);
      expect(rawReview.policy_hash).toBe(rawAction.planned_policy_hash);
      expect(rawReview.action_hash).toBe(rawAction.planned_action_hash);
      expect(rawReview.context_hash).toBe(rawAction.planned_context_hash);
      const publicReviews = new ActionReviewStore(verify).listForAction(seeded.actionId);
      expect(publicReviews).toHaveLength(1);
      expect(publicReviews[0]).toMatchObject({
        id: seeded.reviewId,
        actionId: seeded.actionId,
        jobId: seeded.jobId,
        decision: "approved",
        reviewerId: "researcher-c1bd-two-handle-race",
        source: "human",
        reviewedAt: C1A_REVIEWED_AT,
        expiresAt: EXPIRES_AT,
      });
      expect(publicReviews[0]?.invalidatedAt).toBeUndefined();
      expect(publicReviews[0]?.invalidationReason).toBeUndefined();

      // The loser bearer token is absent from every public projection and
      // from the serialized fixed error. (The raw action intentionally holds
      // the winner token, so it is not included in this token-free set.)
      const publicValues: unknown[] = [
        rawAction,
        rawReview,
        runningRawEvents,
        rawJob,
        new ActionQueue(verify).get(seeded.actionId),
        publicReviews,
        publicEvents,
        publicJob,
      ];
      for (const value of publicValues) {
        expect(JSON.stringify(value)).not.toContain(loser.token);
      }
      expect(loser.message).not.toContain(loser.token);
      expect(loser.errorSerialization).not.toContain(loser.token);
      expect(loser.errorString).not.toContain(loser.token);
    } finally {
      try { verify.close(); } catch { /* best effort */ }
    }
  }, C1BD_TEST_TIMEOUT_MS);
});

// ===========================================================================
// P0.2 Packet 2 Slice C2-A - dispatch mark and finalize RED contract
// ===========================================================================
//
// These tests deliberately exercise the public lifecycle methods through a
// real C1A claim.  The claim is the only fixture path allowed to create a
// bearer token; C2-A then proves that the token is used only as a bound
// capability and is never selected into JavaScript/public records.

const C2A_OWNER = "c2a-worker";
const C2A_TOKEN = "c".repeat(64);
const C2A_WRONG_TOKEN = "d".repeat(64);
const C2A_MARKED_AT = "2099-01-01T00:01:05.000Z";
const C2A_FINALIZED_AT = "2099-01-01T00:01:10.000Z";
const C2A_ERROR_HEX = "e".repeat(64);
const C2A_FIXED_ERROR_CODE = "HTTP_TIMEOUT";

type C2ALifecycleMethod = "markDispatch" | "finalize";

interface C2ASqlProbe {
  prepare: number;
  exec: number;
  sql: string[];
}

/**
 * Count SQL issued through the lifecycle handle.  Fixture setup is done on
 * the original handle first, so a zero count is a meaningful caller-boundary
 * assertion rather than a count of setup statements.
 */
function c2aCountingDb(handle: BountyDatabase, probe: C2ASqlProbe): BountyDatabase {
  return new Proxy(handle, {
    get(target, property): unknown {
      if (property === "prepare") {
        return (sql: string) => {
          probe.prepare += 1;
          probe.sql.push(sql);
          return target.prepare(sql);
        };
      }
      if (property === "exec") {
        return (sql: string) => {
          probe.exec += 1;
          probe.sql.push(sql);
          return target.exec(sql);
        };
      }
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === "function"
        ? (value as (...args: unknown[]) => unknown).bind(target)
        : value;
    },
  }) as BountyDatabase;
}

function c2aClaimedFixture(
  handle: BountyDatabase,
  suffix: string,
  options: { leaseMs?: number; owner?: string; token?: string } = {},
): {
  seeded: ReturnType<typeof seedC1AApprovedAction>;
  claimed: ClaimedActionContext;
  owner: string;
  token: string;
} {
  const seeded = seedC1AApprovedAction(handle, suffix);
  const owner = options.owner ?? C2A_OWNER;
  const token = options.token ?? C2A_TOKEN;
  const lifecycle = new ActionLifecycle(handle, {
    ...seeded.authority,
    now: () => new Date(C1A_CLAIMED_AT),
    generateExecutionToken: () => token,
  });
  const claimed = lifecycle.claim({
    actionId: seeded.actionId,
    executionOwner: owner,
    leaseMs: options.leaseMs ?? 120_000,
  });
  expect(claimed.executionToken).toBe(token);
  expect(claimed.action.executionOwner).toBe(owner);
  return { seeded, claimed, owner, token };
}

function c2aLifecycleFor(
  handle: BountyDatabase,
  fixture: ReturnType<typeof c2aClaimedFixture>,
  now: () => Date,
): ActionLifecycle {
  return new ActionLifecycle(handle, {
    ...fixture.seeded.authority,
    now,
    // markDispatch/finalize must never generate a new capability.
    generateExecutionToken: () => {
      throw new Error("C2A token generation must not run");
    },
  });
}

function c2aRawState(
  handle: BountyDatabase,
  fixture: ReturnType<typeof c2aClaimedFixture>,
): {
  action: Record<string, unknown>;
  review: Record<string, unknown>;
  job: Record<string, unknown>;
  events: Array<Record<string, unknown>>;
} {
  return {
    action: readActionRow(handle, fixture.seeded.actionId),
    review: handle
      .prepare("SELECT * FROM action_reviews WHERE id = ?")
      .get(fixture.seeded.reviewId) as Record<string, unknown>,
    job: readJobRow(handle, fixture.seeded.jobId),
    events: handle
      .prepare("SELECT * FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
      .all(fixture.seeded.jobId) as Array<Record<string, unknown>>,
  };
}

function c2aAssertTokenFreeSelects(sql: readonly string[]): void {
  for (const statement of sql) {
    if (!/^\s*SELECT\b/i.test(statement)) continue;
    const projection = statement.match(/^\s*SELECT([\s\S]*?)\bFROM\b/i)?.[1] ?? "";
    // A lifecycle probe may compute `(execution_token = ?) AS ...` or
    // `(execution_token IS NULL) AS ...`; it may not project the bearer
    // value itself.  This catches both raw and aliased token projections.
    expect(projection).not.toMatch(
      /(?:^|[,\s(])(?:[a-z_][\w]*\.)?execution_token\s*(?:,|\)|AS\b|$)/i,
    );
  }
}

function c2aErrorCode(run: () => unknown): BountyPilotError {
  const error = captureC1AError(run);
  expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
  return error;
}

const C2A_MARK_INVALID_CASES: Array<{ name: string; input: unknown; code: string }> = [
  { name: "null envelope", input: null, code: "ACTION_LIFECYCLE_INVALID" },
  { name: "array envelope", input: [], code: "ACTION_LIFECYCLE_INVALID" },
  {
    name: "hostile proxy envelope",
    input: new Proxy(
      { actionId: "never-read", executionToken: C2A_TOKEN, executionOwner: C2A_OWNER },
      {
        get: () => { throw new Error("C2A_PROXY_GET"); },
        getPrototypeOf: () => { throw new Error("C2A_PROXY_PROTO"); },
        ownKeys: () => { throw new Error("C2A_PROXY_KEYS"); },
        getOwnPropertyDescriptor: () => { throw new Error("C2A_PROXY_DESCRIPTOR"); },
      },
    ),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "accessor envelope",
    input: (() => {
      const value: Record<string, unknown> = {
        actionId: "never-read",
        executionToken: C2A_TOKEN,
        executionOwner: C2A_OWNER,
      };
      Object.defineProperty(value, "executionToken", {
        enumerable: true,
        get: () => { throw new Error("C2A_ACCESSOR_GET"); },
      });
      return value;
    })(),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "symbol field",
    input: (() => {
      const value: Record<string | symbol, unknown> = {
        actionId: "never-read",
        executionToken: C2A_TOKEN,
        executionOwner: C2A_OWNER,
      };
      value[Symbol("execution-token")] = C2A_TOKEN;
      return value;
    })(),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "unknown field",
    input: {
      actionId: "never-read",
      executionToken: C2A_TOKEN,
      executionOwner: C2A_OWNER,
      extra: true,
    },
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "malformed action id",
    input: { actionId: " padded", executionToken: C2A_TOKEN, executionOwner: C2A_OWNER },
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "malformed token",
    input: { actionId: "never-read", executionToken: "A".repeat(64), executionOwner: C2A_OWNER },
    code: "ACTION_TOKEN_INVALID",
  },
  {
    name: "malformed owner",
    input: { actionId: "never-read", executionToken: C2A_TOKEN, executionOwner: "bad\nowner" },
    code: "ACTION_OWNER_INVALID",
  },
];

describe("C2-A dispatch/finalize: exact caller boundary and clock isolation", () => {
  it.each(C2A_MARK_INVALID_CASES)(
    "markDispatch rejects $name before SQL, dependencies, or effects",
    ({ input, code }) => {
      const handle = openDb();
      const fixture = c2aClaimedFixture(handle, `boundary-mark-${code.toLowerCase()}`);
      const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
      const counted = c2aCountingDb(handle, probe);
      let dependencyCalls = 0;
      const lifecycle = new ActionLifecycle(counted, {
        ...fixture.seeded.authority,
        loadCurrentProgram: () => {
          dependencyCalls += 1;
          throw new Error("C2A_EFFECT_OR_AUTHORITY");
        },
        resolveBindingMaterial: () => {
          dependencyCalls += 1;
          throw new Error("C2A_EFFECT_OR_AUTHORITY");
        },
        now: () => {
          dependencyCalls += 1;
          throw new Error("C2A_CLOCK_MUST_NOT_RUN");
        },
        generateExecutionToken: () => {
          dependencyCalls += 1;
          throw new Error("C2A_TOKEN_MUST_NOT_RUN");
        },
      });
      const error = c2aErrorCode(() =>
        lifecycle.markDispatch(input as never),
      );
      expect(error.code).toBe(code);
      expect(probe.prepare).toBe(0);
      expect(probe.exec).toBe(0);
      expect(dependencyCalls).toBe(0);
    },
  );

  it.each([
    {
      name: "null outcome",
      outcome: null,
      code: "ACTION_OUTCOME_INVALID",
    },
    {
      name: "array outcome",
      outcome: [],
      code: "ACTION_OUTCOME_INVALID",
    },
    {
      name: "hostile proxy outcome",
      outcome: new Proxy(
        { kind: "success" },
        {
          get: () => { throw new Error("C2A_OUTCOME_PROXY_GET"); },
          ownKeys: () => { throw new Error("C2A_OUTCOME_PROXY_KEYS"); },
          getPrototypeOf: () => { throw new Error("C2A_OUTCOME_PROXY_PROTO"); },
          getOwnPropertyDescriptor: () => { throw new Error("C2A_OUTCOME_PROXY_DESCRIPTOR"); },
        },
      ),
      code: "ACTION_OUTCOME_INVALID",
    },
    {
      name: "accessor outcome",
      outcome: (() => {
        const value: Record<string, unknown> = { kind: "success" };
        Object.defineProperty(value, "kind", {
          enumerable: true,
          get: () => { throw new Error("C2A_OUTCOME_ACCESSOR_GET"); },
        });
        return value;
      })(),
      code: "ACTION_OUTCOME_INVALID",
    },
    {
      name: "unknown outcome tag",
      outcome: { kind: "transport_unknown" },
      code: "ACTION_OUTCOME_INVALID",
    },
    {
      name: "unknown outcome field",
      outcome: { kind: "success", extra: true },
      code: "ACTION_OUTCOME_INVALID",
    },
    {
      name: "malformed outcome code",
      outcome: { kind: "not_dispatched", errorCode: "bad code", errorMessage: "safe" },
      code: "ACTION_OUTCOME_INVALID",
    },
    {
      name: "malformed outcome message",
      outcome: { kind: "not_dispatched", errorCode: C2A_FIXED_ERROR_CODE, errorMessage: 7 },
      code: "ACTION_OUTCOME_INVALID",
    },
  ])(
    "finalize rejects $name before SQL, dependencies, or effects",
    ({ outcome, code }, index) => {
      const handle = openDb();
      const fixture = c2aClaimedFixture(handle, `boundary-finalize-${index}`);
      const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
      const counted = c2aCountingDb(handle, probe);
      let dependencyCalls = 0;
      const lifecycle = new ActionLifecycle(counted, {
        ...fixture.seeded.authority,
        loadCurrentProgram: () => {
          dependencyCalls += 1;
          throw new Error("C2A_EFFECT_OR_AUTHORITY");
        },
        resolveBindingMaterial: () => {
          dependencyCalls += 1;
          throw new Error("C2A_EFFECT_OR_AUTHORITY");
        },
        now: () => {
          dependencyCalls += 1;
          throw new Error("C2A_CLOCK_MUST_NOT_RUN");
        },
        generateExecutionToken: () => {
          dependencyCalls += 1;
          throw new Error("C2A_TOKEN_MUST_NOT_RUN");
        },
      });
      const error = c2aErrorCode(() =>
        lifecycle.finalize({
          actionId: fixture.seeded.actionId,
          executionToken: fixture.token,
          executionOwner: fixture.owner,
          outcome: outcome as never,
        }),
      );
      expect(error.code).toBe(code);
      expect(probe.prepare).toBe(0);
      expect(probe.exec).toBe(0);
      expect(dependencyCalls).toBe(0);
    },
  );

  it.each([
    { name: "mark clock throws", method: "mark" as const, now: () => { throw new Error("C2A_PRIVATE_CLOCK"); } },
    { name: "mark clock is invalid", method: "mark" as const, now: () => new Date(Number.NaN) },
    { name: "finalize clock throws", method: "finalize" as const, now: () => { throw new Error("C2A_PRIVATE_CLOCK"); } },
    { name: "finalize clock is invalid", method: "finalize" as const, now: () => new Date(Number.NaN) },
  ])("$name maps to ACTION_APPROVAL_CONTEXT_UNAVAILABLE with no writes", ({ method, now }) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `clock-${method}`);
    const before = c2aRawState(handle, fixture);
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    let nowCalls = 0;
    const lifecycle = c2aLifecycleFor(counted, fixture, () => {
      nowCalls += 1;
      return now();
    });
    const error = c2aErrorCode(() => {
      if (method === "mark") {
        return lifecycle.markDispatch({
          actionId: fixture.seeded.actionId,
          executionToken: fixture.token,
          executionOwner: fixture.owner,
        });
      }
      return lifecycle.finalize({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
        outcome: { kind: "success" },
      });
    });
    expect(error.code).toBe("ACTION_APPROVAL_CONTEXT_UNAVAILABLE");
    expect(error.message).not.toContain("C2A_PRIVATE");
    expect(nowCalls).toBe(1);
    expect(probe.prepare).toBe(0);
    expect(probe.exec).toBe(0);
    expect(c2aRawState(handle, fixture)).toEqual(before);
  });

  it("markDispatch validates a running lease/review once, writes only the marker and updated_at, and returns the canonical timestamp", () => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, "mark-happy");
    const before = c2aRawState(handle, fixture);
    const beforeJob = { ...before.job };
    const beforeEventCount = before.events.length;
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    let nowCalls = 0;
    const lifecycle = c2aLifecycleFor(counted, fixture, () => {
      nowCalls += 1;
      return new Date(C2A_MARKED_AT);
    });
    const result = lifecycle.markDispatch({
      actionId: fixture.seeded.actionId,
      executionToken: fixture.token,
      executionOwner: fixture.owner,
    });
    expect(result).toEqual({ dispatchStartedAt: C2A_MARKED_AT });
    expect(nowCalls).toBe(1);
    c2aAssertTokenFreeSelects(probe.sql);
    expect(probe.sql.some((sql) => /execution_token\s*=\s*\?/i.test(sql))).toBe(true);

    const after = readActionRow(handle, fixture.seeded.actionId);
    const changed = Object.keys(after).filter((key) => after[key] !== before.action[key]);
    expect(changed.sort()).toEqual(["dispatch_started_at", "updated_at"].sort());
    expect(after.dispatch_started_at).toBe(C2A_MARKED_AT);
    expect(after.updated_at).toBe(C2A_MARKED_AT);
    expect(after.execution_token).toBe(fixture.token);
    expect(after.execution_owner).toBe(fixture.owner);
    expect(after.finished_at).toBeNull();
    expect(after.outcome_certainty).toBeNull();
    expect(after.last_error_code).toBeNull();
    expect(after.last_error_message).toBeNull();
    expect(new WorkflowEventStore(handle).count(fixture.seeded.jobId)).toBe(beforeEventCount);
    expect(readJobRow(handle, fixture.seeded.jobId)).toEqual(beforeJob);
  });

  it("a second mark is ACTION_DISPATCH_ALREADY_MARKED before expired lease/review checks and performs zero writes", () => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, "mark-double");
    const first = c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT));
    expect(first.markDispatch({
      actionId: fixture.seeded.actionId,
      executionToken: fixture.token,
      executionOwner: fixture.owner,
    }).dispatchStartedAt).toBe(C2A_MARKED_AT);

    // Make both lifecycle proofs stale after the marker has been committed.
    handle.prepare("UPDATE actions SET lease_expires_at = ? WHERE id = ?").run(
      C1A_CLAIMED_AT,
      fixture.seeded.actionId,
    );
    handle.prepare("UPDATE action_reviews SET expires_at = ? WHERE id = ?").run(
      C1A_CLAIMED_AT,
      fixture.seeded.reviewId,
    );
    const before = c2aRawState(handle, fixture);
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    const error = c2aErrorCode(() =>
      c2aLifecycleFor(counted, fixture, () => new Date("2099-01-01T00:30:00.000Z")).markDispatch({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
      }),
    );
    expect(error.code).toBe("ACTION_DISPATCH_ALREADY_MARKED");
    expect(probe.prepare).toBeGreaterThan(0);
    expect(probe.exec).toBeGreaterThanOrEqual(2); // BEGIN + ROLLBACK
    expect(c2aRawState(handle, fixture)).toEqual(before);
  });

  it("token mismatch precedes owner comparison, owner mismatch is exact, and mismatch paths never write a token", () => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, "mark-mismatch");
    const before = c2aRawState(handle, fixture);
    const wrongTokenError = c2aErrorCode(() =>
      c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT)).markDispatch({
        actionId: fixture.seeded.actionId,
        executionToken: C2A_WRONG_TOKEN,
        // Deliberately wrong as well: token mismatch has precedence.
        executionOwner: "other-owner",
      }),
    );
    expect(wrongTokenError.code).toBe("ACTION_DISPATCH_TOKEN_MISMATCH");
    expect(wrongTokenError.message).not.toContain(C2A_WRONG_TOKEN);
    const ownerError = c2aErrorCode(() =>
      c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT)).markDispatch({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: "other-owner",
      }),
    );
    expect(ownerError.code).toBe("ACTION_OWNER_INVALID");
    expect(ownerError.message).not.toContain(fixture.owner);
    expect(c2aRawState(handle, fixture)).toEqual(before);
  });

  it.each([
    { name: "success without marker", marked: false, outcome: { kind: "success" } as const, expectedError: "ACTION_DISPATCH_NOT_MARKED" },
    { name: "success with marker", marked: true, outcome: { kind: "success" } as const, expectedStatus: "executed", expectedCertainty: "success" },
    {
      name: "not dispatched without marker",
      marked: false,
      outcome: { kind: "not_dispatched", errorCode: C2A_FIXED_ERROR_CODE, errorMessage: `api_key=private ${C2A_ERROR_HEX}` } as const,
      expectedStatus: "failed",
      expectedCertainty: "not_dispatched",
      expectedErrorCode: C2A_FIXED_ERROR_CODE,
      expectedErrorMessage: "api_key=[REDACTED] [REDACTED]",
    },
    {
      name: "not dispatched with marker",
      marked: true,
      outcome: { kind: "not_dispatched", errorCode: C2A_FIXED_ERROR_CODE, errorMessage: `api_key=private ${C2A_ERROR_HEX}` } as const,
      expectedStatus: "outcome_unknown",
      expectedCertainty: "possibly_dispatched",
      expectedErrorCode: C2A_FIXED_ERROR_CODE,
      expectedErrorMessage: "api_key=[REDACTED] [REDACTED]",
    },
    {
      name: "possibly dispatched without marker",
      marked: false,
      outcome: { kind: "possibly_dispatched", errorCode: "NETWORK_RESET", errorMessage: "transport ambiguity" } as const,
      expectedStatus: "outcome_unknown",
      expectedCertainty: "possibly_dispatched",
      expectedErrorCode: "NETWORK_RESET",
      expectedErrorMessage: "transport ambiguity",
    },
    {
      name: "possibly dispatched with marker",
      marked: true,
      outcome: { kind: "possibly_dispatched", errorCode: "NETWORK_RESET", errorMessage: "transport ambiguity" } as const,
      expectedStatus: "outcome_unknown",
      expectedCertainty: "possibly_dispatched",
      expectedErrorCode: "NETWORK_RESET",
      expectedErrorMessage: "transport ambiguity",
    },
  ])("finalize outcome table: $name", ({ marked, outcome, expectedError, expectedStatus, expectedCertainty, expectedErrorCode, expectedErrorMessage }, index) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `finalize-table-${index}`);
    const markerLifecycle = c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT));
    if (marked) {
      expect(markerLifecycle.markDispatch({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
      }).dispatchStartedAt).toBe(C2A_MARKED_AT);
    }
    const before = c2aRawState(handle, fixture);
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    let nowCalls = 0;
    const lifecycle = c2aLifecycleFor(counted, fixture, () => {
      nowCalls += 1;
      return new Date(C2A_FINALIZED_AT);
    });
    let captured: BountyPilotError | undefined;
    let result: ActionRecord | undefined;
    try {
      result = lifecycle.finalize({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
        outcome,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(BountyPilotError);
      captured = error as BountyPilotError;
    }
    expect(nowCalls).toBe(1);
    c2aAssertTokenFreeSelects(probe.sql);
    if (expectedError) {
      expect(captured?.code).toBe(expectedError);
      expect(captured?.message).not.toContain(fixture.token);
      expect(c2aRawState(handle, fixture)).toEqual(before);
      return;
    }

    expect(captured).toBeUndefined();
    expect(result).toBeDefined();
    expect(result!.status).toBe(expectedStatus);
    expect(result!.outcomeCertainty).toBe(expectedCertainty);
    expect(Object.prototype.hasOwnProperty.call(result!, "executionToken")).toBe(false);
    expect(JSON.stringify(result)).not.toContain(fixture.token);

    const raw = readActionRow(handle, fixture.seeded.actionId);
    expect(raw.status).toBe(expectedStatus);
    expect(raw.outcome_certainty).toBe(expectedCertainty);
    expect(raw.execution_token).toBeNull();
    expect(raw.execution_owner).toBeNull();
    expect(raw.lease_expires_at).toBeNull();
    expect(raw.active_review_id).toBe(fixture.seeded.reviewId);
    // The C1A approval service computes these hashes from the real authority
    // fixture.  Finalize must retain those exact claimed values; the Slice-A
    // raw-seed constants above belong to a different fixture family.
    expect(raw.planned_scope_hash).toBe(before.action.planned_scope_hash);
    expect(raw.planned_policy_hash).toBe(before.action.planned_policy_hash);
    expect(raw.planned_action_hash).toBe(before.action.planned_action_hash);
    expect(raw.planned_context_hash).toBe(before.action.planned_context_hash);
    expect(raw.started_at).toBe(C1A_CLAIMED_AT);
    expect(raw.dispatch_started_at).toBe(marked ? C2A_MARKED_AT : null);
    expect(raw.finished_at).toBe(C2A_FINALIZED_AT);
    expect(raw.updated_at).toBe(C2A_FINALIZED_AT);
    expect(raw.executed_at).toBe(expectedStatus === "executed" ? C2A_FINALIZED_AT : null);
    expect(raw.last_error_code ?? undefined).toBe(expectedErrorCode);
    expect(raw.last_error_message ?? undefined).toBe(expectedErrorMessage);

    const review = handle
      .prepare("SELECT * FROM action_reviews WHERE id = ?")
      .get(fixture.seeded.reviewId) as Record<string, unknown>;
    expect(review).toEqual(before.review);

    const event = new WorkflowEventStore(handle).list(fixture.seeded.jobId).at(-1);
    const eventStatus = expectedStatus === "executed" ? "completed" : expectedStatus === "failed" ? "failed" : "paused";
    const eventMessage = expectedStatus === "executed"
      ? "Action execution completed"
      : expectedStatus === "failed"
        ? "Action execution failed"
        : "Action execution outcome is unknown";
    const reasonCode = expectedStatus === "executed"
      ? "effect_succeeded"
      : expectedStatus === "failed"
        ? "not_dispatched"
        : "reconciliation_required";
    expect(event).toMatchObject({
      phase: "action-execution",
      status: eventStatus,
      message: eventMessage,
      metadata: {
        actionId: fixture.seeded.actionId,
        status: expectedStatus,
        outcomeCertainty: expectedCertainty,
        reasonCode,
      },
    });
    expect(Object.keys(event?.metadata ?? {}).sort()).toEqual(
      ["actionId", "status", "outcomeCertainty", "reasonCode"].sort(),
    );
    expect(JSON.stringify(event)).not.toContain(fixture.token);
    expect(JSON.stringify(event)).not.toContain("api_key");
    expect(JSON.stringify(event)).not.toContain(C2A_ERROR_HEX);

    const job = new JobManager(handle).get(fixture.seeded.jobId);
    expect(job?.status).toBe(expectedStatus === "executed" ? "completed" : expectedStatus === "failed" ? "failed" : "paused");
    expect(job?.pauseReason).toBe(expectedStatus === "outcome_unknown" ? "reconciliation_required" : null);
  });

  it("finalize bounds Unicode diagnostics after secret and standalone-hex sanitization", () => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, "finalize-unicode");
    const message = `  api_key=unicode-secret ${C2A_ERROR_HEX} ${"😀".repeat(2_100)}  `;
    const result = c2aLifecycleFor(handle, fixture, () => new Date(C2A_FINALIZED_AT)).finalize({
      actionId: fixture.seeded.actionId,
      executionToken: fixture.token,
      executionOwner: fixture.owner,
      outcome: {
        kind: "possibly_dispatched",
        errorCode: C2A_FIXED_ERROR_CODE,
        errorMessage: message,
      },
    });
    expect(result.status).toBe("outcome_unknown");
    expect(Array.from(result.lastErrorMessage ?? []).length).toBeLessThanOrEqual(2_000);
    expect(result.lastErrorMessage).not.toContain("unicode-secret");
    expect(result.lastErrorMessage).not.toContain(C2A_ERROR_HEX);
    expect(result.lastErrorMessage).not.toMatch(/[\uD800-\uDFFF]/u);
    expect(JSON.stringify(result)).not.toContain(fixture.token);
  });
});

describe("C2-A finalize: status precedence, token-free probes, and atomic faults", () => {
  it("pre-running status wins over token/owner comparison for both methods", () => {
    const handle = openDb();
    const seeded = seedC1AApprovedAction(handle, "status-precedence");
    let nowCalls = 0;
    const lifecycle = new ActionLifecycle(handle, {
      ...seeded.authority,
      // Per the lifecycle contract, every state-mutating path captures its
      // one validated clock before entering the transaction that reloads and
      // classifies storage status.  A throwing clock would therefore win;
      // use a valid instant to isolate status-vs-token/owner precedence.
      now: () => {
        nowCalls += 1;
        return new Date(C2A_MARKED_AT);
      },
      generateExecutionToken: () => { throw new Error("C2A_TOKEN_MUST_NOT_RUN"); },
    });
    const mark = c2aErrorCode(() => lifecycle.markDispatch({
      actionId: seeded.actionId,
      // Both fields are well-formed but do not match storage.  This keeps
      // the probe at the post-validation status-precedence boundary.
      executionToken: C2A_WRONG_TOKEN,
      executionOwner: "other-owner",
    }));
    expect(mark.code).toBe("ACTION_NOT_APPROVED");
    const finalize = c2aErrorCode(() => lifecycle.finalize({
      actionId: seeded.actionId,
      executionToken: C2A_WRONG_TOKEN,
      executionOwner: "other-owner",
      outcome: { kind: "success" },
    }));
    expect(finalize.code).toBe("ACTION_NOT_APPROVED");
    expect(nowCalls).toBe(2);
  });

  it.each([
    {
      name: "action CAS loss",
      makeDb: (handle: BountyDatabase, fixture: ReturnType<typeof c2aClaimedFixture>) => {
        handle.exec(`
          CREATE TEMP TRIGGER c2a_ignore_finalize
          BEFORE UPDATE ON actions
          FOR EACH ROW
          WHEN OLD.id = '${fixture.seeded.actionId}'
            AND OLD.status = 'running'
            AND NEW.status IN ('executed', 'failed', 'outcome_unknown')
          BEGIN
            SELECT RAISE(IGNORE);
          END;
        `);
        return handle;
      },
      expectedCode: "ACTION_FINALIZE_RACE",
    },
    {
      name: "workflow event fault",
      makeDb: (handle: BountyDatabase) => c1bcFaultingPrepareProxy(
        handle,
        (sql) => /INSERT\s+INTO\s+workflow_events/i.test(sql),
        new Error("C2A_EVENT_DB_FAULT"),
        () => undefined,
      ),
      expectedCode: "C2A_EVENT_DB_FAULT",
    },
    {
      name: "job finalizer fault",
      makeDb: (handle: BountyDatabase) => c1bcFaultingPrepareProxy(
        handle,
        (sql) => /FROM\s+jobs\s+WHERE\s+id\s*=\s*\?/i.test(sql),
        new Error("C2A_JOB_DB_FAULT"),
        () => undefined,
      ),
      expectedCode: "C2A_JOB_DB_FAULT",
    },
  ])("$name rolls back the action, event, review, and job", ({ makeDb, expectedCode }, index) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `fault-${index}`);
    const marker = c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT));
    marker.markDispatch({
      actionId: fixture.seeded.actionId,
      executionToken: fixture.token,
      executionOwner: fixture.owner,
    });
    const before = c2aRawState(handle, fixture);
    const lifecycleDb = makeDb(handle, fixture);
    let captured: unknown;
    try {
      c2aLifecycleFor(lifecycleDb, fixture, () => new Date(C2A_FINALIZED_AT)).finalize({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
        outcome: { kind: "success" },
      });
    } catch (error) {
      captured = error;
    }
    if (expectedCode.startsWith("C2A_")) {
      expect(String(captured)).toContain(expectedCode);
    } else {
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect((captured as BountyPilotError).code).toBe(expectedCode);
    }
    expect(c2aRawState(handle, fixture)).toEqual(before);
    expect(String(captured)).not.toContain(fixture.token);
  });

  it("COMMIT failure wins over finalize success and rolls back every write", () => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, "fault-commit");
    const marker = c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT));
    marker.markDispatch({
      actionId: fixture.seeded.actionId,
      executionToken: fixture.token,
      executionOwner: fixture.owner,
    });
    const before = c2aRawState(handle, fixture);
    const sentinel = new Error("C2A_COMMIT_SENTINEL");
    const seen: string[] = [];
    const commitFaultDb = new Proxy(handle, {
      get(target, property): unknown {
        if (property === "exec") {
          return (sql: string): void => {
            const command = sql.trim().toUpperCase();
            seen.push(command);
            if (command === "COMMIT") throw sentinel;
            target.exec(sql);
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    }) as BountyDatabase;
    let captured: unknown;
    try {
      c2aLifecycleFor(commitFaultDb, fixture, () => new Date(C2A_FINALIZED_AT)).finalize({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
        outcome: { kind: "success" },
      });
    } catch (error) {
      captured = error;
    }
    expect(captured).toBe(sentinel);
    expect(seen).toEqual(["BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"]);
    expect(c2aRawState(handle, fixture)).toEqual(before);
    expect(String(captured)).not.toContain(fixture.token);
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C2-B - expired-lease recovery RED/review contract
// ===========================================================================

const C2B_ACTIVE_AT = "2099-01-01T00:01:10.000Z";
const C2B_RECOVERED_AT = "2099-01-01T00:04:00.000Z";

interface C2BExpectedRecovery {
  status: "failed" | "outcome_unknown";
  certainty: "not_dispatched" | "possibly_dispatched";
  marker: string | null;
  eventStatus: "failed" | "paused";
  message:
    | "Expired action lease recovered before dispatch"
    | "Expired action lease requires reconciliation";
  reasonCode: "lease_expired_not_dispatched" | "reconciliation_required";
  jobStatus: "failed" | "paused";
  pauseReason: null | "reconciliation_required";
}

function c2bAssertRecoveredState(
  handle: BountyDatabase,
  fixture: ReturnType<typeof c2aClaimedFixture>,
  before: ReturnType<typeof c2aRawState>,
  expected: C2BExpectedRecovery,
): void {
  const raw = readActionRow(handle, fixture.seeded.actionId);
  expect(raw.status).toBe(expected.status);
  expect(raw.executed_at).toBeNull();
  expect(raw.execution_token).toBeNull();
  expect(raw.execution_owner).toBeNull();
  expect(raw.lease_expires_at).toBeNull();
  expect(raw.started_at).toBe(before.action.started_at);
  expect(raw.dispatch_started_at).toBe(expected.marker);
  expect(raw.finished_at).toBe(C2B_RECOVERED_AT);
  expect(raw.updated_at).toBe(C2B_RECOVERED_AT);
  expect(raw.outcome_certainty).toBe(expected.certainty);
  expect(raw.last_error_code).toBe("ACTION_LEASE_EXPIRED");
  expect(raw.last_error_message).toBe(expected.message);
  expect(raw.active_review_id).toBe(before.action.active_review_id);
  expect(raw.planned_scope_hash).toBe(before.action.planned_scope_hash);
  expect(raw.planned_policy_hash).toBe(before.action.planned_policy_hash);
  expect(raw.planned_action_hash).toBe(before.action.planned_action_hash);
  expect(raw.planned_context_hash).toBe(before.action.planned_context_hash);

  const review = handle
    .prepare("SELECT * FROM action_reviews WHERE id = ?")
    .get(fixture.seeded.reviewId) as Record<string, unknown>;
  expect(review).toEqual(before.review);

  const events = new WorkflowEventStore(handle).list(fixture.seeded.jobId);
  expect(events).toHaveLength(before.events.length + 1);
  const event = events.at(-1);
  expect(event).toMatchObject({
    phase: "action-recovery",
    status: expected.eventStatus,
    message: expected.message,
    metadata: {
      actionId: fixture.seeded.actionId,
      status: expected.status,
      outcomeCertainty: expected.certainty,
      reasonCode: expected.reasonCode,
    },
  });
  expect(Object.keys(event?.metadata ?? {}).sort()).toEqual(
    ["actionId", "status", "outcomeCertainty", "reasonCode"].sort(),
  );
  expect(JSON.stringify(event)).not.toContain(fixture.token);
  expect(JSON.stringify(event)).not.toContain(fixture.owner);

  const job = new JobManager(handle).get(fixture.seeded.jobId);
  expect(job?.status).toBe(expected.jobStatus);
  expect(job?.pauseReason).toBe(expected.pauseReason);
  expect(JSON.stringify(job)).not.toContain(fixture.token);

  const action = new ActionQueue(handle).get(fixture.seeded.actionId);
  expect(action?.status).toBe(expected.status);
  expect(Object.prototype.hasOwnProperty.call(action ?? {}, "executionToken")).toBe(false);
  expect(JSON.stringify(action)).not.toContain(fixture.token);
}

const C2B_PRE_DISPATCH: C2BExpectedRecovery = {
  status: "failed",
  certainty: "not_dispatched",
  marker: null,
  eventStatus: "failed",
  message: "Expired action lease recovered before dispatch",
  reasonCode: "lease_expired_not_dispatched",
  jobStatus: "failed",
  pauseReason: null,
};

const C2B_AMBIGUOUS: C2BExpectedRecovery = {
  status: "outcome_unknown",
  certainty: "possibly_dispatched",
  marker: null,
  eventStatus: "paused",
  message: "Expired action lease requires reconciliation",
  reasonCode: "reconciliation_required",
  jobStatus: "paused",
  pauseReason: "reconciliation_required",
};

describe("C2-B recovery: caller boundary, missing/non-running, and active lease", () => {
  it.each([
    { name: "null", actionId: null },
    { name: "array", actionId: [] },
    { name: "symbol", actionId: Symbol("action") },
    { name: "padded", actionId: " action-c2b" },
    {
      name: "hostile proxy",
      actionId: new Proxy({}, {
        get: () => { throw new Error("C2B_PROXY_GET"); },
        getPrototypeOf: () => { throw new Error("C2B_PROXY_PROTO"); },
      }),
    },
  ])("rejects $name actionId before SQL, dependencies, or effects", ({ actionId }) => {
    const handle = openDb();
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    let dependencyCalls = 0;
    const unavailable = () => {
      dependencyCalls += 1;
      throw new Error("C2B_DEPENDENCY_MUST_NOT_RUN");
    };
    const lifecycle = new ActionLifecycle(counted, {
      loadCurrentProgram: unavailable,
      resolveBindingMaterial: unavailable,
      now: unavailable,
      generateExecutionToken: unavailable,
    } as unknown as ActionLifecycleDependencies);
    const error = c2aErrorCode(() => lifecycle.recoverExpiredLease(actionId as never));
    expect(error.code).toBe("ACTION_LIFECYCLE_INVALID");
    expect(probe.prepare).toBe(0);
    expect(probe.exec).toBe(0);
    expect(dependencyCalls).toBe(0);
  });

  it("missing action is ACTION_NOT_FOUND without a clock call or write", () => {
    const handle = openDb();
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    let nowCalls = 0;
    const lifecycle = new ActionLifecycle(counted, {
      ...buildC1AAuthorityDependencies(),
      now: () => {
        nowCalls += 1;
        throw new Error("C2B_CLOCK_MUST_NOT_RUN");
      },
      generateExecutionToken: () => { throw new Error("C2B_TOKEN_MUST_NOT_RUN"); },
    });
    const error = c2aErrorCode(() => lifecycle.recoverExpiredLease("action-c2b-missing"));
    expect(error.code).toBe("ACTION_NOT_FOUND");
    expect(nowCalls).toBe(0);
    expect(probe.prepare).toBe(1);
    expect(probe.exec).toBe(0);
  });

  it.each([
    "pending",
    "planned",
    "approved",
    "executed",
    "blocked",
    "failed",
    "outcome_unknown",
  ])("status %s returns not_running byte-identically without a clock", (status) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `non-running-${status}`);
    handle.prepare("UPDATE actions SET status = ? WHERE id = ?").run(
      status,
      fixture.seeded.actionId,
    );
    const before = c2aRawState(handle, fixture);
    let nowCalls = 0;
    const result = c2aLifecycleFor(handle, fixture, () => {
      nowCalls += 1;
      throw new Error("C2B_CLOCK_MUST_NOT_RUN");
    }).recoverExpiredLease(fixture.seeded.actionId);
    expect(result).toEqual({ kind: "not_running" });
    expect(nowCalls).toBe(0);
    expect(c2aRawState(handle, fixture)).toEqual(before);
  });

  it.each([
    { name: "without dispatch marker", marked: false },
    { name: "with dispatch marker", marked: true },
  ])("active future lease is a no-op $name", ({ marked }, index) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `active-${index}`);
    if (marked) {
      c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT)).markDispatch({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
      });
    }
    const before = c2aRawState(handle, fixture);
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    let nowCalls = 0;
    const result = c2aLifecycleFor(counted, fixture, () => {
      nowCalls += 1;
      return new Date(C2B_ACTIVE_AT);
    }).recoverExpiredLease(fixture.seeded.actionId);
    expect(result).toEqual({ kind: "active" });
    expect(nowCalls).toBe(1);
    c2aAssertTokenFreeSelects(probe.sql);
    expect(c2aRawState(handle, fixture)).toEqual(before);
    const publicAction = new ActionQueue(handle).get(fixture.seeded.actionId);
    expect(Object.prototype.hasOwnProperty.call(publicAction ?? {}, "executionToken")).toBe(false);
    expect(JSON.stringify(publicAction)).not.toContain(fixture.token);
    expect(JSON.stringify(result)).not.toContain(fixture.token);
  });
});

describe("C2-B recovery: expired mapping, malformed lifecycle, and idempotence", () => {
  it.each([
    { name: "clean pre-dispatch", marked: false, expected: C2B_PRE_DISPATCH },
    {
      name: "dispatch marker present",
      marked: true,
      expected: { ...C2B_AMBIGUOUS, marker: C2A_MARKED_AT },
    },
  ])("expired $name maps to the exact terminal tuple/event/job", ({ marked, expected }, index) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `expired-${index}`);
    if (marked) {
      c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT)).markDispatch({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
      });
    }
    const before = c2aRawState(handle, fixture);
    const probe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, probe);
    let nowCalls = 0;
    const result = c2aLifecycleFor(counted, fixture, () => {
      nowCalls += 1;
      return new Date(C2B_RECOVERED_AT);
    }).recoverExpiredLease(fixture.seeded.actionId);
    expect(result).toEqual({ kind: "recovered", status: expected.status });
    expect(nowCalls).toBe(1);
    c2aAssertTokenFreeSelects(probe.sql);
    c2bAssertRecoveredState(handle, fixture, before, expected);
    expect(JSON.stringify(result)).not.toContain(fixture.token);
  });

  it.each([
    { name: "missing token", column: "execution_token", value: null },
    { name: "malformed token", column: "execution_token", value: "F".repeat(64) },
    { name: "missing owner", column: "execution_owner", value: null },
    { name: "malformed owner", column: "execution_owner", value: "bad\nowner" },
    { name: "missing lease", column: "lease_expires_at", value: null },
    { name: "malformed lease", column: "lease_expires_at", value: "not-an-iso" },
    { name: "missing start", column: "started_at", value: null },
    { name: "malformed start", column: "started_at", value: "not-an-iso" },
  ])("expired running row with $name is outcome_unknown/possibly_dispatched", ({ column, value }, index) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `malformed-${index}`);
    const allowedColumns = new Set([
      "execution_token",
      "execution_owner",
      "lease_expires_at",
      "started_at",
    ]);
    expect(allowedColumns.has(column)).toBe(true);
    handle.prepare(`UPDATE actions SET ${column} = ? WHERE id = ?`).run(
      value,
      fixture.seeded.actionId,
    );
    const before = c2aRawState(handle, fixture);
    const result = c2aLifecycleFor(handle, fixture, () => new Date(C2B_RECOVERED_AT))
      .recoverExpiredLease(fixture.seeded.actionId);
    expect(result).toEqual({ kind: "recovered", status: "outcome_unknown" });
    c2bAssertRecoveredState(handle, fixture, before, C2B_AMBIGUOUS);
    expect(JSON.stringify(result)).not.toContain(fixture.token);
  });

  it.each([
    { name: "failed pre-dispatch recovery", marked: false, expectedStatus: "failed" },
    { name: "ambiguous post-dispatch recovery", marked: true, expectedStatus: "outcome_unknown" },
  ])("repeated $name returns not_running with no clock and no writes", ({ marked, expectedStatus }, index) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `repeat-${index}`);
    if (marked) {
      c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT)).markDispatch({
        actionId: fixture.seeded.actionId,
        executionToken: fixture.token,
        executionOwner: fixture.owner,
      });
    }
    const first = c2aLifecycleFor(handle, fixture, () => new Date(C2B_RECOVERED_AT))
      .recoverExpiredLease(fixture.seeded.actionId);
    expect(first).toEqual({ kind: "recovered", status: expectedStatus });
    const beforeSecond = c2aRawState(handle, fixture);
    let nowCalls = 0;
    const second = c2aLifecycleFor(handle, fixture, () => {
      nowCalls += 1;
      throw new Error("C2B_CLOCK_MUST_NOT_RUN");
    }).recoverExpiredLease(fixture.seeded.actionId);
    expect(second).toEqual({ kind: "not_running" });
    expect(nowCalls).toBe(0);
    expect(c2aRawState(handle, fixture)).toEqual(beforeSecond);
  });
});

describe("C2-B recovery: CAS/event/job/COMMIT rollback", () => {
  it("a lost terminal CAS throws ACTION_FINALIZE_RACE and preserves every row", () => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, "recovery-cas-loss");
    handle.exec(`
      CREATE TEMP TRIGGER c2b_ignore_recovery
      BEFORE UPDATE ON actions
      FOR EACH ROW
      WHEN OLD.id = '${fixture.seeded.actionId}'
        AND OLD.status = 'running'
        AND NEW.status IN ('failed', 'outcome_unknown')
      BEGIN
        SELECT RAISE(IGNORE);
      END;
    `);
    const before = c2aRawState(handle, fixture);
    const error = c2aErrorCode(() =>
      c2aLifecycleFor(handle, fixture, () => new Date(C2B_RECOVERED_AT))
        .recoverExpiredLease(fixture.seeded.actionId),
    );
    expect(error.code).toBe("ACTION_FINALIZE_RACE");
    expect(error.message).not.toContain(fixture.token);
    expect(c2aRawState(handle, fixture)).toEqual(before);
  });

  it.each([
    {
      name: "workflow event",
      matches: (sql: string) => /INSERT\s+INTO\s+workflow_events/i.test(sql),
      fault: new Error("C2B_EVENT_DB_FAULT"),
    },
    {
      name: "job finalizer",
      matches: (sql: string) => /FROM\s+jobs\s+WHERE\s+id\s*=\s*\?/i.test(sql),
      fault: new Error("C2B_JOB_DB_FAULT"),
    },
  ])("a $name fault propagates exactly and rolls back action/event/job", ({ matches, fault }, index) => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, `recovery-fault-${index}`);
    const before = c2aRawState(handle, fixture);
    const faulting = c1bcFaultingPrepareProxy(handle, matches, fault, () => undefined);
    let captured: unknown;
    try {
      c2aLifecycleFor(faulting, fixture, () => new Date(C2B_RECOVERED_AT))
        .recoverExpiredLease(fixture.seeded.actionId);
    } catch (error) {
      captured = error;
    }
    expect(captured).toBe(fault);
    expect(c2aRawState(handle, fixture)).toEqual(before);
    expect(String(captured)).not.toContain(fixture.token);
  });

  it("COMMIT failure wins and rolls back recovered action, event, and job", () => {
    const handle = openDb();
    const fixture = c2aClaimedFixture(handle, "recovery-commit");
    const before = c2aRawState(handle, fixture);
    const sentinel = new Error("C2B_COMMIT_SENTINEL");
    const seen: string[] = [];
    const commitFaultDb = new Proxy(handle, {
      get(target, property): unknown {
        if (property === "exec") {
          return (sql: string): void => {
            const command = sql.trim().toUpperCase();
            seen.push(command);
            if (command === "COMMIT") throw sentinel;
            target.exec(sql);
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    }) as BountyDatabase;
    let captured: unknown;
    try {
      c2aLifecycleFor(commitFaultDb, fixture, () => new Date(C2B_RECOVERED_AT))
        .recoverExpiredLease(fixture.seeded.actionId);
    } catch (error) {
      captured = error;
    }
    expect(captured).toBe(sentinel);
    expect(seen).toEqual(["BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"]);
    expect(c2aRawState(handle, fixture)).toEqual(before);
    expect(String(captured)).not.toContain(fixture.token);
  });

  it.each([
    { operation: "finalize" as const, ignoredWrite: "event" as const },
    { operation: "finalize" as const, ignoredWrite: "job" as const },
    { operation: "recoverExpiredLease" as const, ignoredWrite: "event" as const },
    { operation: "recoverExpiredLease" as const, ignoredWrite: "job" as const },
  ])(
    "$operation fails closed when SQLite silently ignores the lifecycle $ignoredWrite write",
    ({ operation, ignoredWrite }, index) => {
      const handle = openDb();
      const fixture = c2aClaimedFixture(
        handle,
        `silent-write-${operation}-${ignoredWrite}-${index}`,
      );

      if (operation === "finalize") {
        c2aLifecycleFor(handle, fixture, () => new Date(C2A_MARKED_AT)).markDispatch({
          actionId: fixture.seeded.actionId,
          executionToken: fixture.token,
          executionOwner: fixture.owner,
        });
      }

      const before = c2aRawState(handle, fixture);
      let ignoredWriteCalls = 0;
      const counterFunction = `c2_atomicity_counter_${index}`;
      handle.function(counterFunction, () => {
        ignoredWriteCalls += 1;
        return 1;
      });
      if (ignoredWrite === "event") {
        handle.exec(`
          CREATE TEMP TRIGGER c2_atomicity_ignore_event_${index}
          BEFORE INSERT ON workflow_events
          FOR EACH ROW
          WHEN NEW.job_id = '${fixture.seeded.jobId}'
          BEGIN
            SELECT ${counterFunction}();
            SELECT RAISE(IGNORE);
          END;
        `);
      } else {
        handle.exec(`
          CREATE TEMP TRIGGER c2_atomicity_ignore_job_${index}
          BEFORE UPDATE ON jobs
          FOR EACH ROW
          WHEN OLD.id = '${fixture.seeded.jobId}'
          BEGIN
            SELECT ${counterFunction}();
            SELECT RAISE(IGNORE);
          END;
        `);
      }

      let captured: unknown;
      try {
        const lifecycle = c2aLifecycleFor(
          handle,
          fixture,
          () => new Date(
            operation === "finalize" ? C2A_FINALIZED_AT : C2B_RECOVERED_AT,
          ),
        );
        if (operation === "finalize") {
          lifecycle.finalize({
            actionId: fixture.seeded.actionId,
            executionToken: fixture.token,
            executionOwner: fixture.owner,
            outcome: { kind: "success" },
          });
        } else {
          lifecycle.recoverExpiredLease(fixture.seeded.actionId);
        }
      } catch (error) {
        captured = error;
      }

      // SQLite BEFORE triggers may return `changes = 0` without throwing.
      // Treating that as success would commit a terminal action without its
      // event, or commit action+event while leaving the job tuple stale.
      // The store primitive therefore has to turn the zero-change result into
      // a fixed, cause-free domain error so the outer lifecycle transaction
      // rolls every earlier write back.
      expect(captured).toBeInstanceOf(BountyPilotError);
      if (!(captured instanceof BountyPilotError)) return;
      expect(Object.prototype.hasOwnProperty.call(captured, "cause")).toBe(false);
      expect(captured.code).toBe(
        ignoredWrite === "event"
          ? "WORKFLOW_EVENT_WRITE_FAILED"
          : "JOB_FINALIZE_WRITE_FAILED",
      );
      expect(captured.message).not.toContain(fixture.token);
      expect(captured.message).not.toContain(fixture.owner);
      expect(ignoredWriteCalls).toBe(1);
      expect(c2aRawState(handle, fixture)).toEqual(before);
    },
  );
});

// ===========================================================================
// P0.2 Packet 2 Slice C3-A1 - human reconciliation caller and mapping contract
// ===========================================================================

const C3A_RECONCILED_AT = "2099-01-01T00:02:00.000Z";
const C3A_REVIEWER = "researcher-c3a";
const C3A_ATTESTATION_HEX = "b".repeat(64);
const C3A_AMBIGUITY_CODE = "REMOTE_OUTCOME_UNKNOWN";
const C3A_AMBIGUITY_PUBLIC_TEXT = "Remote response ended before outcome confirmation";

interface C3ADependencyProbe {
  authority: number;
  clock: number;
  token: number;
}

interface C3ARawState {
  action: Record<string, unknown>;
  reviews: Array<Record<string, unknown>>;
  job: Record<string, unknown>;
  events: Array<Record<string, unknown>>;
}

function c3aRawState(
  handle: BountyDatabase,
  fixture: ReturnType<typeof c2aClaimedFixture>,
): C3ARawState {
  return {
    action: readActionRow(handle, fixture.seeded.actionId),
    reviews: handle
      .prepare("SELECT * FROM action_reviews WHERE action_id = ? ORDER BY rowid ASC")
      .all(fixture.seeded.actionId) as Array<Record<string, unknown>>,
    job: readJobRow(handle, fixture.seeded.jobId),
    events: handle
      .prepare("SELECT * FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
      .all(fixture.seeded.jobId) as Array<Record<string, unknown>>,
  };
}

function c3aLifecycleFor(
  handle: BountyDatabase,
  authority: ReturnType<typeof buildC1AAuthorityDependencies>,
  now: () => Date,
  probe: C3ADependencyProbe,
): ActionLifecycle {
  return new ActionLifecycle(handle, {
    ...authority,
    loadCurrentProgram: () => {
      probe.authority += 1;
      throw new Error("C3A_AUTHORITY_MUST_NOT_RUN");
    },
    resolveBindingMaterial: () => {
      probe.authority += 1;
      throw new Error("C3A_AUTHORITY_MUST_NOT_RUN");
    },
    now: () => {
      probe.clock += 1;
      return now();
    },
    generateExecutionToken: () => {
      probe.token += 1;
      throw new Error("C3A_TOKEN_MUST_NOT_RUN");
    },
  });
}

function c3aOutcomeUnknownFixture(
  handle: BountyDatabase,
  suffix: string,
  options: { marked?: boolean; historicalApproval?: boolean } = {},
): ReturnType<typeof c2aClaimedFixture> {
  const fixture = c2aClaimedFixture(handle, suffix);
  const lifecycle = c2aLifecycleFor(handle, fixture, () => new Date(C2A_FINALIZED_AT));
  if (options.marked) {
    lifecycle.markDispatch({
      actionId: fixture.seeded.actionId,
      executionToken: fixture.token,
      executionOwner: fixture.owner,
    });
  }
  const unknown = lifecycle.finalize({
    actionId: fixture.seeded.actionId,
    executionToken: fixture.token,
    executionOwner: fixture.owner,
    outcome: {
      kind: "possibly_dispatched",
      errorCode: C3A_AMBIGUITY_CODE,
      errorMessage: `api_key=c3a-private ${C2A_ERROR_HEX} ${C3A_AMBIGUITY_PUBLIC_TEXT}`,
    },
  });
  expect(unknown.status).toBe("outcome_unknown");
  expect(unknown.outcomeCertainty).toBe("possibly_dispatched");

  if (options.historicalApproval) {
    // Reconciliation proves outcome provenance rather than authorizing a new
    // effect, so a once-valid original approval may now be expired and carry
    // a historical invalidation. Its linkage and hashes must remain exact.
    handle.prepare(
      `UPDATE action_reviews
       SET expires_at = ?, invalidated_at = ?, invalidation_reason = ?
       WHERE id = ?`,
    ).run(
      "2099-01-01T00:01:05.000Z",
      "2099-01-01T00:01:06.000Z",
      "review_expired",
      fixture.seeded.reviewId,
    );
  }
  return fixture;
}

function c3aValidInput(
  actionId: string,
  resolution: "effect_confirmed" | "no_successful_effect_confirmed" = "effect_confirmed",
): {
  actionId: string;
  reviewerId: string;
  attestation: string;
  resolution: "effect_confirmed" | "no_successful_effect_confirmed";
} {
  return {
    actionId,
    reviewerId: C3A_REVIEWER,
    attestation: "Human verified the final outcome in the trusted system of record",
    resolution,
  };
}

const C3A_BOUNDARY_ACTION_ID = "action-c3a-boundary";
const C3A_BOUNDARY_BASE = c3aValidInput(C3A_BOUNDARY_ACTION_ID);

const C3A_INVALID_INPUT_CASES: Array<{
  name: string;
  input: unknown;
  code: string;
}> = [
  { name: "null envelope", input: null, code: "ACTION_LIFECYCLE_INVALID" },
  { name: "array envelope", input: [], code: "ACTION_LIFECYCLE_INVALID" },
  {
    name: "hostile proxy envelope",
    input: new Proxy(C3A_BOUNDARY_BASE, {
      get: () => { throw new Error("C3A_PRIVATE_PROXY_GET"); },
      getPrototypeOf: () => { throw new Error("C3A_PRIVATE_PROXY_PROTO"); },
      ownKeys: () => { throw new Error("C3A_PRIVATE_PROXY_KEYS"); },
      getOwnPropertyDescriptor: () => { throw new Error("C3A_PRIVATE_PROXY_DESCRIPTOR"); },
    }),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "custom prototype envelope",
    input: Object.assign(Object.create({ inherited: true }), C3A_BOUNDARY_BASE),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "accessor field",
    input: (() => {
      const value = { ...C3A_BOUNDARY_BASE };
      Object.defineProperty(value, "attestation", {
        enumerable: true,
        get: () => { throw new Error("C3A_PRIVATE_ACCESSOR"); },
      });
      return value;
    })(),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "non-enumerable required field",
    input: (() => {
      const value = { ...C3A_BOUNDARY_BASE };
      Object.defineProperty(value, "attestation", {
        enumerable: false,
        value: C3A_BOUNDARY_BASE.attestation,
      });
      return value;
    })(),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "symbol field",
    input: (() => {
      const value: Record<string | symbol, unknown> = { ...C3A_BOUNDARY_BASE };
      value[Symbol("attestation")] = "private";
      return value;
    })(),
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "unknown field",
    input: { ...C3A_BOUNDARY_BASE, extra: true },
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "missing field",
    input: {
      actionId: C3A_BOUNDARY_ACTION_ID,
      reviewerId: C3A_REVIEWER,
      resolution: "effect_confirmed",
    },
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "malformed action id",
    input: { ...C3A_BOUNDARY_BASE, actionId: ` ${C3A_BOUNDARY_ACTION_ID}` },
    code: "ACTION_LIFECYCLE_INVALID",
  },
  {
    name: "policy reviewer",
    input: { ...C3A_BOUNDARY_BASE, reviewerId: "system:policy-gate" },
    code: "ACTION_RECONCILIATION_REVIEWER_INVALID",
  },
  {
    name: "non-string reviewer",
    input: { ...C3A_BOUNDARY_BASE, reviewerId: 7 },
    code: "ACTION_RECONCILIATION_REVIEWER_INVALID",
  },
  {
    name: "blank reviewer",
    input: { ...C3A_BOUNDARY_BASE, reviewerId: "   " },
    code: "ACTION_RECONCILIATION_REVIEWER_INVALID",
  },
  {
    name: "control-character reviewer",
    input: { ...C3A_BOUNDARY_BASE, reviewerId: "researcher\u0001private" },
    code: "ACTION_RECONCILIATION_REVIEWER_INVALID",
  },
  {
    name: "overlong reviewer",
    input: { ...C3A_BOUNDARY_BASE, reviewerId: "r".repeat(257) },
    code: "ACTION_RECONCILIATION_REVIEWER_INVALID",
  },
  {
    name: "non-string attestation",
    input: { ...C3A_BOUNDARY_BASE, attestation: 7 },
    code: "ACTION_RECONCILIATION_ATTESTATION_REQUIRED",
  },
  {
    name: "empty attestation",
    input: { ...C3A_BOUNDARY_BASE, attestation: "   " },
    code: "ACTION_RECONCILIATION_ATTESTATION_REQUIRED",
  },
  {
    name: "redaction-marker-only attestation",
    input: { ...C3A_BOUNDARY_BASE, attestation: " [REDACTED]\n [REDACTED] " },
    code: "ACTION_RECONCILIATION_ATTESTATION_REQUIRED",
  },
  {
    name: "standalone-token-only attestation",
    input: { ...C3A_BOUNDARY_BASE, attestation: C3A_ATTESTATION_HEX },
    code: "ACTION_RECONCILIATION_ATTESTATION_REQUIRED",
  },
  {
    name: "invalid resolution literal",
    input: { ...C3A_BOUNDARY_BASE, resolution: "unknown" },
    code: "ACTION_RECONCILIATION_RESOLUTION_INVALID",
  },
  {
    name: "non-string resolution",
    input: { ...C3A_BOUNDARY_BASE, resolution: 1 },
    code: "ACTION_RECONCILIATION_RESOLUTION_INVALID",
  },
];

describe("C3-A1 reconciliation: exact DTO and pure reviewer/attestation/resolution boundary", () => {
  it.each(C3A_INVALID_INPUT_CASES)(
    "rejects $name before SQL, clock, authority, or token generation",
    ({ input, code }) => {
      const handle = openDb();
      const sqlProbe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
      const counted = c2aCountingDb(handle, sqlProbe);
      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const lifecycle = c3aLifecycleFor(
        counted,
        buildC1AAuthorityDependencies(),
        () => { throw new Error("C3A_CLOCK_MUST_NOT_RUN"); },
        dependencyProbe,
      );
      const error = c2aErrorCode(() => lifecycle.reconcileOutcome(input as never));
      expect(error.code).toBe(code);
      expect(error.message).not.toContain("C3A_PRIVATE");
      expect(error.message).not.toContain(C3A_ATTESTATION_HEX);
      expect(sqlProbe.prepare).toBe(0);
      expect(sqlProbe.exec).toBe(0);
      expect(dependencyProbe).toEqual({ authority: 0, clock: 0, token: 0 });
    },
  );
});

describe("C3-A1 reconciliation: token-free status preflight and clock ordering", () => {
  it("missing action is ACTION_NOT_FOUND without clock, authority, token generation, or writes", () => {
    const handle = openDb();
    const sqlProbe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
    const counted = c2aCountingDb(handle, sqlProbe);
    const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
    const lifecycle = c3aLifecycleFor(
      counted,
      buildC1AAuthorityDependencies(),
      () => { throw new Error("C3A_CLOCK_MUST_NOT_RUN"); },
      dependencyProbe,
    );
    const error = c2aErrorCode(() => lifecycle.reconcileOutcome(
      c3aValidInput("action-c3a-missing"),
    ));
    expect(error.code).toBe("ACTION_NOT_FOUND");
    expect(dependencyProbe).toEqual({ authority: 0, clock: 0, token: 0 });
    expect(sqlProbe.prepare).toBeGreaterThan(0);
    expect(sqlProbe.exec).toBe(0);
    c2aAssertTokenFreeSelects(sqlProbe.sql);
  });

  it.each([
    { status: "pending", code: "ACTION_NOT_APPROVED" },
    { status: "planned", code: "ACTION_NOT_APPROVED" },
    { status: "approved", code: "ACTION_NOT_APPROVED" },
    { status: "running", code: "ACTION_LEASE_HELD" },
    { status: "executed", code: "ACTION_TERMINAL" },
    { status: "blocked", code: "ACTION_TERMINAL" },
    { status: "failed", code: "ACTION_TERMINAL" },
  ])(
    "status $status maps to $code before clock/authority and remains byte-identical",
    ({ status, code }, index) => {
      const handle = openDb();
      const fixture = c2aClaimedFixture(handle, `c3a-status-${index}`);
      handle.prepare("UPDATE actions SET status = ? WHERE id = ?").run(
        status,
        fixture.seeded.actionId,
      );
      const before = c3aRawState(handle, fixture);
      const sqlProbe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
      const counted = c2aCountingDb(handle, sqlProbe);
      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const lifecycle = c3aLifecycleFor(
        counted,
        fixture.seeded.authority,
        () => { throw new Error("C3A_CLOCK_MUST_NOT_RUN"); },
        dependencyProbe,
      );
      const error = c2aErrorCode(() => lifecycle.reconcileOutcome(
        c3aValidInput(fixture.seeded.actionId),
      ));
      expect(error.code).toBe(code);
      expect(error.message).not.toContain(fixture.token);
      expect(error.message).not.toContain(fixture.owner);
      expect(dependencyProbe).toEqual({ authority: 0, clock: 0, token: 0 });
      expect(sqlProbe.prepare).toBeGreaterThan(0);
      expect(sqlProbe.exec).toBe(0);
      c2aAssertTokenFreeSelects(sqlProbe.sql);
      expect(c3aRawState(handle, fixture)).toEqual(before);
    },
  );

  it.each([
    { name: "throwing clock", now: () => { throw new Error("C3A_PRIVATE_CLOCK"); } },
    { name: "invalid clock", now: () => new Date(Number.NaN) },
  ])(
    "$name after outcome_unknown preflight is fixed ACTION_APPROVAL_CONTEXT_UNAVAILABLE with no writes",
    ({ now }, index) => {
      const handle = openDb();
      const fixture = c3aOutcomeUnknownFixture(handle, `c3a-clock-${index}`);
      const before = c3aRawState(handle, fixture);
      const sqlProbe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
      const counted = c2aCountingDb(handle, sqlProbe);
      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const lifecycle = c3aLifecycleFor(
        counted,
        fixture.seeded.authority,
        now,
        dependencyProbe,
      );
      const error = c2aErrorCode(() => lifecycle.reconcileOutcome(
        c3aValidInput(fixture.seeded.actionId),
      ));
      expect(error.code).toBe("ACTION_APPROVAL_CONTEXT_UNAVAILABLE");
      expect(error.message).not.toContain("C3A_PRIVATE_CLOCK");
      expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
      expect(sqlProbe.prepare).toBeGreaterThan(0);
      expect(sqlProbe.exec).toBe(0);
      c2aAssertTokenFreeSelects(sqlProbe.sql);
      expect(c3aRawState(handle, fixture)).toEqual(before);
    },
  );
});

describe("C3-A1 reconciliation: exact human review/action/event/job mappings with zero effects", () => {
  it.each([
    {
      name: "effect confirmed from a historically invalidated approval",
      resolution: "effect_confirmed" as const,
      marked: true,
      historicalApproval: true,
      expectedStatus: "executed" as const,
      expectedDecision: "executed" as const,
      expectedCertainty: "success" as const,
      expectedEventStatus: "completed" as const,
      expectedJobStatus: "completed" as const,
    },
    {
      name: "no successful effect confirmed",
      resolution: "no_successful_effect_confirmed" as const,
      marked: false,
      historicalApproval: false,
      expectedStatus: "failed" as const,
      expectedDecision: "failed" as const,
      expectedCertainty: "possibly_dispatched" as const,
      expectedEventStatus: "failed" as const,
      expectedJobStatus: "failed" as const,
    },
  ])(
    "$name persists one non-active reconciliation review and atomically finalizes the action/event/job",
    ({
      resolution,
      marked,
      historicalApproval,
      expectedStatus,
      expectedDecision,
      expectedCertainty,
      expectedEventStatus,
      expectedJobStatus,
    }, index) => {
      const handle = openDb();
      const fixture = c3aOutcomeUnknownFixture(
        handle,
        `c3a-mapping-${index}`,
        { marked, historicalApproval },
      );
      const before = c3aRawState(handle, fixture);
      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const lifecycle = c3aLifecycleFor(
        handle,
        fixture.seeded.authority,
        () => new Date(C3A_RECONCILED_AT),
        dependencyProbe,
      );
      const rawAttestation = [
        "  api_key=c3a-attestation-secret",
        C3A_ATTESTATION_HEX,
        "Dashboard evidence confirms the final outcome",
        String.fromCharCode(0xd800),
        "x".repeat(2_100),
        "  ",
      ].join(" ");
      const input = index === 0
        ? Object.assign(Object.create(null), {
            actionId: fixture.seeded.actionId,
            reviewerId: `  ${C3A_REVIEWER}  `,
            attestation: rawAttestation,
            resolution,
          })
        : {
            actionId: fixture.seeded.actionId,
            reviewerId: `  ${C3A_REVIEWER}  `,
            attestation: rawAttestation,
            resolution,
          };

      const result = lifecycle.reconcileOutcome(input);
      expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
      expect(result.status).toBe(expectedStatus);
      expect(result.action.status).toBe(expectedStatus);
      expect(result.action.id).toBe(fixture.seeded.actionId);
      expect(result.reconciliationReviewId).not.toBe(fixture.seeded.reviewId);
      expect(Object.prototype.hasOwnProperty.call(result.action, "executionToken")).toBe(false);
      expect(JSON.stringify(result)).not.toContain(fixture.token);
      expect(JSON.stringify(result)).not.toContain(fixture.owner);
      expect(JSON.stringify(result)).not.toContain("c3a-attestation-secret");
      expect(JSON.stringify(result)).not.toContain(C3A_ATTESTATION_HEX);

      const after = c3aRawState(handle, fixture);
      expect(after.reviews).toHaveLength(before.reviews.length + 1);
      const originalReview = after.reviews.find(
        (review) => review.id === fixture.seeded.reviewId,
      );
      expect(originalReview).toEqual(before.reviews[0]);
      const reconciliationReview = after.reviews.find(
        (review) => review.id === result.reconciliationReviewId,
      );
      expect(reconciliationReview).toBeDefined();
      expect(reconciliationReview).toMatchObject({
        id: result.reconciliationReviewId,
        action_id: fixture.seeded.actionId,
        job_id: fixture.seeded.jobId,
        decision: expectedDecision,
        reviewer_id: C3A_REVIEWER,
        source: "human",
        reviewed_at: C3A_RECONCILED_AT,
        created_at: C3A_RECONCILED_AT,
        expires_at: null,
        invalidated_at: null,
        invalidation_reason: null,
        scope_hash: before.action.planned_scope_hash,
        policy_hash: before.action.planned_policy_hash,
        action_hash: before.action.planned_action_hash,
        context_hash: before.action.planned_context_hash,
      });
      const persistedAttestation = reconciliationReview?.note as string;
      expect(Array.from(persistedAttestation).length).toBe(2_000);
      expect(persistedAttestation).toContain("Dashboard evidence confirms the final outcome");
      expect(persistedAttestation).not.toContain("c3a-attestation-secret");
      expect(persistedAttestation).not.toContain(C3A_ATTESTATION_HEX);
      expect(persistedAttestation).not.toMatch(/[\uD800-\uDFFF]/u);

      expect(after.action.status).toBe(expectedStatus);
      expect(after.action.outcome_certainty).toBe(expectedCertainty);
      expect(after.action.active_review_id).toBe(fixture.seeded.reviewId);
      expect(after.action.active_review_id).not.toBe(result.reconciliationReviewId);
      expect(after.action.planned_scope_hash).toBe(before.action.planned_scope_hash);
      expect(after.action.planned_policy_hash).toBe(before.action.planned_policy_hash);
      expect(after.action.planned_action_hash).toBe(before.action.planned_action_hash);
      expect(after.action.planned_context_hash).toBe(before.action.planned_context_hash);
      expect(after.action.started_at).toBe(before.action.started_at);
      expect(after.action.dispatch_started_at).toBe(before.action.dispatch_started_at);
      expect(after.action.finished_at).toBe(before.action.finished_at);
      expect(after.action.updated_at).toBe(C3A_RECONCILED_AT);
      expect(after.action.execution_token).toBeNull();
      expect(after.action.execution_owner).toBeNull();
      expect(after.action.lease_expires_at).toBeNull();
      if (expectedStatus === "executed") {
        expect(after.action.executed_at).toBe(C3A_RECONCILED_AT);
        expect(after.action.last_error_code).toBeNull();
        expect(after.action.last_error_message).toBeNull();
      } else {
        expect(after.action.executed_at).toBeNull();
        expect(after.action.last_error_code).toBe(before.action.last_error_code);
        expect(after.action.last_error_message).toBe(before.action.last_error_message);
      }

      expect(after.events).toHaveLength(before.events.length + 1);
      const publicEvent = new WorkflowEventStore(handle).list(fixture.seeded.jobId).at(-1);
      expect(publicEvent).toMatchObject({
        phase: "action-reconciliation",
        status: expectedEventStatus,
        message: "Action outcome reconciled",
        metadata: {
          actionId: fixture.seeded.actionId,
          reconciliationReviewId: result.reconciliationReviewId,
          resolution,
          status: expectedStatus,
        },
      });
      expect(Object.keys(publicEvent?.metadata ?? {}).sort()).toEqual(
        ["actionId", "reconciliationReviewId", "resolution", "status"].sort(),
      );
      expect(JSON.stringify(publicEvent)).not.toContain("Dashboard evidence");
      expect(JSON.stringify(publicEvent)).not.toContain("c3a-attestation-secret");
      expect(JSON.stringify(publicEvent)).not.toContain(C3A_ATTESTATION_HEX);
      expect(JSON.stringify(publicEvent)).not.toContain(fixture.token);
      expect(JSON.stringify(publicEvent)).not.toContain(fixture.owner);

      const publicJob = new JobManager(handle).get(fixture.seeded.jobId);
      expect(publicJob?.status).toBe(expectedJobStatus);
      expect(publicJob?.pauseReason).toBeNull();
      expect(JSON.stringify(publicJob)).not.toContain(fixture.token);
      expect(result.action).toEqual(new ActionQueue(handle).get(fixture.seeded.actionId));
    },
  );
});

// ===========================================================================
// P0.2 Packet 2 Slice C3-A2.1 - historical provenance fail-closed matrix
// ===========================================================================

interface C3AProvenanceMutation {
  name: string;
  code: "ACTION_REVIEW_INVALID" | "ACTION_RECORD_INVALID";
  mutate: (
    handle: BountyDatabase,
    fixture: ReturnType<typeof c2aClaimedFixture>,
  ) => void;
}

const C3A_MALFORMED_PROVENANCE_CASES: readonly C3AProvenanceMutation[] = [
  {
    name: "missing active approval link",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE actions SET active_review_id = NULL WHERE id = ?")
        .run(fixture.seeded.actionId);
    },
  },
  {
    name: "action planned hash is malformed",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE actions SET planned_scope_hash = ? WHERE id = ?")
        .run("0".repeat(64), fixture.seeded.actionId);
    },
  },
  {
    name: "original review decision is not approved",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE action_reviews SET decision = 'failed' WHERE id = ?")
        .run(fixture.seeded.reviewId);
    },
  },
  {
    name: "original review points at a different job",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      const otherJob = new JobManager(handle).create("c3a-other-job", "safe");
      handle.prepare("UPDATE action_reviews SET job_id = ? WHERE id = ?")
        .run(otherJob.id, fixture.seeded.reviewId);
    },
  },
  {
    name: "human approval uses the policy reviewer identity",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE action_reviews SET reviewer_id = ? WHERE id = ?")
        .run("system:policy-gate", fixture.seeded.reviewId);
    },
  },
  {
    name: "approval creation and review timestamps differ",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE action_reviews SET created_at = ? WHERE id = ?")
        .run("2099-01-01T00:00:01.000Z", fixture.seeded.reviewId);
    },
  },
  {
    name: "approval expiry is not strictly after review",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE action_reviews SET expires_at = reviewed_at WHERE id = ?")
        .run(fixture.seeded.reviewId);
    },
  },
  {
    name: "historical invalidation has no reason",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE action_reviews SET invalidated_at = ?, invalidation_reason = NULL WHERE id = ?")
        .run("2099-01-01T00:01:30.000Z", fixture.seeded.reviewId);
    },
  },
  {
    name: "historical invalidation reason is unknown",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE action_reviews SET invalidated_at = ?, invalidation_reason = ? WHERE id = ?")
        .run("2099-01-01T00:01:30.000Z", "private_unknown_reason", fixture.seeded.reviewId);
    },
  },
  {
    name: "original review hash differs from the planned action hash",
    code: "ACTION_REVIEW_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE action_reviews SET action_hash = ? WHERE id = ?")
        .run("d".repeat(64), fixture.seeded.reviewId);
    },
  },
  {
    name: "required outcome-unknown action belongs to a terminal job",
    code: "ACTION_RECORD_INVALID",
    mutate: (handle, fixture) => {
      handle.prepare("UPDATE jobs SET status = 'completed' WHERE id = ?")
        .run(fixture.seeded.jobId);
    },
  },
];

describe("C3-A2.1 reconciliation: malformed original approval provenance fails closed", () => {
  it.each(C3A_MALFORMED_PROVENANCE_CASES)(
    "$name returns $code with zero lifecycle writes",
    ({ mutate, code }, index) => {
      const handle = openDb();
      const fixture = c3aOutcomeUnknownFixture(handle, `c3a-provenance-invalid-${index}`);
      mutate(handle, fixture);
      const before = c3aRawState(handle, fixture);
      const allJobsBefore = handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all();
      const sqlProbe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
      const counted = c2aCountingDb(handle, sqlProbe);
      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const lifecycle = c3aLifecycleFor(
        counted,
        fixture.seeded.authority,
        () => new Date(C3A_RECONCILED_AT),
        dependencyProbe,
      );
      const error = c2aErrorCode(() => lifecycle.reconcileOutcome(
        c3aValidInput(fixture.seeded.actionId),
      ));
      expect(error.code).toBe(code);
      expect(error.message).not.toContain(fixture.token);
      expect(error.message).not.toContain(fixture.owner);
      expect(error.message).not.toContain("private_unknown_reason");
      expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
      c2aAssertTokenFreeSelects(sqlProbe.sql);
      expect(c3aRawState(handle, fixture)).toEqual(before);
      expect(handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all()).toEqual(allJobsBefore);
    },
  );
});

describe("C3-A2.1 reconciliation: valid historical provenance remains usable", () => {
  it.each([
    {
      name: "expired approval without invalidation",
      mutate: (handle: BountyDatabase, fixture: ReturnType<typeof c2aClaimedFixture>) => {
        handle.prepare(
          "UPDATE action_reviews SET expires_at = ?, invalidated_at = NULL, invalidation_reason = NULL WHERE id = ?",
        ).run("2099-01-01T00:01:30.000Z", fixture.seeded.reviewId);
      },
    },
    {
      name: "historically invalidated approval that has not expired",
      mutate: (handle: BountyDatabase, fixture: ReturnType<typeof c2aClaimedFixture>) => {
        handle.prepare(
          "UPDATE action_reviews SET invalidated_at = ?, invalidation_reason = ? WHERE id = ?",
        ).run("2099-01-01T00:01:30.000Z", "scope_drift", fixture.seeded.reviewId);
      },
    },
    {
      name: "policy approval provenance",
      mutate: (handle: BountyDatabase, fixture: ReturnType<typeof c2aClaimedFixture>) => {
        handle.prepare(
          "UPDATE action_reviews SET source = 'policy', reviewer_id = ? WHERE id = ?",
        ).run("system:policy-gate", fixture.seeded.reviewId);
      },
    },
  ])("accepts $name without consulting current authority", ({ mutate }, index) => {
    const handle = openDb();
    const fixture = c3aOutcomeUnknownFixture(handle, `c3a-provenance-valid-${index}`);
    mutate(handle, fixture);
    const before = c3aRawState(handle, fixture);
    const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
    const result = c3aLifecycleFor(
      handle,
      fixture.seeded.authority,
      () => new Date(C3A_RECONCILED_AT),
      dependencyProbe,
    ).reconcileOutcome(c3aValidInput(fixture.seeded.actionId));

    expect(result.status).toBe("executed");
    expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
    const after = c3aRawState(handle, fixture);
    expect(after.reviews).toHaveLength(before.reviews.length + 1);
    expect(after.reviews.find((review) => review.id === fixture.seeded.reviewId))
      .toEqual(before.reviews[0]);
    const reconciliationReview = after.reviews.find(
      (review) => review.id === result.reconciliationReviewId,
    );
    expect(reconciliationReview).toMatchObject({
      decision: "executed",
      source: "human",
      reviewer_id: C3A_REVIEWER,
      expires_at: null,
      invalidated_at: null,
      invalidation_reason: null,
    });
    expect(after.action.active_review_id).toBe(fixture.seeded.reviewId);
    expect(after.action.status).toBe("executed");
    expect(new JobManager(handle).get(fixture.seeded.jobId)?.status).toBe("completed");
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C3-A2.2 - reconciliation transactional atomicity
// ===========================================================================

describe("C3-A2.2 reconciliation: silent SQLite write loss rolls back every row", () => {
  it.each([
    { stage: "review" as const, code: "ACTION_RECORD_INVALID" },
    { stage: "action" as const, code: "ACTION_RECONCILIATION_RACE" },
    { stage: "event" as const, code: "WORKFLOW_EVENT_WRITE_FAILED" },
    { stage: "job" as const, code: "JOB_FINALIZE_WRITE_FAILED" },
  ])(
    "RAISE(IGNORE) at the $stage write is observed exactly once as $code and fully rolls back",
    ({ stage, code }, index) => {
      const handle = openDb();
      const fixture = c3aOutcomeUnknownFixture(handle, `c3a-atomic-ignore-${index}`);
      const before = c3aRawState(handle, fixture);
      const allJobsBefore = handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all();
      let ignoredWriteCalls = 0;
      const counterFunction = `c3a_atomicity_counter_${index}`;
      handle.function(counterFunction, () => {
        ignoredWriteCalls += 1;
        return 1;
      });

      if (stage === "review") {
        handle.exec(`
          CREATE TEMP TRIGGER c3a_ignore_reconciliation_review_${index}
          BEFORE INSERT ON action_reviews
          FOR EACH ROW
          WHEN NEW.action_id = '${fixture.seeded.actionId}'
            AND NEW.decision IN ('executed', 'failed')
          BEGIN
            SELECT ${counterFunction}();
            SELECT RAISE(IGNORE);
          END;
        `);
      } else if (stage === "action") {
        handle.exec(`
          CREATE TEMP TRIGGER c3a_ignore_reconciliation_action_${index}
          BEFORE UPDATE ON actions
          FOR EACH ROW
          WHEN OLD.id = '${fixture.seeded.actionId}'
            AND OLD.status = 'outcome_unknown'
            AND NEW.status IN ('executed', 'failed')
          BEGIN
            SELECT ${counterFunction}();
            SELECT RAISE(IGNORE);
          END;
        `);
      } else if (stage === "event") {
        handle.exec(`
          CREATE TEMP TRIGGER c3a_ignore_reconciliation_event_${index}
          BEFORE INSERT ON workflow_events
          FOR EACH ROW
          WHEN NEW.job_id = '${fixture.seeded.jobId}'
            AND NEW.phase = 'action-reconciliation'
          BEGIN
            SELECT ${counterFunction}();
            SELECT RAISE(IGNORE);
          END;
        `);
      } else {
        handle.exec(`
          CREATE TEMP TRIGGER c3a_ignore_reconciliation_job_${index}
          BEFORE UPDATE ON jobs
          FOR EACH ROW
          WHEN OLD.id = '${fixture.seeded.jobId}'
          BEGIN
            SELECT ${counterFunction}();
            SELECT RAISE(IGNORE);
          END;
        `);
      }

      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const error = c2aErrorCode(() => c3aLifecycleFor(
        handle,
        fixture.seeded.authority,
        () => new Date(C3A_RECONCILED_AT),
        dependencyProbe,
      ).reconcileOutcome(c3aValidInput(fixture.seeded.actionId)));
      expect(error.code).toBe(code);
      expect(Object.prototype.hasOwnProperty.call(error, "cause")).toBe(false);
      expect(error.message).not.toContain(fixture.token);
      expect(error.message).not.toContain(fixture.owner);
      expect(ignoredWriteCalls).toBe(1);
      expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
      expect(c3aRawState(handle, fixture)).toEqual(before);
      expect(handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all()).toEqual(allJobsBefore);
    },
  );
});

describe("C3-A2.2 reconciliation: database faults and COMMIT failure are never hidden", () => {
  it.each([
    {
      stage: "review insert",
      matches: (sql: string) => /INSERT\s+INTO\s+action_reviews/i.test(sql),
    },
    {
      stage: "action CAS",
      matches: (sql: string) =>
        /UPDATE\s+actions[\s\S]*SET\s+status\s*=\s*'executed'/i.test(sql),
    },
    {
      stage: "event insert",
      matches: (sql: string) => /INSERT\s+INTO\s+workflow_events/i.test(sql),
    },
    {
      stage: "job update",
      matches: (sql: string) => /UPDATE\s+jobs\s+SET\s+status/i.test(sql),
    },
  ])("a thrown $stage fault propagates exactly and rolls back review/action/event/job", ({ stage, matches }, index) => {
    const handle = openDb();
    const fixture = c3aOutcomeUnknownFixture(handle, `c3a-atomic-fault-${index}`);
    const before = c3aRawState(handle, fixture);
    const allJobsBefore = handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all();
    const fault = new Error(`C3A_${stage.toUpperCase().replaceAll(" ", "_")}_FAULT`);
    const faulting = c1bcFaultingPrepareProxy(handle, matches, fault, () => undefined);
    const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
    let captured: unknown;
    try {
      c3aLifecycleFor(
        faulting,
        fixture.seeded.authority,
        () => new Date(C3A_RECONCILED_AT),
        dependencyProbe,
      ).reconcileOutcome(c3aValidInput(fixture.seeded.actionId));
    } catch (error) {
      captured = error;
    }
    expect(captured).toBe(fault);
    expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
    expect(String(captured)).not.toContain(fixture.token);
    expect(String(captured)).not.toContain(fixture.owner);
    expect(c3aRawState(handle, fixture)).toEqual(before);
    expect(handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all()).toEqual(allJobsBefore);
  });

  it("COMMIT failure wins over a successful reconciliation and ROLLBACK restores every row", () => {
    const handle = openDb();
    const fixture = c3aOutcomeUnknownFixture(handle, "c3a-atomic-commit");
    const before = c3aRawState(handle, fixture);
    const allJobsBefore = handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all();
    const sentinel = new Error("C3A_RECONCILIATION_COMMIT_FAULT");
    const seen: string[] = [];
    const commitFaultDb = new Proxy(handle, {
      get(target, property): unknown {
        if (property === "exec") {
          return (sql: string): void => {
            const command = sql.trim().toUpperCase();
            seen.push(command);
            if (command === "COMMIT") throw sentinel;
            target.exec(sql);
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function"
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    }) as BountyDatabase;
    const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
    let captured: unknown;
    try {
      c3aLifecycleFor(
        commitFaultDb,
        fixture.seeded.authority,
        () => new Date(C3A_RECONCILED_AT),
        dependencyProbe,
      ).reconcileOutcome(c3aValidInput(fixture.seeded.actionId));
    } catch (error) {
      captured = error;
    }
    expect(captured).toBe(sentinel);
    expect(seen).toEqual(["BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"]);
    expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
    expect(String(captured)).not.toContain(fixture.token);
    expect(String(captured)).not.toContain(fixture.owner);
    expect(c3aRawState(handle, fixture)).toEqual(before);
    expect(handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all()).toEqual(allJobsBefore);
  });
});

// ===========================================================================
// P0.2 Packet 2 Slice C3-A2.3 - locked-source CAS and final race coverage
// ===========================================================================

describe("C3-A2.3 reconciliation: the terminal CAS re-proves locked provenance", () => {
  it.each([
    { mutation: "original approval provenance" as const },
    { mutation: "pre-existing executed_at" as const },
  ])(
    "a reconciliation-review trigger that changes $mutation causes ACTION_RECONCILIATION_RACE and full rollback",
    ({ mutation }, index) => {
      const handle = openDb();
      const fixture = c3aOutcomeUnknownFixture(handle, `c3a-cas-reproof-${index}`);
      const before = c3aRawState(handle, fixture);
      const allJobsBefore = handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all();
      let triggerCalls = 0;
      const counterFunction = `c3a_cas_reproof_counter_${index}`;
      handle.function(counterFunction, () => {
        triggerCalls += 1;
        return 1;
      });
      const mutationSql = mutation === "original approval provenance"
        ? `UPDATE action_reviews
             SET context_hash = '${"e".repeat(64)}'
             WHERE id = '${fixture.seeded.reviewId}';`
        : `UPDATE actions
             SET executed_at = '2099-01-01T00:01:59.000Z'
             WHERE id = '${fixture.seeded.actionId}';`;
      handle.exec(`
        CREATE TEMP TRIGGER c3a_mutate_before_reconciliation_cas_${index}
        BEFORE INSERT ON action_reviews
        FOR EACH ROW
        WHEN NEW.action_id = '${fixture.seeded.actionId}'
          AND NEW.decision IN ('executed', 'failed')
        BEGIN
          SELECT ${counterFunction}();
          ${mutationSql}
        END;
      `);

      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      let captured: unknown;
      try {
        c3aLifecycleFor(
          handle,
          fixture.seeded.authority,
          () => new Date(C3A_RECONCILED_AT),
          dependencyProbe,
        ).reconcileOutcome(c3aValidInput(fixture.seeded.actionId));
      } catch (error) {
        captured = error;
      }

      expect(triggerCalls).toBe(1);
      expect(captured).toBeInstanceOf(BountyPilotError);
      expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
      expect(c3aRawState(handle, fixture)).toEqual(before);
      expect(handle.prepare("SELECT * FROM jobs ORDER BY id ASC").all()).toEqual(allJobsBefore);
      if (!(captured instanceof BountyPilotError)) return;
      expect(captured.code).toBe("ACTION_RECONCILIATION_RACE");
      expect(Object.prototype.hasOwnProperty.call(captured, "cause")).toBe(false);
      expect(captured.message).not.toContain(fixture.token);
      expect(captured.message).not.toContain(fixture.owner);
    },
  );
});

const C3A_RECOVERY_RECONCILED_AT = "2099-01-01T00:05:00.000Z";

describe("C3-A2.3 reconciliation: recovery-derived audit slots remain immutable provenance", () => {
  it.each([
    {
      name: "missing started_at",
      startedAt: null,
      dispatchStartedAt: null,
      resolution: "effect_confirmed" as const,
      expectedStatus: "executed" as const,
    },
    {
      name: "malformed started_at",
      startedAt: "not-a-canonical-start",
      dispatchStartedAt: null,
      resolution: "no_successful_effect_confirmed" as const,
      expectedStatus: "failed" as const,
    },
    {
      name: "malformed dispatch_started_at",
      startedAt: C1A_CLAIMED_AT,
      dispatchStartedAt: "not-a-canonical-dispatch",
      resolution: "effect_confirmed" as const,
      expectedStatus: "executed" as const,
    },
  ])(
    "an outcome_unknown recovered from $name can be reconciled while preserving both raw slots",
    ({ startedAt, dispatchStartedAt, resolution, expectedStatus }, index) => {
      const handle = openDb();
      const fixture = c2aClaimedFixture(handle, `c3a-recovered-slots-${index}`);
      handle.prepare(
        "UPDATE actions SET started_at = ?, dispatch_started_at = ? WHERE id = ?",
      ).run(startedAt, dispatchStartedAt, fixture.seeded.actionId);

      const recovered = c2aLifecycleFor(
        handle,
        fixture,
        () => new Date(C2B_RECOVERED_AT),
      ).recoverExpiredLease(fixture.seeded.actionId);
      expect(recovered).toEqual({ kind: "recovered", status: "outcome_unknown" });
      const before = c3aRawState(handle, fixture);
      expect(before.action.started_at).toBe(startedAt);
      expect(before.action.dispatch_started_at).toBe(dispatchStartedAt);
      expect(before.action.finished_at).toBe(C2B_RECOVERED_AT);
      expect(before.action.outcome_certainty).toBe("possibly_dispatched");

      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const result = c3aLifecycleFor(
        handle,
        fixture.seeded.authority,
        () => new Date(C3A_RECOVERY_RECONCILED_AT),
        dependencyProbe,
      ).reconcileOutcome(c3aValidInput(fixture.seeded.actionId, resolution));
      expect(result.status).toBe(expectedStatus);
      expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });

      const after = c3aRawState(handle, fixture);
      expect(after.action.started_at).toBe(before.action.started_at);
      expect(after.action.dispatch_started_at).toBe(before.action.dispatch_started_at);
      expect(after.action.finished_at).toBe(before.action.finished_at);
      expect(after.action.active_review_id).toBe(before.action.active_review_id);
      expect(after.action.planned_scope_hash).toBe(before.action.planned_scope_hash);
      expect(after.action.planned_policy_hash).toBe(before.action.planned_policy_hash);
      expect(after.action.planned_action_hash).toBe(before.action.planned_action_hash);
      expect(after.action.planned_context_hash).toBe(before.action.planned_context_hash);
      expect(after.action.updated_at).toBe(C3A_RECOVERY_RECONCILED_AT);
      expect(after.reviews).toHaveLength(before.reviews.length + 1);
      expect(after.events).toHaveLength(before.events.length + 1);
      expect(JSON.stringify(result)).not.toContain(fixture.token);
      expect(JSON.stringify(result)).not.toContain(fixture.owner);
    },
  );
});

describe("C3-A2.3 reconciliation: remaining marker/resolution cross-product is token-free", () => {
  it.each([
    {
      name: "unmarked effect confirmation",
      marked: false,
      resolution: "effect_confirmed" as const,
      expectedStatus: "executed" as const,
      expectedDecision: "executed" as const,
      expectedEventStatus: "completed" as const,
    },
    {
      name: "marked no-success confirmation",
      marked: true,
      resolution: "no_successful_effect_confirmed" as const,
      expectedStatus: "failed" as const,
      expectedDecision: "failed" as const,
      expectedEventStatus: "failed" as const,
    },
  ])(
    "$name preserves the marker independently of resolution and leaks no raw metadata/token",
    ({ marked, resolution, expectedStatus, expectedDecision, expectedEventStatus }, index) => {
      const handle = openDb();
      const fixture = c3aOutcomeUnknownFixture(
        handle,
        `c3a-cross-product-${index}`,
        { marked },
      );
      const privateMetadataSecret = `c3a-metadata-secret-${index}`;
      handle.prepare("UPDATE actions SET metadata_json = ? WHERE id = ?").run(
        JSON.stringify({
          api_key: privateMetadataSecret,
          bearer: fixture.token,
          publicFinding: "visible reconciliation metadata",
        }),
        fixture.seeded.actionId,
      );
      const before = c3aRawState(handle, fixture);
      const sqlProbe: C2ASqlProbe = { prepare: 0, exec: 0, sql: [] };
      const counted = c2aCountingDb(handle, sqlProbe);
      const dependencyProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const result = c3aLifecycleFor(
        counted,
        fixture.seeded.authority,
        () => new Date(C3A_RECONCILED_AT),
        dependencyProbe,
      ).reconcileOutcome({
        actionId: fixture.seeded.actionId,
        reviewerId: C3A_REVIEWER,
        attestation: `Human evidence remains meaningful after token ${fixture.token}`,
        resolution,
      });

      expect(result.status).toBe(expectedStatus);
      expect(dependencyProbe).toEqual({ authority: 0, clock: 1, token: 0 });
      c2aAssertTokenFreeSelects(sqlProbe.sql);
      expect(sqlProbe.sql.join("\n")).not.toContain(fixture.token);

      const after = c3aRawState(handle, fixture);
      expect(after.action.dispatch_started_at).toBe(before.action.dispatch_started_at);
      expect(after.action.status).toBe(expectedStatus);
      const reconciliationReview = after.reviews.find(
        (review) => review.id === result.reconciliationReviewId,
      );
      expect(reconciliationReview).toMatchObject({
        decision: expectedDecision,
        source: "human",
      });
      expect(String(reconciliationReview?.note)).not.toContain(fixture.token);

      const rawEvent = after.events.at(-1);
      expect(rawEvent).toMatchObject({
        phase: "action-reconciliation",
        status: expectedEventStatus,
        message: "Action outcome reconciled",
      });
      const rawEventMetadata = JSON.parse(String(rawEvent?.metadata_json)) as Record<string, unknown>;
      expect(rawEventMetadata).toEqual({
        actionId: fixture.seeded.actionId,
        reconciliationReviewId: result.reconciliationReviewId,
        resolution,
        status: expectedStatus,
      });
      expect(Object.keys(rawEventMetadata).sort()).toEqual(
        ["actionId", "reconciliationReviewId", "resolution", "status"].sort(),
      );

      const publicAction = new ActionQueue(handle).get(fixture.seeded.actionId);
      const publicReviews = new ActionReviewStore(handle).listForAction(fixture.seeded.actionId);
      const publicEvents = new WorkflowEventStore(handle).list(fixture.seeded.jobId);
      const publicJob = new JobManager(handle).get(fixture.seeded.jobId);
      expect(publicAction?.metadata).toMatchObject({
        api_key: "[REDACTED]",
        bearer: "[REDACTED]",
        publicFinding: "visible reconciliation metadata",
      });
      for (const output of [result, publicAction, publicReviews, publicEvents, publicJob, rawEventMetadata]) {
        const serialized = JSON.stringify(output);
        expect(serialized).not.toContain(privateMetadataSecret);
        expect(serialized).not.toContain(fixture.token);
        expect(serialized).not.toContain(fixture.owner);
      }
    },
  );
});

// ===========================================================================
// P0.2 Packet 2 Slice C3-A2.4 - true two-handle reconciliation race
// ===========================================================================

describe("C3-A2.4 reconciliation: two independent handles race after preflight", () => {
  const TEST_TIMEOUT_MS = 30_000;
  const BARRIER_TIMEOUT_MS = 15_000;

  type ReconciliationRaceCounts = {
    authority: number;
    clock: number;
    token: number;
  };

  type ReconciliationRaceOutcome =
    | {
        kind: "success";
        role: "a" | "b";
        reviewerId: string;
        status: string;
        reconciliationReviewId: string;
        counts: ReconciliationRaceCounts;
      }
    | {
        kind: "error";
        role: "a" | "b";
        reviewerId: string;
        code: string | null;
        message: string;
        serialization: string;
        counts: ReconciliationRaceCounts;
      };

  function launchReconciliationWorker(input: {
    role: "a" | "b";
    actionId: string;
    dbPath: string;
    barrier: SharedArrayBuffer;
    reviewerId: string;
  }): { worker: Worker; outcome: Promise<ReconciliationRaceOutcome> } {
    // The clock is the synchronization point because reconcileOutcome invokes
    // it exactly once after the token-free status preflight and immediately
    // before BEGIN IMMEDIATE. Both independent callers therefore prove they
    // observed outcome_unknown before either can acquire the write lock.
    const source = `
      const { parentPort, workerData } = require('node:worker_threads');
      const { DatabaseSync } = require('node:sqlite');
      const { tsImport } = require('tsx/esm/api');
      const i32 = new Int32Array(workerData.barrier);
      const counts = { authority: 0, clock: 0, token: 0 };

      function meetAfterPreflight() {
        const arrived = Atomics.add(i32, 0, 1) + 1;
        if (arrived === 2) {
          Atomics.store(i32, 1, 1);
          Atomics.notify(i32, 1, Infinity);
          return;
        }
        const deadline = Date.now() + workerData.barrierTimeoutMs;
        while (Atomics.load(i32, 1) !== 1) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) throw new Error('C3A reconciliation barrier timeout');
          const current = Atomics.load(i32, 1);
          Atomics.wait(i32, 1, current, Math.min(50, remaining));
        }
      }

      let db = null;
      let payload;
      (async () => {
        try {
          const { ActionLifecycle } = await tsImport(workerData.moduleUrl, workerData.parentUrl);
          db = new DatabaseSync(workerData.dbPath);
          db.exec('PRAGMA busy_timeout = 10000;');
          db.exec('PRAGMA foreign_keys = ON;');
          const lifecycle = new ActionLifecycle(db, {
            loadCurrentProgram: () => {
              counts.authority += 1;
              throw new Error('C3A authority dependency must not run');
            },
            resolveBindingMaterial: () => {
              counts.authority += 1;
              throw new Error('C3A resolver dependency must not run');
            },
            now: () => {
              counts.clock += 1;
              meetAfterPreflight();
              return new Date(workerData.nowIso);
            },
            generateExecutionToken: () => {
              counts.token += 1;
              throw new Error('C3A token dependency must not run');
            },
          });
          const result = lifecycle.reconcileOutcome({
            actionId: workerData.actionId,
            reviewerId: workerData.reviewerId,
            attestation: 'Human verified the outcome in the trusted system of record',
            resolution: 'effect_confirmed',
          });
          payload = {
            kind: 'success',
            role: workerData.role,
            reviewerId: workerData.reviewerId,
            status: result.status,
            reconciliationReviewId: result.reconciliationReviewId,
            counts,
          };
        } catch (error) {
          const isObject = error !== null && typeof error === 'object';
          const code = isObject && typeof error.code === 'string' ? error.code : null;
          const message = isObject && typeof error.message === 'string'
            ? error.message
            : String(error);
          let serialization;
          try { serialization = JSON.stringify(error); } catch (_) { serialization = String(error); }
          if (typeof serialization !== 'string') serialization = String(error);
          payload = {
            kind: 'error',
            role: workerData.role,
            reviewerId: workerData.reviewerId,
            code,
            message,
            serialization,
            counts,
          };
        } finally {
          if (db) {
            try { db.close(); } catch (_) { /* best effort */ }
          }
        }
        parentPort.postMessage(payload);
      })();
    `;

    const worker = new Worker(source, {
      eval: true,
      workerData: {
        moduleUrl: new URL("../src/core/actions/action-lifecycle.ts", import.meta.url).href,
        parentUrl: import.meta.url,
        dbPath: input.dbPath,
        actionId: input.actionId,
        role: input.role,
        reviewerId: input.reviewerId,
        barrier: input.barrier,
        barrierTimeoutMs: BARRIER_TIMEOUT_MS,
        nowIso: C3A_RECONCILED_AT,
      },
    });

    const outcome = new Promise<ReconciliationRaceOutcome>((resolve, reject) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error(`C3A ${input.role} reconciliation worker timed out`));
      }, TEST_TIMEOUT_MS - 5_000);
      worker.once("message", (message: ReconciliationRaceOutcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve(message);
      });
      worker.once("error", (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        reject(error);
      });
      worker.once("exit", (code) => {
        if (settled || code === 0) return;
        settled = true;
        clearTimeout(timeout);
        reject(new Error(`C3A ${input.role} reconciliation worker exited with code ${code}`));
      });
    });
    return { worker, outcome };
  }

  it("commits one human attestation and makes the stale caller fail with ACTION_RECONCILIATION_RACE", async () => {
    const handle = openDb();
    const fixture = c3aOutcomeUnknownFixture(handle, "c3a-two-handle-race", { marked: true });
    const before = c3aRawState(handle, fixture);
    handle.close();
    db = null;

    const barrier = new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT);
    const cells = new Int32Array(barrier);
    const first = launchReconciliationWorker({
      role: "a",
      actionId: fixture.seeded.actionId,
      dbPath: dbFile,
      barrier,
      reviewerId: "researcher-c3a-race-a",
    });
    const second = launchReconciliationWorker({
      role: "b",
      actionId: fixture.seeded.actionId,
      dbPath: dbFile,
      barrier,
      reviewerId: "researcher-c3a-race-b",
    });

    let outcomes: ReconciliationRaceOutcome[];
    try {
      outcomes = await Promise.all([first.outcome, second.outcome]);
    } finally {
      await Promise.allSettled([first.worker.terminate(), second.worker.terminate()]);
    }

    expect(Atomics.load(cells, 0)).toBe(2);
    expect(Atomics.load(cells, 1)).toBe(1);
    const winners = outcomes.filter(
      (outcome): outcome is Extract<ReconciliationRaceOutcome, { kind: "success" }> =>
        outcome.kind === "success",
    );
    const losers = outcomes.filter(
      (outcome): outcome is Extract<ReconciliationRaceOutcome, { kind: "error" }> =>
        outcome.kind === "error",
    );
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    const winner = winners[0]!;
    const loser = losers[0]!;
    expect(winner.status).toBe("executed");
    expect(loser.code).toBe("ACTION_RECONCILIATION_RACE");
    expect(winner.counts).toEqual({ authority: 0, clock: 1, token: 0 });
    expect(loser.counts).toEqual({ authority: 0, clock: 1, token: 0 });
    expect(loser.message).not.toContain(fixture.token);
    expect(loser.serialization).not.toContain(fixture.token);

    const verify = openBountyDatabase(dbFile);
    try {
      const action = readActionRow(verify, fixture.seeded.actionId);
      expect(action).toMatchObject({
        status: "executed",
        active_review_id: fixture.seeded.reviewId,
        executed_at: C3A_RECONCILED_AT,
        updated_at: C3A_RECONCILED_AT,
      });

      const reviews = verify
        .prepare("SELECT * FROM action_reviews WHERE action_id = ? ORDER BY rowid ASC")
        .all(fixture.seeded.actionId) as Array<Record<string, unknown>>;
      expect(reviews).toHaveLength(before.reviews.length + 1);
      expect(reviews.filter((review) => review.decision === "executed")).toHaveLength(1);
      const reconciliationReview = reviews.find(
        (review) => review.id === winner.reconciliationReviewId,
      );
      expect(reconciliationReview).toMatchObject({
        action_id: fixture.seeded.actionId,
        job_id: fixture.seeded.jobId,
        decision: "executed",
        reviewer_id: winner.reviewerId,
        source: "human",
        reviewed_at: C3A_RECONCILED_AT,
        created_at: C3A_RECONCILED_AT,
        expires_at: null,
        invalidated_at: null,
        invalidation_reason: null,
      });
      expect(reviews.some((review) => review.reviewer_id === loser.reviewerId)).toBe(false);

      const events = verify
        .prepare(
          "SELECT * FROM workflow_events WHERE job_id = ? AND phase = 'action-reconciliation'",
        )
        .all(fixture.seeded.jobId) as Array<Record<string, unknown>>;
      expect(events).toHaveLength(1);
      expect(new JobManager(verify).get(fixture.seeded.jobId)?.status).toBe("completed");

      // A caller arriving after the winner committed sees the public terminal
      // classification before the clock and cannot create any new evidence.
      const thirdProbe: C3ADependencyProbe = { authority: 0, clock: 0, token: 0 };
      const thirdError = c2aErrorCode(() => c3aLifecycleFor(
        verify,
        fixture.seeded.authority,
        () => { throw new Error("C3A third caller clock must not run"); },
        thirdProbe,
      ).reconcileOutcome(c3aValidInput(fixture.seeded.actionId)));
      expect(thirdError.code).toBe("ACTION_TERMINAL");
      expect(thirdProbe).toEqual({ authority: 0, clock: 0, token: 0 });
      expect(
        verify.prepare("SELECT COUNT(*) AS count FROM action_reviews WHERE action_id = ?")
          .get(fixture.seeded.actionId),
      ).toEqual({ count: before.reviews.length + 1 });
      expect(
        verify.prepare(
          "SELECT COUNT(*) AS count FROM workflow_events WHERE job_id = ? AND phase = 'action-reconciliation'",
        ).get(fixture.seeded.jobId),
      ).toEqual({ count: 1 });
    } finally {
      try { verify.close(); } catch { /* best effort */ }
    }
  }, TEST_TIMEOUT_MS);
});
