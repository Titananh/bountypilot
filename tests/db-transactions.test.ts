import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Worker } from "node:worker_threads";
import {
  openBountyDatabase,
  withImmediateTransaction,
  type BountyDatabase,
} from "../src/stores/db/database.js";
import { BountyPilotError } from "../src/utils/errors.js";

class FakeDatabase {
  execLog: string[] = [];
  inTransaction = false;
  failOnCommit = false;
  failOnRollback = false;
  commitError: Error | null = null;
  rollbackError: Error | null = null;

  private static normalize(sql: string): string {
    return sql.trim().replace(/;$/, "").replace(/\s+/g, " ").toUpperCase();
  }

  exec(sql: string): void {
    const normalized = FakeDatabase.normalize(sql);
    this.execLog.push(normalized);
    if (normalized === "BEGIN IMMEDIATE") {
      if (this.inTransaction) {
        throw new Error("SQLITE_ERROR: cannot start a transaction within a transaction");
      }
      this.inTransaction = true;
      return;
    }
    if (normalized === "BEGIN") {
      throw new Error("SQLITE_ERROR: helper requires BEGIN IMMEDIATE, received BEGIN");
    }
    if (normalized === "COMMIT") {
      if (this.failOnCommit) {
        throw this.commitError ?? new Error("commit failed");
      }
      this.inTransaction = false;
      return;
    }
    if (normalized === "ROLLBACK") {
      if (this.failOnRollback) {
        throw this.rollbackError ?? new Error("rollback failed");
      }
      this.inTransaction = false;
      return;
    }
  }
}

let tmpDir = "";
let dbFile = "";
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
      // best-effort cleanup
    }
    db = null;
  }
}

beforeEach(() => {
  tmpDir = mkdtempSync(path.join(tmpdir(), "bountypilot-tx-"));
  dbFile = path.join(tmpDir, "bounty.db");
});

afterEach(() => {
  closeDb();
  if (tmpDir && existsSync(tmpDir)) {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

describe("withImmediateTransaction", () => {
  it("issues BEGIN IMMEDIATE first, ends with COMMIT, returns callback result (FakeDatabase)", () => {
    const fake = new FakeDatabase();
    const sentinel = { kind: "tx-sentinel" };
    const result = withImmediateTransaction(fake as unknown as BountyDatabase, () => sentinel);
    expect(result).toBe(sentinel);
    expect(fake.execLog[0]).toBe("BEGIN IMMEDIATE");
    expect(fake.execLog[fake.execLog.length - 1]).toBe("COMMIT");
    expect(fake.inTransaction).toBe(false);
  });

  it("commits a normal callback, returns the sentinel, and persists inserts", () => {
    const handle = openDb();
    handle.exec("CREATE TABLE t (n INTEGER)");
    const sentinel = { kind: "tx-sentinel" };
    const result = withImmediateTransaction(handle, () => {
      handle.exec("INSERT INTO t VALUES (1)");
      return sentinel;
    });
    expect(result).toBe(sentinel);
    const rows = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(rows.map((row) => row.n)).toEqual([1]);
    const after = withImmediateTransaction(handle, () => "post-commit");
    expect(after).toBe("post-commit");
  });

  it("propagates the exact callback error, rolls back, and clears the guard for a healthy second call", () => {
    const handle = openDb();
    handle.exec("CREATE TABLE t (n INTEGER)");
    const sentinel = new Error("sentinel");
    let thrown: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        handle.exec("INSERT INTO t VALUES (1)");
        throw sentinel;
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBe(sentinel);
    const rows = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(rows).toEqual([]);
    const after = withImmediateTransaction(handle, () => {
      handle.exec("INSERT INTO t VALUES (2)");
      return 2;
    });
    expect(after).toBe(2);
    const all = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(all.map((row) => row.n)).toEqual([2]);
  });

  it("rolls back, raises DB_TRANSACTION_THENABLE, and a healthy follow-up call still commits", () => {
    const handle = openDb();
    handle.exec("CREATE TABLE t (n INTEGER)");
    let thrown: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        handle.exec("INSERT INTO t VALUES (1)");
        return Promise.resolve("ignored");
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(BountyPilotError);
    expect((thrown as BountyPilotError).code).toBe("DB_TRANSACTION_THENABLE");
    const rows = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(rows).toEqual([]);
    const after = withImmediateTransaction(handle, () => {
      handle.exec("INSERT INTO t VALUES (3)");
      return "recovered";
    });
    expect(after).toBe("recovered");
    const all = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(all.map((row) => row.n)).toEqual([3]);
  });

  it("rolls back, raises DB_TRANSACTION_THENABLE for custom thenable, never invokes .then, and a follow-up commits", () => {
    const handle = openDb();
    handle.exec("CREATE TABLE t (n INTEGER)");
    let thenCalled = false;
    const custom = {
      then: () => {
        thenCalled = true;
        return undefined;
      },
    };
    let thrown: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        handle.exec("INSERT INTO t VALUES (1)");
        return custom;
      });
    } catch (err) {
      thrown = err;
    }
    expect(thenCalled).toBe(false);
    expect(thrown).toBeInstanceOf(BountyPilotError);
    expect((thrown as BountyPilotError).code).toBe("DB_TRANSACTION_THENABLE");
    const rows = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(rows).toEqual([]);
    const after = withImmediateTransaction(handle, () => {
      handle.exec("INSERT INTO t VALUES (4)");
      return "ok";
    });
    expect(after).toBe("ok");
  });

  it("rolls back, preserves a throwing then-getter error, clears the guard, and allows recovery", () => {
    const handle = openDb();
    handle.exec("CREATE TABLE t (n INTEGER)");
    const getterError = new Error("then getter exploded");
    let getterReads = 0;
    const poisoned = Object.defineProperty({}, "then", {
      get(): never {
        getterReads += 1;
        throw getterError;
      },
    });
    let thrown: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        handle.exec("INSERT INTO t VALUES (1)");
        return poisoned;
      });
    } catch (err) {
      thrown = err;
    }
    expect(getterReads).toBe(1);
    expect(thrown).toBe(getterError);
    expect(handle.prepare("SELECT n FROM t").all()).toEqual([]);
    const recovered = withImmediateTransaction(handle, () => {
      handle.exec("INSERT INTO t VALUES (5)");
      return "recovered";
    });
    expect(recovered).toBe("recovered");
    expect(handle.prepare("SELECT n FROM t").all()).toEqual([{ n: 5 }]);
  });

  it("rejects nested calls with DB_TRANSACTION_NESTED, never runs inner, and outer commits", () => {
    const handle = openDb();
    handle.exec("CREATE TABLE t (n INTEGER)");
    let innerCalled = false;
    let caught: unknown = null;
    const outer = withImmediateTransaction(handle, () => {
      try {
        withImmediateTransaction(handle, () => {
          innerCalled = true;
        });
      } catch (err) {
        caught = err;
      }
      handle.exec("INSERT INTO t VALUES (42)");
      return "outer";
    });
    expect(outer).toBe("outer");
    expect(innerCalled).toBe(false);
    expect(caught).toBeInstanceOf(BountyPilotError);
    expect((caught as BountyPilotError).code).toBe("DB_TRANSACTION_NESTED");
    const rows = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(rows.map((row) => row.n)).toEqual([42]);
  });

  it("does not roll back a manually-started transaction when the helper BEGIN fails", () => {
    const handle = openDb();
    handle.exec("CREATE TABLE t (n INTEGER)");
    handle.exec("BEGIN");
    handle.exec("INSERT INTO t VALUES (7)");
    let callbackCalled = false;
    let thrown: unknown = null;
    try {
      withImmediateTransaction(handle, () => {
        callbackCalled = true;
      });
    } catch (err) {
      thrown = err;
    }
    expect(callbackCalled).toBe(false);
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toMatch(/cannot start.*transaction|within a transaction/i);
    const insideRows = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(insideRows.map((row) => row.n)).toEqual([7]);
    handle.exec("ROLLBACK");
    const afterRows = handle.prepare("SELECT n FROM t").all() as Array<{ n: number }>;
    expect(afterRows).toEqual([]);
    const recovered = withImmediateTransaction(handle, () => {
      handle.exec("INSERT INTO t VALUES (9)");
      return "recovered";
    });
    expect(recovered).toBe("recovered");
    const finalRows = handle.prepare("SELECT n FROM t ORDER BY n ASC").all() as Array<{ n: number }>;
    expect(finalRows.map((row) => row.n)).toEqual([9]);
  });

  it("treats the guard per handle, not globally (two distinct DB files)", () => {
    const dbFileA = path.join(tmpDir, "guard-a.db");
    const dbFileB = path.join(tmpDir, "guard-b.db");
    const handleA = openBountyDatabase(dbFileA);
    const handleB = openBountyDatabase(dbFileB);
    try {
      handleA.exec("CREATE TABLE a (n INTEGER)");
      handleB.exec("CREATE TABLE b (n INTEGER)");
      const outer = withImmediateTransaction(handleA, () => {
        const inner = withImmediateTransaction(handleB, () => {
          handleB.exec("INSERT INTO b VALUES (1)");
          return "inner";
        });
        expect(inner).toBe("inner");
        handleA.exec("INSERT INTO a VALUES (1)");
        return "outer";
      });
      expect(outer).toBe("outer");
      const aRows = handleA.prepare("SELECT n FROM a").all() as Array<{ n: number }>;
      const bRows = handleB.prepare("SELECT n FROM b").all() as Array<{ n: number }>;
      expect(aRows.map((row) => row.n)).toEqual([1]);
      expect(bRows.map((row) => row.n)).toEqual([1]);
    } finally {
      try { handleB.close(); } catch { /* ignore */ }
      try { handleA.close(); } catch { /* ignore */ }
    }
  });

  it("rolls back exactly once and rethrows the exact commit error when COMMIT fails (FakeDatabase)", () => {
    const fake = new FakeDatabase();
    const commitError = new Error("disk full");
    fake.failOnCommit = true;
    fake.commitError = commitError;
    let thrown: unknown = null;
    try {
      withImmediateTransaction(fake as unknown as BountyDatabase, () => 123);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBe(commitError);
    expect(fake.execLog).toEqual(["BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"]);
    expect(fake.inTransaction).toBe(false);
  });

  it("raises DB_TRANSACTION_ROLLBACK_FAILED, leaves the DB active, and clears the WeakSet guard", () => {
    const fake = new FakeDatabase();
    const commitError = new Error("commit boom");
    const rollbackError = new Error("rollback boom");
    fake.failOnCommit = true;
    fake.commitError = commitError;
    fake.failOnRollback = true;
    fake.rollbackError = rollbackError;
    let thrown: unknown = null;
    try {
      withImmediateTransaction(fake as unknown as BountyDatabase, () => "ok");
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(BountyPilotError);
    expect((thrown as BountyPilotError).code).toBe("DB_TRANSACTION_ROLLBACK_FAILED");
    expect(fake.execLog).toEqual(["BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"]);
    expect(fake.inTransaction).toBe(true);
    fake.inTransaction = false;
    fake.failOnCommit = false;
    fake.failOnRollback = false;
    const value = withImmediateTransaction(fake as unknown as BountyDatabase, () => "after");
    expect(value).toBe("after");
    expect(fake.execLog).toEqual([
      "BEGIN IMMEDIATE",
      "COMMIT",
      "ROLLBACK",
      "BEGIN IMMEDIATE",
      "COMMIT",
    ]);
    expect(fake.inTransaction).toBe(false);
  });

  it("callback throw + rollback failure raises DB_TRANSACTION_ROLLBACK_FAILED and isolates guard cleanup", () => {
    const fake = new FakeDatabase();
    const rollbackError = new Error("rollback boom");
    fake.failOnRollback = true;
    fake.rollbackError = rollbackError;
    const sentinel = new Error("callback boom");
    let thrown: unknown = null;
    try {
      withImmediateTransaction(fake as unknown as BountyDatabase, () => {
        throw sentinel;
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(BountyPilotError);
    expect((thrown as BountyPilotError).code).toBe("DB_TRANSACTION_ROLLBACK_FAILED");
    expect(fake.execLog).toEqual(["BEGIN IMMEDIATE", "ROLLBACK"]);
    expect(fake.inTransaction).toBe(true);
    fake.inTransaction = false;
    fake.failOnRollback = false;
    const value = withImmediateTransaction(fake as unknown as BountyDatabase, () => "after");
    expect(value).toBe("after");
    expect(fake.execLog).toEqual([
      "BEGIN IMMEDIATE",
      "ROLLBACK",
      "BEGIN IMMEDIATE",
      "COMMIT",
    ]);
    expect(fake.inTransaction).toBe(false);
  });
});

type CasRole = "holder" | "contender";

type CasMessageKind =
  | "ready"
  | "cas-changes"
  | "callback-entered"
  | "holder-saw-callback"
  | "contender-attempting";

interface CasWorkerMessage {
  kind: CasMessageKind | "worker-error";
  value: number;
  message?: string;
}

interface CasHarnessOutcome {
  holder: CasWorkerMessage[];
  contender: CasWorkerMessage[];
  holderError: string | null;
  contenderError: string | null;
  holderExitCode: number | null;
  contenderExitCode: number | null;
}

const CAS_PARENT_PHASE_TIMEOUT_MS = 5_000;
const CAS_WORKER_WAIT_TIMEOUT_MS = 3_000;
const CAS_HOLD_MS = 100;
const CAS_TEST_TIMEOUT_MS = 15_000;

const CAS_OFFSETS = {
  ready: 0,
  start: 1,
  holderHeld: 2,
  contenderAttempting: 3,
  contenderCallbackEntered: 4,
} as const;

function boundedWait(i32: Int32Array, offset: number, value: number, timeoutMs: number): boolean {
  const deadline = Date.now() + timeoutMs;
  while (Atomics.load(i32, offset) !== value) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      return false;
    }
    const cur = Atomics.load(i32, offset);
    const rc = Atomics.wait(i32, offset, cur, Math.min(50, remaining));
    if (rc === "timed-out" && Date.now() >= deadline) {
      return false;
    }
  }
  return true;
}

function runWorkerCas(
  dbPath: string,
  sab: SharedArrayBuffer,
): Promise<CasHarnessOutcome> {
  return new Promise<CasHarnessOutcome>((resolve, reject) => {
    const moduleUrl = new URL("../src/stores/db/database.ts", import.meta.url).href;
    const source = `
      const { parentPort, workerData } = require('node:worker_threads');
      const { DatabaseSync } = require('node:sqlite');
      const { tsImport } = require('tsx/esm/api');
      const sab = workerData.sab;
      const i32 = new Int32Array(sab);
      const ROLE = workerData.role;
      const ACTION_ID = workerData.actionId;
      const TOKEN = workerData.token;
      const DB_PATH = workerData.dbPath;
      const READY_OFFSET = 0;
      const START_OFFSET = 1;
      const HOLDER_HELD_OFFSET = 2;
      const CONTENDER_ATTEMPTING_OFFSET = 3;
      const CONTENDER_CALLBACK_OFFSET = 4;
      const HOLD_MS = ${CAS_HOLD_MS};
      const WAIT_TIMEOUT_MS = ${CAS_WORKER_WAIT_TIMEOUT_MS};
      function send(payload) { parentPort.postMessage(payload); }
      function waitValue(offset, value) {
        const deadline = Date.now() + WAIT_TIMEOUT_MS;
        while (Atomics.load(i32, offset) !== value) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) { throw new Error('barrier timeout offset=' + offset + ' want=' + value + ' got=' + Atomics.load(i32, offset)); }
          const cur = Atomics.load(i32, offset);
          const rc = Atomics.wait(i32, offset, cur, Math.min(50, remaining));
          if (rc === 'timed-out' && Date.now() >= deadline) {
            throw new Error('barrier timeout offset=' + offset + ' want=' + value + ' got=' + Atomics.load(i32, offset));
          }
        }
      }
      let db = null;
      (async () => {
        try {
          const { withImmediateTransaction } = await tsImport(workerData.moduleUrl, workerData.parentUrl);
          db = new DatabaseSync(DB_PATH);
          db.exec('PRAGMA busy_timeout = 5000;');
          Atomics.store(i32, READY_OFFSET, 1);
          Atomics.notify(i32, READY_OFFSET, Infinity);
          send({ kind: 'ready', value: 1 });
          waitValue(START_OFFSET, 1);
          if (typeof withImmediateTransaction !== 'function') {
            throw new Error('withImmediateTransaction missing');
          }
          if (ROLE === 'holder') {
            let changes = -1;
            withImmediateTransaction(db, () => {
              const update = db.prepare(
                "UPDATE actions SET execution_token = ? WHERE id = ? AND status = 'approved' AND execution_token IS NULL"
              );
              const result = update.run(TOKEN, ACTION_ID);
              changes = Number(result.changes ?? 0);
              Atomics.store(i32, HOLDER_HELD_OFFSET, 1);
              Atomics.notify(i32, HOLDER_HELD_OFFSET, Infinity);
              waitValue(CONTENDER_ATTEMPTING_OFFSET, 1);
              const waitRc = Atomics.wait(i32, HOLDER_HELD_OFFSET, 1, HOLD_MS);
              const contenderFlag = Atomics.load(i32, CONTENDER_CALLBACK_OFFSET);
              send({ kind: 'holder-saw-callback', value: contenderFlag });
              void waitRc;
            });
            send({ kind: 'cas-changes', value: changes });
          } else {
            waitValue(HOLDER_HELD_OFFSET, 1);
            Atomics.store(i32, CONTENDER_ATTEMPTING_OFFSET, 1);
            Atomics.notify(i32, CONTENDER_ATTEMPTING_OFFSET, Infinity);
            send({ kind: 'contender-attempting', value: 1 });
            let changes = -1;
            withImmediateTransaction(db, () => {
              send({ kind: 'callback-entered', value: 1 });
              Atomics.store(i32, CONTENDER_CALLBACK_OFFSET, 1);
              Atomics.notify(i32, CONTENDER_CALLBACK_OFFSET, Infinity);
              const update = db.prepare(
                "UPDATE actions SET execution_token = ? WHERE id = ? AND status = 'approved' AND execution_token IS NULL"
              );
              const result = update.run(TOKEN, ACTION_ID);
              changes = Number(result.changes ?? 0);
            });
            send({ kind: 'cas-changes', value: changes });
          }
        } catch (err) {
          const message = err && err.message ? err.message : String(err);
          parentPort.postMessage({ kind: 'worker-error', value: 0, message });
          throw err;
        } finally {
          if (db) {
            try { db.close(); } catch (_) { /* ignore */ }
          }
        }
      })().catch(() => {
        process.exitCode = 1;
      });
    `;
    let holder: Worker | null = null;
    let contender: Worker | null = null;
    const outcome: CasHarnessOutcome = {
      holder: [],
      contender: [],
      holderError: null,
      contenderError: null,
      holderExitCode: null,
      contenderExitCode: null,
    };
    const wire = (
      worker: Worker,
      bucket: CasWorkerMessage[],
      role: CasRole,
    ): void => {
      worker.on("message", (msg: CasWorkerMessage) => {
        if (msg.kind === "worker-error") {
          if (role === "holder") outcome.holderError = String(msg.message ?? "worker-error");
          else outcome.contenderError = String(msg.message ?? "worker-error");
          return;
        }
        bucket.push({ kind: msg.kind, value: Number(msg.value) });
      });
      worker.on("error", (err) => {
        if (role === "holder") outcome.holderError = err.message;
        else outcome.contenderError = err.message;
      });
      worker.on("messageerror", () => {
        if (role === "holder") outcome.holderError = "messageerror";
        else outcome.contenderError = "messageerror";
      });
      worker.on("exit", (code) => {
        if (role === "holder") outcome.holderExitCode = code;
        else outcome.contenderExitCode = code;
      });
    };
    const teardown = async (): Promise<void> => {
      if (holder) {
        try { await holder.terminate(); } catch (_) { /* ignore */ }
        holder = null;
      }
      if (contender) {
        try { await contender.terminate(); } catch (_) { /* ignore */ }
        contender = null;
      }
    };
    try {
      holder = new Worker(source, {
        eval: true,
        workerData: {
          moduleUrl,
          parentUrl: import.meta.url,
          sab,
          role: "holder" as CasRole,
          token: "holder",
          actionId: "action-cas",
          dbPath,
        },
      });
      wire(holder, outcome.holder, "holder");
      contender = new Worker(source, {
        eval: true,
        workerData: {
          moduleUrl,
          parentUrl: import.meta.url,
          sab,
          role: "contender" as CasRole,
          token: "contender",
          actionId: "action-cas",
          dbPath,
        },
      });
      wire(contender, outcome.contender, "contender");
    } catch (err) {
      void teardown().then(() => reject(err), () => reject(err));
      return;
    }
    const waitForReady = async (): Promise<void> => {
      const start = Date.now();
      while (Date.now() - start < CAS_PARENT_PHASE_TIMEOUT_MS) {
        if (
          outcome.holder.some((m) => m.kind === "ready") &&
          outcome.contender.some((m) => m.kind === "ready")
        ) {
          return;
        }
        await new Promise((r) => setTimeout(r, 10));
      }
      await teardown();
      throw new Error("timeout waiting for workers ready");
    };
    const waitForExit = async (): Promise<void> => {
      const start = Date.now();
      while (Date.now() - start < CAS_PARENT_PHASE_TIMEOUT_MS) {
        if (outcome.holderExitCode !== null && outcome.contenderExitCode !== null) {
          return;
        }
        await new Promise((r) => setTimeout(r, 10));
      }
      await teardown();
      throw new Error("timeout waiting for workers exit");
    };
    (async () => {
      try {
        await waitForReady();
        const i32 = new Int32Array(sab);
        if (i32[CAS_OFFSETS.start] === 0) {
          Atomics.store(i32, CAS_OFFSETS.start, 1);
          Atomics.notify(i32, CAS_OFFSETS.start, Infinity);
        }
        await waitForExit();
        if (outcome.holderExitCode !== 0 || outcome.contenderExitCode !== 0) {
          throw new Error(
            `worker exit codes holder=${outcome.holderExitCode} contender=${outcome.contenderExitCode} holderError=${outcome.holderError ?? "<none>"} contenderError=${outcome.contenderError ?? "<none>"}`,
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

describe("withImmediateTransaction true-concurrency CAS", () => {
  it("serializes contender behind holder and lets exactly one worker claim the action", async () => {
    const handle = openDb();
    handle.exec(
      "INSERT INTO actions (id, job_id, adapter, action_type, target, risk_level, requires_approval, status, metadata_json, created_at, executed_at) VALUES ('action-cas', NULL, 'http', 'GET', 'http://lab.test/', 'low', 0, 'approved', '{}', '2026-01-01T00:00:00.000Z', NULL)",
    );
    handle.close();
    db = null;
    const sab = new SharedArrayBuffer(5 * Int32Array.BYTES_PER_ELEMENT);
    const outcome = await runWorkerCas(dbFile, sab);
    expect(outcome.holderError).toBeNull();
    expect(outcome.contenderError).toBeNull();
    const holderCas = outcome.holder.find((m) => m.kind === "cas-changes");
    const contenderCas = outcome.contender.find((m) => m.kind === "cas-changes");
    expect(holderCas?.value).toBe(1);
    expect(contenderCas?.value).toBe(0);
    const holderSaw = outcome.holder.find((m) => m.kind === "holder-saw-callback");
    expect(holderSaw).toBeDefined();
    expect(holderSaw?.value).toBe(0);
    const contenderAttempting = outcome.contender.some(
      (m) => m.kind === "contender-attempting",
    );
    expect(contenderAttempting).toBe(true);
    const contenderCallbackEntered = outcome.contender.some(
      (m) => m.kind === "callback-entered",
    );
    expect(contenderCallbackEntered).toBe(true);
    const verify = openBountyDatabase(dbFile);
    try {
      const rows = verify
        .prepare("SELECT execution_token FROM actions WHERE id = 'action-cas'")
        .all() as Array<{ execution_token: string | null }>;
      expect(rows[0]?.execution_token).toBe("holder");
    } finally {
      try { verify.close(); } catch (_) { /* ignore */ }
    }
  }, CAS_TEST_TIMEOUT_MS);
});

type SeqMessageKind = "ready" | "result" | "worker-error";
interface SeqWorkerMessage {
  kind: SeqMessageKind;
  value: number;
  message?: string;
}
interface SeqHarnessOutcome {
  a: SeqWorkerMessage[];
  b: SeqWorkerMessage[];
  aError: string | null;
  bError: string | null;
  aExitCode: number | null;
  bExitCode: number | null;
}

const SEQ_PARENT_PHASE_TIMEOUT_MS = 8_000;
const SEQ_WORKER_WAIT_TIMEOUT_MS = 3_000;
const SEQ_ITERATIONS_PER_WORKER = 12;
const SEQ_BARRIER_OFFSETS = { ready: 0, start: 1 } as const;
const SEQ_TEST_TIMEOUT_MS = 25_000;

function runWorkerSeq(
  dbPath: string,
  jobId: string,
  sab: SharedArrayBuffer,
): Promise<SeqHarnessOutcome> {
  return new Promise<SeqHarnessOutcome>((resolve, reject) => {
    const moduleUrl = new URL("../src/stores/db/database.ts", import.meta.url).href;
    const source = `
      const { parentPort, workerData } = require('node:worker_threads');
      const { DatabaseSync } = require('node:sqlite');
      const { tsImport } = require('tsx/esm/api');
      const sab = workerData.sab;
      const i32 = new Int32Array(sab);
      const JOB_ID = workerData.jobId;
      const DB_PATH = workerData.dbPath;
      const ITERATIONS = workerData.iterations;
      const READY_OFFSET = 0;
      const START_OFFSET = 1;
      const CONTENTION_OFFSETS = [2, 3, 4, 5];
      const WAIT_TIMEOUT_MS = ${SEQ_WORKER_WAIT_TIMEOUT_MS};
      function send(payload) { parentPort.postMessage(payload); }
      function waitValue(offset, value) {
        const deadline = Date.now() + WAIT_TIMEOUT_MS;
        while (Atomics.load(i32, offset) !== value) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) { throw new Error('barrier timeout offset=' + offset + ' want=' + value + ' got=' + Atomics.load(i32, offset)); }
          const cur = Atomics.load(i32, offset);
          const rc = Atomics.wait(i32, offset, cur, Math.min(50, remaining));
          if (rc === 'timed-out' && Date.now() >= deadline) {
            throw new Error('barrier timeout offset=' + offset + ' want=' + value + ' got=' + Atomics.load(i32, offset));
          }
        }
      }
      let db = null;
      (async () => {
        try {
          const { withImmediateTransaction } = await tsImport(workerData.moduleUrl, workerData.parentUrl);
          db = new DatabaseSync(DB_PATH);
          db.exec('PRAGMA busy_timeout = 5000;');
          Atomics.store(i32, READY_OFFSET, 1);
          Atomics.notify(i32, READY_OFFSET, Infinity);
          send({ kind: 'ready', value: 1 });
          waitValue(START_OFFSET, 1);
          if (typeof withImmediateTransaction !== 'function') {
            throw new Error('withImmediateTransaction missing');
          }
          const maxStmt = db.prepare('SELECT COALESCE(MAX(sequence), 0) AS m FROM workflow_events WHERE job_id = ?');
          const insert = db.prepare(
            "INSERT INTO workflow_events (id, job_id, sequence, phase, status, message, metadata_json, created_at) VALUES (?, ?, ?, 'recon', 'ok', ?, NULL, ?)"
          );
          for (let i = 0; i < ITERATIONS; i++) {
            const slot = CONTENTION_OFFSETS[i % CONTENTION_OFFSETS.length];
            withImmediateTransaction(db, () => {
              const cur = Atomics.load(i32, slot);
              if (cur === 0) {
                const rc = Atomics.wait(i32, slot, 0, 1);
                void rc;
              }
              const row = maxStmt.get(JOB_ID);
              const next = Number(row.m) + 1;
              const id = JOB_ID + '-' + next + '-' + Math.random().toString(36).slice(2, 10);
              const ts = new Date(Date.now() + next).toISOString();
              insert.run(id, JOB_ID, next, 'iter-' + next, ts);
              send({ kind: 'result', value: next });
              return next;
            });
          }
        } catch (err) {
          const message = err && err.message ? err.message : String(err);
          parentPort.postMessage({ kind: 'worker-error', value: 0, message });
          throw err;
        } finally {
          if (db) {
            try { db.close(); } catch (_) { /* ignore */ }
          }
        }
      })().catch(() => {
        process.exitCode = 1;
      });
    `;
    let a: Worker | null = null;
    let b: Worker | null = null;
    const outcome: SeqHarnessOutcome = {
      a: [],
      b: [],
      aError: null,
      bError: null,
      aExitCode: null,
      bExitCode: null,
    };
    const wire = (
      worker: Worker,
      bucket: SeqWorkerMessage[],
      key: "a" | "b",
    ): void => {
      worker.on("message", (msg: SeqWorkerMessage) => {
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
      worker.on("messageerror", () => {
        if (key === "a") outcome.aError = "messageerror";
        else outcome.bError = "messageerror";
      });
      worker.on("exit", (code) => {
        if (key === "a") outcome.aExitCode = code;
        else outcome.bExitCode = code;
      });
    };
    const teardown = async (): Promise<void> => {
      if (a) {
        try { await a.terminate(); } catch (_) { /* ignore */ }
        a = null;
      }
      if (b) {
        try { await b.terminate(); } catch (_) { /* ignore */ }
        b = null;
      }
    };
    try {
      a = new Worker(source, {
        eval: true,
        workerData: {
          moduleUrl,
          parentUrl: import.meta.url,
          sab,
          jobId,
          iterations: SEQ_ITERATIONS_PER_WORKER,
          dbPath,
          name: "a",
        },
      });
      wire(a, outcome.a, "a");
      b = new Worker(source, {
        eval: true,
        workerData: {
          moduleUrl,
          parentUrl: import.meta.url,
          sab,
          jobId,
          iterations: SEQ_ITERATIONS_PER_WORKER,
          dbPath,
          name: "b",
        },
      });
      wire(b, outcome.b, "b");
    } catch (err) {
      void teardown().then(() => reject(err), () => reject(err));
      return;
    }
    const waitForReady = async (): Promise<void> => {
      const start = Date.now();
      while (Date.now() - start < SEQ_PARENT_PHASE_TIMEOUT_MS) {
        if (outcome.a.some((m) => m.kind === "ready") && outcome.b.some((m) => m.kind === "ready")) {
          return;
        }
        await new Promise((r) => setTimeout(r, 10));
      }
      await teardown();
      throw new Error("timeout waiting for sequence workers ready");
    };
    const waitForExit = async (): Promise<void> => {
      const start = Date.now();
      while (Date.now() - start < SEQ_PARENT_PHASE_TIMEOUT_MS) {
        if (outcome.aExitCode !== null && outcome.bExitCode !== null) {
          return;
        }
        await new Promise((r) => setTimeout(r, 10));
      }
      await teardown();
      throw new Error("timeout waiting for sequence workers exit");
    };
    (async () => {
      try {
        await waitForReady();
        const i32 = new Int32Array(sab);
        if (i32[SEQ_BARRIER_OFFSETS.start] === 0) {
          Atomics.store(i32, SEQ_BARRIER_OFFSETS.start, 1);
          Atomics.notify(i32, SEQ_BARRIER_OFFSETS.start, Infinity);
        }
        await waitForExit();
        if (outcome.aExitCode !== 0 || outcome.bExitCode !== 0) {
          throw new Error(
            `sequence worker exit codes a=${outcome.aExitCode} b=${outcome.bExitCode} aError=${outcome.aError ?? "<none>"} bError=${outcome.bError ?? "<none>"}`,
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

describe("withImmediateTransaction workflow_events sequence atomicity", () => {
  it("two workers, 12 iterations each, produce exactly sequences 1..24 with no gaps", async () => {
    const handle = openDb();
    handle.close();
    db = null;
    const sab = new SharedArrayBuffer(6 * Int32Array.BYTES_PER_ELEMENT);
    const jobId = "job-seq";
    const outcome = await runWorkerSeq(dbFile, jobId, sab);
    expect(outcome.aError).toBeNull();
    expect(outcome.bError).toBeNull();
    const verify = openBountyDatabase(dbFile);
    try {
      const countRow = verify
        .prepare("SELECT COUNT(*) AS c, COUNT(DISTINCT sequence) AS d FROM workflow_events WHERE job_id = ?")
        .get(jobId) as { c: number; d: number };
      expect(countRow.c).toBe(24);
      expect(countRow.d).toBe(24);
      const seqs = (verify
        .prepare("SELECT sequence FROM workflow_events WHERE job_id = ? ORDER BY sequence ASC")
        .all(jobId) as Array<{ sequence: number }>).map((row) => row.sequence);
      expect(seqs).toEqual(Array.from({ length: 24 }, (_, i) => i + 1));
      let duplicate: unknown = null;
      try {
        verify
          .prepare(
            "INSERT INTO workflow_events (id, job_id, sequence, phase, status, message, metadata_json, created_at) VALUES (?, ?, 1, 'recon', 'ok', 'dup', NULL, ?)",
          )
          .run("dup-1", jobId, new Date().toISOString());
      } catch (err) {
        duplicate = err;
      }
      expect(duplicate).toBeInstanceOf(Error);
    } finally {
      try { verify.close(); } catch (_) { /* ignore */ }
    }
  }, SEQ_TEST_TIMEOUT_MS);
});
