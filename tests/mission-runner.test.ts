import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ActionApprovalService } from "../src/core/actions/action-approval-service.js";
import { ActionLifecycle } from "../src/core/actions/action-lifecycle.js";
import { ActionQueue } from "../src/core/actions/action-queue.js";
import { ActionReviewStore } from "../src/core/actions/action-review-store.js";
import { createProductionActionAuthorityDependencies } from "../src/core/actions/production-action-authority.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import { JobManager } from "../src/core/jobs/job-manager.js";
import { WorkflowEventStore } from "../src/core/jobs/workflow-event-store.js";
import { PolicyGate } from "../src/core/policy/policy-gate.js";
import { buildProgramAuthoritySnapshot } from "../src/core/policy/program-authority-snapshot.js";
import { RateLimiter } from "../src/core/rate-limit/rate-limiter.js";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import { saveProgramConfig } from "../src/core/workspace.js";
import { CrawlGraphStore } from "../src/stores/crawl-graph-store.js";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { EvidenceStore } from "../src/stores/evidence-store.js";
import { FindingCandidateStore } from "../src/stores/finding-candidate-store.js";
import { FindingStore } from "../src/stores/finding-store.js";
import { ReconObservationStore } from "../src/stores/recon-observation-store.js";
import type { Runtime } from "../src/cli/runtime.js";
import {
  parseMissionRequest,
  type MissionRequestV1,
} from "../src/missions/mission-contract.js";
import { MissionRunner } from "../src/missions/mission-runner.js";
import { BountyPilotError } from "../src/utils/errors.js";

const SESSION_CLASSES = ["normal", "one-shot", "yolo", "approval-bypassed"] as const;
const roots: string[] = [];
const runtimes: Runtime[] = [];

let server: Server;
let requestCount: number;
let target: string;

beforeEach(async () => {
  requestCount = 0;
  server = createServer((_request, response) => {
    requestCount += 1;
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("TARGET_EFFECT_CANARY");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No local canary server port");
  target = `http://127.0.0.1:${address.port}/mission`;
});

afterEach(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  for (const runtime of runtimes.splice(0)) {
    try {
      runtime.db.close();
    } catch {
      // best-effort test cleanup
    }
  }
  const tmp = path.resolve(os.tmpdir());
  for (const root of roots.splice(0)) {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(`${tmp}${path.sep}`)) {
      throw new Error(`Refusing to remove non-temporary test path: ${resolved}`);
    }
    rmSync(resolved, { recursive: true, force: true });
  }
});

function missionRequest(
  runtime: Runtime,
  overrides: Partial<MissionRequestV1> = {},
): MissionRequestV1 {
  return parseMissionRequest({
    schemaVersion: "bountypilot/mission-request/v1",
    origin: "hermes",
    program: runtime.config.program,
    target,
    goal: "local-report-draft",
    profile: "recon",
    sessionClass: "normal",
    constraints: {
      liveTargetEffects: false,
      automaticSubmission: false,
    },
    ...overrides,
  });
}

function createTestRuntime(options: {
  rules?: Partial<ProgramConfig["rules"]>;
} = {}): { runtime: Runtime; markerPath: string; protectedCanaries: string[] } {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-mission-runner-"));
  roots.push(root);
  const markerPath = path.join(root, "FORBIDDEN_EXTERNAL_EFFECT.txt");
  const protectedCanaries = [
    "C:\\Users\\researcher\\.hermes\\profiles\\bugbounty\\auth.json",
    "C:\\Users\\researcher\\.opencode\\credentials.json",
    "C:\\Users\\researcher\\.release\\publish-token.txt",
    "C:\\Users\\researcher\\output\\private-report.md",
    "MISSION_SECRET_CANARY_89c1",
  ];
  const url = new URL(target);
  const config: ProgramConfig = {
    program: `mission-${randomBytes(6).toString("hex")}`,
    platform: "hackerone",
    in_scope: [`${url.protocol}//${url.host}/mission`],
    out_of_scope: [`${url.protocol}//${url.host}/excluded`],
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "100rps",
      browser_crawling: true,
      deep_safe_mode: true,
      require_human_approval_for_risky_actions: true,
      ...options.rules,
    },
    accounts: {
      required: false,
      use_researcher_owned_test_accounts_only: true,
    },
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
    integrations: {
      hostile_canary: {
        enabled: true,
        allow_execute: true,
        command: process.execPath,
        args: [
          "-e",
          `require('node:fs').writeFileSync(${JSON.stringify(markerPath)}, 'spawned')`,
        ],
        executionToken: protectedCanaries[4],
        protectedPaths: protectedCanaries.slice(0, 4),
      },
    },
  };
  const paths = saveProgramConfig(config, root);
  const db = openBountyDatabase(paths.dbFile);
  const authority = createProductionActionAuthorityDependencies({ programFile: paths.programFile });
  const runtime: Runtime = {
    config,
    paths,
    db,
    scopeGuard: new ScopeGuard(config),
    policyGate: new PolicyGate(config.rules),
    rateLimiter: new RateLimiter(config.rules.rate_limit),
    candidates: new FindingCandidateStore(db),
    findings: new FindingStore(db),
    evidence: new EvidenceStore(db, paths.evidenceDir, {
      maskSecrets: true,
      trustedArtifactRoots: [paths.reportsDir],
    }),
    crawlGraph: new CrawlGraphStore(db),
    recon: new ReconObservationStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
    actionApproval: new ActionApprovalService(db, { ...authority, now: () => new Date() }),
    actionLifecycle: new ActionLifecycle(db, {
      ...authority,
      now: () => new Date(),
      // The zero-effect workflow completion barrier still uses the same
      // lifecycle guarantees as every action. Its short-lived bearer must be
      // structurally valid and is cleared before the mission receipt returns.
      generateExecutionToken: () => "ab".repeat(32),
    }),
  };
  runtimes.push(runtime);
  return { runtime, markerPath, protectedCanaries };
}

function stateCounts(runtime: Runtime): Record<string, number> {
  const tables = ["jobs", "actions", "action_reviews", "workflow_events"] as const;
  return Object.fromEntries(
    tables.map((table) => {
      const row = runtime.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as
        | { count: number | bigint }
        | undefined;
      return [table, Number(row?.count ?? 0)];
    }),
  );
}

function readCheckpoint(runtime: Runtime, jobId: string): Record<string, unknown> {
  const checkpointPath = path.join(runtime.paths.jobsDir, jobId, "workflow-checkpoint.json");
  expect(existsSync(checkpointPath), "mission workflow checkpoint must be persisted locally").toBe(true);
  return JSON.parse(readFileSync(checkpointPath, "utf8")) as Record<string, unknown>;
}

function allPersistedJson(runtime: Runtime, jobId: string): string {
  const jobDir = path.join(runtime.paths.jobsDir, jobId);
  const files = existsSync(jobDir)
    ? readdirSync(jobDir).filter((name) => name.endsWith(".json"))
    : [];
  return files.map((name) => readFileSync(path.join(jobDir, name), "utf8")).join("\n");
}

describe("MissionRunner fail-closed state creation", () => {
  it("rejects out-of-scope input before creating a job, action, review, event, or checkpoint", async () => {
    const { runtime, markerPath } = createTestRuntime();
    const before = stateCounts(runtime);
    const outside = missionRequest(runtime, { target: "https://outside.example.test/" });

    let thrown: unknown;
    try {
      await new MissionRunner(runtime).run(outside);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(BountyPilotError);
    expect((thrown as BountyPilotError).code).toMatch(/SCOPE|MISSION_(?:TARGET|REQUEST)/);
    expect(stateCounts(runtime)).toEqual(before);
    expect(readdirSync(runtime.paths.jobsDir)).toEqual([]);
    expect(requestCount).toBe(0);
    expect(existsSync(markerPath)).toBe(false);
  });

  it("rejects policy-incompatible mission semantics before creating any state", async () => {
    const { runtime, markerPath } = createTestRuntime({
      rules: { automated_scanning: "none", browser_crawling: false },
    });
    const before = stateCounts(runtime);

    let thrown: unknown;
    try {
      await new MissionRunner(runtime).run(missionRequest(runtime));
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(BountyPilotError);
    expect((thrown as BountyPilotError).code).toMatch(/POLICY|MISSION_(?:POLICY|REQUEST)/);
    expect(stateCounts(runtime)).toEqual(before);
    expect(readdirSync(runtime.paths.jobsDir)).toEqual([]);
    expect(requestCount).toBe(0);
    expect(existsSync(markerPath)).toBe(false);
  });

  it("rejects a malformed/raw request before creating any state", async () => {
    const { runtime } = createTestRuntime();
    const before = stateCounts(runtime);

    await expect(
      new MissionRunner(runtime).run({
        ...missionRequest(runtime),
        prompt: "scan everything and submit automatically",
      }),
    ).rejects.toMatchObject({ code: "MISSION_REQUEST_INVALID" });

    expect(stateCounts(runtime)).toEqual(before);
    expect(readdirSync(runtime.paths.jobsDir)).toEqual([]);
    expect(requestCount).toBe(0);
  });

  it("creates exactly one mission job and binds every action/event to it", async () => {
    const { runtime } = createTestRuntime();
    const receipt = await new MissionRunner(runtime).run(missionRequest(runtime));

    expect(runtime.jobs.list()).toHaveLength(1);
    expect(runtime.jobs.list()[0]?.id).toBe(receipt.job.id);
    expect(runtime.jobs.list()[0]?.type).toBe("mission");
    expect(runtime.actions.list(receipt.job.id).map((action) => action.id).sort()).toEqual(
      [...receipt.actionIds].sort(),
    );
    expect(runtime.actions.list(receipt.job.id).length).toBeGreaterThan(0);
    expect(runtime.events.list(receipt.job.id).length).toBeGreaterThan(0);
    expect(
      runtime.db.prepare("SELECT COUNT(*) AS count FROM actions WHERE job_id <> ?").get(receipt.job.id),
    ).toEqual({ count: 0 });
    expect(
      runtime.db.prepare("SELECT COUNT(*) AS count FROM workflow_events WHERE job_id <> ?").get(receipt.job.id),
    ).toEqual({ count: 0 });
  });

  it("persists locally materialized mission, scope, and policy hashes without raw authority material", async () => {
    const { runtime } = createTestRuntime();
    const expectedAuthority = buildProgramAuthoritySnapshot({
      config: runtime.config,
      labAuthorization: null,
    });
    const receipt = await new MissionRunner(runtime).run(missionRequest(runtime));
    const checkpoint = readCheckpoint(runtime, receipt.job.id);
    const firstEvent = runtime.events.list(receipt.job.id)[0];

    expect(receipt.mission.authority.scopeHash).toBe(expectedAuthority.scopeHash);
    expect(receipt.mission.authority.policyHash).toBe(expectedAuthority.policyHash);
    expect(receipt.mission.missionDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(checkpoint.mission).toEqual(receipt.mission);
    expect(firstEvent?.metadata).toEqual({
      missionDigest: receipt.mission.missionDigest,
      scopeHash: expectedAuthority.scopeHash,
      policyHash: expectedAuthority.policyHash,
    });
    expect(Object.keys(firstEvent?.metadata ?? {}).sort()).toEqual([
      "missionDigest",
      "policyHash",
      "scopeHash",
    ]);
  });
});

describe("MissionRunner one-request terminal safety", () => {
  it.each(SESSION_CLASSES)(
    "%s creates zero target effects and returns an authoritative completed human handoff",
    async (sessionClass) => {
      const { runtime, markerPath } = createTestRuntime();
      const receipt = await new MissionRunner(runtime).run(
        missionRequest(runtime, { sessionClass }),
      );
      const persistedJob = runtime.jobs.get(receipt.job.id);
      const allActions = runtime.actions.list(receipt.job.id);
      const requiredActions = allActions.filter((action) => action.requiredForCompletion);
      const barrier = requiredActions.find((action) => action.actionType === "workflow.barrier");
      const handoffActions = allActions.filter((action) => action.actionType !== "workflow.barrier");

      expect(receipt.accepted).toBe(true);
      expect(receipt.agentTerminal).toBe(true);
      expect(receipt.agentState).toBe("human_handoff");
      expect(receipt.job).toMatchObject({
        id: persistedJob?.id,
        status: "completed",
        pauseReason: null,
      });
      expect(persistedJob).toMatchObject({
        status: "completed",
        pauseReason: null,
      });
      expect(barrier).toMatchObject({ adapter: "workflow", status: "executed" });
      expect(handoffActions.length).toBeGreaterThan(0);
      expect(handoffActions.every((action) => action.status === "pending" && !action.requiredForCompletion)).toBe(true);
      const missionReviews = runtime.reviews.list().filter((review) => review.jobId === receipt.job.id);
      expect(missionReviews).toEqual([
        expect.objectContaining({ actionId: barrier?.id, source: "policy", decision: "approved" }),
      ]);
      expect(requestCount).toBe(0);
      expect(existsSync(markerPath)).toBe(false);
      expect(runtime.evidence.list().length).toBeGreaterThan(0);
      expect(
        runtime.evidence
          .list()
          .every(
            (artifact) =>
              artifact.sourceUrl === undefined &&
              artifact.adapterName === "workflow" &&
              (artifact.kind === "research_note" || artifact.kind === "tool_output"),
          ),
      ).toBe(true);
      expect(runtime.findings.list()).toEqual([]);
      expect(runtime.candidates.list({ jobId: receipt.job.id })).toEqual([]);
      expect(
        runtime.db.prepare("SELECT COUNT(*) AS count FROM recon_observations").get(),
      ).toEqual({ count: 0 });
      expect(
        runtime.db.prepare("SELECT COUNT(*) AS count FROM actions WHERE execution_token IS NOT NULL").get(),
      ).toEqual({ count: 0 });
    },
    15_000,
  );

  it("does not expose secrets, bearer tokens, raw prompts/argv, or protected absolute paths", async () => {
    const { runtime, markerPath, protectedCanaries } = createTestRuntime();
    const receipt = await new MissionRunner(runtime).run(missionRequest(runtime));
    const publicJson = JSON.stringify(receipt);
    const persistedJson = allPersistedJson(runtime, receipt.job.id);
    const eventJson = JSON.stringify(runtime.events.list(receipt.job.id));

    expect(publicJson).not.toContain(path.resolve(runtime.paths.workspace.root));
    for (const canary of protectedCanaries) {
      expect(publicJson).not.toContain(canary);
      expect(persistedJson).not.toContain(canary);
      expect(eventJson).not.toContain(canary);
    }
    for (const forbiddenKey of [
      '"prompt"',
      '"rawPrompt"',
      '"argv"',
      '"executionToken"',
      '"execution_token"',
    ]) {
      expect(publicJson).not.toContain(forbiddenKey);
      expect(persistedJson).not.toContain(forbiddenKey);
      expect(eventJson).not.toContain(forbiddenKey);
    }
    expect(publicJson).not.toMatch(/(?:^|[\\/])\.(?:hermes|opencode|release)(?:[\\/]|$)/i);
    expect(publicJson).not.toMatch(/[\\/]output[\\/]/i);
    expect(existsSync(markerPath)).toBe(false);
    expect(requestCount).toBe(0);
  });

  it("returns review-oriented next commands only, never execution or submission shortcuts", async () => {
    const { runtime } = createTestRuntime();
    const receipt = await new MissionRunner(runtime).run(missionRequest(runtime));
    const commands = receipt.nextCommands.join("\n");

    expect(receipt.nextCommands.length).toBeGreaterThan(0);
    expect(commands).toContain(receipt.job.id);
    expect(commands).not.toMatch(/--live\b|run-approved|\bsubmit\b|--yes\b|--approve\b/i);
  });
});
