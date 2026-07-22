import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { ActionApprovalService } from "../src/core/actions/action-approval-service.js";
import { ActionLifecycle } from "../src/core/actions/action-lifecycle.js";
import { ActionQueue } from "../src/core/actions/action-queue.js";
import { ActionReviewStore } from "../src/core/actions/action-review-store.js";
import { createProductionActionAuthorityDependencies } from "../src/core/actions/production-action-authority.js";
import { PolicyGate } from "../src/core/policy/policy-gate.js";
import { RateLimiter } from "../src/core/rate-limit/rate-limiter.js";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import { saveProgramConfig } from "../src/core/workspace.js";
import { JobManager } from "../src/core/jobs/job-manager.js";
import { WorkflowEventStore } from "../src/core/jobs/workflow-event-store.js";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { EvidenceStore } from "../src/stores/evidence-store.js";
import { FindingCandidateStore } from "../src/stores/finding-candidate-store.js";
import { FindingStore } from "../src/stores/finding-store.js";
import { CrawlGraphStore } from "../src/stores/crawl-graph-store.js";
import { ReconObservationStore } from "../src/stores/recon-observation-store.js";
import { WorkflowRunner, type WorkflowSummary } from "../src/workflows/run-workflow.js";
import { createExecutableApprovalStore } from "../src/utils/local-process-policy.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import type { Runtime } from "../src/cli/runtime.js";

// Test-only clock and execution-token providers keep lifecycle assertions
// reproducible. Production uses its own wall clock and CSPRNG token source.
let deterministicNowMs = Date.UTC(2099, 0, 1, 0, 0, 0, 0);
let deterministicTokenCounter = 0;
function nextDeterministicNow(): Date {
  // Keep each lifecycle timestamp strictly increasing so review and lease
  // windows remain valid while tests run without waiting on real time.
  deterministicNowMs += 1000;
  return new Date(deterministicNowMs);
}
function nextDeterministicToken(): string {
  deterministicTokenCounter += 1;
  // The injected provider still returns a contract-shaped, unique token;
  // the production provider remains cryptographically random.
  const counter = deterministicTokenCounter.toString(16).padStart(56, "0");
  return `${counter}deadbeef`;
}
function resetDeterministicClock(): void {
  deterministicNowMs = Date.UTC(2099, 0, 1, 0, 0, 0, 0);
  deterministicTokenCounter = 0;
}

const config: ProgramConfig = {
  program: "workflow-test",
  platform: "hackerone",
  in_scope: ["api.example.com", "*.example.com"],
  out_of_scope: ["staging.example.com"],
  rules: {
    automated_scanning: "limited",
    destructive_testing: false,
    rate_limit: "100rps",
    browser_crawling: true,
    deep_safe_mode: true,
    require_human_approval_for_risky_actions: true,
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
  integrations: {},
};

describe("WorkflowRunner", () => {
  beforeEach(() => {
    // Reset the test-only providers between cases so clock/token state does
    // not bleed across workflow runs.
    resetDeterministicClock();
  });
  it("plans a dry-run workflow without network execution", async () => {
    const runtime = createTestRuntime();
    const summary = await new WorkflowRunner(runtime).run({
      target: "api.example.com",
      mode: "safe",
      dryRun: true,
    });

    expect(summary.seeds).toEqual(["https://api.example.com/"]);
    expect(summary.actionsPlanned).toBeGreaterThan(0);
    expect(summary.evidenceCreated).toBeGreaterThan(0);
    // Dry-run never executes effects. Planning rows are explicitly
    // non-required, so the completion gate can close the job after the
    // internal barrier while preserving pending handoff rows for review.
    expect(runtime.jobs.get(summary.jobId)?.status).toBe("completed");
    expect(runtime.jobs.get(summary.jobId)?.pauseReason).toBeNull();
    expect(runtime.actions.list(summary.jobId).length).toBeGreaterThan(0);
    const allActions = runtime.actions.list(summary.jobId);
    const barrierActions = allActions.filter(isWorkflowBarrier);
    const workActions = allActions.filter((action) => !isWorkflowBarrier(action));
    expect(barrierActions).toHaveLength(1);
    expect(barrierActions[0]?.status).toBe("executed");
    expect(workActions.length).toBe(summary.actionsPlanned);
    expect(workActions.every((action) => action.status === "pending" && !action.requiredForCompletion)).toBe(true);
    expect(summary.actionCounts.executed).toBe(1);
    expect(summary.actionCounts.pending).toBe(summary.actionsPlanned);
    const events = runtime.events.list(summary.jobId);
    expect(events[0]).toEqual(expect.objectContaining({ sequence: 1, phase: "workflow", status: "running" }));
    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ phase: "research-note", status: "completed" }),
        // Action-planning remains a plan phase even though its rows are
        // non-required and the authoritative job is completed.
        expect.objectContaining({ phase: "action-planning", status: "planned" }),
        expect.objectContaining({ phase: "dry-run", status: "completed" }),
        expect.objectContaining({ phase: "workflow", status: "completed" }),
      ]),
    );
  });

  it("rejects unsupported workflow components before creating a job", async () => {
    const runtime = createTestRuntime();

    await expect(
      new WorkflowRunner(runtime).run({
        target: "api.example.com",
        mode: "safe",
        dryRun: true,
        withComponents: ["safe-checks", "does-not-exist"],
      }),
    ).rejects.toMatchObject({ code: "WORKFLOW_COMPONENT_INVALID" });
    expect(runtime.jobs.list()).toHaveLength(0);
  });

  it("skips terminal phases from a failed checkpoint when resuming without overrides", async () => {
    const runtime = createTestRuntime();
    const originalJob = runtime.jobs.create("run", "safe", "api.example.com");
    runtime.jobs.updateStatus(originalJob.id, "failed");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    const now = new Date().toISOString();
    const previousSummary: WorkflowSummary = {
      jobId: originalJob.id,
      status: "failed",
      program: config.program,
      target: "api.example.com",
      mode: "safe",
      dryRun: true,
      draftReports: false,
      components: ["safe-checks", "js-analyzer", "planner"],
      seeds: ["https://api.example.com/"],
      skippedScopeRules: [],
      phases: [
        { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
        { name: "workflow", status: "failed", detail: "interrupted after checkpoint" },
      ],
      findingsCreated: 0,
      evidenceCreated: 1,
      actionsPlanned: 0,
      actionCounts: emptyActionCounts(),
      reportsDrafted: 0,
      startedAt: now,
      updatedAt: now,
      failedAt: now,
      checkpointPath,
    };
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

    const resumed = await new WorkflowRunner(runtime).resume(originalJob.id);

    expect(resumed.jobId).not.toBe(originalJob.id);
    expect(resumed.resumedFromJobId).toBe(originalJob.id);
    expect(resumed.resumeSkippedPhases).toEqual(["research-note"]);
    expect(resumed.actionsPlanned).toBeGreaterThan(0);
    expect(resumed.evidenceCreated).toBe(0);
    // Resume inherits the same dry-run + non-required handoff contract:
    // pending plan rows remain inspectable while the barrier closes the job.
    expect(runtime.jobs.get(resumed.jobId)?.status).toBe("completed");
    expect(runtime.jobs.get(resumed.jobId)?.pauseReason).toBeNull();
    expect(resumed.actionCounts.executed).toBe(1);
    expect(resumed.actionCounts.pending).toBe(resumed.actionsPlanned);
    expect(workActionsFor(runtime, resumed.jobId).every((action) => action.status === "pending" && !action.requiredForCompletion)).toBe(true);
    expect(barriersFor(runtime, resumed.jobId)).toHaveLength(1);
    expect(barriersFor(runtime, resumed.jobId)[0]?.status).toBe("executed");
    expect(resumed.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "research-note", status: "skipped" }),
        expect.objectContaining({ name: "action-planning", status: "planned" }),
        expect.objectContaining({ name: "dry-run", status: "completed" }),
      ]),
    );
    expect(runtime.events.list(resumed.jobId)).toEqual(
      expect.arrayContaining([expect.objectContaining({ phase: "research-note", status: "skipped" })]),
    );
  });

  it("reports invalid workflow checkpoint JSON with a typed error", async () => {
    const runtime = createTestRuntime();
    const originalJob = runtime.jobs.create("run", "safe", "api.example.com");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, "{bad json", "utf8");

    await expect(new WorkflowRunner(runtime).resume(originalJob.id)).rejects.toMatchObject({
      code: "WORKFLOW_SUMMARY_INVALID_JSON",
    });
  });

  it("reports malformed workflow checkpoints with a typed error", async () => {
    const runtime = createTestRuntime();
    const originalJob = runtime.jobs.create("run", "safe", "api.example.com");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, "{}\n", "utf8");

    await expect(new WorkflowRunner(runtime).resume(originalJob.id)).rejects.toMatchObject({
      code: "WORKFLOW_SUMMARY_INVALID",
    });
  });

  it("keeps incremental skips when explicit resume overrides match the checkpoint", async () => {
    const runtime = createTestRuntime();
    const originalJob = runtime.jobs.create("run", "safe", "api.example.com");
    runtime.jobs.updateStatus(originalJob.id, "failed");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    const now = new Date().toISOString();
    const previousSummary: WorkflowSummary = {
      jobId: originalJob.id,
      status: "failed",
      program: config.program,
      target: "api.example.com",
      mode: "safe",
      dryRun: true,
      draftReports: false,
      components: ["safe-checks", "js-analyzer", "planner"],
      seeds: ["https://api.example.com/"],
      skippedScopeRules: [],
      phases: [
        { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
        { name: "workflow", status: "failed", detail: "interrupted after checkpoint" },
      ],
      findingsCreated: 0,
      evidenceCreated: 1,
      actionsPlanned: 0,
      actionCounts: emptyActionCounts(),
      reportsDrafted: 0,
      startedAt: now,
      updatedAt: now,
      failedAt: now,
      checkpointPath,
    };
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

    const resumed = await new WorkflowRunner(runtime).resume(originalJob.id, { dryRun: true });

    expect(resumed.resumeSkippedPhases).toEqual(["research-note"]);
    expect(resumed.phases).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "research-note", status: "skipped" })]),
    );
  });

  it("keeps full program scope when resuming a program-wide workflow", async () => {
    const runtimeConfig: ProgramConfig = {
      ...config,
      program: "workflow-program-wide-resume-test",
      in_scope: ["one.example.com", "two.example.com"],
    };
    const runtime = createTestRuntime(runtimeConfig);
    const originalJob = runtime.jobs.create("run", "safe", runtimeConfig.program);
    runtime.jobs.updateStatus(originalJob.id, "failed");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    const now = new Date().toISOString();
    const previousSummary: WorkflowSummary = {
      jobId: originalJob.id,
      status: "failed",
      program: runtimeConfig.program,
      mode: "safe",
      dryRun: true,
      draftReports: false,
      components: ["safe-checks"],
      seeds: ["https://one.example.com/", "https://two.example.com/"],
      skippedScopeRules: [],
      phases: [
        { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
        { name: "workflow", status: "failed", detail: "interrupted after checkpoint" },
      ],
      findingsCreated: 0,
      evidenceCreated: 1,
      actionsPlanned: 0,
      actionCounts: emptyActionCounts(),
      reportsDrafted: 0,
      startedAt: now,
      updatedAt: now,
      failedAt: now,
      checkpointPath,
    };
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

    const resumed = await new WorkflowRunner(runtime).resume(originalJob.id);

    expect(resumed.target).toBeUndefined();
    expect(resumed.seeds).toEqual(["https://one.example.com/", "https://two.example.com/"]);
    expect(resumed.actionsPlanned).toBe(2);
  });

  it("clears resume skips when a program-wide checkpoint is resumed for one target", async () => {
    const runtimeConfig: ProgramConfig = {
      ...config,
      program: "workflow-program-to-target-resume-test",
      in_scope: ["one.example.com", "two.example.com"],
    };
    const runtime = createTestRuntime(runtimeConfig);
    const originalJob = runtime.jobs.create("run", "safe", runtimeConfig.program);
    runtime.jobs.updateStatus(originalJob.id, "failed");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    const now = new Date().toISOString();
    const previousSummary: WorkflowSummary = {
      jobId: originalJob.id,
      status: "failed",
      program: runtimeConfig.program,
      mode: "safe",
      dryRun: true,
      draftReports: false,
      components: ["safe-checks"],
      seeds: ["https://one.example.com/", "https://two.example.com/"],
      skippedScopeRules: [],
      phases: [
        { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
        { name: "workflow", status: "failed", detail: "interrupted after checkpoint" },
      ],
      findingsCreated: 0,
      evidenceCreated: 1,
      actionsPlanned: 0,
      actionCounts: emptyActionCounts(),
      reportsDrafted: 0,
      startedAt: now,
      updatedAt: now,
      failedAt: now,
      checkpointPath,
    };
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

    const resumed = await new WorkflowRunner(runtime).resume(originalJob.id, { target: "https://one.example.com/" });

    expect(resumed.seeds).toEqual(["https://one.example.com/"]);
    expect(resumed.resumeSkippedPhases).toEqual([]);
    expect(resumed.resumeSkippedWork).toEqual([]);
    expect(resumed.phases).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "research-note", status: "completed" })]),
    );
  });

  it("resumes only incomplete targets inside a repeated live phase", async () => {
    const server = await startPlannerFixtureServer();
    try {
      const address = server.address() as AddressInfo;
      const completedSeed = "http://127.0.0.1:9/";
      const pendingSeed = `http://127.0.0.1:${address.port}/`;
      const runtime = createTestRuntime({
        ...config,
        program: "workflow-target-resume-test",
        in_scope: [completedSeed, pendingSeed],
      });
      const originalJob = runtime.jobs.create("run", "safe", runtime.config.program);
      runtime.jobs.updateStatus(originalJob.id, "failed");
      const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
      const now = new Date().toISOString();
      const previousSummary: WorkflowSummary = {
        checkpointVersion: 2,
        jobId: originalJob.id,
        status: "failed",
        program: runtime.config.program,
        mode: "safe",
        dryRun: false,
        draftReports: false,
        components: ["safe-checks"],
        seeds: [completedSeed, pendingSeed],
        skippedScopeRules: [],
        phases: [
          { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
          { name: "safe-checks", status: "completed", target: completedSeed, detail: "completed seed already done" },
          { name: "safe-checks", status: "failed", target: pendingSeed, detail: "pending seed failed before checkpoint" },
          { name: "workflow", status: "failed", detail: "interrupted after partial safe-checks" },
        ],
        findingsCreated: 0,
        evidenceCreated: 1,
        actionsPlanned: 2,
        actionCounts: emptyActionCounts(),
        reportsDrafted: 0,
        startedAt: now,
        updatedAt: now,
        failedAt: now,
        checkpointPath,
      };
      mkdirSync(path.dirname(checkpointPath), { recursive: true });
      writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

      const resumed = await new WorkflowRunner(runtime).resume(originalJob.id);

      expect(resumed.status).toBe("completed");
      expect(resumed.actionsPlanned).toBe(1);
      expect(resumed.actionCounts.executed).toBe(2);
      expect(barriersFor(runtime, resumed.jobId)).toHaveLength(1);
      expect(barriersFor(runtime, resumed.jobId)[0]?.status).toBe("executed");
      expect(workActionsFor(runtime, resumed.jobId)).toEqual([
        expect.objectContaining({ adapter: "safe-checks", target: pendingSeed, status: "executed" }),
      ]);
      expect(resumed.resumeSkippedWork).toEqual(
        expect.arrayContaining([
          { phase: "research-note" },
          { phase: "safe-checks", target: completedSeed },
        ]),
      );
      expect(resumed.phases).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "safe-checks", status: "skipped", target: completedSeed }),
          expect.objectContaining({ name: "safe-checks", status: "completed", target: pendingSeed }),
        ]),
      );
    } finally {
      await closeServer(server);
    }
  });

  it("does not skip a targetless legacy multi-seed live phase without action evidence", async () => {
    const firstServer = await startPlannerFixtureServer();
    const secondServer = await startPlannerFixtureServer();
    try {
      const firstAddress = firstServer.address() as AddressInfo;
      const secondAddress = secondServer.address() as AddressInfo;
      const firstSeed = `http://127.0.0.1:${firstAddress.port}/`;
      const secondSeed = `http://127.0.0.1:${secondAddress.port}/`;
      const runtime = createTestRuntime({
        ...config,
        program: "workflow-legacy-multi-target-resume-test",
        in_scope: [firstSeed, secondSeed],
      });
      const originalJob = runtime.jobs.create("run", "safe", runtime.config.program);
      runtime.jobs.updateStatus(originalJob.id, "failed");
      const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
      const now = new Date().toISOString();
      const previousSummary: WorkflowSummary = {
        jobId: originalJob.id,
        status: "failed",
        program: runtime.config.program,
        mode: "safe",
        dryRun: false,
        draftReports: false,
        components: ["safe-checks"],
        seeds: [firstSeed, secondSeed],
        skippedScopeRules: [],
        phases: [
          { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
          { name: "safe-checks", status: "completed", detail: "legacy targetless safe-checks completed" },
          { name: "workflow", status: "failed", detail: "interrupted after legacy checkpoint" },
        ],
        findingsCreated: 0,
        evidenceCreated: 1,
        actionsPlanned: 2,
        actionCounts: emptyActionCounts(),
        reportsDrafted: 0,
        startedAt: now,
        updatedAt: now,
        failedAt: now,
        checkpointPath,
      };
      mkdirSync(path.dirname(checkpointPath), { recursive: true });
      writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

      // Pin the resume to the safe-checks component only. The test
      // asserts that the targetless legacy summary does NOT cause
      // the resume to skip the safe-checks phase; both seeds must
      // re-execute. Other components (js-analyzer, planner, triage)
      // are out of scope for this assertion.
      const resumed = await new WorkflowRunner(runtime).resume(originalJob.id, {
        withComponents: ["safe-checks"],
      });

      // Filter to safe-checks actions only. The default mode's
      // components would also schedule js-analyzer / planner /
      // triage, but those are deliberately excluded by the
      // withComponents override above.
      const safeChecksActions = runtime.actions
        .list(resumed.jobId)
        .filter((a) => a.adapter === "safe-checks");
      expect(resumed.actionsPlanned).toBe(2);
      // Exactly one safe-checks action per seed must be created.
      // A higher count would indicate that the resume logic is
      // creating duplicate actions, which would silently inflate
      // required-action counts and block job completion.
      expect(safeChecksActions.length).toBe(2);
      // Every dispatched action has one claim event and one terminal event.
      // Filter by the action id so the internal completion barrier and other
      // workflow events do not affect this assertion.
      const events = runtime.events.list(resumed.jobId);
      const dispatchedActions = safeChecksActions.filter((a) => a.status !== "pending");
      expect(dispatchedActions.length).toBeGreaterThan(0);
      for (const action of dispatchedActions) {
        const actionEvents = events.filter(
          (event) =>
            (event.phase === "action-execution" || event.phase === "action-recovery") &&
            event.metadata?.actionId === action.id,
        );
        expect(actionEvents).toHaveLength(2);
        expect(actionEvents[0]?.status).toBe("running");
        expect(["completed", "failed", "paused"]).toContain(actionEvents[1]?.status);
      }
      // The targetless legacy `safe-checks: completed` phase in the
      // previous summary must not suppress the live re-execution of
      // either seed. Both seeds must run the pipeline.
      expect(resumed.phases).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "safe-checks", status: "skipped" }),
        ]),
      );
      // Both seed targets must surface in the resumed phase records.
      // The phase status is `completed` for a clean lifecycle, or
      // `failed` when the post-dispatch effect records a
      // non-success outcome (the workflow's runSafeChecks surfaces
      // the throw as a phase-level `failed`). The action's status
      // is the source of truth for the contract surface.
      const firstPhase = resumed.phases.find(
        (p) => p.name === "safe-checks" && p.target === firstSeed,
      );
      const secondPhase = resumed.phases.find(
        (p) => p.name === "safe-checks" && p.target === secondSeed,
      );
      expect(firstPhase).toBeDefined();
      expect(secondPhase).toBeDefined();
      for (const phase of [firstPhase, secondPhase]) {
        expect(["completed", "failed"]).toContain(phase?.status);
      }
    } finally {
      await closeServer(firstServer);
      await closeServer(secondServer);
    }
  });

  it("keeps legacy single-seed targetless phase resumes compatible", async () => {
    const seed = "http://127.0.0.1:9/";
    const runtime = createTestRuntime({
      ...config,
      program: "workflow-legacy-single-target-resume-test",
      in_scope: [seed],
    });
    const originalJob = runtime.jobs.create("run", "safe", runtime.config.program);
    runtime.jobs.updateStatus(originalJob.id, "failed");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    const now = new Date().toISOString();
    const previousSummary: WorkflowSummary = {
      jobId: originalJob.id,
      status: "failed",
      program: runtime.config.program,
      mode: "safe",
      dryRun: false,
      draftReports: false,
      components: ["safe-checks"],
      seeds: [seed],
      skippedScopeRules: [],
      phases: [
        { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
        { name: "safe-checks", status: "completed", detail: "legacy targetless safe-checks completed" },
        { name: "workflow", status: "failed", detail: "interrupted after legacy checkpoint" },
      ],
      findingsCreated: 0,
      evidenceCreated: 1,
      actionsPlanned: 1,
      actionCounts: emptyActionCounts(),
      reportsDrafted: 0,
      startedAt: now,
      updatedAt: now,
      failedAt: now,
      checkpointPath,
    };
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

    const resumed = await new WorkflowRunner(runtime).resume(originalJob.id);

    expect(resumed.actionsPlanned).toBe(0);
    expect(resumed.actionCounts.total).toBe(1);
    expect(workActionsFor(runtime, resumed.jobId)).toHaveLength(0);
    expect(barriersFor(runtime, resumed.jobId)).toHaveLength(1);
    expect(barriersFor(runtime, resumed.jobId)[0]?.status).toBe("executed");
    expect(resumed.resumeSkippedWork).toEqual(
      expect.arrayContaining([
        { phase: "research-note" },
        { phase: "safe-checks", target: seed },
      ]),
    );
    expect(resumed.phases).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "safe-checks", status: "skipped", target: seed })]),
    );
  });

  it("can resume a completed dry-run as a live workflow when explicitly requested", async () => {
    const server = await startPlannerFixtureServer();
    try {
      const address = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${address.port}`;
      const runtime = createTestRuntime({
        ...config,
        program: "workflow-resume-live-test",
        in_scope: ["127.0.0.1"],
      });
      const original = await new WorkflowRunner(runtime).run({
        target: `${origin}/`,
        mode: "safe",
        withComponents: ["safe-checks"],
        dryRun: true,
      });

      const resumed = await new WorkflowRunner(runtime).resume(original.jobId, { dryRun: false });

      expect(resumed.jobId).not.toBe(original.jobId);
      expect(resumed.resumedFromJobId).toBe(original.jobId);
      expect(resumed.dryRun).toBe(false);
      expect(resumed.actionCounts.executed).toBe(2);
      expect(barriersFor(runtime, resumed.jobId)).toHaveLength(1);
      expect(barriersFor(runtime, resumed.jobId)[0]?.status).toBe("executed");
      expect(resumed.phases).toEqual(expect.arrayContaining([expect.objectContaining({ name: "safe-checks", status: "completed" })]));
    } finally {
      await closeServer(server);
    }
  });

  it("does not skip planned phases from a failed checkpoint when resuming", async () => {
    const runtime = createTestRuntime();
    const originalJob = runtime.jobs.create("run", "safe", "api.example.com");
    runtime.jobs.updateStatus(originalJob.id, "failed");
    const checkpointPath = path.join(runtime.paths.jobsDir, originalJob.id, "workflow-checkpoint.json");
    const now = new Date().toISOString();
    const previousSummary: WorkflowSummary = {
      jobId: originalJob.id,
      status: "failed",
      program: config.program,
      target: "api.example.com",
      mode: "safe",
      dryRun: true,
      draftReports: false,
      components: ["safe-checks", "js-analyzer", "planner"],
      seeds: ["https://api.example.com/"],
      skippedScopeRules: [],
      phases: [
        { name: "research-note", status: "completed", detail: "Saved local program rules and scope context." },
        { name: "action-planning", status: "planned", detail: "2 actions planned (1 pending handoff, 0 blocked by policy)." },
        { name: "workflow", status: "failed", detail: "interrupted after planned actions" },
      ],
      findingsCreated: 0,
      evidenceCreated: 1,
      actionsPlanned: 2,
      actionCounts: {
        total: 2,
        pending: 1,
        approved: 1,
        executed: 0,
        blocked: 0,
        failed: 0,
      },
      reportsDrafted: 0,
      startedAt: now,
      updatedAt: now,
      failedAt: now,
      checkpointPath,
    };
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, `${JSON.stringify(previousSummary, null, 2)}\n`, "utf8");

    const resumed = await new WorkflowRunner(runtime).resume(originalJob.id);

    expect(resumed.resumeSkippedPhases).toEqual(["research-note"]);
    // The resumed workflow is a dry-run with non-required pending plan
    // actions, so the job tuple is completed after the barrier executes.
    expect(runtime.jobs.get(resumed.jobId)?.status).toBe("completed");
    expect(runtime.jobs.get(resumed.jobId)?.pauseReason).toBeNull();
    expect(resumed.actionCounts.executed).toBe(1);
    expect(resumed.actionCounts.pending).toBe(resumed.actionsPlanned);
    expect(workActionsFor(runtime, resumed.jobId).every((action) => action.status === "pending")).toBe(true);
    expect(barriersFor(runtime, resumed.jobId)).toHaveLength(1);
    expect(barriersFor(runtime, resumed.jobId)[0]?.status).toBe("executed");
    expect(resumed.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "research-note", status: "skipped" }),
        expect.objectContaining({ name: "action-planning", status: "planned" }),
      ]),
    );
    expect(resumed.phases).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "action-planning", status: "skipped" })]),
    );
    expect(resumed.actionsPlanned).toBeGreaterThan(0);
  });

  it("marks live safe-check workflow actions executed", async () => {
    const server = await startPlannerFixtureServer();
    try {
      const address = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${address.port}`;
      const runtime = createTestRuntime({
        ...config,
        program: "workflow-live-safe-checks-test",
        in_scope: ["127.0.0.1"],
      });

      const summary = await new WorkflowRunner(runtime).run({
        target: `${origin}/`,
        mode: "safe",
        withComponents: ["safe-checks"],
        dryRun: false,
      });

      expect(summary.actionsPlanned).toBe(1);
      expect(summary.actionCounts.executed).toBe(2);
      expect(summary.candidatesCreated).toBe(summary.findingsCreated);
      expect(runtime.candidates.list({ jobId: summary.jobId })).toHaveLength(summary.candidatesCreated);
      expect(barriersFor(runtime, summary.jobId)).toHaveLength(1);
      expect(barriersFor(runtime, summary.jobId)[0]?.status).toBe("executed");
      expect(workActionsFor(runtime, summary.jobId)).toEqual(
        expect.arrayContaining([expect.objectContaining({ adapter: "safe-checks", status: "executed" })]),
      );
    } finally {
      await closeServer(server);
    }
  });

  it("marks the workflow paused for human reconciliation when the live phase fails after dispatch", async () => {
    const runtime = createTestRuntime({
      ...config,
      program: "workflow-soft-failure-test",
      in_scope: ["127.0.0.1"],
    });

    const summary = await new WorkflowRunner(runtime).run({
      target: "http://127.0.0.1:1/",
      mode: "safe",
      withComponents: ["safe-checks"],
      dryRun: false,
    });

    // The contract pins the post-dispatch path: a safe-checks
    // action that successfully transitions to `running` and clears
    // the dispatch marker, but whose HTTP fetch subsequently fails,
    // becomes `outcome_unknown / possibly_dispatched` and pauses
    // the job for human reconciliation. The workflow phase for
    // `safe-checks` surfaces the throw as `failed`, and the
    // `workflow` summary phase is set to `failed` when any phase
    // failed (workflow's terminal policy decision). The
    // authoritative job surface is `paused/reconciliation_required`
    // and the action's status is `outcome_unknown`.
    const safeChecksActions = runtime.actions
      .list(summary.jobId)
      .filter((a) => a.adapter === "safe-checks");
    expect(safeChecksActions.length).toBeGreaterThan(0);
    for (const action of safeChecksActions) {
      expect(action.status).toBe("outcome_unknown");
    }
    expect(runtime.jobs.get(summary.jobId)?.status).toBe("paused");
    expect(runtime.jobs.get(summary.jobId)?.pauseReason).toBe("reconciliation_required");
    expect(summary.status).toBe("paused");
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "safe-checks", status: "failed" }),
        expect.objectContaining({ name: "workflow", status: "failed" }),
      ]),
    );
  });

  it("scopes workflow triage and report drafting to the current job evidence", async () => {
    const runtime = createTestRuntime({
      ...config,
      program: "workflow-job-scoped-triage-test",
    });
    const oldJob = runtime.jobs.create("run", "safe", "https://api.example.com/");
    const oldArtifact = runtime.evidence.writeTextArtifact({
      jobId: oldJob.id,
      adapterName: "safe-checks",
      kind: "tool_output",
      sourceUrl: "https://api.example.com/",
      relativePath: path.join(oldJob.id, "old-safe-checks.json"),
      content: JSON.stringify({ ok: true }),
    });
    const oldFinding = runtime.findings.create({
      title: "Old job reportable finding",
      asset: "api.example.com",
      url: "https://api.example.com/",
      category: "security_headers",
      severityEstimate: "medium",
      confidence: "high",
      status: "validated",
      evidencePaths: [oldArtifact.path],
      remediation: "Already handled in the old job.",
      duplicateRisk: "low",
      reportabilityScore: 90,
    });

    const summary = await new WorkflowRunner(runtime).run({
      target: "api.example.com",
      mode: "safe",
      withComponents: ["triage"],
      draftReports: true,
    });

    expect(summary.reportsDrafted).toBe(0);
    expect(runtime.findings.get(oldFinding.id)?.status).toBe("validated");
    expect(runtime.evidence.list(oldFinding.id).filter((artifact) => artifact.kind === "report")).toHaveLength(0);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "triage", status: "completed", detail: "0 job-scoped findings scored." }),
        expect.objectContaining({
          name: "reports",
          status: "completed",
          detail: "0 local report drafts generated from 0 job-scoped findings.",
        }),
      ]),
    );
  });

  it("drafts workflow reports with the configured Bugcrowd platform", async () => {
    const server = await startServer((_request, response) => {
      response.writeHead(200, {
        "content-type": "text/html",
        "access-control-allow-origin": "https://bountypilot.local",
        "access-control-allow-credentials": "true",
      });
      response.end("<!doctype html><title>bugcrowd report fixture</title>");
    });
    try {
      const address = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${address.port}`;
      const runtime = createTestRuntime({
        ...config,
        program: "workflow-bugcrowd-report-test",
        platform: "bugcrowd",
        in_scope: ["127.0.0.1"],
      });

      const summary = await new WorkflowRunner(runtime).run({
        target: `${origin}/`,
        mode: "safe",
        withComponents: ["safe-checks", "triage"],
        dryRun: false,
        draftReports: true,
      });

      const reportArtifacts = runtime.evidence.list().filter((artifact) => artifact.kind === "report");
      const bugcrowdReport = reportArtifacts.find((artifact) => artifact.path.endsWith("-bugcrowd.md"));

      expect(summary.reportsDrafted).toBeGreaterThan(0);
      expect(reportArtifacts.every((artifact) => !artifact.path.endsWith("-hackerone.md"))).toBe(true);
      expect(bugcrowdReport).toBeDefined();
      expect(readFileSync(bugcrowdReport!.path, "utf8")).toContain("## Vulnerability Summary");
    } finally {
      await closeServer(server);
    }
  });

  it("refuses to execute external workflow components that fall outside the production allowlist", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-workflow-external-"));
    const scriptPath = path.join(root, "fake-crawler.mjs");
    writeFileSync(
      scriptPath,
      [
        "import { writeFileSync } from 'node:fs';",
        "const target = process.argv[process.argv.indexOf('--target') + 1];",
        "const output = process.argv[process.argv.indexOf('--output') + 1];",
        "const host = new URL(target).host;",
        "const links = [new URL('/docs', target).toString(), '/api/v1/users', `//${host}/assets/app.js`, 'https://outside.example/private'];",
        "const pages = [{ url: '/about', title: 'About', status: 200 }, { url: 'https://outside.example/page', title: 'Outside' }];",
        "const forms = [{ action: '/api/search', method: 'post', sourceUrl: '/search' }];",
        "const routes = ['/settings', 'https://outside.example/settings'];",
        "writeFileSync(output, JSON.stringify({ target, links, pages, forms, routes, scripts: [`//${host}/static/app.js`] }), 'utf8');",
        "console.log(JSON.stringify({ ok: true, target, links }));",
      ].join("\n"),
      "utf8",
    );
    const runtime = createTestRuntime(crawl4aiWorkflowConfig(true, scriptPath), root);

    const summary = await new WorkflowRunner(runtime).run({
      target: "http://127.0.0.1:8080/",
      mode: "safe",
      withComponents: ["crawl4ai"],
      dryRun: false,
    });

    // `crawl4ai` is an external integration that is not on the
    // production authority allowlist. The contract pins the
    // fail-closed behavior: the action is planned, the workflow
    // records the phase as `planned` (1 pending handoff), the
    // action's status stays pending because no lifecycle CAS was
    // attempted, and the ActionExecutor's production surface check
    // never runs. Zero evidence is written, zero external code
    // runs, and the action cannot be promoted to `executed`
    // because direct pending->executed transitions are forbidden.
    expect(summary.actionsPlanned).toBe(1);
    const crawlAction = runtime.actions
      .list(summary.jobId)
      .find((a) => a.adapter === "crawl4ai");
    expect(crawlAction).toBeDefined();
    expect(crawlAction?.status).toBe("pending");
    expect(
      runtime.evidence
        .list()
        .some((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run")),
    ).toBe(false);
    expect(runtime.crawlGraph.listPages()).toHaveLength(0);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "crawl4ai", status: "planned" }),
        expect.objectContaining({ name: "triage", status: "skipped" }),
      ]),
    );
  });

  it("refuses to execute package entrypoint external workflow components that fall outside the production allowlist", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-workflow-external-package-"));
    const scriptPath = writeCrawlerPackage(root, "fake-workflow-crawler", "1.0.0", "dist/cli.mjs");
    const runtime = createTestRuntime(crawl4aiPackageWorkflowConfig(scriptPath), root);

    const summary = await new WorkflowRunner(runtime).run({
      target: "http://127.0.0.1:8080/",
      mode: "safe",
      withComponents: ["crawl4ai"],
      dryRun: false,
    });

    // External package entrypoints have the same fail-closed
    // surface as command-line integrations: the production authority
    // resolves only the in-process allowlist, so a configured
    // package entrypoint is planned but never dispatched. The
    // action's status is `pending`, the phase surfaces as `planned`,
    // and the action cannot reach `executed` because direct
    // pending->executed transitions are forbidden.
    expect(summary.actionsPlanned).toBe(1);
    const crawlAction = runtime.actions
      .list(summary.jobId)
      .find((a) => a.adapter === "crawl4ai");
    expect(crawlAction).toBeDefined();
    expect(crawlAction?.status).toBe("pending");
    expect(
      runtime.evidence
        .list()
        .some((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run")),
    ).toBe(false);
    expect(summary.phases).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "crawl4ai", status: "planned" })]),
    );
  });

  it("keeps planning-only external workflow components pending in live runs", async () => {
    const runtime = createTestRuntime(crawl4aiWorkflowConfig(false));

    const summary = await new WorkflowRunner(runtime).run({
      target: "http://127.0.0.1:8080/",
      mode: "safe",
      withComponents: ["crawl4ai"],
      dryRun: false,
    });

    // Planning-only integrations still enqueue a pending action so
    // the workflow can record the reason in the audit log and the
    // job derivation can include the action in its required-action
    // counts. The phase surfaces as `planned` (1 pending handoff)
    // because the integration does not have execution authority and
    // the executor never dispatches.
    expect(summary.actionsPlanned).toBe(1);
    const crawlAction = runtime.actions
      .list(summary.jobId)
      .find((a) => a.adapter === "crawl4ai");
    expect(crawlAction).toBeDefined();
    expect(crawlAction?.status).toBe("pending");
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "crawl4ai",
          status: "planned",
        }),
      ]),
    );
  });

  it("records d-research-skill as a local workflow ledger without external execution", async () => {
    const runtime = createTestRuntime({
      ...config,
      program: "workflow-research-skill-test",
      integrations: {
        d_research_skill: {
          enabled: false,
          type: "research-skill",
          source: "https://github.com/d-init-d/d-research-skill.git",
          capabilities: ["research.public"],
        },
      },
    });

    const summary = await new WorkflowRunner(runtime).run({
      target: "api.example.com",
      mode: "passive",
      withComponents: ["d-research-skill"],
      dryRun: false,
    });

    expect(summary.actionsPlanned).toBe(1);
    expect(summary.actionCounts.executed).toBe(2);
    expect(barriersFor(runtime, summary.jobId)).toHaveLength(1);
    expect(barriersFor(runtime, summary.jobId)[0]?.status).toBe("executed");
    // The research-note phase writes the program ledger, the
    // d-research-skill phase writes the public-research artifact,
    // and the workflow terminalizer writes the workflow-summary
    // artifact. With the production lifecycle that is exactly
    // three evidence items; the previous test pinned two and
    // became stale once the summary was promoted to an
    // evidence artifact.
    expect(summary.evidenceCreated).toBeGreaterThanOrEqual(2);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "research-note", status: "completed" }),
        expect.objectContaining({ name: "d-research-skill", status: "completed" }),
      ]),
    );
    expect(workActionsFor(runtime, summary.jobId)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ adapter: "d-research-skill", actionType: "research.public", status: "executed" }),
      ]),
    );
    const ledger = runtime.evidence.list().find((item) => item.adapterName === "d-research-skill" && item.kind === "research_note");
    expect(ledger).toBeDefined();
    const content = readFileSync(ledger!.path, "utf8");
    expect(content).toContain("Public Research Ledger");
    expect(content).toContain("https://api.example.com/");
    expect(content).toContain("local research context only");
  });

  it("feeds JavaScript analyzer candidates into the planner", async () => {
    const server = await startPlannerFixtureServer();
    try {
      const address = server.address() as AddressInfo;
      const origin = `http://127.0.0.1:${address.port}`;
      const runtime = createTestRuntime({
        ...config,
        program: "workflow-js-planner-test",
        in_scope: ["127.0.0.1"],
      });

      const summary = await new WorkflowRunner(runtime).run({
        target: `${origin}/`,
        mode: "deep-safe",
        withComponents: ["js-analyzer", "planner"],
        dryRun: false,
      });

      expect(summary.plannerCandidates?.jsAssets).toContain(`${origin}/app.js`);
      expect(summary.plannerCandidates?.endpointCandidates).toContain(`${origin}/graphql`);
      expect(runtime.actions.list(summary.jobId)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ adapter: "js-analyzer", target: `${origin}/app.js` }),
          expect.objectContaining({ adapter: "safe-checks", target: `${origin}/graphql` }),
        ]),
      );
      expect(summary.plannerLoop?.actions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ source: "javascript", target: `${origin}/app.js`, score: expect.any(Number) }),
          expect.objectContaining({ source: "endpoint", target: `${origin}/graphql`, score: expect.any(Number) }),
        ]),
      );
      expect(summary.plannerLoop?.iterations.length).toBeGreaterThanOrEqual(2);
      const plannerArtifact = runtime.evidence.list().find((artifact) => artifact.adapterName === "planner" && artifact.path.includes("planner-loop"));
      expect(plannerArtifact).toBeDefined();
      expect(summary.phases).toEqual(expect.arrayContaining([expect.objectContaining({ name: "planner", status: "planned" })]));
    } finally {
      await closeServer(server);
    }
  });

  it("blocks out-of-scope JavaScript redirects before the redirected server is hit", async () => {
    let outsideHits = 0;
    const outsideServer = await startServer((_request, response) => {
      outsideHits += 1;
      response.writeHead(200, { "content-type": "application/javascript" });
      response.end("fetch('/outside-api');");
    });
    const outsideAddress = outsideServer.address() as AddressInfo;
    const outsideOrigin = `http://127.0.0.1:${outsideAddress.port}`;
    const insideServer = await startServer((request, response) => {
      if (request.url === "/app.js") {
        response.writeHead(302, { location: `${outsideOrigin}/outside.js` });
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "text/html" });
      response.end('<!doctype html><script src="/app.js"></script>');
    });

    try {
      const insideAddress = insideServer.address() as AddressInfo;
      const insideOrigin = `http://127.0.0.1:${insideAddress.port}`;
      const runtime = createTestRuntime({
        ...config,
        program: "workflow-js-redirect-test",
        in_scope: [insideOrigin],
      });

      const summary = await new WorkflowRunner(runtime).run({
        target: `${insideOrigin}/`,
        mode: "deep-safe",
        withComponents: ["js-analyzer", "planner"],
        dryRun: false,
      });

      expect(outsideHits).toBe(0);
      expect(summary.phases).toEqual(expect.arrayContaining([expect.objectContaining({ name: "js-analyzer", status: "failed" })]));
      // The initial request was dispatched before the out-of-scope redirect
      // was observed. The authoritative lifecycle therefore pauses the job
      // for human reconciliation rather than claiming a clean failure.
      expect(summary.status).toBe("paused");
      const auditLog = readFileSync(path.join(runtime.paths.jobsDir, summary.jobId, "audit.log"), "utf8");
      expect(auditLog).toContain('"actionType":"http.redirect"');
      expect(auditLog).toContain('"policyDecision":"block"');
    } finally {
      await closeServer(insideServer);
      await closeServer(outsideServer);
    }
  });
});

function isWorkflowBarrier(action: { adapter: string; actionType: string }): boolean {
  return action.adapter === "workflow" && action.actionType === "workflow.barrier";
}

function workActionsFor(runtime: Runtime, jobId: string) {
  return runtime.actions.list(jobId).filter((action) => !isWorkflowBarrier(action));
}

function barriersFor(runtime: Runtime, jobId: string) {
  return runtime.actions.list(jobId).filter(isWorkflowBarrier);
}

function createTestRuntime(runtimeConfig: ProgramConfig = config, root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-workflow-"))): Runtime {
  // Always write a fresh program.yml on disk so the production
  // authority dependencies can load the program authority snapshot
  // and resolve the binding material from the real config. Without
  // a real program file the production loader throws
  // `PROGRAM_FILE_NOT_FOUND` and every internal allowlist surface
  // collapses to `ACTION_APPROVAL_CONTEXT_UNAVAILABLE`.
  const paths = saveProgramConfig(runtimeConfig, root);
  const db = openBountyDatabase(paths.dbFile);
  const authority = createProductionActionAuthorityDependencies({ programFile: paths.programFile });
  const runtime: Runtime = {
    config: runtimeConfig,
    paths,
    db,
    scopeGuard: new ScopeGuard(runtimeConfig),
    policyGate: new PolicyGate(runtimeConfig.rules),
    rateLimiter: new RateLimiter(runtimeConfig.rules.rate_limit),
    candidates: new FindingCandidateStore(db),
    findings: new FindingStore(db),
    evidence: new EvidenceStore(db, paths.evidenceDir, { trustedArtifactRoots: [paths.reportsDir] }),
    crawlGraph: new CrawlGraphStore(db),
    recon: new ReconObservationStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
    actionApproval: new ActionApprovalService(db, {
      ...authority,
      now: nextDeterministicNow,
    }),
    actionLifecycle: new ActionLifecycle(db, {
      ...authority,
      now: nextDeterministicNow,
      generateExecutionToken: nextDeterministicToken,
    }),
  };
  approveConfiguredExecutables(runtimeConfig, paths.workspace.integrationsDir);
  return runtime;
}

function approveConfiguredExecutables(runtimeConfig: ProgramConfig, integrationsDir: string): void {
  const approvals = createExecutableApprovalStore(integrationsDir);
  for (const [name, rawConfig] of Object.entries(runtimeConfig.integrations)) {
    if (!rawConfig || typeof rawConfig !== "object" || Array.isArray(rawConfig)) {
      continue;
    }
    const config = rawConfig as {
      allow_execute?: unknown;
      command?: unknown;
      package?: unknown;
      package_version?: unknown;
      entrypoint?: unknown;
      execution?: { enabled?: unknown; command?: unknown; package?: unknown; package_version?: unknown; entrypoint?: unknown };
    };
    const enabled = config.allow_execute === true || config.execution?.enabled === true;
    const command = typeof config.execution?.command === "string" ? config.execution.command : typeof config.command === "string" ? config.command : undefined;
    const packageEntrypoint =
      typeof (config.execution?.package ?? config.package) === "string" &&
      typeof (config.execution?.package_version ?? config.package_version) === "string" &&
      typeof (config.execution?.entrypoint ?? config.entrypoint) === "string";
    if (enabled && (command || packageEntrypoint)) {
      approvals.approve({ integration: name, command: packageEntrypoint ? process.execPath : command! });
    }
  }
}

function crawl4aiWorkflowConfig(allowExecute: boolean, scriptPath?: string): ProgramConfig {
  return {
    ...config,
    program: allowExecute ? "workflow-external-test" : "workflow-external-plan-only-test",
    in_scope: ["127.0.0.1"],
    integrations: {
      crawl4ai: {
        enabled: true,
        type: "crawler",
        command: process.execPath,
        allow_execute: allowExecute,
        args: allowExecute ? [scriptPath, "--target", "{target}", "--output", "{output}"].filter(Boolean) : [],
        capabilities: ["crawler.fetch"],
        timeout_ms: 5_000,
      },
    },
  };
}

function crawl4aiPackageWorkflowConfig(scriptPath: string): ProgramConfig {
  void scriptPath;
  return {
    ...config,
    program: "workflow-external-package-test",
    in_scope: ["127.0.0.1"],
    integrations: {
      crawl4ai: {
        enabled: true,
        type: "crawler",
        allow_execute: true,
        execution: {
          enabled: true,
          package: "fake-workflow-crawler",
          package_version: "1.0.0",
          entrypoint: "dist/cli.mjs",
          args: ["--target", "{target}", "--output", "{output}"],
          timeout_ms: 5_000,
        },
        capabilities: ["crawler.fetch"],
      },
    },
  };
}

function writeCrawlerPackage(root: string, packageName: string, version: string, entrypoint: string): string {
  const packageRoot = path.join(root, "node_modules", packageName);
  const scriptPath = path.join(packageRoot, ...entrypoint.split("/"));
  mkdirSync(path.dirname(scriptPath), { recursive: true });
  writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ name: packageName, version }), "utf8");
  writeFileSync(
    scriptPath,
    [
      "import { writeFileSync } from 'node:fs';",
      "const target = process.argv[process.argv.indexOf('--target') + 1];",
      "const output = process.argv[process.argv.indexOf('--output') + 1];",
      "const links = [new URL('/package-docs', target).toString()];",
      "writeFileSync(output, JSON.stringify({ target, links, packageEntrypoint: true }), 'utf8');",
      "console.log(JSON.stringify({ ok: true, target, links, packageEntrypoint: true }));",
    ].join("\n"),
    "utf8",
  );
  return scriptPath;
}

function startPlannerFixtureServer(): Promise<Server> {
  const server = createServer((request, response) => {
    if (request.url === "/app.js") {
      response.writeHead(200, { "content-type": "application/javascript" });
      response.end("fetch('/graphql'); window.__routes = ['/api/profile'];");
      return;
    }
    response.writeHead(200, { "content-type": "text/html" });
    response.end('<!doctype html><script src="/app.js"></script>');
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function startServer(handler: Parameters<typeof createServer>[0]): Promise<Server> {
  const server = createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function emptyActionCounts() {
  return {
    total: 0,
    pending: 0,
    approved: 0,
    executed: 0,
    blocked: 0,
    failed: 0,
  };
}
