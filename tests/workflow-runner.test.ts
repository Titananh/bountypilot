import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ActionQueue } from "../src/core/actions/action-queue.js";
import { ActionReviewStore } from "../src/core/actions/action-review-store.js";
import { PolicyGate } from "../src/core/policy/policy-gate.js";
import { RateLimiter } from "../src/core/rate-limit/rate-limiter.js";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import { ensureProgramWorkspace } from "../src/core/workspace.js";
import { JobManager } from "../src/core/jobs/job-manager.js";
import { WorkflowEventStore } from "../src/core/jobs/workflow-event-store.js";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { EvidenceStore } from "../src/stores/evidence-store.js";
import { FindingCandidateStore } from "../src/stores/finding-candidate-store.js";
import { FindingStore } from "../src/stores/finding-store.js";
import { CrawlGraphStore } from "../src/stores/crawl-graph-store.js";
import { WorkflowRunner, type WorkflowSummary } from "../src/workflows/run-workflow.js";
import { createExecutableApprovalStore } from "../src/utils/local-process-policy.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import type { Runtime } from "../src/cli/runtime.js";

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
    expect(runtime.jobs.get(summary.jobId)?.status).toBe("completed");
    expect(runtime.actions.list(summary.jobId).length).toBe(summary.actionsPlanned);
    const events = runtime.events.list(summary.jobId);
    expect(events[0]).toEqual(expect.objectContaining({ sequence: 1, phase: "workflow", status: "running" }));
    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ phase: "research-note", status: "completed" }),
        expect.objectContaining({ phase: "action-planning", status: "completed" }),
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
    expect(resumed.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "research-note", status: "skipped" }),
        expect.objectContaining({ name: "action-planning", status: "completed" }),
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
      expect(resumed.actionCounts.executed).toBe(1);
      expect(runtime.actions.list(resumed.jobId)).toEqual([
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

      const resumed = await new WorkflowRunner(runtime).resume(originalJob.id);

      expect(resumed.actionsPlanned).toBe(2);
      expect(resumed.actionCounts.executed).toBe(2);
      expect(resumed.phases).not.toEqual(
        expect.arrayContaining([expect.objectContaining({ name: "safe-checks", status: "skipped" })]),
      );
      expect(resumed.phases).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "safe-checks", status: "completed", target: firstSeed }),
          expect.objectContaining({ name: "safe-checks", status: "completed", target: secondSeed }),
        ]),
      );
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
    expect(resumed.actionCounts.total).toBe(0);
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
      expect(resumed.actionCounts.executed).toBe(1);
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
        { name: "action-planning", status: "planned", detail: "2 actions planned (1 pending approval, 0 blocked by policy)." },
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
    expect(resumed.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "research-note", status: "skipped" }),
        expect.objectContaining({ name: "action-planning", status: "completed" }),
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
      expect(summary.actionCounts.executed).toBe(1);
      expect(summary.candidatesCreated).toBe(summary.findingsCreated);
      expect(runtime.candidates.list({ jobId: summary.jobId })).toHaveLength(summary.candidatesCreated);
      expect(runtime.actions.list(summary.jobId)).toEqual(
        expect.arrayContaining([expect.objectContaining({ adapter: "safe-checks", status: "executed" })]),
      );
    } finally {
      await closeServer(server);
    }
  });

  it("marks the workflow failed when a non-fatal phase records failure", async () => {
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

    expect(summary.status).toBe("failed");
    expect(runtime.jobs.get(summary.jobId)?.status).toBe("failed");
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

  it("executes explicitly enabled external workflow components", async () => {
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

    expect(summary.actionsPlanned).toBe(1);
    expect(summary.evidenceCreated).toBeGreaterThanOrEqual(3);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "crawl4ai", status: "completed" }),
        expect.objectContaining({ name: "triage", status: "skipped" }),
      ]),
    );
    expect(runtime.actions.list(summary.jobId)).toEqual(
      expect.arrayContaining([expect.objectContaining({ adapter: "crawl4ai", status: "executed" })]),
    );
    expect(runtime.evidence.list().some((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run"))).toBe(true);
    const crawledPages = runtime.crawlGraph.listPages().map((page) => page.url);
    expect(crawledPages).toEqual(
      expect.arrayContaining([
        "http://127.0.0.1:8080/docs",
        "http://127.0.0.1:8080/about",
        "http://127.0.0.1:8080/api/v1/users",
        "http://127.0.0.1:8080/assets/app.js",
        "http://127.0.0.1:8080/static/app.js",
        "http://127.0.0.1:8080/api/search",
        "http://127.0.0.1:8080/settings",
      ]),
    );
    expect(crawledPages.some((url) => url.includes("outside.example"))).toBe(false);
    const externalRun = runtime.evidence.list().find((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run"));
    const externalRunContent = JSON.parse(readFileSync(externalRun!.path, "utf8"));
    expect(externalRunContent.normalizedCrawlerOutput.endpointCandidates).toEqual(
      expect.arrayContaining(["/api/search", "/api/v1/users"]),
    );
    expect(externalRunContent.normalizedCrawlerOutput.jsAssets).toEqual(
      expect.arrayContaining([`//127.0.0.1:8080/assets/app.js`, `//127.0.0.1:8080/static/app.js`]),
    );
  });

  it("executes package entrypoint external workflow components", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-workflow-external-package-"));
    const scriptPath = writeCrawlerPackage(root, "fake-workflow-crawler", "1.0.0", "dist/cli.mjs");
    const runtime = createTestRuntime(crawl4aiPackageWorkflowConfig(scriptPath), root);

    const summary = await new WorkflowRunner(runtime).run({
      target: "http://127.0.0.1:8080/",
      mode: "safe",
      withComponents: ["crawl4ai"],
      dryRun: false,
    });

    expect(summary.actionsPlanned).toBe(1);
    expect(summary.phases).toEqual(expect.arrayContaining([expect.objectContaining({ name: "crawl4ai", status: "completed" })]));
    expect(runtime.actions.list(summary.jobId)).toEqual(
      expect.arrayContaining([expect.objectContaining({ adapter: "crawl4ai", status: "executed" })]),
    );
    const artifact = runtime.evidence.list().find((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run"));
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.package).toMatchObject({ name: "fake-workflow-crawler", version: "1.0.0" });
    expect(content.args[0]).toBe(realpathSync.native(scriptPath));
  });

  it("keeps planning-only external workflow components skipped in live runs", async () => {
    const runtime = createTestRuntime(crawl4aiWorkflowConfig(false));

    const summary = await new WorkflowRunner(runtime).run({
      target: "http://127.0.0.1:8080/",
      mode: "safe",
      withComponents: ["crawl4ai"],
      dryRun: false,
    });

    expect(summary.actionsPlanned).toBe(0);
    expect(runtime.actions.list(summary.jobId)).toHaveLength(0);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "crawl4ai",
          status: "skipped",
          detail: expect.stringContaining("planning-only"),
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
    expect(summary.actionCounts.executed).toBe(1);
    expect(summary.evidenceCreated).toBe(2);
    expect(summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "research-note", status: "completed" }),
        expect.objectContaining({ name: "d-research-skill", status: "completed" }),
      ]),
    );
    expect(runtime.actions.list(summary.jobId)).toEqual(
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
      expect(summary.phases).toEqual(expect.arrayContaining([expect.objectContaining({ name: "js-analyzer", status: "completed" })]));
      const auditLog = readFileSync(path.join(runtime.paths.jobsDir, summary.jobId, "audit.log"), "utf8");
      expect(auditLog).toContain('"actionType":"http.redirect"');
      expect(auditLog).toContain('"policyDecision":"block"');
    } finally {
      await closeServer(insideServer);
      await closeServer(outsideServer);
    }
  });
});

function createTestRuntime(runtimeConfig: ProgramConfig = config, root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-workflow-"))): Runtime {
  const paths = ensureProgramWorkspace(runtimeConfig.program, root);
  const db = openBountyDatabase(paths.dbFile);
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
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
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
