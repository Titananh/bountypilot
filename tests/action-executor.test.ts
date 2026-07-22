import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
import { ActionExecutor } from "../src/workflows/action-executor.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import type { Runtime } from "../src/cli/runtime.js";

const crawlerMock = vi.hoisted(() => ({
  crawlWithPlaywright: vi.fn(),
  lastInput: undefined as any,
}));

vi.mock("../src/engines/crawler/playwright-crawler.js", () => ({
  crawlWithPlaywright: crawlerMock.crawlWithPlaywright,
}));

let server: Server;
let baseUrl: string;
let requestCount = 0;
const runtimes: Runtime[] = [];
const roots: string[] = [];

beforeEach(async () => {
  requestCount = 0;
  crawlerMock.crawlWithPlaywright.mockReset();
  crawlerMock.crawlWithPlaywright.mockImplementation(async (input: any) => {
    crawlerMock.lastInput = input;
    const request = {
      url: input.url,
      method: "GET",
      resourceType: "document",
    };
    const decision = await input.authorizeRequest(request);
    const normalized = typeof decision === "boolean" ? { allowed: decision } : decision;
    await input.onRequest({
      ...request,
      transport: "http",
      allowed: normalized.allowed,
      reason: normalized.reason ?? "mock request",
    });
    if (normalized.allowed) await input.beforeRequest?.(request);
    return { url: input.url, title: "Mock page", evidence: [], links: [] };
  });
  server = createServer((_request, response) => {
    requestCount += 1;
    response.writeHead(200, {
      "content-type": "text/html",
    });
    response.end("<html><head></head><body><script src=\"/app.js\"></script></body></html>");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No test server port");
  baseUrl = `http://127.0.0.1:${address.port}/`;
});

afterEach(async () => {
  vi.restoreAllMocks();
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  for (const runtime of runtimes.splice(0)) {
    try {
      runtime.db.close();
    } catch {
      // best-effort test cleanup
    }
  }
  const tempRoot = path.resolve(os.tmpdir());
  for (const root of roots.splice(0)) {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(`${tempRoot}${path.sep}`)) {
      throw new Error(`Refusing to remove non-temporary test path: ${resolved}`);
    }
    rmSync(resolved, { recursive: true, force: true });
  }
});

describe("ActionExecutor", () => {
  it("executes approved safe-check actions against an in-scope local target", async () => {
    const wait = vi.spyOn(RateLimiter.prototype, "wait").mockResolvedValue();
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create("test-actions", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "safe-checks",
      actionType: "http.get",
      target: baseUrl,
      riskLevel: "low",
      requiresApproval: false,
    });

    const result = await new ActionExecutor(runtime).execute(action.id);

    expect(result.status).toBe("executed");
    expect(result.message).toContain("safe checks completed");
    expect(result.evidenceCreated).toBe(1);
    expect(result.findingsCreated).toBeGreaterThan(0);
    expect(result.candidatesCreated).toBe(result.findingsCreated);
    expect(runtime.actions.get(action.id)?.status).toBe("executed");
    expect(runtime.evidence.list().length).toBeGreaterThan(0);
    expect(runtime.findings.list().length).toBeGreaterThan(0);
    expect(runtime.candidates.list({ jobId: job.id })).toHaveLength(result.candidatesCreated);
    expect(runtime.jobs.get(job.id)?.status).toBe("completed");
    const events = runtime.events.list(job.id);
    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          phase: "action-review",
          status: "completed",
          metadata: expect.objectContaining({ source: "policy" }),
        }),
        expect.objectContaining({
          phase: "action-execution",
          status: "running",
          message: "Action execution claimed",
        }),
        expect.objectContaining({
          phase: "action-execution",
          status: "completed",
          metadata: expect.objectContaining({
            status: "executed",
            outcomeCertainty: "success",
          }),
        }),
      ]),
    );
    expect(JSON.stringify(events)).not.toMatch(/execution_?token|executionToken/i);
    expect(JSON.stringify(result)).not.toMatch(/execution_?token|executionToken/i);
    expect(wait).toHaveBeenCalledWith(baseUrl);
  });

  it("rate-limits the initial JavaScript request through fresh claim authority", async () => {
    const wait = vi.spyOn(RateLimiter.prototype, "wait").mockResolvedValue();
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create("test-actions", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "js-analyzer",
      actionType: "http.get",
      target: baseUrl,
      riskLevel: "low",
      requiresApproval: false,
    });

    const result = await new ActionExecutor(runtime).execute(action.id);

    expect(result.status).toBe("executed");
    expect(wait).toHaveBeenCalledWith(baseUrl);
    expect(wait.mock.calls.some(([url]) => String(url).endsWith("/app.js"))).toBe(true);
  });

  it("revalidates authority after a rate wait and before the first network request", async () => {
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create("test-actions", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "safe-checks",
      actionType: "http.get",
      target: baseUrl,
      riskLevel: "low",
      requiresApproval: false,
    });
    let drifted = false;
    vi.spyOn(RateLimiter.prototype, "wait").mockImplementation(async () => {
      if (!drifted) {
        drifted = true;
        saveProgramConfig(
          { ...runtime.config, rules: { ...runtime.config.rules, rate_limit: "50rps" } },
          path.dirname(runtime.paths.workspace.root),
        );
      }
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "ACTION_AUTHORITY_DRIFT",
    });
    expect(requestCount).toBe(0);
    expect(runtime.actions.get(action.id)).toMatchObject({ status: "failed" });
  });

  it("refuses to execute pending actions before approval", async () => {
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create("test-actions", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "safe-checks",
      actionType: "http.get",
      target: baseUrl,
      riskLevel: "low",
      requiresApproval: true,
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toThrow("must be approved");
    expect(runtime.actions.get(action.id)?.status).toBe("pending");
  });

  it.each([
    { metadata: { planningOnly: true }, requiredForCompletion: true },
    { metadata: { handoffOnly: true }, requiredForCompletion: true },
    { metadata: {}, requiredForCompletion: false },
  ])("rejects planning/handoff-only actions before any effect gate (%j)", async ({ metadata, requiredForCompletion }) => {
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create("test-actions", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "safe-checks",
      actionType: "http.get",
      target: baseUrl,
      riskLevel: "low",
      requiresApproval: false,
      metadata,
      requiredForCompletion,
    });
    const wait = vi.spyOn(runtime.rateLimiter, "wait");

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "ACTION_HANDOFF_ONLY",
    });
    expect(wait).not.toHaveBeenCalled();
    expect(runtime.actions.get(action.id)?.status).toBe("pending");
    expect(runtime.reviews.listForAction(action.id)).toHaveLength(0);
  });

  it.each([
    { label: "missing internal marker", metadata: undefined, jobType: "run" },
    {
      label: "extra forged metadata",
      metadata: { internal: true, purpose: "workflow_completion_barrier", forged: true },
      jobType: "run",
    },
    {
      label: "non-workflow job provenance",
      metadata: { internal: true, purpose: "workflow_completion_barrier" },
      jobType: "test-actions",
    },
    {
      label: "missing workflow target provenance",
      metadata: { internal: true, purpose: "workflow_completion_barrier" },
      jobType: "run",
      omitJobTarget: true,
    },
  ])("rejects a forged workflow completion barrier ($label)", async ({ metadata, jobType, omitJobTarget }) => {
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create(jobType, "safe", omitJobTarget ? undefined : baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "workflow",
      actionType: "workflow.barrier",
      riskLevel: "low",
      requiresApproval: false,
      requiredForCompletion: true,
      ...(metadata === undefined ? {} : { metadata }),
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
    });
    expect(runtime.actions.get(action.id)).toMatchObject({ status: "pending" });
    expect(runtime.reviews.listForAction(action.id)).toHaveLength(0);
    expect(crawlerMock.crawlWithPlaywright).not.toHaveBeenCalled();
  });

  it("rechecks workflow barrier provenance during claim after approval", async () => {
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create("run", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "workflow",
      actionType: "workflow.barrier",
      riskLevel: "low",
      requiresApproval: false,
      requiredForCompletion: true,
      metadata: { internal: true, purpose: "workflow_completion_barrier" },
    });
    const approved = runtime.actionApproval!.approvePolicy({
      actionId: action.id,
      ttlMs: 60_000,
      note: "test policy approval",
    });
    expect(approved.action.status).toBe("approved");

    // The public projection can still be mutated by a hostile in-process
    // caller after approval. Claim must re-materialize the source and reject
    // the forged barrier before generating/holding an execution token.
    runtime.db
      .prepare("UPDATE actions SET metadata_json = ? WHERE id = ?")
      .run(JSON.stringify({ internal: true, purpose: "workflow_completion_barrier", forged: true }), action.id);

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
    });
    expect(runtime.actions.get(action.id)).toMatchObject({ status: "approved" });
    expect(runtime.actions.get(action.id)?.executionOwner).toBeUndefined();
  });

  it("rebuilds scope, rate, and browser evidence authority from the successful claim", async () => {
    const runtime = createTestRuntime(baseUrl);
    const job = runtime.jobs.create("test-actions", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "playwright",
      actionType: "browser.navigate",
      target: baseUrl,
      riskLevel: "low",
      requiresApproval: false,
    });

    // Deliberately poison the long-lived runtime snapshots. The authority
    // loader still reads the program file written by createTestRuntime.
    runtime.scopeGuard = new ScopeGuard({
      ...runtime.config,
      in_scope: ["stale.invalid"],
    });
    runtime.rateLimiter = {
      wait: vi.fn(async () => {
        throw new Error("stale runtime rate limiter must not be used");
      }),
    } as unknown as RateLimiter;
    const freshConfig: ProgramConfig = {
      ...runtime.config,
      evidence: {
        ...runtime.config.evidence,
        screenshots: false,
        har: false,
        console_logs: false,
        dom_snapshot: false,
        browser_trace: false,
        video: false,
      },
    };
    saveProgramConfig(freshConfig, path.dirname(runtime.paths.workspace.root));

    const result = await new ActionExecutor(runtime).execute(action.id);

    expect(result.status).toBe("executed");
    expect(crawlerMock.lastInput.evidence).toMatchObject({
      screenshots: false,
      har: false,
      consoleLogs: false,
      domSnapshot: false,
      browserTrace: false,
      video: false,
    });
    expect(crawlerMock.lastInput.authorizeRequest).toEqual(expect.any(Function));
    expect(runtime.actions.get(action.id)?.status).toBe("executed");
  });

  it("stops later browser requests when the active dispatch lease expires", async () => {
    // Drive only the lifecycle clock.  Mutating lease_expires_at directly to
    // a past value makes the row structurally invalid because the dispatch
    // marker would then be later than the lease.  Advancing the injected
    // clock models the real expiry while preserving that invariant.
    const clock = { offsetMs: 0 };
    const runtime = createTestRuntime(baseUrl, () => new Date(Date.now() + clock.offsetMs));
    vi.spyOn(RateLimiter.prototype, "wait").mockResolvedValue();
    const job = runtime.jobs.create("test-actions", "safe", baseUrl);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "playwright",
      actionType: "browser.navigate",
      target: baseUrl,
      riskLevel: "low",
      requiresApproval: false,
    });
    let secondRequestContinued = false;
    crawlerMock.crawlWithPlaywright.mockImplementationOnce(async (input: any) => {
      const first = { url: input.url, method: "GET", resourceType: "document" };
      const firstDecision = await input.authorizeRequest(first);
      expect(typeof firstDecision === "boolean" ? firstDecision : firstDecision.allowed).toBe(true);
      await input.onRequest({ ...first, transport: "http", allowed: true, reason: "first request" });
      await input.beforeRequest(first);

      clock.offsetMs = 61_000;

      const second = { url: new URL("/second", input.url).toString(), method: "GET", resourceType: "document" };
      const secondDecision = await input.authorizeRequest(second);
      expect(typeof secondDecision === "boolean" ? secondDecision : secondDecision.allowed).toBe(true);
      await input.onRequest({ ...second, transport: "http", allowed: true, reason: "second request" });
      await input.beforeRequest(second);
      // This line is reachable only if the request-boundary lifecycle check
      // is accidentally bypassed.  Keep an explicit continuation marker so
      // the test cannot pass merely because the mock throws and finalization
      // converts that throw into outcome_unknown.
      secondRequestContinued = true;
      throw new Error("second request must not pass the active-dispatch boundary");
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "ACTION_LEASE_EXPIRED",
    });
    expect(secondRequestContinued).toBe(false);
    expect(runtime.actions.get(action.id)).toMatchObject({
      status: "outcome_unknown",
      outcomeCertainty: "possibly_dispatched",
    });
    expect(runtime.jobs.get(job.id)).toMatchObject({
      status: "paused",
      pauseReason: "reconciliation_required",
    });
  });
});

function createTestRuntime(seedUrl: string, now: () => Date = () => new Date()): Runtime {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-action-executor-"));
  roots.push(root);
  const url = new URL(seedUrl);
  const config: ProgramConfig = {
    program: "action-executor-test",
    platform: "hackerone",
    in_scope: [url.hostname],
    out_of_scope: [],
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
    evidence: new EvidenceStore(db, paths.evidenceDir, { trustedArtifactRoots: [paths.reportsDir] }),
    crawlGraph: new CrawlGraphStore(db),
    recon: new ReconObservationStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
    actionApproval: new ActionApprovalService(db, {
      ...authority,
      now,
    }),
    actionLifecycle: new ActionLifecycle(db, {
      ...authority,
      now,
      generateExecutionToken: () => randomBytes(32).toString("hex"),
    }),
  };
  runtimes.push(runtime);
  return runtime;
}
