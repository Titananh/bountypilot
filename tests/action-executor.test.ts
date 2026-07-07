import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
import { ActionExecutor } from "../src/workflows/action-executor.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import type { Runtime } from "../src/cli/runtime.js";

let server: Server;
let baseUrl: string;

beforeEach(async () => {
  server = createServer((_request, response) => {
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
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

describe("ActionExecutor", () => {
  it("executes approved safe-check actions against an in-scope local target", async () => {
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
    expect(result.evidenceCreated).toBe(1);
    expect(result.findingsCreated).toBeGreaterThan(0);
    expect(result.candidatesCreated).toBe(result.findingsCreated);
    expect(runtime.actions.get(action.id)?.status).toBe("executed");
    expect(runtime.evidence.list().length).toBeGreaterThan(0);
    expect(runtime.findings.list().length).toBeGreaterThan(0);
    expect(runtime.candidates.list({ jobId: job.id })).toHaveLength(result.candidatesCreated);
    expect(runtime.events.list(job.id)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          phase: "action:safe-checks",
          status: "completed",
          message: expect.stringContaining("safe checks completed"),
        }),
      ]),
    );
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
});

function createTestRuntime(seedUrl: string): Runtime {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-action-executor-"));
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
  const paths = ensureProgramWorkspace(config.program, root);
  const db = openBountyDatabase(paths.dbFile);
  return {
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
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
  };
}
