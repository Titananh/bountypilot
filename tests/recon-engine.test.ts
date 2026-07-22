import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { BountyDatabase } from "../src/stores/db/database.js";
import { describe, expect, it, vi } from "vitest";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { ReconObservationStore } from "../src/stores/recon-observation-store.js";
import {
  parseToolOutput,
  TOOL_ADAPTER_SPECS,
  toolApprovalIntegrationName,
} from "../src/integrations/tool-manager/tool-adapter-runner.js";
import { ToolManager } from "../src/integrations/tool-manager/tool-manager.js";
import { runHuntPlaybook, runHuntRecon } from "../src/hunting/recon-engine.js";
import { createExecutableApprovalStore } from "../src/utils/local-process-policy.js";
import type { Runtime } from "../src/cli/runtime.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import { ensureProgramWorkspace } from "../src/core/workspace.js";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import { PolicyGate } from "../src/core/policy/policy-gate.js";
import { RateLimiter } from "../src/core/rate-limit/rate-limiter.js";
import { FindingCandidateStore } from "../src/stores/finding-candidate-store.js";
import { FindingStore } from "../src/stores/finding-store.js";
import { EvidenceStore } from "../src/stores/evidence-store.js";
import { CrawlGraphStore } from "../src/stores/crawl-graph-store.js";
import { JobManager } from "../src/core/jobs/job-manager.js";
import { WorkflowEventStore } from "../src/core/jobs/workflow-event-store.js";
import { ActionQueue } from "../src/core/actions/action-queue.js";
import { ActionReviewStore } from "../src/core/actions/action-review-store.js";

describe("bug results engine foundations", () => {
  it("parses common bounty tool outputs into normalized observations", () => {
    const observations = parseToolOutput({
      tool: "httpx",
      actionType: "http.probe",
      target: "https://api.example.com/",
      content: [
        JSON.stringify({ url: "https://api.example.com/v1/users?debug=true", title: "API" }),
        JSON.stringify({ url: "https://api.example.com/static/app.js" }),
      ].join("\n"),
    });

    expect(observations.map((observation) => observation.kind)).toEqual(expect.arrayContaining(["parameter", "js_asset"]));
    expect(observations.every((observation) => observation.sourceAdapter === "httpx")).toBe(true);
  });

  it("parses dedicated tool formats into rich recon observations", () => {
    const cases = [
      {
        tool: "subfinder",
        actionType: "research.public",
        content: "api.example.com\nstatic.example.com\n",
        expectedKinds: ["host"],
      },
      {
        tool: "httpx",
        actionType: "http.probe",
        content: JSON.stringify({ url: "https://api.example.com/admin", status_code: 200, tech: ["nginx", "express"] }),
        expectedKinds: ["endpoint", "technology"],
      },
      {
        tool: "katana",
        actionType: "crawler.fetch",
        content: JSON.stringify({ url: "https://api.example.com/login", tag: "form", action: "/session", method: "POST" }),
        expectedKinds: ["endpoint", "form"],
      },
      {
        tool: "nuclei",
        actionType: "http.scan",
        content: JSON.stringify({ "template-id": "exposed-panel", "matched-at": "https://api.example.com/panel", info: { severity: "medium" } }),
        expectedKinds: ["endpoint", "vulnerability_signal"],
      },
      {
        tool: "ffuf",
        actionType: "http.fuzz",
        content: JSON.stringify({ results: [{ url: "https://api.example.com/backup.zip", status: 200, length: 42 }] }),
        expectedKinds: ["endpoint"],
      },
      {
        tool: "dalfox",
        actionType: "http.validate",
        content: JSON.stringify({ target: "https://api.example.com/search?q=test", param: "q", type: "V", poc: "https://api.example.com/search?q=%3Csvg%3E" }),
        expectedKinds: ["parameter", "finding_candidate"],
      },
      {
        tool: "naabu",
        actionType: "tcp.scan",
        content: JSON.stringify({ host: "api.example.com", port: 443, protocol: "tcp" }),
        expectedKinds: ["host", "port"],
      },
    ];

    for (const item of cases) {
      const observations = parseToolOutput({
        tool: item.tool,
        actionType: item.actionType,
        target: "https://api.example.com/",
        content: item.content,
      });
      expect(observations.map((observation) => observation.kind), item.tool).toEqual(expect.arrayContaining(item.expectedKinds));
    }
  });

  it("keeps host-only line output as hosts instead of target-relative URLs", () => {
    const observations = parseToolOutput({
      tool: "subfinder",
      actionType: "research.public",
      target: "https://api.example.com/",
      content: "assets.example.com\n",
    });

    expect(observations).toHaveLength(1);
    expect(observations[0]?.kind).toBe("host");
    expect(observations[0]?.normalizedValue).toBe("assets.example.com");
  });

  it("deduplicates recon observations by fingerprint", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-recon-"));
    let db: BountyDatabase | undefined;
    try {
      db = openBountyDatabase(path.join(dir, "test.sqlite"));
      const store = new ReconObservationStore(db);

      const first = store.upsert({
        jobId: "job-one",
        kind: "endpoint",
        value: "https://api.example.com/v1/users",
        sourceAdapter: "httpx",
        sourceUrl: "https://api.example.com/",
        scopeAllowed: true,
        confidence: "low",
      });
      const second = store.upsert({
        jobId: "job-two",
        kind: "endpoint",
        value: "https://api.example.com/v1/users",
        sourceAdapter: "httpx",
        sourceUrl: "https://api.example.com/",
        scopeAllowed: true,
        confidence: "medium",
      });

      expect(second.id).toBe(first.id);
      expect(store.list()).toHaveLength(1);
      expect(store.list()[0]?.confidence).toBe("medium");
    } finally {
      db?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("includes bug bounty tools in the trusted registry", () => {
    const names = new ToolManager().list().map((tool) => tool.name);

    expect(names).toEqual(expect.arrayContaining(["subfinder", "httpx", "katana", "nuclei", "ffuf", "dalfox"]));
  });

  it("keeps live recon as a scoped planning handoff even when a tool is approved", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-live-recon-"));
    const runtime = createReconRuntime(dir);
    const subfinderSpec = TOOL_ADAPTER_SPECS.find((spec) => spec.tool === "subfinder" && spec.actionType === "research.public");
    expect(subfinderSpec).toBeDefined();
    const originalArgs = [...subfinderSpec!.defaultArgs];
    subfinderSpec!.defaultArgs = ["-e", "console.log('api.example.com')"];

    try {
      createExecutableApprovalStore(runtime.paths.workspace.integrationsDir).approve({
        integration: toolApprovalIntegrationName("subfinder"),
        command: process.execPath,
        note: "vitest live recon fixture",
      });

      const result = await runHuntRecon(runtime, "https://api.example.com/", {
        profile: "passive",
        live: true,
        tools: ["subfinder"],
      });

      expect(result.ok).toBe(true);
      expect(result.actionsPlanned).toBe(1);
      expect(result.tools).toEqual([
        expect.objectContaining({
          tool: "subfinder",
          actionType: "research.public",
          status: "pending",
          approvalPresent: true,
          observations: 0,
        }),
      ]);
      expect(result.observations).toHaveLength(0);
      expect(runtime.recon.list({ jobId: result.jobId, sourceAdapter: "subfinder" })).toHaveLength(0);
      expect(result.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ adapterName: "hunt-recon", kind: "research_note", jobId: result.jobId }),
        ]),
      );
      // Recon is planning-only, so pending handoff rows are non-required and
      // do not hold the authoritative job in approval_required.
      expect(runtime.jobs.get(result.jobId)?.status).toBe("completed");
      expect(runtime.jobs.get(result.jobId)?.pauseReason).toBeNull();
      expect(runtime.actions.summarize(result.jobId)).toMatchObject({ pending: 1, executed: 0 });
      expect(runtime.actions.list(result.jobId).every((action) => action.requiredForCompletion === false && action.metadata?.handoffOnly === true)).toBe(true);
    } finally {
      subfinderSpec!.defaultArgs = originalArgs;
      runtime.db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runs a web recon fixture pipeline and keeps review-required tools pending", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-web-recon-fixture-"));
    const runtime = createReconRuntime(dir);
    const restoreSpecs = replaceToolArgs([
      {
        tool: "subfinder",
        args: nodePrintArgs(["api.example.com", "staging.example.com", "cdn.example.com"]),
      },
      {
        tool: "httpx",
        args: nodePrintArgs([
          JSON.stringify({ url: "https://api.example.com/v1/users?debug=true", title: "API", tech: ["nginx", "express"] }),
          JSON.stringify({ url: "https://staging.example.com/private", title: "Out of scope" }),
        ]),
      },
      {
        tool: "katana",
        args: nodePrintArgs([
          JSON.stringify({ url: "https://api.example.com/login", tag: "form", action: "/session", method: "POST" }),
          JSON.stringify({ url: "https://cdn.example.com/static/app.js" }),
        ]),
      },
    ]);

    try {
      const approvals = createExecutableApprovalStore(runtime.paths.workspace.integrationsDir);
      for (const tool of ["subfinder", "httpx", "katana"]) {
        approvals.approve({
          integration: toolApprovalIntegrationName(tool),
          command: process.execPath,
          note: "vitest web recon fixture",
        });
      }

      const result = await runHuntRecon(runtime, "https://api.example.com/", {
        profile: "web",
        live: true,
        tools: ["subfinder", "httpx", "katana", "nuclei", "ffuf", "dalfox"],
      });

      expect(result.ok).toBe(true);
      expect(result.actionsPlanned).toBe(6);
      expect(result.tools).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ tool: "subfinder", status: "pending", observations: 0 }),
          expect.objectContaining({ tool: "httpx", status: "pending", observations: 0 }),
          expect.objectContaining({ tool: "katana", status: "pending", observations: 0 }),
          expect.objectContaining({ tool: "nuclei", status: "pending", approvalPresent: false }),
          expect.objectContaining({ tool: "ffuf", status: "pending", approvalPresent: false }),
          expect.objectContaining({ tool: "dalfox", status: "pending", approvalPresent: false }),
        ]),
      );
      expect(result.observations).toHaveLength(0);
      expect(runtime.recon.list({ jobId: result.jobId })).toHaveLength(0);
      expect(runtime.crawlGraph.listPages()).toHaveLength(0);
      expect(runtime.jobs.get(result.jobId)?.status).toBe("completed");
      expect(runtime.jobs.get(result.jobId)?.pauseReason).toBeNull();
      expect(runtime.actions.summarize(result.jobId)).toMatchObject({
        total: 6,
        pending: 6,
        executed: 0,
      });
      expect(runtime.actions.list(result.jobId).every((action) => action.requiredForCompletion === false && action.metadata?.handoffOnly === true)).toBe(true);
      expect(runtime.jobs.get(result.jobId)?.status).toBe("completed");
      expect(result.nextCommands).toEqual(expect.arrayContaining([`bounty actions review --job ${result.jobId}`]));
    } finally {
      restoreSpecs();
      runtime.db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps runHuntPlaybook live mode as a planning handoff when lifecycle execution is unavailable", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-approval-bypass-"));
    const runtime = createReconRuntime(dir);
    // The xss playbook schedules a medium-risk exploit_validation action that
    // requires human approval. In a non-lab program the policy gate returns
    // "require_approval", which the action queue stores as status="pending".
    // The guard must fire BEFORE runSafeChecks / validate* / analyzeJavaScript
    // are ever invoked, so we spy on globalThis.fetch to make any live escape
    // a loud failure.
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    fetchSpy.mockImplementation(() => {
      throw new Error("live fetch must not run while action is pending");
    });

    let result: Awaited<ReturnType<typeof runHuntPlaybook>> | undefined;
    try {
      result = await runHuntPlaybook(runtime, "xss", "https://api.example.com/", true);

      // The job must be paused; ok/paused are both true because the playbook
      // finished its planning phase successfully and intentionally halted for
      // human approval — that is a non-failure, planned halt, not a failure.
      // No findings may be created, and zero fetch calls may have escaped.
      expect(result.ok).toBe(true);
      expect(result.paused).toBe(true);
      expect(result.findingsCreated).toHaveLength(0);
      expect(result.nextCommands).toEqual(
        expect.arrayContaining([`bounty actions review --job ${result.jobId}`, `bounty review --job ${result.jobId}`]),
      );
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(runtime.jobs.get(result.jobId)?.status).toBe("paused");
      expect(runtime.actions.summarize(result.jobId)).toMatchObject({ total: 3, pending: 3, blocked: 0, executed: 0 });
      const liveActions = runtime.actions.list(result.jobId);
      expect(liveActions.filter((action) => action.adapter === "manual-validation").every((action) => action.requiredForCompletion === false && action.metadata?.handoffOnly === true)).toBe(true);

      // The pending action queued by the xss playbook must still be present
      // and in status="pending" — the guard must not silently flip it.
      const actions = runtime.actions.list(result.jobId);
      expect(actions.some((action) => action.status === "pending")).toBe(true);

      // The last recorded workflow event for this job must be the paused
      // approval-required event so downstream review tooling can find it.
      const events = runtime.events.list(result.jobId);
      const lastEvent = events[events.length - 1];
      expect(lastEvent?.status).toBe("paused");
      expect(lastEvent?.metadata?.reason).toBe("approval_required");
      expect(lastEvent?.metadata?.pendingActions).toBe(3);
      expect(lastEvent?.metadata?.blockedActions).toBe(0);
    } finally {
      fetchSpy.mockRestore();
      runtime.db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps lab_mode live playbooks behind the lifecycle handoff in a planning-only fixture", async () => {
    // P0.2 containment regression: lab_mode must NOT exempt live playbooks
    // from the approval gate. With lab_mode=true and a non-lab-offensive
    // playbook (xss), the exploit_validation capability still resolves to
    // require_approval. The guard must pause the run before any network call.
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-approval-bypass-lab-"));
    const runtime = createReconRuntime(dir, {
      ...reconConfig,
      program: `${reconConfig.program}-lab`,
      rules: { ...reconConfig.rules, lab_mode: true },
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    fetchSpy.mockImplementation(() => {
      throw new Error("lab-mode live fetch must not run while action is pending");
    });

    let result: Awaited<ReturnType<typeof runHuntPlaybook>> | undefined;
    try {
      result = await runHuntPlaybook(runtime, "xss", "https://api.example.com/", true);

      // Same pause contract as the non-lab case, but with lab_mode enabled.
      // The lab_mode exception that used to allow the live run to proceed
      // is gone: ok=true, paused=true, no findings, no fetch calls, job
      // paused, and the workflow event is the approval_required pause.
      expect(result.ok).toBe(true);
      expect(result.paused).toBe(true);
      expect(result.findingsCreated).toHaveLength(0);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(runtime.jobs.get(result.jobId)?.status).toBe("paused");
      expect(runtime.actions.summarize(result.jobId)).toMatchObject({ total: 3, pending: 3, blocked: 0, executed: 0 });

      const events = runtime.events.list(result.jobId);
      const lastEvent = events[events.length - 1];
      expect(lastEvent?.status).toBe("paused");
      expect(lastEvent?.metadata?.reason).toBe("approval_required");
      expect(lastEvent?.metadata?.pendingActions).toBe(3);
    } finally {
      fetchSpy.mockRestore();
      runtime.db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails closed runHuntPlaybook when an action is policy-blocked and emits zero network traffic", async () => {
    // P0.2 containment regression: blocked actions must NOT be treated as
    // pausable, must NOT be approved by humans, and must NOT run any network
    // traffic. Configure a program where automated_scanning=none, which the
    // policy gate uses to block every http.* action (including the xss
    // safe-checks and manual-validation actions). In live mode the playbook
    // must report ok=false, paused=undefined, job=failed, and a status=blocked
    // workflow event with a policy-blocked message — and zero fetch calls.
    const blockedProgramConfig: ProgramConfig = {
      ...reconConfig,
      program: `${reconConfig.program}-blocked`,
      rules: { ...reconConfig.rules, automated_scanning: "none" },
    };
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-policy-blocked-"));
    const runtime = createReconRuntime(dir, blockedProgramConfig);
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    fetchSpy.mockImplementation(() => {
      throw new Error("live fetch must not run while actions are policy-blocked");
    });

    let result: Awaited<ReturnType<typeof runHuntPlaybook>> | undefined;
    try {
      result = await runHuntPlaybook(runtime, "xss", "https://api.example.com/", true);

      // Fail-closed contract: ok=false, paused is not true, no findings, no
      // fetch calls, job is marked failed, and a policy-blocked message is
      // recorded. Blocked actions are not pausable; the run did not finish
      // successfully.
      expect(result.ok).toBe(false);
      expect(result.paused).toBeUndefined();
      expect(result.findingsCreated).toHaveLength(0);
      expect(result.nextCommands).not.toContain(`bounty actions review --job ${result.jobId}`);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(runtime.jobs.get(result.jobId)?.status).toBe("failed");
      const summary = runtime.actions.summarize(result.jobId);
      expect(summary.blocked).toBeGreaterThan(0);
      expect(summary.pending).toBe(0);

      // The workflow event for this job must be the blocked event with a
      // policy-blocked reason. The pause gate must NOT have fired even if
      // some pending rows were created, because blocked wins.
      const events = runtime.events.list(result.jobId);
      const lastEvent = events[events.length - 1];
      expect(lastEvent?.status).toBe("blocked");
      expect(lastEvent?.metadata?.reason).toBe("policy_blocked");
      expect(lastEvent?.message).toMatch(/policy-blocked/);
    } finally {
      fetchSpy.mockRestore();
      runtime.db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("completes runHuntPlaybook dry-run while retaining non-required handoff rows", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-approval-bypass-dry-"));
    const runtime = createReconRuntime(dir);
    // Positive control: the same xss playbook schedules a pending
    // exploit_validation action. With `live=false` the live approval-pause
    // guard is skipped, so the playbook must reach completion while the
    // pending action remains queued for human review.
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    fetchSpy.mockImplementation(() => {
      throw new Error("dry-run playbook must not perform network I/O");
    });

    let result: Awaited<ReturnType<typeof runHuntPlaybook>> | undefined;
    try {
      result = await runHuntPlaybook(runtime, "xss", "https://api.example.com/", false);

      // The pause branch must NOT have fired: ok=true, paused is undefined,
      // and the job is reported as completed.
      expect(result.ok).toBe(true);
      expect(result.paused).toBeUndefined();
      expect(runtime.jobs.get(result.jobId)?.status).toBe("completed");

      // The same xss pending action must still be queued — the playbook
      // planning phase is independent of the live approval gate.
      expect(runtime.actions.summarize(result.jobId)).toMatchObject({ total: 3, pending: 3, executed: 0 });
      expect(runtime.actions.list(result.jobId).every((action) => !action.requiredForCompletion)).toBe(true);

      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
      runtime.db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const reconConfig: ProgramConfig = {
  program: "recon-live-fixture",
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

function createReconRuntime(root: string, config: ProgramConfig = reconConfig): Runtime {
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
    evidence: new EvidenceStore(db, paths.evidenceDir, {
      maskSecrets: config.evidence.mask_secrets !== false,
      trustedArtifactRoots: [paths.reportsDir],
    }),
    crawlGraph: new CrawlGraphStore(db),
    recon: new ReconObservationStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
  };
}

function nodePrintArgs(lines: string[]): string[] {
  return ["-e", `for (const line of ${JSON.stringify(lines)}) console.log(line);`];
}

function replaceToolArgs(replacements: Array<{ tool: string; args: string[] }>): () => void {
  const originals: Array<{ spec: (typeof TOOL_ADAPTER_SPECS)[number]; args: string[] }> = [];
  for (const replacement of replacements) {
    const spec = TOOL_ADAPTER_SPECS.find((candidate) => candidate.tool === replacement.tool);
    expect(spec, replacement.tool).toBeDefined();
    originals.push({ spec: spec!, args: [...spec!.defaultArgs] });
    spec!.defaultArgs = replacement.args;
  }
  return () => {
    for (const original of originals) {
      original.spec.defaultArgs = original.args;
    }
  };
}
