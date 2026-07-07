import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { BountyDatabase } from "../src/stores/db/database.js";
import { describe, expect, it } from "vitest";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { ReconObservationStore } from "../src/stores/recon-observation-store.js";
import {
  parseToolOutput,
  TOOL_ADAPTER_SPECS,
  toolApprovalIntegrationName,
} from "../src/integrations/tool-manager/tool-adapter-runner.js";
import { ToolManager } from "../src/integrations/tool-manager/tool-manager.js";
import { runHuntRecon } from "../src/hunting/recon-engine.js";
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

  it("runs live recon through an approved executable and stores scoped observations", async () => {
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
          status: "executed",
          approvalPresent: true,
          observations: 1,
        }),
      ]);
      expect(result.observations).toEqual([
        expect.objectContaining({
          kind: "host",
          normalizedValue: "api.example.com",
          sourceAdapter: "subfinder",
          sourceUrl: "https://api.example.com/",
          scopeAllowed: true,
        }),
      ]);
      expect(runtime.recon.list({ jobId: result.jobId, sourceAdapter: "subfinder" })).toHaveLength(1);
      expect(result.evidence).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ adapterName: "hunt-recon", kind: "research_note", jobId: result.jobId }),
          expect.objectContaining({ adapterName: "subfinder", kind: "tool_output", jobId: result.jobId }),
        ]),
      );
      expect(runtime.jobs.get(result.jobId)?.status).toBe("completed");
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
          expect.objectContaining({ tool: "subfinder", status: "executed", observations: 2 }),
          expect.objectContaining({ tool: "httpx", status: "executed", observations: 3 }),
          expect.objectContaining({ tool: "katana", status: "executed", observations: 3 }),
          expect.objectContaining({ tool: "nuclei", status: "pending", approvalPresent: false }),
          expect.objectContaining({ tool: "ffuf", status: "pending", approvalPresent: false }),
          expect.objectContaining({ tool: "dalfox", status: "pending", approvalPresent: false }),
        ]),
      );
      expect(result.observations.map((observation) => observation.kind)).toEqual(
        expect.arrayContaining(["host", "parameter", "technology", "endpoint", "form", "js_asset"]),
      );
      expect(result.observations.map((observation) => observation.normalizedValue)).toEqual(
        expect.arrayContaining([
          "api.example.com",
          "cdn.example.com",
          "https://api.example.com/v1/users?debug=true",
          "nginx",
          "express",
          "https://api.example.com/login",
          "https://api.example.com/session",
          "https://cdn.example.com/static/app.js",
        ]),
      );
      expect(result.observations.map((observation) => observation.normalizedValue)).not.toContain("staging.example.com");
      expect(result.observations.map((observation) => observation.normalizedValue)).not.toContain("https://staging.example.com/private");
      expect(runtime.recon.list({ jobId: result.jobId })).toHaveLength(result.observations.length);
      expect(runtime.crawlGraph.listPages().map((page) => page.url)).toEqual(
        expect.arrayContaining([
          "https://api.example.com/v1/users?debug=true",
          "https://api.example.com/login",
          "https://api.example.com/session",
          "https://cdn.example.com/static/app.js",
        ]),
      );
      expect(runtime.actions.summarize(result.jobId)).toMatchObject({
        total: 6,
        pending: 3,
        executed: 3,
      });
      expect(runtime.jobs.get(result.jobId)?.status).toBe("paused");
      expect(result.nextCommands).toEqual(expect.arrayContaining([`bounty actions review --job ${result.jobId}`]));
    } finally {
      restoreSpecs();
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

function createReconRuntime(root: string): Runtime {
  const paths = ensureProgramWorkspace(reconConfig.program, root);
  const db = openBountyDatabase(paths.dbFile);
  return {
    config: reconConfig,
    paths,
    db,
    scopeGuard: new ScopeGuard(reconConfig),
    policyGate: new PolicyGate(reconConfig.rules),
    rateLimiter: new RateLimiter(reconConfig.rules.rate_limit),
    candidates: new FindingCandidateStore(db),
    findings: new FindingStore(db),
    evidence: new EvidenceStore(db, paths.evidenceDir, {
      maskSecrets: reconConfig.evidence.mask_secrets !== false,
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
