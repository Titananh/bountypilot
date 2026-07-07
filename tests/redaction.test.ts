import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ActionQueue } from "../src/core/actions/action-queue.js";
import { ActionReviewStore } from "../src/core/actions/action-review-store.js";
import { PolicyGate } from "../src/core/policy/policy-gate.js";
import { RateLimiter } from "../src/core/rate-limit/rate-limiter.js";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import { saveProgramConfig } from "../src/core/workspace.js";
import { JobManager } from "../src/core/jobs/job-manager.js";
import { WorkflowEventStore } from "../src/core/jobs/workflow-event-store.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import type { Runtime } from "../src/cli/runtime.js";
import { openBountyDatabase, type BountyDatabase } from "../src/stores/db/database.js";
import { CrawlGraphStore } from "../src/stores/crawl-graph-store.js";
import { EvidenceStore } from "../src/stores/evidence-store.js";
import { FindingCandidateStore } from "../src/stores/finding-candidate-store.js";
import { FindingStore } from "../src/stores/finding-store.js";
import { maskSecretsDeep } from "../src/utils/secrets.js";
import { writeHandoffBundle } from "../src/workflows/handoff-bundle.js";
import { writeWorkspaceSummary } from "../src/workflows/workspace-summary.js";

const roots: string[] = [];
const dbs: BountyDatabase[] = [];

afterEach(() => {
  for (const db of dbs.splice(0)) {
    db.close();
  }
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("secret redaction", () => {
  it("masks structured secrets without mutating the original object", () => {
    const input = {
      token: "live-token",
      nested: {
        password: "letmein",
        message: "authorization: bearer auth-secret",
        headers: {
          authorization: "Bearer header-secret",
          "x-api-key": "key-secret",
        },
      },
      public: "keep me",
    };

    const masked = maskSecretsDeep(input);

    expect(input.token).toBe("live-token");
    expect(masked.public).toBe("keep me");
    expect(JSON.stringify(masked)).not.toContain("live-token");
    expect(JSON.stringify(masked)).not.toContain("letmein");
    expect(JSON.stringify(masked)).not.toContain("auth-secret");
    expect(JSON.stringify(masked)).not.toContain("header-secret");
    expect(JSON.stringify(masked)).not.toContain("key-secret");
    expect(masked.token).toBe("[REDACTED]");
    expect(masked.nested.headers.authorization).toBe("[REDACTED]");
  });

  it("masks workflow event messages and metadata before persistence", () => {
    const { db, events } = createStores();

    const recorded = events.record({
      jobId: "job-1",
      phase: "workflow",
      status: "running",
      message: "starting token=event-message-secret",
      metadata: {
        token: "event-token-secret",
        nested: {
          password: "event-password-secret",
          detail: "authorization: bearer event-auth-secret",
        },
      },
    });

    const listed = events.list("job-1")[0];
    const raw = db.prepare("SELECT message, metadata_json FROM workflow_events WHERE id = ?").get(recorded.id) as {
      message: string;
      metadata_json: string;
    };

    for (const value of [recorded, listed, raw]) {
      const serialized = JSON.stringify(value);
      expect(serialized).not.toContain("event-message-secret");
      expect(serialized).not.toContain("event-token-secret");
      expect(serialized).not.toContain("event-password-secret");
      expect(serialized).not.toContain("event-auth-secret");
      expect(serialized).toContain("[REDACTED]");
    }
  });

  it("masks action review notes before persistence", () => {
    const { db, reviews } = createStores();

    const recorded = reviews.record({
      actionId: "action-1",
      jobId: "job-1",
      decision: "approved",
      note: "approved with password=review-password-secret and token=review-token-secret",
    });

    const listed = reviews.listForAction("action-1")[0];
    const raw = db.prepare("SELECT note FROM action_reviews WHERE id = ?").get(recorded.id) as { note: string };

    for (const value of [recorded, listed, raw]) {
      const serialized = JSON.stringify(value);
      expect(serialized).not.toContain("review-password-secret");
      expect(serialized).not.toContain("review-token-secret");
      expect(serialized).toContain("[REDACTED]");
    }
  });

  it("masks secrets when writing handoff bundle snapshots", () => {
    const runtime = createRuntime();
    const job = runtime.jobs.create("run", "safe", "https://api.example.com/?token=job-target-secret");
    runtime.events.record({
      jobId: job.id,
      phase: "workflow",
      status: "running",
      message: "running with token=timeline-message-secret",
      metadata: {
        token: "timeline-token-secret",
        nested: {
          password: "timeline-password-secret",
        },
      },
    });
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "safe-checks",
      actionType: "http.head",
      target: "https://api.example.com/?token=action-target-secret",
      riskLevel: "low",
      requiresApproval: true,
    });
    runtime.reviews.record({
      actionId: action.id,
      jobId: job.id,
      decision: "approved",
      note: "approved password=handoff-review-secret",
    });
    const auditDir = path.join(runtime.paths.jobsDir, job.id);
    mkdirSync(auditDir, { recursive: true });
    writeFileSync(
      path.join(auditDir, "audit.log"),
      `${JSON.stringify({
        actionType: "legacy.audit",
        reason: "token=audit-reason-secret",
        metadata: { authorization: "Bearer audit-header-secret" },
      })}\nmalformed password=audit-malformed-secret\n`,
      "utf8",
    );

    const outputDir = path.join(runtime.paths.programDir, "handoff-redaction");
    writeHandoffBundle(runtime, { jobId: job.id, output: outputDir });

    const exported = [
      "program.yml",
      "actions.json",
      "workspace-summary.json",
      "manifest.json",
      path.join("jobs", job.id, "timeline.json"),
      path.join("jobs", job.id, "audit.json"),
    ]
      .map((relativePath) => readFileSync(path.join(outputDir, relativePath), "utf8"))
      .join("\n");

    for (const secret of [
      "job-target-secret",
      "timeline-message-secret",
      "timeline-token-secret",
      "timeline-password-secret",
      "action-target-secret",
      "handoff-review-secret",
      "audit-reason-secret",
      "audit-header-secret",
      "audit-malformed-secret",
      "program-config-token-secret",
    ]) {
      expect(exported).not.toContain(secret);
    }
    expect(exported).toContain("[REDACTED]");
  });

  it("filters handoff findings to the selected job", () => {
    const runtime = createRuntime();
    const includedJob = runtime.jobs.create("run", "safe", "https://api.example.com/included");
    const excludedJob = runtime.jobs.create("run", "safe", "https://api.example.com/excluded");
    const includedArtifact = runtime.evidence.writeTextArtifact({
      jobId: includedJob.id,
      adapterName: "safe-checks",
      kind: "tool_output",
      sourceUrl: "https://api.example.com/included",
      relativePath: path.join(includedJob.id, "included.json"),
      content: "{}",
    });
    const excludedArtifact = runtime.evidence.writeTextArtifact({
      jobId: excludedJob.id,
      adapterName: "safe-checks",
      kind: "tool_output",
      sourceUrl: "https://api.example.com/excluded",
      relativePath: path.join(excludedJob.id, "excluded.json"),
      content: "{}",
    });
    const includedFinding = runtime.findings.create({
      title: "Included finding",
      asset: "api.example.com",
      url: "https://api.example.com/included",
      category: "test",
      severityEstimate: "low",
      confidence: "low",
      status: "new",
      evidencePaths: [includedArtifact.path],
      duplicateRisk: "unknown",
      reportabilityScore: 10,
    });
    const excludedFinding = runtime.findings.create({
      title: "Excluded finding",
      asset: "api.example.com",
      url: "https://api.example.com/excluded",
      category: "test",
      severityEstimate: "low",
      confidence: "low",
      status: "new",
      evidencePaths: [excludedArtifact.path],
      duplicateRisk: "unknown",
      reportabilityScore: 10,
    });

    const outputDir = path.join(runtime.paths.programDir, "handoff-job-filter");
    writeHandoffBundle(runtime, { jobId: includedJob.id, output: outputDir });

    const exportedFindings = JSON.parse(readFileSync(path.join(outputDir, "findings.json"), "utf8"));
    expect(exportedFindings.findings.map((finding: any) => finding.id)).toEqual([includedFinding.id]);
    expect(JSON.stringify(exportedFindings)).not.toContain(excludedFinding.id);
  });

  it("masks secrets when writing workspace summary files", () => {
    const runtime = createRuntime();
    const job = runtime.jobs.create("run", "safe", "https://api.example.com/?token=summary-target-secret");
    runtime.events.record({
      jobId: job.id,
      phase: "workflow",
      status: "running",
      message: "summary event password=summary-event-secret",
    });
    runtime.candidates.create({
      id: "cand_summary",
      jobId: job.id,
      title: "Summary candidate",
      asset: "api.example.com",
      url: "https://api.example.com/",
      category: "summary_candidate",
      severityEstimate: "medium",
      confidence: "medium",
      status: "needs_manual_verification",
      evidenceIds: [],
      observationIds: [],
      falsePositiveRisk: "medium",
      duplicateRisk: "unknown",
      reportability: "needs_review",
      reasoningSummary: "Candidate summary export test.",
      nextManualSteps: ["Review candidate."],
    });

    const outputPath = path.join(runtime.paths.programDir, "workspace-summary-redaction.json");
    writeWorkspaceSummary(runtime, outputPath);

    const exported = readFileSync(outputPath, "utf8");
    const parsed = JSON.parse(exported);
    expect(parsed.candidates).toMatchObject({ total: 1, readyForDraft: 0, linkedFindings: 0 });
    expect(exported).not.toContain("summary-target-secret");
    expect(exported).not.toContain("summary-event-secret");
    expect(exported).toContain("[REDACTED]");
  });
});

function createStores(): { db: BountyDatabase; events: WorkflowEventStore; reviews: ActionReviewStore } {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-redaction-stores-"));
  roots.push(root);
  const db = openBountyDatabase(path.join(root, "bounty.sqlite"));
  dbs.push(db);
  return {
    db,
    events: new WorkflowEventStore(db),
    reviews: new ActionReviewStore(db),
  };
}

function createRuntime(): Runtime {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-redaction-runtime-"));
  roots.push(root);
  const config: ProgramConfig = {
    program: "redaction-handoff-test",
    platform: "hackerone",
    in_scope: ["api.example.com"],
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
    integrations: {
      secret_adapter: {
        enabled: true,
        token: "program-config-token-secret",
      },
    },
  };
  const paths = saveProgramConfig(config, root);
  const db = openBountyDatabase(paths.dbFile);
  dbs.push(db);
  return {
    config,
    paths,
    db,
    scopeGuard: new ScopeGuard(config),
    policyGate: new PolicyGate(),
    rateLimiter: new RateLimiter(config.rules.rate_limit),
    candidates: new FindingCandidateStore(db),
    findings: new FindingStore(db),
    evidence: new EvidenceStore(db, paths.evidenceDir),
    crawlGraph: new CrawlGraphStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
  };
}
