import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
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
import { FindingStore } from "../src/stores/finding-store.js";
import { CrawlGraphStore } from "../src/stores/crawl-graph-store.js";
import { ActionExecutor } from "../src/workflows/action-executor.js";
import { approvedExecutableStorePath, createExecutableApprovalStore } from "../src/utils/local-process-policy.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import type { Runtime } from "../src/cli/runtime.js";

describe("ExternalIntegrationExecutor", () => {
  it("executes an explicitly enabled trusted external crawler process", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-external-executor-"));
    const scriptPath = path.join(root, "fake-crawler.mjs");
    writeFileSync(
      scriptPath,
      [
        "import { writeFileSync } from 'node:fs';",
        "const target = process.argv[process.argv.indexOf('--target') + 1];",
        "const output = process.argv[process.argv.indexOf('--output') + 1];",
        "const links = { internal: [{ href: new URL('/docs', target).toString(), text: 'Docs' }, { url: '/about', title: 'About' }], external: [{ href: 'https://outside.example/' }] };",
        "const pages = [{ source_url: new URL('/pricing', target).toString(), title: 'Pricing' }];",
        "const endpoints = [new URL('/graphql', target).toString(), '/api/profile'];",
        "const jsAssets = [new URL('/static/app.js', target).toString()];",
        "const forms = [{ action: '/login', method: 'post' }];",
        "const routes = ['/account/settings'];",
        "writeFileSync(output, JSON.stringify({ target, wroteOutput: true, result: { links, pages, endpoints, jsAssets, forms, routes } }), 'utf8');",
        "console.log(JSON.stringify({ ok: true, target, links }));",
      ].join("\n"),
      "utf8",
    );
    const runtime = createTestRuntime(root, process.execPath, true, scriptPath);
    const rateLimiter = new RecordingRateLimiter();
    runtime.rateLimiter = rateLimiter;
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("external-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "crawl4ai",
      actionType: "crawler.fetch",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    const result = await new ActionExecutor(runtime).execute(action.id);

    expect(rateLimiter.waits).toEqual([target]);
    expect(result.status).toBe("executed");
    expect(result.evidenceCreated).toBe(2);
    expect(runtime.actions.get(action.id)?.status).toBe("executed");
    const artifact = runtime.evidence.list().find((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run"));
    expect(artifact).toBeDefined();
    expect(artifact!.path).toContain(action.id);
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.execute).toBe(true);
    expect(content.exitCode).toBe(0);
    expect(content.commandSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(content.envKeys).not.toContain("PATH");
    expect(content.envKeys).not.toContain("HOME");
    expect(content.stdout).toContain(target);
    expect(content.normalizedCrawlerOutput.links.length).toBeGreaterThan(0);
    expect(content.normalizedCrawlerOutput.endpointCandidates).toEqual(
      expect.arrayContaining(["/api/profile", "http://127.0.0.1:8080/graphql"]),
    );
    expect(content.normalizedCrawlerOutput.jsAssets).toEqual(
      expect.arrayContaining(["http://127.0.0.1:8080/static/app.js"]),
    );
    expect(content.normalizedCrawlerOutput.forms).toEqual(
      expect.arrayContaining([expect.objectContaining({ action: "/login", method: "POST" })]),
    );
    expect(content.normalizedCrawlerOutput.routes).toEqual(expect.arrayContaining(["/account/settings"]));
    expect(runtime.crawlGraph.listPages().map((page) => page.url)).toEqual(
      expect.arrayContaining([
        target,
        "http://127.0.0.1:8080/docs",
        "http://127.0.0.1:8080/about",
        "http://127.0.0.1:8080/pricing",
        "http://127.0.0.1:8080/graphql",
        "http://127.0.0.1:8080/api/profile",
        "http://127.0.0.1:8080/static/app.js",
        "http://127.0.0.1:8080/login",
        "http://127.0.0.1:8080/account/settings",
      ]),
    );
    expect(runtime.crawlGraph.getPage("http://127.0.0.1:8080/docs")?.title).toBe("Docs");
    expect(runtime.crawlGraph.getPage("http://127.0.0.1:8080/pricing")?.title).toBe("Pricing");
    expect(runtime.crawlGraph.getPage("https://outside.example/")).toBeUndefined();
  });

  it("executes a pinned npm package entrypoint through an approved node executable", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-external-package-"));
    const scriptPath = writeCrawlerPackage(root, "fake-crawler", "1.0.0", "dist/cli.mjs");
    const runtime = createTestRuntime(root, process.execPath, true, scriptPath, 5_000, {
      package: "fake-crawler",
      package_version: "1.0.0",
      entrypoint: "dist/cli.mjs",
    });
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("external-package-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "crawl4ai",
      actionType: "crawler.fetch",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    const result = await new ActionExecutor(runtime).execute(action.id);

    expect(result.status).toBe("executed");
    const artifact = runtime.evidence.list().find((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run"));
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.command).toBe(resolveRealPath(process.execPath));
    expect(content.package).toMatchObject({ name: "fake-crawler", version: "1.0.0", entrypoint: resolveRealPath(scriptPath) });
    expect(content.package.entrypointSha256).toBe(sha256File(scriptPath));
    expect(content.package.packageJsonSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(content.args[0]).toBe(resolveRealPath(scriptPath));
    expect(content.stdout).toContain(target);
  });

  it("refuses pinned npm package entrypoints when the entrypoint hash drifts", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-external-package-drift-"));
    const scriptPath = writeCrawlerPackage(root, "fake-crawler", "1.0.0", "dist/cli.mjs");
    const runtime = createTestRuntime(root, process.execPath, true, scriptPath, 5_000, {
      package: "fake-crawler",
      package_version: "1.0.0",
      entrypoint: "dist/cli.mjs",
      entrypoint_sha256: sha256File(scriptPath),
    });
    writeFileSync(scriptPath, "console.log('changed');\n", "utf8");
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("external-package-drift-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "crawl4ai",
      actionType: "crawler.fetch",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "PACKAGE_ENTRYPOINT_HASH_MISMATCH",
    });
    expect(runtime.actions.get(action.id)?.status).toBe("failed");
    expect(runtime.evidence.list().filter((item) => item.adapterName === "crawl4ai")).toHaveLength(0);
  });

  it("refuses external execution unless the integration opts in explicitly", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-external-disabled-"));
    const runtime = createTestRuntime(root, process.execPath, false);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("external-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "crawl4ai",
      actionType: "crawler.fetch",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toThrow("planning only");
    expect(runtime.actions.get(action.id)?.status).toBe("failed");
  });

  it("refuses external execution when the executable has not been locally approved", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-external-unapproved-"));
    const scriptPath = path.join(root, "fake-crawler.mjs");
    writeFileSync(scriptPath, "console.log(JSON.stringify({ ok: true }));", "utf8");
    const runtime = createTestRuntime(root, process.execPath, true, scriptPath);
    rmSync(approvedExecutableStorePath(runtime.paths.workspace.integrationsDir), { force: true });
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("external-unapproved-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "crawl4ai",
      actionType: "crawler.fetch",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "EXECUTABLE_APPROVAL_MISSING",
    });
    expect(runtime.actions.get(action.id)?.status).toBe("failed");
  });

  it("blocks hardcoded out-of-scope URLs in external process arguments before spawn", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-external-scope-args-"));
    const markerPath = path.join(root, "external-process-ran.txt");
    const scriptPath = path.join(root, "marker-crawler.mjs");
    writeFileSync(
      scriptPath,
      [
        "import { writeFileSync } from 'node:fs';",
        `writeFileSync(${JSON.stringify(markerPath)}, 'ran', 'utf8');`,
        "console.log('ran');",
      ].join("\n"),
      "utf8",
    );
    const runtime = createTestRuntime(root, process.execPath, true, scriptPath);
    const crawl4aiConfig = runtime.config.integrations.crawl4ai as { args: string[] };
    crawl4aiConfig.args = [
      scriptPath,
      "--target",
      "{target}",
      "--callback",
      "https://evil.example/callback?token=secret-value",
      "--output",
      "{output}",
    ];
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("external-scope-args-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "crawl4ai",
      actionType: "crawler.fetch",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toMatchObject({
      code: "EXTERNAL_ARGUMENT_SCOPE_BLOCKED",
    });
    expect(existsSync(markerPath)).toBe(false);
    expect(runtime.actions.get(action.id)?.status).toBe("failed");
  });

  it("kills external process trees on timeout", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-external-timeout-"));
    const scriptPath = path.join(root, "timeout-crawler.mjs");
    const markerPath = path.join(root, "child-still-running.txt");
    const spawnedPath = path.join(root, "child-spawned.txt");
    writeFileSync(
      scriptPath,
      [
        "import { spawn } from 'node:child_process';",
        "import { writeFileSync } from 'node:fs';",
        `const markerPath = ${JSON.stringify(markerPath)};`,
        `const spawnedPath = ${JSON.stringify(spawnedPath)};`,
        "spawn(process.execPath, ['-e', `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(markerPath)}, 'alive'), 1200); setInterval(() => {}, 1000);`], { stdio: 'ignore' });",
        "writeFileSync(spawnedPath, 'spawned');",
        "setInterval(() => {}, 1000);",
      ].join("\n"),
      "utf8",
    );
    const runtime = createTestRuntime(root, process.execPath, true, scriptPath, 250);
    const target = "http://127.0.0.1:8080/";
    const job = runtime.jobs.create("external-timeout-test", "safe", target);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "crawl4ai",
      actionType: "crawler.fetch",
      target,
      riskLevel: "low",
      requiresApproval: false,
    });

    await expect(new ActionExecutor(runtime).execute(action.id)).rejects.toThrow("timed out");
    expect(runtime.actions.get(action.id)?.status).toBe("failed");
    expect(existsSync(spawnedPath)).toBe(true);

    await delay(1_600);

    // Some Windows sandboxes deny taskkill /T even for child processes; the timeout artifact is still asserted below.
    if (process.platform !== "win32") {
      expect(existsSync(markerPath)).toBe(false);
    }
    const artifact = runtime.evidence.list().find((item) => item.adapterName === "crawl4ai" && item.path.includes("external-run"));
    expect(artifact).toBeDefined();
    const content = JSON.parse(readFileSync(artifact!.path, "utf8"));
    expect(content.timedOut).toBe(true);
  }, 30_000);
});

function createTestRuntime(
  root: string,
  command: string,
  allowExecute = true,
  scriptPath?: string,
  timeoutMs = 5_000,
  packageExecution?: {
    package: string;
    package_version: string;
    entrypoint: string;
    entrypoint_sha256?: string;
    package_json_sha256?: string;
  },
): Runtime {
  const processArgs = ["--target", "{target}", "--output", "{output}"];
  const config: ProgramConfig = {
    program: "external-executor-test",
    platform: "hackerone",
    in_scope: ["127.0.0.1"],
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
      crawl4ai: {
        enabled: true,
        type: "crawler",
        ...(packageExecution
          ? {
              execution: {
                ...packageExecution,
                args: processArgs,
                timeout_ms: timeoutMs,
              },
            }
          : {
              command,
              args: allowExecute ? [scriptPath, ...processArgs].filter(Boolean) : [],
              timeout_ms: timeoutMs,
            }),
        allow_execute: allowExecute,
        capabilities: ["crawler.fetch"],
      },
    },
  };
  const paths = ensureProgramWorkspace(config.program, root);
  const db = openBountyDatabase(paths.dbFile);
  const runtime: Runtime = {
    config,
    paths,
    db,
    scopeGuard: new ScopeGuard(config),
    policyGate: new PolicyGate(config.rules),
    rateLimiter: new RateLimiter(config.rules.rate_limit),
    findings: new FindingStore(db),
    evidence: new EvidenceStore(db, paths.evidenceDir, { trustedArtifactRoots: [paths.reportsDir] }),
    crawlGraph: new CrawlGraphStore(db),
    jobs: new JobManager(db),
    events: new WorkflowEventStore(db),
    actions: new ActionQueue(db),
    reviews: new ActionReviewStore(db),
  };
  if (allowExecute) {
    createExecutableApprovalStore(paths.workspace.integrationsDir).approve({
      integration: "crawl4ai",
      command: packageExecution ? process.execPath : command,
    });
  }
  return runtime;
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
      "writeFileSync(output, JSON.stringify({ target, packageEntrypoint: true }), 'utf8');",
      "console.log(JSON.stringify({ ok: true, target, packageEntrypoint: true }));",
    ].join("\n"),
    "utf8",
  );
  return scriptPath;
}

function resolveRealPath(filePath: string): string {
  return realpathSync.native(filePath);
}

function sha256File(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class RecordingRateLimiter extends RateLimiter {
  readonly waits: string[] = [];

  override async wait(urlOrHost: string): Promise<void> {
    this.waits.push(urlOrHost);
  }
}
