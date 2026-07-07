import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { Runtime } from "../../cli/runtime.js";
import type { ActionRecord } from "../../core/actions/action-queue.js";
import type { ExecutionMode } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";
import { killProcessTree, spawnOutputProcess } from "../../utils/process-tree.js";
import { maskSecrets } from "../../utils/secrets.js";
import {
  assertLocalProcessArgument,
  localProcessEnv,
  resolveApprovedLocalProcess,
  type LocalProcessConfig,
  type VerifiedExecutable,
} from "../../utils/local-process-policy.js";
import { IntegrationManager, type ResolvedIntegration } from "../integration-manager/integration-manager.js";

export interface ExternalIntegrationExecutionResult {
  message: string;
  evidenceCreated: number;
  findingsCreated: number;
}

interface ProcessResult {
  command: string;
  commandSha256: string;
  args: string[];
  cwd: string;
  envKeys: string[];
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
}

interface IntegrationProcessConfig extends LocalProcessConfig {
  timeout_ms?: number;
}

interface NormalizedCrawlerOutput {
  pages: Array<{ url: string; title?: string; status?: number }>;
  links: string[];
  endpointCandidates: string[];
  jsAssets: string[];
  forms: Array<{ action?: string; method?: string; sourceUrl?: string }>;
  routes: string[];
}

const EXECUTABLE_TYPES = new Set(["crawler", "research-skill", "external-tool"]);
const DEFAULT_TIMEOUT_MS = 30_000;
const TIMEOUT_KILL_GRACE_MS = 2_000;
const MAX_CAPTURE_BYTES = 512_000;

export class ExternalIntegrationExecutor {
  constructor(private readonly runtime: Runtime) {}

  async execute(action: ActionRecord, scopedUrl: string, mode: ExecutionMode): Promise<ExternalIntegrationExecutionResult> {
    const manager = new IntegrationManager(this.runtime.config);
    const integration = manager.get(action.adapter);
    if (!integration) {
      throw new BountyPilotError(`Integration not found: ${action.adapter}`, "EXTERNAL_INTEGRATION_NOT_FOUND");
    }
    if (!EXECUTABLE_TYPES.has(integration.type)) {
      throw new BountyPilotError(
        `Integration ${integration.name} is ${integration.type}; external process execution is only enabled for crawler, research-skill, and external-tool adapters.`,
        "EXTERNAL_EXECUTOR_UNSUPPORTED_TYPE",
      );
    }
    if (!isExecutionEnabled(integration)) {
      throw new BountyPilotError(
        `Integration ${integration.name} is configured for planning only. Set allow_execute=true or execution.enabled=true to run a trusted local process.`,
        "EXTERNAL_EXECUTION_DISABLED",
      );
    }

    const validation = manager.validateCallPlan({
      integration: integration.name,
      capability: action.actionType,
      actionType: action.actionType,
      target: scopedUrl,
      mode,
      riskLevel: action.riskLevel,
    });
    if (!validation.ok) {
      throw new BountyPilotError(validation.reasons.join("; "), "EXTERNAL_EXECUTION_PRECHECK_BLOCKED");
    }

    const processConfig = processConfigForIntegration(integration);
    const launch = resolveApprovedLocalProcess({
      integration: integration.name,
      config: processConfig,
      integrationsDir: this.runtime.paths.workspace.integrationsDir,
      cwd: this.runtime.paths.programDir,
    });

    const outputRelativePath = path.join(
      action.jobId ?? "ad-hoc-actions",
      `${safeFileName(integration.name)}-${safeFileName(action.actionType)}-${safeFileName(action.id)}-external-run.json`,
    );
    const rawOutputRelativePath = path.join(
      action.jobId ?? "ad-hoc-actions",
      `${safeFileName(integration.name)}-${safeFileName(action.actionType)}-${safeFileName(action.id)}-tool-output.json`,
    );
    const outputPath = path.join(this.runtime.paths.evidenceDir, outputRelativePath);
    const rawOutputPath = path.join(this.runtime.paths.evidenceDir, rawOutputRelativePath);
    mkdirSync(path.dirname(outputPath), { recursive: true });
    const args = [
      ...launch.baseArgs,
      ...renderArgs({
        args: processConfig.args ?? [],
        target: scopedUrl,
        outputPath: rawOutputPath,
        jobId: action.jobId,
        mode,
        appendTarget: validation.capability?.requiresTarget === true,
      }),
    ];
    assertArgumentUrlsStayInScope(this.runtime, args);
    const timeoutMs = processConfig.timeout_ms ?? DEFAULT_TIMEOUT_MS;

    await this.runtime.rateLimiter.wait(scopedUrl);
    const result = await runProcess({
      executable: launch.executable,
      args,
      cwd: this.runtime.paths.programDir,
      timeoutMs,
    });
    const rawOutput = readOptionalText(rawOutputPath);
    const normalizedCrawlerOutput =
      result.exitCode === 0 && !result.timedOut && integration.type === "crawler"
        ? normalizeCrawlerOutput(scopedUrl, [result.stdout, rawOutput].filter(Boolean).join("\n"))
        : emptyNormalizedCrawlerOutput();
    if (
      normalizedCrawlerOutput.links.length > 0 ||
      normalizedCrawlerOutput.pages.length > 0 ||
      normalizedCrawlerOutput.endpointCandidates.length > 0 ||
      normalizedCrawlerOutput.jsAssets.length > 0 ||
      normalizedCrawlerOutput.routes.length > 0
    ) {
      this.recordCrawlerGraph(scopedUrl, normalizedCrawlerOutput);
    }

    let evidenceCreated = 1;
    if (rawOutput !== undefined) {
      this.runtime.evidence.create({
        jobId: action.jobId,
        adapterName: integration.name,
        kind: "tool_output",
        sourceUrl: scopedUrl,
        path: rawOutputPath,
      });
      evidenceCreated += 1;
    }

    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId: action.jobId,
      adapterName: integration.name,
      kind: "tool_output",
      sourceUrl: scopedUrl,
      relativePath: outputRelativePath,
      content: `${JSON.stringify(
        {
          execute: true,
          integration: integration.name,
          capability: validation.capability?.id ?? action.actionType,
          target: scopedUrl,
          mode,
          timeoutMs,
          command: result.command,
          resolvedCommand: result.command,
          commandSha256: result.commandSha256,
          package: launch.npmPackage
            ? {
                name: launch.npmPackage.name,
                version: launch.npmPackage.version,
                packageJson: launch.npmPackage.packageJson,
                packageJsonSha256: launch.npmPackage.packageJsonSha256,
                entrypoint: launch.npmPackage.entrypoint,
                entrypointSha256: launch.npmPackage.entrypointSha256,
              }
            : undefined,
          args: result.args,
          cwd: result.cwd,
          envKeys: result.envKeys,
          rawOutputPath: rawOutput ? rawOutputPath : undefined,
          rawOutputPreview: rawOutput?.slice(0, 10_000),
          exitCode: result.exitCode,
          signal: result.signal,
          timedOut: result.timedOut,
          durationMs: result.durationMs,
          stdout: result.stdout,
          stderr: result.stderr,
          normalizedCrawlerOutput,
        },
        null,
        2,
      )}\n`,
    });

    if (result.timedOut) {
      throw new BountyPilotError(`External integration ${integration.name} timed out after ${timeoutMs}ms`, "EXTERNAL_TIMEOUT");
    }
    if (result.exitCode !== 0) {
      throw new BountyPilotError(
        `External integration ${integration.name} exited with code ${result.exitCode}. Evidence: ${artifact.path}`,
        "EXTERNAL_NONZERO_EXIT",
      );
    }

    return {
      message: `${integration.name} external execution completed`,
      evidenceCreated,
      findingsCreated: 0,
    };
  }

  private recordCrawlerGraph(
    scopedUrl: string,
    normalized: NormalizedCrawlerOutput,
  ): void {
    this.runtime.crawlGraph.upsertPage({ url: scopedUrl });
    for (const page of normalized.pages) {
      const target = absoluteScopedUrl(page.url, scopedUrl, this.runtime);
      if (!target) continue;
      this.runtime.crawlGraph.upsertPage({ url: target, title: page.title, status: page.status });
      this.runtime.crawlGraph.addEdge(scopedUrl, target);
    }
    for (const link of [
      ...normalized.links,
      ...normalized.endpointCandidates,
      ...normalized.jsAssets,
      ...normalized.routes,
      ...normalized.forms.map((form) => form.action).filter((action): action is string => typeof action === "string"),
    ]) {
      const target = absoluteScopedUrl(link, scopedUrl, this.runtime);
      if (!target) continue;
      this.runtime.crawlGraph.upsertPage({ url: target });
      this.runtime.crawlGraph.addEdge(scopedUrl, target);
    }
  }
}

function isExecutionEnabled(integration: ResolvedIntegration): boolean {
  return integration.config.allow_execute === true || integration.config.execution?.enabled === true;
}

function processConfigForIntegration(integration: ResolvedIntegration): IntegrationProcessConfig {
  const execution = integration.config.execution ?? {};
  return {
    command: execution.command ?? integration.config.command,
    args: execution.args ?? integration.config.args ?? [],
    package: execution.package ?? integration.config.package,
    package_version: execution.package_version ?? integration.config.package_version,
    entrypoint: execution.entrypoint ?? integration.config.entrypoint,
    entrypoint_sha256: execution.entrypoint_sha256 ?? integration.config.entrypoint_sha256,
    package_json_sha256: execution.package_json_sha256 ?? integration.config.package_json_sha256,
    timeout_ms: execution.timeout_ms ?? integration.config.timeout_ms,
  };
}

function renderArgs(input: {
  args: string[];
  target: string;
  outputPath: string;
  jobId?: string;
  mode: ExecutionMode;
  appendTarget: boolean;
}): string[] {
  const rendered = input.args.map((arg) =>
    arg
      .replaceAll("{target}", input.target)
      .replaceAll("{output}", input.outputPath)
      .replaceAll("{jobId}", input.jobId ?? "")
      .replaceAll("{mode}", input.mode),
  );
  if (input.appendTarget && !rendered.includes(input.target) && !input.args.some((arg) => arg.includes("{target}"))) {
    rendered.push(input.target);
  }
  for (const arg of rendered) assertSafeArgument(arg);
  return rendered;
}

function assertArgumentUrlsStayInScope(runtime: Runtime, args: string[]): void {
  for (const arg of args) {
    for (const url of extractHttpUrls(arg)) {
      const result = runtime.scopeGuard.test(url);
      if (!result.allowed) {
        throw new BountyPilotError(
          `External integration argument URL is out of scope: ${maskSecrets(url)} (${result.reason})`,
          "EXTERNAL_ARGUMENT_SCOPE_BLOCKED",
        );
      }
    }
  }
}

function extractHttpUrls(value: string): string[] {
  return [...value.matchAll(/https?:\/\/[^\s"'<>\\]+/gi)].map((match) => trimTrailingUrlPunctuation(match[0]));
}

function trimTrailingUrlPunctuation(value: string): string {
  return value.replace(/[),.;\]}]+$/g, "");
}

function runProcess(input: { executable: VerifiedExecutable; args: string[]; cwd: string; timeoutMs: number }): Promise<ProcessResult> {
  for (const arg of input.args) assertSafeArgument(arg);

  return new Promise((resolve, reject) => {
    const started = Date.now();
    const env = localProcessEnv();
    const child = spawnOutputProcess(input.executable.realPath, input.args, {
      cwd: input.cwd,
      env,
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;
    let killFallback: NodeJS.Timeout | undefined;

    const buildResult = (exitCode: number | null, signal: NodeJS.Signals | null): ProcessResult => ({
      command: input.executable.realPath,
      commandSha256: input.executable.sha256,
      args: input.args,
      cwd: input.cwd,
      envKeys: Object.keys(env).sort(),
      exitCode,
      signal,
      timedOut,
      durationMs: Date.now() - started,
      stdout,
      stderr,
    });
    const clearTimers = () => {
      if (timeout) clearTimeout(timeout);
      if (killFallback) clearTimeout(killFallback);
    };
    const resolveOnce = (result: ProcessResult) => {
      if (settled) return;
      settled = true;
      clearTimers();
      resolve(result);
    };
    const rejectOnce = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimers();
      reject(error);
    };

    timeout = setTimeout(() => {
      timedOut = true;
      killProcessTree(child);
      killFallback = setTimeout(() => {
        resolveOnce(buildResult(null, null));
      }, TIMEOUT_KILL_GRACE_MS);
      killFallback.unref();
    }, input.timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.on("error", (error) => {
      rejectOnce(new BountyPilotError(error.message, "EXTERNAL_PROCESS_SPAWN_FAILED"));
    });
    child.on("close", (exitCode, signal) => {
      resolveOnce(buildResult(exitCode, signal));
    });
  });
}

function assertSafeArgument(argument: string): void {
  assertLocalProcessArgument(argument, "EXTERNAL_ARGUMENT_INVALID");
}

function appendBounded(current: string, chunk: string): string {
  const next = current + chunk;
  return next.length > MAX_CAPTURE_BYTES ? next.slice(0, MAX_CAPTURE_BYTES) : next;
}

function readOptionalText(filePath: string): string | undefined {
  if (!existsSync(filePath)) {
    return undefined;
  }
  return readFileSync(filePath, "utf8").slice(0, MAX_CAPTURE_BYTES);
}

function normalizeCrawlerOutput(seedUrl: string, content: string): NormalizedCrawlerOutput {
  const parsed = parseJsonLike(content);
  if (!parsed) {
    return emptyNormalizedCrawlerOutput();
  }
  const pages = new Map<string, { url: string; title?: string; status?: number }>();
  const links = new Set<string>();
  const endpointCandidates = new Set<string>();
  const jsAssets = new Set<string>();
  const forms = new Map<string, { action?: string; method?: string; sourceUrl?: string }>();
  const routes = new Set<string>();
  collectCrawlerArtifacts(parsed, { pages, links, endpointCandidates, jsAssets, forms, routes });
  links.delete(seedUrl);
  pages.delete(seedUrl);
  endpointCandidates.delete(seedUrl);
  jsAssets.delete(seedUrl);
  routes.delete(seedUrl);
  return {
    pages: [...pages.values()],
    links: [...links].sort(),
    endpointCandidates: [...endpointCandidates].sort(),
    jsAssets: [...jsAssets].sort(),
    forms: [...forms.values()],
    routes: [...routes].sort(),
  };
}

function emptyNormalizedCrawlerOutput(): NormalizedCrawlerOutput {
  return {
    pages: [],
    links: [],
    endpointCandidates: [],
    jsAssets: [],
    forms: [],
    routes: [],
  };
}

function parseJsonLike(content: string): unknown | undefined {
  const trimmed = content.trim();
  if (!trimmed) return undefined;
  const candidates = [trimmed, ...trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).reverse()];
  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate) as unknown;
    } catch {
      continue;
    }
  }
  return undefined;
}

function collectCrawlerArtifacts(
  value: unknown,
  output: {
    pages: Map<string, { url: string; title?: string; status?: number }>;
    links: Set<string>;
    endpointCandidates: Set<string>;
    jsAssets: Set<string>;
    forms: Map<string, { action?: string; method?: string; sourceUrl?: string }>;
    routes: Set<string>;
  },
  contextKey = "",
): void {
  if (typeof value === "string") {
    collectCrawlerString(value, output, contextKey);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectCrawlerArtifacts(item, output, contextKey);
    return;
  }
  if (!value || typeof value !== "object") {
    return;
  }
  const record = value as Record<string, unknown>;
  const url = firstString(record.url, record.href, record.link, record.sourceUrl, record.source_url, record.finalUrl, record.final_url);
  const status = firstNumber(record.status, record.statusCode, record.status_code);
  const title = firstString(record.title, record.name, record.text, record.label);
  if (url) {
    collectCrawlerString(url, output, contextKey);
    const existing = output.pages.get(url);
    output.pages.set(url, { url, title: title ?? existing?.title, status: status ?? existing?.status });
  }
  const formAction = firstString(record.action, record.formAction, record.form_action);
  const formMethod = firstString(record.method, record.httpMethod, record.http_method);
  if (formAction || (formMethod && url)) {
    const action = formAction ?? url;
    const key = `${formMethod ?? "GET"} ${action ?? ""} ${url ?? ""}`;
    output.forms.set(key, {
      action,
      method: formMethod?.toUpperCase(),
      sourceUrl: url,
    });
    if (action) collectCrawlerString(action, output, "forms");
  }
  for (const [key, child] of Object.entries(record)) {
    if (key === "html" || key === "markdown" || key === "content" || key === "screenshot") {
      continue;
    }
    collectCrawlerArtifacts(child, output, key);
  }
}

function collectCrawlerString(
  value: string,
  output: {
    links: Set<string>;
    endpointCandidates: Set<string>;
    jsAssets: Set<string>;
    routes: Set<string>;
  },
  contextKey: string,
): void {
  if (!looksLikeUrl(value)) return;
  output.links.add(value);
  const normalizedKey = contextKey.toLowerCase();
  if (looksLikeJsAsset(value) || normalizedKey.includes("script") || normalizedKey.includes("js")) {
    output.jsAssets.add(value);
  }
  if (looksLikeEndpoint(value) || /endpoint|api|graphql|route|request/.test(normalizedKey)) {
    output.endpointCandidates.add(value);
  }
  if (value.startsWith("/") && !looksLikeJsAsset(value) && /route|path|url|link/.test(normalizedKey)) {
    output.routes.add(value);
  }
}

function firstString(...values: unknown[]): string | undefined {
  return values.find((value): value is string => typeof value === "string" && value.length > 0);
}

function firstNumber(...values: unknown[]): number | undefined {
  return values.find((value): value is number => typeof value === "number" && Number.isFinite(value));
}

function looksLikeUrl(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://") || value.startsWith("/") || value.startsWith("//");
}

function looksLikeJsAsset(value: string): boolean {
  try {
    return new URL(value, "https://example.invalid").pathname.toLowerCase().endsWith(".js");
  } catch {
    return value.toLowerCase().split(/[?#]/)[0]?.endsWith(".js") === true;
  }
}

function looksLikeEndpoint(value: string): boolean {
  try {
    const pathname = new URL(value, "https://example.invalid").pathname.toLowerCase();
    return /\/(?:api|graphql|gql|v\d+)(?:\/|$)|\.(?:json|graphql)$/.test(pathname);
  } catch {
    return /\/(?:api|graphql|gql|v\d+)(?:\/|$)|\.(?:json|graphql)(?:[?#]|$)/i.test(value);
  }
}

function absoluteScopedUrl(value: string, baseUrl: string, runtime: Runtime): string | undefined {
  try {
    const url = new URL(value, baseUrl).toString();
    return runtime.scopeGuard.test(url).allowed ? url : undefined;
  } catch {
    return undefined;
  }
}

function safeFileName(value: string): string {
  return value.replace(/[^a-z0-9.-]/gi, "_");
}
