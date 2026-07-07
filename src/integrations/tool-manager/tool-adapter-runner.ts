import path from "node:path";
import type { ActionRecord } from "../../core/actions/action-queue.js";
import { createJobAuditLogger, type Runtime } from "../../cli/runtime.js";
import type { ExecutionMode, ReconObservation, ReconObservationKind, RiskLevel, ToolAdapterRunInput, ToolAdapterRunResult, ToolAdapterSpec } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";
import {
  assertLocalProcessArgument,
  createExecutableApprovalStore,
  localProcessEnv,
  resolveApprovedLocalProcess,
} from "../../utils/local-process-policy.js";
import { killProcessTree, spawnOutputProcess } from "../../utils/process-tree.js";
import { maskSecrets } from "../../utils/secrets.js";
import { ToolManager } from "./tool-manager.js";

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_CAPTURE_BYTES = 768_000;

export const TOOL_ADAPTER_SPECS: ToolAdapterSpec[] = [
  { tool: "subfinder", actionType: "research.public", defaultArgs: ["-silent", "-d", "{host}"], outputFormat: "lines" },
  { tool: "gau", actionType: "research.public", defaultArgs: ["{host}"], outputFormat: "lines" },
  { tool: "waybackurls", actionType: "research.public", defaultArgs: ["{host}"], outputFormat: "lines" },
  { tool: "dnsx", actionType: "http.probe", defaultArgs: ["-silent", "-json", "-d", "{host}"], outputFormat: "jsonl" },
  { tool: "httpx", actionType: "http.probe", defaultArgs: ["-silent", "-json", "-u", "{url}"], outputFormat: "jsonl" },
  { tool: "katana", actionType: "crawler.fetch", defaultArgs: ["-silent", "-jsonl", "-u", "{url}"], outputFormat: "jsonl" },
  { tool: "nuclei", actionType: "http.scan", defaultArgs: ["-jsonl", "-u", "{url}", "-rate-limit", "1"], outputFormat: "jsonl" },
  { tool: "ffuf", actionType: "http.fuzz", defaultArgs: ["-u", "{url}/FUZZ", "-of", "json"], outputFormat: "json" },
  { tool: "dalfox", actionType: "http.validate", defaultArgs: ["url", "{url}", "--format", "json"], outputFormat: "json" },
  { tool: "naabu", actionType: "tcp.scan", defaultArgs: ["-json", "-host", "{host}", "-rate", "50"], outputFormat: "jsonl" },
];

export class ToolAdapterRunner {
  constructor(private readonly runtime: Runtime) {}

  async execute(input: ToolAdapterRunInput): Promise<ToolAdapterRunResult> {
    const scoped = this.runtime.scopeGuard.assertAllowed(input.target);
    const manager = new ToolManager();
    const tool = manager.assertAllowedForMode(input.tool, input.mode);
    const action = tool.actions.find((candidate) => candidate.action_type === input.actionType) ?? tool.actions[0];
    if (!action) {
      throw new BountyPilotError(`Tool ${tool.name} has no trusted actions`, "TOOL_ACTION_NOT_FOUND");
    }
    const validation = manager.validateRunPlan({
      tool: tool.name,
      mode: input.mode,
      actionType: action.action_type,
      target: scoped.url,
      labModeEnabled: this.runtime.config.rules.lab_mode === true,
      programRules: this.runtime.config.rules,
    });
    if (!validation.allowed) {
      throw new BountyPilotError(validation.reasons.join("; "), "TOOL_RUN_PLAN_BLOCKED");
    }

    const approval = latestToolApproval(this.runtime, tool.name);
    if (!approval) {
      throw new BountyPilotError(`Tool ${tool.name} has no approved executable. Run tools approve-executable first.`, "TOOL_EXECUTABLE_APPROVAL_MISSING");
    }
    const launch = resolveApprovedLocalProcess({
      integration: toolApprovalIntegrationName(tool.name),
      config: { command: approval.command },
      integrationsDir: this.runtime.paths.workspace.integrationsDir,
      cwd: this.runtime.paths.programDir,
    });
    const spec = toolAdapterSpec(tool.name, action.action_type);
    const args = renderToolArgs(spec.defaultArgs, scoped.url).map(assertAndReturnArgument);
    const started = Date.now();
    const processResult = await runProcess({
      executable: launch.executable.realPath,
      commandSha256: launch.executable.sha256,
      args,
      cwd: this.runtime.paths.programDir,
      timeoutMs: input.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    });
    const durationMs = Date.now() - started;
    const parsed = parseToolOutput({
      tool: tool.name,
      actionType: action.action_type,
      target: scoped.url,
      content: [processResult.stdout, processResult.stderr].filter(Boolean).join("\n"),
    });
    const observations = parsed
      .map((observation) => ({
        ...observation,
        jobId: input.jobId,
        sourceUrl: observation.sourceUrl ?? scoped.url,
        scopeAllowed: scopedObservationAllowed(this.runtime, observation),
      }))
      .filter((observation) => observation.scopeAllowed)
      .map((observation) => this.runtime.recon.upsert(observation));

    for (const observation of observations) {
      if (
        observation.kind === "url" ||
        observation.kind === "endpoint" ||
        observation.kind === "parameter" ||
        observation.kind === "js_asset" ||
        observation.kind === "form"
      ) {
        this.runtime.crawlGraph.upsertPage({ url: observation.normalizedValue });
        this.runtime.crawlGraph.addEdge(scoped.url, observation.normalizedValue);
      }
    }

    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId: input.jobId,
      adapterName: tool.name,
      kind: "tool_output",
      sourceUrl: scoped.url,
      relativePath: path.join(input.jobId ?? "ad-hoc-tools", `${safeFileName(tool.name)}-${safeFileName(action.action_type)}.json`),
      content: `${JSON.stringify(
        {
          tool: tool.name,
          actionType: action.action_type,
          target: scoped.url,
          command: launch.executable.realPath,
          commandSha256: launch.executable.sha256,
          args,
          cwd: this.runtime.paths.programDir,
          exitCode: processResult.exitCode,
          signal: processResult.signal,
          timedOut: processResult.timedOut,
          durationMs,
          stdout: maskSecrets(processResult.stdout),
          stderr: maskSecrets(processResult.stderr),
          observations: observations.map((observation) => observation.id),
        },
        null,
        2,
      )}\n`,
    });

    createJobAuditLogger(this.runtime.paths, input.jobId ?? "ad-hoc-tools").log({
      jobId: input.jobId,
      actionType: action.action_type,
      url: scoped.url,
      adapterName: tool.name,
      status: processResult.exitCode === 0 && !processResult.timedOut ? "completed" : "failed",
      policyDecision: validation.requiresApproval ? "require_approval" : "allow",
      reason: validation.reasons.join("; "),
      metadata: {
        commandSha256: launch.executable.sha256,
        exitCode: processResult.exitCode,
        timedOut: processResult.timedOut,
        observations: observations.length,
      },
    });

    return {
      tool: tool.name,
      actionType: action.action_type,
      target: scoped.url,
      exitCode: processResult.exitCode,
      timedOut: processResult.timedOut,
      durationMs,
      stdout: processResult.stdout,
      stderr: processResult.stderr,
      evidence: artifact,
      observations,
    };
  }

  async executeAction(action: ActionRecord, scopedUrl: string, mode: ExecutionMode): Promise<{ message: string; evidenceCreated: number; findingsCreated: number }> {
    const tool = actionToolName(action);
    const result = await this.execute({
      tool,
      actionType: action.actionType,
      target: scopedUrl,
      mode,
      jobId: action.jobId,
    });
    if (result.timedOut) {
      throw new BountyPilotError(`Tool ${tool} timed out after ${result.durationMs}ms`, "TOOL_EXECUTION_TIMEOUT");
    }
    if (result.exitCode !== 0) {
      throw new BountyPilotError(`Tool ${tool} exited with code ${result.exitCode}. Evidence: ${result.evidence.path}`, "TOOL_EXECUTION_NONZERO");
    }
    return {
      message: `${tool} completed with ${result.observations.length} scoped observation(s)`,
      evidenceCreated: 1,
      findingsCreated: 0,
    };
  }
}

export function toolApprovalIntegrationName(tool: string): string {
  return `tool_${tool.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_")}`;
}

export function latestToolApproval(runtime: Runtime, tool: string) {
  return createExecutableApprovalStore(runtime.paths.workspace.integrationsDir).list(toolApprovalIntegrationName(tool))[0];
}

export function toolAdapterSpec(tool: string, actionType?: string): ToolAdapterSpec {
  const normalized = tool.trim().toLowerCase();
  const spec = TOOL_ADAPTER_SPECS.find((candidate) => candidate.tool === normalized && (!actionType || candidate.actionType === actionType))
    ?? TOOL_ADAPTER_SPECS.find((candidate) => candidate.tool === normalized);
  if (!spec) {
    throw new BountyPilotError(`No tool adapter spec is registered for ${tool}`, "TOOL_ADAPTER_SPEC_NOT_FOUND");
  }
  return spec;
}

export function actionToolName(action: ActionRecord): string {
  const tool = action.metadata?.tool;
  if (typeof tool === "string" && tool.trim()) {
    return tool.trim();
  }
  throw new BountyPilotError(`Action ${action.id} does not include tool metadata`, "TOOL_ACTION_METADATA_MISSING");
}

export function parseToolOutput(input: {
  tool: string;
  actionType: string;
  target: string;
  content: string;
}): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const output: Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> = [];
  const lines = input.content.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    const parsed = parseJsonRecord(line);
    if (parsed) {
      output.push(...observationsFromRecord(input, parsed));
      continue;
    }
    output.push(...observationsFromLine(input, line));
  }
  const entireJson = parseJsonRecord(input.content.trim());
  if (entireJson && lines.length <= 1) {
    output.push(...observationsFromRecord(input, entireJson));
  }
  return dedupeObservations(output);
}

interface ProcessResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
}

function runProcess(input: {
  executable: string;
  commandSha256: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
}): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawnOutputProcess(input.executable, input.args, {
      cwd: input.cwd,
      env: localProcessEnv(),
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      killProcessTree(child);
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
      clearTimeout(timeout);
      reject(new BountyPilotError(error.message, "TOOL_PROCESS_SPAWN_FAILED"));
    });
    child.on("close", (exitCode, signal) => {
      clearTimeout(timeout);
      resolve({ exitCode, signal, timedOut, stdout, stderr });
    });
  });
}

function renderToolArgs(args: string[], target: string): string[] {
  const url = new URL(target);
  const host = url.hostname;
  const origin = url.origin;
  return args.map((arg) => arg.replaceAll("{url}", target).replaceAll("{host}", host).replaceAll("{origin}", origin));
}

function assertAndReturnArgument(argument: string): string {
  assertLocalProcessArgument(argument, "TOOL_ARGUMENT_INVALID");
  return argument;
}

function parseJsonRecord(value: string): unknown | undefined {
  if (!value || !(value.startsWith("{") || value.startsWith("["))) {
    return undefined;
  }
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function observationsFromRecord(
  input: { tool: string; actionType: string; target: string },
  value: unknown,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  if (Array.isArray(value)) {
    return value.flatMap((item) => observationsFromRecord(input, item));
  }
  if (!value || typeof value !== "object") {
    return [];
  }
  const record = value as Record<string, unknown>;
  const nested = nestedRecords(record).flatMap((item) => observationsFromRecord(input, item));
  const output = toolSpecificObservations(input, record);
  if (output.length === 0) {
    output.push(...genericRecordObservations(input, record));
  }
  return [...nested, ...output];
}

function observationsFromLine(
  input: { tool: string; actionType: string; target: string },
  line: string,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const tokens = line.split(/\s+/).filter(Boolean);
  return tokens
    .filter((token) => looksLikeObservation(token))
    .map((token) => observationForValue(input, token, { line, parser: "line" }));
}

function toolSpecificObservations(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  switch (input.tool) {
    case "dnsx":
      return parseDnsxRecord(input, record);
    case "httpx":
      return parseHttpxRecord(input, record);
    case "katana":
      return parseKatanaRecord(input, record);
    case "nuclei":
      return parseNucleiRecord(input, record);
    case "ffuf":
      return parseFfufRecord(input, record);
    case "dalfox":
      return parseDalfoxRecord(input, record);
    case "naabu":
      return parseNaabuRecord(input, record);
    default:
      return [];
  }
}

function parseDnsxRecord(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  return [
    ...hostsFromValues(input, record, firstString(record.host, record.input), ...stringArray(record.cname)),
    ...stringArray(record.a, record.aaaa).map((address) => technologyObservation(input, `dns:${address}`, record, "low")),
  ];
}

function parseHttpxRecord(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const url = firstString(record.url, record.input, record.final_url, record.finalUrl);
  const output = url ? [observationForValue(input, url, record, { confidence: "medium" })] : [];
  for (const tech of stringArray(record.tech, record.technologies)) {
    output.push(technologyObservation(input, tech, { ...record, url }, "medium"));
  }
  const webserver = firstString(record.webserver, record.server);
  if (webserver) {
    output.push(technologyObservation(input, `server:${webserver}`, { ...record, url }, "low"));
  }
  return output;
}

function parseKatanaRecord(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const url = firstString(record.url, record.request, record.endpoint, record.href, record.link);
  const output = url ? [observationForValue(input, url, record, { confidence: "medium" })] : [];
  const formAction = firstString(record.action, record.formAction, record.form_action);
  const tag = firstString(record.tag, record.tagName, record.type)?.toLowerCase();
  const method = firstString(record.method, record.httpMethod, record.http_method);
  if (formAction || tag === "form" || method) {
    output.push(formObservation(input, formAction ?? url ?? input.target, { ...record, method }, "medium"));
  }
  return output;
}

function parseNucleiRecord(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const url = firstString(record.url, record.host, record.matched, record["matched-at"], record["matched_at"]);
  const template = firstString(record.template, record["template-id"], record.templateID, record.template_id);
  const info = objectRecord(record.info);
  const severity = firstString(record.severity, info?.severity)?.toLowerCase();
  const output = url ? [observationForValue(input, url, record, { confidence: "medium" })] : [];
  if (template) {
    output.push(vulnerabilitySignalObservation(input, template, record, {
      confidence: severity && severity !== "info" ? "medium" : "low",
      riskHint: riskFromSeverity(severity) ?? "medium",
    }));
  }
  return output;
}

function parseFfufRecord(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const url = firstString(record.url, record.redirectlocation, record.redirectLocation);
  if (!url) return [];
  const status = numberValue(record.status, record.status_code, record.statusCode);
  const confidence = status && [200, 201, 202, 204, 301, 302, 307, 308, 401, 403].includes(status) ? "medium" : "low";
  return [observationForValue(input, url, record, { confidence })];
}

function parseDalfoxRecord(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const url = firstString(record.url, record.target, record.poc, record.evidence, record.request);
  const param = firstString(record.param, record.parameter);
  const verified = booleanLike(record.verified) || /^(v|verified|triggered)$/i.test(firstString(record.type, record.status) ?? "");
  const output = url ? [observationForValue(input, url, record, { confidence: verified ? "high" : "medium" })] : [];
  if (param) {
    output.push(parameterObservation(input, url ?? input.target, param, record, verified ? "high" : "medium"));
  }
  if (verified || firstString(record.poc, record.evidence)) {
    output.push(findingCandidateObservation(input, `dalfox:xss:${param ?? "unknown"}`, record, {
      confidence: verified ? "high" : "medium",
      riskHint: "medium",
    }));
  }
  return output;
}

function parseNaabuRecord(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const host = firstString(record.host, record.ip, record.address);
  const port = numberValue(record.port);
  const output = hostsFromValues(input, record, host);
  if (host && port) {
    output.push(portObservation(input, host, port, record));
  }
  return output;
}

function genericRecordObservations(
  input: { tool: string; actionType: string; target: string },
  record: Record<string, unknown>,
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  const candidates = [
    firstString(record.url, record.input, record.host, record.matched, record["matched-at"], record.final_url, record.finalUrl),
    firstString(record.path, record.endpoint, record.link, record.href),
  ].filter((candidate): candidate is string => Boolean(candidate));
  const output: Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> = [];
  for (const candidate of candidates) {
    output.push(observationForValue(input, candidate, record));
  }
  const template = firstString(record.template, record["template-id"], record.templateID);
  if (template) {
    output.push(vulnerabilitySignalObservation(input, template, record, { confidence: "medium", riskHint: "medium" }));
  }
  return output;
}

function observationForValue(
  input: { tool: string; actionType: string; target: string },
  value: string,
  metadata: Record<string, unknown>,
  options: { confidence?: "low" | "medium" | "high"; riskHint?: RiskLevel } = {},
): Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint"> {
  const absolute = absoluteObservationValue(value, input.target);
  const kind = observationKind(absolute);
  const riskHint = options.riskHint ?? riskHintFor(input.tool, kind);
  return {
    kind,
    value,
    normalizedValue: kind === "host" ? absolute.toLowerCase() : normalizeUrlLike(absolute),
    sourceAdapter: input.tool,
    sourceUrl: input.target,
    scopeAllowed: true,
    confidence: options.confidence ?? (input.tool === "nuclei" ? "medium" : "low"),
    riskHint,
    metadata,
  };
}

function hostsFromValues(
  input: { tool: string; actionType: string; target: string },
  metadata: Record<string, unknown>,
  ...values: Array<string | undefined>
): Array<Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">> {
  return values
    .filter((value): value is string => Boolean(value))
    .map((value) => observationForValue(input, value, metadata, { confidence: "medium" }))
    .filter((observation) => observation.kind === "host");
}

function technologyObservation(
  input: { tool: string; actionType: string; target: string },
  value: string,
  metadata: Record<string, unknown>,
  confidence: "low" | "medium" | "high",
): Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint"> {
  const normalizedValue = value.trim().toLowerCase();
  return {
    kind: "technology",
    value,
    normalizedValue,
    sourceAdapter: input.tool,
    sourceUrl: firstString(metadata.url, metadata.input, metadata.host) ?? input.target,
    scopeAllowed: true,
    confidence,
    riskHint: "low",
    metadata,
  };
}

function formObservation(
  input: { tool: string; actionType: string; target: string },
  value: string,
  metadata: Record<string, unknown>,
  confidence: "low" | "medium" | "high",
): Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint"> {
  const absolute = absoluteObservationValue(value, input.target);
  return {
    kind: "form",
    value,
    normalizedValue: normalizeUrlLike(absolute),
    sourceAdapter: input.tool,
    sourceUrl: firstString(metadata.url, metadata.source, metadata.input) ?? input.target,
    scopeAllowed: true,
    confidence,
    riskHint: "low",
    metadata,
  };
}

function portObservation(
  input: { tool: string; actionType: string; target: string },
  host: string,
  port: number,
  metadata: Record<string, unknown>,
): Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint"> {
  const normalizedHost = normalizeHostCandidate(host);
  const normalizedValue = `${normalizedHost}:${port}`;
  return {
    kind: "port",
    value: normalizedValue,
    normalizedValue,
    sourceAdapter: input.tool,
    sourceUrl: input.target,
    scopeAllowed: true,
    confidence: "medium",
    riskHint: "low",
    metadata,
  };
}

function parameterObservation(
  input: { tool: string; actionType: string; target: string },
  url: string,
  parameter: string,
  metadata: Record<string, unknown>,
  confidence: "low" | "medium" | "high",
): Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint"> {
  const absolute = absoluteObservationValue(url, input.target);
  const normalizedUrl = normalizeUrlWithParameter(absolute, parameter);
  return {
    kind: "parameter",
    value: `${absolute}#param=${parameter}`,
    normalizedValue: normalizedUrl,
    sourceAdapter: input.tool,
    sourceUrl: input.target,
    scopeAllowed: true,
    confidence,
    riskHint: "medium",
    metadata: { ...metadata, parameter },
  };
}

function vulnerabilitySignalObservation(
  input: { tool: string; actionType: string; target: string },
  value: string,
  metadata: Record<string, unknown>,
  options: { confidence: "low" | "medium" | "high"; riskHint: RiskLevel },
): Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint"> {
  return {
    kind: "vulnerability_signal",
    value,
    normalizedValue: `${input.tool}:${value}`.toLowerCase(),
    sourceAdapter: input.tool,
    sourceUrl: firstString(metadata.url, metadata.host, metadata.matched, metadata["matched-at"]) ?? input.target,
    scopeAllowed: true,
    confidence: options.confidence,
    riskHint: options.riskHint,
    metadata,
  };
}

function findingCandidateObservation(
  input: { tool: string; actionType: string; target: string },
  value: string,
  metadata: Record<string, unknown>,
  options: { confidence: "low" | "medium" | "high"; riskHint: RiskLevel },
): Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint"> {
  return {
    kind: "finding_candidate",
    value,
    normalizedValue: value.toLowerCase(),
    sourceAdapter: input.tool,
    sourceUrl: firstString(metadata.url, metadata.target, metadata.poc) ?? input.target,
    scopeAllowed: true,
    confidence: options.confidence,
    riskHint: options.riskHint,
    metadata,
  };
}

function scopedObservationAllowed(
  runtime: Runtime,
  observation: Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">,
): boolean {
  if (observation.kind === "host") {
    return runtime.scopeGuard.test(`https://${observation.normalizedValue}`).allowed;
  }
  if (observation.kind === "port") {
    return runtime.scopeGuard.test(`https://${observation.normalizedValue.split(":")[0]}`).allowed;
  }
  if (observation.normalizedValue.startsWith("http://") || observation.normalizedValue.startsWith("https://")) {
    return runtime.scopeGuard.test(observation.normalizedValue).allowed;
  }
  const candidates = scopeCandidatesFromObservation(observation);
  if (candidates.length > 0) {
    return candidates.every((candidate) => runtime.scopeGuard.test(candidate).allowed);
  }
  return true;
}

function observationKind(value: string): ReconObservationKind {
  if (!value.startsWith("http://") && !value.startsWith("https://")) {
    return "host";
  }
  const url = new URL(value);
  const pathname = url.pathname.toLowerCase();
  if (pathname.endsWith(".js")) return "js_asset";
  if ([...url.searchParams.keys()].length > 0) return "parameter";
  if (/\/(?:api|graphql|gql|v\d+)(?:\/|$)|\.(?:json|graphql)$/.test(pathname)) return "endpoint";
  if (pathname !== "/" && pathname !== "") return "endpoint";
  return "url";
}

function absoluteObservationValue(value: string, target: string): string {
  const trimmed = value.trim();
  if (looksLikeHostOnly(trimmed)) {
    return normalizeHostCandidate(trimmed);
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?\//i.test(trimmed)) {
    return new URL(`https://${trimmed}`).toString();
  }
  try {
    return new URL(trimmed, target).toString();
  } catch {
    return normalizeHostCandidate(trimmed);
  }
}

function normalizeUrlLike(value: string): string {
  try {
    const url = new URL(value);
    url.hash = "";
    url.hostname = url.hostname.toLowerCase();
    url.searchParams.sort();
    return url.toString();
  } catch {
    return value.trim().toLowerCase();
  }
}

function riskHintFor(tool: string, kind: ReconObservationKind): RiskLevel | undefined {
  if (tool === "nuclei") return "medium";
  if (kind === "endpoint" || kind === "parameter") return "low";
  return undefined;
}

function looksLikeObservation(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://") || /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/\S*)?$/i.test(value);
}

function firstString(...values: unknown[]): string | undefined {
  return values.find((value): value is string => typeof value === "string" && value.trim().length > 0);
}

function stringArray(...values: unknown[]): string[] {
  return values.flatMap((value) => {
    if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
    if (typeof value === "string" && value.trim().length > 0) return [value];
    return [];
  });
}

function nestedRecords(record: Record<string, unknown>): unknown[] {
  return [
    ...arrayValue(record.results),
    ...arrayValue(record.data),
    ...arrayValue(record.items),
    ...arrayValue(record.matches),
  ];
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function numberValue(...values: unknown[]): number | undefined {
  for (const value of values) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && /^\d+$/.test(value.trim())) return Number(value.trim());
  }
  return undefined;
}

function booleanLike(value: unknown): boolean {
  return value === true || (typeof value === "string" && /^(true|yes|verified|v)$/i.test(value));
}

function looksLikeHostOnly(value: string): boolean {
  return /^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?$/i.test(value);
}

function normalizeHostCandidate(value: string): string {
  return value
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
}

function normalizeUrlWithParameter(value: string, parameter: string): string {
  try {
    const url = new URL(value);
    url.hash = "";
    for (const key of [...url.searchParams.keys()]) {
      if (key !== parameter) url.searchParams.delete(key);
    }
    if (!url.searchParams.has(parameter)) url.searchParams.set(parameter, "");
    url.searchParams.sort();
    return url.toString();
  } catch {
    return `${value}#param=${parameter}`.toLowerCase();
  }
}

function riskFromSeverity(severity: string | undefined): RiskLevel | undefined {
  if (!severity) return undefined;
  if (severity === "critical" || severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

function scopeCandidatesFromObservation(
  observation: Omit<ReconObservation, "id" | "firstSeenAt" | "lastSeenAt" | "fingerprint">,
): string[] {
  const candidates = [
    observation.sourceUrl,
    firstString(
      observation.metadata.url,
      observation.metadata.input,
      observation.metadata.host,
      observation.metadata.target,
      observation.metadata.matched,
      observation.metadata["matched-at"],
      observation.metadata.final_url,
      observation.metadata.finalUrl,
    ),
  ].filter((candidate): candidate is string => Boolean(candidate));
  return candidates
    .filter((candidate) => looksLikeObservation(candidate))
    .map((candidate) => {
      const absolute = absoluteObservationValue(candidate, observation.sourceUrl ?? "https://example.invalid/");
      return absolute.startsWith("http://") || absolute.startsWith("https://") ? absolute : `https://${absolute}`;
    });
}

function dedupeObservations<T extends { kind: string; normalizedValue: string; sourceAdapter: string }>(observations: T[]): T[] {
  const seen = new Set<string>();
  const output: T[] = [];
  for (const observation of observations) {
    const key = `${observation.kind}:${observation.normalizedValue}:${observation.sourceAdapter}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(observation);
  }
  return output;
}

function appendBounded(current: string, chunk: string): string {
  const next = current + chunk;
  return next.length > MAX_CAPTURE_BYTES ? next.slice(0, MAX_CAPTURE_BYTES) : next;
}

function safeFileName(value: string): string {
  return value.replace(/[^a-z0-9.-]/gi, "_");
}
