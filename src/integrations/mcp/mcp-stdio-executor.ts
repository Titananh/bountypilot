import path from "node:path";
import { createJobAuditLogger, type Runtime } from "../../cli/runtime.js";
import type { ActionRecord } from "../../core/actions/action-queue.js";
import type { ExecutionMode } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";
import { maskSecrets } from "../../utils/secrets.js";
import {
  assertLocalProcessArgument,
  localProcessEnv,
  resolveApprovedLocalProcess,
  type LocalProcessConfig,
  type VerifiedExecutable,
} from "../../utils/local-process-policy.js";
import { killProcessTree, releaseProcessHandles, spawnPipedProcess } from "../../utils/process-tree.js";
import type { AdapterCapabilityMetadata } from "../adapters/adapter.js";
import { IntegrationManager, type ResolvedIntegration } from "../integration-manager/integration-manager.js";
import { McpClientManager, type McpCallPlanValidation } from "./mcp-client-manager.js";

export interface McpExecutionResult {
  message: string;
  evidenceCreated: number;
  findingsCreated: number;
}

export interface McpToolCallInput {
  server: string;
  tool: string;
  mode: ExecutionMode;
  target?: string;
  arguments?: Record<string, unknown>;
  jobId?: string;
  actionId?: string;
  approvedAction?: boolean;
}

export interface McpSessionStepInput {
  tool: string;
  target?: string;
  arguments?: Record<string, unknown>;
  label?: string;
}

export interface McpSessionInput {
  server: string;
  mode: ExecutionMode;
  target?: string;
  steps: McpSessionStepInput[];
  jobId?: string;
}

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc?: "2.0";
  id?: number;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

interface McpFailureContext {
  phase: "stdout_frame";
  code: string;
  message: string;
  stdoutPreview: string;
  stdoutPreviewTruncated: boolean;
}

interface McpStreamEvent {
  sequence: number;
  elapsedMs: number;
  direction: "stdout";
  kind: "response" | "request" | "notification" | "progress" | "log" | "unknown";
  id?: number;
  method?: string;
  stepIndex?: number;
  preview: string;
  previewTruncated: boolean;
}

interface McpStreamEventLog {
  total: number;
  captured: number;
  dropped: number;
  truncated: boolean;
  events: McpStreamEvent[];
}

interface StdioCallResult {
  command: string;
  commandSha256: string;
  args: string[];
  envKeys: string[];
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  durationMs: number;
  stderr: string;
  failure?: McpFailureContext;
  streamEvents: McpStreamEventLog;
  initialize: JsonRpcResponse;
  call: JsonRpcResponse;
}

interface IntegrationProcessConfig extends LocalProcessConfig {
  timeout_ms?: number;
}

interface PreparedMcpSessionStep {
  index: number;
  label?: string;
  tool: string;
  target?: string;
  arguments: Record<string, unknown>;
  validation: Record<string, unknown>;
  scopedPostcondition?: AdapterCapabilityMetadata["scopedPostcondition"];
}

interface McpScopedPostconditionResult {
  kind: "current_or_final_url_in_scope";
  ok: boolean;
  evidenceUsable: boolean;
  code?: "MCP_POSTCONDITION_URL_MISSING" | "MCP_POSTCONDITION_SCOPE_BLOCKED";
  url?: string;
  matchedInScope?: string;
  matchedOutOfScope?: string;
  reason?: string;
}

interface StdioSessionResult {
  command: string;
  commandSha256: string;
  args: string[];
  envKeys: string[];
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  durationMs: number;
  stderr: string;
  failure?: McpFailureContext;
  streamEvents: McpStreamEventLog;
  initialize: JsonRpcResponse;
  steps: Array<{
    index: number;
    tool: string;
    arguments: Record<string, unknown>;
    durationMs: number;
    response: JsonRpcResponse;
  }>;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const TIMEOUT_KILL_GRACE_MS = 2_000;
const MAX_CAPTURE_BYTES = 512_000;
const MAX_MCP_FRAME_BYTES = 512_000;
const MAX_MCP_HEADER_BYTES = 8_192;
const MAX_MCP_TRANSCRIPT_PREVIEW_CHARS = 16_384;
const MAX_MCP_STREAM_EVENTS = 120;
const MAX_MCP_STREAM_EVENT_PREVIEW_CHARS = 2_048;

export class McpStdioExecutor {
  constructor(private readonly runtime: Runtime) {}

  async executeAction(action: ActionRecord, scopedUrl: string | undefined, mode: ExecutionMode): Promise<McpExecutionResult> {
    const integration = this.integration(action.adapter);
    const capability = integration.registration?.capabilities.find((candidate) => candidate.actionType === action.actionType);
    const tool = capability?.mcpTools?.[0];
    if (!tool) {
      throw new BountyPilotError(
        `No MCP tool is registered for ${integration.name} ${action.actionType}`,
        "MCP_TOOL_NOT_REGISTERED",
      );
    }
    return this.executeCall({
      server: integration.name,
      tool,
      mode,
      target: scopedUrl,
      arguments: defaultArgumentsForAction(tool, scopedUrl, action, this.runtime.config.program),
      jobId: action.jobId,
      actionId: action.id,
      approvedAction: true,
    });
  }

  async executeCall(input: McpToolCallInput): Promise<McpExecutionResult> {
    const integration = this.integration(input.server);
    if (!isExecutionEnabled(integration)) {
      throw new BountyPilotError(
        `MCP integration ${integration.name} is configured for planning only. Set allow_execute=true or execution.enabled=true to run it.`,
        "MCP_EXECUTION_DISABLED",
      );
    }
    if ((integration.config.transport ?? integration.registration?.mcp?.defaultTransport) !== "stdio") {
      throw new BountyPilotError("Only stdio MCP execution is implemented.", "MCP_TRANSPORT_UNSUPPORTED");
    }
    const target = input.target ? this.runtime.scopeGuard.assertAllowed(input.target).url : undefined;
    const callArguments = {
      ...defaultArgumentsForTool(input.tool, target),
      ...(input.arguments ?? {}),
    };
    assertArgumentsStayInScope(this.runtime, callArguments, target);
    const validation = new McpClientManager(this.runtime.config).validateCallPlan({
      server: integration.name,
      tool: input.tool,
      mode: input.mode,
      target,
      arguments: callArguments,
    });
    if (!validation.ok) {
      throw new BountyPilotError(validation.reasons.join("; "), "MCP_EXECUTION_PRECHECK_BLOCKED");
    }
    if (validation.requiresApproval && !input.approvedAction) {
      throw new BountyPilotError("MCP call requires an approved queued action before execution.", "MCP_REQUIRES_APPROVAL");
    }
    if (target) {
      await this.runtime.rateLimiter.wait(target);
    }

    const processConfig = processConfigForIntegration(integration);
    const launch = resolveApprovedLocalProcess({
      integration: integration.name,
      config: processConfig,
      integrationsDir: this.runtime.paths.workspace.integrationsDir,
      cwd: this.runtime.paths.programDir,
    });
    const args = [...launch.baseArgs, ...(processConfig.args ?? [])];
    const timeoutMs = processConfig.timeout_ms ?? DEFAULT_TIMEOUT_MS;
    const started = Date.now();
    const result = await callMcpTool({
      executable: launch.executable,
      args,
      cwd: this.runtime.paths.programDir,
      timeoutMs,
      tool: input.tool,
      arguments: callArguments,
    });
    const validationSummary = summarizeValidation(validation);
    const postcondition =
      result.timedOut || result.failure || result.call.error
        ? undefined
        : evaluateMcpScopedPostcondition(validation.capability?.scopedPostcondition, result.call.result, this.runtime);
    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId: input.jobId,
      adapterName: integration.name,
      kind: "tool_output",
      sourceUrl: target,
      relativePath: path.join(
        input.jobId ?? "ad-hoc-actions",
        `${safeFileName(integration.name)}-${safeFileName(input.tool)}${input.actionId ? `-${safeFileName(input.actionId)}` : ""}-mcp-result.json`,
      ),
      content: `${JSON.stringify(
        {
          execute: true,
          server: integration.name,
          tool: input.tool,
          target,
          mode: input.mode,
          actionId: input.actionId,
          approvedAction: input.approvedAction === true,
          arguments: callArguments,
          validation: validationSummary,
          postcondition,
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
          envKeys: result.envKeys,
          timeoutMs,
          exitCode: result.exitCode,
          signal: result.signal,
          timedOut: result.timedOut,
          durationMs: result.durationMs,
          stderr: result.stderr,
          failure: result.failure,
          streamEvents: result.streamEvents,
          initialize: result.initialize,
          call: result.call,
        },
        null,
        2,
      )}\n`,
    });
    const audit = createJobAuditLogger(this.runtime.paths, input.jobId ?? "ad-hoc-mcp");
    audit.log({
      jobId: input.jobId,
      actionType: validation.capability?.actionType ?? input.tool,
      url: target,
      adapterName: integration.name,
      toolName: input.tool,
      durationMs: Date.now() - started,
      status: result.call.error ? "error" : postcondition?.ok === false ? "blocked" : "completed",
      policyDecision: postcondition?.ok === false ? "block" : validation.decision,
      metadata: { evidence: artifact.path, postcondition, streamEvents: streamEventSummary(result.streamEvents) },
    });
    recordMcpStreamTimelineEvent(this.runtime, {
      jobId: input.jobId,
      server: integration.name,
      tool: input.tool,
      evidencePath: artifact.path,
      streamEvents: result.streamEvents,
      status: result.failure || result.timedOut || result.call.error ? "failed" : postcondition?.ok === false ? "blocked" : "completed",
    });

    if (result.timedOut) {
      throw new BountyPilotError(`MCP call timed out after ${timeoutMs}ms. Evidence: ${artifact.path}`, "MCP_TIMEOUT");
    }
    if (result.failure) {
      throw new BountyPilotError(
        `MCP call failed while reading stdout: ${result.failure.message}. Evidence: ${artifact.path}`,
        result.failure.code,
      );
    }
    if (result.call.error) {
      throw new BountyPilotError(
        `MCP tool ${input.tool} failed: ${result.call.error.message ?? "unknown error"}. Evidence: ${artifact.path}`,
        "MCP_TOOL_CALL_FAILED",
      );
    }
    assertMcpScopedPostcondition(postcondition, `MCP tool ${input.tool}`, artifact.path);

    return {
      message: `${integration.name} MCP tool ${input.tool} completed`,
      evidenceCreated: 1,
      findingsCreated: 0,
    };
  }

  async executeSession(input: McpSessionInput): Promise<McpExecutionResult> {
    if (input.steps.length === 0) {
      throw new BountyPilotError("MCP session requires at least one step", "MCP_SESSION_EMPTY");
    }

    const integration = this.integration(input.server);
    if (!isExecutionEnabled(integration)) {
      throw new BountyPilotError(
        `MCP integration ${integration.name} is configured for planning only. Set allow_execute=true or execution.enabled=true to run it.`,
        "MCP_EXECUTION_DISABLED",
      );
    }
    if ((integration.config.transport ?? integration.registration?.mcp?.defaultTransport) !== "stdio") {
      throw new BountyPilotError("Only stdio MCP execution is implemented.", "MCP_TRANSPORT_UNSUPPORTED");
    }

    const preparedSteps = await this.prepareSessionSteps(integration.name, input);
    const processConfig = processConfigForIntegration(integration);
    const launch = resolveApprovedLocalProcess({
      integration: integration.name,
      config: processConfig,
      integrationsDir: this.runtime.paths.workspace.integrationsDir,
      cwd: this.runtime.paths.programDir,
    });
    const args = [...launch.baseArgs, ...(processConfig.args ?? [])];
    const baseTimeoutMs = processConfig.timeout_ms ?? DEFAULT_TIMEOUT_MS;
    const timeoutMs = Math.min(120_000, Math.max(baseTimeoutMs, baseTimeoutMs * preparedSteps.length));
    const started = Date.now();
    const result = await callMcpSession({
      executable: launch.executable,
      args,
      cwd: this.runtime.paths.programDir,
      timeoutMs,
      steps: preparedSteps.map((step) => ({
        index: step.index,
        tool: step.tool,
        arguments: step.arguments,
      })),
    });

    const stepPostconditions = result.steps.map((step) => {
      const prepared = preparedSteps[step.index];
      return step.response.error || isMcpErrorResult(step.response.result)
        ? undefined
        : evaluateMcpScopedPostcondition(prepared?.scopedPostcondition, step.response.result, this.runtime);
    });
    const responseRecords = result.steps.map((step, index) => ({
      ...step,
      postcondition: stepPostconditions[index],
    }));

    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId: input.jobId,
      adapterName: integration.name,
      kind: "tool_output",
      sourceUrl: input.target ?? preparedSteps.find((step) => step.target)?.target,
      relativePath: path.join(
        input.jobId ?? "ad-hoc-actions",
        `${safeFileName(integration.name)}-mcp-session.json`,
      ),
      content: `${JSON.stringify(
        {
          execute: true,
          server: integration.name,
          mode: input.mode,
          target: input.target,
          steps: preparedSteps,
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
          envKeys: result.envKeys,
          timeoutMs,
          exitCode: result.exitCode,
          signal: result.signal,
          timedOut: result.timedOut,
          durationMs: result.durationMs,
          stderr: result.stderr,
          failure: result.failure,
          streamEvents: result.streamEvents,
          initialize: result.initialize,
          responses: responseRecords,
        },
        null,
        2,
      )}\n`,
    });

    const audit = createJobAuditLogger(this.runtime.paths, input.jobId ?? "ad-hoc-mcp-session");
    const failed = result.steps.find((step) => step.response.error || isMcpErrorResult(step.response.result));
    const failedPostconditionIndex = stepPostconditions.findIndex((postcondition) => postcondition?.ok === false);
    const streamStatus =
      result.failure || result.timedOut || failed ? "failed" : failedPostconditionIndex >= 0 ? "blocked" : "completed";
    for (const [index, step] of result.steps.entries()) {
      const prepared = preparedSteps[step.index];
      const postcondition = stepPostconditions[index];
      audit.log({
        jobId: input.jobId,
        actionType: String(prepared?.validation.capability ?? prepared?.tool ?? step.tool),
        url: prepared?.target,
        adapterName: integration.name,
        toolName: step.tool,
        durationMs: step.durationMs,
        status: step.response.error ? "error" : postcondition?.ok === false ? "blocked" : "completed",
        policyDecision: postcondition?.ok === false ? "block" : String(prepared?.validation.decision ?? "allow"),
        metadata: { evidence: artifact.path, sessionStep: step.index, postcondition, streamEvents: streamEventSummary(result.streamEvents) },
      });
    }
    recordMcpStreamTimelineEvent(this.runtime, {
      jobId: input.jobId,
      server: integration.name,
      tool: "session",
      evidencePath: artifact.path,
      streamEvents: result.streamEvents,
      status: streamStatus,
    });

    if (result.timedOut) {
      throw new BountyPilotError(`MCP session timed out after ${timeoutMs}ms. Evidence: ${artifact.path}`, "MCP_TIMEOUT");
    }
    if (result.failure) {
      throw new BountyPilotError(
        `MCP session failed while reading stdout: ${result.failure.message}. Evidence: ${artifact.path}`,
        result.failure.code,
      );
    }
    if (failed) {
      throw new BountyPilotError(
        `MCP session step ${failed.index + 1} failed. Evidence: ${artifact.path}`,
        "MCP_TOOL_CALL_FAILED",
      );
    }
    if (result.steps.length !== preparedSteps.length) {
      throw new BountyPilotError(
        `MCP session completed ${result.steps.length}/${preparedSteps.length} steps. Evidence: ${artifact.path}`,
        "MCP_SESSION_INCOMPLETE",
      );
    }
    if (failedPostconditionIndex >= 0) {
      const step = result.steps[failedPostconditionIndex];
      assertMcpScopedPostcondition(
        stepPostconditions[failedPostconditionIndex],
        `MCP session step ${step ? step.index + 1 : failedPostconditionIndex + 1}`,
        artifact.path,
      );
    }

    return {
      message: `${integration.name} MCP session completed ${result.steps.length} steps`,
      evidenceCreated: 1,
      findingsCreated: 0,
    };
  }

  private async prepareSessionSteps(server: string, input: McpSessionInput): Promise<PreparedMcpSessionStep[]> {
    const manager = new McpClientManager(this.runtime.config);
    const prepared: PreparedMcpSessionStep[] = [];
    for (const [index, step] of input.steps.entries()) {
      const target = scopedStepTarget(this.runtime, input.target, step);
      if (target) {
        await this.runtime.rateLimiter.wait(target);
      }
      assertArgumentsStayInScope(this.runtime, step.arguments ?? {}, target);
      const callArguments = {
        ...defaultArgumentsForTool(step.tool, target),
        ...(step.arguments ?? {}),
      };
      const validation = manager.validateCallPlan({
        server,
        tool: step.tool,
        mode: input.mode,
        target,
        arguments: callArguments,
      });
      if (!validation.ok) {
        throw new BountyPilotError(
          `MCP session step ${index + 1} blocked: ${validation.reasons.join("; ")}`,
          "MCP_EXECUTION_PRECHECK_BLOCKED",
        );
      }
      if (validation.requiresApproval) {
        throw new BountyPilotError(
          `MCP session step ${index + 1} requires an approved queued action before execution.`,
          "MCP_REQUIRES_APPROVAL",
        );
      }
      prepared.push({
        index,
        label: step.label,
        tool: step.tool,
        target,
        arguments: callArguments,
        validation: summarizeValidation(validation),
        scopedPostcondition: validation.capability?.scopedPostcondition,
      });
    }
    return prepared;
  }

  private integration(name: string): ResolvedIntegration {
    const integration = new IntegrationManager(this.runtime.config).get(name);
    if (!integration) {
      throw new BountyPilotError(`MCP integration not found: ${name}`, "MCP_INTEGRATION_NOT_FOUND");
    }
    if (!integration.registration?.mcp && integration.type !== "mcp") {
      throw new BountyPilotError(`${integration.name} is not an MCP integration`, "MCP_INTEGRATION_INVALID");
    }
    if (integration.status !== "configured") {
      throw new BountyPilotError(
        `MCP integration ${integration.name} is ${integration.status}: ${integration.message ?? "not ready"}`,
        "MCP_INTEGRATION_NOT_READY",
      );
    }
    return integration;
  }
}

function callMcpTool(input: {
  executable: VerifiedExecutable;
  args: string[];
  cwd: string;
  timeoutMs: number;
  tool: string;
  arguments: Record<string, unknown>;
}): Promise<StdioCallResult> {
  for (const arg of input.args) assertSafeArgument(arg);

  return new Promise((resolve, reject) => {
    const started = Date.now();
    const env = localProcessEnv();
    const child = spawnPipedProcess(input.executable.realPath, input.args, {
      cwd: input.cwd,
      env,
    });
    const parser = new McpFrameParser();
    const streamRecorder = new McpStreamEventRecorder();
    let stderr = "";
    let stdoutPreview = "";
    let timedOut = false;
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;
    let killFallback: NodeJS.Timeout | undefined;
    const responses = new Map<number, JsonRpcResponse>();
    let initializeResponse: JsonRpcResponse | undefined;
    let callResponse: JsonRpcResponse | undefined;

    const clearTimers = (): void => {
      if (timeout) clearTimeout(timeout);
      if (killFallback) clearTimeout(killFallback);
    };
    const resolveCall = (
      exitCode: number | null,
      signal: NodeJS.Signals | null,
      failure?: McpFailureContext,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      resolve({
        command: input.executable.realPath,
        commandSha256: input.executable.sha256,
        args: input.args,
        envKeys: Object.keys(env).sort(),
        exitCode,
        signal,
        timedOut,
        durationMs: Date.now() - started,
        stderr,
        failure,
        streamEvents: streamRecorder.snapshot(),
        initialize: initializeResponse ?? errorResponse(1, "MCP initialize response was not received"),
        call: callResponse ?? errorResponse(2, failure?.message ?? "MCP tool call response was not received"),
      });
    };
    timeout = setTimeout(() => {
      timedOut = true;
      killProcessTree(child);
      releaseProcessHandles(child);
      killFallback = setTimeout(() => {
        resolveCall(null, null);
      }, TIMEOUT_KILL_GRACE_MS);
      killFallback.unref();
    }, input.timeoutMs);
    const finishIfReady = (): void => {
      if (!initializeResponse || !callResponse) return;
      killProcessTree(child);
      releaseProcessHandles(child);
      resolveCall(null, null);
    };
    const failWithParserError = (error: unknown): void => {
      if (settled) return;
      killProcessTree(child);
      releaseProcessHandles(child);
      resolveCall(null, null, mcpFailureContext(error, stdoutPreview));
    };

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutPreview = appendTranscriptPreview(stdoutPreview, chunk);
      let messages: unknown[];
      try {
        messages = parser.push(chunk);
      } catch (error) {
        failWithParserError(error);
        return;
      }
      for (const message of messages) {
        streamRecorder.record(message, { elapsedMs: Date.now() - started });
        const response = message as JsonRpcResponse;
        if (isJsonRpcResponse(response)) {
          responses.set(response.id, response);
        }
        if (responses.has(1) && !initializeResponse) {
          initializeResponse = responses.get(1);
          writeFrame(child.stdin, {
            jsonrpc: "2.0",
            method: "notifications/initialized",
          });
          writeFrame(child.stdin, {
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
              name: input.tool,
              arguments: input.arguments,
            },
          });
        }
        if (responses.has(2) && !callResponse) {
          callResponse = responses.get(2);
        }
        finishIfReady();
      }
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimers();
      reject(new BountyPilotError(error.message, "MCP_PROCESS_SPAWN_FAILED"));
    });
    child.on("close", (exitCode, signal) => {
      resolveCall(exitCode, signal);
    });

    writeFrame(child.stdin, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "BountyPilot",
          version: "0.1.0",
        },
      },
    });
  });
}

function callMcpSession(input: {
  executable: VerifiedExecutable;
  args: string[];
  cwd: string;
  timeoutMs: number;
  steps: Array<{ index: number; tool: string; arguments: Record<string, unknown> }>;
}): Promise<StdioSessionResult> {
  for (const arg of input.args) assertSafeArgument(arg);

  return new Promise((resolve, reject) => {
    const started = Date.now();
    const env = localProcessEnv();
    const child = spawnPipedProcess(input.executable.realPath, input.args, {
      cwd: input.cwd,
      env,
    });
    const parser = new McpFrameParser();
    const streamRecorder = new McpStreamEventRecorder();
    let stderr = "";
    let stdoutPreview = "";
    let timedOut = false;
    let settled = false;
    let timeout: NodeJS.Timeout | undefined;
    let killFallback: NodeJS.Timeout | undefined;
    let initializeResponse: JsonRpcResponse | undefined;
    let activeStep: { id: number; startedAt: number; step: { index: number; tool: string; arguments: Record<string, unknown> } } | undefined;
    let nextStepIndex = 0;
    let nextId = 2;
    const stepResponses: StdioSessionResult["steps"] = [];

    const clearTimers = (): void => {
      if (timeout) clearTimeout(timeout);
      if (killFallback) clearTimeout(killFallback);
    };
    const resolveSession = (
      exitCode: number | null = null,
      signal: NodeJS.Signals | null = null,
      failure?: McpFailureContext,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimers();
      resolve({
        command: input.executable.realPath,
        commandSha256: input.executable.sha256,
        args: input.args,
        envKeys: Object.keys(env).sort(),
        exitCode,
        signal,
        timedOut,
        durationMs: Date.now() - started,
        stderr,
        failure,
        streamEvents: streamRecorder.snapshot(),
        initialize: initializeResponse ?? errorResponse(1, "MCP initialize response was not received"),
        steps: stepResponses,
      });
    };
    timeout = setTimeout(() => {
      timedOut = true;
      killProcessTree(child);
      releaseProcessHandles(child);
      killFallback = setTimeout(() => {
        resolveSession();
      }, TIMEOUT_KILL_GRACE_MS);
      killFallback.unref();
    }, input.timeoutMs);
    const failWithParserError = (error: unknown): void => {
      if (settled) return;
      killProcessTree(child);
      releaseProcessHandles(child);
      resolveSession(null, null, mcpFailureContext(error, stdoutPreview));
    };

    const sendNextStep = (): void => {
      if (settled) return;
      if (nextStepIndex >= input.steps.length) {
        killProcessTree(child);
        releaseProcessHandles(child);
        resolveSession();
        return;
      }
      const step = input.steps[nextStepIndex];
      activeStep = { id: nextId++, startedAt: Date.now(), step };
      nextStepIndex += 1;
      writeFrame(child.stdin, {
        jsonrpc: "2.0",
        id: activeStep.id,
        method: "tools/call",
        params: {
          name: step.tool,
          arguments: step.arguments,
        },
      });
    };

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutPreview = appendTranscriptPreview(stdoutPreview, chunk);
      let messages: unknown[];
      try {
        messages = parser.push(chunk);
      } catch (error) {
        failWithParserError(error);
        return;
      }
      for (const message of messages) {
        const response = message as JsonRpcResponse;
        streamRecorder.record(message, {
          elapsedMs: Date.now() - started,
          stepIndex: activeStep && (typeof response.id !== "number" || response.id === activeStep.id) ? activeStep.step.index : undefined,
        });
        if (!isJsonRpcResponse(response)) continue;
        if (response.id === 1 && !initializeResponse) {
          initializeResponse = response;
          writeFrame(child.stdin, {
            jsonrpc: "2.0",
            method: "notifications/initialized",
          });
          sendNextStep();
          continue;
        }
        if (activeStep && response.id === activeStep.id) {
          stepResponses.push({
            index: activeStep.step.index,
            tool: activeStep.step.tool,
            arguments: activeStep.step.arguments,
            durationMs: Date.now() - activeStep.startedAt,
            response,
          });
          const failed = response.error || isMcpErrorResult(response.result);
          activeStep = undefined;
          if (failed) {
            killProcessTree(child);
            releaseProcessHandles(child);
            resolveSession();
          } else {
            sendNextStep();
          }
        }
      }
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimers();
      reject(new BountyPilotError(error.message, "MCP_PROCESS_SPAWN_FAILED"));
    });
    child.on("close", (exitCode, signal) => {
      resolveSession(exitCode, signal);
    });

    writeFrame(child.stdin, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "BountyPilot",
          version: "0.1.0",
        },
      },
    });
  });
}

class McpFrameParser {
  private buffer = Buffer.alloc(0);

  push(chunk: Buffer): unknown[] {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const messages: unknown[] = [];
    while (true) {
      const headerEnd = this.buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        if (this.buffer.length > MAX_MCP_HEADER_BYTES) {
          throw new BountyPilotError("MCP stdout frame header exceeded the maximum size", "MCP_FRAME_TOO_LARGE");
        }
        break;
      }
      if (headerEnd > MAX_MCP_HEADER_BYTES) {
        throw new BountyPilotError("MCP stdout frame header exceeded the maximum size", "MCP_FRAME_TOO_LARGE");
      }
      const header = this.buffer.slice(0, headerEnd).toString("utf8");
      const contentLength = parseContentLength(header);
      if (contentLength === undefined) {
        throw new BountyPilotError("MCP stdout frame is missing a valid Content-Length header", "MCP_FRAME_INVALID");
      }
      if (contentLength > MAX_MCP_FRAME_BYTES) {
        throw new BountyPilotError("MCP stdout frame exceeded the maximum size", "MCP_FRAME_TOO_LARGE");
      }
      const bodyStart = headerEnd + 4;
      const bodyEnd = bodyStart + contentLength;
      if (this.buffer.length < bodyEnd) break;
      const body = this.buffer.slice(bodyStart, bodyEnd).toString("utf8");
      this.buffer = this.buffer.slice(bodyEnd);
      try {
        messages.push(JSON.parse(body) as unknown);
      } catch {
        throw new BountyPilotError("MCP stdout frame contained malformed JSON", "MCP_FRAME_INVALID");
      }
    }
    return messages;
  }
}

class McpStreamEventRecorder {
  private total = 0;
  private readonly events: McpStreamEvent[] = [];

  record(message: unknown, context: { elapsedMs: number; stepIndex?: number }): void {
    this.total += 1;
    if (this.events.length >= MAX_MCP_STREAM_EVENTS) {
      return;
    }

    const record = objectRecord(message);
    const rawPreview = stringifyStreamMessage(message);
    const safePreview = safeTranscriptText(rawPreview);
    const previewTruncated = safePreview.length > MAX_MCP_STREAM_EVENT_PREVIEW_CHARS;
    const id = typeof record?.id === "number" ? record.id : undefined;
    const method = typeof record?.method === "string" ? record.method : undefined;

    this.events.push({
      sequence: this.total,
      elapsedMs: context.elapsedMs,
      direction: "stdout",
      kind: classifyMcpStreamEvent(record),
      id,
      method,
      stepIndex: context.stepIndex,
      preview: previewTruncated ? safePreview.slice(0, MAX_MCP_STREAM_EVENT_PREVIEW_CHARS) : safePreview,
      previewTruncated,
    });
  }

  snapshot(): McpStreamEventLog {
    const dropped = Math.max(0, this.total - this.events.length);
    return {
      total: this.total,
      captured: this.events.length,
      dropped,
      truncated: dropped > 0 || this.events.some((event) => event.previewTruncated),
      events: [...this.events],
    };
  }
}

function writeFrame(stream: NodeJS.WritableStream, request: JsonRpcRequest): void {
  const body = JSON.stringify(request);
  stream.write(`Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`);
}

function parseContentLength(header: string): number | undefined {
  const line = header.split(/\r?\n/).find((item) => item.toLowerCase().startsWith("content-length:"));
  if (!line) return undefined;
  const value = Number(line.split(":")[1]?.trim());
  return Number.isInteger(value) && value >= 0 ? value : undefined;
}

function defaultArgumentsForTool(tool: string, target?: string): Record<string, unknown> {
  if (!target) return {};
  if (tool.includes("navigate")) return { url: target };
  return { target };
}

function defaultArgumentsForAction(
  tool: string,
  target: string | undefined,
  action: ActionRecord,
  programName: string,
): Record<string, unknown> {
  if (target) return defaultArgumentsForTool(tool, target);
  if (tool.startsWith("desktop_")) return { program: action.target ?? programName };
  return {};
}

function scopedStepTarget(runtime: Runtime, sessionTarget: string | undefined, step: McpSessionStepInput): string | undefined {
  const candidate = step.target ?? sessionTarget ?? targetFromArguments(step.arguments);
  return candidate ? runtime.scopeGuard.assertAllowed(candidate).url : undefined;
}

function targetFromArguments(args?: Record<string, unknown>): string | undefined {
  const value = args?.url ?? args?.target;
  return typeof value === "string" && (value.startsWith("http://") || value.startsWith("https://")) ? value : undefined;
}

function assertArgumentsStayInScope(runtime: Runtime, args: Record<string, unknown>, baseUrl?: string): void {
  for (const value of collectUrlStrings(args)) {
    const candidate = value.startsWith("http://") || value.startsWith("https://") ? value : baseUrl ? new URL(value, baseUrl).toString() : undefined;
    if (candidate) {
      runtime.scopeGuard.assertAllowed(candidate);
    }
  }
}

function collectUrlStrings(value: unknown): string[] {
  if (typeof value === "string") {
    return value.startsWith("http://") || value.startsWith("https://") || value.startsWith("/") ? [value] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectUrlStrings(item));
  }
  if (value && typeof value === "object") {
    return Object.values(value).flatMap((item) => collectUrlStrings(item));
  }
  return [];
}

function isMcpErrorResult(result: unknown): boolean {
  return Boolean(result && typeof result === "object" && (result as { isError?: unknown }).isError === true);
}

function isJsonRpcResponse(message: unknown): message is JsonRpcResponse & { id: number } {
  const record = objectRecord(message);
  return (
    Boolean(record) &&
    typeof record?.id === "number" &&
    typeof record.method !== "string" &&
    ("result" in record || "error" in record)
  );
}

function evaluateMcpScopedPostcondition(
  scopedPostcondition: AdapterCapabilityMetadata["scopedPostcondition"] | undefined,
  result: unknown,
  runtime: Runtime,
): McpScopedPostconditionResult | undefined {
  if (scopedPostcondition !== "current_or_final_url_in_scope") {
    return undefined;
  }
  const stateUrl = extractCurrentOrFinalUrl(result);
  if (!stateUrl) {
    return {
      kind: "current_or_final_url_in_scope",
      ok: false,
      evidenceUsable: false,
      code: "MCP_POSTCONDITION_URL_MISSING",
      reason: "MCP result did not include a current or final page URL",
    };
  }
  const scope = runtime.scopeGuard.test(stateUrl);
  if (!scope.allowed) {
    return {
      kind: "current_or_final_url_in_scope",
      ok: false,
      evidenceUsable: false,
      code: "MCP_POSTCONDITION_SCOPE_BLOCKED",
      url: scope.url,
      matchedOutOfScope: scope.matchedOutOfScope,
      reason: scope.reason,
    };
  }
  return {
    kind: "current_or_final_url_in_scope",
    ok: true,
    evidenceUsable: true,
    url: scope.url,
    matchedInScope: scope.matchedInScope,
    reason: scope.reason,
  };
}

function assertMcpScopedPostcondition(
  postcondition: McpScopedPostconditionResult | undefined,
  context: string,
  artifactPath: string,
): void {
  if (!postcondition || postcondition.ok) {
    return;
  }
  throw new BountyPilotError(
    `${context} failed scoped postcondition: ${postcondition.reason ?? "state URL was not in scope"}. Evidence: ${artifactPath}`,
    postcondition.code ?? "MCP_POSTCONDITION_SCOPE_BLOCKED",
  );
}

const MCP_STATE_URL_KEYS = new Set(["currentUrl", "current_url", "finalUrl", "final_url", "pageUrl", "page_url"]);

function extractCurrentOrFinalUrl(value: unknown, seen = new Set<unknown>()): string | undefined {
  if (typeof value === "string") {
    return extractCurrentOrFinalUrlFromText(value, seen);
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = extractCurrentOrFinalUrl(item, seen);
      if (found) return found;
    }
    return undefined;
  }
  if (!value || typeof value !== "object") {
    return undefined;
  }
  if (seen.has(value)) {
    return undefined;
  }
  seen.add(value);
  const record = value as Record<string, unknown>;
  for (const key of MCP_STATE_URL_KEYS) {
    const candidate = record[key];
    if (typeof candidate === "string" && isHttpUrlString(candidate)) {
      return candidate;
    }
  }
  for (const item of Object.values(record)) {
    const found = extractCurrentOrFinalUrl(item, seen);
    if (found) return found;
  }
  return undefined;
}

function extractCurrentOrFinalUrlFromText(value: string, seen: Set<unknown>): string | undefined {
  const trimmed = value.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return extractCurrentOrFinalUrl(JSON.parse(trimmed) as unknown, seen);
    } catch {
      // Continue with label extraction below.
    }
  }
  const match = value.match(
    /\b(?:Current URL|currentUrl|current_url|Final URL|finalUrl|final_url|Page URL|pageUrl|page_url)\b\s*[:=]\s*["']?(https?:\/\/[^\s"'<>]+)/i,
  );
  return match?.[1];
}

function isHttpUrlString(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://");
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

function summarizeValidation(validation: McpCallPlanValidation): Record<string, unknown> {
  return {
    ok: validation.ok,
    decision: validation.decision,
    reasons: validation.reasons,
    server: validation.server,
    tool: validation.tool,
    requiresApproval: validation.requiresApproval,
    capability: validation.capability?.id,
  };
}

function streamEventSummary(streamEvents: McpStreamEventLog): Record<string, unknown> {
  const countsByKind = streamEvents.events.reduce<Record<string, number>>((counts, event) => {
    counts[event.kind] = (counts[event.kind] ?? 0) + 1;
    return counts;
  }, {});
  const methods = uniqueStrings(
    streamEvents.events.map((event) => event.method).filter((method): method is string => Boolean(method)),
  ).slice(0, 12);
  return {
    total: streamEvents.total,
    captured: streamEvents.captured,
    dropped: streamEvents.dropped,
    truncated: streamEvents.truncated,
    countsByKind,
    methods,
  };
}

function recordMcpStreamTimelineEvent(
  runtime: Runtime,
  input: {
    jobId?: string;
    server: string;
    tool: string;
    evidencePath: string;
    streamEvents: McpStreamEventLog;
    status: "completed" | "failed" | "blocked";
  },
): void {
  if (!input.jobId) {
    return;
  }
  const interestingEvents = input.streamEvents.events.filter((event) => event.kind !== "response");
  if (interestingEvents.length === 0 && !input.streamEvents.truncated) {
    return;
  }

  runtime.events.record({
    jobId: input.jobId,
    phase: "mcp-stream",
    status: input.status,
    message: `MCP stream captured ${input.streamEvents.total} stdout event(s) for ${input.server}/${input.tool}.`,
    metadata: {
      server: input.server,
      tool: input.tool,
      evidence: input.evidencePath,
      ...streamEventSummary(input.streamEvents),
    },
  });
}

function classifyMcpStreamEvent(record: Record<string, unknown> | undefined): McpStreamEvent["kind"] {
  if (!record) {
    return "unknown";
  }
  const id = record.id;
  const method = typeof record.method === "string" ? record.method : undefined;
  if (method) {
    const normalized = method.toLowerCase();
    if (normalized === "notifications/progress" || normalized.endsWith("/progress")) {
      return "progress";
    }
    if (normalized === "notifications/message" || normalized === "logging/message" || normalized.includes("log")) {
      return "log";
    }
    return typeof id === "number" ? "request" : "notification";
  }
  if (typeof id === "number" && ("result" in record || "error" in record)) {
    return "response";
  }
  return "unknown";
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function stringifyStreamMessage(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function uniqueStrings(items: string[]): string[] {
  return [...new Set(items)];
}

function errorResponse(id: number, message: string): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id,
    error: { code: -32_000, message },
  };
}

function assertSafeArgument(argument: string): void {
  assertLocalProcessArgument(argument, "MCP_ARGUMENT_INVALID");
}

function mcpFailureContext(error: unknown, stdoutPreview: string): McpFailureContext {
  const normalized =
    error instanceof BountyPilotError
      ? error
      : new BountyPilotError("MCP stdout frame parsing failed", "MCP_FRAME_INVALID");
  return {
    phase: "stdout_frame",
    code: normalized.code,
    message: normalized.message,
    stdoutPreview,
    stdoutPreviewTruncated: stdoutPreview.length >= MAX_MCP_TRANSCRIPT_PREVIEW_CHARS,
  };
}

function appendTranscriptPreview(current: string, chunk: Buffer): string {
  return appendBounded(current, safeTranscriptText(chunk.toString("utf8")), MAX_MCP_TRANSCRIPT_PREVIEW_CHARS);
}

function safeTranscriptText(value: string): string {
  return maskSecrets(value).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "?");
}

function appendBounded(current: string, chunk: string, maxLength = MAX_CAPTURE_BYTES): string {
  const next = current + chunk;
  return next.length > maxLength ? next.slice(0, maxLength) : next;
}

function safeFileName(value: string): string {
  return value.replace(/[^a-z0-9.-]/gi, "_");
}
