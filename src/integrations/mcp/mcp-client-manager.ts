import type { ProgramConfig } from "../../core/config/program-schema.js";
import { ScopeGuard } from "../../core/scope/scope-guard.js";
import type { ExecutionMode, PolicyDecision } from "../../types.js";
import type { AdapterCallPlanValidation, AdapterCapabilityMetadata, AdapterHealth } from "../adapters/adapter.js";
import { AdapterRegistry, findCapability, normalizeAdapterKey } from "../adapters/registry.js";
import { IntegrationManager, type IntegrationStatus, type ResolvedIntegration } from "../integration-manager/integration-manager.js";

export interface McpServerRecord {
  name: string;
  enabled: boolean;
  capabilities: string[];
  tools: string[];
  status: IntegrationStatus | "error";
  transport?: "stdio" | "http" | "sse";
  command?: string;
  url?: string;
  message?: string;
}

export interface McpCallPlan {
  server: string;
  tool: string;
  mode: ExecutionMode;
  target?: string;
  arguments?: Record<string, unknown>;
}

export interface McpCallPlanValidation {
  ok: boolean;
  decision: PolicyDecision;
  reasons: string[];
  server?: string;
  tool?: string;
  capability?: AdapterCapabilityMetadata;
  requiresApproval: boolean;
}

export interface McpPreparedCallPlan {
  execute: false;
  server: string;
  tool: string;
  mode: ExecutionMode;
  target?: string;
  arguments: Record<string, unknown>;
  validation: McpCallPlanValidation;
  message: string;
}

export class McpClientManager {
  private readonly integrations: IntegrationManager;
  private readonly scopeGuard: ScopeGuard;

  constructor(
    private readonly config: ProgramConfig,
    registry: AdapterRegistry = new AdapterRegistry(),
  ) {
    this.integrations = new IntegrationManager(config, registry);
    this.scopeGuard = new ScopeGuard(config);
  }

  listServers(): McpServerRecord[] {
    return this.integrations
      .listDetailed()
      .filter((integration) => isMcpIntegration(integration))
      .map((integration) => {
        const tools = mcpTools(integration.capabilityMetadata);
        return {
          name: integration.name,
          enabled: integration.enabled,
          capabilities: integration.capabilityMetadata.map((capability) => capability.id),
          tools,
          status: integration.status,
          transport: integration.config.transport ?? integration.registration?.mcp?.defaultTransport,
          command: integration.config.command,
          url: integration.config.url ?? integration.config.endpoint,
          message: integration.message,
        };
      });
  }

  health(): AdapterHealth[] {
    return this.listServers().map((server) => ({
      name: server.name,
      ok: server.status === "configured",
      status: server.status === "configured" ? "ok" : server.status,
      message:
        server.status === "configured"
          ? `${server.name}: configured for safe MCP call planning; no external connection attempted`
          : server.message,
      details: {
        transport: server.transport,
        command: server.command,
        url: server.url,
        tools: server.tools,
      },
    }));
  }

  doctor(): string[] {
    return this.health().map((entry) => `${entry.name}: ${entry.status}${entry.message ? ` - ${entry.message}` : ""}`);
  }

  validateCallPlan(plan: McpCallPlan): McpCallPlanValidation {
    const integration = this.integrations.get(plan.server);
    if (!integration) {
      return blocked(`Unknown MCP server: ${plan.server}`, plan.server, plan.tool);
    }
    if (!isMcpIntegration(integration)) {
      return blocked(`${integration.name} is not an MCP-backed adapter`, integration.name, plan.tool);
    }
    if (!integration.registration) {
      return blocked(`${integration.name} is not registered as a trusted MCP adapter`, integration.name, plan.tool);
    }

    const capability = findCapability(integration.registration.capabilities, plan.tool);
    if (!capability || !capability.mcpTools?.some((tool) => normalizeAdapterKey(tool) === normalizeAdapterKey(plan.tool))) {
      return blocked(`MCP tool ${plan.tool} is not registered for ${integration.name}`, integration.name, plan.tool);
    }

    const scopeFailure = validateMcpPlanScope(plan, this.scopeGuard);
    if (scopeFailure) {
      return blocked(scopeFailure, integration.name, plan.tool);
    }

    const validation: AdapterCallPlanValidation = this.integrations.validateCallPlan({
      integration: integration.name,
      capability: capability.id,
      actionType: capability.actionType,
      target: plan.target,
      mode: plan.mode,
      options: {
        mcpTool: plan.tool,
        arguments: plan.arguments ?? {},
      },
    });

    return {
      ok: validation.ok,
      decision: validation.decision,
      reasons: validation.reasons,
      server: integration.name,
      tool: plan.tool,
      capability: validation.capability,
      requiresApproval: validation.requiresApproval,
    };
  }

  prepareCallPlan(plan: McpCallPlan): McpPreparedCallPlan {
    const validation = this.validateCallPlan(plan);
    return {
      execute: false,
      server: validation.server ?? plan.server,
      tool: plan.tool,
      mode: plan.mode,
      target: plan.target,
      arguments: plan.arguments ?? {},
      validation,
      message: "zero-execution, scope-checked MCP handoff only; no external connection or tool execution is performed.",
    };
  }
}

const TARGET_LIKE_ARGUMENT_KEYS = new Set([
  "url",
  "uri",
  "endpoint",
  "origin",
  "host",
  "hostname",
  "domain",
  "target",
]);
const MAX_ARGUMENT_DEPTH = 32;
const MAX_ARGUMENT_NODES = 10_000;

interface ArgumentNode {
  value: unknown;
  path: string;
  depth: number;
  targetLike: boolean;
}

function validateMcpPlanScope(plan: McpCallPlan, scopeGuard: ScopeGuard): string | undefined {
  if (plan.target !== undefined) {
    if (typeof plan.target !== "string") {
      return "MCP plan target must be a string";
    }
    const failure = scopeFailure(scopeGuard, plan.target, "MCP plan target");
    if (failure) return failure;
  }

  if (plan.arguments === undefined) return undefined;
  if (!isPlainRecord(plan.arguments)) {
    return "MCP arguments must be a plain object";
  }

  const seen = new WeakSet<object>();
  const nodes: ArgumentNode[] = [{ value: plan.arguments, path: "arguments", depth: 0, targetLike: false }];
  let visited = 0;

  try {
    while (nodes.length > 0) {
      const node = nodes.pop()!;
      visited += 1;
      if (visited > MAX_ARGUMENT_NODES) {
        return `MCP arguments exceed the ${MAX_ARGUMENT_NODES}-node safety limit`;
      }

      if (node.targetLike && typeof node.value !== "string") {
        return `${node.path} must contain a string target`;
      }

      if (typeof node.value === "string") {
        if (node.targetLike || looksLikeAbsoluteHttpUrl(node.value)) {
          const failure = scopeFailure(scopeGuard, node.value, `MCP argument ${node.path}`);
          if (failure) return failure;
        }
        continue;
      }
      if (node.value === null || typeof node.value === "boolean") continue;
      if (typeof node.value === "number") {
        if (!Number.isFinite(node.value)) return `${node.path} contains a non-finite number`;
        continue;
      }
      if (typeof node.value !== "object") {
        return `${node.path} contains an unsupported ${typeof node.value} value`;
      }
      if (node.depth >= MAX_ARGUMENT_DEPTH) {
        return `MCP arguments exceed the ${MAX_ARGUMENT_DEPTH}-level nesting limit at ${node.path}`;
      }
      if (seen.has(node.value)) {
        return `MCP arguments contain a cycle or repeated object reference at ${node.path}`;
      }
      seen.add(node.value);

      const arrayValue = Array.isArray(node.value) ? node.value : undefined;
      const isArray = arrayValue !== undefined;
      const prototype = Object.getPrototypeOf(node.value);
      if ((!isArray && prototype !== Object.prototype && prototype !== null) || (isArray && prototype !== Array.prototype)) {
        return `${node.path} contains a non-plain object`;
      }

      const descriptors = Object.getOwnPropertyDescriptors(node.value);
      const keys = Reflect.ownKeys(descriptors);
      for (const key of keys) {
        if (typeof key === "symbol") return `${node.path} contains a symbol-keyed property`;
        if (isArray && key === "length") continue;

        const descriptor = descriptors[key];
        if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set) {
          return `${formatArgumentPath(node.path, key, isArray)} contains an accessor property`;
        }
        if (!descriptor.enumerable) {
          return `${formatArgumentPath(node.path, key, isArray)} is a non-enumerable property`;
        }
        if (arrayValue && !isArrayIndex(key, arrayValue.length)) {
          return `${formatArgumentPath(node.path, key, true)} is not a valid array element`;
        }

        nodes.push({
          value: descriptor.value,
          path: formatArgumentPath(node.path, key, isArray),
          depth: node.depth + 1,
          targetLike: !isArray && TARGET_LIKE_ARGUMENT_KEYS.has(key.toLowerCase()),
        });
      }

      if (arrayValue && keys.length - 1 !== arrayValue.length) {
        return `${node.path} contains sparse array elements`;
      }
    }
  } catch (error) {
    return `MCP arguments could not be inspected safely: ${errorMessage(error)}`;
  }

  return undefined;
}

function scopeFailure(scopeGuard: ScopeGuard, candidate: string, label: string): string | undefined {
  try {
    const result = scopeGuard.test(candidate);
    return result.allowed ? undefined : `${label} blocked by ScopeGuard: ${result.reason}`;
  } catch (error) {
    return `${label} is invalid: ${errorMessage(error)}`;
  }
}

function looksLikeAbsoluteHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return /^[\u0000-\u0020]*https?:/i.test(value);
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  try {
    if (Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function isArrayIndex(key: string, length: number): boolean {
  if (!/^(0|[1-9]\d*)$/.test(key)) return false;
  const index = Number(key);
  return Number.isSafeInteger(index) && index >= 0 && index < length && index < 2 ** 32 - 1;
}

function formatArgumentPath(parent: string, key: string, parentIsArray: boolean): string {
  if (parentIsArray && /^\d+$/.test(key)) return `${parent}[${key}]`;
  return /^[A-Za-z_$][\w$]*$/.test(key) ? `${parent}.${key}` : `${parent}[${JSON.stringify(key)}]`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMcpIntegration(integration: ResolvedIntegration): boolean {
  return integration.registration?.mcp !== undefined || integration.type === "mcp";
}

function mcpTools(capabilities: AdapterCapabilityMetadata[]): string[] {
  return [...new Set(capabilities.flatMap((capability) => capability.mcpTools ?? []))];
}

function blocked(reason: string, server?: string, tool?: string): McpCallPlanValidation {
  return {
    ok: false,
    decision: "block",
    reasons: [reason],
    server,
    tool,
    requiresApproval: false,
  };
}
