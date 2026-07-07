import type { ProgramConfig } from "../../core/config/program-schema.js";
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

  constructor(
    private readonly config: ProgramConfig,
    registry: AdapterRegistry = new AdapterRegistry(),
  ) {
    this.integrations = new IntegrationManager(config, registry);
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
      message: "This is a policy-safe planned call only. Use `mcp call` only for explicitly enabled stdio MCP integrations.",
    };
  }
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
