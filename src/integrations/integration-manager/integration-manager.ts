import { z } from "zod";
import type { ProgramConfig } from "../../core/config/program-schema.js";
import { PolicyGate } from "../../core/policy/policy-gate.js";
import type { ExecutionMode, PolicyDecision, RiskLevel } from "../../types.js";
import type {
  AdapterCallPlan,
  AdapterCallPlanValidation,
  AdapterCapabilityMetadata,
  AdapterHealth,
  AdapterRegistration,
  AdapterType,
  McpTransport,
} from "../adapters/adapter.js";
import {
  AdapterRegistry,
  findCapability,
  normalizeAdapterKey,
  summarizeCapabilities,
} from "../adapters/registry.js";

export type IntegrationStatus = "configured" | "not_configured" | "planned" | "disabled" | "error";

const AdapterTypeSchema = z.enum(["mcp", "crawler", "research-skill", "external-tool", "browser", "desktop"]);
const McpTransportSchema = z.enum(["stdio", "http", "sse"]);
const IntegrationExecutionSchema = z
  .object({
    enabled: z.boolean().optional(),
    command: z.string().min(1).optional(),
    args: z.array(z.string()).optional(),
    package: z.string().min(1).optional(),
    package_version: z.string().min(1).optional(),
    entrypoint: z.string().min(1).optional(),
    entrypoint_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
    package_json_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
    timeout_ms: z.number().int().positive().max(120_000).optional(),
  })
  .passthrough();

const IntegrationConfigSchema = z
  .object({
    enabled: z.boolean().optional(),
    allow_execute: z.boolean().optional(),
    type: AdapterTypeSchema.optional(),
    source: z.string().min(1).optional(),
    transport: McpTransportSchema.optional(),
    command: z.string().min(1).optional(),
    args: z.array(z.string()).optional(),
    package: z.string().min(1).optional(),
    package_version: z.string().min(1).optional(),
    entrypoint: z.string().min(1).optional(),
    entrypoint_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
    package_json_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
    url: z.string().min(1).optional(),
    endpoint: z.string().min(1).optional(),
    timeout_ms: z.number().int().positive().max(120_000).optional(),
    capabilities: z.array(z.string().min(1)).optional(),
    blocked_capabilities: z.array(z.string().min(1)).optional(),
    execution: IntegrationExecutionSchema.optional(),
    options: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();

export type IntegrationConfig = z.infer<typeof IntegrationConfigSchema>;

export interface IntegrationRecord {
  name: string;
  type: AdapterType | "unknown";
  enabled: boolean;
  status: IntegrationStatus;
  displayName?: string;
  capabilities?: string[];
  riskyCapabilities?: string[];
  message?: string;
}

export interface ResolvedIntegration extends IntegrationRecord {
  config: IntegrationConfig;
  configKey?: string;
  registration?: AdapterRegistration;
  capabilityMetadata: AdapterCapabilityMetadata[];
  unknownCapabilities: string[];
  configErrors: string[];
  missingConfig: string[];
}

interface ParsedIntegrationConfig {
  config: IntegrationConfig;
  errors: string[];
}

export class IntegrationManager {
  private readonly registry: AdapterRegistry;

  constructor(
    private readonly config: ProgramConfig,
    registry: AdapterRegistry = new AdapterRegistry(),
  ) {
    this.registry = registry;
  }

  list(): IntegrationRecord[] {
    return this.resolveAll().map((integration) => ({
      name: integration.name,
      type: integration.type,
      enabled: integration.enabled,
      status: integration.status,
      displayName: integration.displayName,
      capabilities: integration.capabilities,
      riskyCapabilities: integration.riskyCapabilities,
      message: integration.message,
    }));
  }

  listDetailed(): ResolvedIntegration[] {
    return this.resolveAll();
  }

  get(name: string): ResolvedIntegration | undefined {
    const key = normalizeAdapterKey(name);
    return this.resolveAll().find(
      (integration) =>
        normalizeAdapterKey(integration.name) === key ||
        integration.registration?.aliases?.some((alias) => normalizeAdapterKey(alias) === key),
    );
  }

  capabilities(name: string): AdapterCapabilityMetadata[] {
    return this.get(name)?.capabilityMetadata ?? [];
  }

  doctor(): AdapterHealth[] {
    return this.resolveAll().map((integration) => ({
      name: integration.name,
      ok: integration.status === "configured",
      status: healthStatus(integration.status),
      message: integration.message,
      details: {
        type: integration.type,
        enabled: integration.enabled,
        capabilities: integration.capabilities ?? [],
        riskyCapabilities: integration.riskyCapabilities ?? [],
        missingConfig: integration.missingConfig,
        configErrors: integration.configErrors,
      },
    }));
  }

  validateCallPlan(plan: AdapterCallPlan): AdapterCallPlanValidation {
    const integration = this.get(plan.integration);
    if (!integration) {
      return blocked(`Unknown integration: ${plan.integration}`);
    }
    if (!integration.registration) {
      return blocked(`Integration ${integration.name} is not registered as a trusted adapter`, integration.name);
    }
    if (integration.status !== "configured") {
      return blocked(
        `Integration ${integration.name} is ${integration.status}: ${integration.message ?? "not ready"}`,
        integration.name,
      );
    }

    const capability = findCapability(integration.registration.capabilities, plan.capability);
    if (!capability) {
      return blocked(`Capability ${plan.capability} is not known for ${integration.name}`, integration.name);
    }
    if (!findCapability(integration.capabilityMetadata, capability.id)) {
      return blocked(`Capability ${capability.id} is not enabled for ${integration.name}`, integration.name, capability);
    }
    if (plan.actionType && plan.actionType !== capability.actionType) {
      return blocked(
        `Action type ${plan.actionType} does not match capability ${capability.id} (${capability.actionType})`,
        integration.name,
        capability,
      );
    }
    if (!capability.allowedModes.includes(plan.mode)) {
      return blocked(`Capability ${capability.id} is not allowed in ${plan.mode} mode`, integration.name, capability);
    }
    if (capability.requiresScope && !plan.target) {
      return blocked(`Capability ${capability.id} requires an in-scope target`, integration.name, capability);
    }
    if (capability.requiresTarget && !plan.target) {
      return blocked(`Capability ${capability.id} requires an explicit in-scope target`, integration.name, capability);
    }
    if (capability.blockedByDefault || capability.destructive || plan.destructive) {
      return blocked(`Capability ${capability.id} is blocked because it is destructive or unsafe`, integration.name, capability);
    }

    const policy = new PolicyGate(this.config.rules).evaluate({
      mode: plan.mode,
      actionType: capability.actionType,
      target: plan.target,
      riskLevel: maxRisk(capability.riskLevel, plan.riskLevel),
      stateChanging: plan.stateChanging ?? capability.stateChanging,
      destructive: plan.destructive ?? capability.destructive,
      capability: capability.id,
      requiresApprovalByDefault: capability.requiresApprovalByDefault,
      labModeEnabled: this.config.rules.lab_mode === true,
    });

    return {
      ok: policy.decision !== "block",
      decision: policy.decision,
      reasons: [policy.reason],
      integration: integration.name,
      capability,
      requiresApproval: policy.decision === "require_approval",
    };
  }

  private resolveAll(): ResolvedIntegration[] {
    const rawIntegrations = integrationConfigEntries(this.config);
    const consumedKeys = new Set<string>();
    const resolved = this.registry.list().map((registration) => {
      const match = findRawConfigForRegistration(rawIntegrations, registration);
      if (match) consumedKeys.add(match.key);
      return resolveRegisteredIntegration(registration, match?.key, match?.value);
    });

    for (const [key, value] of rawIntegrations) {
      if (consumedKeys.has(key)) continue;
      resolved.push(resolveUnknownIntegration(key, value));
    }

    return resolved;
  }
}

function integrationConfigEntries(config: ProgramConfig): Array<[string, unknown]> {
  return Object.entries(config.integrations as Record<string, unknown>);
}

function findRawConfigForRegistration(
  entries: Array<[string, unknown]>,
  registration: AdapterRegistration,
): { key: string; value: unknown } | undefined {
  const keys = new Set([registration.name, ...(registration.aliases ?? [])].map(normalizeAdapterKey));
  const match = entries.find(([key]) => keys.has(normalizeAdapterKey(key)));
  return match ? { key: match[0], value: match[1] } : undefined;
}

function resolveRegisteredIntegration(
  registration: AdapterRegistration,
  configKey: string | undefined,
  rawConfig: unknown,
): ResolvedIntegration {
  const parsed = parseIntegrationConfig(rawConfig, registration.defaultEnabled);
  const config = parsed.config;
  const configErrors = [...parsed.errors];
  if (config.type && config.type !== registration.type) {
    configErrors.push(`type must be ${registration.type}`);
  }

  const missingConfig = config.enabled ? missingRequiredConfig(registration, config) : [];
  const enabledCapabilities = enabledCapabilityMetadata(registration, config);
  const unknownCapabilities = unknownConfiguredCapabilities(registration, config);
  const status = integrationStatus({
    hasConfig: rawConfig !== undefined,
    enabled: config.enabled === true,
    configErrors,
    missingConfig,
    unknownCapabilities,
  });
  const summary = summarizeCapabilities(enabledCapabilities);

  return {
    name: registration.name,
    type: registration.type,
    enabled: config.enabled === true,
    status,
    displayName: registration.displayName,
    capabilities: summary.actions,
    riskyCapabilities: summary.riskyCapabilities,
    message: integrationMessage(registration, status, configErrors, missingConfig, unknownCapabilities),
    config,
    configKey,
    registration,
    capabilityMetadata: enabledCapabilities,
    unknownCapabilities,
    configErrors,
    missingConfig,
  };
}

function resolveUnknownIntegration(configKey: string, rawConfig: unknown): ResolvedIntegration {
  const parsed = parseIntegrationConfig(rawConfig, false);
  const type = parsed.config.type ?? "unknown";
  const configErrors = parsed.errors.length > 0 ? parsed.errors : [`${configKey} is not present in the adapter registry`];

  return {
    name: configKey,
    type,
    enabled: parsed.config.enabled === true,
    status: "error",
    message: configErrors.join("; "),
    config: parsed.config,
    configKey,
    capabilityMetadata: [],
    capabilities: [],
    riskyCapabilities: [],
    unknownCapabilities: parsed.config.capabilities ?? [],
    configErrors,
    missingConfig: [],
  };
}

function parseIntegrationConfig(rawConfig: unknown, defaultEnabled: boolean): ParsedIntegrationConfig {
  if (rawConfig === undefined) {
    return { config: { enabled: defaultEnabled }, errors: [] };
  }

  const candidate = typeof rawConfig === "boolean" ? { enabled: rawConfig } : rawConfig;
  const parsed = IntegrationConfigSchema.safeParse(candidate);
  if (!parsed.success) {
    return {
      config: { enabled: defaultEnabled },
      errors: parsed.error.issues.map((issue) => `${issue.path.join(".") || "config"}: ${issue.message}`),
    };
  }

  return {
    config: {
      ...parsed.data,
      enabled: parsed.data.enabled ?? defaultEnabled,
    },
    errors: [],
  };
}

function missingRequiredConfig(registration: AdapterRegistration, config: IntegrationConfig): string[] {
  const missing = (registration.configuration?.requiredWhenEnabled ?? []).filter((field) => !hasConfigValue(config, field));
  if (registration.mcp) {
    if (!config.transport) {
      missing.push("transport");
    } else if (config.transport === "stdio" && !hasConfigValue(config, "command")) {
      missing.push("command");
    } else if ((config.transport === "http" || config.transport === "sse") && !config.url && !config.endpoint) {
      missing.push("url");
    }
  }
  return [...new Set(missing)];
}

function hasConfigValue(config: IntegrationConfig, field: string): boolean {
  if (field === "command" && hasPackageEntrypointConfig(config)) {
    return true;
  }
  const value = config[field as keyof IntegrationConfig];
  if (configValuePresent(value)) {
    return true;
  }
  const executionValue = config.execution?.[field as keyof NonNullable<IntegrationConfig["execution"]>];
  return configValuePresent(executionValue);
}

function configValuePresent(value: unknown): boolean {
  return Array.isArray(value) ? value.length > 0 : value !== undefined && value !== "";
}

function hasPackageEntrypointConfig(config: IntegrationConfig): boolean {
  const packageName = config.execution?.package ?? config.package;
  const packageVersion = config.execution?.package_version ?? config.package_version;
  const entrypoint = config.execution?.entrypoint ?? config.entrypoint;
  return configValuePresent(packageName) && configValuePresent(packageVersion) && configValuePresent(entrypoint);
}

function enabledCapabilityMetadata(
  registration: AdapterRegistration,
  config: IntegrationConfig,
): AdapterCapabilityMetadata[] {
  const requested = config.capabilities?.map(normalizeAdapterKey);
  const blockedCapabilities = new Set((config.blocked_capabilities ?? []).map(normalizeAdapterKey));

  return registration.capabilities.filter((capability) => {
    const identifiers = capabilityIdentifiers(capability);
    const requestedMatch = !requested || identifiers.some((identifier) => requested.includes(identifier));
    const blockedMatch = identifiers.some((identifier) => blockedCapabilities.has(identifier));
    return requestedMatch && !blockedMatch;
  });
}

function unknownConfiguredCapabilities(registration: AdapterRegistration, config: IntegrationConfig): string[] {
  return (config.capabilities ?? []).filter((capability) => !findCapability(registration.capabilities, capability));
}

function capabilityIdentifiers(capability: AdapterCapabilityMetadata): string[] {
  return [capability.id, capability.actionType, ...(capability.mcpTools ?? [])].map(normalizeAdapterKey);
}

function integrationStatus(input: {
  hasConfig: boolean;
  enabled: boolean;
  configErrors: string[];
  missingConfig: string[];
  unknownCapabilities: string[];
}): IntegrationStatus {
  if (input.configErrors.length > 0 || input.unknownCapabilities.length > 0) return "error";
  if (!input.enabled) return input.hasConfig ? "disabled" : "planned";
  if (input.missingConfig.length > 0) return "not_configured";
  return "configured";
}

function integrationMessage(
  registration: AdapterRegistration,
  status: IntegrationStatus,
  configErrors: string[],
  missingConfig: string[],
  unknownCapabilities: string[],
): string {
  if (configErrors.length > 0) return configErrors.join("; ");
  if (unknownCapabilities.length > 0) return `Unknown capabilities: ${unknownCapabilities.join(", ")}`;
  if (missingConfig.length > 0) return `Missing required config: ${missingConfig.join(", ")}`;
  if (status === "configured") return `${registration.displayName} is configured for safe planning`;
  if (status === "disabled") return `${registration.displayName} is disabled in config`;
  return `${registration.displayName} is available as a planned adapter`;
}

function healthStatus(status: IntegrationStatus): AdapterHealth["status"] {
  if (status === "configured") return "ok";
  if (status === "not_configured") return "not_configured";
  if (status === "planned") return "planned";
  if (status === "disabled") return "disabled";
  return "error";
}

function blocked(
  reason: string,
  integration?: string,
  capability?: AdapterCapabilityMetadata,
): AdapterCallPlanValidation {
  return {
    ok: false,
    decision: "block",
    reasons: [reason],
    integration,
    capability,
    requiresApproval: false,
  };
}

function maxRisk(defaultRisk: RiskLevel, override?: RiskLevel): RiskLevel {
  if (!override) return defaultRisk;
  const order: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };
  return order[override] > order[defaultRisk] ? override : defaultRisk;
}

export type IntegrationCallPlan = AdapterCallPlan;
export type IntegrationCallPlanValidation = AdapterCallPlanValidation;
export type IntegrationPolicyDecision = PolicyDecision;
export type IntegrationExecutionMode = ExecutionMode;
export type IntegrationRiskLevel = RiskLevel;
export type IntegrationMcpTransport = McpTransport;
