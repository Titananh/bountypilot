import type { ExecutionMode, PolicyDecision, RiskLevel } from "../../types.js";

export type AdapterType = "mcp" | "crawler" | "research-skill" | "external-tool" | "browser" | "desktop";

export type AdapterHealthStatus = "ok" | "not_configured" | "disabled" | "planned" | "error";

export type McpTransport = "stdio" | "http" | "sse";

export interface AdapterHealth {
  name: string;
  ok: boolean;
  status: AdapterHealthStatus;
  message?: string;
  details?: Record<string, unknown>;
}

export interface AdapterCapabilityMetadata {
  id: string;
  title: string;
  description: string;
  actionType: string;
  riskLevel: RiskLevel;
  allowedModes: ExecutionMode[];
  produces: string[];
  requiresTarget?: boolean;
  requiresScope?: boolean;
  stateChanging?: boolean;
  destructive?: boolean;
  requiresApprovalByDefault?: boolean;
  blockedByDefault?: boolean;
  scopedPostcondition?: "current_or_final_url_in_scope";
  mcpTools?: string[];
}

export interface AdapterCapabilities {
  actions: string[];
  produces: string[];
  riskyCapabilities: string[];
  metadata?: AdapterCapabilityMetadata[];
}

export interface AdapterRegistration {
  name: string;
  aliases?: string[];
  type: AdapterType;
  displayName: string;
  description: string;
  defaultEnabled: boolean;
  capabilities: AdapterCapabilityMetadata[];
  configuration?: {
    requiredWhenEnabled?: string[];
    optional?: string[];
  };
  mcp?: {
    serverName: string;
    defaultTransport: McpTransport;
    localOnly: boolean;
  };
}

export interface AdapterCallPlan {
  integration: string;
  capability: string;
  actionType?: string;
  target?: string;
  mode: ExecutionMode;
  riskLevel?: RiskLevel;
  stateChanging?: boolean;
  destructive?: boolean;
  options?: Record<string, unknown>;
}

export interface AdapterCallPlanValidation {
  ok: boolean;
  decision: PolicyDecision;
  reasons: string[];
  integration?: string;
  capability?: AdapterCapabilityMetadata;
  requiresApproval: boolean;
}

export interface AdapterRunInput {
  target: string;
  jobId?: string;
  mode: string;
  dryRun?: boolean;
  options?: Record<string, unknown>;
}

export interface AdapterRunResult {
  adapterName: string;
  artifacts: unknown[];
  rawOutputPath?: string;
}

export interface NormalizedArtifact {
  type: string;
  payload: unknown;
}

export interface BountyAdapter {
  name: string;
  type: AdapterType;
  doctor(): Promise<AdapterHealth>;
  capabilities(): Promise<AdapterCapabilities>;
  run(input: AdapterRunInput): Promise<AdapterRunResult>;
  normalize(result: AdapterRunResult): Promise<NormalizedArtifact[]>;
}
