import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { parse } from "yaml";
import { z } from "zod";
import type { ExecutionMode, RiskLevel } from "../../types.js";
import { BLOCKED_CAPABILITIES, PolicyGate } from "../../core/policy/policy-gate.js";
import type { ProgramConfig } from "../../core/config/program-schema.js";
import { BountyPilotError } from "../../utils/errors.js";

const requireFromHere = createRequire(import.meta.url);

const ExecutionModeSchema = z.enum(["passive", "safe", "deep-safe", "lab-offensive"]);
const RiskLevelSchema = z.enum(["low", "medium", "high"]);

const NpmPackageNameSchema = z
  .string()
  .min(1)
  .regex(/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i, "npm package must be a package name, not a shell fragment");

const PinnedVersionSchema = z
  .string()
  .min(1)
  .refine((value) => value !== "latest" && !/[<>=^~*]/.test(value), "version must be an exact pinned version");

const TrustedChecksumSchema = z
  .string()
  .min(1)
  .refine(
    (value) => /^sha256:[a-f0-9]{64}$/i.test(value) || /^managed-by-[a-z0-9-]+$/i.test(value),
    "checksum must be sha256:<digest> or a managed-by-* lockfile marker",
  );

const HttpsSourceSchema = z
  .string()
  .url()
  .refine((value) => value.startsWith("https://"), "tool sources must use https");

const InstallMetadataSchema = z
  .object({
    type: z.enum(["npm", "docker", "local", "manual"]),
    package: NpmPackageNameSchema.optional(),
    image: z
      .string()
      .min(1)
      .refine((value) => !/[;&|`$<>\s]/.test(value), "docker image must not contain shell control characters or whitespace")
      .optional(),
    command: z.string().min(1).optional(),
  })
  .superRefine((install, ctx) => {
    if (install.type === "npm" && !install.package) {
      ctx.addIssue({ code: "custom", path: ["package"], message: "npm installs require a package name" });
    }
    if (install.type === "docker" && !install.image) {
      ctx.addIssue({ code: "custom", path: ["image"], message: "docker installs require an image" });
    }
    if ((install.type === "local" || install.type === "manual") && !install.command) {
      return;
    }
    if (install.command && /[;&|`$<>]/.test(install.command)) {
      ctx.addIssue({
        code: "custom",
        path: ["command"],
        message: "install command cannot contain shell control characters",
      });
    }
  });

const ToolRegistryActionSchema = z.object({
  action_type: z.string().min(1),
  risk_level: RiskLevelSchema.default("low"),
  capabilities: z.array(z.string().min(1)).default([]),
  state_changing: z.boolean().default(false),
  destructive: z.boolean().default(false),
  requires_approval: z.boolean().default(false),
  network: z.boolean().optional(),
  filesystem_write: z.boolean().optional(),
});

const ToolRegistryEntrySchema = z.object({
  name: z.string().min(1),
  category: z.string().min(1),
  description: z.string().min(1),
  source: HttpsSourceSchema,
  version: PinnedVersionSchema,
  checksum: TrustedChecksumSchema,
  install: InstallMetadataSchema,
  permissions: z.object({
    network: z.boolean(),
    filesystem_write: z.boolean(),
    destructive: z.boolean(),
    active_scanning: z.boolean(),
  }),
  safety: z.object({
    allowed_modes: z.array(ExecutionModeSchema).min(1),
    blocked_capabilities: z.array(z.string()),
  }),
  actions: z.array(ToolRegistryActionSchema).default([]),
});

const ToolRegistrySchema = z.object({
  tools: z.array(ToolRegistryEntrySchema),
}).superRefine((registry, ctx) => {
  const names = new Set<string>();
  for (const [index, tool] of registry.tools.entries()) {
    if (names.has(tool.name)) {
      ctx.addIssue({ code: "custom", path: ["tools", index, "name"], message: `duplicate tool name: ${tool.name}` });
    }
    names.add(tool.name);
  }
});

export type ToolRegistryEntry = z.infer<typeof ToolRegistryEntrySchema>;
export type ToolRegistryAction = z.infer<typeof ToolRegistryActionSchema>;

export interface ToolSearchOptions {
  query?: string;
  category?: string;
  mode?: ExecutionMode;
  capability?: string;
  includeBlocked?: boolean;
}

export interface ToolPlanStep {
  title: string;
  reason: string;
  command?: string;
  args?: string[];
  manual: boolean;
}

export interface ToolInstallPlan {
  tool: string;
  version: string;
  status: "ready" | "manual" | "blocked";
  execution: "plan_only";
  requiresApproval: boolean;
  steps: ToolPlanStep[];
  warnings: string[];
}

export interface InstalledToolState {
  installed?: boolean;
  version?: string;
  checksum?: string;
}

export interface ToolUpdatePlan {
  tool: string;
  fromVersion?: string;
  toVersion: string;
  status: "up_to_date" | "install_required" | "update_available" | "manual_review_required" | "blocked";
  requiresApproval: boolean;
  steps: ToolPlanStep[];
  warnings: string[];
}

export interface ToolDoctorCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

export interface ToolDoctorResult {
  name: string;
  category: string;
  version: string;
  installType: ToolRegistryEntry["install"]["type"];
  allowedModes: ExecutionMode[];
  status: "available" | "not_installed" | "blocked" | "manual" | "misconfigured";
  message: string;
  checks: ToolDoctorCheck[];
}

export interface ToolRunPlan {
  tool: string;
  mode: ExecutionMode;
  actionType: string;
  target?: string;
  riskLevel?: RiskLevel;
  capabilities?: string[];
  stateChanging?: boolean;
  destructive?: boolean;
  labModeEnabled?: boolean;
  programRules?: ProgramConfig["rules"];
}

export interface ToolRunPlanValidation {
  tool: string;
  actionType: string;
  allowed: boolean;
  requiresApproval: boolean;
  riskLevel?: RiskLevel;
  reasons: string[];
  warnings: string[];
}

const BUILT_IN_TOOLS: ToolRegistryEntry[] = [
  {
    name: "playwright",
    category: "browser-evidence",
    description: "Local browser automation and evidence capture.",
    source: "https://github.com/microsoft/playwright",
    version: "1.55.0",
    checksum: "managed-by-package-lock",
    install: { type: "npm", package: "playwright" },
    permissions: {
      network: true,
      filesystem_write: true,
      destructive: false,
      active_scanning: false,
    },
    safety: {
      allowed_modes: ["safe", "deep-safe"],
      blocked_capabilities: ["destructive_testing", "data_exfiltration", "waf_evasion"],
    },
    actions: [
      {
        action_type: "browser.navigate",
        risk_level: "low",
        capabilities: ["browser_automation", "evidence_capture"],
        state_changing: false,
        destructive: false,
        requires_approval: false,
        network: true,
        filesystem_write: true,
      },
      {
        action_type: "browser.request",
        risk_level: "low",
        capabilities: ["browser_automation"],
        state_changing: false,
        destructive: false,
        requires_approval: false,
        network: true,
        filesystem_write: false,
      },
    ],
  },
  ...bugBountyToolRegistry(),
];

function bugBountyToolRegistry(): ToolRegistryEntry[] {
  return [
    localTool("subfinder", {
      category: "subdomain-enumeration",
      description: "Passive subdomain discovery for authorized program assets.",
      source: "https://github.com/projectdiscovery/subfinder",
      actionType: "research.public",
      capabilities: ["public_recon", "subdomain_discovery"],
      allowedModes: ["safe", "deep-safe"],
      activeScanning: false,
      riskLevel: "low",
    }),
    localTool("dnsx", {
      category: "dns-resolution",
      description: "Resolve discovered hosts and filter dead DNS records.",
      source: "https://github.com/projectdiscovery/dnsx",
      actionType: "http.probe",
      capabilities: ["dns_resolution"],
      allowedModes: ["safe", "deep-safe"],
      activeScanning: false,
      riskLevel: "low",
    }),
    localTool("httpx", {
      category: "live-host-discovery",
      description: "Identify live HTTP services, titles, technologies, redirects, and status codes.",
      source: "https://github.com/projectdiscovery/httpx",
      actionType: "http.probe",
      capabilities: ["http_probe", "technology_detection"],
      allowedModes: ["safe", "deep-safe"],
      activeScanning: false,
      riskLevel: "low",
    }),
    localTool("katana", {
      category: "urls-and-crawling",
      description: "Crawl in-scope web apps for URLs, forms, and JavaScript routes.",
      source: "https://github.com/projectdiscovery/katana",
      actionType: "crawler.fetch",
      capabilities: ["crawler.fetch", "endpoint_discovery"],
      allowedModes: ["safe", "deep-safe"],
      activeScanning: false,
      riskLevel: "low",
    }),
    localTool("gau", {
      category: "urls-and-history",
      description: "Gather historical URLs for parameter and endpoint review.",
      source: "https://github.com/lc/gau",
      actionType: "research.public",
      capabilities: ["public_recon", "historical_url_discovery"],
      allowedModes: ["safe", "deep-safe"],
      activeScanning: false,
      riskLevel: "low",
    }),
    localTool("waybackurls", {
      category: "urls-and-history",
      description: "Pull archived URLs for scoped hosts.",
      source: "https://github.com/tomnomnom/waybackurls",
      actionType: "research.public",
      capabilities: ["public_recon", "historical_url_discovery"],
      allowedModes: ["safe", "deep-safe"],
      activeScanning: false,
      riskLevel: "low",
    }),
    localTool("nuclei", {
      category: "vulnerability-scanners",
      description: "Template-based checks that require rate limits, program permission, and review.",
      source: "https://github.com/projectdiscovery/nuclei",
      actionType: "http.scan",
      capabilities: ["template_scan", "vulnerability_signal"],
      allowedModes: ["safe", "deep-safe", "lab-offensive"],
      activeScanning: true,
      riskLevel: "medium",
      requiresApproval: true,
    }),
    localTool("ffuf", {
      category: "content-discovery",
      description: "Directory, file, and parameter discovery with strict rate limits and review.",
      source: "https://github.com/ffuf/ffuf",
      actionType: "http.fuzz",
      capabilities: ["content_discovery"],
      allowedModes: ["deep-safe", "lab-offensive"],
      activeScanning: true,
      riskLevel: "medium",
      requiresApproval: true,
    }),
    localTool("dalfox", {
      category: "xss-validation",
      description: "XSS parameter validation; keep live use to explicitly permitted scopes or owned labs.",
      source: "https://github.com/hahwul/dalfox",
      actionType: "http.validate",
      capabilities: ["xss_validation", "exploit_validation"],
      allowedModes: ["deep-safe", "lab-offensive"],
      activeScanning: true,
      riskLevel: "high",
      requiresApproval: true,
    }),
    localTool("naabu", {
      category: "port-scanning",
      description: "Fast port discovery that is frequently restricted by program rules.",
      source: "https://github.com/projectdiscovery/naabu",
      actionType: "tcp.scan",
      capabilities: ["port_discovery"],
      allowedModes: ["lab-offensive"],
      activeScanning: true,
      riskLevel: "high",
      requiresApproval: true,
    }),
    localTool("nmap", {
      category: "port-scanning",
      description: "Network mapper for explicitly authorized assets; review-required by default.",
      source: "https://github.com/nmap/nmap",
      actionType: "tcp.scan",
      capabilities: ["port_discovery", "service_detection"],
      allowedModes: ["lab-offensive"],
      activeScanning: true,
      riskLevel: "high",
      requiresApproval: true,
    }),
    localTool("jq", {
      category: "workflow-utilities",
      description: "Local JSON parser used for artifact review and pipeline stitching.",
      source: "https://github.com/jqlang/jq",
      actionType: "artifact.parse",
      capabilities: ["local_parsing"],
      allowedModes: ["passive", "safe", "deep-safe", "lab-offensive"],
      activeScanning: false,
      riskLevel: "low",
      network: false,
      filesystemWrite: false,
    }),
    localTool("curl", {
      category: "http-utility",
      description: "Single-request HTTP evidence helper for scoped, rate-limited checks.",
      source: "https://github.com/curl/curl",
      actionType: "http.get",
      capabilities: ["http_probe", "evidence_capture"],
      allowedModes: ["safe", "deep-safe", "lab-offensive"],
      activeScanning: false,
      riskLevel: "low",
      network: true,
      filesystemWrite: false,
    }),
    localTool("crawl4ai", {
      category: "crawler",
      description: "Optional crawler integration for in-scope read-only crawl graphs.",
      source: "https://github.com/unclecode/crawl4ai",
      actionType: "crawler.fetch",
      capabilities: ["crawler.fetch", "crawl_graph"],
      allowedModes: ["safe", "deep-safe", "lab-offensive"],
      activeScanning: false,
      riskLevel: "low",
      requiresApproval: true,
    }),
    localTool("playwright-mcp", {
      category: "mcp-browser",
      description: "Optional Playwright MCP browser adapter for scoped evidence capture.",
      source: "https://github.com/microsoft/playwright-mcp",
      actionType: "browser.navigate",
      capabilities: ["browser_automation", "mcp_live_execution", "evidence_capture"],
      allowedModes: ["safe", "deep-safe", "lab-offensive"],
      activeScanning: false,
      riskLevel: "low",
      requiresApproval: true,
    }),
    localTool("d-research-skill", {
      category: "research",
      description: "Local planning-only public research skill for program context and duplicate hints.",
      source: "https://github.com/openai/codex",
      actionType: "research.public",
      capabilities: ["public_recon", "local_planning"],
      allowedModes: ["passive", "safe", "deep-safe"],
      activeScanning: false,
      riskLevel: "low",
      network: false,
      filesystemWrite: true,
    }),
  ];
}

function localTool(
  name: string,
  input: {
    category: string;
    description: string;
    source: string;
    actionType: string;
    capabilities: string[];
    allowedModes: ExecutionMode[];
    activeScanning: boolean;
    riskLevel: RiskLevel;
    requiresApproval?: boolean;
    network?: boolean;
    filesystemWrite?: boolean;
  },
): ToolRegistryEntry {
  return {
    name,
    category: input.category,
    description: input.description,
    source: input.source,
    version: "0.0.0",
    checksum: "managed-by-bountypilot-arsenal",
    install: { type: "local", command: name },
    permissions: {
      network: input.network ?? true,
      filesystem_write: input.filesystemWrite ?? true,
      destructive: false,
      active_scanning: input.activeScanning,
    },
    safety: {
      allowed_modes: input.allowedModes,
      blocked_capabilities: ["brute_force", "credential_stuffing", "destructive_testing", "data_exfiltration", "waf_evasion"],
    },
    actions: [
      {
        action_type: input.actionType,
        risk_level: input.riskLevel,
        capabilities: input.capabilities,
        state_changing: false,
        destructive: false,
        requires_approval: input.requiresApproval ?? false,
        network: input.network ?? true,
        filesystem_write: input.filesystemWrite ?? true,
      },
    ],
  };
}

export class ToolManager {
  private readonly registry: ToolRegistryEntry[];

  constructor(registry: ToolRegistryEntry[] = BUILT_IN_TOOLS) {
    this.registry = parseRegistry({ tools: registry }, "inline tool registry");
  }

  static loadRegistryFile(filePath: string): ToolRegistryEntry[] {
    if (!existsSync(filePath)) {
      throw new BountyPilotError(`Tool registry not found: ${filePath}`, "TOOL_REGISTRY_NOT_FOUND");
    }
    return parseRegistry(parse(readFileSync(filePath, "utf8")), filePath);
  }

  static fromRegistryFile(filePath: string, options?: { includeBuiltIns?: boolean }): ToolManager {
    const loaded = ToolManager.loadRegistryFile(filePath);
    return new ToolManager(options?.includeBuiltIns ? mergeRegistry(BUILT_IN_TOOLS, loaded) : loaded);
  }

  list(category?: string): ToolRegistryEntry[] {
    return this.registry.filter((tool) => !category || tool.category === category);
  }

  search(input: string | ToolSearchOptions): ToolRegistryEntry[] {
    const options = typeof input === "string" ? { query: input } : input;
    const query = normalizeSearch(options.query);
    const capability = options.capability?.toLowerCase();

    return this.registry.filter((tool) => {
      if (options.category && tool.category !== options.category) return false;
      if (options.mode && !tool.safety.allowed_modes.includes(options.mode) && !options.includeBlocked) return false;
      if (capability && !tool.actions.some((action) => action.capabilities.some((item) => item.toLowerCase() === capability))) {
        return false;
      }
      if (!query) return true;
      const haystack = [
        tool.name,
        tool.category,
        tool.description,
        tool.source,
        tool.install.type,
        tool.install.package,
        tool.install.image,
        ...tool.actions.map((action) => action.action_type),
        ...tool.actions.flatMap((action) => action.capabilities),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return query.every((term) => haystack.includes(term));
    });
  }

  get(name: string): ToolRegistryEntry | undefined {
    return this.registry.find((tool) => tool.name === name);
  }

  assertAllowedForMode(name: string, mode: ExecutionMode): ToolRegistryEntry {
    const tool = this.get(name);
    if (!tool) {
      throw new BountyPilotError(`Unknown trusted tool: ${name}`, "TOOL_UNKNOWN");
    }
    if (!tool.safety.allowed_modes.includes(mode)) {
      throw new BountyPilotError(`Tool ${name} is not allowed in ${mode} mode`, "TOOL_MODE_BLOCKED");
    }
    if (tool.permissions.destructive) {
      throw new BountyPilotError(`Tool ${name} is marked destructive and is blocked`, "TOOL_DESTRUCTIVE_BLOCKED");
    }
    return tool;
  }

  createInstallPlan(name: string): ToolInstallPlan {
    const tool = this.requireTool(name);
    const warnings: string[] = [];
    const steps: ToolPlanStep[] = [];

    if (tool.permissions.destructive) {
      return {
        tool: tool.name,
        version: tool.version,
        status: "blocked",
        execution: "plan_only",
        requiresApproval: true,
        steps,
        warnings: ["Tool is marked destructive in the trusted registry and cannot be installed automatically."],
      };
    }

    steps.push({
      title: "Review trusted registry metadata",
      reason: `Confirm source ${tool.source}, pinned version ${tool.version}, and checksum marker ${tool.checksum}.`,
      manual: true,
    });

    if (tool.install.command) {
      warnings.push("Registry install.command is treated as metadata only; ToolManager does not execute arbitrary install scripts.");
    }

    if (tool.install.type === "manual") {
      return {
        tool: tool.name,
        version: tool.version,
        status: "manual",
        execution: "plan_only",
        requiresApproval: true,
        steps: [
          ...steps,
          {
            title: "Follow vendor-maintained manual install instructions",
            reason: "Manual tools can vary by platform, so BountyPilot records the plan but does not run installer steps.",
            manual: true,
          },
        ],
        warnings,
      };
    }

    const installStep = installStepFor(tool);
    const hasExecutablePlan = installStep?.command && !installStep.manual;
    return {
      tool: tool.name,
      version: tool.version,
      status: hasExecutablePlan ? "ready" : "manual",
      execution: "plan_only",
      requiresApproval: true,
      steps: installStep ? [...steps, installStep] : steps,
      warnings,
    };
  }

  createUpdatePlan(name: string, current?: InstalledToolState): ToolUpdatePlan {
    const tool = this.requireTool(name);
    if (tool.permissions.destructive) {
      return {
        tool: tool.name,
        fromVersion: current?.version,
        toVersion: tool.version,
        status: "blocked",
        requiresApproval: true,
        steps: [],
        warnings: ["Tool is marked destructive in the trusted registry and cannot be updated automatically."],
      };
    }

    if (!current || current.installed === false || !current.version) {
      const installPlan = this.createInstallPlan(name);
      return {
        tool: tool.name,
        toVersion: tool.version,
        status: "install_required",
        requiresApproval: true,
        steps: installPlan.steps,
        warnings: installPlan.warnings,
      };
    }

    if (current.version === tool.version && (!current.checksum || current.checksum === tool.checksum)) {
      return {
        tool: tool.name,
        fromVersion: current.version,
        toVersion: tool.version,
        status: "up_to_date",
        requiresApproval: false,
        steps: [],
        warnings: [],
      };
    }

    if (current.version === tool.version && current.checksum && current.checksum !== tool.checksum) {
      return {
        tool: tool.name,
        fromVersion: current.version,
        toVersion: tool.version,
        status: "manual_review_required",
        requiresApproval: true,
        steps: [
          {
            title: "Review checksum drift",
            reason: `Installed checksum ${current.checksum} does not match trusted registry marker ${tool.checksum}.`,
            manual: true,
          },
        ],
        warnings: ["Checksum drift at the same version can indicate a local packaging change or tampering."],
      };
    }

    const installPlan = this.createInstallPlan(name);
    return {
      tool: tool.name,
      fromVersion: current.version,
      toVersion: tool.version,
      status: "update_available",
      requiresApproval: true,
      steps: [
        {
          title: "Review update metadata",
          reason: `Compare installed version ${current.version} with trusted registry version ${tool.version} before applying changes.`,
          manual: true,
        },
        ...installPlan.steps,
      ],
      warnings: installPlan.warnings,
    };
  }

  createUpdatePlans(current: Record<string, string | InstalledToolState> = {}): ToolUpdatePlan[] {
    return this.registry.map((tool) => {
      const state = current[tool.name];
      return this.createUpdatePlan(tool.name, typeof state === "string" ? { version: state } : state);
    });
  }

  validateRunPlan(plan: ToolRunPlan): ToolRunPlanValidation {
    const tool = this.get(plan.tool);
    const reasons: string[] = [];
    const warnings: string[] = [];
    let requiresApproval = false;
    let riskLevel = plan.riskLevel;

    if (!tool) {
      return {
        tool: plan.tool,
        actionType: plan.actionType,
        allowed: false,
        requiresApproval: false,
        riskLevel,
        reasons: [`Unknown trusted tool: ${plan.tool}`],
        warnings,
      };
    }

    const action = tool.actions.find((candidate) => candidate.action_type === plan.actionType);
    if (!action) {
      return {
        tool: tool.name,
        actionType: plan.actionType,
        allowed: false,
        requiresApproval: false,
        riskLevel,
        reasons: [`Action ${plan.actionType} is not declared in trusted metadata for ${tool.name}`],
        warnings,
      };
    }

    riskLevel = maxRisk(plan.riskLevel, action.risk_level);
    if (!tool.safety.allowed_modes.includes(plan.mode)) {
      reasons.push(`Tool ${tool.name} is not allowed in ${plan.mode} mode`);
    }
    if (tool.permissions.destructive || action.destructive || plan.destructive) {
      reasons.push(`Tool ${tool.name} run plan is destructive and is blocked`);
    }
    if (action.network === true && !tool.permissions.network) {
      reasons.push(`Action ${plan.actionType} requires network access but ${tool.name} is not trusted for network use`);
    }
    if (action.filesystem_write === true && !tool.permissions.filesystem_write) {
      reasons.push(`Action ${plan.actionType} writes files but ${tool.name} is not trusted for filesystem writes`);
    }

    const trustedCapabilities = new Set(action.capabilities);
    for (const capability of plan.capabilities ?? []) {
      if (!trustedCapabilities.has(capability)) {
        reasons.push(`Capability ${capability} is not declared for ${tool.name} ${plan.actionType}`);
      }
    }

    const blockedCapabilities = blockedCapabilitiesFor(tool);
    for (const capability of new Set([...action.capabilities, ...(plan.capabilities ?? [])])) {
      if (blockedCapabilities.has(capability)) {
        reasons.push(`Capability is blocked for ${tool.name}: ${capability}`);
      }
    }

    const policy = new PolicyGate(plan.programRules).evaluate({
      mode: plan.mode,
      actionType: plan.actionType,
      target: plan.target,
      riskLevel,
      stateChanging: action.state_changing || plan.stateChanging,
      destructive: tool.permissions.destructive || action.destructive || plan.destructive,
      requiresApprovalByDefault: action.requires_approval,
      labModeEnabled: plan.labModeEnabled === true,
    });
    if (policy.decision === "block") {
      reasons.push(policy.reason);
    }
    if (policy.decision === "require_approval" || action.requires_approval) {
      requiresApproval = true;
      if (policy.reason !== "Allowed by policy") warnings.push(policy.reason);
    }

    return {
      tool: tool.name,
      actionType: plan.actionType,
      allowed: reasons.length === 0,
      requiresApproval,
      riskLevel,
      reasons: reasons.length === 0 ? ["Allowed by trusted registry metadata"] : reasons,
      warnings,
    };
  }

  assertRunPlanAllowed(plan: ToolRunPlan): ToolRunPlanValidation {
    const validation = this.validateRunPlan(plan);
    if (!validation.allowed) {
      throw new BountyPilotError(validation.reasons.join("; "), "TOOL_RUN_PLAN_BLOCKED");
    }
    return validation;
  }

  doctor(options?: { mode?: ExecutionMode }): ToolDoctorResult[] {
    return this.registry.map((tool) => doctorTool(tool, options?.mode));
  }

  private requireTool(name: string): ToolRegistryEntry {
    const tool = this.get(name);
    if (!tool) {
      throw new BountyPilotError(`Unknown trusted tool: ${name}`, "TOOL_UNKNOWN");
    }
    return tool;
  }
}

function parseRegistry(input: unknown, source: string): ToolRegistryEntry[] {
  const result = ToolRegistrySchema.safeParse(input);
  if (!result.success) {
    throw new BountyPilotError(
      `Invalid tool registry ${source}: ${result.error.issues[0]?.message ?? "schema validation failed"}`,
      "TOOL_REGISTRY_INVALID",
    );
  }
  return result.data.tools;
}

function mergeRegistry(base: ToolRegistryEntry[], overlay: ToolRegistryEntry[]): ToolRegistryEntry[] {
  const byName = new Map(base.map((tool) => [tool.name, tool]));
  for (const tool of overlay) {
    byName.set(tool.name, tool);
  }
  return [...byName.values()];
}

function normalizeSearch(query?: string): string[] {
  return query
    ? query
        .trim()
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean)
    : [];
}

function installStepFor(tool: ToolRegistryEntry): ToolPlanStep | undefined {
  if (tool.install.type === "npm" && tool.install.package) {
    return {
      title: "Prepare exact npm install",
      reason: "The command is generated from trusted package metadata and pinned to the registry version.",
      command: "npm",
      args: ["install", "--save-dev", `${tool.install.package}@${tool.version}`],
      manual: false,
    };
  }

  if (tool.install.type === "docker" && tool.install.image) {
    if (tool.install.image.endsWith(":latest")) {
      return {
        title: "Reject floating docker tag",
        reason: "Docker images must be pinned by digest or non-latest tag before they can be planned.",
        manual: true,
      };
    }
    return {
      title: "Prepare pinned docker pull",
      reason: "The pull is planned from trusted image metadata and still requires human approval before execution.",
      command: "docker",
      args: ["pull", tool.install.image],
      manual: false,
    };
  }

  if (tool.install.type === "local" && tool.install.command) {
    return {
      title: "Verify local executable",
      reason: "Local tools are expected to be installed outside BountyPilot; ToolManager only checks for the command.",
      command: tool.install.command,
      args: ["--version"],
      manual: true,
    };
  }

  return undefined;
}

function doctorTool(tool: ToolRegistryEntry, mode?: ExecutionMode): ToolDoctorResult {
  const checks: ToolDoctorCheck[] = [
    {
      name: "registry",
      status: "pass",
      message: `Trusted source ${tool.source} pinned to ${tool.version} with ${tool.checksum}.`,
    },
  ];

  if (tool.permissions.destructive) {
    checks.push({ name: "safety", status: "fail", message: "Tool is marked destructive and is blocked by default." });
    return doctorResult(tool, "blocked", checks);
  }

  const blockedActionCapabilities = tool.actions
    .flatMap((action) => action.capabilities)
    .filter((capability) => BLOCKED_CAPABILITIES.has(capability));
  if (blockedActionCapabilities.length > 0) {
    checks.push({
      name: "safety",
      status: "fail",
      message: `Tool declares globally blocked capabilities: ${[...new Set(blockedActionCapabilities)].join(", ")}.`,
    });
    return doctorResult(tool, "blocked", checks);
  }

  if (mode && !tool.safety.allowed_modes.includes(mode)) {
    checks.push({ name: "mode", status: "fail", message: `Tool is not allowed in ${mode} mode.` });
    return doctorResult(tool, "blocked", checks);
  }

  checks.push({
    name: "safety",
    status: "pass",
    message: `Allowed modes: ${tool.safety.allowed_modes.join(", ")}; blocked capabilities: ${tool.safety.blocked_capabilities.join(", ") || "none"}.`,
  });

  const installCheck = checkInstall(tool);
  checks.push(installCheck);

  if (tool.install.type === "manual") return doctorResult(tool, "manual", checks);
  if (installCheck.status === "fail") return doctorResult(tool, "not_installed", checks);
  if (installCheck.status === "warn") return doctorResult(tool, "manual", checks);
  return doctorResult(tool, "available", checks);
}

function doctorResult(
  tool: ToolRegistryEntry,
  status: ToolDoctorResult["status"],
  checks: ToolDoctorCheck[],
): ToolDoctorResult {
  const failing = checks.find((check) => check.status === "fail");
  const warning = checks.find((check) => check.status === "warn");
  const install = checks.find((check) => check.name === "install");
  return {
    name: tool.name,
    category: tool.category,
    version: tool.version,
    installType: tool.install.type,
    allowedModes: [...tool.safety.allowed_modes],
    status,
    message:
      failing?.message ??
      warning?.message ??
      install?.message ??
      `${tool.category} registry entry is trusted and pinned to ${tool.version}.`,
    checks,
  };
}

function checkInstall(tool: ToolRegistryEntry): ToolDoctorCheck {
  if (tool.install.type === "manual") {
    return {
      name: "install",
      status: "warn",
      message:
        "Manual installation and executable availability are unverified; doctor does not run installers or commands.",
    };
  }

  if (tool.install.type === "npm" && tool.install.package) {
    try {
      requireFromHere.resolve(`${tool.install.package}/package.json`);
      return {
        name: "install",
        status: "pass",
        message: `npm package metadata for ${tool.install.package} is resolvable locally; executable availability is not verified.`,
      };
    } catch {
      return {
        name: "install",
        status: "fail",
        message: `npm package ${tool.install.package} is not installed locally or its package metadata is not resolvable.`,
      };
    }
  }

  if (tool.install.type === "docker") {
    return {
      name: "install",
      status: "warn",
      message: `Docker image ${tool.install.image ?? "metadata"} is registry metadata only; Docker CLI and image availability are unverified because doctor does not invoke Docker.`,
    };
  }

  if (tool.install.type === "local" && tool.install.command) {
    return {
      name: "install",
      status: "warn",
      message: `Local command ${tool.install.command} is registry metadata only; executable availability is unverified because doctor does not probe PATH.`,
    };
  }

  return {
    name: "install",
    status: "warn",
    message: "Install availability is unverified; no safe package-resolution check is configured for this tool.",
  };
}

function blockedCapabilitiesFor(tool: ToolRegistryEntry): Set<string> {
  return new Set([...BLOCKED_CAPABILITIES, ...tool.safety.blocked_capabilities]);
}

function maxRisk(left?: RiskLevel, right?: RiskLevel): RiskLevel | undefined {
  if (!left) return right;
  if (!right) return left;
  const rank: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };
  return rank[left] >= rank[right] ? left : right;
}
