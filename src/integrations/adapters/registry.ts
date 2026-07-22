import type { AdapterCapabilityMetadata, AdapterRegistration } from "./adapter.js";

const SAFE_MODES = ["safe", "deep-safe"] as const;
const RESEARCH_MODES = ["passive", "safe", "deep-safe"] as const;

export const BUILT_IN_ADAPTER_REGISTRY: AdapterRegistration[] = [
  {
    name: "playwright",
    type: "browser",
    displayName: "Playwright",
    description: "Local browser crawling and evidence capture through the bundled Playwright dependency.",
    defaultEnabled: true,
    capabilities: [
      {
        id: "browser.navigate",
        title: "Navigate in scoped browser",
        description: "Open an in-scope URL in a local browser context and collect safe page evidence.",
        actionType: "browser.navigate",
        riskLevel: "low",
        allowedModes: [...SAFE_MODES],
        produces: ["screenshot", "har", "console_log", "dom_snapshot", "crawl_graph"],
        requiresTarget: true,
        requiresScope: true,
      },
      {
        id: "browser.request",
        title: "Record scoped browser request",
        description: "Observe a browser request that remains inside the imported program scope.",
        actionType: "browser.request",
        riskLevel: "low",
        allowedModes: [...SAFE_MODES],
        produces: ["request_sample", "response_sample"],
        requiresTarget: true,
        requiresScope: true,
      },
    ],
  },
  {
    name: "playwright_mcp",
    aliases: ["playwright-mcp"],
    type: "mcp",
    displayName: "Playwright MCP",
    description: "Optional MCP bridge for browser automation. BountyPilot records scope-checked plans and human handoffs only; it never starts the MCP server.",
    defaultEnabled: false,
    configuration: {
      optional: [
        "transport",
        "command",
        "args",
        "url",
        "endpoint",
        "timeout_ms",
        "capabilities",
        "package",
        "package_version",
        "entrypoint",
        "entrypoint_sha256",
        "package_json_sha256",
        "execution",
      ],
    },
    mcp: {
      serverName: "playwright",
      defaultTransport: "stdio",
      localOnly: true,
    },
    capabilities: [
      {
        id: "browser.navigate",
        title: "MCP browser navigate",
        description: "Plan a Playwright MCP navigation for an in-scope URL.",
        actionType: "browser.navigate",
        riskLevel: "low",
        allowedModes: [...SAFE_MODES],
        produces: ["screenshot", "dom_snapshot", "crawl_graph"],
        requiresTarget: true,
        requiresScope: true,
        mcpTools: ["browser_navigate"],
      },
      {
        id: "browser.snapshot",
        title: "MCP browser snapshot",
        description: "Plan a read-only snapshot of the current scoped browser page.",
        actionType: "browser.snapshot",
        riskLevel: "low",
        allowedModes: [...SAFE_MODES],
        produces: ["dom_snapshot", "screenshot"],
        requiresTarget: false,
        requiresScope: true,
        scopedPostcondition: "current_or_final_url_in_scope",
        mcpTools: ["browser_snapshot"],
      },
    ],
  },
  {
    name: "crawl4ai",
    type: "crawler",
    displayName: "Crawl4AI",
    description: "Optional external crawler adapter. BountyPilot records scoped plans and human handoffs only; it never dispatches the crawler.",
    defaultEnabled: false,
    configuration: {
      requiredWhenEnabled: ["command"],
      optional: [
        "args",
        "timeout_ms",
        "capabilities",
        "package",
        "package_version",
        "entrypoint",
        "entrypoint_sha256",
        "package_json_sha256",
        "execution",
      ],
    },
    capabilities: [
      {
        id: "crawler.fetch",
        title: "Fetch scoped pages",
        description: "Plan low-rate crawling for explicitly in-scope pages.",
        actionType: "crawler.fetch",
        riskLevel: "low",
        allowedModes: [...SAFE_MODES],
        produces: ["crawl_graph", "tool_output"],
        requiresTarget: true,
        requiresScope: true,
      },
    ],
  },
  {
    name: "windows_mcp",
    aliases: ["windows-mcp"],
    type: "desktop",
    displayName: "Windows MCP",
    description: "Optional local desktop automation MCP. BountyPilot records local plans and human handoffs only; it never starts the desktop bridge.",
    defaultEnabled: false,
    configuration: {
      optional: [
        "transport",
        "command",
        "args",
        "timeout_ms",
        "capabilities",
        "package",
        "package_version",
        "entrypoint",
        "entrypoint_sha256",
        "package_json_sha256",
        "execution",
      ],
    },
    mcp: {
      serverName: "windows",
      defaultTransport: "stdio",
      localOnly: true,
    },
    capabilities: [
      {
        id: "desktop.session.plan",
        title: "Plan desktop session",
        description: "Create a local-only desktop automation plan without controlling unrelated applications.",
        actionType: "desktop.session.plan",
        riskLevel: "medium",
        allowedModes: [...SAFE_MODES],
        produces: ["research_note", "tool_output"],
        requiresTarget: false,
        stateChanging: false,
        requiresApprovalByDefault: true,
        mcpTools: ["desktop_session_plan"],
      },
      {
        id: "desktop.screenshot",
        title: "Capture desktop screenshot",
        description: "Plan an optional local desktop screenshot for approved evidence capture.",
        actionType: "desktop.screenshot",
        riskLevel: "medium",
        allowedModes: ["deep-safe"],
        produces: ["desktop_screenshot"],
        requiresTarget: false,
        stateChanging: false,
        requiresApprovalByDefault: true,
        mcpTools: ["desktop_screenshot"],
      },
    ],
  },
  {
    name: "d_research_skill",
    aliases: ["d-research-skill", "d-research"],
    type: "research-skill",
    displayName: "d-research-skill",
    description: "Optional public research skill adapter for citation-led program research.",
    defaultEnabled: false,
    configuration: {
      requiredWhenEnabled: ["source"],
      optional: ["capabilities"],
    },
    capabilities: [
      {
        id: "research.public",
        title: "Public research",
        description: "Collect public, non-invasive context without expanding program authorization.",
        actionType: "research.public",
        riskLevel: "low",
        allowedModes: [...RESEARCH_MODES],
        produces: ["research_note"],
        requiresTarget: false,
      },
    ],
  },
];

export class AdapterRegistry {
  constructor(private readonly registrations: AdapterRegistration[] = BUILT_IN_ADAPTER_REGISTRY) {}

  list(): AdapterRegistration[] {
    return [...this.registrations];
  }

  get(name: string): AdapterRegistration | undefined {
    const key = normalizeAdapterKey(name);
    return this.registrations.find(
      (registration) =>
        normalizeAdapterKey(registration.name) === key ||
        registration.aliases?.some((alias) => normalizeAdapterKey(alias) === key),
    );
  }
}

export function normalizeAdapterKey(value: string): string {
  return value.trim().toLowerCase().replaceAll("-", "_");
}

export function findCapability(
  capabilities: AdapterCapabilityMetadata[],
  requested: string,
): AdapterCapabilityMetadata | undefined {
  const key = normalizeAdapterKey(requested);
  return capabilities.find(
    (capability) =>
      normalizeAdapterKey(capability.id) === key ||
      normalizeAdapterKey(capability.actionType) === key ||
      capability.mcpTools?.some((tool) => normalizeAdapterKey(tool) === key),
  );
}

export function summarizeCapabilities(capabilities: AdapterCapabilityMetadata[]): {
  actions: string[];
  produces: string[];
  riskyCapabilities: string[];
} {
  return {
    actions: capabilities.map((capability) => capability.actionType),
    produces: [...new Set(capabilities.flatMap((capability) => capability.produces))],
    riskyCapabilities: capabilities
      .filter(
        (capability) =>
          capability.riskLevel !== "low" ||
          capability.destructive ||
          capability.stateChanging ||
          capability.requiresApprovalByDefault ||
          capability.blockedByDefault,
      )
      .map((capability) => capability.id),
  };
}
