import { describe, expect, it } from "vitest";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import { IntegrationManager } from "../src/integrations/integration-manager/integration-manager.js";

describe("IntegrationManager", () => {
  it("lists built-in adapter registry defaults", () => {
    const integrations = new IntegrationManager(testConfig({})).list();

    expect(integrations.find((integration) => integration.name === "playwright")).toMatchObject({
      enabled: true,
      status: "configured",
      type: "browser",
    });
    expect(integrations.find((integration) => integration.name === "playwright_mcp")).toMatchObject({
      enabled: false,
      status: "planned",
      type: "mcp",
    });
  });

  it("reports enabled MCP adapters as not configured without transport details", () => {
    const manager = new IntegrationManager(
      testConfig({
        playwright_mcp: {
          enabled: true,
          type: "mcp",
        },
      }),
    );

    const integration = manager.get("playwright-mcp");
    expect(integration?.status).toBe("not_configured");
    expect(integration?.missingConfig).toEqual(["transport"]);
    expect(manager.doctor().find((entry) => entry.name === "playwright_mcp")).toMatchObject({
      ok: false,
      status: "not_configured",
    });
  });

  it("validates a configured safe browser MCP call plan", () => {
    const manager = new IntegrationManager(
      testConfig({
        playwright_mcp: {
          enabled: true,
          type: "mcp",
          transport: "stdio",
          command: "npx",
          capabilities: ["browser.navigate"],
        },
      }),
    );

    const validation = manager.validateCallPlan({
      integration: "playwright-mcp",
      capability: "browser.navigate",
      target: "https://api.example.com/",
      mode: "safe",
    });

    expect(validation).toMatchObject({
      ok: true,
      decision: "allow",
      requiresApproval: false,
    });
  });

  it("keeps scoped postcondition metadata on Playwright MCP snapshots", () => {
    const manager = new IntegrationManager(testConfig({}));
    const integration = manager.get("playwright-mcp");
    const snapshot = integration?.capabilityMetadata.find((capability) => capability.id === "browser.snapshot");

    expect(snapshot).toMatchObject({
      mcpTools: ["browser_snapshot"],
      scopedPostcondition: "current_or_final_url_in_scope",
    });
  });

  it("blocks browser MCP calls when browser crawling is disabled by program rules", () => {
    const manager = new IntegrationManager(
      testConfig(
        {
          playwright_mcp: {
            enabled: true,
            type: "mcp",
            transport: "stdio",
            command: "npx",
            capabilities: ["browser.navigate"],
          },
        },
        { browser_crawling: false },
      ),
    );

    const validation = manager.validateCallPlan({
      integration: "playwright-mcp",
      capability: "browser.navigate",
      target: "https://api.example.com/",
      mode: "safe",
    });

    expect(validation).toMatchObject({
      ok: false,
      decision: "block",
      reasons: [expect.stringContaining("Browser crawling")],
    });
  });

  it("blocks crawler calls when automated scanning is disabled by program rules", () => {
    const manager = new IntegrationManager(
      testConfig(
        {
          crawl4ai: {
            enabled: true,
            type: "crawler",
            command: "crawl4ai",
            capabilities: ["crawler.fetch"],
          },
        },
        { automated_scanning: "none" },
      ),
    );

    const validation = manager.validateCallPlan({
      integration: "crawl4ai",
      capability: "crawler.fetch",
      target: "https://api.example.com/",
      mode: "safe",
    });

    expect(validation).toMatchObject({
      ok: false,
      decision: "block",
      reasons: [expect.stringContaining("Automated scanning")],
    });
  });

  it("accepts execution.command as the stdio MCP command for readiness", () => {
    const manager = new IntegrationManager(
      testConfig({
        playwright_mcp: {
          enabled: true,
          type: "mcp",
          transport: "stdio",
          execution: {
            enabled: true,
            command: "npx",
          },
          capabilities: ["browser.navigate"],
        },
      }),
    );

    const integration = manager.get("playwright-mcp");
    expect(integration?.status).toBe("configured");
    expect(integration?.missingConfig).toEqual([]);
  });

  it("requires an in-scope target for capabilities marked requiresScope", () => {
    const manager = new IntegrationManager(
      testConfig({
        playwright_mcp: {
          enabled: true,
          type: "mcp",
          transport: "stdio",
          command: "npx",
          capabilities: ["browser.snapshot"],
        },
      }),
    );

    expect(
      manager.validateCallPlan({
        integration: "playwright-mcp",
        capability: "browser.snapshot",
        mode: "safe",
      }),
    ).toMatchObject({
      ok: false,
      decision: "block",
      reasons: ["Capability browser.snapshot requires an in-scope target"],
    });
  });

  it("fails closed for disabled integrations and unknown capabilities", () => {
    const manager = new IntegrationManager(testConfig({}));

    expect(
      manager.validateCallPlan({
        integration: "playwright_mcp",
        capability: "browser.navigate",
        target: "https://api.example.com/",
        mode: "safe",
      }),
    ).toMatchObject({ ok: false, decision: "block" });

    expect(
      new IntegrationManager(
        testConfig({
          playwright_mcp: {
            enabled: true,
            type: "mcp",
            transport: "stdio",
            command: "npx",
          },
        }),
      ).validateCallPlan({
        integration: "playwright_mcp",
        capability: "data_exfiltration",
        target: "https://api.example.com/",
        mode: "safe",
      }),
    ).toMatchObject({ ok: false, decision: "block" });
  });

  it("surfaces unknown configured adapters as registry errors", () => {
    const manager = new IntegrationManager(
      testConfig({
        custom_mcp: {
          enabled: true,
          type: "mcp",
          transport: "stdio",
          command: "custom-server",
        },
      }),
    );

    expect(manager.get("custom_mcp")).toMatchObject({
      status: "error",
      enabled: true,
      type: "mcp",
    });
  });
});

function testConfig(integrations: Record<string, unknown>, ruleOverrides: Partial<ProgramConfig["rules"]> = {}): ProgramConfig {
  return {
    program: "integration-test",
    platform: "hackerone",
    in_scope: ["api.example.com"],
    out_of_scope: [],
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "100rps",
      browser_crawling: true,
      deep_safe_mode: true,
      require_human_approval_for_risky_actions: true,
      ...ruleOverrides,
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
    integrations,
  };
}
