import { describe, expect, it } from "vitest";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import { McpClientManager } from "../src/integrations/mcp/mcp-client-manager.js";

describe("McpClientManager", () => {
  it("lists MCP-capable adapters with declared tools", () => {
    const servers = new McpClientManager(testConfig({})).listServers();

    expect(servers.find((server) => server.name === "playwright_mcp")).toMatchObject({
      enabled: false,
      status: "planned",
      tools: ["browser_navigate", "browser_snapshot"],
    });
    expect(servers.find((server) => server.name === "windows_mcp")?.tools).toContain("desktop_session_plan");
  });

  it("validates MCP tool plans without executing external calls", () => {
    const manager = new McpClientManager(
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

    const plan = manager.prepareCallPlan({
      server: "playwright-mcp",
      tool: "browser_navigate",
      target: "https://api.example.com/",
      mode: "safe",
      arguments: {
        navigation: {
          url: "https://api.example.com/path",
          mirrors: ["https://api.example.com/asset"],
          hostname: "api.example.com",
        },
      },
    });

    expect(plan.execute).toBe(false);
    expect(plan.message).toContain("zero-execution, scope-checked MCP handoff");
    expect(plan.message).not.toContain("Use `mcp call`");
    expect(plan.validation).toMatchObject({
      ok: true,
      decision: "allow",
      server: "playwright_mcp",
      tool: "browser_navigate",
    });
  });

  it("blocks an out-of-scope plan target", () => {
    const validation = configuredPlaywrightManager().validateCallPlan({
      server: "playwright-mcp",
      tool: "browser_navigate",
      target: "https://outside.example.net/",
      mode: "safe",
    });

    expect(validation).toMatchObject({ ok: false, decision: "block" });
    expect(validation.reasons[0]).toContain("MCP plan target blocked by ScopeGuard");
  });

  it.each([
    {
      label: "an absolute URL under an arbitrary key",
      arguments: { payload: { redirect: "https://outside.example.net/path" } },
      path: "arguments.payload.redirect",
    },
    {
      label: "a host under a target-like key",
      arguments: { payload: [{ hostname: "outside.example.net" }] },
      path: "arguments.payload[0].hostname",
    },
  ])("blocks nested arguments containing $label", ({ arguments: callArguments, path }) => {
    const validation = configuredPlaywrightManager().validateCallPlan({
      server: "playwright-mcp",
      tool: "browser_navigate",
      target: "https://api.example.com/",
      mode: "safe",
      arguments: callArguments,
    });

    expect(validation).toMatchObject({ ok: false, decision: "block" });
    expect(validation.reasons[0]).toContain(`MCP argument ${path} blocked by ScopeGuard`);
  });

  it.each([
    { label: "a malformed target", arguments: { request: { endpoint: "https://[" } } },
    { label: "a non-string target", arguments: { request: { target: 42 } } },
  ])("fails closed for $label in nested arguments", ({ arguments: callArguments }) => {
    const validation = configuredPlaywrightManager().validateCallPlan({
      server: "playwright-mcp",
      tool: "browser_navigate",
      target: "https://api.example.com/",
      mode: "safe",
      arguments: callArguments,
    });

    expect(validation).toMatchObject({ ok: false, decision: "block" });
  });

  it("fails closed for cycles, excessive nesting, and unsafe values", () => {
    const manager = configuredPlaywrightManager();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    let deeplyNested: Record<string, unknown> = {};
    const deepRoot = deeplyNested;
    for (let depth = 0; depth < 40; depth += 1) {
      const child: Record<string, unknown> = {};
      deeplyNested.child = child;
      deeplyNested = child;
    }

    for (const callArguments of [cyclic, deepRoot, { callback: () => undefined }]) {
      const validation = manager.validateCallPlan({
        server: "playwright-mcp",
        tool: "browser_navigate",
        target: "https://api.example.com/",
        mode: "safe",
        arguments: callArguments,
      });
      expect(validation).toMatchObject({ ok: false, decision: "block" });
    }
  });

  it("blocks unregistered MCP tools", () => {
    const manager = new McpClientManager(
      testConfig({
        playwright_mcp: {
          enabled: true,
          type: "mcp",
          transport: "stdio",
          command: "npx",
        },
      }),
    );

    expect(
      manager.validateCallPlan({
        server: "playwright_mcp",
        tool: "browser_click",
        target: "https://api.example.com/",
        mode: "safe",
      }),
    ).toMatchObject({
      ok: false,
      decision: "block",
    });
  });

  it("requires approval for local desktop MCP plans in safe mode", () => {
    const manager = new McpClientManager(
      testConfig({
        windows_mcp: {
          enabled: true,
          type: "desktop",
          transport: "stdio",
          command: "windows-mcp",
          capabilities: ["desktop.session.plan"],
        },
      }),
    );

    const validation = manager.validateCallPlan({
      server: "windows-mcp",
      tool: "desktop_session_plan",
      mode: "safe",
    });

    expect(validation).toMatchObject({
      ok: true,
      decision: "require_approval",
      requiresApproval: true,
    });
  });
});

function configuredPlaywrightManager(): McpClientManager {
  return new McpClientManager(
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
}

function testConfig(integrations: Record<string, unknown>): ProgramConfig {
  return {
    program: "mcp-test",
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
