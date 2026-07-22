import { describe, expect, it } from "vitest";
import { McpStdioExecutor } from "../src/integrations/mcp/mcp-stdio-executor.js";

describe("McpStdioExecutor boundary", () => {
  it("rejects action dispatch even when a caller supplies approvedAction", async () => {
    const executor = new McpStdioExecutor(undefined as never);
    await expect(executor.executeAction({} as never, "https://example.com/", "safe"))
      .rejects.toMatchObject({ code: "MCP_EXECUTION_DISABLED" });
  });

  it("rejects direct MCP calls before any server configuration is read", async () => {
    const executor = new McpStdioExecutor(undefined as never);
    await expect(executor.executeCall({
      server: "untrusted-server",
      tool: "browser_navigate",
      mode: "safe",
      target: "https://example.com/",
      approvedAction: true,
    })).rejects.toMatchObject({ code: "MCP_EXECUTION_DISABLED" });
  });

  it("rejects direct multi-step sessions", async () => {
    const executor = new McpStdioExecutor(undefined as never);
    await expect(executor.executeSession({
      server: "untrusted-server",
      mode: "safe",
      steps: [{ tool: "browser_snapshot" }],
    })).rejects.toMatchObject({ code: "MCP_EXECUTION_DISABLED" });
  });
});
