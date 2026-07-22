import { describe, expect, it } from "vitest";
import { ExternalIntegrationExecutor } from "../src/integrations/external/external-integration-executor.js";

describe("ExternalIntegrationExecutor boundary", () => {
  it("fails closed before inspecting configuration or spawning a process", async () => {
    const marker = { spawned: false };
    const executor = new ExternalIntegrationExecutor(undefined as never);

    await expect(
      executor.execute(
        {
          id: "action-external-test",
          jobId: "job-external-test",
          adapter: "crawl4ai",
          actionType: "crawler.fetch",
          target: "https://example.com/",
          riskLevel: "low",
          requiresApproval: false,
          status: "approved",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          metadata: { marker },
        },
        "https://example.com/",
        "safe",
      ),
    ).rejects.toMatchObject({ code: "EXTERNAL_EXECUTION_DISABLED" });
    expect(marker.spawned).toBe(false);
  });
});
