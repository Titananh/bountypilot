import { describe, expect, it } from "vitest";
import { AgentPlanner } from "../src/engines/agent-planner/agent-planner.js";
import type { EvidenceArtifact, NormalizedFinding } from "../src/types.js";

describe("AgentPlanner", () => {
  it("plans actions without executing them", () => {
    const actions = new AgentPlanner().plan({
      urls: ["https://api.example.com"],
      endpointCandidates: ["https://api.example.com/graphql"],
      jsAssets: ["https://api.example.com/app.js"],
      mode: "safe",
    });
    expect(actions.length).toBeGreaterThan(0);
    expect(actions.every((action) => action.target.includes("example.com"))).toBe(true);
  });

  it("ranks endpoint feedback deterministically and suppresses canonical duplicates", () => {
    const result = new AgentPlanner().planLoop({
      urls: ["https://api.example.com/", "https://api.example.com/#fragment"],
      endpointCandidates: [
        "https://api.example.com/v1/users",
        "https://api.example.com/graphql?b=2&a=1",
        "https://api.example.com/graphql?a=1&b=2",
      ],
      jsAssets: ["https://api.example.com/app.js"],
      mode: "safe",
      maxIterations: 2,
    });

    expect(result.actions[0]).toMatchObject({
      adapter: "safe-checks",
      actionType: "http.get",
      target: "https://api.example.com/graphql?a=1&b=2",
      riskLevel: "medium",
      requiresApproval: true,
      source: "endpoint",
    });
    expect(result.actions.filter((action) => action.target.includes("graphql"))).toHaveLength(1);
    expect(result.iterations.some((iteration) => iteration.skippedDuplicates > 0)).toBe(true);
  });

  it("honors action history and action budget before returning queued candidates", () => {
    const result = new AgentPlanner().planLoop({
      urls: ["https://api.example.com/", "https://app.example.com/", "https://cdn.example.com/"],
      endpointCandidates: ["https://api.example.com/graphql"],
      jsAssets: ["https://api.example.com/app.js"],
      mode: "deep-safe",
      maxIterations: 3,
      maxActions: 2,
      actions: [
        {
          adapter: "safe-checks",
          actionType: "http.get",
          target: "https://api.example.com/",
          status: "executed",
        },
        {
          adapter: "js-analyzer",
          actionType: "http.get",
          target: "https://api.example.com/app.js",
          status: "blocked",
        },
      ],
    });

    expect(result.actions).toHaveLength(2);
    expect(result.actions.some((action) => action.target === "https://api.example.com/")).toBe(false);
    expect(result.actions.some((action) => action.target === "https://api.example.com/app.js")).toBe(false);
    expect(result.iterations.some((iteration) => iteration.skippedExistingActions > 0)).toBe(true);
    expect(result.iterations.some((iteration) => iteration.skippedFailedOrBlockedHistory > 0)).toBe(true);
  });

  it("uses finding and evidence feedback without bypassing mode approval hints", () => {
    const finding: NormalizedFinding = {
      id: "finding-1",
      title: "Possible account access control issue",
      asset: "api.example.com",
      url: "https://api.example.com/account/123",
      category: "access_control",
      severityEstimate: "high",
      confidence: "high",
      status: "needs_validation",
      evidencePaths: ["proof.json"],
      duplicateRisk: "low",
      reportabilityScore: 72,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };
    const evidence: EvidenceArtifact = {
      id: "evidence-1",
      jobId: "job-1",
      adapterName: "js-analyzer",
      kind: "tool_output",
      sourceUrl: "https://api.example.com/evidence-source",
      path: "proof.json",
      createdAt: "2026-01-01T00:00:00.000Z",
    };

    const result = new AgentPlanner().planLoop({
      urls: [],
      endpointCandidates: [],
      jsAssets: [],
      mode: "safe",
      findings: [finding],
      evidence: [evidence],
      maxIterations: 2,
    });

    expect(result.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          target: "https://api.example.com/account/123",
          source: "finding",
          riskLevel: "medium",
          requiresApproval: true,
        }),
        expect.objectContaining({
          target: "https://api.example.com/evidence-source",
          source: "evidence",
          riskLevel: "low",
          requiresApproval: false,
        }),
      ]),
    );
  });
});
