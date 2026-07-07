import { describe, expect, it } from "vitest";
import { DuplicateRiskEngine } from "../src/engines/duplicate-risk/duplicate-risk-engine.js";
import { TriageEngine } from "../src/engines/triage/triage-engine.js";
import type { EvidenceArtifact, NormalizedFinding } from "../src/types.js";

const finding: NormalizedFinding = {
  id: "finding-1",
  title: "GraphQL introspection enabled",
  asset: "api.example.com",
  url: "https://api.example.com/graphql",
  category: "graphql",
  severityEstimate: "medium",
  confidence: "high",
  status: "validated",
  evidencePaths: ["evidence.json"],
  duplicateRisk: "unknown",
  reportabilityScore: 60,
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
};

describe("DuplicateRiskEngine", () => {
  it("marks same URL and category as high local duplicate risk", () => {
    const result = new DuplicateRiskEngine().estimate(finding, [{ ...finding, id: "finding-2" }]);
    expect(result.risk).toBe("high");
  });

  it("normalizes URLs before estimating duplicate risk", () => {
    const result = new DuplicateRiskEngine().estimate(
      { ...finding, url: "https://api.example.com/graphql/?debug=true" },
      [{ ...finding, id: "finding-2", url: "https://api.example.com/graphql" }],
    );
    expect(result.risk).toBe("high");
    expect(result.matchingFindingIds).toEqual(["finding-2"]);
  });

  it("flags very similar local titles as medium duplicate risk", () => {
    const result = new DuplicateRiskEngine().estimate(
      { ...finding, asset: "admin.example.com", url: "https://admin.example.com/graphql" },
      [{ ...finding, id: "finding-2", asset: "api.example.com" }],
    );
    expect(result.risk).toBe("medium");
    expect(result.reasons.join(" ")).toContain("private platform reports cannot be checked locally");
  });

  it("uses route templates and category aliases for local duplicate tuning", () => {
    const result = new DuplicateRiskEngine().estimate(
      {
        ...finding,
        title: "BOLA user profile authorization bypass",
        category: "access_control",
        url: "https://api.example.com/v1/users/123/profile",
      },
      [
        {
          ...finding,
          id: "finding-2",
          title: "IDOR user profile authorization bypass",
          category: "idor",
          url: "https://api.example.com/v1/users/456/profile",
        },
        {
          ...finding,
          id: "finding-3",
          title: "Access control issue",
          category: "authorization",
          url: "https://other.example.com/account",
        },
      ],
    );
    expect(result.risk).toBe("high");
    expect(result.matchingFindingIds).toEqual(["finding-2"]);
    expect(result.reasons.join(" ")).toContain("route template");
  });

  it("keeps divergent query parameters below high duplicate risk", () => {
    const result = new DuplicateRiskEngine().estimate(
      {
        ...finding,
        title: "Open redirect on OAuth callback",
        category: "open_redirect",
        url: "https://app.example.com/oauth/callback?redirect_uri=https://example.net",
      },
      [
        {
          ...finding,
          id: "finding-2",
          title: "Open redirect on OAuth callback",
          category: "redirect",
          url: "https://app.example.com/oauth/callback?next=https://example.net",
        },
      ],
    );
    expect(result.risk).toBe("medium");
    expect(result.reasons.join(" ")).toContain("query parameter names differ");
  });

  it("handles malformed local URLs without crashing", () => {
    const result = new DuplicateRiskEngine().estimate(
      { ...finding, url: "not a url", asset: "api.example.com" },
      [{ ...finding, id: "finding-2", url: "also not a url", asset: "other.example.com" }],
    );
    expect(result.risk).toBe("medium");
  });
});

describe("TriageEngine", () => {
  it("raises reportability with evidence and confidence", () => {
    const result = new TriageEngine().triage(finding, [
      {
        id: "evidence-1",
        adapterName: "safe-checks",
        kind: "tool_output",
        path: "evidence.json",
        createdAt: "2026-01-01T00:00:00.000Z",
      },
    ]);
    expect(result.reportabilityScore).toBeGreaterThan(60);
  });

  it("counts linked evidence paths even when artifact metadata is unavailable", () => {
    const result = new TriageEngine().triage({ ...finding, status: "needs_validation", reportabilityScore: 45 }, []);
    expect(result.evidenceQuality).toBe("moderate");
    expect(result.reportabilityScore).toBeGreaterThan(45);
    expect(result.recommendation).toBe("needs_manual_impact_validation");
  });

  it("holds low-value categories with weak evidence out of standalone reporting", () => {
    const result = new TriageEngine().triage(
      {
        ...finding,
        title: "Missing HSTS",
        category: "security_headers",
        severityEstimate: "info",
        evidencePaths: [],
        reportabilityScore: 25,
      },
      [],
    );
    expect(result.evidenceQuality).toBe("weak");
    expect(result.recommendation).toBe("do_not_report_alone");
  });

  it("does not treat three weak artifact kinds as strong evidence", () => {
    const result = new TriageEngine().triage(finding, [
      evidence("evidence-1", "research_note"),
      evidence("evidence-2", "evidence_note"),
      evidence("evidence-3", "console_log"),
    ]);
    expect(result.evidenceQuality).toBe("moderate");
    expect(result.reasons.join(" ")).toContain("request or reproduction context is still limited");
  });

  it("boosts impact signals only when evidence can support them", () => {
    const strong = new TriageEngine().triage(
      {
        ...finding,
        title: "IDOR exposes another user's billing profile",
        category: "access_control",
        reportabilityScore: 45,
      },
      [
        evidence("evidence-1", "reproduction_note", "https://api.example.com/v1/users/123/billing"),
        evidence("evidence-2", "request_sample", "https://api.example.com/v1/users/123/billing"),
      ],
    );
    expect(strong.evidenceQuality).toBe("strong");
    expect(strong.reportabilityScore).toBeGreaterThanOrEqual(90);
    expect(strong.recommendation).toBe("ready_for_draft");
  });

  it("keeps weak evidence out of standalone reporting even for serious-looking findings", () => {
    const result = new TriageEngine().triage(
      {
        ...finding,
        title: "IDOR exposes account records",
        category: "idor",
        severityEstimate: "critical",
        evidencePaths: [],
        reportabilityScore: 90,
      },
      [],
    );
    expect(result.evidenceQuality).toBe("weak");
    expect(result.reportabilityScore).toBe(100);
    expect(result.recommendation).toBe("do_not_report_alone");
  });

  it("records source alignment and stale evidence as deterministic triage reasons", () => {
    const result = new TriageEngine().triage(
      {
        ...finding,
        updatedAt: "2026-03-15T00:00:00.000Z",
        status: "needs_validation",
        confidence: "medium",
        reportabilityScore: 45,
      },
      [
        {
          ...evidence("evidence-1", "tool_output", "https://other.example.com/graphql"),
          createdAt: "2026-01-01T00:00:00.000Z",
        },
      ],
    );
    expect(result.evidenceQuality).toBe("moderate");
    expect(result.reportabilityScore).toBeLessThan(60);
    expect(result.reasons.join(" ")).toContain("do not align");
    expect(result.reasons.join(" ")).toContain("stale");
  });
});

function evidence(id: string, kind: EvidenceArtifact["kind"], sourceUrl = finding.url): EvidenceArtifact {
  return {
    id,
    findingId: finding.id,
    adapterName: "test-adapter",
    kind,
    sourceUrl,
    path: `${id}.json`,
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}
