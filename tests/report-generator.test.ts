import { describe, expect, it } from "vitest";
import { generateBugcrowdReport, generateHackerOneReport, generateReproductionNote } from "../src/engines/report-generator/report-generator.js";
import { buildReportReview } from "../src/engines/report-generator/report-review.js";
import { TriageEngine } from "../src/engines/triage/triage-engine.js";
import type { DuplicateRiskResult } from "../src/engines/duplicate-risk/duplicate-risk-engine.js";
import type { EvidenceArtifact, NormalizedFinding } from "../src/types.js";

const finding: NormalizedFinding = {
  id: "finding-1",
  title: "Missing HSTS",
  asset: "api.example.com",
  url: "https://api.example.com",
  category: "security_headers",
  severityEstimate: "info",
  confidence: "medium",
  status: "needs_validation",
  evidencePaths: ["evidence/safe-checks.json"],
  duplicateRisk: "unknown",
  reportabilityScore: 20,
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
};

describe("ReportGenerator", () => {
  it("generates HackerOne-style report sections", () => {
    const report = generateHackerOneReport(
      finding,
      [
        {
          id: "evidence-1",
          adapterName: "safe-checks",
          kind: "tool_output",
          sourceUrl: "https://api.example.com?token=abc123",
          path: "evidence/safe-checks.json",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
      ],
    );
    expect(report).toContain("## Summary");
    expect(report).toContain("## Scope Confirmation");
    expect(report).toContain("## Safe Reproduction Steps");
    expect(report).toContain("## Evidence Manifest");
    expect(report).toContain("Private HackerOne duplicate visibility cannot be checked locally");
    expect(report).toContain("## Safe Testing Statement");
    expect(report).toContain("token=[REDACTED]");
    expect(report).not.toContain("abc123");
  });

  it("generates Bugcrowd-style report sections", () => {
    const report = generateBugcrowdReport(
      finding,
      [
        {
          id: "evidence-1",
          adapterName: "safe-checks",
          kind: "tool_output",
          sourceUrl: "https://api.example.com?token=abc123",
          path: "evidence/safe-checks.json",
          createdAt: "2026-01-01T00:00:00.000Z",
        },
      ],
    );
    expect(report).toContain("## Vulnerability Summary");
    expect(report).toContain("## Affected Target");
    expect(report).toContain("## Steps To Reproduce");
    expect(report).toContain("## Proof And Attachments");
    expect(report).toContain("Bugcrowd private duplicate visibility cannot be checked locally");
    expect(report).toContain("token=[REDACTED]");
    expect(report).not.toContain("abc123");
  });

  it("generates conservative reproduction notes", () => {
    const note = generateReproductionNote(finding, []);
    expect(note).toContain("## Safe Validation Boundary");
    expect(note).toContain("Do not change server state");
    expect(note).toContain("Stop and request human approval");
    expect(note).toContain("evidence/safe-checks.json");
  });

  it("blocks low-value report reviews without strong evidence", () => {
    const triage = new TriageEngine().triage(finding, []);
    const review = buildReportReview({
      finding,
      evidence: [],
      manifest: manifest([]),
      duplicate: duplicate("unknown"),
      triage,
      generatedAt: "2026-01-01T00:00:00.000Z",
    });

    expect(review.readiness).toBe("blocked");
    expect(review.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "evidence_present", status: "warn" }),
        expect.objectContaining({ id: "category_reportability", status: "fail" }),
      ]),
    );
    expect(review.nextSteps.join(" ")).toContain("low-value category");
  });

  it("marks validated findings with complete evidence ready for draft review", () => {
    const strongFinding: NormalizedFinding = {
      ...finding,
      title: "IDOR exposes billing profile",
      category: "access_control",
      severityEstimate: "high",
      confidence: "high",
      status: "validated",
      duplicateRisk: "low",
      reportabilityScore: 75,
      evidencePaths: ["repro.md", "request.json", "screen.png"],
    };
    const evidence = [
      evidenceArtifact("evidence-repro", "reproduction_note", "repro.md"),
      evidenceArtifact("evidence-request", "request_sample", "request.json"),
      evidenceArtifact("evidence-screen", "screenshot", "screen.png"),
    ];
    const triage = new TriageEngine().triage(strongFinding, evidence);
    const review = buildReportReview({
      finding: strongFinding,
      evidence,
      manifest: manifest(evidence),
      duplicate: duplicate("low"),
      triage,
      generatedAt: "2026-01-01T00:00:00.000Z",
    });

    expect(review.recommendation).toBe("ready_for_draft");
    expect(review.readiness).toBe("ready_for_draft");
    expect(review.blockers).toEqual([]);
    expect(review.warnings).toEqual([]);
    expect(review.nextSteps.join(" ")).toContain("Draft the report locally");
  });
});

function evidenceArtifact(id: string, kind: EvidenceArtifact["kind"], artifactPath: string): EvidenceArtifact {
  return {
    id,
    findingId: finding.id,
    adapterName: "test",
    kind,
    sourceUrl: finding.url,
    path: artifactPath,
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

function manifest(evidence: EvidenceArtifact[]) {
  return {
    generatedAt: "2026-01-01T00:00:00.000Z",
    evidenceRoot: "evidence",
    artifactCount: evidence.length,
    artifacts: evidence.map((artifact) => ({
      ...artifact,
      relativePath: artifact.path,
      bytes: 10,
      sha256: "a".repeat(64),
      readable: true,
    })),
    safety: {
      contentsEmbedded: false as const,
      note: "metadata only",
    },
  };
}

function duplicate(risk: DuplicateRiskResult["risk"]): DuplicateRiskResult {
  return {
    risk,
    reasons: ["test duplicate context"],
    matchingFindingIds: [],
  };
}
