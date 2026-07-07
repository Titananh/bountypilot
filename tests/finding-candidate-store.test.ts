import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { FindingCandidateStore } from "../src/stores/finding-candidate-store.js";

describe("FindingCandidateStore", () => {
  it("creates cand_ ids and filters candidates by lifecycle state", () => {
    const { candidates } = createStore();
    const created = candidates.create(candidateInput({
      jobId: "job-one",
      reportability: "ready_for_draft",
      status: "ready_for_draft",
    }));

    expect(created.id).toMatch(/^cand_/);
    expect(candidates.get(created.id)).toMatchObject({
      id: created.id,
      jobId: "job-one",
      reportability: "ready_for_draft",
    });
    expect(candidates.list({ jobId: "job-one" })).toHaveLength(1);
    expect(candidates.list({ reportability: "ready_for_draft" })).toHaveLength(1);
    expect(candidates.list({ status: "needs_manual_verification" })).toHaveLength(0);
  });

  it("deduplicates by fingerprint and updates evidence and finding links", () => {
    const { candidates } = createStore();
    const first = candidates.create(candidateInput({
      jobId: "job-one",
      title: "Reflected input candidate",
      evidenceIds: ["evidence-one"],
    }));
    const second = candidates.create(candidateInput({
      jobId: "job-one",
      title: "Reflected input candidate",
      evidenceIds: ["evidence-two"],
      confidence: "high",
    }));

    expect(second.id).toBe(first.id);
    expect(candidates.list()).toHaveLength(1);
    expect(candidates.get(first.id)?.evidenceIds).toEqual(["evidence-two"]);

    const linkedEvidence = candidates.linkEvidence(first.id, "evidence-three");
    expect(linkedEvidence?.evidenceIds).toEqual(["evidence-two", "evidence-three"]);

    const linkedFinding = candidates.linkFinding(first.id, "finding-one");
    expect(linkedFinding).toMatchObject({
      findingId: "finding-one",
      status: "promoted",
    });
    expect(candidates.list({ findingId: "finding-one" })).toHaveLength(1);
  });
});

function createStore(): { db: ReturnType<typeof openBountyDatabase>; candidates: FindingCandidateStore } {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-candidates-"));
  const db = openBountyDatabase(path.join(root, "bounty.sqlite"));
  return { db, candidates: new FindingCandidateStore(db) };
}

function candidateInput(overrides: Partial<Parameters<FindingCandidateStore["create"]>[0]> = {}): Parameters<FindingCandidateStore["create"]>[0] {
  return {
    title: "Open redirect candidate",
    asset: "api.example.com",
    url: "https://api.example.com/redirect?next=https://example.org",
    category: "open_redirect",
    severityEstimate: "medium",
    confidence: "medium",
    status: "needs_manual_verification",
    evidenceIds: [],
    observationIds: [],
    falsePositiveRisk: "medium",
    duplicateRisk: "unknown",
    reportability: "needs_review",
    reasoningSummary: "Evidence-backed signal needs manual validation.",
    nextManualSteps: ["Review request and response evidence."],
    ...overrides,
  };
}
