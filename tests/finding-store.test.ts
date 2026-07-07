import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { FindingStore } from "../src/stores/finding-store.js";

describe("FindingStore", () => {
  it("links evidence paths idempotently", () => {
    const { findings } = createStore();
    findings.create({
      id: "finding-link",
      title: "Manual finding",
      asset: "api.example.com",
      url: "https://api.example.com/",
      category: "manual",
      severityEstimate: "low",
      confidence: "medium",
      status: "needs_manual_review",
      evidencePaths: [],
      duplicateRisk: "unknown",
      reportabilityScore: 40,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    });

    findings.linkEvidencePath("finding-link", "C:\\evidence\\proof.txt");
    const linked = findings.linkEvidencePath("finding-link", "C:\\evidence\\proof.txt");

    expect(linked.evidencePaths).toEqual(["C:\\evidence\\proof.txt"]);
    expect(findings.get("finding-link")?.evidencePaths).toEqual(["C:\\evidence\\proof.txt"]);
  });

  it("recovers from malformed evidence path JSON", () => {
    const { db, findings } = createStore();
    insertFindingRow(db, "finding-bad-json", "{bad json");

    expect(findings.get("finding-bad-json")?.evidencePaths).toEqual([]);
    expect(findings.list()[0]?.evidencePaths).toEqual([]);
  });

  it("recovers from non-array evidence path JSON", () => {
    const { db, findings } = createStore();
    insertFindingRow(db, "finding-object-json", '{"not":"array"}');

    expect(findings.get("finding-object-json")?.evidencePaths).toEqual([]);
  });
});

function createStore(): { db: ReturnType<typeof openBountyDatabase>; findings: FindingStore } {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-findings-"));
  const db = openBountyDatabase(path.join(root, "bounty.sqlite"));
  return { db, findings: new FindingStore(db) };
}

function insertFindingRow(db: ReturnType<typeof openBountyDatabase>, id: string, evidencePaths: string): void {
  db.prepare(
    `INSERT INTO findings (
      id, title, asset, url, category, severity_estimate, confidence, status,
      evidence_paths, raw_output_path, remediation, duplicate_risk, reportability_score, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    "Corrupt evidence paths",
    "api.example.com",
    "https://api.example.com/",
    "test",
    "info",
    "low",
    "needs_manual_review",
    evidencePaths,
    null,
    null,
    "unknown",
    10,
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:00:00.000Z",
  );
}
