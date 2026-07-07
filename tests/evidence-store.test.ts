import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { EvidenceStore, type EvidenceManifest } from "../src/stores/evidence-store.js";
import { FindingStore } from "../src/stores/finding-store.js";

describe("EvidenceStore", () => {
  it("links finding evidence paths back to job-level artifacts and writes a manifest", () => {
    const { evidence, findings } = createStores();
    const artifact = evidence.writeTextArtifact({
      jobId: "job-1",
      adapterName: "safe-checks",
      kind: "tool_output",
      sourceUrl: "https://api.example.com",
      relativePath: path.join("job-1", "safe-checks.json"),
      content: JSON.stringify({ ok: true }),
      createdAt: "2026-01-01T00:00:00.000Z",
    });
    const finding = findings.create({
      id: "finding-1",
      title: "Missing HSTS",
      asset: "api.example.com",
      url: "https://api.example.com",
      category: "security_headers",
      severityEstimate: "info",
      confidence: "medium",
      status: "needs_validation",
      evidencePaths: [artifact.path],
      duplicateRisk: "unknown",
      reportabilityScore: 20,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    });

    expect(evidence.list(finding.id).map((item) => item.id)).toEqual([artifact.id]);

    const manifestArtifact = evidence.writeManifest({
      findingId: finding.id,
      relativePath: path.join(finding.id, "evidence-manifest.json"),
      createdAt: "2026-01-01T00:01:00.000Z",
    });
    const manifest = JSON.parse(readFileSync(manifestArtifact.path, "utf8")) as EvidenceManifest;

    expect(manifest.artifactCount).toBe(1);
    expect(manifest.artifacts[0]?.id).toBe(artifact.id);
    expect(manifest.artifacts[0]?.relativePath).toContain("safe-checks.json");
    expect(manifest.artifacts[0]?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(manifest.safety.contentsEmbedded).toBe(false);
  });

  it("rejects text artifact paths outside the evidence root", () => {
    const { evidence } = createStores();
    expect(() =>
      evidence.writeTextArtifact({
        adapterName: "test",
        kind: "research_note",
        relativePath: path.join("..", "escape.md"),
        content: "outside",
      }),
    ).toThrow(/escapes the evidence directory/);
  });

  it("rejects text artifact writes through symlinked directories", () => {
    const { evidence, evidenceRoot } = createStores();
    const outsideDir = mkdtempSync(path.join(os.tmpdir(), "bountypilot-evidence-outside-"));
    const linkPath = path.join(evidenceRoot, "link");
    try {
      mkdirSync(evidenceRoot, { recursive: true });
      symlinkSync(outsideDir, linkPath, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      if (isSymlinkUnavailable(error)) {
        return;
      }
      throw error;
    }

    expect(() =>
      evidence.writeTextArtifact({
        adapterName: "test",
        kind: "research_note",
        relativePath: path.join("link", "escape.md"),
        content: "outside",
      }),
    ).toThrow(/trusted artifact roots|escapes/);
    expect(existsSync(path.join(outsideDir, "escape.md"))).toBe(false);
  });

  it("masks secret-like values in text artifacts by default", () => {
    const { evidence } = createStores();
    const artifact = evidence.writeTextArtifact({
      adapterName: "test",
      kind: "tool_output",
      relativePath: path.join("job-1", "tool-output.json"),
      content: '{"token":"abc123","password":"letmein"}',
    });

    const content = readFileSync(artifact.path, "utf8");
    expect(content).not.toContain("abc123");
    expect(content).not.toContain("letmein");
    expect(content).toContain("[REDACTED]");
  });

  it("keeps JSON evidence parseable when masking escaped preview strings", () => {
    const { evidence } = createStores();
    const artifact = evidence.writeTextArtifact({
      adapterName: "test",
      kind: "tool_output",
      relativePath: path.join("job-1", "stream-output.json"),
      content: JSON.stringify(
        {
          streamEvents: {
            events: [
              {
                preview: JSON.stringify({
                  jsonrpc: "2.0",
                  params: { data: "running browser_navigate token=stream-secret" },
                }),
              },
            ],
          },
        },
        null,
        2,
      ),
    });

    const content = readFileSync(artifact.path, "utf8");
    expect(content).not.toContain("stream-secret");
    expect(JSON.parse(content).streamEvents.events[0].preview).toContain("[REDACTED]");
  });

  it("masks existing text artifacts when registering them", () => {
    const { evidence, evidenceRoot } = createStores();
    const artifactPath = path.join(evidenceRoot, "job-1", "external-output.txt");
    mkdirSync(path.dirname(artifactPath), { recursive: true });
    writeFileSync(artifactPath, "authorization: bearer live-secret-token", "utf8");

    evidence.create({
      adapterName: "external-tool",
      kind: "tool_output",
      path: artifactPath,
    });

    expect(readFileSync(artifactPath, "utf8")).toBe("authorization: bearer [REDACTED]");
  });

  it("rejects registered artifact paths outside trusted roots without mutating them", () => {
    const { evidence, evidenceRoot } = createStores();
    const outsidePath = path.join(evidenceRoot, "..", "outside-tool-output.txt");
    writeFileSync(outsidePath, "authorization: bearer outside-secret", "utf8");

    expect(() =>
      evidence.create({
        adapterName: "external-tool",
        kind: "tool_output",
        path: outsidePath,
      }),
    ).toThrow(/trusted artifact roots/);
    expect(readFileSync(outsidePath, "utf8")).toContain("outside-secret");
  });

  it("copies manual evidence files into the evidence root", () => {
    const { evidence, evidenceRoot } = createStores();
    const sourcePath = path.join(evidenceRoot, "..", "manual-note.txt");
    writeFileSync(sourcePath, "password=manual-copy-secret", "utf8");

    const artifact = evidence.copyFileArtifact({
      adapterName: "manual",
      kind: "evidence_note",
      sourcePath,
      relativePath: path.join("finding-1", "manual", "manual-note.txt"),
    });

    expect(artifact.path).toBe(path.join(evidenceRoot, "finding-1", "manual", "manual-note.txt"));
    expect(readFileSync(artifact.path, "utf8")).not.toContain("manual-copy-secret");
  });

  it("reports missing manual evidence sources with a stable code", () => {
    const { evidence, evidenceRoot } = createStores();

    try {
      evidence.copyFileArtifact({
        adapterName: "manual",
        kind: "evidence_note",
        sourcePath: path.join(evidenceRoot, "missing.txt"),
        relativePath: path.join("manual", "missing.txt"),
      });
      throw new Error("Expected copyFileArtifact to fail.");
    } catch (error) {
      expect(error).toMatchObject({ code: "EVIDENCE_SOURCE_NOT_FOUND" });
    }
  });

  it("can preserve text artifacts when masking is disabled", () => {
    const { evidence } = createStores({ maskSecrets: false });
    const artifact = evidence.writeTextArtifact({
      adapterName: "test",
      kind: "tool_output",
      relativePath: path.join("job-1", "raw-output.json"),
      content: '{"token":"abc123"}',
    });

    expect(readFileSync(artifact.path, "utf8")).toContain("abc123");
  });

  it("does not hash database-poisoned manifest paths outside trusted roots", () => {
    const { db, evidence, evidenceRoot } = createStores();
    const outsidePath = path.join(evidenceRoot, "..", "poison.txt");
    writeFileSync(outsidePath, "do not hash me", "utf8");
    db.prepare(
      `INSERT INTO evidence_artifacts (
        id, finding_id, job_id, adapter_name, kind, source_url, path, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run("evidence-poison", null, null, "poison", "tool_output", null, outsidePath, "2026-01-01T00:00:00.000Z");

    const manifest = evidence.buildManifest();

    expect(manifest.artifactCount).toBe(1);
    expect(manifest.artifacts[0]).toMatchObject({ id: "evidence-poison", readable: false });
    expect(manifest.artifacts[0]?.sha256).toBeUndefined();
  });
});

function createStores(options: { maskSecrets?: boolean } = {}): {
  db: ReturnType<typeof openBountyDatabase>;
  evidence: EvidenceStore;
  evidenceRoot: string;
  findings: FindingStore;
} {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-evidence-"));
  const db = openBountyDatabase(path.join(root, "bounty.sqlite"));
  const evidenceRoot = path.join(root, "evidence");
  return {
    db,
    evidence: new EvidenceStore(db, evidenceRoot, options),
    evidenceRoot,
    findings: new FindingStore(db),
  };
}

function isSymlinkUnavailable(error: unknown): boolean {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "EPERM";
}
