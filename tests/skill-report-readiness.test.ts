import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const skillRoot = path.join(repoRoot, "skills", "bug-bounty-pilot");

describe("bug-bounty-pilot report readiness assets", () => {
  it("ships a report score template with readiness checks and blockers", () => {
    const template = JSON.parse(readFileSync(path.join(skillRoot, "templates", "report-score.json"), "utf8")) as Record<string, any>;

    expect(template).toMatchObject({
      candidateId: expect.any(String),
      score: expect.any(Number),
      readiness: "blocked",
      checks: expect.any(Object),
    });
    expect(template.blockers.length).toBeGreaterThan(0);
    expect(Object.keys(template.checks)).toEqual(
      expect.arrayContaining([
        "assetInScope",
        "categoryClear",
        "reproductionSteps",
        "impactStatement",
        "evidencePresent",
        "secretsMasked",
        "duplicateRiskNoted",
        "safeTestingStatement",
        "remediationPresent",
      ]),
    );
  });

  it("keeps report-writing prompts local-draft-only", () => {
    const reportWriter = readFileSync(path.join(skillRoot, "prompts", "report-writer.md"), "utf8");
    const reportScore = readFileSync(path.join(skillRoot, "prompts", "report-score.md"), "utf8");

    expect(reportWriter).toContain("No auto-submit");
    expect(reportWriter).toContain("Do not fabricate tool results");
    expect(reportScore).toContain("no secrets leaked");
    expect(reportScore).toContain("ready_for_draft");
  });
});

