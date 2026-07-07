import { describe, expect, it } from "vitest";
import { BUG_BOUNTY_PILOT_SKILL_ID, loadSkillDefinition } from "../src/skills/skill-definition.js";

describe("bug-bounty-pilot skill workflow", () => {
  it("declares the recon-to-report workflow steps with commands and artifacts", () => {
    const workflow = loadSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID).workflow;
    const ids = workflow.steps.map((step) => step.id);

    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(
      expect.arrayContaining([
        "authorization_check",
        "program_import",
        "scope_validation",
        "passive_recon",
        "web_recon",
        "playbook_execution",
        "finding_candidate_generation",
        "evidence_collection",
        "reportability_score",
        "report_draft",
        "handoff_bundle",
      ]),
    );
    expect(workflow.steps.every((step) => step.cli_commands.length > 0)).toBe(true);
    expect(workflow.steps.every((step) => step.artifacts.length > 0)).toBe(true);
  });

  it("keeps active workflow phases scoped and approval-aware", () => {
    const steps = loadSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID).workflow.steps;
    const passiveRecon = steps.find((step) => step.id === "passive_recon");
    const webRecon = steps.find((step) => step.id === "web_recon");
    const reportDraft = steps.find((step) => step.id === "report_draft");

    expect(passiveRecon).toMatchObject({
      risk_level: "low",
      requires_scope: true,
      requires_approval: false,
    });
    expect(passiveRecon?.blocked_capabilities).toEqual(expect.arrayContaining(["active_request", "live_crawl"]));
    expect(webRecon).toMatchObject({
      risk_level: "medium",
      requires_scope: true,
      requires_approval: true,
    });
    expect(reportDraft?.blocked_capabilities).toContain("auto_submit_report");
  });
});

