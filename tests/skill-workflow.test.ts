import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { BUG_BOUNTY_PILOT_SKILL_ID, loadSkillDefinition, validateSkillDefinition } from "../src/skills/skill-definition.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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
    const handoff = workflow.steps.find((step) => step.id === "handoff_bundle");
    expect(handoff?.cli_commands).toContain("bounty export bundle --job <job-id> --include-artifacts");
    expect(workflow.steps.flatMap((step) => step.cli_commands).join("\n")).not.toContain("--include-evidence");
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

  it("fails validation when workflow commands drift from the CLI contract", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-contract-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      const workflowPath = path.join(skillRoot, "workflow.yml");
      writeFileSync(
        workflowPath,
        readFileSync(workflowPath, "utf8").replace("--include-artifacts", "--include-evidence"),
        "utf8",
      );

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "workflow:cli_command_contract",
            status: "fail",
            message: expect.stringContaining("--include-evidence"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
