import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { BUG_BOUNTY_PILOT_SKILL_ID, loadSkillDefinition, validateSkillDefinition } from "../src/skills/skill-definition.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("bug-bounty-pilot skill policy", () => {
  it("validates the bundled skill package", () => {
    const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID);

    expect(result.ok, result.checks.filter((check) => check.status === "fail").map((check) => check.message).join("\n")).toBe(true);
    expect(result.checks.length).toBeGreaterThan(30);
    expect(result.files.agents).toContain("agents/openai.yaml");
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "agents/openai.yaml:schema", status: "pass" }),
        expect.objectContaining({ name: "agents/openai.yaml:default_prompt", status: "pass" }),
      ]),
    );
  });

  it("defines fixed safe modes and non-bypassable external tool rules", () => {
    const skill = loadSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID);

    expect(Object.keys(skill.policy.modes).sort()).toEqual(["deep-safe", "lab-offensive", "passive", "safe"]);
    expect(skill.policy.modes.passive.blocked_capabilities).toEqual(
      expect.arrayContaining(["active_request", "live_crawl", "port_scan", "fuzzing", "active_scan"]),
    );
    expect(skill.policy.blocked_always).toEqual(
      expect.arrayContaining([
        "brute_force",
        "credential_stuffing",
        "password_spraying",
        "destructive_payload",
        "malware",
        "waf_evasion",
        "data_exfiltration",
        "auth_bypass_without_permission",
        "mass_internet_scan",
        "auto_submit_report",
        "dump_sensitive_data",
      ]),
    );
    expect(skill.policy.approval_required).toEqual(expect.arrayContaining(["ffuf", "dalfox", "naabu", "nmap", "external_tool_execution"]));
    expect(skill.policy.external_tools).toMatchObject({
      require_absolute_path: true,
      require_approval: true,
      no_shell: true,
      bounded_output: true,
    });
  });

  it("fails validation when UI metadata stops invoking the bundled skill", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-agent-metadata-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      const metadataPath = path.join(skillRoot, "agents", "openai.yaml");
      writeFileSync(
        metadataPath,
        readFileSync(metadataPath, "utf8").replace("$bug-bounty-pilot", "bug bounty pilot"),
        "utf8",
      );

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "agents/openai.yaml:default_prompt",
            status: "fail",
            message: expect.stringContaining("$bug-bounty-pilot"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
