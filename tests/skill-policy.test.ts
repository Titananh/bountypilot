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
        expect.objectContaining({ name: "SKILL.md:frontmatter", status: "pass" }),
        expect.objectContaining({ name: "SKILL.md:name", status: "pass" }),
        expect.objectContaining({ name: "agents/openai.yaml:schema", status: "pass" }),
        expect.objectContaining({ name: "agents/openai.yaml:default_prompt", status: "pass" }),
        expect.objectContaining({ name: "skill:allowed-files", status: "pass" }),
        expect.objectContaining({ name: "skill:no-auxiliary-docs", status: "pass" }),
        expect.objectContaining({ name: "prompts:contracts", status: "pass" }),
        expect.objectContaining({ name: "templates:syntax", status: "pass" }),
        expect.objectContaining({ name: "skill:placeholder-targets", status: "pass" }),
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

  it("fails validation when SKILL.md frontmatter drifts from the skill id", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-frontmatter-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      const skillPath = path.join(skillRoot, "SKILL.md");
      writeFileSync(
        skillPath,
        readFileSync(skillPath, "utf8").replace('name: "bug-bounty-pilot"', 'name: "bug-hunter"'),
        "utf8",
      );

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "SKILL.md:name",
            status: "fail",
            message: expect.stringContaining("bug-bounty-pilot"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails validation when skill assets include sample public domains instead of placeholders", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-placeholder-targets-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      const templatePath = path.join(skillRoot, "templates", "report.md");
      writeFileSync(
        templatePath,
        `${readFileSync(templatePath, "utf8")}\nUnsafe sample: https://example.com/\n`,
        "utf8",
      );

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "skill:placeholder-targets",
            status: "fail",
            message: expect.stringContaining("templates/report.md"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails validation when a structured skill template has invalid syntax", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-template-syntax-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      writeFileSync(path.join(skillRoot, "templates", "finding.json"), "{ invalid json", "utf8");

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "templates:syntax",
            status: "fail",
            message: expect.stringContaining("templates/finding.json"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails validation when prompt safety contracts are weakened", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-prompt-contracts-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      const promptPath = path.join(skillRoot, "prompts", "report-writer.md");
      writeFileSync(
        promptPath,
        readFileSync(promptPath, "utf8").replace("No auto-submit.", "Submit reports when ready."),
        "utf8",
      );

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "prompts:contracts",
            status: "fail",
            message: expect.stringContaining("prompts/report-writer.md: missing no auto-submit"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails validation when auxiliary documentation is added to the skill package", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-aux-docs-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      writeFileSync(path.join(skillRoot, "README.md"), "# Extra docs\n", "utf8");

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "skill:no-auxiliary-docs",
            status: "fail",
            message: expect.stringContaining("README.md"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails validation when an unexpected file would be bundled with the skill", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-skill-unexpected-file-"));
    try {
      const skillRoot = path.join(root, "skills", BUG_BOUNTY_PILOT_SKILL_ID);
      cpSync(path.join(repoRoot, "skills", BUG_BOUNTY_PILOT_SKILL_ID), skillRoot, { recursive: true });
      writeFileSync(path.join(skillRoot, ".env"), "SECRET=do-not-bundle\n", "utf8");

      const result = validateSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID, root);

      expect(result.ok).toBe(false);
      expect(result.checks).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            name: "skill:allowed-files",
            status: "fail",
            message: expect.stringContaining(".env"),
          }),
        ]),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
