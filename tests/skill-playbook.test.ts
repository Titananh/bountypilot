import { describe, expect, it } from "vitest";
import { BUG_BOUNTY_PILOT_SKILL_ID, loadSkillDefinition } from "../src/skills/skill-definition.js";

describe("bug-bounty-pilot skill playbooks", () => {
  it("declares the minimum bug-specific playbooks", () => {
    const playbooks = loadSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID).playbooks.playbooks;
    const ids = playbooks.map((playbook) => playbook.id);

    expect(ids).toEqual(
      expect.arrayContaining([
        "headers",
        "cors",
        "cookies",
        "source-map",
        "js-secrets",
        "exposed-files",
        "xss-candidate",
        "open-redirect-candidate",
        "graphql-introspection",
        "nuclei-low",
      ]),
    );
  });

  it("keeps scanner and validation tools review-required", () => {
    const playbooks = loadSkillDefinition(BUG_BOUNTY_PILOT_SKILL_ID).playbooks.playbooks;
    const reviewToolPlaybooks = playbooks.filter((playbook) =>
      playbook.tools.some((tool) => ["nuclei", "ffuf", "dalfox", "naabu", "nmap"].includes(tool)),
    );

    expect(reviewToolPlaybooks.length).toBeGreaterThan(0);
    expect(reviewToolPlaybooks.every((playbook) => playbook.requires_approval)).toBe(true);
    expect(playbooks.find((playbook) => playbook.id === "js-secrets")?.finding_threshold).toBe("manual_verification_required");
  });
});

