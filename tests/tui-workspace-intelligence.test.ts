import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { saveProgramConfig, programWorkspace } from "../src/core/workspace.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { FindingStore } from "../src/stores/finding-store.js";
import { ReconObservationStore } from "../src/stores/recon-observation-store.js";
import { loadWorkspaceInsight } from "../src/cli/tui/workspace-intelligence.js";

const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("TUI workspace intelligence", () => {
  it("returns setup guidance when no program is imported", () => {
    const workspace = createWorkspace();

    const insight = loadWorkspaceInsight(workspace);

    expect(insight.status).toBe("setup");
    expect(insight.next).toEqual(expect.arrayContaining(["bugbounty init", "bugbounty import <program.yml>"]));
    expect(insight.tools.total).toBeGreaterThan(0);
    expect(insight.integrations.total).toBe(0);
  });

  it("summarizes local findings and recon observations without running tools", () => {
    const workspace = createWorkspace();
    saveProgramConfig(programConfig(), workspace);
    const paths = programWorkspace("tui-intel", workspace);
    const db = openBountyDatabase(paths.dbFile);
    try {
      new FindingStore(db).create({
        title: "Reflected XSS candidate",
        asset: "https://api.example.com",
        url: "https://api.example.com/search?q=test",
        category: "xss",
        severityEstimate: "medium",
        confidence: "medium",
        status: "needs_validation",
        evidencePaths: ["evidence/xss-note.md"],
        duplicateRisk: "unknown",
        reportabilityScore: 82,
      });
      new ReconObservationStore(db).upsert({
        kind: "endpoint",
        value: "https://api.example.com/search",
        sourceAdapter: "fixture",
        scopeAllowed: true,
        confidence: "medium",
      });
    } finally {
      db.close();
    }

    const insight = loadWorkspaceInsight(workspace);

    expect(insight.status).toBe("ready");
    expect(insight.program).toBe("tui-intel");
    expect(insight.findings).toMatchObject({ total: 1, ready: 1, bestScore: 82 });
    expect(insight.recon).toMatchObject({ total: 1, inScope: 1 });
    expect(insight.tools.total).toBeGreaterThan(0);
    expect(insight.integrations.total).toBeGreaterThan(0);
    expect(insight.integrations.mcp).toBeGreaterThan(0);
    expect(insight.findings.top?.title).toBe("Reflected XSS candidate");
  });
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-tui-intel-"));
  workspaces.push(workspace);
  return workspace;
}

function programConfig(): ProgramConfig {
  return {
    program: "tui-intel",
    platform: "hackerone",
    in_scope: ["api.example.com"],
    out_of_scope: ["internal.example.com"],
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "1rps",
      browser_crawling: true,
      deep_safe_mode: true,
      lab_mode: false,
      require_human_approval_for_risky_actions: true,
    },
    accounts: {
      required: false,
      use_researcher_owned_test_accounts_only: true,
    },
    evidence: {
      screenshots: true,
      har: true,
      console_logs: true,
      dom_snapshot: true,
      video: "optional",
      browser_trace: true,
      desktop_screenshots: "optional",
      mask_secrets: true,
    },
    integrations: {
      playwright: { enabled: true },
      playwright_mcp: { enabled: false, allow_execute: false },
      crawl4ai: { enabled: false, allow_execute: false },
      windows_mcp: { enabled: false, allow_execute: false },
      d_research_skill: { enabled: false, source: "https://github.com/d-init-d/d-research-skill.git" },
    },
  };
}
