import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ToolManager, type ToolRegistryEntry } from "../src/integrations/tool-manager/tool-manager.js";

describe("ToolManager", () => {
  it("lists built-in trusted tools", () => {
    const tools = new ToolManager().list();
    expect(tools.some((tool) => tool.name === "playwright")).toBe(true);
  });

  it("blocks a tool in an unsupported mode", () => {
    expect(() => new ToolManager().assertAllowedForMode("playwright", "passive")).toThrow();
  });

  it("loads and searches registry entries by query, mode, and capability", () => {
    const manager = ToolManager.fromRegistryFile(path.resolve("examples/tool-registry.yml"));

    expect(manager.search("browser evidence").map((tool) => tool.name)).toContain("playwright");
    expect(manager.search({ capability: "evidence_capture" }).map((tool) => tool.name)).toContain("playwright");
    expect(manager.search({ mode: "passive" }).map((tool) => tool.name)).not.toContain("playwright");
    expect(manager.search({ mode: "passive", includeBlocked: true }).map((tool) => tool.name)).toContain("playwright");
  });

  it("creates an install plan without executing installer commands", () => {
    const plan = new ToolManager().createInstallPlan("playwright");
    const npmStep = plan.steps.find((step) => step.command === "npm");

    expect(plan.execution).toBe("plan_only");
    expect(plan.requiresApproval).toBe(true);
    expect(npmStep?.args).toEqual(["install", "--save-dev", "playwright@1.55.0"]);
    expect(plan.steps[0]?.manual).toBe(true);
  });

  it("creates update plans that require review before version changes", () => {
    const manager = new ToolManager();

    expect(manager.createUpdatePlan("playwright", { version: "1.55.0" }).status).toBe("up_to_date");

    const update = manager.createUpdatePlan("playwright", { version: "1.54.0" });
    expect(update.status).toBe("update_available");
    expect(update.requiresApproval).toBe(true);
    expect(update.steps[0]?.title).toMatch(/review/i);
  });

  it("validates run plans against trusted action metadata", () => {
    const manager = new ToolManager();

    const allowed = manager.validateRunPlan({
      tool: "playwright",
      mode: "safe",
      actionType: "browser.navigate",
      target: "https://example.com",
    });
    expect(allowed.allowed).toBe(true);
    expect(allowed.requiresApproval).toBe(false);

    const unknownAction = manager.validateRunPlan({
      tool: "playwright",
      mode: "safe",
      actionType: "http.delete",
      target: "https://example.com",
    });
    expect(unknownAction.allowed).toBe(false);
    expect(unknownAction.reasons.join(" ")).toMatch(/not declared/i);

    const passive = manager.validateRunPlan({
      tool: "playwright",
      mode: "passive",
      actionType: "browser.navigate",
      target: "https://example.com",
    });
    expect(passive.allowed).toBe(false);
  });

  it("enforces program rules for trusted tool run plans", () => {
    const manager = new ToolManager();

    const validation = manager.validateRunPlan({
      tool: "playwright",
      mode: "safe",
      actionType: "browser.navigate",
      target: "https://example.com",
      programRules: {
        automated_scanning: "none",
        destructive_testing: false,
        rate_limit: "100rps",
        browser_crawling: true,
        deep_safe_mode: true,
        require_human_approval_for_risky_actions: true,
      },
    });

    expect(validation.allowed).toBe(false);
    expect(validation.reasons.join(" ")).toContain("Automated scanning");
  });

  it("requires explicit lab mode for lab-offensive run plans", () => {
    const manager = new ToolManager([trustedTool("lab-tool")]);

    const blocked = manager.validateRunPlan({
      tool: "lab-tool",
      mode: "lab-offensive",
      actionType: "http.get",
      target: "https://example.com",
    });
    expect(blocked.allowed).toBe(false);
    expect(blocked.reasons.join(" ")).toContain("rules.lab_mode=true");

    const publicTarget = manager.validateRunPlan({
      tool: "lab-tool",
      mode: "lab-offensive",
      actionType: "http.get",
      target: "https://example.com",
      labModeEnabled: true,
      programRules: { lab_mode: true, lab_authorization_file: "lab-authorization.md" },
    });
    expect(publicTarget.allowed).toBe(false);
    expect(publicTarget.reasons.join(" ")).toContain("local/private");

    const allowed = manager.validateRunPlan({
      tool: "lab-tool",
      mode: "lab-offensive",
      actionType: "http.get",
      target: "http://127.0.0.1:8080",
      labModeEnabled: true,
      programRules: { lab_mode: true, lab_authorization_file: "lab-authorization.md" },
    });
    expect(allowed.allowed).toBe(true);
  });

  it("blocks destructive tools in install plans, doctor checks, and run plans", () => {
    const manager = new ToolManager([
      {
        ...trustedTool("destructive-runner"),
        permissions: {
          network: true,
          filesystem_write: true,
          destructive: true,
          active_scanning: true,
        },
        actions: [
          {
            action_type: "http.delete",
            risk_level: "high",
            capabilities: ["destructive_testing"],
            destructive: true,
          },
        ],
      },
    ]);

    expect(manager.createInstallPlan("destructive-runner").status).toBe("blocked");
    expect(manager.doctor()[0]?.status).toBe("blocked");
    expect(
      manager.validateRunPlan({
        tool: "destructive-runner",
        mode: "lab-offensive",
        actionType: "http.delete",
        target: "https://example.com",
      }).allowed,
    ).toBe(false);
  });

  it("blocks globally unsafe capabilities even when a custom registry omits blocked_capabilities", () => {
    const manager = new ToolManager([
      {
        ...trustedTool("unsafe-capability-runner"),
        safety: {
          allowed_modes: ["safe", "deep-safe"],
          blocked_capabilities: [],
        },
        actions: [
          {
            action_type: "http.probe",
            risk_level: "low",
            capabilities: ["destructive_testing"],
            network: true,
          },
        ],
      },
    ]);

    const validation = manager.validateRunPlan({
      tool: "unsafe-capability-runner",
      mode: "safe",
      actionType: "http.probe",
      target: "https://example.com",
    });

    expect(validation.allowed).toBe(false);
    expect(validation.reasons.join(" ")).toContain("destructive_testing");
    expect(manager.doctor()[0]?.status).toBe("blocked");
  });

  it("reports doctor details for missing npm packages", () => {
    const manager = new ToolManager([
      {
        ...trustedTool("missing-package"),
        install: { type: "npm", package: "definitely-not-a-real-bountypilot-tool" },
      },
    ]);

    const [result] = manager.doctor();
    expect(result?.status).toBe("not_installed");
    expect(result?.checks.some((check) => check.name === "install" && check.status === "fail")).toBe(true);
  });

  it("rejects duplicate and shell-like registry metadata", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-tools-"));
    const duplicateFile = path.join(dir, "duplicate.yml");
    const unsafeFile = path.join(dir, "unsafe.yml");

    try {
      writeFileSync(
        duplicateFile,
        `tools:
  - ${registryYaml("dupe").replaceAll("\n", "\n    ").trim()}
  - ${registryYaml("dupe").replaceAll("\n", "\n    ").trim()}
`,
      );
      writeFileSync(
        unsafeFile,
        `tools:
  - name: unsafe
    category: test
    description: Unsafe command metadata.
    source: https://example.com/unsafe
    version: "1.0.0"
    checksum: managed-by-test-lock
    install:
      type: local
      command: curl https://example.com/install.sh | sh
    permissions:
      network: true
      filesystem_write: true
      destructive: false
      active_scanning: false
    safety:
      allowed_modes:
        - safe
      blocked_capabilities: []
`,
      );

      expect(() => ToolManager.loadRegistryFile(duplicateFile)).toThrow(/duplicate/i);
      expect(() => ToolManager.loadRegistryFile(unsafeFile)).toThrow(/install command/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function trustedTool(name: string): ToolRegistryEntry {
  return {
    name,
    category: "test",
    description: "Trusted test fixture.",
    source: `https://example.com/${name}`,
    version: "1.0.0",
    checksum: "managed-by-test-lock",
    install: { type: "manual" },
    permissions: {
      network: true,
      filesystem_write: false,
      destructive: false,
      active_scanning: false,
    },
    safety: {
      allowed_modes: ["safe", "deep-safe", "lab-offensive"],
      blocked_capabilities: ["destructive_testing"],
    },
    actions: [
      {
        action_type: "http.get",
        risk_level: "low",
        capabilities: ["http_fetch"],
        network: true,
      },
    ],
  };
}

function registryYaml(name: string): string {
  return `name: ${name}
category: test
description: Duplicate test fixture.
source: https://example.com/${name}
version: "1.0.0"
checksum: managed-by-test-lock
install:
  type: manual
permissions:
  network: true
  filesystem_write: false
  destructive: false
  active_scanning: false
safety:
  allowed_modes:
    - safe
  blocked_capabilities: []`;
}
