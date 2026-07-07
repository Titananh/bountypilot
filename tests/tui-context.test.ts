import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildContextPrompt, listContextFiles } from "../src/cli/tui/context.js";

const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("TUI context picker", () => {
  it("lists useful local files while skipping generated directories", () => {
    const workspace = createWorkspace();
    mkdirSync(path.join(workspace, "src"), { recursive: true });
    mkdirSync(path.join(workspace, "node_modules", "pkg"), { recursive: true });
    writeFileSync(path.join(workspace, "src", "auth.ts"), "export const auth = true;\n", "utf8");
    writeFileSync(path.join(workspace, "node_modules", "pkg", "index.js"), "ignored\n", "utf8");

    const files = listContextFiles(workspace, "auth");

    expect(files.map((file) => file.path)).toEqual(["src/auth.ts"]);
  });

  it("builds bounded redacted context prompts", () => {
    const workspace = createWorkspace();
    writeFileSync(path.join(workspace, "notes.md"), "token sk-secret-api-key-1234567890\nsafe note\n", "utf8");

    const prompt = buildContextPrompt(workspace, ["notes.md"]);

    expect(prompt).toContain("--- notes.md ---");
    expect(prompt).toContain("sk-***");
    expect(prompt).toContain("safe note");
  });
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-tui-context-"));
  workspaces.push(workspace);
  return workspace;
}
