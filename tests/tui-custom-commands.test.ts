import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadCustomCommands, renderCustomCommandPrompt } from "../src/cli/tui/custom-commands.js";

const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("TUI custom commands", () => {
  it("loads markdown commands from local command directories", () => {
    const workspace = createWorkspace();
    writeCommand(
      workspace,
      ".bounty/commands/recon-plan.md",
      [
        "---",
        "description: Build a scoped recon plan",
        "model: ollama/llama3.1",
        "agent: hunt",
        "subtask: true",
        "---",
        "Create a dry-run recon plan for $ARGUMENTS.",
      ].join("\n"),
    );
    writeCommand(workspace, ".opencode/commands/report/review.md", "Review this report: {{args}}");
    writeCommand(workspace, "commands/smoke.md", "Run a local smoke review.");

    const commands = loadCustomCommands(workspace);

    expect(commands).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "/recon-plan",
          description: "Build a scoped recon plan",
          model: "ollama/llama3.1",
          agent: "hunt",
          subtask: true,
        }),
        expect.objectContaining({
          id: "/report:review",
          description: "Review this report: {{args}}",
        }),
        expect.objectContaining({
          id: "/smoke",
          description: "Run a local smoke review.",
        }),
      ]),
    );
  });

  it("renders command templates with arguments", () => {
    const workspace = createWorkspace();
    writeCommand(workspace, ".bounty/commands/xss.md", "Check $ARGUMENTS and {{args}} safely.");

    const command = loadCustomCommands(workspace)[0]!;

    expect(renderCustomCommandPrompt(command, "https://example.com")).toBe(
      "Check https://example.com and https://example.com safely.",
    );
  });
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-tui-commands-"));
  workspaces.push(workspace);
  return workspace;
}

function writeCommand(workspace: string, relativePath: string, content: string): void {
  const file = path.join(workspace, relativePath);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${content}\n`, "utf8");
}
