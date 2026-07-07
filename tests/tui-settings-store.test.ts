import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { TuiSettingsStore } from "../src/cli/tui/settings-store.js";

const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("TuiSettingsStore", () => {
  it("reads defaults, persists updates, and normalizes invalid themes", () => {
    const workspace = createWorkspace();
    const store = new TuiSettingsStore(workspace);

    expect(store.read()).toEqual({ theme: "opencode", details: true, thinking: false, recentModels: [] });

    const written = store.write({ theme: "missing" as never, details: false, thinking: true, recentModels: [" openai/gpt-4.1-mini ", "", "openai/gpt-4.1-mini"] });
    expect(written).toEqual({ theme: "opencode", details: false, thinking: true, recentModels: ["openai/gpt-4.1-mini"] });
    expect(existsSync(store.file)).toBe(true);

    const updated = store.update({ theme: "matrix", details: true, recentModels: Array.from({ length: 14 }, (_, index) => `p/m${index}`) });
    expect(updated).toEqual({ theme: "matrix", details: true, thinking: true, recentModels: Array.from({ length: 12 }, (_, index) => `p/m${index}`) });
    expect(new TuiSettingsStore(workspace).read()).toEqual(updated);
  });
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-tui-settings-"));
  workspaces.push(workspace);
  return workspace;
}
