import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { TuiSessionStore } from "../src/cli/tui/session-store.js";

const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("TuiSessionStore", () => {
  it("creates, lists, resumes, updates, and deletes local sessions", () => {
    const workspace = createWorkspace();
    const store = new TuiSessionStore(workspace);

    const created = store.create({
      title: "Bug bounty run",
      providerId: "openai",
      model: "gpt-4.1-mini",
      messages: [{ role: "user", content: "token sk-supersecret12345 should not persist" }],
    });

    expect(store.list()).toEqual([
      expect.objectContaining({
        id: created.id,
        title: "Bug bounty run",
        providerId: "openai",
        model: "gpt-4.1-mini",
        messages: 1,
      }),
    ]);
    expect(store.read(created.id).messages[0]?.content).toContain("sk-***");

    const updated = store.update(created.id, { mode: "hunt" });
    expect(updated.mode).toBe("hunt");

    store.delete(created.id);
    expect(store.list()).toEqual([]);
  });
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-tui-session-"));
  workspaces.push(workspace);
  return workspace;
}
