import { describe, expect, it } from "vitest";
import { renderBountyTuiCommandPaletteSnapshot, renderBountyTuiConnectSnapshot } from "../src/cli/tui/run.js";

describe("OpenCode-style TUI render snapshots", () => {
  it("renders the provider connect selector with gutter selection and compact rows", () => {
    const snapshot = renderBountyTuiConnectSnapshot();

    expect(snapshot).toContain("\u2502 /connect");
    expect(snapshot).toContain("\u2502 search _");
    expect(snapshot).toContain("\u2502 > OpenAI");
    expect(snapshot).toContain("gpt-4.1-mini  openai");
    expect(snapshot).toContain("\u2502   OpenRouter");
    expect(snapshot).toContain("anthropic/claude-sonnet  openrouter");
    expect(snapshot).not.toContain("Choose a provider");
    expect(snapshot).not.toContain("paste API key");
  });

  it("renders the command palette as an OpenCode-style command list", () => {
    const snapshot = renderBountyTuiCommandPaletteSnapshot("/mod");

    expect(snapshot).toContain("\u2502 / commands");
    expect(snapshot).toContain("\u2502 / mod");
    expect(snapshot).toContain("/models");
    expect(snapshot).toContain("ctrl+x m");
    expect(snapshot).toContain("/model");
    expect(snapshot).toContain("/mode");
    expect(snapshot).not.toContain("command palette");
    expect(snapshot).not.toContain("essential commands");
  });
});
