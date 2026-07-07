import { describe, expect, it } from "vitest";
import {
  SLASH_COMMANDS,
  appendPromptHistory,
  appendRecentModel,
  backspaceComposerText,
  boundedComposerCursor,
  classifyAssistantLine,
  composerFooterHint,
  cycleModelOption,
  deleteComposerText,
  displayModelLabel,
  filterSlashCommands,
  formatTranscriptTitleMetrics,
  insertComposerText,
  killComposerAfterCursor,
  killComposerPreviousWord,
  killComposerWordBeforeCursor,
  maskedInput,
  nextTuiMode,
  parseSlashCommand,
  previousTuiMode,
  safeComposerAppend,
  sortModelOptionsByRecent,
  truncateTuiText,
  windowItemsFromEnd,
} from "../src/cli/tui/state.js";
import { TUI_THEMES, nextThemeId, themeById } from "../src/cli/tui/theme.js";

describe("TUI state helpers", () => {
  it("cycles modes like the opencode-style Tab switcher", () => {
    expect(nextTuiMode("chat")).toBe("plan");
    expect(nextTuiMode("plan")).toBe("hunt");
    expect(nextTuiMode("hunt")).toBe("review");
    expect(nextTuiMode("review")).toBe("chat");
    expect(previousTuiMode("chat")).toBe("review");
    expect(previousTuiMode("review")).toBe("hunt");
    expect(previousTuiMode("hunt")).toBe("plan");
    expect(previousTuiMode("plan")).toBe("chat");
  });

  it("parses slash commands with arguments", () => {
    expect(parseSlashCommand("/recon https://example.com")).toEqual({
      command: "/recon",
      args: "https://example.com",
    });
    expect(parseSlashCommand("hello")).toBeUndefined();
  });

  it("filters command palette entries and masks API keys", () => {
    expect(filterSlashCommands("/mod").map((command) => command.id)).toEqual(["/models", "/model", "/mode", "/agent", "/agents"]);
    expect(maskedInput("sk-test-secret")).toBe("**************");
  });

  it("exposes setup, tooling, integration, and settings slash commands", () => {
    const commands = SLASH_COMMANDS.map((command) => command.id);
    expect(commands).toEqual(
      expect.arrayContaining([
        "/model",
        "/mode",
        "/agent",
        "/agents",
        "/init",
        "/tools",
        "/mcp",
        "/details",
        "/thinking",
        "/summarize",
        "/undo",
        "/redo",
        "/export",
        "/editor",
        "/share",
        "/unshare",
        "/quit",
      ]),
    );
    expect(SLASH_COMMANDS.find((command) => command.id === "/models")?.keybind).toBe("ctrl+x m");
    expect(SLASH_COMMANDS.find((command) => command.id === "/sessions")?.keybind).toBe("ctrl+x l");
    expect(SLASH_COMMANDS.find((command) => command.id === "/new")?.keybind).toBe("ctrl+x n");
    expect(SLASH_COMMANDS.find((command) => command.id === "/exit")?.keybind).toBe("ctrl+x q");
  });

  it("exposes opencode-style theme switching", () => {
    expect(TUI_THEMES.map((theme) => theme.id)).toEqual(expect.arrayContaining(["opencode", "system", "tokyonight"]));
    expect(themeById("missing").id).toBe("opencode");
    expect(nextThemeId("opencode")).toBe("system");
  });

  it("bounds composer input length", () => {
    const long = safeComposerAppend("a".repeat(3999), "bcdef");
    expect(long).toHaveLength(4000);
  });

  it("edits composer text around a bounded cursor", () => {
    expect(boundedComposerCursor("abc", -2)).toBe(0);
    expect(boundedComposerCursor("abc", 9)).toBe(3);
    expect(insertComposerText("ac", 1, "b")).toEqual({ value: "abc", cursor: 2 });
    expect(backspaceComposerText("abc", 2)).toEqual({ value: "ac", cursor: 1 });
    expect(deleteComposerText("abc", 1)).toEqual({ value: "ac", cursor: 1 });
    expect(killComposerAfterCursor("abc def", 3)).toEqual({ value: "abc", cursor: 3 });
    expect(killComposerWordBeforeCursor("scan target please", 12)).toEqual({ value: "scan please", cursor: 5 });
  });

  it("tracks prompt history with trimming, dedupe, and a bounded limit", () => {
    expect(appendPromptHistory([], "   ")).toEqual([]);
    expect(appendPromptHistory(["one"], "one")).toEqual(["one"]);
    expect(appendPromptHistory(["one"], " two ")).toEqual(["one", "two"]);
    expect(appendPromptHistory(["one", "two"], "three", 2)).toEqual(["two", "three"]);
  });

  it("tracks recent models and cycles sorted model options", () => {
    const options = [
      { provider: "openai", model: "gpt-4.1-mini", selected: false },
      { provider: "ollama", model: "llama3.1", selected: true },
      { provider: "openrouter", model: "anthropic/claude-sonnet-4", selected: false },
    ];

    const recent = appendRecentModel(["ollama/llama3.1"], options[0], 2);
    expect(recent).toEqual(["openai/gpt-4.1-mini", "ollama/llama3.1"]);
    expect(sortModelOptionsByRecent(options, recent).map((option) => `${option.provider}/${option.model}`)).toEqual([
      "openai/gpt-4.1-mini",
      "ollama/llama3.1",
      "openrouter/anthropic/claude-sonnet-4",
    ]);
    expect(cycleModelOption(options, { provider: "ollama", model: "llama3.1" }, "next")).toEqual(options[2]);
    expect(cycleModelOption(options, { provider: "ollama", model: "llama3.1" }, "previous")).toEqual(options[0]);
  });

  it("kills the previous composer word without touching earlier lines", () => {
    expect(killComposerPreviousWord("scan target please")).toBe("scan target ");
    expect(killComposerPreviousWord("scan target   ")).toBe("scan ");
    expect(killComposerPreviousWord("first line\nsecond")).toBe("first line\n");
    expect(killComposerPreviousWord("")).toBe("");
  });

  it("windows transcript items from the newest edge with bounded scroll", () => {
    const items = ["a", "b", "c", "d", "e", "f"];

    expect(windowItemsFromEnd(items, 3, 0)).toMatchObject({
      items: ["d", "e", "f"],
      offset: 0,
      hasOlder: true,
      hasNewer: false,
      start: 3,
      end: 6,
    });
    expect(windowItemsFromEnd(items, 3, 2)).toMatchObject({
      items: ["b", "c", "d"],
      offset: 2,
      hasOlder: true,
      hasNewer: true,
      start: 1,
      end: 4,
    });
    expect(windowItemsFromEnd(items, 3, 99)).toMatchObject({
      items: ["a", "b", "c"],
      offset: 3,
      hasOlder: false,
      hasNewer: true,
      start: 0,
      end: 3,
    });
  });

  it("truncates selector text without wrapping rows", () => {
    expect(truncateTuiText("short", 8)).toBe("short");
    expect(truncateTuiText("Add OpenAI, OpenRouter, Ollama, or another provider", 24)).toBe("Add OpenAI, OpenRoute...");
    expect(truncateTuiText("abcdef", 3)).toBe("...");
    expect(truncateTuiText("abcdef", 0)).toBe("");
  });

  it("formats raw provider model ids like OpenCode composer labels", () => {
    expect(displayModelLabel("ollama", "llama3.1")).toBe("Llama 3.1");
    expect(displayModelLabel("openai", "gpt-4.1-mini")).toBe("GPT 4.1 Mini");
    expect(displayModelLabel("openrouter", "anthropic/claude-sonnet-4")).toBe("Claude Sonnet 4");
  });

  it("classifies assistant transcript lines for OpenCode-style rendering", () => {
    expect(classifyAssistantLine("")).toBe("blank");
    expect(classifyAssistantLine("* Grep \"homepage\"")).toBe("tool");
    expect(classifyAssistantLine("-> Read packages/app.tsx")).toBe("tool");
    expect(classifyAssistantLine("$ bugbounty hunt recon target --dry-run")).toBe("command");
    expect(classifyAssistantLine("~ Asking questions...")).toBe("status");
    expect(classifyAssistantLine("\u25c9 Build \u00b7 Claude Opus 4.5")).toBe("status");
    expect(classifyAssistantLine("Provider error: missing API key")).toBe("error");
    expect(classifyAssistantLine("I found several candidates.")).toBe("text");
  });

  it("formats OpenCode-style transcript title metrics from local transcript size", () => {
    expect(formatTranscriptTitleMetrics([{ role: "system", content: "hidden" }])).toBe("0 0% ($0.00)");
    expect(formatTranscriptTitleMetrics([{ role: "user", content: "a".repeat(400) }], { contextWindowTokens: 1000 })).toBe("100 10% ($0.00)");
    expect(formatTranscriptTitleMetrics([{ role: "assistant", content: "a".repeat(4000) }], { contextWindowTokens: 2000, costUsd: 0.25 })).toBe("1,000 50% ($0.25)");
  });

  it("shows screen-specific composer hints", () => {
    expect(composerFooterHint("chat")).toContain("/ palette");
    expect(composerFooterHint("chat")).toContain("shift+enter newline");
    expect(composerFooterHint("chat")).toContain("arrows edit/history");
    expect(composerFooterHint("connect")).toContain("enter select");
    expect(composerFooterHint("connect", "api-key")).toContain("enter save");
    expect(composerFooterHint("sessions")).toContain("type search");
    expect(composerFooterHint("palette")).toContain("enter run");
    expect(composerFooterHint("themes")).toContain("enter apply");
  });
});
