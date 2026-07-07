export type TuiMode = "chat" | "plan" | "hunt" | "review";
export type TuiScreen =
  | "chat"
  | "connect"
  | "models"
  | "sessions"
  | "palette"
  | "hunt"
  | "doctor"
  | "results"
  | "init"
  | "tools"
  | "mcp"
  | "help"
  | "themes"
  | "context"
  | "action";

export interface SlashCommandSpec {
  id: string;
  title: string;
  description: string;
  screen?: TuiScreen;
  keybind?: string;
}

export interface ParsedSlashCommand {
  command: string;
  args: string;
}

export interface TuiWindowSlice<T> {
  items: T[];
  offset: number;
  hasOlder: boolean;
  hasNewer: boolean;
  start: number;
  end: number;
}

export interface ComposerEditResult {
  value: string;
  cursor: number;
}

export interface TuiModelOption {
  provider: string;
  model: string;
  selected: boolean;
}

export type TuiAssistantLineKind = "blank" | "text" | "tool" | "command" | "status" | "error";

export const TUI_MODES: TuiMode[] = ["chat", "plan", "hunt", "review"];

export const SLASH_COMMANDS: SlashCommandSpec[] = [
  { id: "/help", title: "Help", description: "Show terminal commands", screen: "help" },
  { id: "/connect", title: "Connect provider", description: "Providers", screen: "connect" },
  { id: "/models", title: "Switch model", description: "Provider/model", screen: "models", keybind: "ctrl+x m" },
  { id: "/model", title: "Switch model", description: "Alias for /models", screen: "models" },
  { id: "/sessions", title: "Sessions", description: "Local sessions", screen: "sessions", keybind: "ctrl+x l" },
  { id: "/resume", title: "Resume session", description: "Alias for /sessions", screen: "sessions" },
  { id: "/continue", title: "Continue session", description: "Alias for /sessions", screen: "sessions" },
  { id: "/theme", title: "Theme", description: "Alias for /themes", screen: "themes" },
  { id: "/themes", title: "Themes", description: "Palette", screen: "themes", keybind: "ctrl+x t" },
  { id: "/context", title: "Context files", description: "File picker", screen: "context" },
  { id: "/init", title: "Initialize", description: "Workspace setup", screen: "init" },
  { id: "/mode", title: "Switch agent", description: "Set or cycle Build, Plan, Hunt, Review" },
  { id: "/agent", title: "Switch agent", description: "Alias for /mode" },
  { id: "/agents", title: "Switch agent", description: "Alias for /mode" },
  { id: "/new", title: "New session", description: "Clean session", keybind: "ctrl+x n" },
  { id: "/clear", title: "New session", description: "Alias for /new" },
  { id: "/compact", title: "Compact session", description: "Summarize context", keybind: "ctrl+x c" },
  { id: "/summarize", title: "Compact session", description: "Alias for /compact" },
  { id: "/details", title: "Details", description: "Tool details" },
  { id: "/thinking", title: "Thinking", description: "Reasoning blocks" },
  { id: "/editor", title: "External editor", description: "Editor", keybind: "ctrl+x e" },
  { id: "/export", title: "Export session", description: "Markdown", keybind: "ctrl+x x" },
  { id: "/undo", title: "Undo", description: "Undo last message", keybind: "ctrl+x u" },
  { id: "/redo", title: "Redo", description: "Redo last message", keybind: "ctrl+x r" },
  { id: "/share", title: "Share", description: "Share status" },
  { id: "/unshare", title: "Unshare", description: "Share status" },
  { id: "/exit", title: "Exit", description: "Close the terminal UI", keybind: "ctrl+x q" },
  { id: "/quit", title: "Quit", description: "Alias for /exit" },
  { id: "/q", title: "Quit", description: "Alias for /exit" },
  { id: "/doctor", title: "Doctor", description: "Readiness", screen: "doctor" },
  { id: "/results", title: "Results", description: "Findings", screen: "results" },
  { id: "/tools", title: "Tools", description: "Tool readiness", screen: "tools" },
  { id: "/mcp", title: "MCP", description: "Integrations", screen: "mcp" },
  { id: "/hunt", title: "Hunt panel", description: "Workflows", screen: "hunt" },
  { id: "/recon", title: "Recon plan", description: "Dry-run recon", screen: "hunt" },
  { id: "/actions", title: "Safe actions", description: "Action planner", screen: "action" },
];

export function nextTuiMode(mode: TuiMode): TuiMode {
  const index = TUI_MODES.indexOf(mode);
  return TUI_MODES[(index + 1) % TUI_MODES.length]!;
}

export function previousTuiMode(mode: TuiMode): TuiMode {
  const index = TUI_MODES.indexOf(mode);
  return TUI_MODES[(index - 1 + TUI_MODES.length) % TUI_MODES.length]!;
}

export function parseSlashCommand(value: string): ParsedSlashCommand | undefined {
  const trimmed = value.trim();
  if (!trimmed.startsWith("/")) return undefined;
  const [raw = "", ...parts] = trimmed.split(/\s+/);
  return { command: raw.toLowerCase(), args: parts.join(" ").trim() };
}

export function filterSlashCommands(query: string, commands: SlashCommandSpec[] = SLASH_COMMANDS): SlashCommandSpec[] {
  const normalized = query.trim().toLowerCase().replace(/^\//, "");
  if (!normalized) return commands;
  return commands.filter((command) =>
    [command.id, command.title, command.description].some((value) => value.toLowerCase().includes(normalized)),
  );
}

export function safeComposerAppend(current: string, input: string): string {
  const next = `${current}${input}`;
  return next.length > 4000 ? next.slice(0, 4000) : next;
}

export function boundedComposerCursor(value: string, cursor: number): number {
  return Math.max(0, Math.min(value.length, Math.floor(cursor)));
}

export function insertComposerText(value: string, cursor: number, input: string): ComposerEditResult {
  const safeCursor = boundedComposerCursor(value, cursor);
  const available = Math.max(0, 4000 - value.length);
  const boundedInput = input.slice(0, available);
  const nextValue = `${value.slice(0, safeCursor)}${boundedInput}${value.slice(safeCursor)}`;
  return { value: nextValue, cursor: safeCursor + boundedInput.length };
}

export function backspaceComposerText(value: string, cursor: number): ComposerEditResult {
  const safeCursor = boundedComposerCursor(value, cursor);
  if (safeCursor === 0) return { value, cursor: 0 };
  return {
    value: `${value.slice(0, safeCursor - 1)}${value.slice(safeCursor)}`,
    cursor: safeCursor - 1,
  };
}

export function deleteComposerText(value: string, cursor: number): ComposerEditResult {
  const safeCursor = boundedComposerCursor(value, cursor);
  if (safeCursor >= value.length) return { value, cursor: safeCursor };
  return {
    value: `${value.slice(0, safeCursor)}${value.slice(safeCursor + 1)}`,
    cursor: safeCursor,
  };
}

export function killComposerAfterCursor(value: string, cursor: number): ComposerEditResult {
  const safeCursor = boundedComposerCursor(value, cursor);
  return { value: value.slice(0, safeCursor), cursor: safeCursor };
}

export function killComposerWordBeforeCursor(value: string, cursor: number): ComposerEditResult {
  const safeCursor = boundedComposerCursor(value, cursor);
  const beforeCursor = value.slice(0, safeCursor);
  const withoutTrailingSpaces = beforeCursor.replace(/[^\S\r\n]+$/, "");
  const nextBeforeCursor = withoutTrailingSpaces.replace(/[^ \t\r\n]+$/, "");
  return {
    value: `${nextBeforeCursor}${value.slice(safeCursor)}`,
    cursor: nextBeforeCursor.length,
  };
}

export function appendPromptHistory(history: readonly string[], value: string, limit = 50): string[] {
  const normalized = value.trim();
  if (!normalized) return [...history];
  const boundedLimit = Math.max(1, Math.floor(limit));
  const next = history[history.length - 1] === normalized ? [...history] : [...history, normalized];
  return next.slice(-boundedLimit);
}

export function modelOptionKey(option: Pick<TuiModelOption, "provider" | "model">): string {
  return `${option.provider}/${option.model}`;
}

export function appendRecentModel(recentModels: readonly string[], option: Pick<TuiModelOption, "provider" | "model">, limit = 12): string[] {
  const key = modelOptionKey(option);
  const boundedLimit = Math.max(1, Math.floor(limit));
  return [key, ...recentModels.filter((entry) => entry !== key)].slice(0, boundedLimit);
}

export function sortModelOptionsByRecent<T extends TuiModelOption>(options: readonly T[], recentModels: readonly string[]): T[] {
  const rank = new Map(recentModels.map((key, index) => [key, index]));
  return [...options].sort((left, right) => {
    const leftRank = rank.get(modelOptionKey(left)) ?? Number.MAX_SAFE_INTEGER;
    const rightRank = rank.get(modelOptionKey(right)) ?? Number.MAX_SAFE_INTEGER;
    if (leftRank !== rightRank) return leftRank - rightRank;
    if (left.selected !== right.selected) return left.selected ? -1 : 1;
    return modelOptionKey(left).localeCompare(modelOptionKey(right));
  });
}

export function cycleModelOption<T extends TuiModelOption>(options: readonly T[], current: Pick<TuiModelOption, "provider" | "model"> | undefined, direction: "next" | "previous"): T | undefined {
  if (options.length === 0) return undefined;
  if (!current) return options[0];
  const currentKey = modelOptionKey(current);
  const currentIndex = options.findIndex((option) => modelOptionKey(option) === currentKey);
  const baseIndex = currentIndex === -1 ? 0 : currentIndex;
  const nextIndex = direction === "next"
    ? (baseIndex + 1) % options.length
    : (baseIndex - 1 + options.length) % options.length;
  return options[nextIndex];
}

export function killComposerPreviousWord(value: string): string {
  const withoutTrailingSpaces = value.replace(/[^\S\r\n]+$/, "");
  return withoutTrailingSpaces.replace(/[^ \t\r\n]+$/, "");
}

export function truncateTuiText(value: string, maxLength: number): string {
  if (maxLength <= 0) return "";
  if (value.length <= maxLength) return value;
  if (maxLength <= 3) return ".".repeat(maxLength);
  return `${value.slice(0, maxLength - 3)}...`;
}

export function displayModelLabel(providerId: string | undefined, model: string | undefined): string {
  const raw = model ?? providerId ?? "-";
  const tail = raw.split("/").filter(Boolean).pop() ?? raw;
  const spaced = tail
    .replace(/[_-]+/g, " ")
    .replace(/([a-z])(\d)/gi, "$1 $2")
    .replace(/\s+/g, " ")
    .trim();
  if (!spaced) return "-";
  return spaced
    .split(" ")
    .map((part) => {
      const lower = part.toLowerCase();
      if (["ai", "api", "gpt", "llm", "mcp", "xss", "ssrf", "idor"].includes(lower)) return lower.toUpperCase();
      if (/^\d/.test(part)) return part;
      return `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`;
    })
    .join(" ");
}

export function classifyAssistantLine(line: string): TuiAssistantLineKind {
  const trimmed = line.trim();
  if (!trimmed) return "blank";
  if (/^(provider error|error|blocked):/i.test(trimmed)) return "error";
  if (/^\$ /.test(trimmed)) return "command";
  if (trimmed.startsWith("◉ ")) return "status";
  if (/^(\*|->|→)\s/.test(trimmed)) return "tool";
  if (/^(~\s|asking|planned safe action|action planned|running|reading|searching)\b/i.test(trimmed)) return "status";
  return "text";
}

export function formatTranscriptTitleMetrics(
  messages: readonly { role?: string; content: string }[],
  options: { contextWindowTokens?: number; costUsd?: number } = {},
): string {
  const contextWindowTokens = Math.max(1, Math.floor(options.contextWindowTokens ?? 200_000));
  const visibleContent = messages
    .filter((message) => message.role !== "system")
    .map((message) => message.content)
    .join("\n");
  const estimatedTokens = Math.max(0, Math.ceil(visibleContent.length / 4));
  const percent = Math.min(100, Math.round((estimatedTokens / contextWindowTokens) * 100));
  const cost = Math.max(0, options.costUsd ?? 0);
  return `${estimatedTokens.toLocaleString("en-US")} ${percent}% ($${cost.toFixed(2)})`;
}

export function boundedScrollOffset(totalItems: number, visibleCount: number, requestedOffset: number): number {
  const safeVisible = Math.max(1, Math.floor(visibleCount));
  const maxOffset = Math.max(0, totalItems - safeVisible);
  return Math.max(0, Math.min(maxOffset, Math.floor(requestedOffset)));
}

export function windowItemsFromEnd<T>(items: T[], visibleCount: number, scrollOffset: number): TuiWindowSlice<T> {
  const safeVisible = Math.max(1, Math.floor(visibleCount));
  const offset = boundedScrollOffset(items.length, safeVisible, scrollOffset);
  const start = Math.max(0, items.length - safeVisible - offset);
  const end = Math.min(items.length, start + safeVisible);
  return {
    items: items.slice(start, end),
    offset,
    hasOlder: start > 0,
    hasNewer: end < items.length,
    start,
    end,
  };
}

export function maskedInput(value: string): string {
  if (!value) return "";
  return "*".repeat(Math.min(value.length, 48));
}

export function commandScreen(command: string): TuiScreen | undefined {
  return SLASH_COMMANDS.find((candidate) => candidate.id === command)?.screen;
}

export function composerFooterHint(screen: TuiScreen, connectStage: "provider" | "api-key" = "provider"): string {
  if (screen === "connect") return connectStage === "api-key" ? "enter save   esc providers" : "enter select   arrows move   type search";
  if (screen === "models") return "enter select   arrows move   type search   esc chat";
  if (screen === "sessions") return "enter resume   arrows move   type search   esc chat";
  if (screen === "palette") return "enter run   arrows move   type filter   esc close";
  if (screen === "themes") return "enter apply   arrows move   esc chat";
  if (screen === "context") return "enter attach   arrows move   type search   esc chat";
  if (screen === "action") return "enter plan   arrows move   esc chat";
  if (screen === "chat") return "enter send   arrows edit/history   shift+enter newline   / palette";
  return "enter send   / commands   esc chat";
}
