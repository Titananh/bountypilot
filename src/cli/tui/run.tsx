import React from "react";
import { render } from "ink";
import { ProviderManager } from "../../providers/provider-manager.js";
import { BountyPilotTuiApp } from "./app.js";
import { SLASH_COMMANDS, displayModelLabel, filterSlashCommands, formatTranscriptTitleMetrics, truncateTuiText } from "./state.js";
import { TUI_DEMO_TITLE, TUI_DEMO_USER, tuiDemoAssistantLines } from "./demo.js";

export interface RunBountyTuiOptions {
  cwd?: string;
  providerId?: string;
  model?: string;
  systemPrompt: string;
  temperature: number;
  maxTokens: number;
  noInteractive?: boolean;
  demoSnapshot?: boolean;
  demoSession?: boolean;
}

export async function runBountyTui(options: RunBountyTuiOptions): Promise<void> {
  const cwd = options.cwd ?? process.cwd();
  if (options.demoSnapshot || (options.demoSession && (options.noInteractive || !shouldLaunchInteractiveTui()))) {
    process.stdout.write(`${renderBountyTuiDemoSnapshot(cwd, options)}\n`);
    return;
  }
  if (options.noInteractive || !shouldLaunchInteractiveTui()) {
    process.stdout.write(`${renderBountyTuiSnapshot(cwd, options)}\n`);
    return;
  }

  const instance = render(
    <BountyPilotTuiApp
      cwd={cwd}
      providerId={options.providerId}
      model={options.model}
      systemPrompt={options.systemPrompt}
      temperature={options.temperature}
      maxTokens={options.maxTokens}
      demoSession={options.demoSession}
    />,
    {
      alternateScreen: true,
      exitOnCtrlC: false,
      interactive: true,
      maxFps: 30,
    },
  );
  await instance.waitUntilExit();
}

export function shouldLaunchInteractiveTui(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY && process.env.BOUNTYPILOT_LEGACY_CHAT !== "1");
}

export function renderBountyTuiSnapshot(cwd = process.cwd(), options: Partial<RunBountyTuiOptions> = {}): string {
  const selected = selectedSnapshotProvider(cwd, options);

  if (!selected) {
    return renderBountyTuiConnectSnapshot();
  }

  return [
    "│ _",
    `│ Build  ${displayModelLabel(selected.id, options.model ?? selected.model)}  BountyPilot Zen`,
    "",
    snapshotFooter(),
    "",
    "non-interactive snapshot: run in a real terminal to open the full-screen TUI.",
  ].join("\n");
}

export function renderBountyTuiConnectSnapshot(): string {
  return [
    ".........",
    "│ /connect",
    "│ search _",
    "│ > OpenAI                    gpt-4.1-mini  openai",
    "│   OpenRouter                anthropic/claude-sonnet  openrouter",
    "│   Ollama                    llama3.1  ollama",
    "",
    "│ _",
    "│ Connect  connect provider  BountyPilot Zen",
    "",
    snapshotFooter(),
    "",
    "non-interactive snapshot: run in a real terminal to open the full-screen TUI.",
  ].join("\n");
}

export function renderBountyTuiCommandPaletteSnapshot(query = "/"): string {
  const commands = filterSlashCommands(query, SLASH_COMMANDS).slice(0, 8);
  return [
    ".........",
    "│ / commands",
    `│ / ${query.replace(/^\//, "") || "_"}`,
    ...commands.map((command, index) => {
      const prefix = index === 0 ? ">" : " ";
      const keybind = truncateTuiText(command.keybind ?? "", 10).padEnd(10);
      const id = truncateTuiText(command.id, 14).padEnd(14);
      const title = truncateTuiText(command.title, 22).padEnd(22);
      const detail = truncateTuiText(command.description, 42);
      return `│ ${prefix} ${keybind} ${id}${title}${detail}`;
    }),
    "",
    "│ _",
    "│ Build  Claude Opus 4.5  BountyPilot Zen",
    "",
    snapshotFooter(),
  ].join("\n");
}

export function renderBountyTuiDemoSnapshot(cwd = process.cwd(), options: Partial<RunBountyTuiOptions> = {}): string {
  const selected = selectedSnapshotProvider(cwd, options);
  const modelLabel = selected ? displayModelLabel(selected.id, options.model ?? selected.model) : "Claude Opus 4.5";
  const width = 100;
  const assistant = tuiDemoAssistantLines(modelLabel);

  return [
    renderSnapshotTitle(TUI_DEMO_TITLE, width, [
      { role: "user", content: TUI_DEMO_USER },
      { role: "assistant", content: assistant.join("\n") },
    ]),
    "",
    ...renderSnapshotBlock(TUI_DEMO_USER, width),
    "",
    ...assistant.flatMap((line) => renderSnapshotAssistantLine(line, width)),
    "",
    ...renderSnapshotComposer("Build", modelLabel, width),
    snapshotFooter(width),
  ].join("\n");
}

function selectedSnapshotProvider(cwd: string, options: Partial<RunBountyTuiOptions>): ReturnType<ProviderManager["list"]>[number] | undefined {
  const manager = new ProviderManager(cwd);
  const providers = safeListProviders(manager);
  const ready = providers.filter((provider) => provider.status === "configured");
  return options.providerId
    ? ready.find((provider) => provider.id === options.providerId)
    : ready[0];
}

function renderSnapshotTitle(title: string, width: number, messages: Array<{ role: "user" | "assistant"; content: string }>): string {
  const contentWidth = Math.max(40, width - 4);
  const metrics = formatTranscriptTitleMetrics(messages, { contextWindowTokens: 10_000, costUsd: 0.02 });
  const label = truncateTuiText(`# ${title}`, Math.max(16, contentWidth - metrics.length - 2));
  const gap = " ".repeat(Math.max(1, contentWidth - label.length - metrics.length));
  return `│ ${label}${gap}${metrics}`;
}

function renderSnapshotBlock(value: string, width: number): string[] {
  const contentWidth = Math.max(40, width - 4);
  return wrapSnapshotText(value, contentWidth).map((line) => `│ ${line.padEnd(contentWidth)}`);
}

function renderSnapshotAssistantLine(value: string, width: number): string[] {
  if (!value) return [""];
  const contentWidth = Math.max(40, width - 2);
  return wrapSnapshotText(value, contentWidth).map((line) => line);
}

function renderSnapshotComposer(mode: string, modelLabel: string, width: number): string[] {
  const contentWidth = Math.max(40, width - 4);
  const label = `${mode}  ${modelLabel}  BountyPilot Zen`;
  return [
    `│ ${"_".padEnd(contentWidth)}`,
    `│ ${label.padEnd(contentWidth)}`,
  ];
}

function snapshotFooter(width = 100): string {
  const left = ".........          esc interrupt";
  const right = "ctrl+t variants  tab agents  ctrl+p commands";
  const gap = " ".repeat(Math.max(2, width - left.length - right.length));
  return `${left}${gap}${right}`;
}

function wrapSnapshotText(value: string, width: number): string[] {
  if (value.length <= width) return [value];
  const lines: string[] = [];
  let rest = value;
  while (rest.length > width) {
    let splitAt = rest.lastIndexOf(" ", width);
    if (splitAt < Math.floor(width * 0.45)) splitAt = width;
    lines.push(rest.slice(0, splitAt).trimEnd());
    rest = rest.slice(splitAt).trimStart();
  }
  lines.push(rest);
  return lines;
}

function safeListProviders(manager: ProviderManager): ReturnType<ProviderManager["list"]> {
  try {
    return manager.list();
  } catch {
    return [];
  }
}
