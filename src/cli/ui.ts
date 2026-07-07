import { maskSecrets, maskSecretsDeep } from "../utils/secrets.js";

const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;

type ColorName =
  | "dim"
  | "green"
  | "yellow"
  | "red"
  | "cyan"
  | "blue"
  | "bold"
  | "primary"
  | "accent"
  | "muted";

type ChatRole = "user" | "assistant" | "system";

const codes: Record<ColorName, [string, string]> = {
  dim: ["2", "22"],
  green: ["32", "39"],
  yellow: ["33", "39"],
  red: ["31", "39"],
  cyan: ["36", "39"],
  blue: ["34", "39"],
  bold: ["1", "22"],
  primary: ["38;5;216", "39"],
  accent: ["38;5;141", "39"],
  muted: ["38;5;245", "39"],
};

export function color(text: string, name: ColorName): string {
  if (!useColor) return text;
  const [open, close] = codes[name];
  return `\u001B[${open}m${text}\u001B[${close}m`;
}

export function header(subtitle?: string): void {
  const parts = [color("bountypilot", "primary")];
  if (subtitle) {
    parts.push(color(" / ", "dim"), color(maskSecrets(subtitle), "bold"));
  }
  console.log(truncateVisible(parts.join(""), terminalWidth(100)));
}

export function chatHeader(input: { title: string; subtitle?: string; chips?: string[] }): void {
  const maxWidth = terminalWidth(88);
  const title = color(input.title, "primary");
  const subtitle = input.subtitle ? `${color(" ", "dim")}${color(maskSecrets(input.subtitle), "bold")}` : "";
  console.log(truncateVisible(`${title}${subtitle}`, maxWidth));
  if ((input.chips ?? []).length > 0) {
    const chips = input.chips!
      .map((chip) => color(maskSecrets(chip), "muted"))
      .join(color("  /  ", "dim"));
    console.log(truncateVisible(`  ${chips}`, maxWidth));
  }
}

export function status(
  label: "ok" | "warn" | "error" | "blocked" | "planned" | "running",
  message: string,
): void {
  const colorName =
    label === "ok" ? "green" : label === "warn" || label === "planned" ? "yellow" : label === "running" ? "cyan" : "red";
  const badge = statusBadge(label);
  console.log(`${color(badge, colorName)} ${maskSecrets(message)}`);
}

export function error(message: string): void {
  console.error(`${color(statusBadge("error"), "red")} ${maskSecrets(message)}`);
}

export function kv(label: string, value: string | number | boolean | undefined): string {
  return `${color(label.padEnd(14), "muted")} ${displayValue(value, label)}`;
}

export function list(title: string, items: string[]): void {
  console.log(sectionTitle(title));
  if (items.length === 0) {
    console.log(`  ${color("-", "dim")}`);
    return;
  }
  for (const item of items) console.log(`  ${color("-", "dim")} ${maskSecrets(item)}`);
}

export function commandList(title: string, commands: string[]): void {
  console.log(sectionTitle(title));
  if (commands.length === 0) {
    console.log(`  ${color("$", "primary")} -`);
    return;
  }
  const width = Math.max(1, terminalWidth(100) - 4);
  for (const command of commands) {
    console.log(`  ${color("$", "primary")} ${truncateVisible(maskSecrets(command), width)}`);
  }
}

export function panel(title: string, lines: string[]): void {
  const safeTitle = maskSecrets(title);
  const safeLines = lines.map((line) => maskSecrets(line));
  const maxWidth = terminalWidth(100);
  const prefix = `  ${color("|", "dim")} `;
  const contentWidth = Math.max(1, maxWidth - visibleLength(prefix));
  console.log(sectionTitle(truncateVisible(safeTitle, maxWidth)));
  for (const line of safeLines) {
    console.log(`${prefix}${truncateVisible(line, contentWidth)}`);
  }
}

export function menu(
  title: string,
  items: Array<{ index: string | number; label: string; detail?: string; lines?: string[] }>,
): void {
  const maxWidth = terminalWidth(100);
  console.log(sectionTitle(title));
  for (const item of items) {
    const index = color(String(item.index).padStart(2), "primary");
    const label = color(maskSecrets(item.label), "bold");
    const detail = item.detail ? `${color("  ", "dim")}${color(maskSecrets(item.detail), "muted")}` : "";
    console.log(truncateVisible(` ${index}  ${label}${detail}`, maxWidth));
    for (const line of item.lines ?? []) {
      console.log(truncateVisible(`     ${color("$", "primary")} ${maskSecrets(line)}`, maxWidth));
    }
  }
}

export function chatMessage(role: ChatRole, text: string): void {
  const safeText = maskSecrets(text);
  const maxWidth = terminalWidth(100);
  const marker = role === "user" ? ">" : role === "assistant" ? "|" : "!";
  const roleColor = role === "user" ? "primary" : role === "assistant" ? "accent" : "muted";
  const prefix = `  ${color(marker, roleColor)} `;
  const contentWidth = Math.max(1, maxWidth - visibleLength(prefix));
  console.log(color(role, roleColor));
  for (const rawLine of safeText.split(/\r?\n/)) {
    const wrapped = wrapVisible(rawLine, contentWidth);
    for (const line of wrapped.length > 0 ? wrapped : [""]) {
      console.log(`${prefix}${line}`);
    }
  }
}

export function chatHint(commands: string[]): void {
  const hint = commands.map((command) => color(command, "muted")).join(color("  ", "dim"));
  console.log(truncateVisible(`  ${hint}`, terminalWidth(100)));
}

export function chatPrompt(): string {
  return `${color("bugbounty", "primary")} ${color(">", "muted")} `;
}

export function textBlock(title: string, text: string): void {
  const safeTitle = maskSecrets(title);
  const safeText = maskSecrets(text);
  const maxWidth = terminalWidth(100);
  const prefix = `  ${color("|", "dim")} `;
  const contentWidth = Math.max(1, maxWidth - visibleLength(prefix));
  console.log(sectionTitle(truncateVisible(safeTitle, maxWidth)));
  for (const rawLine of safeText.split(/\r?\n/)) {
    const wrapped = wrapVisible(rawLine, contentWidth);
    for (const line of wrapped.length > 0 ? wrapped : [""]) {
      console.log(`${prefix}${line}`);
    }
  }
}

export function table(headers: string[], rows: Array<Array<string | number | boolean | undefined>>): void {
  const safeHeaders = headers.map((headerText) => maskSecrets(headerText));
  const stringRows = rows.map((row) => row.map((cell, index) => displayValue(cell, headers[index])));
  const naturalWidths = safeHeaders.map((headerText, index) =>
    Math.max(
      visibleLength(headerText),
      ...stringRows.map((row) => visibleLength(row[index] ?? "")),
    ),
  );
  const widths = fitTableWidths(naturalWidths, safeHeaders, terminalWidth(120, { capWhenPiped: false }));
  const renderRow = (row: string[]): string =>
    row.map((cell, index) => padVisibleEnd(truncateVisible(cell, widths[index]), widths[index])).join(color("  ", "dim"));

  console.log(color(renderRow(safeHeaders), "muted"));
  console.log(color(widths.map((width) => "-".repeat(width)).join("  "), "dim"));
  for (const row of stringRows) console.log(renderRow(row));
}

export function json(value: unknown): void {
  console.log(JSON.stringify(maskSecretsDeep(value), null, 2));
}

export function blank(): void {
  console.log("");
}

function visibleLength(value: string): number {
  return value.replace(/\u001B\[[0-9;]*m/g, "").length;
}

function sectionTitle(title: string): string {
  return color(maskSecrets(title), "accent");
}

function statusBadge(label: "ok" | "warn" | "error" | "blocked" | "planned" | "running"): string {
  return `[${label}]`;
}

function terminalWidth(maxWidth: number, options: { capWhenPiped?: boolean } = {}): number {
  const override = Number(process.env.BOUNTYPILOT_COLUMNS);
  if (Number.isFinite(override) && override > 0) {
    return Math.min(Math.max(40, Math.floor(override)), maxWidth);
  }
  if (!process.stdout.isTTY) {
    return options.capWhenPiped === false ? Number.MAX_SAFE_INTEGER : maxWidth;
  }
  const configured = Number(process.env.COLUMNS ?? process.stdout.columns);
  if (!Number.isFinite(configured) || configured <= 0) {
    return maxWidth;
  }
  return Math.min(Math.max(40, Math.floor(configured)), maxWidth);
}

function fitTableWidths(naturalWidths: number[], headers: string[], maxWidth: number): number[] {
  const gapWidth = Math.max(0, naturalWidths.length - 1) * 2;
  const available = Math.max(naturalWidths.length * 4, maxWidth - gapWidth);
  const minWidths = headers.map((headerText) => Math.min(Math.max(visibleLength(headerText), 4), 16));
  const widths = naturalWidths.map((width, index) => Math.max(width, minWidths[index]));

  while (widths.reduce((sum, width) => sum + width, 0) > available) {
    const widestIndex = widths.reduce((widest, width, index) => {
      if (width <= minWidths[index]) return widest;
      return widest === -1 || width > widths[widest] ? index : widest;
    }, -1);
    if (widestIndex === -1) break;
    widths[widestIndex] -= 1;
  }

  return widths;
}

function displayValue(value: string | number | boolean | undefined, key?: string): string {
  if (value === undefined) {
    return "-";
  }
  if (key) {
    const masked = maskSecretsDeep({ [key]: value }) as Record<string, unknown>;
    return String(masked[key] ?? "-");
  }
  return typeof value === "string" ? maskSecrets(value) : String(value);
}

function padVisibleEnd(value: string, width: number): string {
  return `${value}${" ".repeat(Math.max(0, width - visibleLength(value)))}`;
}

function truncateVisible(value: string, width: number): string {
  if (width <= 0 || visibleLength(value) <= width) {
    return value;
  }
  if (width <= 3) {
    return ".".repeat(width);
  }

  let output = "";
  let visible = 0;
  for (let index = 0; index < value.length && visible < width - 3; ) {
    if (value[index] === "\u001B") {
      const match = /^\u001B\[[0-9;]*m/.exec(value.slice(index));
      if (match) {
        output += match[0];
        index += match[0].length;
        continue;
      }
    }
    output += value[index];
    visible += 1;
    index += 1;
  }
  return `${output}...`;
}

function wrapVisible(value: string, width: number): string[] {
  if (!value) return [""];
  if (visibleLength(value) <= width) return [value];

  const words = value.split(/(\s+)/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    if (!word) continue;
    if (visibleLength(current) + visibleLength(word) <= width) {
      current += word;
      continue;
    }
    if (current.trim()) {
      lines.push(current.trimEnd());
      current = "";
    }
    if (visibleLength(word) > width) {
      let rest = word;
      while (visibleLength(rest) > width) {
        lines.push(truncateVisible(rest, width));
        rest = rest.slice(Math.max(1, width - 3));
      }
      current = rest;
      continue;
    }
    current = word.trimStart();
  }
  if (current.trim()) lines.push(current.trimEnd());
  return lines;
}
