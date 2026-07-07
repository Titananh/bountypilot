import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { parse } from "yaml";

export interface TuiCustomCommand {
  id: string;
  title: string;
  description: string;
  prompt: string;
  sourcePath: string;
  model?: string;
  agent?: string;
  subtask?: boolean;
}

interface ParsedCommandFile {
  frontmatter: Record<string, unknown>;
  body: string;
}

const COMMAND_DIRS = [path.join(".bounty", "commands"), path.join(".opencode", "commands"), "commands"];
const MAX_COMMAND_FILE_BYTES = 64 * 1024;
const MAX_COMMANDS = 80;

export function loadCustomCommands(cwd: string): TuiCustomCommand[] {
  const byId = new Map<string, TuiCustomCommand>();
  for (const relativeDir of COMMAND_DIRS) {
    const dir = path.join(cwd, relativeDir);
    for (const file of listMarkdownFiles(dir)) {
      const command = loadCommandFile(cwd, file);
      if (command && !byId.has(command.id)) byId.set(command.id, command);
      if (byId.size >= MAX_COMMANDS) return [...byId.values()];
    }
  }
  return [...byId.values()].sort((left, right) => left.id.localeCompare(right.id));
}

export function renderCustomCommandPrompt(command: TuiCustomCommand, args: string): string {
  const trimmedArgs = args.trim();
  const replacements: Record<string, string> = {
    "$ARGUMENTS": trimmedArgs,
    "{{args}}": trimmedArgs,
    "{{arguments}}": trimmedArgs,
  };
  let prompt = command.prompt;
  for (const [needle, value] of Object.entries(replacements)) {
    prompt = prompt.split(needle).join(value);
  }
  return prompt.trim();
}

function listMarkdownFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const files: string[] = [];
  walk(dir, files);
  return files.sort();
}

function walk(dir: string, files: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(entryPath, files);
      continue;
    }
    if (entry.isFile() && /\.md$/i.test(entry.name)) files.push(entryPath);
  }
}

function loadCommandFile(cwd: string, file: string): TuiCustomCommand | undefined {
  const stats = statSync(file);
  if (stats.size <= 0 || stats.size > MAX_COMMAND_FILE_BYTES) return undefined;
  const parsed = parseCommandFile(readFileSync(file, "utf8"));
  const prompt = parsed.body.trim();
  if (!prompt) return undefined;
  const relative = path.relative(cwd, file).replace(/\\/g, "/");
  const id = commandIdFromPath(relative);
  if (!id) return undefined;
  const title = stringValue(parsed.frontmatter.title) ?? id.slice(1);
  const description = stringValue(parsed.frontmatter.description) ?? firstPromptLine(prompt) ?? "Custom local command";
  return {
    id,
    title,
    description,
    prompt,
    sourcePath: relative,
    model: stringValue(parsed.frontmatter.model),
    agent: stringValue(parsed.frontmatter.agent),
    subtask: booleanValue(parsed.frontmatter.subtask),
  };
}

function parseCommandFile(raw: string): ParsedCommandFile {
  if (!raw.startsWith("---")) return { frontmatter: {}, body: raw };
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/m.exec(raw);
  if (!match) return { frontmatter: {}, body: raw };
  try {
    const frontmatter = parse(match[1] ?? "") as unknown;
    return {
      frontmatter: frontmatter && typeof frontmatter === "object" && !Array.isArray(frontmatter) ? frontmatter as Record<string, unknown> : {},
      body: match[2] ?? "",
    };
  } catch {
    return { frontmatter: {}, body: match[2] ?? "" };
  }
}

function commandIdFromPath(relative: string): string | undefined {
  const normalized = relative
    .replace(/\\/g, "/")
    .replace(/^(?:\.bounty\/commands|\.opencode\/commands|commands)\//, "")
    .replace(/\.md$/i, "")
    .toLowerCase()
    .replace(/[^a-z0-9/_-]+/g, "-")
    .replace(/\/+/g, ":")
    .replace(/-+/g, "-")
    .replace(/^[-:]+|[-:]+$/g, "");
  if (!normalized || normalized.length > 80) return undefined;
  return `/${normalized}`;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function firstPromptLine(prompt: string): string | undefined {
  return prompt
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean)
    ?.slice(0, 120);
}
