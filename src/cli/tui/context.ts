import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { maskSecrets } from "../../utils/secrets.js";
import { BountyPilotError } from "../../utils/errors.js";

export interface ContextFileEntry {
  path: string;
  size: number;
  kind: string;
}

const SKIPPED_DIRS = new Set([
  ".bounty",
  ".cache",
  ".git",
  ".next",
  "coverage",
  "dist",
  "node_modules",
  "tmp",
]);

export function listContextFiles(cwd: string, query = "", limit = 80): ContextFileEntry[] {
  const root = path.resolve(cwd);
  const normalizedQuery = normalizeQuery(query);
  const results: ContextFileEntry[] = [];
  walk(root, root, normalizedQuery, results, limit, 0);
  return results.sort((left, right) => rankPath(left.path, normalizedQuery) - rankPath(right.path, normalizedQuery));
}

export function buildContextPrompt(cwd: string, files: string[], maxBytesPerFile = 12_000): string {
  const uniqueFiles = [...new Set(files)].slice(0, 8);
  if (uniqueFiles.length === 0) return "";
  const blocks = uniqueFiles.map((file) => {
    const text = readContextFile(cwd, file, maxBytesPerFile);
    return [`--- ${file} ---`, text].join("\n");
  });
  return ["Attached local context files:", ...blocks].join("\n\n");
}

function readContextFile(cwd: string, relativePath: string, maxBytes: number): string {
  const root = path.resolve(cwd);
  const resolved = path.resolve(root, relativePath);
  if (!isInside(root, resolved)) {
    throw new BountyPilotError(`Context file escapes project root: ${relativePath}`, "TUI_CONTEXT_OUTSIDE_ROOT");
  }
  const stat = statSync(resolved);
  if (!stat.isFile()) {
    throw new BountyPilotError(`Context path is not a file: ${relativePath}`, "TUI_CONTEXT_NOT_FILE");
  }
  const raw = readFileSync(resolved);
  const bounded = raw.subarray(0, maxBytes).toString("utf8");
  const suffix = raw.length > maxBytes ? "\n[truncated]" : "";
  return `${redactContextText(bounded)}${suffix}`;
}

function walk(
  root: string,
  dir: string,
  query: string,
  output: ContextFileEntry[],
  limit: number,
  depth: number,
): void {
  if (output.length >= limit || depth > 5) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (output.length >= limit) return;
    if (entry.name.startsWith(".") && entry.name !== ".env.example") {
      continue;
    }
    const absolute = path.join(dir, entry.name);
    const relative = path.relative(root, absolute).replace(/\\/g, "/");
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) {
        walk(root, absolute, query, output, limit, depth + 1);
      }
      continue;
    }
    if (!entry.isFile() || !isUsefulFile(relative, query)) {
      continue;
    }
    try {
      const stat = statSync(absolute);
      output.push({ path: relative, size: stat.size, kind: path.extname(relative).replace(/^\./, "") || "file" });
    } catch {
      // Ignore files that disappear during listing.
    }
  }
}

function isUsefulFile(relative: string, query: string): boolean {
  const normalized = relative.toLowerCase();
  if (/\.(png|jpg|jpeg|gif|webp|ico|exe|dll|bin|zip|tgz|mp4|mov)$/i.test(relative)) return false;
  if (!query) return true;
  return normalizeQuery(normalized).includes(query);
}

function rankPath(relative: string, query: string): number {
  if (!query) return relative.split("/").length;
  const normalized = normalizeQuery(relative);
  if (normalized === query) return 0;
  if (normalized.startsWith(query)) return 1;
  const basename = normalizeQuery(path.basename(relative));
  if (basename.startsWith(query)) return 2;
  return 3 + normalized.indexOf(query);
}

function normalizeQuery(value: string): string {
  return value.trim().toLowerCase().replace(/^@/, "");
}

function isInside(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function redactContextText(value: string): string {
  return maskSecrets(value)
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "sk-***")
    .replace(/\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{12,}\b/g, "github_***");
}
