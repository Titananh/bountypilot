import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { workspacePaths } from "../../core/workspace.js";
import { type TuiThemeId, themeById } from "./theme.js";

export interface TuiSettings {
  theme: TuiThemeId;
  details: boolean;
  thinking: boolean;
  recentModels: string[];
}

const DEFAULT_SETTINGS: TuiSettings = {
  theme: "opencode",
  details: true,
  thinking: false,
  recentModels: [],
};

export class TuiSettingsStore {
  readonly file: string;

  constructor(cwd = process.cwd()) {
    this.file = path.join(workspacePaths(cwd).root, "tui", "settings.json");
  }

  read(): TuiSettings {
    if (!existsSync(this.file)) return { ...DEFAULT_SETTINGS };
    try {
      const parsed = JSON.parse(readFileSync(this.file, "utf8")) as Partial<TuiSettings>;
      return normalizeSettings(parsed);
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }

  write(settings: TuiSettings): TuiSettings {
    const normalized = normalizeSettings(settings);
    mkdirSync(path.dirname(this.file), { recursive: true });
    writeFileSync(this.file, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
    return normalized;
  }

  update(patch: Partial<TuiSettings>): TuiSettings {
    return this.write({ ...this.read(), ...patch });
  }
}

function normalizeSettings(value: Partial<TuiSettings>): TuiSettings {
  return {
    theme: themeById(value.theme).id,
    details: typeof value.details === "boolean" ? value.details : DEFAULT_SETTINGS.details,
    thinking: typeof value.thinking === "boolean" ? value.thinking : DEFAULT_SETTINGS.thinking,
    recentModels: normalizeRecentModels(value.recentModels),
  };
}

function normalizeRecentModels(value: unknown): string[] {
  if (!Array.isArray(value)) return [...DEFAULT_SETTINGS.recentModels];
  return [...new Set(value.filter((entry): entry is string => typeof entry === "string").map((entry) => entry.trim()).filter(Boolean))].slice(0, 12);
}
