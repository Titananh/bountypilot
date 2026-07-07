import type { TuiMode } from "./state.js";

export type TuiThemeId = "opencode" | "system" | "tokyonight" | "matrix";

export interface TuiTheme {
  id: TuiThemeId;
  name: string;
  description: string;
  accent: string;
  secondary: string;
  success: string;
  warning: string;
  error: string;
  muted: string;
  border: string;
  surface: string;
  mode: Record<TuiMode, string>;
}

export const TUI_THEMES: TuiTheme[] = [
  {
    id: "opencode",
    name: "Opencode",
    description: "Clean magenta/cyan terminal palette.",
    accent: "magentaBright",
    secondary: "cyan",
    success: "green",
    warning: "yellow",
    error: "red",
    muted: "gray",
    border: "gray",
    surface: "blackBright",
    mode: {
      chat: "cyan",
      plan: "yellow",
      hunt: "magentaBright",
      review: "green",
    },
  },
  {
    id: "system",
    name: "System",
    description: "Uses conservative ANSI colors for broad terminals.",
    accent: "white",
    secondary: "blueBright",
    success: "green",
    warning: "yellow",
    error: "red",
    muted: "gray",
    border: "gray",
    surface: "blackBright",
    mode: {
      chat: "blueBright",
      plan: "yellow",
      hunt: "white",
      review: "green",
    },
  },
  {
    id: "tokyonight",
    name: "Tokyonight",
    description: "Blue and purple contrast for dark terminals.",
    accent: "blueBright",
    secondary: "magenta",
    success: "greenBright",
    warning: "yellow",
    error: "redBright",
    muted: "gray",
    border: "blue",
    surface: "blackBright",
    mode: {
      chat: "blueBright",
      plan: "yellow",
      hunt: "magenta",
      review: "greenBright",
    },
  },
  {
    id: "matrix",
    name: "Matrix",
    description: "High-contrast green terminal style.",
    accent: "greenBright",
    secondary: "green",
    success: "greenBright",
    warning: "yellow",
    error: "red",
    muted: "gray",
    border: "green",
    surface: "blackBright",
    mode: {
      chat: "greenBright",
      plan: "yellow",
      hunt: "green",
      review: "cyan",
    },
  },
];

export function themeById(id?: string): TuiTheme {
  return TUI_THEMES.find((theme) => theme.id === id) ?? TUI_THEMES[0]!;
}

export function nextThemeId(id: TuiThemeId): TuiThemeId {
  const index = TUI_THEMES.findIndex((theme) => theme.id === id);
  return TUI_THEMES[(index + 1) % TUI_THEMES.length]!.id;
}
