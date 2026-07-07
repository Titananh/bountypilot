import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { BountyPilotError } from "../utils/errors.js";
import { workspacePaths } from "../core/workspace.js";

export type ProviderType = "known" | "openai-compatible" | "local";
export type ProviderStatus = "configured" | "missing_auth" | "disabled" | "missing_config";
export type ProviderAuthKind = "api_key" | "env" | "none";

export interface ProviderCatalogEntry {
  id: string;
  displayName: string;
  type: ProviderType;
  authEnv?: string;
  baseURL?: string;
  defaultModel?: string;
  models: string[];
  notes: string;
}

export interface ProviderConfig {
  id: string;
  type: ProviderType;
  enabled: boolean;
  baseURL?: string;
  model?: string;
  models: string[];
  timeoutMs?: number;
  createdAt: string;
  updatedAt: string;
}

interface StoredProviderAuth {
  type: ProviderAuthKind;
  key?: string;
  env?: string;
  createdAt: string;
  updatedAt: string;
}

interface ProviderStoreFile {
  version: 1;
  providers: Record<string, ProviderConfig>;
}

interface ProviderAuthFile {
  version: 1;
  providers: Record<string, StoredProviderAuth>;
}

export interface ProviderAuthSummary {
  type: ProviderAuthKind | "missing";
  source?: string;
  present: boolean;
}

export interface ProviderSummary {
  id: string;
  displayName: string;
  type: ProviderType;
  enabled: boolean;
  status: ProviderStatus;
  message: string;
  baseURL?: string;
  model?: string;
  models: string[];
  timeoutMs?: number;
  auth: ProviderAuthSummary;
  configPath: string;
  authPath: string;
}

export interface ProviderConnectInput {
  id: string;
  apiKey?: string;
  apiKeyEnv?: string;
  model?: string;
  baseURL?: string;
  openaiCompatible?: boolean;
  local?: boolean;
  disabled?: boolean;
  timeoutMs?: number;
  models?: string[];
}

export interface ProviderConnectResult {
  ok: boolean;
  provider: ProviderSummary;
  configPath: string;
  authPath: string;
  nextCommands: string[];
  warnings: string[];
}

export interface ProviderVerifyResult {
  ok: boolean;
  provider: ProviderSummary;
  checks: Array<{ name: string; status: "pass" | "warn" | "fail"; message: string }>;
  live?: {
    ok: boolean;
    status?: number;
    models?: number;
    message: string;
  };
  nextCommands: string[];
}

export const PROVIDER_CATALOG: ProviderCatalogEntry[] = [
  {
    id: "openai",
    displayName: "OpenAI",
    type: "known",
    authEnv: "OPENAI_API_KEY",
    baseURL: "https://api.openai.com/v1",
    defaultModel: "gpt-4.1-mini",
    models: ["gpt-4.1-mini", "gpt-4o-mini"],
    notes: "OpenAI API-compatible provider.",
  },
  {
    id: "anthropic",
    displayName: "Anthropic",
    type: "known",
    authEnv: "ANTHROPIC_API_KEY",
    baseURL: "https://api.anthropic.com/v1",
    defaultModel: "claude-sonnet-4-20250514",
    models: ["claude-sonnet-4-20250514", "claude-3-5-haiku-latest"],
    notes: "Known provider entry; live model checks are skipped unless the API exposes OpenAI-compatible /models.",
  },
  {
    id: "gemini",
    displayName: "Google Gemini",
    type: "known",
    authEnv: "GEMINI_API_KEY",
    baseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
    defaultModel: "gemini-2.5-flash",
    models: ["gemini-2.5-flash", "gemini-2.5-pro"],
    notes: "Gemini OpenAI-compatible endpoint.",
  },
  {
    id: "openrouter",
    displayName: "OpenRouter",
    type: "known",
    authEnv: "OPENROUTER_API_KEY",
    baseURL: "https://openrouter.ai/api/v1",
    defaultModel: "anthropic/claude-sonnet-4",
    models: ["anthropic/claude-sonnet-4", "google/gemini-2.5-flash", "openai/gpt-4.1-mini"],
    notes: "OpenAI-compatible router provider.",
  },
  {
    id: "ollama",
    displayName: "Ollama",
    type: "local",
    baseURL: "http://127.0.0.1:11434/v1",
    defaultModel: "llama3.1",
    models: ["llama3.1", "qwen2.5-coder", "mistral"],
    notes: "Local OpenAI-compatible server; no API key required by default.",
  },
];

export class ProviderManager {
  readonly configPath: string;
  readonly authPath: string;

  constructor(private readonly cwd = process.cwd()) {
    const paths = workspacePaths(cwd);
    this.configPath = path.join(paths.providersDir, "providers.json");
    this.authPath = path.join(paths.providersDir, "auth.json");
  }

  catalog(): ProviderCatalogEntry[] {
    return [...PROVIDER_CATALOG];
  }

  connect(input: ProviderConnectInput): ProviderConnectResult {
    const id = normalizeProviderId(input.id);
    const catalog = providerCatalogEntry(id);
    const now = new Date().toISOString();
    const store = this.readStore();
    const authStore = this.readAuthStore();
    const type = input.local ? "local" : input.openaiCompatible || !catalog ? "openai-compatible" : catalog.type;
    const baseURL = normalizeBaseURL(input.baseURL ?? catalog?.baseURL);
    const models = uniqueNonEmpty([...(input.models ?? []), input.model, ...(catalog?.models ?? [])]);
    const model = input.model ?? catalog?.defaultModel ?? models[0];
    const warnings: string[] = [];

    if (type !== "local" && !baseURL) {
      throw new BountyPilotError("Custom providers require --base-url.", "PROVIDER_BASE_URL_REQUIRED");
    }
    if (type !== "local" && !input.apiKey && !input.apiKeyEnv && !catalog?.authEnv) {
      throw new BountyPilotError("Provider credentials require --api-key, --api-key-stdin, or --api-key-env.", "PROVIDER_AUTH_REQUIRED");
    }

    const previous = store.providers[id];
    store.providers[id] = {
      id,
      type,
      enabled: input.disabled === true ? false : previous?.enabled ?? true,
      baseURL,
      model,
      models,
      timeoutMs: input.timeoutMs ?? previous?.timeoutMs,
      createdAt: previous?.createdAt ?? now,
      updatedAt: now,
    };

    const previousAuth = authStore.providers[id];
    if (type === "local") {
      authStore.providers[id] = {
        type: "none",
        createdAt: previousAuth?.createdAt ?? now,
        updatedAt: now,
      };
    } else if (input.apiKey) {
      authStore.providers[id] = {
        type: "api_key",
        key: input.apiKey.trim(),
        createdAt: previousAuth?.createdAt ?? now,
        updatedAt: now,
      };
    } else {
      const env = input.apiKeyEnv ?? previousAuth?.env ?? catalog?.authEnv;
      authStore.providers[id] = {
        type: "env",
        env,
        createdAt: previousAuth?.createdAt ?? now,
        updatedAt: now,
      };
      if (env && !process.env[env]) {
        warnings.push(`Environment variable ${env} is not set in the current shell.`);
      }
    }

    this.writeStore(store);
    this.writeAuthStore(authStore);
    const provider = this.get(id);
    return {
      ok: provider.status === "configured",
      provider,
      configPath: this.configPath,
      authPath: this.authPath,
      nextCommands: providerNextCommands(provider),
      warnings,
    };
  }

  list(): ProviderSummary[] {
    const store = this.readStore();
    return Object.keys(store.providers)
      .sort((left, right) => left.localeCompare(right))
      .map((id) => this.get(id));
  }

  get(id: string): ProviderSummary {
    const providerId = normalizeProviderId(id);
    const store = this.readStore();
    const config = store.providers[providerId];
    if (!config) {
      throw new BountyPilotError(`Provider not found: ${providerId}`, "PROVIDER_NOT_FOUND");
    }
    return this.summary(config);
  }

  models(id?: string): Array<{ provider: string; model: string; selected: boolean }> {
    if (id) {
      const provider = this.get(id);
      return provider.models.map((model) => ({ provider: provider.id, model, selected: model === provider.model }));
    }
    return this.list().flatMap((provider) =>
      provider.models.map((model) => ({ provider: provider.id, model, selected: model === provider.model })),
    );
  }

  doctor(): ProviderVerifyResult[] {
    return this.list().map((provider) => this.verify(provider.id));
  }

  verify(id: string): ProviderVerifyResult {
    const provider = this.get(id);
    const checks: ProviderVerifyResult["checks"] = [
      {
        name: "enabled",
        status: provider.enabled ? "pass" : "warn",
        message: provider.enabled ? "provider is enabled" : "provider is disabled",
      },
      {
        name: "base_url",
        status: provider.type === "local" || provider.baseURL ? "pass" : "fail",
        message: provider.baseURL ?? "base URL is required",
      },
      {
        name: "model",
        status: provider.model ? "pass" : "warn",
        message: provider.model ?? "no default model selected",
      },
      {
        name: "auth",
        status: provider.auth.present ? "pass" : provider.type === "local" ? "pass" : "fail",
        message: authMessage(provider.auth),
      },
    ];
    return {
      ok: checks.every((check) => check.status !== "fail"),
      provider,
      checks,
      nextCommands: providerNextCommands(provider),
    };
  }

  async verifyLive(id: string): Promise<ProviderVerifyResult> {
    const result = this.verify(id);
    const provider = result.provider;
    if (!result.ok) {
      return result;
    }
    if (!provider.baseURL) {
      result.live = { ok: false, message: "Provider has no base URL to verify." };
      result.ok = false;
      return result;
    }
    try {
      const auth = this.readResolvedAuth(provider.id);
      const response = await fetch(`${provider.baseURL.replace(/\/+$/, "")}/models`, {
        method: "GET",
        headers: auth ? { authorization: `Bearer ${auth}` } : {},
        signal: AbortSignal.timeout(provider.timeoutMs ?? 10_000),
      });
      const body = await response.json().catch(() => undefined) as { data?: unknown[] } | undefined;
      result.live = {
        ok: response.ok,
        status: response.status,
        models: Array.isArray(body?.data) ? body.data.length : undefined,
        message: response.ok ? "live provider model endpoint responded" : `live provider check returned HTTP ${response.status}`,
      };
      result.ok = result.ok && response.ok;
      result.checks.push({
        name: "live_models",
        status: response.ok ? "pass" : "fail",
        message: result.live.message,
      });
      return result;
    } catch (error) {
      result.live = {
        ok: false,
        message: error instanceof Error ? error.message : String(error),
      };
      result.ok = false;
      result.checks.push({ name: "live_models", status: "fail", message: result.live.message });
      return result;
    }
  }

  resolveAuth(id: string): string | undefined {
    const provider = this.get(id);
    return this.readResolvedAuth(provider.id);
  }

  disconnect(id: string): { ok: true; provider: string; configPath: string; authPath: string } {
    const providerId = normalizeProviderId(id);
    const store = this.readStore();
    const authStore = this.readAuthStore();
    if (!store.providers[providerId] && !authStore.providers[providerId]) {
      throw new BountyPilotError(`Provider not found: ${providerId}`, "PROVIDER_NOT_FOUND");
    }
    delete store.providers[providerId];
    delete authStore.providers[providerId];
    this.writeStore(store);
    this.writeAuthStore(authStore);
    return { ok: true, provider: providerId, configPath: this.configPath, authPath: this.authPath };
  }

  private summary(config: ProviderConfig): ProviderSummary {
    const catalog = providerCatalogEntry(config.id);
    const auth = this.authSummary(config.id, config.type);
    const status = providerStatus(config, auth);
    return {
      id: config.id,
      displayName: catalog?.displayName ?? config.id,
      type: config.type,
      enabled: config.enabled,
      status,
      message: providerStatusMessage(status, auth),
      baseURL: config.baseURL,
      model: config.model,
      models: config.models,
      timeoutMs: config.timeoutMs,
      auth,
      configPath: this.configPath,
      authPath: this.authPath,
    };
  }

  private authSummary(id: string, type: ProviderType): ProviderAuthSummary {
    if (type === "local") {
      return { type: "none", present: true };
    }
    const auth = this.readAuthStore().providers[id];
    if (!auth) {
      return { type: "missing", present: false };
    }
    if (auth.type === "api_key") {
      return { type: "api_key", source: this.authPath, present: Boolean(auth.key?.trim()) };
    }
    if (auth.type === "env") {
      return { type: "env", source: auth.env, present: Boolean(auth.env && process.env[auth.env]) };
    }
    return { type: "none", present: false };
  }

  private readResolvedAuth(id: string): string | undefined {
    const auth = this.readAuthStore().providers[id];
    if (!auth) return undefined;
    if (auth.type === "api_key") return auth.key;
    if (auth.type === "env" && auth.env) return process.env[auth.env];
    return undefined;
  }

  private readStore(): ProviderStoreFile {
    if (!existsSync(this.configPath)) {
      return { version: 1, providers: {} };
    }
    const parsed = JSON.parse(readFileSync(this.configPath, "utf8")) as unknown;
    if (!isProviderStoreFile(parsed)) {
      throw new BountyPilotError(`Invalid provider config file: ${this.configPath}`, "PROVIDER_CONFIG_INVALID");
    }
    return parsed;
  }

  private readAuthStore(): ProviderAuthFile {
    if (!existsSync(this.authPath)) {
      return { version: 1, providers: {} };
    }
    const parsed = JSON.parse(readFileSync(this.authPath, "utf8")) as unknown;
    if (!isProviderAuthFile(parsed)) {
      throw new BountyPilotError(`Invalid provider auth file: ${this.authPath}`, "PROVIDER_AUTH_INVALID");
    }
    return parsed;
  }

  private writeStore(store: ProviderStoreFile): void {
    mkdirSync(path.dirname(this.configPath), { recursive: true });
    writeFileSync(this.configPath, `${JSON.stringify(store, null, 2)}\n`, "utf8");
  }

  private writeAuthStore(store: ProviderAuthFile): void {
    mkdirSync(path.dirname(this.authPath), { recursive: true });
    writeFileSync(this.authPath, `${JSON.stringify(store, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  }
}

export function normalizeProviderId(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!normalized) {
    throw new BountyPilotError("Provider id is required.", "PROVIDER_ID_INVALID");
  }
  return normalized;
}

function providerCatalogEntry(id: string): ProviderCatalogEntry | undefined {
  return PROVIDER_CATALOG.find((entry) => entry.id === id);
}

function providerStatus(config: ProviderConfig, auth: ProviderAuthSummary): ProviderStatus {
  if (!config.enabled) return "disabled";
  if (config.type !== "local" && !auth.present) return "missing_auth";
  if (config.type !== "local" && !config.baseURL) return "missing_config";
  return "configured";
}

function providerStatusMessage(status: ProviderStatus, auth: ProviderAuthSummary): string {
  if (status === "configured") return "provider is ready for guarded API use";
  if (status === "disabled") return "provider is configured but disabled";
  if (status === "missing_auth") return `credential is missing (${auth.source ?? "no auth source"})`;
  return "provider configuration is incomplete";
}

function providerNextCommands(provider: ProviderSummary): string[] {
  const commands = [
    `bounty providers show ${provider.id}`,
    `bounty providers models ${provider.id}`,
    `bounty providers verify ${provider.id}`,
    "bounty providers doctor",
  ];
  if (!provider.auth.present && provider.auth.type === "env" && provider.auth.source) {
    commands.unshift(`set ${provider.auth.source}=<api-key>`);
  }
  if (provider.status === "configured") {
    commands.push(`bounty providers verify ${provider.id} --live`);
  }
  return [...new Set(commands)];
}

function authMessage(auth: ProviderAuthSummary): string {
  if (auth.type === "api_key") return auth.present ? "stored API key is present" : "stored API key is empty";
  if (auth.type === "env") return auth.present ? `environment variable ${auth.source} is set` : `environment variable ${auth.source ?? "-"} is missing`;
  if (auth.type === "none") return "no API key required";
  return "no provider credential found";
}

function normalizeBaseURL(value?: string): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  try {
    const url = new URL(trimmed);
    return url.toString().replace(/\/+$/, "");
  } catch {
    throw new BountyPilotError(`Invalid provider base URL: ${value}`, "PROVIDER_BASE_URL_INVALID");
  }
}

function uniqueNonEmpty(values: Array<string | undefined>): string[] {
  return [...new Set(values.map((value) => value?.trim()).filter((value): value is string => Boolean(value)))];
}

function isProviderStoreFile(value: unknown): value is ProviderStoreFile {
  return isRecord(value) && value.version === 1 && isRecord(value.providers);
}

function isProviderAuthFile(value: unknown): value is ProviderAuthFile {
  return isRecord(value) && value.version === 1 && isRecord(value.providers);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
