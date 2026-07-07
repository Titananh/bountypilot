import { BountyPilotError } from "../utils/errors.js";
import { ProviderManager, type ProviderSummary } from "./provider-manager.js";

export type ProviderChatRole = "system" | "user" | "assistant";

export interface ProviderChatMessage {
  role: ProviderChatRole;
  content: string;
}

export interface ProviderChatInput {
  providerId?: string;
  model?: string;
  messages: ProviderChatMessage[];
  temperature?: number;
  maxTokens?: number;
}

export interface ProviderChatSession {
  provider: ProviderSummary;
  model: string;
}

export interface ProviderChatResult extends ProviderChatSession {
  message: string;
  usage?: Record<string, unknown>;
}

export class ProviderChatClient {
  constructor(private readonly manager: ProviderManager) {}

  resolveSession(input: { providerId?: string; model?: string } = {}): ProviderChatSession {
    const provider = input.providerId ? this.manager.get(input.providerId) : this.defaultProvider();
    if (provider.status !== "configured") {
      throw new BountyPilotError(
        `Provider ${provider.id} is not ready for chat: ${provider.message}`,
        "PROVIDER_CHAT_NOT_READY",
      );
    }
    const model = input.model ?? provider.model ?? provider.models[0];
    if (!model) {
      throw new BountyPilotError(`Provider ${provider.id} has no model configured.`, "PROVIDER_CHAT_MODEL_MISSING");
    }
    if (!provider.baseURL) {
      throw new BountyPilotError(`Provider ${provider.id} has no base URL configured.`, "PROVIDER_CHAT_BASE_URL_MISSING");
    }
    return { provider, model };
  }

  async complete(input: ProviderChatInput): Promise<ProviderChatResult> {
    const session = this.resolveSession({ providerId: input.providerId, model: input.model });
    const auth = this.manager.resolveAuth(session.provider.id);
    if (isAnthropicProvider(session.provider)) {
      return this.completeAnthropic(session, auth, input);
    }
    return this.completeOpenAICompatible(session, auth, input);
  }

  private defaultProvider(): ProviderSummary {
    const providers = this.manager.list().filter((provider) => provider.status === "configured");
    if (providers.length === 0) {
      throw new BountyPilotError(
        "No chat provider is configured. Run `bugbounty providers catalog`, then `bugbounty providers connect <id>`.",
        "PROVIDER_CHAT_NOT_CONFIGURED",
      );
    }
    return providers[0]!;
  }

  private async completeOpenAICompatible(
    session: ProviderChatSession,
    auth: string | undefined,
    input: ProviderChatInput,
  ): Promise<ProviderChatResult> {
    const response = await fetch(`${session.provider.baseURL!.replace(/\/+$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(auth ? { authorization: `Bearer ${auth}` } : {}),
      },
      body: JSON.stringify({
        model: session.model,
        messages: input.messages,
        temperature: input.temperature,
        max_tokens: input.maxTokens,
      }),
      signal: AbortSignal.timeout(session.provider.timeoutMs ?? 60_000),
    });
    const body = await readProviderJson(response);
    if (!response.ok) {
      throw providerHttpError(response, body);
    }
    const message = openAIMessageContent(body);
    if (!message) {
      throw new BountyPilotError("Provider response did not contain assistant message content.", "PROVIDER_CHAT_RESPONSE_INVALID");
    }
    return { ...session, message, usage: objectValue(body, "usage") };
  }

  private async completeAnthropic(
    session: ProviderChatSession,
    auth: string | undefined,
    input: ProviderChatInput,
  ): Promise<ProviderChatResult> {
    if (!auth) {
      throw new BountyPilotError(`Provider ${session.provider.id} requires an API key for chat.`, "PROVIDER_CHAT_AUTH_MISSING");
    }
    const system = input.messages.find((message) => message.role === "system")?.content;
    const messages = input.messages
      .filter((message) => message.role !== "system")
      .map((message) => ({ role: message.role, content: message.content }));
    const response = await fetch(`${session.provider.baseURL!.replace(/\/+$/, "")}/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": auth,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: session.model,
        system,
        messages,
        temperature: input.temperature,
        max_tokens: input.maxTokens ?? 1200,
      }),
      signal: AbortSignal.timeout(session.provider.timeoutMs ?? 60_000),
    });
    const body = await readProviderJson(response);
    if (!response.ok) {
      throw providerHttpError(response, body);
    }
    const message = anthropicMessageContent(body);
    if (!message) {
      throw new BountyPilotError("Provider response did not contain assistant message content.", "PROVIDER_CHAT_RESPONSE_INVALID");
    }
    return { ...session, message, usage: objectValue(body, "usage") };
  }
}

function isAnthropicProvider(provider: ProviderSummary): boolean {
  return provider.id === "anthropic" || /api\.anthropic\.com/i.test(provider.baseURL ?? "");
}

async function readProviderJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { text };
  }
}

function providerHttpError(response: Response, body: unknown): BountyPilotError {
  const message = providerErrorMessage(body) ?? response.statusText;
  return new BountyPilotError(`Provider chat returned HTTP ${response.status}: ${message}`, "PROVIDER_CHAT_HTTP_ERROR");
}

function providerErrorMessage(body: unknown): string | undefined {
  if (!isRecord(body)) return undefined;
  const error = body.error;
  if (isRecord(error) && typeof error.message === "string") return error.message;
  if (typeof body.message === "string") return body.message;
  if (typeof body.text === "string") return body.text.slice(0, 500);
  return undefined;
}

function openAIMessageContent(body: unknown): string | undefined {
  const choices = isRecord(body) && Array.isArray(body.choices) ? body.choices : [];
  const first = choices[0];
  if (!isRecord(first) || !isRecord(first.message)) return undefined;
  return contentToText(first.message.content);
}

function anthropicMessageContent(body: unknown): string | undefined {
  if (!isRecord(body) || !Array.isArray(body.content)) return undefined;
  return body.content
    .map((item) => (isRecord(item) && item.type === "text" ? item.text : undefined))
    .filter((text): text is string => typeof text === "string")
    .join("\n")
    .trim();
}

function contentToText(content: unknown): string | undefined {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return undefined;
  const text = content
    .map((item) => {
      if (typeof item === "string") return item;
      if (!isRecord(item)) return undefined;
      if (typeof item.text === "string") return item.text;
      if (typeof item.content === "string") return item.content;
      return undefined;
    })
    .filter((item): item is string => Boolean(item))
    .join("\n")
    .trim();
  return text || undefined;
}

function objectValue(value: unknown, key: string): Record<string, unknown> | undefined {
  if (!isRecord(value)) return undefined;
  const nested = value[key];
  return isRecord(nested) ? nested : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
