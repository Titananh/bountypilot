import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { workspacePaths } from "../../core/workspace.js";
import type { ProviderChatMessage } from "../../providers/provider-chat-client.js";
import { BountyPilotError } from "../../utils/errors.js";
import type { TuiMode } from "./state.js";

export interface TuiSessionRecord {
  id: string;
  title: string;
  cwd: string;
  providerId?: string;
  model?: string;
  mode: TuiMode;
  contextFiles?: string[];
  messages: ProviderChatMessage[];
  createdAt: string;
  updatedAt: string;
}

export interface TuiSessionSummary {
  id: string;
  title: string;
  providerId?: string;
  model?: string;
  mode: TuiMode;
  messages: number;
  updatedAt: string;
}

export class TuiSessionStore {
  readonly dir: string;

  constructor(private readonly cwd = process.cwd()) {
    this.dir = path.join(workspacePaths(cwd).root, "sessions");
  }

  create(input: Partial<Pick<TuiSessionRecord, "title" | "providerId" | "model" | "mode" | "contextFiles" | "messages">> = {}): TuiSessionRecord {
    const now = new Date().toISOString();
    const record: TuiSessionRecord = {
      id: `session-${now.replace(/[^0-9]/g, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`,
      title: input.title ?? "New bounty session",
      cwd: this.cwd,
      providerId: input.providerId,
      model: input.model,
      mode: input.mode ?? "chat",
      contextFiles: input.contextFiles ?? [],
      messages: input.messages ?? [],
      createdAt: now,
      updatedAt: now,
    };
    this.write(record);
    return record;
  }

  list(): TuiSessionSummary[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir)
      .filter((file) => file.endsWith(".json"))
      .map((file) => this.read(path.basename(file, ".json")))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
      .map((record) => ({
        id: record.id,
        title: record.title,
        providerId: record.providerId,
        model: record.model,
        mode: record.mode,
        messages: record.messages.length,
        updatedAt: record.updatedAt,
      }));
  }

  read(id: string): TuiSessionRecord {
    const file = this.filePath(id);
    if (!existsSync(file)) {
      throw new BountyPilotError(`TUI session not found: ${id}`, "TUI_SESSION_NOT_FOUND");
    }
    const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
    if (!isTuiSessionRecord(parsed)) {
      throw new BountyPilotError(`Invalid TUI session file: ${file}`, "TUI_SESSION_INVALID");
    }
    return parsed;
  }

  update(id: string, patch: Partial<Omit<TuiSessionRecord, "id" | "createdAt">>): TuiSessionRecord {
    const record = this.read(id);
    const next: TuiSessionRecord = {
      ...record,
      ...patch,
      id: record.id,
      createdAt: record.createdAt,
      updatedAt: new Date().toISOString(),
    };
    this.write(next);
    return next;
  }

  delete(id: string): void {
    const file = this.filePath(id);
    if (existsSync(file)) rmSync(file);
  }

  private write(record: TuiSessionRecord): void {
    mkdirSync(this.dir, { recursive: true });
    writeFileSync(this.filePath(record.id), `${JSON.stringify(redactSession(record), null, 2)}\n`, "utf8");
  }

  private filePath(id: string): string {
    if (!/^session-[a-zA-Z0-9-]+$/.test(id)) {
      throw new BountyPilotError(`Invalid TUI session id: ${id}`, "TUI_SESSION_ID_INVALID");
    }
    return path.join(this.dir, `${id}.json`);
  }
}

function redactSession(record: TuiSessionRecord): TuiSessionRecord {
  return {
    ...record,
    messages: record.messages.map((message) => ({
      role: message.role,
      content: message.content.replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "sk-***"),
    })),
  };
}

function isTuiSessionRecord(value: unknown): value is TuiSessionRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as TuiSessionRecord;
  return (
    typeof record.id === "string" &&
    typeof record.title === "string" &&
    typeof record.cwd === "string" &&
    typeof record.mode === "string" &&
    Array.isArray(record.messages) &&
    typeof record.createdAt === "string" &&
    typeof record.updatedAt === "string"
  );
}
