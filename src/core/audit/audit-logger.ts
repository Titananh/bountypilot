import { mkdirSync, appendFileSync } from "node:fs";
import path from "node:path";
import { maskSecretsDeep } from "../../utils/secrets.js";
import { nowIso } from "../../utils/time.js";

export interface AuditEvent {
  timestamp?: string;
  jobId?: string;
  actionType: string;
  method?: string;
  url?: string;
  status?: number | string;
  durationMs?: number;
  toolName?: string;
  adapterName?: string;
  findingId?: string;
  policyDecision?: string;
  reason?: string;
  metadata?: Record<string, unknown>;
}

export class AuditLogger {
  constructor(private readonly auditFile: string) {
    mkdirSync(path.dirname(auditFile), { recursive: true });
  }

  log(event: AuditEvent): void {
    const safeEvent = maskSecretsDeep({
      ...event,
      timestamp: event.timestamp ?? nowIso(),
    });
    appendFileSync(this.auditFile, `${JSON.stringify(safeEvent)}\n`, "utf8");
  }
}
