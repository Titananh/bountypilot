import type { Runtime } from "../../cli/runtime.js";
import type { ActionRecord } from "../../core/actions/action-queue.js";
import type { ExecutionMode } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";

export interface McpExecutionResult {
  message: string;
  evidenceCreated: number;
  findingsCreated: number;
}

export interface McpToolCallInput {
  server: string;
  tool: string;
  mode: ExecutionMode;
  target?: string;
  arguments?: Record<string, unknown>;
  jobId?: string;
  actionId?: string;
  /** Retained for source compatibility; it is never trusted by this class. */
  approvedAction?: boolean;
}

export interface McpSessionStepInput {
  tool: string;
  target?: string;
  arguments?: Record<string, unknown>;
  label?: string;
}

export interface McpSessionInput {
  server: string;
  mode: ExecutionMode;
  target?: string;
  steps: McpSessionStepInput[];
  jobId?: string;
}

const DISABLED_MESSAGE =
  "MCP stdio execution is disabled at the authoritative boundary; use the planning command and human handoff.";

/**
 * No process-spawning implementation lives behind this API.  MCP plans are
 * persisted by the CLI, and any future effect adapter must be registered in
 * production-action-authority and routed through ActionExecutor first.
 */
export class McpStdioExecutor {
  constructor(_runtime: Runtime) {}

  async executeAction(
    _action: ActionRecord,
    _scopedUrl: string | undefined,
    _mode: ExecutionMode,
  ): Promise<McpExecutionResult> {
    throw new BountyPilotError(DISABLED_MESSAGE, "MCP_EXECUTION_DISABLED");
  }

  async executeCall(_input: McpToolCallInput): Promise<McpExecutionResult> {
    throw new BountyPilotError(DISABLED_MESSAGE, "MCP_EXECUTION_DISABLED");
  }

  async executeSession(_input: McpSessionInput): Promise<McpExecutionResult> {
    throw new BountyPilotError(DISABLED_MESSAGE, "MCP_EXECUTION_DISABLED");
  }
}
