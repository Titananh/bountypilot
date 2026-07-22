import type { Runtime } from "../../cli/runtime.js";
import type { ActionRecord } from "../../core/actions/action-queue.js";
import type { ExecutionMode } from "../../types.js";
import { BountyPilotError } from "../../utils/errors.js";

/**
 * External integrations are deliberately a planning/handoff surface in this
 * release.  Keeping the type and class gives downstream callers a stable
 * migration point, while making the effect boundary impossible to bypass by
 * constructing an ActionRecord directly.  Approved target effects must be
 * implemented as a production ActionExecutor surface first.
 */
export interface ExternalIntegrationExecutionResult {
  message: string;
  evidenceCreated: number;
  findingsCreated: number;
}

const DISABLED_MESSAGE =
  "External integration execution is disabled at the authoritative boundary; record a plan and use the human handoff.";

export class ExternalIntegrationExecutor {
  constructor(_runtime: Runtime) {}

  async execute(
    _action: ActionRecord,
    _scopedUrl: string,
    _mode: ExecutionMode,
  ): Promise<ExternalIntegrationExecutionResult> {
    throw new BountyPilotError(DISABLED_MESSAGE, "EXTERNAL_EXECUTION_DISABLED");
  }
}
