import path from "node:path";

import { loadProgramFile } from "../config/config-loader.js";
import type { ProgramConfig } from "../config/program-schema.js";
import { ScopeGuard } from "../scope/scope-guard.js";
import { BountyPilotError } from "../../utils/errors.js";
import type {
  ActionAuthorityDependencies,
  ActionMaterialSource,
  ResolvedBindingMaterial,
} from "./action-approval-service.js";
import type { CapabilityEnforcementInput } from "./action-approval-context.js";

export type ProductionActionSurface =
  | "workflow-barrier"
  | "safe-checks"
  | "safe-checks-reviewed"
  | "js-analyzer"
  | "playwright"
  | "public-research";

export const WORKFLOW_BARRIER_ADAPTER = "workflow";
export const WORKFLOW_BARRIER_ACTION_TYPE = "workflow.barrier";
export const WORKFLOW_BARRIER_PURPOSE = "workflow_completion_barrier";

// The barrier is a workflow-owned scheduling sentinel, not a general
// purpose action capability.  Keep the accepted job types deliberately
// narrow: these are the only job kinds created by WorkflowRunner for which
// the scheduling window/barrier protocol exists.
const WORKFLOW_BARRIER_JOB_TYPES = new Set(["run", "mission"]);

const PUBLIC_RESEARCH_ADAPTERS = new Set([
  "d-research",
  "d_research",
  "d-research-skill",
  "d_research_skill",
]);

/**
 * Builds the narrow production authority seam shared by approval and
 * execution lifecycle services. The program file is captured once, while its
 * contents are reloaded for every materialization.
 */
export function createProductionActionAuthorityDependencies(input: {
  programFile: string;
}): ActionAuthorityDependencies {
  const programFile = path.resolve(input.programFile);
  return {
    loadCurrentProgram: () => loadProgramFile(programFile),
    resolveBindingMaterial: ({ source, program }) =>
      resolveProductionBindingMaterial(source, program.config),
  };
}

/**
 * Returns only the explicitly trusted in-process surfaces. Optional tools,
 * MCP adapters, desktop bridges, and configured integrations deliberately do
 * not resolve here.
 */
export function productionActionSurface(
  adapter: string,
  actionType: string,
  riskLevel?: "low" | "medium" | "high",
): ProductionActionSurface | undefined {
  if (adapter === WORKFLOW_BARRIER_ADAPTER && actionType === WORKFLOW_BARRIER_ACTION_TYPE) {
    return "workflow-barrier";
  }
  if (adapter === "safe-checks" && actionType === "http.get") {
    // Planner follow-up probes (for example GraphQL/auth observations) are
    // still non-destructive GETs, but intentionally require a human gate.
    // Keep them on a distinct authority surface so a medium-risk row cannot
    // be silently treated as the low-risk auto-executable capability.
    return riskLevel === "medium" ? "safe-checks-reviewed" : "safe-checks";
  }
  if (adapter === "js-analyzer" && actionType === "http.get") return "js-analyzer";
  if (adapter === "playwright" && actionType === "browser.navigate") return "playwright";
  if (PUBLIC_RESEARCH_ADAPTERS.has(adapter) && actionType === "research.public") {
    return "public-research";
  }
  return undefined;
}

function resolveProductionBindingMaterial(
  source: ActionMaterialSource,
  config: ProgramConfig,
): ResolvedBindingMaterial {
  const surface = productionActionSurface(source.action.adapter, source.action.actionType, source.action.riskLevel);
  if (!surface) throw unsupportedBinding();
  if (surface === "workflow-barrier" && !isAuthenticWorkflowBarrier(source)) {
    // A caller can enqueue arbitrary rows with the public adapter/type pair.
    // Do not let that pair alone mint a completion capability; the complete
    // source projection (action/job linkage and exact internal marker) must
    // prove that the row came from the workflow barrier protocol.
    throw unsupportedBinding();
  }

  const capabilityEnforcement = capabilityFor(surface);
  if (source.action.riskLevel !== capabilityEnforcement.riskLevel) {
    throw unsupportedBinding();
  }

  const normalizedTarget = normalizeTarget(source, config);
  return {
    normalizedTarget,
    capabilityEnforcement,
    integration: { kind: "builtin" },
  };
}

function isAuthenticWorkflowBarrier(source: ActionMaterialSource): boolean {
  const { action, job } = source;
  if (
    action.jobId !== job.id ||
    action.target !== null ||
    job.target === null ||
    action.riskLevel !== "low" ||
    action.requiresApproval !== false ||
    action.requiredForCompletion !== true ||
    !WORKFLOW_BARRIER_JOB_TYPES.has(job.type)
  ) {
    return false;
  }

  // Metadata is part of the materialized source hash.  Requiring an exact,
  // two-field plain record prevents callers from smuggling a look-alike
  // purpose, extra control fields, or a truthy non-boolean `internal` flag
  // through the generic action queue.
  const metadata = action.metadata;
  if (Object.getPrototypeOf(metadata) !== Object.prototype && Object.getPrototypeOf(metadata) !== null) {
    return false;
  }
  const keys = Object.keys(metadata);
  return (
    keys.length === 2 &&
    Object.prototype.hasOwnProperty.call(metadata, "internal") &&
    Object.prototype.hasOwnProperty.call(metadata, "purpose") &&
    metadata.internal === true &&
    metadata.purpose === WORKFLOW_BARRIER_PURPOSE
  );
}

function normalizeTarget(
  source: ActionMaterialSource,
  config: ProgramConfig,
): string | null {
  if (source.action.target === null) return null;
  return new ScopeGuard(config).test(source.action.target).url;
}

function capabilityFor(surface: ProductionActionSurface): CapabilityEnforcementInput {
  if (surface === "workflow-barrier") {
    return {
      id: WORKFLOW_BARRIER_ACTION_TYPE,
      title: "Internal workflow completion barrier",
      description: "Close the workflow scheduling window without producing an external effect.",
      actionType: WORKFLOW_BARRIER_ACTION_TYPE,
      riskLevel: "low",
      allowedModes: ["passive", "safe", "deep-safe", "lab-offensive"],
      produces: [],
      requiresTarget: false,
      requiresScope: false,
      stateChanging: false,
      destructive: false,
      requiresApprovalByDefault: false,
      blockedByDefault: false,
    };
  }
  if (surface === "safe-checks") {
    return {
      id: "http.get",
      title: "Scoped safe HTTP checks",
      description: "Issue one low-rate, non-destructive GET against an explicitly in-scope URL.",
      actionType: "http.get",
      riskLevel: "low",
      allowedModes: ["safe", "deep-safe", "lab-offensive"],
      produces: ["tool_output", "finding_candidate"],
      requiresTarget: true,
      requiresScope: true,
      stateChanging: false,
      destructive: false,
      requiresApprovalByDefault: false,
      blockedByDefault: false,
    };
  }
  if (surface === "safe-checks-reviewed") {
    return {
      id: "http.get.reviewed",
      title: "Scoped reviewed HTTP checks",
      description: "Issue one low-rate, non-destructive GET after explicit human approval.",
      actionType: "http.get",
      riskLevel: "medium",
      allowedModes: ["deep-safe", "lab-offensive"],
      produces: ["tool_output", "finding_candidate"],
      requiresTarget: true,
      requiresScope: true,
      stateChanging: false,
      destructive: false,
      requiresApprovalByDefault: true,
      blockedByDefault: false,
    };
  }
  if (surface === "js-analyzer") {
    return {
      id: "http.get",
      title: "Scoped JavaScript analysis",
      description: "Fetch scoped public client content for local static analysis.",
      actionType: "http.get",
      riskLevel: "low",
      allowedModes: ["safe", "deep-safe", "lab-offensive"],
      produces: ["tool_output", "finding_candidate"],
      requiresTarget: true,
      requiresScope: true,
      stateChanging: false,
      destructive: false,
      requiresApprovalByDefault: false,
      blockedByDefault: false,
      scopedPostcondition: "current_or_final_url_in_scope",
    };
  }
  if (surface === "playwright") {
    return {
      id: "browser.navigate",
      title: "Navigate in scoped browser",
      description: "Open an in-scope URL in a local browser context and collect safe page evidence.",
      actionType: "browser.navigate",
      riskLevel: "low",
      allowedModes: ["safe", "deep-safe", "lab-offensive"],
      produces: ["screenshot", "har", "console_log", "dom_snapshot", "crawl_graph"],
      requiresTarget: true,
      requiresScope: true,
      stateChanging: false,
      destructive: false,
      requiresApprovalByDefault: false,
      blockedByDefault: false,
    };
  }
  return {
    id: "research.public",
    title: "Local public-research note",
    description: "Record public, non-invasive research context locally without invoking an external adapter.",
    actionType: "research.public",
    riskLevel: "low",
    allowedModes: ["passive", "safe", "deep-safe", "lab-offensive"],
    produces: ["research_note"],
    requiresTarget: false,
    requiresScope: false,
    stateChanging: false,
    destructive: false,
    requiresApprovalByDefault: false,
    blockedByDefault: false,
  };
}

function unsupportedBinding(): BountyPilotError {
  return new BountyPilotError(
    "Action authority binding is unavailable for this execution surface.",
    "ACTION_APPROVAL_CONTEXT_UNAVAILABLE",
  );
}
