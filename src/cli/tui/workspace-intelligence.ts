import { loadWorkspaceProgram } from "../../core/config/config-loader.js";
import type { ProgramConfig } from "../../core/config/program-schema.js";
import { programWorkspace, workspacePaths } from "../../core/workspace.js";
import { ActionQueue } from "../../core/actions/action-queue.js";
import { JobManager } from "../../core/jobs/job-manager.js";
import { IntegrationManager } from "../../integrations/integration-manager/integration-manager.js";
import { ToolManager, type ToolDoctorResult } from "../../integrations/tool-manager/tool-manager.js";
import { toolApprovalIntegrationName } from "../../integrations/tool-manager/tool-adapter-runner.js";
import { EvidenceStore } from "../../stores/evidence-store.js";
import { FindingStore } from "../../stores/finding-store.js";
import { ReconObservationStore } from "../../stores/recon-observation-store.js";
import { openBountyDatabase } from "../../stores/db/database.js";
import { BountyPilotError } from "../../utils/errors.js";
import { createExecutableApprovalStore } from "../../utils/local-process-policy.js";

export interface TuiWorkspaceInsight {
  status: "ready" | "setup" | "blocked";
  program?: string;
  platform?: string;
  rateLimit?: string;
  scope: {
    in: number;
    out: number;
  };
  jobs: {
    total: number;
    running: number;
    failed: number;
    latest?: {
      id: string;
      type: string;
      status: string;
      target?: string;
    };
  };
  actions: {
    pending: number;
    approved: number;
    blocked: number;
    failed: number;
  };
  findings: {
    total: number;
    ready: number;
    bestScore: number;
    top?: {
      id: string;
      title: string;
      severity: string;
      score: number;
    };
  };
  evidence: {
    total: number;
  };
  recon: {
    total: number;
    inScope: number;
  };
  tools: {
    total: number;
    available: number;
    approvedExecutables: number;
    reviewRequired: number;
    activeScanning: number;
    missing: number;
    top: Array<{
      name: string;
      category: string;
      status: ToolDoctorResult["status"];
      approved: boolean;
      message: string;
    }>;
  };
  integrations: {
    total: number;
    configured: number;
    planned: number;
    disabled: number;
    mcp: number;
    risky: number;
    top: Array<{
      name: string;
      type: string;
      status: string;
      capabilities: number;
      message?: string;
    }>;
  };
  next: string[];
  message: string;
}

export function loadWorkspaceInsight(cwd: string): TuiWorkspaceInsight {
  let db: ReturnType<typeof openBountyDatabase> | undefined;
  try {
    const loaded = loadWorkspaceProgram(cwd);
    const paths = programWorkspace(loaded.config.program, cwd);
    db = openBountyDatabase(paths.dbFile);
    const tools = summarizeTools(cwd);
    const integrations = summarizeIntegrations(loaded.config);
    const jobs = new JobManager(db).list(100);
    const actions = new ActionQueue(db).summarize();
    const findings = new FindingStore(db).list();
    const evidence = new EvidenceStore(db, paths.evidenceDir, {
      maskSecrets: loaded.config.evidence.mask_secrets !== false,
      trustedArtifactRoots: [paths.reportsDir],
    }).list();
    const recon = new ReconObservationStore(db).list({ limit: 1000 });
    const topFinding = [...findings].sort((left, right) => right.reportabilityScore - left.reportabilityScore)[0];
    const readyFindings = findings.filter((finding) => finding.reportabilityScore >= 75 && finding.evidencePaths.length > 0);
    const failedJobs = jobs.filter((job) => job.status === "failed").length;
    const runningJobs = jobs.filter((job) => job.status === "running").length;

    return {
      status: actions.blocked > 0 || actions.failed > 0 || failedJobs > 0 ? "blocked" : "ready",
      program: loaded.config.program,
      platform: loaded.config.platform,
      rateLimit: loaded.config.rules.rate_limit,
      scope: {
        in: loaded.config.in_scope.length,
        out: loaded.config.out_of_scope.length,
      },
      jobs: {
        total: jobs.length,
        running: runningJobs,
        failed: failedJobs,
        latest: jobs[0]
          ? {
              id: jobs[0].id,
              type: jobs[0].type,
              status: jobs[0].status,
              target: jobs[0].target,
            }
          : undefined,
      },
      actions: {
        pending: actions.pending,
        approved: actions.approved,
        blocked: actions.blocked,
        failed: actions.failed,
      },
      findings: {
        total: findings.length,
        ready: readyFindings.length,
        bestScore: topFinding?.reportabilityScore ?? 0,
        top: topFinding
          ? {
              id: topFinding.id,
              title: topFinding.title,
              severity: topFinding.severityEstimate,
              score: topFinding.reportabilityScore,
            }
          : undefined,
      },
      evidence: {
        total: evidence.length,
      },
      recon: {
        total: recon.length,
        inScope: recon.filter((observation) => observation.scopeAllowed).length,
      },
      tools,
      integrations,
      next: recommendInsightNext({
        jobs: jobs.length,
        actionsPending: actions.pending,
        actionsApproved: actions.approved,
        findings: findings.length,
        readyFindings: readyFindings.length,
        evidence: evidence.length,
        recon: recon.length,
        toolsApproved: tools.approvedExecutables,
        integrationsConfigured: integrations.configured,
      }),
      message: "Workspace loaded from local .bounty state.",
    };
  } catch (error) {
    return insightFromError(error, cwd);
  } finally {
    db?.close();
  }
}

function recommendInsightNext(input: {
  jobs: number;
  actionsPending: number;
  actionsApproved: number;
  findings: number;
  readyFindings: number;
  evidence: number;
  recon: number;
  toolsApproved: number;
  integrationsConfigured: number;
}): string[] {
  if (input.actionsPending > 0) return ["Review pending actions", "Run /hunt for dry-run commands"];
  if (input.actionsApproved > 0) return ["Execute approved actions manually", "Record evidence after validation"];
  if (input.readyFindings > 0) return ["Open /results", "Score report readiness"];
  if (input.findings > 0 && input.evidence === 0) return ["Record evidence", "Add reproduction notes"];
  if (input.recon > 0 && input.findings === 0) return ["Run a focused playbook", "Review recon observations"];
  if (input.integrationsConfigured === 0) return ["Open /mcp", "Enable only needed integrations"];
  if (input.toolsApproved === 0) return ["Open /tools", "Approve trusted executables before live recon"];
  if (input.jobs === 0) return ["Run /hunt doctor", "Start recon with dry-run"];
  return ["Review latest job", "Open /results"];
}

function insightFromError(error: unknown, cwd: string): TuiWorkspaceInsight {
  const message = error instanceof BountyPilotError ? error.message : error instanceof Error ? error.message : String(error);
  const tools = summarizeTools(cwd);
  return {
    status: "setup",
    scope: { in: 0, out: 0 },
    jobs: { total: 0, running: 0, failed: 0 },
    actions: { pending: 0, approved: 0, blocked: 0, failed: 0 },
    findings: { total: 0, ready: 0, bestScore: 0 },
    evidence: { total: 0 },
    recon: { total: 0, inScope: 0 },
    tools,
    integrations: emptyIntegrations(),
    next: ["bugbounty init", "bugbounty import <program.yml>", "bugbounty hunt doctor <target>"],
    message,
  };
}

function summarizeTools(cwd: string): TuiWorkspaceInsight["tools"] {
  try {
    const manager = new ToolManager();
    const records = manager.doctor();
    const registry = manager.list();
    const approvalStore = createExecutableApprovalStore(workspacePaths(cwd).integrationsDir);
    const approvalCount = registry.reduce(
      (count, tool) => count + approvalStore.list(toolApprovalIntegrationName(tool.name)).length,
      0,
    );
    const approvedTools = new Set(
      registry
        .filter((tool) => approvalStore.list(toolApprovalIntegrationName(tool.name)).length > 0)
        .map((tool) => tool.name),
    );
    const reviewRequired = registry.filter((tool) => tool.actions.some((action) => action.requires_approval)).length;
    const activeScanning = registry.filter((tool) => tool.permissions.active_scanning).length;

    return {
      total: records.length,
      available: records.filter((record) => record.status === "available").length,
      approvedExecutables: approvalCount,
      reviewRequired,
      activeScanning,
      missing: records.filter((record) => record.status === "not_installed").length,
      top: records
        .sort((left, right) => toolStatusRank(left.status) - toolStatusRank(right.status))
        .slice(0, 8)
        .map((record) => ({
          name: record.name,
          category: record.category,
          status: record.status,
          approved: approvedTools.has(record.name),
          message: record.message,
        })),
    };
  } catch (error) {
    return {
      total: 0,
      available: 0,
      approvedExecutables: 0,
      reviewRequired: 0,
      activeScanning: 0,
      missing: 0,
      top: [
        {
          name: "tools",
          category: "doctor",
          status: "misconfigured",
          approved: false,
          message: error instanceof Error ? error.message : String(error),
        },
      ],
    };
  }
}

function summarizeIntegrations(config: ProgramConfig): TuiWorkspaceInsight["integrations"] {
  try {
    const records = new IntegrationManager(config).list();
    return {
      total: records.length,
      configured: records.filter((record) => record.status === "configured").length,
      planned: records.filter((record) => record.status === "planned" || record.status === "not_configured").length,
      disabled: records.filter((record) => record.status === "disabled").length,
      mcp: records.filter((record) => record.type === "mcp").length,
      risky: records.filter((record) => (record.riskyCapabilities?.length ?? 0) > 0).length,
      top: records.slice(0, 8).map((record) => ({
        name: record.displayName ?? record.name,
        type: record.type,
        status: record.status,
        capabilities: record.capabilities?.length ?? 0,
        message: record.message,
      })),
    };
  } catch {
    return emptyIntegrations();
  }
}

function emptyIntegrations(): TuiWorkspaceInsight["integrations"] {
  return {
    total: 0,
    configured: 0,
    planned: 0,
    disabled: 0,
    mcp: 0,
    risky: 0,
    top: [],
  };
}

function toolStatusRank(status: ToolDoctorResult["status"]): number {
  switch (status) {
    case "blocked":
      return 0;
    case "misconfigured":
      return 1;
    case "not_installed":
      return 2;
    case "manual":
      return 3;
    case "available":
      return 4;
  }
}
