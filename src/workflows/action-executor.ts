import path from "node:path";
import { createJobAuditLogger, type Runtime } from "../cli/runtime.js";
import type { ActionRecord } from "../core/actions/action-queue.js";
import { fetchScopedText } from "../core/http/scoped-fetch.js";
import { BountyPilotError } from "../utils/errors.js";
import type { ExecutionMode } from "../types.js";
import { runSafeChecks } from "../engines/safe-checks/safe-checks.js";
import { analyzeJavaScript } from "../engines/js-analyzer/js-analyzer.js";
import { crawlWithPlaywright } from "../engines/crawler/playwright-crawler.js";
import { DuplicateRiskEngine } from "../engines/duplicate-risk/duplicate-risk-engine.js";
import { ExternalIntegrationExecutor } from "../integrations/external/external-integration-executor.js";
import { IntegrationManager } from "../integrations/integration-manager/integration-manager.js";
import { McpStdioExecutor } from "../integrations/mcp/mcp-stdio-executor.js";
import { ToolAdapterRunner } from "../integrations/tool-manager/tool-adapter-runner.js";
import type { AdapterCapabilityMetadata } from "../integrations/adapters/adapter.js";

export interface ActionExecutionResult {
  action: ActionRecord;
  status: "executed" | "blocked" | "failed";
  message: string;
  evidenceCreated: number;
  findingsCreated: number;
}

export class ActionExecutor {
  constructor(private readonly runtime: Runtime) {}

  async execute(actionId: string): Promise<ActionExecutionResult> {
    const action = this.runtime.actions.get(actionId);
    if (!action) {
      throw new BountyPilotError(`Action not found: ${actionId}`, "ACTION_NOT_FOUND");
    }
    if (action.status !== "approved") {
      throw new BountyPilotError(`Action ${action.id} must be approved before execution`, "ACTION_NOT_APPROVED");
    }
    const targetRequirement = this.targetRequirement(action);
    if (targetRequirement.requiresTarget && !action.target) {
      this.runtime.actions.fail(action.id);
      throw new BountyPilotError(`Action ${action.id} has no target`, "ACTION_TARGET_MISSING");
    }

    const job = action.jobId ? this.runtime.jobs.get(action.jobId) : undefined;
    const mode = job?.mode ?? "safe";
    const scopedUrl = action.target && (targetRequirement.requiresTarget || isHttpTarget(action.target))
      ? this.runtime.scopeGuard.assertAllowed(action.target).url
      : undefined;
    const policy = this.runtime.policyGate.evaluate({
      mode,
      actionType: action.actionType,
      target: scopedUrl,
      riskLevel: action.riskLevel,
      capability: targetRequirement.capability?.id,
      stateChanging: targetRequirement.capability?.stateChanging,
      destructive: targetRequirement.capability?.destructive,
      requiresApprovalByDefault: targetRequirement.capability?.requiresApprovalByDefault,
      labModeEnabled: this.runtime.config.rules.lab_mode === true,
    });
    const audit = createJobAuditLogger(this.runtime.paths, action.jobId ?? "ad-hoc-actions");
    audit.log({
      jobId: action.jobId,
      actionType: action.actionType,
      url: scopedUrl,
      adapterName: action.adapter,
      policyDecision: policy.decision,
      reason: policy.reason,
      metadata: { actionId: action.id },
    });

    if (policy.decision === "block") {
      this.runtime.actions.block(action.id);
      this.recordActionEvent(action, "blocked", policy.reason, { decision: policy.decision });
      throw new BountyPilotError(policy.reason, "POLICY_BLOCKED");
    }
    if (policy.decision === "require_approval" && !action.requiresApproval) {
      throw new BountyPilotError(policy.reason, "ACTION_REQUIRES_APPROVAL");
    }

    try {
      const result = await this.executeApprovedAction(action, scopedUrl, mode);
      this.runtime.actions.markExecuted(action.id);
      this.recordActionEvent(action, "completed", result.message, {
        evidenceCreated: result.evidenceCreated,
        findingsCreated: result.findingsCreated,
      });
      return {
        action: this.runtime.actions.get(action.id) ?? action,
        status: "executed",
        message: result.message,
        evidenceCreated: result.evidenceCreated,
        findingsCreated: result.findingsCreated,
      };
    } catch (error) {
      this.runtime.actions.fail(action.id);
      this.recordActionEvent(action, "failed", error instanceof Error ? error.message : String(error));
      throw error;
    }
  }

  private recordActionEvent(
    action: ActionRecord,
    status: "completed" | "failed" | "blocked",
    message: string,
    metadata: Record<string, unknown> = {},
  ): void {
    if (!action.jobId) {
      return;
    }
    this.runtime.events.record({
      jobId: action.jobId,
      phase: `action:${action.adapter}`,
      status,
      message,
      metadata: {
        actionId: action.id,
        actionType: action.actionType,
        target: action.target,
        riskLevel: action.riskLevel,
        ...metadata,
      },
    });
  }

  private async executeApprovedAction(
    action: ActionRecord,
    scopedUrl: string | undefined,
    mode: ExecutionMode,
  ): Promise<{ message: string; evidenceCreated: number; findingsCreated: number }> {
    if (action.adapter === "safe-checks" && action.actionType === "http.get") {
      return this.executeSafeChecks(action, requireScopedTarget(action, scopedUrl));
    }
    if (action.adapter === "js-analyzer" && action.actionType === "http.get") {
      return this.executeJsAnalyzer(action, requireScopedTarget(action, scopedUrl));
    }
    if (action.adapter === "playwright" && action.actionType === "browser.navigate") {
      return this.executePlaywright(action, requireScopedTarget(action, scopedUrl));
    }
    if (action.adapter === "tool-manager") {
      return new ToolAdapterRunner(this.runtime).executeAction(action, requireScopedTarget(action, scopedUrl), mode);
    }

    const integration = new IntegrationManager(this.runtime.config).get(action.adapter);
    if (integration?.registration?.mcp || integration?.type === "mcp") {
      return new McpStdioExecutor(this.runtime).executeAction(action, scopedUrl, mode);
    }

    return new ExternalIntegrationExecutor(this.runtime).execute(action, requireScopedTarget(action, scopedUrl), mode);
  }

  private targetRequirement(action: ActionRecord): { requiresTarget: boolean; capability?: AdapterCapabilityMetadata } {
    const integration = new IntegrationManager(this.runtime.config).get(action.adapter);
    const capability = integration?.registration?.capabilities.find((candidate) => candidate.actionType === action.actionType);
    const mcpBacked = Boolean(integration?.registration?.mcp || integration?.type === "mcp" || integration?.type === "desktop");
    return {
      requiresTarget: !(mcpBacked && capability?.requiresTarget === false),
      capability,
    };
  }

  private async executeSafeChecks(
    action: ActionRecord,
    scopedUrl: string,
  ): Promise<{ message: string; evidenceCreated: number; findingsCreated: number }> {
    await this.runtime.rateLimiter.wait(scopedUrl);
    const result = await runSafeChecks(scopedUrl);
    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId: action.jobId,
      adapterName: "safe-checks",
      kind: "tool_output",
      sourceUrl: scopedUrl,
      relativePath: path.join(action.jobId ?? "ad-hoc-actions", `${safeFileName(new URL(scopedUrl).hostname)}-safe-checks.json`),
      content: JSON.stringify(result, null, 2),
    });

    let findingsCreated = 0;
    const history = this.runtime.findings.list();
    for (const candidate of result.findings) {
      const scope = this.runtime.scopeGuard.assertAllowed(scopedUrl);
      const duplicate = new DuplicateRiskEngine().estimate(
        {
          title: candidate.title,
          asset: scope.host,
          url: scopedUrl,
          category: candidate.category,
        },
        history,
      );
      this.runtime.findings.create({
        title: candidate.title,
        asset: scope.host,
        url: scopedUrl,
        category: candidate.category,
        severityEstimate: candidate.severityEstimate,
        confidence: candidate.confidence,
        status: "needs_validation",
        evidencePaths: [artifact.path],
        remediation: candidate.remediation,
        duplicateRisk: duplicate.risk,
        reportabilityScore: candidate.severityEstimate === "medium" ? 45 : 20,
      });
      findingsCreated += 1;
    }

    return {
      message: `safe checks completed with ${result.findings.length} finding candidates`,
      evidenceCreated: 1,
      findingsCreated,
    };
  }

  private async executeJsAnalyzer(
    action: ActionRecord,
    scopedUrl: string,
  ): Promise<{ message: string; evidenceCreated: number; findingsCreated: number }> {
    const audit = createJobAuditLogger(this.runtime.paths, action.jobId ?? "ad-hoc-actions");
    const fetchText = async (requestUrl: string): Promise<string> => {
      return fetchScopedText(requestUrl, {
        allowUrl: (url) => this.runtime.scopeGuard.test(url).allowed,
        wait: async (url) => {
          const requestScope = this.runtime.scopeGuard.assertAllowed(url);
          await this.runtime.rateLimiter.wait(requestScope.url);
        },
        headers: { "User-Agent": "BountyPilot/0.1 action-executor-js" },
        onRequest: (event) => {
          audit.log({
            jobId: action.jobId,
            actionType: "http.get",
            method: "GET",
            url: event.url,
            status: event.status,
            adapterName: "js-analyzer",
            durationMs: event.durationMs,
            policyDecision: "allow",
            metadata: { redirectHop: event.redirectHop, redirectedFrom: event.redirectedFrom },
          });
        },
        onBlockedRedirect: (event) => {
          audit.log({
            jobId: action.jobId,
            actionType: "http.redirect",
            method: "GET",
            url: event.targetUrl,
            status: event.redirectStatus,
            adapterName: "js-analyzer",
            policyDecision: "block",
            reason: "Redirect target blocked by ScopeGuard",
            metadata: { fromUrl: event.fromUrl, location: event.location, redirectHop: event.redirectHop },
          });
        },
      });
    };

    const result = await analyzeJavaScript(scopedUrl, {
      allowUrl: (requestUrl) => this.runtime.scopeGuard.test(requestUrl).allowed,
      fetchText,
    });
    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId: action.jobId,
      adapterName: "js-analyzer",
      kind: "tool_output",
      sourceUrl: scopedUrl,
      relativePath: path.join(action.jobId ?? "ad-hoc-actions", `${safeFileName(new URL(scopedUrl).hostname)}-js-analysis.json`),
      content: JSON.stringify(result, null, 2),
    });

    let findingsCreated = 0;
    if (result.possibleSecrets.length > 0) {
      const scope = this.runtime.scopeGuard.assertAllowed(scopedUrl);
      this.runtime.findings.create({
        title: "Possible secret-like pattern observed in public client-side content",
        asset: scope.host,
        url: scopedUrl,
        category: "public_js_secret_pattern",
        severityEstimate: "medium",
        confidence: "low",
        status: "needs_manual_review",
        evidencePaths: [artifact.path],
        remediation: "Manually verify whether the masked value is a real secret before reporting or validating impact.",
        duplicateRisk: "unknown",
        reportabilityScore: 55,
      });
      findingsCreated = 1;
    }

    return {
      message: `JavaScript analysis completed with ${result.endpointCandidates.length} endpoint candidates`,
      evidenceCreated: 1,
      findingsCreated,
    };
  }

  private async executePlaywright(
    action: ActionRecord,
    scopedUrl: string,
  ): Promise<{ message: string; evidenceCreated: number; findingsCreated: number }> {
    await this.runtime.rateLimiter.wait(scopedUrl);
    const audit = createJobAuditLogger(this.runtime.paths, action.jobId ?? "ad-hoc-actions");
    const result = await crawlWithPlaywright({
      url: scopedUrl,
      evidenceDir: this.runtime.paths.evidenceDir,
      jobId: action.jobId,
      evidence: {
        screenshots: this.runtime.config.evidence.screenshots,
        har: this.runtime.config.evidence.har,
        consoleLogs: this.runtime.config.evidence.console_logs,
        domSnapshot: this.runtime.config.evidence.dom_snapshot,
        browserTrace: this.runtime.config.evidence.browser_trace,
        video: this.runtime.config.evidence.video,
      },
      allowUrl: (requestUrl) => this.runtime.scopeGuard.test(requestUrl).allowed,
      onRequest: (event) => {
        audit.log({
          jobId: action.jobId,
          actionType: "browser.request",
          method: event.method,
          url: event.url,
          adapterName: "playwright",
          policyDecision: event.allowed ? "allow" : "block",
          reason: event.allowed ? "Request remained in scope" : "Request blocked by ScopeGuard",
        });
      },
    });

    for (const artifact of result.evidence) {
      this.runtime.evidence.create(artifact);
    }
    this.runtime.crawlGraph.upsertPage({ url: scopedUrl, title: result.title });
    for (const link of result.links.filter((link) => this.runtime.scopeGuard.test(link).allowed)) {
      this.runtime.crawlGraph.upsertPage({ url: link });
      this.runtime.crawlGraph.addEdge(scopedUrl, link);
    }

    return {
      message: `Playwright crawl completed with ${result.links.length} discovered links`,
      evidenceCreated: result.evidence.length,
      findingsCreated: 0,
    };
  }
}

function safeFileName(value: string): string {
  return value.replace(/[^a-z0-9.-]/gi, "_");
}

function requireScopedTarget(action: ActionRecord, scopedUrl: string | undefined): string {
  if (!scopedUrl) {
    throw new BountyPilotError(`Action ${action.id} has no scoped target`, "ACTION_TARGET_MISSING");
  }
  return scopedUrl;
}

function isHttpTarget(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://");
}
