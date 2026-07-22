import path from "node:path";
import { createJobAuditLogger, type Runtime } from "../cli/runtime.js";
import type { ActionRecord } from "../core/actions/action-queue.js";
import type {
  ClaimedActionContext,
  EffectOutcome,
} from "../core/actions/action-lifecycle.js";
import {
  materializeActionAuthority,
  type ActionMaterialSource,
} from "../core/actions/action-approval-service.js";
import {
  createProductionActionAuthorityDependencies,
  productionActionSurface,
  type ProductionActionSurface,
} from "../core/actions/production-action-authority.js";
import { fetchScopedResponse, fetchScopedText } from "../core/http/scoped-fetch.js";
import { resolveNetworkTarget } from "../core/http/network-address-policy.js";
import { BountyPilotError } from "../utils/errors.js";
import { runSafeChecks } from "../engines/safe-checks/safe-checks.js";
import { analyzeJavaScript } from "../engines/js-analyzer/js-analyzer.js";
import { crawlWithPlaywright } from "../engines/crawler/playwright-crawler.js";
import { DuplicateRiskEngine } from "../engines/duplicate-risk/duplicate-risk-engine.js";
import { candidateBaselineReportabilityScore, evaluateFindingCandidateReadiness } from "../engines/finding-candidates/finding-candidate-engine.js";
import { EvidenceStore } from "../stores/evidence-store.js";
import type { ProgramConfig } from "../core/config/program-schema.js";
import { RateLimiter } from "../core/rate-limit/rate-limiter.js";
import { ScopeGuard, type ScopeMatch } from "../core/scope/scope-guard.js";

const POLICY_APPROVAL_TTL_MS = 5 * 60_000;
const EXECUTION_OWNER = `bountypilot-action-executor:${process.pid}`;
const rateLimitersByRuntime = new WeakMap<Runtime, Map<string, RateLimiter>>();

export interface ActionExecutionResult {
  action: ActionRecord;
  status: "executed" | "blocked" | "failed";
  message: string;
  evidenceCreated: number;
  candidatesCreated: number;
  findingsCreated: number;
  plannerCandidates?: {
    endpointCandidates: string[];
    jsAssets: string[];
  };
}

interface ApprovedActionResult {
  message: string;
  evidenceCreated: number;
  candidatesCreated: number;
  findingsCreated: number;
  plannerCandidates?: ActionExecutionResult["plannerCandidates"];
}

interface EffectAuthorityContext {
  config: ProgramConfig;
  scopeGuard: ScopeGuard;
  rateLimiter: RateLimiter;
  evidence: EvidenceStore;
  /** Re-loads and re-binds authority immediately before each target request. */
  authorizeUrl(url: string): ScopeMatch;
}

export class ActionExecutor {
  constructor(private readonly runtime: Runtime) {}

  async execute(actionId: string): Promise<ActionExecutionResult> {
    if (!this.runtime.actionApproval || !this.runtime.actionLifecycle) {
      throw new BountyPilotError(
        "Action approval and execution lifecycle are unavailable.",
        "ACTION_LIFECYCLE_UNAVAILABLE",
      );
    }
    let action = this.runtime.actions.get(actionId);
    if (!action) {
      throw new BountyPilotError(`Action not found: ${actionId}`, "ACTION_NOT_FOUND");
    }
    const surface = productionActionSurface(action.adapter, action.actionType, action.riskLevel);
    if (!surface) throw unsupportedExecution(action);
    // Planning and handoff rows are intentionally non-effect-capable. Reject
    // them before any rate wait, approval preview, or execution claim.
    rejectPlanningOrHandoff(action);

    action = this.ensureApproved(action);
    const claimed = this.runtime.actionLifecycle.claim({
      actionId: action.id,
      executionOwner: EXECUTION_OWNER,
    });
    action = claimed.action;

    let dispatchMarked = false;
    try {
      // The claim carries the exact, freshly materialized authority that was
      // compared inside the lifecycle transaction. Every effect dependency is
      // rebuilt from that authority; runtime snapshots are never consulted.
      const effect = createEffectAuthorityContext(claimed, this.runtime);
      const scopedUrl = this.scopedTarget(action, surface, effect.scopeGuard);
      if (scopedUrl) {
        // Close the claim-to-request window before writing the running
        // dispatch marker or entering an effect adapter.
        effect.authorizeUrl(scopedUrl);
      }

      const audit = createJobAuditLogger(this.runtime.paths, action.jobId ?? "ad-hoc-actions");
      audit.log({
        jobId: action.jobId,
        actionType: action.actionType,
        url: scopedUrl,
        adapterName: action.adapter,
        policyDecision: action.requiresApproval ? "require_approval" : "allow",
        reason: "Action authority revalidated and execution claimed",
        metadata: { actionId: action.id, surface },
      });

      const markDispatchOnce = (): void => {
        const lifecycleInput = {
          actionId: action.id,
          executionToken: claimed.executionToken,
          executionOwner: EXECUTION_OWNER,
        };
        if (dispatchMarked) {
          this.runtime.actionLifecycle.assertDispatchActive(lifecycleInput);
          return;
        }
        this.runtime.actionLifecycle.markDispatch(lifecycleInput);
        dispatchMarked = true;
      };
      const result = await this.executeApprovedAction(
        action,
        scopedUrl,
        surface,
        effect,
        markDispatchOnce,
      );
      const finalized = this.runtime.actionLifecycle.finalize({
        actionId: action.id,
        executionToken: claimed.executionToken,
        executionOwner: EXECUTION_OWNER,
        outcome: { kind: "success" },
      });
      return {
        action: finalized,
        status: "executed",
        message: result.message,
        evidenceCreated: result.evidenceCreated,
        candidatesCreated: result.candidatesCreated,
        findingsCreated: result.findingsCreated,
        ...(result.plannerCandidates ? { plannerCandidates: result.plannerCandidates } : {}),
      };
    } catch (error) {
      if (error instanceof BountyPilotError && error.code === "ACTION_LEASE_EXPIRED") {
        const recovery = this.runtime.actionLifecycle.recoverExpiredLease(action.id);
        if (recovery.kind === "recovered") {
          throw error;
        }
      }
      const outcome = failureOutcome(error, dispatchMarked);
      try {
        this.runtime.actionLifecycle.finalize({
          actionId: action.id,
          executionToken: claimed.executionToken,
          executionOwner: EXECUTION_OWNER,
          outcome,
        });
      } catch (finalizeError) {
        // Lifecycle errors are fixed and token-free. Prefer them when durable
        // outcome recording failed; the claimed bearer is never attached to
        // either error surface.
        throw finalizeError;
      }
      throw error;
    }
  }

  private ensureApproved(action: ActionRecord): ActionRecord {
    if (action.status === "approved") return action;
    if (action.status !== "pending" || action.requiresApproval) {
      throw actionStatusError(action);
    }

    const challenge = this.runtime.actionApproval.preview(action.id);
    if (challenge.policyDecision === "block") {
      throw new BountyPilotError(challenge.policyReason, "POLICY_BLOCKED");
    }
    if (challenge.policyDecision !== "allow") {
      throw new BountyPilotError(
        `Action ${action.id} must be approved before execution`,
        "ACTION_REQUIRES_APPROVAL",
      );
    }
    return this.runtime.actionApproval.approvePolicy({
      actionId: action.id,
      ttlMs: POLICY_APPROVAL_TTL_MS,
      note: "Finite policy approval for an allowlisted internal execution surface.",
    }).action;
  }

  private scopedTarget(
    action: ActionRecord,
    surface: ProductionActionSurface,
    scopeGuard: ScopeGuard,
  ): string | undefined {
    if (surface === "workflow-barrier") {
      if (action.target) throw unsupportedExecution(action);
      return undefined;
    }
    if (surface === "public-research" && !action.target) return undefined;
    if (!action.target) {
      throw new BountyPilotError(`Action ${action.id} has no target`, "ACTION_TARGET_MISSING");
    }
    return scopeGuard.assertAllowed(action.target).url;
  }

  private async executeApprovedAction(
    action: ActionRecord,
    scopedUrl: string | undefined,
    surface: ProductionActionSurface,
    effect: EffectAuthorityContext,
    markDispatch: () => void,
  ): Promise<ApprovedActionResult> {
    if (surface === "workflow-barrier") {
      markDispatch();
      return {
        message: "Internal workflow completion barrier executed",
        evidenceCreated: 0,
        candidatesCreated: 0,
        findingsCreated: 0,
      };
    }
    if (surface === "safe-checks" || surface === "safe-checks-reviewed") {
      return this.executeSafeChecks(action, requireScopedTarget(action, scopedUrl), effect, markDispatch);
    }
    if (surface === "js-analyzer") {
      return this.executeJsAnalyzer(action, requireScopedTarget(action, scopedUrl), effect, markDispatch);
    }
    if (surface === "playwright") {
      return this.executePlaywright(
        action,
        requireScopedTarget(action, scopedUrl),
        effect,
        markDispatch,
      );
    }
    markDispatch();
    return this.executeLocalPublicResearch(action, scopedUrl, effect);
  }

  private async executeSafeChecks(
    action: ActionRecord,
    scopedUrl: string,
    effect: EffectAuthorityContext,
    markDispatch: () => void,
  ): Promise<ApprovedActionResult> {
    const audit = createJobAuditLogger(this.runtime.paths, action.jobId ?? "ad-hoc-actions");
    const result = await runSafeChecks(scopedUrl, {
      allowUrl: (requestUrl) => effect.authorizeUrl(requestUrl).allowed,
      fetchResponse: (requestUrl) => fetchScopedResponse(requestUrl, {
        allowUrl: (url) => effect.authorizeUrl(url).allowed,
        wait: async (url) => {
          const requestScope = effect.authorizeUrl(url);
          if (!requestScope.allowed) {
            throw new BountyPilotError(requestScope.reason, "SCOPE_BLOCKED");
          }
          await effect.rateLimiter.wait(requestScope.url);
        },
        beforeRequest: (url) => {
          // Re-materialize after the (possibly delayed) rate gate. The
          // pre-wait check is not sufficient because scope/policy files can
          // change while a request is queued.
          const requestScope = effect.authorizeUrl(url);
          if (!requestScope.allowed) {
            throw new BountyPilotError(requestScope.reason, "SCOPE_BLOCKED");
          }
          // Re-resolve immediately after the rate gate. A hostname can change
          // answers while a request is queued; private/reserved answers are
          // never accepted at the effect boundary.
          return resolveNetworkTarget(requestScope.url).then(() => {
            // The lifecycle marker is granted only after the current
            // authority, address, and rate gates have passed.
            markDispatch();
          });
        },
        headers: {
          "User-Agent": "BountyPilot/0.2 safe-checks",
          "Origin": "https://bountypilot.local",
        },
        onRequest: (event) => {
          audit.log({
            jobId: action.jobId,
            actionType: "http.get",
            method: "GET",
            url: event.url,
            status: event.status,
            adapterName: "safe-checks",
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
            adapterName: "safe-checks",
            policyDecision: "block",
            reason: "Redirect target blocked by ScopeGuard",
            metadata: { fromUrl: event.fromUrl, location: event.location, redirectHop: event.redirectHop },
          });
        },
      }),
    });
    const artifact = effect.evidence.writeTextArtifact({
      jobId: action.jobId,
      adapterName: "safe-checks",
      kind: "tool_output",
      sourceUrl: scopedUrl,
      relativePath: path.join(action.jobId ?? "ad-hoc-actions", `${safeFileName(new URL(scopedUrl).hostname)}-safe-checks.json`),
      content: JSON.stringify(result, null, 2),
    });

    let findingsCreated = 0;
    let candidatesCreated = 0;
    const history = this.runtime.findings.list();
    for (const candidate of result.findings) {
      const scope = effect.scopeGuard.assertAllowed(scopedUrl);
      const duplicate = new DuplicateRiskEngine().estimate(
        {
          title: candidate.title,
          asset: scope.host,
          url: scopedUrl,
          category: candidate.category,
        },
        history,
      );
      const readiness = evaluateFindingCandidateReadiness({
        confidence: candidate.confidence,
        severity: candidate.severityEstimate,
        evidenceCount: 1,
        duplicateRisk: duplicate.risk,
      });
      const finding = this.runtime.findings.create({
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
        reportabilityScore: candidateBaselineReportabilityScore(readiness),
      });
      effect.evidence.linkToFinding(artifact.id, finding.id);
      this.runtime.candidates.create({
        jobId: action.jobId,
        title: candidate.title,
        asset: scope.host,
        url: scopedUrl,
        category: candidate.category,
        severityEstimate: candidate.severityEstimate,
        confidence: candidate.confidence,
        status: readiness.status,
        evidenceIds: [artifact.id],
        findingId: finding.id,
        falsePositiveRisk: readiness.falsePositiveRisk,
        duplicateRisk: duplicate.risk,
        reportability: readiness.reportability,
        reasoningSummary: readiness.reasoningSummary,
        nextManualSteps: readiness.nextManualSteps,
      });
      candidatesCreated += 1;
      findingsCreated += 1;
    }

    return {
      message: `safe checks completed with ${result.findings.length} finding candidates`,
      evidenceCreated: 1,
      candidatesCreated,
      findingsCreated,
    };
  }

  private async executeJsAnalyzer(
    action: ActionRecord,
    scopedUrl: string,
    effect: EffectAuthorityContext,
    markDispatch: () => void,
  ): Promise<ApprovedActionResult> {
    const audit = createJobAuditLogger(this.runtime.paths, action.jobId ?? "ad-hoc-actions");
    const fetchText = async (requestUrl: string): Promise<string> => {
      return fetchScopedText(requestUrl, {
        allowUrl: (url) => effect.authorizeUrl(url).allowed,
        wait: async (url) => {
          const requestScope = effect.authorizeUrl(url);
          if (!requestScope.allowed) {
            throw new BountyPilotError(requestScope.reason, "SCOPE_BLOCKED");
          }
          await effect.rateLimiter.wait(requestScope.url);
        },
        beforeRequest: (url) => {
          const requestScope = effect.authorizeUrl(url);
          if (!requestScope.allowed) {
            throw new BountyPilotError(requestScope.reason, "SCOPE_BLOCKED");
          }
          return resolveNetworkTarget(requestScope.url).then(() => markDispatch());
        },
        headers: { "User-Agent": "BountyPilot/0.2 action-executor-js" },
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
      allowUrl: (requestUrl) => effect.authorizeUrl(requestUrl).allowed,
      fetchText,
    });
    const artifact = effect.evidence.writeTextArtifact({
      jobId: action.jobId,
      adapterName: "js-analyzer",
      kind: "tool_output",
      sourceUrl: scopedUrl,
      relativePath: path.join(action.jobId ?? "ad-hoc-actions", `${safeFileName(new URL(scopedUrl).hostname)}-js-analysis.json`),
      content: JSON.stringify(result, null, 2),
    });

    let findingsCreated = 0;
    let candidatesCreated = 0;
    if (result.possibleSecrets.length > 0) {
      const scope = effect.scopeGuard.assertAllowed(scopedUrl);
      const duplicate = new DuplicateRiskEngine().estimate(
        {
          title: "Possible secret-like pattern observed in public client-side content",
          asset: scope.host,
          url: scopedUrl,
          category: "public_js_secret_pattern",
        },
        this.runtime.findings.list(),
      );
      const readiness = evaluateFindingCandidateReadiness({
        confidence: "low",
        severity: "medium",
        evidenceCount: 1,
        duplicateRisk: duplicate.risk,
      });
      const finding = this.runtime.findings.create({
        title: "Possible secret-like pattern observed in public client-side content",
        asset: scope.host,
        url: scopedUrl,
        category: "public_js_secret_pattern",
        severityEstimate: "medium",
        confidence: "low",
        status: "needs_manual_review",
        evidencePaths: [artifact.path],
        remediation: "Manually verify whether the masked value is a real secret before reporting or validating impact.",
        duplicateRisk: duplicate.risk,
        reportabilityScore: candidateBaselineReportabilityScore(readiness),
      });
      effect.evidence.linkToFinding(artifact.id, finding.id);
      this.runtime.candidates.create({
        jobId: action.jobId,
        title: finding.title,
        asset: scope.host,
        url: scopedUrl,
        category: finding.category,
        severityEstimate: finding.severityEstimate,
        confidence: finding.confidence,
        status: readiness.status,
        evidenceIds: [artifact.id],
        findingId: finding.id,
        falsePositiveRisk: readiness.falsePositiveRisk,
        duplicateRisk: duplicate.risk,
        reportability: readiness.reportability,
        reasoningSummary: readiness.reasoningSummary,
        nextManualSteps: readiness.nextManualSteps,
      });
      candidatesCreated = 1;
      findingsCreated = 1;
    }

    return {
      message: `JavaScript analysis completed with ${result.endpointCandidates.length} endpoint candidates`,
      evidenceCreated: 1,
      candidatesCreated,
      findingsCreated,
      plannerCandidates: {
        endpointCandidates: [...result.endpointCandidates],
        jsAssets: [...result.scriptUrls],
      },
    };
  }

  private async executePlaywright(
    action: ActionRecord,
    scopedUrl: string,
    effect: EffectAuthorityContext,
    markDispatch: () => void,
  ): Promise<ApprovedActionResult> {
    const audit = createJobAuditLogger(this.runtime.paths, action.jobId ?? "ad-hoc-actions");
    const result = await crawlWithPlaywright({
      url: scopedUrl,
      evidenceDir: this.runtime.paths.evidenceDir,
      jobId: action.jobId,
      evidence: {
        screenshots: effect.config.evidence.screenshots,
        har: effect.config.evidence.har,
        consoleLogs: effect.config.evidence.console_logs,
        domSnapshot: effect.config.evidence.dom_snapshot,
        browserTrace: effect.config.evidence.browser_trace,
        video: effect.config.evidence.video,
      },
      authorizeRequest: async ({ url, method }) => {
        if (method.toUpperCase() !== "GET" && method.toUpperCase() !== "HEAD" && method.toUpperCase() !== "OPTIONS") {
          return { allowed: false, reason: `Browser request method ${method.toUpperCase()} is not allowed` };
        }
        const requestScope = effect.authorizeUrl(url);
        if (!requestScope.allowed) {
          return { allowed: false, reason: requestScope.reason };
        }
        await effect.rateLimiter.wait(requestScope.url);
        return { allowed: true, reason: requestScope.reason };
      },
      onRequest: (event) => {
        audit.log({
          jobId: action.jobId,
          actionType: event.transport === "websocket" ? "browser.websocket" : "browser.request",
          method: event.method,
          url: event.url,
          adapterName: "playwright",
          policyDecision: event.allowed ? "allow" : "block",
          reason: event.reason,
        });
      },
      beforeRequest: async ({ url, method }) => {
        if (method.toUpperCase() !== "GET" && method.toUpperCase() !== "HEAD" && method.toUpperCase() !== "OPTIONS") {
          throw new BountyPilotError(`Browser request method ${method.toUpperCase()} is not allowed`, "POLICY_BLOCKED");
        }
        const requestScope = effect.authorizeUrl(url);
        if (!requestScope.allowed) {
          throw new BountyPilotError(requestScope.reason, "SCOPE_BLOCKED");
        }
        await resolveNetworkTarget(requestScope.url);
        markDispatch();
      },
    });

    for (const artifact of result.evidence) {
      effect.evidence.create(artifact);
    }
    this.runtime.crawlGraph.upsertPage({ url: scopedUrl, title: result.title });
    for (const link of result.links.filter((link) => effect.scopeGuard.test(link).allowed)) {
      this.runtime.crawlGraph.upsertPage({ url: link });
      this.runtime.crawlGraph.addEdge(scopedUrl, link);
    }
    effect.evidence.writeTextArtifact({
      jobId: action.jobId,
      adapterName: "playwright",
      kind: "crawl_graph",
      sourceUrl: scopedUrl,
      relativePath: path.join(
        action.jobId ?? "ad-hoc-actions",
        `${safeFileName(new URL(scopedUrl).hostname)}-crawl-graph.json`,
      ),
      content: JSON.stringify({ url: result.url, title: result.title, links: result.links }, null, 2),
    });

    return {
      message: `Playwright crawl completed with ${result.links.length} discovered links`,
      evidenceCreated: result.evidence.length + 1,
      candidatesCreated: 0,
      findingsCreated: 0,
    };
  }

  private executeLocalPublicResearch(
    action: ActionRecord,
    scopedUrl: string | undefined,
    effect: EffectAuthorityContext,
  ): ApprovedActionResult {
    const artifact = effect.evidence.writeTextArtifact({
      jobId: action.jobId,
      adapterName: action.adapter,
      kind: "research_note",
      sourceUrl: scopedUrl,
      relativePath: path.join(
        action.jobId ?? "ad-hoc-actions",
        `${safeFileName(action.id)}-public-research.json`,
      ),
      content: JSON.stringify(
        {
          kind: "local_public_research_record",
          actionId: action.id,
          program: effect.config.program,
          target: scopedUrl ?? null,
          externalExecution: false,
          note: "Recorded locally; no external research adapter was invoked.",
        },
        null,
        2,
      ),
    });
    return {
      message: `Local public-research record created at ${artifact.path}`,
      evidenceCreated: 1,
      candidatesCreated: 0,
      findingsCreated: 0,
    };
  }
}

function createEffectAuthorityContext(
  claimed: ClaimedActionContext,
  runtime: Runtime,
): EffectAuthorityContext {
  const authority = claimed.effectAuthority;
  if (
    !authority ||
    !authority.config ||
    !authority.programConfig ||
    authority.config !== authority.programConfig ||
    !authority.source
  ) {
    throw new BountyPilotError(
      "Claimed action authority is unavailable for effect execution.",
      "ACTION_EFFECT_AUTHORITY_UNAVAILABLE",
    );
  }
  const config = authority.config;
  const authorityDependencies = createProductionActionAuthorityDependencies({
    programFile: runtime.paths.programFile,
  });
  const expectedHashes = {
    scopeHash: authority.scopeHash,
    policyHash: authority.policyHash,
    actionHash: authority.actionHash,
    contextHash: authority.contextHash,
  };
  const authorizeUrl = (url: string): ScopeMatch => {
    let current;
    try {
      current = materializeActionAuthority(
        authority.source as ActionMaterialSource,
        authorityDependencies,
      );
    } catch {
      throw new BountyPilotError(
        "Current action authority could not be revalidated.",
        "ACTION_EFFECT_AUTHORITY_UNAVAILABLE",
      );
    }
    const challenge = current.challenge;
    if (current.definitiveBlock !== null) {
      throw new BountyPilotError(
        "Current action authority blocks the target request.",
        current.definitiveBlock === "scope" ? "SCOPE_BLOCKED" : "POLICY_BLOCKED",
      );
    }
    if (
      challenge.scopeHash !== expectedHashes.scopeHash ||
      challenge.policyHash !== expectedHashes.policyHash ||
      challenge.actionHash !== expectedHashes.actionHash ||
      challenge.contextHash !== expectedHashes.contextHash
    ) {
      throw new BountyPilotError(
        "Action authority changed before the target request.",
        "ACTION_AUTHORITY_DRIFT",
      );
    }
    return new ScopeGuard(current.material.program.config).test(url);
  };
  return {
    config,
    scopeGuard: new ScopeGuard(config),
    rateLimiter: sharedRateLimiter(runtime, config.rules.rate_limit),
    authorizeUrl,
    evidence: new EvidenceStore(runtime.db, runtime.paths.evidenceDir, {
      maskSecrets: config.evidence.mask_secrets !== false,
      trustedArtifactRoots: [runtime.paths.reportsDir],
    }),
  };
}

function sharedRateLimiter(runtime: Runtime, rateLimit: string): RateLimiter {
  let byRate = rateLimitersByRuntime.get(runtime);
  if (!byRate) {
    byRate = new Map<string, RateLimiter>();
    rateLimitersByRuntime.set(runtime, byRate);
  }
  let limiter = byRate.get(rateLimit);
  if (!limiter) {
    limiter = new RateLimiter(rateLimit);
    byRate.set(rateLimit, limiter);
  }
  return limiter;
}

function rejectPlanningOrHandoff(action: ActionRecord): void {
  if (
    action.requiredForCompletion === false ||
    action.metadata?.planningOnly === true ||
    action.metadata?.handoffOnly === true
  ) {
    throw new BountyPilotError(
      "Planning-only and handoff-only actions cannot be executed.",
      "ACTION_HANDOFF_ONLY",
    );
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

function unsupportedExecution(action: ActionRecord): BountyPilotError {
  return new BountyPilotError(
    `Action ${action.id} is not an allowlisted internal execution surface`,
    "ACTION_EXECUTION_UNSUPPORTED",
  );
}

function actionStatusError(action: ActionRecord): BountyPilotError {
  if (action.status === "running") {
    return new BountyPilotError("Action execution lease is already held.", "ACTION_LEASE_HELD");
  }
  if (action.status === "outcome_unknown") {
    return new BountyPilotError(
      "Action execution requires human reconciliation.",
      "ACTION_RECONCILIATION_REQUIRED",
    );
  }
  if (action.status === "blocked") {
    return new BountyPilotError("Action is blocked by current authority.", "POLICY_BLOCKED");
  }
  if (action.status === "executed" || action.status === "failed") {
    return new BountyPilotError("Action is already terminal.", "ACTION_TERMINAL");
  }
  return new BountyPilotError(
    `Action ${action.id} must be approved before execution`,
    "ACTION_NOT_APPROVED",
  );
}

function failureOutcome(error: unknown, dispatchMarked: boolean): EffectOutcome {
  const errorCode =
    error instanceof BountyPilotError && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)
      ? error.code
      : "ACTION_EFFECT_FAILED";
  const errorMessage =
    error instanceof BountyPilotError
      ? error.message
      : dispatchMarked
        ? "Action effect failed after dispatch."
        : "Action failed before dispatch.";
  return dispatchMarked
    ? { kind: "possibly_dispatched", errorCode, errorMessage }
    : { kind: "not_dispatched", errorCode, errorMessage };
}
