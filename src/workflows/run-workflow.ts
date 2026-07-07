import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { crawlWithPlaywright } from "../engines/crawler/playwright-crawler.js";
import { AgentPlanner, type PlannerActionContext, type PlannerLoopResult } from "../engines/agent-planner/agent-planner.js";
import { DuplicateRiskEngine } from "../engines/duplicate-risk/duplicate-risk-engine.js";
import { candidateBaselineReportabilityScore, evaluateFindingCandidateReadiness } from "../engines/finding-candidates/finding-candidate-engine.js";
import { analyzeJavaScript, type JsAnalysisResult } from "../engines/js-analyzer/js-analyzer.js";
import { writeHackerOneReport } from "../engines/report-generator/report-generator.js";
import { runSafeChecks } from "../engines/safe-checks/safe-checks.js";
import { TriageEngine, type TriageResult } from "../engines/triage/triage-engine.js";
import type { EvidenceArtifact, ExecutionMode, NormalizedFinding, PolicyDecision, RiskLevel } from "../types.js";
import { maskSecrets } from "../utils/secrets.js";
import { nowIso } from "../utils/time.js";
import { BountyPilotError } from "../utils/errors.js";
import type { AuditLogger } from "../core/audit/audit-logger.js";
import type { ActionQueueSummary, ActionRecord } from "../core/actions/action-queue.js";
import type { JobStatus } from "../core/jobs/job-manager.js";
import { fetchScopedText } from "../core/http/scoped-fetch.js";
import { createJobAuditLogger, type Runtime } from "../cli/runtime.js";
import { IntegrationManager, type ResolvedIntegration } from "../integrations/integration-manager/integration-manager.js";
import { ActionExecutor } from "./action-executor.js";

export interface WorkflowOptions {
  target?: string;
  mode: ExecutionMode;
  withComponents?: string[];
  dryRun?: boolean;
  draftReports?: boolean;
  resumeFromJobId?: string;
  resumeSkipPhases?: string[];
  resumeProgress?: ResumeProgress;
}

export interface WorkflowPhaseResult {
  name: string;
  status: "completed" | "failed" | "skipped" | "planned";
  detail: string;
  target?: string;
}

export interface WorkflowSkippedWork {
  phase: string;
  target?: string;
}

export interface WorkflowSummary {
  checkpointVersion?: number;
  jobId: string;
  status: JobStatus;
  program: string;
  target?: string;
  mode: ExecutionMode;
  dryRun: boolean;
  draftReports: boolean;
  components: string[];
  seeds: string[];
  skippedScopeRules: string[];
  phases: WorkflowPhaseResult[];
  candidatesCreated: number;
  findingsCreated: number;
  evidenceCreated: number;
  actionsPlanned: number;
  actionCounts: ActionQueueSummary;
  reportsDrafted: number;
  plannerCandidates?: {
    endpointCandidates: string[];
    jsAssets: string[];
  };
  plannerLoop?: PlannerLoopResult;
  startedAt: string;
  updatedAt: string;
  completedAt?: string;
  failedAt?: string;
  resumedFromJobId?: string;
  resumeSkippedPhases?: string[];
  resumeSkippedWork?: WorkflowSkippedWork[];
  checkpointPath?: string;
  summaryPath?: string;
}

interface ExternalWorkflowComponent {
  name: string;
  capability: string;
  actionType: string;
  riskLevel: RiskLevel;
}

export interface ResumeProgress {
  globalPhases: Set<string>;
  seedPhases: Map<string, Set<string>>;
  plannerCandidates?: WorkflowSummary["plannerCandidates"];
}

export class WorkflowRunner {
  constructor(private readonly runtime: Runtime) {}

  loadSummary(jobId: string): WorkflowSummary | undefined {
    return readWorkflowSummary(this.runtime.paths.jobsDir, jobId);
  }

  async resume(
    jobId: string,
    overrides: Partial<Omit<WorkflowOptions, "resumeFromJobId" | "resumeSkipPhases">> = {},
  ): Promise<WorkflowSummary> {
    const previous = this.loadSummary(jobId);
    if (!previous) {
      throw new BountyPilotError(`Workflow summary not found for job: ${jobId}`, "WORKFLOW_SUMMARY_NOT_FOUND");
    }
    const resumeChangesExecution = hasResumeExecutionOverrides(previous, overrides);
    if (previous.status === "completed" && !resumeChangesExecution) {
      return previous;
    }

    return this.run({
      target: overrides.target ?? previous.target,
      mode: overrides.mode ?? previous.mode,
      withComponents: overrides.withComponents ?? previous.components,
      dryRun: overrides.dryRun ?? previous.dryRun,
      draftReports: overrides.draftReports ?? previous.draftReports,
      resumeFromJobId: jobId,
      resumeProgress: resumeChangesExecution ? emptyResumeProgress() : resumableProgress(previous, this.runtime.actions.list(jobId)),
    });
  }

  async run(options: WorkflowOptions): Promise<WorkflowSummary> {
    const resolved = resolveSeeds(this.runtime, options.target);
    const components = componentSet(options.mode, options.withComponents);
    const job = this.runtime.jobs.create("run", options.mode, options.target ?? this.runtime.config.program);
    const audit = createJobAuditLogger(this.runtime.paths, job.id);
    const startedAt = nowIso();
    const summary: WorkflowSummary = {
      checkpointVersion: 2,
      jobId: job.id,
      status: job.status,
      program: this.runtime.config.program,
      target: options.target,
      mode: options.mode,
      dryRun: options.dryRun === true,
      draftReports: options.draftReports === true,
      components: [...components],
      seeds: resolved.seeds,
      skippedScopeRules: resolved.skippedScopeRules,
      phases: [],
      candidatesCreated: 0,
      findingsCreated: 0,
      evidenceCreated: 0,
      actionsPlanned: 0,
      actionCounts: emptyActionCounts(),
      reportsDrafted: 0,
      plannerCandidates: { endpointCandidates: [], jsAssets: [] },
      startedAt,
      updatedAt: startedAt,
      resumedFromJobId: options.resumeFromJobId,
      resumeSkippedPhases: [],
      resumeSkippedWork: [],
      checkpointPath: workflowCheckpointPath(this.runtime.paths.jobsDir, job.id),
    };
    const resumeProgress = options.resumeProgress ?? resumeProgressFromPhaseNames(options.resumeSkipPhases ?? []);
    const resumeSkipPhases = resumeProgress.globalPhases;
    if (resumeProgress.plannerCandidates) {
      summary.plannerCandidates = copyPlannerCandidates(resumeProgress.plannerCandidates);
    }

    this.runtime.jobs.updateStatus(job.id, "running");
    summary.status = "running";
    this.writeCheckpoint(summary);
    this.runtime.events.record({
      jobId: job.id,
      phase: "workflow",
      status: "running",
      message: "Workflow started.",
      metadata: {
        mode: options.mode,
        target: options.target,
        components: [...components],
        dryRun: summary.dryRun,
        resumedFromJobId: options.resumeFromJobId,
        resumeSkipPhases: [...resumeSkipPhases],
        resumeSkippedSeedPhases: resumeProgressForMetadata(resumeProgress),
      },
    });
    audit.log({
      jobId: job.id,
      actionType: "workflow.start",
      adapterName: "workflow",
      policyDecision: "allow",
      metadata: { mode: options.mode, target: options.target, components: [...components] },
    });

    try {
      this.recordProgramResearchNote(job.id, summary, resumeSkipPhases);

      if (options.dryRun) {
        await this.planDryRunActions(job.id, options.mode, resolved.seeds, components, summary, resumeSkipPhases);
        if (!this.skipResumePhase(summary, "dry-run", resumeSkipPhases)) {
          this.recordPhase(summary, {
            name: "dry-run",
            status: "completed",
            detail: "Planned workflow actions without network execution.",
          });
        }
      } else {
        this.runResearchSkill(job.id, options.mode, resolved.seeds, components, summary, resumeSkipPhases);
        await this.runSafeChecks(job.id, options.mode, resolved.seeds, components, summary, resumeProgress);
        await this.runJsAnalysis(job.id, options.mode, resolved.seeds, components, summary, resumeProgress);
        await this.runPlaywrightCrawl(job.id, options.mode, resolved.seeds, components, summary, resumeProgress);
        await this.runExternalWorkflowComponents(job.id, options.mode, resolved.seeds, components, summary, resumeSkipPhases);
        await this.runPlanner(job.id, options.mode, resolved.seeds, components, summary, resumeSkipPhases);
        this.runTriage(summary, components, resumeSkipPhases);
        if (options.draftReports) {
          this.draftReports(summary, resumeSkipPhases);
        }
      }

      const failedPhases = summary.phases.filter((phase) => phase.status === "failed");
      if (failedPhases.length > 0) {
        const detail = `Workflow failed because ${failedPhases.length} phase(s) failed: ${failedPhases.map((phase) => phase.name).join(", ")}.`;
        summary.status = "failed";
        summary.failedAt = nowIso();
        this.recordPhase(summary, { name: "workflow", status: "failed", detail });
        summary.summaryPath = this.writeSummary(job.id, summary);
        audit.log({
          jobId: job.id,
          actionType: "workflow.failed",
          adapterName: "workflow",
          status: "failed",
          policyDecision: "block",
          reason: detail,
          metadata: {
            failedPhases: failedPhases.map((phase) => ({ name: phase.name, detail: phase.detail })),
            findingsCreated: summary.findingsCreated,
            candidatesCreated: summary.candidatesCreated,
            evidenceCreated: summary.evidenceCreated,
            actionsPlanned: summary.actionsPlanned,
            reportsDrafted: summary.reportsDrafted,
          },
        });
        this.runtime.jobs.updateStatus(job.id, "failed");
        return summary;
      }

      summary.status = "completed";
      summary.completedAt = nowIso();
      this.refreshSummaryState(summary);
      summary.summaryPath = this.writeSummary(job.id, summary);
      audit.log({
        jobId: job.id,
        actionType: "workflow.complete",
        adapterName: "workflow",
        status: "completed",
        policyDecision: "allow",
        metadata: {
          findingsCreated: summary.findingsCreated,
          candidatesCreated: summary.candidatesCreated,
          evidenceCreated: summary.evidenceCreated,
          actionsPlanned: summary.actionsPlanned,
          reportsDrafted: summary.reportsDrafted,
        },
      });
      this.runtime.jobs.updateStatus(job.id, "completed");
      this.runtime.events.record({
        jobId: job.id,
        phase: "workflow",
        status: "completed",
        message: "Workflow completed.",
        metadata: {
          findingsCreated: summary.findingsCreated,
          candidatesCreated: summary.candidatesCreated,
          evidenceCreated: summary.evidenceCreated,
          actionsPlanned: summary.actionsPlanned,
          reportsDrafted: summary.reportsDrafted,
        },
      });
      return summary;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      summary.status = "failed";
      summary.failedAt = nowIso();
      this.recordPhase(summary, { name: "workflow", status: "failed", detail: message });
      summary.summaryPath = this.writeSummary(job.id, summary);
      audit.log({
        jobId: job.id,
        actionType: "workflow.failed",
        adapterName: "workflow",
        status: "failed",
        policyDecision: "block",
        reason: message,
      });
      this.runtime.jobs.updateStatus(job.id, "failed");
      throw error;
    }
  }

  private recordProgramResearchNote(jobId: string, summary: WorkflowSummary, resumeSkipPhases: Set<string>): void {
    if (this.skipResumePhase(summary, "research-note", resumeSkipPhases)) {
      return;
    }

    const content = maskSecrets(`# Program Research Ledger

Program: ${this.runtime.config.program}
Platform: ${this.runtime.config.platform}
Mode: ${summary.mode}

## In Scope
${this.runtime.config.in_scope.map((entry) => `- ${entry}`).join("\n")}

## Out Of Scope
${this.runtime.config.out_of_scope.map((entry) => `- ${entry}`).join("\n")}

## Safety Rules
- Rate limit: ${this.runtime.config.rules.rate_limit}
- Destructive testing: ${this.runtime.config.rules.destructive_testing}
- Human approval for risky actions: ${this.runtime.config.rules.require_human_approval_for_risky_actions}

This note is local program context only. It is not authorization beyond the imported program scope.
`);
    this.runtime.evidence.writeTextArtifact({
      jobId,
      adapterName: "workflow",
      kind: "research_note",
      relativePath: path.join(jobId, "program-research.md"),
      content,
    });
    summary.evidenceCreated += 1;
    this.recordPhase(summary, {
      name: "research-note",
      status: "completed",
      detail: "Saved local program rules and scope context.",
    });
  }

  private async planDryRunActions(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    components: Set<string>,
    summary: WorkflowSummary,
    resumeSkipPhases: Set<string>,
  ): Promise<void> {
    if (this.skipResumePhase(summary, "action-planning", resumeSkipPhases)) {
      return;
    }

    if (seeds.length === 0) {
      this.recordPhase(summary, {
        name: "action-planning",
        status: "skipped",
        detail: "No in-scope seeds were available for dry-run planning.",
      });
      return;
    }

    const audit = createJobAuditLogger(this.runtime.paths, jobId);
    let plannedCount = 0;
    let pending = 0;
    let blocked = 0;
    for (const seed of seeds) {
      const actions = plannedComponentActions(seed, components);
      for (const action of actions) {
        const result = this.planWorkflowAction({
          audit,
          jobId,
          adapter: action.adapter,
          actionType: action.actionType,
          target: seed,
          mode,
          riskLevel: action.riskLevel,
        });
        plannedCount += 1;
        if (result.decision === "require_approval") pending += 1;
        if (result.decision === "block") blocked += 1;
        summary.actionsPlanned += 1;
      }
    }

    this.recordPhase(summary, {
      name: "action-planning",
      status: blocked > 0 || pending > 0 ? "planned" : "completed",
      detail: `${plannedCount} actions planned (${pending} pending approval, ${blocked} blocked by policy).`,
    });
  }

  private runResearchSkill(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    components: Set<string>,
    summary: WorkflowSummary,
    resumeSkipPhases: Set<string>,
  ): void {
    const componentName = "d-research-skill";
    if (!components.has(componentName)) {
      return;
    }
    if (this.skipResumePhase(summary, componentName, resumeSkipPhases)) {
      return;
    }
    if (seeds.length === 0) {
      this.recordPhase(summary, {
        name: componentName,
        status: "skipped",
        detail: "No in-scope seeds were available for local public research planning.",
      });
      return;
    }

    const audit = createJobAuditLogger(this.runtime.paths, jobId);
    const actions: ActionRecord[] = [];
    for (const seed of seeds) {
      const planned = this.planWorkflowAction({
        audit,
        jobId,
        adapter: componentName,
        actionType: "research.public",
        target: seed,
        mode,
        riskLevel: "low",
        capability: "research.public",
      });
      summary.actionsPlanned += 1;
      if (planned.allowed) {
        actions.push(this.runtime.actions.markExecuted(planned.action.id));
      } else {
        actions.push(planned.action);
      }
    }

    const source = researchSkillSource(this.runtime.config.integrations.d_research_skill);
    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId,
      adapterName: componentName,
      kind: "research_note",
      relativePath: path.join(jobId, "d-research-ledger.md"),
      content: maskSecrets(`# Public Research Ledger

Program: ${this.runtime.config.program}
Platform: ${this.runtime.config.platform}
Mode: ${mode}
Adapter: ${componentName}
Source: ${source ?? "local planning only"}

## Seeds
${seeds.map((seed) => `- ${seed}`).join("\n")}

## Skipped Scope Rules
${summary.skippedScopeRules.length > 0 ? summary.skippedScopeRules.map((rule) => `- ${rule}`).join("\n") : "- none"}

## Action Queue
${actions.map((action) => `- ${action.id}: ${action.target ?? "program"} (${action.status})`).join("\n")}

## Notes
- Public research does not expand authorization beyond the imported program scope.
- This workflow phase creates local research context only and does not execute external skills.
- Add citations, program policy observations, and duplicate signals here before drafting reports.
`),
    });
    summary.evidenceCreated += 1;
    this.recordPhase(summary, {
      name: componentName,
      status: "completed",
      detail: `${actions.length} local public research actions recorded. Ledger: ${artifact.path}`,
    });
  }

  private async runSafeChecks(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    components: Set<string>,
    summary: WorkflowSummary,
    resumeProgress: ResumeProgress,
  ): Promise<void> {
    if (!components.has("safe-checks")) {
      this.recordPhase(summary, { name: "safe-checks", status: "skipped", detail: "Component not selected." });
      return;
    }
    if (this.skipResumePhase(summary, "safe-checks", resumeProgress.globalPhases)) {
      return;
    }

    for (const seed of seeds) {
      const scope = this.runtime.scopeGuard.assertAllowed(seed);
      if (this.skipResumeSeedPhase(summary, "safe-checks", scope.url, resumeProgress)) {
        continue;
      }
      const audit = createJobAuditLogger(this.runtime.paths, jobId);
      const planned = this.planWorkflowAction({
        audit,
        jobId,
        adapter: "safe-checks",
        actionType: "http.get",
        target: scope.url,
        mode,
        riskLevel: "low",
      });
      summary.actionsPlanned += 1;
      if (!planned.allowed) {
        this.recordPhase(summary, {
          name: "safe-checks",
          status: planned.decision === "block" ? "skipped" : "planned",
          target: scope.url,
          detail: `${scope.url}: ${planned.reason}`,
        });
        continue;
      }

      try {
        await this.runtime.rateLimiter.wait(scope.url);
        const started = Date.now();
        const result = await runSafeChecks(scope.url);
        const artifact = this.runtime.evidence.writeTextArtifact({
          jobId,
          adapterName: "safe-checks",
          kind: "tool_output",
          sourceUrl: scope.url,
          relativePath: path.join(jobId, `${safeFileName(scope.host)}-safe-checks.json`),
          content: JSON.stringify(result, null, 2),
        });
        summary.evidenceCreated += 1;

        for (const candidate of result.findings) {
          const duplicate = new DuplicateRiskEngine().estimate(
            {
              title: candidate.title,
              asset: scope.host,
              url: scope.url,
              category: candidate.category,
            },
            this.runtime.findings.list(),
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
            url: scope.url,
            category: candidate.category,
            severityEstimate: candidate.severityEstimate,
            confidence: candidate.confidence,
            status: "needs_validation",
            evidencePaths: [artifact.path],
            remediation: candidate.remediation,
            duplicateRisk: duplicate.risk,
            reportabilityScore: candidateBaselineReportabilityScore(readiness),
          });
          this.runtime.evidence.linkToFinding(artifact.id, finding.id);
          this.runtime.candidates.create({
            jobId,
            title: candidate.title,
            asset: scope.host,
            url: scope.url,
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
          summary.candidatesCreated += 1;
          summary.findingsCreated += 1;
        }

        audit.log({
          jobId,
          actionType: "http.get",
          url: scope.url,
          adapterName: "safe-checks",
          status: result.status,
          durationMs: Date.now() - started,
          policyDecision: "allow",
          metadata: { findings: result.findings.length },
        });
        this.runtime.actions.markExecuted(planned.action.id);
        this.recordPhase(summary, {
          name: "safe-checks",
          status: "completed",
          target: scope.url,
          detail: `${scope.host}: ${result.findings.length} candidates.`,
        });
      } catch (error) {
        this.runtime.actions.fail(planned.action.id);
        this.recordPhase(summary, { name: "safe-checks", status: "failed", target: scope.url, detail: `${scope.url}: ${errorMessage(error)}` });
      }
    }
  }

  private async runJsAnalysis(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    components: Set<string>,
    summary: WorkflowSummary,
    resumeProgress: ResumeProgress,
  ): Promise<void> {
    if (!components.has("js-analyzer")) {
      this.recordPhase(summary, { name: "js-analyzer", status: "skipped", detail: "Component not selected." });
      return;
    }
    if (this.skipResumePhase(summary, "js-analyzer", resumeProgress.globalPhases)) {
      return;
    }

    for (const seed of seeds) {
      const scope = this.runtime.scopeGuard.assertAllowed(seed);
      if (this.skipResumeSeedPhase(summary, "js-analyzer", scope.url, resumeProgress)) {
        continue;
      }
      const audit = createJobAuditLogger(this.runtime.paths, jobId);
      const planned = this.planWorkflowAction({
        audit,
        jobId,
        adapter: "js-analyzer",
        actionType: "http.get",
        target: scope.url,
        mode,
        riskLevel: "low",
      });
      summary.actionsPlanned += 1;
      if (!planned.allowed) {
        this.recordPhase(summary, {
          name: "js-analyzer",
          status: planned.decision === "block" ? "skipped" : "planned",
          target: scope.url,
          detail: `${scope.url}: ${planned.reason}`,
        });
        continue;
      }

      const fetchText = async (requestUrl: string): Promise<string> => {
        return fetchScopedText(requestUrl, {
          allowUrl: (url) => this.runtime.scopeGuard.test(url).allowed,
          wait: async (url) => {
            const requestScope = this.runtime.scopeGuard.assertAllowed(url);
            await this.runtime.rateLimiter.wait(requestScope.url);
          },
          headers: { "User-Agent": "BountyPilot/0.1 workflow-js-analyzer" },
          onRequest: (event) => {
            audit.log({
              jobId,
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
              jobId,
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

      try {
        const result = await analyzeJavaScript(scope.url, {
          allowUrl: (requestUrl) => this.runtime.scopeGuard.test(requestUrl).allowed,
          fetchText,
        });
        this.recordPlannerCandidates(summary, scope.url, result);
        const artifact = this.runtime.evidence.writeTextArtifact({
          jobId,
          adapterName: "js-analyzer",
          kind: "tool_output",
          sourceUrl: scope.url,
          relativePath: path.join(jobId, `${safeFileName(scope.host)}-js-analysis.json`),
          content: JSON.stringify(result, null, 2),
        });
        summary.evidenceCreated += 1;

        if (result.possibleSecrets.length > 0) {
          const duplicate = new DuplicateRiskEngine().estimate(
            {
              title: "Possible secret-like pattern observed in public client-side content",
              asset: scope.host,
              url: scope.url,
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
            url: scope.url,
            category: "public_js_secret_pattern",
            severityEstimate: "medium",
            confidence: "low",
            status: "needs_manual_review",
            evidencePaths: [artifact.path],
            remediation: "Manually verify whether the masked value is a real secret before reporting or validating impact.",
            duplicateRisk: duplicate.risk,
            reportabilityScore: candidateBaselineReportabilityScore(readiness),
          });
          this.runtime.evidence.linkToFinding(artifact.id, finding.id);
          this.runtime.candidates.create({
            jobId,
            title: finding.title,
            asset: scope.host,
            url: scope.url,
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
          summary.candidatesCreated += 1;
          summary.findingsCreated += 1;
        }

        this.runtime.actions.markExecuted(planned.action.id);
        this.recordPhase(summary, {
          name: "js-analyzer",
          status: "completed",
          target: scope.url,
          detail: `${scope.host}: ${result.scriptUrls.length} scripts, ${result.endpointCandidates.length} endpoint candidates.`,
        });
      } catch (error) {
        this.runtime.actions.fail(planned.action.id);
        this.recordPhase(summary, { name: "js-analyzer", status: "failed", target: scope.url, detail: `${scope.url}: ${errorMessage(error)}` });
      }
    }
  }

  private async runPlaywrightCrawl(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    components: Set<string>,
    summary: WorkflowSummary,
    resumeProgress: ResumeProgress,
  ): Promise<void> {
    if (!components.has("playwright")) {
      this.recordPhase(summary, { name: "playwright", status: "skipped", detail: "Component not selected." });
      return;
    }
    if (this.skipResumePhase(summary, "playwright", resumeProgress.globalPhases)) {
      return;
    }

    for (const seed of seeds.slice(0, 3)) {
      const scope = this.runtime.scopeGuard.assertAllowed(seed);
      if (this.skipResumeSeedPhase(summary, "playwright", scope.url, resumeProgress)) {
        continue;
      }
      const audit = createJobAuditLogger(this.runtime.paths, jobId);
      const planned = this.planWorkflowAction({
        audit,
        jobId,
        adapter: "playwright",
        actionType: "browser.navigate",
        target: scope.url,
        mode,
        riskLevel: "low",
      });
      summary.actionsPlanned += 1;
      if (!planned.allowed) {
        this.recordPhase(summary, {
          name: "playwright",
          status: planned.decision === "block" ? "skipped" : "planned",
          target: scope.url,
          detail: `${scope.url}: ${planned.reason}`,
        });
        continue;
      }

      try {
        await this.runtime.rateLimiter.wait(scope.url);
        const result = await crawlWithPlaywright({
          url: scope.url,
          evidenceDir: this.runtime.paths.evidenceDir,
          jobId,
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
              jobId,
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
          summary.evidenceCreated += 1;
        }
        this.runtime.crawlGraph.upsertPage({ url: scope.url, title: result.title });
        for (const link of result.links.filter((link) => this.runtime.scopeGuard.test(link).allowed)) {
          this.runtime.crawlGraph.upsertPage({ url: link });
          this.runtime.crawlGraph.addEdge(scope.url, link);
        }
        this.runtime.evidence.writeTextArtifact({
          jobId,
          adapterName: "playwright",
          kind: "crawl_graph",
          sourceUrl: scope.url,
          relativePath: path.join(jobId, `${safeFileName(scope.host)}-crawl-graph.json`),
          content: JSON.stringify({ url: result.url, title: result.title, links: result.links }, null, 2),
        });
        summary.evidenceCreated += 1;
        this.runtime.actions.markExecuted(planned.action.id);
        this.recordPhase(summary, {
          name: "playwright",
          status: "completed",
          target: scope.url,
          detail: `${scope.host}: captured ${result.evidence.length + 1} artifacts and ${result.links.length} links.`,
        });
      } catch (error) {
        this.runtime.actions.fail(planned.action.id);
        this.recordPhase(summary, { name: "playwright", status: "failed", target: scope.url, detail: `${scope.url}: ${errorMessage(error)}` });
      }
    }
  }

  private async runPlanner(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    components: Set<string>,
    summary: WorkflowSummary,
    resumeSkipPhases: Set<string>,
  ): Promise<void> {
    if (!components.has("planner")) {
      this.recordPhase(summary, { name: "planner", status: "skipped", detail: "Component not selected." });
      return;
    }
    if (this.skipResumePhase(summary, "planner", resumeSkipPhases)) {
      return;
    }
    if (mode === "passive") {
      this.recordPhase(summary, {
        name: "planner",
        status: "skipped",
        detail: "Passive mode records context only and does not queue active HTTP/browser actions.",
      });
      return;
    }

    const pages = this.runtime.crawlGraph
      .listPages()
      .map((page) => page.url)
      .filter((url) => this.runtime.scopeGuard.test(url).allowed);
    const reconObservations = this.runtime.recon?.list({ scopeAllowed: true, limit: 1000 }) ?? [];
    const reconUrls = reconObservations
      .filter((observation) => observation.kind === "url" || observation.kind === "endpoint" || observation.kind === "js_asset" || observation.kind === "parameter")
      .map((observation) => observation.normalizedValue)
      .filter((url) => this.runtime.scopeGuard.test(url).allowed);
    const reconEndpoints = reconObservations
      .filter((observation) => observation.kind === "endpoint" || observation.kind === "parameter")
      .map((observation) => observation.normalizedValue)
      .filter((url) => this.runtime.scopeGuard.test(url).allowed);
    const reconJsAssets = reconObservations
      .filter((observation) => observation.kind === "js_asset")
      .map((observation) => observation.normalizedValue)
      .filter((url) => this.runtime.scopeGuard.test(url).allowed);
    const plannerFeedbackFindings = this.plannerFeedbackFindings(summary);
    const plannerFeedbackEvidence = this.plannerFeedbackEvidence(summary);
    const plannerActionContext = this.plannerActionContext(summary);
    const planLoop = new AgentPlanner().planLoop({
      urls: [...new Set([...seeds, ...pages, ...reconUrls])],
      endpointCandidates: [...new Set([...(summary.plannerCandidates?.endpointCandidates ?? []), ...reconEndpoints])],
      jsAssets: [...new Set([...(summary.plannerCandidates?.jsAssets ?? []), ...reconJsAssets])],
      mode,
      findings: plannerFeedbackFindings,
      evidence: plannerFeedbackEvidence,
      actions: plannerActionContext,
      maxIterations: 3,
    });
    summary.plannerLoop = planLoop;
    const plannerArtifact = this.runtime.evidence.writeTextArtifact({
      jobId,
      adapterName: "planner",
      kind: "tool_output",
      relativePath: path.join(jobId, "planner-loop.json"),
      content: JSON.stringify(planLoop, null, 2),
    });
    summary.evidenceCreated += 1;
    const audit = createJobAuditLogger(this.runtime.paths, jobId);

    let enqueued = 0;
    let pending = 0;
    let blocked = 0;
    for (const action of planLoop.actions) {
      if (!this.runtime.scopeGuard.test(action.target).allowed) {
        continue;
      }
      const planned = this.planWorkflowAction({
        audit,
        jobId,
        adapter: action.adapter,
        actionType: action.actionType,
        target: action.target,
        mode,
        riskLevel: action.riskLevel,
      });
      enqueued += 1;
      if (planned.decision === "require_approval") pending += 1;
      if (planned.decision === "block") blocked += 1;
    }
    summary.actionsPlanned += enqueued;
    const suppressed = planLoop.iterations.reduce(
      (total, iteration) =>
        total + iteration.skippedDuplicates + iteration.skippedExistingActions + iteration.skippedFailedOrBlockedHistory,
      0,
    );
    this.recordPhase(summary, {
      name: "planner",
      status: pending > 0 || blocked > 0 ? "planned" : "completed",
      detail: `${enqueued} safe next actions queued (${pending} pending approval, ${blocked} blocked by policy, ${suppressed} suppressed). Plan: ${plannerArtifact.path}`,
    });
  }

  private async runExternalWorkflowComponents(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    components: Set<string>,
    summary: WorkflowSummary,
    resumeSkipPhases: Set<string>,
  ): Promise<void> {
    for (const component of EXTERNAL_WORKFLOW_COMPONENTS) {
      if (!components.has(component.name)) {
        continue;
      }
      if (this.skipResumePhase(summary, component.name, resumeSkipPhases)) {
        continue;
      }
      await this.runExternalWorkflowComponent(jobId, mode, seeds, component, summary);
    }
  }

  private async runExternalWorkflowComponent(
    jobId: string,
    mode: ExecutionMode,
    seeds: string[],
    component: ExternalWorkflowComponent,
    summary: WorkflowSummary,
  ): Promise<void> {
    if (seeds.length === 0) {
      this.recordPhase(summary, {
        name: component.name,
        status: "skipped",
        detail: "No in-scope seeds were available for external component execution.",
      });
      return;
    }

    const manager = new IntegrationManager(this.runtime.config);
    const integration = manager.get(component.name);
    if (!integration) {
      this.recordPhase(summary, {
        name: component.name,
        status: "skipped",
        detail: `Integration ${component.name} is not registered.`,
      });
      return;
    }

    const readiness = externalWorkflowExecutionReadiness(integration);
    if (!readiness.ok) {
      this.recordPhase(summary, {
        name: component.name,
        status: "skipped",
        detail: readiness.detail,
      });
      return;
    }

    const audit = createJobAuditLogger(this.runtime.paths, jobId);
    const executor = new ActionExecutor(this.runtime);
    let planned = 0;
    let executed = 0;
    let pending = 0;
    let failed = 0;
    let blocked = 0;
    const reasons: string[] = [];

    for (const seed of seeds) {
      const scope = this.runtime.scopeGuard.assertAllowed(seed);
      const validation = manager.validateCallPlan({
        integration: integration.name,
        capability: component.capability,
        actionType: component.actionType,
        target: scope.url,
        mode,
        riskLevel: component.riskLevel,
      });
      if (!validation.ok) {
        blocked += 1;
        reasons.push(`${scope.url}: ${validation.reasons.join("; ")}`);
        continue;
      }

      try {
        const action = this.planWorkflowAction({
          audit,
          jobId,
          adapter: component.name,
          actionType: component.actionType,
          target: scope.url,
          mode,
          riskLevel: component.riskLevel,
          capability: component.capability,
        });
        summary.actionsPlanned += 1;
        planned += 1;
        if (!action.allowed) {
          pending += 1;
          continue;
        }

        const result = await executor.execute(action.action.id);
        summary.evidenceCreated += result.evidenceCreated;
        summary.findingsCreated += result.findingsCreated;
        summary.candidatesCreated += result.candidatesCreated;
        executed += 1;
      } catch (error) {
        failed += 1;
        reasons.push(`${scope.url}: ${errorMessage(error)}`);
      }
    }

    this.recordPhase(summary, {
      name: component.name,
      status: externalWorkflowPhaseStatus({ executed, pending, failed, blocked }),
      detail: externalWorkflowPhaseDetail(component.name, { planned, executed, pending, failed, blocked, reasons }),
    });
  }

  private runTriage(summary: WorkflowSummary, components: Set<string>, resumeSkipPhases: Set<string>): void {
    if (!components.has("triage")) {
      this.recordPhase(summary, { name: "triage", status: "skipped", detail: "Component not selected." });
      return;
    }
    if (this.skipResumePhase(summary, "triage", resumeSkipPhases)) {
      return;
    }

    const scopedFindings = this.workflowFindingEvidence(summary);
    const triageEngine = new TriageEngine();
    const results: TriageResult[] = scopedFindings.map(({ finding, evidence }) => triageEngine.triage(finding, evidence));
    const content = JSON.stringify(results, null, 2);
    this.runtime.evidence.writeTextArtifact({
      jobId: summary.jobId,
      adapterName: "triage",
      kind: "tool_output",
      relativePath: path.join(summary.jobId, "triage.json"),
      content,
    });
    summary.evidenceCreated += 1;
    this.recordPhase(summary, { name: "triage", status: "completed", detail: `${results.length} job-scoped findings scored.` });
  }

  private draftReports(summary: WorkflowSummary, resumeSkipPhases: Set<string>): void {
    if (this.skipResumePhase(summary, "reports", resumeSkipPhases)) {
      return;
    }

    const scopedFindings = this.workflowFindingEvidence(summary);
    for (const { finding, evidence } of scopedFindings) {
      const triage = new TriageEngine().triage(finding, evidence);
      if (triage.reportabilityScore < 60 || triage.recommendation === "do_not_report_alone") {
        continue;
      }
      const reportPath = writeHackerOneReport(this.runtime.paths.reportsDir, finding, evidence);
      this.runtime.evidence.create({
        findingId: finding.id,
        adapterName: "report-generator",
        kind: "report",
        sourceUrl: finding.url,
        path: reportPath,
      });
      this.runtime.findings.updateStatus(finding.id, "report_drafted");
      summary.reportsDrafted += 1;
      summary.evidenceCreated += 1;
    }
    this.recordPhase(summary, {
      name: "reports",
      status: "completed",
      detail: `${summary.reportsDrafted} local report drafts generated from ${scopedFindings.length} job-scoped findings.`,
    });
  }

  private workflowFindingEvidence(summary: WorkflowSummary): Array<{ finding: NormalizedFinding; evidence: EvidenceArtifact[] }> {
    return this.runtime.findings
      .list()
      .map((finding) => ({
        finding,
        evidence: this.runtime.evidence.list(finding.id).filter((artifact) => artifact.jobId === summary.jobId),
      }))
      .filter((item) => item.evidence.length > 0);
  }

  private plannerFeedbackEvidence(summary: WorkflowSummary): EvidenceArtifact[] {
    const jobIds = plannerFeedbackJobIds(summary);
    return this.runtime.evidence.list().filter((artifact) => artifact.jobId !== undefined && jobIds.has(artifact.jobId));
  }

  private plannerFeedbackFindings(summary: WorkflowSummary): NormalizedFinding[] {
    const jobIds = plannerFeedbackJobIds(summary);
    return this.runtime.findings
      .list()
      .filter((finding) => this.runtime.evidence.list(finding.id).some((artifact) => artifact.jobId !== undefined && jobIds.has(artifact.jobId)));
  }

  private plannerActionContext(summary: WorkflowSummary): PlannerActionContext[] {
    const jobIds = plannerFeedbackJobIds(summary);
    return [...jobIds].flatMap((jobId) =>
      this.runtime.actions.list(jobId).map((action) => ({
        adapter: action.adapter,
        actionType: action.actionType,
        target: action.target,
        status: action.status,
      })),
    );
  }

  private planWorkflowAction(input: {
    audit: AuditLogger;
    jobId: string;
    adapter: string;
    actionType: string;
    target?: string;
    mode: ExecutionMode;
    riskLevel: RiskLevel;
    stateChanging?: boolean;
    destructive?: boolean;
    capability?: string;
  }): { action: ActionRecord; allowed: boolean; decision: PolicyDecision; reason: string } {
    const policy = this.runtime.policyGate.evaluate({
      mode: input.mode,
      actionType: input.actionType,
      target: input.target,
      riskLevel: input.riskLevel,
      stateChanging: input.stateChanging,
      destructive: input.destructive,
      capability: input.capability,
      labModeEnabled: this.runtime.config.rules.lab_mode === true,
    });

    const action = this.runtime.actions.enqueue({
      jobId: input.jobId,
      adapter: input.adapter,
      actionType: input.actionType,
      target: input.target,
      riskLevel: input.riskLevel,
      requiresApproval: policy.decision === "require_approval",
      status: policy.decision === "block" ? "blocked" : undefined,
    });

    input.audit.log({
      jobId: input.jobId,
      actionType: input.actionType,
      url: input.target,
      adapterName: input.adapter,
      policyDecision: policy.decision,
      reason: policy.reason,
      metadata: { actionId: action.id, actionStatus: action.status },
    });

    if (policy.decision === "block") {
      throw new BountyPilotError(policy.reason, "POLICY_BLOCKED");
    }

    return {
      action,
      allowed: policy.decision === "allow",
      decision: policy.decision,
      reason: policy.reason,
    };
  }

  private recordPlannerCandidates(summary: WorkflowSummary, baseUrl: string, result: JsAnalysisResult): void {
    summary.plannerCandidates ??= { endpointCandidates: [], jsAssets: [] };
    summary.plannerCandidates.jsAssets = mergeUniqueScopedUrls(
      summary.plannerCandidates.jsAssets,
      result.scriptUrls,
      baseUrl,
      this.runtime,
    );
    summary.plannerCandidates.endpointCandidates = mergeUniqueScopedUrls(
      summary.plannerCandidates.endpointCandidates,
      result.endpointCandidates,
      baseUrl,
      this.runtime,
    );
  }

  private recordPhase(summary: WorkflowSummary, phase: WorkflowPhaseResult): void {
    summary.phases.push(phase);
    this.runtime.events.record({
      jobId: summary.jobId,
      phase: phase.name,
      status: phase.status,
      message: phase.detail,
      metadata: {
        mode: summary.mode,
        target: phase.target ?? summary.target,
        phaseTarget: phase.target,
        actionsPlanned: summary.actionsPlanned,
        evidenceCreated: summary.evidenceCreated,
        findingsCreated: summary.findingsCreated,
        candidatesCreated: summary.candidatesCreated,
      },
    });
    this.writeCheckpoint(summary);
  }

  private skipResumePhase(summary: WorkflowSummary, phaseName: string, resumeSkipPhases: Set<string>): boolean {
    if (!resumeSkipPhases.has(phaseName)) {
      return false;
    }
    summary.resumeSkippedPhases ??= [];
    pushUnique(summary.resumeSkippedPhases, phaseName);
    summary.resumeSkippedWork ??= [];
    summary.resumeSkippedWork.push({ phase: phaseName });
    this.recordPhase(summary, {
      name: phaseName,
      status: "skipped",
      detail: `Skipped because ${phaseName} already completed in resumed job ${summary.resumedFromJobId}.`,
    });
    return true;
  }

  private skipResumeSeedPhase(
    summary: WorkflowSummary,
    phaseName: string,
    target: string,
    resumeProgress: ResumeProgress,
  ): boolean {
    const normalizedTarget = normalizeResumeTarget(target);
    if (!resumeProgress.seedPhases.get(phaseName)?.has(normalizedTarget)) {
      return false;
    }
    summary.resumeSkippedPhases ??= [];
    pushUnique(summary.resumeSkippedPhases, phaseName);
    summary.resumeSkippedWork ??= [];
    summary.resumeSkippedWork.push({ phase: phaseName, target });
    this.recordPhase(summary, {
      name: phaseName,
      status: "skipped",
      target,
      detail: `Skipped because ${phaseName} already completed for ${target} in resumed job ${summary.resumedFromJobId}.`,
    });
    return true;
  }

  private refreshSummaryState(summary: WorkflowSummary): void {
    summary.actionCounts = this.runtime.actions.summarize(summary.jobId);
    summary.updatedAt = nowIso();
  }

  private writeCheckpoint(summary: WorkflowSummary): string {
    this.refreshSummaryState(summary);
    const checkpointPath = summary.checkpointPath ?? workflowCheckpointPath(this.runtime.paths.jobsDir, summary.jobId);
    summary.checkpointPath = checkpointPath;
    mkdirSync(path.dirname(checkpointPath), { recursive: true });
    writeFileSync(checkpointPath, summaryContent(summary), "utf8");
    return checkpointPath;
  }

  private writeSummary(jobId: string, summary: WorkflowSummary): string {
    const relativePath = path.join(jobId, "workflow-summary.json");
    summary.summaryPath = path.join(this.runtime.paths.evidenceDir, relativePath);
    this.writeCheckpoint(summary);
    const artifact = this.runtime.evidence.writeTextArtifact({
      jobId,
      adapterName: "workflow",
      kind: "tool_output",
      relativePath,
      content: summaryContent(summary),
    });
    return artifact.path;
  }
}

function componentSet(mode: ExecutionMode, selected?: string[]): Set<string> {
  if (selected && selected.length > 0) {
    return new Set(selected.map((item) => normalizeComponent(item)).map((item) => validateComponent(item)));
  }

  if (mode === "passive") {
    return new Set(["planner"]);
  }
  if (mode === "safe") {
    return new Set(["safe-checks", "js-analyzer", "triage", "planner"]);
  }
  return new Set(["safe-checks", "js-analyzer", "playwright", "triage", "planner"]);
}

const WORKFLOW_COMPONENTS = new Set([
  "safe-checks",
  "js-analyzer",
  "playwright",
  "triage",
  "planner",
  "crawl4ai",
  "playwright-mcp",
  "d-research-skill",
]);

function validateComponent(component: string): string {
  if (WORKFLOW_COMPONENTS.has(component)) {
    return component;
  }
  throw new BountyPilotError(
    `Unsupported workflow component: ${component}. Use one of: ${[...WORKFLOW_COMPONENTS].join(", ")}.`,
    "WORKFLOW_COMPONENT_INVALID",
  );
}

function normalizeComponent(component: string): string {
  const value = component.trim().toLowerCase();
  if (value === "js") return "js-analyzer";
  if (value === "crawl" || value === "browser") return "playwright";
  if (value === "playwright_mcp" || value === "playwright-mcp") return "playwright-mcp";
  if (value === "safe") return "safe-checks";
  if (value === "agent") return "planner";
  if (value === "d-research" || value === "d_research" || value === "d-research-skill" || value === "d_research_skill") {
    return "d-research-skill";
  }
  return value;
}

function plannedComponentActions(seed: string, components: Set<string>): Array<{ adapter: string; actionType: string; riskLevel: "low" | "medium" | "high" }> {
  const actions: Array<{ adapter: string; actionType: string; riskLevel: "low" | "medium" | "high" }> = [];
  if (components.has("safe-checks")) actions.push({ adapter: "safe-checks", actionType: "http.get", riskLevel: "low" });
  if (components.has("js-analyzer")) actions.push({ adapter: "js-analyzer", actionType: "http.get", riskLevel: "low" });
  if (components.has("playwright")) actions.push({ adapter: "playwright", actionType: "browser.navigate", riskLevel: "low" });
  if (components.has("playwright-mcp")) actions.push({ adapter: "playwright-mcp", actionType: "browser.navigate", riskLevel: "low" });
  if (components.has("crawl4ai")) actions.push({ adapter: "crawl4ai", actionType: "crawler.fetch", riskLevel: "low" });
  if (components.has("d-research-skill")) actions.push({ adapter: "d-research-skill", actionType: "research.public", riskLevel: "low" });
  if (components.has("planner")) actions.push({ adapter: "planner", actionType: "agent.plan", riskLevel: "low" });
  void seed;
  return actions;
}

const EXTERNAL_WORKFLOW_COMPONENTS: ExternalWorkflowComponent[] = [
  {
    name: "playwright-mcp",
    capability: "browser.navigate",
    actionType: "browser.navigate",
    riskLevel: "low",
  },
  {
    name: "crawl4ai",
    capability: "crawler.fetch",
    actionType: "crawler.fetch",
    riskLevel: "low",
  },
];

function externalWorkflowExecutionReadiness(integration: ResolvedIntegration): { ok: boolean; detail: string } {
  if (integration.status !== "configured") {
    return {
      ok: false,
      detail: `Integration ${integration.name} is ${integration.status}: ${integration.message ?? "not ready"}.`,
    };
  }
  if (!integrationExecutionEnabled(integration)) {
    return {
      ok: false,
      detail: `Integration ${integration.name} is planning-only; set allow_execute=true or execution.enabled=true to run it inside a workflow.`,
    };
  }
  if (integration.type === "mcp" && (integration.config.transport ?? integration.registration?.mcp?.defaultTransport) !== "stdio") {
    return {
      ok: false,
      detail: `Integration ${integration.name} is configured for non-stdio MCP transport; workflow execution currently supports stdio MCP only.`,
    };
  }
  if (!hasExternalProcessLaunchConfig(integration)) {
    return {
      ok: false,
      detail: `Integration ${integration.name} has no execution command or pinned package entrypoint configured.`,
    };
  }
  return { ok: true, detail: `Integration ${integration.name} is ready for workflow execution.` };
}

function integrationExecutionEnabled(integration: ResolvedIntegration): boolean {
  return integration.config.allow_execute === true || integration.config.execution?.enabled === true;
}

function hasExternalProcessLaunchConfig(integration: ResolvedIntegration): boolean {
  return Boolean(integration.config.execution?.command ?? integration.config.command) || hasPackageEntrypointConfig(integration);
}

function hasPackageEntrypointConfig(integration: ResolvedIntegration): boolean {
  const packageName = integration.config.execution?.package ?? integration.config.package;
  const packageVersion = integration.config.execution?.package_version ?? integration.config.package_version;
  const entrypoint = integration.config.execution?.entrypoint ?? integration.config.entrypoint;
  return hasConfigValue(packageName) && hasConfigValue(packageVersion) && hasConfigValue(entrypoint);
}

function hasConfigValue(value: unknown): boolean {
  return Array.isArray(value) ? value.length > 0 : value !== undefined && value !== "";
}

function researchSkillSource(config: unknown): string | undefined {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    return undefined;
  }
  const source = (config as { source?: unknown }).source;
  return typeof source === "string" && source.trim().length > 0 ? source : undefined;
}

function externalWorkflowPhaseStatus(input: {
  executed: number;
  pending: number;
  failed: number;
  blocked: number;
}): WorkflowPhaseResult["status"] {
  if (input.failed > 0) return "failed";
  if (input.pending > 0) return "planned";
  if (input.executed > 0) return "completed";
  if (input.blocked > 0) return "skipped";
  return "skipped";
}

function externalWorkflowPhaseDetail(
  componentName: string,
  input: { planned: number; executed: number; pending: number; failed: number; blocked: number; reasons: string[] },
): string {
  const summary = `${componentName}: ${input.planned} actions planned, ${input.executed} executed, ${input.pending} pending approval, ${input.blocked} blocked, ${input.failed} failed.`;
  const reason = input.reasons[0];
  return reason ? `${summary} First detail: ${reason}` : summary;
}

function resolveSeeds(runtime: Runtime, target?: string): { seeds: string[]; skippedScopeRules: string[] } {
  const skippedScopeRules: string[] = [];
  const rawSeeds = target && target !== runtime.config.program ? [target] : runtime.config.in_scope;
  const seeds: string[] = [];

  for (const raw of rawSeeds) {
    const value = raw.trim();
    if (!value || value.startsWith("*.")) {
      skippedScopeRules.push(value);
      continue;
    }

    const candidate = value.startsWith("http://") || value.startsWith("https://") ? value : `https://${value}`;
    const result = runtime.scopeGuard.test(candidate);
    if (result.allowed) {
      seeds.push(result.url);
    } else {
      skippedScopeRules.push(`${value} (${result.reason})`);
    }
  }

  return { seeds: [...new Set(seeds)], skippedScopeRules };
}

function safeFileName(value: string): string {
  return value.replace(/[^a-z0-9.-]/gi, "_");
}

function mergeUniqueScopedUrls(current: string[], candidates: string[], baseUrl: string, runtime: Runtime): string[] {
  const merged = new Set(current);
  for (const candidate of candidates) {
    const url = toScopedAbsoluteUrl(candidate, baseUrl, runtime);
    if (url) {
      merged.add(url);
    }
  }
  return [...merged].sort();
}

function toScopedAbsoluteUrl(candidate: string, baseUrl: string, runtime: Runtime): string | undefined {
  try {
    const url = new URL(candidate, baseUrl).toString();
    return runtime.scopeGuard.test(url).allowed ? url : undefined;
  } catch {
    return undefined;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function emptyActionCounts(): ActionQueueSummary {
  return {
    total: 0,
    pending: 0,
    approved: 0,
    executed: 0,
    blocked: 0,
    failed: 0,
  };
}

function emptyResumeProgress(): ResumeProgress {
  return {
    globalPhases: new Set(),
    seedPhases: new Map(),
  };
}

function resumeProgressFromPhaseNames(phaseNames: string[]): ResumeProgress {
  const progress = emptyResumeProgress();
  for (const phaseName of phaseNames) {
    progress.globalPhases.add(phaseName);
  }
  return progress;
}

function hasResumeExecutionOverrides(
  previous: WorkflowSummary,
  overrides: Partial<Omit<WorkflowOptions, "resumeFromJobId" | "resumeSkipPhases">>,
): boolean {
  return (
    targetOverrideChangesExecution(previous, overrides.target) ||
    (overrides.mode !== undefined && overrides.mode !== previous.mode) ||
    (overrides.withComponents !== undefined && !sameComponents(overrides.withComponents, previous.components)) ||
    (overrides.dryRun !== undefined && overrides.dryRun !== previous.dryRun) ||
    (overrides.draftReports !== undefined && overrides.draftReports !== previous.draftReports)
  );
}

function targetOverrideChangesExecution(previous: WorkflowSummary, target: string | undefined): boolean {
  if (target === undefined) {
    return false;
  }
  if (previous.target === undefined) {
    return true;
  }
  return normalizeResumeTarget(target) !== normalizeResumeTarget(previous.target);
}

function sameComponents(left: string[], right: string[]): boolean {
  const normalizedLeft = [...new Set(left.map((item) => normalizeComponent(item)))].sort();
  const normalizedRight = [...new Set(right.map((item) => normalizeComponent(item)))].sort();
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

const SEEDED_RESUME_PHASES = new Set(["safe-checks", "js-analyzer", "playwright"]);

function resumableProgress(summary: WorkflowSummary, actions: ActionRecord[] = []): ResumeProgress {
  const progress = emptyResumeProgress();
  progress.plannerCandidates = copyPlannerCandidates(summary.plannerCandidates);
  const legacyTarget = legacySingleSeedTarget(summary);
  const targetlessCompletedSeedPhases = new Set<string>();
  const targetlessFailedSeedPhases = new Set<string>();

  for (const phase of summary.phases) {
    if (phase.status === "planned" || phase.status === "skipped") {
      continue;
    }
    if (isSeededResumePhase(phase.name)) {
      const target = phase.target ?? legacyTarget;
      if (phase.status === "completed") {
        if (target) {
          addSeedPhase(progress, phase.name, target);
        } else {
          targetlessCompletedSeedPhases.add(phase.name);
        }
      }
      if (phase.status === "failed") {
        if (target) {
          deleteSeedPhase(progress, phase.name, target);
        } else {
          targetlessFailedSeedPhases.add(phase.name);
        }
      }
      continue;
    }
    if (phase.status === "completed") {
      progress.globalPhases.add(phase.name);
    }
    if (phase.status === "failed") {
      progress.globalPhases.delete(phase.name);
    }
  }

  progress.globalPhases.delete("workflow");
  applyLegacyActionProgress(progress, targetlessCompletedSeedPhases, targetlessFailedSeedPhases, actions);
  return progress;
}

function applyLegacyActionProgress(
  progress: ResumeProgress,
  completedPhases: Set<string>,
  failedPhases: Set<string>,
  actions: ActionRecord[],
): void {
  if (completedPhases.size === 0 && failedPhases.size === 0) {
    return;
  }
  const actionsByPhase = new Map<string, ActionRecord[]>();
  for (const action of actions) {
    if (!isSeededResumePhase(action.adapter) || !action.target) {
      continue;
    }
    const existing = actionsByPhase.get(action.adapter) ?? [];
    existing.push(action);
    actionsByPhase.set(action.adapter, existing);
  }

  for (const phaseName of completedPhases) {
    for (const action of actionsByPhase.get(phaseName) ?? []) {
      if (action.status === "executed" && action.target) {
        addSeedPhase(progress, phaseName, action.target);
      }
    }
  }
  for (const phaseName of failedPhases) {
    const phaseActions = actionsByPhase.get(phaseName) ?? [];
    if (phaseActions.length === 0) {
      progress.seedPhases.delete(phaseName);
      continue;
    }
    for (const action of phaseActions) {
      if ((action.status === "failed" || action.status === "blocked") && action.target) {
        deleteSeedPhase(progress, phaseName, action.target);
      }
    }
  }
}

function addSeedPhase(progress: ResumeProgress, phaseName: string, target: string): void {
  const targets = progress.seedPhases.get(phaseName) ?? new Set<string>();
  targets.add(normalizeResumeTarget(target));
  progress.seedPhases.set(phaseName, targets);
}

function deleteSeedPhase(progress: ResumeProgress, phaseName: string, target: string): void {
  const targets = progress.seedPhases.get(phaseName);
  if (!targets) return;
  targets.delete(normalizeResumeTarget(target));
  if (targets.size === 0) {
    progress.seedPhases.delete(phaseName);
  }
}

function isSeededResumePhase(phaseName: string): boolean {
  return SEEDED_RESUME_PHASES.has(phaseName);
}

function legacySingleSeedTarget(summary: WorkflowSummary): string | undefined {
  return summary.seeds.length === 1 ? summary.seeds[0] : undefined;
}

function normalizeResumeTarget(target: string): string {
  try {
    return new URL(target).toString();
  } catch {
    return target;
  }
}

function copyPlannerCandidates(candidates: WorkflowSummary["plannerCandidates"]): WorkflowSummary["plannerCandidates"] {
  return candidates
    ? {
        endpointCandidates: [...candidates.endpointCandidates],
        jsAssets: [...candidates.jsAssets],
      }
    : undefined;
}

function plannerFeedbackJobIds(summary: Pick<WorkflowSummary, "jobId" | "resumedFromJobId">): Set<string> {
  return new Set([summary.jobId, summary.resumedFromJobId].filter((jobId): jobId is string => Boolean(jobId)));
}

function resumeProgressForMetadata(progress: ResumeProgress): Array<{ phase: string; targets: string[] }> {
  return [...progress.seedPhases.entries()]
    .map(([phase, targets]) => ({ phase, targets: [...targets].sort() }))
    .sort((left, right) => left.phase.localeCompare(right.phase));
}

function pushUnique(values: string[], value: string): void {
  if (!values.includes(value)) {
    values.push(value);
  }
}

function workflowCheckpointPath(jobsDir: string, jobId: string): string {
  return path.join(jobsDir, jobId, "workflow-checkpoint.json");
}

function readWorkflowSummary(jobsDir: string, jobId: string): WorkflowSummary | undefined {
  const filePath = workflowCheckpointPath(jobsDir, jobId);
  if (!existsSync(filePath)) {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Workflow summary is not valid JSON: ${filePath}. ${reason}`, "WORKFLOW_SUMMARY_INVALID_JSON");
  }
  if (!isWorkflowSummary(parsed, jobId)) {
    throw new BountyPilotError(`Workflow summary is malformed: ${filePath}`, "WORKFLOW_SUMMARY_INVALID");
  }
  parsed.candidatesCreated ??= 0;
  return parsed;
}

function summaryContent(summary: WorkflowSummary): string {
  return `${JSON.stringify(summary, null, 2)}\n`;
}

function isWorkflowSummary(value: unknown, jobId: string): value is WorkflowSummary {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<WorkflowSummary>;
  return (
    candidate.jobId === jobId &&
    (candidate.checkpointVersion === undefined || typeof candidate.checkpointVersion === "number") &&
    typeof candidate.program === "string" &&
    (candidate.target === undefined || typeof candidate.target === "string") &&
    isWorkflowStatus(candidate.status) &&
    isExecutionMode(candidate.mode) &&
    typeof candidate.dryRun === "boolean" &&
    typeof candidate.draftReports === "boolean" &&
    Array.isArray(candidate.components) &&
    candidate.components.every((item) => typeof item === "string") &&
    Array.isArray(candidate.seeds) &&
    candidate.seeds.every((item) => typeof item === "string") &&
    Array.isArray(candidate.skippedScopeRules) &&
    candidate.skippedScopeRules.every((item) => typeof item === "string") &&
    Array.isArray(candidate.phases) &&
    candidate.phases.every(isWorkflowPhaseResult) &&
    (candidate.plannerCandidates === undefined || isPlannerCandidates(candidate.plannerCandidates)) &&
    (candidate.plannerLoop === undefined || isPlannerLoopResult(candidate.plannerLoop)) &&
    (candidate.candidatesCreated === undefined || typeof candidate.candidatesCreated === "number") &&
    typeof candidate.findingsCreated === "number" &&
    typeof candidate.evidenceCreated === "number" &&
    typeof candidate.actionsPlanned === "number" &&
    typeof candidate.reportsDrafted === "number" &&
    typeof candidate.startedAt === "string" &&
    typeof candidate.updatedAt === "string" &&
    (candidate.resumedFromJobId === undefined || typeof candidate.resumedFromJobId === "string") &&
    (candidate.resumeSkippedPhases === undefined ||
      (Array.isArray(candidate.resumeSkippedPhases) && candidate.resumeSkippedPhases.every((item) => typeof item === "string"))) &&
    (candidate.resumeSkippedWork === undefined ||
      (Array.isArray(candidate.resumeSkippedWork) && candidate.resumeSkippedWork.every(isWorkflowSkippedWork)))
  );
}

function isWorkflowPhaseResult(value: unknown): value is WorkflowPhaseResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<WorkflowPhaseResult>;
  return (
    typeof candidate.name === "string" &&
    typeof candidate.detail === "string" &&
    (candidate.status === "completed" ||
      candidate.status === "failed" ||
      candidate.status === "skipped" ||
      candidate.status === "planned") &&
    (candidate.target === undefined || typeof candidate.target === "string")
  );
}

function isWorkflowSkippedWork(value: unknown): value is WorkflowSkippedWork {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<WorkflowSkippedWork>;
  return typeof candidate.phase === "string" && (candidate.target === undefined || typeof candidate.target === "string");
}

function isPlannerCandidates(value: unknown): value is NonNullable<WorkflowSummary["plannerCandidates"]> {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<NonNullable<WorkflowSummary["plannerCandidates"]>>;
  return (
    Array.isArray(candidate.endpointCandidates) &&
    candidate.endpointCandidates.every((item) => typeof item === "string") &&
    Array.isArray(candidate.jsAssets) &&
    candidate.jsAssets.every((item) => typeof item === "string")
  );
}

function isPlannerLoopResult(value: unknown): value is PlannerLoopResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<PlannerLoopResult>;
  return (
    Array.isArray(candidate.actions) &&
    candidate.actions.every(isPlannerLoopAction) &&
    Array.isArray(candidate.iterations) &&
    candidate.iterations.every(isPlannerLoopIteration) &&
    Boolean(candidate.inputSummary && typeof candidate.inputSummary === "object")
  );
}

function isPlannerLoopAction(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.adapter === "string" &&
    typeof candidate.actionType === "string" &&
    typeof candidate.target === "string" &&
    (candidate.riskLevel === "low" || candidate.riskLevel === "medium" || candidate.riskLevel === "high") &&
    typeof candidate.requiresApproval === "boolean" &&
    typeof candidate.reason === "string" &&
    typeof candidate.score === "number" &&
    typeof candidate.iteration === "number" &&
    typeof candidate.dedupeKey === "string" &&
    typeof candidate.source === "string"
  );
}

function isPlannerLoopIteration(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.index === "number" &&
    typeof candidate.label === "string" &&
    typeof candidate.candidates === "number" &&
    typeof candidate.selected === "number" &&
    typeof candidate.skippedDuplicates === "number" &&
    typeof candidate.skippedExistingActions === "number" &&
    typeof candidate.skippedFailedOrBlockedHistory === "number"
  );
}

function isWorkflowStatus(value: unknown): value is JobStatus {
  return value === "queued" || value === "running" || value === "paused" || value === "completed" || value === "failed";
}

function isExecutionMode(value: unknown): value is ExecutionMode {
  return value === "passive" || value === "safe" || value === "deep-safe" || value === "lab-offensive";
}
