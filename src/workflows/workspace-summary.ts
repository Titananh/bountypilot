import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { Runtime } from "../cli/runtime.js";
import { TriageEngine, type TriageResult } from "../engines/triage/triage-engine.js";
import type { ActionQueueSummary } from "../core/actions/action-queue.js";
import type { JobStatus } from "../core/jobs/job-manager.js";
import type { WorkflowEventStatus } from "../core/jobs/workflow-event-store.js";
import type {
  DuplicateRisk,
  FindingCandidate,
  FindingCandidateReportability,
  FindingCandidateStatus,
  FindingStatus,
  NormalizedFinding,
  SeverityEstimate,
} from "../types.js";
import { maskSecretsDeep } from "../utils/secrets.js";
import { nowIso } from "../utils/time.js";

export interface WorkspaceSummary {
  generatedAt: string;
  program: {
    name: string;
    platform: string;
    workspace: string;
    rateLimit: string;
  };
  scope: {
    inScope: number;
    outOfScope: number;
  };
  jobs: {
    total: number;
    byStatus: Record<JobStatus, number>;
    recent: Array<{
      id: string;
      type: string;
      status: JobStatus;
      mode: string;
      target?: string;
      updatedAt: string;
    }>;
  };
  actions: ActionQueueSummary;
  findings: {
    total: number;
    bySeverity: Record<SeverityEstimate, number>;
    byStatus: Record<FindingStatus, number>;
    byDuplicateRisk: Record<DuplicateRisk, number>;
    averageReportabilityScore: number;
    topReportable: WorkspaceFindingSummary[];
  };
  candidates: {
    total: number;
    byStatus: Record<FindingCandidateStatus, number>;
    byReportability: Record<FindingCandidateReportability, number>;
    readyForDraft: number;
    linkedFindings: number;
    top: WorkspaceCandidateSummary[];
  };
  triage: {
    byRecommendation: Record<TriageResult["recommendation"], number>;
    readyForDraft: number;
    needsManualImpactValidation: number;
    doNotReportAlone: number;
  };
  evidence: {
    total: number;
    byKind: Record<string, number>;
    missingFiles: number;
  };
  reports: {
    files: number;
  };
  timeline: {
    totalEvents: number;
    recent: Array<{
      jobId: string;
      sequence: number;
      phase: string;
      status: WorkflowEventStatus;
      message: string;
      createdAt: string;
    }>;
  };
  nextActions: string[];
}

export interface WorkspaceFindingSummary {
  id: string;
  title: string;
  asset: string;
  severity: SeverityEstimate;
  status: FindingStatus;
  duplicateRisk: DuplicateRisk;
  reportabilityScore: number;
  triageRecommendation: TriageResult["recommendation"];
}

export interface WorkspaceCandidateSummary {
  id: string;
  title: string;
  asset: string;
  severity: SeverityEstimate;
  status: FindingCandidateStatus;
  reportability: FindingCandidateReportability;
  confidence: FindingCandidate["confidence"];
  findingId?: string;
}

export function buildWorkspaceSummary(runtime: Runtime): WorkspaceSummary {
  const jobs = runtime.jobs.list(100);
  const actions = runtime.actions.summarize();
  const findings = runtime.findings.list();
  const candidates = runtime.candidates.list();
  const evidence = runtime.evidence.list();
  const triageEngine = new TriageEngine();
  const triageResults = findings.map((finding) => triageEngine.triage(finding, runtime.evidence.list(finding.id)));
  const triageByFinding = new Map(triageResults.map((result) => [result.findingId, result]));

  const bySeverity = countBy<SeverityEstimate>(
    findings.map((finding) => finding.severityEstimate),
    ["critical", "high", "medium", "low", "info", "unknown"],
  );
  const byStatus = countBy<FindingStatus>(
    findings.map((finding) => finding.status),
    ["new", "needs_validation", "validated", "needs_manual_review", "report_drafted", "submitted", "duplicate", "invalid"],
  );
  const byDuplicateRisk = countBy<DuplicateRisk>(
    findings.map((finding) => finding.duplicateRisk),
    ["high", "medium", "low", "unknown"],
  );
  const byRecommendation = countBy<TriageResult["recommendation"]>(
    triageResults.map((result) => result.recommendation),
    ["ready_for_draft", "needs_manual_impact_validation", "do_not_report_alone"],
  );

  return {
    generatedAt: nowIso(),
    program: {
      name: runtime.config.program,
      platform: runtime.config.platform,
      workspace: runtime.paths.programDir,
      rateLimit: runtime.config.rules.rate_limit,
    },
    scope: {
      inScope: runtime.config.in_scope.length,
      outOfScope: runtime.config.out_of_scope.length,
    },
    jobs: {
      total: jobs.length,
      byStatus: countBy<JobStatus>(
        jobs.map((job) => job.status),
        ["queued", "running", "paused", "failed", "completed"],
      ),
      recent: jobs.slice(0, 8).map((job) => ({
        id: job.id,
        type: job.type,
        status: job.status,
        mode: job.mode,
        target: job.target,
        updatedAt: job.updatedAt,
      })),
    },
    actions,
    findings: {
      total: findings.length,
      bySeverity,
      byStatus,
      byDuplicateRisk,
      averageReportabilityScore: average(findings.map((finding) => finding.reportabilityScore)),
      topReportable: topReportableFindings(findings, triageByFinding),
    },
    candidates: {
      total: candidates.length,
      byStatus: countBy<FindingCandidateStatus>(
        candidates.map((candidate) => candidate.status),
        ["needs_manual_verification", "ready_for_draft", "promoted", "dismissed"],
      ),
      byReportability: countBy<FindingCandidateReportability>(
        candidates.map((candidate) => candidate.reportability),
        ["blocked", "needs_review", "ready_for_draft"],
      ),
      readyForDraft: candidates.filter((candidate) => candidate.reportability === "ready_for_draft").length,
      linkedFindings: candidates.filter((candidate) => Boolean(candidate.findingId)).length,
      top: topCandidates(candidates),
    },
    triage: {
      byRecommendation,
      readyForDraft: byRecommendation.ready_for_draft,
      needsManualImpactValidation: byRecommendation.needs_manual_impact_validation,
      doNotReportAlone: byRecommendation.do_not_report_alone,
    },
    evidence: {
      total: evidence.length,
      byKind: countLoose(evidence.map((artifact) => artifact.kind)),
      missingFiles: runtime.evidence.buildManifest().artifacts.filter((artifact) => !artifact.readable).length,
    },
    reports: {
      files: countFiles(runtime.paths.reportsDir),
    },
    timeline: {
      totalEvents: runtime.events.count(),
      recent: runtime.events.recent(8).map((event) => ({
        jobId: event.jobId,
        sequence: event.sequence,
        phase: event.phase,
        status: event.status,
        message: event.message,
        createdAt: event.createdAt,
      })),
    },
    nextActions: recommendNextActions({
      actions,
      findings,
      candidates,
      triageResults,
      evidenceTotal: evidence.length,
      jobsTotal: jobs.length,
    }),
  };
}

export function writeWorkspaceSummary(runtime: Runtime, outputPath?: string): string {
  const summary = buildWorkspaceSummary(runtime);
  const resolvedPath = outputPath
    ? path.resolve(outputPath)
    : path.join(runtime.paths.evidenceDir, "workspace-summary.json");
  mkdirSync(path.dirname(resolvedPath), { recursive: true });
  writeFileSync(resolvedPath, `${JSON.stringify(maskSecretsDeep(summary), null, 2)}\n`, "utf8");
  return resolvedPath;
}

function topReportableFindings(
  findings: NormalizedFinding[],
  triageByFinding: Map<string, TriageResult>,
): WorkspaceFindingSummary[] {
  return [...findings]
    .sort((left, right) => right.reportabilityScore - left.reportabilityScore || left.createdAt.localeCompare(right.createdAt))
    .slice(0, 8)
    .map((finding) => ({
      id: finding.id,
      title: finding.title,
      asset: finding.asset,
      severity: finding.severityEstimate,
      status: finding.status,
      duplicateRisk: finding.duplicateRisk,
      reportabilityScore: finding.reportabilityScore,
      triageRecommendation: triageByFinding.get(finding.id)?.recommendation ?? "needs_manual_impact_validation",
    }));
}

function topCandidates(candidates: FindingCandidate[]): WorkspaceCandidateSummary[] {
  const reportabilityRank: Record<FindingCandidateReportability, number> = {
    ready_for_draft: 3,
    needs_review: 2,
    blocked: 1,
  };
  return [...candidates]
    .sort((left, right) =>
      reportabilityRank[right.reportability] - reportabilityRank[left.reportability] ||
      right.evidenceIds.length - left.evidenceIds.length ||
      left.createdAt.localeCompare(right.createdAt),
    )
    .slice(0, 8)
    .map((candidate) => ({
      id: candidate.id,
      title: candidate.title,
      asset: candidate.asset,
      severity: candidate.severityEstimate,
      status: candidate.status,
      reportability: candidate.reportability,
      confidence: candidate.confidence,
      findingId: candidate.findingId,
    }));
}

function recommendNextActions(input: {
  actions: ActionQueueSummary;
  findings: NormalizedFinding[];
  candidates: FindingCandidate[];
  triageResults: TriageResult[];
  evidenceTotal: number;
  jobsTotal: number;
}): string[] {
  const recommendations: string[] = [];
  if (input.jobsTotal === 0) {
    recommendations.push("Run `bounty run <target> --dry-run` to create the first scoped workflow checkpoint.");
  }
  if (input.actions.pending > 0) {
    recommendations.push("Review pending actions with `bounty actions list --pending`, then approve or block them.");
  }
  if (input.actions.approved > 0) {
    recommendations.push("Execute approved internal actions with `bounty actions run-approved --job <job-id>`.");
  }
  if (input.candidates.some((candidate) => candidate.reportability === "needs_review")) {
    recommendations.push("Review finding candidates with `bounty findings candidates --reportability needs_review`.");
  }
  if (input.candidates.some((candidate) => candidate.reportability === "ready_for_draft")) {
    recommendations.push("Score report-ready candidates with `bounty reports score <candidate-id> --json`.");
  }
  if (input.findings.some((finding) => finding.status === "needs_validation" || finding.status === "needs_manual_review")) {
    recommendations.push("Use `bounty triage <finding-id>` and `bounty reproduce <finding-id>` before drafting reports.");
  }
  if (input.triageResults.some((result) => result.recommendation === "ready_for_draft")) {
    recommendations.push("Draft ready findings with `bounty report <finding-id> --platform hackerone`.");
  }
  if (input.evidenceTotal > 0) {
    recommendations.push("Create an evidence manifest with `bounty evidence --manifest` before sharing artifacts.");
  }
  if (recommendations.length === 0) {
    recommendations.push("Import scope and start with a dry-run workflow; no actionable local state is available yet.");
  }
  return recommendations;
}

function countBy<T extends string>(values: T[], keys: T[]): Record<T, number> {
  const counts = Object.fromEntries(keys.map((key) => [key, 0])) as Record<T, number>;
  for (const value of values) {
    counts[value] += 1;
  }
  return counts;
}

function countLoose(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}

function average(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
}

function countFiles(directory: string): number {
  try {
    return readdirSync(directory, { withFileTypes: true }).filter((entry) => entry.isFile()).length;
  } catch {
    return 0;
  }
}
