import type { DuplicateRiskResult } from "../duplicate-risk/duplicate-risk-engine.js";
import type { TriageResult } from "../triage/triage-engine.js";
import type { EvidenceManifest } from "../../stores/evidence-store.js";
import type { EvidenceArtifact, NormalizedFinding } from "../../types.js";
import { nowIso } from "../../utils/time.js";

export type ReportReviewStatus = "pass" | "warn" | "fail";
export type ReportReadiness = "ready_for_draft" | "needs_review" | "blocked";

export interface ReportReviewCheck {
  id: string;
  title: string;
  status: ReportReviewStatus;
  detail: string;
}

export interface ReportReview {
  generatedAt: string;
  platform: string;
  findingId: string;
  readiness: ReportReadiness;
  score: number;
  recommendation: TriageResult["recommendation"];
  counts: {
    evidence: number;
    readableEvidence: number;
    unreadableEvidence: number;
    linkedEvidencePaths: number;
    evidenceKinds: Record<string, number>;
  };
  checks: ReportReviewCheck[];
  blockers: string[];
  warnings: string[];
  nextSteps: string[];
}

export interface ReportReviewInput {
  finding: NormalizedFinding;
  evidence: EvidenceArtifact[];
  manifest: EvidenceManifest;
  duplicate: DuplicateRiskResult;
  triage: TriageResult;
  platform?: string;
  generatedAt?: string;
}

const LOW_VALUE_CATEGORIES = new Set(["security_headers", "server_banner", "cookie_flags"]);
const REQUEST_CONTEXT_KINDS = new Set<EvidenceArtifact["kind"]>(["har", "request_sample", "response_sample", "tool_output"]);
const STATE_CONTEXT_KINDS = new Set<EvidenceArtifact["kind"]>(["screenshot", "dom_snapshot", "browser_trace", "desktop_screenshot"]);

export function buildReportReview(input: ReportReviewInput): ReportReview {
  const checks = buildChecks(input);
  const blockers = checks.filter((check) => check.status === "fail").map((check) => check.detail);
  const warnings = checks.filter((check) => check.status === "warn").map((check) => check.detail);
  const readiness = readinessFromChecks(checks, input.triage);

  return {
    generatedAt: input.generatedAt ?? nowIso(),
    platform: input.platform ?? "hackerone",
    findingId: input.finding.id,
    readiness,
    score: input.triage.reportabilityScore,
    recommendation: input.triage.recommendation,
    counts: {
      evidence: input.manifest.artifactCount,
      readableEvidence: input.manifest.artifacts.filter((artifact) => artifact.readable).length,
      unreadableEvidence: input.manifest.artifacts.filter((artifact) => !artifact.readable).length,
      linkedEvidencePaths: input.finding.evidencePaths.length,
      evidenceKinds: evidenceKinds(input.evidence),
    },
    checks,
    blockers,
    warnings,
    nextSteps: nextStepsFor(readiness, checks, input),
  };
}

function buildChecks(input: ReportReviewInput): ReportReviewCheck[] {
  const { finding, evidence, manifest, duplicate, triage } = input;
  const kinds = new Set(evidence.map((artifact) => artifact.kind));
  const unreadable = manifest.artifacts.filter((artifact) => !artifact.readable);
  const storedPathCount = new Set(evidence.map((artifact) => artifact.path)).size;
  const missingPathMetadataCount = finding.evidencePaths.filter(
    (evidencePath) => !evidence.some((artifact) => artifact.path === evidencePath),
  ).length;

  return [
    targetCheck(finding),
    evidencePresenceCheck(manifest, finding),
    artifactReadabilityCheck(manifest, unreadable),
    linkedPathMetadataCheck(missingPathMetadataCount, storedPathCount),
    reproductionCheck(kinds),
    requestContextCheck(kinds),
    stateContextCheck(kinds),
    sourceAlignmentCheck(finding, evidence),
    duplicateRiskCheck(duplicate),
    findingStatusCheck(finding),
    triageRecommendationCheck(triage),
    lowValueCategoryCheck(finding, triage),
    safetyBoundaryCheck(),
  ];
}

function targetCheck(finding: NormalizedFinding): ReportReviewCheck {
  if (!finding.url.trim() || !finding.asset.trim()) {
    return check("target", "Target context", "fail", "Finding is missing an asset or URL.");
  }
  if (!parseUrl(finding.url)) {
    return check("target", "Target context", "warn", "Finding URL is not a parseable absolute URL; confirm scope manually.");
  }
  return check("target", "Target context", "pass", "Finding has an asset and parseable URL for scope review.");
}

function evidencePresenceCheck(manifest: EvidenceManifest, finding: NormalizedFinding): ReportReviewCheck {
  if (manifest.artifactCount === 0 && finding.evidencePaths.length === 0) {
    return check("evidence_present", "Evidence present", "fail", "No evidence artifacts or linked evidence paths are available.");
  }
  if (manifest.artifactCount === 0) {
    return check(
      "evidence_present",
      "Evidence present",
      "warn",
      "Finding references evidence paths, but no stored artifact metadata is available.",
    );
  }
  if (manifest.artifactCount === 1) {
    return check("evidence_present", "Evidence present", "warn", "Only one evidence artifact is linked; add corroborating proof if possible.");
  }
  return check("evidence_present", "Evidence present", "pass", `${manifest.artifactCount} evidence artifacts are linked.`);
}

function artifactReadabilityCheck(manifest: EvidenceManifest, unreadable: EvidenceManifest["artifacts"]): ReportReviewCheck {
  if (manifest.artifactCount === 0) {
    return check("artifact_readability", "Artifact readability", "warn", "No stored artifacts are available to verify for readability.");
  }
  if (unreadable.length > 0) {
    return check(
      "artifact_readability",
      "Artifact readability",
      "fail",
      `${unreadable.length} evidence artifact(s) are unreadable or outside trusted artifact roots.`,
    );
  }
  const hashed = manifest.artifacts.filter((artifact) => typeof artifact.sha256 === "string" && artifact.sha256.length === 64).length;
  return check("artifact_readability", "Artifact readability", "pass", `${hashed} artifact(s) are readable and hashable.`);
}

function linkedPathMetadataCheck(missingPathMetadataCount: number, storedPathCount: number): ReportReviewCheck {
  if (missingPathMetadataCount === 0) {
    return check("linked_path_metadata", "Linked path metadata", "pass", `${storedPathCount} linked path(s) have stored artifact metadata.`);
  }
  return check(
    "linked_path_metadata",
    "Linked path metadata",
    "warn",
    `${missingPathMetadataCount} finding evidence path(s) do not have stored artifact metadata.`,
  );
}

function reproductionCheck(kinds: Set<EvidenceArtifact["kind"]>): ReportReviewCheck {
  if (kinds.has("reproduction_note")) {
    return check("reproduction", "Reproduction note", "pass", "A local safe reproduction note is linked.");
  }
  return check("reproduction", "Reproduction note", "warn", "Add a safe reproduction note before using the report draft.");
}

function requestContextCheck(kinds: Set<EvidenceArtifact["kind"]>): ReportReviewCheck {
  if ([...REQUEST_CONTEXT_KINDS].some((kind) => kinds.has(kind))) {
    return check("request_context", "Request context", "pass", "Evidence includes request, response, HAR, or tool output context.");
  }
  return check("request_context", "Request context", "warn", "Evidence lacks request, response, HAR, or tool output context.");
}

function stateContextCheck(kinds: Set<EvidenceArtifact["kind"]>): ReportReviewCheck {
  if ([...STATE_CONTEXT_KINDS].some((kind) => kinds.has(kind))) {
    return check("state_context", "State context", "pass", "Evidence includes visual or browser state context.");
  }
  return check("state_context", "State context", "warn", "Evidence lacks visual or browser state context.");
}

function sourceAlignmentCheck(finding: NormalizedFinding, evidence: EvidenceArtifact[]): ReportReviewCheck {
  const sourceUrls = evidence.map((artifact) => artifact.sourceUrl).filter((sourceUrl): sourceUrl is string => Boolean(sourceUrl));
  if (sourceUrls.length === 0) {
    return check("source_alignment", "Source alignment", "warn", "No evidence source URLs are available for alignment checks.");
  }
  if (sourceUrls.some((sourceUrl) => sourceUrlMatchesFinding(sourceUrl, finding))) {
    return check("source_alignment", "Source alignment", "pass", "At least one evidence source URL aligns with the finding target.");
  }
  return check("source_alignment", "Source alignment", "warn", "Evidence source URLs do not align with the finding target.");
}

function duplicateRiskCheck(duplicate: DuplicateRiskResult): ReportReviewCheck {
  if (duplicate.risk === "high") {
    return check("duplicate_risk", "Duplicate risk", "fail", "High local duplicate risk requires comparison before submission.");
  }
  if (duplicate.risk === "medium") {
    return check("duplicate_risk", "Duplicate risk", "warn", "Medium local duplicate risk should be compared before submission.");
  }
  if (duplicate.risk === "unknown") {
    return check("duplicate_risk", "Duplicate risk", "warn", "No local duplicate signal was found; private platform duplicates remain unknown.");
  }
  return check("duplicate_risk", "Duplicate risk", "pass", "Local duplicate risk is low.");
}

function findingStatusCheck(finding: NormalizedFinding): ReportReviewCheck {
  if (finding.status === "duplicate" || finding.status === "invalid") {
    return check("finding_status", "Finding status", "fail", `Finding status is ${finding.status}; do not submit as a standalone report.`);
  }
  if (finding.status === "needs_manual_review" || finding.status === "needs_validation" || finding.status === "new") {
    return check("finding_status", "Finding status", "warn", `Finding status is ${finding.status}; complete manual validation first.`);
  }
  if (finding.status === "submitted") {
    return check("finding_status", "Finding status", "warn", "Finding is already marked submitted.");
  }
  return check("finding_status", "Finding status", "pass", `Finding status is ${finding.status}.`);
}

function triageRecommendationCheck(triage: TriageResult): ReportReviewCheck {
  if (triage.recommendation === "do_not_report_alone") {
    return check("triage_recommendation", "Triage recommendation", "fail", "Triage recommends not reporting this finding alone.");
  }
  if (triage.recommendation === "needs_manual_impact_validation") {
    return check(
      "triage_recommendation",
      "Triage recommendation",
      "warn",
      `Triage score is ${triage.reportabilityScore}/100 and needs manual impact validation.`,
    );
  }
  return check("triage_recommendation", "Triage recommendation", "pass", `Triage score is ${triage.reportabilityScore}/100.`);
}

function lowValueCategoryCheck(finding: NormalizedFinding, triage: TriageResult): ReportReviewCheck {
  if (!LOW_VALUE_CATEGORIES.has(finding.category)) {
    return check("category_reportability", "Category reportability", "pass", "Finding category is not in the low-value standalone list.");
  }
  if (triage.evidenceQuality === "strong" && triage.reportabilityScore >= 65) {
    return check("category_reportability", "Category reportability", "warn", "Low-value category has strong evidence, but impact still needs review.");
  }
  return check("category_reportability", "Category reportability", "fail", "Low-value category needs stronger validated impact before reporting alone.");
}

function safetyBoundaryCheck(): ReportReviewCheck {
  return check(
    "safety_boundary",
    "Safety boundary",
    "pass",
    "Review is local-only and does not submit reports, execute tools, or contact target systems.",
  );
}

function readinessFromChecks(checks: ReportReviewCheck[], triage: TriageResult): ReportReadiness {
  if (checks.some((check) => check.status === "fail")) {
    return "blocked";
  }
  if (triage.recommendation === "ready_for_draft" && checks.every((check) => check.status === "pass")) {
    return "ready_for_draft";
  }
  return "needs_review";
}

function nextStepsFor(readiness: ReportReadiness, checks: ReportReviewCheck[], input: ReportReviewInput): string[] {
  const failedIds = new Set(checks.filter((check) => check.status === "fail").map((check) => check.id));
  const warningIds = new Set(checks.filter((check) => check.status === "warn").map((check) => check.id));
  const steps: string[] = [];

  if (failedIds.has("evidence_present") || warningIds.has("evidence_present")) {
    steps.push("Attach at least one directly relevant request, response, tool output, screenshot, or note artifact.");
  }
  if (failedIds.has("artifact_readability")) {
    steps.push("Run evidence verification and replace unreadable or untrusted artifact paths.");
  }
  if (warningIds.has("reproduction")) {
    steps.push("Generate a safe reproduction note and review it before drafting.");
  }
  if (warningIds.has("request_context")) {
    steps.push("Add request, response, HAR, or tool output context that demonstrates the observation safely.");
  }
  if (warningIds.has("state_context")) {
    steps.push("Add a screenshot, DOM snapshot, or browser trace when visual or state context matters.");
  }
  if (failedIds.has("duplicate_risk") || warningIds.has("duplicate_risk")) {
    steps.push("Compare the finding against local history and the platform before submission.");
  }
  if (failedIds.has("category_reportability")) {
    steps.push("Do not submit this low-value category alone without stronger validated impact.");
  }
  if (warningIds.has("finding_status") || failedIds.has("finding_status")) {
    steps.push("Update the finding status only after safe manual validation is complete.");
  }
  if (warningIds.has("triage_recommendation") || failedIds.has("triage_recommendation")) {
    steps.push(...input.triage.reasons.slice(0, 3));
  }
  if (readiness === "ready_for_draft") {
    steps.push("Draft the report locally and perform a final manual redaction pass before submitting on the platform.");
  }

  return unique(steps);
}

function evidenceKinds(evidence: EvidenceArtifact[]): Record<string, number> {
  return evidence.reduce<Record<string, number>>((counts, artifact) => {
    counts[artifact.kind] = (counts[artifact.kind] ?? 0) + 1;
    return counts;
  }, {});
}

function sourceUrlMatchesFinding(sourceUrl: string, finding: NormalizedFinding): boolean {
  const source = parseUrl(sourceUrl);
  const findingUrl = parseUrl(finding.url);
  const assetHost = hostnameFromAsset(finding.asset);

  if (source && findingUrl && source.hostname === findingUrl.hostname) {
    return true;
  }
  if (source && assetHost && source.hostname === assetHost) {
    return true;
  }
  return normalizeForMatching(sourceUrl).includes(normalizeForMatching(finding.asset));
}

function hostnameFromAsset(value: string): string | undefined {
  const url = parseUrl(value.includes("://") ? value : `https://${value}`);
  return url?.hostname;
}

function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function normalizeForMatching(value: string): string {
  return value.toLowerCase().replace(/[_-]+/g, " ").replace(/[^a-z0-9.]+/g, " ").trim();
}

function check(id: string, title: string, status: ReportReviewStatus, detail: string): ReportReviewCheck {
  return { id, title, status, detail };
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
