import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { EvidenceArtifact, NormalizedFinding } from "../../types.js";
import { maskSecrets } from "../../utils/secrets.js";

export const SUPPORTED_REPORT_PLATFORMS = ["hackerone", "bugcrowd"] as const;
export type ReportPlatform = (typeof SUPPORTED_REPORT_PLATFORMS)[number];

export function isSupportedReportPlatform(value: string): value is ReportPlatform {
  return SUPPORTED_REPORT_PLATFORMS.includes(value as ReportPlatform);
}

export function generateHackerOneReport(finding: NormalizedFinding, evidence: EvidenceArtifact[]): string {
  const evidenceReferences = collectEvidenceReferences(finding, evidence);
  const evidenceLines = formatEvidenceReferences(evidenceReferences);
  const reproduction = buildSafeReproductionSteps(finding, evidenceReferences);

  return maskSecrets(`# ${finding.title}

## Summary
A safe, scoped review identified **${finding.title}** on an explicitly authorized asset. Current confidence is **${finding.confidence}** and severity is estimated as **${finding.severityEstimate}** until program-side impact is validated.

## Target
- Asset: ${finding.asset}
- URL: ${finding.url}
- Category: ${finding.category}
- Severity Estimate: ${finding.severityEstimate}
- Confidence: ${finding.confidence}
- Finding ID: ${finding.id}

## Scope Confirmation
The target was evaluated through BountyPilot scope checks before evidence collection or report generation. Do not use this draft for any asset that is not explicitly in scope for the program.

## Safe Reproduction Steps
${reproduction}

## Observed Behavior
${safeObservationForCategory(finding)}

## Expected Behavior
The application should enforce the intended security control without requiring destructive testing, unauthorized access, data extraction, or high-volume traffic to demonstrate the issue.

## Impact
Potential impact should be stated only when safely validated from the linked evidence. Current reportability score: **${finding.reportabilityScore}/100** (${scoreBand(finding.reportabilityScore)}). If impact cannot be verified without accessing real user data, changing server state, bypassing authorization, or exceeding program limits, leave impact as a cautious hypothesis and request guidance from the program.

## Evidence Manifest
${evidenceLines}

Artifact contents are not embedded in this draft. Review each artifact locally, redact secrets and unrelated personal data, and attach only the minimum evidence needed to support the report.

## Suggested Remediation
${finding.remediation ?? "Add a targeted remediation once the root cause is confirmed."}

## Duplicate Risk and Reportability
- Local duplicate risk: ${formatDuplicateRisk(finding.duplicateRisk)}
- Private HackerOne duplicate visibility cannot be checked locally; this score only reflects the local BountyPilot workspace.
- Current status: ${finding.status}

## Submission Checklist
- Confirm the asset and exact URL are still in scope.
- Confirm every attached artifact is sanitized and directly relevant.
- Confirm no proof requires destructive behavior, credential attacks, spam, WAF evasion, state changes, or access to data you do not own.
- Confirm the report is submitted manually by a human researcher.

## Safe Testing Statement
Testing was limited to authorized, explicitly in-scope assets. BountyPilot blocks out-of-scope targets, destructive testing, brute force, credential stuffing, data exfiltration, spam, WAF evasion, and automatic report submission. Stop immediately and request explicit approval if further validation would cross those boundaries.
`);
}

export function generateBugcrowdReport(finding: NormalizedFinding, evidence: EvidenceArtifact[]): string {
  const evidenceReferences = collectEvidenceReferences(finding, evidence);
  const evidenceLines = formatEvidenceReferences(evidenceReferences);
  const reproduction = buildSafeReproductionSteps(finding, evidenceReferences);

  return maskSecrets(`# ${finding.title}

## Vulnerability Summary
BountyPilot identified **${finding.title}** during safe, local-first testing of an explicitly authorized target. Confidence is **${finding.confidence}** and the local severity estimate is **${finding.severityEstimate}** until the program validates impact.

## Affected Target
- Asset: ${finding.asset}
- URL: ${finding.url}
- Vulnerability Category: ${finding.category}
- Severity Estimate: ${finding.severityEstimate}
- Confidence: ${finding.confidence}
- Local Finding ID: ${finding.id}

## Scope And Testing Boundary
The target must remain explicitly in scope before any manual submission. This draft is based on BountyPilot evidence and does not prove authorization for assets outside the imported program scope.

## Steps To Reproduce
${reproduction}

## Observed Result
${safeObservationForCategory(finding)}

## Expected Result
The application should enforce the intended security control while allowing validation through non-destructive, authorized, rate-limited testing only.

## Security Impact
Describe impact only when it is supported by the linked evidence and program rules. Current local reportability score: **${finding.reportabilityScore}/100** (${scoreBand(finding.reportabilityScore)}). Do not access data that does not belong to the researcher, do not change server state, and do not escalate validation without explicit approval.

## Proof And Attachments
${evidenceLines}

Do not paste raw artifact contents into this draft. Review each artifact locally, redact secrets and unrelated personal data, and attach the minimum proof needed on Bugcrowd.

## Suggested Remediation
${finding.remediation ?? "Add a targeted remediation once the root cause is confirmed."}

## Duplicate And Validation Notes
- Local duplicate risk: ${formatDuplicateRisk(finding.duplicateRisk)}
- Bugcrowd private duplicate visibility cannot be checked locally; review the program and platform before submitting.
- Current local status: ${finding.status}

## Safe Testing Statement
Testing was limited to authorized, explicitly in-scope assets. BountyPilot blocks out-of-scope targets, destructive testing, brute force, credential stuffing, data exfiltration, spam, WAF evasion, and automatic report submission. This draft must be submitted manually by a human researcher after final redaction.
`);
}

export function generateReproductionNote(finding: NormalizedFinding, evidence: EvidenceArtifact[]): string {
  const evidenceReferences = collectEvidenceReferences(finding, evidence);

  return maskSecrets(`# Reproduction Notes: ${finding.title}

## Finding
- ID: ${finding.id}
- URL: ${finding.url}
- Status: ${finding.status}
- Category: ${finding.category}

## Safe Validation Boundary
- Confirm the target remains explicitly in scope before repeating any check.
- Use only the original passive or safe observation path that produced the evidence.
- Do not change server state, attempt authorization bypass, access data you do not own, send high-volume traffic, evade controls, or submit automatically.
- Stop and request human approval if stronger proof would require riskier validation.

## Minimal Safe Reproduction
${buildSafeReproductionSteps(finding, evidenceReferences)}

## Evidence To Review
${formatEvidenceReferences(evidenceReferences)}

## Notes For Manual Review
- Record only non-sensitive observations needed to explain expected versus observed behavior.
- Treat impact as unvalidated unless the linked evidence demonstrates it within program rules.
`);
}

export function writeHackerOneReport(
  reportsDir: string,
  finding: NormalizedFinding,
  evidence: EvidenceArtifact[],
): string {
  mkdirSync(reportsDir, { recursive: true });
  const reportPath = path.join(reportsDir, `${finding.id}-hackerone.md`);
  writeFileSync(reportPath, generateHackerOneReport(finding, evidence), "utf8");
  return reportPath;
}

export function writeBugcrowdReport(
  reportsDir: string,
  finding: NormalizedFinding,
  evidence: EvidenceArtifact[],
): string {
  mkdirSync(reportsDir, { recursive: true });
  const reportPath = path.join(reportsDir, `${finding.id}-bugcrowd.md`);
  writeFileSync(reportPath, generateBugcrowdReport(finding, evidence), "utf8");
  return reportPath;
}

export function writePlatformReport(
  reportsDir: string,
  platform: ReportPlatform,
  finding: NormalizedFinding,
  evidence: EvidenceArtifact[],
): string {
  switch (platform) {
    case "hackerone":
      return writeHackerOneReport(reportsDir, finding, evidence);
    case "bugcrowd":
      return writeBugcrowdReport(reportsDir, finding, evidence);
  }
}

interface EvidenceReference {
  id?: string;
  adapterName?: string;
  kind: string;
  sourceUrl?: string;
  path: string;
  createdAt?: string;
}

function collectEvidenceReferences(finding: NormalizedFinding, evidence: EvidenceArtifact[]): EvidenceReference[] {
  const referencesByPath = new Map<string, EvidenceReference>();

  for (const artifact of evidence) {
    referencesByPath.set(artifact.path, {
      id: artifact.id,
      adapterName: artifact.adapterName,
      kind: artifact.kind,
      sourceUrl: artifact.sourceUrl,
      path: artifact.path,
      createdAt: artifact.createdAt,
    });
  }

  for (const evidencePath of finding.evidencePaths) {
    if (!referencesByPath.has(evidencePath)) {
      referencesByPath.set(evidencePath, {
        kind: "linked_evidence_path",
        path: evidencePath,
      });
    }
  }

  return [...referencesByPath.values()].sort((left, right) => {
    if (!left.createdAt || !right.createdAt) return 0;
    return left.createdAt.localeCompare(right.createdAt);
  });
}

function buildSafeReproductionSteps(finding: NormalizedFinding, evidence: EvidenceReference[]): string {
  const evidenceStep = evidence.length
    ? "Review the linked evidence manifest below and repeat only the same passive or safe observation needed to confirm the condition."
    : "Collect a safe reproduction artifact before submission; do not rely on an unverified draft.";

  return [
    `1. Confirm ${finding.asset} and ${finding.url} are still explicitly in scope for the program.`,
    `2. ${evidenceStep}`,
    "3. Verify the observed condition without changing application state, using credentials that belong to the researcher when authentication is required.",
    "4. Capture only the minimum non-sensitive proof needed to show expected versus observed behavior.",
    "5. Stop and request explicit approval if validation would require destructive testing, credential attacks, data access, high-volume traffic, control evasion, or automated submission.",
  ].join("\n");
}

function formatEvidenceReferences(evidence: EvidenceReference[]): string {
  if (evidence.length === 0) {
    return "- No linked evidence artifacts yet. Generate a safe reproduction note or evidence manifest before submission.";
  }

  return evidence.map(formatEvidenceReference).join("\n");
}

function formatEvidenceReference(evidence: EvidenceReference): string {
  const details = [
    evidence.id ? `${evidence.kind} (${evidence.id})` : evidence.kind,
    evidence.adapterName ? `adapter: ${evidence.adapterName}` : undefined,
    evidence.sourceUrl ? `source: ${evidence.sourceUrl}` : undefined,
    evidence.createdAt ? `created: ${evidence.createdAt}` : undefined,
  ].filter((item): item is string => Boolean(item));

  return `- ${details.join("; ")}\n  Path: ${evidence.path}`;
}

function safeObservationForCategory(finding: NormalizedFinding): string {
  const category = finding.category.toLowerCase();
  if (category.includes("header")) {
    return `Response metadata for ${finding.url} indicates: ${finding.title}. This should be validated by reviewing response headers only.`;
  }
  if (category.includes("cors")) {
    return `Response metadata for ${finding.url} indicates a potentially unsafe CORS configuration. Validate with header review only unless the program explicitly approves deeper testing.`;
  }
  if (category.includes("graphql")) {
    return `The target appears to expose GraphQL behavior related to: ${finding.title}. Validate with benign schema or response observation only, and do not query sensitive data.`;
  }
  if (category.includes("secret")) {
    return `Public client-side content appears to contain a secret-like pattern. Treat this as unconfirmed until manually verified, and do not use or test the value against live services.`;
  }
  return `The linked evidence indicates: ${finding.title}. Keep validation to non-destructive observation unless the program explicitly approves stronger testing.`;
}

function formatDuplicateRisk(risk: NormalizedFinding["duplicateRisk"]): string {
  switch (risk) {
    case "high":
      return "high - local history contains a strong duplicate signal; review before drafting.";
    case "medium":
      return "medium - local history contains related findings; compare scope, URL, category, and impact.";
    case "low":
      return "low - local history has a weak related signal, but platform-private duplicates remain unknown.";
    case "unknown":
      return "unknown - no local duplicate signal was found, and platform-private duplicates cannot be checked locally.";
  }
}

function scoreBand(score: number): string {
  if (score >= 75) return "strong draft candidate";
  if (score >= 60) return "draft candidate after manual review";
  if (score >= 40) return "needs impact validation";
  return "do not report alone";
}
