import type {
  Confidence,
  DuplicateRisk,
  FindingCandidate,
  FindingCandidateReportability,
  FindingCandidateStatus,
  SeverityEstimate,
} from "../../types.js";

export interface FindingCandidateReadinessInput {
  confidence: Confidence;
  severity: SeverityEstimate;
  evidenceCount: number;
  duplicateRisk: DuplicateRisk;
}

export interface FindingCandidateReadiness {
  status: FindingCandidateStatus;
  reportability: FindingCandidateReportability;
  falsePositiveRisk: DuplicateRisk;
  reasoningSummary: string;
  nextManualSteps: string[];
}

export function evaluateFindingCandidateReadiness(input: FindingCandidateReadinessInput): FindingCandidateReadiness {
  const falsePositiveRisk = falsePositiveRiskFor(input.confidence);
  const severityReady = input.severity === "medium" || input.severity === "high" || input.severity === "critical";
  if (input.duplicateRisk === "high") {
    return {
      status: "needs_manual_verification",
      reportability: "blocked",
      falsePositiveRisk,
      reasoningSummary: "Candidate has high local duplicate risk and must be reviewed before drafting.",
      nextManualSteps: ["Compare against existing findings before investing in a report draft."],
    };
  }
  if (input.evidenceCount < 2) {
    return {
      status: "needs_manual_verification",
      reportability: "needs_review",
      falsePositiveRisk,
      reasoningSummary: "Candidate has an evidence-backed signal but needs corroborating proof before draft readiness.",
      nextManualSteps: ["Record a reproduction note and at least one supporting request, response, screenshot, or tool output."],
    };
  }
  if (input.confidence === "high" && severityReady) {
    return {
      status: "ready_for_draft",
      reportability: "ready_for_draft",
      falsePositiveRisk,
      reasoningSummary: "Candidate has high confidence, enough evidence, and a reportable severity estimate.",
      nextManualSteps: ["Run reports score and review the local draft blockers before manual submission."],
    };
  }
  return {
    status: "needs_manual_verification",
    reportability: severityReady ? "needs_review" : "blocked",
    falsePositiveRisk,
    reasoningSummary: severityReady
      ? "Candidate has enough artifacts but still needs manual confidence or impact validation."
      : "Candidate severity is below the threshold for standalone draft readiness.",
    nextManualSteps: [
      "Validate impact safely inside scope.",
      "Add request/response context and update confidence only after manual review.",
    ],
  };
}

export function candidateBaselineReportabilityScore(candidate: Pick<FindingCandidate, "reportability">): number {
  if (candidate.reportability === "ready_for_draft") return 70;
  if (candidate.reportability === "needs_review") return 45;
  return 20;
}

function falsePositiveRiskFor(confidence: Confidence): DuplicateRisk {
  if (confidence === "high") return "low";
  if (confidence === "medium") return "medium";
  return "high";
}
