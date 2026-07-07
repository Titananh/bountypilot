import type { EvidenceArtifact, NormalizedFinding } from "../../types.js";

export interface TriageResult {
  findingId: string;
  evidenceQuality: "weak" | "moderate" | "strong";
  reportabilityScore: number;
  recommendation: "do_not_report_alone" | "needs_manual_impact_validation" | "ready_for_draft";
  reasons: string[];
}

const LOW_VALUE_CATEGORIES = new Set(["security_headers", "server_banner", "cookie_flags"]);
const STRONG_EVIDENCE_KINDS = new Set<EvidenceArtifact["kind"]>([
  "har",
  "request_sample",
  "response_sample",
  "reproduction_note",
  "tool_output",
  "screenshot",
  "dom_snapshot",
]);
const NETWORK_OR_TOOL_EVIDENCE_KINDS = new Set<EvidenceArtifact["kind"]>(["har", "request_sample", "response_sample", "tool_output"]);
const VISUAL_OR_STATE_EVIDENCE_KINDS = new Set<EvidenceArtifact["kind"]>([
  "screenshot",
  "dom_snapshot",
  "browser_trace",
  "desktop_screenshot",
]);
const STALE_EVIDENCE_AFTER_MS = 30 * 24 * 60 * 60 * 1000;

const SEVERITY_ADJUSTMENTS: Record<NormalizedFinding["severityEstimate"], number> = {
  critical: 20,
  high: 15,
  medium: 8,
  low: 2,
  info: -8,
  unknown: -5,
};

interface ImpactSignal {
  label: string;
  pattern: RegExp;
  strongEvidenceAdjustment: number;
}

const IMPACT_SIGNALS: ImpactSignal[] = [
  {
    label: "broken access control or object-level authorization",
    pattern: /\b(idor|bola|bopla|access control|authorization|authorisation|authz|object level|object property)\b/i,
    strongEvidenceAdjustment: 12,
  },
  {
    label: "credential, token, or secret exposure",
    pattern: /\b(secret|token|api key|apikey|credential|jwt|session|private key|password|oauth)\b/i,
    strongEvidenceAdjustment: 10,
  },
  {
    label: "server-side injection or request forgery impact",
    pattern: /\b(ssrf|sql injection|sqli|rce|command injection|template injection|xxe)\b/i,
    strongEvidenceAdjustment: 12,
  },
  {
    label: "stored client-side or redirect impact",
    pattern: /\b(stored xss|cross site scripting|xss|open redirect|redirect_uri|cors)\b/i,
    strongEvidenceAdjustment: 6,
  },
  {
    label: "GraphQL exposure",
    pattern: /\b(graphql|introspection)\b/i,
    strongEvidenceAdjustment: 5,
  },
  {
    label: "cloud storage or debug surface exposure",
    pattern: /\b(bucket|s3|gcs|azure blob|debug|swagger|openapi|source map|sourcemap)\b/i,
    strongEvidenceAdjustment: 6,
  },
];

export class TriageEngine {
  triage(finding: NormalizedFinding, evidence: EvidenceArtifact[]): TriageResult {
    const reasons: string[] = [];
    let score = finding.reportabilityScore;

    const evidenceProfile = profileEvidence(finding, evidence);
    score += evidenceProfile.scoreAdjustment;
    reasons.push(...evidenceProfile.reasons);

    const impactProfile = profileImpact(finding, evidenceProfile.evidenceQuality);
    score += impactProfile.scoreAdjustment;
    reasons.push(...impactProfile.reasons);

    score += SEVERITY_ADJUSTMENTS[finding.severityEstimate];
    if (finding.severityEstimate === "info") {
      reasons.push("Informational severity usually needs a strong impact chain before reporting.");
    } else if (finding.severityEstimate === "high" || finding.severityEstimate === "critical") {
      reasons.push("Severity estimate increases reportability, pending safe evidence review.");
    }

    if (finding.confidence === "high") {
      score += 12;
      reasons.push("High confidence increases reportability.");
    }
    if (finding.confidence === "low") {
      score -= 15;
      reasons.push("Low confidence requires manual validation before drafting.");
    }

    if (finding.duplicateRisk === "high") {
      score -= 30;
      reasons.push("High local duplicate risk should be reviewed before drafting.");
    } else if (finding.duplicateRisk === "medium") {
      score -= 15;
      reasons.push("Medium local duplicate risk should be compared against prior findings.");
    } else if (finding.duplicateRisk === "low") {
      score -= 5;
      reasons.push("Low local duplicate signal is present.");
    } else {
      reasons.push("No local duplicate signal was provided; private platform duplicates remain unknown.");
    }

    if (LOW_VALUE_CATEGORIES.has(finding.category)) {
      score -= evidenceProfile.evidenceQuality === "strong" ? 10 : 25;
      reasons.push("Category is usually low reportability unless chained with stronger validated impact.");
    }

    if (finding.status === "validated") {
      score += 10;
      reasons.push("Finding is marked validated.");
    } else if (finding.status === "needs_manual_review") {
      score -= 15;
      reasons.push("Finding still needs manual review before submission.");
    } else if (finding.status === "needs_validation") {
      score -= 10;
      reasons.push("Finding still needs safe validation before submission.");
    } else if (finding.status === "duplicate" || finding.status === "invalid") {
      score -= 40;
      reasons.push("Finding status should prevent standalone reporting.");
    }

    const reportabilityScore = clamp(Math.round(score), 0, 100);
    const recommendation = recommend(finding, evidenceProfile.evidenceQuality, reportabilityScore);

    return {
      findingId: finding.id,
      evidenceQuality: evidenceProfile.evidenceQuality,
      reportabilityScore,
      recommendation,
      reasons,
    };
  }
}

interface EvidenceProfile {
  evidenceQuality: TriageResult["evidenceQuality"];
  scoreAdjustment: number;
  reasons: string[];
}

function profileEvidence(finding: NormalizedFinding, evidence: EvidenceArtifact[]): EvidenceProfile {
  const linkedPaths = new Set([...finding.evidencePaths, ...evidence.map((artifact) => artifact.path)]);
  const kinds = new Set(evidence.map((artifact) => artifact.kind));
  const adapters = new Set(evidence.map((artifact) => artifact.adapterName));
  const strongKinds = evidence.filter((artifact) => STRONG_EVIDENCE_KINDS.has(artifact.kind)).length;
  const hasReproductionNote = kinds.has("reproduction_note");
  const hasRequestOrResponse = evidence.some((artifact) => NETWORK_OR_TOOL_EVIDENCE_KINDS.has(artifact.kind));
  const hasVisualOrState = evidence.some((artifact) => VISUAL_OR_STATE_EVIDENCE_KINDS.has(artifact.kind));

  if (linkedPaths.size === 0) {
    return {
      evidenceQuality: "weak",
      scoreAdjustment: -25,
      reasons: ["No linked evidence artifacts or evidence paths are available."],
    };
  }

  if (evidence.length === 0) {
    return {
      evidenceQuality: "moderate",
      scoreAdjustment: 6,
      reasons: ["Finding has linked evidence paths, but artifact metadata was not loaded."],
    };
  }

  const adjustments = evidenceContextAdjustments(finding, evidence, kinds, adapters);

  if (hasReproductionNote && hasRequestOrResponse) {
    return {
      evidenceQuality: "strong",
      scoreAdjustment: 22 + adjustments.scoreAdjustment,
      reasons: ["Evidence includes a reproduction note and supporting request, response, HAR, or tool output.", ...adjustments.reasons],
    };
  }

  if ((hasRequestOrResponse && hasVisualOrState && kinds.size >= 2) || (strongKinds >= 3 && hasRequestOrResponse)) {
    return {
      evidenceQuality: "strong",
      scoreAdjustment: 18 + adjustments.scoreAdjustment,
      reasons: ["Multiple complementary evidence artifacts with request/state context are available.", ...adjustments.reasons],
    };
  }

  if (strongKinds >= 3 || kinds.size >= 3) {
    return {
      evidenceQuality: "moderate",
      scoreAdjustment: 12 + adjustments.scoreAdjustment,
      reasons: ["Multiple evidence artifacts are available, but request or reproduction context is still limited.", ...adjustments.reasons],
    };
  }

  return {
    evidenceQuality: "moderate",
    scoreAdjustment: 10 + adjustments.scoreAdjustment,
    reasons: ["At least one linked evidence artifact is available.", ...adjustments.reasons],
  };
}

interface ScoreProfile {
  scoreAdjustment: number;
  reasons: string[];
}

function profileImpact(finding: NormalizedFinding, evidenceQuality: TriageResult["evidenceQuality"]): ScoreProfile {
  const haystack = normalizeForMatching(`${finding.category} ${finding.title}`);
  const matchedSignals = IMPACT_SIGNALS.filter((signal) => signal.pattern.test(haystack));
  if (matchedSignals.length === 0) {
    return { scoreAdjustment: 0, reasons: [] };
  }

  const strongestSignal = matchedSignals.reduce((strongest, signal) =>
    signal.strongEvidenceAdjustment > strongest.strongEvidenceAdjustment ? signal : strongest,
  );
  const adjustment =
    evidenceQuality === "strong"
      ? strongestSignal.strongEvidenceAdjustment
      : Math.ceil(strongestSignal.strongEvidenceAdjustment / 2);

  return {
    scoreAdjustment: adjustment,
    reasons: [
      `Impact signal detected for ${strongestSignal.label}; reportability still depends on evidence quality and duplicate review.`,
    ],
  };
}

function evidenceContextAdjustments(
  finding: NormalizedFinding,
  evidence: EvidenceArtifact[],
  kinds: Set<EvidenceArtifact["kind"]>,
  adapters: Set<string>,
): ScoreProfile {
  const reasons: string[] = [];
  let scoreAdjustment = 0;

  if (kinds.size >= 3) {
    scoreAdjustment += 4;
    reasons.push("Evidence covers multiple artifact kinds.");
  }
  if (adapters.size >= 2) {
    scoreAdjustment += 3;
    reasons.push("Evidence was produced by multiple local adapters.");
  }

  const sourceAlignment = evidenceSourceAlignment(finding, evidence);
  scoreAdjustment += sourceAlignment.scoreAdjustment;
  reasons.push(...sourceAlignment.reasons);

  const freshness = evidenceFreshness(finding, evidence);
  scoreAdjustment += freshness.scoreAdjustment;
  reasons.push(...freshness.reasons);

  return { scoreAdjustment, reasons };
}

function evidenceSourceAlignment(finding: NormalizedFinding, evidence: EvidenceArtifact[]): ScoreProfile {
  const sourceUrls = evidence.map((artifact) => artifact.sourceUrl).filter((sourceUrl): sourceUrl is string => Boolean(sourceUrl));
  if (sourceUrls.length === 0) {
    return { scoreAdjustment: 0, reasons: [] };
  }

  if (sourceUrls.some((sourceUrl) => sourceUrlMatchesFinding(sourceUrl, finding))) {
    return {
      scoreAdjustment: 4,
      reasons: ["At least one evidence source URL aligns with the finding asset or URL."],
    };
  }

  return {
    scoreAdjustment: -6,
    reasons: ["Evidence source URLs do not align with the finding asset or URL and need manual review."],
  };
}

function evidenceFreshness(finding: NormalizedFinding, evidence: EvidenceArtifact[]): ScoreProfile {
  const findingUpdatedAt = Date.parse(finding.updatedAt);
  const evidenceTimestamps = evidence.map((artifact) => Date.parse(artifact.createdAt)).filter((timestamp) => Number.isFinite(timestamp));
  if (!Number.isFinite(findingUpdatedAt) || evidenceTimestamps.length === 0) {
    return { scoreAdjustment: 0, reasons: [] };
  }

  const newestEvidence = Math.max(...evidenceTimestamps);
  if (findingUpdatedAt - newestEvidence > STALE_EVIDENCE_AFTER_MS) {
    return {
      scoreAdjustment: -8,
      reasons: ["Newest evidence is stale relative to the latest finding update."],
    };
  }

  if (newestEvidence >= findingUpdatedAt - 60 * 1000) {
    return {
      scoreAdjustment: 3,
      reasons: ["Evidence timestamps are current for the latest finding state."],
    };
  }

  return { scoreAdjustment: 0, reasons: [] };
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

function recommend(
  finding: NormalizedFinding,
  evidenceQuality: TriageResult["evidenceQuality"],
  reportabilityScore: number,
): TriageResult["recommendation"] {
  if (
    finding.status === "duplicate" ||
    finding.status === "invalid" ||
    evidenceQuality === "weak" ||
    (LOW_VALUE_CATEGORIES.has(finding.category) && reportabilityScore < 65)
  ) {
    return "do_not_report_alone";
  }

  if (
    finding.status === "needs_manual_review" ||
    finding.status === "needs_validation" ||
    finding.confidence === "low" ||
    reportabilityScore < 75
  ) {
    return "needs_manual_impact_validation";
  }

  return "ready_for_draft";
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function normalizeForMatching(value: string): string {
  return value.toLowerCase().replace(/[_-]+/g, " ").replace(/[^a-z0-9.]+/g, " ").trim();
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
