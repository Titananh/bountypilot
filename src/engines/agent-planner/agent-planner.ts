import type { EvidenceArtifact, ExecutionMode, NormalizedFinding, RiskLevel } from "../../types.js";

export interface PlannerActionContext {
  adapter: string;
  actionType: string;
  target?: string;
  status: "pending" | "approved" | "executed" | "blocked" | "failed";
}

export interface PlannerInput {
  urls: string[];
  endpointCandidates: string[];
  jsAssets: string[];
  mode: ExecutionMode;
  findings?: NormalizedFinding[];
  evidence?: EvidenceArtifact[];
  actions?: PlannerActionContext[];
  maxIterations?: number;
  maxActions?: number;
}

export interface PlannedAction {
  adapter: string;
  actionType: string;
  target: string;
  riskLevel: RiskLevel;
  requiresApproval: boolean;
  reason: string;
  score: number;
  iteration: number;
  dedupeKey: string;
  source: "seed" | "crawl" | "javascript" | "endpoint" | "finding" | "evidence";
}

export interface PlannerLoopIteration {
  index: number;
  label: string;
  candidates: number;
  selected: number;
  skippedDuplicates: number;
  skippedExistingActions: number;
  skippedFailedOrBlockedHistory: number;
}

export interface PlannerLoopResult {
  actions: PlannedAction[];
  iterations: PlannerLoopIteration[];
  inputSummary: {
    urls: number;
    endpointCandidates: number;
    jsAssets: number;
    findings: number;
    evidence: number;
    existingActions: number;
    maxIterations: number;
    maxActions: number;
  };
}

interface CandidateAction extends PlannedAction {}

const DEFAULT_MAX_ITERATIONS = 2;
const DEFAULT_MAX_ACTIONS = 40;

export class AgentPlanner {
  plan(input: PlannerInput): PlannedAction[] {
    return this.planLoop(input).actions;
  }

  planLoop(input: PlannerInput): PlannerLoopResult {
    const maxIterations = clamp(Math.floor(input.maxIterations ?? DEFAULT_MAX_ITERATIONS), 1, 3);
    const maxActions = clamp(Math.floor(input.maxActions ?? DEFAULT_MAX_ACTIONS), 1, 100);
    const existing = profileExistingActions(input.actions ?? []);
    const selectedByKey = new Map<string, CandidateAction>();
    const iterations: PlannerLoopIteration[] = [];

    const iterationInputs: Array<{ index: number; label: string; candidates: CandidateAction[] }> = [
      {
        index: 0,
        label: "baseline seed, crawl, and JavaScript coverage",
        candidates: baselineCandidates(input),
      },
      {
        index: 1,
        label: "feedback from endpoints, findings, evidence, and action history",
        candidates: feedbackCandidates(input, existing),
      },
      {
        index: 2,
        label: "diversity pass for under-covered hosts",
        candidates: diversityCandidates(input, selectedByKey, existing),
      },
    ];

    for (const iteration of iterationInputs.slice(0, maxIterations)) {
      let skippedDuplicates = 0;
      let skippedExistingActions = 0;
      let skippedFailedOrBlockedHistory = 0;
      let selected = 0;

      for (const candidate of rankCandidates(iteration.candidates)) {
        if (selectedByKey.size >= maxActions) break;
        if (selectedByKey.has(candidate.dedupeKey)) {
          skippedDuplicates += 1;
          continue;
        }
        if (existing.active.has(candidate.dedupeKey)) {
          skippedExistingActions += 1;
          continue;
        }
        if (existing.failedOrBlocked.has(candidate.dedupeKey)) {
          skippedFailedOrBlockedHistory += 1;
          continue;
        }
        selectedByKey.set(candidate.dedupeKey, candidate);
        selected += 1;
      }

      iterations.push({
        index: iteration.index,
        label: iteration.label,
        candidates: iteration.candidates.length,
        selected,
        skippedDuplicates,
        skippedExistingActions,
        skippedFailedOrBlockedHistory,
      });
    }

    return {
      actions: rankCandidates([...selectedByKey.values()]),
      iterations,
      inputSummary: {
        urls: uniqueUrls(input.urls).length,
        endpointCandidates: uniqueUrls(input.endpointCandidates).length,
        jsAssets: uniqueUrls(input.jsAssets).length,
        findings: input.findings?.length ?? 0,
        evidence: input.evidence?.length ?? 0,
        existingActions: input.actions?.length ?? 0,
        maxIterations,
        maxActions,
      },
    };
  }
}

interface ExistingActionProfile {
  active: Set<string>;
  failedOrBlocked: Set<string>;
  executed: Set<string>;
}

function baselineCandidates(input: PlannerInput): CandidateAction[] {
  const candidates: CandidateAction[] = [];
  for (const url of uniqueUrls(input.urls).slice(0, 50)) {
    candidates.push(
      candidate(input, {
        adapter: "safe-checks",
        actionType: "http.get",
        target: url,
        riskLevel: "low",
        reason: "Run low-risk security header and metadata checks.",
        score: 45,
        iteration: 0,
        source: "seed",
      }),
    );
  }

  for (const asset of uniqueUrls(input.jsAssets).slice(0, 25)) {
    candidates.push(
      candidate(input, {
        adapter: "js-analyzer",
        actionType: "http.get",
        target: asset,
        riskLevel: "low",
        reason: "Analyze public JavaScript for endpoints and masked secret-like patterns.",
        score: 62,
        iteration: 0,
        source: "javascript",
      }),
    );
  }

  return candidates;
}

function feedbackCandidates(input: PlannerInput, existing: ExistingActionProfile): CandidateAction[] {
  const candidates: CandidateAction[] = [];

  for (const endpoint of normalizeTargets(input.endpointCandidates).slice(0, 50)) {
    const endpointKind = classifyEndpoint(endpoint);
    candidates.push(
      candidate(input, {
        adapter: "safe-checks",
        actionType: "http.get",
        target: endpoint,
        riskLevel: endpointKind === "graphql" || endpointKind === "auth" ? "medium" : "low",
        reason: endpointReason(endpointKind),
        score: endpointScore(endpointKind),
        iteration: 1,
        source: "endpoint",
      }),
    );
  }

  for (const finding of input.findings ?? []) {
    if (!shouldPlanFindingFollowUp(finding)) continue;
    candidates.push(
      candidate(input, {
        adapter: "safe-checks",
        actionType: "http.get",
        target: finding.url,
        riskLevel: finding.severityEstimate === "high" || finding.severityEstimate === "critical" ? "medium" : "low",
        reason: `Re-check finding ${finding.id} because it is ${finding.status} with ${finding.confidence} confidence.`,
        score: findingFollowUpScore(finding),
        iteration: 1,
        source: "finding",
      }),
    );
  }

  for (const sourceUrl of evidenceSourceUrls(input.evidence ?? [])) {
    const dedupeKey = actionKey("safe-checks", "http.get", sourceUrl);
    if (existing.executed.has(dedupeKey)) continue;
    candidates.push(
      candidate(input, {
        adapter: "safe-checks",
        actionType: "http.get",
        target: sourceUrl,
        riskLevel: "low",
        reason: "Evidence introduced an in-scope source URL that has not been covered by an executed action.",
        score: 50,
        iteration: 1,
        source: "evidence",
      }),
    );
  }

  return candidates;
}

function diversityCandidates(
  input: PlannerInput,
  selectedByKey: Map<string, CandidateAction>,
  existing: ExistingActionProfile,
): CandidateAction[] {
  const candidates: CandidateAction[] = [];
  const coveredHosts = new Set(
    [...selectedByKey.values()]
      .map((action) => hostKey(action.target))
      .filter((host): host is string => Boolean(host)),
  );

  for (const url of uniqueUrls([...input.urls, ...input.endpointCandidates, ...input.jsAssets]).slice(0, 75)) {
    const host = hostKey(url);
    if (!host || coveredHosts.has(host)) continue;
    const dedupeKey = actionKey("safe-checks", "http.get", url);
    if (existing.active.has(dedupeKey) || existing.failedOrBlocked.has(dedupeKey)) continue;
    candidates.push(
      candidate(input, {
        adapter: "safe-checks",
        actionType: "http.get",
        target: url,
        riskLevel: "low",
        reason: "Add low-risk coverage for an in-scope host not represented in higher-ranked planner actions.",
        score: 42,
        iteration: 2,
        source: "crawl",
      }),
    );
  }

  return candidates;
}

function candidate(
  input: PlannerInput,
  partial: Omit<CandidateAction, "requiresApproval" | "dedupeKey">,
): CandidateAction {
  return {
    ...partial,
    requiresApproval: requiresApproval(input.mode, partial.riskLevel),
    dedupeKey: actionKey(partial.adapter, partial.actionType, partial.target),
  };
}

function profileExistingActions(actions: PlannerActionContext[]): ExistingActionProfile {
  const active = new Set<string>();
  const failedOrBlocked = new Set<string>();
  const executed = new Set<string>();

  for (const action of actions) {
    if (!action.target) continue;
    const key = actionKey(action.adapter, action.actionType, action.target);
    if (action.status === "failed" || action.status === "blocked") {
      failedOrBlocked.add(key);
      continue;
    }
    if (action.status === "executed") {
      executed.add(key);
    }
    active.add(key);
  }

  return { active, failedOrBlocked, executed };
}

function rankCandidates(candidates: CandidateAction[]): CandidateAction[] {
  return [...candidates].sort(compareCandidate);
}

function compareCandidate(left: CandidateAction, right: CandidateAction): number {
  return (
    right.score - left.score ||
    left.iteration - right.iteration ||
    riskRank(left.riskLevel) - riskRank(right.riskLevel) ||
    left.adapter.localeCompare(right.adapter) ||
    left.actionType.localeCompare(right.actionType) ||
    left.target.localeCompare(right.target)
  );
}

function classifyEndpoint(value: string): "graphql" | "auth" | "api" | "generic" {
  const normalized = value.toLowerCase();
  if (normalized.includes("graphql")) return "graphql";
  if (/\b(auth|oauth|login|session|token|sso)\b/.test(normalized)) return "auth";
  if (/\/api\/|\/v\d+\//.test(normalized) || normalized.endsWith(".json")) return "api";
  return "generic";
}

function endpointReason(kind: ReturnType<typeof classifyEndpoint>): string {
  switch (kind) {
    case "graphql":
      return "GraphQL-looking endpoint may merit safe introspection indicator checks.";
    case "auth":
      return "Authentication-looking endpoint should receive careful low-impact metadata checks.";
    case "api":
      return "API-looking endpoint was discovered from local evidence and is suitable for safe metadata checks.";
    case "generic":
      return "Discovered endpoint can be queued for safe metadata checks after review.";
  }
}

function endpointScore(kind: ReturnType<typeof classifyEndpoint>): number {
  switch (kind) {
    case "graphql":
      return 88;
    case "auth":
      return 76;
    case "api":
      return 66;
    case "generic":
      return 52;
  }
}

function shouldPlanFindingFollowUp(finding: NormalizedFinding): boolean {
  return (
    finding.status === "new" ||
    finding.status === "needs_validation" ||
    finding.status === "needs_manual_review" ||
    (finding.status === "validated" && finding.reportabilityScore >= 70 && finding.duplicateRisk !== "high")
  );
}

function findingFollowUpScore(finding: NormalizedFinding): number {
  let score = 58;
  if (finding.status === "needs_validation" || finding.status === "needs_manual_review") score += 12;
  if (finding.status === "validated") score += 8;
  if (finding.confidence === "high") score += 8;
  if (finding.confidence === "low") score -= 8;
  if (finding.severityEstimate === "critical") score += 16;
  if (finding.severityEstimate === "high") score += 12;
  if (finding.severityEstimate === "medium") score += 6;
  if (finding.duplicateRisk === "medium") score -= 10;
  if (finding.duplicateRisk === "high") score -= 25;
  return clamp(score, 20, 95);
}

function evidenceSourceUrls(evidence: EvidenceArtifact[]): string[] {
  return uniqueUrls(
    evidence
      .filter((artifact) => artifact.kind !== "report")
      .map((artifact) => artifact.sourceUrl)
      .filter((sourceUrl): sourceUrl is string => Boolean(sourceUrl)),
  );
}

function requiresApproval(mode: ExecutionMode, riskLevel: RiskLevel): boolean {
  if (mode === "passive") return true;
  if (riskLevel === "medium") return mode !== "deep-safe" && mode !== "lab-offensive";
  if (riskLevel === "high") return mode !== "lab-offensive";
  return false;
}

function actionKey(adapter: string, actionType: string, target: string): string {
  return `${adapter}|${actionType}|${normalizeTarget(target)}`;
}

function normalizeTarget(value: string): string {
  try {
    const url = new URL(value);
    url.hash = "";
    url.pathname = url.pathname.replace(/\/+$/, "") || "/";
    url.searchParams.sort();
    return url.toString();
  } catch {
    return value.toLowerCase().trim();
  }
}

function uniqueUrls(values: string[]): string[] {
  const seen = new Set<string>();
  const output: string[] = [];
  for (const value of values) {
    const normalized = normalizeTarget(value);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    output.push(normalized);
  }
  return output;
}

function normalizeTargets(values: string): string[];
function normalizeTargets(values: string[]): string[];
function normalizeTargets(values: string | string[]): string[] {
  return (Array.isArray(values) ? values : [values]).map(normalizeTarget).filter((value) => value.length > 0);
}

function hostKey(value: string): string | undefined {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function riskRank(value: RiskLevel): number {
  switch (value) {
    case "low":
      return 0;
    case "medium":
      return 1;
    case "high":
      return 2;
  }
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
