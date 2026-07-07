export type ExecutionMode = "passive" | "safe" | "deep-safe" | "lab-offensive";

export type RiskLevel = "low" | "medium" | "high";

export type PolicyDecision = "allow" | "block" | "require_approval";

export type FindingStatus =
  | "new"
  | "needs_validation"
  | "validated"
  | "needs_manual_review"
  | "report_drafted"
  | "submitted"
  | "duplicate"
  | "invalid";

export type SeverityEstimate = "info" | "low" | "medium" | "high" | "critical" | "unknown";

export type Confidence = "low" | "medium" | "high";

export type DuplicateRisk = "low" | "medium" | "high" | "unknown";

export interface NormalizedFinding {
  id: string;
  title: string;
  asset: string;
  url: string;
  category: string;
  severityEstimate: SeverityEstimate;
  confidence: Confidence;
  status: FindingStatus;
  evidencePaths: string[];
  rawOutputPath?: string;
  remediation?: string;
  duplicateRisk: DuplicateRisk;
  reportabilityScore: number;
  createdAt: string;
  updatedAt: string;
}

export interface EvidenceArtifact {
  id: string;
  findingId?: string;
  jobId?: string;
  adapterName: string;
  kind:
    | "screenshot"
    | "har"
    | "console_log"
    | "dom_snapshot"
    | "browser_trace"
    | "video"
    | "desktop_screenshot"
    | "desktop_action_log"
    | "request_sample"
    | "response_sample"
    | "research_note"
    | "evidence_note"
    | "crawl_graph"
    | "reproduction_note"
    | "tool_output"
    | "report";
  sourceUrl?: string;
  path: string;
  createdAt: string;
}

export type ReconObservationKind =
  | "host"
  | "url"
  | "endpoint"
  | "js_asset"
  | "parameter"
  | "form"
  | "port"
  | "technology"
  | "vulnerability_signal"
  | "finding_candidate";

export type BugClass =
  | "xss"
  | "ssrf"
  | "idor"
  | "graphql"
  | "cors"
  | "open-redirect"
  | "js-secrets"
  | "exposure";

export interface ReconObservation {
  id: string;
  jobId?: string;
  kind: ReconObservationKind;
  value: string;
  normalizedValue: string;
  sourceAdapter: string;
  sourceUrl?: string;
  scopeAllowed: boolean;
  confidence: Confidence;
  riskHint?: RiskLevel;
  metadata: Record<string, unknown>;
  fingerprint: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ToolAdapterSpec {
  tool: string;
  actionType: string;
  defaultArgs: string[];
  outputFormat: "lines" | "json" | "jsonl" | "mixed";
}

export interface ToolAdapterRunInput {
  tool: string;
  actionType: string;
  target: string;
  mode: ExecutionMode;
  jobId?: string;
  timeoutMs?: number;
}

export interface ToolAdapterRunResult {
  tool: string;
  actionType: string;
  target: string;
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
  evidence: EvidenceArtifact;
  observations: ReconObservation[];
}

export interface PlaybookResult {
  ok: boolean;
  bugClass: BugClass;
  target: string;
  live: boolean;
  jobId: string;
  observations: ReconObservation[];
  findingsCreated: NormalizedFinding[];
  evidence: EvidenceArtifact[];
  actionsPlanned: number;
  nextCommands: string[];
}
