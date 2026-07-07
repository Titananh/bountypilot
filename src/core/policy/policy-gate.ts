import type { ExecutionMode, PolicyDecision, RiskLevel } from "../../types.js";
import { isIP } from "node:net";
import type { ProgramConfig } from "../config/program-schema.js";

type ProgramRules = ProgramConfig["rules"];

export interface PolicyAction {
  mode: ExecutionMode;
  actionType: string;
  target?: string;
  riskLevel?: RiskLevel;
  stateChanging?: boolean;
  destructive?: boolean;
  capability?: string;
  requiresApprovalByDefault?: boolean;
  labModeEnabled?: boolean;
}

export interface PolicyResult {
  decision: PolicyDecision;
  reason: string;
}

export const BLOCKED_CAPABILITIES = new Set([
  "brute_force",
  "credential_stuffing",
  "destructive_testing",
  "password_spraying",
  "spam",
  "payment_abuse",
  "waf_evasion",
  "data_exfiltration",
  "malware_execution",
  "mass_scanning",
  "real_user_account_takeover",
]);

const PASSIVE_ACTIONS = new Set([
  "scope.test",
  "scope.list",
  "config.load",
  "program.import",
  "research.public",
  "report.generate",
  "finding.list",
  "evidence.list",
]);

const DEFAULT_RULES: ProgramRules = {
  automated_scanning: "limited",
  destructive_testing: false,
  rate_limit: "1rps",
  browser_crawling: true,
  deep_safe_mode: true,
  lab_mode: false,
  require_human_approval_for_risky_actions: true,
};

export class PolicyGate {
  private readonly rules: ProgramRules;

  constructor(rules: Partial<ProgramRules> = {}) {
    this.rules = { ...DEFAULT_RULES, ...rules };
  }

  evaluate(action: PolicyAction): PolicyResult {
    if (action.destructive) {
      return { decision: "block", reason: "Destructive testing is blocked by default" };
    }
    if (action.capability && BLOCKED_CAPABILITIES.has(action.capability)) {
      return { decision: "block", reason: `Capability is blocked: ${action.capability}` };
    }
    if (action.mode === "deep-safe" && this.rules.deep_safe_mode === false) {
      return { decision: "block", reason: "Deep-safe mode is disabled by program rules" };
    }
    if (this.rules.automated_scanning === "none" && isAutomatedScanningAction(action)) {
      return { decision: "block", reason: "Automated scanning is disabled by program rules" };
    }
    if (this.rules.browser_crawling === false && isBrowserCrawlingAction(action)) {
      return { decision: "block", reason: "Browser crawling is disabled by program rules" };
    }
    const labModeEnabled = action.labModeEnabled ?? this.rules.lab_mode === true;
    if (action.mode === "lab-offensive" && labModeEnabled !== true) {
      return { decision: "block", reason: "Lab-offensive mode requires rules.lab_mode=true in the program config" };
    }
    if (action.mode === "lab-offensive" && !this.rules.lab_authorization_file) {
      return {
        decision: "block",
        reason: "Lab-offensive mode requires rules.lab_authorization_file with explicit local lab authorization",
      };
    }
    if (action.mode === "lab-offensive" && action.target && !isLocalOrPrivateTarget(action.target)) {
      return { decision: "block", reason: "Lab-offensive mode is limited to local/private lab targets" };
    }
    if (action.mode !== "lab-offensive" && action.capability === "exploit_validation") {
      return { decision: "require_approval", reason: "Exploit validation requires human approval outside lab mode" };
    }
    if (action.mode === "passive" && !PASSIVE_ACTIONS.has(action.actionType)) {
      return { decision: "block", reason: "Passive mode only allows non-invasive research and metadata actions" };
    }
    if (action.mode === "safe" && action.stateChanging) {
      return { decision: "block", reason: "Safe mode blocks state-changing actions" };
    }
    if (action.mode === "safe" && action.riskLevel && action.riskLevel !== "low") {
      return { decision: "require_approval", reason: "Safe mode requires approval for medium/high risk actions" };
    }
    if (action.mode === "deep-safe" && action.riskLevel === "high") {
      return { decision: "require_approval", reason: "Deep-safe mode requires approval for high risk actions" };
    }
    if (this.rules.require_human_approval_for_risky_actions && isRiskyAction(action)) {
      return { decision: "require_approval", reason: "Program rules require approval for risky actions" };
    }
    if (action.requiresApprovalByDefault) {
      return { decision: "require_approval", reason: "Action is configured to require human approval" };
    }
    return { decision: "allow", reason: "Allowed by policy" };
  }

  assertAllowed(action: PolicyAction): PolicyResult {
    const result = this.evaluate(action);
    if (result.decision === "block") {
      throw new Error(result.reason);
    }
    return result;
  }
}

function isAutomatedScanningAction(action: PolicyAction): boolean {
  return actionMatches(action, "http.") || actionMatches(action, "browser.") || actionMatches(action, "crawler.");
}

function isBrowserCrawlingAction(action: PolicyAction): boolean {
  return actionMatches(action, "browser.") || actionMatches(action, "crawler.");
}

function actionMatches(action: PolicyAction, prefix: string): boolean {
  return action.actionType.startsWith(prefix) || action.capability?.startsWith(prefix) === true;
}

function isRiskyAction(action: PolicyAction): boolean {
  return action.riskLevel === "medium" || action.riskLevel === "high" || action.stateChanging === true || action.requiresApprovalByDefault === true;
}

function isLocalOrPrivateTarget(target: string): boolean {
  const host = targetHost(target);
  if (!host) return false;
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const ipVersion = isIP(host);
  if (ipVersion === 4) return isPrivateIpv4(host);
  if (ipVersion === 6) return isPrivateIpv6(host);
  return false;
}

function targetHost(target: string): string | undefined {
  try {
    return new URL(target).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  } catch {
    try {
      return new URL(`https://${target}`).hostname.toLowerCase().replace(/^\[|\]$/g, "");
    } catch {
      return undefined;
    }
  }
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second] = parts;
  return first === 10 || first === 127 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
}

function isPrivateIpv6(host: string): boolean {
  return host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:");
}
