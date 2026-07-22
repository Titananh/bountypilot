// P0.2 Packet 0 — Program authority snapshot.
//
// The authority snapshot is the deterministic projection of program
// configuration that is bound into every action approval and execution
// claim. Two callers must agree on the hash before any live effect is
// allowed to run.
//
// The hash contract is:
//
//   scopeHash  = SHA256( "bountypilot/scope-snapshot/v1"  || 0x00 ||
//                        canonicalJson(ScopeSnapshot) )
//   policyHash = SHA256( "bountypilot/policy-snapshot/v1" || 0x00 ||
//                        canonicalJson(PolicySnapshot) )
//
// Where `canonicalJson` is the project-wide canonical JSON utility
// (sorted keys, arrays preserve order, set-like arrays are normalized by
// the caller, UTF-8 with no whitespace/BOM).
//
// The authority snapshot must:
//   * never bind absolute workspace paths, so moving a workspace does
//     not invalidate a previously approved plan;
//   * always normalize the lab authorization relative path before
//     binding it, so `./notes/lab-authorization.md` and
//     `notes/lab-authorization.md` are equal;
//   * bind the byte length and SHA-256 of the lab authorization file
//     (not its absolute path);
//   * never bind raw integration configuration, secrets, or
//     command/argv/header/option passthrough fields;
//   * never bind the configured `lab_authorization_file` (the policy
//     path field is treated as non-authoritative metadata that the
//     loader normalizes).

import { sha256Canonical } from "../../utils/canonical-json.js";
import { BountyPilotError } from "../../utils/errors.js";
import type { ProgramConfig } from "../config/program-schema.js";
import { BLOCKED_CAPABILITIES } from "../policy/policy-gate.js";
import {
  MAX_LAB_AUTHORIZATION_FILE_BYTES,
  type LabAuthorization,
} from "../config/config-loader.js";

export const SCOPE_SNAPSHOT_SCHEMA_VERSION = "scope-snapshot/v1";
export const SCOPE_SEMANTICS_VERSION = "scope/v1";
export const POLICY_SNAPSHOT_SCHEMA_VERSION = "policy-snapshot/v1";
export const POLICY_SEMANTICS_VERSION = "policy/v1";
export const AUTHORITY_SNAPSHOT_SCHEMA_VERSION = "authority-snapshot/v1";

export const SCOPE_HASH_DOMAIN = "bountypilot/scope-snapshot/v1";
export const POLICY_HASH_DOMAIN = "bountypilot/policy-snapshot/v1";

export interface ScopeSnapshot {
  schemaVersion: typeof SCOPE_SNAPSHOT_SCHEMA_VERSION;
  semanticsVersion: typeof SCOPE_SEMANTICS_VERSION;
  program: string;
  platform: string;
  inScope: string[];
  outOfScope: string[];
}

export interface PolicySnapshotLabAuthorization {
  relativePath: string;
  byteLength: number;
  contentSha256: string;
}

export interface PolicySnapshot {
  schemaVersion: typeof POLICY_SNAPSHOT_SCHEMA_VERSION;
  semanticsVersion: typeof POLICY_SEMANTICS_VERSION;
  rules: {
    automated_scanning: "none" | "limited" | "allowed";
    destructive_testing: boolean;
    rate_limit: string;
    browser_crawling: boolean;
    deep_safe_mode: boolean;
    lab_mode: boolean;
    require_human_approval_for_risky_actions: boolean;
  };
  accounts: {
    required: boolean;
    use_researcher_owned_test_accounts_only: boolean;
  };
  evidence: {
    screenshots: boolean;
    har: boolean;
    console_logs: boolean;
    dom_snapshot: boolean;
    video: boolean | "optional";
    browser_trace: boolean;
    desktop_screenshots: boolean | "optional";
    mask_secrets: boolean;
  };
  blockedCapabilities: string[];
  labAuthorization: PolicySnapshotLabAuthorization | null;
}

export interface ProgramAuthoritySnapshot {
  schemaVersion: typeof AUTHORITY_SNAPSHOT_SCHEMA_VERSION;
  scope: ScopeSnapshot;
  policy: PolicySnapshot;
  scopeHash: string;
  policyHash: string;
}

export interface BuildProgramAuthorityInput {
  config: ProgramConfig;
  labAuthorization: LabAuthorization | null;
}

export function normalizeScopeArrays(
  inScope: readonly string[],
  outOfScope: readonly string[],
): { inScope: string[]; outOfScope: string[] } {
  return {
    inScope: normalizeScopeSet(inScope),
    outOfScope: normalizeScopeSet(outOfScope),
  };
}

export function buildScopeSnapshot(config: ProgramConfig): ScopeSnapshot {
  const { inScope, outOfScope } = normalizeScopeArrays(config.in_scope, config.out_of_scope ?? []);
  return {
    schemaVersion: SCOPE_SNAPSHOT_SCHEMA_VERSION,
    semanticsVersion: SCOPE_SEMANTICS_VERSION,
    program: config.program,
    platform: config.platform,
    inScope,
    outOfScope,
  };
}

export function buildPolicySnapshot(
  config: ProgramConfig,
  labAuthorization: LabAuthorization | null,
): PolicySnapshot {
  const rules = normalizePolicyRules(config.rules);
  const policyLab = resolveLabAuthorization(config, labAuthorization);
  return {
    schemaVersion: POLICY_SNAPSHOT_SCHEMA_VERSION,
    semanticsVersion: POLICY_SEMANTICS_VERSION,
    rules,
    accounts: {
      required: config.accounts.required,
      use_researcher_owned_test_accounts_only: config.accounts.use_researcher_owned_test_accounts_only,
    },
    evidence: {
      screenshots: config.evidence.screenshots,
      har: config.evidence.har,
      console_logs: config.evidence.console_logs,
      dom_snapshot: config.evidence.dom_snapshot,
      video: config.evidence.video,
      browser_trace: config.evidence.browser_trace,
      desktop_screenshots: config.evidence.desktop_screenshots,
      mask_secrets: config.evidence.mask_secrets,
    },
    blockedCapabilities: [...BLOCKED_CAPABILITIES].sort(),
    labAuthorization: policyLab,
  };
}

export function buildProgramAuthoritySnapshot(
  input: BuildProgramAuthorityInput,
): ProgramAuthoritySnapshot {
  const scope = buildScopeSnapshot(input.config);
  const policy = buildPolicySnapshot(input.config, input.labAuthorization);
  return {
    schemaVersion: AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    scope,
    policy,
    scopeHash: computeScopeHash(scope),
    policyHash: computePolicyHash(policy),
  };
}

export function computeScopeHash(scope: ScopeSnapshot): string {
  return sha256Canonical(scope, SCOPE_HASH_DOMAIN);
}

export function computePolicyHash(policy: PolicySnapshot): string {
  return sha256Canonical(policy, POLICY_HASH_DOMAIN);
}

function normalizeScopeSet(values: readonly string[]): string[] {
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string") {
      throw new BountyPilotError(
        "Scope entries must be strings",
        "CANONICAL_VALUE_UNSUPPORTED",
      );
    }
    const trimmed = normalizeScopeRule(value);
    if (trimmed.length === 0) {
      throw new BountyPilotError(
        "Scope entries must not be empty after trim",
        "CANONICAL_VALUE_UNSUPPORTED",
      );
    }
    seen.add(trimmed);
  }
  return [...seen].sort();
}

/** Normalize only URL components whose comparison is case-insensitive. */
function normalizeScopeRule(value: string): string {
  const trimmed = value.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    const separator = trimmed.indexOf(":");
    if (separator > 0 && /^\d+$/.test(trimmed.slice(separator + 1))) {
      return `${trimmed.slice(0, separator).toLowerCase()}:${trimmed.slice(separator + 1)}`;
    }
    return trimmed.toLowerCase();
  }
  try {
    const parsed = new URL(trimmed);
    const protocol = parsed.protocol.toLowerCase();
    const host = parsed.hostname.toLowerCase();
    const port = parsed.port ? `:${parsed.port}` : "";
    // ScopeRuleSchema rejects credentials, query and fragment. Preserve the
    // pathname bytes because origin servers may treat path case as semantic.
    return `${protocol}//${host}${port}${parsed.pathname || "/"}`;
  } catch {
    // Invalid values are rejected by the config loader; retain their bytes so
    // authority hashing never silently aliases two malformed inputs.
    return trimmed;
  }
}

function normalizePolicyRules(
  rules: ProgramConfig["rules"],
): PolicySnapshot["rules"] {
  // Normalize lab_mode undefined → false. Exclude lab_authorization_file
  // because the configured path is loader metadata, not a semantic
  // policy attribute.
  return {
    automated_scanning: rules.automated_scanning,
    destructive_testing: rules.destructive_testing,
    rate_limit: rules.rate_limit,
    browser_crawling: rules.browser_crawling,
    deep_safe_mode: rules.deep_safe_mode,
    lab_mode: rules.lab_mode === true,
    require_human_approval_for_risky_actions: rules.require_human_approval_for_risky_actions,
  };
}

function resolveLabAuthorization(
  config: ProgramConfig,
  labAuthorization: LabAuthorization | null,
): PolicySnapshotLabAuthorization | null {
  const configured = config.rules.lab_authorization_file;
  if (configured === undefined) {
    if (labAuthorization !== null) {
      throw new BountyPilotError(
        "Lab authorization metadata was provided for a program that has no configured lab authorization file",
        "LAB_AUTHORIZATION_METADATA_MISMATCH",
      );
    }
    return null;
  }
  if (labAuthorization === null) {
    throw new BountyPilotError(
      "Program has a configured lab authorization file but no lab authorization metadata was loaded",
      "LAB_AUTHORIZATION_METADATA_MISMATCH",
    );
  }
  const normalizedConfigured = normalizeLabRelativePath(configured);
  const normalizedLoaded = normalizeLabRelativePath(labAuthorization.relativePath);
  if (normalizedLoaded !== normalizedConfigured) {
    throw new BountyPilotError(
      "Loaded lab authorization metadata does not match the configured path",
      "LAB_AUTHORIZATION_METADATA_MISMATCH",
    );
  }
  assertLabAuthorizationMetadata(labAuthorization);
  return {
    relativePath: normalizedLoaded,
    byteLength: labAuthorization.byteLength,
    contentSha256: labAuthorization.contentSha256,
  };
}

export function normalizeLabRelativePath(value: string): string {
  if (typeof value !== "string") {
    throw invalidLabAuthorizationPath();
  }
  const normalized = value
    .trim()
    .replaceAll("\\", "/")
    .replace(/^\.\/+/, "")
    .replace(/\/+$/u, "");
  if (
    normalized.length === 0 ||
    /[\u0000-\u001F\u007F]/.test(normalized) ||
    normalized.startsWith("/") ||
    /^[A-Za-z]:/.test(normalized) ||
    normalized.includes(":")
  ) {
    throw invalidLabAuthorizationPath();
  }
  for (const segment of normalized.split("/")) {
    if (segment === "" || segment === "." || segment === "..") {
      throw invalidLabAuthorizationPath();
    }
  }
  return normalized;
}

function assertLabAuthorizationMetadata(labAuthorization: LabAuthorization): void {
  if (
    !Number.isSafeInteger(labAuthorization.byteLength) ||
    labAuthorization.byteLength < 0 ||
    labAuthorization.byteLength > MAX_LAB_AUTHORIZATION_FILE_BYTES ||
    typeof labAuthorization.contentSha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(labAuthorization.contentSha256)
  ) {
    throw new BountyPilotError(
      "Loaded lab authorization metadata is malformed",
      "LAB_AUTHORIZATION_METADATA_MISMATCH",
    );
  }
}

function invalidLabAuthorizationPath(): BountyPilotError {
  return new BountyPilotError(
    "Lab authorization path must be a safe relative path inside the program workspace",
    "LAB_AUTHORIZATION_FILE_PATH_INVALID",
  );
}
