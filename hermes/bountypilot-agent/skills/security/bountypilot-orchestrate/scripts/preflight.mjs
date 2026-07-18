#!/usr/bin/env node

import process from "node:process";

const VALUE_OPTIONS = new Set(["--program", "--target", "--finding", "--stage", "--session", "--mode"]);
const FLAG_OPTIONS = new Set([
  "--program-imported",
  "--scope-confirmed",
  "--policy-confirmed",
  "--json",
]);
const STAGES = new Set(["intake", "recon", "evidence", "validate", "duplicate-check", "triage", "report"]);
const SESSIONS = new Set(["normal", "one-shot", "yolo", "approval-bypassed"]);
const MODES = new Set(["plan", "dry-run", "live"]);
const RESTRICTED_SESSIONS = new Set(["one-shot", "yolo", "approval-bypassed"]);

function usage() {
  return [
    "Usage:",
    "  node preflight.mjs --program NAME --stage STAGE --session SESSION --mode MODE [options]",
    "",
    "Stages: intake, recon, evidence, validate, duplicate-check, triage, report",
    "Sessions: normal, one-shot, yolo, approval-bypassed",
    "Modes: plan, dry-run, live",
    "Options: --target URL_OR_HOST --finding ID --program-imported --scope-confirmed",
    "         --policy-confirmed --json",
  ].join("\n");
}

function die(message) {
  process.stderr.write(`preflight: ${message}\n${usage()}\n`);
  process.exit(2);
}

function parseArgs(argv) {
  if (argv.length === 0) die("arguments are required");
  if (argv.includes("--help")) {
    if (argv.length !== 1) die("--help cannot be combined with other arguments");
    process.stdout.write(`${usage()}\n`);
    process.exit(0);
  }

  const parsed = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) die(`unexpected positional argument: ${token}`);
    if (!VALUE_OPTIONS.has(token) && !FLAG_OPTIONS.has(token)) die(`unknown option: ${token}`);
    if (Object.hasOwn(parsed, token)) die(`duplicate option: ${token}`);

    if (FLAG_OPTIONS.has(token)) {
      parsed[token] = true;
      continue;
    }

    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) die(`missing value for ${token}`);
    if (value.trim() !== value || value.length === 0) die(`invalid empty or padded value for ${token}`);
    if (value.length > 2048) die(`value too long for ${token}`);
    parsed[token] = value;
    index += 1;
  }
  return parsed;
}

function required(parsed, name) {
  const value = parsed[name];
  if (typeof value !== "string") die(`${name} is required`);
  return value;
}

function validateProgram(program) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(program)) {
    die("--program must be an exact imported name using letters, digits, dot, underscore, or hyphen");
  }
}

function validateFinding(finding) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(finding)) {
    die("--finding contains unsupported characters");
  }
}

function validateTarget(target) {
  if (target.length > 2048 || /[\u0000-\u001f\u007f\s]/.test(target)) die("--target contains unsafe whitespace or control characters");
  if (target.includes("://")) {
    let url;
    try {
      url = new URL(target);
    } catch {
      die("--target must be a valid HTTP(S) URL or hostname");
    }
    if (!new Set(["http:", "https:"]).has(url.protocol)) die("--target URL must use HTTP or HTTPS");
    if (url.username || url.password || url.hash || url.search) die("--target URL must not contain credentials, a query, or a fragment");
    if (!url.hostname) die("--target URL must include a hostname");
    if (!/^[A-Za-z0-9.-]+$/.test(url.hostname) || url.hostname.includes("..")) {
      die("--target URL hostname is outside the Hermes shell-safe subset");
    }
    if (!/^\/[A-Za-z0-9._~+/-]*$/.test(url.pathname)) {
      die("--target URL path is outside the Hermes shell-safe subset");
    }
    return;
  }
  const hostPort = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::\d{1,5})?$/;
  if (!hostPort.test(target) || target.includes("..")) die("--target must be a shell-safe hostname, IPv4 literal, or HTTP(S) URL");
}

function buildArgv({ program, target, finding, stage, mode }) {
  const base = ["bounty", "--program", program];
  switch (stage) {
    case "intake":
      return [...base, "programs", "show", program, "--json"];
    case "recon":
      if (mode === "plan") return [...base, "hunt", "plan", target, "--profile", "recon", "--json"];
      return [...base, "hunt", "recon", target, "--profile", "passive", "--dry-run", "--json"];
    case "evidence":
      return [...base, "evidence", "verify", finding, "--json"];
    case "validate":
      return [...base, "reproduce", finding, "--mode", "safe", "--json"];
    case "duplicate-check":
    case "triage":
      return [...base, "triage", finding, "--json"];
    case "report":
      return [...base, "reports", "draft", finding, "--platform", "hackerone", "--json"];
    default:
      throw new Error(`unhandled stage: ${stage}`);
  }
}

const parsed = parseArgs(process.argv.slice(2));
const program = required(parsed, "--program");
const stage = required(parsed, "--stage");
const session = required(parsed, "--session");
const mode = required(parsed, "--mode");
const target = parsed["--target"];
const finding = parsed["--finding"];

validateProgram(program);
if (!STAGES.has(stage)) die(`unsupported --stage: ${stage}`);
if (!SESSIONS.has(session)) die(`unsupported --session: ${session}`);
if (!MODES.has(mode)) die(`unsupported --mode: ${mode}`);
if (target !== undefined) validateTarget(target);
if (finding !== undefined) validateFinding(finding);
if (stage === "recon" && target === undefined) die("--target is required for recon");
if (new Set(["evidence", "validate", "duplicate-check", "triage", "report"]).has(stage) && finding === undefined) {
  die(`--finding is required for ${stage}`);
}
if (parsed["--scope-confirmed"] && !parsed["--program-imported"]) die("--scope-confirmed requires --program-imported");
if (parsed["--policy-confirmed"] && !parsed["--program-imported"]) die("--policy-confirmed requires --program-imported");

const blockReasons = [];
if (!parsed["--program-imported"]) blockReasons.push("exact program import has not been confirmed");
if (stage !== "intake" && !parsed["--scope-confirmed"]) blockReasons.push("current scope has not been confirmed");
if (stage !== "intake" && !parsed["--policy-confirmed"]) blockReasons.push("current policy has not been confirmed");
if (RESTRICTED_SESSIONS.has(session) && mode === "live") {
  blockReasons.push(`${session} sessions may not produce live target effects`);
}
if (mode === "live") {
  blockReasons.push("the Hermes BountyPilot v0.1 integration is plan-and-dry-run only; live actions require a separate human-controlled BountyPilot workflow");
}
if (stage === "report" && mode === "live") blockReasons.push("report work is local-only and submission is user-controlled");

let decision;
if (blockReasons.length > 0) decision = "BLOCK";
else if (RESTRICTED_SESSIONS.has(session)) decision = "LOCAL_ONLY";
else if (mode === "live") decision = "BOUNTYPILOT_GATE";
else decision = mode === "dry-run" ? "DRY_RUN" : "LOCAL_ONLY";

const result = {
  schema: "bountypilot-preflight/v1",
  decision,
  stage,
  session,
  mode,
  program,
  target: target ?? null,
  finding: finding ?? null,
  untrustedClaims: {
    exactProgramImported: Boolean(parsed["--program-imported"]),
    scopeConfirmed: Boolean(parsed["--scope-confirmed"]),
    policyConfirmed: Boolean(parsed["--policy-confirmed"]),
  },
  blockReasons,
  plannedBountyPilotArgv: decision === "BLOCK" ? null : buildArgv({ program, target, finding, stage, mode }),
  invariants: [
    "This plan does not execute a command or authorize target access.",
    "Claim flags are orchestration notes, not approval or materialized authority.",
    "Out-of-scope and exclusion decisions take precedence.",
    "This Hermes integration is limited to local planning, public-passive research, and BountyPilot dry-runs.",
    "Live, risky, state-changing, external, or MCP actions require a separate human-controlled BountyPilot workflow.",
    "The agent may draft reports but the user must submit them.",
  ],
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
