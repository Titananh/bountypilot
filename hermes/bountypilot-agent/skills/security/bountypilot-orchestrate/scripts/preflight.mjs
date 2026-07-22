#!/usr/bin/env node

import process from "node:process";

const VALUE_OPTIONS = new Set(["--program", "--target", "--goal", "--profile", "--session"]);
const FLAG_OPTIONS = new Set(["--json"]);
const PROFILES = new Set(["recon", "web", "validate"]);
const SESSIONS = new Set(["normal", "one-shot", "yolo", "approval-bypassed"]);
const GOAL = "local-report-draft";

function usage() {
  return [
    "Usage:",
    "  node preflight.mjs --program NAME --goal local-report-draft --profile PROFILE --session SESSION [--target ABSOLUTE_HTTP_URL] [--json]",
    "",
    "Profiles: recon, web, validate",
    "Sessions: normal, one-shot, yolo, approval-bypassed",
    "This helper emits one typed, zero-live BountyPilot mission argv and never executes it.",
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
    if (typeof token !== "string" || !token.startsWith("--")) die("unexpected positional argument");
    if (!VALUE_OPTIONS.has(token) && !FLAG_OPTIONS.has(token)) die(`unknown option: ${token}`);
    if (Object.hasOwn(parsed, token)) die(`duplicate option: ${token}`);
    if (FLAG_OPTIONS.has(token)) {
      parsed[token] = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) die(`missing value for ${token}`);
    if (value.trim() !== value || value.length === 0 || value.length > 2048) die(`invalid value for ${token}`);
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

function validateTarget(target) {
  if (target.length > 2048 || /[\u0000-\u001f\u007f\s]/.test(target)) {
    die("--target contains unsafe whitespace or control characters");
  }
  let url;
  try {
    url = new URL(target);
  } catch {
    die("--target must be an absolute HTTP(S) URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") die("--target URL must use HTTP or HTTPS");
  if (url.username || url.password || url.hash || url.search) {
    die("--target URL must not contain credentials, a query, or a fragment");
  }
  if (!url.hostname || !/^[A-Za-z0-9.-]+$/.test(url.hostname) || url.hostname.includes("..")) {
    die("--target URL hostname is outside the fixed shell-safe subset");
  }
  if (!/^\/[A-Za-z0-9._~+/-]*$/.test(url.pathname)) {
    die("--target URL path is outside the fixed shell-safe subset");
  }
}

const parsed = parseArgs(process.argv.slice(2));
const program = required(parsed, "--program");
const goal = required(parsed, "--goal");
const profile = required(parsed, "--profile");
const sessionClass = required(parsed, "--session");
const target = parsed["--target"];

validateProgram(program);
if (goal !== GOAL) die(`unsupported --goal: ${goal}`);
if (!PROFILES.has(profile)) die(`unsupported --profile: ${profile}`);
if (!SESSIONS.has(sessionClass)) die(`unsupported --session: ${sessionClass}`);
if (target !== undefined) validateTarget(target);

const missionRequest = {
  schemaVersion: "bountypilot/mission-request/v1",
  origin: "hermes",
  program,
  goal,
  profile,
  sessionClass,
  ...(target === undefined ? {} : { target }),
  constraints: {
    liveTargetEffects: false,
    automaticSubmission: false,
  },
};

const plannedBountyPilotArgv = [
  "bounty",
  "--program",
  program,
  "mission",
  "start",
  "--goal",
  goal,
  "--profile",
  profile,
  "--session",
  sessionClass,
  ...(target === undefined ? [] : ["--target", target]),
  "--json",
];

const result = {
  schemaVersion: "bountypilot/mission-preflight/v2",
  decision: "MISSION_READY",
  missionRequest,
  plannedBountyPilotArgv,
  invariants: [
    "This helper plans exactly one typed command and never executes it.",
    "BountyPilot reloads and materializes program, scope, and policy authority.",
    "Every session class remains zero-live and automatic submission is impossible.",
    "The raw user prompt and retrieved web content never enter argv.",
    "Completed local missions use the generic human_handoff receipt.",
    "The fixed goal is intent only; preflight proves no bug, finding, evidence, validation, or report.",
  ],
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
