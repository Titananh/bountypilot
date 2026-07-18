#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";

const MAX_BYTES = 1024 * 1024;
const REQUIRED_SECTIONS = [
  "Summary",
  "Program and Asset",
  "Program Custom Fields",
  "Weakness",
  "Severity",
  "Steps to Reproduce",
  "Actual Result",
  "Expected Result",
  "Impact",
  "Evidence",
  "Scope and Safety",
  "Duplicate-Risk Note",
  "Remediation",
  "Researcher Attestation",
];

function usage() {
  return "Usage: node report-lint.mjs --file REPORT.md [--json]";
}

function die(message) {
  process.stderr.write(`report-lint: ${message}\n${usage()}\n`);
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
    if (!new Set(["--file", "--json"]).has(token)) die(`unknown or positional argument: ${token}`);
    if (Object.hasOwn(parsed, token)) die(`duplicate option: ${token}`);
    if (token === "--json") {
      parsed[token] = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) die("missing value for --file");
    if (value.length === 0 || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) die("invalid --file path");
    parsed[token] = value;
    index += 1;
  }
  if (typeof parsed["--file"] !== "string") die("--file is required");
  return parsed;
}

function readReport(file) {
  const absolute = path.resolve(file);
  let stat;
  try {
    stat = fs.lstatSync(absolute);
  } catch (error) {
    die(`cannot inspect report: ${error.message}`);
  }
  if (stat.isSymbolicLink()) die("report path must not be a symbolic link");
  if (!stat.isFile()) die("report path must be a regular file");
  if (stat.size === 0) die("report file is empty");
  if (stat.size > MAX_BYTES) die(`report exceeds ${MAX_BYTES} bytes`);

  let bytes;
  try {
    bytes = fs.readFileSync(absolute);
  } catch (error) {
    die(`cannot read report: ${error.message}`);
  }
  if (bytes.includes(0)) die("report contains a NUL byte");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    die("report must be valid UTF-8");
  }
  return { absolute, text: text.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n") };
}

function sectionMap(text, errors) {
  const matches = [...text.matchAll(/^## ([^\n]+?)[ \t]*$/gm)];
  const counts = new Map();
  for (const match of matches) counts.set(match[1], (counts.get(match[1]) ?? 0) + 1);

  for (const name of REQUIRED_SECTIONS) {
    if (!counts.has(name)) errors.push({ code: "MISSING_SECTION", message: `Missing section: ${name}` });
    else if (counts.get(name) !== 1) errors.push({ code: "DUPLICATE_SECTION", message: `Section must appear once: ${name}` });
  }
  for (const name of counts.keys()) {
    if (!REQUIRED_SECTIONS.includes(name)) errors.push({ code: "UNEXPECTED_SECTION", message: `Unexpected level-two section: ${name}` });
  }

  const positions = new Map(matches.map((match) => [match[1], match.index]));
  for (let index = 1; index < REQUIRED_SECTIONS.length; index += 1) {
    const previous = positions.get(REQUIRED_SECTIONS[index - 1]);
    const current = positions.get(REQUIRED_SECTIONS[index]);
    if (previous !== undefined && current !== undefined && current < previous) {
      errors.push({ code: "SECTION_ORDER", message: `${REQUIRED_SECTIONS[index]} must follow ${REQUIRED_SECTIONS[index - 1]}` });
    }
  }

  const sections = new Map();
  for (let index = 0; index < matches.length; index += 1) {
    const match = matches[index];
    const start = match.index + match[0].length;
    const end = matches[index + 1]?.index ?? text.length;
    sections.set(match[1], text.slice(start, end).trim());
  }
  return sections;
}

function meaningfulLength(value) {
  return value.replace(/[`*_>#|\[\]()-]/g, " ").replace(/\s+/g, " ").trim().length;
}

function requireMatch(section, pattern, code, message, errors) {
  if (!pattern.test(section ?? "")) errors.push({ code, message });
}

const args = parseArgs(process.argv.slice(2));
const { absolute, text } = readReport(args["--file"]);
const errors = [];
const warnings = [];

const h1Matches = [...text.matchAll(/^# ([^#\n].*)$/gm)];
if (h1Matches.length !== 1) {
  errors.push({ code: "TITLE_COUNT", message: "Report must contain exactly one level-one title" });
} else {
  const title = h1Matches[0][1].trim();
  if (title.length < 20 || title.length > 180) errors.push({ code: "TITLE_LENGTH", message: "Title must be 20 to 180 characters" });
  if (/^(?:bug|vulnerability|security issue|report)$/i.test(title)) errors.push({ code: "TITLE_VAGUE", message: "Title is too vague" });
}

if (/\{\{[^{}\n]+\}\}|\b(?:TODO|TBD|FIXME)\b|\[\[(?:REPLACE|PLACEHOLDER)[^\]]*\]\]/i.test(text)) {
  errors.push({ code: "PLACEHOLDER", message: "Report contains an unresolved placeholder" });
}

const guaranteePatterns = [
  /\b(?:zero|no) duplicate risk\b/i,
  /\b(?:there (?:are|is)|has) no duplicates?\b/i,
  /\bguaranteed (?:bounty|validity|valid|acceptance)\b/i,
  /\bHackerOne (?:will|must) accept\b/i,
  /\bautomatically submit(?:ted|s|ting)?\b/i,
];
for (const pattern of guaranteePatterns) {
  if (pattern.test(text)) errors.push({ code: "FORBIDDEN_CLAIM", message: `Forbidden certainty or automation claim: ${pattern.source}` });
}

const secretPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /^\s*Authorization:\s*Bearer\s+[A-Za-z0-9._~+\/-]{12,}/im,
  /^\s*(?:Cookie|Set-Cookie):\s*[^\n]*(?:session|token|auth)=[^;\s]{8,}/im,
  /^\s*(?:api[_ -]?key|access[_ -]?token|secret|password)\s*[:=]\s*(?!\[?redacted\b)\S{8,}/im,
];
for (const pattern of secretPatterns) {
  if (pattern.test(text)) errors.push({ code: "POSSIBLE_SECRET", message: "Report appears to contain an unredacted secret" });
}

const sections = sectionMap(text, errors);
for (const name of REQUIRED_SECTIONS) {
  if (sections.has(name) && meaningfulLength(sections.get(name)) === 0) {
    errors.push({ code: "EMPTY_SECTION", message: `Section is empty: ${name}` });
  }
}

const summary = sections.get("Summary") ?? "";
if (meaningfulLength(summary) < 60) errors.push({ code: "SUMMARY_SHORT", message: "Summary must explain the condition and bounded consequence" });

const programAsset = sections.get("Program and Asset") ?? "";
requireMatch(programAsset, /^\s*- Program:\s*\S.+$/im, "PROGRAM_MISSING", "Program and Asset must name the exact program", errors);
requireMatch(programAsset, /^\s*- Asset:\s*\S.+$/im, "ASSET_MISSING", "Program and Asset must name the exact asset", errors);
requireMatch(programAsset, /^\s*- Policy source\/revision:\s*\S.+$/im, "POLICY_SOURCE_MISSING", "Program and Asset must include policy source/revision", errors);

const customFields = sections.get("Program Custom Fields") ?? "";
requireMatch(customFields, /^\s*- Program custom fields:\s*\S.+$/im, "CUSTOM_FIELDS_MISSING", "Program Custom Fields must list current required fields or state None", errors);

const weakness = sections.get("Weakness") ?? "";
requireMatch(weakness, /^\s*- Weakness:\s*(?:CWE|CAPEC)-\d+\b/im, "WEAKNESS_INVALID", "Weakness must include a program-accepted CWE or CAPEC identifier", errors);
requireMatch(weakness, /^\s*- Rationale:\s*.{30,}$/im, "WEAKNESS_RATIONALE", "Weakness requires a substantive rationale", errors);

const severity = sections.get("Severity") ?? "";
requireMatch(severity, /^\s*- Rating:\s*(?:None|Low|Medium|High|Critical)\s*$/im, "SEVERITY_INVALID", "Severity rating must be None, Low, Medium, High, or Critical", errors);
requireMatch(severity, /^\s*- Method:\s*\S.+$/im, "SEVERITY_METHOD", "Severity must name the program method", errors);
requireMatch(severity, /^\s*- Rationale:\s*.{40,}$/im, "SEVERITY_RATIONALE", "Severity requires an evidence-bounded rationale", errors);
if (/^\s*- Method:\s*.*CVSS/im.test(severity) && !/^\s*- Vector:\s*CVSS:\d\.\d\//im.test(severity)) {
  errors.push({ code: "CVSS_VECTOR", message: "A CVSS method requires a versioned CVSS vector" });
}

const steps = sections.get("Steps to Reproduce") ?? "";
const numberedSteps = [...steps.matchAll(/^\s*\d+\.\s+(.+)$/gm)].filter((match) => meaningfulLength(match[1]) >= 12);
if (numberedSteps.length < 3) errors.push({ code: "STEPS_INCOMPLETE", message: "Provide at least three substantive numbered reproduction steps" });

for (const [name, minimum] of [["Actual Result", 40], ["Expected Result", 40], ["Impact", 80], ["Remediation", 40]]) {
  if (meaningfulLength(sections.get(name) ?? "") < minimum) {
    errors.push({ code: `${name.toUpperCase().replace(/[^A-Z]+/g, "_")}_SHORT`, message: `${name} needs more specific detail` });
  }
}

const evidence = sections.get("Evidence") ?? "";
requireMatch(evidence, /^\s*- Evidence ID:\s*[A-Za-z0-9][A-Za-z0-9._:-]{2,127}\s*$/im, "EVIDENCE_ID", "Evidence must include a valid BountyPilot evidence ID", errors);
requireMatch(evidence, /^\s*- SHA-256:\s*[a-f0-9]{64}\s*$/im, "EVIDENCE_DIGEST", "Evidence must include a lowercase SHA-256 digest", errors);
requireMatch(evidence, /^\s*- Evidence limitations:\s*\S.+$/im, "EVIDENCE_LIMITS", "Evidence must state limitations", errors);

const scopeSafety = sections.get("Scope and Safety") ?? "";
for (const [label, code] of [
  ["Exact program import", "EXACT_IMPORT"],
  ["In-scope decision", "SCOPE_DECISION"],
  ["Out-of-scope precedence checked", "SCOPE_PRECEDENCE"],
  ["Sensitive data extracted", "SENSITIVE_DATA"],
  ["Unexpected target effects", "TARGET_EFFECTS"],
]) {
  const expected = new Set(["Sensitive data extracted", "Unexpected target effects"]).has(label) ? "no" : "yes";
  requireMatch(scopeSafety, new RegExp(`^\\s*- ${label}:\\s*${expected}\\s*$`, "im"), code, `${label} must be ${expected}`, errors);
}

const duplicate = sections.get("Duplicate-Risk Note") ?? "";
requireMatch(duplicate, /^\s*- Checked at:\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z\s*$/im, "DUPLICATE_TIME", "Duplicate check needs an ISO-8601 UTC timestamp", errors);
requireMatch(duplicate, /^\s*- Sources checked:\s*\S.+$/im, "DUPLICATE_SOURCES", "Duplicate check must list accessible sources", errors);
requireMatch(duplicate, /^\s*- Private visibility:\s*.*(?:unavailable|unknown|not visible|cannot access).*/im, "DUPLICATE_LIMIT", "Duplicate note must acknowledge private visibility limits", errors);
requireMatch(duplicate, /^\s*- Risk:\s*(?:low|medium|high|unknown)\b.*$/im, "DUPLICATE_RISK", "Duplicate risk must be low, medium, high, or unknown with rationale", errors);

const attestation = sections.get("Researcher Attestation") ?? "";
for (const [label, expected, code] of [
  ["Human validation", "pending", "HUMAN_VALIDATION_PENDING"],
  ["Human submission required", "yes", "HUMAN_SUBMISSION"],
  ["Agent submitted", "no", "AGENT_SUBMISSION"],
]) {
  requireMatch(attestation, new RegExp(`^\\s*- ${label}:\\s*${expected}\\s*$`, "im"), code, `${label} must be ${expected}`, errors);
}

if (!/^\s*- Remaining uncertainty:\s*\S.+$/im.test(attestation)) {
  warnings.push({ code: "UNCERTAINTY_MISSING", message: "State remaining uncertainty in the attestation" });
}
if (/\b(?:all users|complete compromise|full takeover)\b/i.test(sections.get("Impact") ?? "")) {
  warnings.push({ code: "BROAD_IMPACT", message: "Review broad impact language against verified evidence" });
}

const result = { ok: errors.length === 0, file: absolute, errors, warnings };
if (args["--json"]) {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} else {
  process.stdout.write(result.ok ? `PASS ${absolute}\n` : `FAIL ${absolute}\n`);
  for (const item of errors) process.stdout.write(`ERROR ${item.code}: ${item.message}\n`);
  for (const item of warnings) process.stdout.write(`WARN ${item.code}: ${item.message}\n`);
}
process.exitCode = result.ok ? 0 : 1;
