import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { z } from "zod";
import { BountyPilotError } from "../utils/errors.js";

export const BUG_BOUNTY_PILOT_SKILL_ID = "bug-bounty-pilot";

export type SkillRunMode = "passive" | "safe" | "deep-safe" | "lab-offensive";

export interface SkillDefinition {
  id: string;
  root: string;
  skillMarkdown: string;
  policy: SkillPolicy;
  workflow: SkillWorkflow;
  toolRegistry: SkillToolRegistry;
  playbooks: SkillPlaybookRegistry;
  vmProfile: SkillVmProfile;
  prompts: Record<string, string>;
  templates: Record<string, string>;
  examples: Record<string, string>;
}

export interface SkillListEntry {
  id: string;
  root: string;
  title: string;
  bundled: boolean;
}

export interface SkillValidationCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

export interface SkillValidationResult {
  ok: boolean;
  id: string;
  root: string;
  checks: SkillValidationCheck[];
  files: {
    required: string[];
    prompts: string[];
    templates: string[];
    examples: string[];
  };
  policy?: SkillPolicy;
  workflow?: SkillWorkflow;
  toolRegistry?: SkillToolRegistry;
  playbooks?: SkillPlaybookRegistry;
  vmProfile?: SkillVmProfile;
}

export interface SkillBundleFile {
  path: string;
  size: number;
  sha256: string;
}

export interface SkillBundleManifest {
  schemaVersion: "bountypilot.skill.bundle.v1";
  id: string;
  title: string;
  generatedAt: string;
  contentsPrefix: string;
  validation: {
    checks: number;
    failures: number;
    warnings: number;
  };
  modes: string[];
  workflowSteps: string[];
  tools: string[];
  playbooks: string[];
  files: SkillBundleFile[];
  totalBytes: number;
}

export interface SkillBundleResult {
  ok: true;
  id: string;
  source: string;
  output: string;
  format: "zip";
  files: number;
  bytes: number;
  sha256: string;
  manifest: SkillBundleManifest;
}

const SkillModeSchema = z.enum(["passive", "safe", "deep-safe", "lab-offensive"]);
const RiskLevelSchema = z.enum(["low", "medium", "high"]);

const ModePolicySchema = z.object({
  allowed_capabilities: z.array(z.string()),
  review_required_capabilities: z.array(z.string()),
  blocked_capabilities: z.array(z.string()),
});

const SkillPolicySchema = z.object({
  modes: z.record(SkillModeSchema, ModePolicySchema),
  scope: z.object({
    default: z.string(),
    out_of_scope_precedence: z.boolean(),
    require_program_import: z.boolean(),
    require_scope_match: z.boolean(),
  }),
  rate_limit: z.object({
    default_rps: z.number(),
    per_host: z.boolean(),
    burst: z.number(),
  }),
  blocked_always: z.array(z.string()),
  approval_required: z.array(z.string()),
  evidence: z.object({
    mask_secrets: z.boolean(),
    redact_tokens: z.boolean(),
    store_local_only: z.boolean(),
  }),
  external_tools: z.object({
    require_absolute_path: z.boolean(),
    require_approval: z.boolean(),
    no_shell: z.boolean(),
    timeout_seconds: z.number(),
    bounded_output: z.boolean(),
    checksum_or_approval_required: z.boolean(),
  }),
});

const WorkflowStepSchema = z.object({
  id: z.string().min(1),
  purpose: z.string().min(1),
  allowed_modes: z.array(SkillModeSchema).min(1),
  inputs: z.array(z.string()),
  outputs: z.array(z.string()),
  risk_level: RiskLevelSchema,
  requires_scope: z.boolean(),
  requires_approval: z.boolean(),
  blocked_capabilities: z.array(z.string()),
  cli_commands: z.array(z.string()).min(1),
  failure_behavior: z.string().min(1),
  artifacts: z.array(z.string()),
});

const SkillWorkflowSchema = z.object({
  steps: z.array(WorkflowStepSchema).min(1),
});

const ToolRegistryItemSchema = z.object({
  name: z.string().min(1),
  category: z.string().min(1),
  policy: z.string().min(1),
  produces: z.array(z.string()),
  approval_required: z.boolean(),
});

const SkillToolRegistrySchema = z.object({
  tools: z.array(ToolRegistryItemSchema).min(1),
});

const PlaybookSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string().min(1),
  modes: z.array(SkillModeSchema).min(1),
  required_observations: z.array(z.string()),
  tools: z.array(z.string()),
  steps: z.array(z.string()),
  evidence_required: z.array(z.string()),
  finding_threshold: z.string().min(1),
  requires_approval: z.boolean(),
  lab_only: z.boolean(),
  blocked_if: z.array(z.string()),
  report_template: z.string().min(1),
});

const SkillPlaybookRegistrySchema = z.object({
  playbooks: z.array(PlaybookSchema).min(1),
});

const SkillVmProfileSchema = z.object({
  base_os: z.string(),
  package_manager: z.string(),
  node: z.string(),
  go: z.string(),
  python: z.string(),
  browser_runtime: z.string(),
  install_policy: z.string(),
  default_bootstrap_level: z.string(),
  safe_level_tools: z.array(z.string()),
  full_level_tools: z.array(z.string()),
  notes: z.array(z.string()),
});

export type SkillPolicy = z.infer<typeof SkillPolicySchema>;
export type SkillWorkflow = z.infer<typeof SkillWorkflowSchema>;
export type SkillToolRegistry = z.infer<typeof SkillToolRegistrySchema>;
export type SkillPlaybookRegistry = z.infer<typeof SkillPlaybookRegistrySchema>;
export type SkillVmProfile = z.infer<typeof SkillVmProfileSchema>;

const REQUIRED_SKILL_FILES = [
  "SKILL.md",
  "README.md",
  "policy.yml",
  "workflow.yml",
  "tool-registry.yml",
  "playbooks.yml",
  "vm-profile.yml",
];

const REQUIRED_PROMPTS = [
  "planner.md",
  "recon.md",
  "hunt.md",
  "triage.md",
  "evidence-review.md",
  "report-writer.md",
  "report-score.md",
  "safety-refusal.md",
];

const REQUIRED_TEMPLATES = [
  "program.yml",
  "local-lab-program.yml",
  "finding.json",
  "recon-observation.json",
  "evidence-manifest.json",
  "report.md",
  "report-score.json",
  "action-review.md",
  "handoff-summary.md",
];

const REQUIRED_EXAMPLES = [
  "safe-runbook.md",
  "vm-bootstrap.md",
  "local-lab-workflow.md",
  "public-program-workflow.md",
  "report-example.md",
];

const REQUIRED_MODES: SkillRunMode[] = ["passive", "safe", "deep-safe", "lab-offensive"];
const REQUIRED_WORKFLOW_STEPS = [
  "authorization_check",
  "program_import",
  "scope_validation",
  "passive_recon",
  "web_recon",
  "playbook_execution",
  "finding_candidate_generation",
  "evidence_collection",
  "reportability_score",
  "report_draft",
  "handoff_bundle",
];
const REQUIRED_TOOLS = [
  "subfinder",
  "dnsx",
  "httpx",
  "katana",
  "gau",
  "waybackurls",
  "nuclei",
  "ffuf",
  "dalfox",
  "naabu",
  "nmap",
  "jq",
  "curl",
  "playwright",
  "crawl4ai",
  "playwright-mcp",
  "d-research-skill",
];
const REQUIRED_PLAYBOOKS = [
  "headers",
  "cors",
  "cookies",
  "source-map",
  "js-secrets",
  "exposed-files",
  "xss-candidate",
  "open-redirect-candidate",
  "graphql-introspection",
  "nuclei-low",
];
const REQUIRED_BLOCKED_ALWAYS = [
  "brute_force",
  "credential_stuffing",
  "password_spraying",
  "destructive_payload",
  "malware",
  "waf_evasion",
  "data_exfiltration",
  "auth_bypass_without_permission",
  "mass_internet_scan",
  "auto_submit_report",
  "dump_sensitive_data",
];
const REQUIRED_APPROVAL = ["ffuf", "dalfox", "naabu", "nmap", "external_tool_execution", "mcp_live_execution"];

export function listSkillDefinitions(cwd = process.cwd()): SkillListEntry[] {
  const entries = new Map<string, SkillListEntry>();
  for (const parent of candidateSkillParents(cwd)) {
    if (!existsSync(parent)) continue;
    for (const entry of readdirSync(parent, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const root = path.join(parent, entry.name);
      if (!existsSync(path.join(root, "SKILL.md"))) continue;
      entries.set(entry.name, {
        id: entry.name,
        root,
        title: readSkillTitle(root) ?? entry.name,
        bundled: isBundledSkillRoot(root),
      });
    }
  }
  return [...entries.values()].sort((left, right) => left.id.localeCompare(right.id));
}

export function loadSkillDefinition(id = BUG_BOUNTY_PILOT_SKILL_ID, cwd = process.cwd()): SkillDefinition {
  const validation = validateSkillDefinition(id, cwd);
  if (!validation.ok) {
    const details = validation.checks.filter((check) => check.status === "fail").map((check) => `${check.name}: ${check.message}`).join("; ");
    throw new BountyPilotError(`Skill ${id} is invalid. ${details}`, "SKILL_INVALID");
  }
  const root = validation.root;
  return {
    id,
    root,
    skillMarkdown: readSkillFile(root, "SKILL.md"),
    policy: validation.policy!,
    workflow: validation.workflow!,
    toolRegistry: validation.toolRegistry!,
    playbooks: validation.playbooks!,
    vmProfile: validation.vmProfile!,
    prompts: readDirectoryFiles(path.join(root, "prompts"), REQUIRED_PROMPTS),
    templates: readDirectoryFiles(path.join(root, "templates"), REQUIRED_TEMPLATES),
    examples: readDirectoryFiles(path.join(root, "examples"), REQUIRED_EXAMPLES),
  };
}

export function validateSkillDefinition(id = BUG_BOUNTY_PILOT_SKILL_ID, cwd = process.cwd()): SkillValidationResult {
  const root = resolveSkillRoot(id, cwd);
  const checks: SkillValidationCheck[] = [];

  for (const file of REQUIRED_SKILL_FILES) {
    checks.push(fileCheck(file, path.join(root, file)));
  }
  for (const file of REQUIRED_PROMPTS) {
    checks.push(fileCheck(`prompts/${file}`, path.join(root, "prompts", file)));
  }
  for (const file of REQUIRED_TEMPLATES) {
    checks.push(fileCheck(`templates/${file}`, path.join(root, "templates", file)));
  }
  for (const file of REQUIRED_EXAMPLES) {
    checks.push(fileCheck(`examples/${file}`, path.join(root, "examples", file)));
  }

  const policy = parseYamlSchema(path.join(root, "policy.yml"), SkillPolicySchema, "policy.yml", checks);
  const workflow = parseYamlSchema(path.join(root, "workflow.yml"), SkillWorkflowSchema, "workflow.yml", checks);
  const toolRegistry = parseYamlSchema(path.join(root, "tool-registry.yml"), SkillToolRegistrySchema, "tool-registry.yml", checks);
  const playbooks = parseYamlSchema(path.join(root, "playbooks.yml"), SkillPlaybookRegistrySchema, "playbooks.yml", checks);
  const vmProfile = parseYamlSchema(path.join(root, "vm-profile.yml"), SkillVmProfileSchema, "vm-profile.yml", checks);

  if (policy) {
    pushSetCheck(checks, "policy:modes", REQUIRED_MODES, Object.keys(policy.modes));
    pushSetCheck(checks, "policy:blocked_always", REQUIRED_BLOCKED_ALWAYS, policy.blocked_always);
    pushSetCheck(checks, "policy:approval_required", REQUIRED_APPROVAL, policy.approval_required);
    checks.push({
      name: "policy:external_tools",
      status:
        policy.external_tools.require_absolute_path &&
        policy.external_tools.require_approval &&
        policy.external_tools.no_shell &&
        policy.external_tools.bounded_output
          ? "pass"
          : "fail",
      message: "external tools must require absolute paths, approval, no shell, and bounded output",
    });
  }

  if (workflow) {
    pushSetCheck(checks, "workflow:steps", REQUIRED_WORKFLOW_STEPS, workflow.steps.map((step) => step.id));
    const missingArtifacts = workflow.steps.filter((step) => step.artifacts.length === 0).map((step) => step.id);
    checks.push({
      name: "workflow:artifacts",
      status: missingArtifacts.length === 0 ? "pass" : "fail",
      message: missingArtifacts.length === 0 ? "all steps declare artifacts" : `Missing artifacts: ${missingArtifacts.join(", ")}`,
    });
    const missingCommands = workflow.steps.filter((step) => step.cli_commands.length === 0).map((step) => step.id);
    checks.push({
      name: "workflow:cli_commands",
      status: missingCommands.length === 0 ? "pass" : "fail",
      message: missingCommands.length === 0 ? "all steps declare CLI commands" : `Missing CLI commands: ${missingCommands.join(", ")}`,
    });
  }

  if (toolRegistry) {
    pushSetCheck(checks, "tool-registry:tools", REQUIRED_TOOLS, toolRegistry.tools.map((tool) => tool.name));
    const reviewToolsWithoutApproval = toolRegistry.tools
      .filter((tool) => tool.policy === "review-required" && !tool.approval_required)
      .map((tool) => tool.name);
    checks.push({
      name: "tool-registry:review-required",
      status: reviewToolsWithoutApproval.length === 0 ? "pass" : "fail",
      message:
        reviewToolsWithoutApproval.length === 0
          ? "review-required tools require approval"
          : `Missing approval flag: ${reviewToolsWithoutApproval.join(", ")}`,
    });
  }

  if (playbooks) {
    pushSetCheck(checks, "playbooks:required", REQUIRED_PLAYBOOKS, playbooks.playbooks.map((playbook) => playbook.id));
    const approvalIssues = playbooks.playbooks
      .filter((playbook) => playbook.tools.some((tool) => ["nuclei", "ffuf", "dalfox", "naabu"].includes(tool)) && !playbook.requires_approval)
      .map((playbook) => playbook.id);
    checks.push({
      name: "playbooks:review-required-tools",
      status: approvalIssues.length === 0 ? "pass" : "fail",
      message: approvalIssues.length === 0 ? "scanner/fuzzer playbooks require approval" : `Missing approval: ${approvalIssues.join(", ")}`,
    });
  }

  return {
    ok: checks.every((check) => check.status !== "fail"),
    id,
    root,
    checks,
    files: {
      required: REQUIRED_SKILL_FILES,
      prompts: REQUIRED_PROMPTS.map((file) => `prompts/${file}`),
      templates: REQUIRED_TEMPLATES.map((file) => `templates/${file}`),
      examples: REQUIRED_EXAMPLES.map((file) => `examples/${file}`),
    },
    policy,
    workflow,
    toolRegistry,
    playbooks,
    vmProfile,
  };
}

export function exportSkillDefinition(input: { id?: string; output: string; cwd?: string }): { id: string; source: string; output: string; files: number } {
  const id = input.id ?? BUG_BOUNTY_PILOT_SKILL_ID;
  const source = resolveSkillRoot(id, input.cwd ?? process.cwd());
  const output = path.resolve(input.cwd ?? process.cwd(), input.output);
  cpSync(source, output, { recursive: true, force: true });
  return {
    id,
    source,
    output,
    files: countFiles(output),
  };
}

export function bundleSkillDefinition(input: { id?: string; output?: string; cwd?: string; generatedAt?: string }): SkillBundleResult {
  const cwd = input.cwd ?? process.cwd();
  const id = input.id ?? BUG_BOUNTY_PILOT_SKILL_ID;
  const validation = validateSkillDefinition(id, cwd);
  if (!validation.ok) {
    const details = validation.checks.filter((check) => check.status === "fail").map((check) => `${check.name}: ${check.message}`).join("; ");
    throw new BountyPilotError(`Skill ${id} is invalid and cannot be bundled. ${details}`, "SKILL_INVALID");
  }
  const source = validation.root;
  const output = path.resolve(cwd, input.output ?? path.join(".bounty", "skills", "bundles", `${id}.skill.zip`));
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const files = collectSkillBundleFiles(source);
  const manifest: SkillBundleManifest = {
    schemaVersion: "bountypilot.skill.bundle.v1",
    id,
    title: readSkillTitle(source) ?? id,
    generatedAt,
    contentsPrefix: id,
    validation: {
      checks: validation.checks.length,
      failures: validation.checks.filter((check) => check.status === "fail").length,
      warnings: validation.checks.filter((check) => check.status === "warn").length,
    },
    modes: Object.keys(validation.policy?.modes ?? {}),
    workflowSteps: validation.workflow?.steps.map((step) => step.id) ?? [],
    tools: validation.toolRegistry?.tools.map((tool) => tool.name) ?? [],
    playbooks: validation.playbooks?.playbooks.map((playbook) => playbook.id) ?? [],
    files: files.map(({ data: _data, ...file }) => file),
    totalBytes: files.reduce((sum, file) => sum + file.size, 0),
  };
  const manifestData = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const zipEntries = [
    { name: `${id}/MANIFEST.bountypilot.json`, data: manifestData },
    ...files.map((file) => ({ name: `${id}/${file.path}`, data: file.data })),
  ];
  mkdirSync(path.dirname(output), { recursive: true });
  const archive = writeZipStoreArchive(zipEntries, generatedAt);
  writeFileSync(output, archive);
  return {
    ok: true,
    id,
    source,
    output,
    format: "zip",
    files: files.length,
    bytes: archive.length,
    sha256: sha256Hex(archive),
    manifest,
  };
}

export function resolveSkillRoot(id = BUG_BOUNTY_PILOT_SKILL_ID, cwd = process.cwd()): string {
  const candidates = candidateSkillParents(cwd).map((parent) => path.join(parent, id));
  for (const candidate of candidates) {
    if (existsSync(path.join(candidate, "SKILL.md"))) {
      return candidate;
    }
  }
  throw new BountyPilotError(`Skill not found: ${id}`, "SKILL_NOT_FOUND");
}

function candidateSkillParents(cwd: string): string[] {
  return [
    process.env.BOUNTYPILOT_SKILLS_DIR,
    path.join(cwd, ".bounty", "skills"),
    path.join(cwd, "skills"),
    path.join(packageRoot(), "skills"),
  ].filter((item): item is string => Boolean(item));
}

function packageRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
}

function isBundledSkillRoot(root: string): boolean {
  return path.relative(path.join(packageRoot(), "skills"), root).split(path.sep)[0] !== "..";
}

function readSkillTitle(root: string): string | undefined {
  const text = readText(path.join(root, "SKILL.md"));
  const heading = /^#\s+(.+)$/m.exec(text ?? "");
  return heading?.[1]?.trim();
}

function readSkillFile(root: string, relativePath: string): string {
  return readFileSync(path.join(root, relativePath), "utf8");
}

function readDirectoryFiles(root: string, fileNames: string[]): Record<string, string> {
  return Object.fromEntries(fileNames.map((fileName) => [fileName, readFileSync(path.join(root, fileName), "utf8")]));
}

function fileCheck(name: string, filePath: string): SkillValidationCheck {
  if (!existsSync(filePath)) {
    return { name, status: "fail", message: `Missing ${filePath}` };
  }
  const stats = statSync(filePath);
  if (!stats.isFile()) {
    return { name, status: "fail", message: `Not a file: ${filePath}` };
  }
  return { name, status: "pass", message: filePath };
}

function parseYamlSchema<T extends z.ZodType>(
  filePath: string,
  schema: T,
  label: string,
  checks: SkillValidationCheck[],
): z.infer<T> | undefined {
  if (!existsSync(filePath)) {
    return undefined;
  }
  try {
    const parsed = YAML.parse(readFileSync(filePath, "utf8")) as unknown;
    const result = schema.safeParse(parsed);
    if (!result.success) {
      checks.push({
        name: `${label}:schema`,
        status: "fail",
        message: result.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; "),
      });
      return undefined;
    }
    checks.push({ name: `${label}:schema`, status: "pass", message: "valid" });
    return result.data;
  } catch (error) {
    checks.push({
      name: `${label}:syntax`,
      status: "fail",
      message: error instanceof Error ? error.message : String(error),
    });
    return undefined;
  }
}

function pushSetCheck(checks: SkillValidationCheck[], name: string, required: string[], actual: string[]): void {
  const actualSet = new Set(actual);
  const missing = required.filter((item) => !actualSet.has(item));
  checks.push({
    name,
    status: missing.length === 0 ? "pass" : "fail",
    message: missing.length === 0 ? `${required.length}/${required.length} required entries present` : `Missing: ${missing.join(", ")}`,
  });
}

function countFiles(root: string): number {
  let count = 0;
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      count += countFiles(fullPath);
    } else if (entry.isFile()) {
      count += 1;
    }
  }
  return count;
}

interface SkillBundleFileWithData extends SkillBundleFile {
  data: Buffer;
}

interface ZipEntry {
  name: string;
  data: Buffer;
}

function collectSkillBundleFiles(root: string, current = root): SkillBundleFileWithData[] {
  const files: SkillBundleFileWithData[] = [];
  for (const entry of readdirSync(current, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
    const fullPath = path.join(current, entry.name);
    const stats = lstatSync(fullPath);
    if (stats.isSymbolicLink()) {
      throw new BountyPilotError(`Skill bundle refuses symbolic links: ${fullPath}`, "SKILL_BUNDLE_INVALID");
    }
    if (stats.isDirectory()) {
      files.push(...collectSkillBundleFiles(root, fullPath));
      continue;
    }
    if (!stats.isFile()) continue;
    const data = readFileSync(fullPath);
    const relativePath = path.relative(root, fullPath).split(path.sep).join("/");
    files.push({
      path: relativePath,
      size: data.byteLength,
      sha256: sha256Hex(data),
      data,
    });
  }
  return files;
}

function writeZipStoreArchive(entries: ZipEntry[], generatedAt: string): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  const timestamp = dosTimestamp(new Date(generatedAt));

  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const size = entry.data.byteLength;
    if (size > 0xffffffff || offset > 0xffffffff) {
      throw new BountyPilotError("Skill bundle is too large for the built-in ZIP writer.", "SKILL_BUNDLE_TOO_LARGE");
    }
    const crc = crc32(entry.data);
    const localHeader = Buffer.alloc(30 + name.byteLength);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(timestamp.time, 10);
    localHeader.writeUInt16LE(timestamp.date, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(size, 18);
    localHeader.writeUInt32LE(size, 22);
    localHeader.writeUInt16LE(name.byteLength, 26);
    localHeader.writeUInt16LE(0, 28);
    name.copy(localHeader, 30);
    localParts.push(localHeader, entry.data);

    const centralHeader = Buffer.alloc(46 + name.byteLength);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(timestamp.time, 12);
    centralHeader.writeUInt16LE(timestamp.date, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(size, 20);
    centralHeader.writeUInt32LE(size, 24);
    centralHeader.writeUInt16LE(name.byteLength, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    name.copy(centralHeader, 46);
    centralParts.push(centralHeader);

    offset += localHeader.byteLength + entry.data.byteLength;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const centralOffset = offset;
  const centralSize = centralDirectory.byteLength;
  if (entries.length > 0xffff || centralOffset > 0xffffffff || centralSize > 0xffffffff) {
    throw new BountyPilotError("Skill bundle is too large for the built-in ZIP writer.", "SKILL_BUNDLE_TOO_LARGE");
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(centralOffset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

function dosTimestamp(date: Date): { time: number; date: number } {
  const safeDate = Number.isNaN(date.getTime()) ? new Date("1980-01-01T00:00:00.000Z") : date;
  const year = Math.min(Math.max(safeDate.getUTCFullYear(), 1980), 2107);
  return {
    time: (safeDate.getUTCHours() << 11) | (safeDate.getUTCMinutes() << 5) | Math.floor(safeDate.getUTCSeconds() / 2),
    date: ((year - 1980) << 9) | ((safeDate.getUTCMonth() + 1) << 5) | safeDate.getUTCDate(),
  };
}

let crc32Table: Uint32Array | undefined;

function crc32(data: Buffer): number {
  const table = crc32Table ?? (crc32Table = buildCrc32Table());
  let crc = 0xffffffff;
  for (const byte of data) {
    crc = (crc >>> 8) ^ table[(crc ^ byte) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildCrc32Table(): Uint32Array {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
}

function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function readText(filePath: string): string | undefined {
  try {
    return readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }
}
