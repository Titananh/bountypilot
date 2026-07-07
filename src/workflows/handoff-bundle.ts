import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { stringify } from "yaml";
import type { Runtime } from "../cli/runtime.js";
import { buildWorkspaceSummary } from "./workspace-summary.js";
import { WorkflowRunner, type WorkflowSummary } from "./run-workflow.js";
import { BountyPilotError } from "../utils/errors.js";
import { maskSecrets, maskSecretsDeep } from "../utils/secrets.js";
import { nowIso } from "../utils/time.js";

export interface HandoffBundleOptions {
  output?: string;
  jobId?: string;
  includeArtifacts?: boolean;
}

export interface HandoffBundleFile {
  label: string;
  path: string;
}

export interface HandoffBundleResult {
  generatedAt: string;
  program: string;
  outputDir: string;
  includeArtifacts: boolean;
  jobId?: string;
  files: HandoffBundleFile[];
  jobs: Array<{
    id: string;
    timelineEvents: number;
    auditEvents: number;
    workflowSummaryIncluded: boolean;
  }>;
  artifactsCopied: number;
}

export function writeHandoffBundle(runtime: Runtime, options: HandoffBundleOptions = {}): HandoffBundleResult {
  const generatedAt = nowIso();
  const outputDir = path.resolve(options.output ?? defaultBundleDir(runtime, generatedAt));
  mkdirSync(outputDir, { recursive: true });

  const files: HandoffBundleFile[] = [];
  const writeJson = (label: string, relativePath: string, value: unknown): string => {
    const filePath = path.join(outputDir, relativePath);
    mkdirSync(path.dirname(filePath), { recursive: true });
    writeFileSync(filePath, `${JSON.stringify(maskSecretsDeep(value), null, 2)}\n`, "utf8");
    files.push({ label, path: filePath });
    return filePath;
  };

  const jobs = options.jobId
    ? runtime.jobs.list(500).filter((job) => job.id === options.jobId)
    : runtime.jobs.list(500);
  if (options.jobId && jobs.length === 0) {
    throw new BountyPilotError(`Job not found: ${options.jobId}`, "JOB_NOT_FOUND");
  }
  const actions = options.jobId ? runtime.actions.list(options.jobId) : runtime.actions.list();
  const reviews = options.jobId ? runtime.reviews.listForJob(options.jobId) : runtime.reviews.list(10_000);
  const evidenceManifest = runtime.evidence.buildManifest({ jobId: options.jobId });
  const findings = findingsForBundle(runtime.findings.list(), evidenceManifest, options.jobId);
  const workspaceSummary = buildWorkspaceSummary(runtime);
  const workflowRunner = new WorkflowRunner(runtime);

  writeText("program config", "program.yml", stringify(maskSecretsDeep(runtime.config)), outputDir, files);
  writeJson("workspace summary", "workspace-summary.json", workspaceSummary);
  writeJson("findings", "findings.json", { generatedAt, count: findings.length, findings });
  writeJson("actions", "actions.json", {
    generatedAt,
    jobId: options.jobId,
    count: actions.length,
    actions,
    reviews,
  });
  writeJson("evidence manifest", "evidence-manifest.json", evidenceManifest);
  writeText("bundle README", "README.md", bundleReadme(runtime, options, generatedAt), outputDir, files);

  const jobResults = jobs.map((job) => {
    const timeline = runtime.events.list(job.id, 1_000);
    const auditEvents = readAuditEvents(runtime.paths.jobsDir, job.id);
    const workflowSummary = workflowRunner.loadSummary(job.id);
    writeJson(`job ${job.id} timeline`, path.join("jobs", job.id, "timeline.json"), {
      generatedAt,
      job,
      events: timeline,
    });
    writeJson(`job ${job.id} audit`, path.join("jobs", job.id, "audit.json"), {
      generatedAt,
      jobId: job.id,
      source: path.join(runtime.paths.jobsDir, job.id, "audit.log"),
      eventCount: auditEvents.length,
      events: auditEvents,
    });
    if (workflowSummary) {
      writeJson(`job ${job.id} workflow summary`, path.join("jobs", job.id, "workflow-summary.json"), workflowSummary);
    }
    return {
      id: job.id,
      timelineEvents: timeline.length,
      auditEvents: auditEvents.length,
      workflowSummaryIncluded: Boolean(workflowSummary),
    };
  });

  const artifactsCopied = options.includeArtifacts ? copyArtifacts(outputDir, runtime.paths.evidenceDir, evidenceManifest.artifacts, files) : 0;

  const result: HandoffBundleResult = {
    generatedAt,
    program: runtime.config.program,
    outputDir,
    includeArtifacts: options.includeArtifacts === true,
    jobId: options.jobId,
    files: [],
    jobs: jobResults,
    artifactsCopied,
  };
  const manifestPath = writeJson("bundle manifest", "manifest.json", { ...result, files });
  result.files = [...files.filter((file) => file.path !== manifestPath), { label: "bundle manifest", path: manifestPath }];
  writeFileSync(manifestPath, `${JSON.stringify(maskSecretsDeep(result), null, 2)}\n`, "utf8");
  return result;
}

function defaultBundleDir(runtime: Runtime, generatedAt: string): string {
  return path.join(runtime.paths.programDir, "exports", `handoff-${generatedAt.replace(/[:.]/g, "-")}`);
}

function writeText(label: string, relativePath: string, content: string, outputDir: string, files: HandoffBundleFile[]): void {
  const filePath = path.join(outputDir, relativePath);
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, content, "utf8");
  files.push({ label, path: filePath });
}

function bundleReadme(runtime: Runtime, options: HandoffBundleOptions, generatedAt: string): string {
  return `# BountyPilot Handoff Bundle

Program: ${runtime.config.program}
Generated: ${generatedAt}
Job filter: ${options.jobId ?? "all jobs"}
Artifacts copied: ${options.includeArtifacts === true ? "yes" : "no"}

This bundle is a local audit and handoff snapshot. Review all evidence before sharing it with a third-party platform.

Recommended review order:
1. workspace-summary.json
2. evidence-manifest.json
3. jobs/<job-id>/timeline.json
4. jobs/<job-id>/audit.json
5. actions.json for approval/block review notes
6. findings.json
`;
}

function copyArtifacts(
  outputDir: string,
  evidenceRoot: string,
  artifacts: Array<{ id: string; path: string; relativePath?: string; readable: boolean }>,
  files: HandoffBundleFile[],
): number {
  let copied = 0;
  const root = path.resolve(evidenceRoot);
  for (const artifact of artifacts) {
    if (!artifact.readable || !existsSync(artifact.path)) {
      continue;
    }
    const relativePath = artifact.relativePath ?? path.basename(artifact.path);
    const safeRelativePath = safeBundleRelativePath(relativePath, artifact.id);
    const targetPath = path.join(outputDir, "artifacts", safeRelativePath);
    const resolvedTarget = path.resolve(targetPath);
    const artifactRoot = path.resolve(outputDir, "artifacts");
    const targetFromRoot = path.relative(artifactRoot, resolvedTarget);
    if (targetFromRoot.startsWith("..") || path.isAbsolute(targetFromRoot)) {
      continue;
    }
    const sourceFromRoot = path.relative(root, path.resolve(artifact.path));
    if (sourceFromRoot.startsWith("..") || path.isAbsolute(sourceFromRoot)) {
      continue;
    }
    mkdirSync(path.dirname(resolvedTarget), { recursive: true });
    copyFileSync(artifact.path, resolvedTarget);
    files.push({ label: `artifact ${artifact.id}`, path: resolvedTarget });
    copied += 1;
  }
  return copied;
}

function safeBundleRelativePath(relativePath: string, artifactId: string): string {
  const normalized = relativePath.replace(/\\/g, "/");
  const parts = normalized.split("/").filter((part) => part && part !== "." && part !== "..");
  return parts.length > 0 ? parts.join("/") : `${artifactId}.artifact`;
}

function findingsForBundle(
  findings: ReturnType<Runtime["findings"]["list"]>,
  evidenceManifest: ReturnType<Runtime["evidence"]["buildManifest"]>,
  jobId?: string,
): ReturnType<Runtime["findings"]["list"]> {
  if (!jobId) {
    return findings;
  }
  const findingIds = new Set(evidenceManifest.artifacts.map((artifact) => artifact.findingId).filter(Boolean));
  const artifactPaths = new Set(evidenceManifest.artifacts.map((artifact) => path.resolve(artifact.path)));
  return findings.filter(
    (finding) =>
      findingIds.has(finding.id) ||
      finding.evidencePaths.some((evidencePath) => artifactPaths.has(path.resolve(evidencePath))),
  );
}

function readAuditEvents(jobsDir: string, jobId: string): Array<Record<string, unknown>> {
  const filePath = path.join(jobsDir, jobId, "audit.log");
  if (!existsSync(filePath)) {
    return [];
  }
  return readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return maskSecretsDeep(JSON.parse(line) as Record<string, unknown>);
      } catch {
        return { malformed: true, raw: maskSecrets(line) };
      }
    });
}
