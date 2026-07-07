import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { BUG_BOUNTY_PILOT_SKILL_ID, bundleSkillDefinition, verifySkillBundle } from "../../skills/skill-definition.js";
import { BountyPilotError } from "../../utils/errors.js";
import { runReleaseCheck, type ReleaseCheckResult } from "./release-check.js";

export interface ReleaseBundleArtifact {
  name: string;
  path: string;
  kind: "npm-tarball" | "skill-bundle" | "sbom" | "manifest" | "checksums";
  bytes: number;
  sha256: string;
}

export interface ReleaseBundleManifest {
  schemaVersion: "bountypilot.release.bundle.v1";
  generatedAt: string;
  packageName?: string;
  version?: string;
  releaseCheck: {
    ok: boolean;
    checks: number;
    failures: number;
    warnings: number;
  };
  artifacts: ReleaseBundleArtifact[];
}

export interface ReleaseBundleResult {
  ok: true;
  outputDir: string;
  manifestPath: string;
  checksumsPath: string;
  artifacts: ReleaseBundleArtifact[];
  releaseCheck: ReleaseCheckResult;
  nextCommands: string[];
}

export interface BuildReleaseBundleInput {
  cwd?: string;
  output?: string;
  force?: boolean;
  skipSbom?: boolean;
  generatedAt?: string;
}

export interface ReleaseBundleVerificationCheck {
  name: string;
  status: "pass" | "fail";
  message: string;
}

export interface ReleaseBundleVerificationResult {
  ok: boolean;
  bundleDir: string;
  manifestPath: string;
  checksumsPath: string;
  manifest?: ReleaseBundleManifest;
  checks: ReleaseBundleVerificationCheck[];
  files: {
    expected: number;
    verified: number;
    missing: string[];
    mismatched: string[];
    extra: string[];
  };
}

export function buildReleaseBundle(input: BuildReleaseBundleInput = {}): ReleaseBundleResult {
  const cwd = input.cwd ?? process.cwd();
  const outputDir = path.resolve(cwd, input.output ?? path.join(".bounty", "release"));
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const releaseCheck = runReleaseCheck(cwd);
  if (!releaseCheck.ok) {
    const failures = releaseCheck.checks.filter((check) => check.status === "fail").map((check) => check.name).join(", ");
    throw new BountyPilotError(`Release checks failed; refusing to bundle artifacts. Failing checks: ${failures}`, "RELEASE_CHECK_FAILED");
  }

  prepareOutputDir(outputDir, Boolean(input.force));

  const tarball = packNpmTarball(cwd, outputDir);
  const skillBundle = bundleStandaloneSkill(cwd, outputDir);
  const primaryArtifacts = [artifactFor(tarball, "npm-tarball"), artifactFor(skillBundle, "skill-bundle")];
  if (!input.skipSbom) {
    primaryArtifacts.push(artifactFor(writeSbom(cwd, outputDir), "sbom"));
  }

  const manifestPath = path.join(outputDir, "release-manifest.json");
  const manifestArtifacts = primaryArtifacts.map((artifact) => portableArtifact(artifact, outputDir));
  const manifest: ReleaseBundleManifest = {
    schemaVersion: "bountypilot.release.bundle.v1",
    generatedAt,
    packageName: releaseCheck.packageName,
    version: releaseCheck.version,
    releaseCheck: {
      ok: releaseCheck.ok,
      checks: releaseCheck.checks.length,
      failures: releaseCheck.checks.filter((check) => check.status === "fail").length,
      warnings: releaseCheck.checks.filter((check) => check.status === "warn").length,
    },
    artifacts: manifestArtifacts,
  };
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  const manifestArtifact = artifactFor(manifestPath, "manifest");
  const checksumsPath = path.join(outputDir, "SHA256SUMS.txt");
  writeChecksums(checksumsPath, [...primaryArtifacts, manifestArtifact], outputDir);
  const checksumsArtifact = artifactFor(checksumsPath, "checksums");
  const artifacts = [...primaryArtifacts, manifestArtifact, checksumsArtifact];

  return {
    ok: true,
    outputDir,
    manifestPath,
    checksumsPath,
    artifacts,
    releaseCheck,
    nextCommands: [
      `bounty release check --json`,
      `bounty skill verify-bundle ${path.join(outputDir, `${BUG_BOUNTY_PILOT_SKILL_ID}.skill.zip`)}`,
      `bounty release verify-bundle ${outputDir}`,
      `Get-Content ${checksumsPath}`,
    ],
  };
}

export function verifyReleaseBundle(input: { bundleDir: string; cwd?: string }): ReleaseBundleVerificationResult {
  const cwd = input.cwd ?? process.cwd();
  const bundleDir = path.resolve(cwd, input.bundleDir);
  const manifestPath = path.join(bundleDir, "release-manifest.json");
  const checksumsPath = path.join(bundleDir, "SHA256SUMS.txt");
  const checks: ReleaseBundleVerificationCheck[] = [];

  if (!existsSync(bundleDir)) {
    checks.push({ name: "bundle:directory", status: "fail", message: `Missing release bundle directory: ${bundleDir}` });
    return releaseBundleVerificationResult({ bundleDir, manifestPath, checksumsPath, checks });
  }
  checks.push({ name: "bundle:directory", status: "pass", message: bundleDir });

  const manifest = readReleaseManifest(manifestPath, checks);
  const checksums = readChecksums(checksumsPath, checks);
  if (!manifest) {
    return releaseBundleVerificationResult({ bundleDir, manifestPath, checksumsPath, checks });
  }

  checks.push({
    name: "manifest:release-check",
    status: manifest.releaseCheck.ok && manifest.releaseCheck.failures === 0 ? "pass" : "fail",
    message: `${manifest.releaseCheck.checks} checks, ${manifest.releaseCheck.failures} failure(s), ${manifest.releaseCheck.warnings} warning(s)`,
  });

  const expectedFiles = [
    ...manifest.artifacts.map((artifact) => ({
      artifact,
      relativePath: artifactRelativePath(artifact),
      absolutePath: artifactAbsolutePath(bundleDir, artifact),
    })),
    {
      artifact: artifactFor(manifestPath, "manifest"),
      relativePath: "release-manifest.json",
      absolutePath: manifestPath,
    },
  ];
  const missing: string[] = [];
  const mismatched: string[] = [];
  let verified = 0;

  for (const expected of expectedFiles) {
    if (!isSafeBundleRelativePath(expected.relativePath)) {
      mismatched.push(expected.relativePath);
      checks.push({ name: `file:path:${expected.relativePath}`, status: "fail", message: "artifact path must stay inside the release bundle" });
      continue;
    }
    if (!existsSync(expected.absolutePath)) {
      missing.push(expected.relativePath);
      continue;
    }
    const actual = artifactFor(expected.absolutePath, expected.artifact.kind);
    const checksum = checksums.get(expected.relativePath);
    const hashMatches = actual.bytes === expected.artifact.bytes && actual.sha256 === expected.artifact.sha256;
    const checksumMatches = checksum === actual.sha256;
    if (!hashMatches || !checksumMatches) {
      mismatched.push(expected.relativePath);
      continue;
    }
    verified += 1;
  }

  checks.push({
    name: "files:presence",
    status: missing.length === 0 ? "pass" : "fail",
    message: missing.length === 0 ? `${expectedFiles.length}/${expectedFiles.length} files present` : `Missing: ${missing.join(", ")}`,
  });
  checks.push({
    name: "files:hashes",
    status: mismatched.length === 0 ? "pass" : "fail",
    message: mismatched.length === 0 ? `${verified}/${expectedFiles.length} hashes verified` : `Mismatched: ${mismatched.join(", ")}`,
  });

  const expectedNames = new Set([...expectedFiles.map((file) => file.relativePath), "SHA256SUMS.txt"]);
  const extra = readdirSync(bundleDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => !expectedNames.has(name));
  checks.push({
    name: "files:extra",
    status: extra.length === 0 ? "pass" : "fail",
    message: extra.length === 0 ? "no extra files" : extra.join(", "),
  });

  const skillBundle = manifest.artifacts.find((artifact) => artifact.kind === "skill-bundle");
  if (!skillBundle) {
    checks.push({ name: "skill-bundle:file", status: "fail", message: "skill bundle artifact is missing from release manifest" });
  } else {
    const skillVerification = verifySkillBundle({ bundle: artifactAbsolutePath(bundleDir, skillBundle), cwd });
    checks.push({
      name: "skill-bundle:verify",
      status: skillVerification.ok ? "pass" : "fail",
      message: skillVerification.ok
        ? `${skillVerification.files.verified}/${skillVerification.files.expected} skill files verified`
        : skillVerification.checks.filter((check) => check.status === "fail").map((check) => check.name).join(", "),
    });
  }

  return releaseBundleVerificationResult({
    bundleDir,
    manifestPath,
    checksumsPath,
    manifest,
    checks,
    files: {
      expected: expectedFiles.length,
      verified,
      missing,
      mismatched,
      extra,
    },
  });
}

function prepareOutputDir(outputDir: string, force: boolean): void {
  if (existsSync(outputDir)) {
    const entries = readdirSync(outputDir);
    if (entries.length > 0 && !force) {
      throw new BountyPilotError(`Release bundle output is not empty: ${outputDir}. Use --force to replace it.`, "RELEASE_BUNDLE_OUTPUT_EXISTS");
    }
    if (force) {
      rmSync(outputDir, { recursive: true, force: true });
    }
  }
  mkdirSync(outputDir, { recursive: true });
}

function packNpmTarball(cwd: string, outputDir: string): string {
  const stdout = execNpm(["pack", "--json", "--ignore-scripts", "--pack-destination", outputDir], {
    cwd,
    encoding: "utf8",
    env: npmEnv(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const parsed = JSON.parse(stdout) as Array<{ filename?: string; name?: string }>;
  const filename = parsed[0]?.filename ?? parsed[0]?.name;
  if (!filename) {
    throw new BountyPilotError("npm pack did not return a tarball filename.", "RELEASE_BUNDLE_PACK_FAILED");
  }
  const tarball = path.isAbsolute(filename) ? filename : path.join(outputDir, filename);
  if (!existsSync(tarball)) {
    throw new BountyPilotError(`npm pack reported a missing tarball: ${tarball}`, "RELEASE_BUNDLE_PACK_FAILED");
  }
  return tarball;
}

function bundleStandaloneSkill(cwd: string, outputDir: string): string {
  const output = path.join(outputDir, `${BUG_BOUNTY_PILOT_SKILL_ID}.skill.zip`);
  bundleSkillDefinition({ id: BUG_BOUNTY_PILOT_SKILL_ID, cwd, output });
  const verified = verifySkillBundle({ bundle: output, cwd });
  if (!verified.ok) {
    const failures = verified.checks.filter((check) => check.status === "fail").map((check) => check.name).join(", ");
    throw new BountyPilotError(`Standalone skill bundle verification failed: ${failures}`, "RELEASE_BUNDLE_SKILL_INVALID");
  }
  return output;
}

function writeSbom(cwd: string, outputDir: string): string {
  const output = path.join(outputDir, "bountypilot-sbom.cdx.json");
  const sbom = execNpm(["run", "--silent", "sbom"], {
    cwd,
    encoding: "utf8",
    env: npmEnv(),
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 20 * 1024 * 1024,
  });
  writeFileSync(output, sbom, "utf8");
  return output;
}

function artifactFor(filePath: string, kind: ReleaseBundleArtifact["kind"]): ReleaseBundleArtifact {
  const data = readFileSync(filePath);
  return {
    name: path.basename(filePath),
    path: filePath,
    kind,
    bytes: statSync(filePath).size,
    sha256: createHash("sha256").update(data).digest("hex"),
  };
}

function portableArtifact(artifact: ReleaseBundleArtifact, outputDir: string): ReleaseBundleArtifact {
  return {
    ...artifact,
    path: path.relative(outputDir, artifact.path).split(path.sep).join("/"),
  };
}

function writeChecksums(output: string, artifacts: ReleaseBundleArtifact[], outputDir: string): void {
  const lines = artifacts.map((artifact) => `${artifact.sha256}  ${path.relative(outputDir, artifact.path).split(path.sep).join("/")}`);
  writeFileSync(output, `${lines.join("\n")}\n`, "utf8");
}

function readReleaseManifest(filePath: string, checks: ReleaseBundleVerificationCheck[]): ReleaseBundleManifest | undefined {
  if (!existsSync(filePath)) {
    checks.push({ name: "manifest:file", status: "fail", message: `Missing ${filePath}` });
    return undefined;
  }
  checks.push({ name: "manifest:file", status: "pass", message: filePath });
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8")) as ReleaseBundleManifest;
    if (
      parsed.schemaVersion !== "bountypilot.release.bundle.v1" ||
      !Array.isArray(parsed.artifacts) ||
      !parsed.releaseCheck ||
      typeof parsed.releaseCheck.checks !== "number"
    ) {
      checks.push({ name: "manifest:schema", status: "fail", message: "invalid release bundle manifest schema" });
      return undefined;
    }
    checks.push({ name: "manifest:schema", status: "pass", message: parsed.schemaVersion });
    return parsed;
  } catch (error) {
    checks.push({ name: "manifest:json", status: "fail", message: error instanceof Error ? error.message : String(error) });
    return undefined;
  }
}

function readChecksums(filePath: string, checks: ReleaseBundleVerificationCheck[]): Map<string, string> {
  const output = new Map<string, string>();
  if (!existsSync(filePath)) {
    checks.push({ name: "checksums:file", status: "fail", message: `Missing ${filePath}` });
    return output;
  }
  checks.push({ name: "checksums:file", status: "pass", message: filePath });
  for (const line of readFileSync(filePath, "utf8").split(/\r?\n/)) {
    if (!line.trim()) continue;
    const match = /^([a-f0-9]{64})\s+\*?(.+)$/.exec(line.trim());
    if (match) {
      output.set(match[2]!.replaceAll("\\", "/"), match[1]!);
    }
  }
  checks.push({
    name: "checksums:entries",
    status: output.size > 0 ? "pass" : "fail",
    message: `${output.size} checksum entr${output.size === 1 ? "y" : "ies"}`,
  });
  return output;
}

function releaseBundleVerificationResult(input: {
  bundleDir: string;
  manifestPath: string;
  checksumsPath: string;
  checks: ReleaseBundleVerificationCheck[];
  manifest?: ReleaseBundleManifest;
  files?: ReleaseBundleVerificationResult["files"];
}): ReleaseBundleVerificationResult {
  return {
    ok: input.checks.every((check) => check.status !== "fail"),
    bundleDir: input.bundleDir,
    manifestPath: input.manifestPath,
    checksumsPath: input.checksumsPath,
    manifest: input.manifest,
    checks: input.checks,
    files: input.files ?? {
      expected: 0,
      verified: 0,
      missing: [],
      mismatched: [],
      extra: [],
    },
  };
}

function artifactRelativePath(artifact: ReleaseBundleArtifact): string {
  return path.isAbsolute(artifact.path) ? path.basename(artifact.path) : artifact.path.replaceAll("\\", "/");
}

function artifactAbsolutePath(bundleDir: string, artifact: ReleaseBundleArtifact): string {
  return path.isAbsolute(artifact.path) ? artifact.path : path.join(bundleDir, ...artifact.path.split("/"));
}

function isSafeBundleRelativePath(value: string): boolean {
  return Boolean(value) && !path.isAbsolute(value) && !value.split(/[\\/]+/).includes("..");
}

function execNpm(args: string[], options: Parameters<typeof execFileSync>[2]): string {
  const invocation = npmInvocation(args);
  return execFileSync(invocation.command, invocation.args, options) as string;
}

function npmInvocation(args: string[]): { command: string; args: string[] } {
  if (process.platform !== "win32") {
    return { command: "npm", args };
  }
  const npmCli = npmCliPath();
  if (npmCli) {
    return { command: process.execPath, args: [npmCli, ...args] };
  }
  return { command: "npm.cmd", args };
}

function npmCliPath(): string | undefined {
  const candidates = [
    process.env.npm_execpath,
    process.env.APPDATA ? path.join(process.env.APPDATA, "npm", "node_modules", "npm", "bin", "npm-cli.js") : undefined,
    process.env.ProgramFiles ? path.join(process.env.ProgramFiles, "nodejs", "node_modules", "npm", "bin", "npm-cli.js") : undefined,
    path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
  ].filter((candidate): candidate is string => Boolean(candidate));
  return candidates.find((candidate) => existsSync(candidate));
}

function npmEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    npm_config_update_notifier: "false",
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
  };
}
