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
    artifacts: primaryArtifacts,
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
      `Get-Content ${checksumsPath}`,
    ],
  };
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

function writeChecksums(output: string, artifacts: ReleaseBundleArtifact[], outputDir: string): void {
  const lines = artifacts.map((artifact) => `${artifact.sha256}  ${path.relative(outputDir, artifact.path).split(path.sep).join("/")}`);
  writeFileSync(output, `${lines.join("\n")}\n`, "utf8");
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
