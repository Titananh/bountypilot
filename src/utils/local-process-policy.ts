import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { BountyPilotError } from "./errors.js";
import { createId } from "./ids.js";
import { nowIso } from "./time.js";

const requireFromHere = createRequire(import.meta.url);

export interface ApprovedExecutableRecord {
  id: string;
  integration: string;
  command: string;
  realPath: string;
  sha256: string;
  approvedAt: string;
  note?: string;
}

export interface VerifiedExecutable {
  command: string;
  realPath: string;
  sha256: string;
  approval: ApprovedExecutableRecord;
}

export interface LocalProcessConfig {
  command?: string;
  args?: string[];
  package?: string;
  package_version?: string;
  entrypoint?: string;
  entrypoint_sha256?: string;
  package_json_sha256?: string;
}

export interface ResolvedLocalProcess {
  executable: VerifiedExecutable;
  baseArgs: string[];
  npmPackage?: {
    name: string;
    version: string;
    packageRoot: string;
    packageJson: string;
    packageJsonSha256: string;
    entrypoint: string;
    entrypointSha256: string;
  };
}

export type InspectedNpmPackageEntrypoint = NonNullable<ResolvedLocalProcess["npmPackage"]>;

interface ApprovalFile {
  version: 1;
  records: ApprovedExecutableRecord[];
}

export class LocalExecutableApprovalStore {
  constructor(private readonly filePath: string) {}

  list(integration?: string): ApprovedExecutableRecord[] {
    const records = this.read().records;
    const normalizedIntegration = integration ? normalizeIntegration(integration) : undefined;
    return records
      .filter((record) => !normalizedIntegration || record.integration === normalizedIntegration)
      .sort((left, right) => right.approvedAt.localeCompare(left.approvedAt));
  }

  approve(input: { integration: string; command: string; note?: string }): ApprovedExecutableRecord {
    const integration = normalizeIntegration(input.integration);
    const executable = resolveLocalExecutable(input.command);
    const file = this.read();
    const existing = file.records.find(
      (record) => record.integration === integration && record.realPath === executable.realPath && record.sha256 === executable.sha256,
    );
    if (existing) {
      const updated = input.note ? { ...existing, note: input.note } : existing;
      if (updated !== existing) {
        file.records = file.records.map((record) => (record.id === existing.id ? updated : record));
        this.write(file);
      }
      return updated;
    }

    const record: ApprovedExecutableRecord = {
      id: createId("approval"),
      integration,
      command: executable.command,
      realPath: executable.realPath,
      sha256: executable.sha256,
      approvedAt: nowIso(),
      note: input.note?.trim() || undefined,
    };
    file.records = [
      ...file.records.filter((current) => !(current.integration === integration && current.realPath === executable.realPath)),
      record,
    ];
    this.write(file);
    return record;
  }

  verify(input: { integration: string; command: string }): VerifiedExecutable {
    const integration = normalizeIntegration(input.integration);
    const executable = resolveLocalExecutable(input.command);
    const records = this.read().records.filter((record) => record.integration === integration);
    const samePath = records.find((record) => record.realPath === executable.realPath);
    if (!samePath) {
      throw new BountyPilotError(
        `Executable ${executable.realPath} is not approved for integration ${integration}. Run integrations approve-executable first.`,
        "EXECUTABLE_APPROVAL_MISSING",
      );
    }
    if (samePath.sha256 !== executable.sha256) {
      throw new BountyPilotError(
        `Executable hash changed for ${executable.realPath}. Re-approve the executable before running it.`,
        "EXECUTABLE_APPROVAL_HASH_MISMATCH",
      );
    }
    return { ...executable, approval: samePath };
  }

  private read(): ApprovalFile {
    if (!existsSync(this.filePath)) {
      return { version: 1, records: [] };
    }
    try {
      const parsed = JSON.parse(readFileSync(this.filePath, "utf8")) as unknown;
      if (!isApprovalFile(parsed)) {
        throw new BountyPilotError("Executable approval store is malformed", "EXECUTABLE_APPROVAL_STORE_INVALID");
      }
      return parsed;
    } catch (error) {
      if (error instanceof BountyPilotError) throw error;
      throw new BountyPilotError("Executable approval store is not valid JSON", "EXECUTABLE_APPROVAL_STORE_INVALID_JSON");
    }
  }

  private write(file: ApprovalFile): void {
    mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tempPath = `${this.filePath}.tmp-${process.pid}-${Date.now()}`;
    writeFileSync(tempPath, `${JSON.stringify(file, null, 2)}\n`, "utf8");
    renameSync(tempPath, this.filePath);
  }
}

export function approvedExecutableStorePath(integrationsDir: string): string {
  return path.join(integrationsDir, "approved-executables.json");
}

export function createExecutableApprovalStore(integrationsDir: string): LocalExecutableApprovalStore {
  return new LocalExecutableApprovalStore(approvedExecutableStorePath(integrationsDir));
}

export function resolveLocalExecutable(command: string): Omit<VerifiedExecutable, "approval"> {
  const trimmed = command.trim();
  if (!trimmed) {
    throw new BountyPilotError("Executable command is empty", "EXECUTABLE_COMMAND_INVALID");
  }
  if (/[\0\r\n;&|`$<>]/.test(trimmed)) {
    throw new BountyPilotError("Executable command contains shell control characters", "EXECUTABLE_COMMAND_INVALID");
  }
  if (!path.isAbsolute(trimmed)) {
    throw new BountyPilotError("Executable command must be an absolute path", "EXECUTABLE_COMMAND_NOT_ABSOLUTE");
  }
  assertExecutableExtensionAllowed(trimmed);
  assertShellInterpreterBlocked(trimmed);

  let stats;
  try {
    stats = statSync(trimmed);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new BountyPilotError(`Executable not found: ${trimmed}`, "EXECUTABLE_NOT_FOUND");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Could not inspect executable: ${reason}`, "EXECUTABLE_INSPECT_FAILED");
  }
  if (!stats.isFile()) {
    throw new BountyPilotError(`Executable is not a file: ${trimmed}`, "EXECUTABLE_NOT_FILE");
  }

  const realPath = realpathSync.native(trimmed);
  return {
    command: path.resolve(trimmed),
    realPath,
    sha256: sha256File(realPath),
  };
}

export function resolveApprovedLocalProcess(input: {
  integration: string;
  config: LocalProcessConfig;
  integrationsDir: string;
  cwd?: string;
}): ResolvedLocalProcess {
  const hasPackageConfig =
    input.config.package !== undefined || input.config.package_version !== undefined || input.config.entrypoint !== undefined;
  const command = input.config.command?.trim();
  if (command && hasPackageConfig) {
    throw new BountyPilotError(
      "Configure either an absolute executable command or a pinned package entrypoint, not both.",
      "LOCAL_PROCESS_CONFIG_AMBIGUOUS",
    );
  }

  const approvalStore = createExecutableApprovalStore(input.integrationsDir);
  if (hasPackageConfig) {
    const packageVersion = validatePinnedPackageVersion(input.config.package_version);
    const npmPackage = inspectLocalPackageEntrypoint({ ...input.config, package_version: packageVersion }, input.cwd);
    return {
      executable: approvalStore.verify({ integration: input.integration, command: process.execPath }),
      baseArgs: [npmPackage.entrypoint],
      npmPackage,
    };
  }

  if (!command) {
    throw new BountyPilotError("Integration has no command or package entrypoint configured", "LOCAL_PROCESS_COMMAND_MISSING");
  }
  return {
    executable: approvalStore.verify({ integration: input.integration, command }),
    baseArgs: [],
  };
}

export function assertLocalProcessArgument(argument: string, code = "PROCESS_ARGUMENT_INVALID"): void {
  if (/[\0\r\n]/.test(argument)) {
    throw new BountyPilotError("Process argument contains control characters", code);
  }
}

export function localProcessEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { NO_COLOR: "1" };
  for (const key of ["SystemRoot", "WINDIR", "TEMP", "TMP"]) {
    if (process.env[key]) {
      env[key] = process.env[key];
    }
  }
  return env;
}

function sha256File(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

export function inspectLocalPackageEntrypoint(config: LocalProcessConfig, cwd = process.cwd()): InspectedNpmPackageEntrypoint {
  const packageName = validateNpmPackageName(config.package);
  const entrypoint = validatePackageEntrypoint(config.entrypoint);
  const packageJsonPath = resolvePackageJson(packageName, cwd);
  const packageJsonSha256 = sha256File(packageJsonPath);
  assertExpectedSha256("package metadata", packageJsonSha256, config.package_json_sha256, "PACKAGE_ENTRYPOINT_METADATA_HASH_MISMATCH");
  const packageJson = readPackageJson(packageJsonPath);
  const packageVersion = config.package_version ? validatePinnedPackageVersion(config.package_version) : validatePinnedPackageVersion(packageJson.version);
  if (packageJson.version !== packageVersion) {
    throw new BountyPilotError(
      `Installed package ${packageName} is ${packageJson.version ?? "unknown"}, expected pinned version ${packageVersion}.`,
      "PACKAGE_ENTRYPOINT_VERSION_MISMATCH",
    );
  }

  const packageRoot = realpathSync.native(path.dirname(packageJsonPath));
  const realPackageJson = realpathSync.native(packageJsonPath);
  const entrypointPath = path.resolve(packageRoot, ...entrypoint.split("/"));
  let stats;
  try {
    stats = statSync(entrypointPath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new BountyPilotError(`Package entrypoint not found: ${entrypointPath}`, "PACKAGE_ENTRYPOINT_NOT_FOUND");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Could not inspect package entrypoint: ${reason}`, "PACKAGE_ENTRYPOINT_INSPECT_FAILED");
  }
  if (!stats.isFile()) {
    throw new BountyPilotError(`Package entrypoint is not a file: ${entrypointPath}`, "PACKAGE_ENTRYPOINT_NOT_FILE");
  }
  const realEntrypoint = realpathSync.native(entrypointPath);
  if (!isPathInside(packageRoot, realEntrypoint)) {
    throw new BountyPilotError("Package entrypoint must stay inside the installed package root", "PACKAGE_ENTRYPOINT_OUTSIDE_ROOT");
  }
  const entrypointSha256 = sha256File(realEntrypoint);
  assertExpectedSha256("package entrypoint", entrypointSha256, config.entrypoint_sha256, "PACKAGE_ENTRYPOINT_HASH_MISMATCH");

  return {
    name: packageName,
    version: packageVersion,
    packageRoot,
    packageJson: realPackageJson,
    packageJsonSha256,
    entrypoint: realEntrypoint,
    entrypointSha256,
  };
}

function resolvePackageJson(packageName: string, cwd: string): string {
  try {
    return requireFromHere.resolve(`${packageName}/package.json`, { paths: [cwd, process.cwd()] });
  } catch {
    throw new BountyPilotError(
      `Pinned package ${packageName} is not installed locally. Install it first; BountyPilot will not run npx or fetch packages at execution time.`,
      "PACKAGE_ENTRYPOINT_PACKAGE_NOT_FOUND",
    );
  }
}

function readPackageJson(packageJsonPath: string): { version?: string } {
  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as unknown;
    return parsed && typeof parsed === "object" ? (parsed as { version?: string }) : {};
  } catch {
    throw new BountyPilotError(`Package metadata is not valid JSON: ${packageJsonPath}`, "PACKAGE_ENTRYPOINT_METADATA_INVALID");
  }
}

function validateNpmPackageName(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    throw new BountyPilotError("Package entrypoint config requires package", "PACKAGE_ENTRYPOINT_CONFIG_INVALID");
  }
  if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(trimmed)) {
    throw new BountyPilotError("Package entrypoint package must be a package name, not a shell fragment", "PACKAGE_ENTRYPOINT_CONFIG_INVALID");
  }
  return trimmed;
}

function validatePinnedPackageVersion(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    throw new BountyPilotError("Package entrypoint config requires package_version", "PACKAGE_ENTRYPOINT_CONFIG_INVALID");
  }
  if (trimmed === "latest" || /[<>=^~*]/.test(trimmed)) {
    throw new BountyPilotError("Package entrypoint package_version must be an exact pinned version", "PACKAGE_ENTRYPOINT_CONFIG_INVALID");
  }
  return trimmed;
}

function assertExpectedSha256(label: string, actual: string, expected: string | undefined, code: string): void {
  const normalizedExpected = validateOptionalSha256(expected, code);
  if (normalizedExpected && normalizedExpected !== actual) {
    throw new BountyPilotError(
      `Pinned ${label} hash changed. Expected ${normalizedExpected}, got ${actual}.`,
      code,
    );
  }
}

function validateOptionalSha256(value: string | undefined, code: string): string | undefined {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed) {
    return undefined;
  }
  if (!/^[a-f0-9]{64}$/.test(trimmed)) {
    throw new BountyPilotError("Pinned package hash must be a SHA-256 hex digest", code);
  }
  return trimmed;
}

function validatePackageEntrypoint(value: string | undefined): string {
  const trimmed = value?.trim().replace(/\\/g, "/");
  if (!trimmed) {
    throw new BountyPilotError("Package entrypoint config requires entrypoint", "PACKAGE_ENTRYPOINT_CONFIG_INVALID");
  }
  if (/[\0\r\n;&|`$<>]/.test(trimmed) || path.isAbsolute(trimmed) || trimmed === ".." || trimmed.startsWith("../") || trimmed.includes("/../")) {
    throw new BountyPilotError("Package entrypoint must be a relative path inside the package", "PACKAGE_ENTRYPOINT_CONFIG_INVALID");
  }
  if (trimmed.endsWith("/")) {
    throw new BountyPilotError("Package entrypoint must point to a file", "PACKAGE_ENTRYPOINT_CONFIG_INVALID");
  }
  return trimmed.replace(/^\.\//, "");
}

function isPathInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function normalizeIntegration(value: string): string {
  return value.trim().toLowerCase().replaceAll("-", "_");
}

function assertExecutableExtensionAllowed(command: string): void {
  const extension = path.extname(command).toLowerCase();
  if (extension === ".cmd" || extension === ".bat" || extension === ".ps1") {
    throw new BountyPilotError("Shell shim executables are not allowed; approve the real binary path instead.", "EXECUTABLE_SHIM_UNSUPPORTED");
  }
}

function assertShellInterpreterBlocked(command: string): void {
  const basename = path.basename(command).toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/i, "");
  if (["cmd", "powershell", "pwsh", "bash", "sh", "zsh", "fish"].includes(basename)) {
    throw new BountyPilotError("Shell interpreters are not allowed as integration executables", "EXECUTABLE_SHELL_BLOCKED");
  }
}

function isApprovalFile(value: unknown): value is ApprovalFile {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ApprovalFile>;
  return (
    candidate.version === 1 &&
    Array.isArray(candidate.records) &&
    candidate.records.every((record) => isApprovalRecord(record))
  );
}

function isApprovalRecord(value: unknown): value is ApprovedExecutableRecord {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<ApprovedExecutableRecord>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.integration === "string" &&
    typeof candidate.command === "string" &&
    typeof candidate.realPath === "string" &&
    typeof candidate.sha256 === "string" &&
    /^[a-f0-9]{64}$/i.test(candidate.sha256) &&
    typeof candidate.approvedAt === "string" &&
    (candidate.note === undefined || typeof candidate.note === "string")
  );
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
