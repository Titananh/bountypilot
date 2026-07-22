import { createHash } from "node:crypto";
import {
  closeSync,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  statSync,
  type Stats,
} from "node:fs";
import path from "node:path";
import { parse } from "yaml";
import { ZodError } from "zod";
import { ProgramSchema, type ProgramConfig } from "./program-schema.js";
import { findProgramName, programWorkspace } from "../workspace.js";
import { BountyPilotError } from "../../utils/errors.js";

export const MAX_PROGRAM_FILE_BYTES = 1_000_000;
export const MAX_LAB_AUTHORIZATION_FILE_BYTES = 200_000;

export interface LabAuthorization {
  relativePath: string;
  byteLength: number;
  contentSha256: string;
}

export interface LabAuthorizationFileAccess {
  realpath(filePath: string): string;
  readUpTo(filePath: string, maxBytes: number): Buffer;
}

export interface LoadedProgram {
  config: ProgramConfig;
  programFile: string;
  labAuthorization: LabAuthorization | null;
}

export function loadProgramFile(
  filePath: string,
  access: LabAuthorizationFileAccess = secureLabAuthorizationFileAccess,
): LoadedProgram {
  const raw = readProgramFile(filePath);
  let config: ProgramConfig;
  try {
    const parsed = parse(raw);
    config = ProgramSchema.parse(parsed);
  } catch (error) {
    if (error instanceof ZodError) {
      const details = error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
      throw new BountyPilotError(`Invalid program.yml: ${details}`, "PROGRAM_SCHEMA_INVALID");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Invalid program.yml syntax: ${reason}`, "PROGRAM_YAML_INVALID");
  }
  if (config.rules.lab_mode === true && !config.rules.lab_authorization_file) {
    throw new BountyPilotError(
      "rules.lab_mode=true requires rules.lab_authorization_file pointing to a local authorization note.",
      "LAB_AUTHORIZATION_FILE_REQUIRED",
    );
  }
  const labAuthorization = loadLabAuthorization(filePath, config, access);
  return {
    config,
    programFile: filePath,
    labAuthorization,
  };
}

export function loadLabAuthorization(
  programFile: string,
  config: ProgramConfig,
  access: LabAuthorizationFileAccess = secureLabAuthorizationFileAccess,
): LabAuthorization | null {
  const configured = config.rules.lab_authorization_file;
  if (!configured) {
    return null;
  }
  const normalizedRelative = normalizeRelativePath(configured);
  assertSafeRelativePath(normalizedRelative);
  const workspaceEntry = path.dirname(path.resolve(programFile));
  const candidateEntry = path.resolve(workspaceEntry, normalizedRelative);

  const workspaceReal = safeRealpath(access, workspaceEntry, "LAB_AUTHORIZATION_FILE_NOT_FOUND");
  const candidateReal = safeRealpath(access, candidateEntry, "LAB_AUTHORIZATION_FILE_NOT_FOUND");
  assertRealpathContains(workspaceReal, candidateReal);

  const raw = safeReadUpTo(access, candidateReal, MAX_LAB_AUTHORIZATION_FILE_BYTES + 1);
  if (!Buffer.isBuffer(raw)) {
    throw new BountyPilotError(
      "Lab authorization reader returned a non-buffer payload",
      "LAB_AUTHORIZATION_FILE_READ_FAILED",
    );
  }
  if (raw.byteLength > MAX_LAB_AUTHORIZATION_FILE_BYTES) {
    throw new BountyPilotError(
      "Lab authorization file is too large to load",
      "LAB_AUTHORIZATION_FILE_TOO_LARGE",
    );
  }
  const contentSha256 = createHash("sha256").update(raw).digest("hex");
  return {
    relativePath: normalizedRelative,
    byteLength: raw.byteLength,
    contentSha256,
  };
}

export function labAuthorizationFilePath(programFile: string, config: ProgramConfig): string | undefined {
  const relativePath = config.rules.lab_authorization_file;
  return relativePath ? path.resolve(path.dirname(programFile), relativePath) : undefined;
}

export function loadWorkspaceProgram(cwd = process.cwd(), requested?: string): LoadedProgram {
  const programName = findProgramName(cwd, requested);
  const paths = programWorkspace(programName, cwd);
  return loadProgramFile(paths.programFile);
}

export const secureLabAuthorizationFileAccess: LabAuthorizationFileAccess = {
  realpath(filePath: string): string {
    try {
      return realpathSync(filePath);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        throw new BountyPilotError(
          "Lab authorization file could not be located",
          "LAB_AUTHORIZATION_FILE_NOT_FOUND",
        );
      }
      throw new BountyPilotError(
        "Lab authorization file could not be resolved",
        "LAB_AUTHORIZATION_FILE_READ_FAILED",
      );
    }
  },
  readUpTo(filePath: string, maxBytes: number): Buffer {
    let fd: number | undefined;
    try {
      fd = openSync(filePath, "r");
      const stats = fstatSync(fd);
      if (!stats.isFile()) {
        throw new BountyPilotError(
          "Lab authorization path is not a regular file",
          "LAB_AUTHORIZATION_FILE_NOT_FILE",
        );
      }
      if (stats.size > MAX_LAB_AUTHORIZATION_FILE_BYTES) {
        throw new BountyPilotError(
          "Lab authorization file is too large to load",
          "LAB_AUTHORIZATION_FILE_TOO_LARGE",
        );
      }
      const buffer = Buffer.alloc(maxBytes);
      let totalRead = 0;
      while (totalRead < maxBytes) {
        const bytesRead = readSync(fd, buffer, totalRead, maxBytes - totalRead, null);
        if (bytesRead === 0) break;
        totalRead += bytesRead;
      }
      return buffer.subarray(0, totalRead);
    } catch (error) {
      if (error instanceof BountyPilotError) {
        throw error;
      }
      throw new BountyPilotError(
        "Lab authorization file could not be read",
        "LAB_AUTHORIZATION_FILE_READ_FAILED",
      );
    } finally {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          // best effort
        }
      }
    }
  },
};

function readProgramFile(filePath: string): string {
  let stats: Stats;
  try {
    stats = statSync(filePath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new BountyPilotError("Program file could not be located", "PROGRAM_FILE_NOT_FOUND");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(
      `Program file metadata could not be read: ${reason}`,
      "PROGRAM_FILE_READ_FAILED",
    );
  }
  if (!stats.isFile()) {
    throw new BountyPilotError("Program path is not a file", "PROGRAM_FILE_NOT_FILE");
  }
  if (stats.size > MAX_PROGRAM_FILE_BYTES) {
    throw new BountyPilotError("Program file is too large to load", "PROGRAM_FILE_TOO_LARGE");
  }
  try {
    return readFileSync(filePath, "utf8");
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(
      `Program file could not be read: ${reason}`,
      "PROGRAM_FILE_READ_FAILED",
    );
  }
}

function normalizeRelativePath(value: string): string {
  return value
    .replaceAll("\\", "/")
    .replace(/^\.\/+/, "")
    .replace(/\/+$/u, "");
}

function assertSafeRelativePath(value: string): void {
  if (value.length === 0) {
    throw new BountyPilotError(
      "Lab authorization path is empty after normalization",
      "LAB_AUTHORIZATION_FILE_PATH_INVALID",
    );
  }
  if (/[\u0000-\u001F\u007F]/.test(value)) {
    throw new BountyPilotError(
      "Lab authorization path contains control characters",
      "LAB_AUTHORIZATION_FILE_PATH_INVALID",
    );
  }
  if (value.startsWith("/") || /^[A-Za-z]:/.test(value)) {
    throw new BountyPilotError(
      "Lab authorization path must be a safe relative path inside the program workspace",
      "LAB_AUTHORIZATION_FILE_PATH_INVALID",
    );
  }
  if (value.includes(":")) {
    throw new BountyPilotError(
      "Lab authorization path must not contain a Windows drive or alternate data stream separator",
      "LAB_AUTHORIZATION_FILE_PATH_INVALID",
    );
  }
  const segments = value.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === "." || segment === "..") {
      throw new BountyPilotError(
        "Lab authorization path must not contain empty or escape segments",
        "LAB_AUTHORIZATION_FILE_PATH_INVALID",
      );
    }
  }
}

function safeRealpath(
  access: LabAuthorizationFileAccess,
  filePath: string,
  notFoundCode: "LAB_AUTHORIZATION_FILE_NOT_FOUND",
): string {
  try {
    return access.realpath(filePath);
  } catch (error) {
    if (error instanceof BountyPilotError && error.code === notFoundCode) {
      throw error;
    }
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new BountyPilotError(
        "Lab authorization file could not be located",
        notFoundCode,
      );
    }
    if (error instanceof BountyPilotError) {
      throw error;
    }
    throw new BountyPilotError(
      "Lab authorization file could not be resolved",
      "LAB_AUTHORIZATION_FILE_READ_FAILED",
    );
  }
}

function safeReadUpTo(
  access: LabAuthorizationFileAccess,
  filePath: string,
  maxBytes: number,
): Buffer {
  try {
    return access.readUpTo(filePath, maxBytes);
  } catch (error) {
    if (error instanceof BountyPilotError) {
      if (error.code === "LAB_AUTHORIZATION_FILE_TOO_LARGE") {
        throw new BountyPilotError(
          "Lab authorization file is too large to load",
          "LAB_AUTHORIZATION_FILE_TOO_LARGE",
        );
      }
      if (error.code === "LAB_AUTHORIZATION_FILE_NOT_FILE") {
        throw new BountyPilotError(
          "Lab authorization path is not a regular file",
          "LAB_AUTHORIZATION_FILE_NOT_FILE",
        );
      }
    }
    throw new BountyPilotError(
      "Lab authorization file could not be read",
      "LAB_AUTHORIZATION_FILE_READ_FAILED",
    );
  }
}

function assertRealpathContains(workspaceReal: string, candidateReal: string): void {
  const relative = path.relative(workspaceReal, candidateReal);
  if (
    relative === "" ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new BountyPilotError(
      "Lab authorization file is outside the program workspace",
      "LAB_AUTHORIZATION_FILE_SYMLINK_ESCAPE",
    );
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
