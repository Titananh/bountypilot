import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { parse } from "yaml";
import { ZodError } from "zod";
import { ProgramSchema, type ProgramConfig } from "./program-schema.js";
import { findProgramName, programWorkspace } from "../workspace.js";
import { BountyPilotError } from "../../utils/errors.js";

export interface LoadedProgram {
  config: ProgramConfig;
  programFile: string;
}

export const MAX_PROGRAM_FILE_BYTES = 1_000_000;
export const MAX_LAB_AUTHORIZATION_FILE_BYTES = 200_000;

export function loadProgramFile(filePath: string): LoadedProgram {
  const stats = statProgramFile(filePath);
  if (!stats.isFile()) {
    throw new BountyPilotError(`Program path is not a file: ${filePath}`, "PROGRAM_FILE_NOT_FILE");
  }
  if (stats.size > MAX_PROGRAM_FILE_BYTES) {
    throw new BountyPilotError(
      `Program file is too large: ${stats.size} bytes (max ${MAX_PROGRAM_FILE_BYTES})`,
      "PROGRAM_FILE_TOO_LARGE",
    );
  }

  const raw = readProgramFile(filePath);
  try {
    const parsed = parse(raw);
    const config = ProgramSchema.parse(parsed);
    validateLabAuthorizationFile(filePath, config);
    return {
      config,
      programFile: filePath,
    };
  } catch (error) {
    if (error instanceof BountyPilotError) {
      throw error;
    }
    if (error instanceof ZodError) {
      const details = error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
      throw new BountyPilotError(`Invalid program.yml: ${details}`, "PROGRAM_SCHEMA_INVALID");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Invalid program.yml syntax: ${reason}`, "PROGRAM_YAML_INVALID");
  }
}

export function labAuthorizationFilePath(programFile: string, config: ProgramConfig): string | undefined {
  const relativePath = config.rules.lab_authorization_file;
  return relativePath ? path.resolve(path.dirname(programFile), relativePath) : undefined;
}

function validateLabAuthorizationFile(programFile: string, config: ProgramConfig): void {
  const authorizationPath = labAuthorizationFilePath(programFile, config);
  if (config.rules.lab_mode === true && !authorizationPath) {
    throw new BountyPilotError(
      "rules.lab_mode=true requires rules.lab_authorization_file pointing to a local authorization note.",
      "LAB_AUTHORIZATION_FILE_REQUIRED",
    );
  }
  if (!authorizationPath) return;

  let stats;
  try {
    stats = statSync(authorizationPath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new BountyPilotError(`Lab authorization file not found: ${authorizationPath}`, "LAB_AUTHORIZATION_FILE_NOT_FOUND");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Could not read lab authorization file metadata: ${reason}`, "LAB_AUTHORIZATION_FILE_READ_FAILED");
  }
  if (!stats.isFile()) {
    throw new BountyPilotError(`Lab authorization path is not a file: ${authorizationPath}`, "LAB_AUTHORIZATION_FILE_NOT_FILE");
  }
  if (stats.size > MAX_LAB_AUTHORIZATION_FILE_BYTES) {
    throw new BountyPilotError(
      `Lab authorization file is too large: ${stats.size} bytes (max ${MAX_LAB_AUTHORIZATION_FILE_BYTES})`,
      "LAB_AUTHORIZATION_FILE_TOO_LARGE",
    );
  }
}

export function loadWorkspaceProgram(cwd = process.cwd(), requested?: string): LoadedProgram {
  const programName = findProgramName(cwd, requested);
  const paths = programWorkspace(programName, cwd);
  return loadProgramFile(paths.programFile);
}

function statProgramFile(filePath: string) {
  try {
    return statSync(filePath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new BountyPilotError(`Program file not found: ${filePath}`, "PROGRAM_FILE_NOT_FOUND");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Could not read program file metadata: ${reason}`, "PROGRAM_FILE_READ_FAILED");
  }
}

function readProgramFile(filePath: string): string {
  try {
    return readFileSync(filePath, "utf8");
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Could not read program file: ${reason}`, "PROGRAM_FILE_READ_FAILED");
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
