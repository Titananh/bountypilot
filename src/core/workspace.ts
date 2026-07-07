import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { stringify } from "yaml";
import { isValidProgramName, type ProgramConfig } from "./config/program-schema.js";
import { BountyPilotError } from "../utils/errors.js";

export interface WorkspacePaths {
  root: string;
  programsDir: string;
  dbDir: string;
  logsDir: string;
  toolsDir: string;
  integrationsDir: string;
  providersDir: string;
}

export interface ProgramWorkspace {
  workspace: WorkspacePaths;
  programDir: string;
  programFile: string;
  researchDir: string;
  jobsDir: string;
  evidenceDir: string;
  reportsDir: string;
  dbFile: string;
}

export function workspacePaths(cwd = process.cwd()): WorkspacePaths {
  const root = path.resolve(cwd, ".bounty");
  return {
    root,
    programsDir: path.join(root, "programs"),
    dbDir: path.join(root, "db"),
    logsDir: path.join(root, "logs"),
    toolsDir: path.join(root, "tools"),
    integrationsDir: path.join(root, "integrations"),
    providersDir: path.join(root, "providers"),
  };
}

export function ensureWorkspace(cwd = process.cwd()): WorkspacePaths {
  const paths = workspacePaths(cwd);
  for (const dir of Object.values(paths)) {
    mkdirSync(dir, { recursive: true });
  }
  return paths;
}

export function programWorkspace(programName: string, cwd = process.cwd()): ProgramWorkspace {
  assertValidProgramName(programName);
  const workspace = workspacePaths(cwd);
  const programDir = path.join(workspace.programsDir, programName);
  return {
    workspace,
    programDir,
    programFile: path.join(programDir, "program.yml"),
    researchDir: path.join(programDir, "research"),
    jobsDir: path.join(programDir, "jobs"),
    evidenceDir: path.join(programDir, "evidence"),
    reportsDir: path.join(programDir, "reports"),
    dbFile: path.join(programDir, "bountypilot.sqlite"),
  };
}

export function ensureProgramWorkspace(programName: string, cwd = process.cwd()): ProgramWorkspace {
  ensureWorkspace(cwd);
  const paths = programWorkspace(programName, cwd);
  const dirs = [
    paths.programDir,
    paths.researchDir,
    paths.jobsDir,
    paths.evidenceDir,
    paths.reportsDir,
  ];
  for (const dir of dirs) {
    mkdirSync(dir, { recursive: true });
  }
  return paths;
}

function assertValidProgramName(programName: string): void {
  if (!isValidProgramName(programName)) {
    throw new BountyPilotError(
      `Invalid program name: ${programName}. Use letters, numbers, dots, underscores, and hyphens only.`,
      "PROGRAM_NAME_INVALID",
    );
  }
}

export function saveProgramConfig(config: ProgramConfig, cwd = process.cwd()): ProgramWorkspace {
  const paths = ensureProgramWorkspace(config.program, cwd);
  writeFileSync(paths.programFile, stringify(config), "utf8");
  return paths;
}

export function findProgramName(cwd = process.cwd(), requested?: string): string {
  if (requested) {
    return requested;
  }

  const paths = workspacePaths(cwd);
  if (!existsSync(paths.programsDir)) {
    throw new BountyPilotError("No .bounty workspace found. Run `bounty init` first.", "WORKSPACE_NOT_FOUND");
  }

  const candidates = readdirSync(paths.programsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);

  if (candidates.length === 0) {
    throw new BountyPilotError("No imported programs found. Run `bounty import <program.yml>` first.", "PROGRAM_NOT_FOUND");
  }
  if (candidates.length > 1) {
    throw new BountyPilotError(
      `Multiple programs found (${candidates.join(", ")}). Pass --program <name>.`,
      "PROGRAM_AMBIGUOUS",
    );
  }
  return candidates[0];
}
