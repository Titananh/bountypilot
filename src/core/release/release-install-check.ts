import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export interface ReleaseInstallCheckItem {
  name: string;
  status: "pass" | "fail";
  message: string;
}

export interface ReleaseInstallCheckResult {
  ok: boolean;
  command: string;
  resolvedCommand: string;
  verificationCwd: string;
  checks: ReleaseInstallCheckItem[];
  version?: string;
  nextCommands: string[];
}

export interface BuildReleaseInstallCheckInput {
  command?: string;
  argsPrefix?: string[];
  cwd?: string;
  timeoutMs?: number;
}

interface InstallCommandRun {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: string;
}

const OUTPUT_LIMIT = 64 * 1024;

export function buildReleaseInstallCheck(input: BuildReleaseInstallCheckInput = {}): ReleaseInstallCheckResult {
  const cwd = input.cwd ?? process.cwd();
  const command = input.command?.trim() || "bugbounty";
  const argsPrefix = input.argsPrefix ?? [];
  const timeoutMs = input.timeoutMs ?? 30_000;
  const verificationCwd = mkdtempSync(path.join(os.tmpdir(), "bountypilot-install-check-"));
  const checks: ReleaseInstallCheckItem[] = [];
  let resolvedCommand = command;
  let version: string | undefined;

  try {
    const resolved = resolveInstallCommand(command, cwd);
    resolvedCommand = resolved.resolvedCommand;

    const versionRun = runInstalledCommand({ ...resolved, argsPrefix, args: ["--version"], cwd: verificationCwd, timeoutMs });
    const versionText = firstOutputLine(versionRun);
    version = versionText || undefined;
    checks.push({
      name: "command:version",
      status: versionRun.status === 0 && Boolean(versionText) ? "pass" : "fail",
      message: versionRun.status === 0 && versionText ? versionText : commandFailureMessage(versionRun),
    });

    const helpRun = runInstalledCommand({ ...resolved, argsPrefix, args: ["--help"], cwd: verificationCwd, timeoutMs });
    checks.push({
      name: "command:help",
      status: helpRun.status === 0 && combinedOutput(helpRun).includes("BountyPilot safe, local-first") ? "pass" : "fail",
      message:
        helpRun.status === 0 && combinedOutput(helpRun).includes("BountyPilot safe, local-first")
          ? "help output identifies BountyPilot"
          : commandFailureMessage(helpRun),
    });

    const skillRun = runInstalledCommand({
      ...resolved,
      argsPrefix,
      args: ["skill", "validate", "bug-bounty-pilot", "--json"],
      cwd: verificationCwd,
      timeoutMs,
    });
    const skillJson = parseJsonObject(skillRun.stdout);
    checks.push({
      name: "skill:validate",
      status: skillRun.status === 0 && skillJson?.ok === true ? "pass" : "fail",
      message:
        skillRun.status === 0 && skillJson?.ok === true
          ? `${Number(skillJson.checks?.length ?? 0)} skill checks passed`
          : commandFailureMessage(skillRun),
    });

    const skillShowRun = runInstalledCommand({
      ...resolved,
      argsPrefix,
      args: ["skill", "show", "bug-bounty-pilot", "--json"],
      cwd: verificationCwd,
      timeoutMs,
    });
    const skillShowJson = parseJsonObject(skillShowRun.stdout);
    const defaultPrompt = skillShowJson?.agentMetadata?.interface?.default_prompt;
    const skillMetadataOk =
      skillShowRun.status === 0 &&
      skillShowJson?.frontmatter?.name === "bug-bounty-pilot" &&
      typeof defaultPrompt === "string" &&
      defaultPrompt.includes("$bug-bounty-pilot");
    checks.push({
      name: "skill:metadata",
      status: skillMetadataOk ? "pass" : "fail",
      message: skillMetadataOk ? "frontmatter and agent metadata are present" : commandFailureMessage(skillShowRun),
    });

    const skillScoreRun = runInstalledCommand({
      ...resolved,
      argsPrefix,
      args: ["skill", "score", "bug-bounty-pilot", "--json"],
      cwd: installedPackageRoot(resolved.resolvedCommand, cwd),
      timeoutMs,
    });
    const skillScoreJson = parseJsonObject(skillScoreRun.stdout);
    const skillScoreOk =
      skillScoreRun.status === 0 &&
      skillScoreJson?.ok === true &&
      typeof skillScoreJson?.score === "number" &&
      skillScoreJson.score >= 90 &&
      skillScoreJson?.validation?.failures?.length === 0 &&
      skillScoreJson?.bundle?.ok === true &&
      skillScoreJson?.release?.ok === true;
    checks.push({
      name: "skill:score",
      status: skillScoreOk ? "pass" : "fail",
      message: skillScoreOk ? `${skillScoreJson.score}/100 ${skillScoreJson.readiness ?? "ready"}` : commandFailureMessage(skillScoreRun),
    });

    const quickstartRun = runInstalledCommand({ ...resolved, argsPrefix, args: ["quickstart", "--json"], cwd: verificationCwd, timeoutMs });
    const quickstartJson = parseJsonObject(quickstartRun.stdout);
    const nextCommands = Array.isArray(quickstartJson?.nextCommands) ? quickstartJson.nextCommands : [];
    checks.push({
      name: "quickstart:fresh-user",
      status:
        quickstartRun.status === 0 &&
        typeof quickstartJson?.status === "string" &&
        quickstartJson?.workspace?.found === false &&
        nextCommands.includes("bounty init --guided")
          ? "pass"
          : "fail",
      message:
        quickstartRun.status === 0 && typeof quickstartJson?.status === "string"
          ? `fresh quickstart status ${quickstartJson.status}`
          : commandFailureMessage(quickstartRun),
    });
  } catch (error) {
    checks.push({
      name: "command:resolve",
      status: "fail",
      message: error instanceof Error ? error.message : String(error),
    });
  } finally {
    rmSync(verificationCwd, { recursive: true, force: true });
  }

  const ok = checks.every((check) => check.status === "pass");
  return {
    ok,
    command,
    resolvedCommand,
    verificationCwd,
    checks,
    version,
    nextCommands: ok
      ? ["bugbounty quickstart <in-scope-target>", "bugbounty providers catalog", "bugbounty hunt profiles"]
      : ["npm install -g bountypilot", "bugbounty release install-check --json"],
  };
}

interface ResolvedInstallCommand {
  resolvedCommand: string;
  commandForSpawn: string;
  commandPrefix: string[];
}

function resolveInstallCommand(command: string, cwd: string): ResolvedInstallCommand {
  const candidate = command.includes("/") || command.includes("\\") ? path.resolve(cwd, command) : findOnPath(command);
  if (!candidate) {
    throw new Error(`Could not resolve installed command: ${command}`);
  }
  if (process.platform === "win32" && /\.(?:cmd|bat)$/i.test(candidate)) {
    return {
      resolvedCommand: candidate,
      commandForSpawn: "cmd.exe",
      commandPrefix: ["/d", "/c", windowsCmdShimCall(candidate)],
    };
  }
  return {
    resolvedCommand: candidate,
    commandForSpawn: candidate,
    commandPrefix: [],
  };
}

function installedPackageRoot(resolvedCommand: string, cwd: string): string {
  const candidates = [
    path.join(cwd, "node_modules", "bountypilot"),
    npmBinPackageRoot(resolvedCommand),
    cwd,
  ].filter((candidate): candidate is string => Boolean(candidate));
  return candidates.find((candidate) => existsSync(path.join(candidate, "package.json"))) ?? cwd;
}

function npmBinPackageRoot(resolvedCommand: string): string | undefined {
  const binDir = path.dirname(resolvedCommand);
  if (path.basename(binDir).toLowerCase() !== ".bin") return undefined;
  return path.join(path.dirname(binDir), "bountypilot");
}

function findOnPath(command: string): string | undefined {
  const pathEntries = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const extensions = process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";") : [""];
  const names = process.platform === "win32" && !path.extname(command) ? extensions.map((extension) => `${command}${extension.toLowerCase()}`) : [command];
  for (const pathEntry of pathEntries) {
    for (const name of names) {
      const candidate = path.join(pathEntry, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

function windowsCmdShimCall(command: string): string {
  return `call ${quoteCmd(command)}`;
}

function quoteCmd(value: string): string {
  return `"${value.replace(/[%^"]/g, (char) => `^${char}`)}"`;
}

function quoteCmdArg(value: string): string {
  return quoteCmd(value);
}

function runInstalledCommand(input: ResolvedInstallCommand & { argsPrefix: string[]; args: string[]; cwd: string; timeoutMs: number }): InstallCommandRun {
  const commandArgs =
    input.commandPrefix.length > 0
      ? [...input.commandPrefix.slice(0, -1), `${input.commandPrefix.at(-1)} ${[...input.argsPrefix, ...input.args].map(quoteCmdArg).join(" ")}`]
      : [...input.argsPrefix, ...input.args];
  const result = spawnSync(input.commandForSpawn, commandArgs, {
    cwd: input.cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      NO_COLOR: "1",
      BOUNTYPILOT_INSTALL_CHECK: "1",
    },
    maxBuffer: OUTPUT_LIMIT,
    timeout: input.timeoutMs,
    windowsHide: true,
    windowsVerbatimArguments: input.commandPrefix.length > 0,
  });
  return {
    status: result.status,
    stdout: bounded(result.stdout ?? ""),
    stderr: bounded(result.stderr ?? ""),
    error: result.error?.message,
  };
}

function firstOutputLine(run: InstallCommandRun): string {
  return combinedOutput(run).split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? "";
}

function combinedOutput(run: InstallCommandRun): string {
  return `${run.stdout}${run.stderr ? `\n${run.stderr}` : ""}`;
}

function commandFailureMessage(run: InstallCommandRun): string {
  if (run.error) return run.error;
  const output = firstOutputLine(run);
  return output || `exit status ${run.status ?? "unknown"}`;
}

function parseJsonObject(text: string): Record<string, any> | undefined {
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function bounded(text: string): string {
  return text.length > OUTPUT_LIMIT ? `${text.slice(0, OUTPUT_LIMIT)}\n[truncated]\n` : text;
}
