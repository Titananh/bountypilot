import { spawnSync } from "node:child_process";
import { BountyPilotError } from "./errors.js";

export interface OpenPathCommand {
  command: string;
  args: string[];
}

export function buildOpenPathCommand(targetPath: string, platform: NodeJS.Platform = process.platform): OpenPathCommand {
  if (targetPath.trim() === "") {
    throw new BountyPilotError("Path to open cannot be empty.", "OPEN_TARGET_INVALID");
  }

  if (platform === "win32") {
    return { command: "explorer.exe", args: [targetPath] };
  }

  if (platform === "darwin") {
    return { command: "open", args: [targetPath] };
  }

  return { command: "xdg-open", args: [targetPath] };
}

export function openPath(targetPath: string): void {
  const opener = buildOpenPathCommand(targetPath);
  const result = spawnSync(opener.command, opener.args, {
    shell: false,
    stdio: "ignore",
    windowsHide: true,
  });

  if (result.error || (typeof result.status === "number" && result.status !== 0)) {
    throw new BountyPilotError(`Could not open path: ${targetPath}`, "OPEN_FAILED");
  }
}
