import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("installer scripts", () => {
  it("resolves the GitHub source in Bash dry-run mode without installing globally", () => {
    if (!commandAvailable("bash")) return;

    const result = spawnSync("bash", [path.join(repoRoot, "scripts", "install.sh")], {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        BOUNTYPILOT_INSTALL_DRY_RUN: "1",
        BOUNTYPILOT_SOURCE: "github:OWNER/REPO",
      },
    });

    expect(result.status, outputOf(result)).toBe(0);
    expect(outputOf(result)).toContain("Installing BountyPilot from github:OWNER/REPO");
    expect(outputOf(result)).toContain("Dry run: npm install -g github:OWNER/REPO");
  });

  it("resolves the npm version source in PowerShell dry-run mode without installing globally", () => {
    const shell = process.platform === "win32" ? "powershell.exe" : "pwsh";
    if (!commandAvailable(shell)) return;

    const args =
      process.platform === "win32"
        ? ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(repoRoot, "scripts", "install.ps1")]
        : ["-NoProfile", "-File", path.join(repoRoot, "scripts", "install.ps1")];
    const result = spawnSync(shell, args, {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        BOUNTYPILOT_INSTALL_DRY_RUN: "true",
        BOUNTYPILOT_VERSION: "0.1.0",
      },
    });

    expect(result.status, outputOf(result)).toBe(0);
    expect(outputOf(result)).toContain("Installing BountyPilot from bountypilot@0.1.0");
    expect(outputOf(result)).toContain("Dry run: npm install -g bountypilot@0.1.0");
  });
});

function commandAvailable(command: string): boolean {
  return spawnSync(command, ["--version"], { encoding: "utf8" }).status === 0;
}

function outputOf(result: SpawnSyncReturns<string>): string {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}
