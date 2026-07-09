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
      timeout: 15_000,
      env: {
        ...process.env,
        BOUNTYPILOT_INSTALL_DRY_RUN: "1",
        BOUNTYPILOT_SOURCE: "github:OWNER/REPO#main",
      },
    });

    expect(result.status, outputOf(result)).toBe(0);
    expect(outputOf(result)).toContain("Installing BountyPilot from github:OWNER/REPO#main");
    expect(outputOf(result)).toContain("Dry run: npm install -g github:OWNER/REPO#main");
    expect(outputOf(result)).not.toContain("Install verified");
  });

  it("pins the GitHub source from BOUNTYPILOT_REF in Bash dry-run mode", () => {
    if (!commandAvailable("bash")) return;

    const result = spawnSync("bash", [path.join(repoRoot, "scripts", "install.sh")], {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        BOUNTYPILOT_INSTALL_DRY_RUN: "1",
        BOUNTYPILOT_SOURCE: "github:OWNER/REPO",
        BOUNTYPILOT_REF: "release/v0.1.0",
      },
    });

    expect(result.status, outputOf(result)).toBe(0);
    expect(outputOf(result)).toContain("Installing BountyPilot from github:OWNER/REPO#release/v0.1.0");
    expect(outputOf(result)).toContain("Dry run: npm install -g github:OWNER/REPO#release/v0.1.0");
  });

  it("rejects unsupported Bash installer sources before npm install", () => {
    if (!commandAvailable("bash")) return;

    const result = spawnSync("bash", [path.join(repoRoot, "scripts", "install.sh")], {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        BOUNTYPILOT_INSTALL_DRY_RUN: "1",
        BOUNTYPILOT_SOURCE: "https://example.com/package.tgz",
      },
    });

    expect(result.status, outputOf(result)).not.toBe(0);
    expect(outputOf(result)).toContain("Invalid BOUNTYPILOT_SOURCE");
    expect(outputOf(result)).not.toContain("Dry run: npm install -g");
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
      timeout: 30_000,
      env: {
        ...process.env,
        BOUNTYPILOT_INSTALL_DRY_RUN: "true",
        BOUNTYPILOT_VERSION: "0.1.0",
      },
    });

    expect(result.status, outputOf(result)).toBe(0);
    expect(outputOf(result)).toContain("Installing BountyPilot from bountypilot@0.1.0");
    expect(outputOf(result)).toContain("Dry run: npm install -g bountypilot@0.1.0");
    expect(outputOf(result)).not.toContain("Install verified");
  });

  it("pins the GitHub source from BOUNTYPILOT_REF in PowerShell dry-run mode", () => {
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
        BOUNTYPILOT_SOURCE: "github:OWNER/REPO",
        BOUNTYPILOT_REF: "main",
      },
    });

    expect(result.status, outputOf(result)).toBe(0);
    expect(outputOf(result)).toContain("Installing BountyPilot from github:OWNER/REPO#main");
    expect(outputOf(result)).toContain("Dry run: npm install -g github:OWNER/REPO#main");
  });

  it("rejects unsupported PowerShell installer sources before npm install", () => {
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
        BOUNTYPILOT_SOURCE: "file:../unexpected",
      },
    });

    expect(result.status, outputOf(result)).not.toBe(0);
    expect(outputOf(result)).toContain("Invalid BOUNTYPILOT_SOURCE");
    expect(outputOf(result)).not.toContain("Dry run: npm install -g");
  });
});

function commandAvailable(command: string): boolean {
  return spawnSync(command, ["--version"], { encoding: "utf8" }).status === 0;
}

function outputOf(result: SpawnSyncReturns<string>): string {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}
