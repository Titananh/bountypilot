import { spawn, spawnSync, type ChildProcessWithoutNullStreams, type SpawnSyncReturns } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCacheDir = path.join(os.tmpdir(), "bountypilot-package-bin-npm-cache");

describe("packaged bugbounty bin", () => {
  it("builds a GitHub-style source checkout through prepare", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-source-prepare-"));
    try {
      const sourceDir = path.join(root, "source");
      copySourceCheckout(sourceDir);
      rmSync(path.join(sourceDir, "dist"), { recursive: true, force: true });
      linkWorkspaceNodeModules(sourceDir);

      const prepared = runNpm(["run", "prepare"], sourceDir);
      expectCommand(prepared).toExit(0);
      const cliPath = path.join(sourceDir, "dist", "cli", "index.js");
      expect(existsSync(cliPath)).toBe(true);

      const help = spawnSync(process.execPath, [cliPath, "--help"], {
        cwd: sourceDir,
        encoding: "utf8",
        env: smokeEnv(),
        timeout: 30_000,
      });
      expectCommand(help).toExit(0);
      expect(outputOf(help)).toContain("BountyPilot safe, local-first");

      const skillValidate = spawnSync(process.execPath, [cliPath, "skill", "validate", "bug-bounty-pilot", "--json"], {
        cwd: sourceDir,
        encoding: "utf8",
        env: smokeEnv(),
        timeout: 30_000,
      });
      expectCommand(skillValidate).toExit(0);
      expect(JSON.parse(skillValidate.stdout).ok).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);

  it("installs the packed package and runs a fresh-user first-run flow", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-package-bin-"));
    try {
      const packDir = path.join(root, "pack");
      const consumerDir = path.join(root, "consumer");
      mkdirSync(packDir, { recursive: true });
      mkdirSync(consumerDir, { recursive: true });
      const pack = runNpm(["pack", "--json", "--ignore-scripts", "--pack-destination", packDir], repoRoot);
      expectCommand(pack).toExit(0);
      const packed = JSON.parse(pack.stdout) as Array<{ filename: string }>;
      const tarball = path.join(packDir, packed[0]!.filename);
      expect(existsSync(tarball)).toBe(true);

      installPackedPackageOffline(tarball, consumerDir);

      const binPath = path.join(consumerDir, "node_modules", ".bin", process.platform === "win32" ? "bugbounty.cmd" : "bugbounty");
      const legacyBinPath = path.join(consumerDir, "node_modules", ".bin", process.platform === "win32" ? "bounty.cmd" : "bounty");
      expect(existsSync(binPath)).toBe(true);
      expect(existsSync(legacyBinPath)).toBe(true);
      const help = runBounty(binPath, ["--help"], consumerDir);
      expectCommand(help).toExit(0);
      expect(outputOf(help)).toContain("BountyPilot safe, local-first");

      const skillValidate = runBounty(binPath, ["skill", "validate", "bug-bounty-pilot", "--json"], consumerDir);
      expectCommand(skillValidate).toExit(0);
      expect(JSON.parse(skillValidate.stdout).ok).toBe(true);

      const skillBundlePath = path.join(consumerDir, "bug-bounty-pilot.skill.zip");
      const skillBundle = runBounty(binPath, ["skill", "bundle", "bug-bounty-pilot", "--output", skillBundlePath, "--json"], consumerDir);
      expectCommand(skillBundle).toExit(0);
      expect(JSON.parse(skillBundle.stdout)).toMatchObject({ ok: true, output: skillBundlePath });
      const skillVerify = runBounty(binPath, ["skill", "verify-bundle", skillBundlePath, "--json"], consumerDir);
      expectCommand(skillVerify).toExit(0);
      expect(JSON.parse(skillVerify.stdout)).toMatchObject({ ok: true, files: { missing: [], mismatched: [], extra: [] } });

      const freshQuickstart = runBounty(binPath, ["quickstart", "--json"], consumerDir);
      expectCommand(freshQuickstart).toExit(0);
      const parsedFreshQuickstart = JSON.parse(freshQuickstart.stdout);
      expect(parsedFreshQuickstart.status).toBe("needs_review");
      expect(parsedFreshQuickstart.workspace.found).toBe(false);
      expect(parsedFreshQuickstart.nextCommands).toEqual(expect.arrayContaining(["bounty init --guided"]));

      const freshReadiness = runBounty(binPath, ["beta", "readiness", "--json"], consumerDir);
      expectCommand(freshReadiness).toExit(0);
      const parsedFreshReadiness = JSON.parse(freshReadiness.stdout);
      expect(parsedFreshReadiness.ok).toBe(true);
      expect(parsedFreshReadiness.release.ok).toBe(true);
      expect(parsedFreshReadiness.status).toBe("needs_review");

      const readinessReport = path.join(consumerDir, "beta-readiness.json");
      const writeReadiness = runBounty(binPath, ["beta", "readiness", "--write", "--output", readinessReport, "--json"], consumerDir);
      expectCommand(writeReadiness).toExit(0);
      expect(existsSync(readinessReport)).toBe(true);
      expect(JSON.parse(readFileSync(readinessReport, "utf8")).release.ok).toBe(true);

      const installedPackageRoot = path.join(consumerDir, "node_modules", "bountypilot");
      const localProgram = path.join(installedPackageRoot, "examples", "local-program.yml");
      const guidedInit = runBounty(binPath, ["init", "--guided", "--program-file", localProgram, "--json"], consumerDir);
      expectCommand(guidedInit).toExit(0);
      expect(JSON.parse(guidedInit.stdout).import.program).toBe("local-lab");

      const importedQuickstart = runBounty(binPath, ["quickstart", "http://127.0.0.1:8080", "--json"], consumerDir);
      expectCommand(importedQuickstart).toExit(0);
      const parsedImportedQuickstart = JSON.parse(importedQuickstart.stdout);
      expect(parsedImportedQuickstart.program.name).toBe("local-lab");
      expect(parsedImportedQuickstart.sections.map((section: any) => section.id)).toContain("hunt");

      const demo = await startBountyDemo(binPath, consumerDir);
      try {
        expect(demo.ready.target).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/);
        const labRun = runBounty(
          binPath,
          ["lab", "e2e", demo.ready.target, "--live", "--with", "safe-checks,js-analyzer", "--json"],
          consumerDir,
        );
        expectCommand(labRun).toExit(0);
        const parsedLabRun = JSON.parse(labRun.stdout);
        expect(parsedLabRun).toMatchObject({ ok: true, live: true, dryRun: false, mode: "lab-offensive" });
        expect(parsedLabRun.summary.evidenceCreated).toBeGreaterThanOrEqual(2);
      } finally {
        await demo.stop();
      }

      const readyReadiness = runBounty(binPath, ["beta", "readiness", "--json"], consumerDir);
      expectCommand(readyReadiness).toExit(0);
      const parsedReadyReadiness = JSON.parse(readyReadiness.stdout);
      expect(parsedReadyReadiness.ok).toBe(true);
      expect(parsedReadyReadiness.status).toBe("ready");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);
});

function copySourceCheckout(destination: string): void {
  cpSync(repoRoot, destination, {
    recursive: true,
    filter(source) {
      const relative = path.relative(repoRoot, source);
      if (!relative) return true;
      const first = relative.split(path.sep)[0];
      return ![".bounty", ".git", ".release", "dist", "node_modules"].includes(first ?? "");
    },
  });
}

function linkWorkspaceNodeModules(sourceDir: string): void {
  const source = path.join(repoRoot, "node_modules");
  const destination = path.join(sourceDir, "node_modules");
  if (existsSync(destination)) return;
  symlinkSync(source, destination, process.platform === "win32" ? "junction" : "dir");
}

function runBounty(binPath: string, args: string[], cwd: string): SpawnSyncReturns<string> {
  const command = process.platform === "win32" ? "cmd.exe" : binPath;
  const commandArgs = process.platform === "win32" ? ["/d", "/c", windowsCallCommandLine(cwd, binPath, args)] : args;
  return spawnSync(command, commandArgs, {
    cwd,
    encoding: "utf8",
    env: smokeEnv(),
    timeout: 30_000,
  });
}

function installPackedPackageOffline(tarball: string, consumerDir: string): void {
  writeFileSync(path.join(consumerDir, "package.json"), '{"private":true,"type":"module"}\n', "utf8");
  const nodeModulesDir = path.join(consumerDir, "node_modules");
  const extractDir = path.join(consumerDir, "extract");
  mkdirSync(nodeModulesDir, { recursive: true });
  mkdirSync(extractDir, { recursive: true });

  const extract = spawnSync("tar", ["-xzf", tarball, "-C", extractDir], { encoding: "utf8" });
  expectCommand(extract).toExit(0);
  renameSync(path.join(extractDir, "package"), path.join(nodeModulesDir, "bountypilot"));
  linkRuntimeDependencies(nodeModulesDir);
  writeBountyBins(nodeModulesDir);
}

function linkRuntimeDependencies(nodeModulesDir: string): void {
  const packageJson = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
  for (const dependency of Object.keys(packageJson.dependencies ?? {})) {
    const source = path.join(repoRoot, "node_modules", ...dependency.split("/"));
    const destination = path.join(nodeModulesDir, ...dependency.split("/"));
    if (existsSync(destination)) continue;
    mkdirSync(path.dirname(destination), { recursive: true });
    symlinkSync(source, destination, process.platform === "win32" ? "junction" : "dir");
  }
}

function writeBountyBins(nodeModulesDir: string): void {
  writeBountyBin(nodeModulesDir, "bugbounty");
  writeBountyBin(nodeModulesDir, "bounty");
}

function writeBountyBin(nodeModulesDir: string, commandName: "bugbounty" | "bounty"): void {
  const binDir = path.join(nodeModulesDir, ".bin");
  mkdirSync(binDir, { recursive: true });
  if (process.platform === "win32") {
    writeFileSync(
      path.join(binDir, `${commandName}.cmd`),
      "@ECHO off\r\nnode \"%~dp0\\..\\bountypilot\\dist\\cli\\index.js\" %*\r\n",
      "utf8",
    );
    return;
  }
  const binPath = path.join(binDir, commandName);
  writeFileSync(
    binPath,
    "#!/usr/bin/env sh\nbasedir=$(dirname \"$(printf '%s\\n' \"$0\" | sed -e 's,\\\\,/,g')\")\nexec node \"$basedir/../bountypilot/dist/cli/index.js\" \"$@\"\n",
    "utf8",
  );
  chmodSync(binPath, 0o755);
}

interface DemoHandle {
  ready: any;
  stop: () => Promise<void>;
}

function startBountyDemo(binPath: string, cwd: string): Promise<DemoHandle> {
  const child = spawnBounty(binPath, ["lab", "demo", "--port", "0", "--json"], cwd);
  let stdout = "";
  let stderr = "";
  let settled = false;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      settled = true;
      child.kill();
      reject(new Error(`demo lab did not become ready. stdout=${stdout} stderr=${stderr}`));
    }, 10_000);

    const tryResolve = () => {
      if (settled) return;
      try {
        const parsed = JSON.parse(stdout.trim());
        settled = true;
        clearTimeout(timeout);
        resolve({ ready: parsed, stop: () => stopChild(child) });
      } catch {
        // Wait for the complete pretty-printed JSON object.
      }
    };

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      tryResolve();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });
    child.on("exit", (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(new Error(`demo lab exited before ready with status ${status}. stdout=${stdout} stderr=${stderr}`));
    });
  });
}

function spawnBounty(binPath: string, args: string[], cwd: string): ChildProcessWithoutNullStreams {
  if (process.platform === "win32") {
    return spawn(process.execPath, [installedCliPath(binPath), ...args], {
      cwd,
      env: smokeEnv(),
      windowsHide: true,
    });
  }
  return spawn(binPath, args, {
    cwd,
    env: smokeEnv(),
  });
}

function installedCliPath(binPath: string): string {
  return path.resolve(path.dirname(binPath), "..", "bountypilot", "dist", "cli", "index.js");
}

function windowsCallCommandLine(cwd: string, binPath: string, args: string[]): string {
  const relativeBin = path.relative(cwd, binPath);
  return [relativeBin, ...args].join(" ");
}

function stopChild(child: ChildProcessWithoutNullStreams): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.killed) {
      resolve();
      return;
    }
    const timeout = setTimeout(() => {
      child.kill();
      resolve();
    }, 5_000);
    child.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

function runNpm(args: string[], cwd: string): SpawnSyncReturns<string> {
  const npmExecPath = process.env.npm_execpath;
  const command = npmExecPath && existsSync(npmExecPath) ? process.execPath : process.platform === "win32" ? "npm.cmd" : "npm";
  const argsWithCache = ["--cache", npmCacheDir, ...args];
  const commandArgs = npmExecPath && existsSync(npmExecPath) ? [npmExecPath, ...argsWithCache] : argsWithCache;
  return spawnSync(command, commandArgs, {
    cwd,
    encoding: "utf8",
    shell: process.platform === "win32" && command.endsWith(".cmd"),
    env: smokeEnv(),
    timeout: 120_000,
  });
}

function smokeEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NO_COLOR: "1",
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1",
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_cache: npmCacheDir,
    NPM_CONFIG_CACHE: npmCacheDir,
    npm_config_update_notifier: "false",
  };
}

function outputOf(result: SpawnSyncReturns<string>): string {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function expectCommand(result: SpawnSyncReturns<string>): { toExit(status: number): void } {
  return {
    toExit(status: number) {
      expect(result.error, outputOf(result)).toBeUndefined();
      expect(result.status, outputOf(result)).toBe(status);
    },
  };
}
