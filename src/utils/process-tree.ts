import { spawn, spawnSync, type ChildProcess, type ChildProcessByStdio, type SpawnOptions } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import type { Readable, Writable } from "node:stream";

type PipedChildProcess = ChildProcessByStdio<Writable, Readable, Readable>;
type OutputChildProcess = ChildProcessByStdio<null, Readable, Readable>;

type LocalProcessOptions = Omit<SpawnOptions, "detached" | "shell" | "stdio" | "windowsHide">;
const WINDOWS_TASKKILL_TIMEOUT_MS = 1_000;

export function spawnPipedProcess(command: string, args: string[], options: LocalProcessOptions): PipedChildProcess {
  return spawn(command, args, {
    ...options,
    detached: process.platform !== "win32",
    shell: false,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  }) as PipedChildProcess;
}

export function spawnOutputProcess(command: string, args: string[], options: LocalProcessOptions): OutputChildProcess {
  return spawn(command, args, {
    ...options,
    detached: process.platform !== "win32",
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  }) as OutputChildProcess;
}

export function killProcessTree(child: ChildProcess): void {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }

  const pid = child.pid;
  if (!pid) {
    child.kill();
    return;
  }

  if (process.platform === "win32") {
    const taskkill = windowsTaskkillPath();
    if (!taskkill) {
      child.kill("SIGKILL");
      return;
    }
    const result = spawnSync(taskkill, ["/pid", String(pid), "/t", "/f"], {
      shell: false,
      windowsHide: true,
      stdio: "ignore",
      timeout: WINDOWS_TASKKILL_TIMEOUT_MS,
    });
    if (result.error || result.status !== 0) {
      child.kill("SIGKILL");
    }
    return;
  }

  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }

  const forceKill = setTimeout(() => {
    if (child.exitCode !== null || child.signalCode !== null) {
      return;
    }
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      // The process group already exited.
    }
  }, 1_000);
  forceKill.unref();
}

export function releaseProcessHandles(child: ChildProcess): void {
  try {
    child.stdin?.end();
  } catch {
    // The stream may already be closed.
  }
  try {
    child.stdin?.destroy();
  } catch {
    // The stream may already be closed.
  }
  try {
    child.stdout?.destroy();
  } catch {
    // The stream may already be closed.
  }
  try {
    child.stderr?.destroy();
  } catch {
    // The stream may already be closed.
  }
  child.unref();
}

function windowsTaskkillPath(): string | undefined {
  const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
  if (!systemRoot) {
    return undefined;
  }
  const candidate = path.join(systemRoot, "System32", "taskkill.exe");
  return existsSync(candidate) ? candidate : undefined;
}
