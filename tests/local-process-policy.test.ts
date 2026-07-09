import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  LocalExecutableApprovalStore,
  localProcessEnv,
  resolveApprovedLocalProcess,
  resolveLocalExecutable,
} from "../src/utils/local-process-policy.js";

describe("local process policy", () => {
  it("approves and verifies absolute executable files by path and hash", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-process-policy-"));
    const executable = path.join(root, "tool-bin");
    writeFileSync(executable, "test executable", "utf8");
    const store = new LocalExecutableApprovalStore(path.join(root, "approved-executables.json"));

    const approval = store.approve({ integration: "crawl4ai", command: executable, note: "local test tool" });
    const verified = store.verify({ integration: "crawl4ai", command: executable });

    expect(approval.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(verified.approval.id).toBe(approval.id);
    expect(store.list("crawl4ai")).toHaveLength(1);
  });

  it("rejects bare commands and shell shims", () => {
    expect(() => resolveLocalExecutable("npx")).toThrow(/absolute path/);

    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-process-shim-"));
    const shim = path.join(root, "npx.cmd");
    writeFileSync(shim, "@echo off\n", "utf8");

    try {
      resolveLocalExecutable(shim);
      throw new Error("Expected shim resolution to fail.");
    } catch (error) {
      expect(error).toMatchObject({ code: "EXECUTABLE_SHIM_UNSUPPORTED" });
    }
  });

  it("blocks execution when an approved executable hash changes", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-process-hash-"));
    const executable = path.join(root, "tool-bin");
    writeFileSync(executable, "version one", "utf8");
    const store = new LocalExecutableApprovalStore(path.join(root, "approved-executables.json"));
    store.approve({ integration: "crawl4ai", command: executable });

    writeFileSync(executable, "version two", "utf8");

    try {
      store.verify({ integration: "crawl4ai", command: executable });
      throw new Error("Expected verification to fail.");
    } catch (error) {
      expect(error).toMatchObject({ code: "EXECUTABLE_APPROVAL_HASH_MISMATCH" });
    }
  });

  it("resolves pinned npm package entrypoints through an approved node executable", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-process-package-"));
    const entrypoint = writePackage(root, "fake-runner", "1.2.3", "dist/cli.mjs");
    const store = new LocalExecutableApprovalStore(path.join(root, "approved-executables.json"));
    store.approve({ integration: "crawl4ai", command: process.execPath });

    const resolved = resolveApprovedLocalProcess({
      integration: "crawl4ai",
      integrationsDir: root,
      cwd: root,
      config: {
        package: "fake-runner",
        package_version: "1.2.3",
        entrypoint: "dist/cli.mjs",
      },
    });

    expect(resolved.executable.realPath).toBe(resolveLocalExecutable(process.execPath).realPath);
    // Resolve both sides via the OS so Windows 8.3 short-name aliasing
    // (e.g. C:\Users\runneradmin\... vs C:\Users\RUNNER~1\...) does not
    // break the assertion. path.resolve alone does not expand short names.
    expect(realpathSync(resolved.baseArgs[0])).toBe(realpathSync(entrypoint));
    expect(resolved.npmPackage).toMatchObject({
      name: "fake-runner",
      version: "1.2.3",
      entrypoint,
      entrypointSha256: sha256Text("console.log('ok');\n"),
    });
    expect(resolved.npmPackage?.packageJsonSha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("rejects pinned npm package entrypoints when package files drift", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-process-package-drift-"));
    const entrypoint = writePackage(root, "fake-runner", "1.2.3", "dist/cli.mjs");
    const store = new LocalExecutableApprovalStore(path.join(root, "approved-executables.json"));
    store.approve({ integration: "crawl4ai", command: process.execPath });
    const entrypointSha256 = sha256Text("console.log('ok');\n");

    writeFileSync(entrypoint, "console.log('changed');\n", "utf8");

    expect(() =>
      resolveApprovedLocalProcess({
        integration: "crawl4ai",
        integrationsDir: root,
        cwd: root,
        config: {
          package: "fake-runner",
          package_version: "1.2.3",
          entrypoint: "dist/cli.mjs",
          entrypoint_sha256: entrypointSha256,
        },
      }),
    ).toThrow(/entrypoint hash changed/);
  });

  it("rejects pinned npm package entrypoints when package metadata drifts", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-process-package-json-drift-"));
    writePackage(root, "fake-runner", "1.2.3", "dist/cli.mjs");
    const packageJsonPath = path.join(root, "node_modules", "fake-runner", "package.json");
    const store = new LocalExecutableApprovalStore(path.join(root, "approved-executables.json"));
    store.approve({ integration: "crawl4ai", command: process.execPath });
    const packageJsonSha256 = sha256Text(JSON.stringify({ name: "fake-runner", version: "1.2.3" }));

    writeFileSync(packageJsonPath, JSON.stringify({ name: "fake-runner", version: "1.2.3", bin: "dist/cli.mjs" }), "utf8");

    expect(() =>
      resolveApprovedLocalProcess({
        integration: "crawl4ai",
        integrationsDir: root,
        cwd: root,
        config: {
          package: "fake-runner",
          package_version: "1.2.3",
          entrypoint: "dist/cli.mjs",
          package_json_sha256: packageJsonSha256,
        },
      }),
    ).toThrow(/metadata hash changed/);
  });

  it("rejects unpinned, mismatched, ambiguous, or escaping package entrypoints", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-process-package-invalid-"));
    writePackage(root, "fake-runner", "1.2.3", "dist/cli.mjs");
    const store = new LocalExecutableApprovalStore(path.join(root, "approved-executables.json"));
    store.approve({ integration: "crawl4ai", command: process.execPath });

    expect(() =>
      resolveApprovedLocalProcess({
        integration: "crawl4ai",
        integrationsDir: root,
        cwd: root,
        config: { package: "fake-runner", package_version: "latest", entrypoint: "dist/cli.mjs" },
      }),
    ).toThrow(/exact pinned version/);
    expect(() =>
      resolveApprovedLocalProcess({
        integration: "crawl4ai",
        integrationsDir: root,
        cwd: root,
        config: { package: "fake-runner", package_version: "9.9.9", entrypoint: "dist/cli.mjs" },
      }),
    ).toThrow(/expected pinned version/);
    expect(() =>
      resolveApprovedLocalProcess({
        integration: "crawl4ai",
        integrationsDir: root,
        cwd: root,
        config: { command: process.execPath, package: "fake-runner", package_version: "1.2.3", entrypoint: "dist/cli.mjs" },
      }),
    ).toThrow(/either an absolute executable command or a pinned package entrypoint/);
    expect(() =>
      resolveApprovedLocalProcess({
        integration: "crawl4ai",
        integrationsDir: root,
        cwd: root,
        config: { package: "fake-runner", package_version: "1.2.3", entrypoint: "../escape.mjs" },
      }),
    ).toThrow(/relative path/);
  });

  it("builds a minimized process environment", () => {
    const env = localProcessEnv();

    expect(Object.keys(env)).not.toContain("PATH");
    expect(Object.keys(env)).not.toContain("Path");
    expect(Object.keys(env)).not.toContain("PATHEXT");
    expect(Object.keys(env)).not.toContain("HOME");
    expect(Object.keys(env)).not.toContain("USERPROFILE");
  expect(env.NO_COLOR).toBe("1");
  });
});

function writePackage(root: string, packageName: string, version: string, entrypoint: string): string {
  const packageRoot = path.join(root, "node_modules", packageName);
  const entrypointPath = path.join(packageRoot, ...entrypoint.split("/"));
  mkdirSync(path.dirname(entrypointPath), { recursive: true });
  writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ name: packageName, version }), "utf8");
  writeFileSync(entrypointPath, "console.log('ok');\n", "utf8");
  return path.resolve(entrypointPath);
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
