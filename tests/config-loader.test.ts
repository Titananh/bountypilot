import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadProgramFile, MAX_PROGRAM_FILE_BYTES } from "../src/core/config/config-loader.js";
import { BountyPilotError } from "../src/utils/errors.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("program config loader", () => {
  it("loads a valid program file", () => {
    const root = createRoot();
    const filePath = path.join(root, "program.yml");
    writeFileSync(filePath, validProgramYaml(), "utf8");

    const loaded = loadProgramFile(filePath);

    expect(loaded.config.program).toBe("loader-test");
    expect(loaded.programFile).toBe(filePath);
  });

  it("reports missing files, directories, oversized files, and malformed YAML with stable codes", () => {
    const root = createRoot();

    expectBountyError(() => loadProgramFile(path.join(root, "missing.yml")), "PROGRAM_FILE_NOT_FOUND");

    const directoryPath = path.join(root, "config-dir");
    mkdirSync(directoryPath);
    expectBountyError(() => loadProgramFile(directoryPath), "PROGRAM_FILE_NOT_FILE");

    const oversizedPath = path.join(root, "huge.yml");
    writeFileSync(oversizedPath, "x".repeat(MAX_PROGRAM_FILE_BYTES + 1), "utf8");
    expectBountyError(() => loadProgramFile(oversizedPath), "PROGRAM_FILE_TOO_LARGE");

    const malformedPath = path.join(root, "malformed.yml");
    writeFileSync(malformedPath, "program: [", "utf8");
    expectBountyError(() => loadProgramFile(malformedPath), "PROGRAM_YAML_INVALID");
  });

  it("keeps schema validation failures separate from YAML syntax failures", () => {
    const root = createRoot();
    const invalidSchemaPath = path.join(root, "invalid-schema.yml");
    writeFileSync(invalidSchemaPath, "program: loader-test\n", "utf8");

    expectBountyError(() => loadProgramFile(invalidSchemaPath), "PROGRAM_SCHEMA_INVALID");
  });

  it("rejects program names that could escape the workspace", () => {
    const root = createRoot();
    for (const programName of ["../evil", "evil/name", "evil\\name", "C:evil", "   "]) {
      const filePath = path.join(root, `${programName.replace(/[^a-zA-Z0-9]/g, "_") || "blank"}.yml`);
      writeFileSync(filePath, validProgramYaml().replace("loader-test", programName), "utf8");

      expectBountyError(() => loadProgramFile(filePath), "PROGRAM_SCHEMA_INVALID");
    }
  });

  it("rejects bare scope rules with paths instead of silently broadening to host scope", () => {
    const root = createRoot();
    const invalidInScopePath = path.join(root, "invalid-in-scope-path.yml");
    writeFileSync(invalidInScopePath, validProgramYaml().replace('"loader.example"', '"loader.example/app"'), "utf8");
    expectBountyError(() => loadProgramFile(invalidInScopePath), "PROGRAM_SCHEMA_INVALID");

    const invalidOutScopePath = path.join(root, "invalid-out-scope-path.yml");
    writeFileSync(
      invalidOutScopePath,
      validProgramYaml().replace("out_of_scope: []", `out_of_scope:\n  - "loader.example/admin"`),
      "utf8",
    );
    expectBountyError(() => loadProgramFile(invalidOutScopePath), "PROGRAM_SCHEMA_INVALID");
  });

  it("allows explicit URL scope rules with path prefixes", () => {
    const root = createRoot();
    const filePath = path.join(root, "url-path-scope.yml");
    writeFileSync(filePath, validProgramYaml().replace('"loader.example"', '"https://loader.example/app"'), "utf8");

    const loaded = loadProgramFile(filePath);

    expect(loaded.config.in_scope).toEqual(["https://loader.example/app"]);
  });

  it("requires an explicit local authorization file for lab mode", () => {
    const root = createRoot();
    const missingPath = path.join(root, "lab-missing-auth.yml");
    writeFileSync(missingPath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");
    expectBountyError(() => loadProgramFile(missingPath), "LAB_AUTHORIZATION_FILE_NOT_FOUND");

    const validPath = path.join(root, "lab-valid.yml");
    writeFileSync(path.join(root, "lab-authorization.md"), "Authorized local lab owned by researcher.\n", "utf8");
    writeFileSync(validPath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");

    const loaded = loadProgramFile(validPath);

    expect(loaded.config.rules.lab_mode).toBe(true);
    expect(loaded.config.rules.lab_authorization_file).toBe("lab-authorization.md");
  });

  it("rejects lab authorization paths that escape the program directory", () => {
    const root = createRoot();
    const filePath = path.join(root, "lab-escape.yml");
    writeFileSync(filePath, withLabMode(validProgramYaml(), "../authorization.md"), "utf8");

    expectBountyError(() => loadProgramFile(filePath), "PROGRAM_SCHEMA_INVALID");
  });
});

function createRoot(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-config-loader-"));
  roots.push(root);
  return root;
}

function expectBountyError(run: () => void, code: string): void {
  expect(() => run()).toThrow(BountyPilotError);
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(BountyPilotError);
    expect((error as BountyPilotError).code).toBe(code);
  }
}

function validProgramYaml(): string {
  return `program: loader-test
platform: hackerone

in_scope:
  - "loader.example"

out_of_scope: []

rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "100rps"
  browser_crawling: true
  deep_safe_mode: true
  require_human_approval_for_risky_actions: true

accounts:
  required: false
  use_researcher_owned_test_accounts_only: true

evidence:
  screenshots: true
  har: true
  console_logs: true
  dom_snapshot: true
  video: optional
  browser_trace: true
  desktop_screenshots: optional
  mask_secrets: true

integrations: {}
`;
}

function withLabMode(yaml: string, authorizationFile: string): string {
  return yaml.replace(
    "  deep_safe_mode: true\n  require_human_approval_for_risky_actions: true",
    `  deep_safe_mode: true\n  lab_mode: true\n  lab_authorization_file: ${JSON.stringify(authorizationFile)}\n  require_human_approval_for_risky_actions: true`,
  );
}
