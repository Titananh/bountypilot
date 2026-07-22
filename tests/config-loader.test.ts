import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  loadProgramFile,
  MAX_LAB_AUTHORIZATION_FILE_BYTES,
  MAX_PROGRAM_FILE_BYTES,
  type LabAuthorizationFileAccess,
} from "../src/core/config/config-loader.js";
import { BountyPilotError } from "../src/utils/errors.js";

const roots: string[] = [];

// Probe the platform symlink capability exactly once per test file. Caching
// avoids spawning a throwaway temp directory before every symlink test, which
// would otherwise make the suite noisier on Windows hosts that lack
// SeCreateSymbolicLinkPrivilege (developer mode not enabled).
let symlinkCapability: boolean | undefined;
function canCreateSymlink(): boolean {
  if (symlinkCapability !== undefined) return symlinkCapability;
  const probeDir = mkdtempSync(path.join(os.tmpdir(), "bountypilot-config-loader-symlink-probe-"));
  const target = path.join(probeDir, "target.txt");
  const link = path.join(probeDir, "link");
  writeFileSync(target, "x", "utf8");
  try {
    try {
      symlinkSync(target, link, "file");
      rmSync(link);
      symlinkCapability = true;
      return true;
    } catch {
      symlinkCapability = false;
      return false;
    }
  } finally {
    rmSync(probeDir, { recursive: true, force: true });
  }
}

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
    expect(loaded.labAuthorization).toBeNull();
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
    const noPath = path.join(root, "lab-no-auth-path.yml");
    writeFileSync(noPath, withLabModeWithoutAuthorization(validProgramYaml()), "utf8");
    expectBountyError(() => loadProgramFile(noPath), "LAB_AUTHORIZATION_FILE_REQUIRED");

    const missingPath = path.join(root, "lab-missing-auth.yml");
    writeFileSync(missingPath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");
    expectBountyError(() => loadProgramFile(missingPath), "LAB_AUTHORIZATION_FILE_NOT_FOUND");

    const validPath = path.join(root, "lab-valid.yml");
    const authorizationBytes = Buffer.from("Authorized local lab owned by researcher.\n", "utf8");
    writeFileSync(path.join(root, "lab-authorization.md"), authorizationBytes);
    writeFileSync(validPath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");

    const loaded = loadProgramFile(validPath);

    expect(loaded.config.rules.lab_mode).toBe(true);
    expect(loaded.config.rules.lab_authorization_file).toBe("lab-authorization.md");
    expect(loaded.labAuthorization).toEqual({
      relativePath: "lab-authorization.md",
      byteLength: authorizationBytes.byteLength,
      contentSha256: createHash("sha256").update(authorizationBytes).digest("hex"),
    });
  });

  it("reads lab authorization bytes once through loadProgramFile and returns metadata from that same Buffer", () => {
    const root = createRoot();
    const filePath = path.join(root, "lab-read-once.yml");
    writeFileSync(filePath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");
    const bytes = Buffer.from([0x41, 0x00, 0x0d, 0x0a, 0xff, 0x42]);
    let reads = 0;
    const access: LabAuthorizationFileAccess = {
      realpath: (candidate) => path.resolve(candidate),
      readUpTo: (_candidate, maxBytes) => {
        reads += 1;
        expect(maxBytes).toBe(MAX_LAB_AUTHORIZATION_FILE_BYTES + 1);
        return bytes;
      },
    };

    const loaded = loadProgramFile(filePath, access);
    expect(reads).toBe(1);
    expect(loaded.labAuthorization).toEqual({
      relativePath: "lab-authorization.md",
      byteLength: bytes.byteLength,
      contentSha256: createHash("sha256").update(bytes).digest("hex"),
    });
  });

  it("rejects lab authorization paths that escape the program directory", () => {
    const root = createRoot();
    const filePath = path.join(root, "lab-escape.yml");
    writeFileSync(filePath, withLabMode(validProgramYaml(), "../authorization.md"), "utf8");

    expectBountyError(() => loadProgramFile(filePath), "PROGRAM_SCHEMA_INVALID");
  });

  it("rejects an on-disk lab authorization file larger than the cap", () => {
    const root = createRoot();
    const authRelative = "lab-authorization.md";
    const authPath = path.join(root, authRelative);
    const payload = "A".repeat(MAX_LAB_AUTHORIZATION_FILE_BYTES + 1);
    writeFileSync(authPath, payload, "utf8");
    const filePath = path.join(root, "lab-oversize.yml");
    writeFileSync(filePath, withLabMode(validProgramYaml(), authRelative), "utf8");

    const error = expectBountyError(() => loadProgramFile(filePath), "LAB_AUTHORIZATION_FILE_TOO_LARGE");
    expect(error.message).not.toContain(root);
  });

  it.runIf(canCreateSymlink())(
    "rejects lab authorization symlinks whose real path escapes the program directory",
    () => {
      // The lab authorization file is presented as a relative path inside
      // the program directory, but the entry is a symlink that resolves to
      // a file outside the program workspace. The loader must reject the
      // escape via realpath containment.
      const root = createRoot();
      const outsideRoot = mkdtempSync(path.join(os.tmpdir(), "bountypilot-config-loader-outside-"));
      roots.push(outsideRoot);
      const realAuth = path.join(outsideRoot, "real-authorization.md");
      writeFileSync(realAuth, "owned by attacker\n", "utf8");
      const linkPath = path.join(root, "lab-authorization.md");
      symlinkSync(realAuth, linkPath, "file");
      const filePath = path.join(root, "lab-symlink.yml");
      writeFileSync(filePath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");

      const error = expectBountyError(() => loadProgramFile(filePath), "LAB_AUTHORIZATION_FILE_SYMLINK_ESCAPE");
      expect(error.message).not.toContain(root);
      expect(error.message).not.toContain(outsideRoot);
    },
  );

  it.runIf(canCreateSymlink())(
    "rejects a nested directory symlink whose resolved authorization file escapes the program directory",
    () => {
      const root = createRoot();
      const outsideRoot = createRoot();
      writeFileSync(path.join(outsideRoot, "authorization.md"), "outside\n", "utf8");
      symlinkSync(outsideRoot, path.join(root, "notes"), "junction");
      const filePath = path.join(root, "lab-nested-symlink.yml");
      writeFileSync(filePath, withLabMode(validProgramYaml(), "notes/authorization.md"), "utf8");

      const error = expectBountyError(() => loadProgramFile(filePath), "LAB_AUTHORIZATION_FILE_SYMLINK_ESCAPE");
      expect(error.message).not.toContain(root);
      expect(error.message).not.toContain(outsideRoot);
    },
  );

  it("rejects cross-platform drive-relative and ADS-like authorization paths before filesystem access", () => {
    const root = createRoot();
    for (const unsafePath of ["C:relative-note.md", "authorization.md:stream"]) {
      const filePath = path.join(root, `lab-invalid-${unsafePath.replace(/[^a-z0-9]/gi, "_")}.yml`);
      writeFileSync(filePath, withLabMode(validProgramYaml(), unsafePath), "utf8");
      expectBountyError(() => loadProgramFile(filePath), "LAB_AUTHORIZATION_FILE_PATH_INVALID");
    }
  });

  it("rejects a lab authorization directory without exposing its absolute path", () => {
    const root = createRoot();
    mkdirSync(path.join(root, "authorization-note"));
    const filePath = path.join(root, "lab-directory.yml");
    writeFileSync(filePath, withLabMode(validProgramYaml(), "authorization-note"), "utf8");
    const error = expectBountyError(() => loadProgramFile(filePath), "LAB_AUTHORIZATION_FILE_NOT_FILE");
    expect(error.message).not.toContain(root);
  });

  it("treats lab_authorization_file as a normal relative path when lab_mode stays false", () => {
    // The schema makes lab_mode the toggle that turns authorization
    // enforcement on. When lab_mode stays false, a relative
    // lab_authorization_file pointing at a real file must still load the
    // program without surfacing LAB_AUTHORIZATION_FILE_REQUIRED, so config
    // authors can keep an unused pointer to a research note around without
    // breaking unrelated jobs.
    const root = createRoot();
    const authRelative = "lab-authorization.md";
    const authorizationBytes = Buffer.from("Authorized local lab owned by researcher.\n", "utf8");
    writeFileSync(path.join(root, authRelative), authorizationBytes);
    const filePath = path.join(root, "lab-off.yml");
    writeFileSync(
      filePath,
      withLabModeOff(validProgramYaml(), authRelative),
      "utf8",
    );

    const loaded = loadProgramFile(filePath);

    // The contract for this test is the loader's behaviour: a config with
    // lab_mode: false plus a real lab_authorization_file must load
    // successfully and the relative path must round-trip into the parsed
    // config without error.
    expect(loaded.config.rules.lab_mode).toBe(false);
    expect(loaded.config.rules.lab_authorization_file).toBe(authRelative);
    expect(loaded.labAuthorization).toEqual({
      relativePath: authRelative,
      byteLength: authorizationBytes.byteLength,
      contentSha256: createHash("sha256").update(authorizationBytes).digest("hex"),
    });
  });

  it("returns the stable LAB_AUTHORIZATION_FILE_NOT_FOUND code when lab_mode is on and the file is missing", () => {
    // A focused pin for the missing-file stable code so that future
    // refactors of the error handling cannot accidentally generalize the
    // code into a generic read failure.
    const root = createRoot();
    const missingPath = path.join(root, "lab-missing-only.yml");
    writeFileSync(missingPath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");

    const error = expectBountyError(() => loadProgramFile(missingPath), "LAB_AUTHORIZATION_FILE_NOT_FOUND");
    expect(error.message).not.toContain(root);
  });

  it("accepts a safe relative lab_authorization_file with a leading ./ segment and returns normalized metadata", () => {
    // ProgramSchema rejects paths containing ".." or absolute prefixes, but
    // a leading "./" is a normal form of a relative path. The loader must
    // resolve and read through it without complaint.
    const root = createRoot();
    const authRelative = "./notes/lab-authorization.md";
    const authDir = path.join(root, "notes");
    mkdirSync(authDir);
    const authorizationBytes = Buffer.from("Authorized local lab owned by researcher.\n", "utf8");
    writeFileSync(path.join(authDir, "lab-authorization.md"), authorizationBytes);
    const filePath = path.join(root, "lab-normalized.yml");
    writeFileSync(filePath, withLabMode(validProgramYaml(), authRelative), "utf8");

    const loaded = loadProgramFile(filePath);

    expect(loaded.config.rules.lab_mode).toBe(true);
    expect(loaded.config.rules.lab_authorization_file).toBe(authRelative);
    expect(loaded.labAuthorization).toEqual({
      relativePath: "notes/lab-authorization.md",
      byteLength: authorizationBytes.byteLength,
      contentSha256: createHash("sha256").update(authorizationBytes).digest("hex"),
    });
  });

  it.runIf(canCreateSymlink())(
    "allows an intra-workspace symlinked lab authorization file when the real path stays inside the program directory",
    () => {
      // A safe nested symlink must not be misclassified as an escape. The
      // lab-authorization.md entry is a symlink that points at a real file
      // located in the same program directory; only files whose real path
      // resolves outside the program workspace must be rejected.
      const root = createRoot();
      const realAuth = path.join(root, "real-authorization.md");
      writeFileSync(realAuth, "Authorized local lab owned by researcher.\n", "utf8");
      const linkPath = path.join(root, "lab-authorization.md");
      symlinkSync(realAuth, linkPath, "file");
      const filePath = path.join(root, "lab-intra-symlink.yml");
      writeFileSync(filePath, withLabMode(validProgramYaml(), "lab-authorization.md"), "utf8");

      const loaded = loadProgramFile(filePath);

      expect(loaded.config.rules.lab_mode).toBe(true);
      expect(loaded.config.rules.lab_authorization_file).toBe("lab-authorization.md");
      expect(loaded.labAuthorization?.relativePath).toBe("lab-authorization.md");
    },
  );
});

function createRoot(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-config-loader-"));
  roots.push(root);
  return root;
}

function expectBountyError(run: () => void, code: string): BountyPilotError {
  let thrown: unknown;
  try {
    run();
  } catch (error) {
    thrown = error;
  }
  expect(thrown, "expected function to throw").toBeInstanceOf(BountyPilotError);
  expect((thrown as BountyPilotError).code).toBe(code);
  return thrown as BountyPilotError;
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

function withLabModeOff(yaml: string, authorizationFile: string): string {
  return yaml.replace(
    "  deep_safe_mode: true\n  require_human_approval_for_risky_actions: true",
    `  deep_safe_mode: true\n  lab_mode: false\n  lab_authorization_file: ${JSON.stringify(authorizationFile)}\n  require_human_approval_for_risky_actions: true`,
  );
}

function withLabModeWithoutAuthorization(yaml: string): string {
  return yaml.replace(
    "  deep_safe_mode: true\n  require_human_approval_for_risky_actions: true",
    "  deep_safe_mode: true\n  lab_mode: true\n  require_human_approval_for_risky_actions: true",
  );
}
