import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import YAML from "yaml";
import * as installerRuntime from "../scripts/install-hermes-bountypilot.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distributionRoot = path.join(repoRoot, "hermes", "bountypilot-agent");
const securitySkillsRoot = path.join(distributionRoot, "skills", "security");
const installerPath = path.join(repoRoot, "scripts", "install-hermes-bountypilot.mjs");
const preflightPath = path.join(
  securitySkillsRoot,
  "bountypilot-orchestrate",
  "scripts",
  "preflight.mjs",
);
const reportLintPath = path.join(
  securitySkillsRoot,
  "bountypilot-report",
  "scripts",
  "report-lint.mjs",
);
const reportTemplatePath = path.join(
  securitySkillsRoot,
  "bountypilot-report",
  "templates",
  "hackerone-report.md",
);

const expectedSkillNames = [
  "bountypilot-duplicate-check",
  "bountypilot-evidence",
  "bountypilot-orchestrate",
  "bountypilot-program-intake",
  "bountypilot-recon",
  "bountypilot-report",
  "bountypilot-safety",
  "bountypilot-triage",
  "bountypilot-validate",
].sort();

interface InstallerModule {
  MANAGED_SKILL_NAMES: readonly string[];
  applyManagedEntries(options: {
    sourceRoot?: string;
    profileDir: string;
    profile?: string;
    faultAfterOperations?: number;
  }): Promise<Record<string, unknown>>;
  createInstallPlan(options: {
    sourceRoot?: string;
    profileDir: string;
    profile?: string;
  }): Promise<Record<string, unknown>>;
  resolveHermesProfile(options: {
    profile?: string;
    hermesHome?: string;
    env?: Record<string, string | undefined>;
    platform?: NodeJS.Platform;
    homeDirectory?: string;
  }): { hermesRoot: string; profile: string; profileDir: string };
  validateDistributionSource(sourceRoot?: string): Promise<string>;
  verifyInstallation(options: {
    sourceRoot?: string;
    profileDir: string;
    profile?: string;
  }): Promise<{ ok: boolean; entries: Array<{ relativePath: string; status: string }> }>;
}

const installer = installerRuntime as unknown as InstallerModule;
const tempRoots: string[] = [];

afterEach(() => {
  const tmp = path.resolve(os.tmpdir());
  for (const root of tempRoots.splice(0)) {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(`${tmp}${path.sep}`)) {
      throw new Error(`Refusing to remove non-temporary test path: ${resolved}`);
    }
    rmSync(resolved, { force: true, recursive: true });
  }
});

function makeTempRoot(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-hermes-"));
  tempRoots.push(root);
  return root;
}

function writeText(filePath: string, value: string): void {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, value, "utf8");
}

function runNode(script: string, args: string[]) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    shell: false,
  });
}

function walkFiles(root: string): string[] {
  const files: string[] = [];
  const visit = (current: string) => {
    const stat = lstatSync(current);
    expect(stat.isSymbolicLink(), current).toBe(false);
    if (stat.isDirectory()) {
      for (const name of readdirSync(current).sort()) visit(path.join(current, name));
      return;
    }
    expect(stat.isFile(), current).toBe(true);
    files.push(path.relative(root, current).replaceAll(path.sep, "/"));
  };
  visit(root);
  return files;
}

function makeProfile(homeRoot: string, name = "bugbounty"): string {
  const profileDir = path.join(homeRoot, "profiles", name);
  mkdirSync(profileDir, { recursive: true });
  return profileDir;
}

function validReport(): string {
  return `# Missing authorization check on account export exposes another user's export status

## Summary

An authenticated low-privilege user can provide another test account identifier to the in-scope export-status component and observe that account's sanitized export state. Testing used two researcher-controlled accounts and demonstrated only the bounded authorization mismatch.

## Program and Asset

- Program: acme-security
- Asset: https://portal.example.test
- Endpoint/component: /api/export/status account_id parameter
- Policy source/revision: https://hackerone.com/acme/policy retrieved 2026-07-18T00:00:00Z

## Program Custom Fields

- Program custom fields: Environment=production; Account ownership=two researcher-controlled test accounts

## Weakness

- Weakness: CWE-639
- Rationale: The component accepts a user-controlled account identifier without enforcing ownership for the requesting account.

## Severity

- Rating: Medium
- Method: Program-defined qualitative method
- Vector: Not applicable
- Rationale: The demonstrated result reveals bounded export-status metadata for another controlled account but does not expose exported content.

## Steps to Reproduce

1. Sign in with researcher-controlled test account A and open the export-status component.
2. Replace the account identifier with the identifier of researcher-controlled test account B using the minimal recorded request.
3. Observe the sanitized status value for account B and compare it with evidence item ev-20260718-001.

## Actual Result

The service returns the export-status metadata belonging to controlled account B while the request is authenticated as controlled account A.

## Expected Result

The service should reject an account identifier that is not owned by the authenticated account and return no cross-account status metadata.

## Impact

An authenticated user who already knows another account identifier could learn limited export-state metadata across the account boundary. The evidence does not demonstrate access to export contents, arbitrary identifiers, elevated roles, or unrelated records.

## Evidence

- Evidence ID: ev-20260718-001
- SHA-256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
- Context: Sanitized request and response comparison for the two researcher-controlled test accounts
- Evidence limitations: Account identifiers and session material are redacted; no export content was requested

## Scope and Safety

- Exact program import: yes
- In-scope decision: yes
- Out-of-scope precedence checked: yes
- Validation method: Two researcher-controlled test accounts and one minimal comparison
- Sensitive data extracted: no
- Unexpected target effects: no

## Duplicate-Risk Note

- Checked at: 2026-07-18T00:00:00Z
- Sources checked: local BountyPilot history, the researcher's own authorized records, and public disclosures
- Candidate matches: None found in the accessible sources
- Private visibility: unavailable; private program reports may still exist
- Risk: unknown because the program's private report history is not visible

## Remediation

Enforce server-side ownership on the requested account identifier before loading export state, and add a cross-account authorization regression test.

## Researcher Attestation

- Human validation: pending
- Human submission required: yes
- Agent submitted: no
- Remaining uncertainty: Private duplicate visibility and production implementation details remain unavailable
`;
}

describe("Hermes BountyPilot skill distribution", () => {
  it("ships a strict credential-free manifest and the expected bundle", async () => {
    await expect(installer.validateDistributionSource(distributionRoot)).resolves.toBe(
      path.resolve(distributionRoot),
    );

    expect(readdirSync(distributionRoot).sort()).toEqual([
      "SOUL.md",
      "distribution.yaml",
      "skill-bundles",
      "skills",
    ]);

    const packageJson = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf8")) as {
      version: string;
      files: string[];
      scripts: Record<string, string>;
    };
    const manifest = YAML.parse(
      readFileSync(path.join(distributionRoot, "distribution.yaml"), "utf8"),
    ) as Record<string, unknown>;
    expect(manifest).toMatchObject({
      name: "bountypilot-agent",
      version: packageJson.version,
      hermes_requires: ">=0.17.0",
      license: "MIT",
    });
    expect(manifest).not.toHaveProperty("env_requires");
    expect(packageJson.files).toContain("hermes");
    expect(packageJson.scripts).toMatchObject({
      "hermes:plan": "node scripts/install-hermes-bountypilot.mjs --dry-run",
      "hermes:install": "node scripts/install-hermes-bountypilot.mjs --apply",
      "hermes:verify": "node scripts/install-hermes-bountypilot.mjs --verify",
    });
    const readme = readFileSync(path.join(repoRoot, "README.md"), "utf8");
    expect(readme).toContain("hermes profile use bugbounty");
    expect(readme).toContain("hermes chat");
    expect(readme).not.toContain("hermes chat -p bugbounty");
    expect(readme).not.toContain("hermes -p bugbounty chat");
    expect(readme).toContain("--name bugbounty");

    const expectedOwned = [
      "SOUL.md",
      "distribution.yaml",
      "skill-bundles/bountypilot.yaml",
      ...expectedSkillNames.map((name) => `skills/security/${name}`),
    ].sort();
    expect((manifest.distribution_owned as string[]).sort()).toEqual(expectedOwned);

    const bundle = YAML.parse(
      readFileSync(path.join(distributionRoot, "skill-bundles", "bountypilot.yaml"), "utf8"),
    ) as { name: string; skills: string[]; instruction: string };
    expect(bundle.name).toBe("bountypilot");
    expect(bundle.skills).toEqual([
      "security/bountypilot-orchestrate",
      "security/bountypilot-safety",
    ]);
    expect(bundle.instruction).toContain("category-qualified");
    expect(bundle.instruction).toContain("zero live");
  });

  it("keeps all nine skills modern, qualified, and free of executable bypasses", () => {
    expect(readdirSync(securitySkillsRoot).sort()).toEqual(expectedSkillNames);
    const requiredSections = [
      "## When to Use",
      "## Prerequisites",
      "## How to Run",
      "## Quick Reference",
      "## Procedure",
      "## Pitfalls",
      "## Verification",
    ];

    for (const skillName of expectedSkillNames) {
      const skillDir = path.join(securitySkillsRoot, skillName);
      const text = readFileSync(path.join(skillDir, "SKILL.md"), "utf8");
      const frontmatter = text.match(/^---\r?\n([\s\S]*?)\r?\n---/)?.[1];
      expect(frontmatter, skillName).toBeTruthy();
      const metadata = YAML.parse(frontmatter ?? "") as { name: string; description: string };
      expect(metadata.name, skillName).toBe(skillName);
      expect(metadata.description.length, skillName).toBeLessThanOrEqual(60);
      expect(metadata.description.endsWith("."), skillName).toBe(true);
      expect(text, skillName).toMatch(/^# .+ Skill$/m);
      expect(text, skillName).not.toMatch(/\b(?:TODO|TBD|FIXME)\b/);

      let lastIndex = -1;
      for (const section of requiredSections) {
        const index = text.indexOf(section);
        expect(index, `${skillName}:${section}`).toBeGreaterThan(lastIndex);
        lastIndex = index;
      }
      const verification = text.slice(text.indexOf("## Verification"));
      expect(verification.match(/```text/g)?.length, skillName).toBe(1);

      const agent = YAML.parse(
        readFileSync(path.join(skillDir, "agents", "openai.yaml"), "utf8"),
      ) as { interface: { default_prompt: string } };
      expect(agent.interface.default_prompt, skillName).toContain(`$${skillName}`);
    }

    const allText = walkFiles(distributionRoot)
      .filter((name) => /\.(?:md|mjs|ya?ml)$/u.test(name))
      .map((name) => readFileSync(path.join(distributionRoot, ...name.split("/")), "utf8"))
      .join("\n");
    expect(allText).not.toMatch(/(?:^|\s)hermes\b[^\n]*(?:\s-z\b|--oneshot\b|--yolo\b)/im);
    expect(allText).not.toMatch(/bounty\b[^\n]*--live\b/i);

    const zeroLiveFiles = [
      path.join(securitySkillsRoot, "bountypilot-validate", "SKILL.md"),
      path.join(
        securitySkillsRoot,
        "bountypilot-validate",
        "references",
        "validation-boundaries.md",
      ),
      path.join(
        securitySkillsRoot,
        "bountypilot-recon",
        "references",
        "recon-boundaries.md",
      ),
      path.join(securitySkillsRoot, "bountypilot-triage", "SKILL.md"),
      path.join(securitySkillsRoot, "bountypilot-duplicate-check", "SKILL.md"),
    ];
    const zeroLiveText = zeroLiveFiles.map((file) => readFileSync(file, "utf8")).join("\n");
    expect(zeroLiveText).not.toMatch(/lifecycle to execute|normal sessions?,?\s+(?:run|execute)|authorized low-risk observation/i);
    expect(zeroLiveText).toMatch(/HUMAN_HANDOFF/);
    expect(zeroLiveText).toContain("Hermes does not execute");
  });

  it("keeps bundled helper scripts local and non-spawning", () => {
    for (const script of [preflightPath, reportLintPath]) {
      const text = readFileSync(script, "utf8");
      expect(text, script).not.toMatch(/node:(?:child_process|http|https|net|tls|dgram)/);
      expect(text, script).not.toMatch(/\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/);
    }
  });
});

describe("Hermes BountyPilot helper behavior", () => {
  it("emits a dry-run plan but blocks every live mode and unsafe target token", () => {
    const base = [
      "--program",
      "acme-security",
      "--stage",
      "recon",
      "--session",
      "normal",
      "--program-imported",
      "--scope-confirmed",
      "--policy-confirmed",
      "--target",
      "https://api.example.test/v1/status",
      "--json",
    ];
    const dryRun = runNode(preflightPath, [...base, "--mode", "dry-run"]);
    expect(dryRun.status, dryRun.stderr).toBe(0);
    const dryResult = JSON.parse(dryRun.stdout) as Record<string, unknown>;
    expect(dryResult).toMatchObject({
      decision: "DRY_RUN",
      mode: "dry-run",
      untrustedClaims: {
        exactProgramImported: true,
        scopeConfirmed: true,
        policyConfirmed: true,
      },
    });
    expect(dryResult.plannedBountyPilotArgv).toEqual([
      "bounty",
      "--program",
      "acme-security",
      "hunt",
      "recon",
      "https://api.example.test/v1/status",
      "--profile",
      "passive",
      "--dry-run",
      "--json",
    ]);

    const live = runNode(preflightPath, [...base, "--mode", "live"]);
    expect(live.status, live.stderr).toBe(0);
    expect(JSON.parse(live.stdout)).toMatchObject({
      decision: "BLOCK",
      plannedBountyPilotArgv: null,
    });

    const unsafe = runNode(preflightPath, [
      ...base.slice(0, -2),
      "https://api.example.test/v1/status?next=x&cmd=y",
      "--json",
      "--mode",
      "dry-run",
    ]);
    expect(unsafe.status).toBe(2);
    expect(unsafe.stderr).toMatch(/query|shell-safe/i);
  });

  it("rejects unresolved report templates and accepts a completed canonical report", () => {
    const template = runNode(reportLintPath, ["--file", reportTemplatePath, "--json"]);
    expect(template.status).toBe(1);
    const templateResult = JSON.parse(template.stdout) as {
      ok: boolean;
      errors: Array<{ code: string }>;
    };
    expect(templateResult.ok).toBe(false);
    expect(templateResult.errors.map((error) => error.code)).toContain("PLACEHOLDER");

    const root = makeTempRoot();
    const completedPath = path.join(root, "completed-report.md");
    writeText(completedPath, validReport());
    const completed = runNode(reportLintPath, ["--file", completedPath, "--json"]);
    expect(completed.status, completed.stdout + completed.stderr).toBe(0);
    expect(JSON.parse(completed.stdout)).toMatchObject({ ok: true, errors: [] });

    const selfAttestedPath = path.join(root, "self-attested-report.md");
    writeText(
      selfAttestedPath,
      validReport().replace("- Human validation: pending", "- Human validation: yes"),
    );
    const selfAttested = runNode(reportLintPath, ["--file", selfAttestedPath, "--json"]);
    expect(selfAttested.status).toBe(1);
    expect(
      (JSON.parse(selfAttested.stdout) as { errors: Array<{ code: string }> }).errors.map(
        (error) => error.code,
      ),
    ).toContain("HUMAN_VALIDATION_PENDING");
  });
});

describe("Hermes BountyPilot safe merge installer", () => {
  it("plans without mutation, preserves profile canaries, backs up conflicts, and is idempotent", async () => {
    const root = makeTempRoot();
    const home = path.join(root, "Hermes Home With Spaces");
    const profileDir = makeProfile(home);
    const otherProfile = makeProfile(home, "other");
    const canaries = new Map<string, string>([
      [path.join(profileDir, ".env"), "ENV_CANARY_71d0"],
      [path.join(profileDir, "auth.json"), "AUTH_CANARY_71d0"],
      [path.join(profileDir, "config.yaml"), "CONFIG_CANARY_71d0"],
      [path.join(profileDir, "SOUL.md"), "SOUL_CANARY_71d0"],
      [path.join(profileDir, "skills", "personal", "unrelated", "SKILL.md"), "SKILL_CANARY_71d0"],
      [path.join(profileDir, "skill-bundles", "unrelated.yaml"), "name: unrelated\nskills: [personal/unrelated]\n"],
      [path.join(otherProfile, ".env"), "OTHER_PROFILE_CANARY_71d0"],
    ]);
    for (const [filePath, value] of canaries) writeText(filePath, value);

    const conflictPath = path.join(
      profileDir,
      "skills",
      "security",
      expectedSkillNames[0],
      "SKILL.md",
    );
    writeText(conflictPath, "OLD_MANAGED_SKILL_71d0");
    const legacyPath = path.join(profileDir, "skill-bundles", "bountypilot.yml");
    writeText(legacyPath, "name: bountypilot\nskills: [legacy]\n");

    const plan = await installer.createInstallPlan({ profileDir });
    expect(plan.mode).toBe("plan");
    expect(plan.changeCount).toBe(11);
    expect(existsSync(path.join(profileDir, "local"))).toBe(false);
    expect(readFileSync(conflictPath, "utf8")).toBe("OLD_MANAGED_SKILL_71d0");

    const cliPlan = spawnSync(
      process.execPath,
      [installerPath, "--dry-run", "--json", "--hermes-home", home, "--profile", "bugbounty"],
      { cwd: repoRoot, encoding: "utf8", shell: false },
    );
    expect(cliPlan.status, cliPlan.stderr).toBe(0);
    for (const value of canaries.values()) expect(cliPlan.stdout).not.toContain(value);
    expect(cliPlan.stdout).not.toContain(root);

    const applied = await installer.applyManagedEntries({ profileDir });
    expect(applied).toMatchObject({ changed: true, mode: "apply", verified: true });
    for (const [filePath, value] of canaries) expect(readFileSync(filePath, "utf8")).toBe(value);
    expect(existsSync(legacyPath)).toBe(false);

    const backupRoot = applied.backupRoot as string;
    expect(readFileSync(path.join(backupRoot, "skills", "security", expectedSkillNames[0], "SKILL.md"), "utf8")).toBe(
      "OLD_MANAGED_SKILL_71d0",
    );
    expect(readFileSync(path.join(backupRoot, "skill-bundles", "bountypilot.yml"), "utf8")).toContain(
      "legacy",
    );

    const installedSkill = path.join(profileDir, "skills", "security", expectedSkillNames[0], "SKILL.md");
    const installedMtime = statSync(installedSkill).mtimeMs;
    const backupRuns = readdirSync(path.join(profileDir, "local", "bountypilot-agent", "backups")).sort();
    const second = await installer.applyManagedEntries({ profileDir });
    expect(second).toMatchObject({ changed: false, changeCount: 0, verified: true });
    expect(statSync(installedSkill).mtimeMs).toBe(installedMtime);
    expect(readdirSync(path.join(profileDir, "local", "bountypilot-agent", "backups")).sort()).toEqual(
      backupRuns,
    );

    await expect(installer.verifyInstallation({ profileDir })).resolves.toMatchObject({ ok: true });
    writeText(installedSkill, `${readFileSync(installedSkill, "utf8")}\nDRIFT\n`);
    await expect(installer.verifyInstallation({ profileDir })).resolves.toMatchObject({ ok: false });
  });

  it("rolls back an injected failure and rejects type conflicts before mutation", async () => {
    const root = makeTempRoot();
    const rollbackProfile = makeProfile(path.join(root, "rollback-home"));
    const firstManaged = expectedSkillNames[0];
    const originalPath = path.join(
      rollbackProfile,
      "skills",
      "security",
      firstManaged,
      "SKILL.md",
    );
    writeText(originalPath, "ROLLBACK_ORIGINAL_8f3c");

    await expect(
      installer.applyManagedEntries({
        profileDir: rollbackProfile,
        faultAfterOperations: 2,
      }),
    ).rejects.toThrow("Injected installer fault");
    expect(readFileSync(originalPath, "utf8")).toBe("ROLLBACK_ORIGINAL_8f3c");
    expect(
      existsSync(path.join(rollbackProfile, "skills", "security", expectedSkillNames[1])),
    ).toBe(false);

    const conflictProfile = makeProfile(path.join(root, "conflict-home"));
    const conflictTarget = path.join(
      conflictProfile,
      "skills",
      "security",
      firstManaged,
    );
    writeText(conflictTarget, "FILE_WHERE_DIRECTORY_IS_REQUIRED");
    await expect(installer.createInstallPlan({ profileDir: conflictProfile })).rejects.toThrow(
      /type|directory/i,
    );
    expect(existsSync(path.join(conflictProfile, "local"))).toBe(false);
  });

  it("normalizes profile-scoped homes, blocks slug collisions, and rejects links when supported", async () => {
    const root = makeTempRoot();
    const home = path.join(root, "home");
    const profileDir = makeProfile(home);
    expect(installer.resolveHermesProfile({ hermesHome: profileDir, profile: "bugbounty" })).toMatchObject({
      hermesRoot: path.resolve(home),
      profile: "bugbounty",
      profileDir: path.resolve(profileDir),
    });
    expect(() => installer.resolveHermesProfile({ hermesHome: home, profile: "../escape" })).toThrow(
      /invalid/i,
    );

    writeText(
      path.join(profileDir, "skill-bundles", "renamed.yaml"),
      "name: bountypilot\nskills: [personal/example]\n",
    );
    await expect(installer.createInstallPlan({ profileDir })).rejects.toThrow(/reserved bountypilot slug/i);

    rmSync(path.join(profileDir, "skill-bundles", "renamed.yaml"));
    const external = path.join(root, "external");
    mkdirSync(external);
    const linkedTarget = path.join(profileDir, "skills", "security", expectedSkillNames[0]);
    mkdirSync(path.dirname(linkedTarget), { recursive: true });
    let linkCreated = false;
    try {
      symlinkSync(external, linkedTarget, process.platform === "win32" ? "junction" : "dir");
      linkCreated = true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (!new Set(["EPERM", "EACCES", "ENOTSUP"]).has(code ?? "")) throw error;
    }
    if (linkCreated) {
      await expect(installer.createInstallPlan({ profileDir })).rejects.toThrow(/symbolic link|junction/i);
    }
  });
});
