import { spawnSync } from "node:child_process";
import {
  cpSync,
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

interface ProfileSafetyConfig {
  delegation: {
    max_iterations: number;
    max_concurrent_children: number;
    max_spawn_depth: number;
    orchestrator_enabled: boolean;
    child_timeout_seconds: number;
  };
  agent: {
    disabled_toolsets: string[];
    operator_note?: string;
  };
  terminal: {
    backend: string;
    cwd: string;
    home_mode: string;
    docker_network: boolean;
    docker_mount_cwd_to_workspace: boolean;
    docker_persist_across_processes: boolean;
    container_persistent: boolean;
    docker_forward_env: string[];
    env_passthrough: string[];
    command_timeout_seconds?: number;
  };
  approvals: {
    mode: string;
    cron_mode: string;
  };
  security: {
    allow_lazy_installs: boolean;
  };
  operator_metadata?: {
    canary: string;
  };
}

function safeProfileConfigObject(canary = "PROFILE_CONFIG_CANARY_SAFE"): ProfileSafetyConfig {
  return {
    delegation: {
      max_iterations: 30,
      max_concurrent_children: 3,
      max_spawn_depth: 1,
      orchestrator_enabled: true,
      child_timeout_seconds: 1800,
    },
    agent: {
      disabled_toolsets: [
        "web",
        "browser",
        "mcp",
        "delegation",
        "cronjob",
        "messaging",
        "homeassistant",
        "code_execution",
        "unrelated-local-toolset",
      ],
      operator_note: "unrelated profile-owned key",
    },
    terminal: {
      backend: "docker",
      cwd: "/workspace",
      home_mode: "profile",
      docker_network: false,
      docker_mount_cwd_to_workspace: true,
      docker_persist_across_processes: false,
      container_persistent: false,
      docker_forward_env: [],
      env_passthrough: [],
      command_timeout_seconds: 900,
    },
    approvals: {
      mode: "manual",
      cron_mode: "deny",
    },
    security: {
      allow_lazy_installs: false,
    },
    operator_metadata: { canary },
  };
}

function safeProfileConfig(canary?: string): string {
  return YAML.stringify(safeProfileConfigObject(canary));
}

function makeProfile(homeRoot: string, name = "bugbounty"): string {
  const profileDir = path.join(homeRoot, "profiles", name);
  mkdirSync(profileDir, { recursive: true });
  writeText(path.join(profileDir, "config.yaml"), safeProfileConfig());
  writeText(path.join(profileDir, "SOUL.md"), "PROFILE_SOUL_CANARY_SAFE\n");
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
  it.each([
    { relativePath: "README.md", directory: false },
    { relativePath: "credentials", directory: true },
    { relativePath: path.join("skills", "personal"), directory: true },
  ])("rejects unexpected copied distribution entry $relativePath", async ({ relativePath, directory }) => {
    const root = makeTempRoot();
    const copied = path.join(root, "distribution");
    cpSync(distributionRoot, copied, { recursive: true });
    const unexpected = path.join(copied, relativePath);
    if (directory) {
      mkdirSync(unexpected, { recursive: true });
    } else {
      writeText(unexpected, "UNEXPECTED_DISTRIBUTION_ENTRY");
    }

    await expect(installer.validateDistributionSource(copied)).rejects.toThrow(
      /unexpected top-level entry|exactly the security skill category/i,
    );
  });

  it("ships a strict credential-free manifest and the expected bundle", async () => {
    await expect(installer.validateDistributionSource(distributionRoot)).resolves.toBe(
      path.resolve(distributionRoot),
    );

    for (const entry of ["SOUL.md", "config.yaml", "distribution.yaml", "skill-bundles", "skills"]) {
      expect(existsSync(path.join(distributionRoot, entry)), entry).toBe(true);
    }

    const packageJson = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf8")) as {
      version: string;
      bin: Record<string, string>;
      files: string[];
      scripts: Record<string, string>;
    };
    const manifest = YAML.parse(
      readFileSync(path.join(distributionRoot, "distribution.yaml"), "utf8"),
    ) as Record<string, unknown>;
    expect(packageJson.version).toBe("0.2.0");
    expect(manifest).toMatchObject({
      name: "bountypilot-agent",
      version: "0.2.0",
      hermes_requires: ">=0.17.0",
      license: "MIT",
    });
    expect(manifest).not.toHaveProperty("env_requires");
    expect(packageJson.files).toEqual([
      "dist",
      "examples",
      "hermes",
      "skills",
      "scripts",
      "README.md",
    ]);
    expect(packageJson.bin).toMatchObject({
      "bountypilot-hermes": "./scripts/install-hermes-bountypilot.mjs",
    });
    expect(packageJson.scripts).toMatchObject({
      "hermes:plan": "node scripts/install-hermes-bountypilot.mjs --dry-run",
      "hermes:install": "node scripts/install-hermes-bountypilot.mjs --apply",
      "hermes:verify": "node scripts/install-hermes-bountypilot.mjs --verify",
    });
    const readme = readFileSync(path.join(repoRoot, "README.md"), "utf8");
    expect(readme).toContain("hermes profile use bugbounty");
    expect(readme).toContain("hermes chat");
    expect(readme).toContain("npm install -g .");
    expect(readme).toContain("bounty --version");
    expect(readme).toContain("codex/hermes-bountypilot-agent");
    expect(readme).toContain("The current v1 receipt is terminal for Hermes");
    expect(readme).not.toContain("hermes chat -p bugbounty");
    expect(readme).not.toContain("hermes -p bugbounty chat");
    expect(readme).toContain("--name bugbounty");
    expect(readme).not.toMatch(/hermes profile install\s+github\.com\//i);
    expect(readme).not.toMatch(/repository root is an installable Hermes/i);
    expect(readme).not.toMatch(/profile manifest is at the repository root/i);

    const expectedOwned = [
      "SOUL.md",
      "config.yaml",
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

    const rootDistributionFiles = [
      path.join(distributionRoot, "SOUL.md"),
      path.join(distributionRoot, "config.yaml"),
      path.join(distributionRoot, "distribution.yaml"),
      path.join(distributionRoot, "skill-bundles", "bountypilot.yaml"),
    ];
    const skillDistributionFiles = walkFiles(securitySkillsRoot)
      .filter((name) => /\.(?:md|mjs|ya?ml)$/u.test(name))
      .map((name) => path.join(securitySkillsRoot, ...name.split("/")));
    const allText = [...rootDistributionFiles, ...skillDistributionFiles]
      .map((file) => readFileSync(file, "utf8"))
      .join("\n");
    expect(allText).not.toMatch(/(?:^|\s)hermes\b[^\n]*(?:\s-z\b|--oneshot\b|--yolo\b)/im);
    expect(allText).not.toMatch(/bounty\b[^\n]*--live\b/i);
    expect(allText).not.toMatch(/after (?:a|the) (?:valid )?mission receipt[^\n]*delegate/i);

    const orchestratorText = readFileSync(
      path.join(securitySkillsRoot, "bountypilot-orchestrate", "SKILL.md"),
      "utf8",
    );
    expect(orchestratorText).toContain("Require exactly `0.2.0`");
    expect(orchestratorText).toContain("`agentTerminal` is `true`");
    expect(orchestratorText).toContain("`workflow.reportsDrafted: 0`");
    expect(orchestratorText).toMatch(/Do not call\s+`delegate_task`/);
    expect(orchestratorText).not.toMatch(/may write one local draft after/i);

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
  it("emits exactly one typed one-request mission argv and no legacy stage command", () => {
    const base = [
      "--program",
      "acme-security",
      "--target",
      "https://api.example.test/v1/status",
      "--goal",
      "local-report-draft",
      "--profile",
      "recon",
      "--session",
      "normal",
      "--json",
    ];
    const planned = runNode(preflightPath, base);
    expect(planned.status, planned.stderr).toBe(0);
    const result = JSON.parse(planned.stdout) as Record<string, unknown>;
    expect(result.plannedBountyPilotArgv).toEqual([
      "bounty",
      "--program",
      "acme-security",
      "mission",
      "start",
      "--goal",
      "local-report-draft",
      "--profile",
      "recon",
      "--session",
      "normal",
      "--target",
      "https://api.example.test/v1/status",
      "--json",
    ]);
    const argvFields = Object.entries(result).filter(
      ([key, value]) => /argv/i.test(key) && Array.isArray(value),
    );
    expect(argvFields).toEqual([["plannedBountyPilotArgv", result.plannedBountyPilotArgv]]);

    const serialized = JSON.stringify(result);
    expect(result.invariants).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/generic human_handoff receipt/i),
        expect.stringMatching(/proves no bug, finding, evidence, validation, or report/i),
      ]),
    );
    expect(serialized).not.toContain("human_action_handoff");
    for (const forbidden of [
      "--program-imported",
      "--scope-confirmed",
      "--policy-confirmed",
      '"untrustedClaims"',
      '"stage"',
      '"mode"',
      '"finding"',
      '"prompt"',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    const argv = result.plannedBountyPilotArgv as string[];
    expect(argv.slice(argv.indexOf("mission"), argv.indexOf("mission") + 2)).toEqual([
      "mission",
      "start",
    ]);
    expect(argv).not.toContain("hunt");
    expect(argv).not.toContain("programs");
    expect(argv).not.toContain("reproduce");
    expect(argv).not.toContain("triage");
    expect(argv).not.toContain("reports");
  });

  it.each(["normal", "one-shot", "yolo", "approval-bypassed"])(
    "keeps the %s session in the same zero-live, zero-submit typed mission contract",
    (session) => {
      const run = runNode(preflightPath, [
        "--program",
        "acme-security",
        "--target",
        "https://api.example.test/v1/status",
        "--goal",
        "local-report-draft",
        "--profile",
        "recon",
        "--session",
        session,
        "--json",
      ]);
      expect(run.status, run.stderr).toBe(0);
      const result = JSON.parse(run.stdout) as {
        missionRequest: {
          constraints: { liveTargetEffects: boolean; automaticSubmission: boolean };
        };
        plannedBountyPilotArgv: string[];
      };
      expect(result.missionRequest.constraints).toEqual({
        liveTargetEffects: false,
        automaticSubmission: false,
      });
      expect(result.plannedBountyPilotArgv).toContain(session);
      expect(result.plannedBountyPilotArgv).not.toContain("--live");
      expect(result.plannedBountyPilotArgv).not.toContain("submit");
    },
  );

  it.each([
    { forbidden: ["--program-imported"] },
    { forbidden: ["--scope-confirmed"] },
    { forbidden: ["--policy-confirmed"] },
    { forbidden: ["--stage", "recon"] },
    { forbidden: ["--mode", "dry-run"] },
    { forbidden: ["--finding", "finding-1"] },
    { forbidden: ["--live"] },
  ])("rejects obsolete or untrusted preflight vector $forbidden", ({ forbidden }) => {
    const run = runNode(preflightPath, [
      "--program",
      "acme-security",
      "--target",
      "https://api.example.test/v1/status",
      "--goal",
      "local-report-draft",
      "--profile",
      "recon",
      "--session",
      "normal",
      ...forbidden,
      "--json",
    ]);
    expect(run.status).toBe(2);
    expect(run.stdout).not.toContain("plannedBountyPilotArgv");
    expect(run.stderr).toMatch(/unknown|unsupported|unexpected/i);
  });

  it.each([
    ["--goal", "find-and-submit-everything"],
    ["--profile", "lab-aggressive"],
    ["--profile", "safe-checks,playwright"],
  ])("rejects arbitrary mission semantics %j", (replacement) => {
    const args = [
      "--program",
      "acme-security",
      "--target",
      "https://api.example.test/v1/status",
      "--goal",
      "local-report-draft",
      "--profile",
      "recon",
      "--session",
      "normal",
      "--json",
    ];
    const index = args.indexOf(replacement[0]!);
    args[index + 1] = replacement[1]!;
    const run = runNode(preflightPath, args);
    expect(run.status).toBe(2);
    expect(run.stdout).not.toContain("plannedBountyPilotArgv");
  });

  it("rejects a bare hostname target", () => {
    const run = runNode(preflightPath, [
      "--program",
      "acme-security",
      "--target",
      "api.example.test",
      "--goal",
      "local-report-draft",
      "--profile",
      "recon",
      "--session",
      "normal",
      "--json",
    ]);
    expect(run.status).toBe(2);
    expect(run.stdout).not.toContain("plannedBountyPilotArgv");
    expect(run.stderr).toMatch(/absolute HTTP\(S\) URL/i);
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
      [path.join(profileDir, "config.yaml"), safeProfileConfig("CONFIG_CANARY_71d0")],
      [path.join(profileDir, "SOUL.md"), "SOUL_CANARY_71d0\n"],
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
    expect(cliPlan.stdout).not.toContain("CONFIG_CANARY_71d0");
    expect(cliPlan.stdout).not.toContain("SOUL_CANARY_71d0");
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

  const unsafeProfileCases: Array<{
    label: string;
    mutate: (config: ProfileSafetyConfig) => void;
  }> = [
    {
      label: "a required disabled toolset is absent",
      mutate: (config) => {
        config.agent.disabled_toolsets = config.agent.disabled_toolsets.filter(
          (toolset) => toolset !== "web",
        );
      },
    },
    {
      label: "delegation iteration bound drifts",
      mutate: (config) => {
        config.delegation.max_iterations = 31;
      },
    },
    {
      label: "delegation concurrency bound drifts",
      mutate: (config) => {
        config.delegation.max_concurrent_children = 4;
      },
    },
    {
      label: "delegation depth bound drifts",
      mutate: (config) => {
        config.delegation.max_spawn_depth = 2;
      },
    },
    {
      label: "delegation orchestrator is disabled",
      mutate: (config) => {
        config.delegation.orchestrator_enabled = false;
      },
    },
    {
      label: "delegation child timeout drifts",
      mutate: (config) => {
        config.delegation.child_timeout_seconds = 1801;
      },
    },
    {
      label: "terminal backend is local",
      mutate: (config) => {
        config.terminal.backend = "local";
      },
    },
    {
      label: "terminal working directory exposes a host path",
      mutate: (config) => {
        config.terminal.cwd = "/host/workspace";
      },
    },
    {
      label: "terminal home mode is not profile-isolated",
      mutate: (config) => {
        config.terminal.home_mode = "host";
      },
    },
    {
      label: "Docker networking is enabled",
      mutate: (config) => {
        config.terminal.docker_network = true;
      },
    },
    {
      label: "workspace mount is disabled",
      mutate: (config) => {
        config.terminal.docker_mount_cwd_to_workspace = false;
      },
    },
    {
      label: "Docker process persistence is enabled",
      mutate: (config) => {
        config.terminal.docker_persist_across_processes = true;
      },
    },
    {
      label: "container persistence is enabled",
      mutate: (config) => {
        config.terminal.container_persistent = true;
      },
    },
    {
      label: "an environment variable is forwarded",
      mutate: (config) => {
        config.terminal.docker_forward_env = ["SECRET_CANARY_FORWARD"];
      },
    },
    {
      label: "an environment variable is passed through",
      mutate: (config) => {
        config.terminal.env_passthrough = ["SECRET_CANARY_PASSTHROUGH"];
      },
    },
    {
      label: "approval mode is automatic",
      mutate: (config) => {
        config.approvals.mode = "automatic";
      },
    },
    {
      label: "cron approval is allowed",
      mutate: (config) => {
        config.approvals.cron_mode = "allow";
      },
    },
    {
      label: "lazy installs are enabled",
      mutate: (config) => {
        config.security.allow_lazy_installs = true;
      },
    },
  ];

  it.each(unsafeProfileCases)(
    "rejects before planning when $label",
    async ({ mutate }) => {
      const root = makeTempRoot();
      const profileDir = makeProfile(path.join(root, "home"));
      const configPath = path.join(profileDir, "config.yaml");
      const soulPath = path.join(profileDir, "SOUL.md");
      const config = safeProfileConfigObject("UNSAFE_CONFIG_CANARY_4b90");
      mutate(config);
      const configText = YAML.stringify(config);
      const soulText = "UNSAFE_SOUL_CANARY_4b90\n";
      writeText(configPath, configText);
      writeText(soulPath, soulText);

      await expect(installer.createInstallPlan({ profileDir })).rejects.toThrow(
        /zero-live safety contract/i,
      );
      expect(readFileSync(configPath, "utf8")).toBe(configText);
      expect(readFileSync(soulPath, "utf8")).toBe(soulText);
      expect(existsSync(path.join(profileDir, "local"))).toBe(false);
    },
  );

  it.each([
    { label: "plan", mode: ["--dry-run"] },
    { label: "apply", mode: ["--apply"] },
    { label: "verify", mode: ["--verify"] },
  ])(
    "rejects an unsafe target config before $label without leaking or mutation",
    ({ mode }) => {
      const root = makeTempRoot();
      const home = path.join(root, "home");
      const profileDir = makeProfile(home);
      const configPath = path.join(profileDir, "config.yaml");
      const soulPath = path.join(profileDir, "SOUL.md");
      const config = safeProfileConfigObject("CLI_UNSAFE_CONFIG_CANARY_e112");
      config.terminal.docker_network = true;
      const configText = YAML.stringify(config);
      const soulText = "CLI_UNSAFE_SOUL_CANARY_e112\n";
      writeText(configPath, configText);
      writeText(soulPath, soulText);
      const managedCanaryPath = path.join(
        profileDir,
        "skills",
        "security",
        expectedSkillNames[0],
        "SKILL.md",
      );
      writeText(managedCanaryPath, "CLI_UNSAFE_MANAGED_CANARY_e112");

      const run = spawnSync(
        process.execPath,
        [
          installerPath,
          ...mode,
          "--json",
          "--hermes-home",
          home,
          "--profile",
          "bugbounty",
        ],
        { cwd: repoRoot, encoding: "utf8", shell: false },
      );
      expect(run.status).toBe(1);
      const output = `${run.stdout}\n${run.stderr}`;
      expect(output).not.toContain("CLI_UNSAFE_CONFIG_CANARY_e112");
      expect(output).not.toContain("CLI_UNSAFE_SOUL_CANARY_e112");
      expect(output).not.toContain("CLI_UNSAFE_MANAGED_CANARY_e112");
      expect(output).not.toContain(root);
      expect(readFileSync(configPath, "utf8")).toBe(configText);
      expect(readFileSync(soulPath, "utf8")).toBe(soulText);
      expect(readFileSync(managedCanaryPath, "utf8")).toBe("CLI_UNSAFE_MANAGED_CANARY_e112");
      expect(existsSync(path.join(profileDir, "local"))).toBe(false);
    },
  );

  it.each([
    { label: "plan", mode: ["--dry-run"] },
    { label: "apply", mode: ["--apply"] },
    { label: "verify", mode: ["--verify"] },
  ])(
    "rejects a missing target config before $label without leaking or mutation",
    ({ mode }) => {
      const root = makeTempRoot();
      const home = path.join(root, "home");
      const profileDir = makeProfile(home);
      const soulPath = path.join(profileDir, "SOUL.md");
      const soulText = "CLI_MISSING_CONFIG_SOUL_CANARY_a11f\n";
      writeText(soulPath, soulText);
      rmSync(path.join(profileDir, "config.yaml"));

      const run = spawnSync(
        process.execPath,
        [
          installerPath,
          ...mode,
          "--json",
          "--hermes-home",
          home,
          "--profile",
          "bugbounty",
        ],
        { cwd: repoRoot, encoding: "utf8", shell: false },
      );
      expect(run.status).toBe(1);
      const output = `${run.stdout}\n${run.stderr}`;
      expect(output).not.toContain("CLI_MISSING_CONFIG_SOUL_CANARY_a11f");
      expect(output).not.toContain(root);
      expect(readFileSync(soulPath, "utf8")).toBe(soulText);
      expect(existsSync(path.join(profileDir, "config.yaml"))).toBe(false);
      expect(existsSync(path.join(profileDir, "local"))).toBe(false);
    },
  );

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
