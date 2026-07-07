import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { nodeEngineSupportsSqliteRuntime, runReleaseCheck } from "../src/core/release/release-check.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("release checks", () => {
  it("requires a Node runtime new enough for node:sqlite", () => {
    expect(nodeEngineSupportsSqliteRuntime(">=20")).toBe(false);
    expect(nodeEngineSupportsSqliteRuntime(">=22.12.0")).toBe(false);
    expect(nodeEngineSupportsSqliteRuntime(">=22.13.0")).toBe(true);
    expect(nodeEngineSupportsSqliteRuntime(">=24")).toBe(true);
  });

  it("fails malformed structured example files", () => {
    const root = writeReleaseFixture();
    writeFileSync(path.join(root, "examples", "mcp-steps.json"), "{bad json", "utf8");
    writeFileSync(path.join(root, "examples", "integrations.yml"), "integrations: [", "utf8");

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "examples/mcp-steps.json:json", status: "fail" }),
        expect.objectContaining({ name: "examples/integrations.yml:yaml", status: "fail" }),
      ]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails integration examples with invalid package hash pins", () => {
    const root = writeReleaseFixture();
    writeFileSync(
      path.join(root, "examples", "integrations.yml"),
      `integrations:
  playwright_mcp:
    enabled: false
    type: mcp
    transport: stdio
    execution:
      enabled: false
      package: "@playwright/mcp"
      package_version: "1.0.0"
      entrypoint: "cli.js"
      entrypoint_sha256: "not-a-sha"
    capabilities:
      - browser.navigate
`,
      "utf8",
    );

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "examples/integrations.yml:yaml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub release workflow is missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "workflows", "release.yml"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/workflows/release.yml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub CodeQL workflow is missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "workflows", "codeql.yml"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/workflows/codeql.yml", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when public repository files are missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, "LICENSE"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "LICENSE", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails when GitHub community templates are missing", () => {
    const root = writeReleaseFixture();
    rmSync(path.join(root, ".github", "pull_request_template.md"));

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: ".github/pull_request_template.md", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });

  it("fails malformed workflow summary examples", () => {
    const root = writeReleaseFixture();
    writeText(
      root,
      "examples/workflow-summary.json",
      JSON.stringify({ ...workflowSummaryExample(), checkpointVersion: 1 }, null, 2),
    );

    const result = runReleaseCheck(root);

    expect(result.checks).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "examples/workflow-summary.json:json", status: "fail" })]),
    );
    expect(result.ok).toBe(false);
  });
});

function writeReleaseFixture(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "bountypilot-release-check-"));
  writeText(
    root,
    "package.json",
    JSON.stringify(
      {
        name: "fixture",
        version: "0.0.0",
        type: "module",
        license: "MIT",
        files: ["dist", "examples", "skills"],
        bin: { bugbounty: "./dist/cli/index.js", bounty: "./dist/cli/index.js" },
        scripts: {
          clean: "echo clean",
          build: "echo build",
          test: "echo test",
          "test:smoke": "echo smoke",
          "test:package-bin": "echo package",
          typecheck: "echo typecheck",
          "release:check": "echo release",
          sbom: "echo sbom",
          "verify:release": "echo verify",
          prepack: "echo prepack",
          dev: "echo dev",
        },
        engines: { node: ">=22.13.0" },
      },
      null,
      2,
    ),
  );
  writeText(root, "README.md", "# fixture\n");
  writeText(root, "tsconfig.json", "{}\n");
  writeText(root, "package-lock.json", "{}\n");
  writeText(root, "LICENSE", "MIT License\n");
  writeText(root, "SECURITY.md", "# Security\n");
  writeText(root, "CONTRIBUTING.md", "# Contributing\n");
  writeText(
    root,
    "scripts/install.sh",
    `#!/usr/bin/env bash
MIN_NODE_VERSION="22.13.0"
if [[ "\${BOUNTYPILOT_INSTALL_DRY_RUN:-}" == "1" ]]; then
  echo "Dry run: npm install -g bountypilot"
  exit 0
fi
npm install -g bountypilot
`,
  );
  writeText(
    root,
    "scripts/install.ps1",
    `$MinNodeVersion = [version]"22.13.0"
if ($env:BOUNTYPILOT_INSTALL_DRY_RUN -eq "1") {
  Write-Host "Dry run: npm install -g bountypilot"
  exit 0
}
npm install -g bountypilot
if ($LASTEXITCODE -ne 0) { Write-Error "npm install failed" }
`,
  );
  writeText(
    root,
    ".github/workflows/ci.yml",
    `name: CI
on: [push]
jobs:
  verify:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: \${{ matrix.os }}
    steps:
      - run: npm ci
      - run: npm run verify:release
`,
  );
  writeText(
    root,
    ".github/workflows/release.yml",
    `name: Release
on:
  push:
    tags: ["v*"]
permissions:
  attestations: write
  contents: write
  id-token: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
      - run: npm run verify:release
      - run: npm pack
      - run: npm run --silent sbom > bountypilot-sbom.cdx.json
      - run: node dist/cli/index.js skill bundle bug-bounty-pilot --output bug-bounty-pilot.skill.zip --json
      - run: node dist/cli/index.js skill verify-bundle bug-bounty-pilot.skill.zip --json
      - run: sha256sum bountypilot-*.tgz bug-bounty-pilot.skill.zip bountypilot-sbom.cdx.json > SHA256SUMS.txt
      - uses: actions/attest-build-provenance@v2
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            bug-bounty-pilot.skill.zip
            bountypilot-sbom.cdx.json
            SHA256SUMS.txt
`,
  );
  writeText(
    root,
    ".github/workflows/codeql.yml",
    `name: CodeQL
jobs:
  analyze:
    steps:
      - uses: github/codeql-action/init@v3
        with:
          languages: javascript-typescript
          queries: security-extended
      - run: npm run build
`,
  );
  writeText(
    root,
    ".github/pull_request_template.md",
    "## Safety Checklist\n- [ ] No real target data\n- [ ] `npm run verify:release`\n",
  );
  writeText(
    root,
    ".github/dependabot.yml",
    "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n    open-pull-requests-limit: 5\n",
  );
  writeText(
    root,
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    "name: Bug report\nbody:\n  - type: markdown\n    attributes:\n      value: Safety confirmation secrets\n",
  );
  writeText(
    root,
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    "name: Feature request\nbody:\n  - type: markdown\n    attributes:\n      value: Safety mode scope, policy\n",
  );
  writeText(root, ".github/ISSUE_TEMPLATE/config.yml", "blank_issues_enabled: false\n");
  writeText(root, "dist/cli/index.js", "#!/usr/bin/env node\n");
  writeText(root, "examples/local-lab-authorization.md", "Authorized local lab.\n");
  writeText(root, "examples/program.yml", programYaml("fixture", false));
  writeText(root, "examples/local-program.yml", programYaml("fixture-local", true));
  writeText(root, "examples/integrations.yml", "integrations: {}\n");
  writeText(root, "examples/tool-registry.yml", "tools: []\n");
  writeText(root, "examples/safe-workflow.md", "# safe workflow\n");
  writeText(root, "examples/mcp-steps.json", JSON.stringify({ steps: [] }, null, 2));
  writeText(root, "examples/workflow-summary.json", JSON.stringify(workflowSummaryExample(), null, 2));
  writeText(root, "examples/sample-finding.json", JSON.stringify({ id: "finding", title: "Title", url: "https://example.com", status: "new", evidencePaths: [] }, null, 2));
  writeText(root, "examples/sample-evidence-manifest.json", JSON.stringify({ generatedAt: "2026-07-05T00:00:00.000Z", artifacts: [] }, null, 2));
  writeText(root, "examples/sample-report.md", "# report\n");
  writeText(root, "examples/evidence/finding-example-security-header/reproduction.md", "# reproduction\n");
  writeText(
    root,
    "examples/evidence/finding-example-security-header/safe-check-output.json",
    JSON.stringify({ target: "https://example.com", checks: [], safeTesting: true }, null, 2),
  );
  cpSync(path.join(repoRoot, "skills", "bug-bounty-pilot"), path.join(root, "skills", "bug-bounty-pilot"), { recursive: true });
  return root;
}

function workflowSummaryExample(): Record<string, unknown> {
  return {
    checkpointVersion: 2,
    jobId: "job-example",
    status: "completed",
    program: "fixture",
    mode: "safe",
    dryRun: false,
    draftReports: false,
    components: ["safe-checks"],
    seeds: ["https://example.com/"],
    skippedScopeRules: [],
    phases: [
      { name: "research-note", status: "skipped", detail: "already completed" },
      { name: "safe-checks", status: "completed", target: "https://example.com/", detail: "example.com: 0 candidates." },
    ],
    findingsCreated: 0,
    candidatesCreated: 0,
    evidenceCreated: 1,
    actionsPlanned: 1,
    actionCounts: {
      total: 1,
      pending: 0,
      approved: 0,
      executed: 1,
      blocked: 0,
      failed: 0,
    },
    reportsDrafted: 0,
    startedAt: "2026-07-05T00:00:00.000Z",
    updatedAt: "2026-07-05T00:01:00.000Z",
    resumeSkippedWork: [{ phase: "research-note" }],
  };
}

function writeText(root: string, relativePath: string, content: string): void {
  const filePath = path.join(root, relativePath);
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, content.endsWith("\n") ? content : `${content}\n`, "utf8");
}

function programYaml(program: string, lab: boolean): string {
  return `program: ${program}
platform: hackerone
in_scope:
  - example.com
out_of_scope: []
rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "1rps"
  browser_crawling: true
  deep_safe_mode: true
  lab_mode: ${lab ? "true" : "false"}
${lab ? "  lab_authorization_file: local-lab-authorization.md\n" : ""}  require_human_approval_for_risky_actions: true
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
