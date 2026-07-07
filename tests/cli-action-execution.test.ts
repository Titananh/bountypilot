import { createServer, type Server } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bountyCli = path.join(repoRoot, "dist", "cli", "index.js");

const workspaces: string[] = [];
let server: Server;
let baseUrl: string;

beforeEach(async () => {
  server = createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "text/html",
    });
    response.end("<html><head><title>Local lab</title></head><body>ok</body></html>");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No test server port");
  baseUrl = `http://127.0.0.1:${address.port}/`;
});

afterEach(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("CLI action execution", () => {
  it("serves the built-in demo lab and validates it through lab e2e", async () => {
    const workspace = createWorkspace();

    const rejectedHost = await runCli(["lab", "demo", "--host", "0.0.0.0", "--port", "0", "--json"], workspace);
    expectCommand(rejectedHost).toExit(1);
    expect(JSON.parse(rejectedHost.stdout).error.code).toBe("LAB_DEMO_HOST_NOT_LOOPBACK");

    const demo = await startDemoLabCli(workspace);
    try {
      expect(demo.ready).toMatchObject({
        ok: true,
        host: "127.0.0.1",
      });
      expect(demo.ready.target).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/);
      const ssrfTarget = ssrfDemoTarget(demo.ready.target);
      expect(demo.ready.nextCommands).toEqual(
        expect.arrayContaining([
          `bounty lab e2e ${demo.ready.target}`,
          `bounty lab e2e ${demo.ready.target} --live --with safe-checks,js-analyzer`,
          `bounty hunt playbook cors ${new URL("/api/cors-demo", demo.ready.target).toString()} --live`,
          `bounty hunt playbook ssrf ${ssrfTarget} --live`,
          `bounty hunt playbook open-redirect ${new URL("/redirect?next=https://example.org", demo.ready.target).toString()} --live`,
          `bounty hunt playbook exposure ${new URL("/.env", demo.ready.target).toString()} --live`,
          `bounty hunt playbook xss ${new URL("/search?q=%3Cbountypilot-xss%3E", demo.ready.target).toString()} --live`,
          `bounty hunt playbook graphql ${new URL("/graphql", demo.ready.target).toString()} --live`,
          `bounty hunt playbook idor ${new URL("/api/account?id=1001", demo.ready.target).toString()} --live`,
          `bounty hunt playbook js-secrets ${demo.ready.target} --live`,
        ]),
      );

      const home = await fetch(demo.ready.target);
      expect(home.status).toBe(200);
      expect(await home.text()).toContain("BountyPilot Local Demo Lab");
      const corsDemo = await fetch(new URL("/api/cors-demo", demo.ready.target), {
        headers: { Origin: "https://bountypilot.local" },
      });
      expect(corsDemo.headers.get("access-control-allow-origin")).toBe("https://bountypilot.local");
      expect(corsDemo.headers.get("access-control-allow-credentials")).toBe("true");
      const ssrfDemo = await fetch(ssrfTarget);
      expect(ssrfDemo.status).toBe(200);
      const ssrfDemoText = await ssrfDemo.text();
      expect(ssrfDemoText).toContain('"serverFetch": true');
      expect(ssrfDemoText).toContain("/healthz");
      const redirectDemo = await fetch(new URL("/redirect?next=https://example.org", demo.ready.target), {
        redirect: "manual",
      });
      expect(redirectDemo.status).toBe(302);
      expect(redirectDemo.headers.get("location")).toBe("https://example.org");
      const exposureDemo = await fetch(new URL("/.env", demo.ready.target));
      expect(exposureDemo.status).toBe(200);
      expect(await exposureDemo.text()).toContain("API_KEY=bp_demo_env_key_for_local_detection_only");
      const reflectedSearchDemo = await fetch(new URL("/search?q=%3Cbountypilot-xss%3E", demo.ready.target));
      expect(reflectedSearchDemo.status).toBe(200);
      expect(await reflectedSearchDemo.text()).toContain("<bountypilot-xss>");
      const graphqlIntrospectionDemo = await fetch(new URL("/graphql", demo.ready.target), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
      });
      expect(graphqlIntrospectionDemo.status).toBe(200);
      expect(await graphqlIntrospectionDemo.text()).toContain('"__schema"');
      const accountDemo = await fetch(new URL("/api/account?id=1001", demo.ready.target));
      expect(accountDemo.status).toBe(200);
      expect(await accountDemo.text()).toContain('"ownerUserId": "demo-user-a"');

      const authDir = path.join(workspace, "auth");
      const programFile = path.join(workspace, "local-lab.yml");
      mkdirSync(authDir, { recursive: true });
      writeFileSync(path.join(authDir, "lab.md"), "Authorized local lab owned by the researcher.\n", "utf8");
      writeFileSync(programFile, localLabProgramYaml(), "utf8");
      expectCommand(await runCli(["init"], workspace)).toExit(0);
      expectCommand(await runCli(["import", programFile], workspace)).toExit(0);

      const liveRun = await runCli(["lab", "e2e", demo.ready.target, "--live", "--with", "safe-checks,js-analyzer", "--json"], workspace);
      expectCommand(liveRun).toExit(0);
      const parsedLiveRun = JSON.parse(liveRun.stdout);
      expect(parsedLiveRun).toMatchObject({ ok: true, live: true, dryRun: false, mode: "lab-offensive" });
      expect(parsedLiveRun.summary).toMatchObject({ status: "completed", dryRun: false });
      expect(parsedLiveRun.summary.evidenceCreated).toBeGreaterThanOrEqual(2);
      expect(parsedLiveRun.summary.findingsCreated).toBeGreaterThanOrEqual(2);
      expect(parsedLiveRun.summary.phases).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "safe-checks", status: "completed" }),
          expect.objectContaining({ name: "js-analyzer", status: "completed" }),
        ]),
      );

      const corsPlaybook = await runCli(
        ["hunt", "playbook", "cors", new URL("/api/cors-demo", demo.ready.target).toString(), "--live", "--json"],
        workspace,
      );
      expectCommand(corsPlaybook).toExit(0);
      expect(corsPlaybook.stderr).toBe("");
      const parsedCorsPlaybook = JSON.parse(corsPlaybook.stdout);
      expect(parsedCorsPlaybook.bugClass).toBe("cors");
      expect(parsedCorsPlaybook.findingsCreated.length).toBeGreaterThanOrEqual(1);
      expect(parsedCorsPlaybook.findingsCreated[0].category).toBe("cors");
      expect(parsedCorsPlaybook.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "finding_candidate", sourceAdapter: "hunt-playbook" }),
        ]),
      );
      expect(parsedCorsPlaybook.evidence.length).toBeGreaterThanOrEqual(3);
      const corsValidation = parsedCorsPlaybook.evidence.find((item: { path?: string }) =>
        item.path?.endsWith("cors-validation.json"),
      );
      expect(corsValidation?.path).toBeTruthy();
      const corsEvidenceText = readFileSync(corsValidation.path, "utf8");
      expect(corsEvidenceText).toContain('"credentialedReflectedOrigin": true');
      expect(corsEvidenceText).toContain('"corsCandidate": true');

      const reportScore = await runCli(
        ["reports", "score", parsedCorsPlaybook.findingsCreated[0].id, "--job", parsedCorsPlaybook.jobId, "--json"],
        workspace,
      );
      expectCommand(reportScore).toExit(0);
      expect(reportScore.stderr).toBe("");
      const parsedReportScore = JSON.parse(reportScore.stdout);
      expect(parsedReportScore.findingId).toBe(parsedCorsPlaybook.findingsCreated[0].id);
      expect(parsedReportScore.score).toBeGreaterThan(0);
      expect(parsedReportScore.nextCommands).toEqual(expect.arrayContaining([expect.stringContaining("bounty reports review")]));

      const ssrfPlaybook = await runCli(["hunt", "playbook", "ssrf", ssrfTarget, "--live", "--json"], workspace);
      expectCommand(ssrfPlaybook).toExit(0);
      expect(ssrfPlaybook.stderr).toBe("");
      const parsedSsrfPlaybook = JSON.parse(ssrfPlaybook.stdout);
      expect(parsedSsrfPlaybook.bugClass).toBe("ssrf");
      expect(parsedSsrfPlaybook.findingsCreated.length).toBeGreaterThanOrEqual(1);
      expect(parsedSsrfPlaybook.findingsCreated[0].category).toBe("ssrf_server_fetch_indicator");
      expect(parsedSsrfPlaybook.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "finding_candidate", sourceAdapter: "hunt-playbook" }),
        ]),
      );
      const ssrfValidation = parsedSsrfPlaybook.evidence.find((item: { path?: string }) =>
        item.path?.endsWith("ssrf-server-fetch-validation.json"),
      );
      expect(ssrfValidation?.path).toBeTruthy();
      const ssrfEvidenceText = readFileSync(ssrfValidation.path, "utf8");
      expect(ssrfEvidenceText).toContain('"ssrfCandidate": true');
      expect(ssrfEvidenceText).toContain('"probeMatched": true');

      const ssrfResults = await runCli(["results", "--job", parsedSsrfPlaybook.jobId, "--json"], workspace);
      expectCommand(ssrfResults).toExit(0);
      const parsedSsrfResults = JSON.parse(ssrfResults.stdout);
      expect(parsedSsrfResults.findings[0].category).toBe("ssrf_server_fetch_indicator");
      expect(parsedSsrfResults.reconSignals.total).toBeGreaterThanOrEqual(1);

      const redirectPlaybook = await runCli(
        ["hunt", "playbook", "open-redirect", new URL("/redirect?next=https://example.org", demo.ready.target).toString(), "--live", "--json"],
        workspace,
      );
      expectCommand(redirectPlaybook).toExit(0);
      expect(redirectPlaybook.stderr).toBe("");
      const parsedRedirectPlaybook = JSON.parse(redirectPlaybook.stdout);
      expect(parsedRedirectPlaybook.bugClass).toBe("open-redirect");
      expect(parsedRedirectPlaybook.findingsCreated.length).toBeGreaterThanOrEqual(1);
      expect(parsedRedirectPlaybook.findingsCreated[0].category).toBe("open_redirect");
      expect(parsedRedirectPlaybook.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "finding_candidate", sourceAdapter: "hunt-playbook" }),
        ]),
      );

      const redirectResults = await runCli(["results", "--job", parsedRedirectPlaybook.jobId, "--json"], workspace);
      expectCommand(redirectResults).toExit(0);
      const parsedRedirectResults = JSON.parse(redirectResults.stdout);
      expect(parsedRedirectResults.findings[0].category).toBe("open_redirect");
      expect(parsedRedirectResults.reconSignals.total).toBeGreaterThanOrEqual(1);

      const exposurePlaybook = await runCli(
        ["hunt", "playbook", "exposure", new URL("/.env", demo.ready.target).toString(), "--live", "--json"],
        workspace,
      );
      expectCommand(exposurePlaybook).toExit(0);
      expect(exposurePlaybook.stderr).toBe("");
      const parsedExposurePlaybook = JSON.parse(exposurePlaybook.stdout);
      expect(parsedExposurePlaybook.bugClass).toBe("exposure");
      expect(parsedExposurePlaybook.findingsCreated.length).toBeGreaterThanOrEqual(1);
      expect(parsedExposurePlaybook.findingsCreated[0].category).toBe("sensitive_file_exposure");
      expect(parsedExposurePlaybook.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "finding_candidate", sourceAdapter: "hunt-playbook" }),
        ]),
      );
      const exposureValidation = parsedExposurePlaybook.evidence.find((item: { path?: string }) =>
        item.path?.endsWith("exposure-validation.json"),
      );
      expect(exposureValidation?.path).toBeTruthy();
      const exposureEvidenceText = readFileSync(exposureValidation.path, "utf8");
      expect(exposureEvidenceText).toContain("API_KEY=[REDACTED]");
      expect(exposureEvidenceText).not.toContain("bp_demo_env_key_for_local_detection_only");

      const exposureResults = await runCli(["results", "--job", parsedExposurePlaybook.jobId, "--json"], workspace);
      expectCommand(exposureResults).toExit(0);
      const parsedExposureResults = JSON.parse(exposureResults.stdout);
      expect(parsedExposureResults.findings[0].category).toBe("sensitive_file_exposure");
      expect(parsedExposureResults.reconSignals.total).toBeGreaterThanOrEqual(1);

      const xssPlaybook = await runCli(
        ["hunt", "playbook", "xss", new URL("/search?q=%3Cbountypilot-xss%3E", demo.ready.target).toString(), "--live", "--json"],
        workspace,
      );
      expectCommand(xssPlaybook).toExit(0);
      expect(xssPlaybook.stderr).toBe("");
      const parsedXssPlaybook = JSON.parse(xssPlaybook.stdout);
      expect(parsedXssPlaybook.bugClass).toBe("xss");
      expect(parsedXssPlaybook.findingsCreated.length).toBeGreaterThanOrEqual(1);
      expect(parsedXssPlaybook.findingsCreated[0].category).toBe("reflected_xss_candidate");
      expect(parsedXssPlaybook.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "finding_candidate", sourceAdapter: "hunt-playbook" }),
        ]),
      );
      const xssValidation = parsedXssPlaybook.evidence.find((item: { path?: string }) =>
        item.path?.endsWith("xss-reflection-validation.json"),
      );
      expect(xssValidation?.path).toBeTruthy();
      const xssEvidenceText = readFileSync(xssValidation.path, "utf8");
      expect(xssEvidenceText).toContain('"reflectedXssCandidate": true');
      expect(xssEvidenceText).toContain("<bountypilot-xss>");

      const xssResults = await runCli(["results", "--job", parsedXssPlaybook.jobId, "--json"], workspace);
      expectCommand(xssResults).toExit(0);
      const parsedXssResults = JSON.parse(xssResults.stdout);
      expect(parsedXssResults.findings[0].category).toBe("reflected_xss_candidate");
      expect(parsedXssResults.reconSignals.total).toBeGreaterThanOrEqual(1);

      const graphqlPlaybook = await runCli(
        ["hunt", "playbook", "graphql", new URL("/graphql", demo.ready.target).toString(), "--live", "--json"],
        workspace,
      );
      expectCommand(graphqlPlaybook).toExit(0);
      expect(graphqlPlaybook.stderr).toBe("");
      const parsedGraphqlPlaybook = JSON.parse(graphqlPlaybook.stdout);
      expect(parsedGraphqlPlaybook.bugClass).toBe("graphql");
      expect(parsedGraphqlPlaybook.findingsCreated.length).toBeGreaterThanOrEqual(1);
      expect(parsedGraphqlPlaybook.findingsCreated[0].category).toBe("graphql_introspection_enabled");
      expect(parsedGraphqlPlaybook.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "finding_candidate", sourceAdapter: "hunt-playbook" }),
        ]),
      );
      const graphqlValidation = parsedGraphqlPlaybook.evidence.find((item: { path?: string }) =>
        item.path?.endsWith("graphql-introspection-validation.json"),
      );
      expect(graphqlValidation?.path).toBeTruthy();
      const graphqlEvidenceText = readFileSync(graphqlValidation.path, "utf8");
      expect(graphqlEvidenceText).toContain('"introspectionEnabled": true');
      expect(graphqlEvidenceText).toContain('"queryTypeName": "Query"');

      const graphqlResults = await runCli(["results", "--job", parsedGraphqlPlaybook.jobId, "--json"], workspace);
      expectCommand(graphqlResults).toExit(0);
      const parsedGraphqlResults = JSON.parse(graphqlResults.stdout);
      expect(parsedGraphqlResults.findings[0].category).toBe("graphql_introspection_enabled");
      expect(parsedGraphqlResults.reconSignals.total).toBeGreaterThanOrEqual(1);

      const idorPlaybook = await runCli(
        ["hunt", "playbook", "idor", new URL("/api/account?id=1001", demo.ready.target).toString(), "--live", "--json"],
        workspace,
      );
      expectCommand(idorPlaybook).toExit(0);
      expect(idorPlaybook.stderr).toBe("");
      const parsedIdorPlaybook = JSON.parse(idorPlaybook.stdout);
      expect(parsedIdorPlaybook.bugClass).toBe("idor");
      expect(parsedIdorPlaybook.findingsCreated.length).toBeGreaterThanOrEqual(1);
      expect(parsedIdorPlaybook.findingsCreated[0].category).toBe("idor_adjacent_object_access");
      expect(parsedIdorPlaybook.observations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "finding_candidate", sourceAdapter: "hunt-playbook" }),
        ]),
      );
      const idorValidation = parsedIdorPlaybook.evidence.find((item: { path?: string }) =>
        item.path?.endsWith("idor-adjacent-object-validation.json"),
      );
      expect(idorValidation?.path).toBeTruthy();
      const idorEvidenceText = readFileSync(idorValidation.path, "utf8");
      expect(idorEvidenceText).toContain('"idorCandidate": true');
      expect(idorEvidenceText).toContain('"adjacentValue": "1002"');

      const idorResults = await runCli(["results", "--job", parsedIdorPlaybook.jobId, "--json"], workspace);
      expectCommand(idorResults).toExit(0);
      const parsedIdorResults = JSON.parse(idorResults.stdout);
      expect(parsedIdorResults.findings[0].category).toBe("idor_adjacent_object_access");
      expect(parsedIdorResults.reconSignals.total).toBeGreaterThanOrEqual(1);
    } finally {
      await demo.stop();
    }
  }, 100_000);

  it("runs a guarded local lab e2e gate with explicit live execution", async () => {
    const workspace = createWorkspace();
    const authDir = path.join(workspace, "auth");
    const programFile = path.join(workspace, "local-lab.yml");
    mkdirSync(authDir, { recursive: true });
    writeFileSync(path.join(authDir, "lab.md"), "Authorized local lab owned by the researcher.\n", "utf8");
    writeFileSync(programFile, localLabProgramYaml(), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);

    const dryRun = await runCli(["lab", "e2e", baseUrl, "--json"], workspace);
    expectCommand(dryRun).toExit(0);
    expect(dryRun.stderr).toBe("");
    const parsedDryRun = JSON.parse(dryRun.stdout);
    expect(parsedDryRun).toMatchObject({
      ok: true,
      live: false,
      dryRun: true,
      mode: "lab-offensive",
    });
    expect(parsedDryRun.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "lab_mode", status: "pass" }),
        expect.objectContaining({ name: "authorization", status: "pass" }),
        expect.objectContaining({ name: "scope", status: "pass" }),
        expect.objectContaining({ name: "policy", status: "pass" }),
        expect.objectContaining({ name: "workflow_execution", status: "pass" }),
      ]),
    );
    expect(parsedDryRun.summary).toMatchObject({ status: "completed", mode: "lab-offensive", dryRun: true });
    expect(parsedDryRun.nextCommands).toContain(
      `bounty lab e2e ${baseUrl} --live --with safe-checks,js-analyzer,triage,planner`,
    );

    const liveRun = await runCli(["lab", "e2e", baseUrl, "--live", "--with", "safe-checks,js-analyzer", "--json"], workspace);
    expectCommand(liveRun).toExit(0);
    expect(liveRun.stderr).toBe("");
    const parsedLiveRun = JSON.parse(liveRun.stdout);
    expect(parsedLiveRun).toMatchObject({
      ok: true,
      live: true,
      dryRun: false,
      mode: "lab-offensive",
      components: ["safe-checks", "js-analyzer"],
    });
    expect(parsedLiveRun.summary).toMatchObject({ status: "completed", mode: "lab-offensive", dryRun: false });
    expect(parsedLiveRun.summary.evidenceCreated).toBeGreaterThanOrEqual(2);
    expect(parsedLiveRun.summary.phases).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "safe-checks", status: "completed" }),
        expect.objectContaining({ name: "js-analyzer", status: "completed" }),
      ]),
    );
    expect(parsedLiveRun.events.length).toBeGreaterThan(0);
    expect(parsedLiveRun.nextCommands).toEqual(expect.arrayContaining([`bounty jobs show ${parsedLiveRun.summary.jobId}`]));
  }, 25_000);

  it("creates manual findings and attaches manual evidence files", async () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, localProgramYaml(), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);

    const initialEvidence = path.join(workspace, "initial-proof.txt");
    writeFileSync(initialEvidence, "initial password=manual-initial-secret", "utf8");
    const findingCreate = await runCli(
      [
        "findings",
        "create",
        "--title",
        "Manual local observation",
        "--url",
        baseUrl,
        "--category",
        "manual_observation",
        "--severity",
        "low",
        "--confidence",
        "medium",
        "--duplicate-risk",
        "low",
        "--reportability-score",
        "42",
        "--note",
        "manual note token=manual-note-secret",
        "--evidence",
        initialEvidence,
        "--json",
      ],
      workspace,
    );
    expectCommand(findingCreate).toExit(0);
    expect(findingCreate.stderr).toBe("");
    const parsedFindingCreate = JSON.parse(findingCreate.stdout);
    expect(parsedFindingCreate.finding).toMatchObject({
      title: "Manual local observation",
      severityEstimate: "low",
      confidence: "medium",
      duplicateRisk: "low",
      reportabilityScore: 42,
    });
    expect(parsedFindingCreate.evidence).toHaveLength(2);
    expect(readFileSync(parsedFindingCreate.evidence[0].path, "utf8")).not.toContain("manual-note-secret");
    expect(readFileSync(parsedFindingCreate.evidence[1].path, "utf8")).not.toContain("manual-initial-secret");

    const evidenceSource = path.join(workspace, "manual-note.txt");
    writeFileSync(evidenceSource, "manual evidence token=manual-evidence-secret", "utf8");
    const evidenceAdd = await runCli(
      ["evidence", "add", "--finding", parsedFindingCreate.finding.id, "--file", evidenceSource, "--kind", "evidence_note", "--json"],
      workspace,
    );
    expectCommand(evidenceAdd).toExit(0);
    expect(evidenceAdd.stderr).toBe("");
    const parsedEvidenceAdd = JSON.parse(evidenceAdd.stdout);
    expect(parsedEvidenceAdd.findingId).toBe(parsedFindingCreate.finding.id);
    expect(existsSync(parsedEvidenceAdd.artifact.path)).toBe(true);
    expect(readFileSync(parsedEvidenceAdd.artifact.path, "utf8")).not.toContain("manual-evidence-secret");

    const textEvidence = await runCli(
      [
        "evidence",
        "add",
        "--finding",
        parsedFindingCreate.finding.id,
        "--text",
        "inline evidence token=manual-inline-secret",
        "--name",
        "inline-note",
        "--json",
      ],
      workspace,
    );
    expectCommand(textEvidence).toExit(0);
    const parsedTextEvidence = JSON.parse(textEvidence.stdout);
    expect(readFileSync(parsedTextEvidence.artifact.path, "utf8")).not.toContain("manual-inline-secret");

    const stdinEvidence = await runCli(
      [
        "evidence",
        "add",
        "--finding",
        parsedFindingCreate.finding.id,
        "--stdin",
        "--name",
        "stdin-note",
        "--json",
      ],
      workspace,
      "stdin evidence password=manual-stdin-secret",
    );
    expectCommand(stdinEvidence).toExit(0);
    const parsedStdinEvidence = JSON.parse(stdinEvidence.stdout);
    expect(readFileSync(parsedStdinEvidence.artifact.path, "utf8")).not.toContain("manual-stdin-secret");

    const standaloneEvidence = await runCli(
      ["evidence", "add", "--text", "standalone link evidence", "--name", "standalone-link", "--json"],
      workspace,
    );
    expectCommand(standaloneEvidence).toExit(0);
    const parsedStandaloneEvidence = JSON.parse(standaloneEvidence.stdout);
    expect(parsedStandaloneEvidence.findingId).toBeUndefined();
    const evidenceLink = await runCli(
      ["evidence", "link", parsedStandaloneEvidence.artifact.id, parsedFindingCreate.finding.id, "--json"],
      workspace,
    );
    expectCommand(evidenceLink).toExit(0);
    expect(JSON.parse(evidenceLink.stdout).artifact.findingId).toBe(parsedFindingCreate.finding.id);

    const evidenceJson = await runCli(["evidence", parsedFindingCreate.finding.id, "--json"], workspace);
    expectCommand(evidenceJson).toExit(0);
    expect(JSON.parse(evidenceJson.stdout).evidence).toHaveLength(6);

    const reportReview = await runCli(["reports", "review", parsedFindingCreate.finding.id], workspace);
    expectCommand(reportReview).toExit(0);
    expect(outputOf(reportReview)).toContain("reports review");
    expect(outputOf(reportReview)).toContain("report readiness");
    expect(outputOf(reportReview)).toContain("next commands");

    const reportReviewJson = await runCli(["reports", "review", parsedFindingCreate.finding.id, "--write", "--json"], workspace);
    expectCommand(reportReviewJson).toExit(0);
    expect(reportReviewJson.stderr).toBe("");
    const parsedReportReview = JSON.parse(reportReviewJson.stdout);
    expect(parsedReportReview.review.readiness).toBe("needs_review");
    expect(parsedReportReview.review.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "reproduction", status: "warn" }),
        expect.objectContaining({ id: "artifact_readability", status: "pass" }),
      ]),
    );
    expect(parsedReportReview.artifact.kind).toBe("tool_output");
    expect(existsSync(parsedReportReview.artifact.path)).toBe(true);
    expect(parsedReportReview.nextCommands).toContain(`bounty reproduce ${parsedFindingCreate.finding.id}`);

    const reportJson = await runCli(["report", parsedFindingCreate.finding.id, "--json"], workspace);
    expectCommand(reportJson).toExit(0);
    expect(reportJson.stderr).toBe("");
    const parsedReport = JSON.parse(reportJson.stdout);
    expect(parsedReport.finding.status).toBe("report_drafted");
    expect(parsedReport.artifact.kind).toBe("report");
    expect(existsSync(parsedReport.report.path)).toBe(true);
  }, 20_000);

  it("records browser evidence with request and response samples for report readiness", async () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, localProgramYaml(), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);

    const findingCreate = await runCli(
      [
        "findings",
        "create",
        "--title",
        "Recorded browser evidence observation",
        "--url",
        baseUrl,
        "--category",
        "manual_observation",
        "--severity",
        "medium",
        "--confidence",
        "medium",
        "--duplicate-risk",
        "low",
        "--reportability-score",
        "55",
        "--json",
      ],
      workspace,
    );
    expectCommand(findingCreate).toExit(0);
    const finding = JSON.parse(findingCreate.stdout).finding;

    const record = await runCli(["evidence", "record", baseUrl, "--finding", finding.id, "--json"], workspace);
    expectCommand(record).toExit(0);
    expect(record.stderr).toBe("");
    const parsedRecord = JSON.parse(record.stdout);
    const artifactKinds = parsedRecord.artifacts.map((artifact: any) => artifact.kind);
    expect(artifactKinds).toEqual(expect.arrayContaining(["request_sample", "response_sample", "reproduction_note"]));
    for (const artifact of parsedRecord.artifacts) {
      expect(existsSync(artifact.path)).toBe(true);
    }

    const responseSample = parsedRecord.artifacts.find((artifact: any) => artifact.kind === "response_sample");
    expect(readFileSync(responseSample.path, "utf8")).toContain("Local lab");

    const reportScore = await runCli(["reports", "score", finding.id, "--job", parsedRecord.jobId, "--json"], workspace);
    expectCommand(reportScore).toExit(0);
    expect(reportScore.stderr).toBe("");
    const parsedScore = JSON.parse(reportScore.stdout);
    expect(parsedScore.counts.evidenceKinds).toMatchObject({
      request_sample: 1,
      response_sample: 1,
      reproduction_note: 1,
    });
    expect(parsedScore.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "request_context", status: "pass" }),
        expect.objectContaining({ id: "reproduction", status: "pass" }),
      ]),
    );
  }, 35_000);

  it("prints clean JSON for live check and JavaScript commands", async () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, localProgramYaml(), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);

    const checkJson = await runCli(["check", baseUrl, "--json"], workspace);
    expectCommand(checkJson).toExit(0);
    expect(checkJson.stderr).toBe("");
    expect(JSON.parse(checkJson.stdout)).toMatchObject({ ok: true, status: "completed" });

    const jsJson = await runCli(["js", baseUrl, "--json"], workspace);
    expectCommand(jsJson).toExit(0);
    expect(jsJson.stderr).toBe("");
    expect(JSON.parse(jsJson.stdout)).toMatchObject({ ok: true, status: "completed" });
  }, 20_000);

  it("reviews actions interactively without executing them", async () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, localProgramYaml(), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);
    expectCommand(await runCli(["run", baseUrl, "--dry-run", "--with", "safe-checks"], workspace)).toExit(0);

    const summary = readOnlyWorkflowSummary(workspace);
    const action = actionsForJob(workspace, summary.jobId)[0];
    expect(action?.id).toBeDefined();
    forceActionPending(workspace, action.id);
    expect(actionsForJob(workspace, summary.jobId).find((candidate) => candidate.id === action.id)?.status).toBe("pending");

    const interactiveReview = await runCli(
      ["actions", "review", "--job", summary.jobId, "--interactive", "--json"],
      workspace,
      "approve interactive local approval\n",
    );
    expectCommand(interactiveReview).toExit(0);
    expect(interactiveReview.stderr).toBe("");
    const parsedReview = JSON.parse(interactiveReview.stdout);
    expect(parsedReview.summary).toMatchObject({ approved: 1, blocked: 0, skipped: 0, quit: false });
    expect(parsedReview.decisions[0]).toMatchObject({
      actionId: action.id,
      decision: "approved",
      statusBefore: "pending",
      statusAfter: "approved",
    });
    expect(parsedReview.decisions[0].review.note).toBe("interactive local approval");
    expect(parsedReview.nextCommands).toContain(`bounty actions execute ${action.id}`);

    const updatedAction = actionsForJob(workspace, summary.jobId).find((candidate) => candidate.id === action.id);
    expect(updatedAction.status).toBe("approved");
    expect(updatedAction.executedAt).toBeUndefined();
    const actionShow = await runCli(["actions", "show", action.id, "--json"], workspace);
    expectCommand(actionShow).toExit(0);
    const parsedActionShow = JSON.parse(actionShow.stdout);
    expect(parsedActionShow.reviews[0]).toMatchObject({ decision: "approved", note: "interactive local approval" });
  }, 20_000);

  it("runs approved internal actions and records evidence", async () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, localProgramYaml(), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);

    const dryRun = await runCli(["run", baseUrl, "--dry-run", "--with", "safe-checks"], workspace);
    expectCommand(dryRun).toExit(0);

    const summary = readOnlyWorkflowSummary(workspace);
    expect(summary.actionsPlanned).toBe(1);
    expect(summary.actionCounts.approved).toBe(1);
    const actionId = actionsForJob(workspace, summary.jobId)[0]?.id;
    expect(actionId).toBeDefined();

    const review = await runCli(["actions", "review", "--job", summary.jobId], workspace);
    expectCommand(review).toExit(0);
    expect(outputOf(review)).toContain("actions review");
    expect(outputOf(review)).toContain(actionId!);
    expect(outputOf(review)).toContain(`bounty actions show ${actionId}`);
    expect(outputOf(review)).toContain(`bounty actions execute ${actionId}`);

    const reviewJson = await runCli(["actions", "review", "--job", summary.jobId, "--json"], workspace);
    expectCommand(reviewJson).toExit(0);
    expect(reviewJson.stderr).toBe("");
    const parsedReview = JSON.parse(reviewJson.stdout);
    expect(parsedReview.actions[0].id).toBe(actionId);
    expect(parsedReview.nextCommands).toContain(`bounty actions execute ${actionId}`);

    const missingReviewJob = await runCli(["actions", "review", "--job", "job-does-not-exist", "--json"], workspace);
    expectCommand(missingReviewJob).toExit(1);
    expect(missingReviewJob.stderr).toBe("");
    expect(JSON.parse(missingReviewJob.stdout).error.code).toBe("JOB_NOT_FOUND");

    const invalidReviewLimit = await runCli(["actions", "review", "--job", summary.jobId, "--limit", "0", "--json"], workspace);
    expectCommand(invalidReviewLimit).toExit(1);
    expect(invalidReviewLimit.stderr).toBe("");
    expect(JSON.parse(invalidReviewLimit.stdout).error.code).toBe("CLI_INVALID_LIMIT");

    const missingActionsJob = await runCli(["actions", "list", "--job", "job-does-not-exist", "--json"], workspace);
    expectCommand(missingActionsJob).toExit(1);
    expect(missingActionsJob.stderr).toBe("");
    expect(JSON.parse(missingActionsJob.stdout).error.code).toBe("JOB_NOT_FOUND");

    const actionShowHuman = await runCli(["actions", "show", actionId!], workspace);
    expectCommand(actionShowHuman).toExit(0);
    expect(outputOf(actionShowHuman)).toContain("next commands");
    expect(outputOf(actionShowHuman)).toContain(`bounty actions execute ${actionId}`);

    const approve = await runCli(["actions", "approve", actionId!, "--note", "authorized local lab check", "--json"], workspace);
    expectCommand(approve).toExit(0);
    const parsedApproval = JSON.parse(outputOf(approve));
    expect(parsedApproval.review.note).toBe("authorized local lab check");

    const actionShow = await runCli(["actions", "show", actionId!, "--json"], workspace);
    expectCommand(actionShow).toExit(0);
    const parsedActionShow = JSON.parse(outputOf(actionShow));
    expect(parsedActionShow.action.id).toBe(actionId);
    expect(parsedActionShow.reviews[0].decision).toBe("approved");

    const execute = await runCli(["actions", "run-approved", "--job", summary.jobId], workspace);
    expectCommand(execute).toExit(0);
    expect(outputOf(execute)).toContain("executed");
    expect(outputOf(execute)).toContain("safe-checks");

    const jobShow = await runCli(["jobs", "show", summary.jobId], workspace);
    expectCommand(jobShow).toExit(0);
    expect(outputOf(jobShow)).toContain("executed");
    expect(outputOf(jobShow)).toContain("1");
    expect(outputOf(jobShow)).toContain("Action approved by human review");

    const findings = await runCli(["findings"], workspace);
    expectCommand(findings).toExit(0);
    const findingId = outputOf(findings).match(/finding-[a-f0-9-]+/)?.[0];
    expect(findingId, outputOf(findings)).toBeDefined();

    const findingsJson = await runCli(["findings", "--json"], workspace);
    expectCommand(findingsJson).toExit(0);
    expect(findingsJson.stderr).toBe("");
    const parsedFindings = JSON.parse(findingsJson.stdout);
    expect(parsedFindings.findings.some((finding: any) => finding.id === findingId)).toBe(true);

    const findingShow = await runCli(["findings", "show", findingId!], workspace);
    expectCommand(findingShow).toExit(0);
    expect(outputOf(findingShow)).toContain("findings show");
    expect(outputOf(findingShow)).toContain("recommend");

    const findingStatus = await runCli(
      ["findings", "status", findingId!, "validated", "--note", "local lab verified", "--json"],
      workspace,
    );
    expectCommand(findingStatus).toExit(0);
    expect(findingStatus.stderr).toBe("");
    const parsedStatus = JSON.parse(findingStatus.stdout);
    expect(parsedStatus.findingId).toBe(findingId);
    expect(parsedStatus.status).toBe("validated");
    expect(parsedStatus.finding.status).toBe("validated");
    expect(existsSync(parsedStatus.artifact.path)).toBe(true);

    const jobScopedEvidenceAdd = await runCli(
      [
        "evidence",
        "add",
        "--finding",
        findingId!,
        "--job",
        summary.jobId,
        "--text",
        "job scoped evidence token=job-scoped-secret",
        "--name",
        "job-scoped-note",
        "--json",
      ],
      workspace,
    );
    expectCommand(jobScopedEvidenceAdd).toExit(0);
    expect(jobScopedEvidenceAdd.stderr).toBe("");
    const parsedJobScopedEvidenceAdd = JSON.parse(jobScopedEvidenceAdd.stdout);
    expect(parsedJobScopedEvidenceAdd.jobId).toBe(summary.jobId);
    expect(parsedJobScopedEvidenceAdd.artifact.jobId).toBe(summary.jobId);

    const findingShowAfterStatus = await runCli(["findings", "show", findingId!, "--json"], workspace);
    expectCommand(findingShowAfterStatus).toExit(0);
    const parsedFinding = JSON.parse(outputOf(findingShowAfterStatus).slice(outputOf(findingShowAfterStatus).indexOf("{")));
    expect(parsedFinding.finding.status).toBe("validated");

    const triageJson = await runCli(["triage", findingId!, "--json"], workspace);
    expectCommand(triageJson).toExit(0);
    expect(triageJson.stderr).toBe("");
    const parsedTriage = JSON.parse(triageJson.stdout);
    expect(parsedTriage.finding.id).toBe(findingId);
    expect(typeof parsedTriage.triage.reportabilityScore).toBe("number");
    expect(parsedTriage.triage.recommendation).toBeDefined();

    const reproduceJson = await runCli(["reproduce", findingId!, "--json"], workspace);
    expectCommand(reproduceJson).toExit(0);
    expect(reproduceJson.stderr).toBe("");
    const parsedReproduce = JSON.parse(reproduceJson.stdout);
    expect(parsedReproduce.findingId).toBe(findingId);
    expect(existsSync(parsedReproduce.artifact.path)).toBe(true);

    const reportJson = await runCli(["report", findingId!, "--force-local-draft", "--json"], workspace);
    expectCommand(reportJson).toExit(0);
    expect(reportJson.stderr).toBe("");
    const parsedReport = JSON.parse(reportJson.stdout);
    expect(parsedReport.findingId).toBe(findingId);
    expect(parsedReport.status).toBe("report_drafted");
    expect(parsedReport.finding.status).toBe("report_drafted");
    expect(parsedReport.artifact.kind).toBe("report");
    expect(parsedReport.report.path).toBe(parsedReport.path);
    expect(existsSync(parsedReport.path)).toBe(true);

    const evidenceJson = await runCli(["evidence", findingId!, "--json"], workspace);
    expectCommand(evidenceJson).toExit(0);
    expect(evidenceJson.stderr).toBe("");
    expect(JSON.parse(evidenceJson.stdout).evidence.length).toBeGreaterThan(0);

    const evidenceManifestJson = await runCli(["evidence", findingId!, "--manifest", "--json"], workspace);
    expectCommand(evidenceManifestJson).toExit(0);
    expect(evidenceManifestJson.stderr).toBe("");
    const parsedEvidenceManifest = JSON.parse(evidenceManifestJson.stdout);
    expect(parsedEvidenceManifest.artifact.kind).toBe("tool_output");
    expect(existsSync(parsedEvidenceManifest.artifact.path)).toBe(true);

    const evidenceVerify = await runCli(["evidence", "verify", "--json"], workspace);
    expectCommand(evidenceVerify).toExit(0);
    const parsedManifest = JSON.parse(outputOf(evidenceVerify).slice(outputOf(evidenceVerify).indexOf("{")));
    expect(parsedManifest.artifactCount).toBeGreaterThan(0);
    expect(parsedManifest.artifacts.every((artifact: any) => artifact.readable)).toBe(true);

    const bundleDir = path.join(workspace, "action-handoff");
    const bundle = await runCli(["export", "bundle", "--job", summary.jobId, "--output", bundleDir, "--json"], workspace);
    expectCommand(bundle).toExit(0);
    const bundleActions = JSON.parse(readFileSync(path.join(bundleDir, "actions.json"), "utf8"));
    expect(bundleActions.reviews[0].note).toBe("authorized local lab check");

    expect(findFiles(path.join(workspace, ".bounty"), "safe-checks.json").length).toBeGreaterThan(0);
  }, 20_000);

  it("returns a failing exit code when an approved batch action fails", async () => {
    const workspace = createWorkspace();
    const programFile = path.join(workspace, "program.yml");
    writeFileSync(programFile, localProgramYaml(), "utf8");

    expectCommand(await runCli(["init"], workspace)).toExit(0);
    expectCommand(await runCli(["import", programFile], workspace)).toExit(0);
    expectCommand(await runCli(["run", baseUrl, "--dry-run", "--with", "safe-checks"], workspace)).toExit(0);

    const summary = readOnlyWorkflowSummary(workspace);
    const actionId = actionsForJob(workspace, summary.jobId)[0]?.id;
    expect(actionId).toBeDefined();
    expectCommand(await runCli(["actions", "approve", actionId!, "--note", "approved before target drift"], workspace)).toExit(0);
    poisonActionTarget(workspace, actionId!, "https://outside.example/");

    const execute = await runCli(["actions", "run-approved", "--job", summary.jobId, "--json"], workspace);
    expectCommand(execute).toExit(1);
    expect(execute.stderr).toBe("");
    const parsed = JSON.parse(execute.stdout);
    expect(parsed.summary).toMatchObject({ total: 1, executed: 0, failed: 1 });
    expect(parsed.results[0].status).toBe("failed");
    expect(parsed.results[0].message).toMatch(/scope|out of scope|No in_scope/i);
  }, 20_000);
});

function localProgramYaml(): string {
  return `program: cli-action-execution
platform: hackerone

in_scope:
  - "127.0.0.1"

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

function localLabProgramYaml(): string {
  return `program: cli-action-execution
platform: local

in_scope:
  - "127.0.0.1"

out_of_scope: []

rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "100rps"
  browser_crawling: true
  deep_safe_mode: true
  lab_mode: true
  lab_authorization_file: auth/lab.md
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

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-cli-actions-"));
  workspaces.push(workspace);
  return workspace;
}

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

function runCli(args: string[], cwd: string, input?: string): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bountyCli, ...args], {
      cwd,
      env: {
        ...process.env,
        NO_COLOR: "1",
      },
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timeout = setTimeout(() => {
      settled = true;
      child.kill();
      resolve({
        status: null,
        stdout,
        stderr,
        error: new Error(`CLI timed out: ${args.join(" ")}`),
      });
    }, 30_000);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    if (input !== undefined) {
      child.stdin.end(input);
    }
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ status: null, stdout, stderr, error });
    });
    child.on("close", (status) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ status, stdout, stderr });
    });
  }, 45_000);
}

interface DemoLabCliHandle {
  child: ChildProcessWithoutNullStreams;
  ready: any;
  stop: () => Promise<void>;
}

function startDemoLabCli(cwd: string): Promise<DemoLabCliHandle> {
  const child = spawn(process.execPath, [bountyCli, "lab", "demo", "--port", "0", "--json"], {
    cwd,
    env: {
      ...process.env,
      NO_COLOR: "1",
    },
    windowsHide: true,
  });

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
        resolve({
          child,
          ready: parsed,
          stop: () => stopDemoLabCli(child),
        });
      } catch {
        // Wait for the full pretty-printed JSON object.
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

function stopDemoLabCli(child: ChildProcessWithoutNullStreams): Promise<void> {
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

function outputOf(result: CliResult): string {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function expectCommand(result: CliResult): { toExit(status: number): void } {
  return {
    toExit(status: number) {
      expect(result.error, outputOf(result)).toBeUndefined();
      expect(result.status, outputOf(result)).toBe(status);
    },
  };
}

function readOnlyWorkflowSummary(workspace: string): Record<string, any> {
  const summaries = findFiles(path.join(workspace, ".bounty"), "workflow-summary.json");
  const finalSummary = summaries.find((summaryPath) =>
    summaryPath.includes(`${path.sep}evidence${path.sep}`),
  );
  expect(finalSummary, summaries.join("\n")).toBeDefined();
  return JSON.parse(readFileSync(finalSummary!, "utf8"));
}

function actionsForJob(workspace: string, jobId: string): any[] {
  const dbPath = findFiles(path.join(workspace, ".bounty"), "bountypilot.sqlite")[0];
  expect(dbPath).toBeDefined();
  const actionsOutput = JSON.parse(
    outputOfSync([bountyCli, "--program", "cli-action-execution", "actions", "list", "--job", jobId, "--json"], workspace),
  );
  return actionsOutput.actions;
}

function poisonActionTarget(workspace: string, actionId: string, target: string): void {
  const dbPath = findFiles(path.join(workspace, ".bounty"), "bountypilot.sqlite")[0];
  expect(dbPath).toBeDefined();
  const db = new DatabaseSync(dbPath!);
  try {
    db.prepare("UPDATE actions SET target = ? WHERE id = ?").run(target, actionId);
  } finally {
    db.close();
  }
}

function forceActionPending(workspace: string, actionId: string): void {
  const dbPath = findFiles(path.join(workspace, ".bounty"), "bountypilot.sqlite")[0];
  expect(dbPath).toBeDefined();
  const db = new DatabaseSync(dbPath!);
  try {
    db.prepare("UPDATE actions SET status = ?, requires_approval = ? WHERE id = ?").run("pending", 1, actionId);
  } finally {
    db.close();
  }
}

function ssrfDemoTarget(baseUrl: string): string {
  const target = new URL("/api/fetch", baseUrl);
  target.searchParams.set("url", new URL("/healthz", baseUrl).toString());
  return target.toString();
}

function outputOfSync(args: string[], cwd: string): string {
  const result = spawnSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      NO_COLOR: "1",
    },
  });
  expect(result.status, `${result.stdout ?? ""}${result.stderr ?? ""}`).toBe(0);
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function findFiles(root: string, fileName: string): string[] {
  if (!existsSync(root)) return [];
  const matches: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      matches.push(...findFiles(fullPath, fileName));
    } else if (entry.name === fileName || entry.name.endsWith(`-${fileName}`)) {
      matches.push(fullPath);
    }
  }
  return matches;
}
