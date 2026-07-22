#!/usr/bin/env node
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, type Stats } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { Command, Option } from "commander";
import type { ActionRecord } from "../core/actions/action-queue.js";
import { labAuthorizationFilePath, loadProgramFile, loadWorkspaceProgram } from "../core/config/config-loader.js";
import type { ProgramConfig } from "../core/config/program-schema.js";
import type { WorkflowEventRecord } from "../core/jobs/workflow-event-store.js";
import { runPackageReleaseCheck, runReleaseCheck } from "../core/release/release-check.js";
import { ensureWorkspace, programWorkspace, saveProgramConfig, workspacePaths } from "../core/workspace.js";
import { AgentPlanner, type PlannerActionContext } from "../engines/agent-planner/agent-planner.js";
import { DuplicateRiskEngine } from "../engines/duplicate-risk/duplicate-risk-engine.js";
import { candidateBaselineReportabilityScore } from "../engines/finding-candidates/finding-candidate-engine.js";
import {
  generateReproductionNote,
  isSupportedReportPlatform,
  writePlatformReport,
} from "../engines/report-generator/report-generator.js";
import { buildReportReview, type ReportReadiness } from "../engines/report-generator/report-review.js";
import { TriageEngine } from "../engines/triage/triage-engine.js";
import { IntegrationManager } from "../integrations/integration-manager/integration-manager.js";
import { McpClientManager } from "../integrations/mcp/mcp-client-manager.js";
import type { McpSessionStepInput } from "../integrations/mcp/mcp-stdio-executor.js";
import { ToolManager } from "../integrations/tool-manager/tool-manager.js";
import { latestToolApproval, toolApprovalIntegrationName } from "../integrations/tool-manager/tool-adapter-runner.js";
import { buildReleaseBundle, verifyReleaseBundle } from "../core/release/release-bundle.js";
import { buildReleaseGithubBootstrap } from "../core/release/release-github-bootstrap.js";
import { buildReleaseInstallCheck } from "../core/release/release-install-check.js";
import { buildReleasePublishPlan, buildReleasePublishStatus } from "../core/release/release-publish-plan.js";
import {
  ARSENAL_TOOLS,
  HUNT_PROFILES,
  getHuntProfile,
  renderVmArsenalMarkdown,
  renderVmBootstrapScript,
  type HuntProfile,
  type VmBootstrapLevel,
} from "../hunting/hunt-arsenal.js";
import { BUG_CLASSES, runHuntPlaybook, runHuntRecon, type HuntReconProfile } from "../hunting/recon-engine.js";
import { startDemoLabServer, type DemoLabServerHandle, type DemoLabServerInfo } from "../labs/demo-lab-server.js";
import { MissionRunner } from "../missions/mission-runner.js";
import { ProviderManager, type ProviderSummary, type ProviderVerifyResult } from "../providers/provider-manager.js";
import { ProviderChatClient, type ProviderChatMessage, type ProviderChatSession } from "../providers/provider-chat-client.js";
import {
  BUG_BOUNTY_PILOT_SKILL_ID,
  bundleSkillDefinition,
  exportSkillDefinition,
  listSkillDefinitions,
  loadSkillDefinition,
  validateSkillDefinition,
  verifySkillBundle,
  type SkillRunMode,
} from "../skills/skill-definition.js";
import { renderSkillReadinessPublicPlan, scoreSkillReadiness } from "../skills/skill-readiness.js";
import { runSkill, type SkillRunResult } from "../skills/skill-runner.js";
import { ActionExecutor } from "../workflows/action-executor.js";
import {
  WORKFLOW_BARRIER_ACTION_TYPE,
  WORKFLOW_BARRIER_ADAPTER,
  WORKFLOW_BARRIER_PURPOSE,
} from "../core/actions/production-action-authority.js";
import { writeHandoffBundle } from "../workflows/handoff-bundle.js";
import { WorkflowRunner, type WorkflowOptions, type WorkflowSummary } from "../workflows/run-workflow.js";
import { buildWorkspaceSummary, writeWorkspaceSummary, type WorkspaceSummary } from "../workflows/workspace-summary.js";
import { BountyPilotError } from "../utils/errors.js";
import { openPath } from "../utils/open-path.js";
import {
  createExecutableApprovalStore,
  inspectLocalPackageEntrypoint,
  resolveLocalExecutable,
  type InspectedNpmPackageEntrypoint,
} from "../utils/local-process-policy.js";
import { maskSecrets, maskSecretsDeep } from "../utils/secrets.js";
import type {
  BugClass,
  Confidence,
  DuplicateRisk,
  EvidenceArtifact,
  FindingCandidate,
  FindingCandidateReportability,
  FindingCandidateStatus,
  FindingStatus,
  NormalizedFinding,
  ReconObservation,
  ReconObservationKind,
  SeverityEstimate,
} from "../types.js";
import {
  createJobAuditLogger,
  createRuntime,
  modeFromOptions,
  planAllowedAction,
  planAllowedActionWithRecord,
  type Runtime,
} from "./runtime.js";
import * as ui from "./ui.js";

const program = new Command();
const MAX_MCP_SESSION_STEPS = 100;
const MAX_MCP_SESSION_STEPS_FILE_BYTES = 1_000_000;
const FINDING_STATUSES: FindingStatus[] = [
  "new",
  "needs_validation",
  "validated",
  "needs_manual_review",
  "report_drafted",
  "submitted",
  "duplicate",
  "invalid",
];
const SEVERITY_ESTIMATES: SeverityEstimate[] = ["info", "low", "medium", "high", "critical", "unknown"];
const CONFIDENCE_LEVELS: Confidence[] = ["low", "medium", "high"];
const DUPLICATE_RISKS: DuplicateRisk[] = ["low", "medium", "high", "unknown"];
const FINDING_CANDIDATE_STATUSES: FindingCandidateStatus[] = [
  "needs_manual_verification",
  "ready_for_draft",
  "promoted",
  "dismissed",
];
const FINDING_CANDIDATE_REPORTABILITIES: FindingCandidateReportability[] = [
  "blocked",
  "needs_review",
  "ready_for_draft",
];
const EVIDENCE_KINDS: Array<EvidenceArtifact["kind"]> = [
  "screenshot",
  "har",
  "console_log",
  "dom_snapshot",
  "browser_trace",
  "video",
  "desktop_screenshot",
  "desktop_action_log",
  "request_sample",
  "response_sample",
  "research_note",
  "evidence_note",
  "crawl_graph",
  "reproduction_note",
  "tool_output",
  "report",
];
const RECON_OBSERVATION_KINDS: ReconObservationKind[] = [
  "host",
  "url",
  "endpoint",
  "js_asset",
  "parameter",
  "form",
  "port",
  "technology",
  "vulnerability_signal",
  "finding_candidate",
];

program.exitOverride();
program.configureOutput({
  writeErr: (text) => {
    if (!requestedJsonOutput(process.argv)) {
      process.stderr.write(text);
    }
  },
});

function rootProgramName(): string | undefined {
  return program.opts<{ program?: string }>().program;
}

function rootToolRegistryPath(): string | undefined {
  return program.opts<{ toolRegistry?: string }>().toolRegistry ?? process.env.BOUNTYPILOT_TOOL_REGISTRY;
}

function commandFromArgs(args: unknown[]): Command {
  return args[args.length - 1] as Command;
}

program
  .name("bugbounty")
  .description("BountyPilot safe, local-first, scoped bug bounty CLI")
  .version("0.2.0")
  .option("-p, --program <name>", "Program name to load from .bounty/programs")
  .option("--tool-registry <path>", "Trusted tool registry YAML to merge with built-in tools")
  .addHelpText(
    "after",
    `

Common workflows:
  bugbounty init
  bugbounty import examples/program.yml
  bugbounty run api.example.com --dry-run --with safe-checks,js-analyzer,playwright,planner
  bugbounty cockpit
  bugbounty jobs timeline <job-id>
  bugbounty dashboard

Machine-readable output:
  Add --json to supported workflow, job, scope, action, tool, integration, MCP, planning, and reporting commands.

Local lab gate:
  bugbounty import examples/local-program.yml
  bugbounty lab demo --port 8080
  bugbounty lab e2e http://127.0.0.1:8080 --live --with safe-checks,js-analyzer
`,
  )
  .action(async () => {
    await runChatCommand({
      messageParts: [],
      options: { temperature: "0.2", maxTokens: "1200" },
      defaultLaunch: true,
    });
  });

const mission = program.command("mission").description("Run one typed, scope-bound local research mission");

mission
  .command("start")
  .option("--target <url>", "Optional in-scope HTTP(S) target")
  .option("--goal <goal>", "Mission goal (only local-report-draft is accepted)", "local-report-draft")
  .option("--profile <profile>", "Mission profile: recon, web, or validate", "web")
  .option("--session <class>", "Hermes session class", "normal")
  .option("--json", "Print the typed mission receipt as JSON")
  .description("Turn one Hermes request into one local, zero-live BountyPilot workflow")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      target?: string;
      goal: string;
      profile: string;
      session: string;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());

    try {
      const receipt = await new MissionRunner(runtime).run({
        schemaVersion: "bountypilot/mission-request/v1",
        origin: "hermes",
        program: runtime.config.program,
        goal: options.goal,
        profile: options.profile,
        sessionClass: options.session,
        ...(options.target ? { target: options.target } : {}),
        constraints: {
          liveTargetEffects: false,
          automaticSubmission: false,
        },
      });

      if (options.json || requestedJsonOutput(process.argv)) {
        ui.json(receipt);
        return;
      }

      ui.header("mission handoff");
      ui.status(receipt.accepted ? "ok" : "blocked", receipt.agentState);
      ui.panel("mission", [
        ui.kv("program", receipt.mission.request.program),
        ui.kv("profile", receipt.mission.request.profile),
        ui.kv("job", receipt.job.id),
        ui.kv("status", receipt.job.status),
        ui.kv("actions", receipt.actionIds.length),
        ui.kv("live target effects", false),
        ui.kv("automatic submission", false),
      ]);
      ui.blank();
      ui.commandList("human review commands", receipt.nextCommands);
    } catch (error) {
      if (!isMissionSemanticError(error)) {
        throw error;
      }
      const normalized = normalizeCliError(error);
      if (options.json || requestedJsonOutput(process.argv)) {
        ui.json({ ok: false, error: normalized });
      } else {
        ui.error(`[${normalized.code}] ${normalized.message}`);
      }
      process.exitCode = 2;
    }
  });

program
  .command("init")
  .option("--guided", "Print setup checks and copy-paste next commands")
  .option("--program-file <path>", "Validate and import a program file during guided setup")
  .option("--json", "Print machine-readable JSON")
  .description("Create a local .bounty workspace")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ guided?: boolean; programFile?: string; json?: boolean }>();
    const paths = ensureWorkspace(process.cwd());
    const imported = options.programFile ? importProgramIntoWorkspace(options.programFile, process.cwd()) : undefined;
    const guided = Boolean(options.guided || options.programFile);
    const doctor = guided ? buildDoctorGuidance(process.cwd(), false) : undefined;
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({
        ok: true,
        guided,
        workspace: paths.root,
        paths,
        import: imported,
        doctor,
        nextCommands: doctor?.nextCommands,
      });
      return;
    }
    ui.header(guided ? "guided setup" : "safe scoped evidence cli");
    ui.status("ok", "workspace initialized");
    ui.panel("workspace", [ui.kv("root", paths.root)]);
    if (imported) {
      ui.blank();
      ui.status("ok", `imported ${imported.program}`);
      ui.panel("program", [
        ui.kv("name", imported.program),
        ui.kv("platform", imported.config.platform),
        ui.kv("workspace", imported.paths.programDir),
        ui.kv("execution opt-ins stripped", imported.strippedExecutionOptIns.length),
      ]);
    }
    if (doctor) {
      ui.blank();
      ui.table(
        ["status", "check", "message"],
        doctor.checks.map((check) => [check.status, check.name, check.message]),
      );
      ui.blank();
      ui.commandList("next commands", doctor.nextCommands);
    }
  });

program
  .command("quickstart")
  .argument("[target]", "Optional in-scope target URL or host to build the first hunt loop around")
  .option("--profile <profile>", "Hunt profile for target-specific commands", "web")
  .option("--program-file <path>", "Program file to reference in setup commands when no program is imported")
  .option("--bootstrap-level <level>", "Arsenal bootstrap level: safe or full", "safe")
  .option("--write", "Write a local Markdown quickstart runbook")
  .option("--output <path>", "Runbook path when --write is used. Defaults to .bounty/quickstart.md.")
  .option("--json", "Print machine-readable JSON")
  .description("Generate a VM-first runbook from setup to hunt, results, evidence, and reporting")
  .action((target: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      profile: string;
      programFile?: string;
      bootstrapLevel: string;
      write?: boolean;
      output?: string;
      json?: boolean;
    }>();
    const profile = requireHuntProfile(options.profile);
    const bootstrapLevel = parseVmBootstrapLevel(options.bootstrapLevel);
    const runbook = buildQuickstartRunbook({
      cwd: process.cwd(),
      target,
      profile,
      programFile: options.programFile,
      bootstrapLevel,
    });
    const outputPath = options.write ? resolveQuickstartRunbookPath(process.cwd(), options.output) : undefined;
    const payload = outputPath ? { ...runbook, outputPath } : runbook;
    if (outputPath) {
      writeQuickstartRunbook(payload.markdown, outputPath);
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("quickstart");
    printQuickstartRunbook(payload);
  });

program
  .command("import")
  .argument("<programFile>", "Path to program.yml")
  .option("--json", "Print machine-readable JSON")
  .description("Import and validate a bug bounty program scope")
  .action((programFile: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const imported = importProgramIntoWorkspace(programFile, process.cwd());
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(imported);
      return;
    }
    ui.header("program import");
    ui.status("ok", `imported ${imported.program}`);
    ui.panel("program", [
      ui.kv("name", imported.program),
      ui.kv("platform", imported.config.platform),
      ui.kv("workspace", imported.paths.programDir),
      ui.kv("rate limit", imported.config.rules.rate_limit),
      ui.kv("lab authorization", imported.labAuthorizationFile ?? "-"),
      ui.kv("execution opt-ins stripped", imported.strippedExecutionOptIns.length),
    ]);
  });

const programs = program.command("programs").description("Manage imported bounty program workspaces");

programs
  .command("list")
  .option("--json", "Print machine-readable JSON")
  .description("List imported program workspaces")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const payload = listProgramSummaries(process.cwd());
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("programs");
    if (payload.programs.length === 0) {
      ui.status("warn", "no imported programs found");
      return;
    }
    ui.table(
      ["status", "name", "platform", "in scope", "out scope", "program file", "message"],
      payload.programs.map((entry) => [
        entry.status,
        entry.name,
        entry.platform,
        entry.inScope,
        entry.outOfScope,
        entry.programFile,
        entry.message,
      ]),
    );
  });

programs
  .command("show")
  .argument("[name]", "Program name. Defaults to --program or the only imported program.")
  .option("--json", "Print machine-readable JSON")
  .description("Show imported program config and workspace paths")
  .action((name: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const loaded = loadWorkspaceProgram(process.cwd(), name ?? rootProgramName());
    const paths = programWorkspace(loaded.config.program, process.cwd());
    const payload = {
      config: loaded.config,
      programFile: loaded.programFile,
      paths,
      integrations: Object.keys(loaded.config.integrations ?? {}),
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("programs show");
    ui.panel("program", [
      ui.kv("name", loaded.config.program),
      ui.kv("platform", loaded.config.platform),
      ui.kv("program file", loaded.programFile),
      ui.kv("workspace", paths.programDir),
      ui.kv("rate limit", loaded.config.rules.rate_limit),
      ui.kv("in scope", loaded.config.in_scope.length),
      ui.kv("out scope", loaded.config.out_of_scope.length),
      ui.kv("integrations", payload.integrations.length),
    ]);
    ui.blank();
    ui.list("in scope", loaded.config.in_scope);
    ui.blank();
    ui.list("out of scope", loaded.config.out_of_scope);
  });

programs
  .command("validate")
  .argument("<programFile>", "Path to a program.yml file")
  .option("--json", "Print machine-readable JSON")
  .description("Validate a program.yml file without importing it")
  .action((programFile: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const loaded = loadProgramFile(path.resolve(programFile));
    const payload = {
      ok: true,
      programFile: loaded.programFile,
      program: loaded.config.program,
      platform: loaded.config.platform,
      inScope: loaded.config.in_scope.length,
      outOfScope: loaded.config.out_of_scope.length,
      rateLimit: loaded.config.rules.rate_limit,
      integrations: Object.keys(loaded.config.integrations ?? {}),
    };
    if (options.json) {
      ui.json(payload);
      return;
    }
    ui.header("programs validate");
    ui.status("ok", "program file is valid");
    ui.panel("program", [
      ui.kv("name", payload.program),
      ui.kv("platform", payload.platform),
      ui.kv("in scope", payload.inScope),
      ui.kv("out scope", payload.outOfScope),
      ui.kv("rate limit", payload.rateLimit),
      ui.kv("integrations", payload.integrations.length),
    ]);
  });

const scope = program.command("scope").description("Inspect and test program scope");

scope
  .command("list")
  .option("--json", "Print machine-readable JSON")
  .description("List in-scope and out-of-scope rules")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const payload = {
      program: runtime.config.program,
      platform: runtime.config.platform,
      rateLimit: runtime.config.rules.rate_limit,
      inScope: runtime.config.in_scope,
      outOfScope: runtime.config.out_of_scope,
    };
    if (options.json) {
      ui.json(payload);
      return;
    }
    ui.header("scope");
    ui.panel("program", [
      ui.kv("name", payload.program),
      ui.kv("platform", payload.platform),
      ui.kv("rate limit", payload.rateLimit),
    ]);
    ui.blank();
    ui.list("in scope", payload.inScope);
    ui.blank();
    ui.list("out of scope", payload.outOfScope);
  });

scope
  .command("test")
  .argument("<url>", "URL or host to test")
  .option("--json", "Print machine-readable JSON")
  .description("Check whether a URL is allowed by ScopeGuard")
  .action((url: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const result = runtime.scopeGuard.test(url);
    if (options.json) {
      ui.json(result);
      process.exitCode = result.allowed ? 0 : 2;
      return;
    }
    ui.header("scope test");
    ui.status(result.allowed ? "ok" : "blocked", result.reason);
    ui.panel("target", [
      ui.kv("url", result.url),
      ui.kv("host", result.host),
      ui.kv("in scope", result.matchedInScope),
      ui.kv("out scope", result.matchedOutOfScope),
    ]);
    process.exitCode = result.allowed ? 0 : 2;
  });

program
  .command("run")
  .argument("[target]", "Program name, URL, or host. Defaults to the imported program scope.")
  .option("--mode <mode>", "Execution mode", "safe")
  .option(
    "--with <components>",
    "Comma-separated components: safe-checks,js-analyzer,playwright,triage,planner,crawl4ai,playwright-mcp,d-research-skill",
  )
  .option("--dry-run", "Plan workflow actions without network execution")
  .option("--draft-reports", "Generate local report drafts for high-reportability findings")
  .option("--json", "Print machine-readable JSON")
  .description("Run the scoped BountyPilot workflow pipeline")
  .action(async (target: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      mode?: string;
      with?: string;
      dryRun?: boolean;
      draftReports?: boolean;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    if (!options.json) {
      ui.header("workflow");
      ui.status(options.dryRun ? "planned" : "running", `${mode} pipeline started`);
    }
    const summary = await new WorkflowRunner(runtime).run({
      target,
      mode,
      dryRun: options.dryRun,
      draftReports: options.draftReports,
      withComponents: parseComponentList(options.with),
    });
    if (summary.status === "failed" || summary.phases.some((phase) => phase.status === "failed")) {
      process.exitCode = 1;
    } else if (options.dryRun !== true && summary.status === "paused") {
      process.exitCode = 2;
    }
    if (options.json) {
      ui.json({ summary: workflowSummaryForDisplay(runtime, summary), events: runtime.events.list(summary.jobId) });
    } else {
      printWorkflowSummary(workflowSummaryForDisplay(runtime, summary));
      printWorkflowTimeline(runtime.events.list(summary.jobId, 8), "recent events");
    }
  });

const hunt = program.command("hunt").description("Run authorized bug bounty hunting profiles");

hunt
  .command("profiles")
  .option("--json", "Print machine-readable JSON")
  .description("List guided hunting profiles inspired by recon-to-report bug bounty workflows")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    if (options.json) {
      ui.json({ profiles: HUNT_PROFILES });
      return;
    }
    ui.header("hunt profiles");
    ui.table(
      ["profile", "mode", "components", "purpose"],
      HUNT_PROFILES.map((profile) => [profile.id, profile.mode, profile.components.join(","), profile.purpose]),
    );
  });

hunt
  .command("doctor")
  .argument("[target]", "Optional in-scope URL or host")
  .option("--profile <id>", "Hunt profile: recon, web, validate, lab-aggressive", "recon")
  .option("--json", "Print machine-readable JSON")
  .description("Check whether the workspace is ready to hunt a scoped target")
  .action((target: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ profile: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const profile = requireHuntProfile(options.profile);
    const result = buildHuntDoctor(runtime, profile, target);
    if (options.json) {
      ui.json(result);
      process.exitCode = result.ok ? 0 : 1;
      return;
    }
    ui.header("hunt doctor");
    printHuntDoctor(result);
    process.exitCode = result.ok ? 0 : 1;
  });

hunt
  .command("plan")
  .argument("<target>", "In-scope URL or host")
  .option("--profile <id>", "Hunt profile: recon, web, validate, lab-aggressive", "recon")
  .option("--write", "Write a local Markdown hunt plan")
  .option("--output <path>", "Plan path when --write is used. Defaults to the program research folder.")
  .option("--json", "Print machine-readable JSON")
  .description("Build a scoped hunt plan without running network activity")
  .action((target: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ profile: string; write?: boolean; output?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const profile = requireHuntProfile(options.profile);
    const scoped = runtime.scopeGuard.assertAllowed(target);
    const payload = buildHuntPlanPayload(runtime, profile, scoped.url, options.write ? resolveHuntPlanPath(runtime, profile, options.output) : undefined);
    if (payload.planPath) {
      mkdirSync(path.dirname(payload.planPath), { recursive: true });
      writeFileSync(payload.planPath, payload.markdown, "utf8");
    }
    if (options.json) {
      ui.json(payload);
      return;
    }
    ui.header("hunt plan");
    ui.status("ok", `${profile.id} plan ready`);
    printHuntPlan(payload);
  });

hunt
  .command("run")
  .argument("<target>", "In-scope URL or host")
  .option("--profile <id>", "Hunt profile: recon, web, validate, lab-aggressive", "recon")
  .option("--dry-run", "Plan workflow actions without network execution")
  .option("--live", "Run selected profile components after scope and policy gates pass")
  .option("--draft-reports", "Generate local report drafts for high-reportability findings")
  .option("--json", "Print machine-readable JSON")
  .description("Run a guided hunt profile through BountyPilot guardrails")
  .action(async (target: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ profile: string; dryRun?: boolean; live?: boolean; draftReports?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const profile = requireHuntProfile(options.profile);
    const dryRun = options.live === true ? false : true;
    if (options.dryRun && options.live) {
      throw new BountyPilotError("Use either --dry-run or --live, not both.", "HUNT_MODE_CONFLICT");
    }
    if (!options.json) {
      ui.header("hunt run");
      ui.status(dryRun ? "planned" : "running", `${profile.id} profile started`);
      ui.panel("profile", [
        ui.kv("target", target),
        ui.kv("profile", profile.id),
        ui.kv("mode", profile.mode),
        ui.kv("live", !dryRun),
      ]);
    }
    const summary = await new WorkflowRunner(runtime).run({
      target,
      mode: profile.mode,
      dryRun,
      draftReports: options.draftReports,
      withComponents: profile.components,
    });
    if (summary.status === "failed") {
      process.exitCode = 1;
    }
    const payload = {
      ok: summary.status !== "failed",
      profile,
      summary: workflowSummaryForDisplay(runtime, summary),
      events: runtime.events.list(summary.jobId),
      nextCommands: huntNextCommands(summary),
    };
    if (options.json) {
      ui.json(payload);
      return;
    }
    printWorkflowSummary(payload.summary, "hunt workflow handoff");
    printWorkflowTimeline(runtime.events.list(summary.jobId, 8), "recent events");
    ui.blank();
    ui.commandList("hunt follow-up", payload.nextCommands);
  });

hunt
  .command("recon")
  .argument("<target>", "In-scope URL or host")
  .option("--profile <profile>", "Recon profile: passive or web", "passive")
  .option("--tools <tools>", "Comma-separated trusted tools to include")
  .option("--dry-run", "Plan recon actions without executing tools")
  .option("--live", "Record live intent for human handoff; tools are not executed automatically")
  .option("--json", "Print machine-readable JSON")
  .description("Plan a scoped recon pipeline and store a zero-effect human handoff")
  .action(async (target: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ profile: string; tools?: string; dryRun?: boolean; live?: boolean; json?: boolean }>();
    if (options.dryRun && options.live) {
      throw new BountyPilotError("Use either --dry-run or --live, not both.", "HUNT_MODE_CONFLICT");
    }
    const runtime = createRuntime(rootProgramName());
    const result = await runHuntRecon(runtime, target, {
      profile: parseHuntReconProfile(options.profile),
      live: options.live === true,
      tools: parseCommaList(options.tools),
    });
    if (!result.ok) {
      process.exitCode = 1;
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("hunt recon");
    ui.status(result.ok ? "planned" : "warn", `${result.profile} recon handoff recorded`);
    ui.panel("recon", [
      ui.kv("job", result.jobId),
      ui.kv("target", result.target),
      ui.kv("live", result.live),
      ui.kv("actions", result.actionsPlanned),
      ui.kv("observations", result.observations.length),
      ui.kv("evidence", result.evidence.length),
    ]);
    ui.blank();
    ui.table(
      ["status", "tool", "executable pin", "observations", "message"],
      result.tools.map((tool) => [tool.status, tool.tool, tool.approvalPresent, tool.observations, tool.message]),
    );
    ui.blank();
    ui.commandList("next commands", result.nextCommands);
  });

hunt
  .command("playbook")
  .argument("<bugClass>", `Bug class: ${BUG_CLASSES.join(", ")}`)
  .argument("<target>", "In-scope URL or host")
  .option("--dry-run", "Plan playbook actions without target execution")
  .option("--live", "Execute only allowlisted low-risk built-ins through lifecycle; keep validation as human handoff")
  .option("--json", "Print machine-readable JSON")
  .description("Run a guarded bug-class playbook with lifecycle-bound low-risk checks and human validation handoff")
  .action(async (bugClass: string, target: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ dryRun?: boolean; live?: boolean; json?: boolean }>();
    if (options.dryRun && options.live) {
      throw new BountyPilotError("Use either --dry-run or --live, not both.", "HUNT_MODE_CONFLICT");
    }
    const runtime = createRuntime(rootProgramName());
    const result = await runHuntPlaybook(runtime, parseBugClass(bugClass), target, options.live === true);
    // Policy blocks are failures. A paused playbook is a successful guarded
    // handoff: allowed low-risk work may have completed, but validation is not
    // represented as finished or report-ready.
    if (!result.ok) {
      process.exitCode = 1;
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    const headlineStatus: "ok" | "planned" | "blocked" = result.paused
      ? "planned"
      : result.ok
        ? "ok"
        : "blocked";
    const headlineLabel = result.paused
      ? `${result.bugClass} playbook paused for human approval`
      : !result.ok
        ? `${result.bugClass} playbook blocked by policy`
        : result.live && result.actionsExecuted > 0
          ? `${result.bugClass} playbook low-risk execution completed`
          : `${result.bugClass} playbook plan recorded`;
    ui.header("hunt playbook");
    ui.status(headlineStatus, headlineLabel);
    ui.panel("playbook", [
      ui.kv("job", result.jobId),
      ui.kv("target", result.target),
      ui.kv("live", result.live),
      ui.kv("actions", result.actionsPlanned),
      ui.kv("executed", result.actionsExecuted),
      ui.kv("pending", result.actionsPending),
      ui.kv("observations", result.observations.length),
      ui.kv("findings", result.findingsCreated.length),
      ui.kv("evidence", result.evidence.length),
      ui.kv("paused", result.paused === true),
      ui.kv("blocked", !result.ok),
    ]);
    if (result.findingsCreated.length > 0) {
      ui.blank();
      ui.table(
        ["severity", "confidence", "score", "id", "title"],
        result.findingsCreated.map((finding) => [
          finding.severityEstimate,
          finding.confidence,
          finding.reportabilityScore,
          finding.id,
          finding.title,
        ]),
      );
    }
    ui.blank();
    ui.commandList("next commands", result.nextCommands);
  });

hunt
  .command("autopilot")
  .argument("<target>", "In-scope URL or host")
  .option("--profile <id>", "Hunt profile: recon, web, validate, lab-aggressive", "web")
  .option("--dry-run", "Plan workflow actions without network execution")
  .option("--live", "Run selected profile components after scope and policy gates pass")
  .option("--write-plan", "Write the Markdown hunt plan before running")
  .option("--plan-output <path>", "Plan path when --write-plan is used")
  .option("--draft-reports", "Generate local report drafts for high-reportability findings")
  .option("--bundle", "Write a local handoff bundle for the generated job")
  .option("--bundle-output <path>", "Bundle output directory")
  .option("--include-artifacts", "Copy readable evidence files into the handoff bundle")
  .option("--json", "Print machine-readable JSON")
  .description("Run plan, profile workflow, review, and optional handoff bundle as one guarded flow")
  .action(async (target: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      profile: string;
      dryRun?: boolean;
      live?: boolean;
      writePlan?: boolean;
      planOutput?: string;
      draftReports?: boolean;
      bundle?: boolean;
      bundleOutput?: string;
      includeArtifacts?: boolean;
      json?: boolean;
    }>();
    if (options.dryRun && options.live) {
      throw new BountyPilotError("Use either --dry-run or --live, not both.", "HUNT_MODE_CONFLICT");
    }
    const runtime = createRuntime(rootProgramName());
    const profile = requireHuntProfile(options.profile);
    const scoped = runtime.scopeGuard.assertAllowed(target);
    const live = options.live === true;
    const plan = options.writePlan
      ? buildHuntPlanPayload(runtime, profile, scoped.url, resolveHuntPlanPath(runtime, profile, options.planOutput))
      : undefined;
    if (plan?.planPath) {
      mkdirSync(path.dirname(plan.planPath), { recursive: true });
      writeFileSync(plan.planPath, plan.markdown, "utf8");
    }
    if (!options.json) {
      ui.header("hunt autopilot");
      ui.status(live ? "running" : "planned", `${profile.id} autopilot started`);
      ui.panel("autopilot", [
        ui.kv("target", scoped.url),
        ui.kv("profile", profile.id),
        ui.kv("mode", profile.mode),
        ui.kv("live", live),
        ui.kv("plan", plan?.planPath),
      ]);
    }
    const recon = await runHuntRecon(runtime, scoped.url, {
      profile: profile.id === "recon" ? "passive" : "web",
      live,
    });
    const summary = await new WorkflowRunner(runtime).run({
      target: scoped.url,
      mode: profile.mode,
      dryRun: !live,
      draftReports: options.draftReports,
      withComponents: profile.components,
    });
    const review = buildJobReview(runtime, summary.jobId, 12);
    const bundle = options.bundle
      ? writeHandoffBundle(runtime, {
          jobId: summary.jobId,
          output: options.bundleOutput,
          includeArtifacts: options.includeArtifacts === true,
        })
      : undefined;
    const payload: HuntAutopilotResult = {
      ok: summary.status !== "failed",
      profile,
      target: scoped.url,
      live,
      plan,
      recon,
      summary: workflowSummaryForDisplay(runtime, summary),
      review,
      bundle,
      nextCommands: huntNextCommands(summary),
    };
    if (summary.status === "failed") {
      process.exitCode = 1;
    }
    if (options.json) {
      ui.json(payload);
      return;
    }
    printWorkflowSummary(payload.summary, "autopilot finished");
    printWorkflowTimeline(runtime.events.list(summary.jobId, 8), "recent events");
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      review.cockpit.checks.map((check) => [check.status, check.name, check.message]),
    );
    if (bundle) {
      ui.blank();
      ui.status("ok", `handoff bundle written: ${bundle.outputDir}`);
    }
    ui.blank();
    ui.panel("recon", [
      ui.kv("job", recon.jobId),
      ui.kv("tools", recon.tools.length),
      ui.kv("observations", recon.observations.length),
      ui.kv("actions", recon.actionsPlanned),
    ]);
    ui.blank();
    ui.commandList("autopilot follow-up", payload.nextCommands);
  });

const recon = program.command("recon").description("Inspect normalized recon observations");

recon
  .command("list")
  .option("--job <jobId>", "Only include observations from one job")
  .option("--kind <kind>", `Filter by kind: ${RECON_OBSERVATION_KINDS.join(", ")}`)
  .option("--source <adapter>", "Filter by source adapter/tool")
  .option("--include-out-of-scope", "Include observations that were stored as out-of-scope")
  .option("--limit <limit>", "Maximum number of observations", "50")
  .option("--json", "Print machine-readable JSON")
  .description("List stored recon observations")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      job?: string;
      kind?: string;
      source?: string;
      includeOutOfScope?: boolean;
      limit: string;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) requireJob(runtime, options.job);
    const limit = parsePositiveIntegerOption(options.limit, "limit", 50);
    const kind = options.kind ? parseReconObservationKind(options.kind) : undefined;
    const sourceAdapter = options.source ? parseNonEmptyTextOption(options.source, "source") : undefined;
    const observations = runtime.recon.list({
      jobId: options.job,
      kind,
      sourceAdapter,
      scopeAllowed: options.includeOutOfScope ? undefined : true,
      limit,
    });
    const counts = reconObservationCounts(observations);
    const payload = {
      ok: true,
      filters: {
        jobId: options.job,
        kind,
        sourceAdapter,
        includeOutOfScope: options.includeOutOfScope === true,
        limit,
      },
      counts,
      observations,
      nextCommands: observations.slice(0, 5).map((observation) => `bounty recon show ${observation.id}`),
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("recon observations");
    if (observations.length === 0) {
      ui.status("warn", "no recon observations found");
      return;
    }
    ui.panel("filters", [
      ui.kv("job", options.job ?? "-"),
      ui.kv("kind", kind ?? "-"),
      ui.kv("source", sourceAdapter ?? "-"),
      ui.kv("limit", limit),
      ui.kv("observations", observations.length),
    ]);
    ui.blank();
    ui.table(
      ["kind", "confidence", "risk", "source", "value"],
      observations.map((observation) => [
        observation.kind,
        observation.confidence,
        observation.riskHint ?? "-",
        observation.sourceAdapter,
        observation.normalizedValue,
      ]),
    );
    ui.blank();
    ui.commandList("next commands", payload.nextCommands);
  });

recon
  .command("show")
  .argument("<idOrFingerprint>", "Recon observation id or fingerprint")
  .option("--json", "Print machine-readable JSON")
  .description("Show one recon observation with related job evidence")
  .action((idOrFingerprint: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const observation = runtime.recon.get(idOrFingerprint);
    if (!observation) {
      throw new BountyPilotError(`Recon observation not found: ${idOrFingerprint}`, "RECON_OBSERVATION_NOT_FOUND");
    }
    const evidence = observation.jobId ? runtime.evidence.list().filter((artifact) => artifact.jobId === observation.jobId) : [];
    const payload = {
      ok: true,
      observation,
      evidence,
      nextCommands: [
        observation.jobId ? `bounty jobs timeline ${observation.jobId}` : undefined,
        observation.jobId ? `bounty evidence --job ${observation.jobId}` : undefined,
        observation.sourceUrl ? `bounty hunt playbook xss ${observation.sourceUrl} --dry-run` : undefined,
      ].filter((item): item is string => Boolean(item)),
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("recon show");
    ui.panel("observation", [
      ui.kv("id", observation.id),
      ui.kv("kind", observation.kind),
      ui.kv("value", observation.value),
      ui.kv("normalized", observation.normalizedValue),
      ui.kv("source", observation.sourceAdapter),
      ui.kv("source url", observation.sourceUrl ?? "-"),
      ui.kv("job", observation.jobId ?? "-"),
      ui.kv("scope", observation.scopeAllowed ? "allowed" : "out-of-scope"),
      ui.kv("confidence", observation.confidence),
      ui.kv("risk", observation.riskHint ?? "-"),
      ui.kv("fingerprint", observation.fingerprint),
      ui.kv("last seen", observation.lastSeenAt),
    ]);
    if (evidence.length > 0) {
      ui.blank();
      ui.table(
        ["kind", "adapter", "id", "path"],
        evidence.slice(0, 20).map((artifact) => [artifact.kind, artifact.adapterName, artifact.id, artifact.path]),
      );
    }
    ui.blank();
    ui.commandList("next commands", payload.nextCommands);
  });

const arsenal = program.command("arsenal").description("Plan a VM-ready bug bounty tool arsenal");

arsenal
  .command("profiles")
  .option("--json", "Print machine-readable JSON")
  .description("List curated tool categories and run policies")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    if (options.json) {
      ui.json({ tools: ARSENAL_TOOLS });
      return;
    }
    ui.header("arsenal profiles");
    ui.table(
      ["tool", "category", "policy", "purpose"],
      ARSENAL_TOOLS.map((tool) => [tool.name, tool.category, tool.runPolicy, tool.purpose]),
    );
  });

arsenal
  .command("vm")
  .option("--write", "Write the VM arsenal plan as Markdown")
  .option("--output <path>", "Plan path when --write is used. Defaults to .bounty/arsenal/vm-arsenal.md.")
  .option("--json", "Print machine-readable JSON")
  .description("Generate a VM bootstrap plan without installing tools")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ write?: boolean; output?: string; json?: boolean }>();
    const markdown = renderVmArsenalMarkdown();
    const outputPath = options.write ? resolveArsenalPlanPath(process.cwd(), options.output) : undefined;
    if (outputPath) {
      mkdirSync(path.dirname(outputPath), { recursive: true });
      writeFileSync(outputPath, markdown, "utf8");
    }
    const payload = {
      ok: true,
      outputPath,
      profiles: HUNT_PROFILES,
      tools: ARSENAL_TOOLS,
      markdown,
      nextCommands: ["bounty providers catalog", "bounty hunt profiles", "bounty hunt run <in-scope-target> --profile recon --dry-run"],
    };
    if (options.json) {
      ui.json(payload);
      return;
    }
    ui.header("arsenal vm");
    ui.status("ok", outputPath ? `wrote ${outputPath}` : "vm arsenal plan ready");
    ui.table(
      ["tool", "category", "policy"],
      ARSENAL_TOOLS.map((tool) => [tool.name, tool.category, tool.runPolicy]),
    );
    ui.blank();
    ui.commandList("next commands", payload.nextCommands);
  });

arsenal
  .command("bootstrap")
  .option("--level <level>", "Bootstrap level: safe or full", "safe")
  .option("--write", "Write the bootstrap script")
  .option("--output <path>", "Script path when --write is used. Defaults to .bounty/arsenal/bootstrap.sh.")
  .option("--json", "Print machine-readable JSON")
  .description("Generate a reviewed VM install script without executing it")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ level: string; write?: boolean; output?: string; json?: boolean }>();
    const level = parseVmBootstrapLevel(options.level);
    const script = renderVmBootstrapScript(level);
    const outputPath = options.write ? resolveArsenalBootstrapPath(process.cwd(), options.output) : undefined;
    if (outputPath) {
      mkdirSync(path.dirname(outputPath), { recursive: true });
      writeFileSync(outputPath, script, "utf8");
    }
    const payload = {
      ok: true,
      level,
      outputPath,
      script,
      nextCommands: outputPath
        ? [`less ${outputPath}`, `bash ${outputPath}`, "bounty arsenal profiles", "bounty hunt profiles"]
        : ["bounty arsenal bootstrap --write", "bounty arsenal profiles", "bounty hunt profiles"],
    };
    if (options.json) {
      ui.json(payload);
      return;
    }
    ui.header("arsenal bootstrap");
    ui.status("ok", outputPath ? `wrote ${outputPath}` : "bootstrap script generated");
    ui.panel("script", [
      ui.kv("level", level),
      ui.kv("output", outputPath),
      ui.kv("execution", "not run"),
    ]);
    ui.blank();
    ui.commandList("next commands", payload.nextCommands);
  });

const skill = program.command("skill").description("Manage packaged BountyPilot skills and workflow engines");

skill
  .command("list")
  .option("--json", "Print machine-readable JSON")
  .description("List available local and bundled skills")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const skills = listSkillDefinitions(process.cwd());
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, skills });
      return;
    }
    ui.header("skills");
    ui.table(
      ["id", "bundled", "title", "root"],
      skills.map((entry) => [entry.id, entry.bundled, entry.title, entry.root]),
    );
  });

skill
  .command("show")
  .argument("[id]", "Skill id", BUG_BOUNTY_PILOT_SKILL_ID)
  .option("--json", "Print machine-readable JSON")
  .description("Show a skill definition summary")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const definition = loadSkillDefinition(id, process.cwd());
    const payload = {
      ok: true,
      id: definition.id,
      root: definition.root,
      frontmatter: definition.frontmatter,
      agentMetadata: definition.agentMetadata,
      modes: Object.keys(definition.policy.modes),
      workflowSteps: definition.workflow.steps.map((step) => step.id),
      tools: definition.toolRegistry.tools.map((tool) => tool.name),
      playbooks: definition.playbooks.playbooks.map((playbook) => playbook.id),
      prompts: Object.keys(definition.prompts),
      templates: Object.keys(definition.templates),
      examples: Object.keys(definition.examples),
      markdown: definition.skillMarkdown,
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("skill show");
    ui.panel("skill", [
      ui.kv("id", definition.id),
      ui.kv("name", definition.frontmatter.name),
      ui.kv("root", definition.root),
      ui.kv("modes", payload.modes.join(", ")),
      ui.kv("steps", payload.workflowSteps.length),
      ui.kv("tools", payload.tools.length),
      ui.kv("playbooks", payload.playbooks.length),
      ui.kv("prompts", payload.prompts.length),
      ui.kv("templates", payload.templates.length),
    ]);
    ui.blank();
    ui.commandList("next commands", [
      `bounty skill validate ${definition.id}`,
      `bounty skill score ${definition.id}`,
      `bounty skill run ${definition.id} <in-scope-target> --mode passive --dry-run`,
      `bounty skill export ${definition.id} --output .bounty/skills/${definition.id}`,
    ]);
  });

skill
  .command("validate")
  .argument("[id]", "Skill id", BUG_BOUNTY_PILOT_SKILL_ID)
  .option("--json", "Print machine-readable JSON")
  .description("Validate skill policy, workflow, registry, playbooks, and package files")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const result = validateSkillDefinition(id, process.cwd());
    if (!result.ok) {
      process.exitCode = 1;
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("skill validate");
    ui.status(result.ok ? "ok" : "blocked", result.ok ? "skill package is valid" : "skill package has blockers");
    ui.panel("skill", [
      ui.kv("id", result.id),
      ui.kv("root", result.root),
      ui.kv("checks", result.checks.length),
      ui.kv("failures", result.checks.filter((check) => check.status === "fail").length),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      result.checks.map((check) => [check.status, check.name, check.message]),
    );
  });

skill
  .command("score")
  .argument("[id]", "Skill id", BUG_BOUNTY_PILOT_SKILL_ID)
  .option("--repo <repo>", "Optional GitHub repository OWNER/REPO for concrete publish readiness checks")
  .option("--branch <branch>", "Branch to use when --repo is provided. Defaults to current branch or main.")
  .option("--tag <tag>", "Release tag to use when --repo is provided. Defaults to v<package.version>.")
  .option("--remote <kind>", "Preferred remote style when --repo is provided: https or ssh", "https")
  .option("--gh-command <command>", "GitHub CLI command to probe when --repo is provided", "gh")
  .option("--gh-command-arg <arg>", "Argument to prepend before gh probe arguments. Repeat for wrappers.", collectOption, [] as string[])
  .option("--timeout-ms <ms>", "Per-command timeout in milliseconds for GitHub probes", "8000")
  .option("--online", "When --repo is provided, verify pushed branch/tag state through git ls-remote")
  .option("--actions", "When --repo is provided, verify required GitHub Actions runs through GitHub CLI")
  .option("--write-public-plan <path>", "Write a Markdown checklist for the remaining public-readiness work")
  .option("--strict", "Exit non-zero unless readiness is ultimate with no blockers or warnings")
  .option("--json", "Print machine-readable JSON")
  .description("Score skill readiness across validation, bundle verification, and release gates")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      repo?: string;
      branch?: string;
      tag?: string;
      remote: string;
      ghCommand: string;
      ghCommandArg: string[];
      timeoutMs: string;
      online?: boolean;
      actions?: boolean;
      writePublicPlan?: string;
      strict?: boolean;
      json?: boolean;
    }>();
    const timeoutMs = parsePositiveIntegerOption(options.timeoutMs, "timeout-ms", 8_000);
    const result = scoreSkillReadiness({
      id,
      cwd: process.cwd(),
      repo: options.repo,
      branch: options.branch,
      tag: options.tag,
      remote: parseReleaseRemotePreference(options.remote),
      ghCommand: options.ghCommand,
      ghArgsPrefix: options.ghCommandArg,
      timeoutMs,
      online: options.online,
      actions: options.actions,
    });
    const publicReadinessPlanPath = options.writePublicPlan
      ? writePublicReadinessPlan(options.writePublicPlan, renderSkillReadinessPublicPlan(result))
      : undefined;
    if (!result.ok || (options.strict && !result.ultimate)) {
      process.exitCode = 1;
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(publicReadinessPlanPath ? { ...result, publicReadinessPlanPath } : result);
      return;
    }
    ui.header("skill score");
    ui.status(result.ok ? "ok" : "blocked", `${result.score}/100 ${result.readiness}`);
    ui.panel("readiness", [
      ui.kv("id", result.id),
      ui.kv("root", result.root),
      ui.kv("score", `${result.score}/100`),
      ui.kv("ultimate", result.ultimate),
      ui.kv("validation", `${result.validation.checks} checks, ${result.validation.failures.length} failure(s)`),
      ui.kv("bundle", result.bundle.ok ? `${result.bundle.files} files verified` : "failed"),
      ui.kv("release", `${result.release.checks} checks, ${result.release.failures.length} failure(s), ${result.release.warnings.length} warning(s)`),
    ]);
    ui.blank();
    ui.table(
      ["layer", "score", "readiness", "blockers", "warnings"],
      [
        [
          "local",
          `${result.layers.local.score}/100`,
          result.layers.local.readiness,
          result.layers.local.blockers.length,
          result.layers.local.warnings.length,
        ],
        [
          "publish",
          `${result.layers.publish.score}/100`,
          result.layers.publish.readiness,
          result.layers.publish.blockers.length,
          result.layers.publish.warnings.length,
        ],
      ],
    );
    ui.blank();
    ui.panel("public readiness", [
      ui.kv("score", `${result.publicReadiness.score}/100`),
      ui.kv("readiness", result.publicReadiness.readiness),
      ui.kv("ultimate", result.publicReadiness.ultimate),
      ui.kv("missing", result.publicReadiness.missing.length),
      ui.kv("plan", publicReadinessPlanPath ?? "not written"),
    ]);
    ui.blank();
    ui.table(
      ["status", "requirement", "message"],
      result.publicReadiness.requirements.map((requirement) => [requirement.status, requirement.name, requirement.message]),
    );
    ui.blank();
    ui.table(
      ["status", "phase", "requirements", "commands"],
      result.publicReadiness.fixPlan.map((step) => [
        step.status,
        step.id,
        step.requirements.join(", ") || "-",
        step.commands.length,
      ]),
    );
    const publicFixCommands = [...new Set(result.publicReadiness.missing.flatMap((requirement) => requirement.commands))];
    if (publicFixCommands.length > 0) {
      ui.blank();
      ui.commandList("public readiness fixes", publicFixCommands);
    }
    if (result.github) {
      ui.blank();
      ui.panel("github", [
        ui.kv("repo", result.github.repo),
        ui.kv("branch", result.github.branch),
        ui.kv("tag", result.github.tag),
        ui.kv("origin", result.github.origin ?? "not configured"),
        ui.kv("bootstrap", result.github.ok ? "ready" : "needs setup"),
      ]);
      ui.blank();
      ui.table(
        ["status", "check", "message"],
        result.github.checks.map((check) => [check.status, check.name, check.message]),
      );
    }
    if (result.publish) {
      ui.blank();
      ui.panel("publish", [
        ui.kv("repo", result.publish.repo),
        ui.kv("branch", result.publish.branch),
        ui.kv("tag", result.publish.tag),
        ui.kv("online", result.publish.online),
        ui.kv("actions", result.publish.actions),
        ui.kv("status", result.publish.ok ? "verified" : "needs verification"),
      ]);
      ui.blank();
      ui.table(
        ["status", "check", "message"],
        result.publish.checks.map((check) => [check.status, check.name, check.message]),
      );
    }
    if (result.blockers.length > 0) {
      ui.blank();
      ui.table(
        ["blocker", "message"],
        result.blockers.map((issue) => [issue.name, issue.message]),
      );
    }
    if (result.warnings.length > 0) {
      ui.blank();
      ui.table(
        ["warning", "message"],
        result.warnings.map((issue) => [issue.name, issue.message]),
      );
    }
    ui.blank();
    ui.commandList("next commands", result.nextSteps);
  });

skill
  .command("export")
  .argument("[id]", "Skill id", BUG_BOUNTY_PILOT_SKILL_ID)
  .requiredOption("--output <path>", "Destination directory")
  .option("--json", "Print machine-readable JSON")
  .description("Copy a bundled skill into a local workspace skill directory")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ output: string; json?: boolean }>();
    const result = exportSkillDefinition({ id, output: options.output, cwd: process.cwd() });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, ...result });
      return;
    }
    ui.header("skill export");
    ui.status("ok", `exported ${result.id}`);
    ui.panel("export", [
      ui.kv("source", result.source),
      ui.kv("output", result.output),
      ui.kv("files", result.files),
    ]);
    ui.blank();
    ui.commandList("next commands", [`bounty skill validate ${result.id}`, `bounty skill show ${result.id}`]);
  });

skill
  .command("bundle")
  .argument("[id]", "Skill id", BUG_BOUNTY_PILOT_SKILL_ID)
  .option("--output <path>", "Destination ZIP path. Defaults to .bounty/skills/bundles/<id>.skill.zip.")
  .option("--json", "Print machine-readable JSON")
  .description("Write a portable skill ZIP bundle with a SHA-256 manifest")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ output?: string; json?: boolean }>();
    const result = bundleSkillDefinition({ id, output: options.output, cwd: process.cwd() });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("skill bundle");
    ui.status("ok", `bundled ${result.id}`);
    ui.panel("bundle", [
      ui.kv("source", result.source),
      ui.kv("output", result.output),
      ui.kv("format", result.format),
      ui.kv("files", result.files),
      ui.kv("bytes", result.bytes),
      ui.kv("sha256", result.sha256),
    ]);
    ui.blank();
    ui.commandList("next commands", [`bounty skill validate ${result.id}`, `Get-FileHash -Algorithm SHA256 ${result.output}`]);
  });

skill
  .command("verify-bundle")
  .argument("<bundle>", "Path to a bug-bounty-pilot.skill.zip bundle")
  .option("--json", "Print machine-readable JSON")
  .description("Verify a standalone skill ZIP bundle manifest and SHA-256 hashes")
  .action((bundle: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const result = verifySkillBundle({ bundle, cwd: process.cwd() });
    if (!result.ok) {
      process.exitCode = 1;
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("skill verify-bundle");
    ui.status(result.ok ? "ok" : "blocked", result.ok ? "skill bundle verified" : "skill bundle failed verification");
    ui.panel("bundle", [
      ui.kv("path", result.bundle),
      ui.kv("bytes", result.bytes),
      ui.kv("sha256", result.sha256),
      ui.kv("skill", result.manifest?.id),
      ui.kv("files", `${result.files.verified}/${result.files.expected}`),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      result.checks.map((check) => [check.status, check.name, check.message]),
    );
  });

skill
  .command("run")
  .argument("[id]", "Skill id", BUG_BOUNTY_PILOT_SKILL_ID)
  .argument("<target>", "In-scope URL or host")
  .option("--program <program>", "Program workspace to load")
  .option("--mode <mode>", "Skill mode: passive, safe, deep-safe, or lab-offensive", "passive")
  .option("--with <components>", "Comma-separated workflow components")
  .option("--dry-run", "Plan actions without live execution")
  .option("--live", "Run allowed live workflow phases after scope and policy gates pass")
  .option("--review-required", "Keep review-required actions explicit in the result")
  .option("--json", "Print machine-readable JSON")
  .description("Run a skill workflow through the existing BountyPilot safety engine")
  .action(async (id: string, target: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      program?: string;
      mode: string;
      with?: string;
      dryRun?: boolean;
      live?: boolean;
      reviewRequired?: boolean;
      json?: boolean;
    }>();
    const result = await runSkill({
      id,
      target,
      program: options.program ?? rootProgramName(),
      mode: parseSkillRunMode(options.mode),
      withComponents: parseComponentList(options.with),
      dryRun: options.dryRun,
      live: options.live,
      reviewRequired: options.reviewRequired,
      cwd: process.cwd(),
    });
    if (!result.ok) {
      process.exitCode = 1;
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    printSkillRunResult(result);
  });

const lab = program.command("lab").description("Run local lab safety and E2E gates");

lab
  .command("demo")
  .option("--host <host>", "Loopback host to bind", "127.0.0.1")
  .option("--port <port>", "TCP port to listen on; use 0 for a random free port", "8080")
  .option("--json", "Print machine-readable ready metadata")
  .description("Serve a loopback-only demo lab for local BountyPilot practice")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ host?: string; port?: string; json?: boolean }>();
    const handle = await startDemoLabServer({
      host: options.host ?? "127.0.0.1",
      port: parsePortOption(options.port, "port", 8080),
    });
    if (options.json) {
      ui.json({ ok: true, ...handle.info });
    } else {
      printDemoLabReady(handle.info);
    }
    await waitForDemoLabShutdown(handle);
  });

lab
  .command("e2e")
  .argument("<target>", "Local/private lab URL or host to validate")
  .option("--live", "Run selected workflow components against the local lab after gates pass")
  .option(
    "--with <components>",
    "Comma-separated components: safe-checks,js-analyzer,playwright,triage,planner,crawl4ai,playwright-mcp,d-research-skill",
    defaultLabE2eComponents().join(","),
  )
  .option("--draft-reports", "Generate local report drafts during the live workflow")
  .option("--json", "Print machine-readable JSON")
  .description("Run a local lab preflight plus optional live E2E workflow")
  .action(async (target: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ live?: boolean; with?: string; draftReports?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const components = parseComponentList(options.with) ?? defaultLabE2eComponents();
    const result = await runLabE2eGate(runtime, target, {
      live: options.live === true,
      components,
      draftReports: options.draftReports === true,
    });
    if (!result.ok) {
      process.exitCode = result.summary?.status === "failed" ? 1 : 2;
    }
    if (options.json) {
      ui.json(result);
      return;
    }
    printLabE2eResult(result);
  });

program
  .command("dashboard")
  .option("--json", "Print machine-readable JSON")
  .description("Show a local workspace health, workflow, finding, and evidence dashboard")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const summary = buildWorkspaceSummary(runtime);
    if (options.json) {
      ui.json(summary);
      return;
    }
    ui.header("dashboard");
    printWorkspaceSummary(summary);
  });

program
  .command("cockpit")
  .option("--job <jobId>", "Focus the cockpit on one workflow job")
  .option("--limit <limit>", "Maximum recent jobs, events, actions, findings, and observations", "12")
  .option("--watch", "Refresh the cockpit until stopped or --iterations is reached")
  .option("--interval-ms <ms>", "Watch refresh interval in milliseconds", "3000")
  .option("--iterations <count>", "Maximum watch refreshes")
  .option("--json", "Print machine-readable JSON")
  .description("Open an opencode-style local command cockpit for workspace, jobs, recon, tools, and providers")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      job?: string;
      limit?: string;
      watch?: boolean;
      intervalMs?: string;
      iterations?: string;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    const limit = parsePositiveIntegerOption(options.limit, "limit", 12);
    const watch = options.watch === true;
    const intervalMs = parsePositiveIntegerOption(options.intervalMs, "interval-ms", 3000);
    const iterations = options.iterations
      ? parsePositiveIntegerOption(options.iterations, "iterations", 1)
      : watch && options.json
        ? 1
        : undefined;

    if (!watch) {
      const snapshot = buildCockpitSnapshot(runtime, { jobId: options.job, limit, refresh: 1 });
      if (options.json) {
        ui.json(snapshot);
        return;
      }
      ui.header("cockpit");
      printCockpitSnapshot(snapshot);
      return;
    }

    const snapshots: CockpitSnapshot[] = [];
    let refresh = 0;
    while (true) {
      refresh += 1;
      const snapshot = buildCockpitSnapshot(runtime, { jobId: options.job, limit, refresh });
      snapshots.push(snapshot);
      if (!options.json) {
        ui.header("cockpit");
        printCockpitSnapshot(snapshot);
      }
      if (iterations !== undefined && refresh >= iterations) {
        break;
      }
      await sleep(intervalMs);
    }

    if (options.json) {
      ui.json({
        ok: snapshots.every((snapshot) => snapshot.ok),
        watch: true,
        iterations: snapshots.length,
        latest: snapshots[snapshots.length - 1],
        snapshots,
      });
    }
  });

program
  .command("review")
  .requiredOption("--job <jobId>", "Job id to review")
  .option("--limit <limit>", "Maximum recent workflow events and reviewable actions", "12")
  .option("--json", "Print machine-readable JSON")
  .description("Open a focused local review cockpit for one workflow job")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job: string; limit: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const limit = parsePositiveIntegerOption(options.limit, "limit", 12);
    const review = buildJobReview(runtime, options.job, limit);
    if (options.json) {
      ui.json(review);
      return;
    }
    ui.header("review");
    ui.status(workflowStatusLabel(review.summary?.status ?? review.job.status), `job review ready: ${review.job.id}`);
    ui.panel("job", [
      ui.kv("id", review.job.id),
      ui.kv("status", review.summary?.status ?? review.job.status),
      ui.kv("mode", review.job.mode),
      ui.kv("type", review.job.type),
      ui.kv("target", review.job.target),
      ui.kv("health", review.cockpit.status),
      ui.kv("actions", review.actionCounts.total),
      ui.kv("pending", review.actionCounts.pending),
      ui.kv("approved", review.actionCounts.approved),
      ui.kv("evidence", review.evidence.total),
      ui.kv("findings", review.findings.total),
      ui.kv("events", review.events.length),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      review.cockpit.checks.map((check) => [check.status, check.name, check.message]),
    );
    if (review.cockpit.phaseCounts.total > 0) {
      ui.blank();
      ui.table(
        ["status", "phases"],
        Object.entries(review.cockpit.phaseCounts.byStatus).map(([status, count]) => [status, count]),
      );
    }
    ui.blank();
    if (review.actions.length === 0) {
      ui.status("warn", "no pending or approved actions found");
    } else {
      ui.table(
        ["status", "risk", "adapter", "type", "id", "target"],
        review.actions.map((action) => [action.status, action.riskLevel, action.adapter, action.actionType, action.id, action.target]),
      );
    }
    ui.blank();
    ui.table(
      ["kind", "count"],
      Object.entries(review.evidence.byKind).map(([kind, count]) => [kind, count]),
    );
    if (review.findings.top.length > 0) {
      ui.blank();
      ui.table(
        ["score", "ready", "severity", "status", "id", "title"],
        review.findings.top.map((finding) => [
          finding.score,
          finding.readiness,
          finding.severity,
          finding.status,
          finding.id,
          finding.title,
        ]),
      );
    }
    printWorkflowTimeline(review.events, "recent events");
    ui.blank();
    ui.commandList("next commands", review.nextCommands);
  });

program
  .command("results")
  .option("--job <jobId>", "Only include findings and recon observations tied to one workflow job")
  .option("--limit <limit>", "Maximum findings and recon signals to display", "12")
  .option("--min-score <score>", "Only include findings with reportability score at or above this value", "0")
  .option("--ready-only", "Only include findings that are ready for draft")
  .option("--json", "Print machine-readable JSON")
  .description("Show bug bounty result candidates with evidence, readiness, blockers, and next commands")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      job?: string;
      limit?: string;
      minScore?: string;
      readyOnly?: boolean;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    const limit = parsePositiveIntegerOption(options.limit, "limit", 12);
    const minScore = parseReportabilityScore(options.minScore ?? "0");
    const board = buildResultsBoard(runtime, {
      jobId: options.job,
      limit,
      minScore,
      readyOnly: options.readyOnly === true,
    });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(board);
      return;
    }
    ui.header("results");
    printResultsBoard(board);
  });

const exportCommand = program.command("export").description("Export local workspace artifacts");

exportCommand
  .command("summary")
  .option("--output <path>", "Output JSON path. Defaults to the program evidence directory.")
  .option("--json", "Print machine-readable JSON")
  .description("Export a JSON workspace summary for audit, handoff, or backup")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ output?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const outputPath = writeWorkspaceSummary(runtime, options.output);
    if (options.json) {
      ui.json({ ok: true, program: runtime.config.program, path: outputPath });
      return;
    }
    ui.header("export summary");
    ui.status("ok", "workspace summary exported");
    ui.panel("artifact", [
      ui.kv("program", runtime.config.program),
      ui.kv("path", outputPath),
    ]);
  });

exportCommand
  .command("bundle")
  .option("--output <dir>", "Output directory. Defaults to the program exports directory.")
  .option("--job <jobId>", "Include only one job's timelines, audit logs, actions, and evidence manifest entries")
  .option("--include-artifacts", "Copy readable evidence artifact files into the bundle")
  .option("--json", "Print machine-readable JSON")
  .description("Write a local handoff bundle with summaries, timelines, audit logs, findings, actions, and evidence metadata")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ output?: string; job?: string; includeArtifacts?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const result = writeHandoffBundle(runtime, {
      output: options.output,
      jobId: options.job,
      includeArtifacts: options.includeArtifacts,
    });
    if (options.json) {
      ui.json(result);
      return;
    }
    ui.header("export bundle");
    ui.status("ok", "handoff bundle exported");
    ui.panel("bundle", [
      ui.kv("program", result.program),
      ui.kv("path", result.outputDir),
      ui.kv("files", result.files.length),
      ui.kv("jobs", result.jobs.length),
      ui.kv("artifacts", result.artifactsCopied),
    ]);
  });

const findingsCommand = program
  .command("findings")
  .option("--json", "Print machine-readable JSON")
  .description("List local findings")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const findings = runtime.findings.list();
    if (options.json) {
      ui.json({ findings });
      return;
    }
    ui.header("findings");
    if (findings.length === 0) {
      ui.status("warn", "no findings stored yet");
      return;
    }
    ui.table(
      ["severity", "confidence", "status", "id", "title"],
      findings.map((finding) => [
        finding.severityEstimate,
        finding.confidence,
        finding.status,
        finding.id,
        finding.title,
      ]),
    );
  });

findingsCommand
  .command("candidates")
  .option("--job <jobId>", "Only list candidates from one workflow job")
  .option("--status <status>", "Filter by candidate status")
  .option("--reportability <state>", "Filter by reportability: blocked, needs_review, ready_for_draft")
  .option("--limit <count>", "Maximum candidates to return", "100")
  .option("--json", "Print machine-readable JSON")
  .description("List finding candidates with evidence threshold and reportability state")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      job?: string;
      status?: string;
      reportability?: string;
      limit: string;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) requireJob(runtime, options.job);
    const candidates = runtime.candidates.list({
      jobId: options.job,
      status: options.status ? parseFindingCandidateStatus(options.status) : undefined,
      reportability: options.reportability ? parseFindingCandidateReportability(options.reportability) : undefined,
      limit: parsePositiveIntegerOption(options.limit, "limit", 5000),
    });
    const payload = {
      ok: true,
      jobId: options.job,
      candidates,
      totals: {
        total: candidates.length,
        byStatus: countBy(candidates, (candidate) => candidate.status),
        byReportability: countBy(candidates, (candidate) => candidate.reportability),
      },
      nextCommands: candidates.slice(0, 5).flatMap((candidate) => [
        `bounty findings candidate ${candidate.id}`,
        `bounty reports score ${candidate.id}${options.job ? ` --job ${options.job}` : ""}`,
      ]),
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("findings candidates");
    if (candidates.length === 0) {
      ui.status("warn", "no finding candidates stored yet");
      return;
    }
    ui.table(
      ["reportability", "status", "confidence", "severity", "evidence", "id", "title"],
      candidates.map((candidate) => [
        candidate.reportability,
        candidate.status,
        candidate.confidence,
        candidate.severityEstimate,
        candidate.evidenceIds.length,
        candidate.id,
        candidate.title,
      ]),
    );
  });

findingsCommand
  .command("candidate")
  .argument("<candidateId>", "Finding candidate id")
  .option("--json", "Print machine-readable JSON")
  .description("Show one finding candidate, linked evidence, observations, and next manual steps")
  .action((candidateId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const candidate = runtime.candidates.get(candidateId);
    if (!candidate) throw new BountyPilotError(`Finding candidate not found: ${candidateId}`, "FINDING_CANDIDATE_NOT_FOUND");
    const evidence = evidenceForCandidate(runtime, candidate);
    const observations = candidate.observationIds
      .map((observationId) => runtime.recon.get(observationId))
      .filter((observation): observation is ReconObservation => Boolean(observation));
    const finding = candidate.findingId ? runtime.findings.get(candidate.findingId) : undefined;
    const payload = {
      ok: true,
      candidate,
      finding,
      evidence,
      observations,
      nextCommands: candidateNextCommands(candidate),
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("findings candidate");
    ui.panel("candidate", [
      ui.kv("id", candidate.id),
      ui.kv("title", candidate.title),
      ui.kv("url", candidate.url),
      ui.kv("status", candidate.status),
      ui.kv("reportability", candidate.reportability),
      ui.kv("confidence", candidate.confidence),
      ui.kv("severity", candidate.severityEstimate),
      ui.kv("finding", candidate.findingId ?? "-"),
      ui.kv("evidence", evidence.length),
    ]);
    if (candidate.nextManualSteps.length > 0) {
      ui.blank();
      ui.list("next manual steps", candidate.nextManualSteps);
    }
  });

findingsCommand
  .command("promote-candidate")
  .argument("<candidateId>", "Finding candidate id to promote into a local finding")
  .option("--status <status>", "Finding status to assign after promotion", "needs_validation")
  .option("--json", "Print machine-readable JSON")
  .description("Promote a candidate into a local finding while keeping evidence linked")
  .action((candidateId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ status: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const result = promoteCandidate(runtime, candidateId, parseFindingStatus(options.status));
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("findings promote-candidate");
    ui.status("ok", result.created ? "candidate promoted into a finding" : "candidate already linked to a finding");
    ui.panel("candidate", [
      ui.kv("candidate", result.candidate.id),
      ui.kv("finding", result.finding.id),
      ui.kv("title", result.finding.title),
      ui.kv("evidence", result.evidence.length),
    ]);
  });

findingsCommand
  .command("create")
  .requiredOption("--title <title>", "Finding title")
  .requiredOption("--url <url>", "In-scope affected URL")
  .option("--asset <asset>", "Asset label. Defaults to the scoped host.")
  .option("--category <category>", "Finding category", "manual_observation")
  .option("--severity <severity>", "Severity estimate: info, low, medium, high, critical, unknown", "unknown")
  .option("--confidence <confidence>", "Confidence: low, medium, high", "low")
  .option("--status <status>", "Initial finding status", "needs_manual_review")
  .option("--score <score>", "Reportability score from 0 to 100", "25")
  .option("--reportability-score <score>", "Reportability score from 0 to 100. Alias for --score.")
  .option("--duplicate-risk <risk>", "Duplicate risk: low, medium, high, unknown", "unknown")
  .option("--remediation <text>", "Suggested remediation")
  .option("--note <text>", "Manual note to attach as local evidence")
  .option("--job <jobId>", "Optional job id for attached note/evidence artifacts")
  .option("--evidence <path>", "Local evidence file to attach. Repeat for multiple files.", collectOption, [] as string[])
  .option("--evidence-kind <kind>", "Evidence kind for attached files", "evidence_note")
  .option("--json", "Print machine-readable JSON")
  .description("Create a manual local finding for an in-scope target")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      title: string;
      url: string;
      asset?: string;
      category: string;
      severity: string;
      confidence: string;
      status: string;
      score: string;
      reportabilityScore?: string;
      duplicateRisk: string;
      remediation?: string;
      note?: string;
      job?: string;
      evidence: string[];
      evidenceKind: string;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) requireJob(runtime, options.job);
    const scope = runtime.scopeGuard.assertAllowed(options.url);
    const finding = runtime.findings.create({
      title: parseNonEmptyTextOption(options.title, "title"),
      asset: options.asset?.trim() || scope.host,
      url: scope.url,
      category: parseNonEmptyTextOption(options.category, "category"),
      severityEstimate: parseSeverityEstimate(options.severity),
      confidence: parseConfidence(options.confidence),
      status: parseFindingStatus(options.status),
      evidencePaths: [],
      remediation: options.remediation?.trim() || undefined,
      duplicateRisk: parseDuplicateRisk(options.duplicateRisk),
      reportabilityScore: parseReportabilityScore(options.reportabilityScore ?? options.score),
    });
    const evidence: EvidenceArtifact[] = [];
    const note = options.note?.trim();
    if (note) {
      evidence.push(
        runtime.evidence.writeTextArtifact({
          findingId: finding.id,
          jobId: options.job,
          adapterName: "manual",
          kind: "evidence_note",
          sourceUrl: finding.url,
          relativePath: manualTextEvidenceRelativePath("manual-note.md", finding.id),
          content: [`# Manual Finding Note`, ``, `Finding: ${finding.id}`, `URL: ${finding.url}`, ``, note, ``].join("\n"),
        }),
      );
    }
    const evidenceKind = parseEvidenceKind(options.evidenceKind);
    for (const evidencePath of options.evidence) {
      evidence.push(
        runtime.evidence.copyFileArtifact({
          findingId: finding.id,
          jobId: options.job,
          adapterName: "manual",
          kind: evidenceKind,
          sourceUrl: finding.url,
          sourcePath: evidencePath,
          relativePath: manualEvidenceRelativePath(evidencePath, undefined, finding.id),
        }),
      );
    }
    let linkedFinding = finding;
    for (const artifact of evidence) {
      linkedFinding = runtime.findings.linkEvidencePath(finding.id, artifact.path);
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, finding: linkedFinding, evidence });
      return;
    }
    ui.header("findings create");
    ui.status("ok", "manual finding created");
    ui.panel("finding", [
      ui.kv("id", finding.id),
      ui.kv("title", finding.title),
      ui.kv("url", finding.url),
      ui.kv("status", finding.status),
      ui.kv("score", linkedFinding.reportabilityScore),
      ui.kv("evidence", evidence.length),
    ]);
  });

findingsCommand
  .command("show")
  .argument("<findingId>", "Finding id to inspect")
  .option("--json", "Print machine-readable JSON")
  .description("Show finding details, linked evidence, duplicate risk, and triage")
  .action((findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const finding = runtime.findings.get(findingId);
    if (!finding) throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
    const evidence = runtime.evidence.list(findingId);
    const duplicate = new DuplicateRiskEngine().estimate(
      finding,
      runtime.findings.list().filter((item) => item.id !== finding.id),
    );
    const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
    const payload = { finding, evidence, duplicate, triage };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("findings show");
    ui.panel("finding", [
      ui.kv("id", finding.id),
      ui.kv("title", finding.title),
      ui.kv("asset", finding.asset),
      ui.kv("url", finding.url),
      ui.kv("category", finding.category),
      ui.kv("severity", finding.severityEstimate),
      ui.kv("confidence", finding.confidence),
      ui.kv("status", finding.status),
      ui.kv("duplicate", duplicate.risk),
      ui.kv("evidence", evidence.length),
      ui.kv("score", `${triage.reportabilityScore}/100`),
      ui.kv("recommend", triage.recommendation),
    ]);
    if (evidence.length > 0) {
      ui.blank();
      ui.table(
        ["kind", "adapter", "id", "path"],
        evidence.map((artifact) => [artifact.kind, artifact.adapterName, artifact.id, artifact.path]),
      );
    }
    ui.blank();
    ui.list("reasons", [...duplicate.reasons, ...triage.reasons]);
  });

findingsCommand
  .command("status")
  .argument("<findingId>", "Finding id to update")
  .argument("<status>", "New status")
  .option("--note <text>", "Optional local status-change note")
  .option("--json", "Print machine-readable JSON")
  .description("Update a finding lifecycle status")
  .action((findingId: string, statusValue: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ note?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const finding = runtime.findings.get(findingId);
    if (!finding) throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
    const status = parseFindingStatus(statusValue);
    runtime.findings.updateStatus(findingId, status);
    const artifact = runtime.evidence.writeTextArtifact({
      findingId,
      adapterName: "finding-store",
      kind: "evidence_note",
      sourceUrl: finding.url,
      relativePath: path.join(findingId, `status-${status}.md`),
      content: [
        `# Finding Status Update`,
        ``,
        `Finding: ${finding.id}`,
        `Previous status: ${finding.status}`,
        `New status: ${status}`,
        `Note: ${options.note ?? "-"}`,
        ``,
      ].join("\n"),
    });
    const updatedFinding = runtime.findings.get(findingId);
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, findingId, previousStatus: finding.status, status, finding: updatedFinding, artifact });
      return;
    }
    ui.header("findings status");
    ui.status("ok", "finding status updated");
    ui.panel("finding", [
      ui.kv("id", finding.id),
      ui.kv("previous", finding.status),
      ui.kv("status", status),
      ui.kv("note", artifact.path),
    ]);
  });

const evidenceCommand = program
  .command("evidence")
  .argument("[findingId]", "Optional finding id")
  .option("--job <jobId>", "Only include evidence from a job")
  .option("--manifest", "Write a local evidence manifest JSON artifact")
  .option("--open", "Open the evidence artifact folder in the local OS file browser")
  .option("--json", "Print machine-readable JSON")
  .description("List evidence artifacts")
  .action((findingId: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; manifest?: boolean; open?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) requireJob(runtime, options.job);
    if (options.manifest) {
      const artifact = runtime.evidence.writeManifest({ findingId, jobId: options.job });
      if (options.json) {
        ui.json({ ok: true, findingId, jobId: options.job, artifact });
        if (options.open) openPath(path.dirname(artifact.path));
        return;
      }
      ui.header("evidence");
      ui.status("ok", "manifest written");
      ui.panel("manifest", [
        ui.kv("finding", findingId ?? "workspace"),
        ui.kv("job", options.job ?? "-"),
        ui.kv("path", artifact.path),
      ]);
      if (options.open) openPath(path.dirname(artifact.path));
      return;
    }

    const evidence = filterEvidenceByJob(runtime.evidence.list(findingId), options.job);
    if (options.json) {
      ui.json({ findingId, jobId: options.job, evidence });
      if (options.open && evidence.length > 0) {
        openPath(findingId ? path.dirname(evidence[0].path) : runtime.paths.evidenceDir);
      }
      return;
    }
    ui.header("evidence");
    if (evidence.length === 0) {
      ui.status("warn", "no evidence artifacts found");
      return;
    }
    ui.table(
      ["kind", "id", "source", "path"],
      evidence.map((artifact) => [artifact.kind, artifact.id, artifact.sourceUrl, artifact.path]),
    );
    if (options.open) {
      openPath(findingId ? path.dirname(evidence[0].path) : runtime.paths.evidenceDir);
      ui.status("ok", "open requested for local evidence folder");
    }
  });

evidenceCommand
  .command("list")
  .argument("[findingId]", "Optional finding id")
  .option("--job <jobId>", "Only include evidence from a job")
  .option("--open", "Open the evidence artifact folder in the local OS file browser")
  .option("--json", "Print machine-readable JSON")
  .description("List local evidence artifacts")
  .action((findingId: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; open?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const jobId = commandJobOption(command, options.job);
    if (jobId) requireJob(runtime, jobId);
    const evidence = filterEvidenceByJob(runtime.evidence.list(findingId), jobId);
    const openTarget = evidenceOpenTarget(runtime, evidence, findingId);
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, findingId, jobId, evidence, openTarget });
      if (options.open) openPath(openTarget);
      return;
    }
    ui.header("evidence list");
    if (evidence.length === 0) {
      ui.status("warn", "no evidence artifacts found");
      return;
    }
    ui.table(
      ["kind", "id", "job", "source", "path"],
      evidence.map((artifact) => [artifact.kind, artifact.id, artifact.jobId ?? "-", artifact.sourceUrl, artifact.path]),
    );
    if (options.open) {
      openPath(openTarget);
      ui.status("ok", "open requested for local evidence folder");
    }
  });

evidenceCommand
  .command("show")
  .argument("<evidenceId>", "Evidence artifact id")
  .option("--open", "Open the evidence artifact folder in the local OS file browser")
  .option("--json", "Print machine-readable JSON")
  .description("Show one local evidence artifact and manifest metadata")
  .action((evidenceId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ open?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const artifact = runtime.evidence.get(evidenceId);
    if (!artifact) {
      throw new BountyPilotError(`Evidence artifact not found: ${evidenceId}`, "EVIDENCE_NOT_FOUND");
    }
    const manifest = runtime.evidence.buildManifestForArtifacts([artifact], {
      findingId: artifact.findingId,
      jobId: artifact.jobId,
    });
    const entry = manifest.artifacts[0];
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, artifact, manifest: entry, openTarget: path.dirname(artifact.path) });
      if (options.open) openPath(path.dirname(artifact.path));
      return;
    }
    ui.header("evidence show");
    ui.panel("evidence", [
      ui.kv("id", artifact.id),
      ui.kv("finding", artifact.findingId ?? "-"),
      ui.kv("job", artifact.jobId ?? "-"),
      ui.kv("kind", artifact.kind),
      ui.kv("adapter", artifact.adapterName),
      ui.kv("source", artifact.sourceUrl ?? "-"),
      ui.kv("path", artifact.path),
      ui.kv("readable", entry?.readable ?? false),
      ui.kv("sha256", entry?.sha256 ?? "-"),
    ]);
    if (options.open) openPath(path.dirname(artifact.path));
  });

evidenceCommand
  .command("manifest")
  .argument("[findingId]", "Optional finding id")
  .option("--job <jobId>", "Only include evidence from a job")
  .option("--open", "Open the manifest artifact folder in the local OS file browser")
  .option("--json", "Print machine-readable JSON")
  .description("Write a local evidence manifest JSON artifact")
  .action((findingId: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; open?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const jobId = commandJobOption(command, options.job);
    if (jobId) requireJob(runtime, jobId);
    const manifest = runtime.evidence.buildManifest({ findingId, jobId });
    const artifact = runtime.evidence.writeManifest({ findingId, jobId });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, findingId, jobId, manifest, artifact });
      if (options.open) openPath(path.dirname(artifact.path));
      return;
    }
    ui.header("evidence manifest");
    ui.status("ok", "manifest written");
    ui.panel("manifest", [
      ui.kv("finding", findingId ?? "workspace"),
      ui.kv("job", jobId ?? "-"),
      ui.kv("artifacts", manifest.artifactCount),
      ui.kv("path", artifact.path),
    ]);
    if (options.open) openPath(path.dirname(artifact.path));
  });

evidenceCommand
  .command("open")
  .argument("[findingId]", "Optional finding id")
  .option("--job <jobId>", "Open evidence for one job")
  .option("--json", "Print machine-readable JSON")
  .description("Open the local evidence artifact folder")
  .action((findingId: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const jobId = commandJobOption(command, options.job);
    if (jobId) requireJob(runtime, jobId);
    const evidence = filterEvidenceByJob(runtime.evidence.list(findingId), jobId);
    const target = evidenceOpenTarget(runtime, evidence, findingId);
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, findingId, jobId, evidence: evidence.length, path: target });
      return;
    }
    openPath(target);
    ui.header("evidence open");
    ui.status("ok", "open requested for local evidence folder");
    ui.panel("evidence", [
      ui.kv("finding", findingId ?? "workspace"),
      ui.kv("job", jobId ?? "-"),
      ui.kv("artifacts", evidence.length),
      ui.kv("path", target),
    ]);
  });

evidenceCommand
  .command("add")
  .option("--file <path>", "Local evidence file to copy into the workspace")
  .option("--text <text>", "Text evidence content to store")
  .option("--stdin", "Read text evidence content from stdin")
  .option("--finding <findingId>", "Finding id to link this evidence to")
  .option("--job <jobId>", "Optional job id to associate with this evidence")
  .option("--kind <kind>", "Evidence kind", "evidence_note")
  .option("--source-url <url>", "In-scope source URL. Defaults to the linked finding URL when --finding is set.")
  .option("--label <name>", "Stored file name. Defaults to the source file name.")
  .option("--name <name>", "Stored file name. Alias for --label.")
  .option("--adapter <name>", "Adapter/source label", "manual")
  .option("--relative-path <path>", "Workspace-relative evidence path under the evidence directory")
  .option("--open", "Open the stored evidence folder")
  .option("--json", "Print machine-readable JSON")
  .description("Add manual local evidence to the workspace")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      file?: string;
      text?: string;
      stdin?: boolean;
      finding?: string;
      job?: string;
      kind: string;
      sourceUrl?: string;
      label?: string;
      name?: string;
      adapter: string;
      relativePath?: string;
      open?: boolean;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    const finding = options.finding ? runtime.findings.get(options.finding) : undefined;
    if (options.finding && !finding) {
      throw new BountyPilotError(`Finding not found: ${options.finding}`, "FINDING_NOT_FOUND");
    }
    const jobId = commandJobOption(command, options.job);
    if (jobId) requireJob(runtime, jobId);
    assertSingleEvidenceSource(options);
    const sourceUrl = options.sourceUrl
      ? runtime.scopeGuard.assertAllowed(options.sourceUrl).url
      : finding?.url;
    const adapterName = parseNonEmptyTextOption(options.adapter, "adapter");
    const kind = parseEvidenceKind(options.kind);
    const label = options.label ?? options.name;
    let artifact: EvidenceArtifact;
    if (options.file) {
      const relativePath = options.relativePath ?? manualEvidenceRelativePath(options.file, label, finding?.id);
      artifact = runtime.evidence.copyFileArtifact({
        findingId: finding?.id,
        jobId,
        adapterName,
        kind,
        sourceUrl,
        sourcePath: options.file,
        relativePath,
      });
    } else {
      const content = options.stdin ? readStdinText() : options.text ?? "";
      const relativePath = options.relativePath ?? manualTextEvidenceRelativePath(label ?? "manual-evidence.md", finding?.id);
      artifact = runtime.evidence.writeTextArtifact({
        findingId: finding?.id,
        jobId,
        adapterName,
        kind,
        sourceUrl,
        relativePath,
        content,
      });
    }
    const linkedFinding = finding ? runtime.findings.linkEvidencePath(finding.id, artifact.path) : undefined;
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, findingId: finding?.id, jobId, finding: linkedFinding, artifact });
      if (options.open) openPath(path.dirname(artifact.path));
      return;
    }
    ui.header("evidence add");
    ui.status("ok", "manual evidence added");
    ui.panel("evidence", [
      ui.kv("id", artifact.id),
      ui.kv("finding", artifact.findingId ?? "-"),
      ui.kv("kind", artifact.kind),
      ui.kv("path", artifact.path),
    ]);
    if (options.open) openPath(path.dirname(artifact.path));
  });

evidenceCommand
  .command("record")
  .argument("[url]", "In-scope URL to capture as evidence. Omit for manual note/file evidence.")
  .option("--finding <findingId>", "Finding id to link captured evidence to")
  .option("--job <jobId>", "Optional job id to associate with this capture")
  .option("--type <type>", "Manual evidence type when URL is omitted: note, file, screenshot, http, or an evidence kind", "note")
  .option("--title <title>", "Manual evidence title when URL is omitted")
  .option("--file <path>", "Manual evidence file to copy when URL is omitted")
  .option("--text <text>", "Manual evidence text when URL is omitted")
  .option("--stdin", "Read manual evidence text from stdin when URL is omitted")
  .option("--full", "Capture browser trace and optional richer artifacts")
  .option("--json", "Print machine-readable JSON")
  .description("Capture scoped browser evidence or record manual local evidence")
  .action(async (url: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      finding?: string;
      job?: string;
      type: string;
      title?: string;
      file?: string;
      text?: string;
      stdin?: boolean;
      full?: boolean;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    const jobId = commandJobOption(command, options.job);
    const recordOptions = { ...options, job: jobId };
    if (!url) {
      const result = recordManualEvidence(runtime, recordOptions);
      if (options.json || requestedJsonOutput(process.argv)) {
        ui.json(result);
        return;
      }
      ui.header("evidence record");
      ui.status("ok", "manual evidence recorded");
      ui.panel("evidence", [
        ui.kv("id", result.artifact.id),
        ui.kv("finding", result.findingId ?? "-"),
        ui.kv("job", result.jobId ?? "-"),
        ui.kv("kind", result.artifact.kind),
        ui.kv("path", result.artifact.path),
      ]);
      ui.blank();
      ui.commandList("next commands", result.nextCommands);
      return;
    }
    if (!options.finding) {
      throw new BountyPilotError("URL evidence capture requires --finding <finding-id>.", "EVIDENCE_FINDING_REQUIRED");
    }
    const finding = runtime.findings.get(options.finding);
    if (!finding) {
      throw new BountyPilotError(`Finding not found: ${options.finding}`, "FINDING_NOT_FOUND");
    }
    const scoped = runtime.scopeGuard.assertAllowed(url);
    const job = jobId ? requireJob(runtime, jobId) : runtime.jobs.create("evidence-record", "safe", scoped.url);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const planned = await planAllowedActionWithRecord({
      runtime,
      audit,
      jobId: job.id,
      adapter: "playwright",
      actionType: "browser.navigate",
      target: scoped.url,
      mode: "safe",
      riskLevel: "low",
    });
    const artifacts: EvidenceArtifact[] = [];
    let execution: Awaited<ReturnType<ActionExecutor["execute"]>> | undefined;
    if (planned.allowed) {
      const existingEvidenceIds = new Set(runtime.evidence.list().filter((item) => item.jobId === job.id).map((item) => item.id));
      execution = await new ActionExecutor(runtime).execute(planned.action.id);
      for (const captured of runtime.evidence.list().filter((item) => item.jobId === job.id && !existingEvidenceIds.has(item.id))) {
        const linked = runtime.evidence.linkToFinding(captured.id, finding.id);
        if (linked) {
          artifacts.push(linked);
          runtime.findings.linkEvidencePath(finding.id, linked.path);
        }
      }
    }
    const finalizedJob = runtime.jobs.finalize(job.id);
    const captureMode = execution ? "browser" : "planned";
    const warnings = execution ? [] : ["Browser evidence capture requires an allowlisted execution and approval state."];
    const reproduction = runtime.evidence.writeTextArtifact({
      findingId: finding.id,
      jobId: job.id,
      adapterName: "evidence-record",
      kind: "reproduction_note",
      sourceUrl: scoped.url,
      relativePath: path.join(finding.id, `${job.id}-reproduction.md`),
      content: generateReproductionNote(finding, [...runtime.evidence.list(finding.id), ...artifacts]),
    });
    runtime.findings.linkEvidencePath(finding.id, reproduction.path);
    artifacts.push(reproduction);
    const payload = {
      ok: true,
      findingId: finding.id,
      jobId: job.id,
      url: scoped.url,
      status: finalizedJob.status,
      pauseReason: finalizedJob.pauseReason,
      captureMode,
      warnings,
      execution,
      artifacts,
      links: [],
      nextCommands: [`bounty reports score ${finding.id} --job ${job.id}`, `bounty reports review ${finding.id} --job ${job.id}`],
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("evidence record");
    ui.status(captureMode === "browser" ? "ok" : "planned", captureMode === "browser" ? "browser evidence captured" : "browser evidence queued for human approval");
    ui.panel("capture", [
      ui.kv("finding", finding.id),
      ui.kv("job", job.id),
      ui.kv("url", scoped.url),
      ui.kv("mode", captureMode),
      ui.kv("artifacts", artifacts.length),
    ]);
    if (warnings.length > 0) {
      ui.list("warnings", warnings);
    }
    ui.blank();
    ui.commandList("next commands", payload.nextCommands);
  });

evidenceCommand
  .command("link")
  .argument("<evidenceId>", "Evidence artifact id")
  .argument("<findingId>", "Finding id")
  .option("--json", "Print machine-readable JSON")
  .description("Link an existing evidence artifact to a finding")
  .action((evidenceId: string, findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const finding = runtime.findings.get(findingId);
    if (!finding) throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
    const artifact = runtime.evidence.linkToFinding(evidenceId, findingId);
    if (!artifact) throw new BountyPilotError(`Evidence artifact not found: ${evidenceId}`, "EVIDENCE_NOT_FOUND");
    const linkedFinding = runtime.findings.linkEvidencePath(findingId, artifact.path);
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, finding: linkedFinding, artifact });
      return;
    }
    ui.header("evidence link");
    ui.status("ok", "evidence linked");
    ui.panel("link", [
      ui.kv("evidence", artifact.id),
      ui.kv("finding", linkedFinding.id),
      ui.kv("path", artifact.path),
    ]);
  });

evidenceCommand
  .command("verify")
  .argument("[findingId]", "Optional finding id")
  .option("--job <jobId>", "Only verify evidence from a job")
  .option("--json", "Print machine-readable JSON")
  .description("Verify local evidence artifact readability and hashes")
  .action((findingId: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const jobId = commandJobOption(command, options.job);
    if (jobId) requireJob(runtime, jobId);
    const manifest = runtime.evidence.buildManifest({ findingId, jobId });
    const missing = manifest.artifacts.filter((artifact) => !artifact.readable);
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(manifest);
    } else {
      ui.header("evidence verify");
      ui.status(missing.length === 0 ? "ok" : "warn", `${manifest.artifactCount} artifacts checked, ${missing.length} unreadable`);
      if (manifest.artifacts.length > 0) {
        ui.table(
          ["readable", "bytes", "sha256", "kind", "path"],
          manifest.artifacts.map((artifact) => [
            artifact.readable,
            artifact.bytes,
            artifact.sha256 ? `${artifact.sha256.slice(0, 12)}...` : "-",
            artifact.kind,
            artifact.relativePath ?? artifact.path,
          ]),
        );
      }
    }
    process.exitCode = missing.length === 0 ? 0 : 1;
  });

program
  .command("crawl")
  .argument("<url>", "In-scope URL to crawl")
  .option("--playwright", "Use local Playwright crawler")
  .option("--engine <engine>", "Crawler engine", "playwright")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Run a scoped, non-destructive browser crawl")
  .action(async (url: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ playwright?: boolean; engine: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const scope = runtime.scopeGuard.assertAllowed(url);
    const engine = normalizeIntegrationName(options.engine);
    const job = runtime.jobs.create("crawl", mode, scope.url);
    const audit = createJobAuditLogger(runtime.paths, job.id);

    if (engine !== "playwright") {
      const validation =
        engine === "playwright_mcp"
          ? new McpClientManager(runtime.config).prepareCallPlan({
              server: "playwright-mcp",
              tool: "browser_navigate",
              mode,
              target: scope.url,
              arguments: { url: scope.url },
            }).validation
          : new IntegrationManager(runtime.config).validateCallPlan({
              integration: engine,
              capability: engine === "crawl4ai" ? "crawler.fetch" : "browser.navigate",
              target: scope.url,
              mode,
            });
      const action = runtime.actions.enqueue({
        jobId: job.id,
        adapter: engine,
        actionType: validation.capability?.actionType ?? "crawler.fetch",
        target: scope.url,
        riskLevel: validation.capability?.riskLevel ?? "low",
        requiresApproval: validation.requiresApproval,
        status: validation.decision === "block" ? "blocked" : undefined,
        requiredForCompletion: false,
        metadata: { execute: false, planningOnly: true, handoffOnly: true },
      });
      audit.log({
        jobId: job.id,
        actionType: validation.capability?.actionType ?? "crawler.fetch",
        url: scope.url,
        adapterName: engine,
        policyDecision: validation.decision,
        reason: validation.reasons.join("; "),
        metadata: { actionId: action.id, execute: false },
      });
      const artifact = runtime.evidence.writeTextArtifact({
        jobId: job.id,
        adapterName: engine,
        kind: "crawl_graph",
        sourceUrl: scope.url,
        relativePath: path.join(job.id, `${engine}-crawl-plan.json`),
        content: JSON.stringify(
          {
            engine,
            target: scope.url,
            mode,
            execute: false,
            decision: validation.decision,
            requiresApproval: validation.requiresApproval,
            reasons: validation.reasons,
            capability: validation.capability,
          },
          null,
          2,
        ),
      });
      if (!validation.ok) {
        const finalizedJob = runtime.jobs.finalize(job.id);
        const payload = {
          ok: false,
          jobId: job.id,
          status: finalizedJob.status,
          pauseReason: finalizedJob.pauseReason,
          engine,
          target: scope.url,
          mode,
          execute: false,
          action,
          artifact,
          validation,
        };
        if (options.json) {
          ui.json(payload);
          process.exitCode = 1;
          return;
        }
        throw new BountyPilotError(validation.reasons.join("; "), "CRAWL_PLAN_BLOCKED");
      }
      const finalizedJob = runtime.jobs.finalize(job.id);
      const payload = {
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        engine,
        target: scope.url,
        mode,
        execute: false,
        action,
        artifact,
        validation,
      };
      if (options.json) {
        ui.json(payload);
        return;
      }
      ui.header("crawl");
      ui.status("planned", `${engine} crawl plan recorded for human handoff`);
      ui.panel("job", [
        ui.kv("id", job.id),
        ui.kv("engine", engine),
        ui.kv("target", scope.url),
        ui.kv("execute", false),
        ui.kv("artifact", artifact.path),
      ]);
      return;
    }

    const allowed = await planAllowedAction({
      runtime,
      audit,
      jobId: job.id,
      adapter: "playwright",
      actionType: "browser.navigate",
      target: scope.url,
      mode,
      riskLevel: "low",
    });
    if (!allowed) {
      const finalizedJob = runtime.jobs.finalize(job.id);
      if (options.json) {
        ui.json({
          ok: true,
          jobId: job.id,
          status: finalizedJob.status,
          pauseReason: finalizedJob.pauseReason,
          engine: "playwright",
          target: scope.url,
          mode,
          execute: false,
          actions: runtime.actions.list(job.id),
        });
        return;
      }
      ui.header("crawl");
      ui.status("planned", "action requires approval");
      ui.panel("job", [ui.kv("id", job.id), ui.kv("target", scope.url)]);
      return;
    }

    if (!options.json) {
      ui.header("crawl");
      ui.status("running", `playwright crawl started for ${scope.host}`);
    }
    const action = runtime.actions.list(job.id)[0];
    if (!action) {
      throw new BountyPilotError("Planned crawl action is unavailable.", "ACTION_NOT_FOUND");
    }
    const result = await new ActionExecutor(runtime).execute(action.id);
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        engine: "playwright",
        target: scope.url,
        mode,
        execute: result.status === "executed",
        result,
        evidenceCreated: result.evidenceCreated,
      });
      return;
    }
    ui.status("ok", "crawl completed");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("target", scope.url),
      ui.kv("result", result.message),
      ui.kv("evidence", result.evidenceCreated),
    ]);
  });

program
  .command("browser")
  .argument("<url>", "In-scope URL to open through an approved browser adapter")
  .option("--mcp <name>", "Browser MCP adapter name", "playwright")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Plan a scoped browser automation action")
  .action(async (url: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ mcp: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const scope = runtime.scopeGuard.assertAllowed(url);
    const job = runtime.jobs.create("browser", mode, scope.url);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const adapter = options.mcp === "playwright" ? "playwright-mcp" : options.mcp;
    const mcpPlan = new McpClientManager(runtime.config).prepareCallPlan({
      server: adapter,
      tool: "browser_navigate",
      mode,
      target: scope.url,
      arguments: { url: scope.url },
    });
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter,
      actionType: mcpPlan.validation.capability?.actionType ?? "browser.navigate",
      target: scope.url,
      riskLevel: mcpPlan.validation.capability?.riskLevel ?? "low",
      requiresApproval: mcpPlan.validation.requiresApproval,
      status: mcpPlan.validation.decision === "block" ? "blocked" : undefined,
      requiredForCompletion: false,
      metadata: { execute: false, planningOnly: true, handoffOnly: true, tool: mcpPlan.tool },
    });
    audit.log({
      jobId: job.id,
      actionType: "browser.navigate",
      url: scope.url,
      adapterName: adapter,
      policyDecision: mcpPlan.validation.decision,
      reason: mcpPlan.validation.reasons.join("; "),
      metadata: { actionId: action.id, execute: false, tool: mcpPlan.tool },
    });
    runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: adapter,
      kind: "evidence_note",
      sourceUrl: scope.url,
      relativePath: path.join(job.id, "browser-plan.md"),
      content: `# Browser Action Plan

Target: ${scope.url}
Adapter: ${adapter}
Mode: ${mode}
MCP tool: ${mcpPlan.tool}
Decision: ${mcpPlan.validation.decision}
Reasons:
${mcpPlan.validation.reasons.map((reason) => `- ${reason}`).join("\n")}

This command records a scope-checked browser plan for human handoff. This release never starts an MCP server or dispatches an MCP tool.
`,
    });
    if (!mcpPlan.validation.ok) {
      const finalizedJob = runtime.jobs.finalize(job.id);
      if (options.json) {
        ui.json({ ok: false, jobId: job.id, status: finalizedJob.status, pauseReason: finalizedJob.pauseReason, adapter, target: scope.url, mode, action, plan: mcpPlan });
        process.exitCode = 1;
        return;
      }
      throw new BountyPilotError(mcpPlan.validation.reasons.join("; "), "MCP_PLAN_BLOCKED");
    }
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        adapter,
        target: scope.url,
        mode,
        execute: false,
        action,
        plan: mcpPlan,
      });
      return;
    }
    ui.header("browser");
    ui.status("planned", "browser action recorded for human handoff");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("adapter", adapter),
      ui.kv("target", scope.url),
      ui.kv("mode", mode),
    ]);
  });

program
  .command("desktop")
  .option("--mcp <name>", "Desktop MCP adapter name", "windows")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Plan an approved local desktop automation action")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ mcp: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const adapter = options.mcp === "windows" ? "windows-mcp" : options.mcp;
    const job = runtime.jobs.create("desktop", mode, runtime.config.program);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const mcpPlan = new McpClientManager(runtime.config).prepareCallPlan({
      server: adapter,
      tool: "desktop_session_plan",
      mode,
      arguments: { program: runtime.config.program },
    });
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter,
      actionType: mcpPlan.validation.capability?.actionType ?? "desktop.session.plan",
      target: runtime.config.program,
      riskLevel: mcpPlan.validation.capability?.riskLevel ?? "medium",
      requiresApproval: mcpPlan.validation.requiresApproval,
      status: mcpPlan.validation.decision === "block" ? "blocked" : undefined,
      requiredForCompletion: false,
      metadata: { execute: false, planningOnly: true, handoffOnly: true, tool: mcpPlan.tool },
    });
    audit.log({
      jobId: job.id,
      actionType: "desktop.session.plan",
      adapterName: adapter,
      policyDecision: mcpPlan.validation.decision,
      reason: mcpPlan.validation.reasons.join("; "),
      metadata: { actionId: action.id, execute: false, tool: mcpPlan.tool },
    });
    runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: adapter,
      kind: "desktop_action_log",
      relativePath: path.join(job.id, "desktop-plan.md"),
      content: `# Desktop Automation Plan

Program: ${runtime.config.program}
Adapter: ${adapter}
Mode: ${mode}
MCP tool: ${mcpPlan.tool}
Decision: ${mcpPlan.validation.decision}
Reasons:
${mcpPlan.validation.reasons.map((reason) => `- ${reason}`).join("\n")}

Desktop automation is optional and local-only. It must not control unrelated personal apps, access unrelated files, send messages, install unknown software, or bypass BountyPilot policy gates.
`,
    });
    if (!mcpPlan.validation.ok) {
      const finalizedJob = runtime.jobs.finalize(job.id);
      if (options.json) {
        ui.json({ ok: false, jobId: job.id, status: finalizedJob.status, pauseReason: finalizedJob.pauseReason, adapter, mode, action, plan: mcpPlan });
        process.exitCode = 1;
        return;
      }
      throw new BountyPilotError(mcpPlan.validation.reasons.join("; "), "MCP_PLAN_BLOCKED");
    }
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        adapter,
        mode,
        execute: false,
        action,
        plan: mcpPlan,
      });
      return;
    }
    ui.header("desktop");
    ui.status("planned", "desktop action recorded for human handoff");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("adapter", adapter),
      ui.kv("mode", mode),
    ]);
  });

program
  .command("research")
  .argument("[target]", "Program or in-scope target")
  .option("--skill <name>", "Research skill adapter", "d-research")
  .option("--mode <mode>", "Execution mode", "passive")
  .option("--json", "Print machine-readable JSON")
  .description("Create a structured local research ledger")
  .action(async (target: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ skill: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const scopedTarget = target && target !== runtime.config.program ? runtime.scopeGuard.assertAllowed(target).url : undefined;
    const resolvedTarget = scopedTarget ?? runtime.config.program;
    const job = runtime.jobs.create("research", mode, resolvedTarget);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const allowed = await planAllowedAction({
      runtime,
      audit,
      jobId: job.id,
      adapter: options.skill,
      actionType: "research.public",
      target: scopedTarget,
      mode,
      riskLevel: "low",
    });
    const artifact = runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: options.skill,
      kind: "research_note",
      sourceUrl: resolvedTarget.startsWith("http") ? resolvedTarget : undefined,
      relativePath: path.join(job.id, "research-ledger.md"),
      content: `# Research Ledger

Program: ${runtime.config.program}
Target: ${resolvedTarget}
Skill: ${options.skill}
Mode: ${mode}

## Scope
In scope:
${runtime.config.in_scope.map((entry) => `- ${entry}`).join("\n")}

Out of scope:
${runtime.config.out_of_scope.map((entry) => `- ${entry}`).join("\n")}

## Notes
- Public research does not expand authorization.
- Store citations and public duplicate signals here as the research adapter matures.
`,
    });
    let execution: Awaited<ReturnType<ActionExecutor["execute"]>> | undefined;
    if (allowed) {
      const action = runtime.actions.list(job.id)[0];
      if (!action) {
        throw new BountyPilotError("Planned research action is unavailable.", "ACTION_NOT_FOUND");
      }
      execution = await new ActionExecutor(runtime).execute(action.id);
    }
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        target: resolvedTarget,
        mode,
        skill: options.skill,
        artifact,
        execution,
        actions: runtime.actions.list(job.id),
      });
      return;
    }
    ui.header("research");
    ui.status(execution ? "ok" : "planned", execution?.message ?? "research action requires human approval");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("target", resolvedTarget),
      ui.kv("artifact", artifact.path),
    ]);
  });

program
  .command("check")
  .argument("<url>", "In-scope URL to check")
  .option("--safe", "Run safe checks only")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Run low-rate, non-destructive checks")
  .action(async (url: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ safe?: boolean; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const scope = runtime.scopeGuard.assertAllowed(url);
    const job = runtime.jobs.create("safe-checks", mode, scope.url);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const allowed = await planAllowedAction({
      runtime,
      audit,
      jobId: job.id,
      adapter: "safe-checks",
      actionType: "http.get",
      target: scope.url,
      mode,
      riskLevel: "low",
    });
    if (!allowed) {
      const finalizedJob = runtime.jobs.finalize(job.id);
      if (options.json) {
        ui.json({
          ok: true,
          jobId: job.id,
          status: finalizedJob.status,
          pauseReason: finalizedJob.pauseReason,
          target: scope.url,
          mode,
          execute: false,
          actions: runtime.actions.list(job.id),
        });
        return;
      }
      ui.header("safe checks");
      ui.status("planned", "action requires approval");
      ui.panel("job", [ui.kv("id", job.id), ui.kv("target", scope.url)]);
      return;
    }

    if (!options.json) {
      ui.header("safe checks");
      ui.status("running", `checking ${scope.host}`);
    }
    const action = runtime.actions.list(job.id)[0];
    if (!action) {
      throw new BountyPilotError("Planned safe-check action is unavailable.", "ACTION_NOT_FOUND");
    }
    const result = await new ActionExecutor(runtime).execute(action.id);
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        target: scope.url,
        mode,
        result,
        findingsCreated: result.findingsCreated,
        candidatesCreated: result.candidatesCreated,
        evidenceCreated: result.evidenceCreated,
      });
      return;
    }
    ui.status("ok", "safe checks completed");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("target", scope.url),
      ui.kv("status", finalizedJob.status),
      ui.kv("findings", result.findingsCreated),
      ui.kv("candidates", result.candidatesCreated),
      ui.kv("evidence", result.evidenceCreated),
    ]);
  });

program
  .command("js")
  .argument("<url>", "In-scope page URL")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Analyze public JavaScript without exfiltrating secrets")
  .action(async (url: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const scope = runtime.scopeGuard.assertAllowed(url);
    const job = runtime.jobs.create("js-analyzer", mode, scope.url);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const allowed = await planAllowedAction({
      runtime,
      audit,
      jobId: job.id,
      adapter: "js-analyzer",
      actionType: "http.get",
      target: scope.url,
      mode,
      riskLevel: "low",
    });
    if (!allowed) {
      const finalizedJob = runtime.jobs.finalize(job.id);
      if (options.json) {
        ui.json({
          ok: true,
          jobId: job.id,
          status: finalizedJob.status,
          pauseReason: finalizedJob.pauseReason,
          target: scope.url,
          mode,
          execute: false,
          actions: runtime.actions.list(job.id),
        });
        return;
      }
      ui.header("javascript");
      ui.status("planned", "action requires approval");
      ui.panel("job", [ui.kv("id", job.id), ui.kv("target", scope.url)]);
      return;
    }

    if (!options.json) {
      ui.header("javascript");
      ui.status("running", `analyzing ${scope.host}`);
    }
    const action = runtime.actions.list(job.id)[0];
    if (!action) {
      throw new BountyPilotError("Planned JavaScript analysis action is unavailable.", "ACTION_NOT_FOUND");
    }
    const result = await new ActionExecutor(runtime).execute(action.id);
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        target: scope.url,
        mode,
        result,
      });
      return;
    }
    ui.status("ok", "analysis completed");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("result", result.message),
      ui.kv("endpoints", result.plannerCandidates?.endpointCandidates.length ?? 0),
      ui.kv("scripts", result.plannerCandidates?.jsAssets.length ?? 0),
      ui.kv("findings", result.findingsCreated),
      ui.kv("evidence", result.evidenceCreated),
    ]);
  });

program
  .command("report")
  .argument("<findingId>", "Finding id")
  .option("--platform <platform>", "Report platform", "hackerone")
  .option("--force-local-draft", "Write a local draft even when report readiness is blocked")
  .option("--json", "Print machine-readable JSON")
  .description("Generate a local HackerOne or Bugcrowd markdown report draft")
  .action((findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ platform: string; forceLocalDraft?: boolean; json?: boolean }>();
    if (!isSupportedReportPlatform(options.platform)) {
      throw new BountyPilotError("Unsupported report platform. Use hackerone or bugcrowd.", "REPORT_PLATFORM_UNSUPPORTED");
    }
    const runtime = createRuntime(rootProgramName());
    const finding = runtime.findings.get(findingId);
    if (!finding) {
      throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
    }
    const evidence = runtime.evidence.list(findingId);
    const manifest = runtime.evidence.buildManifest({ findingId });
    const duplicate = new DuplicateRiskEngine().estimate(
      finding,
      runtime.findings.list().filter((item) => item.id !== finding.id),
    );
    const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
    const review = buildReportReview({ finding, evidence, manifest, duplicate, triage, platform: options.platform });
    if (review.readiness === "blocked" && !options.forceLocalDraft) {
      if (options.json || requestedJsonOutput(process.argv)) {
        ui.json({
          ok: false,
          findingId,
          readiness: review.readiness,
          review,
          nextCommands: [`bounty reports score ${findingId} --json`, `bounty reports review ${findingId}`],
        });
        process.exitCode = 2;
        return;
      }
      throw new BountyPilotError(
        `Report readiness is blocked. Run reports score/review first or pass --force-local-draft for a local-only draft.`,
        "REPORT_READINESS_BLOCKED",
      );
    }
    const reportPath = writePlatformReport(runtime.paths.reportsDir, options.platform, finding, evidence);
    runtime.findings.updateStatus(findingId, "report_drafted");
    const artifact = runtime.evidence.create({
      findingId,
      adapterName: "report-generator",
      kind: "report",
      sourceUrl: finding.url,
      path: reportPath,
    });
    const updatedFinding = runtime.findings.get(findingId);
    if (options.json) {
      ui.json({
        ok: true,
        findingId,
        status: "report_drafted",
        finding: updatedFinding,
        artifact,
        review,
        report: { platform: options.platform, path: reportPath },
        platform: options.platform,
        path: reportPath,
      });
      return;
    }
    ui.header("report");
    ui.status("ok", "draft generated");
    ui.panel("finding", [
      ui.kv("id", finding.id),
      ui.kv("title", finding.title),
      ui.kv("readiness", review.readiness),
      ui.kv("path", reportPath),
    ]);
  });

const reportsCommand = program
  .command("reports")
  .description("Review report readiness before drafting or manual submission");

reportsCommand
  .command("score")
  .argument("<findingOrCandidateId>", "Finding id or candidate id")
  .option("--job <jobId>", "Only score evidence from one workflow job")
  .option("--platform <platform>", "Report platform context", "hackerone")
  .option("--json", "Print machine-readable JSON")
  .description("Print a compact reportability score, readiness, blockers, warnings, and next steps")
  .action((findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; platform: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) {
      requireJob(runtime, options.job);
    }
    let finding = runtime.findings.get(findingId);
    const candidate = finding ? undefined : runtime.candidates.get(findingId);
    if (!finding && !candidate) {
      throw new BountyPilotError(`Finding or candidate not found: ${findingId}`, "FINDING_NOT_FOUND");
    }
    const evidence = candidate
      ? evidenceForCandidate(runtime, candidate, options.job)
      : filterEvidenceByJob(runtime.evidence.list(findingId), options.job);
    finding = finding ?? candidateAsFinding(candidate as FindingCandidate, evidence);
    const manifest = candidate
      ? runtime.evidence.buildManifestForArtifacts(evidence, { findingId: candidate.findingId ?? candidate.id, jobId: options.job })
      : runtime.evidence.buildManifest({ findingId, jobId: options.job });
    const duplicate = new DuplicateRiskEngine().estimate(
      finding,
      runtime.findings.list().filter((item) => item.id !== finding.id && item.id !== candidate?.findingId),
    );
    const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
    const review = buildReportReview({ finding, evidence, manifest, duplicate, triage, platform: options.platform });
    const payload = {
      ok: review.readiness !== "blocked",
      findingId: candidate?.findingId ?? finding.id,
      candidateId: candidate?.id,
      jobId: options.job,
      platform: options.platform,
      score: review.score,
      readiness: review.readiness,
      recommendation: review.recommendation,
      evidence: review.counts.evidence,
      counts: review.counts,
      checks: review.checks,
      blockers: review.blockers,
      warnings: review.warnings,
      nextSteps: review.nextSteps,
      nextCommands: candidate
        ? reportReviewCommands(candidate.id, options.job, review.readiness, "candidate", candidate.findingId)
        : reportReviewCommands(finding.id, options.job, review.readiness),
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      process.exitCode = payload.ok ? 0 : 2;
      return;
    }
    ui.header("reports score");
    ui.status(reportReadinessStatusLabel(review.readiness), `score ${review.score}/100: ${review.readiness}`);
    ui.panel("finding", [
      ui.kv("id", finding.id),
      ui.kv("title", finding.title),
      ...(candidate ? [ui.kv("candidate", candidate.id)] : []),
      ui.kv("evidence", review.counts.evidence),
      ui.kv("recommend", review.recommendation),
    ]);
    if (review.blockers.length > 0) {
      ui.blank();
      ui.list("blockers", review.blockers);
    }
    if (review.warnings.length > 0) {
      ui.blank();
      ui.list("warnings", review.warnings);
    }
    ui.blank();
    ui.commandList("next commands", payload.nextCommands);
    process.exitCode = payload.ok ? 0 : 2;
  });

reportsCommand
  .command("draft")
  .argument("<findingOrCandidateId>", "Finding id or candidate id")
  .option("--platform <platform>", "Report platform", "hackerone")
  .option("--force-local-draft", "Write a local draft even when report readiness is blocked")
  .option("--json", "Print machine-readable JSON")
  .description("Write a local report draft for a report-ready finding or candidate")
  .action((findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ platform: string; forceLocalDraft?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const candidate = runtime.candidates.get(findingId);
    if (candidate && candidate.reportability !== "ready_for_draft" && !options.forceLocalDraft) {
      const payload = {
        ok: false,
        candidateId: candidate.id,
        findingId: candidate.findingId,
        readiness: candidate.reportability,
        blockers: [`Candidate ${candidate.id} is ${candidate.reportability}; run reports score and add evidence before drafting.`],
        nextCommands: candidateNextCommands(candidate),
      };
      if (options.json || requestedJsonOutput(process.argv)) {
        ui.json(payload);
        process.exitCode = 2;
        return;
      }
      throw new BountyPilotError(payload.blockers[0], "REPORT_READINESS_BLOCKED");
    }
    const promoted = candidate
      ? promoteCandidate(runtime, candidate.id, candidate.status === "ready_for_draft" ? "validated" : "needs_validation")
      : undefined;
    const targetFindingId = promoted?.finding.id ?? findingId;
    const result = draftFindingReport(runtime, targetFindingId, options.platform, options.forceLocalDraft === true);
    const payload = {
      ...result,
      candidateId: candidate?.id,
      promoted: promoted?.created,
      nextCommands: [
        ...(candidate ? [`bounty findings candidate ${candidate.id}`] : []),
        `bounty findings show ${result.findingId}`,
        `bounty reports score ${result.findingId} --json`,
      ],
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("reports draft");
    ui.status("ok", "local draft generated");
    ui.panel("draft", [
      ui.kv("finding", result.findingId),
      ui.kv("candidate", candidate?.id ?? "-"),
      ui.kv("readiness", result.review.readiness),
      ui.kv("path", result.report.path),
    ]);
  });

reportsCommand
  .command("bundle")
  .argument("<findingOrCandidateId>", "Finding id or candidate id")
  .option("--job <jobId>", "Workflow job id to bundle. Defaults to the candidate job or the finding evidence job when unambiguous.")
  .option("--output <dir>", "Output directory. Defaults to the program exports directory.")
  .option("--include-artifacts", "Copy readable evidence artifact files into the bundle")
  .option("--json", "Print machine-readable JSON")
  .description("Write a job-scoped handoff bundle for a report candidate or finding")
  .action((findingOrCandidateId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; output?: string; includeArtifacts?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const candidate = runtime.candidates.get(findingOrCandidateId);
    const finding = candidate ? undefined : runtime.findings.get(findingOrCandidateId);
    if (!candidate && !finding) {
      throw new BountyPilotError(`Finding or candidate not found: ${findingOrCandidateId}`, "FINDING_NOT_FOUND");
    }
    const target = resolveReportBundleTarget(runtime, findingOrCandidateId, options.job);
    const result = writeHandoffBundle(runtime, {
      output: options.output,
      jobId: target.jobId,
      includeArtifacts: options.includeArtifacts,
    });
    const payload = {
      ok: true,
      subject: target.subject,
      findingId: target.findingId,
      candidateId: target.candidateId,
      jobId: target.jobId,
      evidence: target.evidence.length,
      bundle: result,
      nextCommands: [
        `bounty export bundle --job ${target.jobId}`,
        `bounty export bundle --job ${target.jobId} --include-artifacts`,
      ],
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("reports bundle");
    ui.status("ok", "report handoff bundle exported");
    ui.panel("bundle", [
      ui.kv("subject", target.subject),
      ui.kv("finding", target.findingId ?? "-"),
      ui.kv("candidate", target.candidateId ?? "-"),
      ui.kv("job", target.jobId),
      ui.kv("path", result.outputDir),
      ui.kv("files", result.files.length),
      ui.kv("artifacts", result.artifactsCopied),
    ]);
  });

reportsCommand
  .command("review")
  .argument("<findingId>", "Finding id")
  .option("--job <jobId>", "Only review evidence from one workflow job")
  .option("--platform <platform>", "Report platform context", "hackerone")
  .option("--write", "Write the review as a local evidence artifact")
  .option("--json", "Print machine-readable JSON")
  .description("Run a local pre-submit report checklist for one finding")
  .action((findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; platform: string; write?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) {
      requireJob(runtime, options.job);
    }
    const finding = runtime.findings.get(findingId);
    if (!finding) {
      throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
    }
    const evidence = filterEvidenceByJob(runtime.evidence.list(findingId), options.job);
    const manifest = runtime.evidence.buildManifest({ findingId, jobId: options.job });
    const duplicate = new DuplicateRiskEngine().estimate(
      finding,
      runtime.findings.list().filter((item) => item.id !== finding.id),
    );
    const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
    const review = buildReportReview({
      finding,
      evidence,
      manifest,
      duplicate,
      triage,
      platform: options.platform,
    });
    const nextCommands = reportReviewCommands(finding.id, options.job, review.readiness);
    let artifact: EvidenceArtifact | undefined;
    if (options.write) {
      artifact = runtime.evidence.writeTextArtifact({
        findingId,
        jobId: options.job,
        adapterName: "report-review",
        kind: "tool_output",
        sourceUrl: finding.url,
        relativePath: path.join(finding.id, options.job ? `${options.job}-report-review.json` : "report-review.json"),
        content: `${JSON.stringify(review, null, 2)}\n`,
      });
    }
    if (options.json) {
      ui.json({
        ok: true,
        findingId,
        jobId: options.job,
        platform: options.platform,
        review,
        artifact,
        nextCommands,
      });
      return;
    }
    ui.header("reports review");
    ui.status(reportReadinessStatusLabel(review.readiness), `report readiness: ${review.readiness}`);
    ui.panel("finding", [
      ui.kv("id", finding.id),
      ui.kv("title", finding.title),
      ui.kv("score", `${review.score}/100`),
      ui.kv("recommend", review.recommendation),
      ui.kv("evidence", review.counts.evidence),
      ui.kv("readable", review.counts.readableEvidence),
      ui.kv("unreadable", review.counts.unreadableEvidence),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "detail"],
      review.checks.map((check) => [check.status, check.title, check.detail]),
    );
    if (review.blockers.length > 0) {
      ui.blank();
      ui.list("blockers", review.blockers);
    }
    if (review.warnings.length > 0) {
      ui.blank();
      ui.list("warnings", review.warnings);
    }
    if (review.nextSteps.length > 0) {
      ui.blank();
      ui.list("next steps", review.nextSteps);
    }
    if (artifact) {
      ui.blank();
      ui.panel("artifact", [ui.kv("id", artifact.id), ui.kv("path", artifact.path)]);
    }
    ui.blank();
    ui.commandList("next commands", nextCommands);
  });

program
  .command("triage")
  .argument("<findingId>", "Finding id")
  .option("--json", "Print machine-readable JSON")
  .description("Estimate evidence quality, duplicate risk, and reportability")
  .action((findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const finding = runtime.findings.get(findingId);
    if (!finding) {
      throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
    }
    const evidence = runtime.evidence.list(findingId);
    const duplicate = new DuplicateRiskEngine().estimate(finding, runtime.findings.list().filter((item) => item.id !== finding.id));
    const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
    if (options.json) {
      ui.json({ finding, evidence, duplicate, triage });
      return;
    }
    ui.header("triage");
    ui.panel("result", [
      ui.kv("finding", finding.id),
      ui.kv("duplicate", duplicate.risk),
      ui.kv("evidence", triage.evidenceQuality),
      ui.kv("score", `${triage.reportabilityScore}/100`),
      ui.kv("recommend", triage.recommendation),
    ]);
    ui.blank();
    ui.list("reasons", [...duplicate.reasons, ...triage.reasons]);
  });

program
  .command("reproduce")
  .argument("<findingId>", "Finding id")
  .option("--with <adapter>", "Optional evidence adapter plan, for example playwright-mcp")
  .option("--mode <mode>", "Execution mode for adapter planning", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Create or print safe reproduction notes for a finding")
  .action((findingId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ with?: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const finding = runtime.findings.get(findingId);
    if (!finding) {
      throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
    }
    const evidence = runtime.evidence.list(findingId);
    const content = generateReproductionNote(finding, evidence);
    const artifact = runtime.evidence.writeTextArtifact({
      findingId,
      adapterName: "reproduce",
      kind: "reproduction_note",
      sourceUrl: finding.url,
      relativePath: path.join(finding.id, "reproduction.md"),
      content,
    });
    let planJobId: string | undefined;
    let planPayload: Record<string, unknown> | undefined;
    if (options.with) {
      const adapter = normalizeIntegrationName(options.with);
      if (adapter !== "playwright_mcp") {
        throw new BountyPilotError(`Unsupported reproduction adapter: ${options.with}`, "REPRODUCE_ADAPTER_UNSUPPORTED");
      }
      runtime.scopeGuard.assertAllowed(finding.url);
      const job = runtime.jobs.create("reproduce", mode, finding.url);
      planJobId = job.id;
      const audit = createJobAuditLogger(runtime.paths, job.id);
      const plan = new McpClientManager(runtime.config).prepareCallPlan({
        server: "playwright-mcp",
        tool: "browser_navigate",
        mode,
        target: finding.url,
        arguments: { url: finding.url, findingId },
      });
      const action = runtime.actions.enqueue({
        jobId: job.id,
        adapter,
        actionType: plan.validation.capability?.actionType ?? "browser.navigate",
        target: finding.url,
        riskLevel: plan.validation.capability?.riskLevel ?? "low",
        requiresApproval: plan.validation.requiresApproval,
        status: plan.validation.decision === "block" ? "blocked" : undefined,
        requiredForCompletion: false,
        metadata: { execute: false, planningOnly: true, handoffOnly: true, tool: plan.tool },
      });
      audit.log({
        jobId: job.id,
        findingId,
        actionType: "browser.navigate",
        url: finding.url,
        adapterName: adapter,
        policyDecision: plan.validation.decision,
        reason: plan.validation.reasons.join("; "),
        metadata: { actionId: action.id, execute: false, tool: plan.tool },
      });
      runtime.evidence.writeTextArtifact({
        findingId,
        jobId: job.id,
        adapterName: adapter,
        kind: "evidence_note",
        sourceUrl: finding.url,
        relativePath: path.join(finding.id, "playwright-mcp-reproduction-plan.json"),
        content: JSON.stringify(plan, null, 2),
      });
      planPayload = { jobId: job.id, adapter, action, plan };
      if (!plan.validation.ok) {
        const finalizedJob = runtime.jobs.finalize(job.id);
        if (options.json) {
          ui.json({
            ok: false,
            findingId,
            artifact,
            plan: { ...planPayload, status: finalizedJob.status, pauseReason: finalizedJob.pauseReason },
          });
          process.exitCode = 1;
          return;
        }
        throw new BountyPilotError(plan.validation.reasons.join("; "), "REPRODUCE_PLAN_BLOCKED");
      }
      const finalizedJob = runtime.jobs.finalize(job.id);
      planPayload = { ...planPayload, status: finalizedJob.status, pauseReason: finalizedJob.pauseReason };
    }
    if (options.json) {
      ui.json({ ok: true, findingId, status: finding.status, artifact, planJobId, plan: planPayload });
      return;
    }
    ui.header("reproduce");
    ui.status("ok", "safe reproduction notes written");
    ui.panel("finding", [
      ui.kv("id", finding.id),
      ui.kv("status", finding.status),
      ui.kv("path", artifact.path),
      ui.kv("plan job", planJobId),
    ]);
  });

const agent = program.command("agent").description("Plan safe next actions without executing them");

agent
  .command("run")
  .requiredOption("--goal <goal>", "Goal for the planner")
  .option("--target <target>", "Optional in-scope URL or host")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Create a safe agent plan for a goal without bypassing CLI policy gates")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ goal: string; target?: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const target = options.target ? runtime.scopeGuard.assertAllowed(options.target).url : runtime.config.program;
    const job = runtime.jobs.create("agent-run", mode, target);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    await planAllowedAction({
      runtime,
      audit,
      jobId: job.id,
      adapter: "agent-planner",
      actionType: "agent.plan",
      target,
      mode,
      riskLevel: "low",
      requiredForCompletion: false,
      metadata: { execute: false, planningOnly: true, handoffOnly: true, goal: options.goal },
    });
    const artifact = runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: "agent-planner",
      kind: "evidence_note",
      sourceUrl: target.startsWith("http") ? target : undefined,
      relativePath: path.join(job.id, "agent-goal.md"),
      content: `# Agent Goal

Goal: ${options.goal}
Target: ${target}
Mode: ${mode}

The agent planner may propose safe CLI actions, but it must not execute browser, HTTP, MCP, desktop, or external tool actions directly. Risky actions require ActionQueue approval.
`,
    });
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        goal: options.goal,
        target,
        mode,
        artifact,
        actions: runtime.actions.list(job.id),
      });
      return;
    }
    ui.header("agent run");
    ui.status("ok", "goal converted into a safe plan");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("target", target),
      ui.kv("mode", mode),
      ui.kv("artifact", artifact.path),
    ]);
  });

agent
  .command("plan")
  .argument("<url>", "In-scope seed URL")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--from-job <jobId>", "Use workflow candidates, evidence, findings, and action history from a prior job")
  .option("--json", "Print machine-readable JSON")
  .description("Create planned actions from current crawl graph and seed URL")
  .action(async (url: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ mode?: string; fromJob?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const scope = runtime.scopeGuard.assertAllowed(url);
    const sourceSummary = options.fromJob ? loadPlannerSourceSummary(runtime, options.fromJob) : undefined;
    const job = runtime.jobs.create("agent-plan", mode, scope.url);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const pages = runtime.crawlGraph
      .listPages()
      .map((page) => page.url)
      .filter((pageUrl) => runtime.scopeGuard.test(pageUrl).allowed);
    const plannerLoop = new AgentPlanner().planLoop({
      urls: [scope.url, ...(sourceSummary?.seeds ?? []), ...pages],
      endpointCandidates: sourceSummary?.plannerCandidates?.endpointCandidates ?? [],
      jsAssets: sourceSummary?.plannerCandidates?.jsAssets ?? [],
      mode,
      findings: plannerFeedbackFindings(runtime, sourceSummary, job.id),
      evidence: plannerFeedbackEvidence(runtime, sourceSummary, job.id),
      actions: plannerActionContext(runtime, sourceSummary, job.id),
      maxIterations: 3,
    });
    const artifact = runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: "agent-planner",
      kind: "tool_output",
      sourceUrl: scope.url,
      relativePath: path.join(job.id, "agent-plan-loop.json"),
      content: JSON.stringify(plannerLoop, null, 2),
    });

    let enqueued = 0;
    for (const action of plannerLoop.actions) {
      if (!runtime.scopeGuard.test(action.target).allowed) {
        audit.log({
          jobId: job.id,
          actionType: action.actionType,
          url: action.target,
          adapterName: action.adapter,
          policyDecision: "block",
          reason: "Planner target blocked by ScopeGuard",
        });
        continue;
      }
      await planAllowedAction({
        runtime,
        audit,
        jobId: job.id,
        adapter: action.adapter,
        actionType: action.actionType,
        target: action.target,
        mode,
        riskLevel: action.riskLevel,
        requiredForCompletion: false,
        metadata: { execute: false, planningOnly: true, handoffOnly: true, planner: true },
      });
      enqueued += 1;
    }
    const finalizedJob = runtime.jobs.finalize(job.id);
    if (options.json) {
      ui.json({
        ok: true,
        jobId: job.id,
        status: finalizedJob.status,
        pauseReason: finalizedJob.pauseReason,
        target: scope.url,
        fromJobId: sourceSummary?.jobId,
        mode,
        planned: plannerLoop.actions,
        plannerLoop,
        artifact,
        enqueued,
        actions: runtime.actions.list(job.id),
      });
      return;
    }
    ui.header("agent plan");
    ui.status("ok", "safe actions planned");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("target", scope.url),
      ui.kv("from job", sourceSummary?.jobId ?? "-"),
      ui.kv("mode", mode),
      ui.kv("actions", enqueued),
      ui.kv("artifact", artifact.path),
    ]);
  });

const jobs = program.command("jobs").description("Inspect workflow and command jobs");

jobs
  .command("list")
  .option("--limit <limit>", "Maximum number of jobs", "25")
  .option("--json", "Print machine-readable JSON")
  .description("List recent jobs")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ limit: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const limit = parsePositiveIntegerOption(options.limit, "limit", 25);
    const records = runtime.jobs.list(limit);
    if (options.json) {
      ui.json({ limit, jobs: records });
      return;
    }
    ui.header("jobs");
    if (records.length === 0) {
      ui.status("warn", "no jobs found");
      return;
    }
    ui.table(
      ["status", "mode", "type", "id", "target"],
      records.map((job) => [job.status, job.mode, job.type, job.id, job.target]),
    );
  });

jobs
  .command("show")
  .argument("<jobId>", "Job id to inspect")
  .option("--json", "Print machine-readable JSON")
  .description("Show job details and workflow checkpoint state")
  .action((jobId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const job = runtime.jobs.get(jobId);
    if (!job) throw new BountyPilotError(`Job not found: ${jobId}`, "JOB_NOT_FOUND");
    const summary = new WorkflowRunner(runtime).loadSummary(jobId);
    const actionCounts = runtime.actions.summarize(job.id);
    const events = runtime.events.list(jobId);
    if (options.json) {
      ui.json({ job, summary: summary ? workflowSummaryForDisplay(runtime, summary) : undefined, actionCounts, events });
      return;
    }
    ui.header("jobs show");
    if (summary) {
      printWorkflowSummary(workflowSummaryForDisplay(runtime, summary), "workflow checkpoint loaded");
      printWorkflowTimeline(events.slice(-8), "recent events");
      return;
    }
    ui.status("ok", "job loaded");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("type", job.type),
      ui.kv("status", job.status),
      ui.kv("mode", job.mode),
      ui.kv("target", job.target),
      ui.kv("created", job.createdAt),
      ui.kv("updated", job.updatedAt),
      ui.kv("actions", actionCounts.total),
      ui.kv("pending", actionCounts.pending),
      ui.kv("approved", actionCounts.approved),
      ui.kv("executed", actionCounts.executed),
      ui.kv("blocked", actionCounts.blocked),
      ui.kv("failed", actionCounts.failed),
    ]);
    printWorkflowTimeline(events.slice(-8), "recent events");
  });

jobs
  .command("timeline")
  .argument("<jobId>", "Job id whose workflow event timeline should be shown")
  .option("--limit <limit>", "Maximum number of workflow events", "50")
  .option("--json", "Print machine-readable JSON")
  .description("Show structured workflow events for a job")
  .action((jobId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ limit: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const job = runtime.jobs.get(jobId);
    if (!job) throw new BountyPilotError(`Job not found: ${jobId}`, "JOB_NOT_FOUND");
    const limit = parsePositiveIntegerOption(options.limit, "limit", 50);
    const events = runtime.events.list(jobId, limit);
    if (options.json) {
      ui.json({ jobId, limit, events });
      return;
    }
    ui.header("jobs timeline");
    printWorkflowTimeline(events);
  });

jobs
  .command("watch")
  .argument("<jobId>", "Job id whose workflow state should be watched")
  .option("--interval-ms <ms>", "Refresh interval in milliseconds", "2000")
  .option("--iterations <count>", "Maximum refreshes before exiting")
  .option("--limit <limit>", "Maximum recent workflow events per refresh", "12")
  .option("--json", "Print one machine-readable snapshot and exit")
  .description("Watch workflow status, action counts, and recent timeline events")
  .action(async (jobId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ intervalMs: string; iterations?: string; limit: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const intervalMs = parsePositiveIntegerOption(options.intervalMs, "interval-ms", 2000);
    const iterations = options.iterations ? parsePositiveIntegerOption(options.iterations, "iterations", 1) : undefined;
    const limit = parsePositiveIntegerOption(options.limit, "limit", 12);

    if (options.json) {
      ui.json(jobWatchSnapshot(runtime, jobId, limit));
      return;
    }

    ui.header("jobs watch");
    let refreshes = 0;
    while (true) {
      const snapshot = jobWatchSnapshot(runtime, jobId, limit);
      refreshes += 1;
      printJobWatchSnapshot(snapshot, refreshes);
      if (snapshot.terminal || (iterations !== undefined && refreshes >= iterations)) {
        break;
      }
      await sleep(intervalMs);
      ui.blank();
    }
  });

jobs
  .command("resume")
  .argument("<jobId>", "Workflow job id to resume")
  .option("--mode <mode>", "Override execution mode")
  .option(
    "--with <components>",
    "Override comma-separated workflow components: safe-checks,js-analyzer,playwright,triage,planner,crawl4ai,playwright-mcp,d-research-skill",
  )
  .option("--dry-run", "Resume as dry-run planning")
  .option("--live", "Resume with live execution for allowed components")
  .option("--draft-reports", "Generate local report drafts for high-reportability findings")
  .option("--json", "Print machine-readable JSON")
  .description("Resume a failed or incomplete workflow from its checkpoint")
  .action(async (jobId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      mode?: string;
      with?: string;
      dryRun?: boolean;
      live?: boolean;
      draftReports?: boolean;
      json?: boolean;
    }>();
    if (options.dryRun && options.live) {
      throw new BountyPilotError("Choose either --dry-run or --live, not both.", "RESUME_MODE_CONFLICT");
    }
    const runtime = createRuntime(rootProgramName());
    const overrides: Partial<Omit<WorkflowOptions, "resumeFromJobId" | "resumeSkipPhases">> = {};
    if (options.mode) overrides.mode = modeFromOptions(options.mode);
    if (options.with) overrides.withComponents = parseComponentList(options.with);
    if (options.dryRun) overrides.dryRun = true;
    if (options.live) overrides.dryRun = false;
    if (options.draftReports) overrides.draftReports = true;

    if (!options.json) {
      ui.header("jobs resume");
      ui.status("running", `loading checkpoint ${jobId}`);
    }
    const summary = await new WorkflowRunner(runtime).resume(jobId, overrides);
    if (summary.status === "failed") {
      process.exitCode = 1;
    }
    if (options.json) {
      ui.json({ summary: workflowSummaryForDisplay(runtime, summary), events: runtime.events.list(summary.jobId) });
      return;
    }
    printWorkflowSummary(
      workflowSummaryForDisplay(runtime, summary),
      summary.jobId === jobId ? "workflow already completed" : "workflow resumed",
    );
    printWorkflowTimeline(runtime.events.list(summary.jobId, 8), "recent events");
  });

const audit = program.command("audit").description("Inspect local job audit logs");

audit
  .command("list")
  .requiredOption("--job <jobId>", "Job id whose audit log should be read")
  .option("--limit <limit>", "Maximum audit events to show", "50")
  .option("--json", "Print machine-readable JSON")
  .description("List audit events for a job")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job: string; limit: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const limit = parsePositiveIntegerOption(options.limit, "limit", 50);
    const job = requireJob(runtime, options.job);
    const events = readAuditEvents(runtime, job.id).slice(0, limit);
    if (options.json) {
      ui.json({ jobId: job.id, limit, events });
      return;
    }
    ui.header("audit");
    if (events.length === 0) {
      ui.status("warn", "no audit events found");
      return;
    }
    ui.table(
      ["time", "decision", "adapter", "action", "status", "url", "reason"],
      events.map((event) => [
        String(event.timestamp ?? "-"),
        String(event.policyDecision ?? "-"),
        String(event.adapterName ?? "-"),
        String(event.actionType ?? "-"),
        String(event.status ?? "-"),
        String(event.url ?? "-"),
        String(event.reason ?? "-"),
      ]),
    );
  });

audit
  .command("export")
  .requiredOption("--job <jobId>", "Job id whose audit log should be exported")
  .option("--output <path>", "Output JSON path. Defaults to the job directory.")
  .option("--json", "Print machine-readable JSON")
  .description("Export audit events as JSON")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job: string; output?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const job = requireJob(runtime, options.job);
    const events = readAuditEvents(runtime, job.id);
    const payload = {
      generatedAt: new Date().toISOString(),
      jobId: job.id,
      source: auditLogPath(runtime, job.id),
      eventCount: events.length,
      events,
    };
    const outputPath = options.output
      ? path.resolve(options.output)
      : path.join(runtime.paths.jobsDir, job.id, "audit-export.json");
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
    if (options.json) {
      ui.json({ ok: true, path: outputPath, ...payload });
      return;
    }
    ui.header("audit export");
    ui.status("ok", "audit exported");
    ui.panel("artifact", [
      ui.kv("job", job.id),
      ui.kv("events", events.length),
      ui.kv("path", outputPath),
    ]);
  });

const actions = program.command("actions").description("Inspect and manage planned actions");

actions
  .command("list")
  .option("--job <jobId>", "Filter by job id")
  .option("--pending", "Only show actions waiting for approval")
  .option("--json", "Print machine-readable JSON")
  .description("List queued actions")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; pending?: boolean; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) requireJob(runtime, options.job);
    const records = runtime.actions
      .list(options.job)
      .filter((action) => !isWorkflowBarrierAction(action))
      .filter((action) => !options.pending || action.status === "pending");
    if (options.json) {
      ui.json({ jobId: options.job, pendingOnly: options.pending === true, actions: records });
      return;
    }
    ui.header("actions");
    if (records.length === 0) {
      ui.status("warn", "no actions found");
      return;
    }
    ui.table(
      ["status", "risk", "approval", "adapter", "type", "id", "target"],
      records.map((action) => [
        action.status,
        action.riskLevel,
        action.requiresApproval,
        action.adapter,
        action.actionType,
        action.id,
        action.target,
      ]),
    );
  });

actions
  .command("review")
  .option("--job <jobId>", "Filter by job id")
  .option("--limit <limit>", "Maximum reviewable actions to show", "10")
  .option("--interactive", "Review actions one-by-one with approve/block/skip prompts")
  .option("--note <text>", "Default human review note for interactive approve/block decisions")
  .option("--json", "Print machine-readable JSON")
  .description("Show pending and approved actions with review commands")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job?: string; limit: string; interactive?: boolean; note?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    if (options.job) requireJob(runtime, options.job);
    const limit = parsePositiveIntegerOption(options.limit, "limit", 10);
    const records = runtime.actions
      .list(options.job)
      .filter((action) => !isWorkflowBarrierAction(action))
      .filter((action) => action.status === "pending" || action.status === "approved")
      .slice(0, limit);
    const nextCommands = records.flatMap(actionReviewCommands);
    if (options.interactive) {
      const result = await runInteractiveActionReview(runtime, records, {
        jobId: options.job,
        limit,
        defaultNote: options.note,
      });
      if (options.json) {
        ui.json(result);
        return;
      }
      printInteractiveActionReviewResult(result);
      return;
    }
    if (options.json) {
      ui.json({ jobId: options.job, limit, actions: records, nextCommands });
      return;
    }
    ui.header("actions review");
    if (records.length === 0) {
      ui.status("warn", "no pending or approved actions found");
      return;
    }
    ui.panel("review queue", [
      ui.kv("actions", records.length),
      ui.kv("job", options.job),
      ui.kv("pending", records.filter((action) => action.status === "pending").length),
      ui.kv("approved", records.filter((action) => action.status === "approved").length),
    ]);
    ui.blank();
    ui.table(
      ["status", "risk", "adapter", "type", "id", "target"],
      records.map((action) => [action.status, action.riskLevel, action.adapter, action.actionType, action.id, action.target]),
    );
    printActionReviewCommands(records);
  });

actions
  .command("show")
  .argument("<actionId>", "Action id to inspect")
  .option("--json", "Print machine-readable JSON")
  .description("Show action details, review history, and related job events")
  .action((actionId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const action = runtime.actions.get(actionId);
    if (!action) throw new BountyPilotError(`Action not found: ${actionId}`, "ACTION_NOT_FOUND");
    const reviews = runtime.reviews.listForAction(action.id);
    const job = action.jobId ? runtime.jobs.get(action.jobId) : undefined;
    const events = action.jobId
      ? runtime.events.list(action.jobId).filter((event) => event.metadata?.actionId === action.id)
      : [];
    const payload = { action, reviews, job, events };
    if (options.json) {
      ui.json(payload);
      return;
    }
    ui.header("actions show");
    ui.panel("action", [
      ui.kv("id", action.id),
      ui.kv("status", action.status),
      ui.kv("adapter", action.adapter),
      ui.kv("type", action.actionType),
      ui.kv("target", action.target),
      ui.kv("risk", action.riskLevel),
      ui.kv("approval", action.requiresApproval),
      ui.kv("job", action.jobId),
    ]);
    if (reviews.length > 0) {
      ui.blank();
      ui.table(
        ["time", "decision", "note"],
        reviews.map((review) => [review.createdAt, review.decision, review.note]),
      );
    }
    printActionReviewCommands([action]);
  });

actions
  .command("approve")
  .argument("<actionId>", "Action id to approve")
  .option("--note <text>", "Human review note to store with the approval")
  .option("--reviewer <id>", "Local human reviewer identifier", "human:local-cli")
  .option("--ttl-seconds <seconds>", "Finite approval lifetime in seconds", "900")
  .option("--json", "Print machine-readable JSON")
  .description("Approve a planned action through the authoritative human-review service")
  .action((actionId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ note?: string; reviewer: string; ttlSeconds: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const ttlSeconds = parsePositiveIntegerOption(options.ttlSeconds, "ttl-seconds", 900);
    const approval = approveActionAsCliHuman(runtime, actionId, {
      note: options.note,
      reviewerId: options.reviewer,
      ttlMs: ttlSeconds * 1_000,
    });
    if (options.json) {
      ui.json(approval);
      return;
    }
    ui.header("actions");
    ui.status("ok", "action approved");
    ui.panel("action", [
      ui.kv("id", approval.action.id),
      ui.kv("adapter", approval.action.adapter),
      ui.kv("type", approval.action.actionType),
      ui.kv("target", approval.action.target),
      ui.kv("reviewer", approval.review.reviewerId),
      ui.kv("expires", approval.review.expiresAt),
      ui.kv("note", approval.review.note),
    ]);
  });

actions
  .command("block")
  .argument("<actionId>", "Action id to block")
  .option("--note <text>", "Human review note to store with the block decision")
  .option("--json", "Print machine-readable JSON")
  .description("Mark a planned action as blocked")
  .action((actionId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ note?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const action = runtime.actions.get(actionId);
    if (!action) throw new BountyPilotError(`Action not found: ${actionId}`, "ACTION_NOT_FOUND");
    const updated = runtime.actions.block(actionId);
    const review = recordActionReview(runtime, updated, "blocked", options.note);
    // Re-derive the owning job after a human block. Required actions must
    // immediately move the job to its authoritative blocked/failed state;
    // otherwise the job can retain a stale approval_required status.
    if (updated.jobId) runtime.jobs.finalize(updated.jobId);
    if (options.json) {
      ui.json({ action: updated, review });
      return;
    }
    ui.header("actions");
    ui.status("blocked", "action blocked");
    ui.panel("action", [
      ui.kv("id", updated.id),
      ui.kv("adapter", updated.adapter),
      ui.kv("type", updated.actionType),
      ui.kv("target", updated.target),
      ui.kv("note", review.note),
    ]);
  });

actions
  .command("execute")
  .argument("<actionId>", "Approved action id to execute")
  .option("--json", "Print machine-readable JSON")
  .description("Execute one approved internal action through BountyPilot policy gates")
  .action(async (actionId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const result = await new ActionExecutor(runtime).execute(actionId);
    if (options.json) {
      ui.json(result);
      return;
    }
    ui.header("actions execute");
    ui.status("ok", result.message);
    ui.panel("action", [
      ui.kv("id", result.action.id),
      ui.kv("status", result.status),
      ui.kv("evidence", result.evidenceCreated),
      ui.kv("findings", result.findingsCreated),
    ]);
  });

actions
  .command("run-approved")
  .requiredOption("--job <jobId>", "Job id whose approved actions should be executed")
  .option("--limit <limit>", "Maximum approved actions to execute", "10")
  .option("--json", "Print machine-readable JSON")
  .description("Execute approved internal actions for a job")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ job: string; limit: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const job = runtime.jobs.get(options.job);
    if (!job) {
      throw new BountyPilotError(`Job not found: ${options.job}`, "JOB_NOT_FOUND");
    }
    const executor = new ActionExecutor(runtime);
    const limit = parsePositiveIntegerOption(options.limit, "limit", 10);
    const approved = runtime.actions.listByStatus("approved", options.job).slice(0, limit);
    const results = [];
    for (const action of approved) {
      try {
        results.push(await executor.execute(action.id));
      } catch (error) {
        const durableAction = runtime.actions.get(action.id) ?? action;
        const durableOutcomeUnknown = durableAction.status === "outcome_unknown";
        results.push({
          action: durableAction,
          status: durableOutcomeUnknown
            ? ("outcome_unknown" as const)
            : error instanceof BountyPilotError && error.code === "POLICY_BLOCKED"
              ? ("blocked" as const)
              : ("failed" as const),
          message: error instanceof Error ? error.message : String(error),
          evidenceCreated: 0,
          findingsCreated: 0,
        });
      }
    }
    const summary = {
      total: results.length,
      executed: results.filter((result) => result.status === "executed").length,
      failed: results.filter((result) => result.status === "failed").length,
      blocked: results.filter((result) => result.status === "blocked").length,
      outcomeUnknown: results.filter((result) => result.status === "outcome_unknown").length,
    };
    if (options.json) {
      ui.json({ jobId: options.job, limit, summary, results });
      process.exitCode = summary.failed > 0 || summary.blocked > 0 || summary.outcomeUnknown > 0 ? 1 : 0;
      return;
    }
    ui.header("actions run-approved");
    if (results.length === 0) {
      ui.status("warn", "no approved actions found for job");
      return;
    }
    ui.status(
      summary.failed > 0 || summary.blocked > 0 || summary.outcomeUnknown > 0 ? "error" : "ok",
      `${summary.executed}/${summary.total} approved actions executed`,
    );
    ui.table(
      ["status", "adapter", "type", "id", "message"],
      results.map((result) => [
        result.status,
        result.action.adapter,
        result.action.actionType,
        result.action.id,
        result.message,
      ]),
    );
    process.exitCode = summary.failed > 0 || summary.blocked > 0 || summary.outcomeUnknown > 0 ? 1 : 0;
  });

const tools = program.command("tools").description("Inspect the trusted external-tool planning registry");

tools
  .command("list")
  .option("--json", "Print machine-readable JSON")
  .description("List supported tool registry entries")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const records = createToolManager().list();
    if (options.json) {
      ui.json({ tools: records });
      return;
    }
    ui.header("tools");
    ui.table(
      ["name", "category", "version", "install", "network", "active"],
      records.map((tool) => [
        tool.name,
        tool.category,
        tool.version,
        tool.install.type,
        tool.permissions.network,
        tool.permissions.active_scanning,
      ]),
    );
  });

tools
  .command("search")
  .argument("[category]", "Optional category or search term")
  .option("--json", "Print machine-readable JSON")
  .description("Search trusted tool registry entries")
  .action((category: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const manager = createToolManager();
    const query = category?.toLowerCase();
    const records = manager
      .list()
      .filter((tool) => !query || tool.category.toLowerCase().includes(query) || tool.name.toLowerCase().includes(query));
    if (options.json) {
      ui.json({ query: category, tools: records });
      return;
    }
    ui.header("tools search");
    if (records.length === 0) {
      ui.status("warn", "no trusted tools matched");
      return;
    }
    ui.table(
      ["name", "category", "version", "source"],
      records.map((tool) => [tool.name, tool.category, tool.version, tool.source]),
    );
  });

tools
  .command("install")
  .argument("<tool>")
  .option("--json", "Print machine-readable JSON")
  .description("Create a trusted install plan")
  .action((tool: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const plan = createToolManager().createInstallPlan(tool);
    if (options.json) {
      ui.json(plan);
      process.exitCode = plan.status === "blocked" ? 1 : 0;
      return;
    }
    ui.header("tools install");
    ui.status(plan.status === "blocked" ? "blocked" : "planned", "install planning only; no installer was executed");
    ui.panel("plan", [
      ui.kv("tool", plan.tool),
      ui.kv("version", plan.version),
      ui.kv("status", plan.status),
      ui.kv("approval", plan.requiresApproval),
      ui.kv("execution", plan.execution),
    ]);
    if (plan.warnings.length > 0) {
      ui.blank();
      ui.list("warnings", plan.warnings);
    }
    ui.blank();
    ui.table(
      ["step", "manual", "command", "reason"],
      plan.steps.map((step) => [
        step.title,
        step.manual,
        step.command ? [step.command, ...(step.args ?? [])].join(" ") : "-",
        step.reason,
      ]),
    );
    process.exitCode = plan.status === "blocked" ? 1 : 0;
  });

tools
  .command("update")
  .option("--json", "Print machine-readable JSON")
  .description("Plan trusted tool updates")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const plans = createToolManager().createUpdatePlans();
    if (options.json) {
      ui.json({ plans });
      return;
    }
    ui.header("tools update");
    ui.status("planned", "update planning only; no downloads were performed");
    ui.table(
      ["tool", "status", "from", "to", "approval", "warnings"],
      plans.map((plan) => [
        plan.tool,
        plan.status,
        plan.fromVersion,
        plan.toVersion,
        plan.requiresApproval,
        plan.warnings.join("; ") || "-",
      ]),
    );
  });

tools
  .command("approve-executable")
  .argument("<tool>", "Trusted tool name")
  .requiredOption("--command <path>", "Absolute path to the reviewed local executable")
  .option("--note <text>", "Human review note")
  .option("--json", "Print machine-readable JSON")
  .description("Record a reviewed local executable pin for a human-controlled handoff; dispatch remains disabled")
  .action((tool: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ command: string; note?: string; json?: boolean }>();
    const manager = createToolManager();
    const entry = manager.get(tool);
    if (!entry) {
      throw new BountyPilotError(`Unknown trusted tool: ${tool}`, "TOOL_UNKNOWN");
    }
    const paths = ensureWorkspace(process.cwd());
    const approval = createExecutableApprovalStore(paths.integrationsDir).approve({
      integration: toolApprovalIntegrationName(entry.name),
      command: options.command,
      note: options.note,
    });
    const payload = {
      ok: true,
      tool: entry.name,
      approval,
      nextCommands: [
        `bounty tools doctor`,
        `bounty tools run ${entry.name} --target <in-scope-url> --action ${entry.actions[0]?.action_type ?? "<action>"}`,
      ],
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("tools approve-executable");
    ui.status("ok", `recorded ${entry.name} executable pin; dispatch remains disabled`);
    ui.panel("approval", [
      ui.kv("tool", entry.name),
      ui.kv("command", approval.command),
      ui.kv("sha256", approval.sha256),
      ui.kv("approved", approval.approvedAt),
    ]);
    ui.blank();
    ui.commandList("next commands", payload.nextCommands);
  });

tools
  .command("approved-executables")
  .argument("[tool]", "Optional trusted tool name")
  .option("--json", "Print machine-readable JSON")
  .description("List reviewed tool executable approvals")
  .action((tool: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const manager = createToolManager();
    const entry = tool ? manager.get(tool) : undefined;
    if (tool && !entry) {
      throw new BountyPilotError(`Unknown trusted tool: ${tool}`, "TOOL_UNKNOWN");
    }
    const paths = workspacePaths(process.cwd());
    const store = createExecutableApprovalStore(paths.integrationsDir);
    const records = entry
      ? store.list(toolApprovalIntegrationName(entry.name))
      : manager.list().flatMap((item) => store.list(toolApprovalIntegrationName(item.name)).map((record) => ({ ...record, tool: item.name })));
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ tool: entry?.name, approvals: records });
      return;
    }
    ui.header("tools approved-executables");
    if (records.length === 0) {
      ui.status("warn", "no approved tool executables found");
      return;
    }
    ui.table(
      ["tool", "command", "sha256", "approved"],
      records.map((record) => [
        "tool" in record && typeof record.tool === "string" ? record.tool : entry?.name,
        record.command,
        record.sha256.slice(0, 12),
        record.approvedAt,
      ]),
    );
  });

tools
  .command("run")
  .argument("<tool>", "Trusted tool name")
  .requiredOption("--target <url>", "In-scope target URL or host")
  .option("--action <action>", "Trusted action type from registry")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Plan a trusted external tool run through BountyPilot policy gates")
  .action(async (tool: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ target: string; action?: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const scope = runtime.scopeGuard.assertAllowed(options.target);
    const manager = createToolManager();
    const toolEntry = manager.assertAllowedForMode(tool, mode);
    const actionType = options.action ?? toolEntry.actions[0]?.action_type;
    if (!actionType) {
      throw new BountyPilotError(`Tool ${toolEntry.name} has no trusted runnable actions`, "TOOL_ACTION_NOT_FOUND");
    }
    const validation = manager.validateRunPlan({
      tool: toolEntry.name,
      mode,
      actionType,
      target: scope.url,
      labModeEnabled: runtime.config.rules.lab_mode === true,
      programRules: runtime.config.rules,
    });
    const job = runtime.jobs.create("tool-run", mode, scope.url);
    const audit = createJobAuditLogger(runtime.paths, job.id);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "tool-manager",
      actionType,
      target: scope.url,
      riskLevel: validation.riskLevel ?? (toolEntry.permissions.active_scanning ? "medium" : "low"),
      requiresApproval: validation.requiresApproval,
      requiredForCompletion: false,
      metadata: {
        tool: toolEntry.name,
        execute: false,
        planningOnly: true,
        handoffOnly: true,
      },
      status: validation.allowed ? undefined : "blocked",
    });
    audit.log({
      jobId: job.id,
      actionType,
      url: scope.url,
      adapterName: "tool-manager",
      policyDecision: validation.allowed ? (validation.requiresApproval ? "require_approval" : "allow") : "block",
      reason: validation.reasons.join("; "),
      metadata: { actionId: action.id, execute: false, warnings: validation.warnings },
    });
    const artifact = runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: "tool-manager",
      kind: "tool_output",
      sourceUrl: scope.url,
      relativePath: path.join(job.id, `${tool}-run-plan.json`),
      content: JSON.stringify(
        {
          tool: toolEntry.name,
          version: toolEntry.version,
          target: scope.url,
          mode,
          actionType,
          validation,
          install: toolEntry.install,
          permissions: toolEntry.permissions,
          safety: toolEntry.safety,
          execution: "planned_only",
        },
        null,
        2,
      ),
    });
    if (!validation.allowed) {
      runtime.jobs.finalize(job.id);
      throw new BountyPilotError(validation.reasons.join("; "), "TOOL_RUN_PLAN_BLOCKED");
    }
    const finalizedJob = runtime.jobs.finalize(job.id);
    const allowed = finalizedJob.status === "completed";
    const payload = {
      job: finalizedJob,
      action: runtime.actions.get(action.id) ?? action,
      tool: toolEntry,
      target: scope.url,
      mode,
      actionType,
      validation,
      artifact,
      execute: false,
      execution: "planned_only",
    };
    if (options.json) {
      ui.json(payload);
      return;
    }
    ui.header("tools run");
    ui.status("planned", "trusted tool run recorded for human handoff");
    ui.panel("job", [
      ui.kv("id", job.id),
      ui.kv("tool", toolEntry.name),
      ui.kv("action", actionType),
      ui.kv("target", scope.url),
      ui.kv("execute", false),
      ui.kv("artifact", artifact.path),
    ]);
  });

tools
  .command("doctor")
  .option("--json", "Print machine-readable JSON")
  .description("Check basic tool health")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const manager = createToolManager();
    const store = createExecutableApprovalStore(workspacePaths(process.cwd()).integrationsDir);
    const results = manager.doctor().map((result) => {
      const approval = store.list(toolApprovalIntegrationName(result.name))[0];
      return {
        ...result,
        approval: approval
          ? { present: true, command: approval.command, sha256: approval.sha256, approvedAt: approval.approvedAt }
          : { present: false },
      };
    });
    if (options.json) {
      ui.json({ tools: results });
      return;
    }
    ui.header("tools doctor");
    ui.table(
      ["name", "status", "pin present", "message"],
      results.map((result) => [result.name, result.status, result.approval.present, result.message]),
    );
  });

const providers = program.command("providers").description("Manage AI/API providers and local credentials");

program
  .command("tui")
  .option("--provider <id>", "Provider id to use")
  .option("--model <model>", "Override the configured provider model for this session")
  .option("--system <text>", "Override the BountyPilot chat system prompt")
  .option("--temperature <number>", "Sampling temperature", "0.2")
  .option("--max-tokens <tokens>", "Maximum response tokens", "1200")
  .option("--no-interactive", "Print a non-interactive TUI snapshot and exit")
  .option("--demo-snapshot", "Print an OpenCode-style transcript demo snapshot and exit")
  .option("--demo-session", "Open the full TUI with an OpenCode-style transcript demo")
  .description("Open the full-screen opencode-style BountyPilot terminal UI")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      provider?: string;
      model?: string;
      system?: string;
      temperature?: string;
      maxTokens?: string;
      noInteractive?: boolean;
      demoSnapshot?: boolean;
      demoSession?: boolean;
    }>();
    const { runBountyTui } = await import("./tui/run.js");
    await runBountyTui({
      cwd: process.cwd(),
      providerId: options.provider,
      model: options.model,
      systemPrompt: options.system ?? defaultChatSystemPrompt(),
      temperature: parseNumberOption(options.temperature, "temperature", 0.2, 0, 2),
      maxTokens: parsePositiveIntegerOption(options.maxTokens, "max-tokens", 1200),
      noInteractive: options.noInteractive === true,
      demoSnapshot: options.demoSnapshot === true,
      demoSession: options.demoSession === true,
    });
  });

program
  .command("chat")
  .argument("[message...]", "Message to send. Omit it to open an interactive chat session.")
  .option("--provider <id>", "Provider id to use")
  .option("--model <model>", "Override the configured provider model")
  .option("--system <text>", "Override the BountyPilot chat system prompt")
  .option("--stdin", "Read the message from stdin")
  .option("--temperature <number>", "Sampling temperature", "0.2")
  .option("--max-tokens <tokens>", "Maximum response tokens", "1200")
  .option("--json", "Print machine-readable JSON for one-shot chat")
  .description("Chat with a configured AI provider in an opencode-style terminal session")
  .action(async (messageParts: string[] | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    await runChatCommand({
      messageParts,
      options: command.opts<ChatCommandOptions>(),
    });
  });

const aiCommand = program
  .command("ai")
  .description("Use configured AI providers for safe planning and local report assistance");

aiCommand
  .command("plan")
  .requiredOption("--target <target>", "In-scope target to plan for")
  .option("--job <jobId>", "Use local job context without executing actions")
  .option("--provider <id>", "Provider id to use")
  .option("--model <model>", "Override the configured provider model")
  .option("--temperature <number>", "Sampling temperature", "0.2")
  .option("--max-tokens <tokens>", "Maximum response tokens", "1200")
  .option("--write", "Store the AI plan as a local evidence note")
  .option("--json", "Print machine-readable JSON")
  .description("Generate a scoped, dry-run-safe plan from local workspace context")
  .action(async (...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<AiPlanCommandOptions>();
    const result = await runAiPlanCommand(options);
    printAiAssistantResult("ai plan", result, options.json === true);
  });

aiCommand
  .command("report")
  .argument("<candidateId>", "Finding candidate id")
  .option("--job <jobId>", "Only use evidence from one workflow job")
  .option("--platform <platform>", "Report platform context", "hackerone")
  .option("--provider <id>", "Provider id to use")
  .option("--model <model>", "Override the configured provider model")
  .option("--temperature <number>", "Sampling temperature", "0.2")
  .option("--max-tokens <tokens>", "Maximum response tokens", "1600")
  .option("--write", "Store the AI report assistance as a local evidence note")
  .option("--json", "Print machine-readable JSON")
  .description("Generate local report prose for an evidence-backed candidate without submitting it")
  .action(async (candidateId: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<AiReportCommandOptions>();
    const result = await runAiReportCommand(candidateId, options);
    printAiAssistantResult("ai report", result, options.json === true);
  });

providers
  .command("catalog")
  .option("--json", "Print machine-readable JSON")
  .description("List built-in provider presets")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const catalog = new ProviderManager(process.cwd()).catalog();
    if (options.json) {
      ui.json({ providers: catalog });
      return;
    }
    ui.header("providers catalog");
    ui.table(
      ["id", "type", "env", "base url", "default model"],
      catalog.map((provider) => [provider.id, provider.type, provider.authEnv, provider.baseURL, provider.defaultModel]),
    );
  });

providers
  .command("connect")
  .argument("<id>", "Provider id, for example openai, openrouter, gemini, ollama, or my-provider")
  .option("--api-key <key>", "API key to store locally. Prefer --api-key-stdin for shell safety.")
  .option("--api-key-stdin", "Read the API key from stdin")
  .option("--api-key-env <name>", "Use an environment variable instead of storing the API key")
  .option("--base-url <url>", "Provider base URL, required for custom OpenAI-compatible providers")
  .option("--model <model>", "Default model id")
  .option("--models <models>", "Comma-separated model allow-list")
  .option("--openai-compatible", "Treat the provider as a custom OpenAI-compatible API")
  .option("--local", "Treat the provider as a local provider that does not require an API key")
  .option("--disabled", "Write the provider config but leave it disabled")
  .option("--timeout-ms <ms>", "Live verification timeout in milliseconds")
  .option("--json", "Print machine-readable JSON")
  .description("Store a provider credential and config, similar to opencode /connect")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      apiKey?: string;
      apiKeyStdin?: boolean;
      apiKeyEnv?: string;
      baseUrl?: string;
      model?: string;
      models?: string;
      openaiCompatible?: boolean;
      local?: boolean;
      disabled?: boolean;
      timeoutMs?: string;
      json?: boolean;
    }>();
    const apiKey = readProviderApiKeyOption(options.apiKey, options.apiKeyStdin);
    const result = new ProviderManager(process.cwd()).connect({
      id,
      apiKey,
      apiKeyEnv: options.apiKeyEnv,
      baseURL: options.baseUrl,
      model: options.model,
      models: parseProviderModelList(options.models),
      openaiCompatible: options.openaiCompatible === true,
      local: options.local === true,
      disabled: options.disabled === true,
      timeoutMs: options.timeoutMs ? parsePositiveIntegerOption(options.timeoutMs, "timeout-ms", 10_000) : undefined,
    });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("providers connect");
    ui.status(result.provider.status === "configured" ? "ok" : "warn", result.provider.message);
    printProviderSummary(result.provider);
    if (result.warnings.length > 0) {
      ui.blank();
      ui.list("warnings", result.warnings);
    }
    ui.blank();
    ui.commandList("next commands", result.nextCommands);
  });

providers
  .command("list")
  .option("--json", "Print machine-readable JSON")
  .description("List configured providers")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const records = new ProviderManager(process.cwd()).list();
    if (options.json) {
      ui.json({ providers: records });
      return;
    }
    ui.header("providers");
    if (records.length === 0) {
      ui.status("warn", "no providers configured");
      ui.commandList("next commands", [
        "bounty providers catalog",
        "echo <api-key> | bounty providers connect openai --api-key-stdin",
      ]);
      return;
    }
    ui.table(
      ["id", "enabled", "status", "auth", "model", "base url"],
      records.map((provider) => [
        provider.id,
        provider.enabled,
        provider.status,
        provider.auth.type === "env" ? `env:${provider.auth.source}` : provider.auth.type,
        provider.model,
        provider.baseURL,
      ]),
    );
  });

providers
  .command("show")
  .argument("<id>", "Provider id")
  .option("--json", "Print machine-readable JSON")
  .description("Show one provider without printing secrets")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const provider = new ProviderManager(process.cwd()).get(id);
    if (options.json) {
      ui.json(provider);
      return;
    }
    ui.header("providers show");
    ui.status(provider.status === "configured" ? "ok" : provider.status === "disabled" ? "warn" : "blocked", provider.message);
    printProviderSummary(provider);
    ui.blank();
    ui.list("models", provider.models);
  });

providers
  .command("models")
  .argument("[id]", "Optional provider id")
  .option("--json", "Print machine-readable JSON")
  .description("List configured provider models")
  .action((id: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const models = new ProviderManager(process.cwd()).models(id);
    if (options.json) {
      ui.json({ provider: id, models });
      return;
    }
    ui.header("providers models");
    if (models.length === 0) {
      ui.status("warn", "no models configured");
      return;
    }
    ui.table(
      ["provider", "selected", "model"],
      models.map((model) => [model.provider, model.selected, model.model]),
    );
  });

providers
  .command("verify")
  .argument("<id>", "Provider id")
  .option("--live", "Call the provider /models endpoint to verify the credential")
  .option("--json", "Print machine-readable JSON")
  .description("Verify local provider config and optionally perform an explicit live check")
  .action(async (id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ live?: boolean; json?: boolean }>();
    const manager = new ProviderManager(process.cwd());
    const result = options.live ? await manager.verifyLive(id) : manager.verify(id);
    if (options.json) {
      ui.json(result);
      process.exitCode = result.ok ? 0 : 1;
      return;
    }
    ui.header("providers verify");
    printProviderVerification(result);
    process.exitCode = result.ok ? 0 : 1;
  });

providers
  .command("doctor")
  .option("--json", "Print machine-readable JSON")
  .description("Check configured provider readiness")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const results = new ProviderManager(process.cwd()).doctor();
    if (options.json) {
      ui.json({ providers: results });
      return;
    }
    ui.header("providers doctor");
    if (results.length === 0) {
      ui.status("warn", "no providers configured");
      ui.commandList("next commands", [
        "bounty providers catalog",
        "echo <api-key> | bounty providers connect openai --api-key-stdin",
      ]);
      return;
    }
    ui.table(
      ["id", "status", "auth", "model", "message"],
      results.map((result) => [
        result.provider.id,
        result.provider.status,
        result.provider.auth.type === "env" ? `env:${result.provider.auth.source}` : result.provider.auth.type,
        result.provider.model,
        result.provider.message,
      ]),
    );
  });

providers
  .command("disconnect")
  .argument("<id>", "Provider id")
  .option("--json", "Print machine-readable JSON")
  .description("Remove a provider config and stored credential")
  .action((id: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const result = new ProviderManager(process.cwd()).disconnect(id);
    if (options.json) {
      ui.json(result);
      return;
    }
    ui.header("providers disconnect");
    ui.status("ok", `${result.provider} removed`);
    ui.panel("files", [
      ui.kv("config", result.configPath),
      ui.kv("auth", result.authPath),
    ]);
  });

const integrations = program.command("integrations").description("Manage adapters and MCP integrations");

integrations
  .command("list")
  .option("--json", "Print machine-readable JSON")
  .description("List known integrations")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const records = new IntegrationManager(runtime.config).list();
    if (options.json) {
      ui.json({ integrations: records });
      return;
    }
    ui.header("integrations");
    ui.table(
      ["name", "type", "enabled", "status"],
      records.map((integration) => [
        integration.name,
        integration.type,
        integration.enabled,
        integration.status,
      ]),
    );
  });

integrations
  .command("show")
  .argument("<name>", "Integration name")
  .option("--json", "Print machine-readable JSON")
  .description("Show detailed integration config, readiness, and capabilities")
  .action((name: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const integration = new IntegrationManager(runtime.config).get(name);
    if (!integration) throw new BountyPilotError(`Integration not found: ${name}`, "INTEGRATION_NOT_FOUND");
    if (options.json) {
      ui.json(integration);
      return;
    }
    ui.header("integrations show");
    ui.status(integrationStatusLabel(integration.status), integration.message ?? integration.status);
    ui.panel("integration", [
      ui.kv("name", integration.name),
      ui.kv("type", integration.type),
      ui.kv("enabled", integration.enabled),
      ui.kv("stored execution intent (dispatch disabled)", integration.config.allow_execute === true || integration.config.execution?.enabled === true),
      ui.kv("status", integration.status),
      ui.kv("config key", integration.configKey),
      ui.kv("transport", integration.config.transport),
      ui.kv("command", integration.config.command),
      ui.kv("stored cmd", integration.config.execution?.command),
      ui.kv("package", integration.config.execution?.package ?? integration.config.package),
      ui.kv("pkg version", integration.config.execution?.package_version ?? integration.config.package_version),
      ui.kv("entrypoint", integration.config.execution?.entrypoint ?? integration.config.entrypoint),
      ui.kv("url", integration.config.url ?? integration.config.endpoint),
      ui.kv("source", integration.config.source),
      ui.kv("missing", integration.missingConfig.join(", ") || "-"),
      ui.kv("errors", integration.configErrors.join("; ") || "-"),
      ui.kv("unknown", integration.unknownCapabilities.join(", ") || "-"),
    ]);
    if (integration.capabilityMetadata.length > 0) {
      ui.blank();
      ui.table(
        ["capability", "action", "risk", "modes", "produces", "mcp tools", "approval"],
        integration.capabilityMetadata.map((capability) => [
          capability.id,
          capability.actionType,
          capability.riskLevel,
          capability.allowedModes.join(","),
          capability.produces.join(","),
          capability.mcpTools?.join(",") || "-",
          capability.requiresApprovalByDefault === true,
        ]),
      );
    }
  });

integrations
  .command("capabilities")
  .argument("[name]", "Optional integration name")
  .option("--json", "Print machine-readable JSON")
  .description("List trusted adapter capabilities")
  .action((name: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const manager = new IntegrationManager(runtime.config);
    const capabilities = name
      ? manager.capabilities(name).map((capability) => ({ integration: normalizeIntegrationName(name), capability }))
      : manager
          .listDetailed()
          .flatMap((integration) =>
            integration.capabilityMetadata.map((capability) => ({
              integration: integration.name,
              capability,
            })),
          );
    if (options.json) {
      ui.json({ integration: name ? normalizeIntegrationName(name) : undefined, capabilities });
      return;
    }
    ui.header("integrations capabilities");
    if (capabilities.length === 0) {
      ui.status("warn", "no capabilities found");
      return;
    }
    ui.table(
      ["integration", "capability", "action", "risk", "modes", "approval"],
      capabilities.map((entry) => [
        entry.integration,
        entry.capability.id,
        entry.capability.actionType,
        entry.capability.riskLevel,
        entry.capability.allowedModes.join(","),
        entry.capability.requiresApprovalByDefault === true,
      ]),
    );
  });

integrations
  .command("preflight")
  .argument("<name>", "Integration name")
  .argument("<capability>", "Capability id, action type, or MCP tool")
  .option("--target <target>", "Optional in-scope target URL or host")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Run a detailed policy and readiness preflight without executing the adapter")
  .action((name: string, capability: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ target?: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const manager = new IntegrationManager(runtime.config);
    const integration = manager.get(name);
    if (!integration) throw new BountyPilotError(`Integration not found: ${name}`, "INTEGRATION_NOT_FOUND");
    const mode = modeFromOptions(options.mode);
    const target = options.target ? runtime.scopeGuard.assertAllowed(options.target).url : undefined;
    const validation = manager.validateCallPlan({
      integration: name,
      capability,
      target,
      mode,
    });
    const payload = {
      execute: false,
      dispatch: "disabled",
      integration: {
        name: integration.name,
        type: integration.type,
        enabled: integration.enabled,
        execute: false,
        executionIntent: integration.config.allow_execute === true || integration.config.execution?.enabled === true,
        dispatch: "disabled",
        status: integration.status,
        message: integration.message,
        missingConfig: integration.missingConfig,
        configErrors: integration.configErrors,
        unknownCapabilities: integration.unknownCapabilities,
      },
      request: {
        capability,
        target,
        mode,
      },
      validation,
    };
    if (options.json) {
      ui.json(payload);
    } else {
      ui.header("integrations preflight");
      ui.status(validation.ok ? (validation.requiresApproval ? "planned" : "ok") : "blocked", validation.reasons.join("; "));
      ui.panel("preflight", [
        ui.kv("execute", false),
        ui.kv("integration", integration.name),
        ui.kv("status", integration.status),
        ui.kv("capability", validation.capability?.id ?? capability),
        ui.kv("action", validation.capability?.actionType),
        ui.kv("decision", validation.decision),
        ui.kv("approval", validation.requiresApproval),
        ui.kv("target", target),
        ui.kv("mode", mode),
        ui.kv("missing", integration.missingConfig.join(", ") || "-"),
      ]);
      ui.blank();
      ui.list("reasons", validation.reasons);
    }
    process.exitCode = validation.ok ? 0 : 1;
  });

integrations
  .command("verify")
  .argument("<name>", "Integration name")
  .argument("<capability>", "Capability id, action type, or MCP tool")
  .requiredOption("--target <target>", "In-scope target URL or host used for policy and scope checks")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Run a local end-to-end readiness gate without executing the integration")
  .action((name: string, capability: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ target: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const verification = buildIntegrationVerification(runtime, {
      name,
      capability,
      target: options.target,
      mode,
    });
    if (options.json) {
      ui.json(verification);
      process.exitCode = verification.ok ? 0 : 1;
      return;
    }
    ui.header("integrations verify");
    ui.status(verification.status === "pass" ? "ok" : verification.status === "warn" ? "warn" : "blocked", verification.message);
    ui.panel("verification", [
      ui.kv("integration", verification.integration.name),
      ui.kv("capability", verification.request.capability),
      ui.kv("target", verification.request.target),
      ui.kv("mode", verification.request.mode),
      ui.kv("execute", false),
      ui.kv("status", verification.status),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      verification.checks.map((check) => [check.status, check.name, check.message]),
    );
    ui.blank();
    ui.commandList("next commands", verification.nextCommands);
    process.exitCode = verification.ok ? 0 : 1;
  });

integrations
  .command("validate")
  .argument("<name>", "Integration name")
  .argument("<capability>", "Capability id or action type")
  .option("--target <target>", "Optional in-scope target URL or host")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Validate an integration call plan without executing it")
  .action((name: string, capability: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ target?: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const target = options.target ? runtime.scopeGuard.assertAllowed(options.target).url : undefined;
    const validation = new IntegrationManager(runtime.config).validateCallPlan({
      integration: name,
      capability,
      target,
      mode,
    });
    if (options.json) {
      ui.json({ integration: normalizeIntegrationName(name), capability, target, mode, validation });
      process.exitCode = validation.ok ? 0 : 1;
      return;
    }
    ui.header("integrations validate");
    ui.status(validation.ok ? (validation.requiresApproval ? "planned" : "ok") : "blocked", validation.reasons.join("; "));
    ui.panel("plan", [
      ui.kv("integration", validation.integration ?? normalizeIntegrationName(name)),
      ui.kv("capability", validation.capability?.id ?? capability),
      ui.kv("decision", validation.decision),
      ui.kv("approval", validation.requiresApproval),
      ui.kv("target", target),
      ui.kv("mode", mode),
    ]);
    process.exitCode = validation.ok ? 0 : 1;
  });

integrations
  .command("setup")
  .argument("<name>", "Integration preset: playwright-mcp or crawl4ai")
  .option("--command <path>", "Absolute local executable path for command-based adapters such as crawl4ai")
  .option("--package <name>", "Local npm package name for package entrypoint adapters", "@playwright/mcp")
  .option("--package-version <version>", "Exact local npm package version to pin")
  .option("--entrypoint <path>", "Package-relative entrypoint", "cli.js")
  .option("--timeout-ms <ms>", "Stored timeout for a future human-controlled handoff")
  // Accepted only for backwards-compatible scripts; hidden and ignored so
  // callers cannot mistake it for an execution capability.
  .addOption(new Option("--enable-execution", "Legacy compatibility flag; external dispatch remains disabled").hideHelp())
  .option("--approve-executable", "Record the local executable hash as non-authoritative handoff metadata")
  .option("--json", "Print machine-readable JSON")
  .description("Configure a known integration preset for planning and human handoff; no external tool is downloaded or dispatched")
  .action((name: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      command?: string;
      package: string;
      packageVersion?: string;
      entrypoint: string;
      timeoutMs?: string;
      approveExecutable?: boolean;
      json?: boolean;
    }>();
    const runtime = createRuntime(rootProgramName());
    const setup = buildIntegrationSetup(runtime, name, options);
    runtime.config.integrations[setup.integration] = setup.config;
    const paths = saveProgramConfig(runtime.config, process.cwd());
    const approval = setup.approvalCommand
      ? createExecutableApprovalStore(runtime.paths.workspace.integrationsDir).approve({
          integration: setup.integration,
          command: setup.approvalCommand,
          note: `integration setup: ${setup.integration}`,
        })
      : undefined;
    const payload = {
      ok: true,
      program: runtime.config.program,
      integration: setup.integration,
      config: setup.config,
      path: paths.programFile,
      detected: setup.detected,
      approval,
      nextCommands: setup.nextCommands,
      warnings: setup.warnings,
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      return;
    }
    ui.header("integrations setup");
    ui.status(setup.warnings.length > 0 ? "warn" : "ok", `${setup.integration} setup written`);
    ui.panel("config", [
      ui.kv("program", runtime.config.program),
      ui.kv("file", paths.programFile),
      ui.kv("integration", setup.integration),
      ui.kv("dispatch", "disabled"),
      ui.kv("approval", approval ? approval.realPath : "-"),
      ui.kv("detected", setup.detected?.summary ?? "-"),
    ]);
    if (setup.warnings.length > 0) {
      ui.blank();
      ui.list("warnings", setup.warnings);
    }
    ui.blank();
    ui.commandList("next commands", setup.nextCommands);
  });

integrations
  .command("enable")
  .argument("<name>", "Integration name, for example playwright-mcp or crawl4ai")
  .option("--json", "Print machine-readable JSON")
  .description("Enable an integration in the imported program config")
  .action((name: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const key = normalizeIntegrationName(name);
    const current = integrationRecord(runtime.config.integrations[key]);
    runtime.config.integrations[key] = {
      ...current,
      enabled: true,
    };
    const paths = saveProgramConfig(runtime.config, process.cwd());
    if (options.json) {
      ui.json({ program: runtime.config.program, integration: key, config: runtime.config.integrations[key], path: paths.programFile });
      return;
    }
    ui.header("integrations enable");
    ui.status("ok", `${key} enabled`);
    ui.panel("config", [
      ui.kv("program", runtime.config.program),
      ui.kv("file", paths.programFile),
      ui.kv("integration", key),
    ]);
  });

integrations
  .command("config")
  .argument("<name>", "Integration name")
  .argument("[pairs...]", "Configuration pairs like key=value")
  .option("--json", "Print machine-readable JSON")
  .description("Set integration configuration values")
  .action((name: string, pairs: string[] = [], ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const key = normalizeIntegrationName(name);
    const current = integrationRecord(runtime.config.integrations[key]);
    for (const pair of pairs) {
      const [rawKey, ...rawValue] = pair.split("=");
      if (!rawKey || rawValue.length === 0) {
        throw new BountyPilotError(`Invalid config pair: ${pair}. Use key=value.`, "CONFIG_PAIR_INVALID");
      }
      setIntegrationConfigValue(current, rawKey, rawValue.join("="));
    }
    runtime.config.integrations[key] = current;
    const paths = saveProgramConfig(runtime.config, process.cwd());
    if (options.json) {
      ui.json({ program: runtime.config.program, integration: key, config: current, path: paths.programFile });
      return;
    }
    ui.header("integrations config");
    ui.status("ok", `${key} configured`);
    ui.panel("config", [
      ui.kv("program", runtime.config.program),
      ui.kv("file", paths.programFile),
      ui.kv("integration", key),
      ui.kv("keys", Object.keys(current).join(", ") || "-"),
    ]);
  });

integrations
  .command("approve-executable")
  .argument("<name>", "Integration name")
  .requiredOption("--command <path>", "Absolute executable path to approve")
  .option("--note <text>", "Optional local approval note")
  .option("--json", "Print machine-readable JSON")
  .description("Approve an absolute local executable path for an integration")
  .action((name: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ command: string; note?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const integration = new IntegrationManager(runtime.config).get(name);
    if (!integration) throw new BountyPilotError(`Integration not found: ${name}`, "INTEGRATION_NOT_FOUND");
    const approval = createExecutableApprovalStore(runtime.paths.workspace.integrationsDir).approve({
      integration: integration.name,
      command: options.command,
      note: options.note,
    });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ ok: true, integration: integration.name, approval });
      return;
    }
    ui.header("integrations approve-executable");
    ui.status("ok", "executable approved");
    ui.panel("approval", [
      ui.kv("integration", integration.name),
      ui.kv("path", approval.realPath),
      ui.kv("sha256", approval.sha256),
      ui.kv("store", runtime.paths.workspace.integrationsDir),
    ]);
  });

integrations
  .command("approved-executables")
  .argument("[name]", "Optional integration name")
  .option("--json", "Print machine-readable JSON")
  .description("List locally approved integration executables")
  .action((name: string | undefined, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const integration = name ? new IntegrationManager(runtime.config).get(name) : undefined;
    if (name && !integration) throw new BountyPilotError(`Integration not found: ${name}`, "INTEGRATION_NOT_FOUND");
    const approvals = createExecutableApprovalStore(runtime.paths.workspace.integrationsDir).list(integration?.name ?? name);
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json({ integration: integration?.name ?? name, approvals });
      return;
    }
    ui.header("integrations approved-executables");
    if (approvals.length === 0) {
      ui.status("warn", "no approved executables found");
      return;
    }
    ui.table(
      ["integration", "sha256", "path"],
      approvals.map((approval) => [approval.integration, approval.sha256.slice(0, 16), approval.realPath]),
    );
  });

integrations
  .command("doctor")
  .option("--json", "Print machine-readable JSON")
  .description("Check integration health")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const guidance = buildIntegrationDoctorGuidance(runtime);
    if (options.json) {
      ui.json(guidance);
      return;
    }
    ui.header("integrations doctor");
    ui.table(
      ["name", "status", "message"],
      guidance.integrations.map((entry) => [entry.name, entry.status, entry.message]),
    );
    ui.blank();
    ui.list("mcp", guidance.mcp);
    ui.blank();
    ui.commandList("next commands", guidance.nextCommands);
  });

const mcp = program.command("mcp").description("Plan MCP handoffs without automatic external execution");

mcp
  .command("plan")
  .argument("<server>", "MCP-backed integration, for example playwright-mcp")
  .argument("<tool>", "Registered MCP tool, for example browser_navigate")
  .option("--target <target>", "Optional in-scope target URL or host")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--arg <pairs...>", "Tool argument pairs like key=value")
  .option("--json", "Print machine-readable JSON")
   .description("Prepare a scope-checked, zero-execution MCP handoff with execute=false")
  .action((server: string, tool: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ target?: string; mode?: string; arg?: string[]; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const target = options.target ? runtime.scopeGuard.assertAllowed(options.target).url : undefined;
    const plan = new McpClientManager(runtime.config).prepareCallPlan({
      server,
      tool,
      mode,
      target,
      arguments: parsePairs(options.arg ?? []),
    });
    if (options.json) {
      ui.json(plan);
      process.exitCode = plan.validation.ok ? 0 : 1;
      return;
    }
    ui.header("mcp plan");
    ui.status(plan.validation.ok ? (plan.validation.requiresApproval ? "planned" : "ok") : "blocked", plan.validation.reasons.join("; "));
    ui.panel("plan", [
      ui.kv("execute", plan.execute),
      ui.kv("server", plan.server),
      ui.kv("tool", plan.tool),
      ui.kv("decision", plan.validation.decision),
      ui.kv("approval", plan.validation.requiresApproval),
      ui.kv("target", plan.target),
    ]);
    process.exitCode = plan.validation.ok ? 0 : 1;
  });

mcp
  .command("call")
  .argument("<server>", "MCP-backed integration, for example playwright-mcp")
  .argument("<tool>", "Registered MCP tool, for example browser_navigate")
  .option("--target <target>", "Optional in-scope target URL or host")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--arg <pairs...>", "Tool argument pairs like key=value")
  .option("--json", "Print machine-readable JSON")
  .description("Plan an MCP tool handoff; external MCP execution remains human-controlled")
  .action(async (server: string, tool: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ target?: string; mode?: string; arg?: string[]; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const target = options.target ? runtime.scopeGuard.assertAllowed(options.target).url : undefined;
    const job = runtime.jobs.create("mcp-call", mode, target ?? server);
    const plan = new McpClientManager(runtime.config).prepareCallPlan({
      server,
      tool,
      mode,
      target,
      arguments: parsePairs(options.arg ?? []),
    });
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: server,
      actionType: plan.validation.capability?.actionType ?? "mcp.call",
      target,
      riskLevel: plan.validation.capability?.riskLevel ?? "medium",
      requiresApproval: plan.validation.requiresApproval,
      status: plan.validation.decision === "block" ? "blocked" : undefined,
      requiredForCompletion: false,
      metadata: { tool, execute: false, planningOnly: true, handoffOnly: true },
    });
    const artifact = runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: server,
      kind: "tool_output",
      sourceUrl: target,
      relativePath: path.join(job.id, "mcp-call-plan.json"),
      content: JSON.stringify({ execute: false, server, tool, target, mode, plan, action }, null, 2),
    });
    const finalizedJob = runtime.jobs.finalize(job.id);
    const payload = { ok: plan.validation.ok, jobId: job.id, status: finalizedJob.status, pauseReason: finalizedJob.pauseReason, server, tool, target, mode, execute: false, plan, action, artifact };
    if (options.json) {
      ui.json(payload);
      if (!plan.validation.ok) process.exitCode = 1;
      return;
    }
    ui.header("mcp call");
    ui.status(plan.validation.ok ? "planned" : "blocked", plan.validation.ok ? "MCP action recorded for human handoff" : plan.validation.reasons.join("; "));
    ui.panel("job", [ui.kv("id", job.id), ui.kv("server", server), ui.kv("tool", tool), ui.kv("status", finalizedJob.status), ui.kv("execute", false)]);
    if (!plan.validation.ok) process.exitCode = 1;
  });

mcp
  .command("session")
  .argument("<server>", "MCP-backed integration, for example playwright-mcp")
  .requiredOption("--steps <path>", "JSON file containing an array of MCP session steps")
  .option("--target <target>", "Default in-scope target URL or host for steps")
  .option("--mode <mode>", "Execution mode", "safe")
  .option("--json", "Print machine-readable JSON")
  .description("Plan a multi-step MCP handoff; external MCP execution remains human-controlled")
  .action(async (server: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ steps: string; target?: string; mode?: string; json?: boolean }>();
    const runtime = createRuntime(rootProgramName());
    const mode = modeFromOptions(options.mode);
    const target = options.target ? runtime.scopeGuard.assertAllowed(options.target).url : undefined;
    const steps = readMcpSessionSteps(options.steps);
    const job = runtime.jobs.create("mcp-session", mode, target ?? server);
    const manager = new McpClientManager(runtime.config);
    const plans = steps.map((step) => manager.prepareCallPlan({
      server,
      tool: step.tool,
      mode,
      target: step.target ? runtime.scopeGuard.assertAllowed(step.target).url : target,
      arguments: step.arguments ?? {},
    }));
    const actions = plans.map((plan, index) => runtime.actions.enqueue({
      jobId: job.id,
      adapter: server,
      actionType: plan.validation.capability?.actionType ?? "mcp.call",
      target: plan.target,
      riskLevel: plan.validation.capability?.riskLevel ?? "medium",
      requiresApproval: plan.validation.requiresApproval,
      status: plan.validation.decision === "block" ? "blocked" : undefined,
      requiredForCompletion: false,
      metadata: { tool: steps[index]?.tool, step: index, execute: false, planningOnly: true, handoffOnly: true },
    }));
    const artifact = runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: server,
      kind: "tool_output",
      relativePath: path.join(job.id, "mcp-session-plan.json"),
      content: JSON.stringify({ execute: false, server, target, mode, plans, actions }, null, 2),
    });
    const finalizedJob = runtime.jobs.finalize(job.id);
    const ok = plans.every((plan) => plan.validation.ok);
    const payload = { ok, jobId: job.id, status: finalizedJob.status, pauseReason: finalizedJob.pauseReason, server, steps, target, mode, execute: false, plans, actions, artifact };
    if (options.json) {
      ui.json(payload);
      if (!ok) process.exitCode = 1;
      return;
    }
    ui.header("mcp session");
    ui.status(ok ? "planned" : "blocked", ok ? "MCP session recorded for human handoff" : "One or more MCP steps are blocked by policy");
    ui.panel("job", [ui.kv("id", job.id), ui.kv("server", server), ui.kv("steps", steps.length), ui.kv("status", finalizedJob.status), ui.kv("execute", false)]);
    if (!ok) process.exitCode = 1;
  });

const release = program.command("release").description("Check local package readiness");

release
  .command("check")
  .option("--json", "Print machine-readable JSON")
  .description("Check whether the built CLI package is ready for local release")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const result = runReleaseCheck(process.cwd());
    if (options.json) {
      ui.json(result);
    } else {
      ui.header("release check");
      printReleaseCheck(result);
    }
    process.exitCode = result.ok ? 0 : 1;
  });

release
  .command("bundle")
  .option("--output <path>", "Release artifact directory. Defaults to .bounty/release.")
  .option("--force", "Replace an existing non-empty release artifact directory")
  .option("--skip-sbom", "Skip SBOM generation for offline smoke tests")
  .option("--json", "Print machine-readable JSON")
  .description("Create local release artifacts: npm tarball, skill ZIP, optional SBOM, manifest, and SHA256SUMS")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ output?: string; force?: boolean; skipSbom?: boolean; json?: boolean }>();
    const result = buildReleaseBundle({
      cwd: process.cwd(),
      output: options.output,
      force: options.force,
      skipSbom: options.skipSbom,
    });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("release bundle");
    ui.status("ok", `wrote ${result.outputDir}`);
    ui.panel("release", [
      ui.kv("output", result.outputDir),
      ui.kv("manifest", result.manifestPath),
      ui.kv("checksums", result.checksumsPath),
      ui.kv("artifacts", result.artifacts.length),
      ui.kv("release warnings", result.releaseCheck.checks.filter((check) => check.status === "warn").length),
    ]);
    ui.blank();
    ui.table(
      ["kind", "bytes", "sha256", "name"],
      result.artifacts.map((artifact) => [artifact.kind, artifact.bytes, artifact.sha256.slice(0, 16), artifact.name]),
    );
    ui.blank();
    ui.commandList("next commands", result.nextCommands);
  });

release
  .command("verify-bundle")
  .argument("<dir>", "Release artifact directory containing release-manifest.json and SHA256SUMS.txt")
  .option("--json", "Print machine-readable JSON")
  .description("Verify local release artifacts, checksums, manifest metadata, and the standalone skill ZIP")
  .action((dir: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ json?: boolean }>();
    const result = verifyReleaseBundle({ bundleDir: dir, cwd: process.cwd() });
    if (!result.ok) {
      process.exitCode = 1;
    }
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("release verify-bundle");
    ui.status(result.ok ? "ok" : "blocked", result.ok ? "release artifacts verified" : "release artifacts failed verification");
    ui.panel("bundle", [
      ui.kv("dir", result.bundleDir),
      ui.kv("manifest", result.manifestPath),
      ui.kv("checksums", result.checksumsPath),
      ui.kv("files", `${result.files.verified}/${result.files.expected}`),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      result.checks.map((check) => [check.status, check.name, check.message]),
    );
  });

release
  .command("install-check")
  .option("--command <command>", "Installed bugbounty command to execute. Defaults to bugbounty.", "bugbounty")
  .option("--command-arg <arg>", "Argument to prepend before install-check arguments. Repeat for wrappers.", collectOption, [] as string[])
  .option("--timeout-ms <ms>", "Per-command timeout in milliseconds", "30000")
  .option("--json", "Print machine-readable JSON")
  .description("Verify an installed BountyPilot CLI can boot, validate the bundled skill, and render fresh quickstart JSON")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ command: string; commandArg: string[]; timeoutMs: string; json?: boolean }>();
    const timeoutMs = parsePositiveIntegerOption(options.timeoutMs, "timeout-ms", 30_000);
    const result = buildReleaseInstallCheck({
      cwd: process.cwd(),
      command: options.command,
      argsPrefix: options.commandArg,
      timeoutMs,
    });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      process.exitCode = result.ok ? 0 : 1;
      return;
    }
    ui.header("release install-check");
    ui.status(result.ok ? "ok" : "blocked", result.ok ? "installed CLI verified" : "installed CLI failed verification");
    ui.panel("command", [
      ui.kv("command", result.command),
      ui.kv("resolved", result.resolvedCommand),
      ui.kv("version", result.version),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      result.checks.map((check) => [check.status, check.name, check.message]),
    );
    ui.blank();
    ui.commandList("next commands", result.nextCommands);
    process.exitCode = result.ok ? 0 : 1;
  });

release
  .command("github-bootstrap")
  .argument("<repo>", "GitHub repository as OWNER/REPO, https://github.com/OWNER/REPO, or git@github.com:OWNER/REPO.git")
  .option("--branch <branch>", "Branch to push and use for raw installer URLs. Defaults to the current branch or main.")
  .option("--tag <tag>", "Release tag to push. Defaults to v<package.version>.")
  .option("--remote <kind>", "Preferred remote style: https or ssh", "https")
  .option("--gh-command <command>", "GitHub CLI command to probe", "gh")
  .option("--gh-command-arg <arg>", "Argument to prepend before gh probe arguments. Repeat for wrappers.", collectOption, [] as string[])
  .option("--timeout-ms <ms>", "Per-command timeout in milliseconds", "8000")
  .option("--write", "Write bootstrap README and scripts to disk")
  .option("--output <path>", "Output directory when --write is used. Defaults to .bounty/release/github-bootstrap.")
  .option("--json", "Print machine-readable JSON")
  .description("Generate a GitHub CLI/auth/remote bootstrap plan and idempotent publish scripts")
  .action((repo: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      branch?: string;
      tag?: string;
      remote: string;
      ghCommand: string;
      ghCommandArg: string[];
      timeoutMs: string;
      write?: boolean;
      output?: string;
      json?: boolean;
    }>();
    const timeoutMs = parsePositiveIntegerOption(options.timeoutMs, "timeout-ms", 8_000);
    const result = buildReleaseGithubBootstrap({
      cwd: process.cwd(),
      repo,
      branch: options.branch,
      tag: options.tag,
      remote: parseReleaseRemotePreference(options.remote),
      ghCommand: options.ghCommand,
      ghArgsPrefix: options.ghCommandArg,
      timeoutMs,
      write: options.write,
      output: options.output,
    });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("release github-bootstrap");
    ui.status(result.ok ? "ok" : "warn", result.ok ? "GitHub publish bootstrap is ready" : "GitHub publish bootstrap has setup steps");
    ui.panel("github", [
      ui.kv("repo", result.repo.webUrl),
      ui.kv("branch", result.branch),
      ui.kv("public branch", result.publicBranch),
      ui.kv("tag", result.tag),
      ui.kv("origin", result.remote.origin ?? "not configured"),
      ui.kv("output", result.outputDir),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      result.checks.map((check) => [check.status, check.name, check.message]),
    );
    ui.blank();
    ui.commandList("install gh", result.commands.installGh);
    ui.blank();
    ui.commandList("auth", result.commands.auth);
    ui.blank();
    ui.commandList("create repository", result.commands.createRepository);
    ui.blank();
    ui.commandList("push", result.commands.push);
    ui.blank();
    ui.commandList("tag", result.commands.tag);
    ui.blank();
    ui.commandList("verify", result.commands.verify);
    if (result.outputFiles) {
      ui.blank();
      ui.panel("files", [
        ui.kv("readme", result.outputFiles.markdown),
        ui.kv("powershell", result.outputFiles.powershell),
        ui.kv("shell", result.outputFiles.shell),
      ]);
    }
  });

release
  .command("publish-plan")
  .argument("<repo>", "GitHub repository as OWNER/REPO, https://github.com/OWNER/REPO, or git@github.com:OWNER/REPO.git")
  .option("--branch <branch>", "Branch to push and use for raw installer URLs. Defaults to the current branch or main.")
  .option("--tag <tag>", "Release tag to push. Defaults to v<package.version>.")
  .option("--remote <kind>", "Preferred remote style: https or ssh", "https")
  .option("--write", "Write the Markdown plan to disk")
  .option("--output <path>", "Markdown output path when --write is used. Defaults to .bounty/release/github-publish-plan.md.")
  .option("--json", "Print machine-readable JSON")
  .description("Generate an exact GitHub push, install, release, and artifact checklist for a public repo")
  .action((repo: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      branch?: string;
      tag?: string;
      remote: string;
      write?: boolean;
      output?: string;
      json?: boolean;
    }>();
    const result = buildReleasePublishPlan({
      cwd: process.cwd(),
      repo,
      branch: options.branch,
      tag: options.tag,
      remote: parseReleaseRemotePreference(options.remote),
      write: options.write,
      output: options.output,
    });
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(result);
      return;
    }
    ui.header("release publish-plan");
    ui.status(result.ok ? "ok" : "blocked", `${result.repo.slug} -> ${result.tag}`);
    ui.panel("github", [
      ui.kv("repo", result.repo.webUrl),
      ui.kv("branch", result.branch),
      ui.kv("public branch", result.publicBranch),
      ui.kv("tag", result.tag),
      ui.kv("origin", result.remote.origin ?? "not configured"),
      ui.kv("origin matches", result.remote.matchesTarget),
      ui.kv("output", result.outputPath),
    ]);
    ui.blank();
    ui.commandList("local verify", result.commands.localVerify);
    ui.blank();
    ui.commandList("github cli preflight", result.commands.githubCliPreflight);
    ui.blank();
    ui.commandList("create repository", result.commands.repositoryCreate);
    ui.blank();
    ui.commandList("remote setup", result.commands.remoteSetup);
    ui.blank();
    ui.commandList("post-push verify", result.commands.postPushVerify);
    ui.blank();
    ui.commandList("actions verify", result.commands.actionsVerify);
    if (result.commands.publicBranchVerify.length > 0) {
      ui.blank();
      ui.commandList("public branch verify", result.commands.publicBranchVerify);
    }
    ui.blank();
    ui.commandList("install verify", result.commands.installVerify);
    ui.blank();
    ui.commandList("release", result.commands.release);
    ui.blank();
    ui.panel("install", [
      ui.kv("npm", result.install.npm),
      ui.kv("shell", result.install.shell),
      ui.kv("powershell", result.install.powershell),
      ui.kv("shell dry-run", result.install.shellDryRun),
      ui.kv("powershell dry-run", result.install.powershellDryRun),
    ]);
    if (!result.ok) {
      process.exitCode = 1;
    }
  });

release
  .command("publish-status")
  .argument("<repo>", "GitHub repository as OWNER/REPO, https://github.com/OWNER/REPO, or git@github.com:OWNER/REPO.git")
  .option("--branch <branch>", "Branch expected to be published. Defaults to the current branch or main.")
  .option("--tag <tag>", "Release tag expected to be published. Defaults to v<package.version>.")
  .option("--remote <kind>", "Preferred remote style: https or ssh", "https")
  .option("--online", "Use git ls-remote to verify the branch/tag on origin")
  .option("--actions", "Use GitHub CLI to verify required Actions workflows completed successfully")
  .option("--write-public-plan <path>", "Write a Markdown public-readiness checklist alongside the status result")
  .option("--json", "Print machine-readable JSON")
  .description("Check whether the local checkout is ready for GitHub one-line install and release publishing")
  .action((repo: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      branch?: string;
      tag?: string;
      remote: string;
      online?: boolean;
      actions?: boolean;
      writePublicPlan?: string;
      json?: boolean;
    }>();
    const result = buildReleasePublishStatus({
      cwd: process.cwd(),
      repo,
      branch: options.branch,
      tag: options.tag,
      remote: parseReleaseRemotePreference(options.remote),
      online: options.online,
      actions: options.actions,
    });
    const publicReadinessPlanPath = options.writePublicPlan
      ? writePublicReadinessPlan(
          options.writePublicPlan,
          renderSkillReadinessPublicPlan(
            scoreSkillReadiness({
              id: BUG_BOUNTY_PILOT_SKILL_ID,
              cwd: process.cwd(),
              repo: result.repo.slug,
              branch: result.branch,
              tag: result.tag,
              remote: parseReleaseRemotePreference(options.remote),
              online: options.online,
              actions: options.actions,
            }),
          ),
        )
      : undefined;
    const payload = publicReadinessPlanPath ? { ...result, publicReadinessPlanPath } : result;
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      process.exitCode = result.ok ? 0 : 1;
      return;
    }
    ui.header("release publish-status");
    ui.status(result.ok ? "ok" : "blocked", result.ok ? `${result.repo.slug} publish preflight passed` : `${result.repo.slug} publish preflight has blockers`);
    ui.panel("github", [
      ui.kv("repo", result.repo.webUrl),
      ui.kv("branch", result.branch),
      ui.kv("public branch", result.publicBranch),
      ui.kv("tag", result.tag),
      ui.kv("origin", result.remote.origin ?? "not configured"),
      ui.kv("online", result.online),
      ui.kv("public plan", publicReadinessPlanPath ?? "not written"),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      result.checks.map((check) => [check.status, check.name, check.message]),
    );
    if (result.nextCommands.length > 0) {
      ui.blank();
      ui.commandList("next commands", result.nextCommands);
    }
    ui.blank();
    ui.commandList("install verify", result.installVerify);
    process.exitCode = result.ok ? 0 : 1;
  });

release
  .command("public-gate")
  .argument("<repo>", "GitHub repository as OWNER/REPO, https://github.com/OWNER/REPO, or git@github.com:OWNER/REPO.git")
  .option("--branch <branch>", "Branch expected to be published. Defaults to the current branch or main.")
  .option("--tag <tag>", "Release tag expected to be published. Defaults to v<package.version>.")
  .option("--remote <kind>", "Preferred remote style: https or ssh", "https")
  .option("--online", "Use git ls-remote to verify the branch/tag on origin")
  .option("--actions", "Use GitHub CLI to verify required Actions workflows completed successfully")
  .option("--gh-command <command>", "GitHub CLI command to probe when --actions is used", "gh")
  .option("--gh-command-arg <arg>", "Argument to prepend before gh probe arguments. Repeat for wrappers.", collectOption, [] as string[])
  .option("--timeout-ms <ms>", "Per-command timeout in milliseconds for GitHub probes", "8000")
  .option("--install-check", "Run installed CLI verification as part of the final gate")
  .option("--install-command <command>", "Installed bugbounty command to execute when --install-check is used", "bugbounty")
  .option("--install-command-arg <arg>", "Argument to prepend before install-check arguments. Repeat for wrappers.", collectOption, [] as string[])
  .option("--write-public-plan <path>", "Write a Markdown public-readiness checklist alongside the gate result")
  .option("--json", "Print machine-readable JSON")
  .description("Run the final public readiness gate for GitHub install, skill score, and publish status")
  .action((repo: string, ...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{
      branch?: string;
      tag?: string;
      remote: string;
      online?: boolean;
      actions?: boolean;
      ghCommand: string;
      ghCommandArg: string[];
      timeoutMs: string;
      installCheck?: boolean;
      installCommand: string;
      installCommandArg: string[];
      writePublicPlan?: string;
      json?: boolean;
    }>();
    const remote = parseReleaseRemotePreference(options.remote);
    const timeoutMs = parsePositiveIntegerOption(options.timeoutMs, "timeout-ms", 8_000);
    const publishStatus = buildReleasePublishStatus({
      cwd: process.cwd(),
      repo,
      branch: options.branch,
      tag: options.tag,
      remote,
      online: options.online,
      actions: options.actions,
      ghCommand: options.ghCommand,
      ghArgsPrefix: options.ghCommandArg,
      timeoutMs,
    });
    const skillScore = scoreSkillReadiness({
      id: BUG_BOUNTY_PILOT_SKILL_ID,
      cwd: process.cwd(),
      repo: publishStatus.repo.slug,
      branch: publishStatus.branch,
      tag: publishStatus.tag,
      remote,
      online: options.online,
      actions: options.actions,
      ghCommand: options.ghCommand,
      ghArgsPrefix: options.ghCommandArg,
      timeoutMs,
    });
    const publicReadinessPlanPath = options.writePublicPlan
      ? writePublicReadinessPlan(options.writePublicPlan, renderSkillReadinessPublicPlan(skillScore))
      : undefined;
    const installCheck = options.installCheck
      ? buildReleaseInstallCheck({
          cwd: process.cwd(),
          command: options.installCommand,
          argsPrefix: options.installCommandArg,
          timeoutMs,
        })
      : undefined;
    const checks = [
      {
        name: "release:publish-status",
        status: publishStatus.ok ? "pass" : "fail",
        message: publishStatus.ok ? "GitHub publish status passed." : "GitHub publish status has blockers.",
      },
      {
        name: "skill:score",
        status: skillScore.ultimate ? "pass" : skillScore.ok ? "warn" : "fail",
        message: `${skillScore.score}/100 ${skillScore.readiness}`,
      },
      {
        name: "skill:local",
        status: skillScore.layers.local.ultimate ? "pass" : skillScore.layers.local.ok ? "warn" : "fail",
        message: `${skillScore.layers.local.score}/100 ${skillScore.layers.local.readiness}`,
      },
      {
        name: "skill:publish",
        status: skillScore.layers.publish.ultimate ? "pass" : skillScore.layers.publish.ok ? "warn" : "fail",
        message: `${skillScore.layers.publish.score}/100 ${skillScore.layers.publish.readiness}`,
      },
      {
        name: "skill:public-readiness",
        status: skillScore.publicReadiness.ultimate ? "pass" : skillScore.publicReadiness.ok ? "warn" : "fail",
        message: `${skillScore.publicReadiness.score}/100 ${skillScore.publicReadiness.readiness}`,
      },
      {
        name: "release:install-check",
        status: installCheck ? (installCheck.ok ? "pass" : "fail") : "warn",
        message: installCheck ? (installCheck.ok ? "Installed CLI verification passed." : "Installed CLI verification failed.") : "Skipped. Re-run with --install-check.",
      },
    ];
    const payload = {
      ok: publishStatus.ok && skillScore.ultimate && (!installCheck || installCheck.ok),
      ultimate: publishStatus.ok && skillScore.ultimate && (!installCheck || installCheck.ok),
      score: skillScore.score,
      readiness: skillScore.readiness,
      repo: publishStatus.repo,
      branch: publishStatus.branch,
      publicBranch: publishStatus.publicBranch,
      tag: publishStatus.tag,
      online: publishStatus.online,
      actions: Boolean(options.actions),
      checks,
      publishStatus,
      skillScore,
      installCheck,
      publicReadinessPlanPath,
      nextCommands: uniqueCommands([...skillScore.nextSteps, ...publishStatus.nextCommands, ...publishStatus.installVerify]),
      urls: publishStatus.urls,
    };
    if (options.json || requestedJsonOutput(process.argv)) {
      ui.json(payload);
      process.exitCode = payload.ok ? 0 : 1;
      return;
    }
    ui.header("release public-gate");
    ui.status(payload.ok ? "ok" : "blocked", payload.ok ? "public release is ultimate" : "public release is not ultimate yet");
    ui.panel("public gate", [
      ui.kv("repo", payload.repo.webUrl),
      ui.kv("branch", payload.branch),
      ui.kv("tag", payload.tag),
      ui.kv("score", `${payload.score}/100`),
      ui.kv("readiness", payload.readiness),
      ui.kv("install check", installCheck ? (installCheck.ok ? "passed" : "failed") : "skipped"),
      ui.kv("public plan", publicReadinessPlanPath ?? "not written"),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      payload.checks.map((check) => [check.status, check.name, check.message]),
    );
    if (payload.nextCommands.length > 0) {
      ui.blank();
      ui.commandList("next commands", payload.nextCommands);
    }
    process.exitCode = payload.ok ? 0 : 1;
  });

const beta = program.command("beta").description("Prepare and inspect beta readiness");

beta
  .command("readiness")
  .option("--write", "Write a local beta readiness JSON report")
  .option("--output <path>", "Report path when --write is used. Defaults to .bounty/beta-readiness.json.")
  .option("--json", "Print machine-readable JSON")
  .description("Check workspace, package, and release gates for beta use")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ write?: boolean; output?: string; json?: boolean }>();
    const result = buildBetaReadiness(process.cwd(), cliPackageRoot());
    const reportPath = options.write ? resolveBetaReadinessReportPath(process.cwd(), options.output) : undefined;
    const payload = reportPath ? { ...result, reportPath } : result;
    if (reportPath) {
      writeBetaReadinessReport(payload, reportPath);
    }
    if (options.json) {
      ui.json(payload);
    } else {
      ui.header("beta readiness");
      printBetaReadiness(payload);
    }
    process.exitCode = payload.ok ? 0 : 1;
  });

beta
  .command("checklist")
  .option("--write", "Write a local beta handoff Markdown checklist")
  .option("--output <path>", "Checklist path when --write is used. Defaults to .bounty/beta-checklist.md.")
  .option("--json", "Print machine-readable JSON")
  .description("Generate a beta handoff checklist from current readiness checks")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ write?: boolean; output?: string; json?: boolean }>();
    const readiness = buildBetaReadiness(process.cwd(), cliPackageRoot());
    const outputPath = options.write ? resolveBetaChecklistPath(process.cwd(), options.output) : undefined;
    const payload = buildBetaChecklist(readiness, outputPath);
    if (outputPath) {
      writeBetaChecklist(payload, outputPath);
    }
    if (options.json) {
      ui.json(payload);
    } else {
      ui.header("beta checklist");
      printBetaChecklist(payload);
    }
    process.exitCode = payload.ok ? 0 : 1;
  });

program
  .command("doctor")
  .option("--deep", "Include release/package readiness checks")
  .option("--json", "Print machine-readable JSON for deep checks")
  .description("Check workspace and project health")
  .action((...args: unknown[]) => {
    const command = commandFromArgs(args);
    const options = command.opts<{ deep?: boolean; json?: boolean }>();
    const guidance = buildDoctorGuidance(process.cwd(), Boolean(options.deep));
    if (options.json) {
      ui.json({
        ok: guidance.ok,
        workspace: {
          found: guidance.workspaceFound,
          path: guidance.workspacePath,
          node: process.version,
        },
        programs: guidance.programs,
        checks: guidance.checks,
        nextCommands: guidance.nextCommands,
        release: guidance.release,
      });
      if (!guidance.ok) {
        process.exitCode = 1;
      }
      return;
    }
    ui.header("doctor");
    ui.status(guidance.workspaceFound ? "ok" : "warn", guidance.workspaceFound ? "workspace found" : "workspace missing");
    ui.panel("runtime", [
      ui.kv("workspace", guidance.workspacePath),
      ui.kv("node", process.version),
      ui.kv("programs", guidance.programs.count),
    ]);
    ui.blank();
    ui.table(
      ["status", "check", "message"],
      guidance.checks.map((check) => [check.status, check.name, check.message]),
    );
    if (guidance.release) {
      ui.blank();
      printReleaseCheck(guidance.release);
      if (!guidance.release.ok) {
        process.exitCode = 1;
      }
    }
    ui.blank();
    ui.commandList("next commands", guidance.nextCommands);
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  if (isCommanderHelpDisplayed(error)) {
    process.exitCode = 0;
    return;
  }
  const normalized = normalizeCliError(error);
  if (requestedJsonOutput(process.argv)) {
    ui.json({ ok: false, error: normalized });
  } else {
    ui.error(`[${normalized.code}] ${normalized.message}`);
  }
  process.exitCode = 1;
});

function printDemoLabReady(info: DemoLabServerInfo): void {
  ui.header("lab demo");
  ui.status("running", "loopback demo lab is listening");
  ui.panel("server", [
    ui.kv("target", info.target),
    ui.kv("host", info.host),
    ui.kv("port", info.port),
    ui.kv("routes", info.routes.length),
  ]);
  ui.blank();
  ui.list("routes", info.routes);
  ui.blank();
  ui.commandList("next commands", info.nextCommands);
  ui.blank();
  ui.status("warn", "press Ctrl+C to stop the local demo lab");
}

function waitForDemoLabShutdown(handle: DemoLabServerHandle): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let closing = false;
    const cleanup = () => {
      handle.server.off("close", onClose);
      handle.server.off("error", onError);
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
    };
    const settle = (error?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) {
        reject(error);
        return;
      }
      resolve();
    };
    const onClose = () => settle();
    const onError = (error: Error) => settle(error);
    const onSignal = () => {
      if (closing) return;
      closing = true;
      void handle.close().catch((error: Error) => settle(error));
    };
    handle.server.once("close", onClose);
    handle.server.once("error", onError);
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
  });
}

type LabE2eCheckStatus = "pass" | "warn" | "fail";

interface LabE2eCheck {
  name: string;
  status: LabE2eCheckStatus;
  message: string;
}

interface LabE2eGateOptions {
  live: boolean;
  components: string[];
  draftReports: boolean;
}

interface LabE2eGateResult {
  ok: boolean;
  program: string;
  target: string;
  mode: "lab-offensive";
  live: boolean;
  dryRun: boolean;
  components: string[];
  authorizationFile?: string;
  checks: LabE2eCheck[];
  scope?: ReturnType<Runtime["scopeGuard"]["test"]>;
  policy?: ReturnType<Runtime["policyGate"]["evaluate"]>;
  summary?: WorkflowSummary;
  events: WorkflowEventRecord[];
  nextCommands: string[];
}

function defaultLabE2eComponents(): string[] {
  return ["safe-checks", "js-analyzer", "triage", "planner"];
}

async function runLabE2eGate(runtime: Runtime, target: string, options: LabE2eGateOptions): Promise<LabE2eGateResult> {
  const components = options.components.length > 0 ? options.components : defaultLabE2eComponents();
  const authorizationFile = labAuthorizationFilePath(runtime.paths.programFile, runtime.config);
  const checks: LabE2eCheck[] = [
    labE2eCheck(
      "lab_mode",
      runtime.config.rules.lab_mode === true ? "pass" : "fail",
      runtime.config.rules.lab_mode === true
        ? "Program enables rules.lab_mode for local/private lab assets."
        : "Program must set rules.lab_mode=true for lab-offensive workflows.",
    ),
    labAuthorizationCheck(authorizationFile),
  ];

  let scope: LabE2eGateResult["scope"];
  try {
    scope = runtime.scopeGuard.test(target);
    checks.push(labE2eCheck("scope", scope.allowed ? "pass" : "fail", scope.reason));
  } catch (error) {
    checks.push(labE2eCheck("scope", "fail", errorReason(error)));
  }

  const policyTarget = scope?.url ?? target;
  const policy = runtime.policyGate.evaluate({
    mode: "lab-offensive",
    actionType: "lab.e2e",
    target: policyTarget,
    riskLevel: "low",
    capability: "lab_validation",
    labModeEnabled: runtime.config.rules.lab_mode === true,
  });
  checks.push(
    labE2eCheck(
      "policy",
      policy.decision === "block" ? "fail" : policy.decision === "require_approval" ? "warn" : "pass",
      policy.reason,
    ),
  );
  if (options.draftReports && !options.live) {
    checks.push(labE2eCheck("draft_reports", "warn", "--draft-reports is ignored unless --live is also set."));
  }

  const result: LabE2eGateResult = {
    ok: false,
    program: runtime.config.program,
    target: policyTarget,
    mode: "lab-offensive",
    live: options.live,
    dryRun: !options.live,
    components,
    authorizationFile,
    checks,
    scope,
    policy,
    events: [],
    nextCommands: [],
  };

  if (!labE2eChecksPassed(checks)) {
    result.nextCommands = buildLabE2eNextCommands(result);
    return result;
  }

  const summary = await new WorkflowRunner(runtime).run({
    target: policyTarget,
    mode: "lab-offensive",
    dryRun: !options.live,
    withComponents: components,
    draftReports: options.live && options.draftReports,
  });
  const displaySummary = workflowSummaryForDisplay(runtime, summary);
  checks.push(
    labE2eCheck(
      "workflow_execution",
      displaySummary.status === "completed" ? "pass" : "fail",
      options.live
        ? `Live local lab workflow finished with status ${displaySummary.status}.`
        : `Dry-run local lab workflow finished with status ${displaySummary.status}.`,
    ),
  );

  result.summary = displaySummary;
  result.events = runtime.events.list(displaySummary.jobId, 8);
  result.ok = displaySummary.status === "completed" && labE2eChecksPassed(checks);
  result.nextCommands = buildLabE2eNextCommands(result);
  return result;
}

function labAuthorizationCheck(authorizationFile: string | undefined): LabE2eCheck {
  if (!authorizationFile) {
    return labE2eCheck("authorization", "fail", "Program must configure rules.lab_authorization_file.");
  }
  try {
    const stats = statSync(authorizationFile);
    if (!stats.isFile()) {
      return labE2eCheck("authorization", "fail", `Lab authorization path is not a file: ${authorizationFile}`);
    }
    return labE2eCheck("authorization", "pass", `Authorization file present: ${authorizationFile}`);
  } catch (error) {
    return labE2eCheck("authorization", "fail", errorReason(error));
  }
}

function labE2eCheck(name: string, status: LabE2eCheckStatus, message: string): LabE2eCheck {
  return { name, status, message };
}

function labE2eChecksPassed(checks: LabE2eCheck[]): boolean {
  return checks.every((check) => check.status !== "fail");
}

function buildLabE2eNextCommands(result: LabE2eGateResult): string[] {
  const target = quoteCliArg(result.target);
  const withOption = result.components.length > 0 ? ` --with ${quoteCliArg(result.components.join(","))}` : "";
  const commands: string[] = [];

  if (!result.ok && result.checks.some((check) => check.name === "lab_mode" || check.name === "authorization")) {
    commands.push("bounty programs show");
  }
  commands.push(`bounty scope test ${target}`);

  if (result.summary) {
    commands.push(`bounty jobs show ${result.summary.jobId}`);
    commands.push(`bounty jobs timeline ${result.summary.jobId}`);
    if (result.summary.actionCounts.pending > 0) {
      commands.push(`bounty actions review --job ${result.summary.jobId}`);
    }
    if (result.summary.actionCounts.approved > 0) {
      commands.push(`bounty actions run-approved --job ${result.summary.jobId}`);
    }
  } else {
    commands.push(`bounty run ${target} --mode lab-offensive --dry-run${withOption}`);
  }

  if (result.ok && !result.live) {
    commands.push(`bounty lab e2e ${target} --live${withOption}`);
  }
  commands.push("bounty dashboard");
  return [...new Set(commands)];
}

function printLabE2eResult(result: LabE2eGateResult): void {
  ui.header("lab e2e");
  ui.status(
    result.ok ? "ok" : result.summary?.status === "failed" ? "error" : "blocked",
    result.live ? "local lab live gate finished" : "local lab dry-run gate finished",
  );
  ui.panel("lab", [
    ui.kv("program", result.program),
    ui.kv("target", result.target),
    ui.kv("mode", result.mode),
    ui.kv("run", result.live ? "live" : "dry-run"),
    ui.kv("components", result.components.join(",")),
    ui.kv("authorization", result.authorizationFile ?? "-"),
    ui.kv("job", result.summary?.jobId),
    ui.kv("status", result.summary?.status),
  ]);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    result.checks.map((check) => [check.status, check.name, check.message]),
  );

  if (result.summary) {
    ui.blank();
    ui.table(
      ["phase", "target", "status", "detail"],
      result.summary.phases.map((phase) => [phase.name, phase.target ?? "", phase.status, phase.detail]),
    );
    printWorkflowTimeline(result.events, "recent events");
  }

  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

function quoteCliArg(value: string): string {
  return /^[A-Za-z0-9._:/,-]+$/.test(value) ? value : JSON.stringify(value);
}

function errorReason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function parseComponentList(value?: string): string[] | undefined {
  if (!value) return undefined;
  const components = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (components.length === 0) {
    throw new BountyPilotError("At least one workflow component is required when --with is provided.", "WORKFLOW_COMPONENTS_EMPTY");
  }
  return components;
}

function parseProviderModelList(value?: string): string[] | undefined {
  if (!value) return undefined;
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function readProviderApiKeyOption(apiKey?: string, apiKeyStdin?: boolean): string | undefined {
  if (apiKey && apiKeyStdin) {
    throw new BountyPilotError("Use either --api-key or --api-key-stdin, not both.", "PROVIDER_AUTH_OPTION_CONFLICT");
  }
  if (!apiKeyStdin) {
    return apiKey;
  }
  const value = readFileSync(0, "utf8").trim();
  if (!value) {
    throw new BountyPilotError("No API key was read from stdin.", "PROVIDER_AUTH_STDIN_EMPTY");
  }
  return value;
}

function readChatStdin(): string {
  const value = readFileSync(0, "utf8").trim();
  if (!value) {
    throw new BountyPilotError("No chat message was read from stdin.", "PROVIDER_CHAT_STDIN_EMPTY");
  }
  return value;
}

interface ChatCommandOptions {
  provider?: string;
  model?: string;
  system?: string;
  stdin?: boolean;
  temperature?: string;
  maxTokens?: string;
  json?: boolean;
}

interface AiBaseCommandOptions {
  provider?: string;
  model?: string;
  temperature?: string;
  maxTokens?: string;
  write?: boolean;
  json?: boolean;
}

interface AiPlanCommandOptions extends AiBaseCommandOptions {
  target: string;
  job?: string;
}

interface AiReportCommandOptions extends AiBaseCommandOptions {
  job?: string;
  platform?: string;
}

interface AiAssistantResult {
  ok: true;
  kind: "plan" | "report";
  provider: string;
  model: string;
  target?: string;
  jobId?: string;
  candidateId?: string;
  findingId?: string;
  platform?: string;
  message: string;
  usage?: Record<string, unknown>;
  artifact?: EvidenceArtifact;
  review?: {
    score: number;
    readiness: ReportReadiness;
    blockers: string[];
    warnings: string[];
  };
  safety: {
    assistantOnly: true;
    execution: "none";
    approvalBypass: false;
    autoSubmit: false;
  };
  nextCommands: string[];
}

async function runChatCommand(input: {
  messageParts?: string[];
  options: ChatCommandOptions;
  defaultLaunch?: boolean;
}): Promise<void> {
  const temperature = parseNumberOption(input.options.temperature, "temperature", 0.2, 0, 2);
  const maxTokens = parsePositiveIntegerOption(input.options.maxTokens, "max-tokens", 1200);
  const client = new ProviderChatClient(new ProviderManager(process.cwd()));
  const systemPrompt = input.options.system ?? defaultChatSystemPrompt();
  const stdinMessage = input.options.stdin ? readChatStdin() : undefined;
  const inlineMessage = (input.messageParts ?? []).join(" ").trim();
  const message = stdinMessage ?? inlineMessage;

  if (input.options.json && !message) {
    throw new BountyPilotError("JSON chat mode requires a message argument or --stdin.", "PROVIDER_CHAT_MESSAGE_REQUIRED");
  }

  if (message) {
    const result = await client.complete({
      providerId: input.options.provider,
      model: input.options.model,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message },
      ],
      temperature,
      maxTokens,
    });
    const payload = {
      ok: true,
      provider: result.provider.id,
      model: result.model,
      message: result.message,
      usage: result.usage,
    };
    if (input.options.json) {
      ui.json(payload);
      return;
    }
    printChatHeader(result);
    ui.blank();
    ui.chatMessage("user", message);
    ui.blank();
    ui.chatMessage("assistant", result.message);
    ui.blank();
    ui.chatHint(["bugbounty chat", "bugbounty cockpit", "bugbounty providers doctor"]);
    return;
  }

  if (process.env.BOUNTYPILOT_LEGACY_CHAT !== "1") {
    const { runBountyTui } = await import("./tui/run.js");
    await runBountyTui({
      cwd: process.cwd(),
      providerId: input.options.provider,
      model: input.options.model,
      systemPrompt,
      temperature,
      maxTokens,
    });
    return;
  }

  try {
    await runInteractiveChat({
      client,
      providerId: input.options.provider,
      model: input.options.model,
      systemPrompt,
      temperature,
      maxTokens,
    });
  } catch (error) {
    if (isChatSetupError(error)) {
      const { renderBountyTuiSnapshot } = await import("./tui/run.js");
      process.stdout.write(`${renderBountyTuiSnapshot(process.cwd(), {
        providerId: input.options.provider,
        model: input.options.model,
        systemPrompt,
        temperature,
        maxTokens,
        noInteractive: true,
      })}\n`);
      process.exitCode = input.defaultLaunch ? 0 : 1;
      return;
    }
    throw error;
  }
}

async function runAiPlanCommand(options: AiPlanCommandOptions): Promise<AiAssistantResult> {
  const runtime = createRuntime(rootProgramName());
  const target = parseNonEmptyTextOption(options.target, "target");
  runtime.scopeGuard.assertAllowed(target);
  const job = options.job ? requireJob(runtime, options.job) : undefined;
  const providerResult = await completeAiAssistant({
    options,
    systemPrompt: aiAssistantSystemPrompt("plan"),
    userPrompt: buildAiPlanPrompt(runtime, target, job?.id),
  });
  const message = maskSecrets(providerResult.message);
  const artifact = options.write
    ? writeAiAssistantArtifact(runtime, {
        kind: "plan",
        target,
        jobId: job?.id,
        title: "AI safe plan",
        content: message,
      })
    : undefined;
  return {
    ok: true,
    kind: "plan",
    provider: providerResult.provider.id,
    model: providerResult.model,
    target,
    jobId: job?.id,
    message,
    usage: providerResult.usage,
    artifact,
    safety: aiAssistantSafety(),
    nextCommands: aiPlanNextCommands(target, job?.id, artifact?.id),
  };
}

async function runAiReportCommand(candidateId: string, options: AiReportCommandOptions): Promise<AiAssistantResult> {
  const runtime = createRuntime(rootProgramName());
  if (options.job) {
    requireJob(runtime, options.job);
  }
  const candidate = runtime.candidates.get(candidateId);
  if (!candidate) {
    throw new BountyPilotError(`Finding candidate not found: ${candidateId}`, "FINDING_CANDIDATE_NOT_FOUND");
  }
  runtime.scopeGuard.assertAllowed(candidate.url);
  const evidence = evidenceForCandidate(runtime, candidate, options.job);
  const finding = candidate.findingId
    ? runtime.findings.get(candidate.findingId) ?? candidateAsFinding(candidate, evidence)
    : candidateAsFinding(candidate, evidence);
  const manifest = runtime.evidence.buildManifestForArtifacts(evidence, {
    findingId: candidate.findingId ?? candidate.id,
    jobId: options.job,
  });
  const duplicate = new DuplicateRiskEngine().estimate(
    finding,
    runtime.findings.list().filter((item) => item.id !== finding.id && item.id !== candidate.findingId),
  );
  const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
  const platform = options.platform ?? "hackerone";
  const review = buildReportReview({ finding, evidence, manifest, duplicate, triage, platform });
  const providerResult = await completeAiAssistant({
    options,
    systemPrompt: aiAssistantSystemPrompt("report"),
    userPrompt: buildAiReportPrompt({ candidate, finding, evidence, review, platform, jobId: options.job }),
  });
  const message = maskSecrets(providerResult.message);
  const artifact = options.write
    ? writeAiAssistantArtifact(runtime, {
        kind: "report",
        target: candidate.url,
        jobId: options.job ?? candidate.jobId,
        findingId: candidate.findingId,
        candidateId: candidate.id,
        title: "AI report assistance",
        content: message,
      })
    : undefined;
  if (artifact) {
    runtime.candidates.linkEvidence(candidate.id, artifact.id);
    if (candidate.findingId) {
      runtime.findings.linkEvidencePath(candidate.findingId, artifact.path);
    }
  }
  return {
    ok: true,
    kind: "report",
    provider: providerResult.provider.id,
    model: providerResult.model,
    target: candidate.url,
    jobId: options.job ?? candidate.jobId,
    candidateId: candidate.id,
    findingId: candidate.findingId,
    platform,
    message,
    usage: providerResult.usage,
    artifact,
    review: {
      score: review.score,
      readiness: review.readiness,
      blockers: review.blockers,
      warnings: review.warnings,
    },
    safety: aiAssistantSafety(),
    nextCommands: aiReportNextCommands(candidate, options.job, review.readiness, artifact?.id),
  };
}

async function completeAiAssistant(input: {
  options: AiBaseCommandOptions;
  systemPrompt: string;
  userPrompt: string;
}) {
  const temperature = parseNumberOption(input.options.temperature, "temperature", 0.2, 0, 2);
  const maxTokens = parsePositiveIntegerOption(input.options.maxTokens, "max-tokens", 1200);
  const client = new ProviderChatClient(new ProviderManager(process.cwd()));
  return client.complete({
    providerId: input.options.provider,
    model: input.options.model,
    messages: [
      { role: "system", content: input.systemPrompt },
      { role: "user", content: input.userPrompt },
    ],
    temperature,
    maxTokens,
  });
}

function printAiAssistantResult(title: string, result: AiAssistantResult, json: boolean): void {
  if (json || requestedJsonOutput(process.argv)) {
    ui.json(result);
    return;
  }
  ui.header(title);
  ui.status("ok", `${result.provider}/${result.model}`);
  ui.panel("context", [
    ui.kv("target", result.target ?? "-"),
    ui.kv("job", result.jobId ?? "-"),
    ui.kv("candidate", result.candidateId ?? "-"),
    ui.kv("finding", result.findingId ?? "-"),
    ui.kv("artifact", result.artifact?.id ?? "-"),
    ui.kv("policy", "assistant only; no execution"),
  ]);
  if (result.review) {
    ui.blank();
    ui.panel("readiness", [
      ui.kv("score", `${result.review.score}/100`),
      ui.kv("status", result.review.readiness),
      ui.kv("blockers", result.review.blockers.length),
      ui.kv("warnings", result.review.warnings.length),
    ]);
  }
  ui.blank();
  ui.textBlock("assistant", result.message);
  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

function aiAssistantSystemPrompt(kind: "plan" | "report"): string {
  const task =
    kind === "plan"
      ? "Generate a scoped, dry-run-first bug bounty plan from local context."
      : "Generate local report assistance from existing candidate and evidence metadata.";
  return [
    "You are BountyPilot's safe AI assistant for authorized security research.",
    task,
    "You are assistant-only: do not claim to execute tools, approve actions, bypass scope, validate exploits, access accounts, exfiltrate data, or submit reports.",
    "Treat intrusive, live, scanner, fuzzer, auth, data access, and lab-offensive steps as pending human review unless the provided context explicitly says they are approved.",
    "Prefer concrete local next steps using BountyPilot CLI commands, dry-run defaults, evidence quality checks, and report-readiness blockers.",
    "Do not include secrets. If a value looks sensitive, redact it.",
    "Return concise Markdown.",
  ].join(" ");
}

function buildAiPlanPrompt(runtime: Runtime, target: string, jobId?: string): string {
  const job = jobId ? requireJob(runtime, jobId) : undefined;
  const evidence = filterEvidenceByJob(runtime.evidence.list(), jobId).slice(0, 20).map(aiEvidenceSummary);
  const context = {
    task: "safe-plan",
    target,
    program: runtime.config.program,
    rules: {
      dryRunFirst: true,
      labMode: runtime.config.rules.lab_mode === true,
    },
    job: job
      ? {
          id: job.id,
          type: job.type,
          target: job.target,
          mode: job.mode,
          status: job.status,
        }
      : undefined,
    actionSummary: job ? runtime.actions.summarize(job.id) : undefined,
    recon: runtime.recon.list({ jobId, scopeAllowed: true, limit: 20 }).map(aiReconSummary),
    candidates: runtime.candidates.list({ jobId, limit: 10 }).map(aiCandidateSummary),
    evidence,
    recentJobs: runtime.jobs.list(5).map((item) => ({
      id: item.id,
      type: item.type,
      target: item.target,
      mode: item.mode,
      status: item.status,
    })),
  };
  return [
    "Create a safe next-step plan for this authorized target.",
    "Use only the local context below. Do not invent completed execution or evidence.",
    "Include: scope/risk assumptions, best next BountyPilot commands, evidence gaps, approval gates, and report-readiness path.",
    "Context JSON:",
    JSON.stringify(maskSecretsDeep(context), null, 2),
  ].join("\n\n");
}

function buildAiReportPrompt(input: {
  candidate: FindingCandidate;
  finding: NormalizedFinding;
  evidence: EvidenceArtifact[];
  review: ReturnType<typeof buildReportReview>;
  platform: string;
  jobId?: string;
}): string {
  const context = {
    task: "report-assistance",
    platform: input.platform,
    jobId: input.jobId,
    candidate: aiCandidateSummary(input.candidate),
    finding: {
      id: input.finding.id,
      title: input.finding.title,
      url: input.finding.url,
      category: input.finding.category,
      severityEstimate: input.finding.severityEstimate,
      confidence: input.finding.confidence,
      status: input.finding.status,
      duplicateRisk: input.finding.duplicateRisk,
    },
    evidence: input.evidence.map(aiEvidenceSummary),
    review: {
      score: input.review.score,
      readiness: input.review.readiness,
      recommendation: input.review.recommendation,
      blockers: input.review.blockers,
      warnings: input.review.warnings,
      nextSteps: input.review.nextSteps,
      counts: input.review.counts,
    },
  };
  return [
    "Write local report assistance for the candidate below.",
    "Do not submit anything. Do not claim exploit validation beyond the evidence metadata. Call out blockers and missing evidence clearly.",
    "Include: title, summary, affected asset, evidence-backed reproduction outline, impact, limitations/false-positive risk, remediation, and next local commands.",
    "Context JSON:",
    JSON.stringify(maskSecretsDeep(context), null, 2),
  ].join("\n\n");
}

function writeAiAssistantArtifact(
  runtime: Runtime,
  input: {
    kind: "plan" | "report";
    target: string;
    jobId?: string;
    findingId?: string;
    candidateId?: string;
    title: string;
    content: string;
  },
): EvidenceArtifact {
  const subject = input.candidateId ?? input.findingId ?? input.jobId ?? input.target;
  return runtime.evidence.writeTextArtifact({
    findingId: input.findingId,
    jobId: input.jobId,
    adapterName: input.kind === "plan" ? "ai-plan" : "ai-report",
    kind: "evidence_note",
    sourceUrl: input.target,
    relativePath: path.join("ai", `${safeFileName(subject)}-${input.kind}-${Date.now()}.md`),
    content: [`# ${input.title}`, "", input.content.trim(), ""].join("\n"),
  });
}

function aiAssistantSafety(): AiAssistantResult["safety"] {
  return {
    assistantOnly: true,
    execution: "none",
    approvalBypass: false,
    autoSubmit: false,
  };
}

function aiPlanNextCommands(target: string, jobId?: string, artifactId?: string): string[] {
  const commands = [
    `bounty hunt recon ${target} --profile passive --dry-run`,
    `bounty hunt recon ${target} --profile web --dry-run`,
    `bounty hunt playbook headers ${target} --dry-run`,
    `bounty evidence verify${jobId ? ` --job ${jobId}` : ""}`,
    ...(jobId ? [`bounty review --job ${jobId}`, `bounty export bundle --job ${jobId}`] : []),
    ...(artifactId ? [`bounty evidence show ${artifactId}`] : []),
  ];
  return [...new Set(commands)];
}

function aiReportNextCommands(
  candidate: FindingCandidate,
  jobId: string | undefined,
  readiness: ReportReadiness,
  artifactId?: string,
): string[] {
  return [
    ...reportReviewCommands(candidate.id, jobId ?? candidate.jobId, readiness, "candidate", candidate.findingId),
    `bounty ai report ${candidate.id}${jobId ? ` --job ${jobId}` : ""} --write`,
    ...(artifactId ? [`bounty evidence show ${artifactId}`] : []),
  ];
}

function aiCandidateSummary(candidate: FindingCandidate): Record<string, unknown> {
  return {
    id: candidate.id,
    jobId: candidate.jobId,
    findingId: candidate.findingId,
    title: candidate.title,
    asset: candidate.asset,
    url: candidate.url,
    category: candidate.category,
    severityEstimate: candidate.severityEstimate,
    confidence: candidate.confidence,
    status: candidate.status,
    reportability: candidate.reportability,
    falsePositiveRisk: candidate.falsePositiveRisk,
    duplicateRisk: candidate.duplicateRisk,
    evidenceIds: candidate.evidenceIds,
    observationIds: candidate.observationIds,
    reasoningSummary: candidate.reasoningSummary,
    nextManualSteps: candidate.nextManualSteps,
  };
}

function aiEvidenceSummary(artifact: EvidenceArtifact): Record<string, unknown> {
  return {
    id: artifact.id,
    findingId: artifact.findingId,
    jobId: artifact.jobId,
    adapterName: artifact.adapterName,
    kind: artifact.kind,
    sourceUrl: artifact.sourceUrl,
    path: artifact.path,
    createdAt: artifact.createdAt,
  };
}

function aiReconSummary(observation: ReconObservation): Record<string, unknown> {
  return {
    id: observation.id,
    jobId: observation.jobId,
    kind: observation.kind,
    value: observation.value,
    sourceAdapter: observation.sourceAdapter,
    scopeAllowed: observation.scopeAllowed,
    confidence: observation.confidence,
    riskHint: observation.riskHint,
    lastSeenAt: observation.lastSeenAt,
  };
}

function shouldLaunchInteractiveTui(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY && process.env.BOUNTYPILOT_LEGACY_CHAT !== "1");
}

function isChatSetupError(error: unknown): boolean {
  return (
    error instanceof BountyPilotError &&
    [
      "PROVIDER_CHAT_NOT_CONFIGURED",
      "PROVIDER_CHAT_NOT_READY",
      "PROVIDER_CHAT_MODEL_MISSING",
      "PROVIDER_CHAT_BASE_URL_MISSING",
    ].includes(error.code)
  );
}

interface InteractiveChatOptions {
  client: ProviderChatClient;
  providerId?: string;
  model?: string;
  systemPrompt: string;
  temperature: number;
  maxTokens: number;
}

async function runInteractiveChat(options: InteractiveChatOptions): Promise<void> {
  const session = options.client.resolveSession({ providerId: options.providerId, model: options.model });
  const messages: ProviderChatMessage[] = [{ role: "system", content: options.systemPrompt }];
  printChatHeader(session);
  ui.blank();
  ui.chatMessage("system", "Ask about scoped recon, evidence quality, report readiness, and safe next steps.");
  ui.blank();
  ui.chatHint(["/help", "/clear", "/exit", "Ctrl+C"]);
  ui.blank();

  const readline = createInterface({ input: process.stdin, output: process.stdout });
  try {
    while (true) {
      const raw = await readline.question(ui.chatPrompt());
      const message = raw.trim();
      if (!message) continue;
      if (message === "/exit" || message === "/quit") {
        ui.status("ok", "chat session closed");
        return;
      }
      if (message === "/help") {
        ui.panel("commands", [
          ui.kv("/help", "show chat commands"),
          ui.kv("/clear", "reset conversation context"),
          ui.kv("/exit", "close chat"),
        ]);
        ui.blank();
        continue;
      }
      if (message === "/clear") {
        messages.splice(1);
        ui.status("ok", "conversation context cleared");
        ui.blank();
        continue;
      }

      messages.push({ role: "user", content: message });
      trimChatHistory(messages);
      ui.blank();
      ui.status("running", `${session.provider.id}/${session.model} thinking`);
      const result = await options.client.complete({
        providerId: session.provider.id,
        model: session.model,
        messages,
        temperature: options.temperature,
        maxTokens: options.maxTokens,
      });
      messages.push({ role: "assistant", content: result.message });
      ui.chatMessage("assistant", result.message);
      ui.blank();
    }
  } finally {
    readline.close();
  }
}

function trimChatHistory(messages: ProviderChatMessage[]): void {
  const maxMessages = 25;
  if (messages.length <= maxMessages) return;
  const system = messages[0]?.role === "system" ? messages[0] : undefined;
  const tail = messages.slice(-(maxMessages - (system ? 1 : 0)));
  messages.splice(0, messages.length, ...(system ? [system] : []), ...tail);
}

function printChatHeader(session: ProviderChatSession): void {
  ui.chatHeader({
    title: "bugbounty",
    subtitle: "chat",
    chips: [
      `model ${session.provider.id}/${session.model}`,
      `project ${shortProjectName(process.cwd())}`,
      "safe-mode",
    ],
  });
  ui.blank();
  ui.panel("session", [
    ui.kv("provider", session.provider.id),
    ui.kv("model", session.model),
    ui.kv("endpoint", session.provider.baseURL),
    ui.kv("policy", "advice only; no auto-execution"),
  ]);
}

function printChatSetup(reason: string): void {
  ui.chatHeader({
    title: "bugbounty",
    subtitle: "chat setup",
    chips: ["provider missing", `project ${shortProjectName(process.cwd())}`, "local-first"],
  });
  ui.blank();
  ui.status("blocked", reason);
  ui.blank();
  ui.menu("choose a provider", [
    {
      index: 1,
      label: "OpenAI",
      detail: "GPT models, cloud API",
      lines: [
        "setx OPENAI_API_KEY your-key",
        "bugbounty providers connect openai --api-key-env OPENAI_API_KEY --model gpt-4.1-mini",
      ],
    },
    {
      index: 2,
      label: "OpenRouter",
      detail: "one key for many models",
      lines: [
        "setx OPENROUTER_API_KEY your-key",
        "bugbounty providers connect openrouter --api-key-env OPENROUTER_API_KEY",
      ],
    },
    {
      index: 3,
      label: "Ollama",
      detail: "local model server",
      lines: [
        "ollama serve",
        "bugbounty providers connect ollama --local --model llama3.1",
      ],
    },
  ]);
  ui.blank();
  ui.commandList("tools", [
    "bugbounty providers catalog",
    "bugbounty providers doctor",
    "bugbounty providers list",
    "bugbounty chat",
  ]);
}

function shortProjectName(cwd: string): string {
  const name = path.basename(cwd) || cwd;
  return name.length <= 24 ? name : `${name.slice(0, 21)}...`;
}

function defaultChatSystemPrompt(): string {
  return [
    "You are BountyPilot, a local-first bug bounty assistant for authorized security research.",
    "Help the user reason about scoped recon, evidence, report readiness, and safe next steps.",
    "Do not claim to run tools, exploit targets, submit reports, bypass scope, or perform destructive actions.",
    "When discussing testing, keep it authorized, low-risk, rate-limited, and evidence-focused.",
  ].join(" ");
}

function requestedJsonOutput(argv: string[]): boolean {
  return argv.includes("--json");
}

function isMissionSemanticError(error: unknown): error is BountyPilotError {
  return error instanceof BountyPilotError && new Set([
    "MISSION_PROGRAM_MISMATCH",
    "MISSION_REQUEST_INVALID",
    "MISSION_TARGET_OUT_OF_SCOPE",
    "MISSION_POLICY_BLOCKED",
  ]).has(error.code);
}

function normalizeCliError(error: unknown): { code: string; message: string } {
  if (error instanceof BountyPilotError) {
    return { code: error.code, message: error.message };
  }
  if (error instanceof Error) {
    const maybeCode = "code" in error && typeof error.code === "string" ? error.code : "UNEXPECTED_ERROR";
    if (maybeCode === "commander.unknownOption") {
      const unknownRootCommand = firstUnknownRootCommand(process.argv);
      if (unknownRootCommand) {
        return { code: "CLI_UNKNOWN_COMMAND", message: `unknown command '${unknownRootCommand}'` };
      }
    }
    return { code: normalizeErrorCode(maybeCode), message: normalizeErrorMessage(error.message) };
  }
  return { code: "UNEXPECTED_ERROR", message: String(error) };
}

function firstUnknownRootCommand(argv: string[]): string | undefined {
  const rootCommandNames = new Set(program.commands.map((command) => command.name()));
  const args = argv.slice(2);
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]!;
    if (token === "-p" || token === "--program" || token === "--tool-registry") {
      index += 1;
      continue;
    }
    if (token.startsWith("-")) {
      continue;
    }
    return rootCommandNames.has(token) ? undefined : token;
  }
  return undefined;
}

function isCommanderHelpDisplayed(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  if ("exitCode" in error && error.exitCode === 0) {
    return true;
  }
  return "code" in error && typeof error.code === "string" && ["commander.helpDisplayed", "commander.version"].includes(error.code);
}

function normalizeErrorCode(code: string): string {
  if (!code.startsWith("commander.")) {
    return code;
  }
  const commanderCode = code.slice("commander.".length);
  const snake = commanderCode
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
  return snake ? `CLI_${snake}` : "CLI_USAGE_ERROR";
}

function normalizeErrorMessage(message: string): string {
  return message.replace(/^error:\s*/i, "");
}

interface ProgramSummaryEntry {
  name: string;
  status: "ok" | "missing" | "invalid";
  programFile: string;
  programDir: string;
  platform?: string;
  inScope?: number;
  outOfScope?: number;
  rateLimit?: string;
  message?: string;
}

interface ImportedProgramResult {
  ok: true;
  program: string;
  config: ProgramConfig;
  source: string;
  paths: ReturnType<typeof saveProgramConfig>;
  labAuthorizationFile?: string;
  strippedExecutionOptIns: Array<{ integration: string; field: string }>;
}

interface DoctorGuidanceCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

interface DoctorGuidance {
  ok: boolean;
  workspaceFound: boolean;
  workspacePath: string;
  programs: ReturnType<typeof listProgramSummaries>;
  checks: DoctorGuidanceCheck[];
  nextCommands: string[];
  release?: ReturnType<typeof runReleaseCheck>;
}

interface BetaReadinessCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

interface BetaReadinessResult {
  ok: boolean;
  status: "ready" | "needs_review" | "blocked";
  score: number;
  generatedAt: string;
  cwd: string;
  packageRoot: string;
  workspace: {
    found: boolean;
    path: string;
  };
  programs: ReturnType<typeof listProgramSummaries>;
  release: ReturnType<typeof runReleaseCheck>;
  checks: BetaReadinessCheck[];
  blockers: string[];
  warnings: string[];
  nextCommands: string[];
  reportPath?: string;
}

interface BetaChecklistResult {
  ok: boolean;
  status: BetaReadinessResult["status"];
  score: number;
  generatedAt: string;
  outputPath?: string;
  readiness: BetaReadinessResult;
  markdown: string;
  nextCommands: string[];
}

interface HuntPlanPayload {
  ok: boolean;
  profile: HuntProfile;
  target: string;
  program: string;
  planPath?: string;
  phases: string[];
  bugClasses: string[];
  validationGates: string[];
  tools: ReturnType<ToolManager["doctor"]>;
  markdown: string;
  nextCommands: string[];
}

interface HuntDoctorCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

interface ArsenalToolReadiness {
  name: string;
  category: string;
  policy: string;
  /** Compatibility field. Availability is deliberately never probed. */
  installed: false;
  status: "unverified" | "manual";
  command?: string;
  message: string;
}

interface HuntDoctorResult {
  ok: boolean;
  profile: HuntProfile;
  target?: string;
  checks: HuntDoctorCheck[];
  providers: ProviderSummary[];
  tools: ReturnType<ToolManager["doctor"]>;
  arsenal: ArsenalToolReadiness[];
  nextCommands: string[];
}

interface HuntAutopilotResult {
  ok: boolean;
  profile: HuntProfile;
  target: string;
  live: boolean;
  plan?: HuntPlanPayload;
  recon: Awaited<ReturnType<typeof runHuntRecon>>;
  summary: WorkflowSummary;
  review: ReturnType<typeof buildJobReview>;
  bundle?: ReturnType<typeof writeHandoffBundle>;
  nextCommands: string[];
}

type QuickstartStatus = "ready" | "needs_review" | "blocked";
type QuickstartCheckStatus = "pass" | "warn" | "fail";

interface QuickstartCheck {
  name: string;
  status: QuickstartCheckStatus;
  message: string;
}

interface QuickstartSection {
  id: string;
  title: string;
  status: QuickstartCheckStatus;
  summary: string;
  commands: string[];
}

interface QuickstartRunbook {
  ok: boolean;
  status: QuickstartStatus;
  generatedAt: string;
  cwd: string;
  target?: string;
  profile: {
    id: string;
    mode: string;
  };
  workspace: {
    found: boolean;
    path: string;
  };
  program?: ProgramSummaryEntry;
  checks: QuickstartCheck[];
  sections: QuickstartSection[];
  providers: {
    total: number;
    configured: number;
  };
  tools: {
    total: number;
    available: number;
  };
  arsenal: {
    total: number;
    installed: number;
  };
  results?: {
    status: ResultsBoardStatus;
    findingsIncluded: number;
    readyForDraft: number;
    reconSignals: number;
  };
  huntDoctor?: HuntDoctorResult;
  nextCommands: string[];
  markdown: string;
  outputPath?: string;
}

function buildQuickstartRunbook(input: {
  cwd: string;
  target?: string;
  profile: HuntProfile;
  programFile?: string;
  bootstrapLevel: VmBootstrapLevel;
}): QuickstartRunbook {
  const doctor = buildDoctorGuidance(input.cwd, false);
  const selectedProgram = selectQuickstartProgram(input.cwd, rootProgramName());
  const runtime = selectedProgram ? safeQuickstartRuntime(selectedProgram.name) : undefined;
  const providers = safeProviderList(input.cwd);
  const configuredProviders = providers.filter((provider) => provider.status === "configured");
  const tools = createToolManager().doctor({ mode: input.profile.mode });
  const availableTools = tools.filter((tool) => tool.status === "available");
  const arsenal = arsenalReadiness();
  const installedArsenal = arsenal.filter((tool) => tool.installed);
  const huntDoctor = runtime && input.target ? buildHuntDoctor(runtime, input.profile, input.target) : undefined;
  const results = runtime
    ? buildResultsBoard(runtime, { limit: 8, minScore: 0, readyOnly: false })
    : undefined;
  const checks = buildQuickstartChecks({
    doctor,
    selectedProgram,
    providers,
    configuredProviders,
    tools,
    availableTools,
    arsenal,
    installedArsenal,
    target: input.target,
    huntDoctor,
    results,
  });
  const status = quickstartStatus(checks);
  const sections = buildQuickstartSections({
    target: input.target,
    profile: input.profile,
    bootstrapLevel: input.bootstrapLevel,
    programFile: input.programFile,
    selectedProgram,
    workspaceFound: doctor.workspaceFound,
    providersConfigured: configuredProviders.length,
    toolsAvailable: availableTools.length,
    arsenalInstalled: installedArsenal.length,
    results,
  });
  const nextCommands = [...new Set(sections.flatMap((section) => section.commands).slice(0, 16))];
  const runbookWithoutMarkdown = {
    ok: status !== "blocked",
    status,
    generatedAt: new Date().toISOString(),
    cwd: input.cwd,
    target: input.target,
    profile: {
      id: input.profile.id,
      mode: input.profile.mode,
    },
    workspace: {
      found: doctor.workspaceFound,
      path: doctor.workspacePath,
    },
    program: selectedProgram,
    checks,
    sections,
    providers: {
      total: providers.length,
      configured: configuredProviders.length,
    },
    tools: {
      total: tools.length,
      available: availableTools.length,
    },
    arsenal: {
      total: arsenal.length,
      installed: installedArsenal.length,
    },
    results: results
      ? {
          status: results.status,
          findingsIncluded: results.totals.findingsIncluded,
          readyForDraft: results.totals.readyForDraft,
          reconSignals: results.reconSignals.total,
        }
      : undefined,
    huntDoctor,
    nextCommands,
  } satisfies Omit<QuickstartRunbook, "markdown" | "outputPath">;
  return {
    ...runbookWithoutMarkdown,
    markdown: renderQuickstartMarkdown(runbookWithoutMarkdown),
  };
}

function selectQuickstartProgram(cwd: string, requested?: string): ProgramSummaryEntry | undefined {
  const programs = listProgramSummaries(cwd).programs.filter((program) => program.status === "ok");
  if (requested) {
    return programs.find((program) => program.name === requested);
  }
  return programs.length === 1 ? programs[0] : undefined;
}

function safeQuickstartRuntime(programName: string): Runtime | undefined {
  try {
    return createRuntime(programName);
  } catch {
    return undefined;
  }
}

function buildQuickstartChecks(input: {
  doctor: DoctorGuidance;
  selectedProgram?: ProgramSummaryEntry;
  providers: ProviderSummary[];
  configuredProviders: ProviderSummary[];
  tools: ReturnType<ToolManager["doctor"]>;
  availableTools: ReturnType<ToolManager["doctor"]>;
  arsenal: ArsenalToolReadiness[];
  installedArsenal: ArsenalToolReadiness[];
  target?: string;
  huntDoctor?: HuntDoctorResult;
  results?: ResultsBoard;
}): QuickstartCheck[] {
  const invalidPrograms = input.doctor.programs.programs.filter((program) => program.status !== "ok");
  return [
    {
      name: "workspace",
      status: input.doctor.workspaceFound ? "pass" : "warn",
      message: input.doctor.workspaceFound ? `workspace found: ${input.doctor.workspacePath}` : "Run bounty init or guided import first.",
    },
    {
      name: "program",
      status: invalidPrograms.length > 0 ? "fail" : input.selectedProgram ? "pass" : "warn",
      message:
        invalidPrograms.length > 0
          ? `${invalidPrograms.length} imported program workspace(s) are invalid.`
          : input.selectedProgram
            ? `using program ${input.selectedProgram.name}`
            : "Import a program file or pass --program when multiple programs exist.",
    },
    {
      name: "providers",
      status: input.configuredProviders.length > 0 ? "pass" : "warn",
      message:
        input.configuredProviders.length > 0
          ? `${input.configuredProviders.length}/${input.providers.length} provider(s) configured.`
          : "No provider configured; local deterministic workflow still works.",
    },
    {
      name: "trusted_tools",
      status: input.availableTools.length > 0 ? "pass" : "warn",
      message: `${input.availableTools.length}/${input.tools.length} trusted tool package/registry record(s) are locally verified; no executable is probed or dispatched.`,
    },
    {
      name: "vm_arsenal",
      status: "warn",
      message: `${input.arsenal.length} VM arsenal entry or entries remain unverified/manual; BountyPilot does not probe PATH or run them.`,
    },
    {
      name: "target",
      status: input.target ? input.huntDoctor?.ok === false ? "fail" : input.huntDoctor ? "pass" : "warn" : "warn",
      message: input.target
        ? input.huntDoctor
          ? input.huntDoctor.ok
            ? "Target-specific hunt doctor checks passed."
            : "Target-specific hunt doctor found blockers."
          : "Target supplied, but no unambiguous program runtime is available for scope checks."
        : "No target supplied; commands will use <in-scope-target> placeholders.",
    },
    {
      name: "results",
      status: input.results?.totals.readyForDraft ? "pass" : input.results?.totals.findingsIncluded ? "warn" : "warn",
      message: input.results
        ? input.results.totals.readyForDraft > 0
          ? `${input.results.totals.readyForDraft} result(s) are report-ready.`
          : `${input.results.totals.findingsIncluded} result candidate(s), ${input.results.reconSignals.total} recon signal(s).`
        : "Results board will become available after a program is imported.",
    },
  ];
}

function quickstartStatus(checks: QuickstartCheck[]): QuickstartStatus {
  if (checks.some((check) => check.status === "fail")) return "blocked";
  if (checks.some((check) => check.status === "warn")) return "needs_review";
  return "ready";
}

function buildQuickstartSections(input: {
  target?: string;
  profile: HuntProfile;
  bootstrapLevel: VmBootstrapLevel;
  programFile?: string;
  selectedProgram?: ProgramSummaryEntry;
  workspaceFound: boolean;
  providersConfigured: number;
  toolsAvailable: number;
  arsenalInstalled: number;
  results?: ResultsBoard;
}): QuickstartSection[] {
  const target = input.target ?? "<in-scope-target>";
  const job = "<job-id>";
  const finding = input.results?.findings[0]?.id ?? "<finding-id>";
  const findingUrl = input.results?.findings[0]?.url ?? target;
  return [
    {
      id: "workspace",
      title: "Workspace And Scope",
      status: input.selectedProgram ? "pass" : "warn",
      summary: input.selectedProgram ? `Program ${input.selectedProgram.name} is ready.` : "Create the workspace and import authorized scope first.",
      commands: input.selectedProgram
        ? ["bounty programs list", "bounty scope list", "bounty doctor"]
        : [
            input.programFile
              ? `bounty init --guided --program-file ${quoteCommandArgument(input.programFile)}`
              : "bounty init --guided",
            "bounty import <program.yml>",
            "bounty doctor",
          ],
    },
    {
      id: "providers",
      title: "Providers",
      status: input.providersConfigured > 0 ? "pass" : "warn",
      summary: input.providersConfigured > 0 ? `${input.providersConfigured} provider(s) configured.` : "Connect an optional AI/API provider.",
      commands: [
        "bounty providers catalog",
        "echo <api-key> | bounty providers connect openai --api-key-stdin --model gpt-4.1-mini",
        "bounty providers doctor",
      ],
    },
    {
      id: "arsenal",
      title: "VM Arsenal",
      status: input.arsenalInstalled > 0 || input.toolsAvailable > 0 ? "pass" : "warn",
      summary: `${input.toolsAvailable} trusted package/registry record(s) verified; VM arsenal executables remain unverified/manual and are never PATH-probed.`,
      commands: [
        `bounty arsenal bootstrap --level ${input.bootstrapLevel} --write`,
        "bounty arsenal profiles",
        "bounty tools doctor",
        "bounty tools approved-executables",
      ],
    },
    {
      id: "hunt",
      title: "Hunt Loop",
      status: input.target && input.selectedProgram ? "pass" : "warn",
      summary: input.target ? `Plan and run the ${input.profile.id} profile against ${target}.` : "Add a target when you are ready to run the hunt loop.",
      commands: [
        `bounty scope test ${target}`,
        `bounty hunt doctor ${target} --profile ${input.profile.id}`,
        `bounty hunt plan ${target} --profile ${input.profile.id} --write`,
        `bounty hunt recon ${target} --profile web --dry-run`,
        `bounty hunt playbook xss ${target} --dry-run`,
        `bounty hunt autopilot ${target} --profile ${input.profile.id} --dry-run --write-plan`,
      ],
    },
    {
      id: "results",
      title: "Results And Reporting",
      status: input.results?.totals.readyForDraft ? "pass" : input.results?.totals.findingsIncluded ? "warn" : "warn",
      summary: input.results
        ? `${input.results.totals.findingsIncluded} result candidate(s), ${input.results.totals.readyForDraft} report-ready.`
        : "Review findings, evidence, and report readiness after recon/playbooks create candidates.",
      commands: [
        "bounty cockpit",
        "bounty results",
        `bounty review --job ${job}`,
        `bounty evidence record ${findingUrl} --finding ${finding} --job ${job}`,
        `bounty reports score ${finding} --job ${job}`,
        `bounty reports review ${finding} --job ${job} --write`,
        `bounty export bundle --job ${job}`,
      ],
    },
  ];
}

function quoteCommandArgument(value: string): string {
  return value.includes(" ") ? `"${value.replace(/"/g, '\\"')}"` : value;
}

function renderQuickstartMarkdown(input: Omit<QuickstartRunbook, "markdown" | "outputPath">): string {
  const lines = [
    "# BountyPilot Quickstart Runbook",
    "",
    `Generated: ${input.generatedAt}`,
    `Status: ${input.status}`,
    `Profile: ${input.profile.id} (${input.profile.mode})`,
    `Target: ${input.target ?? "<in-scope-target>"}`,
    `Workspace: ${input.workspace.path}`,
    "",
    "## Checks",
    "",
    "| Status | Check | Message |",
    "| --- | --- | --- |",
    ...input.checks.map((check) => `| ${check.status} | ${check.name} | ${escapeMarkdownTable(check.message)} |`),
    "",
    "## Runbook",
    "",
  ];
  for (const section of input.sections) {
    lines.push(`### ${section.title}`, "", `Status: ${section.status}`, "", section.summary, "", "```bash");
    lines.push(...section.commands);
    lines.push("```", "");
  }
  lines.push("## Next Commands", "");
  lines.push(...input.nextCommands.map((command) => `- \`${command}\``));
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function escapeMarkdownTable(value: string): string {
  return value.replace(/\|/g, "\\|");
}

function resolveQuickstartRunbookPath(cwd: string, output?: string): string {
  if (output) return path.resolve(output);
  return path.join(ensureWorkspace(cwd).root, "quickstart.md");
}

function writeQuickstartRunbook(markdown: string, outputPath: string): void {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, markdown, "utf8");
}

function importProgramIntoWorkspace(programFile: string, cwd: string): ImportedProgramResult {
  ensureWorkspace(cwd);
  const loaded = loadProgramFile(path.resolve(programFile));
  const sanitized = sanitizeImportedProgramConfig(loaded.config);
  const paths = saveProgramConfig(sanitized.config, cwd);
  const labAuthorizationFile = copyImportedLabAuthorizationFile(loaded.programFile, paths.programFile, sanitized.config);
  return {
    ok: true,
    program: sanitized.config.program,
    config: sanitized.config,
    source: loaded.programFile,
    paths,
    labAuthorizationFile,
    strippedExecutionOptIns: sanitized.strippedExecutionOptIns,
  };
}

function listProgramSummaries(cwd: string): {
  workspace: string;
  programsDir: string;
  count: number;
  programs: ProgramSummaryEntry[];
} {
  const paths = workspacePaths(cwd);
  if (!existsSync(paths.programsDir)) {
    return {
      workspace: paths.root,
      programsDir: paths.programsDir,
      count: 0,
      programs: [],
    };
  }
  const programs = readdirSync(paths.programsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry): ProgramSummaryEntry => {
      const workspace = programWorkspace(entry.name, cwd);
      if (!existsSync(workspace.programFile)) {
        return {
          name: entry.name,
          status: "missing",
          programFile: workspace.programFile,
          programDir: workspace.programDir,
          message: "program.yml missing",
        };
      }
      try {
        const loaded = loadProgramFile(workspace.programFile);
        return {
          name: entry.name,
          status: "ok",
          programFile: loaded.programFile,
          programDir: workspace.programDir,
          platform: loaded.config.platform,
          inScope: loaded.config.in_scope.length,
          outOfScope: loaded.config.out_of_scope.length,
          rateLimit: loaded.config.rules.rate_limit,
          message: loaded.config.program === entry.name ? "ready" : `config program is ${loaded.config.program}`,
        };
      } catch (error) {
        return {
          name: entry.name,
          status: "invalid",
          programFile: workspace.programFile,
          programDir: workspace.programDir,
          message: error instanceof Error ? error.message : String(error),
        };
      }
    })
    .sort((left, right) => left.name.localeCompare(right.name));
  return {
    workspace: paths.root,
    programsDir: paths.programsDir,
    count: programs.length,
    programs,
  };
}

function buildBetaReadiness(cwd: string, packageRoot: string): BetaReadinessResult {
  const paths = workspacePaths(cwd);
  const workspaceFound = existsSync(paths.root);
  const programs = listProgramSummaries(cwd);
  const invalidPrograms = programs.programs.filter((entry) => entry.status !== "ok");
  const readyPrograms = programs.programs.filter((entry) => entry.status === "ok");
  const release = runPackageReleaseCheck(packageRoot);
  const checks: BetaReadinessCheck[] = [
    {
      name: "workspace",
      status: workspaceFound ? "pass" : "warn",
      message: workspaceFound ? `workspace found: ${paths.root}` : "No .bounty workspace found in the current directory.",
    },
    {
      name: "programs",
      status: programs.count === 0 ? "warn" : invalidPrograms.length > 0 ? "fail" : "pass",
      message:
        programs.count === 0
          ? "No imported programs found for local beta practice."
          : invalidPrograms.length > 0
            ? `${invalidPrograms.length} imported program workspace(s) need attention.`
            : `${readyPrograms.length} imported program workspace(s) ready.`,
    },
    {
      name: "package_root",
      status: release.packageName ? "pass" : "fail",
      message: release.packageName ? `${release.packageName}@${release.version ?? "unknown"} at ${packageRoot}` : `No package found at ${packageRoot}.`,
    },
    {
      name: "release_check",
      status: release.ok ? "pass" : "fail",
      message: release.ok ? "Release checks passed." : `${release.checks.filter((check) => check.status === "fail").length} release check(s) failed.`,
    },
    betaReleaseSubsetCheck(release, "package_bin", ["bin.bugbounty", "compiled bin", "dist cli shebang"]),
    betaReleaseSubsetCheck(release, "examples", [
      "examples/program.yml",
      "examples/local-program.yml",
      "examples/local-lab-authorization.md",
      "examples/safe-workflow.md",
    ]),
    ...(release.checks.some((check) => check.name.startsWith("script:"))
      ? [
          betaReleaseSubsetCheck(release, "scripts", [
            "script:build",
            "script:test",
            "script:test:package-bin",
            "script:typecheck",
            "script:verify:release",
          ]),
        ]
      : []),
  ];
  const blockers = checks.filter((check) => check.status === "fail").map((check) => `${check.name}: ${check.message}`);
  const warnings = checks.filter((check) => check.status === "warn").map((check) => `${check.name}: ${check.message}`);
  const status = blockers.length > 0 ? "blocked" : warnings.length > 0 ? "needs_review" : "ready";

  return {
    ok: blockers.length === 0,
    status,
    score: betaReadinessScore(checks),
    generatedAt: new Date().toISOString(),
    cwd,
    packageRoot,
    workspace: {
      found: workspaceFound,
      path: paths.root,
    },
    programs,
    release,
    checks,
    blockers,
    warnings,
    nextCommands: betaReadinessNextCommands({
      workspaceFound,
      programs,
      invalidPrograms,
      readyPrograms,
      release,
      status,
    }),
  };
}

function betaReleaseSubsetCheck(
  release: ReturnType<typeof runReleaseCheck>,
  name: string,
  checkNames: string[],
): BetaReadinessCheck {
  const missing = checkNames.filter((checkName) => !release.checks.some((check) => check.name === checkName));
  const failed = release.checks.filter((check) => checkNames.includes(check.name) && check.status === "fail");
  const warned = release.checks.filter((check) => checkNames.includes(check.name) && check.status === "warn");
  if (missing.length > 0) {
    return { name, status: "fail", message: `Release check did not include: ${missing.join(", ")}.` };
  }
  if (failed.length > 0) {
    return { name, status: "fail", message: `${failed.length} ${name} check(s) failed.` };
  }
  if (warned.length > 0) {
    return { name, status: "warn", message: `${warned.length} ${name} check(s) emitted warnings.` };
  }
  return { name, status: "pass", message: `${checkNames.length} ${name} check(s) passed.` };
}

function betaReadinessScore(checks: BetaReadinessCheck[]): number {
  const penalty = checks.reduce((sum, check) => sum + (check.status === "fail" ? 25 : check.status === "warn" ? 7 : 0), 0);
  return Math.max(0, 100 - penalty);
}

function betaReadinessNextCommands(input: {
  workspaceFound: boolean;
  programs: ReturnType<typeof listProgramSummaries>;
  invalidPrograms: ProgramSummaryEntry[];
  readyPrograms: ProgramSummaryEntry[];
  release: ReturnType<typeof runReleaseCheck>;
  status: BetaReadinessResult["status"];
}): string[] {
  const commands: string[] = [];
  if (!input.workspaceFound) {
    commands.push("bounty init");
    commands.push("bounty import examples/program.yml");
  } else if (input.programs.count === 0) {
    commands.push("bounty programs validate examples/program.yml");
    commands.push("bounty import examples/program.yml");
  } else if (input.invalidPrograms.length > 0) {
    commands.push("bounty programs list");
    for (const entry of input.invalidPrograms.slice(0, 3)) {
      commands.push(`bounty programs validate "${entry.programFile}"`);
    }
  } else {
    commands.push("bounty dashboard");
    commands.push("bounty run <in-scope-target> --dry-run");
  }

  if (!input.release.ok) {
    commands.push("npm run build");
    commands.push("npm run typecheck");
    commands.push("npm test");
    commands.push("bounty release check --json");
  }

  commands.push("npm run verify:release");
  commands.push("npm pack --dry-run");
  commands.push("bounty lab demo --port 8080");
  commands.push("bounty beta readiness --write");
  if (input.status === "ready" && input.readyPrograms.length > 0) {
    commands.push("bounty export summary");
  }
  return [...new Set(commands)];
}

function resolveBetaReadinessReportPath(cwd: string, output?: string): string {
  if (output) {
    return path.resolve(output);
  }
  return path.join(ensureWorkspace(cwd).root, "beta-readiness.json");
}

function writeBetaReadinessReport(result: BetaReadinessResult, outputPath: string): void {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(result, null, 2), "utf8");
}

function buildBetaChecklist(readiness: BetaReadinessResult, outputPath?: string): BetaChecklistResult {
  const nextCommands = betaChecklistNextCommands(readiness);
  return {
    ok: readiness.ok,
    status: readiness.status,
    score: readiness.score,
    generatedAt: readiness.generatedAt,
    outputPath,
    readiness,
    markdown: renderBetaChecklistMarkdown(readiness, nextCommands),
    nextCommands,
  };
}

function betaChecklistNextCommands(readiness: BetaReadinessResult): string[] {
  return [
    ...new Set([
      ...readiness.nextCommands,
      "bounty beta readiness --write",
      "bounty beta checklist --write",
      "npm run verify:release",
      "npm pack --dry-run",
      "bounty lab demo --port 8080",
      "bounty lab e2e http://127.0.0.1:8080 --live --with safe-checks,js-analyzer",
    ]),
  ];
}

function renderBetaChecklistMarkdown(readiness: BetaReadinessResult, nextCommands: string[]): string {
  const lines = [
    "# BountyPilot Beta Handoff Checklist",
    "",
    `Generated: ${readiness.generatedAt}`,
    "",
    "## Readiness",
    "",
    `- Score: ${readiness.score}/100`,
    `- Status: ${readiness.status}`,
    `- Package: ${readiness.release.packageName ?? "unknown"}`,
    `- Version: ${readiness.release.version ?? "unknown"}`,
    `- Workspace: ${readiness.workspace.path}`,
    `- Imported programs: ${readiness.programs.count}`,
    `- Blockers: ${readiness.blockers.length}`,
    `- Warnings: ${readiness.warnings.length}`,
    "",
    "## Gate Checklist",
    "",
    ...readiness.checks.map((check) => `- ${check.status === "pass" ? "[x]" : "[ ]"} ${check.name}: ${check.status} - ${check.message}`),
    "",
    "## Blockers",
    "",
    ...(readiness.blockers.length > 0 ? readiness.blockers.map((blocker) => `- ${blocker}`) : ["- None"]),
    "",
    "## Warnings",
    "",
    ...(readiness.warnings.length > 0 ? readiness.warnings.map((warning) => `- ${warning}`) : ["- None"]),
    "",
    "## Required Commands",
    "",
    ...nextCommands.map((command) => `- \`${command}\``),
    "",
    "## Safety Notes",
    "",
    "- Use BountyPilot only on assets you own or are explicitly authorized to test.",
    "- Keep third-party targets in dry-run mode until scope, authorization, and human approval are verified.",
    "- External integrations stay disabled until explicitly enabled and executable approvals match.",
    "",
  ];
  return lines.join("\n");
}

function resolveBetaChecklistPath(cwd: string, output?: string): string {
  if (output) {
    return path.resolve(output);
  }
  return path.join(ensureWorkspace(cwd).root, "beta-checklist.md");
}

function writeBetaChecklist(result: BetaChecklistResult, outputPath: string): void {
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, result.markdown, "utf8");
}

function requireHuntProfile(id: string): HuntProfile {
  const profile = getHuntProfile(id.trim());
  if (!profile) {
    throw new BountyPilotError(`Unknown hunt profile: ${id}. Use one of: ${HUNT_PROFILES.map((item) => item.id).join(", ")}.`, "HUNT_PROFILE_UNKNOWN");
  }
  return profile;
}

function parseHuntReconProfile(value: string): HuntReconProfile {
  const normalized = value.trim().toLowerCase();
  if (normalized === "passive" || normalized === "web") {
    return normalized;
  }
  throw new BountyPilotError("Recon profile must be passive or web.", "HUNT_RECON_PROFILE_INVALID");
}

function parseSkillRunMode(value: string): SkillRunMode {
  const normalized = value.trim().toLowerCase();
  if (normalized === "passive" || normalized === "safe" || normalized === "deep-safe" || normalized === "lab-offensive") {
    return normalized;
  }
  throw new BountyPilotError(
    `Unsupported skill mode: ${value}. Use passive, safe, deep-safe, or lab-offensive.`,
    "SKILL_MODE_INVALID",
  );
}

function parseReleaseRemotePreference(value: string): "https" | "ssh" {
  const normalized = value.trim().toLowerCase();
  if (normalized === "https" || normalized === "ssh") {
    return normalized;
  }
  throw new BountyPilotError(`Unsupported release remote: ${value}. Use https or ssh.`, "RELEASE_REMOTE_INVALID");
}

function parseBugClass(value: string): BugClass {
  const normalized = value.trim().toLowerCase();
  if (BUG_CLASSES.includes(normalized as BugClass)) {
    return normalized as BugClass;
  }
  throw new BountyPilotError(`Unsupported bug class: ${value}. Use one of: ${BUG_CLASSES.join(", ")}.`, "HUNT_PLAYBOOK_UNKNOWN");
}

function parseCommaList(value?: string): string[] | undefined {
  const items = value?.split(",").map((item) => item.trim()).filter(Boolean);
  return items && items.length > 0 ? items : undefined;
}

function buildHuntPlanPayload(runtime: Runtime, profile: HuntProfile, target: string, output?: string): HuntPlanPayload {
  const tools = createToolManager().doctor({ mode: profile.mode });
  const nextCommands = [
    `bounty scope test ${target}`,
    `bounty hunt run ${target} --profile ${profile.id} --dry-run`,
    `bounty hunt run ${target} --profile ${profile.id} --live`,
    "bounty actions list --pending",
    "bounty dashboard",
  ];
  const planPath = output ? path.resolve(output) : undefined;
  const payloadWithoutMarkdown = {
    ok: true,
    profile,
    target,
    program: runtime.config.program,
    planPath,
    phases: profile.phases,
    bugClasses: profile.bugClasses,
    validationGates: profile.validationGates,
    tools,
    nextCommands,
  };
  return {
    ...payloadWithoutMarkdown,
    markdown: renderHuntPlanMarkdown(payloadWithoutMarkdown),
  };
}

function buildHuntDoctor(runtime: Runtime, profile: HuntProfile, target?: string): HuntDoctorResult {
  const checks: HuntDoctorCheck[] = [
    {
      name: "profile",
      status: "pass",
      message: `${profile.id} uses ${profile.mode} with ${profile.components.join(", ")}`,
    },
    {
      name: "program",
      status: "pass",
      message: runtime.config.program,
    },
  ];
  if (target) {
    try {
      const scope = runtime.scopeGuard.test(target);
      checks.push({ name: "scope", status: scope.allowed ? "pass" : "fail", message: scope.reason });
    } catch (error) {
      checks.push({ name: "scope", status: "fail", message: errorReason(error) });
    }
  } else {
    checks.push({ name: "scope", status: "warn", message: "No target was supplied; run hunt doctor <target> before live hunting." });
  }
  if (profile.mode === "lab-offensive") {
    checks.push({
      name: "lab_mode",
      status: runtime.config.rules.lab_mode === true ? "pass" : "fail",
      message: runtime.config.rules.lab_mode === true ? "program enables lab_mode" : "lab-aggressive requires rules.lab_mode=true",
    });
  }

  const providers = safeProviderList(process.cwd());
  const configuredProviders = providers.filter((provider) => provider.status === "configured");
  checks.push({
    name: "providers",
    status: configuredProviders.length > 0 ? "pass" : "warn",
    message: configuredProviders.length > 0 ? `${configuredProviders.length} provider(s) ready` : "No configured provider found; local deterministic workflow still works.",
  });

  const tools = createToolManager().doctor({ mode: profile.mode });
  const availableTools = tools.filter((tool) => tool.status === "available");
  checks.push({
    name: "trusted_tools",
    status: availableTools.length > 0 ? "pass" : "warn",
    message: `${availableTools.length}/${tools.length} trusted BountyPilot package/registry record(s) verified without executable probing`,
  });

  const arsenal = arsenalReadiness();
  const installedArsenal = arsenal.filter((tool) => tool.installed);
  checks.push({
    name: "vm_arsenal",
    status: "warn",
    message: `${arsenal.length} external arsenal entry or entries remain unverified/manual; PATH probing and dispatch are disabled`,
  });

  return {
    ok: checks.every((check) => check.status !== "fail"),
    profile,
    target,
    checks,
    providers,
    tools,
    arsenal,
    nextCommands: [
      "bounty providers catalog",
      "bounty arsenal bootstrap --write",
      "bounty arsenal profiles",
      target ? `bounty hunt plan ${target} --profile ${profile.id} --write` : "bounty hunt plan <in-scope-target> --profile recon --write",
      target ? `bounty hunt autopilot ${target} --profile ${profile.id} --dry-run --write-plan` : "bounty hunt autopilot <in-scope-target> --profile recon --dry-run --write-plan",
    ],
  };
}

function safeProviderList(cwd: string): ProviderSummary[] {
  try {
    return new ProviderManager(cwd).list();
  } catch {
    return [];
  }
}

function arsenalReadiness(): ArsenalToolReadiness[] {
  return ARSENAL_TOOLS.map((tool) => {
    const command = arsenalCommandName(tool.name);
    return {
      name: tool.name,
      category: tool.category,
      policy: tool.runPolicy,
      installed: false,
      status: command ? "unverified" : "manual",
      command,
      message: command
        ? `${command} availability is unverified; BountyPilot does not probe PATH or run the command`
        : "manual GUI/tool availability is unverified and no process is started",
    };
  });
}

function arsenalCommandName(name: string): string | undefined {
  if (name === "Burp Suite Community") return undefined;
  if (name === "nuclei-templates") return "nuclei";
  return name;
}

function isWorkflowBarrierAction(
  action: Pick<ActionRecord, "adapter" | "actionType" | "target" | "riskLevel" | "requiresApproval" | "requiredForCompletion" | "metadata">,
): boolean {
  if (
    action.adapter !== WORKFLOW_BARRIER_ADAPTER ||
    action.actionType !== WORKFLOW_BARRIER_ACTION_TYPE ||
    action.target !== undefined ||
    action.riskLevel !== "low" ||
    action.requiresApproval !== false ||
    action.requiredForCompletion !== true
  ) {
    return false;
  }
  const metadata = action.metadata;
  if (!metadata || (Object.getPrototypeOf(metadata) !== Object.prototype && Object.getPrototypeOf(metadata) !== null)) {
    return false;
  }
  const keys = Object.keys(metadata);
  return (
    keys.length === 2 &&
    Object.prototype.hasOwnProperty.call(metadata, "internal") &&
    Object.prototype.hasOwnProperty.call(metadata, "purpose") &&
    metadata.internal === true &&
    metadata.purpose === WORKFLOW_BARRIER_PURPOSE
  );
}

function renderHuntPlanMarkdown(input: Omit<HuntPlanPayload, "markdown">): string {
  const lines = [
    `# BountyPilot Hunt Plan: ${input.profile.id}`,
    "",
    `Program: ${input.program}`,
    `Target: ${input.target}`,
    `Mode: ${input.profile.mode}`,
    `Components: ${input.profile.components.join(", ")}`,
    "",
    "## Purpose",
    "",
    input.profile.purpose,
    "",
    "## Phases",
    "",
    ...input.phases.map((phase) => `- ${phase}`),
    "",
    "## Bug Classes",
    "",
    ...input.bugClasses.map((bugClass) => `- ${bugClass}`),
    "",
    "## Validation Gates",
    "",
    ...input.validationGates.map((gate) => `- ${gate}`),
    "",
    "## Tool Readiness",
    "",
    ...input.tools.map((tool) => `- ${tool.name}: ${tool.status} - ${tool.message}`),
    "",
    "## Next Commands",
    "",
    ...input.nextCommands.map((command) => `- \`${command}\``),
    "",
    "## Safety",
    "",
    "- Only test assets explicitly allowed by the imported program scope.",
    "- Keep first runs in dry-run mode until actions and target rules are reviewed.",
    "- Do not submit weak findings without evidence, impact, duplicate review, and report readiness.",
    "",
  ];
  return lines.join("\n");
}

function resolveArsenalPlanPath(cwd: string, output?: string): string {
  if (output) {
    return path.resolve(output);
  }
  return path.join(ensureWorkspace(cwd).root, "arsenal", "vm-arsenal.md");
}

function resolveArsenalBootstrapPath(cwd: string, output?: string): string {
  if (output) {
    return path.resolve(output);
  }
  return path.join(ensureWorkspace(cwd).root, "arsenal", "bootstrap.sh");
}

function resolveHuntPlanPath(runtime: Runtime, profile: HuntProfile, output?: string): string {
  if (output) {
    return path.resolve(output);
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return path.join(runtime.paths.researchDir, `hunt-plan-${profile.id}-${stamp}.md`);
}

function writePublicReadinessPlan(output: string, markdown: string): string {
  const resolved = path.resolve(process.cwd(), output);
  mkdirSync(path.dirname(resolved), { recursive: true });
  writeFileSync(resolved, markdown, "utf8");
  return resolved;
}

function uniqueCommands(commands: string[]): string[] {
  return Array.from(new Set(commands.filter((command) => command.trim().length > 0)));
}

function parseVmBootstrapLevel(value: string): VmBootstrapLevel {
  if (value === "safe" || value === "full") {
    return value;
  }
  throw new BountyPilotError(`Invalid bootstrap level: ${value}. Use safe or full.`, "ARSENAL_BOOTSTRAP_LEVEL_INVALID");
}

function huntNextCommands(summary: WorkflowSummary): string[] {
  const commands = [
    `bounty review --job ${summary.jobId}`,
    `bounty jobs timeline ${summary.jobId}`,
    `bounty evidence verify --job ${summary.jobId}`,
    "bounty dashboard",
  ];
  if (summary.actionCounts.pending > 0) {
    commands.push(`bounty actions review --job ${summary.jobId}`);
  }
  if (summary.findingsCreated > 0) {
    commands.push(`bounty reports review <finding-id> --job ${summary.jobId}`);
  }
  return commands;
}

function buildDoctorGuidance(cwd: string, deep: boolean): DoctorGuidance {
  const paths = workspacePaths(cwd);
  const workspaceFound = existsSync(paths.root);
  const programs = listProgramSummaries(cwd);
  const release = deep ? runReleaseCheck(cwd) : undefined;
  const invalidPrograms = programs.programs.filter((entry) => entry.status !== "ok");
  const readyPrograms = programs.programs.filter((entry) => entry.status === "ok");
  const checks: DoctorGuidanceCheck[] = [
    {
      name: "workspace",
      status: workspaceFound ? "pass" : "warn",
      message: workspaceFound ? "workspace found" : "run bounty init before importing a program",
    },
    {
      name: "node",
      status: "pass",
      message: process.version,
    },
    {
      name: "programs",
      status: !workspaceFound || programs.count === 0 ? "warn" : invalidPrograms.length > 0 ? "fail" : "pass",
      message:
        programs.count === 0
          ? "no imported programs found"
          : invalidPrograms.length > 0
            ? `${invalidPrograms.length} imported program workspace(s) need attention`
            : `${readyPrograms.length} imported program workspace(s) ready`,
    },
    {
      name: "release",
      status: release ? (release.ok ? "pass" : "fail") : "warn",
      message: release ? (release.ok ? "release checks passed" : "release checks failed") : "run bounty doctor --deep for package readiness",
    },
  ];
  const nextCommands = doctorNextCommands({ workspaceFound, programs, invalidPrograms, readyPrograms, release, deep });
  return {
    ok: checks.every((check) => check.status !== "fail"),
    workspaceFound,
    workspacePath: paths.root,
    programs,
    checks,
    nextCommands,
    release,
  };
}

function doctorNextCommands(input: {
  workspaceFound: boolean;
  programs: ReturnType<typeof listProgramSummaries>;
  invalidPrograms: ProgramSummaryEntry[];
  readyPrograms: ProgramSummaryEntry[];
  release?: ReturnType<typeof runReleaseCheck>;
  deep: boolean;
}): string[] {
  const commands: string[] = [];
  if (!input.workspaceFound) {
    commands.push("bounty init");
    commands.push("bounty import examples/program.yml");
    commands.push("bounty doctor");
  } else if (input.programs.count === 0) {
    commands.push("bounty programs list");
    commands.push("bounty programs validate examples/program.yml");
    commands.push("bounty import examples/program.yml");
  } else if (input.invalidPrograms.length > 0) {
    commands.push("bounty programs list");
    for (const entry of input.invalidPrograms.slice(0, 3)) {
      commands.push(`bounty programs validate "${entry.programFile}"`);
    }
  } else {
    commands.push("bounty dashboard");
    commands.push("bounty programs list");
    commands.push("bounty scope list");
    commands.push("bounty run <in-scope-target> --dry-run");
  }

  commands.push("bounty tools doctor");
  commands.push("bounty integrations doctor");
  if (!input.deep) {
    commands.push("bounty doctor --deep");
  } else if (input.release && !input.release.ok) {
    commands.push("npm run build");
    commands.push("npm test");
    commands.push("bounty release check --json");
  }
  return [...new Set(commands)];
}

function approveActionAsCliHuman(
  runtime: Runtime,
  actionId: string,
  input: { reviewerId: string; ttlMs: number; note?: string },
): ReturnType<Runtime["actionApproval"]["approveHuman"]> {
  const action = runtime.actions.get(actionId);
  if (!action) {
    throw new BountyPilotError(`Action not found: ${actionId}`, "ACTION_NOT_FOUND");
  }
  if (isHandoffOnlyAction(action)) {
    throw new BountyPilotError(
      "This action is a planning-only human handoff and cannot receive executable approval.",
      "ACTION_HANDOFF_ONLY",
    );
  }
  const challenge = runtime.actionApproval.preview(actionId);
  return runtime.actionApproval.approveHuman({
    actionId,
    reviewerId: input.reviewerId,
    expectedContextHash: challenge.contextHash,
    ttlMs: input.ttlMs,
    note: input.note,
  });
}

function recordActionReview(
  runtime: Runtime,
  action: ActionRecord,
  decision: "approved" | "blocked",
  note?: string,
): ReturnType<Runtime["reviews"]["record"]> {
  const review = runtime.reviews.record({
    actionId: action.id,
    jobId: action.jobId,
    decision,
    note,
  });
  if (action.jobId) {
    runtime.events.record({
      jobId: action.jobId,
      phase: "action-review",
      status: decision === "approved" ? "completed" : "blocked",
      message: decision === "approved" ? "Action approved by human review." : "Action blocked by human review.",
      metadata: {
        actionId: action.id,
        reviewId: review.id,
        adapter: action.adapter,
        actionType: action.actionType,
        target: action.target,
        note: review.note,
      },
    });
    createJobAuditLogger(runtime.paths, action.jobId).log({
      jobId: action.jobId,
      actionType: "action.review",
      url: action.target,
      adapterName: action.adapter,
      status: decision,
      policyDecision: decision === "approved" ? "allow" : "block",
      reason: review.note,
      metadata: {
        actionId: action.id,
        reviewId: review.id,
        actionStatus: action.status,
      },
    });
  }
  return review;
}

function auditLogPath(runtime: Runtime, jobId: string): string {
  return path.join(runtime.paths.jobsDir, jobId, "audit.log");
}

function readAuditEvents(runtime: Runtime, jobId: string): Array<Record<string, unknown>> {
  const filePath = auditLogPath(runtime, jobId);
  if (!existsSync(filePath)) {
    return [];
  }
  return readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line, index) => {
      try {
        return maskSecretsDeep(JSON.parse(line) as Record<string, unknown>);
      } catch {
        return {
          timestamp: "-",
          actionType: "audit.parse",
          status: "invalid",
          reason: `Could not parse audit log line ${index + 1}`,
        };
      }
    });
}

function requireJob(runtime: Runtime, jobId: string) {
  const job = runtime.jobs.get(jobId);
  if (!job) {
    throw new BountyPilotError(`Job not found: ${jobId}`, "JOB_NOT_FOUND");
  }
  return job;
}

function commandJobOption(command: Command, value?: string): string | undefined {
  return value ?? command.parent?.opts<{ job?: string }>().job;
}

function filterEvidenceByJob(evidence: EvidenceArtifact[], jobId?: string): EvidenceArtifact[] {
  return jobId ? evidence.filter((artifact) => artifact.jobId === jobId) : evidence;
}

function evidenceOpenTarget(runtime: Runtime, evidence: EvidenceArtifact[], findingId?: string): string {
  if (findingId && evidence[0]) {
    return path.dirname(evidence[0].path);
  }
  return runtime.paths.evidenceDir;
}

interface ManualEvidenceRecordOptions {
  finding?: string;
  job?: string;
  type: string;
  title?: string;
  file?: string;
  text?: string;
  stdin?: boolean;
}

function recordManualEvidence(runtime: Runtime, options: ManualEvidenceRecordOptions): {
  ok: true;
  mode: "manual";
  findingId?: string;
  jobId?: string;
  title: string;
  type: string;
  artifact: EvidenceArtifact;
  finding?: NormalizedFinding;
  nextCommands: string[];
} {
  const finding = options.finding ? runtime.findings.get(options.finding) : undefined;
  if (options.finding && !finding) {
    throw new BountyPilotError(`Finding not found: ${options.finding}`, "FINDING_NOT_FOUND");
  }
  const jobId = options.job;
  if (jobId) requireJob(runtime, jobId);
  const type = parseNonEmptyTextOption(options.type, "type").toLowerCase();
  const title = parseNonEmptyTextOption(options.title ?? `${type}-evidence`, "title");
  const sources = [options.file !== undefined, options.text !== undefined, options.stdin === true].filter(Boolean).length;
  if (sources > 1) {
    throw new BountyPilotError("Provide at most one manual evidence source: --file, --text, or --stdin.", "EVIDENCE_SOURCE_INVALID");
  }

  const kind = manualRecordEvidenceKind(type);
  const sourceUrl = finding?.url;
  let artifact: EvidenceArtifact;
  if (options.file) {
    artifact = runtime.evidence.copyFileArtifact({
      findingId: finding?.id,
      jobId,
      adapterName: "evidence-record",
      kind,
      sourceUrl,
      sourcePath: options.file,
      relativePath: manualEvidenceRelativePath(options.file, title, finding?.id),
    });
  } else {
    if (type === "file" || type === "screenshot") {
      throw new BountyPilotError(`Manual evidence type ${type} requires --file <path>.`, "EVIDENCE_SOURCE_INVALID");
    }
    const content = options.stdin
      ? readStdinText()
      : options.text !== undefined
        ? parseNonEmptyTextOption(options.text, "text")
        : defaultManualEvidenceContent(title, type, jobId, finding?.id);
    artifact = runtime.evidence.writeTextArtifact({
      findingId: finding?.id,
      jobId,
      adapterName: "evidence-record",
      kind,
      sourceUrl,
      relativePath: manualTextEvidenceRelativePath(title, finding?.id),
      content,
    });
  }

  const linkedFinding = finding ? runtime.findings.linkEvidencePath(finding.id, artifact.path) : undefined;
  const jobOption = jobId ? ` --job ${jobId}` : "";
  return {
    ok: true,
    mode: "manual",
    findingId: finding?.id,
    jobId,
    title,
    type,
    artifact,
    finding: linkedFinding,
    nextCommands: [
      `bounty evidence show ${artifact.id}`,
      `bounty evidence manifest${finding ? ` ${finding.id}` : ""}${jobOption}`,
      ...(finding ? [`bounty reports score ${finding.id}${jobOption}`] : []),
    ],
  };
}

function manualRecordEvidenceKind(type: string): EvidenceArtifact["kind"] {
  if (type === "note") return "evidence_note";
  if (type === "file") return "evidence_note";
  if (type === "http") return "response_sample";
  if (type === "screenshot") return "screenshot";
  return parseEvidenceKind(type);
}

function defaultManualEvidenceContent(title: string, type: string, jobId?: string, findingId?: string): string {
  return [
    `# ${title}`,
    "",
    `Type: ${type}`,
    `Finding: ${findingId ?? "-"}`,
    `Job: ${jobId ?? "-"}`,
    "",
    "Manual evidence placeholder. Replace or supplement this note with scoped, non-sensitive evidence before drafting a report.",
    "",
  ].join("\n");
}

function evidenceForCandidate(runtime: Runtime, candidate: FindingCandidate, jobId?: string): EvidenceArtifact[] {
  const byId = candidate.evidenceIds
    .map((evidenceId) => runtime.evidence.get(evidenceId))
    .filter((artifact): artifact is EvidenceArtifact => Boolean(artifact));
  const linkedFindingEvidence = candidate.findingId ? runtime.evidence.list(candidate.findingId) : [];
  const unique = new Map<string, EvidenceArtifact>();
  for (const artifact of [...byId, ...linkedFindingEvidence]) {
    unique.set(artifact.id, artifact);
  }
  return filterEvidenceByJob([...unique.values()], jobId);
}

interface ReportBundleTarget {
  subject: "candidate" | "finding";
  candidateId?: string;
  findingId?: string;
  jobId: string;
  evidence: EvidenceArtifact[];
}

function resolveReportBundleTarget(runtime: Runtime, findingOrCandidateId: string, explicitJobId?: string): ReportBundleTarget {
  const candidate = runtime.candidates.get(findingOrCandidateId);
  const finding = candidate ? undefined : runtime.findings.get(findingOrCandidateId);
  if (!candidate && !finding) {
    throw new BountyPilotError(`Finding or candidate not found: ${findingOrCandidateId}`, "FINDING_NOT_FOUND");
  }
  if (candidate?.jobId && explicitJobId && explicitJobId !== candidate.jobId) {
    throw new BountyPilotError(
      `Candidate ${candidate.id} belongs to job ${candidate.jobId}; remove --job or use that job id.`,
      "REPORT_BUNDLE_JOB_MISMATCH",
    );
  }

  const allEvidence = candidate ? evidenceForCandidate(runtime, candidate) : runtime.evidence.list(findingOrCandidateId);
  const jobId = explicitJobId ?? candidate?.jobId ?? inferSingleEvidenceJobId(allEvidence, findingOrCandidateId);
  requireJob(runtime, jobId);
  const evidence = candidate ? evidenceForCandidate(runtime, candidate, jobId) : filterEvidenceByJob(allEvidence, jobId);
  if (evidence.length === 0) {
    throw new BountyPilotError(
      `No evidence artifacts for ${findingOrCandidateId} in job ${jobId}; run reports score or evidence verify first.`,
      "REPORT_BUNDLE_EVIDENCE_NOT_FOUND",
    );
  }

  return {
    subject: candidate ? "candidate" : "finding",
    candidateId: candidate?.id,
    findingId: candidate?.findingId ?? finding?.id,
    jobId,
    evidence,
  };
}

function inferSingleEvidenceJobId(evidence: EvidenceArtifact[], subjectId: string): string {
  const jobIds = [...new Set(evidence.map((artifact) => artifact.jobId).filter((jobId): jobId is string => Boolean(jobId)))];
  if (jobIds.length === 1) {
    return jobIds[0] as string;
  }
  if (jobIds.length === 0) {
    throw new BountyPilotError(
      `Cannot infer a workflow job for ${subjectId}; pass --job <job-id> or use export bundle for a workspace-wide handoff.`,
      "REPORT_BUNDLE_JOB_REQUIRED",
    );
  }
  throw new BountyPilotError(
    `Multiple workflow jobs contain evidence for ${subjectId}; pass --job <job-id> to choose one.`,
    "REPORT_BUNDLE_JOB_AMBIGUOUS",
  );
}

function candidateNextCommands(candidate: FindingCandidate, jobId?: string): string[] {
  const selectedJobId = jobId ?? candidate.jobId;
  const jobOption = selectedJobId ? ` --job ${selectedJobId}` : "";
  const commands = [
    `bounty findings candidate ${candidate.id}`,
    `bounty reports score ${candidate.id}${jobOption}`,
    ...(selectedJobId ? [`bounty reports bundle ${candidate.id}${jobOption}`] : []),
  ];
  if (!candidate.findingId) {
    commands.push(`bounty findings promote-candidate ${candidate.id}`);
  } else {
    commands.push(`bounty findings show ${candidate.findingId}`);
    commands.push(`bounty reports score ${candidate.findingId}${jobOption}`);
    if (candidate.reportability === "ready_for_draft") {
      commands.push(`bounty report ${candidate.findingId} --platform hackerone`);
      commands.push(`bounty report ${candidate.findingId} --platform bugcrowd`);
    }
  }
  return [...new Set(commands)];
}

function promoteCandidate(runtime: Runtime, candidateId: string, status: FindingStatus): {
  ok: true;
  created: boolean;
  candidate: FindingCandidate;
  finding: NormalizedFinding;
  evidence: EvidenceArtifact[];
  nextCommands: string[];
} {
  const candidate = runtime.candidates.get(candidateId);
  if (!candidate) throw new BountyPilotError(`Finding candidate not found: ${candidateId}`, "FINDING_CANDIDATE_NOT_FOUND");
  runtime.scopeGuard.assertAllowed(candidate.url);
  const evidence = evidenceForCandidate(runtime, candidate);
  if (evidence.length === 0) {
    throw new BountyPilotError(
      `Finding candidate ${candidateId} has no stored evidence artifacts to promote.`,
      "FINDING_CANDIDATE_EVIDENCE_MISSING",
    );
  }
  const existing = candidate.findingId ? runtime.findings.get(candidate.findingId) : undefined;
  if (existing) {
    for (const artifact of evidence) {
      runtime.evidence.linkToFinding(artifact.id, existing.id);
      runtime.findings.linkEvidencePath(existing.id, artifact.path);
    }
    const linked = runtime.candidates.linkFinding(candidate.id, existing.id) ?? candidate;
    return {
      ok: true,
      created: false,
      candidate: linked,
      finding: runtime.findings.get(existing.id) ?? existing,
      evidence,
      nextCommands: candidateNextCommands(linked),
    };
  }

  const duplicate = new DuplicateRiskEngine().estimate(
    {
      title: candidate.title,
      asset: candidate.asset,
      url: candidate.url,
      category: candidate.category,
    },
    runtime.findings.list(),
  );
  const finding = runtime.findings.create({
    title: candidate.title,
    asset: candidate.asset,
    url: candidate.url,
    category: candidate.category,
    severityEstimate: candidate.severityEstimate,
    confidence: candidate.confidence,
    status,
    evidencePaths: evidence.map((artifact) => artifact.path),
    remediation: undefined,
    duplicateRisk: duplicate.risk,
    reportabilityScore: candidateBaselineScore(candidate),
  });
  for (const artifact of evidence) {
    runtime.evidence.linkToFinding(artifact.id, finding.id);
  }
  const linked = runtime.candidates.linkFinding(candidate.id, finding.id) ?? { ...candidate, findingId: finding.id, status: "promoted" as const };
  return {
    ok: true,
    created: true,
    candidate: linked,
    finding,
    evidence,
    nextCommands: candidateNextCommands(linked),
  };
}

function candidateAsFinding(candidate: FindingCandidate, evidence: EvidenceArtifact[]): NormalizedFinding {
  return {
    id: candidate.id,
    title: candidate.title,
    asset: candidate.asset,
    url: candidate.url,
    category: candidate.category,
    severityEstimate: candidate.severityEstimate,
    confidence: candidate.confidence,
    status: candidate.status === "ready_for_draft" ? "validated" : "needs_manual_review",
    evidencePaths: evidence.map((artifact) => artifact.path),
    duplicateRisk: candidate.duplicateRisk,
    reportabilityScore: candidateBaselineScore(candidate),
    createdAt: candidate.createdAt,
    updatedAt: candidate.updatedAt,
  };
}

function candidateBaselineScore(candidate: FindingCandidate): number {
  return candidateBaselineReportabilityScore(candidate);
}

function draftFindingReport(
  runtime: Runtime,
  findingId: string,
  platform: string,
  forceLocalDraft: boolean,
): {
  ok: true;
  findingId: string;
  status: "report_drafted";
  finding: NormalizedFinding | undefined;
  artifact: EvidenceArtifact;
  review: ReturnType<typeof buildReportReview>;
  report: { platform: string; path: string };
  platform: string;
  path: string;
} {
  if (!isSupportedReportPlatform(platform)) {
    throw new BountyPilotError("Unsupported report platform. Use hackerone or bugcrowd.", "REPORT_PLATFORM_UNSUPPORTED");
  }
  const finding = runtime.findings.get(findingId);
  if (!finding) {
    throw new BountyPilotError(`Finding not found: ${findingId}`, "FINDING_NOT_FOUND");
  }
  const evidence = runtime.evidence.list(findingId);
  const manifest = runtime.evidence.buildManifest({ findingId });
  const duplicate = new DuplicateRiskEngine().estimate(
    finding,
    runtime.findings.list().filter((item) => item.id !== finding.id),
  );
  const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
  const review = buildReportReview({ finding, evidence, manifest, duplicate, triage, platform });
  if (review.readiness === "blocked" && !forceLocalDraft) {
    throw new BountyPilotError(
      `Report readiness is blocked. Run reports score/review first or pass --force-local-draft for a local-only draft.`,
      "REPORT_READINESS_BLOCKED",
    );
  }
  const reportPath = writePlatformReport(runtime.paths.reportsDir, platform, finding, evidence);
  runtime.findings.updateStatus(findingId, "report_drafted");
  const artifact = runtime.evidence.create({
    findingId,
    adapterName: "report-generator",
    kind: "report",
    sourceUrl: finding.url,
    path: reportPath,
  });
  const updatedFinding = runtime.findings.get(findingId);
  return {
    ok: true,
    findingId,
    status: "report_drafted",
    finding: updatedFinding,
    artifact,
    review,
    report: { platform, path: reportPath },
    platform,
    path: reportPath,
  };
}

type CockpitStatus = "ready" | "needs_review" | "blocked";
type CockpitCheckStatus = "pass" | "warn" | "fail";

interface CockpitCheck {
  name: string;
  status: CockpitCheckStatus;
  message: string;
}

interface CockpitSnapshot {
  ok: boolean;
  generatedAt: string;
  refresh: number;
  status: CockpitStatus;
  focus: {
    mode: "workspace" | "job";
    jobId?: string;
  };
  checks: CockpitCheck[];
  workspace: WorkspaceSummary;
  recon: {
    workspace: CockpitReconSlice;
    focus?: CockpitReconSlice;
  };
  providers: {
    total: number;
    configured: number;
    missingAuth: number;
    missingConfig: number;
    disabled: number;
    records: ProviderSummary[];
  };
  tools: {
    total: number;
    available: number;
    notInstalled: number;
    approvedExecutables: number;
    reviewRequired: string[];
    statusCounts: Record<string, number>;
    topMissing: Array<{
      name: string;
      status: string;
      message: string;
    }>;
  };
  jobReview?: ReturnType<typeof buildJobReview>;
  nextCommands: string[];
}

interface CockpitReconSlice {
  total: number;
  inScope: number;
  outOfScope: number;
  byKind: Record<string, number>;
  bySource: Record<string, number>;
  samples: Array<{
    id: string;
    kind: ReconObservationKind;
    value: string;
    sourceAdapter: string;
    scopeAllowed: boolean;
    confidence: Confidence;
    riskHint?: string;
    jobId?: string;
  }>;
}

function buildCockpitSnapshot(runtime: Runtime, options: { jobId?: string; limit: number; refresh: number }): CockpitSnapshot {
  const workspace = buildWorkspaceSummary(runtime);
  const toolManager = createToolManager();
  const toolDoctor = toolManager.doctor();
  const toolRecords = toolManager.list();
  const approvedToolNames = toolRecords.filter((tool) => latestToolApproval(runtime, tool.name)).map((tool) => tool.name);
  const providerRecords = safeProviderList(process.cwd());
  const workspaceRecon = runtime.recon.list({ limit: 5000 });
  const focusRecon = options.jobId ? runtime.recon.list({ jobId: options.jobId, limit: 5000 }) : undefined;
  const jobReview = options.jobId ? buildJobReview(runtime, options.jobId, options.limit) : undefined;
  const providers = buildCockpitProviderSummary(providerRecords);
  const tools = {
    total: toolDoctor.length,
    available: toolDoctor.filter((tool) => tool.status === "available").length,
    notInstalled: toolDoctor.filter((tool) => tool.status === "not_installed").length,
    approvedExecutables: approvedToolNames.length,
    reviewRequired: toolRecords
      .filter((tool) => tool.actions.some((action) => action.requires_approval))
      .map((tool) => tool.name),
    statusCounts: countBy(toolDoctor, (tool) => tool.status),
    topMissing: toolDoctor
      .filter((tool) => tool.status !== "available")
      .slice(0, options.limit)
      .map((tool) => ({
        name: tool.name,
        status: tool.status,
        message: tool.message,
      })),
  };
  const recon = {
    workspace: buildCockpitReconSlice(workspaceRecon, options.limit),
    focus: focusRecon ? buildCockpitReconSlice(focusRecon, options.limit) : undefined,
  };
  const checks = buildCockpitChecks({ workspace, recon, providers, tools, jobReview });
  const status = cockpitStatus(checks);
  const nextCommands = buildCockpitNextCommands({
    workspace,
    recon,
    providers,
    tools,
    jobReview,
    jobId: options.jobId,
  });

  return {
    ok: status !== "blocked",
    generatedAt: workspace.generatedAt,
    refresh: options.refresh,
    status,
    focus: {
      mode: options.jobId ? "job" : "workspace",
      jobId: options.jobId,
    },
    checks,
    workspace,
    recon,
    providers,
    tools,
    jobReview,
    nextCommands,
  };
}

function buildCockpitReconSlice(observations: ReconObservation[], limit: number): CockpitReconSlice {
  return {
    total: observations.length,
    inScope: observations.filter((observation) => observation.scopeAllowed).length,
    outOfScope: observations.filter((observation) => !observation.scopeAllowed).length,
    byKind: countBy(observations, (observation) => observation.kind),
    bySource: countBy(observations, (observation) => observation.sourceAdapter),
    samples: observations.slice(0, limit).map((observation) => ({
      id: observation.id,
      kind: observation.kind,
      value: observation.value,
      sourceAdapter: observation.sourceAdapter,
      scopeAllowed: observation.scopeAllowed,
      confidence: observation.confidence,
      riskHint: observation.riskHint,
      jobId: observation.jobId,
    })),
  };
}

function buildCockpitProviderSummary(records: ProviderSummary[]): CockpitSnapshot["providers"] {
  return {
    total: records.length,
    configured: records.filter((provider) => provider.status === "configured").length,
    missingAuth: records.filter((provider) => provider.status === "missing_auth").length,
    missingConfig: records.filter((provider) => provider.status === "missing_config").length,
    disabled: records.filter((provider) => provider.status === "disabled").length,
    records,
  };
}

function buildCockpitChecks(input: {
  workspace: WorkspaceSummary;
  recon: CockpitSnapshot["recon"];
  providers: CockpitSnapshot["providers"];
  tools: CockpitSnapshot["tools"];
  jobReview?: ReturnType<typeof buildJobReview>;
}): CockpitCheck[] {
  const checks: CockpitCheck[] = [];
  checks.push(
    cockpitCheck(
      "scope",
      input.workspace.scope.inScope > 0 ? "pass" : "fail",
      input.workspace.scope.inScope > 0
        ? `${input.workspace.scope.inScope} in-scope rule(s) loaded.`
        : "No in-scope rule is loaded; import program scope before any live run.",
    ),
  );
  checks.push(
    cockpitCheck(
      "jobs",
      input.workspace.jobs.total > 0 ? "pass" : "warn",
      input.workspace.jobs.total > 0
        ? `${input.workspace.jobs.total} workflow job(s) are available.`
        : "No workflow job exists yet; start with a dry-run or recon job.",
    ),
  );
  checks.push(actionCockpitCheck(input.workspace.actions));
  checks.push(
    cockpitCheck(
      "findings",
      input.workspace.triage.readyForDraft > 0 ? "pass" : input.workspace.findings.total > 0 ? "warn" : "warn",
      input.workspace.triage.readyForDraft > 0
        ? `${input.workspace.triage.readyForDraft} finding(s) are ready for draft review.`
        : input.workspace.findings.total > 0
          ? `${input.workspace.findings.total} finding(s) need evidence, reproduction, or triage review.`
          : "No finding candidate is available yet.",
    ),
  );
  checks.push(
    cockpitCheck(
      "recon",
      input.recon.workspace.total > 0 ? "pass" : "warn",
      input.recon.workspace.total > 0
        ? `${input.recon.workspace.total} recon observation(s) are normalized locally.`
        : "No recon observations yet; run hunt recon or a bug-class playbook.",
    ),
  );
  checks.push(providerCockpitCheck(input.providers));
  checks.push(toolCockpitCheck(input.tools));

  if (input.jobReview) {
    checks.push(
      cockpitCheck(
        "job",
        input.jobReview.cockpit.status === "blocked" ? "fail" : input.jobReview.cockpit.status === "needs_review" ? "warn" : "pass",
        `Focused job ${input.jobReview.job.id} is ${input.jobReview.cockpit.status}.`,
      ),
    );
  }

  return checks;
}

function actionCockpitCheck(actions: WorkspaceSummary["actions"]): CockpitCheck {
  if (actions.failed > 0 || actions.blocked > 0) {
    return cockpitCheck("actions", "fail", `${actions.failed} failed and ${actions.blocked} blocked action(s) need review.`);
  }
  if (actions.pending > 0 || actions.approved > 0) {
    return cockpitCheck(
      "actions",
      "warn",
      `${actions.pending} pending and ${actions.approved} approved action(s) are waiting for human decision or execution.`,
    );
  }
  return cockpitCheck("actions", "pass", `${actions.total} action(s) have no pending decision.`);
}

function providerCockpitCheck(providers: CockpitSnapshot["providers"]): CockpitCheck {
  if (providers.total === 0) {
    return cockpitCheck("providers", "warn", "No provider is configured; deterministic local workflow remains available.");
  }
  if (providers.configured === 0) {
    return cockpitCheck("providers", "warn", "Providers exist but none are ready; connect or repair credentials.");
  }
  if (providers.configured < providers.total) {
    return cockpitCheck("providers", "warn", `${providers.configured}/${providers.total} provider(s) are configured.`);
  }
  return cockpitCheck("providers", "pass", `${providers.configured} provider(s) are ready.`);
}

function toolCockpitCheck(tools: CockpitSnapshot["tools"]): CockpitCheck {
  if (tools.available === 0) {
    return cockpitCheck("tools", "warn", "No trusted external tool is locally available; dry-run planning still works.");
  }
  if (tools.notInstalled > 0 || tools.approvedExecutables === 0) {
    return cockpitCheck(
      "tools",
      "warn",
      `${tools.available}/${tools.total} trusted tool(s) are available; ${tools.approvedExecutables} executable approval(s) recorded.`,
    );
  }
  return cockpitCheck("tools", "pass", `${tools.available}/${tools.total} trusted tool(s) are available.`);
}

function cockpitCheck(name: string, status: CockpitCheckStatus, message: string): CockpitCheck {
  return { name, status, message };
}

function cockpitStatus(checks: CockpitCheck[]): CockpitStatus {
  if (checks.some((check) => check.status === "fail")) {
    return "blocked";
  }
  if (checks.some((check) => check.status === "warn")) {
    return "needs_review";
  }
  return "ready";
}

function buildCockpitNextCommands(input: {
  workspace: WorkspaceSummary;
  recon: CockpitSnapshot["recon"];
  providers: CockpitSnapshot["providers"];
  tools: CockpitSnapshot["tools"];
  jobReview?: ReturnType<typeof buildJobReview>;
  jobId?: string;
}): string[] {
  const latestJob = input.jobReview?.job ?? input.workspace.jobs.recent[0];
  const target = input.jobReview?.job.target ?? latestJob?.target ?? "<in-scope-target>";
  const commands = [
    "bounty cockpit --watch --iterations 3",
    "bounty dashboard",
    "bounty tools doctor",
    "bounty providers doctor",
  ];

  if (latestJob) {
    commands.push(`bounty cockpit --job ${latestJob.id}`);
    commands.push(`bounty review --job ${latestJob.id}`);
    commands.push(`bounty jobs watch ${latestJob.id} --iterations 3`);
  }
  if (input.workspace.actions.pending > 0) {
    commands.push(latestJob ? `bounty actions review --job ${latestJob.id}` : "bounty actions list --pending");
  }
  if (input.workspace.actions.approved > 0 && latestJob) {
    commands.push(`bounty actions run-approved --job ${latestJob.id}`);
  }
  if (input.recon.focus?.total || input.recon.workspace.total > 0) {
    commands.push(input.jobId ? `bounty recon list --job ${input.jobId}` : "bounty recon list --limit 20");
  } else {
    commands.push(`bounty hunt recon ${target} --profile web --dry-run`);
  }
  if (input.workspace.findings.topReportable.length > 0) {
    const finding = input.workspace.findings.topReportable[0];
    commands.push(`bounty reports score ${finding.id}`);
    commands.push(`bounty reports review ${finding.id} --write`);
  } else {
    commands.push(`bounty hunt playbook xss ${target} --dry-run`);
  }
  if (input.providers.configured === 0) {
    commands.push("bounty providers catalog");
    commands.push("echo <api-key> | bounty providers connect openai --api-key-stdin");
  }
  if (input.tools.notInstalled > 0) {
    commands.push("bounty arsenal bootstrap --level safe --write");
  }
  commands.push("bounty export summary");
  return [...new Set(commands)];
}

type ResultsBoardStatus = "ready" | "needs_review" | "empty";

interface ResultsBoard {
  ok: true;
  generatedAt: string;
  status: ResultsBoardStatus;
  program: {
    name: string;
    platform: string;
    workspace: string;
  };
  job?: {
    id: string;
    type: string;
    status: string;
    mode: string;
    target?: string;
  };
  filters: {
    jobId?: string;
    limit: number;
    minScore: number;
    readyOnly: boolean;
  };
  totals: {
    findingsConsidered: number;
    findingsIncluded: number;
    readyForDraft: number;
    needsReview: number;
    blocked: number;
    evidenceArtifacts: number;
    blockers: number;
    warnings: number;
  };
  findings: ResultsFinding[];
  reconSignals: {
    total: number;
    byKind: Record<string, number>;
    bySource: Record<string, number>;
    samples: Array<{
      id: string;
      kind: ReconObservationKind;
      value: string;
      sourceAdapter: string;
      confidence: Confidence;
      riskHint?: string;
      jobId?: string;
    }>;
  };
  nextCommands: string[];
}

interface ResultsFinding {
  id: string;
  title: string;
  asset: string;
  url: string;
  category: string;
  severity: SeverityEstimate;
  confidence: Confidence;
  status: FindingStatus;
  score: number;
  readiness: ReportReadiness;
  recommendation: string;
  duplicateRisk: DuplicateRisk;
  evidence: number;
  readableEvidence: number;
  evidenceKinds: Record<string, number>;
  blockers: string[];
  warnings: string[];
  nextSteps: string[];
  nextCommands: string[];
  updatedAt: string;
}

function buildResultsBoard(
  runtime: Runtime,
  options: { jobId?: string; limit: number; minScore: number; readyOnly: boolean },
): ResultsBoard {
  const job = options.jobId ? requireJob(runtime, options.jobId) : undefined;
  const jobEvidence = filterEvidenceByJob(runtime.evidence.list(), options.jobId);
  const candidateFindings = options.jobId
    ? findingsForJob(runtime.findings.list(), jobEvidence)
    : runtime.findings.list();
  const reviewed = candidateFindings.map((finding) => buildResultsFinding(runtime, finding, options.jobId));
  const included = reviewed
    .filter((finding) => finding.score >= options.minScore)
    .filter((finding) => !options.readyOnly || finding.readiness === "ready_for_draft")
    .sort(compareResultsFindings)
    .slice(0, options.limit);
  const reconObservations = runtime.recon
    .list({ jobId: options.jobId, limit: 5000 })
    .filter((observation) =>
      observation.scopeAllowed && (
        observation.kind === "finding_candidate" ||
        observation.kind === "vulnerability_signal" ||
        observation.riskHint !== undefined
      ),
    );
  const totals = {
    findingsConsidered: reviewed.length,
    findingsIncluded: included.length,
    readyForDraft: reviewed.filter((finding) => finding.readiness === "ready_for_draft").length,
    needsReview: reviewed.filter((finding) => finding.readiness === "needs_review").length,
    blocked: reviewed.filter((finding) => finding.readiness === "blocked").length,
    evidenceArtifacts: reviewed.reduce((sum, finding) => sum + finding.evidence, 0),
    blockers: reviewed.reduce((sum, finding) => sum + finding.blockers.length, 0),
    warnings: reviewed.reduce((sum, finding) => sum + finding.warnings.length, 0),
  };
  const status: ResultsBoardStatus = totals.readyForDraft > 0 ? "ready" : included.length > 0 ? "needs_review" : "empty";
  return {
    ok: true,
    generatedAt: new Date().toISOString(),
    status,
    program: {
      name: runtime.config.program,
      platform: runtime.config.platform,
      workspace: runtime.paths.programDir,
    },
    job: job
      ? {
          id: job.id,
          type: job.type,
          status: job.status,
          mode: job.mode,
          target: job.target,
        }
      : undefined,
    filters: {
      jobId: options.jobId,
      limit: options.limit,
      minScore: options.minScore,
      readyOnly: options.readyOnly,
    },
    totals,
    findings: included,
    reconSignals: {
      total: reconObservations.length,
      byKind: countBy(reconObservations, (observation) => observation.kind),
      bySource: countBy(reconObservations, (observation) => observation.sourceAdapter),
      samples: reconObservations.slice(0, options.limit).map((observation) => ({
        id: observation.id,
        kind: observation.kind,
        value: observation.value,
        sourceAdapter: observation.sourceAdapter,
        confidence: observation.confidence,
        riskHint: observation.riskHint,
        jobId: observation.jobId,
      })),
    },
    nextCommands: buildResultsNextCommands({ runtime, jobId: options.jobId, findings: included, reconSignals: reconObservations }),
  };
}

function buildResultsFinding(runtime: Runtime, finding: NormalizedFinding, jobId: string | undefined): ResultsFinding {
  const evidence = filterEvidenceByJob(runtime.evidence.list(finding.id), jobId);
  const manifest = runtime.evidence.buildManifest({ findingId: finding.id, jobId });
  const duplicate = new DuplicateRiskEngine().estimate(
    finding,
    runtime.findings.list().filter((item) => item.id !== finding.id),
  );
  const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, evidence);
  const review = buildReportReview({ finding, evidence, manifest, duplicate, triage });
  return {
    id: finding.id,
    title: finding.title,
    asset: finding.asset,
    url: finding.url,
    category: finding.category,
    severity: finding.severityEstimate,
    confidence: finding.confidence,
    status: finding.status,
    score: review.score,
    readiness: review.readiness,
    recommendation: review.recommendation,
    duplicateRisk: duplicate.risk,
    evidence: review.counts.evidence,
    readableEvidence: review.counts.readableEvidence,
    evidenceKinds: review.counts.evidenceKinds,
    blockers: review.blockers,
    warnings: review.warnings,
    nextSteps: review.nextSteps,
    nextCommands: reportReviewCommands(finding.id, jobId, review.readiness),
    updatedAt: finding.updatedAt,
  };
}

function compareResultsFindings(left: ResultsFinding, right: ResultsFinding): number {
  const readinessDelta = readinessRank(right.readiness) - readinessRank(left.readiness);
  if (readinessDelta !== 0) return readinessDelta;
  const scoreDelta = right.score - left.score;
  if (scoreDelta !== 0) return scoreDelta;
  const severityDelta = severityRank(right.severity) - severityRank(left.severity);
  if (severityDelta !== 0) return severityDelta;
  return right.updatedAt.localeCompare(left.updatedAt) || left.id.localeCompare(right.id);
}

function readinessRank(readiness: ReportReadiness): number {
  if (readiness === "ready_for_draft") return 2;
  if (readiness === "needs_review") return 1;
  return 0;
}

function severityRank(severity: SeverityEstimate): number {
  const ranks: Record<SeverityEstimate, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
    unknown: 0,
  };
  return ranks[severity];
}

function buildResultsNextCommands(input: {
  runtime: Runtime;
  jobId?: string;
  findings: ResultsFinding[];
  reconSignals: ReconObservation[];
}): string[] {
  const commands: string[] = [];
  const jobOption = input.jobId ? ` --job ${input.jobId}` : "";
  if (input.findings.length > 0) {
    const top = input.findings[0];
    commands.push(`bounty findings show ${top.id}`);
    commands.push(`bounty reports score ${top.id}${jobOption}`);
    commands.push(`bounty reports review ${top.id}${jobOption} --write`);
    if (top.evidence < 2) {
      commands.push(`bounty evidence record ${top.url} --finding ${top.id}${jobOption}`);
    }
    if (top.readiness !== "blocked") {
      commands.push(`bounty report ${top.id} --platform hackerone`);
      commands.push(`bounty report ${top.id} --platform bugcrowd`);
    }
  }
  if (input.jobId) {
    commands.push(`bounty review --job ${input.jobId}`);
    commands.push(`bounty cockpit --job ${input.jobId}`);
    commands.push(`bounty export bundle --job ${input.jobId}`);
  } else {
    commands.push("bounty cockpit");
  }
  if (input.reconSignals.length > 0) {
    commands.push(input.jobId ? `bounty recon list --job ${input.jobId}` : "bounty recon list --kind finding_candidate");
  }
  if (input.findings.length === 0) {
    const target = input.runtime.jobs.list(1)[0]?.target ?? "<in-scope-target>";
    commands.push(`bounty hunt recon ${target} --profile web --dry-run`);
    commands.push(`bounty hunt playbook xss ${target} --dry-run`);
    commands.push(`bounty hunt playbook js-secrets ${target} --dry-run`);
  }
  commands.push("bounty export summary");
  return [...new Set(commands)];
}

function buildJobReview(runtime: Runtime, jobId: string, limit: number) {
  const job = requireJob(runtime, jobId);
  const summary = new WorkflowRunner(runtime).loadSummary(job.id);
  const displaySummary = summary ? workflowSummaryForDisplay(runtime, summary) : undefined;
  const actionCounts = runtime.actions.summarize(job.id);
  const activeActions = runtime.actions
    .list(job.id)
    .filter((action) => action.status === "pending" || action.status === "approved");
  const actions = activeActions.slice(0, limit);
  const hasReviewablePendingAction = activeActions.some(
    (action) => action.status === "pending" && !isHandoffOnlyAction(action),
  );
  const evidence = filterEvidenceByJob(runtime.evidence.list(), job.id);
  const findings = findingsForJob(runtime.findings.list(), evidence);
  const findingSummaries = summarizeJobFindings(runtime, findings, job.id, limit);
  const cockpit = buildJobReviewCockpit(displaySummary, actionCounts, evidence, findingSummaries);
  const events = runtime.events.list(job.id, limit);
  const byKind = evidence.reduce<Record<string, number>>((counts, artifact) => {
    counts[artifact.kind] = (counts[artifact.kind] ?? 0) + 1;
    return counts;
  }, {});
  const findingCommands = findingSummaries.flatMap((finding) => [
    `bounty findings show ${finding.id}`,
    `bounty reports review ${finding.id} --job ${job.id}`,
    ...(finding.readiness === "ready_for_draft"
      ? [`bounty report ${finding.id} --platform hackerone`, `bounty report ${finding.id} --platform bugcrowd`]
      : []),
  ]);
  const nextCommands = [
    `bounty jobs show ${job.id}`,
    `bounty jobs timeline ${job.id}`,
    `bounty jobs watch ${job.id} --iterations 3`,
    `bounty actions review --job ${job.id}`,
    ...(hasReviewablePendingAction ? [`bounty actions review --job ${job.id} --interactive`] : []),
    ...actions.flatMap(actionReviewCommands),
    `bounty evidence verify --job ${job.id}`,
    ...findingCommands,
    `bounty export bundle --job ${job.id}`,
  ];
  if (actionCounts.approved > 0) {
    nextCommands.push(`bounty actions run-approved --job ${job.id}`);
  }

  return {
    job,
    summary: displaySummary,
    cockpit,
    actionCounts,
    evidence: {
      total: evidence.length,
      byKind,
      artifacts: evidence,
    },
    findings: {
      total: findings.length,
      byStatus: countBy(findings, (finding) => finding.status),
      bySeverity: countBy(findings, (finding) => finding.severityEstimate),
      top: findingSummaries,
    },
    actions,
    events,
    nextCommands: [...new Set(nextCommands)],
  };
}

type JobReviewCheckStatus = "pass" | "warn" | "fail";

interface JobReviewCheck {
  name: string;
  status: JobReviewCheckStatus;
  message: string;
}

interface JobFindingSummary {
  id: string;
  title: string;
  status: FindingStatus;
  severity: SeverityEstimate;
  score: number;
  readiness: ReportReadiness;
  duplicateRisk: DuplicateRisk;
  evidence: number;
}

function buildJobReviewCockpit(
  summary: WorkflowSummary | undefined,
  actionCounts: ReturnType<Runtime["actions"]["summarize"]>,
  evidence: EvidenceArtifact[],
  findings: JobFindingSummary[],
) {
  const phaseCounts = countWorkflowPhaseStatuses(summary);
  const checks: JobReviewCheck[] = [
    workflowReviewCheck(summary),
    phaseReviewCheck(summary),
    actionReviewCheck(actionCounts),
    evidenceReviewCheck(evidence),
    findingReviewCheck(findings),
    reportCandidateReviewCheck(findings),
  ];
  const failed = checks.some((check) => check.status === "fail");
  const needsReview = checks.some((check) => check.status === "warn");
  return {
    status: failed ? "blocked" : needsReview ? "needs_review" : "ready",
    checks,
    phaseCounts,
    reportCandidates: findings.filter((finding) => finding.readiness !== "blocked").length,
  };
}

function findingsForJob(findings: NormalizedFinding[], evidence: EvidenceArtifact[]): NormalizedFinding[] {
  const evidencePaths = new Set(evidence.map((artifact) => artifact.path));
  const evidenceFindingIds = new Set(evidence.map((artifact) => artifact.findingId).filter((id): id is string => Boolean(id)));
  return findings.filter(
    (finding) => evidenceFindingIds.has(finding.id) || finding.evidencePaths.some((evidencePath) => evidencePaths.has(evidencePath)),
  );
}

function summarizeJobFindings(runtime: Runtime, findings: NormalizedFinding[], jobId: string, limit: number): JobFindingSummary[] {
  const history = runtime.findings.list();
  const duplicateEngine = new DuplicateRiskEngine();
  const triageEngine = new TriageEngine();
  return [...findings]
    .sort((left, right) => right.reportabilityScore - left.reportabilityScore || left.id.localeCompare(right.id))
    .slice(0, limit)
    .map((finding) => {
      const evidence = runtime.evidence.list(finding.id).filter((artifact) => artifact.jobId === jobId);
      const manifest = runtime.evidence.buildManifest({ findingId: finding.id, jobId });
      const duplicate = duplicateEngine.estimate(
        {
          title: finding.title,
          asset: finding.asset,
          url: finding.url,
          category: finding.category,
        },
        history.filter((candidate) => candidate.id !== finding.id),
      );
      const triage = triageEngine.triage(finding, evidence);
      const review = buildReportReview({
        finding,
        evidence,
        manifest,
        duplicate,
        triage,
      });
      return {
        id: finding.id,
        title: finding.title,
        status: finding.status,
        severity: finding.severityEstimate,
        score: triage.reportabilityScore,
        readiness: review.readiness,
        duplicateRisk: duplicate.risk,
        evidence: evidence.length,
      };
    });
}

function workflowReviewCheck(summary: WorkflowSummary | undefined): JobReviewCheck {
  if (!summary) {
    return jobReviewCheck("workflow", "warn", "No workflow summary was found for this job.");
  }
  if (summary.status === "failed") {
    return jobReviewCheck("workflow", "fail", "Workflow failed; inspect timeline and resume or rerun deliberately.");
  }
  if (summary.status === "completed") {
    return jobReviewCheck("workflow", "pass", "Workflow completed and checkpoint is available.");
  }
  return jobReviewCheck("workflow", "warn", `Workflow is ${summary.status}; watch or resume before reporting.`);
}

function phaseReviewCheck(summary: WorkflowSummary | undefined): JobReviewCheck {
  if (!summary || summary.phases.length === 0) {
    return jobReviewCheck("phases", "warn", "No workflow phase records were found.");
  }
  const failed = summary.phases.filter((phase) => phase.status === "failed");
  if (failed.length > 0) {
    return jobReviewCheck("phases", "fail", `${failed.length} phase(s) failed: ${failed.map((phase) => phase.name).join(", ")}.`);
  }
  const planned = summary.phases.filter((phase) => phase.status === "planned");
  if (planned.length > 0) {
    return jobReviewCheck("phases", "warn", `${planned.length} phase(s) still need human review or a handoff decision.`);
  }
  return jobReviewCheck("phases", "pass", `${summary.phases.length} phase records are terminal.`);
}

function actionReviewCheck(actionCounts: ReturnType<Runtime["actions"]["summarize"]>): JobReviewCheck {
  if (actionCounts.failed > 0 || actionCounts.blocked > 0) {
    return jobReviewCheck("actions", "fail", `${actionCounts.failed} failed and ${actionCounts.blocked} blocked action(s) need review.`);
  }
  if (actionCounts.pending > 0) {
    return jobReviewCheck("actions", "warn", `${actionCounts.pending} action(s) are pending human review.`);
  }
  if (actionCounts.approved > 0) {
    return jobReviewCheck("actions", "warn", `${actionCounts.approved} approved action(s) await an explicit lifecycle handoff.`);
  }
  return jobReviewCheck("actions", "pass", `${actionCounts.total} action(s) have no pending execution decision.`);
}

function evidenceReviewCheck(evidence: EvidenceArtifact[]): JobReviewCheck {
  if (evidence.length === 0) {
    return jobReviewCheck("evidence", "warn", "No evidence artifacts are linked to this job yet.");
  }
  return jobReviewCheck("evidence", "pass", `${evidence.length} evidence artifact(s) are linked to this job.`);
}

function findingReviewCheck(findings: JobFindingSummary[]): JobReviewCheck {
  if (findings.length === 0) {
    return jobReviewCheck("findings", "warn", "No findings are linked to this job evidence yet.");
  }
  return jobReviewCheck("findings", "pass", `${findings.length} finding(s) are linked to this job.`);
}

function reportCandidateReviewCheck(findings: JobFindingSummary[]): JobReviewCheck {
  const ready = findings.filter((finding) => finding.readiness === "ready_for_draft");
  const reviewable = findings.filter((finding) => finding.readiness === "needs_review");
  if (ready.length > 0) {
    return jobReviewCheck("reports", "pass", `${ready.length} finding(s) are ready for draft review.`);
  }
  if (reviewable.length > 0) {
    return jobReviewCheck("reports", "warn", `${reviewable.length} finding(s) need evidence or reproduction review before drafting.`);
  }
  return jobReviewCheck("reports", "warn", "No report-ready finding candidate is available yet.");
}

function jobReviewCheck(name: string, status: JobReviewCheckStatus, message: string): JobReviewCheck {
  return { name, status, message };
}

function countWorkflowPhaseStatuses(summary: WorkflowSummary | undefined) {
  const byStatus = { completed: 0, failed: 0, skipped: 0, planned: 0 };
  for (const phase of summary?.phases ?? []) {
    byStatus[phase.status] += 1;
  }
  return {
    total: Object.values(byStatus).reduce((sum, count) => sum + count, 0),
    byStatus,
  };
}

function countBy<T, K extends string>(items: T[], select: (item: T) => K): Record<K, number> {
  return items.reduce<Record<K, number>>(
    (counts, item) => {
      const key = select(item);
      counts[key] = (counts[key] ?? 0) + 1;
      return counts;
    },
    {} as Record<K, number>,
  );
}

function reportReviewCommands(
  findingId: string,
  jobId: string | undefined,
  readiness: ReportReadiness,
  subject: "finding" | "candidate" = "finding",
  promotedFindingId?: string,
): string[] {
  const jobOption = jobId ? ` --job ${jobId}` : "";
  if (subject === "candidate") {
    const commands = [
      `bounty findings candidate ${findingId}`,
      `bounty reports score ${findingId}${jobOption}`,
      ...(jobId ? [`bounty reports bundle ${findingId}${jobOption}`] : []),
    ];
    if (promotedFindingId) {
      commands.push(`bounty findings show ${promotedFindingId}`);
      if (readiness !== "blocked") {
        commands.push(`bounty report ${promotedFindingId} --platform hackerone`);
        commands.push(`bounty report ${promotedFindingId} --platform bugcrowd`);
      }
    } else {
      commands.push(`bounty findings promote-candidate ${findingId}`);
    }
    return [...new Set(commands)];
  }
  const commands = [
    `bounty findings show ${findingId}`,
    `bounty triage ${findingId}`,
    `bounty evidence verify ${findingId}${jobOption}`,
    `bounty reproduce ${findingId}`,
    `bounty reports score ${findingId}${jobOption}`,
    `bounty reports review ${findingId}${jobOption} --write`,
    ...(jobId ? [`bounty reports bundle ${findingId}${jobOption}`] : []),
  ];
  if (readiness !== "blocked") {
    commands.push(`bounty report ${findingId} --platform hackerone`);
    commands.push(`bounty report ${findingId} --platform bugcrowd`);
  }
  return [...new Set(commands)];
}

function jobWatchSnapshot(runtime: Runtime, jobId: string, eventLimit: number) {
  const job = requireJob(runtime, jobId);
  const summary = new WorkflowRunner(runtime).loadSummary(jobId);
  const actionCounts = runtime.actions.summarize(job.id);
  const events = runtime.events.list(jobId, eventLimit);
  const status = summary?.status ?? job.status;
  return {
    job,
    summary: summary ? workflowSummaryForDisplay(runtime, summary) : undefined,
    actionCounts,
    events,
    terminal: status === "completed" || status === "failed",
  };
}

function printJobWatchSnapshot(snapshot: ReturnType<typeof jobWatchSnapshot>, refresh: number): void {
  const status = snapshot.summary?.status ?? snapshot.job.status;
  ui.status(workflowStatusLabel(status), `watch refresh ${refresh}: ${status}`);
  ui.panel("job", [
    ui.kv("id", snapshot.job.id),
    ui.kv("type", snapshot.job.type),
    ui.kv("target", snapshot.job.target),
    ui.kv("actions", snapshot.actionCounts.total),
    ui.kv("pending", snapshot.actionCounts.pending),
    ui.kv("approved", snapshot.actionCounts.approved),
    ui.kv("executed", snapshot.actionCounts.executed),
    ui.kv("failed", snapshot.actionCounts.failed),
  ]);
  printWorkflowTimeline(snapshot.events, "recent events");
  const commands = [
    `bounty jobs show ${snapshot.job.id}`,
    `bounty jobs timeline ${snapshot.job.id}`,
    ...(snapshot.actionCounts.pending > 0 ? [`bounty actions review --job ${snapshot.job.id}`] : []),
    ...(snapshot.actionCounts.approved > 0 ? [`bounty actions run-approved --job ${snapshot.job.id}`] : []),
  ];
  ui.blank();
  ui.commandList("next commands", commands);
}

interface InteractiveActionReviewOptions {
  jobId?: string;
  limit: number;
  defaultNote?: string;
}

interface InteractiveActionReviewDecision {
  actionId: string;
  input: string;
  decision: "approved" | "blocked" | "skipped" | "quit";
  statusBefore: ActionRecord["status"];
  statusAfter: ActionRecord["status"];
  message: string;
  review?: ReturnType<Runtime["reviews"]["record"]>;
}

async function runInteractiveActionReview(
  runtime: Runtime,
  actions: ActionRecord[],
  options: InteractiveActionReviewOptions,
) {
  if (actions.length === 0) {
    return {
      ok: true,
      interactive: true,
      jobId: options.jobId,
      limit: options.limit,
      actions,
      decisions: [] as InteractiveActionReviewDecision[],
      summary: { approved: 0, blocked: 0, skipped: 0, quit: false },
      nextCommands: [] as string[],
    };
  }

  const reviewableActions = actions.filter((action) => !isHandoffOnlyAction(action));
  const inputs = reviewableActions.length > 0 ? await collectInteractiveReviewInputs(reviewableActions) : [];
  const parsed = inputs.map((input) => parseInteractiveReviewDecision(input, options.defaultNote));
  const decisions: InteractiveActionReviewDecision[] = [];
  for (let index = 0; index < actions.length; index += 1) {
    const action = actions[index];
    if (isHandoffOnlyAction(action)) {
      decisions.push({
        actionId: action.id,
        input: "",
        decision: "skipped",
        statusBefore: action.status,
        statusAfter: action.status,
        message: "Planning-only handoff retained; executable approval is unavailable.",
      });
      continue;
    }
    const reviewableIndex = reviewableActions.findIndex((candidate) => candidate.id === action.id);
    const decision = parsed[reviewableIndex] ?? { kind: "skipped" as const, input: "", note: options.defaultNote };
    if (decision.kind === "quit") {
      decisions.push({
        actionId: action.id,
        input: decision.input,
        decision: "quit",
        statusBefore: action.status,
        statusAfter: action.status,
        message: "Interactive review stopped by reviewer.",
      });
      break;
    }
    decisions.push(applyInteractiveActionReviewDecision(runtime, action, decision));
  }

  const reviewedActions = actions.map((action) => runtime.actions.get(action.id) ?? action);
  const summary = {
    approved: decisions.filter((decision) => decision.decision === "approved").length,
    blocked: decisions.filter((decision) => decision.decision === "blocked").length,
    skipped: decisions.filter((decision) => decision.decision === "skipped").length,
    quit: decisions.some((decision) => decision.decision === "quit"),
  };
  const nextCommands = [...new Set(reviewedActions.flatMap(actionReviewCommands))];
  return {
    ok: true,
    interactive: true,
    jobId: options.jobId,
    limit: options.limit,
    actions: reviewedActions,
    decisions,
    summary,
    nextCommands,
  };
}

function printInteractiveActionReviewResult(result: Awaited<ReturnType<typeof runInteractiveActionReview>>): void {
  ui.header("actions interactive review");
  if (result.actions.length === 0) {
    ui.status("warn", "no pending or approved actions found");
    return;
  }
  ui.status("ok", `${result.summary.approved} approved, ${result.summary.blocked} blocked, ${result.summary.skipped} skipped`);
  ui.panel("review queue", [
    ui.kv("actions", result.actions.length),
    ui.kv("job", result.jobId),
    ui.kv("quit", result.summary.quit),
  ]);
  ui.blank();
  ui.table(
    ["decision", "before", "after", "action", "message"],
    result.decisions.map((decision) => [
      decision.decision,
      decision.statusBefore,
      decision.statusAfter,
      decision.actionId,
      decision.message,
    ]),
  );
  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

type ParsedInteractiveReviewDecision =
  | { kind: "approved" | "blocked" | "skipped" | "quit"; input: string; note?: string };

async function collectInteractiveReviewInputs(actions: ActionRecord[]): Promise<string[]> {
  if (!process.stdin.isTTY) {
    const input = readFileSync(0, "utf8");
    const lines = input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (lines.length === 0) {
      throw new BountyPilotError(
        "Interactive review requires stdin decisions when input is not a TTY. Use lines like: approve <note>, block <note>, skip, or quit.",
        "ACTION_REVIEW_INTERACTIVE_INPUT_REQUIRED",
      );
    }
    return lines;
  }

  const readline = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const lines: string[] = [];
    for (const [index, action] of actions.entries()) {
      const answer = await readline.question(
        `[${index + 1}/${actions.length}] ${action.id} ${action.status} ${action.adapter}:${action.actionType} (approve/block/skip/quit): `,
      );
      lines.push(answer);
      if (parseInteractiveReviewDecision(answer).kind === "quit") {
        break;
      }
    }
    return lines;
  } finally {
    readline.close();
  }
}

function parseInteractiveReviewDecision(input: string, defaultNote?: string): ParsedInteractiveReviewDecision {
  const trimmed = input.trim();
  const [rawDecision = "", ...noteParts] = trimmed.split(/\s+/);
  const decision = rawDecision.toLowerCase();
  const note = noteParts.join(" ").trim() || defaultNote;
  if (decision === "a" || decision === "approve" || decision === "approved") {
    return { kind: "approved", input: trimmed, note };
  }
  if (decision === "b" || decision === "block" || decision === "blocked") {
    return { kind: "blocked", input: trimmed, note };
  }
  if (decision === "s" || decision === "skip" || decision === "skipped" || decision === "") {
    return { kind: "skipped", input: trimmed, note };
  }
  if (decision === "q" || decision === "quit" || decision === "exit") {
    return { kind: "quit", input: trimmed, note };
  }
  throw new BountyPilotError(
    `Unsupported interactive review decision: ${rawDecision}. Use approve, block, skip, or quit.`,
    "ACTION_REVIEW_DECISION_INVALID",
  );
}

function applyInteractiveActionReviewDecision(
  runtime: Runtime,
  action: ActionRecord,
  decision: ParsedInteractiveReviewDecision,
): InteractiveActionReviewDecision {
  if (decision.kind === "skipped") {
    return {
      actionId: action.id,
      input: decision.input,
      decision: "skipped",
      statusBefore: action.status,
      statusAfter: action.status,
      message: "Action skipped by reviewer.",
    };
  }
  if (decision.kind === "approved") {
    if (action.status !== "pending") {
      return {
        actionId: action.id,
        input: decision.input,
        decision: "skipped",
        statusBefore: action.status,
        statusAfter: action.status,
        message: `Action is already ${action.status}; approve was not applied.`,
      };
    }
    const approval = approveActionAsCliHuman(runtime, action.id, {
      note: decision.note,
      reviewerId: "human:local-cli",
      ttlMs: 15 * 60_000,
    });
    const updated = approval.action;
    const review = approval.review;
    return {
      actionId: action.id,
      input: decision.input,
      decision: "approved",
      statusBefore: action.status,
      statusAfter: updated.status,
      message: "Action approved by interactive review.",
      review,
    };
  }
  if (decision.kind === "blocked") {
    const updated = runtime.actions.block(action.id);
    const review = recordActionReview(runtime, updated, "blocked", decision.note);
    if (updated.jobId) runtime.jobs.finalize(updated.jobId);
    return {
      actionId: action.id,
      input: decision.input,
      decision: "blocked",
      statusBefore: action.status,
      statusAfter: updated.status,
      message: "Action blocked by interactive review.",
      review,
    };
  }
  return {
    actionId: action.id,
    input: decision.input,
    decision: "quit",
    statusBefore: action.status,
    statusAfter: action.status,
    message: "Interactive review stopped by reviewer.",
  };
}

function actionReviewCommands(action: ActionRecord): string[] {
  const commands = [`bounty actions show ${action.id}`];
  if (action.status === "pending" && !isHandoffOnlyAction(action)) {
    commands.push(`bounty actions approve ${action.id} --note "authorized by program scope"`);
    commands.push(`bounty actions block ${action.id} --note "not clearly authorized"`);
  } else if (action.status === "pending" && isHandoffOnlyAction(action)) {
    commands.push(`bounty actions block ${action.id} --note "discard planning-only handoff"`);
  }
  if (action.status === "approved") {
    commands.push(`bounty actions execute ${action.id}`);
    if (action.jobId) {
      commands.push(`bounty actions run-approved --job ${action.jobId}`);
    }
    commands.push(`bounty actions block ${action.id} --note "hold for later review"`);
  }
  if (action.jobId) {
    commands.push(`bounty jobs timeline ${action.jobId}`);
  }
  return commands;
}

function isHandoffOnlyAction(action: ActionRecord): boolean {
  return action.metadata?.handoffOnly === true
    || (action.requiredForCompletion === false && action.metadata?.planningOnly === true);
}

function printActionReviewCommands(actions: ActionRecord[]): void {
  const commands = [...new Set(actions.flatMap(actionReviewCommands))];
  if (commands.length === 0) {
    return;
  }
  ui.blank();
  ui.commandList("next commands", commands);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseFindingStatus(value: string): FindingStatus {
  if (FINDING_STATUSES.includes(value as FindingStatus)) {
    return value as FindingStatus;
  }
  throw new BountyPilotError(
    `Unsupported finding status: ${value}. Use one of: ${FINDING_STATUSES.join(", ")}.`,
    "FINDING_STATUS_INVALID",
  );
}

function parseSeverityEstimate(value: string): SeverityEstimate {
  if (SEVERITY_ESTIMATES.includes(value as SeverityEstimate)) {
    return value as SeverityEstimate;
  }
  throw new BountyPilotError(
    `Unsupported severity estimate: ${value}. Use one of: ${SEVERITY_ESTIMATES.join(", ")}.`,
    "FINDING_SEVERITY_INVALID",
  );
}

function parseConfidence(value: string): Confidence {
  if (CONFIDENCE_LEVELS.includes(value as Confidence)) {
    return value as Confidence;
  }
  throw new BountyPilotError(
    `Unsupported confidence: ${value}. Use one of: ${CONFIDENCE_LEVELS.join(", ")}.`,
    "FINDING_CONFIDENCE_INVALID",
  );
}

function parseDuplicateRisk(value: string): DuplicateRisk {
  if (DUPLICATE_RISKS.includes(value as DuplicateRisk)) {
    return value as DuplicateRisk;
  }
  throw new BountyPilotError(
    `Unsupported duplicate risk: ${value}. Use one of: ${DUPLICATE_RISKS.join(", ")}.`,
    "FINDING_DUPLICATE_RISK_INVALID",
  );
}

function parseFindingCandidateStatus(value: string): FindingCandidateStatus {
  if (FINDING_CANDIDATE_STATUSES.includes(value as FindingCandidateStatus)) {
    return value as FindingCandidateStatus;
  }
  throw new BountyPilotError(
    `Unsupported finding candidate status: ${value}. Use one of: ${FINDING_CANDIDATE_STATUSES.join(", ")}.`,
    "FINDING_CANDIDATE_STATUS_INVALID",
  );
}

function parseFindingCandidateReportability(value: string): FindingCandidateReportability {
  if (FINDING_CANDIDATE_REPORTABILITIES.includes(value as FindingCandidateReportability)) {
    return value as FindingCandidateReportability;
  }
  throw new BountyPilotError(
    `Unsupported finding candidate reportability: ${value}. Use one of: ${FINDING_CANDIDATE_REPORTABILITIES.join(", ")}.`,
    "FINDING_CANDIDATE_REPORTABILITY_INVALID",
  );
}

function parseEvidenceKind(value: string): EvidenceArtifact["kind"] {
  if (EVIDENCE_KINDS.includes(value as EvidenceArtifact["kind"])) {
    return value as EvidenceArtifact["kind"];
  }
  throw new BountyPilotError(
    `Unsupported evidence kind: ${value}. Use one of: ${EVIDENCE_KINDS.join(", ")}.`,
    "EVIDENCE_KIND_INVALID",
  );
}

function parseReconObservationKind(value: string): ReconObservationKind {
  if (RECON_OBSERVATION_KINDS.includes(value as ReconObservationKind)) {
    return value as ReconObservationKind;
  }
  throw new BountyPilotError(
    `Unsupported recon observation kind: ${value}. Use one of: ${RECON_OBSERVATION_KINDS.join(", ")}.`,
    "RECON_OBSERVATION_KIND_INVALID",
  );
}

function reconObservationCounts(observations: Array<{ kind: ReconObservationKind; sourceAdapter: string }>): {
  total: number;
  byKind: Record<string, number>;
  bySource: Record<string, number>;
} {
  const byKind: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  for (const observation of observations) {
    byKind[observation.kind] = (byKind[observation.kind] ?? 0) + 1;
    bySource[observation.sourceAdapter] = (bySource[observation.sourceAdapter] ?? 0) + 1;
  }
  return { total: observations.length, byKind, bySource };
}

function parseReportabilityScore(value: string): number {
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new BountyPilotError(`Invalid reportability score: ${value}. Use an integer from 0 to 100.`, "FINDING_SCORE_INVALID");
  }
  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 100) {
    throw new BountyPilotError(`Invalid reportability score: ${value}. Use an integer from 0 to 100.`, "FINDING_SCORE_INVALID");
  }
  return parsed;
}

function parseNonEmptyTextOption(value: string, optionName: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new BountyPilotError(`Invalid --${optionName}: value cannot be empty.`, `CLI_INVALID_${optionName.toUpperCase()}`);
  }
  return trimmed;
}

function collectOption(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function assertSingleEvidenceSource(options: { file?: string; text?: string; stdin?: boolean }): void {
  const sources = [options.file !== undefined, options.text !== undefined, options.stdin === true].filter(Boolean).length;
  if (sources !== 1) {
    throw new BountyPilotError("Provide exactly one evidence source: --file, --text, or --stdin.", "EVIDENCE_SOURCE_INVALID");
  }
  if (options.file !== undefined) parseNonEmptyTextOption(options.file, "file");
  if (options.text !== undefined) parseNonEmptyTextOption(options.text, "text");
}

function readStdinText(): string {
  const content = readFileSync(0, "utf8");
  return parseNonEmptyTextOption(content, "stdin");
}

function manualEvidenceRelativePath(sourcePath: string, label: string | undefined, findingId: string | undefined): string {
  const rawName = label?.trim() || path.basename(sourcePath);
  const fileName = safeFileName(rawName);
  return findingId ? path.join(findingId, "manual", fileName) : path.join("manual", fileName);
}

function manualTextEvidenceRelativePath(label: string, findingId: string | undefined): string {
  const fileName = safeFileName(label.endsWith(".md") || label.endsWith(".txt") ? label : `${label}.md`);
  return findingId ? path.join(findingId, "manual", fileName) : path.join("manual", fileName);
}

function safeFileName(value: string): string {
  const sanitized = value.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return sanitized || "artifact";
}

function parsePositiveIntegerOption(value: string | undefined, optionName: string, defaultValue: number): number {
  const raw = value ?? String(defaultValue);
  const trimmed = raw.trim();
  if (!/^[1-9]\d*$/.test(trimmed)) {
    throw new BountyPilotError(
      `Invalid --${optionName}: ${raw}. Use a positive integer.`,
      `CLI_INVALID_${optionName.replace(/[^a-zA-Z0-9]+/g, "_").toUpperCase()}`,
    );
  }
  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed)) {
    throw new BountyPilotError(
      `Invalid --${optionName}: ${raw}. Use a safe positive integer.`,
      `CLI_INVALID_${optionName.replace(/[^a-zA-Z0-9]+/g, "_").toUpperCase()}`,
    );
  }
  return parsed;
}

function parseNumberOption(value: string | undefined, optionName: string, defaultValue: number, min: number, max: number): number {
  const raw = value ?? String(defaultValue);
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw new BountyPilotError(
      `Invalid --${optionName}: ${raw}. Use a number from ${min} to ${max}.`,
      `CLI_INVALID_${optionName.replace(/[^a-zA-Z0-9]+/g, "_").toUpperCase()}`,
    );
  }
  return parsed;
}

function parsePortOption(value: string | undefined, optionName: string, defaultValue: number): number {
  const raw = value ?? String(defaultValue);
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new BountyPilotError(
      `Invalid --${optionName}: ${raw}. Use an integer from 0 to 65535.`,
      `CLI_INVALID_${optionName.replace(/[^a-zA-Z0-9]+/g, "_").toUpperCase()}`,
    );
  }
  const parsed = Number(trimmed);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
    throw new BountyPilotError(
      `Invalid --${optionName}: ${raw}. Use an integer from 0 to 65535.`,
      `CLI_INVALID_${optionName.replace(/[^a-zA-Z0-9]+/g, "_").toUpperCase()}`,
    );
  }
  return parsed;
}

function normalizeIntegrationName(name: string): string {
  return name.trim().toLowerCase().replace(/-/g, "_");
}

function copyImportedLabAuthorizationFile(sourceProgramFile: string, savedProgramFile: string, config: ProgramConfig): string | undefined {
  const sourcePath = labAuthorizationFilePath(sourceProgramFile, config);
  const destinationPath = labAuthorizationFilePath(savedProgramFile, config);
  if (!sourcePath || !destinationPath) {
    return undefined;
  }
  if (path.resolve(sourcePath) === path.resolve(destinationPath)) {
    return destinationPath;
  }
  mkdirSync(path.dirname(destinationPath), { recursive: true });
  copyFileSync(sourcePath, destinationPath);
  return destinationPath;
}

function sanitizeImportedProgramConfig(config: ProgramConfig): {
  config: ProgramConfig;
  strippedExecutionOptIns: Array<{ integration: string; field: string }>;
} {
  const strippedExecutionOptIns: Array<{ integration: string; field: string }> = [];
  const integrations: Record<string, unknown> = {};

  for (const [name, value] of Object.entries(config.integrations)) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      integrations[name] = value;
      continue;
    }

    const integration = { ...(value as Record<string, unknown>) };
    if (integration.allow_execute === true) {
      integration.allow_execute = false;
      strippedExecutionOptIns.push({ integration: name, field: "allow_execute" });
    }
    const execution = integrationRecord(integration.execution);
    if (execution.enabled === true) {
      integration.execution = { ...execution, enabled: false };
      strippedExecutionOptIns.push({ integration: name, field: "execution.enabled" });
    }
    integrations[name] = integration;
  }

  return {
    config: { ...config, integrations },
    strippedExecutionOptIns,
  };
}

function createToolManager(): ToolManager {
  const registryPath = rootToolRegistryPath()?.trim();
  return registryPath
    ? ToolManager.fromRegistryFile(path.resolve(registryPath), { includeBuiltIns: true })
    : new ToolManager();
}

function integrationRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? { ...(value as Record<string, unknown>) } : {};
}

function parsePairs(pairs: string[]): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const pair of pairs) {
    const [rawKey, ...rawValue] = pair.split("=");
    const key = rawKey?.trim() ?? "";
    if (!key || /\s/.test(key) || rawValue.length === 0) {
      throw new BountyPilotError(`Invalid argument pair: ${pair}. Use key=value.`, "ARG_PAIR_INVALID");
    }
    if (Object.hasOwn(output, key)) {
      throw new BountyPilotError(`Duplicate argument key: ${key}.`, "ARG_PAIR_INVALID");
    }
    output[key] = parseConfigValue(rawValue.join("="));
  }
  return output;
}

function readMcpSessionSteps(filePath: string): McpSessionStepInput[] {
  const resolvedPath = path.resolve(filePath);
  const stats = statMcpStepsFile(resolvedPath);
  if (!stats.isFile()) {
    throw new BountyPilotError(`MCP session steps path is not a file: ${resolvedPath}`, "MCP_STEPS_NOT_FILE");
  }
  if (stats.size > MAX_MCP_SESSION_STEPS_FILE_BYTES) {
    throw new BountyPilotError(
      `MCP session steps file is too large: ${stats.size} bytes (max ${MAX_MCP_SESSION_STEPS_FILE_BYTES})`,
      "MCP_STEPS_FILE_TOO_LARGE",
    );
  }

  const raw = readFileSync(resolvedPath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`MCP session steps file is not valid JSON: ${reason}`, "MCP_STEPS_INVALID_JSON");
  }
  const rawSteps = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object" && Array.isArray((parsed as { steps?: unknown }).steps)
      ? (parsed as { steps: unknown[] }).steps
      : undefined;
  if (!rawSteps) {
    throw new BountyPilotError("MCP session steps file must be an array or an object with a steps array.", "MCP_STEPS_INVALID");
  }
  if (rawSteps.length === 0) {
    throw new BountyPilotError("MCP session steps file must contain at least one step.", "MCP_STEPS_EMPTY");
  }
  if (rawSteps.length > MAX_MCP_SESSION_STEPS) {
    throw new BountyPilotError(
      `MCP session steps file contains ${rawSteps.length} steps; max is ${MAX_MCP_SESSION_STEPS}.`,
      "MCP_STEPS_TOO_MANY",
    );
  }
  return rawSteps.map((step, index) => {
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      throw new BountyPilotError(`MCP session step ${index + 1} must be an object.`, "MCP_STEPS_INVALID");
    }
    const record = step as Record<string, unknown>;
    const tool = typeof record.tool === "string" ? record.tool.trim() : "";
    if (!tool) {
      throw new BountyPilotError(`MCP session step ${index + 1} requires a tool string.`, "MCP_STEPS_INVALID");
    }
    if (record.arguments !== undefined && (!record.arguments || typeof record.arguments !== "object" || Array.isArray(record.arguments))) {
      throw new BountyPilotError(`MCP session step ${index + 1} arguments must be an object.`, "MCP_STEPS_INVALID");
    }
    return {
      tool,
      target: typeof record.target === "string" && record.target.trim() ? record.target.trim() : undefined,
      label: typeof record.label === "string" && record.label.trim() ? record.label.trim() : undefined,
      arguments: record.arguments as Record<string, unknown> | undefined,
    };
  });
}

function statMcpStepsFile(resolvedPath: string): Stats {
  try {
    return statSync(resolvedPath);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : undefined;
    if (code === "ENOENT") {
      throw new BountyPilotError(`MCP session steps file not found: ${resolvedPath}`, "MCP_STEPS_NOT_FOUND");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Could not read MCP session steps file: ${reason}`, "MCP_STEPS_READ_FAILED");
  }
}

function parseIntegrationConfigValue(key: string, value: string): string | boolean | number | string[] {
  if (key === "capabilities" || key === "blocked_capabilities" || key === "args") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return parseConfigValue(value);
}

interface IntegrationSetupOptions {
  command?: string;
  package: string;
  packageVersion?: string;
  entrypoint: string;
  timeoutMs?: string;
  approveExecutable?: boolean;
}

interface IntegrationSetupResult {
  integration: string;
  config: Record<string, unknown>;
  approvalCommand?: string;
  detected?: {
    summary: string;
    package?: InspectedNpmPackageEntrypoint;
    command?: ReturnType<typeof resolveLocalExecutable>;
  };
  nextCommands: string[];
  warnings: string[];
}

interface IntegrationVerificationCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
  details?: unknown;
}

interface IntegrationVerificationInput {
  name: string;
  capability: string;
  target: string;
  mode: ReturnType<typeof modeFromOptions>;
}

function buildIntegrationVerification(runtime: Runtime, input: IntegrationVerificationInput) {
  const manager = new IntegrationManager(runtime.config);
  const integration = manager.get(input.name);
  if (!integration) throw new BountyPilotError(`Integration not found: ${input.name}`, "INTEGRATION_NOT_FOUND");
  const scopedTarget = runtime.scopeGuard.assertAllowed(input.target).url;
  const validation = manager.validateCallPlan({
    integration: input.name,
    capability: input.capability,
    target: scopedTarget,
    mode: input.mode,
  });
  const executionIntentRecorded = integrationExecutionIntentRecorded(integration.config);
  const checks: IntegrationVerificationCheck[] = [
    {
      name: "scope",
      status: "pass",
      message: `Target is in scope: ${scopedTarget}`,
    },
    {
      name: "configuration",
      status: integration.status === "configured" ? "pass" : "fail",
      message: integration.status === "configured" ? "Integration is configured." : integration.message ?? `Integration is ${integration.status}.`,
      details: {
        missingConfig: integration.missingConfig,
        configErrors: integration.configErrors,
        unknownCapabilities: integration.unknownCapabilities,
      },
    },
    {
      name: "policy",
      status: validation.ok ? (validation.requiresApproval ? "warn" : "pass") : "fail",
      message: validation.ok
        ? validation.requiresApproval
          ? "Policy allows planning but requires an approved queued action; external dispatch remains disabled."
          : "Policy allows this capability for the scoped target; external dispatch remains disabled."
        : validation.reasons.join("; "),
      details: validation,
    },
    {
      name: "dispatch_boundary",
      status: "pass",
      message: executionIntentRecorded
        ? "Legacy execution intent is retained only as non-authoritative metadata; external dispatch is disabled."
        : "This integration is planning/handoff-only; external dispatch is disabled.",
    },
    executableReadinessCheck(),
  ];
  const status = checks.some((check) => check.status === "fail")
    ? "fail"
    : checks.some((check) => check.status === "warn")
      ? "warn"
      : "pass";
  const nextCommands = integrationVerificationNextCommands(integration.name, input.capability, scopedTarget, input.mode, checks);
  return {
    ok: status !== "fail",
    status,
    message:
      status === "pass"
       ? "Integration is ready for a scoped planning and human-handoff path; external dispatch is disabled."
       : status === "warn"
           ? "Integration is planning-ready, but one or more local configuration checks remain."
           : "Integration readiness failed; fix blocking checks before planning.",
    execute: false,
    integration: {
      name: integration.name,
      type: integration.type,
      enabled: integration.enabled,
      status: integration.status,
      executionIntentRecorded,
    },
    request: {
      capability: input.capability,
      target: scopedTarget,
      mode: input.mode,
    },
    checks,
    validation,
    nextCommands,
  };
}

function executableReadinessCheck(): IntegrationVerificationCheck {
  return {
    name: "executable_pin",
    status: "pass",
    message: "Executable pins are optional handoff metadata; they never grant process or MCP dispatch authority.",
  };
}

function integrationVerificationNextCommands(
  integrationName: string,
  capability: string,
  target: string,
  mode: ReturnType<typeof modeFromOptions>,
  checks: IntegrationVerificationCheck[],
): string[] {
  const commands = [
    `bounty integrations preflight ${displayIntegrationName(integrationName)} ${capability} --target ${target} --mode ${mode}`,
    `bounty integrations doctor`,
    `bounty integrations approved-executables ${displayIntegrationName(integrationName)}`,
  ];
  const failedChecks = new Set(checks.filter((check) => check.status === "fail").map((check) => check.name));
  if (failedChecks.has("configuration")) {
    if (integrationName === "playwright_mcp") {
      commands.unshift("bounty integrations setup playwright-mcp");
    } else if (integrationName === "crawl4ai") {
      commands.unshift('bounty integrations setup crawl4ai --command "<absolute-path-to-crawl4ai>"');
    }
  }
  if (integrationName === "playwright_mcp") {
    commands.push(`bounty mcp plan playwright-mcp browser_navigate --target ${target} --arg url=${target}`);
    commands.push(`bounty actions review --job <planned-job-id>`);
  } else if (integrationName === "crawl4ai") {
    commands.push(`bounty run ${target} --dry-run --with crawl4ai`);
    commands.push("bounty review --job <planned-job-id>");
  }
  return [...new Set(commands)];
}

function displayIntegrationName(name: string): string {
  return name.replaceAll("_", "-");
}

function buildIntegrationSetup(runtime: Runtime, name: string, options: IntegrationSetupOptions): IntegrationSetupResult {
  const key = normalizeIntegrationName(name);
  if (key === "playwright_mcp") {
    return buildPlaywrightMcpSetup(runtime, options);
  }
  if (key === "crawl4ai") {
    return buildCrawl4AiSetup(runtime, options);
  }
  throw new BountyPilotError(
    `Unsupported integration setup preset: ${name}. Use playwright-mcp or crawl4ai.`,
    "INTEGRATION_SETUP_UNSUPPORTED",
  );
}

function buildIntegrationDoctorGuidance(runtime: Runtime): {
  integrations: ReturnType<IntegrationManager["doctor"]>;
  mcp: string[];
  nextCommands: string[];
} {
  const manager = new IntegrationManager(runtime.config);
  const integrations = manager.doctor();
  const detailed = manager.listDetailed();
  const mcp = new McpClientManager(runtime.config).doctor();
  return {
    integrations,
    mcp,
    nextCommands: integrationDoctorNextCommands(detailed),
  };
}

function integrationDoctorNextCommands(integrations: ReturnType<IntegrationManager["listDetailed"]>): string[] {
  const commands: string[] = [];
  const playwrightMcp = integrations.find((integration) => integration.name === "playwright_mcp");
  const crawl4ai = integrations.find((integration) => integration.name === "crawl4ai");

  if (!playwrightMcp || playwrightMcp.status !== "configured") {
    commands.push("bounty integrations setup playwright-mcp");
  } else {
    commands.push("bounty integrations preflight playwright-mcp browser.navigate --target <in-scope-url>");
    commands.push("bounty mcp plan playwright-mcp browser_navigate --target <in-scope-url> --arg url=<in-scope-url>");
    commands.push("bounty integrations approved-executables playwright-mcp");
    commands.push("bounty actions review --job <planned-job-id>");
  }

  if (!crawl4ai || crawl4ai.status !== "configured") {
    commands.push('bounty integrations setup crawl4ai --command "<absolute-path-to-crawl4ai>"');
  } else {
    commands.push("bounty integrations preflight crawl4ai crawler.fetch --target <in-scope-url>");
    commands.push("bounty run <in-scope-host> --dry-run --with crawl4ai");
    commands.push("bounty integrations approved-executables crawl4ai");
    commands.push("bounty review --job <planned-job-id>");
  }

  commands.push("bounty tools doctor");
  commands.push("bounty doctor");
  return [...new Set(commands)];
}

function integrationExecutionIntentRecorded(config: Record<string, unknown>): boolean {
  const execution = integrationRecord(config.execution);
  return config.allow_execute === true || execution.enabled === true;
}

function buildPlaywrightMcpSetup(_runtime: Runtime, options: IntegrationSetupOptions): IntegrationSetupResult {
  const packageName = parseNonEmptyTextOption(options.package, "package");
  const entrypoint = parseNonEmptyTextOption(options.entrypoint, "entrypoint");
  const timeoutMs = options.timeoutMs ? parsePositiveIntegerOption(options.timeoutMs, "timeout-ms", 30_000) : undefined;
  let detectedPackage: InspectedNpmPackageEntrypoint | undefined;
  const warnings: string[] = [];

  try {
    detectedPackage = inspectLocalPackageEntrypoint(
      {
        package: packageName,
        package_version: options.packageVersion,
        entrypoint,
      },
      process.cwd(),
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    warnings.push(
      `Could not inspect local package ${packageName}; setup remains planning/handoff-only. A reviewed package pin may be added later as metadata. ${message}`,
    );
  }

  const execution: Record<string, unknown> = {
    enabled: false,
    package: packageName,
    entrypoint,
    args: [],
  };
  const packageVersion = detectedPackage?.version ?? options.packageVersion;
  if (packageVersion) execution.package_version = packageVersion;
  if (detectedPackage) {
    execution.entrypoint_sha256 = detectedPackage.entrypointSha256;
    execution.package_json_sha256 = detectedPackage.packageJsonSha256;
  }
  if (timeoutMs) execution.timeout_ms = timeoutMs;

  const config: Record<string, unknown> = {
    enabled: true,
    type: "mcp",
    transport: "stdio",
    allow_execute: false,
    execution,
    capabilities: ["browser.navigate", "browser.snapshot"],
  };

  const nextCommands = [
    "bounty integrations doctor",
    "bounty integrations preflight playwright-mcp browser.navigate --target <in-scope-url>",
    "bounty mcp plan playwright-mcp browser_navigate --target <in-scope-url> --arg url=<in-scope-url>",
  ];
  nextCommands.push("bounty actions review --job <planned-job-id>");

  return {
    integration: "playwright_mcp",
    config,
    approvalCommand: options.approveExecutable ? process.execPath : undefined,
    detected: detectedPackage ? { summary: `${detectedPackage.name}@${detectedPackage.version}`, package: detectedPackage } : undefined,
    nextCommands,
    warnings,
  };
}

function buildCrawl4AiSetup(_runtime: Runtime, options: IntegrationSetupOptions): IntegrationSetupResult {
  if (!options.command) {
    throw new BountyPilotError("crawl4ai setup requires --command <absolute-path>.", "INTEGRATION_SETUP_COMMAND_REQUIRED");
  }
  const executable = resolveLocalExecutable(options.command);
  const timeoutMs = options.timeoutMs ? parsePositiveIntegerOption(options.timeoutMs, "timeout-ms", 30_000) : undefined;
  const config: Record<string, unknown> = {
    enabled: true,
    type: "crawler",
    allow_execute: false,
    command: executable.command,
    capabilities: ["crawler.fetch"],
  };
  if (timeoutMs) config.timeout_ms = timeoutMs;
  const nextCommands = [
    "bounty integrations doctor",
    "bounty integrations preflight crawl4ai crawler.fetch --target <in-scope-url>",
    "bounty run <in-scope-host> --dry-run --with crawl4ai",
  ];
  nextCommands.push("bounty review --job <planned-job-id>");
  return {
    integration: "crawl4ai",
    config,
    approvalCommand: options.approveExecutable ? executable.command : undefined,
    detected: { summary: executable.realPath, command: executable },
    nextCommands,
    warnings: [],
  };
}

function setIntegrationConfigValue(config: Record<string, unknown>, key: string, value: string): void {
  const pathParts = key.split(".");
  if (pathParts.some((part) => part.trim() === "")) {
    throw new BountyPilotError(`Invalid config key: ${key}`, "CONFIG_PAIR_INVALID");
  }
  if (pathParts.length === 1) {
    config[key] = parseIntegrationConfigValue(key, value);
    return;
  }

  const [rootKey, leafKey, ...rest] = pathParts;
  if (rootKey === "execution") {
    if (
      rest.length > 0 ||
      ![
        "enabled",
        "command",
        "args",
        "package",
        "package_version",
        "entrypoint",
        "entrypoint_sha256",
        "package_json_sha256",
        "timeout_ms",
      ].includes(leafKey)
    ) {
      throw new BountyPilotError(`Invalid execution config key: ${key}`, "CONFIG_PAIR_INVALID");
    }
    const execution = ensureNestedRecord(config, rootKey);
    execution[leafKey] = parseIntegrationConfigValue(leafKey, value);
    return;
  }
  if (rootKey === "options") {
    setNestedOptionValue(ensureNestedRecord(config, rootKey), [leafKey, ...rest], value);
    return;
  }

  throw new BountyPilotError(`Unknown nested integration config key: ${key}`, "CONFIG_PAIR_INVALID");
}

function ensureNestedRecord(config: Record<string, unknown>, key: string): Record<string, unknown> {
  const current = config[key];
  if (current === undefined) {
    const next: Record<string, unknown> = {};
    config[key] = next;
    return next;
  }
  if (!current || typeof current !== "object" || Array.isArray(current)) {
    throw new BountyPilotError(`Config key ${key} is not an object`, "CONFIG_PAIR_INVALID");
  }
  return current as Record<string, unknown>;
}

function setNestedOptionValue(config: Record<string, unknown>, pathParts: string[], value: string): void {
  if (pathParts.some((part) => part.trim() === "")) {
    throw new BountyPilotError("Invalid options config key", "CONFIG_PAIR_INVALID");
  }
  const [head, ...rest] = pathParts;
  if (rest.length === 0) {
    config[head] = parseConfigValue(value);
    return;
  }
  setNestedOptionValue(ensureNestedRecord(config, head), rest, value);
}

function parseConfigValue(value: string): string | boolean | number {
  if (value === "true") return true;
  if (value === "false") return false;
  const numeric = Number(value);
  if (value.trim() !== "" && Number.isFinite(numeric)) return numeric;
  return value;
}

function printSkillRunResult(result: SkillRunResult): void {
  ui.header("skill run");
  ui.status(result.ok ? (result.live ? "ok" : "planned") : "blocked", `${result.skill.id} ${result.mode} finished`);
  ui.panel("run", [
    ui.kv("program", result.program),
    ui.kv("target", result.target),
    ui.kv("mode", result.mode),
    ui.kv("live", result.live),
    ui.kv("dry run", result.dryRun),
    ui.kv("skill", result.skill.root),
    ui.kv("events", result.events.length),
  ]);
  if (result.warnings.length > 0) {
    ui.blank();
    ui.list("warnings", result.warnings);
  }
  if (result.blockers.length > 0) {
    ui.blank();
    ui.list("blockers", result.blockers);
  }
  if (result.recon) {
    ui.blank();
    ui.panel("recon", [
      ui.kv("job", result.recon.jobId),
      ui.kv("profile", result.recon.profile),
      ui.kv("tools", result.recon.tools.length),
      ui.kv("observations", result.recon.observations.length),
      ui.kv("evidence", result.recon.evidence.length),
      ui.kv("actions", result.recon.actionsPlanned),
    ]);
    ui.blank();
    ui.table(
      ["status", "tool", "executable pin", "observations", "message"],
      result.recon.tools.map((tool) => [tool.status, tool.tool, tool.approvalPresent, tool.observations, tool.message]),
    );
  }
  if (result.summary) {
    ui.blank();
    ui.panel("workflow", [
      ui.kv("job", result.summary.jobId),
      ui.kv("status", result.summary.status),
      ui.kv("components", result.summary.components.join(",")),
      ui.kv("findings", result.summary.findingsCreated),
      ui.kv("evidence", result.summary.evidenceCreated),
      ui.kv("actions", result.summary.actionsPlanned),
      ui.kv("pending", result.summary.actionCounts.pending),
      ui.kv("blocked", result.summary.actionCounts.blocked),
      ui.kv("summary", result.summary.summaryPath),
    ]);
    ui.blank();
    ui.table(
      ["phase", "target", "status", "detail"],
      result.summary.phases.map((phase) => [phase.name, phase.target ?? "", phase.status, phase.detail]),
    );
  }
  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

function printWorkflowSummary(summary: WorkflowSummary, message = "workflow finished"): void {
  ui.status(workflowStatusLabel(summary.status), message);
  ui.panel("summary", [
    ui.kv("job", summary.jobId),
    ui.kv("status", summary.status),
    ui.kv("program", summary.program),
    ui.kv("mode", summary.mode),
    ui.kv("seeds", summary.seeds.length),
    ui.kv("findings", summary.findingsCreated),
    ui.kv("evidence", summary.evidenceCreated),
    ui.kv("actions", summary.actionsPlanned),
    ui.kv("pending", summary.actionCounts.pending),
    ui.kv("approved", summary.actionCounts.approved),
    ui.kv("executed", summary.actionCounts.executed),
    ui.kv("blocked", summary.actionCounts.blocked),
    ui.kv("failed", summary.actionCounts.failed),
    ui.kv("reports", summary.reportsDrafted),
    ui.kv("summary", summary.summaryPath),
    ui.kv("checkpoint", summary.checkpointPath),
  ]);
  if (summary.skippedScopeRules.length > 0) {
    ui.blank();
    ui.list("skipped scope rules", summary.skippedScopeRules);
  }
  ui.blank();
  ui.table(
    ["phase", "target", "status", "detail"],
    summary.phases.map((phase) => [phase.name, phase.target ?? "", phase.status, phase.detail]),
  );
  printWorkflowNextCommands(summary);
}

function printWorkflowNextCommands(summary: WorkflowSummary): void {
  const commands = [`bounty jobs show ${summary.jobId}`, `bounty jobs timeline ${summary.jobId}`];
  if (summary.status === "failed" || summary.status === "paused" || summary.status === "queued") {
    commands.push(`bounty jobs resume ${summary.jobId}`);
  }
  if (summary.actionCounts.pending > 0) {
    commands.push(`bounty actions list --job ${summary.jobId} --pending`);
  }
  if (summary.actionCounts.approved > 0) {
    commands.push(`bounty actions run-approved --job ${summary.jobId}`);
  }
  commands.push("bounty dashboard");
  ui.blank();
  ui.commandList("next commands", commands);
}

function printQuickstartRunbook(runbook: QuickstartRunbook): void {
  ui.status(
    runbook.status === "ready" ? "ok" : runbook.status === "needs_review" ? "warn" : "blocked",
    `quickstart ${runbook.status}`,
  );
  ui.panel("runbook", [
    ui.kv("profile", runbook.profile.id),
    ui.kv("target", runbook.target ?? "<in-scope-target>"),
    ui.kv("workspace", runbook.workspace.found),
    ui.kv("program", runbook.program?.name),
    ui.kv("providers", `${runbook.providers.configured}/${runbook.providers.total}`),
    ui.kv("tools", `${runbook.tools.available}/${runbook.tools.total}`),
    ui.kv("arsenal", `${runbook.arsenal.installed}/${runbook.arsenal.total}`),
    ui.kv("results", runbook.results?.findingsIncluded),
    ui.kv("output", runbook.outputPath),
  ]);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    runbook.checks.map((check) => [check.status, check.name, check.message]),
  );
  ui.blank();
  ui.table(
    ["status", "phase", "summary"],
    runbook.sections.map((section) => [section.status, section.title, section.summary]),
  );
  for (const section of runbook.sections) {
    ui.blank();
    ui.commandList(section.title.toLowerCase(), section.commands);
  }
  ui.blank();
  ui.commandList("next commands", runbook.nextCommands);
}

function loadPlannerSourceSummary(runtime: Runtime, jobId: string): WorkflowSummary {
  const job = runtime.jobs.get(jobId);
  if (!job) {
    throw new BountyPilotError(`Job not found: ${jobId}`, "JOB_NOT_FOUND");
  }
  const summary = new WorkflowRunner(runtime).loadSummary(jobId);
  if (!summary) {
    throw new BountyPilotError(`Workflow summary not found for job: ${jobId}`, "WORKFLOW_SUMMARY_NOT_FOUND");
  }
  return summary;
}

function plannerFeedbackEvidence(runtime: Runtime, sourceSummary: WorkflowSummary | undefined, currentJobId: string): EvidenceArtifact[] {
  const jobIds = plannerSourceJobIds(sourceSummary, currentJobId);
  return runtime.evidence.list().filter((artifact) => artifact.jobId !== undefined && jobIds.has(artifact.jobId));
}

function plannerFeedbackFindings(runtime: Runtime, sourceSummary: WorkflowSummary | undefined, currentJobId: string) {
  const jobIds = plannerSourceJobIds(sourceSummary, currentJobId);
  return runtime.findings
    .list()
    .filter((finding) => runtime.evidence.list(finding.id).some((artifact) => artifact.jobId !== undefined && jobIds.has(artifact.jobId)));
}

function plannerActionContext(
  runtime: Runtime,
  sourceSummary: WorkflowSummary | undefined,
  currentJobId: string,
): PlannerActionContext[] {
  const jobIds = plannerSourceJobIds(sourceSummary, currentJobId);
  return [...jobIds].flatMap((jobId) =>
    runtime.actions.list(jobId).map((action) => ({
      adapter: action.adapter,
      actionType: action.actionType,
      target: action.target,
      status: action.status,
    })),
  );
}

function plannerSourceJobIds(sourceSummary: WorkflowSummary | undefined, currentJobId: string): Set<string> {
  return new Set(
    [currentJobId, sourceSummary?.jobId, sourceSummary?.resumedFromJobId].filter((jobId): jobId is string => Boolean(jobId)),
  );
}

function printWorkspaceSummary(summary: WorkspaceSummary): void {
  ui.status("ok", "workspace summary ready");
  ui.panel("workspace", [
    ui.kv("program", summary.program.name),
    ui.kv("platform", summary.program.platform),
    ui.kv("rate limit", summary.program.rateLimit),
    ui.kv("in scope", summary.scope.inScope),
    ui.kv("out scope", summary.scope.outOfScope),
    ui.kv("evidence", summary.evidence.total),
    ui.kv("reports", summary.reports.files),
  ]);
  ui.blank();
  ui.panel("workflow", [
    ui.kv("jobs", summary.jobs.total),
    ui.kv("completed", summary.jobs.byStatus.completed),
    ui.kv("running", summary.jobs.byStatus.running),
    ui.kv("failed", summary.jobs.byStatus.failed),
    ui.kv("events", summary.timeline.totalEvents),
    ui.kv("actions", summary.actions.total),
    ui.kv("pending", summary.actions.pending),
    ui.kv("approved", summary.actions.approved),
    ui.kv("executed", summary.actions.executed),
  ]);
  ui.blank();
  ui.panel("findings", [
    ui.kv("total", summary.findings.total),
    ui.kv("critical", summary.findings.bySeverity.critical),
    ui.kv("high", summary.findings.bySeverity.high),
    ui.kv("medium", summary.findings.bySeverity.medium),
    ui.kv("low", summary.findings.bySeverity.low),
    ui.kv("info", summary.findings.bySeverity.info),
    ui.kv("avg score", `${summary.findings.averageReportabilityScore}/100`),
    ui.kv("ready", summary.triage.readyForDraft),
  ]);
  if (summary.findings.topReportable.length > 0) {
    ui.blank();
    ui.table(
      ["score", "severity", "status", "recommendation", "id", "title"],
      summary.findings.topReportable.map((finding) => [
        finding.reportabilityScore,
        finding.severity,
        finding.status,
        finding.triageRecommendation,
        finding.id,
        finding.title,
      ]),
    );
  }
  if (summary.jobs.recent.length > 0) {
    ui.blank();
    ui.table(
      ["status", "mode", "type", "id", "target"],
      summary.jobs.recent.map((job) => [job.status, job.mode, job.type, job.id, job.target]),
    );
  }
  if (summary.timeline.recent.length > 0) {
    ui.blank();
    ui.table(
      ["time", "status", "phase", "job", "message"],
      summary.timeline.recent.map((event) => [
        event.createdAt,
        event.status,
        event.phase,
        event.jobId,
        event.message,
      ]),
    );
  }
  ui.blank();
  ui.list("next actions", summary.nextActions);
}

function printCockpitSnapshot(snapshot: CockpitSnapshot): void {
  ui.status(
    snapshot.status === "ready" ? "ok" : snapshot.status === "needs_review" ? "warn" : "blocked",
    `cockpit refresh ${snapshot.refresh}: ${snapshot.status}`,
  );
  ui.panel("workspace", [
    ui.kv("program", snapshot.workspace.program.name),
    ui.kv("platform", snapshot.workspace.program.platform),
    ui.kv("focus", snapshot.focus.mode),
    ui.kv("job", snapshot.focus.jobId),
    ui.kv("scope", `${snapshot.workspace.scope.inScope}/${snapshot.workspace.scope.outOfScope}`),
    ui.kv("jobs", snapshot.workspace.jobs.total),
    ui.kv("actions", snapshot.workspace.actions.total),
    ui.kv("pending", snapshot.workspace.actions.pending),
    ui.kv("findings", snapshot.workspace.findings.total),
    ui.kv("ready", snapshot.workspace.triage.readyForDraft),
    ui.kv("evidence", snapshot.workspace.evidence.total),
    ui.kv("recon", snapshot.recon.workspace.total),
  ]);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    snapshot.checks.map((check) => [check.status, check.name, check.message]),
  );

  if (snapshot.jobReview) {
    ui.blank();
    ui.panel("job focus", [
      ui.kv("id", snapshot.jobReview.job.id),
      ui.kv("target", snapshot.jobReview.job.target),
      ui.kv("status", snapshot.jobReview.summary?.status ?? snapshot.jobReview.job.status),
      ui.kv("health", snapshot.jobReview.cockpit.status),
      ui.kv("actions", snapshot.jobReview.actionCounts.total),
      ui.kv("evidence", snapshot.jobReview.evidence.total),
      ui.kv("findings", snapshot.jobReview.findings.total),
    ]);
  }

  if (snapshot.workspace.jobs.recent.length > 0) {
    ui.blank();
    ui.table(
      ["status", "mode", "type", "id", "target"],
      snapshot.workspace.jobs.recent.map((job) => [job.status, job.mode, job.type, job.id, job.target]),
    );
  }

  ui.blank();
  ui.panel("recon", [
    ui.kv("workspace", snapshot.recon.workspace.total),
    ui.kv("in scope", snapshot.recon.workspace.inScope),
    ui.kv("out scope", snapshot.recon.workspace.outOfScope),
    ui.kv("focus", snapshot.recon.focus?.total),
  ]);
  if (Object.keys(snapshot.recon.workspace.byKind).length > 0) {
    ui.table(
      ["kind", "count"],
      Object.entries(snapshot.recon.workspace.byKind).map(([kind, count]) => [kind, count]),
    );
  }
  if (snapshot.recon.workspace.samples.length > 0) {
    ui.blank();
    ui.table(
      ["kind", "scope", "source", "id", "value"],
      snapshot.recon.workspace.samples.map((observation) => [
        observation.kind,
        observation.scopeAllowed,
        observation.sourceAdapter,
        observation.id,
        observation.value,
      ]),
    );
  }

  ui.blank();
  ui.panel("providers/tools", [
    ui.kv("providers", `${snapshot.providers.configured}/${snapshot.providers.total}`),
    ui.kv("tools", `${snapshot.tools.available}/${snapshot.tools.total}`),
    ui.kv("approvals", snapshot.tools.approvedExecutables),
    ui.kv("review req", snapshot.tools.reviewRequired.length),
  ]);
  if (snapshot.providers.records.length > 0) {
    ui.table(
      ["status", "provider", "model", "auth"],
      snapshot.providers.records.map((provider) => [
        provider.status,
        provider.id,
        provider.model,
        provider.auth.type === "env" ? `env:${provider.auth.source ?? "-"}` : provider.auth.type,
      ]),
    );
  }
  if (snapshot.tools.topMissing.length > 0) {
    ui.blank();
    ui.table(
      ["status", "tool", "message"],
      snapshot.tools.topMissing.map((tool) => [tool.status, tool.name, tool.message]),
    );
  }
  if (snapshot.workspace.findings.topReportable.length > 0) {
    ui.blank();
    ui.table(
      ["score", "severity", "recommendation", "id", "title"],
      snapshot.workspace.findings.topReportable.map((finding) => [
        finding.reportabilityScore,
        finding.severity,
        finding.triageRecommendation,
        finding.id,
        finding.title,
      ]),
    );
  }
  ui.blank();
  ui.commandList("next commands", snapshot.nextCommands);
}

function printResultsBoard(board: ResultsBoard): void {
  ui.status(
    board.status === "ready" ? "ok" : "warn",
    board.status === "ready"
      ? `${board.totals.readyForDraft} report-ready finding(s)`
      : board.status === "needs_review"
        ? `${board.totals.findingsIncluded} finding candidate(s) need review`
        : "no bug result candidates matched the current filters",
  );
  ui.panel("results", [
    ui.kv("program", board.program.name),
    ui.kv("job", board.job?.id),
    ui.kv("considered", board.totals.findingsConsidered),
    ui.kv("included", board.totals.findingsIncluded),
    ui.kv("ready", board.totals.readyForDraft),
    ui.kv("review", board.totals.needsReview),
    ui.kv("blocked", board.totals.blocked),
    ui.kv("evidence", board.totals.evidenceArtifacts),
    ui.kv("signals", board.reconSignals.total),
    ui.kv("min score", board.filters.minScore),
  ]);
  if (board.findings.length > 0) {
    ui.blank();
    ui.table(
      ["score", "ready", "severity", "evidence", "status", "id", "title"],
      board.findings.map((finding) => [
        finding.score,
        finding.readiness,
        finding.severity,
        finding.evidence,
        finding.status,
        finding.id,
        finding.title,
      ]),
    );
    const findingsWithBlockers = board.findings.filter((finding) => finding.blockers.length > 0).slice(0, 3);
    if (findingsWithBlockers.length > 0) {
      ui.blank();
      ui.table(
        ["finding", "blocker"],
        findingsWithBlockers.flatMap((finding) =>
          finding.blockers.slice(0, 2).map((blocker) => [finding.id, blocker]),
        ),
      );
    }
  } else {
    ui.blank();
    ui.status("warn", "no findings matched; use recon/playbooks or lower --min-score");
  }
  if (board.reconSignals.samples.length > 0) {
    ui.blank();
    ui.table(
      ["kind", "confidence", "source", "id", "value"],
      board.reconSignals.samples.map((signal) => [
        signal.kind,
        signal.confidence,
        signal.sourceAdapter,
        signal.id,
        signal.value,
      ]),
    );
  }
  ui.blank();
  ui.commandList("next commands", board.nextCommands);
}

function printWorkflowTimeline(events: WorkflowEventRecord[], title = "workflow timeline"): void {
  ui.blank();
  if (events.length === 0) {
    ui.status("warn", "no workflow events found");
    return;
  }
  ui.list(title, [`${events.length} events`]);
  ui.table(
    ["#", "time", "status", "phase", "message"],
    events.map((event) => [event.sequence, event.createdAt, event.status, event.phase, event.message]),
  );
}

function printReleaseCheck(result: ReturnType<typeof runReleaseCheck>): void {
  ui.status(result.ok ? "ok" : "error", result.ok ? "release checks passed" : "release checks failed");
  ui.panel("package", [
    ui.kv("name", result.packageName),
    ui.kv("version", result.version),
    ui.kv("cwd", result.cwd),
    ui.kv("checks", result.checks.length),
    ui.kv("failed", result.checks.filter((check) => check.status === "fail").length),
    ui.kv("warnings", result.checks.filter((check) => check.status === "warn").length),
  ]);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    result.checks.map((check) => [check.status, check.name, check.message]),
  );
}

function printBetaReadiness(result: BetaReadinessResult): void {
  ui.status(
    result.status === "ready" ? "ok" : result.status === "needs_review" ? "warn" : "error",
    result.status === "ready" ? "ready for beta handoff" : result.status === "needs_review" ? "beta readiness needs review" : "beta readiness blocked",
  );
  ui.panel("readiness", [
    ui.kv("score", `${result.score}/100`),
    ui.kv("status", result.status),
    ui.kv("package", result.release.packageName),
    ui.kv("version", result.release.version),
    ui.kv("workspace", result.workspace.path),
    ui.kv("programs", result.programs.count),
    ui.kv("blockers", result.blockers.length),
    ui.kv("warnings", result.warnings.length),
    ui.kv("report", result.reportPath),
  ]);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    result.checks.map((check) => [check.status, check.name, check.message]),
  );
  if (result.blockers.length > 0) {
    ui.blank();
    ui.list("blockers", result.blockers);
  }
  if (result.warnings.length > 0) {
    ui.blank();
    ui.list("warnings", result.warnings);
  }
  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

function printBetaChecklist(result: BetaChecklistResult): void {
  ui.status(
    result.status === "ready" ? "ok" : result.status === "needs_review" ? "warn" : "error",
    result.status === "ready" ? "beta checklist ready" : result.status === "needs_review" ? "beta checklist needs review" : "beta checklist blocked",
  );
  ui.panel("handoff", [
    ui.kv("score", `${result.score}/100`),
    ui.kv("status", result.status),
    ui.kv("package", result.readiness.release.packageName),
    ui.kv("version", result.readiness.release.version),
    ui.kv("workspace", result.readiness.workspace.path),
    ui.kv("programs", result.readiness.programs.count),
    ui.kv("blockers", result.readiness.blockers.length),
    ui.kv("warnings", result.readiness.warnings.length),
    ui.kv("checklist", result.outputPath),
  ]);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    result.readiness.checks.map((check) => [check.status, check.name, check.message]),
  );
  if (result.outputPath) {
    ui.blank();
    ui.status("ok", `wrote ${result.outputPath}`);
  }
  ui.blank();
  ui.commandList("handoff commands", result.nextCommands);
}

function printProviderSummary(provider: ProviderSummary): void {
  ui.panel("provider", [
    ui.kv("id", provider.id),
    ui.kv("name", provider.displayName),
    ui.kv("type", provider.type),
    ui.kv("enabled", provider.enabled),
    ui.kv("status", provider.status),
    ui.kv("auth", provider.auth.type === "env" ? `env:${provider.auth.source}` : provider.auth.type),
    ui.kv("auth ok", provider.auth.present),
    ui.kv("base url", provider.baseURL),
    ui.kv("model", provider.model),
    ui.kv("models", provider.models.length),
    ui.kv("config", provider.configPath),
    ui.kv("auth file", provider.authPath),
  ]);
}

function printProviderVerification(result: ProviderVerifyResult): void {
  ui.status(result.ok ? "ok" : "blocked", result.ok ? "provider ready" : "provider needs attention");
  printProviderSummary(result.provider);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    result.checks.map((check) => [check.status, check.name, check.message]),
  );
  if (result.live) {
    ui.blank();
    ui.panel("live", [
      ui.kv("ok", result.live.ok),
      ui.kv("status", result.live.status),
      ui.kv("models", result.live.models),
      ui.kv("message", result.live.message),
    ]);
  }
  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

function printHuntPlan(result: HuntPlanPayload): void {
  ui.panel("hunt", [
    ui.kv("program", result.program),
    ui.kv("target", result.target),
    ui.kv("profile", result.profile.id),
    ui.kv("mode", result.profile.mode),
    ui.kv("components", result.profile.components.join(",")),
    ui.kv("plan", result.planPath),
  ]);
  ui.blank();
  ui.list("phases", result.phases);
  ui.blank();
  ui.list("validation gates", result.validationGates);
  ui.blank();
  ui.table(
    ["tool", "status", "message"],
    result.tools.map((tool) => [tool.name, tool.status, tool.message]),
  );
  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

function printHuntDoctor(result: HuntDoctorResult): void {
  ui.status(result.ok ? "ok" : "blocked", result.ok ? "hunt workspace ready" : "hunt workspace blocked");
  ui.panel("profile", [
    ui.kv("profile", result.profile.id),
    ui.kv("mode", result.profile.mode),
    ui.kv("target", result.target),
    ui.kv("providers", result.providers.length),
    ui.kv("tools", result.tools.length),
    ui.kv("arsenal", result.arsenal.length),
  ]);
  ui.blank();
  ui.table(
    ["status", "check", "message"],
    result.checks.map((check) => [check.status, check.name, check.message]),
  );
  ui.blank();
  ui.table(
    ["tool", "installed", "policy", "message"],
    result.arsenal.map((tool) => [tool.name, tool.installed, tool.policy, tool.message]),
  );
  ui.blank();
  ui.commandList("next commands", result.nextCommands);
}

function cliPackageRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
}

function workflowSummaryForDisplay(runtime: Runtime, summary: WorkflowSummary): WorkflowSummary {
  const job = runtime.jobs.get(summary.jobId);
  return {
    ...summary,
    status: job?.status ?? summary.status,
    updatedAt: job?.updatedAt ?? summary.updatedAt,
    ...(job?.status === "completed" && !summary.completedAt ? { completedAt: job.updatedAt } : {}),
    ...(job?.status === "failed" && !summary.failedAt ? { failedAt: job.updatedAt } : {}),
    actionCounts: runtime.actions.summarize(summary.jobId),
  };
}

function workflowStatusLabel(status: WorkflowSummary["status"]): "ok" | "warn" | "error" | "blocked" | "planned" | "running" {
  if (status === "failed") return "error";
  if (status === "running") return "running";
  if (status === "paused" || status === "queued") return "planned";
  return "ok";
}

function reportReadinessStatusLabel(readiness: ReportReadiness): "ok" | "warn" | "error" | "blocked" | "planned" | "running" {
  if (readiness === "ready_for_draft") return "ok";
  if (readiness === "blocked") return "blocked";
  return "warn";
}

function integrationStatusLabel(status: string): "ok" | "warn" | "error" | "blocked" | "planned" | "running" {
  if (status === "configured") return "ok";
  if (status === "planned") return "planned";
  if (status === "disabled" || status === "not_configured") return "warn";
  return "error";
}
