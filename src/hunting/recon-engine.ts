import path from "node:path";
import { Buffer } from "node:buffer";
import type { Runtime } from "../cli/runtime.js";
import { createJobAuditLogger } from "../cli/runtime.js";
import { DuplicateRiskEngine } from "../engines/duplicate-risk/duplicate-risk-engine.js";
import { evaluateFindingCandidateReadiness } from "../engines/finding-candidates/finding-candidate-engine.js";
import { analyzeJavaScript } from "../engines/js-analyzer/js-analyzer.js";
import { generateReproductionNote } from "../engines/report-generator/report-generator.js";
import { runSafeChecks } from "../engines/safe-checks/safe-checks.js";
import { TriageEngine } from "../engines/triage/triage-engine.js";
import { fetchScopedText } from "../core/http/scoped-fetch.js";
import { ToolManager } from "../integrations/tool-manager/tool-manager.js";
import { ToolAdapterRunner, latestToolApproval } from "../integrations/tool-manager/tool-adapter-runner.js";
import type {
  BugClass,
  Confidence,
  EvidenceArtifact,
  ExecutionMode,
  FindingCandidate,
  PlaybookResult,
  ReconObservation,
  RiskLevel,
  SeverityEstimate,
} from "../types.js";
import { BountyPilotError } from "../utils/errors.js";
import { maskSecrets } from "../utils/secrets.js";

export type HuntReconProfile = "passive" | "web";

export interface HuntReconOptions {
  profile: HuntReconProfile;
  live: boolean;
  tools?: string[];
}

export interface HuntReconToolResult {
  tool: string;
  actionType: string;
  status: "planned" | "pending" | "executed" | "skipped" | "blocked" | "failed";
  actionId?: string;
  approvalPresent: boolean;
  observations: number;
  evidencePath?: string;
  message: string;
}

export interface HuntReconResult {
  ok: boolean;
  profile: HuntReconProfile;
  target: string;
  live: boolean;
  jobId: string;
  mode: ExecutionMode;
  tools: HuntReconToolResult[];
  observations: ReconObservation[];
  evidence: EvidenceArtifact[];
  actionsPlanned: number;
  nextCommands: string[];
}

export const BUG_CLASSES: BugClass[] = ["xss", "ssrf", "idor", "graphql", "cors", "open-redirect", "js-secrets", "exposure"];

const PASSIVE_RECON_TOOLS = ["subfinder", "gau", "waybackurls"];
const WEB_RECON_TOOLS = ["subfinder", "gau", "waybackurls", "dnsx", "httpx", "katana", "nuclei", "ffuf", "dalfox", "naabu"];
const REVIEW_REQUIRED_RECON_TOOLS = new Set(["nuclei", "ffuf", "dalfox", "naabu"]);

export async function runHuntRecon(runtime: Runtime, target: string, options: HuntReconOptions): Promise<HuntReconResult> {
  const scoped = runtime.scopeGuard.assertAllowed(target);
  const mode: ExecutionMode = options.profile === "web" ? "deep-safe" : "safe";
  const job = runtime.jobs.create("hunt-recon", mode, scoped.url);
  runtime.jobs.updateStatus(job.id, "running");
  runtime.events.record({
    jobId: job.id,
    phase: "hunt-recon",
    status: "running",
    message: `${options.profile} recon started.`,
    metadata: { target: scoped.url, live: options.live },
  });

  const manager = new ToolManager();
  const selectedTools = normalizeToolSelection(options.tools, options.profile);
  const runner = new ToolAdapterRunner(runtime);
  const toolResults: HuntReconToolResult[] = [];
  const evidence: EvidenceArtifact[] = [];
  const observations: ReconObservation[] = [];
  let actionsPlanned = 0;

  const planArtifact = runtime.evidence.writeTextArtifact({
    jobId: job.id,
    adapterName: "hunt-recon",
    kind: "research_note",
    sourceUrl: scoped.url,
    relativePath: path.join(job.id, "recon-plan.json"),
    content: `${JSON.stringify({ target: scoped.url, profile: options.profile, live: options.live, tools: selectedTools }, null, 2)}\n`,
  });
  evidence.push(planArtifact);

  for (const toolName of selectedTools) {
    const tool = manager.get(toolName);
    if (!tool) {
      toolResults.push({
        tool: toolName,
        actionType: "unknown",
        status: "skipped",
        approvalPresent: false,
        observations: 0,
        message: "Tool is not in the trusted registry.",
      });
      continue;
    }
    const actionType = tool.actions[0]?.action_type;
    if (!actionType) {
      toolResults.push({
        tool: tool.name,
        actionType: "unknown",
        status: "skipped",
        approvalPresent: false,
        observations: 0,
        message: "Tool has no trusted action metadata.",
      });
      continue;
    }
    const validation = manager.validateRunPlan({
      tool: tool.name,
      mode,
      actionType,
      target: scoped.url,
      labModeEnabled: runtime.config.rules.lab_mode === true,
      programRules: runtime.config.rules,
    });
    const approvalPresent = Boolean(latestToolApproval(runtime, tool.name));
    const requiresApproval = validation.requiresApproval || REVIEW_REQUIRED_RECON_TOOLS.has(tool.name);
    const action = runtime.actions.enqueue({
      jobId: job.id,
      adapter: "tool-manager",
      actionType,
      target: scoped.url,
      riskLevel: validation.riskLevel ?? (tool.permissions.active_scanning ? "medium" : "low"),
      requiresApproval,
      metadata: { tool: tool.name, reconProfile: options.profile },
      status: validation.allowed ? undefined : "blocked",
    });
    actionsPlanned += 1;
    createJobAuditLogger(runtime.paths, job.id).log({
      jobId: job.id,
      actionType,
      url: scoped.url,
      adapterName: tool.name,
      policyDecision: validation.allowed ? (requiresApproval ? "require_approval" : "allow") : "block",
      reason: validation.reasons.join("; "),
      metadata: { actionId: action.id, approvalPresent, live: options.live },
    });

    if (!validation.allowed) {
      toolResults.push({
        tool: tool.name,
        actionType,
        status: "blocked",
        actionId: action.id,
        approvalPresent,
        observations: 0,
        message: validation.reasons.join("; "),
      });
      continue;
    }
    if (!options.live) {
      toolResults.push({
        tool: tool.name,
        actionType,
        status: requiresApproval ? "pending" : "planned",
        actionId: action.id,
        approvalPresent,
        observations: 0,
        message: "Dry-run planned this tool without execution.",
      });
      continue;
    }
    if (requiresApproval) {
      toolResults.push({
        tool: tool.name,
        actionType,
        status: "pending",
        actionId: action.id,
        approvalPresent,
        observations: 0,
        message: "Tool requires human review before execution.",
      });
      continue;
    }
    if (!approvalPresent) {
      toolResults.push({
        tool: tool.name,
        actionType,
        status: "skipped",
        actionId: action.id,
        approvalPresent,
        observations: 0,
        message: "Executable is not approved for this tool.",
      });
      continue;
    }

    try {
      const result = await runner.execute({
        tool: tool.name,
        actionType,
        target: scoped.url,
        mode,
        jobId: job.id,
      });
      evidence.push(result.evidence);
      observations.push(...result.observations);
      if (result.exitCode === 0 && !result.timedOut) {
        runtime.actions.markExecuted(action.id);
        toolResults.push({
          tool: tool.name,
          actionType,
          status: "executed",
          actionId: action.id,
          approvalPresent,
          observations: result.observations.length,
          evidencePath: result.evidence.path,
          message: "Tool completed.",
        });
      } else {
        runtime.actions.fail(action.id);
        toolResults.push({
          tool: tool.name,
          actionType,
          status: result.timedOut ? "failed" : "failed",
          actionId: action.id,
          approvalPresent,
          observations: result.observations.length,
          evidencePath: result.evidence.path,
          message: result.timedOut ? "Tool timed out." : `Tool exited with code ${result.exitCode}.`,
        });
      }
    } catch (error) {
      runtime.actions.fail(action.id);
      toolResults.push({
        tool: tool.name,
        actionType,
        status: "failed",
        actionId: action.id,
        approvalPresent,
        observations: 0,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const hasFailures = toolResults.some((result) => result.status === "failed");
  const hasPending = toolResults.some((result) => result.status === "pending" || result.status === "planned" || result.status === "skipped");
  runtime.jobs.updateStatus(job.id, hasFailures ? "failed" : hasPending ? "paused" : "completed");
  runtime.events.record({
    jobId: job.id,
    phase: "hunt-recon",
    status: hasFailures ? "failed" : "completed",
    message: `Recon finished with ${observations.length} scoped observation(s).`,
    metadata: { tools: toolResults, evidence: evidence.length, actionsPlanned },
  });

  return {
    ok: !hasFailures,
    profile: options.profile,
    target: scoped.url,
    live: options.live,
    jobId: job.id,
    mode,
    tools: toolResults,
    observations,
    evidence,
    actionsPlanned,
    nextCommands: reconNextCommands(job.id, toolResults),
  };
}

export async function runHuntPlaybook(runtime: Runtime, bugClass: BugClass, target: string, live: boolean): Promise<PlaybookResult> {
  if (!BUG_CLASSES.includes(bugClass)) {
    throw new BountyPilotError(`Unsupported playbook: ${bugClass}`, "HUNT_PLAYBOOK_UNKNOWN");
  }
  const scoped = runtime.scopeGuard.assertAllowed(target);
  const mode: ExecutionMode = "deep-safe";
  const job = runtime.jobs.create("hunt-playbook", mode, scoped.url);
  runtime.jobs.updateStatus(job.id, "running");
  const evidence: EvidenceArtifact[] = [];
  const observations: ReconObservation[] = [];
  const findingsCreated: PlaybookResult["findingsCreated"] = [];
  let actionsPlanned = 0;

  const plan = runtime.evidence.writeTextArtifact({
    jobId: job.id,
    adapterName: "hunt-playbook",
    kind: "research_note",
    sourceUrl: scoped.url,
    relativePath: path.join(job.id, `${bugClass}-playbook-plan.json`),
    content: `${JSON.stringify({ bugClass, target: scoped.url, live, checks: playbookChecks(bugClass) }, null, 2)}\n`,
  });
  evidence.push(plan);

  for (const action of playbookActions(bugClass)) {
    const decision = runtime.policyGate.evaluate({
      mode,
      actionType: action.actionType,
      target: scoped.url,
      riskLevel: action.riskLevel,
      capability: action.capability,
      requiresApprovalByDefault: action.requiresApproval,
      labModeEnabled: runtime.config.rules.lab_mode === true,
    });
    const queued = runtime.actions.enqueue({
      jobId: job.id,
      adapter: action.adapter,
      actionType: action.actionType,
      target: scoped.url,
      riskLevel: action.riskLevel,
      requiresApproval: decision.decision === "require_approval" || action.requiresApproval === true,
      metadata: { bugClass },
      status: decision.decision === "block" ? "blocked" : undefined,
    });
    actionsPlanned += 1;
    createJobAuditLogger(runtime.paths, job.id).log({
      jobId: job.id,
      actionType: action.actionType,
      url: scoped.url,
      adapterName: action.adapter,
      policyDecision: decision.decision,
      reason: decision.reason,
      metadata: { actionId: queued.id, bugClass },
    });
  }

  observations.push(...recordStaticPlaybookObservations(runtime, job.id, bugClass, scoped.url));

  if (live) {
    await runtime.rateLimiter.wait(scoped.url);
    const safe = await runSafeChecks(scoped.url);
    const safeArtifact = runtime.evidence.writeTextArtifact({
      jobId: job.id,
      adapterName: "safe-checks",
      kind: "tool_output",
      sourceUrl: scoped.url,
      relativePath: path.join(job.id, `${bugClass}-safe-checks.json`),
      content: `${JSON.stringify(safe, null, 2)}\n`,
    });
    evidence.push(safeArtifact);

    for (const candidate of safe.findings.filter((finding) => safeFindingMatchesPlaybook(finding.category, bugClass))) {
      findingsCreated.push(createFindingFromSignal(runtime, {
        title: candidate.title,
        url: scoped.url,
        category: candidate.category,
        severity: candidate.severityEstimate,
        confidence: candidate.confidence,
        evidence: safeArtifact,
        remediation: candidate.remediation,
      }));
    }

    if (bugClass === "cors") {
      const validation = await validateCorsCandidate(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
        wait: async (requestUrl) => {
          await runtime.rateLimiter.wait(runtime.scopeGuard.assertAllowed(requestUrl).url);
        },
      });
      if (validation.checked) {
        const corsArtifact = runtime.evidence.writeTextArtifact({
          jobId: job.id,
          adapterName: "hunt-playbook",
          kind: "tool_output",
          sourceUrl: scoped.url,
          relativePath: path.join(job.id, "cors-validation.json"),
          content: `${JSON.stringify(validation, null, 2)}\n`,
        });
        evidence.push(corsArtifact);
        if (validation.corsCandidate || validation.hasCorsHeaders) {
          observations.push(runtime.recon.upsert({
            jobId: job.id,
            kind: validation.corsCandidate ? "finding_candidate" : "vulnerability_signal",
            value: scoped.url,
            sourceAdapter: "hunt-playbook",
            sourceUrl: scoped.url,
            scopeAllowed: true,
            confidence: validation.corsCandidate ? validation.confidence : "low",
            riskHint: validation.corsCandidate ? validation.riskHint : "low",
            metadata: { bugClass, validation },
          }));
        }
        if (validation.corsCandidate) {
          const existingCorsFindings = findingsCreated.filter((finding) => finding.category === "cors");
          if (existingCorsFindings.length === 0) {
            findingsCreated.push(createFindingFromSignal(runtime, {
              title: validation.credentialedReflectedOrigin
                ? "Credentialed CORS reflects an untrusted Origin header"
                : "Permissive CORS response observed",
              url: scoped.url,
              category: "cors",
              severity: validation.riskHint,
              confidence: validation.confidence,
              evidence: corsArtifact,
              remediation: "Use an explicit allowlist of trusted origins and avoid credentialed CORS for untrusted origins.",
            }));
          } else {
            for (const finding of existingCorsFindings) {
              runtime.evidence.linkToFinding(corsArtifact.id, finding.id);
              const updated = runtime.findings.linkEvidencePath(finding.id, corsArtifact.path);
              finding.evidencePaths = updated.evidencePaths;
              finding.updatedAt = updated.updatedAt;
            }
          }
        }
      }
    }

    if (bugClass === "ssrf") {
      const validation = await validateSsrfServerFetchCandidate(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
        labModeEnabled: runtime.config.rules.lab_mode === true,
        wait: async (requestUrl) => {
          await runtime.rateLimiter.wait(runtime.scopeGuard.assertAllowed(requestUrl).url);
        },
      });
      if (validation.checked) {
        const ssrfArtifact = runtime.evidence.writeTextArtifact({
          jobId: job.id,
          adapterName: "hunt-playbook",
          kind: "tool_output",
          sourceUrl: scoped.url,
          relativePath: path.join(job.id, "ssrf-server-fetch-validation.json"),
          content: `${JSON.stringify(validation, null, 2)}\n`,
        });
        evidence.push(ssrfArtifact);
        observations.push(runtime.recon.upsert({
          jobId: job.id,
          kind: validation.ssrfCandidate ? "finding_candidate" : "vulnerability_signal",
          value: scoped.url,
          sourceAdapter: "hunt-playbook",
          sourceUrl: scoped.url,
          scopeAllowed: true,
          confidence: validation.ssrfCandidate ? validation.confidence : "low",
          riskHint: validation.ssrfCandidate ? validation.riskHint : "low",
          metadata: { bugClass, validation },
        }));
        if (validation.ssrfCandidate) {
          findingsCreated.push(createFindingFromSignal(runtime, {
            title: "Server-side fetch behavior is observable in a lab-gated validation",
            url: scoped.url,
            category: "ssrf_server_fetch_indicator",
            severity: validation.riskHint,
            confidence: validation.confidence,
            evidence: ssrfArtifact,
            remediation: "Restrict server-side fetch destinations with explicit allowlists, block link-local/internal ranges, and avoid returning fetch metadata to untrusted users.",
          }));
        }
      }
    }

    if (bugClass === "js-secrets" || bugClass === "xss" || bugClass === "idor") {
      const js = await analyzeJavaScript(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
        fetchText: (requestUrl) => fetchScopedText(requestUrl, {
          allowUrl: (url) => runtime.scopeGuard.test(url).allowed,
          wait: async (url) => {
            await runtime.rateLimiter.wait(runtime.scopeGuard.assertAllowed(url).url);
          },
        }),
      });
      const jsArtifact = runtime.evidence.writeTextArtifact({
        jobId: job.id,
        adapterName: "js-analyzer",
        kind: "tool_output",
        sourceUrl: scoped.url,
        relativePath: path.join(job.id, `${bugClass}-js-analysis.json`),
        content: `${JSON.stringify(js, null, 2)}\n`,
      });
      evidence.push(jsArtifact);
      for (const endpoint of js.endpointCandidates) {
        observations.push(runtime.recon.upsert({
          jobId: job.id,
          kind: endpoint.toLowerCase().endsWith(".js") ? "js_asset" : "endpoint",
          value: endpoint,
          sourceAdapter: "js-analyzer",
          sourceUrl: scoped.url,
          scopeAllowed: runtime.scopeGuard.test(endpoint).allowed,
          confidence: "low",
          metadata: { bugClass },
        }));
      }
      if (bugClass === "js-secrets" && js.possibleSecrets.length > 0) {
        findingsCreated.push(createFindingFromSignal(runtime, {
          title: "Possible secret-like pattern observed in public client-side content",
          url: scoped.url,
          category: "public_js_secret_pattern",
          severity: "medium",
          confidence: "low",
          evidence: jsArtifact,
          remediation: "Manually verify whether the masked value is a real secret before reporting or validating impact.",
        }));
      }
    }

    if (bugClass === "open-redirect") {
      const validation = await validateOpenRedirectCandidate(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
      });
      if (validation.checked) {
        const redirectArtifact = runtime.evidence.writeTextArtifact({
          jobId: job.id,
          adapterName: "hunt-playbook",
          kind: "tool_output",
          sourceUrl: scoped.url,
          relativePath: path.join(job.id, "open-redirect-validation.json"),
          content: `${JSON.stringify(validation, null, 2)}\n`,
        });
        evidence.push(redirectArtifact);
        observations.push(runtime.recon.upsert({
          jobId: job.id,
          kind: validation.openRedirect ? "finding_candidate" : "vulnerability_signal",
          value: scoped.url,
          sourceAdapter: "hunt-playbook",
          sourceUrl: scoped.url,
          scopeAllowed: true,
          confidence: validation.openRedirect ? "medium" : "low",
          riskHint: validation.openRedirect ? "medium" : "low",
          metadata: { bugClass, validation },
        }));
        if (validation.openRedirect) {
          findingsCreated.push(createFindingFromSignal(runtime, {
            title: "Open redirect candidate returns an external Location header",
            url: scoped.url,
            category: "open_redirect",
            severity: "medium",
            confidence: "medium",
            evidence: redirectArtifact,
            remediation: "Validate whether redirects can be abused in an authorized flow, then restrict redirect targets to relative paths or an allow-list.",
          }));
        }
      }
    }

    if (bugClass === "xss") {
      const validation = await validateReflectedXssCandidate(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
        wait: async (requestUrl) => {
          await runtime.rateLimiter.wait(runtime.scopeGuard.assertAllowed(requestUrl).url);
        },
      });
      if (validation.checked) {
        const xssArtifact = runtime.evidence.writeTextArtifact({
          jobId: job.id,
          adapterName: "hunt-playbook",
          kind: "tool_output",
          sourceUrl: scoped.url,
          relativePath: path.join(job.id, "xss-reflection-validation.json"),
          content: `${JSON.stringify(validation, null, 2)}\n`,
        });
        evidence.push(xssArtifact);
        if (validation.reflectedParameters.length > 0) {
          observations.push(runtime.recon.upsert({
            jobId: job.id,
            kind: validation.reflectedXssCandidate ? "finding_candidate" : "vulnerability_signal",
            value: scoped.url,
            sourceAdapter: "hunt-playbook",
            sourceUrl: scoped.url,
            scopeAllowed: true,
            confidence: validation.reflectedXssCandidate ? validation.confidence : "low",
            riskHint: validation.reflectedXssCandidate ? validation.riskHint : "low",
            metadata: { bugClass, validation },
          }));
        }
        if (validation.reflectedXssCandidate) {
          findingsCreated.push(createFindingFromSignal(runtime, {
            title: "Reflected input is returned unescaped in an HTML response",
            url: scoped.url,
            category: "reflected_xss_candidate",
            severity: validation.riskHint,
            confidence: validation.confidence,
            evidence: xssArtifact,
            remediation: "HTML-encode reflected user input in the correct output context and add regression tests for reflected parameters.",
          }));
        }
      }
    }

    if (bugClass === "idor") {
      const validation = await validateIdorAdjacentObjectCandidate(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
        labModeEnabled: runtime.config.rules.lab_mode === true,
        wait: async (requestUrl) => {
          await runtime.rateLimiter.wait(runtime.scopeGuard.assertAllowed(requestUrl).url);
        },
      });
      if (validation.checked) {
        const idorArtifact = runtime.evidence.writeTextArtifact({
          jobId: job.id,
          adapterName: "hunt-playbook",
          kind: "tool_output",
          sourceUrl: scoped.url,
          relativePath: path.join(job.id, "idor-adjacent-object-validation.json"),
          content: `${JSON.stringify(validation, null, 2)}\n`,
        });
        evidence.push(idorArtifact);
        observations.push(runtime.recon.upsert({
          jobId: job.id,
          kind: validation.idorCandidate ? "finding_candidate" : "vulnerability_signal",
          value: scoped.url,
          sourceAdapter: "hunt-playbook",
          sourceUrl: scoped.url,
          scopeAllowed: true,
          confidence: validation.idorCandidate ? validation.confidence : "low",
          riskHint: validation.idorCandidate ? validation.riskHint : "low",
          metadata: { bugClass, validation },
        }));
        if (validation.idorCandidate) {
          findingsCreated.push(createFindingFromSignal(runtime, {
            title: "Adjacent object access differs by identifier in a lab-gated validation",
            url: scoped.url,
            category: "idor_adjacent_object_access",
            severity: validation.riskHint,
            confidence: validation.confidence,
            evidence: idorArtifact,
            remediation: "Enforce object-level authorization on every request using the authenticated principal, not only the object identifier supplied by the client.",
          }));
        }
      }
    }

    if (bugClass === "exposure") {
      const validation = await validateExposureCandidate(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
        wait: async (requestUrl) => {
          await runtime.rateLimiter.wait(runtime.scopeGuard.assertAllowed(requestUrl).url);
        },
      });
      if (validation.checked) {
        const exposureArtifact = runtime.evidence.writeTextArtifact({
          jobId: job.id,
          adapterName: "hunt-playbook",
          kind: "tool_output",
          sourceUrl: scoped.url,
          relativePath: path.join(job.id, "exposure-validation.json"),
          content: `${JSON.stringify(validation, null, 2)}\n`,
        });
        evidence.push(exposureArtifact);
        if (validation.exposed || validation.suspiciousPath || validation.matchedSignals.length > 0) {
          observations.push(runtime.recon.upsert({
            jobId: job.id,
            kind: validation.exposed ? "finding_candidate" : "vulnerability_signal",
            value: scoped.url,
            sourceAdapter: "hunt-playbook",
            sourceUrl: scoped.url,
            scopeAllowed: true,
            confidence: validation.exposed ? validation.confidence : "low",
            riskHint: validation.exposed ? validation.riskHint : "low",
            metadata: { bugClass, validation },
          }));
        }
        if (validation.exposed) {
          findingsCreated.push(createFindingFromSignal(runtime, {
            title: "Sensitive configuration exposure candidate is publicly reachable",
            url: scoped.url,
            category: "sensitive_file_exposure",
            severity: validation.riskHint,
            confidence: validation.confidence,
            evidence: exposureArtifact,
            remediation: "Remove public access to sensitive configuration files, rotate any exposed credentials, and add deployment checks that prevent publishing secret-bearing files.",
          }));
        }
      }
    }

    if (bugClass === "graphql") {
      const looksGraphql = /\/(?:graphql|gql)(?:[/?#]|$)/i.test(scoped.url);
      if (looksGraphql) {
        observations.push(runtime.recon.upsert({
          jobId: job.id,
          kind: "endpoint",
          value: scoped.url,
          sourceAdapter: "hunt-playbook",
          sourceUrl: scoped.url,
          scopeAllowed: true,
          confidence: "medium",
          riskHint: "low",
          metadata: {
            bugClass,
            note: runtime.config.rules.lab_mode === true
              ? "GraphQL-looking route observed; lab-mode introspection validation is allowed."
              : "GraphQL-looking route observed; live introspection is lab-gated and requires manual policy review.",
          },
        }));
      }
      const validation = await validateGraphqlIntrospectionCandidate(scoped.url, {
        allowUrl: (requestUrl) => runtime.scopeGuard.test(requestUrl).allowed,
        labModeEnabled: runtime.config.rules.lab_mode === true,
        wait: async (requestUrl) => {
          await runtime.rateLimiter.wait(runtime.scopeGuard.assertAllowed(requestUrl).url);
        },
      });
      if (validation.checked) {
        const graphqlArtifact = runtime.evidence.writeTextArtifact({
          jobId: job.id,
          adapterName: "hunt-playbook",
          kind: "tool_output",
          sourceUrl: scoped.url,
          relativePath: path.join(job.id, "graphql-introspection-validation.json"),
          content: `${JSON.stringify(validation, null, 2)}\n`,
        });
        evidence.push(graphqlArtifact);
        observations.push(runtime.recon.upsert({
          jobId: job.id,
          kind: validation.introspectionEnabled ? "finding_candidate" : "vulnerability_signal",
          value: scoped.url,
          sourceAdapter: "hunt-playbook",
          sourceUrl: scoped.url,
          scopeAllowed: true,
          confidence: validation.introspectionEnabled ? validation.confidence : "low",
          riskHint: validation.introspectionEnabled ? validation.riskHint : "low",
          metadata: { bugClass, validation },
        }));
        if (validation.introspectionEnabled) {
          findingsCreated.push(createFindingFromSignal(runtime, {
            title: "GraphQL introspection is enabled in a lab-gated validation",
            url: scoped.url,
            category: "graphql_introspection_enabled",
            severity: validation.riskHint,
            confidence: validation.confidence,
            evidence: graphqlArtifact,
            remediation: "Review whether schema introspection should be available in production and restrict it for unauthenticated or untrusted contexts when it exposes sensitive API structure.",
          }));
        }
      }
    }
  }

  for (const finding of findingsCreated) {
    const reproduction = generateReproductionNote(finding, runtime.evidence.list(finding.id));
    const artifact = runtime.evidence.writeTextArtifact({
      findingId: finding.id,
      jobId: job.id,
      adapterName: "hunt-playbook",
      kind: "reproduction_note",
      sourceUrl: finding.url,
      relativePath: path.join(finding.id, `${bugClass}-reproduction.md`),
      content: reproduction,
    });
    evidence.push(artifact);
    runtime.findings.linkEvidencePath(finding.id, artifact.path);
    for (const candidate of runtime.candidates.list({ findingId: finding.id })) {
      const linked = runtime.candidates.linkEvidence(candidate.id, artifact.id);
      if (linked) {
        refreshCandidateReadiness(runtime, linked.id);
      }
    }
  }

  const candidatesCreated = runtime.candidates.list({ jobId: job.id });
  runtime.jobs.updateStatus(job.id, "completed");
  runtime.events.record({
    jobId: job.id,
    phase: `playbook:${bugClass}`,
    status: "completed",
    message: `Playbook completed with ${candidatesCreated.length} finding candidate(s).`,
    metadata: {
      observations: observations.length,
      candidates: candidatesCreated.length,
      findings: findingsCreated.length,
      evidence: evidence.length,
    },
  });

  return {
    ok: true,
    bugClass,
    target: scoped.url,
    live,
    jobId: job.id,
    observations,
    candidatesCreated,
    findingsCreated,
    evidence,
    actionsPlanned,
    nextCommands: playbookNextCommands(
      job.id,
      findingsCreated.map((finding) => finding.id),
      candidatesCreated.map((candidate) => candidate.id),
    ),
  };
}

function normalizeToolSelection(tools: string[] | undefined, profile: HuntReconProfile): string[] {
  const defaults = profile === "web" ? WEB_RECON_TOOLS : PASSIVE_RECON_TOOLS;
  const selected = tools && tools.length > 0 ? tools : defaults;
  return [...new Set(selected.map((tool) => tool.trim().toLowerCase()).filter(Boolean))];
}

function reconNextCommands(jobId: string, tools: HuntReconToolResult[]): string[] {
  return [
    `bounty review --job ${jobId}`,
    `bounty actions review --job ${jobId}`,
    ...(tools.some((tool) => tool.status === "pending") ? [`bounty actions review --job ${jobId} --interactive`] : []),
    `bounty jobs timeline ${jobId}`,
    `bounty evidence verify --job ${jobId}`,
  ];
}

function playbookNextCommands(jobId: string, findingIds: string[], candidateIds: string[] = []): string[] {
  return [
    `bounty review --job ${jobId}`,
    `bounty evidence verify --job ${jobId}`,
    ...(candidateIds.length > 0 ? [`bounty findings candidates --job ${jobId}`] : []),
    ...candidateIds.flatMap((candidateId) => [
      `bounty findings candidate ${candidateId}`,
      `bounty reports score ${candidateId} --job ${jobId}`,
    ]),
    ...findingIds.flatMap((findingId) => [`bounty reports score ${findingId} --job ${jobId}`, `bounty reports review ${findingId} --job ${jobId}`]),
  ];
}

function playbookChecks(bugClass: BugClass): string[] {
  const common = ["scope guard", "policy gate", "evidence threshold", "duplicate risk"];
  if (bugClass === "js-secrets") return [...common, "public JavaScript secret-like pattern review"];
  if (bugClass === "cors") return [...common, "CORS response header review"];
  if (bugClass === "exposure") return [...common, "safe exposure response review"];
  if (bugClass === "graphql") return [...common, "lab-gated GraphQL introspection review"];
  if (bugClass === "idor") return [...common, "lab-gated adjacent object authorization review"];
  if (bugClass === "ssrf") return [...common, "lab-gated server-side fetch review"];
  return [...common, "manual validation required before reporting"];
}

function playbookActions(bugClass: BugClass): Array<{ adapter: string; actionType: string; riskLevel: RiskLevel; capability?: string; requiresApproval?: boolean }> {
  const actions: Array<{ adapter: string; actionType: string; riskLevel: RiskLevel; capability?: string; requiresApproval?: boolean }> = [
    { adapter: "safe-checks", actionType: "http.get", riskLevel: "low" },
  ];
  if (["xss", "idor", "js-secrets"].includes(bugClass)) {
    actions.push({ adapter: "js-analyzer", actionType: "http.get", riskLevel: "low" });
  }
  if (["xss", "ssrf", "idor"].includes(bugClass)) {
    actions.push({ adapter: "manual-validation", actionType: "http.validate", riskLevel: "medium", capability: "exploit_validation", requiresApproval: true });
  }
  if (bugClass === "graphql") {
    actions.push({ adapter: "manual-validation", actionType: "graphql.introspect", riskLevel: "medium", capability: "exploit_validation", requiresApproval: true });
  }
  return actions;
}

function recordStaticPlaybookObservations(runtime: Runtime, jobId: string, bugClass: BugClass, target: string): ReconObservation[] {
  const observations: ReconObservation[] = [];
  const url = new URL(target);
  for (const [name] of url.searchParams) {
    const kind = parameterKindFor(name, bugClass);
    if (!kind) continue;
    observations.push(runtime.recon.upsert({
      jobId,
      kind: "parameter",
      value: `${url.origin}${url.pathname}?${name}=`,
      sourceAdapter: "hunt-playbook",
      sourceUrl: target,
      scopeAllowed: true,
      confidence: "low",
      riskHint: "low",
      metadata: { bugClass, parameter: name, signal: kind },
    }));
  }
  return observations;
}

function parameterKindFor(name: string, bugClass: BugClass): string | undefined {
  const normalized = name.toLowerCase();
  if (bugClass === "open-redirect" && /^(next|url|redirect|redirect_uri|return|return_to|continue)$/i.test(normalized)) return "redirect_parameter";
  if (bugClass === "idor" && /^(id|user|account|org|tenant|file|order|invoice)(_?id)?$/i.test(normalized)) return "object_identifier";
  if (bugClass === "ssrf" && /^(url|uri|endpoint|callback|webhook|image|avatar|feed)$/i.test(normalized)) return "server_fetch_parameter";
  if (bugClass === "xss" && /^(q|query|search|s|name|message|return|next)$/i.test(normalized)) return "reflected_input_parameter";
  return undefined;
}

function safeFindingMatchesPlaybook(category: string, bugClass: BugClass): boolean {
  if (bugClass === "cors") return category === "cors";
  if (bugClass === "exposure") return category.includes("exposure");
  return false;
}

interface CorsValidation {
  checked: boolean;
  reason?: string;
  requestUrl: string;
  requestOrigin: string;
  status?: number;
  allowOrigin?: string;
  allowCredentials: boolean;
  vary?: string;
  hasCorsHeaders: boolean;
  wildcardOrigin: boolean;
  reflectedOrigin: boolean;
  credentialedReflectedOrigin: boolean;
  corsCandidate: boolean;
  confidence: Confidence;
  riskHint: RiskLevel;
  evidence: string[];
}

const CORS_TEST_ORIGIN = "https://bountypilot.local";

async function validateCorsCandidate(
  requestUrl: string,
  options: { allowUrl: (url: string) => boolean; wait?: (url: string) => Promise<void> },
): Promise<CorsValidation> {
  if (!options.allowUrl(requestUrl)) {
    return {
      checked: false,
      reason: "Request URL is out of scope.",
      requestUrl,
      requestOrigin: CORS_TEST_ORIGIN,
      allowCredentials: false,
      hasCorsHeaders: false,
      wildcardOrigin: false,
      reflectedOrigin: false,
      credentialedReflectedOrigin: false,
      corsCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }

  await options.wait?.(requestUrl);
  const response = await fetch(requestUrl, {
    method: "GET",
    redirect: "manual",
    headers: {
      accept: "application/json, text/plain;q=0.7, */*;q=0.2",
      origin: CORS_TEST_ORIGIN,
    },
  });
  await response.body?.cancel().catch(() => undefined);
  const allowOrigin = response.headers.get("access-control-allow-origin") ?? undefined;
  const allowCredentials = response.headers.get("access-control-allow-credentials")?.toLowerCase() === "true";
  const vary = response.headers.get("vary") ?? undefined;
  const hasCorsHeaders = Boolean(allowOrigin || response.headers.get("access-control-allow-methods") || response.headers.get("access-control-allow-headers"));
  const wildcardOrigin = allowOrigin === "*";
  const reflectedOrigin = allowOrigin === CORS_TEST_ORIGIN;
  const credentialedReflectedOrigin = reflectedOrigin && allowCredentials;
  const corsCandidate = credentialedReflectedOrigin || wildcardOrigin;
  const confidence: Confidence = credentialedReflectedOrigin ? "high" : wildcardOrigin ? "medium" : "low";
  const riskHint: RiskLevel = credentialedReflectedOrigin ? "medium" : wildcardOrigin ? "low" : "low";

  return {
    checked: true,
    requestUrl,
    requestOrigin: CORS_TEST_ORIGIN,
    status: response.status,
    allowOrigin,
    allowCredentials,
    vary,
    hasCorsHeaders,
    wildcardOrigin,
    reflectedOrigin,
    credentialedReflectedOrigin,
    corsCandidate,
    confidence,
    riskHint,
    evidence: [
      `HTTP ${response.status} was requested with Origin: ${CORS_TEST_ORIGIN}.`,
      allowOrigin
        ? `Response returned access-control-allow-origin: ${allowOrigin}.`
        : "Response did not include access-control-allow-origin.",
      allowCredentials
        ? "Response allowed credentialed CORS."
        : "Response did not allow credentialed CORS.",
      credentialedReflectedOrigin
        ? "The response reflected the test Origin and allowed credentials."
        : wildcardOrigin
          ? "The response used a wildcard CORS origin."
          : "The response did not meet the finding threshold for permissive CORS.",
    ],
  };
}

interface SsrfServerFetchValidation {
  checked: boolean;
  reason?: string;
  requestUrl: string;
  labModeEnabled: boolean;
  parameter?: string;
  parameterValue?: string;
  normalizedProbeUrl?: string;
  status?: number;
  contentType?: string;
  bytesRead?: number;
  truncated?: boolean;
  observedFetchUrl?: string;
  upstreamStatus?: string;
  serverFetchClaimed: boolean;
  probeMatched: boolean;
  bodyFingerprint?: string;
  ssrfCandidate: boolean;
  confidence: Confidence;
  riskHint: RiskLevel;
  evidence: string[];
}

const SSRF_PARAMETER_PATTERN = /^(url|uri|endpoint|callback|webhook|image|avatar|feed)$/i;
const MAX_SSRF_BODY_BYTES = 48 * 1024;
const SSRF_FETCH_URL_FIELD_PATTERNS = [/^(?:fetchedUrl|fetched_url|requestedUrl|requested_url|targetUrl|target_url|fetchUrl|fetch_url)$/i];
const SSRF_FETCH_BOOL_FIELD_PATTERNS = [/^(?:serverFetch|server_fetch|fetched|fetchAttempted|fetch_attempted)$/i];
const SSRF_UPSTREAM_STATUS_FIELD_PATTERNS = [/^(?:upstreamStatus|upstream_status|fetchStatus|fetch_status|statusCode|status_code)$/i];

async function validateSsrfServerFetchCandidate(
  requestUrl: string,
  options: { allowUrl: (url: string) => boolean; labModeEnabled: boolean; wait?: (url: string) => Promise<void> },
): Promise<SsrfServerFetchValidation> {
  const parsed = new URL(requestUrl);
  const parameter = [...parsed.searchParams.keys()].find((name) => SSRF_PARAMETER_PATTERN.test(name));
  if (!parameter) {
    return emptySsrfValidation(requestUrl, options.labModeEnabled, "No server-fetch query parameter was present; SSRF validation stayed as a manual review action.");
  }
  const parameterValue = parsed.searchParams.get(parameter) ?? "";
  if (!options.allowUrl(requestUrl)) {
    return emptySsrfValidation(requestUrl, options.labModeEnabled, "Request URL is out of scope.", parameter, parameterValue);
  }
  if (!options.labModeEnabled) {
    return emptySsrfValidation(
      requestUrl,
      false,
      "SSRF server-fetch validation is lab-gated; non-lab targets keep this as a recon signal pending explicit manual authorization.",
      parameter,
      parameterValue,
    );
  }

  const normalizedProbeUrl = normalizedLabSafeSsrfProbe(parameterValue, requestUrl);
  if (!normalizedProbeUrl) {
    return emptySsrfValidation(
      requestUrl,
      true,
      "The candidate callback URL was not a lab-safe loopback HTTP(S) URL, so no live SSRF validation request was sent.",
      parameter,
      parameterValue,
    );
  }
  if (!options.allowUrl(normalizedProbeUrl)) {
    return emptySsrfValidation(
      requestUrl,
      true,
      "The callback URL was not allowed by scope, so no live SSRF validation request was sent.",
      parameter,
      parameterValue,
      normalizedProbeUrl,
    );
  }

  await options.wait?.(requestUrl);
  const response = await fetch(requestUrl, {
    method: "GET",
    redirect: "manual",
    headers: {
      accept: "application/json, text/plain;q=0.7, */*;q=0.2",
    },
  });
  const contentType = response.headers.get("content-type") ?? undefined;
  const body = await readBoundedResponseText(response, MAX_SSRF_BODY_BYTES);
  const parsedBody = parseJsonObject(body.text);
  const fields = parsedBody ? flattenPrimitiveFields(parsedBody) : new Map<string, string>();
  const observedFetchUrl = firstFieldValue(fields, SSRF_FETCH_URL_FIELD_PATTERNS);
  const upstreamStatus = firstFieldValue(fields, SSRF_UPSTREAM_STATUS_FIELD_PATTERNS);
  const serverFetchFlag = firstFieldValue(fields, SSRF_FETCH_BOOL_FIELD_PATTERNS);
  const normalizedObservedFetchUrl = observedFetchUrl ? normalizeUrlLike(observedFetchUrl, requestUrl) : undefined;
  const probeMatched = normalizedObservedFetchUrl === normalizedProbeUrl;
  const serverFetchClaimed = serverFetchFlag === "true" || Boolean(upstreamStatus);
  const ssrfCandidate = response.status >= 200 && response.status < 400 && probeMatched && serverFetchClaimed;

  return {
    checked: true,
    requestUrl,
    labModeEnabled: true,
    parameter,
    parameterValue: maskSecrets(parameterValue).slice(0, 240),
    normalizedProbeUrl,
    status: response.status,
    contentType,
    bytesRead: body.bytesRead,
    truncated: body.truncated,
    observedFetchUrl,
    upstreamStatus,
    serverFetchClaimed,
    probeMatched,
    bodyFingerprint: ssrfBodyFingerprint(body.text),
    ssrfCandidate,
    confidence: ssrfCandidate ? "medium" : "low",
    riskHint: ssrfCandidate ? "medium" : "low",
    evidence: [
      `Parameter ${parameter} contained a lab-safe loopback callback URL.`,
      `HTTP ${response.status} returned ${contentType ?? "an unspecified content type"}.`,
      observedFetchUrl
        ? `Response exposed fetched URL metadata: ${maskSecrets(observedFetchUrl).slice(0, 240)}.`
        : "Response did not expose fetched URL metadata.",
      probeMatched
        ? "Fetched URL metadata matched the callback URL supplied in the request."
        : "Fetched URL metadata did not match the callback URL supplied in the request.",
      serverFetchClaimed
        ? "Response contained a server-fetch indicator such as serverFetch=true or upstream status metadata."
        : "Response did not contain a server-fetch indicator.",
      ssrfCandidate
        ? "Lab-gated evidence met the threshold for an SSRF server-fetch finding candidate."
        : "Evidence stayed below the threshold for an SSRF finding candidate.",
    ],
  };
}

function emptySsrfValidation(
  requestUrl: string,
  labModeEnabled: boolean,
  reason: string,
  parameter?: string,
  parameterValue?: string,
  normalizedProbeUrl?: string,
): SsrfServerFetchValidation {
  return {
    checked: false,
    reason,
    requestUrl,
    labModeEnabled,
    parameter,
    parameterValue: parameterValue ? maskSecrets(parameterValue).slice(0, 240) : undefined,
    normalizedProbeUrl,
    serverFetchClaimed: false,
    probeMatched: false,
    ssrfCandidate: false,
    confidence: "low",
    riskHint: "low",
    evidence: [],
  };
}

function normalizedLabSafeSsrfProbe(value: string, baseUrl: string): string | undefined {
  if (!value || value.length > 500) return undefined;
  const normalized = normalizeUrlLike(value, baseUrl);
  if (!normalized) return undefined;
  const parsed = new URL(normalized);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
  return isLoopbackHost(parsed.hostname) ? parsed.toString() : undefined;
}

function normalizeUrlLike(value: string, baseUrl: string): string | undefined {
  try {
    return new URL(value, baseUrl).toString();
  } catch {
    return undefined;
  }
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1" || normalized === "[::1]";
}

function ssrfBodyFingerprint(text: string): string {
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

interface OpenRedirectValidation {
  checked: boolean;
  reason?: string;
  requestUrl: string;
  status?: number;
  location?: string;
  targetUrl?: string;
  targetHost?: string;
  openRedirect: boolean;
  evidence: string[];
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const REDIRECT_PARAMETER_PATTERN = /^(next|url|redirect|redirect_uri|return|return_to|continue)$/i;
const REFLECTED_INPUT_PARAMETER_PATTERN = /^(q|query|search|s|name|message|return|next)$/i;

async function validateOpenRedirectCandidate(
  requestUrl: string,
  options: { allowUrl: (url: string) => boolean },
): Promise<OpenRedirectValidation> {
  const parsed = new URL(requestUrl);
  const redirectParameters = [...parsed.searchParams.keys()].filter((name) => REDIRECT_PARAMETER_PATTERN.test(name));
  if (redirectParameters.length === 0) {
    return {
      checked: false,
      reason: "No redirect-like query parameter was present; live validation did not mutate the URL.",
      requestUrl,
      openRedirect: false,
      evidence: [],
    };
  }
  if (!options.allowUrl(requestUrl)) {
    return {
      checked: false,
      reason: "Request URL is out of scope.",
      requestUrl,
      openRedirect: false,
      evidence: [],
    };
  }

  const response = await fetch(requestUrl, { method: "GET", redirect: "manual" });
  await response.body?.cancel();
  const location = response.headers.get("location") ?? undefined;
  const status = response.status;
  if (!REDIRECT_STATUSES.has(status) || !location) {
    return {
      checked: true,
      requestUrl,
      status,
      openRedirect: false,
      evidence: [`HTTP ${status} did not include a redirect Location header.`],
    };
  }

  const targetUrl = new URL(location, requestUrl).toString();
  const targetHost = new URL(targetUrl).hostname;
  const requestHost = parsed.hostname;
  const isExternal = targetHost !== requestHost;
  return {
    checked: true,
    requestUrl,
    status,
    location,
    targetUrl,
    targetHost,
    openRedirect: isExternal,
    evidence: [
      `HTTP ${status} returned Location: ${location}.`,
      isExternal
        ? `Redirect target host ${targetHost} differs from scoped host ${requestHost}; no redirect was followed.`
        : `Redirect target remains on scoped host ${requestHost}.`,
    ],
  };
}

interface ReflectedXssParameterEvidence {
  name: string;
  valueSample: string;
  rawReflected: boolean;
  escapedReflected: boolean;
  hasHtmlControlCharacters: boolean;
  contextSample?: string;
}

interface ReflectedXssValidation {
  checked: boolean;
  reason?: string;
  requestUrl: string;
  status?: number;
  contentType?: string;
  bytesRead?: number;
  truncated?: boolean;
  candidateParameters: string[];
  reflectedParameters: ReflectedXssParameterEvidence[];
  reflectedXssCandidate: boolean;
  confidence: Confidence;
  riskHint: RiskLevel;
  evidence: string[];
}

const MAX_XSS_BODY_BYTES = 64 * 1024;
const XSS_CONTEXT_CHARS = 120;

async function validateReflectedXssCandidate(
  requestUrl: string,
  options: { allowUrl: (url: string) => boolean; wait?: (url: string) => Promise<void> },
): Promise<ReflectedXssValidation> {
  const parsed = new URL(requestUrl);
  const candidateParameters = [...parsed.searchParams.keys()].filter((name) => REFLECTED_INPUT_PARAMETER_PATTERN.test(name));
  if (candidateParameters.length === 0) {
    return {
      checked: false,
      reason: "No reflected-input query parameter was present; live validation did not mutate the URL.",
      requestUrl,
      candidateParameters: [],
      reflectedParameters: [],
      reflectedXssCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }
  if (!options.allowUrl(requestUrl)) {
    return {
      checked: false,
      reason: "Request URL is out of scope.",
      requestUrl,
      candidateParameters,
      reflectedParameters: [],
      reflectedXssCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }

  await options.wait?.(requestUrl);
  const response = await fetch(requestUrl, {
    method: "GET",
    redirect: "manual",
    headers: {
      accept: "text/html, application/xhtml+xml, text/plain;q=0.7, */*;q=0.2",
    },
  });
  const contentType = response.headers.get("content-type") ?? undefined;
  const body = await readBoundedResponseText(response, MAX_XSS_BODY_BYTES);
  const htmlLike = isHtmlLikeContent(contentType, body.text);
  const reflectedParameters = candidateParameters.flatMap((name) => {
    const value = parsed.searchParams.get(name) ?? "";
    if (!value || value.length > 240) return [];
    const rawReflected = body.text.includes(value);
    const escapedValue = escapeHtml(value);
    const escapedReflected = escapedValue !== value && body.text.includes(escapedValue);
    if (!rawReflected && !escapedReflected) return [];
    return [{
      name,
      valueSample: maskSecrets(value).slice(0, 120),
      rawReflected,
      escapedReflected,
      hasHtmlControlCharacters: hasHtmlControlCharacters(value),
      contextSample: rawReflected ? reflectedContext(body.text, value) : undefined,
    }];
  });
  const unescapedHtmlControlReflection = reflectedParameters.some((item) =>
    item.rawReflected && item.hasHtmlControlCharacters,
  );
  const reflectedXssCandidate = response.status === 200 && htmlLike && unescapedHtmlControlReflection;
  const confidence: Confidence = reflectedXssCandidate ? "medium" : reflectedParameters.length > 0 ? "low" : "low";
  const riskHint: RiskLevel = reflectedXssCandidate ? "medium" : "low";

  return {
    checked: true,
    requestUrl,
    status: response.status,
    contentType,
    bytesRead: body.bytesRead,
    truncated: body.truncated,
    candidateParameters,
    reflectedParameters,
    reflectedXssCandidate,
    confidence,
    riskHint,
    evidence: [
      `HTTP ${response.status} returned ${contentType ?? "an unspecified content type"}.`,
      htmlLike ? "Response body looked HTML-like." : "Response body did not look HTML-like.",
      reflectedParameters.length > 0
        ? `Reflected parameter(s): ${reflectedParameters.map((item) => item.name).join(", ")}.`
        : "No candidate query parameter values were reflected in the bounded response body.",
      reflectedXssCandidate
        ? "At least one reflected value contained HTML-control characters and appeared unescaped; no new payload was generated by the validator."
        : "No unescaped HTML-control reflection was promoted to a finding candidate.",
      body.truncated ? `Body sample was truncated at ${MAX_XSS_BODY_BYTES} bytes.` : "Body was read within the bounded evidence limit.",
    ],
  };
}

interface ExposureValidation {
  checked: boolean;
  reason?: string;
  requestUrl: string;
  status?: number;
  contentType?: string;
  bytesRead?: number;
  truncated?: boolean;
  suspiciousPath: boolean;
  pathSignals: string[];
  matchedSignals: Array<{ name: string; confidence: Confidence }>;
  exposed: boolean;
  confidence: Confidence;
  riskHint: RiskLevel;
  sample?: string;
  evidence: string[];
}

const MAX_EXPOSURE_BODY_BYTES = 64 * 1024;
const EXPOSURE_SAMPLE_CHARS = 1200;

const EXPOSURE_PATH_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "dotenv_file", pattern: /(?:^|\/)\.env(?:$|[.\w-])/i },
  { name: "git_metadata", pattern: /(?:^|\/)\.git\/(?:config|HEAD|index)(?:$|[?#])/i },
  { name: "config_file", pattern: /(?:^|\/)(?:config|settings|secrets?|credentials?)(?:[-_\w]*)\.(?:json|ya?ml|ini|env|txt)(?:$|[?#])/i },
  { name: "backup_or_dump", pattern: /(?:^|\/)(?:backup|dump|database|db|prod|production)(?:[-_\w]*)\.(?:sql|sqlite|db|bak|zip|tar|tgz|gz|json)(?:$|[?#])/i },
  { name: "private_key_file", pattern: /(?:^|\/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|private[-_]?key)(?:$|[.\w-])/i },
];

const EXPOSURE_CONTENT_PATTERNS: Array<{ name: string; pattern: RegExp; confidence: Confidence }> = [
  {
    name: "dotenv_secret_assignment",
    pattern: /(?:^|\n)\s*(?:api[_-]?key|secret|token|password|client[_-]?secret|aws_access_key_id|aws_secret_access_key|database_url|db_password)\s*=/i,
    confidence: "high",
  },
  {
    name: "json_secret_field",
    pattern: /["'](?:api[_-]?key|apiKey|token|secret|password|clientSecret|client_secret|databaseUrl|database_url)["']\s*:/i,
    confidence: "high",
  },
  {
    name: "database_connection_string",
    pattern: /(?:postgres(?:ql)?|mysql|mongodb|redis):\/\/[^\s'"]+/i,
    confidence: "high",
  },
  {
    name: "private_key_block",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
    confidence: "high",
  },
  {
    name: "git_config_content",
    pattern: /\[core\][\s\S]{0,240}(?:repositoryformatversion|filemode|bare\s*=)/i,
    confidence: "medium",
  },
];

async function validateExposureCandidate(
  requestUrl: string,
  options: { allowUrl: (url: string) => boolean; wait?: (url: string) => Promise<void> },
): Promise<ExposureValidation> {
  if (!options.allowUrl(requestUrl)) {
    return {
      checked: false,
      reason: "Request URL is out of scope.",
      requestUrl,
      suspiciousPath: false,
      pathSignals: [],
      matchedSignals: [],
      exposed: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }

  await options.wait?.(requestUrl);
  const parsed = new URL(requestUrl);
  const pathSignals = EXPOSURE_PATH_PATTERNS
    .filter((item) => item.pattern.test(parsed.pathname))
    .map((item) => item.name);
  const response = await fetch(requestUrl, {
    method: "GET",
    redirect: "manual",
    headers: {
      accept: "text/plain, application/json, application/yaml, application/x-yaml, application/xml;q=0.9, */*;q=0.2",
    },
  });
  const contentType = response.headers.get("content-type") ?? undefined;
  const body = await readBoundedResponseText(response, MAX_EXPOSURE_BODY_BYTES);
  const matchedSignals = EXPOSURE_CONTENT_PATTERNS
    .filter((item) => item.pattern.test(body.text))
    .map((item) => ({ name: item.name, confidence: item.confidence }));
  const highConfidenceContent = matchedSignals.some((signal) => signal.confidence === "high");
  const textLike = isTextLikeContentType(contentType);
  const htmlLanding = looksLikeHtmlLandingPage(contentType, body.text);
  const suspiciousPath = pathSignals.length > 0;
  const exposed = response.status === 200 && textLike && !htmlLanding && matchedSignals.length > 0 && (suspiciousPath || highConfidenceContent);
  const confidence: Confidence = exposed && suspiciousPath && highConfidenceContent ? "high" : exposed ? "medium" : "low";
  const riskHint: RiskLevel = exposed && highConfidenceContent ? "medium" : exposed ? "low" : "low";

  return {
    checked: true,
    requestUrl,
    status: response.status,
    contentType,
    bytesRead: body.bytesRead,
    truncated: body.truncated,
    suspiciousPath,
    pathSignals,
    matchedSignals,
    exposed,
    confidence,
    riskHint,
    sample: matchedSignals.length > 0 ? maskExposureSample(body.text.slice(0, EXPOSURE_SAMPLE_CHARS)) : undefined,
    evidence: [
      `HTTP ${response.status} returned ${contentType ?? "an unspecified content type"}.`,
      suspiciousPath ? `Path matched exposure pattern(s): ${pathSignals.join(", ")}.` : "Path did not match known sensitive-file patterns.",
      matchedSignals.length > 0
        ? `Body matched exposure signal(s): ${matchedSignals.map((signal) => signal.name).join(", ")}.`
        : "Body did not match sensitive configuration/content patterns.",
      body.truncated ? `Body sample was truncated at ${MAX_EXPOSURE_BODY_BYTES} bytes.` : "Body was read within the bounded evidence limit.",
    ],
  };
}

async function readBoundedResponseText(response: Response, maxBytes: number): Promise<{ text: string; bytesRead: number; truncated: boolean }> {
  if (!response.body) {
    return { text: "", bytesRead: 0, truncated: false };
  }
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let bytesRead = 0;
  let truncated = false;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      const chunk = Buffer.from(item.value);
      if (bytesRead + chunk.byteLength > maxBytes) {
        const remaining = Math.max(0, maxBytes - bytesRead);
        if (remaining > 0) {
          chunks.push(chunk.subarray(0, remaining));
        }
        bytesRead += chunk.byteLength;
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(chunk);
      bytesRead += chunk.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return {
    text: Buffer.concat(chunks).toString("utf8"),
    bytesRead,
    truncated,
  };
}

function isTextLikeContentType(contentType: string | undefined): boolean {
  if (!contentType) return true;
  return /(?:^text\/|json|xml|ya?ml|javascript|x-www-form-urlencoded|octet-stream)/i.test(contentType);
}

function looksLikeHtmlLandingPage(contentType: string | undefined, text: string): boolean {
  if (contentType && !/html/i.test(contentType)) return false;
  return /^\s*<!doctype html\b/i.test(text) || /^\s*<html[\s>]/i.test(text);
}

function isHtmlLikeContent(contentType: string | undefined, text: string): boolean {
  if (contentType && /html/i.test(contentType)) return true;
  return /^\s*<!doctype html\b/i.test(text) || /^\s*<html[\s>]/i.test(text);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function hasHtmlControlCharacters(value: string): boolean {
  return /[<>"']/.test(value);
}

function reflectedContext(text: string, value: string): string | undefined {
  const index = text.indexOf(value);
  if (index < 0) return undefined;
  const start = Math.max(0, index - XSS_CONTEXT_CHARS);
  const end = Math.min(text.length, index + value.length + XSS_CONTEXT_CHARS);
  return maskSecrets(text.slice(start, end)).replace(/\s+/g, " ").trim();
}

interface IdorObjectSummary {
  url: string;
  status: number;
  contentType?: string;
  objectId?: string;
  ownerValue?: string;
  stableKeys: string[];
  bodyFingerprint: string;
}

interface IdorAdjacentObjectValidation {
  checked: boolean;
  reason?: string;
  requestUrl: string;
  labModeEnabled: boolean;
  parameter?: string;
  originalValue?: string;
  adjacentValue?: string;
  adjacentUrl?: string;
  original?: IdorObjectSummary;
  adjacent?: IdorObjectSummary;
  comparedFields: string[];
  idorCandidate: boolean;
  confidence: Confidence;
  riskHint: RiskLevel;
  evidence: string[];
}

const IDOR_PARAMETER_PATTERN = /^(id|user|account|org|tenant|file|order|invoice)(_?id)?$/i;
const MAX_IDOR_BODY_BYTES = 48 * 1024;
const OWNER_FIELD_PATTERN = /(?:owner|user|account|tenant|org)(?:id|_id|Id)?$/i;

async function validateIdorAdjacentObjectCandidate(
  requestUrl: string,
  options: { allowUrl: (url: string) => boolean; labModeEnabled: boolean; wait?: (url: string) => Promise<void> },
): Promise<IdorAdjacentObjectValidation> {
  const parsed = new URL(requestUrl);
  const parameter = [...parsed.searchParams.keys()].find((name) => IDOR_PARAMETER_PATTERN.test(name));
  if (!parameter) {
    return {
      checked: false,
      reason: "No object identifier query parameter was present; live validation did not mutate the URL.",
      requestUrl,
      labModeEnabled: options.labModeEnabled,
      comparedFields: [],
      idorCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }
  if (!options.allowUrl(requestUrl)) {
    return {
      checked: false,
      reason: "Request URL is out of scope.",
      requestUrl,
      labModeEnabled: options.labModeEnabled,
      parameter,
      comparedFields: [],
      idorCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }
  if (!options.labModeEnabled) {
    return {
      checked: false,
      reason: "IDOR adjacent-object validation is lab-gated; non-lab targets keep this as a recon signal pending manual authorization review.",
      requestUrl,
      labModeEnabled: false,
      parameter,
      comparedFields: [],
      idorCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }

  const originalValue = parsed.searchParams.get(parameter) ?? "";
  const adjacentValue = adjacentIdentifierValue(originalValue);
  if (!adjacentValue) {
    return {
      checked: false,
      reason: "Identifier value was not a small positive integer, so no adjacent lab validation URL was generated.",
      requestUrl,
      labModeEnabled: true,
      parameter,
      originalValue,
      comparedFields: [],
      idorCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }

  const adjacentUrl = new URL(requestUrl);
  adjacentUrl.searchParams.set(parameter, adjacentValue);
  const adjacentUrlString = adjacentUrl.toString();
  if (!options.allowUrl(adjacentUrlString)) {
    return {
      checked: false,
      reason: "Generated adjacent object URL is out of scope.",
      requestUrl,
      labModeEnabled: true,
      parameter,
      originalValue,
      adjacentValue,
      adjacentUrl: adjacentUrlString,
      comparedFields: [],
      idorCandidate: false,
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }

  const original = await fetchIdorObjectSummary(requestUrl, options);
  const adjacent = await fetchIdorObjectSummary(adjacentUrlString, options);
  const comparedFields = comparedIdorFields(original, adjacent);
  const sameStatus = original.status === 200 && adjacent.status === 200;
  const differentObjects = Boolean(original.objectId && adjacent.objectId && original.objectId !== adjacent.objectId);
  const differentOwners = Boolean(original.ownerValue && adjacent.ownerValue && original.ownerValue !== adjacent.ownerValue);
  const differentBodies = original.bodyFingerprint !== adjacent.bodyFingerprint;
  const idorCandidate = sameStatus && differentObjects && differentOwners && differentBodies;

  return {
    checked: true,
    requestUrl,
    labModeEnabled: true,
    parameter,
    originalValue,
    adjacentValue,
    adjacentUrl: adjacentUrlString,
    original,
    adjacent,
    comparedFields,
    idorCandidate,
    confidence: idorCandidate ? "medium" : "low",
    riskHint: idorCandidate ? "medium" : "low",
    evidence: [
      `Original ${parameter}=${originalValue} returned HTTP ${original.status}.`,
      `Adjacent ${parameter}=${adjacentValue} returned HTTP ${adjacent.status}.`,
      differentObjects ? `Object identifiers differed: ${original.objectId} vs ${adjacent.objectId}.` : "Object identifiers did not prove a different object.",
      differentOwners ? "Owner-like fields differed between responses." : "Owner-like fields did not prove cross-object access.",
      idorCandidate
        ? "Lab-gated adjacent object validation observed two different owner-scoped objects without an authorization challenge."
        : "Adjacent object comparison did not meet the finding threshold.",
    ],
  };
}

async function fetchIdorObjectSummary(
  url: string,
  options: { allowUrl: (url: string) => boolean; wait?: (url: string) => Promise<void> },
): Promise<IdorObjectSummary> {
  await options.wait?.(url);
  const response = await fetch(url, {
    method: "GET",
    redirect: "manual",
    headers: { accept: "application/json, text/plain;q=0.6, */*;q=0.2" },
  });
  const contentType = response.headers.get("content-type") ?? undefined;
  const body = await readBoundedResponseText(response, MAX_IDOR_BODY_BYTES);
  const parsed = parseJsonObject(body.text);
  const flat = parsed ? flattenPrimitiveFields(parsed) : new Map<string, string>();
  return {
    url,
    status: response.status,
    contentType,
    objectId: firstFieldValue(flat, [/^(?:id|accountId|account_id|orderId|order_id|invoiceId|invoice_id)$/i]),
    ownerValue: firstFieldValue(flat, [OWNER_FIELD_PATTERN]),
    stableKeys: [...flat.keys()].sort().slice(0, 20),
    bodyFingerprint: idorBodyFingerprint(body.text),
  };
}

function adjacentIdentifierValue(value: string): string | undefined {
  if (!/^\d{1,10}$/.test(value)) return undefined;
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric < 0) return undefined;
  return String(numeric + 1);
}

function comparedIdorFields(original: IdorObjectSummary, adjacent: IdorObjectSummary): string[] {
  const fields = new Set<string>();
  if (original.objectId || adjacent.objectId) fields.add("objectId");
  if (original.ownerValue || adjacent.ownerValue) fields.add("ownerValue");
  if (original.bodyFingerprint !== adjacent.bodyFingerprint) fields.add("bodyFingerprint");
  return [...fields];
}

function flattenPrimitiveFields(value: unknown, prefix = "", output = new Map<string, string>()): Map<string, string> {
  if (Array.isArray(value)) return output;
  if (!isPlainRecord(value)) return output;
  for (const [key, item] of Object.entries(value)) {
    const pathKey = prefix ? `${prefix}.${key}` : key;
    if (typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
      output.set(pathKey, maskSecrets(String(item)).slice(0, 180));
    } else if (isPlainRecord(item)) {
      flattenPrimitiveFields(item, pathKey, output);
    }
  }
  return output;
}

function firstFieldValue(fields: Map<string, string>, patterns: RegExp[]): string | undefined {
  for (const [key, value] of fields) {
    const leaf = key.split(".").at(-1) ?? key;
    if (patterns.some((pattern) => pattern.test(leaf))) {
      return value;
    }
  }
  return undefined;
}

function idorBodyFingerprint(text: string): string {
  let hash = 5381;
  for (let index = 0; index < text.length; index += 1) {
    hash = ((hash << 5) + hash) ^ text.charCodeAt(index);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

interface GraphqlIntrospectionValidation {
  checked: boolean;
  reason?: string;
  requestUrl: string;
  labModeEnabled: boolean;
  status?: number;
  contentType?: string;
  bytesRead?: number;
  truncated?: boolean;
  introspectionEnabled: boolean;
  queryTypeName?: string;
  mutationTypeName?: string;
  subscriptionTypeName?: string;
  schemaTypeCount: number;
  sampledTypes: string[];
  errorMessages: string[];
  confidence: Confidence;
  riskHint: RiskLevel;
  evidence: string[];
}

const MAX_GRAPHQL_BODY_BYTES = 96 * 1024;
const GRAPHQL_INTROSPECTION_QUERY = `
query BountyPilotIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { kind name }
  }
}
`;

async function validateGraphqlIntrospectionCandidate(
  requestUrl: string,
  options: { allowUrl: (url: string) => boolean; labModeEnabled: boolean; wait?: (url: string) => Promise<void> },
): Promise<GraphqlIntrospectionValidation> {
  if (!options.allowUrl(requestUrl)) {
    return {
      checked: false,
      reason: "Request URL is out of scope.",
      requestUrl,
      labModeEnabled: options.labModeEnabled,
      introspectionEnabled: false,
      schemaTypeCount: 0,
      sampledTypes: [],
      errorMessages: [],
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }
  if (!options.labModeEnabled) {
    return {
      checked: false,
      reason: "GraphQL introspection validation is lab-gated; non-lab targets keep this as a recon signal pending review.",
      requestUrl,
      labModeEnabled: false,
      introspectionEnabled: false,
      schemaTypeCount: 0,
      sampledTypes: [],
      errorMessages: [],
      confidence: "low",
      riskHint: "low",
      evidence: [],
    };
  }

  await options.wait?.(requestUrl);
  const response = await fetch(requestUrl, {
    method: "POST",
    redirect: "manual",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({ query: GRAPHQL_INTROSPECTION_QUERY }),
  });
  const contentType = response.headers.get("content-type") ?? undefined;
  const body = await readBoundedResponseText(response, MAX_GRAPHQL_BODY_BYTES);
  const parsed = parseJsonObject(body.text);
  const schema = readGraphqlSchemaSummary(parsed);
  const errorMessages = readGraphqlErrorMessages(parsed);
  const introspectionEnabled = response.status === 200 && schema.schemaTypeCount > 0 && Boolean(schema.queryTypeName);
  const confidence: Confidence = introspectionEnabled ? "high" : "low";
  const riskHint: RiskLevel = introspectionEnabled && Boolean(schema.mutationTypeName) ? "medium" : introspectionEnabled ? "low" : "low";

  return {
    checked: true,
    requestUrl,
    labModeEnabled: true,
    status: response.status,
    contentType,
    bytesRead: body.bytesRead,
    truncated: body.truncated,
    introspectionEnabled,
    queryTypeName: schema.queryTypeName,
    mutationTypeName: schema.mutationTypeName,
    subscriptionTypeName: schema.subscriptionTypeName,
    schemaTypeCount: schema.schemaTypeCount,
    sampledTypes: schema.sampledTypes,
    errorMessages,
    confidence,
    riskHint,
    evidence: [
      `HTTP ${response.status} returned ${contentType ?? "an unspecified content type"}.`,
      introspectionEnabled
        ? `Introspection returned query type ${schema.queryTypeName ?? "unknown"} and ${schema.schemaTypeCount} schema type(s).`
        : "Introspection did not return a usable __schema object.",
      schema.mutationTypeName ? `Mutation type ${schema.mutationTypeName} was present.` : "No mutation type was observed in the schema summary.",
      errorMessages.length > 0 ? `GraphQL error message(s): ${errorMessages.join(" | ")}.` : "No GraphQL errors were returned.",
      body.truncated ? `Body sample was truncated at ${MAX_GRAPHQL_BODY_BYTES} bytes.` : "Body was read within the bounded evidence limit.",
    ],
  };
}

function parseJsonObject(text: string): Record<string, unknown> | undefined {
  try {
    const value = JSON.parse(text) as unknown;
    return isPlainRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function readGraphqlSchemaSummary(value: Record<string, unknown> | undefined): {
  queryTypeName?: string;
  mutationTypeName?: string;
  subscriptionTypeName?: string;
  schemaTypeCount: number;
  sampledTypes: string[];
} {
  const data = isPlainRecord(value?.data) ? value.data : undefined;
  const schema = isPlainRecord(data?.__schema) ? data.__schema : undefined;
  if (!schema) {
    return { schemaTypeCount: 0, sampledTypes: [] };
  }
  const queryType = isPlainRecord(schema.queryType) ? schema.queryType : undefined;
  const mutationType = isPlainRecord(schema.mutationType) ? schema.mutationType : undefined;
  const subscriptionType = isPlainRecord(schema.subscriptionType) ? schema.subscriptionType : undefined;
  const types = Array.isArray(schema.types) ? schema.types : [];
  const sampledTypes = types
    .flatMap((item) => {
      if (!isPlainRecord(item)) return [];
      const name = typeof item.name === "string" ? item.name : undefined;
      const kind = typeof item.kind === "string" ? item.kind : undefined;
      return name ? [`${kind ?? "TYPE"}:${name}`] : [];
    })
    .slice(0, 12);
  return {
    queryTypeName: typeof queryType?.name === "string" ? queryType.name : undefined,
    mutationTypeName: typeof mutationType?.name === "string" ? mutationType.name : undefined,
    subscriptionTypeName: typeof subscriptionType?.name === "string" ? subscriptionType.name : undefined,
    schemaTypeCount: types.length,
    sampledTypes,
  };
}

function readGraphqlErrorMessages(value: Record<string, unknown> | undefined): string[] {
  const errors = Array.isArray(value?.errors) ? value.errors : [];
  return errors
    .flatMap((item) => {
      if (!isPlainRecord(item) || typeof item.message !== "string") return [];
      return [maskSecrets(item.message).slice(0, 180)];
    })
    .slice(0, 5);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function maskExposureSample(value: string): string {
  return maskSecrets(value)
    .replace(/((?:aws_secret_access_key|aws_access_key_id|database_url|db_password|client_secret|api_key|token|password|secret)\s*[:=]\s*)[^\r\n]+/gi, "$1[REDACTED]")
    .replace(/((?:postgres(?:ql)?|mysql|mongodb|redis):\/\/[^:\s]+:)[^@\s]+(@)/gi, "$1[REDACTED]$2");
}

function createFindingFromSignal(runtime: Runtime, input: {
  title: string;
  url: string;
  category: string;
  severity: SeverityEstimate;
  confidence: Confidence;
  evidence: EvidenceArtifact;
  remediation?: string;
  observationIds?: string[];
}) {
  const scope = runtime.scopeGuard.assertAllowed(input.url);
  const duplicate = new DuplicateRiskEngine().estimate(
    {
      title: input.title,
      asset: scope.host,
      url: scope.url,
      category: input.category,
    },
    runtime.findings.list(),
  );
  const finding = runtime.findings.create({
    title: input.title,
    asset: scope.host,
    url: scope.url,
    category: input.category,
    severityEstimate: input.severity,
    confidence: input.confidence,
    status: "needs_validation",
    evidencePaths: [input.evidence.path],
    remediation: input.remediation,
    duplicateRisk: duplicate.risk,
    reportabilityScore: 45,
  });
  runtime.evidence.linkToFinding(input.evidence.id, finding.id);
  const triage = new TriageEngine().triage({ ...finding, duplicateRisk: duplicate.risk }, [input.evidence]);
  const readiness = evaluateFindingCandidateReadiness({
    confidence: input.confidence,
    severity: input.severity,
    evidenceCount: 1,
    duplicateRisk: duplicate.risk,
  });
  runtime.candidates.create({
    jobId: input.evidence.jobId,
    title: input.title,
    asset: scope.host,
    url: scope.url,
    category: input.category,
    severityEstimate: input.severity,
    confidence: input.confidence,
    status: readiness.status,
    evidenceIds: [input.evidence.id],
    observationIds: input.observationIds,
    findingId: finding.id,
    falsePositiveRisk: readiness.falsePositiveRisk,
    duplicateRisk: duplicate.risk,
    reportability: readiness.reportability,
    reasoningSummary: readiness.reasoningSummary,
    nextManualSteps: readiness.nextManualSteps,
  });
  return { ...finding, duplicateRisk: duplicate.risk, reportabilityScore: triage.reportabilityScore };
}

function refreshCandidateReadiness(runtime: Runtime, candidateId: string): FindingCandidate | undefined {
  const candidate = runtime.candidates.get(candidateId);
  if (!candidate) return undefined;
  const duplicate = new DuplicateRiskEngine().estimate(
    {
      title: candidate.title,
      asset: candidate.asset,
      url: candidate.url,
      category: candidate.category,
    },
    runtime.findings.list().filter((finding) => finding.id !== candidate.findingId),
  );
  const readiness = evaluateFindingCandidateReadiness({
    confidence: candidate.confidence,
    severity: candidate.severityEstimate,
    evidenceCount: candidate.evidenceIds.length,
    duplicateRisk: duplicate.risk,
  });
  return runtime.candidates.updateReadiness(candidate.id, {
    status: readiness.status,
    reportability: readiness.reportability,
    falsePositiveRisk: readiness.falsePositiveRisk,
    duplicateRisk: duplicate.risk,
    reasoningSummary: readiness.reasoningSummary,
    nextManualSteps: readiness.nextManualSteps,
  });
}
