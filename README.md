# BountyPilot

BountyPilot is a safe, local-first, scoped bug bounty CLI for authorized security researchers. It is designed to collect evidence, coordinate safe checks, and generate report drafts while preserving scope, rate limits, auditability, reproducibility, and human control.

This repository is the v0.1 foundation. It intentionally avoids unrestricted exploit automation.

## Safety Model

- Only explicitly in-scope assets are allowed.
- Out-of-scope rules override in-scope rules.
- Target actions flow through `ScopeGuard`, `PolicyGate`, `RateLimiter`, `AuditLogger`, `JobManager`, and `ActionQueue`.
- Destructive testing, brute force, credential stuffing, spam, data exfiltration, WAF evasion, malware execution, and mass internet scanning are blocked.
- Reports are generated as local drafts only. BountyPilot does not auto-submit reports.

## CLI Interface

The CLI uses a compact, terminal-first presentation inspired by modern agent CLIs: concise headers, status tags, section panels, and scan-friendly tables. Set `NO_COLOR=1` to disable ANSI color.

## Install From GitHub

BountyPilot requires Node.js 22.13.0 or newer.

After this repository is pushed to GitHub, users can install the CLI with one command:

```bash
npm install -g github:OWNER/REPO
```

Replace `OWNER/REPO` with the GitHub repository, for example `your-name/bountypilot`.

Linux/macOS installer:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.sh | BOUNTYPILOT_SOURCE=github:OWNER/REPO bash
```

Windows PowerShell installer:

```powershell
$env:BOUNTYPILOT_SOURCE="github:OWNER/REPO"; irm https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.ps1 | iex
```

Set `BOUNTYPILOT_INSTALL_DRY_RUN=1` to make either installer verify Node/npm and print the resolved `npm install -g ...` command without installing globally.

If the package is later published to npm, the shortest install command becomes:

```bash
npm install -g bountypilot
```

Verify the install:

```bash
bugbounty --version
bugbounty --help
bugbounty
```

The package also keeps `bounty` as a compatibility alias for older examples and workflows.

OpenCode-style TUI quickstart:

```text
bugbounty
/connect
/models
/hunt
/results
```

If no provider is configured, `bugbounty` opens the `/connect` provider selector in a real terminal and prints the same non-interactive TUI snapshot in CI or piped shells.

GitHub publishing checklist: [docs/github-publish.md](docs/github-publish.md).

## Quick Start

Run the chat-first terminal UI:

```bash
npm install
npm run build
npm install -g .
bugbounty
```

Inside the TUI, use `/connect` to add OpenAI, OpenRouter, Gemini, Anthropic, or Ollama; `/models` to switch `provider/model`; `Tab` to move through Chat, Plan, Hunt, and Review; `/hunt` and `/results` for the bug bounty workflow panels.

Classic workflow commands still work:

```bash
npm install
npm run build
node dist/cli/index.js init
node dist/cli/index.js import examples/program.yml
node dist/cli/index.js release check
npm run verify:release
node dist/cli/index.js programs list
node dist/cli/index.js scope list
node dist/cli/index.js scope test https://api.example.com
node dist/cli/index.js run api.example.com --dry-run --with safe-checks,js-analyzer,playwright,planner
```

The compiled path above is the smoke-tested CLI path. The intended source-mode shorthand is:

```bash
npm run dev -- init
npm run dev -- import examples/program.yml
npm run dev -- scope test https://api.example.com
npm run dev -- run api.example.com --dry-run
```

If source-mode execution fails to resolve TypeScript ESM imports in your Node or `tsx` version, use `npm run build` followed by `node dist/cli/index.js ...`.

BountyPilot requires Node.js 22.13.0 or newer because the local SQLite store uses the built-in `node:sqlite` runtime.

## Safe Workflow Guide

Use the workflow as a gated loop, not a fire-and-forget scan:

1. Start with written authorization from the program owner. BountyPilot scope files document authorization boundaries; they do not create authorization.
2. Run `bounty init`, then `bounty import <program.yml>` to create a local workspace under `.bounty/programs/<program>/`. Imported execution opt-ins are stripped to planning-only state.
3. Confirm boundaries with `bounty scope list` and `bounty scope test <url>` before planning any activity.
   Path-scoped rules must be written as explicit URLs such as `https://api.example.com/app`; bare `api.example.com/app` is rejected to avoid accidental host-wide scope.
4. Start every target with `bounty run <target> --dry-run`. Dry runs write local notes, workflow events, queued component actions, and a summary without target network execution. Live JS/crawl phases or `agent plan --from-job` add richer `plannerCandidates` and planner-loop evidence.
5. Inspect the checkpoint with `bounty jobs show <job-id>`, `bounty jobs timeline <job-id>`, `bounty actions list --pending`, and `bounty actions show <action-id>`.
6. Approve or block actions deliberately with `bounty actions approve` or `bounty actions block`. Actions that require approval stay `pending`; low-risk policy-allowed actions can appear as `approved`, but nothing in the queue runs until `actions execute` or `actions run-approved`.
7. Move to live work only after scope, program rules, rate limits, and action approval are clear: use `bounty run <target> --mode safe`, `bounty actions execute <action-id>`, or `bounty actions run-approved --job <job-id>`.
8. Resume interrupted jobs with `bounty jobs resume <job-id>`. Resume is incremental: unchanged completed global phases are skipped, seed-scoped phases such as `safe-checks`, `js-analyzer`, and `playwright` resume per target, and `resumeSkippedWork[]` plus workflow events show what was reused or continued.
9. Keep external components opt-in. `crawl4ai`, `playwright-mcp`, stdio MCP, and other trusted adapters execute only when the integration is configured, execution is enabled, and the local executable has been approved by absolute path and SHA-256 hash.
10. Export `bounty export bundle --job <job-id>` for handoff. Add `--include-artifacts` when reviewers need copied evidence files, not only manifest references.

Dry-run is the recommended first command for every target because it exercises scope, policy, queueing, timeline, checkpoint, and local evidence paths without touching the target.

## Command Matrix

| Area | Command | External network? | Safety behavior |
| --- | --- | --- | --- |
| Workspace | `bounty init` | No | Creates local `.bounty` directories only. |
| Workspace | `bounty init --guided [--program-file program.yml]` | No | Creates the workspace, optionally imports a program file, runs local setup checks, and prints copy-paste next commands. |
| Workspace | `bounty quickstart [target]` | No | Generates a VM-first runbook from workspace setup through providers, arsenal, hunt loop, results, evidence, and report readiness. |
| Workspace | `bounty quickstart <target> --write` | No | Writes the quickstart runbook to `.bounty/quickstart.md` without executing tools or contacting the target. |
| Workspace | `bounty import <program.yml>` | No | Validates scope, stores the program, and strips imported execution opt-ins to planning-only. |
| Programs | `bounty programs list` | No | Lists imported program workspaces and validation status. |
| Programs | `bounty programs show [name]` | No | Shows imported program config, scope, integrations, and workspace paths. |
| Programs | `bounty programs validate <program.yml>` | No | Validates a program file without importing it. |
| Health | `bounty doctor` | No | Checks local workspace, Node runtime, imported programs, and prints copy-paste next commands. |
| Health | `bounty doctor --deep` | No | Adds package, bin, scripts, dist, and example readiness checks with next-command guidance. |
| Health | `bounty doctor --json` | No | Prints workspace, program, check, release, and next-command guidance as machine-readable JSON. |
| Release | `bounty release check` | No | Checks whether the built local CLI package is ready for handoff or local release. |
| Release | `bounty release check --json` | No | Prints release readiness checks as machine-readable JSON, including structured example validation. |
| Release | `bounty release bundle --output .release` | No | Creates local release artifacts: npm tarball, standalone skill ZIP, SBOM, release manifest, and `SHA256SUMS.txt`. |
| Release | `bounty release verify-bundle .release` | No | Verifies release manifest, SHA256SUMS, artifact hashes/sizes, and the standalone skill ZIP before upload. |
| Release | `bounty release github-bootstrap OWNER/REPO --write` | No | Checks GitHub CLI/auth/remote readiness and writes idempotent GitHub publish scripts. |
| Release | `bounty release publish-plan OWNER/REPO --write` | No | Writes a GitHub publish plan with remote, push, tag, install, Actions, and release artifact commands. |
| Release | `bounty release publish-status OWNER/REPO --online --actions --json` | GitHub git remote and GitHub CLI when requested | Checks release gate, origin target, clean tree, branch/tag state, remote branch/tag publication, and required Actions workflow success after push. |
| Release | `bounty release install-check --json` | No | Verifies an installed `bugbounty` command can boot, validate the bundled skill, and render fresh-user quickstart JSON. |
| Release | `npm run verify:release` | No | Runs build, docs command-snippet verification, tests, fresh-install package-bin smoke, release checks, and dry-run pack as one gate. |
| Release | `npm run test:external-tools` | Local fixture executables only | Exercises trusted external tool parsing, approval, scoped recon execution, review-required scanner gates, and crawl graph wiring without touching the internet. |
| Release | `npm run test:vm-lab` | Local loopback only | Installs the packed CLI into a clean consumer project, starts the demo lab, runs live lab E2E, and verifies beta readiness from the installed binary. |
| Release | `npm run test:vm-real-tools` | Local loopback plus installed real tools | Ubuntu/VM smoke that approves real `httpx` and `katana`, runs live recon against the loopback demo lab, and verifies scoped observations. |
| Skill | `bounty skill validate bug-bounty-pilot` | No | Validates the bundled skill policy, workflow, tool registry, playbooks, prompts, templates, and examples. |
| Skill | `bounty skill score bug-bounty-pilot` | No | Scores skill readiness across validation, temporary bundle verification, release gates, warnings, blockers, and next steps. |
| Skill | `bounty skill score bug-bounty-pilot --repo OWNER/REPO --json` | No | Scores the skill and embeds concrete GitHub publish/bootstrap readiness for a target repository. |
| Skill | `bounty skill bundle bug-bounty-pilot --output bug-bounty-pilot.skill.zip` | No | Writes a portable ZIP bundle with `MANIFEST.bountypilot.json` and SHA-256 hashes for every skill file. |
| Skill | `bounty skill verify-bundle bug-bounty-pilot.skill.zip` | No | Verifies a standalone skill ZIP manifest, file sizes, SHA-256 hashes, and unexpected files before use. |
| Skill | `bounty skill run bug-bounty-pilot <target> --program <program> --mode passive --dry-run` | No | Runs the skill workflow through the existing scoped dry-run safety engine. |
| Beta | `bounty beta readiness` | No | Scores workspace, imported programs, package, examples, scripts, and release checks for beta handoff readiness. |
| Beta | `bounty beta readiness --write [--output beta-readiness.json]` | No | Writes a local beta readiness report with blockers, warnings, release details, and next commands. |
| Beta | `bounty beta checklist` | No | Generates a beta handoff checklist from the current readiness checks, blockers, warnings, safety notes, and required commands. |
| Beta | `bounty beta checklist --write [--output beta-checklist.md]` | No | Writes a local Markdown checklist for beta release handoff or review. |
| Cockpit | `bounty cockpit [--job <job-id>]` | No | Opens an opencode-style command cockpit with workspace health, focused job status, recon observations, provider/tool readiness, and next commands. |
| Cockpit | `bounty cockpit --watch --iterations 3` | No | Refreshes the cockpit snapshot for local progress monitoring without executing tools. |
| Cockpit | `bounty cockpit --json` | No | Prints the cockpit snapshot as machine-readable JSON for automation or handoff. |
| Dashboard | `bounty dashboard` | No | Shows local jobs, actions, findings, evidence, and next steps. |
| Dashboard | `bounty dashboard --json` | No | Prints the same workspace summary as machine-readable JSON. |
| Review | `bounty review --job <job-id>` | No | Opens a focused job review cockpit with health checks, phase counts, action queue, evidence, finding/report readiness, recent timeline, and copy-paste next commands. |
| Results | `bounty results [--job <job-id>]` | No | Shows bug bounty result candidates ranked by report readiness, score, evidence, blockers, recon signals, and next commands. |
| Results | `bounty results --min-score 60 --ready-only --json` | No | Prints filtered report-ready result candidates as machine-readable JSON. |
| Export | `bounty export summary [--output path]` | No | Writes a local JSON workspace summary for audit, handoff, or backup. |
| Export | `bounty export bundle [--job <job-id>] [--include-artifacts]` | No | Writes a local handoff bundle with summary, findings, actions, evidence manifest, timelines, and audit logs. |
| Scope | `bounty scope list` | No | Prints imported in-scope and out-of-scope rules. |
| Scope | `bounty scope list --json` | No | Prints scope rules as clean machine-readable JSON. |
| Scope | `bounty scope test <url>` | No | Returns exit code `0` when allowed and `2` when blocked. |
| Scope | `bounty scope test <url> --json` | No | Prints the ScopeGuard decision as clean machine-readable JSON. |
| Workflow | `bounty run [target] --dry-run` | No | Plans actions, writes local notes, and skips real tool execution. |
| Workflow | `bounty run [target] --dry-run --json` | No | Returns a machine-readable workflow summary and structured timeline events. |
| Workflow | `bounty run [target] --mode safe` | Yes | Runs selected low-risk components only after scope and policy checks. |
| Workflow | `bounty run [target] --mode deep-safe --with safe-checks,js-analyzer,playwright,planner` | Yes | Adds browser evidence capture, still behind scope, policy, and rate limits. |
| Workflow | `bounty run [target] --mode lab-offensive` | Local lab only | Blocked unless the imported program config sets `rules.lab_mode: true`, includes `rules.lab_authorization_file`, and targets local/private lab assets only. |
| Hunt | `bounty hunt profiles` | No | Lists guided recon, web, validate, and lab-aggressive hunt profiles inspired by recon-to-report bug bounty workflows. |
| Hunt | `bounty hunt doctor <target> --profile web` | No | Checks scope, provider config, trusted tools, VM arsenal readiness, and profile gates before hunting. |
| Hunt | `bounty hunt plan <target> --profile web --write` | No | Builds a scoped Markdown hunt plan with phases, bug classes, validation gates, tool readiness, and next commands. |
| Hunt | `bounty hunt recon <target> --profile web --dry-run` | No | Plans trusted recon tools, queues review-required scanners, and stores a recon job without executing external tools. |
| Hunt | `bounty hunt recon <target> --profile web --live` | Yes for approved safe tools only | Runs approved low-risk recon tools, stores normalized observations, and leaves nuclei/ffuf/dalfox/naabu pending review. |
| Hunt | `bounty hunt playbook xss <target> --dry-run` | No | Plans a bug-class playbook and records weak signals as recon observations instead of findings. |
| Hunt | `bounty hunt playbook cors <target> --live` | Yes | Sends a safe Origin-header check, records `cors-validation.json`, and promotes credentialed reflected-origin evidence to a finding candidate. |
| Hunt | `bounty hunt playbook ssrf <target> --live` | Lab only | Records server-fetch findings only when `rules.lab_mode=true`, the callback URL is loopback/in-scope, and response metadata proves the fetch indicator. |
| Hunt | `bounty hunt playbook js-secrets <target> --live` | Yes | Runs safe checks and JavaScript analysis, creating finding candidates only when evidence thresholds are met. |
| Hunt | `bounty hunt run <target> --profile recon --dry-run` | No | Runs the guided hunt profile in planning mode, queues safe next actions, and writes local workflow artifacts. |
| Hunt | `bounty hunt run <target> --profile web --live` | Yes | Runs the selected profile only after imported scope, policy, mode, and rate-limit gates pass. |
| Hunt | `bounty hunt autopilot <target> --profile web --dry-run --write-plan` | No | Runs plan, profile workflow, review cockpit, and optional handoff bundle as one guarded flow. |
| Hunt | `bounty hunt autopilot <target> --profile web --live --bundle` | Yes | Runs live only after guardrails pass, then writes a job-scoped handoff bundle for review. |
| Recon | `bounty recon list [--job <job-id>] [--kind parameter]` | No | Lists normalized recon observations from previous recon/playbook/tool runs with kind/source counts. |
| Recon | `bounty recon show <observation-id-or-fingerprint>` | No | Shows one recon observation, related job evidence, and copy-paste follow-up commands. |
| Arsenal | `bounty arsenal profiles` | No | Lists VM-ready bug bounty tools, categories, purposes, and run policies. |
| Arsenal | `bounty arsenal vm --write [--output vm-arsenal.md]` | No | Writes a VM bootstrap plan for recon, URL discovery, validation, evidence, and reporting tools without installing anything automatically. |
| Arsenal | `bounty arsenal bootstrap --level safe --write [--output bootstrap.sh]` | No | Writes a reviewed Bash install script for passive/safe VM tools; it does not execute the script. |
| Arsenal | `bounty arsenal bootstrap --level full --write [--output bootstrap.sh]` | No | Writes a fuller VM install script including review-required tools such as nuclei, ffuf, dalfox, and naabu. |
| Lab | `bounty lab demo --port 8080` | Local loopback only | Serves a built-in read-only demo lab on loopback for practicing BountyPilot workflows without touching third-party assets. |
| Lab | `bounty lab e2e <local-url>` | No by default; local lab only with `--live` | Runs lab-mode, authorization, scope, and policy gates, then creates a dry-run checkpoint unless `--live` is explicit. |
| Lab | `bounty lab e2e <local-url> --live --with safe-checks,js-analyzer` | Local lab only | Runs selected workflow components against an explicitly in-scope local/private lab target and records workflow evidence. |
| Workflow | `bounty run [target] --with crawl4ai,playwright-mcp` | Yes only when explicitly enabled | Runs external workflow components only when integration execution is enabled and its executable approval hash matches; otherwise records a skipped phase or fails closed before spawn. |
| Workflow | `bounty run [target] --with d-research-skill` | No external skill execution | Records a local public research ledger inside the workflow timeline without expanding scope. |
| Browser | `bounty crawl <url> --playwright` | Yes | Non-destructive crawl, blocks out-of-scope requests. |
| Browser | `bounty crawl <url> --engine playwright-mcp` | No external MCP execution | Validates and records a Playwright MCP crawl plan with `execute=false`. |
| Crawler | `bounty crawl <url> --engine crawl4ai` | No external crawler execution | Validates and records a Crawl4AI crawl plan with `execute=false`. |
| Browser | `bounty browser <url> --mcp playwright` | No external MCP execution | Validates and records a Playwright MCP call plan with `execute=false`. |
| Desktop | `bounty desktop --mcp windows` | No external MCP execution | Validates and records a local-only Windows MCP plan; usually requires approval. |
| Research | `bounty research [target] --skill d-research` | No external skill execution | Writes a local research ledger and scope context. |
| Checks | `bounty check <url> --safe` | Yes | Low-rate GET request and header checks only. |
| JavaScript | `bounty js <url>` | Yes | Fetches public client-side content and masks secret-like values. |
| Findings | `bounty findings` | No | Lists local findings. |
| Findings | `bounty findings create --title <text> --url <url>` | No | Adds a manual local finding after scope validation, with optional note and local evidence attachments. |
| Findings | `bounty findings show <finding-id>` | No | Shows finding details, linked evidence, duplicate risk, and triage context. |
| Findings | `bounty findings status <finding-id> <status>` | No | Updates local lifecycle status and records a status note artifact. |
| Evidence | `bounty evidence [finding-id] [--job <job-id>]` | No | Lists local evidence artifacts, optionally scoped to one job. |
| Evidence | `bounty evidence list [finding-id] [--job <job-id>]` | No | Explicit subcommand alias for listing local evidence artifacts. |
| Evidence | `bounty evidence show <evidence-id>` | No | Shows one evidence artifact with local readability and SHA-256 metadata. |
| Evidence | `bounty evidence add --finding <finding-id> --file <path> [--job <job-id>]` | No | Copies a local evidence file into the workspace and masks text secrets. |
| Evidence | `bounty evidence add --finding <finding-id> --text <text> [--job <job-id>]` | No | Stores inline text evidence with secret masking. |
| Evidence | `bounty evidence add --finding <finding-id> --stdin [--job <job-id>]` | No | Reads text evidence from stdin with secret masking. |
| Evidence | `bounty evidence record --job <job-id> --type note --title <text>` | No | Records a local manual evidence note for a job, matching the skill workflow command shape. |
| Evidence | `bounty evidence record <url> --finding <finding-id> [--job <job-id>]` | Yes | Captures scoped browser evidence, HAR, DOM, console output, request/response samples, and a reproduction note for one finding. |
| Evidence | `bounty evidence link <evidence-id> <finding-id>` | No | Idempotently links an existing local evidence artifact to a finding. |
| Evidence | `bounty evidence manifest [finding-id] [--job <job-id>] --open` | Local OS only | Writes an evidence manifest and optionally opens the local artifact folder. |
| Evidence | `bounty evidence open [finding-id] [--job <job-id>]` | Local OS only | Opens the local evidence folder for a finding, job, or workspace. |
| Evidence | `bounty evidence verify [finding-id] [--job <job-id>]` | No | Checks local evidence readability, file size, and SHA-256 metadata. |
| Reporting | `bounty reports score <finding-id> [--job <job-id>]` | No | Prints reportability score, readiness, evidence counts/checks, blockers, warnings, next steps, and next commands. |
| Reporting | `bounty reports review <finding-id> [--job <job-id>]` | No | Runs a local pre-submit checklist for report readiness, evidence quality, duplicate risk, and safety blockers. |
| Reporting | `bounty reports bundle <candidate-id> [--job <job-id>] [--include-artifacts]` | No | Writes a job-scoped handoff bundle for the report candidate or linked finding. |
| Reporting | `bounty report <finding-id> --platform hackerone|bugcrowd` | No | Writes a local Markdown report draft only when report readiness is not blocked. |
| Reporting | `bounty report <finding-id> --platform hackerone|bugcrowd --force-local-draft` | No | Writes a local-only draft even when readiness is blocked, for manual repair and review. |
| Triage | `bounty triage <finding-id>` | No | Scores local evidence quality and duplicate risk. |
| Reproduction | `bounty reproduce <finding-id>` | No | Writes safe manual reproduction notes. |
| Reproduction | `bounty reproduce <finding-id> --with playwright-mcp` | No external MCP execution | Writes notes and records a Playwright MCP reproduction plan with `execute=false`. |
| Planning | `bounty agent plan <url> [--from-job <job-id>]` | No external tool execution | Queues ranked, de-duplicated safe next actions for human review. |
| Planning | `bounty agent run --goal "<goal>"` | No external tool execution | Converts a goal into a local planner artifact. |
| JSON output | `--json` on crawl/browser/desktop/research/check/js/report/reports/triage/reproduce/agent/release commands | No behavior change | Prints command results, planned actions, and artifact paths as machine-readable JSON where supported. |
| Jobs | `bounty jobs list` | No | Lists local workflow and command jobs. |
| Jobs | `bounty jobs show <job-id>` | No | Shows job details, action counts, checkpoint path, and workflow phases. |
| Jobs | `bounty jobs timeline <job-id>` | No | Shows structured workflow events for progress review, recovery, and handoff. |
| Jobs | `bounty jobs watch <job-id>` | No | Refreshes workflow status, action counts, recent events, and next commands until the job reaches a terminal state or `--iterations` is reached. |
| Jobs | `bounty jobs resume <job-id>` | Depends on resumed mode | Resumes an incomplete workflow from its checkpoint, skipping unchanged terminal work; checkpoint v2 records per-target skips in `resumeSkippedWork[]` and `phases[].target`. |
| Audit | `bounty audit list --job <job-id>` | No | Lists local JSONL audit events for a job. |
| Audit | `bounty audit export --job <job-id>` | No | Exports job audit events as JSON for handoff or review. |
| Actions | `bounty actions list --pending` | No | Shows queued actions that need review. |
| Actions | `bounty actions list --job <job-id> --json` | No | Prints queued actions as clean machine-readable JSON. |
| Actions | `bounty actions review --job <job-id>` | No | Shows pending and approved actions with copy-paste review, block, execute, and timeline commands. |
| Actions | `bounty actions review --job <job-id> --interactive` | No | Lets a human approve, block, skip, or quit one queued action at a time; it never executes actions by itself. |
| Actions | `bounty actions show <action-id>` | No | Shows action details, review history, and related workflow events. |
| Actions | `bounty actions approve <action-id> --note "<why>"` | No | Marks one local action approved and records a human review note. |
| Actions | `bounty actions block <action-id> --note "<why>"` | No | Marks one local action blocked and records a human review note. |
| Actions | `bounty actions execute <action-id>` | Yes for internal or explicitly enabled trusted external adapters | Executes one approved action through scope, policy, rate-limit, audit, and executor gates. |
| Actions | `bounty actions run-approved --job <job-id>` | Yes for internal or explicitly enabled trusted external adapters | Executes approved actions for a job and records per-action results. |
| Tools | `bounty tools list` | No | Shows trusted registry entries. |
| Tools | `bounty --tool-registry examples/tool-registry.yml tools list` | No | Merges a local trusted registry YAML with built-in tool metadata. |
| Tools | `bounty tools list --json` | No | Prints trusted registry entries as clean machine-readable JSON. |
| Tools | `bounty tools search [category]` | No | Searches trusted registry metadata. |
| Tools | `bounty tools search [category] --json` | No | Prints matching trusted registry entries as clean machine-readable JSON. |
| Tools | `bounty tools install <tool>` | No | Generates a trusted install plan only. |
| Tools | `bounty tools install <tool> --json` | No | Prints the install plan as machine-readable JSON without running installers. |
| Tools | `bounty tools run <tool> --target <url>` | No external tool execution | Validates and records a trusted tool run plan. |
| Tools | `bounty tools run <tool> --target <url> --json` | No external tool execution | Prints the trusted run plan, action, validation, and artifact metadata as JSON. |
| Tools | `bounty tools approve-executable <tool> --command <absolute-path>` | Local only | Approves one reviewed executable hash for a trusted tool before any live execution is allowed. |
| Tools | `bounty tools approved-executables [tool]` | No | Lists approved tool executable hashes without running them. |
| Tools | `bounty tools update` | No | Plans updates only; performs no downloads. |
| Tools | `bounty tools update --json` | No | Prints trusted update plans as machine-readable JSON. |
| Tools | `bounty tools doctor` | No | Checks local registry health only. |
| Tools | `bounty tools doctor --json` | No | Prints trusted tool health checks as machine-readable JSON. |
| Providers | `bounty providers catalog` | No | Lists built-in AI/API provider presets such as OpenAI, Anthropic, Gemini, OpenRouter, and Ollama. |
| Providers | `bounty providers connect <id> --api-key-stdin [--model model]` | No external call | Stores a provider credential and config locally, with secrets kept separate from provider metadata like opencode's connect flow. |
| Providers | `bounty providers connect <id> --api-key-env OPENAI_API_KEY [--model model]` | No external call | Configures a provider to read its API key from an environment variable instead of storing it. |
| Providers | `bounty providers connect my-provider --openai-compatible --base-url https://api.example.com/v1 --api-key-stdin --model model` | No external call | Adds a custom OpenAI-compatible provider. |
| Providers | `bounty providers list` | No | Lists configured providers without printing secrets. |
| Providers | `bounty providers show <id>` | No | Shows one provider's config, auth source, status, and models without printing secrets. |
| Providers | `bounty providers models [id]` | No | Lists configured provider models and the selected default model. |
| Providers | `bounty providers verify <id>` | No external call | Verifies local provider config and credential presence. |
| Providers | `bounty providers verify <id> --live` | Yes | Explicitly calls the provider `/models` endpoint to verify the API key. |
| Providers | `bounty providers doctor` | No | Checks all configured provider readiness. |
| Providers | `bounty providers disconnect <id>` | No | Removes a provider config and stored credential. |
| Chat | `bugbounty` | Yes when chatting through a configured provider | Opens the opencode-style full-screen TUI; if no provider is configured, starts `/connect` in TTY or prints the same TUI snapshot in non-TTY. |
| Chat | `bugbounty chat` | Yes when chatting through a configured provider | Alias for the same opencode-style TUI when no message is supplied; advice only, no tool execution. |
| Chat | `bugbounty chat "plan a safe recon flow" --provider openai --json` | Yes | Sends one chat prompt through a configured provider and prints a machine-readable response. |
| Integrations | `bounty integrations list` | No | Shows configured integrations. |
| Integrations | `bounty integrations list --json` | No | Prints integration readiness as clean machine-readable JSON. |
| Integrations | `bounty integrations show <name>` | No | Shows detailed adapter config, readiness, missing fields, and capabilities. |
| Integrations | `bounty integrations capabilities [name]` | No | Lists trusted adapter capabilities. |
| Integrations | `bounty integrations capabilities [name] --json` | No | Prints trusted adapter capabilities as clean machine-readable JSON. |
| Integrations | `bounty integrations preflight <name> <capability>` | No | Runs detailed readiness and policy preflight with `execute=false`. |
| Integrations | `bounty integrations verify <name> <capability> --target <url>` | No | Runs a local end-to-end readiness gate for scope, config, policy, execution opt-in, and executable approval without spawning the integration. |
| Integrations | `bounty integrations validate <name> <capability>` | No | Validates a call plan against adapter metadata and policy. |
| Integrations | `bounty integrations validate <name> <capability> --json` | No | Prints integration validation as machine-readable JSON. |
| Integrations | `bounty integrations setup <playwright-mcp\|crawl4ai>` | No | Writes a safe local preset, optionally pins local package hashes or approves an executable when explicit flags are provided. |
| Integrations | `bounty integrations enable <name>` | No | Enables integration metadata in the imported program config. |
| Integrations | `bounty integrations enable <name> --json` | No | Enables an integration and prints the saved config path as JSON. |
| Integrations | `bounty integrations config <name> key=value` | No | Writes integration config values to `program.yml`. |
| Integrations | `bounty integrations config <name> key=value --json` | No | Writes integration config values and prints the saved config as JSON. |
| Integrations | `bounty integrations approve-executable <name> --command <path>` | No | Locally approves an absolute executable path and SHA-256 hash for one integration. |
| Integrations | `bounty integrations approved-executables [name]` | No | Lists local executable approvals. |
| Integrations | `bounty integrations doctor` | No | Checks configured integration metadata and prints copy-paste setup, preflight, plan, and execution follow-ups. |
| Integrations | `bounty integrations doctor --json` | No | Prints integration health, MCP health, and next-command guidance as machine-readable JSON. |
| MCP | `bounty mcp plan <server> <tool>` | No external MCP execution | Prepares a policy-safe MCP plan with `execute=false`. |
| MCP | `bounty mcp plan <server> <tool> --json` | No external MCP execution | Prints the MCP plan as clean machine-readable JSON. |
| MCP | `bounty mcp call <server> <tool>` | Yes for explicitly enabled stdio MCP | Executes a registered MCP tool only when execution is enabled and its executable approval hash matches. |
| MCP | `bounty mcp session <server> --steps steps.json` | Yes for explicitly enabled stdio MCP | Executes multiple registered MCP tools in one stdio session and stores a transcript evidence artifact. |

## Safe Usage Examples

Inspect a target without touching it:

```bash
bounty init --guided --program-file examples/program.yml
bounty quickstart https://api.example.com --profile web
bounty scope test https://api.example.com
bounty run api.example.com --dry-run --with safe-checks,js-analyzer,playwright,planner
bounty actions list --pending
bounty actions review --job <job-id> --interactive
bounty cockpit
bounty cockpit --job <job-id>
bounty results
bounty results --job <job-id>
bounty jobs show <job-id>
bounty jobs timeline <job-id>
bounty review --job <job-id>
bounty audit list --job <job-id>
bounty dashboard
bounty export summary
bounty export bundle --job <job-id>
bounty beta readiness --write
bounty beta checklist --write
bounty arsenal vm --write
bounty arsenal bootstrap --level safe --write
bounty hunt profiles
bounty hunt doctor https://api.example.com --profile web
bounty hunt plan https://api.example.com --profile web --write
bounty hunt recon https://api.example.com --profile web --dry-run
bounty hunt playbook xss "https://api.example.com/search?q=test" --dry-run
bounty recon list --kind parameter
bounty recon show <observation-id>
bounty cockpit --watch --iterations 3
bounty results --min-score 40
bounty hunt run https://api.example.com --profile recon --dry-run
bounty hunt autopilot https://api.example.com --profile web --dry-run --write-plan
bounty tools approved-executables
bounty findings candidates --job <job-id>
bounty findings candidate <candidate-id>
bounty reports score <candidate-id>
```

Configure an AI/API provider locally:

```bash
bounty providers catalog
echo <api-key> | bounty providers connect openai --api-key-stdin --model gpt-4.1-mini
bounty providers verify openai
bounty providers models openai
```

Generate a VM-first runbook without executing tools:

```bash
bounty quickstart https://api.example.com --profile web --write
bounty quickstart --json
```

Resume incrementally or move to live safe checks after review:

```bash
bounty jobs resume <job-id> --dry-run
bounty jobs resume <job-id> --live --with safe-checks,js-analyzer
bounty run api.example.com --mode safe --with safe-checks,js-analyzer,planner
```

Practice against an owned local lab:

```bash
bounty import examples/local-program.yml
bounty lab demo --port 8080
bounty lab e2e http://127.0.0.1:8080
bounty lab e2e http://127.0.0.1:8080 --live --with safe-checks,js-analyzer
bounty hunt playbook cors http://127.0.0.1:8080/api/cors-demo --live
bounty hunt playbook ssrf "http://127.0.0.1:8080/api/fetch?url=http%3A%2F%2F127.0.0.1%3A8080%2Fhealthz" --live
bounty hunt playbook open-redirect "http://127.0.0.1:8080/redirect?next=https://example.org" --live
bounty hunt playbook exposure http://127.0.0.1:8080/.env --live
bounty hunt playbook xss "http://127.0.0.1:8080/search?q=%3Cbountypilot-xss%3E" --live
bounty hunt playbook graphql http://127.0.0.1:8080/graphql --live
bounty hunt playbook idor "http://127.0.0.1:8080/api/account?id=1001" --live
bounty hunt playbook js-secrets http://127.0.0.1:8080 --live
bounty findings candidates --job <job-id>
bounty reports score <candidate-id> --job <job-id>
```

Execute approved internal actions or low-rate safe checks after approval:

```bash
bounty actions approve <action-id>
bounty actions execute <action-id>
bounty actions run-approved --job <job-id>
bounty findings create --title "Manual local observation" --url https://api.example.com --severity low --confidence medium --duplicate-risk low --note "Observed safely in local evidence" --evidence proof.txt
bounty evidence add --finding <finding-id> --file proof.txt --kind evidence_note
bounty evidence add --finding <finding-id> --text "Safe manual observation" --name manual-note --job <job-id>
bounty evidence link <evidence-id> <finding-id>
bounty findings show <finding-id>
bounty findings status <finding-id> validated --note "safe local validation complete"
bounty findings candidates --reportability needs_review
bounty findings promote-candidate <candidate-id>
bounty check https://api.example.com --safe --mode safe
bounty findings
bounty evidence
bounty evidence verify --job <job-id>
```

Load a local trusted tool registry:

```bash
bounty --tool-registry examples/tool-registry.yml tools list
BOUNTYPILOT_TOOL_REGISTRY=examples/tool-registry.yml bounty tools doctor
```

The repo also includes `examples/sample-finding.json`, `examples/sample-evidence-manifest.json`, `examples/sample-report.md`, and `examples/evidence/finding-example-security-header/` as safe, non-sensitive output examples.

Prepare Playwright MCP without executing it, or execute it only after explicit stdio opt-in and local executable approval:

```bash
bounty integrations setup playwright-mcp
bounty integrations show playwright-mcp
bounty integrations preflight playwright-mcp browser.navigate --target https://api.example.com
bounty integrations validate playwright-mcp browser.navigate --target https://api.example.com
bounty mcp plan playwright-mcp browser_navigate --target https://api.example.com --arg url=https://api.example.com/
bounty integrations setup playwright-mcp --enable-execution --approve-executable
bounty integrations verify playwright-mcp browser.navigate --target https://api.example.com
bounty mcp call playwright-mcp browser_navigate --target https://api.example.com --arg url=https://api.example.com/
bounty mcp session playwright-mcp --target https://api.example.com --steps examples/mcp-steps.json
```

Generate a local report draft:

```bash
bounty reports score <candidate-id> --json
bounty reports draft <candidate-id> --platform hackerone
bounty reports draft <candidate-id> --platform bugcrowd
bounty reports bundle <candidate-id> --include-artifacts
bounty triage finding-00000000-0000-0000-0000-000000000000
bounty reports review finding-00000000-0000-0000-0000-000000000000 --write
bounty report finding-00000000-0000-0000-0000-000000000000 --platform hackerone
bounty report finding-00000000-0000-0000-0000-000000000000 --platform bugcrowd
```

## Workflow

`bounty run` is the main orchestration command. It resolves only explicit in-scope seeds, skips wildcard scope rules instead of enumerating unknown assets, records a local research note, queues actions, runs selected safe components, stores evidence, updates findings and finding candidates, writes structured workflow events, and writes `.bounty/programs/<program>/evidence/<job-id>/workflow-summary.json`.

The normal path is dry-run, review, approval, then live execution. `--dry-run` plans without target network execution. Live runs use `--mode safe` or `--mode deep-safe` and still pass through scope, policy, rate-limit, audit, and action gates. Evidence-backed signals become finding candidates first; weak signals stay as recon observations or `needs_manual_verification`, and only candidates that pass reportability checks are ready for local drafts. The JavaScript analyzer and crawl graph add scoped `plannerCandidates` such as `endpointCandidates` and `jsAssets`; the planner ranks and de-duplicates next actions from those candidates plus local evidence, findings, and action history, then writes a `planner-loop.json` evidence artifact. Actions that require approval remain `pending` until a human approves them; low-risk policy-allowed actions may be queued as `approved`, but still require an explicit execute command.

Use `jobs timeline <job-id>` to inspect phase progress, skipped work, planner output, action review, execution events, and resume decisions. Human workflow output includes copy-paste next-command hints for showing the job, opening the timeline, resuming failed work, reviewing actions, or returning to the dashboard. Use `jobs resume <job-id>` to continue an incomplete checkpoint; when target, mode, and components are unchanged, already terminal global phases are recorded as skipped, while repeated seed-scoped phases record `phases[].target` and only skip the targets that completed before interruption. New summaries include `checkpointVersion: 2` and `resumeSkippedWork[]`; `resumeSkippedPhases[]` remains as a compatibility summary of skipped phase names.

Workflow triage and report drafting are scoped to findings with evidence from the current workflow job. Older findings remain available in the workspace and dashboard, but a new workflow does not silently draft reports from older job evidence. Triage scoring stays deterministic and local-only while considering evidence diversity, source URL alignment, evidence freshness, impact signals, status, confidence, severity, and local duplicate risk. Duplicate-risk scoring normalizes route templates, category aliases, asset families, URL variants, and title similarity, but still cannot see private platform reports.

Use `export bundle --job <job-id>` for a local handoff snapshot with findings, actions, reviews, evidence manifest entries, timelines, and audit logs filtered to that job. `workspace-summary.json` remains workspace-wide; add `--include-artifacts` when you want readable evidence files copied into the bundle directory instead of only referenced by manifest metadata.

Trusted execution exists for `crawler`, `research-skill`, `external-tool`, and `stdio` MCP integrations only when the program config explicitly sets `allow_execute: true` or `execution.enabled: true` and the executable is locally approved with `integrations approve-executable`. Otherwise external components are planning-only or fail closed before spawning. Executors require absolute executable paths, reject bare commands, shell interpreters, `.cmd`/`.bat`/`.ps1` shims, verify the SHA-256 hash before every spawn, use no shell, run with a constrained environment, enforce timeouts, capture stdout/stderr or MCP results, store evidence artifacts, run scope/policy checks, and write audit logs. MCP stdout evidence also includes bounded, redacted `streamEvents` for JSON-RPC responses, notifications, progress messages, log messages, and server requests; workflow timelines record a compact stream summary when notification/progress activity is observed. Stateful Playwright MCP snapshots also fail closed unless the MCP result proves the current or final page URL is still in scope. For npm-distributed tools, configure `execution.package`, `execution.package_version`, and `execution.entrypoint`; BountyPilot resolves the installed local package entrypoint and runs it as `node <absolute-entrypoint>` after the local `node` executable has been approved. Package evidence records `entrypointSha256` and `packageJsonSha256`; add `execution.entrypoint_sha256` and `execution.package_json_sha256` to fail closed when installed package code drifts from the pinned fingerprint. It never runs `npx` or downloads packages at execution time. Tool run-plan validation also enforces BountyPilot's global blocked-capability list even if a custom registry omits `blocked_capabilities`.

`lab-offensive` is reserved for local labs, CTFs, intentionally vulnerable apps, or assets fully owned by the researcher. A lab program must set `rules.lab_mode: true` and `rules.lab_authorization_file: <relative-file>`; the authorization file is copied into the program workspace during import and must remain present for lab-offensive runs.

## Workspace Layout

```text
.bounty/
  programs/
    example-program/
      program.yml
      bountypilot.sqlite
      research/
      jobs/
      evidence/
      reports/
  db/
  logs/
  tools/
  integrations/
```

## Development Phases

1. Core CLI, config loader, workspace structure.
2. ScopeGuard, PolicyGate, RateLimiter, AuditLogger.
3. SQLite stores, JobManager, ActionQueue.
4. Safe commands: crawl, check, js, evidence, report, reproduce.
5. ToolManager, IntegrationManager, and plan/preflight adapters.
6. Human-approved ActionExecutor for internal safe adapters.
7. Dashboard and export summaries for local audit, handoff, and workflow recovery.
8. Sandboxed trusted external process executor for opt-in crawler/research/external-tool adapters.
9. Stdio MCP execution for explicitly enabled registered MCP tools.
10. Multi-step stdio MCP sessions with transcript evidence.
11. Release hardening: workflow resume, MCP stream evidence, planner loops, release checks, package-bin smoke tests, and local handoff/export flows.

## Important

Use BountyPilot only for assets you own or are explicitly authorized to test. Public research is not authorization. If a validation step would access real user data, change state, or require dangerous proof, stop and use a manual validation checklist instead.
