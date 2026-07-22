# BountyPilot

BountyPilot is a safe, local-first, scoped bug bounty CLI for authorized security researchers. It is designed to collect evidence, coordinate safe checks, and generate report drafts while preserving scope, rate limits, auditability, reproducibility, and human control.

This branch is the v0.2 release candidate. It intentionally avoids unrestricted exploit automation; the immutable `v0.2.0` release exists only after review and an explicit future tag publication.

## Safety Model

- Only explicitly in-scope assets are allowed.
- Out-of-scope rules override in-scope rules.
- Target actions flow through `ScopeGuard`, `PolicyGate`, `RateLimiter`, `AuditLogger`, `JobManager`, and `ActionQueue`.
- Destructive testing, brute force, credential stuffing, spam, data exfiltration, WAF evasion, malware execution, and mass internet scanning are blocked.
- External integrations, MCP servers, and registry tools produce plans or handoff artifacts only; BountyPilot does not dispatch them.
- `ActionExecutor` is limited to built-in low-risk actions after the required scope, policy, rate-limit, and human-review gates pass.
- Reports are generated as local drafts only. BountyPilot does not auto-submit reports.
- BountyPilot does not automatically exploit targets and cannot guarantee that it will find a bug, avoid duplicates, or earn a bounty.

## CLI Interface

The CLI uses a compact, terminal-first presentation inspired by modern agent CLIs: concise headers, status tags, section panels, and scan-friendly tables. Set `NO_COLOR=1` to disable ANSI color.

## Install From GitHub

BountyPilot requires Node.js 22.13.0 or newer.

Install the current reviewed candidate directly from its public GitHub branch:

```bash
npm install -g github:Titananh/bountypilot#codex/hermes-bountypilot-agent
```

Linux/macOS installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Titananh/bountypilot/codex/hermes-bountypilot-agent/scripts/install.sh \
  | BOUNTYPILOT_SOURCE=github:Titananh/bountypilot#codex/hermes-bountypilot-agent bash
```

Windows PowerShell installer:

```powershell
$env:BOUNTYPILOT_SOURCE="github:Titananh/bountypilot#codex/hermes-bountypilot-agent"
irm https://raw.githubusercontent.com/Titananh/bountypilot/codex/hermes-bountypilot-agent/scripts/install.ps1 | iex
```

Set `BOUNTYPILOT_INSTALL_DRY_RUN=1` to make either installer verify Node/npm and print the resolved `npm install -g ...` command without installing globally. The scripts require an explicit `BOUNTYPILOT_SOURCE`, `BOUNTYPILOT_REPO`, or `BOUNTYPILOT_VERSION`; they never fall back to an unpublished npm package name.

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

## Hermes Agent Distribution

The Hermes 0.17+ profile distribution is in `hermes/bountypilot-agent`. The repository root is not a Hermes profile and must not be passed to `hermes profile install`. The distribution includes nine scope-first skills for program intake, safety, public-policy research, local evidence, validation notes, duplicate-risk review, triage, orchestration, and HackerOne-style report drafting.

The Hermes skills require the BountyPilot CLI `0.2.0` on `PATH`. Installing the nested profile does not install the CLI. For the current reviewed candidate branch, install both from the same checkout:

```bash
git clone --branch codex/hermes-bountypilot-agent --depth 1 https://github.com/Titananh/bountypilot.git bountypilot
cd bountypilot
npm ci
npm install -g .
bounty --version
hermes profile install ./hermes/bountypilot-agent --name bugbounty --alias -y
hermes profile use bugbounty
```

The distributed profile also disables Hermes web/browser/MCP/delegation toolsets
and configures the terminal as an air-gapped Docker backend
(`terminal.docker_network: false`, no forwarded environment variables). Docker
must be available before starting Hermes; do not silently switch this profile
to a host-local terminal. The supported one-command setup is the dedicated
`hermes profile install` flow above because it installs the reviewed `SOUL.md`
and the complete [`config.yaml`](hermes/bountypilot-agent/config.yaml) together.
Do not reduce that contract to only a Docker backend and network switch: it also
disables every target-capable Hermes toolset, persistence, environment
forwarding, cron approvals, and lazy installs.

`bounty --version` must print `0.2.0` before the profile is used. After an immutable `v0.2.0` tag is actually published, replace the branch in the clone command with `v0.2.0`. Do not create or assume that tag merely to install the current candidate branch.

Never pass the repository root to `hermes profile install`, and do not use `--force` to overlay this dedicated distribution onto an existing profile.

After installing BountyPilot CLI `0.2.0` from the reviewed checkout (or from an npm release only after one is published), merge the managed skills and bundle into an existing named profile without replacing its credentials, SOUL, config, memories, unrelated skills, or unrelated bundles:

```bash
bountypilot-hermes --dry-run --profile bugbounty
bountypilot-hermes --apply --profile bugbounty
bountypilot-hermes --verify --profile bugbounty
hermes profile use bugbounty
hermes chat
```

The merge path is only for an existing profile that is already hardened to the
full zero-live contract in the distributed `config.yaml`. The installer reads
only the required safety fields and fails before any mutation if the profile is
missing them or weakens them. It never prints configuration values. Review the
existing profile's `SOUL.md` yourself as well; when in doubt, create the
dedicated profile instead of merging.

The default profile name is `bugbounty`. `--dry-run` is read-only, validates the
profile safety contract, and shows the ten managed skill/bundle entries that
would change. `--verify` validates both that safety contract and the installed
managed entries. During `--apply`, the installer stages each managed entry and
swaps it into place with a same-filesystem `rename`; if that process reports a
failure, it uses its journal to roll back completed swaps. This is per-entry,
in-process rollback, not whole-profile or power-loss atomicity. Only conflicting
BountyPilot-managed entries are backed up under the profile's
`local/bountypilot-agent/backups/` directory. The merge path deliberately
preserves the existing profile's `SOUL.md` and `config.yaml`.

Inside the interactive Hermes session, invoke the bundle with one natural-language request for a zero-live mission receipt:

```text
/bountypilot Continue the exact imported program ACME as one zero-live BountyPilot dry-run mission. Return the authoritative receipt, pending action IDs, limitations, and exact human review commands. Do not claim that a bug, validation, evidence, or report exists unless the receipt explicitly records it.
```

This v0.2 integration turns one request into exactly one typed local dry-run mission. The current v1 receipt is terminal for Hermes, sets `draftReports: false`, and records `reportsDrafted: 0`; a generic `human_handoff` therefore means the mission finished, not that a report or vulnerability exists. Hermes stops at that receipt and does not delegate or continue research afterward. The other eight suite skills remain available for separate, explicitly requested local follow-up over existing sanitized artifacts. Hermes never dispatches external integrations, MCP servers, registry tools, or live target actions, and it never treats approval-bypass modes as authority. After explicit human review, only BountyPilot's built-in low-risk actions can run through `ActionExecutor`. The agent does not automatically exploit targets or submit reports. The researcher must independently validate and submit any final report, and there is no guarantee of finding a bug, producing a non-duplicate result, receiving acceptance, or earning a bounty.

## Safe Workflow Guide

Use the workflow as a gated loop, not a fire-and-forget scan:

1. Start with written authorization from the program owner. BountyPilot scope files document authorization boundaries; they do not create authorization.
2. Run `bounty init`, then `bounty import <program.yml>` to create a local workspace under `.bounty/programs/<program>/`. Imported execution opt-ins are stripped to planning-only state.
3. Confirm boundaries with `bounty scope list` and `bounty scope test <url>` before planning any activity.
   Path-scoped rules must be written as explicit URLs such as `https://api.example.com/app`; bare `api.example.com/app` is rejected to avoid accidental host-wide scope.
4. Start every target with `bounty run <target> --dry-run`. Dry runs write local notes, workflow events, queued component actions, and a summary without target network execution. Live JS/crawl phases or `agent plan --from-job` add richer `plannerCandidates` and planner-loop evidence.
5. Inspect the checkpoint with `bounty jobs show <job-id>`, `bounty jobs timeline <job-id>`, `bounty actions list --pending`, and `bounty actions show <action-id>`.
6. Approve or block actions deliberately with `bounty actions approve` or `bounty actions block`. Actions that require approval stay `pending`; low-risk policy-allowed actions can appear as `approved`, but built-in actions do not run until `actions execute` or `actions run-approved`.
7. Move to live built-in checks only after scope, program rules, rate limits, and action approval are clear: use `bounty run <target> --mode safe`, `bounty actions execute <action-id>`, or `bounty actions run-approved --job <job-id>`. `ActionExecutor` rejects external, MCP, and registry-tool dispatch.
8. Resume interrupted jobs with `bounty jobs resume <job-id>`. Resume is incremental: unchanged completed global phases are skipped, seed-scoped phases such as `safe-checks`, `js-analyzer`, and `playwright` resume per target, and `resumeSkippedWork[]` plus workflow events show what was reused or continued.
9. Treat external components as handoffs. `crawl4ai`, `playwright-mcp`, other MCP servers, and registry tools can be configured and planned, but BountyPilot does not spawn or dispatch them.
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
| Release | `bounty release publish-plan OWNER/REPO --write` | No | Writes a GitHub publish plan with remote, push, tag, install, Actions, release artifact, and public-readiness checklist commands. |
| Release | `bounty release publish-status OWNER/REPO --online --actions --json` | GitHub git remote and GitHub CLI when requested | Checks release gate, origin target, clean tree, branch/tag state, remote branch/tag publication, required Actions workflow success, and public-readiness next commands after push. |
| Release | `bounty release publish-status OWNER/REPO --write-public-plan .bounty/release/public-readiness.md --json` | No | Checks publish status and writes the same public-readiness Markdown checklist in one command. |
| Release | `bounty release public-gate OWNER/REPO --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json` | GitHub git remote and GitHub CLI when requested | Runs the final public gate by combining publish status, skill score, public-readiness plan output, and optional installed CLI verification. |
| Release | `bounty release install-check --json` | No | Verifies an installed `bugbounty` command can boot, validate the bundled skill, score readiness, expose skill metadata, and render fresh-user quickstart JSON. |
| Release | `npm run verify:release` | No | Runs build, docs command-snippet verification, tests, fresh-install package-bin smoke, release checks, and dry-run pack as one gate. |
| Release | `npm run test:external-tools` | No | Exercises external-tool plan parsing, guard failures, handoff artifacts, and crawl graph wiring with local fixtures; it does not spawn the fixtures. |
| Release | `npm run test:vm-lab` | Local loopback only | Installs the packed CLI into a clean consumer project, starts the demo lab, runs live lab E2E, and verifies beta readiness from the installed binary. |
| Release | `npm run test:vm-real-tools` | No target network through BountyPilot | Ubuntu/VM smoke that detects installed `httpx` and `katana` and verifies plan/handoff metadata without BountyPilot dispatching either tool. |
| Skill | `bounty skill validate bug-bounty-pilot` | No | Validates the bundled skill policy, workflow, tool registry, playbooks, prompts, templates, and examples. |
| Skill | `bounty skill score bug-bounty-pilot` | No | Scores skill readiness across validation, bundle verification, release gates, `layers.local`/`layers.publish`, `publicReadiness.missing[].commands`, and an ordered `publicReadiness.fixPlan`. |
| Skill | `bounty skill score bug-bounty-pilot --repo OWNER/REPO --json` | No | Scores the skill and embeds concrete GitHub publish/bootstrap readiness for a target repository. |
| Skill | `bounty skill score bug-bounty-pilot --repo OWNER/REPO --write-public-plan .bounty/release/public-readiness.md --json` | No | Writes the ordered public-readiness checklist as Markdown for GitHub handoff or release review. |
| Skill | `bounty skill score bug-bounty-pilot --repo OWNER/REPO --strict --json` | No | Fails unless the package, skill bundle, release checks, and GitHub publish preflight have no blockers or warnings. |
| Skill | `bounty skill score bug-bounty-pilot --repo OWNER/REPO --online --actions --strict --json` | GitHub git remote and GitHub CLI | Final public-readiness score after pushing branch/tag and required GitHub Actions complete. |
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
| Workflow | `bounty run [target] --mode safe` | Yes | Runs selected built-in low-risk components only after scope and policy checks. |
| Workflow | `bounty run [target] --mode deep-safe --with safe-checks,js-analyzer,playwright,planner` | Yes | Adds built-in browser evidence capture, still behind scope, policy, and rate limits. |
| Workflow | `bounty run [target] --mode lab-offensive` | Local lab only | Blocked unless the imported program config sets `rules.lab_mode: true`, includes `rules.lab_authorization_file`, and targets local/private lab assets only. |
| Hunt | `bounty hunt profiles` | No | Lists guided recon, web, validate, and lab-aggressive hunt profiles inspired by recon-to-report bug bounty workflows. |
| Hunt | `bounty hunt doctor <target> --profile web` | No | Checks scope, provider config, tool-plan readiness, VM arsenal readiness, and profile gates before hunting. |
| Hunt | `bounty hunt plan <target> --profile web --write` | No | Builds a scoped Markdown hunt plan with phases, bug classes, validation gates, tool readiness, and next commands. |
| Hunt | `bounty hunt recon <target> --profile web --dry-run` | No | Plans recon tools, queues review-required scanners, and stores a recon job without dispatching external tools. |
| Hunt | `bounty hunt recon <target> --profile web --live` | Built-in checks only | Runs eligible built-in low-risk checks and writes external-tool plans for manual handoff; it does not spawn registry tools. |
| Hunt | `bounty hunt playbook xss <target> --dry-run` | No | Plans a bug-class playbook and records weak signals as recon observations instead of findings. |
| Hunt | `bounty hunt playbook cors <target> --live` | Yes | Sends a safe Origin-header check, records `cors-validation.json`, and promotes credentialed reflected-origin evidence to a finding candidate. |
| Hunt | `bounty hunt playbook ssrf <target> --live` | Lab only | Records server-fetch findings only when `rules.lab_mode=true`, the callback URL is loopback/in-scope, and response metadata proves the fetch indicator. |
| Hunt | `bounty hunt playbook js-secrets <target> --live` | Yes | Runs safe checks and JavaScript analysis, creating finding candidates only when evidence thresholds are met. |
| Hunt | `bounty hunt run <target> --profile recon --dry-run` | No | Runs the guided hunt profile in planning mode, queues safe next actions, and writes local workflow artifacts. |
| Hunt | `bounty hunt run <target> --profile web --live` | Built-in checks only | Runs eligible built-in low-risk profile steps after all gates pass and leaves external steps as handoffs. |
| Hunt | `bounty hunt autopilot <target> --profile web --dry-run --write-plan` | No | Runs plan, profile workflow, review cockpit, and optional handoff bundle as one guarded flow. |
| Hunt | `bounty hunt autopilot <target> --profile web --live --bundle` | Built-in checks only | Runs eligible built-in low-risk steps after guardrails pass and bundles external plans for manual handoff. |
| Recon | `bounty recon list [--job <job-id>] [--kind parameter]` | No | Lists normalized recon observations from previous recon/playbook/tool runs with kind/source counts. |
| Recon | `bounty recon show <observation-id-or-fingerprint>` | No | Shows one recon observation, related job evidence, and copy-paste follow-up commands. |
| Arsenal | `bounty arsenal profiles` | No | Lists VM-ready bug bounty tools, categories, purposes, and run policies. |
| Arsenal | `bounty arsenal vm --write [--output vm-arsenal.md]` | No | Writes a VM bootstrap plan for recon, URL discovery, validation, evidence, and reporting tools without installing anything automatically. |
| Arsenal | `bounty arsenal bootstrap --level safe --write [--output bootstrap.sh]` | No | Writes a reviewed Bash install script for passive/safe VM tools; it does not execute the script. |
| Arsenal | `bounty arsenal bootstrap --level full --write [--output bootstrap.sh]` | No | Writes a fuller VM install script including review-required tools such as nuclei, ffuf, dalfox, and naabu. |
| Lab | `bounty lab demo --port 8080` | Local loopback only | Serves a built-in read-only demo lab on loopback for practicing BountyPilot workflows without touching third-party assets. |
| Lab | `bounty lab e2e <local-url>` | No by default; local lab only with `--live` | Runs lab-mode, authorization, scope, and policy gates, then creates a dry-run checkpoint unless `--live` is explicit. |
| Lab | `bounty lab e2e <local-url> --live --with safe-checks,js-analyzer` | Local lab only | Runs selected workflow components against an explicitly in-scope local/private lab target and records workflow evidence. |
| Workflow | `bounty run [target] --with crawl4ai,playwright-mcp` | No external dispatch | Validates the requested adapters and records plan/handoff artifacts; it does not start either component. |
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
| AI assistant | `bounty ai plan --target <target> [--job <job-id>] [--write]` | Provider call only | Generates a scoped dry-run plan from local context; it cannot execute tools, approve actions, or bypass scope. |
| AI assistant | `bounty ai report <candidate-id> [--platform hackerone|bugcrowd] [--write]` | Provider call only | Generates local report prose from candidate/evidence metadata; it never submits reports or claims validation without artifacts. |
| JSON output | `--json` on crawl/browser/desktop/research/check/js/report/reports/triage/reproduce/agent/ai/release commands | No behavior change | Prints command results, planned actions, and artifact paths as machine-readable JSON where supported. |
| Jobs | `bounty jobs list` | No | Lists local workflow and command jobs. |
| Jobs | `bounty jobs show <job-id>` | No | Shows job details, action counts, checkpoint path, and workflow phases. |
| Jobs | `bounty jobs timeline <job-id>` | No | Shows structured workflow events for progress review, recovery, and handoff. |
| Jobs | `bounty jobs watch <job-id>` | No | Refreshes workflow status, action counts, recent events, and next commands until the job reaches a terminal state or `--iterations` is reached. |
| Jobs | `bounty jobs resume <job-id>` | Depends on resumed mode | Resumes an incomplete workflow from its checkpoint, skipping unchanged terminal work; checkpoint v2 records per-target skips in `resumeSkippedWork[]` and `phases[].target`. |
| Audit | `bounty audit list --job <job-id>` | No | Lists local JSONL audit events for a job. |
| Audit | `bounty audit export --job <job-id>` | No | Exports job audit events as JSON for handoff or review. |
| Actions | `bounty actions list --pending` | No | Shows queued actions that need review. |
| Actions | `bounty actions list --job <job-id> --json` | No | Prints queued actions as clean machine-readable JSON. |
| Actions | `bounty actions review --job <job-id>` | No | Shows pending and approved actions with review, block, built-in execute, and timeline commands. |
| Actions | `bounty actions review --job <job-id> --interactive` | No | Lets a human approve, block, skip, or quit one queued action at a time; it never executes actions by itself. |
| Actions | `bounty actions show <action-id>` | No | Shows action details, review history, and related workflow events. |
| Actions | `bounty actions approve <action-id> --note "<why>"` | No | Marks one local action approved and records a human review note. |
| Actions | `bounty actions block <action-id> --note "<why>"` | No | Marks one local action blocked and records a human review note. |
| Actions | `bounty actions execute <action-id>` | Built-in low-risk action only | Executes one approved built-in action through scope, policy, rate-limit, audit, and `ActionExecutor` gates; external actions remain handoffs. |
| Actions | `bounty actions run-approved --job <job-id>` | Built-in low-risk actions only | Executes eligible approved built-in actions for a job; external, MCP, and registry-tool actions are not dispatched. |
| Tools | `bounty tools list` | No | Shows registry entries. |
| Tools | `bounty --tool-registry examples/tool-registry.yml tools list` | No | Merges a local registry YAML with built-in tool metadata. |
| Tools | `bounty tools list --json` | No | Prints registry entries as clean machine-readable JSON. |
| Tools | `bounty tools search [category]` | No | Searches registry metadata. |
| Tools | `bounty tools search [category] --json` | No | Prints matching registry entries as clean machine-readable JSON. |
| Tools | `bounty tools install <tool>` | No | Generates an install plan only. |
| Tools | `bounty tools install <tool> --json` | No | Prints the install plan as machine-readable JSON without running installers. |
| Tools | `bounty tools run <tool> --target <url>` | No external tool execution | Validates and records a tool run plan for handoff. |
| Tools | `bounty tools run <tool> --target <url> --json` | No external tool execution | Prints the run plan, action, validation, and handoff artifact metadata as JSON. |
| Tools | `bounty tools approve-executable <tool> --command <absolute-path>` | Local only | Records a reviewed executable fingerprint as handoff metadata; it does not authorize BountyPilot to spawn the tool. |
| Tools | `bounty tools approved-executables [tool]` | No | Lists recorded executable fingerprints used in manual handoffs. |
| Tools | `bounty tools update` | No | Plans updates only; performs no downloads. |
| Tools | `bounty tools update --json` | No | Prints update plans as machine-readable JSON. |
| Tools | `bounty tools doctor` | No | Checks local registry health only. |
| Tools | `bounty tools doctor --json` | No | Prints tool-plan health checks as machine-readable JSON. |
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
| Integrations | `bounty integrations capabilities [name]` | No | Lists registered adapter capabilities. |
| Integrations | `bounty integrations capabilities [name] --json` | No | Prints registered adapter capabilities as clean machine-readable JSON. |
| Integrations | `bounty integrations preflight <name> <capability>` | No | Runs detailed readiness and policy preflight with `execute=false`. |
| Integrations | `bounty integrations verify <name> <capability> --target <url>` | No | Runs a local readiness gate for scope, config, policy, and handoff metadata without spawning the integration. |
| Integrations | `bounty integrations validate <name> <capability>` | No | Validates a call plan against adapter metadata and policy. |
| Integrations | `bounty integrations validate <name> <capability> --json` | No | Prints integration validation as machine-readable JSON. |
| Integrations | `bounty integrations setup <playwright-mcp\|crawl4ai>` | No | Writes safe local configuration for planning and handoff. |
| Integrations | `bounty integrations enable <name>` | No | Enables integration plan metadata in the imported program config. |
| Integrations | `bounty integrations enable <name> --json` | No | Enables integration plan metadata and prints the saved config path as JSON. |
| Integrations | `bounty integrations config <name> key=value` | No | Writes integration config values to `program.yml`. |
| Integrations | `bounty integrations config <name> key=value --json` | No | Writes integration config values and prints the saved config as JSON. |
| Integrations | `bounty integrations approve-executable <name> --command <path>` | No | Records an absolute executable path and SHA-256 fingerprint for a manual handoff; BountyPilot still does not spawn it. |
| Integrations | `bounty integrations approved-executables [name]` | No | Lists executable fingerprints recorded as manual-handoff metadata. |
| Integrations | `bounty integrations doctor` | No | Checks configured integration metadata and prints setup, preflight, plan, and handoff follow-ups. |
| Integrations | `bounty integrations doctor --json` | No | Prints integration health, MCP health, and next-command guidance as machine-readable JSON. |
| MCP | `bounty mcp plan <server> <tool>` | No external MCP execution | Prepares a policy-safe MCP plan with `execute=false`. |
| MCP | `bounty mcp plan <server> <tool> --json` | No external MCP execution | Prints the MCP plan as clean machine-readable JSON. |
| MCP | `bounty mcp call <server> <tool>` | No external MCP execution | Records a single-tool MCP handoff request; it does not start a server or call the tool. |
| MCP | `bounty mcp session <server> --steps steps.json` | No external MCP execution | Records an ordered MCP session plan for handoff; it does not open a stdio session. |

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

Load a local tool registry for planning and handoff:

```bash
bounty --tool-registry examples/tool-registry.yml tools list
BOUNTYPILOT_TOOL_REGISTRY=examples/tool-registry.yml bounty tools doctor
```

The repo also includes `examples/sample-finding.json`, `examples/sample-evidence-manifest.json`, `examples/sample-report.md`, and `examples/evidence/finding-example-security-header/` as safe, non-sensitive output examples.

Prepare a Playwright MCP handoff. These commands do not start an MCP server or dispatch a tool:

```bash
bounty integrations setup playwright-mcp
bounty integrations show playwright-mcp
bounty integrations preflight playwright-mcp browser.navigate --target https://api.example.com
bounty integrations validate playwright-mcp browser.navigate --target https://api.example.com
bounty mcp plan playwright-mcp browser_navigate --target https://api.example.com --arg url=https://api.example.com/
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

`bounty run` is the main orchestration command. It resolves only explicit in-scope seeds, skips wildcard scope rules instead of enumerating unknown assets, records a local research note, queues actions, runs selected built-in low-risk components, stores evidence, updates findings and finding candidates, writes structured workflow events, and writes `.bounty/programs/<program>/evidence/<job-id>/workflow-summary.json`.

The normal path is dry-run, review, approval, then live execution of eligible built-in low-risk actions. `--dry-run` plans without target network execution. Live built-in runs use `--mode safe` or `--mode deep-safe` and still pass through scope, policy, rate-limit, audit, and action gates. Evidence-backed signals become finding candidates first; weak signals stay as recon observations or `needs_manual_verification`, and only candidates that pass reportability checks are ready for local drafts. The JavaScript analyzer and crawl graph add scoped `plannerCandidates` such as `endpointCandidates` and `jsAssets`; the planner ranks and de-duplicates next actions from those candidates plus local evidence, findings, and action history, then writes a `planner-loop.json` evidence artifact. Actions that require approval remain `pending` until a human approves them; built-in low-risk actions may be queued as `approved`, but still require an explicit execute command. External, MCP, and registry-tool actions remain plans or handoffs regardless of approval metadata.

Use `jobs timeline <job-id>` to inspect phase progress, skipped work, planner output, action review, execution events, and resume decisions. Human workflow output includes copy-paste next-command hints for showing the job, opening the timeline, resuming failed work, reviewing actions, or returning to the dashboard. Use `jobs resume <job-id>` to continue an incomplete checkpoint; when target, mode, and components are unchanged, already terminal global phases are recorded as skipped, while repeated seed-scoped phases record `phases[].target` and only skip the targets that completed before interruption. New summaries include `checkpointVersion: 2` and `resumeSkippedWork[]`; `resumeSkippedPhases[]` remains as a compatibility summary of skipped phase names.

Workflow triage and report drafting are scoped to findings with evidence from the current workflow job. Older findings remain available in the workspace and dashboard, but a new workflow does not silently draft reports from older job evidence. Triage scoring stays deterministic and local-only while considering evidence diversity, source URL alignment, evidence freshness, impact signals, status, confidence, severity, and local duplicate risk. Duplicate-risk scoring normalizes route templates, category aliases, asset families, URL variants, and title similarity, but still cannot see private platform reports.

Use `export bundle --job <job-id>` for a local handoff snapshot with findings, actions, reviews, evidence manifest entries, timelines, and audit logs filtered to that job. `workspace-summary.json` remains workspace-wide; add `--include-artifacts` when you want readable evidence files copied into the bundle directory instead of only referenced by manifest metadata.

External adapters, MCP servers, research skills, and registry tools are planning and handoff surfaces only. BountyPilot validates their metadata, scope, policy, arguments, and blocked capabilities, then records reviewable artifacts; it does not spawn their executables, open stdio sessions, download packages, or dispatch their calls. An executable fingerprint or integration setting is handoff metadata, not execution authority. `ActionExecutor` accepts only built-in low-risk actions and rechecks scope, policy, rate limits, approval, and audit requirements before each run.

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
6. Human-approved `ActionExecutor` for built-in low-risk actions only.
7. Dashboard and export summaries for local audit, handoff, and workflow recovery.
8. Plan and handoff adapters for external crawlers, research skills, and registry tools without process dispatch.
9. MCP call and multi-step session plans without starting a server or opening stdio.
10. Release hardening: workflow resume, planner loops, release checks, package-bin smoke tests, and local handoff/export flows.

## Important

Use BountyPilot only for assets you own or are explicitly authorized to test. Public research is not authorization. If a validation step would access real user data, change state, or require dangerous proof, stop and use a manual validation checklist instead.
