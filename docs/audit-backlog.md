# BountyPilot Audit Backlog

High-value work tracked from the five-agent audit pass:

## P0

- No open P0 items after the current safety hardening pass.

## P1

- No open P1 items after the current resume granularity pass.

## P2

- No open P2 items after the current CLI UX pass.

## Completed in current pass

- Bug-results engine pass adds recon observation persistence, trusted bounty tool approvals and runner metadata, `hunt recon`, `hunt playbook`, report scoring, evidence recording, and planner ingestion of normalized recon observations while keeping dry-run, scope, policy, and review gates intact.
- `hunt` and `arsenal` now provide a VM-ready authorized hunting layer: profile-driven recon/web/validation/lab workflows, scoped Markdown hunt plans, dry-run/live guarded execution, curated tool categories, and a VM arsenal plan based on common bug bounty tool taxonomies.
- `hunt doctor`, `hunt autopilot`, and `arsenal bootstrap` now close the VM workflow loop with readiness checks, one-command guarded plan/run/review/bundle orchestration, and a reviewed Bash bootstrap script generator that never executes automatically.
- `providers` now supports an opencode-style credential/config split with catalog, connect, list, show, models, verify, doctor, and disconnect commands; API keys are stored in `.bounty/providers/auth.json` or resolved from env vars, while provider metadata lives in `.bounty/providers/providers.json`.
- `beta checklist` now generates a Markdown beta handoff checklist from current readiness checks, blockers, warnings, safety notes, and required release/demo-lab commands.
- Package-bin smoke now installs the packed tarball into a clean consumer project and runs a first-user flow through the bin shim, beta readiness, guided local-program import, demo lab startup, and live lab E2E evidence creation.
- `beta readiness` now scores workspace, program, package, script, example, and release readiness for beta handoff, with blockers, warnings, next commands, and optional JSON report output.
- `review --job` now behaves more like a job cockpit: it adds workflow/action/evidence/finding/report health checks, phase counts, job-linked finding summaries, report readiness hints, and state-aware next commands while preserving the existing JSON fields.
- `lab demo` now serves a loopback-only built-in demo lab with safe HTML, JavaScript, and API routes so researchers can practice the full local workflow without touching third-party assets.
- `lab e2e` now runs a local lab preflight plus optional explicit live workflow against local/private lab targets, with lab authorization, scope, policy, workflow summary, recent events, and next-command guidance.
- `d-research-skill` workflow component now records a local public research ledger without executing external skills.
- Program-wide workflow resume keeps the original full scope instead of falling back to the first seed.
- Workflows with non-fatal failed phases now end with failed summary/job status and failing CLI exit code.
- Release checks parse structured JSON/YAML examples and fail malformed shipped examples.
- Human workflow output now includes recent timeline events after `run` and `jobs resume`.
- Package entrypoint execution records package metadata and entrypoint SHA-256 fingerprints, and optional hash pins fail closed when installed package files drift.
- MCP malformed or oversized stdout frame failures now write bounded, redacted failure artifacts before returning `MCP_FRAME_*` errors.
- Checkpoint v2 resume granularity now records `phases[].target` and `resumeSkippedWork[]`, skips repeated live phases per target for `safe-checks`, `js-analyzer`, and `playwright`, keeps legacy single-seed checkpoints compatible, and avoids ambiguous whole-phase skips for legacy multi-seed checkpoints without action evidence.
- Playwright MCP `browser.snapshot` now has a scoped postcondition: evidence is only usable when the MCP result proves the current or final page URL remains in scope; missing or out-of-scope state URLs fail closed with `MCP_POSTCONDITION_*`.
- Human workflow output now prints copy-paste next-command hints for job details, timeline review, resume, action execution, and dashboard follow-up.
- Workflow triage and report drafting now scope findings to evidence created by the current workflow job, preventing a new workflow from silently triaging or drafting reports for findings produced by older jobs.
- `actions review` now presents pending/approved actions as a review queue with copy-paste approve, block, execute, run-approved, and timeline commands.
- `jobs watch` now refreshes job status, action counts, recent events, and next commands until terminal state or a caller-provided iteration limit.
- Crawl4AI/external crawler outputs now normalize pages, links, endpoint candidates, JavaScript assets, forms, and routes, then feed scoped URLs into the crawl graph.
- Triage now uses deterministic local scoring for evidence diversity, source URL alignment, evidence freshness, impact signals, status, confidence, severity, and duplicate risk; duplicate-risk scoring now handles route templates, category aliases, asset families, URL variants, title similarity, query divergence, and status-weighted local history.
- Stdio MCP execution now captures bounded, redacted stream events for JSON-RPC responses, notifications, progress messages, log messages, and server requests, including active step indexes for session events and compact workflow timeline summaries when notification/progress activity is present.
- Agent planner loops now rank and de-duplicate candidates across seeds, crawl graph pages, JavaScript endpoints, evidence source URLs, findings, and action history; workflow and CLI planner paths write planner-loop artifacts while keeping PolicyGate and ActionQueue as the execution authority.
