---
name: "bug-bounty-pilot"
description: "Safe local-first bug bounty workflow engine for authorized scoped targets. Use when Codex needs to plan or run BountyPilot recon, findings, evidence, report scoring, report drafting, VM setup, or handoff workflows without bypassing scope, policy, approval, and dry-run safety gates."
---

# Bug Bounty Pilot Skill

## Purpose
Guide an authorized bug bounty workflow from imported scope to local report draft without bypassing BountyPilot guardrails.

## What This Skill Does
- Validates program scope and rules before any target workflow.
- Plans passive recon, safe web recon, crawl, safe checks, JavaScript analysis, playbook review, evidence collection, triage, duplicate risk, report score, report draft, and handoff bundle.
- Uses BountyPilot stores and queues for observations, actions, findings, evidence, reports, and audit logs.

## What This Skill Does Not Do
- It does not scan random targets, exploit deeply, dump data, bypass authentication, evade WAFs, or submit reports.
- It never executes external tools or MCP calls. Executable paths, checksums, registry policy, and approval records are reviewable handoff metadata only.

## Authorized Use Only
Use this skill only on assets that are explicitly in scope for an imported program or a local/private lab you own.

## Inputs
- Imported BountyPilot program config.
- In-scope target URL or host.
- Execution mode: `passive`, `safe`, `deep-safe`, or `lab-offensive`.
- Optional component list such as `recon,safe-checks,js-analyzer,playbooks`.

## Outputs
- Recon observations, action queue entries, finding candidates or findings, local evidence artifacts, report-readiness scores, report drafts, and handoff bundles.

## Execution Modes
- `passive`: planning, public metadata, passive subdomains, historical URLs, local parsing only.
- `safe`: light HTTP checks, read-only browser evidence, JS extraction, safe crawler, safe checks.
- `deep-safe`: broader crawl and approved discovery/validation tools with rate limits and review gates.
- `lab-offensive`: local/private intentionally vulnerable labs only with `rules.lab_mode=true` and authorization evidence.

## Safety Model
All live work must pass ScopeGuard, PolicyGate, RateLimiter, AuditLogger, and ActionQueue. Review-required tools remain pending until approved.

## Scope Rules
Default deny. Out-of-scope entries take precedence. Program import and scope match are required.

## Policy Gates
The policy in `policy.yml` is authoritative for skill-level mode capability decisions.

## Human Approval Gates
Active scanning, fuzzing, nuclei medium/high, ffuf, dalfox, naabu, and nmap require human review in a separate researcher-controlled workflow. External executable and MCP proposals remain plan/handoff-only even after review; BountyPilot never dispatches them.

## Tool Arsenal
The planning registry is declared in `tool-registry.yml`. Registry entries are never installed, spawned, or dispatched by this skill; an executable fingerprint is not execution authority.

## Recon Workflow
Passive recon creates observations from approved passive sources. Web recon can queue target actions for BountyPilot review; only allowlisted built-in low-risk actions can later execute through `ActionExecutor` after all gates pass.

## Hunt Workflow
The hunt workflow plans and queues steps, executes only eligible built-in low-risk actions through `ActionExecutor`, stores artifacts, creates candidates, scores report readiness, and stops for human review. External and MCP steps stay handoffs.

## Playbook Workflow
Playbooks in `playbooks.yml` define evidence thresholds and approval gates. Weak signals stay as observations or candidates.

## Evidence Workflow
Evidence is local-only, redacted, linked to job/finding/candidate context, and represented by a manifest.

## Report Workflow
Reports are drafted locally only when readiness checks pass. No platform submission is performed.

## CLI Commands
- `bounty skill list`
- `bounty skill show bug-bounty-pilot`
- `bounty skill validate bug-bounty-pilot`
- `bounty skill export bug-bounty-pilot --output .bounty/skills/bug-bounty-pilot`
- `bounty skill bundle bug-bounty-pilot --output bug-bounty-pilot.skill.zip`
- `bounty skill verify-bundle bug-bounty-pilot.skill.zip`
- `bounty skill run bug-bounty-pilot <target> --program <program> --mode passive --dry-run`

## VM Setup
Use `bounty arsenal vm --write` and `bounty arsenal bootstrap --level safe --write` to generate local VM instructions/scripts. Review before running scripts manually.

## Local Lab Usage
Use `lab-offensive` only with local/private lab scope, `rules.lab_mode=true`, and authorization evidence.

## Public Program Usage
Use `passive`, `safe`, or `deep-safe` according to program rules. Keep risky actions pending for manual review.

## Failure Behavior
Missing tools are warnings. Out-of-scope targets block. Parser failures store raw evidence and do not create findings. Missing evidence blocks report drafts.

## Acceptance Criteria
- Skill validates successfully.
- `bounty skill run bug-bounty-pilot ...` routes through BountyPilot runtime guardrails.
- Recon observations, evidence, report score, and local draft workflows remain local and auditable.
