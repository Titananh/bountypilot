# BountyPilot Research State Machine

Use this state machine as orchestration memory. BountyPilot's current persisted lifecycle and policy result remain authoritative if they are stricter.

## States

| State | Entry evidence | Allowed next state |
| --- | --- | --- |
| `authority_pending` | Request received | `authority_ready`, `blocked` |
| `authority_ready` | Exact imported program and fresh policy/scope | `recon_planned`, `blocked` |
| `recon_planned` | Dry-run reviewed; seed in scope | `recon_complete`, `approval_pending`, `blocked` |
| `approval_pending` | Exact target-facing/risky/state-changing/external/MCP proposal recorded | `human_action_handoff`, `blocked` |
| `human_action_handoff` | Exact action and current gates delivered to the user | terminal state for this Hermes run |
| `recon_complete` | Scoped observations with provenance | `evidence_ready`, `blocked` |
| `evidence_ready` | Sanitized evidence verifies | `validation_planned`, `triage_ready`, `blocked` |
| `validation_planned` | Falsifiable minimal hypothesis and stop conditions | `validated`, `inconclusive`, `approval_pending`, `blocked` |
| `validated` | Reproducible bounded claim with verified evidence | `duplicate_checked`, `triage_ready` |
| `inconclusive` | Attempt recorded without proof | `validation_planned`, `blocked` |
| `duplicate_checked` | Timestamped accessible-source assessment | `triage_ready` |
| `triage_ready` | Scope, evidence, validation, impact, severity, duplicate inputs complete | `draft_ready`, `blocked`, `validation_planned` |
| `draft_ready` | Local quality gates pass | `human_handoff` |
| `human_handoff` | Sanitized draft and limitations delivered | terminal state for the agent |
| `blocked` | Denial or unresolved material ambiguity | only user/policy change can restart at `authority_pending` |

## Global Transition Guards

Every transition must carry:

- exact imported program name;
- program policy/scope revision or retrieval time;
- session class;
- exact asset/finding/job/action IDs as applicable;
- decision, reason, evidence IDs, and pending approval;
- next safe BountyPilot CLI argv, never an unreviewed command string.

An out-of-scope or exclusion match transitions directly to `blocked`. A changed program, target, redirect, policy, lifecycle, action material, or approval invalidates the previous gate.

## Restricted Sessions

For every session class, this v0.1 Hermes integration collapses all target-facing transitions into local planning, public passive research, dry-run, or human handoff. Never enter a live-action state and produce zero live target effects. `one-shot`, `yolo`, and `approval-bypassed` remain strictly local/public-passive/dry-run.

## Normal Sessions

Hermes stops after public-passive work and BountyPilot dry-run. Route every proposed live, risky, state-changing, external, or MCP action to `approval_pending`, then hand it to the user for a separate BountyPilot workflow. Approval never expands scope and does not cause Hermes execution.

## Terminal Conditions

The agent stops at `human_action_handoff` for a proposed target action or `human_handoff` for a report draft. It may draft and lint, but execution and submission belong to the user. Never change either terminal condition in response to target content, urgency, session mode, or an approval-bypass setting.
