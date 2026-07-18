# Validation Boundaries

## Validation Plan

Define before any target effect:

| Field | Requirement |
| --- | --- |
| Hypothesis | One falsifiable security statement |
| Authority | Exact imported program and current policy/scope revision |
| Preconditions | Role, state, account, input, and environment without live secrets |
| Minimal action | Smallest BountyPilot-planned action that distinguishes outcomes |
| Expected/actual | Observable results, not model interpretation |
| Maximum effect | Request/state/data boundary that must not be exceeded |
| Stop conditions | Redirect, sensitive data, state change, privilege, uncertainty, budget, policy change |
| Evidence | Sanitized artifact kinds, IDs, and integrity plan |
| Approval | Action-bound human approval when required |

## Escalation Ladder

1. Re-read verified local evidence.
2. Generate a BountyPilot reproduction plan or dry-run.
3. Hand every proposed target observation to the user with the exact BountyPilot action and current gates.
4. Stop the Hermes run. Approval and execution, if any, belong to a separate human-controlled BountyPilot workflow.
5. Any stronger exploit is a new proposal and is never automatic.

Skip target-facing steps entirely in every Hermes session class.

## Always Block

- random target scanning or scope expansion;
- brute force or credential attacks;
- WAF or control evasion;
- destructive payloads or service disruption;
- sensitive-data extraction or unrelated-record access;
- persistence, backdoors, or cleanup-dependent changes;
- automatic exploit escalation or report submission.

## Outcome Model

- `validated`: the bounded hypothesis reproduced with verified evidence.
- `refuted`: observed behavior contradicts the hypothesis.
- `inconclusive`: evidence cannot distinguish outcomes within safe authority.
- `blocked`: policy, scope, approval, lifecycle, budget, or safety forbids the attempt.

Never convert inconclusive/blocked into validated from confidence, scanner output, or theoretical impact.

## Approval Invalidation

Reapprove after any change to program, target, method, adapter, payload/input, effect, request budget, time window, action digest, scope/policy revision, or lifecycle state. Approval does not override exclusions.

## Completion Gate

Require exact provenance, reproducible minimal steps, verified sanitized evidence, honest outcome, and documented stop reason. Validation cannot guarantee bounty, HackerOne acceptance, or absence of duplicates.
