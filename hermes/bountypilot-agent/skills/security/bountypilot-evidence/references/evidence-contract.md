# Evidence Contract

## Artifact Record

Every artifact must carry:

- evidence ID and integrity digest;
- exact program, asset, and source URL when applicable;
- finding/job/action linkage;
- kind, adapter, capture timestamp, and policy/scope revision;
- bounded claim supported and capture prerequisites;
- raw/sanitized classification and redaction note;
- reproduction context and observed result;
- approval reference when the capture required human approval.

## Claim Discipline

Classify statements as:

- **Observation:** directly visible in the artifact.
- **Inference:** reasoned from observations, with assumptions.
- **Validated claim:** reproduced by an authorized minimal action and backed by verified evidence.
- **Unsupported:** omit from reports or mark as a hypothesis.

One artifact may support multiple bounded observations, but do not let a screenshot or scanner label prove an unobserved impact chain.

## Raw and Sanitized Separation

Keep raw evidence local and access-limited when policy permits retention. Create a separate sanitized derivative for reporting; never overwrite raw material. Record the relationship and separate digests. If sensitive data appears unexpectedly, stop capture and preserve only the minimum needed to report safely.

Redact credentials, tokens, cookies, private keys, personal data, unrelated tenant/user records, internal paths, unnecessary request identifiers, and secrets in screenshots, logs, request/response bodies, and filenames.

## Capture Boundaries

- Exact import and fresh scope/policy are mandatory.
- Exclusions override inclusions and redirects require a new scope check.
- One-shot/yolo/approval-bypassed sessions permit local evidence organization, sanitization, verification, and dry-run only.
- Hermes does not perform live capture. Any proposed target capture is handed to the user for a separate BountyPilot policy/lifecycle decision and explicit approval where required.
- Never extract additional sensitive data, escalate exploitation, or repeat effects solely to improve evidence.

## Integrity Gate

Run the BountyPilot manifest and verification commands through `terminal`. Reject missing files, digest mismatch, ambiguous provenance, stale scope, broken finding links, or unsanitized report-facing material.

## Report Mapping

Map each material report sentence to one or more evidence IDs. Attach only sanitized artifacts and state limitations. Evidence quality does not guarantee validity, bounty, duplicate status, or HackerOne acceptance.
