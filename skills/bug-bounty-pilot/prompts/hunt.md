# Hunt Prompt

Use observations and evidence to choose safe playbooks.

Rules:
- Prefer low-risk checks that are read-only and reproducible.
- Queue review-required tools; do not execute them automatically.
- External and MCP proposals remain human handoffs and are never dispatched by BountyPilot, even when reviewed.
- Lab-only validation requires `rules.lab_mode=true`.
- Do not use destructive payloads, credential attacks, WAF evasion, auth bypass without permission, or data dumping.
- Findings need evidence thresholds. Otherwise create `needs_manual_verification` candidates.

Output:
- selected playbooks
- skipped playbooks and reasons
- finding candidates
- manual verification steps
