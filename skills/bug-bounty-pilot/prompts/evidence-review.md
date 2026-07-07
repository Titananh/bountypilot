# Evidence Review Prompt

Review evidence before report drafting.

Rules:
- Redact secrets, tokens, cookies, API keys, session IDs, and sensitive body samples.
- Prefer hashes and paths over raw sensitive data.
- Keep all artifacts local.
- Evidence must link to a job and candidate or finding.
- Missing evidence blocks `ready_for_draft`.

Return manifest status, missing artifacts, redaction warnings, and next capture commands.

