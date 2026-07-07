# Contributing To BountyPilot

Thanks for helping improve BountyPilot. This project is intentionally safe-by-default: changes should make authorized bug bounty work more reliable without creating exploit automation shortcuts.

## Development Setup

```bash
npm ci
npm run build
npm test
npm run verify:release
```

Use Node.js 22.13.0 or newer.

## Safety Rules For Contributions

- Keep dry-run as the default for target-facing workflows.
- Keep live actions behind scope, policy, rate-limit, audit, and approval gates.
- Do not add brute force, credential stuffing, password spraying, destructive payloads, malware, WAF evasion, data exfiltration, mass internet scanning, or auto-submit behavior.
- External tools must use approved absolute executable paths, no shell, bounded output, timeouts, redaction, and audit events.
- Lab-only behavior must require `rules.lab_mode=true`, an authorization file, and local/private scope.
- AI provider output may draft plans and reports, but must not approve or execute actions.

## Release Gate

Before proposing a release-ready change, run:

```bash
npm run verify:release
```

This verifies build, documented command snippets, typecheck, tests, package-bin install smoke, release readiness, and npm pack dry-run.

## Pull Request Checklist

- Scope of change is clear and narrow.
- Tests cover safety-sensitive behavior.
- README, examples, skill files, or docs are updated when CLI behavior changes.
- `npm run verify:release` passes locally.
- No real target data, secrets, cookies, tokens, API keys, or private program details are committed.

