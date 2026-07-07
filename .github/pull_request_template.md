## Summary

- 

## Safety Checklist

- [ ] Dry-run remains the default for target-facing workflows.
- [ ] Live actions still pass through scope, policy, rate-limit, audit, and approval gates.
- [ ] No brute force, credential stuffing, password spraying, destructive payloads, malware, WAF evasion, data exfiltration, mass scanning, or auto-submit behavior was added.
- [ ] External tools still require approved absolute executable paths, no shell, bounded output, timeouts, redaction, and audit events.
- [ ] Lab-only behavior still requires `rules.lab_mode=true`, an authorization file, and local/private scope.
- [ ] No real target data, secrets, cookies, tokens, API keys, or private program details are committed.

## Verification

- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm run verify:release`

