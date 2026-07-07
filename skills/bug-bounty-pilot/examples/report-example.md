# Report Example

## Summary

The target appears to be missing a security header on an in-scope endpoint.

## Scope And Safety

Testing used a single read-only request against an imported in-scope asset. No destructive actions, credential attacks, or data extraction were performed.

## Evidence

- Evidence ID: `ev_example`
- Local path: `.bounty/programs/example/evidence/job_example/safe-checks.json`

## Impact

Impact is informational until manually validated against program policy.

## Remediation

Set the missing header according to the application requirements.

