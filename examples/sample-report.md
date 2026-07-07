# Security header missing on scoped API response

## Summary

The scoped API health endpoint responds without a strict Content-Security-Policy header. This sample report is intentionally low impact and demonstrates BountyPilot's report format without claiming a critical vulnerability.

## Asset

- `https://api.example.com/health`
- Scope status: in scope for the example program

## Steps To Reproduce

1. Import `examples/program.yml`.
2. Run `bounty check https://api.example.com/health --safe --mode safe`.
3. Review the generated evidence note in `examples/evidence/finding-example-security-header/reproduction.md`.

## Impact

The missing header may make future client-side injection bugs easier to exploit, but it is usually not reportable alone unless chained with stronger evidence.

## Evidence

- `examples/evidence/finding-example-security-header/reproduction.md`
- `examples/sample-evidence-manifest.json`

## Suggested Remediation

Set an application-specific Content-Security-Policy and review related hardening headers.

## Duplicate Risk

Medium. Header-only reports are common and may be considered informational unless paired with demonstrated impact.

## Safe Testing Statement

This sample uses only low-rate, non-destructive checks against an explicitly scoped example asset. No real user data, state-changing action, brute force, or destructive validation is involved.
