# Security Policy

BountyPilot is a safe, local-first bug bounty workflow engine. Please use it only on assets you own or are explicitly authorized to test.

## Supported Versions

Security fixes target the latest released version and the default branch.

## Reporting A Vulnerability

If you find a vulnerability in BountyPilot itself, do not publish exploit details before maintainers have had a reasonable chance to respond.

When the project is hosted on GitHub, report privately through GitHub Security Advisories if enabled. If advisories are not enabled yet, open a minimal issue that asks maintainers to enable private disclosure and omit sensitive details.

Include:

- Affected version or commit.
- Local environment and operating system.
- Clear reproduction steps using a local lab or sanitized fixtures.
- Expected and actual behavior.
- Any impact on scope enforcement, approval gates, evidence redaction, provider credential handling, or external tool execution.

## Safety Boundary

Reports about BountyPilot should not include:

- Third-party target data.
- Real user secrets, tokens, cookies, or API keys.
- Payloads for destructive testing, credential attacks, malware, WAF evasion, data exfiltration, or mass scanning.

## Project Guarantees

BountyPilot should fail closed when scope, policy, approval, executable trust, or lab-mode requirements are not satisfied. Regressions in those guarantees are treated as high priority.

