# Recon Prompt

Convert raw recon output into normalized observations.

Rules:
- Drop or block out-of-scope hosts and URLs.
- Deduplicate by fingerprint.
- Preserve source adapter, source URL, confidence, risk hint, and parser warnings.
- Parser failures must save raw output as evidence and must not create a finding.
- Passive mode must not active-probe or crawl a live target.

Observation fields:
- kind
- value
- normalizedValue
- sourceAdapter
- sourceUrl
- scopeAllowed
- confidence
- riskHint
- metadata
- fingerprint

