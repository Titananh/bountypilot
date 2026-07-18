# {{Specific weakness on exact asset allows bounded consequence}}

## Summary

{{State the validated condition, prerequisite, exact component, and bounded consequence in concise language.}}

## Program and Asset

- Program: {{exact imported program name}}
- Asset: {{exact in-scope asset}}
- Endpoint/component: {{exact route, parameter, or component}}
- Policy source/revision: {{URL and revision or retrieval time}}

## Program Custom Fields

- Program custom fields: {{list every current required field and value, or None}}

## Weakness

- Weakness: {{program-accepted CWE-or-CAPEC-ID}}
- Rationale: {{Explain why this classification matches the validated behavior.}}

## Severity

- Rating: {{None, Low, Medium, High, or Critical}}
- Method: {{program method or CVSS version}}
- Vector: {{CVSS vector when applicable, otherwise Not applicable}}
- Rationale: {{Tie the rating to demonstrated conditions and impact without speculative escalation.}}

## Steps to Reproduce

1. {{State the authorized role, account state, and safe prerequisite.}}
2. {{Navigate to or invoke the exact in-scope endpoint/component using the minimal safe input.}}
3. {{Observe the exact result and identify the linked sanitized evidence ID.}}

## Actual Result

{{Describe only the verified observable behavior and relevant response/state.}}

## Expected Result

{{Describe the intended security control or behavior that should occur instead.}}

## Impact

{{Explain the evidence-backed security consequence, affected boundary, required attacker capability, and limitations.}}

## Evidence

- Evidence ID: {{BountyPilot evidence ID}}
- SHA-256: {{64 lowercase hexadecimal characters}}
- Context: {{What the sanitized artifact demonstrates}}
- Evidence limitations: {{Redactions, unavailable data, and what was not tested}}

## Scope and Safety

- Exact program import: yes
- In-scope decision: yes
- Out-of-scope precedence checked: yes
- Validation method: {{minimal authorized method}}
- Sensitive data extracted: no
- Unexpected target effects: no

## Duplicate-Risk Note

- Checked at: {{ISO-8601 UTC timestamp}}
- Sources checked: {{local history, authorized own reports, and public disclosures actually checked}}
- Candidate matches: {{IDs/URLs and comparison, or None found in accessible sources}}
- Private visibility: unavailable; private program reports may still exist
- Risk: {{low, medium, high, or unknown with rationale}}

## Remediation

{{Suggest a proportionate control that addresses the probable root cause without claiming certainty.}}

## Researcher Attestation

- Human validation: pending
- Human submission required: yes
- Agent submitted: no
- Remaining uncertainty: {{State limitations or None beyond private duplicate visibility}}
