# Evidence-First Triage Rubric

Apply gates before scoring. A score organizes review; it never overrides authority or guarantees report validity.

## Hard Gates

Mark `blocked` when any applies:

- exact imported program is missing or ambiguous;
- asset/method is excluded, out of scope, or policy-prohibited;
- evidence integrity or provenance fails;
- only prohibited validation could establish the claim;
- sensitive-data handling is unsafe;
- material claims rely on fabricated or unverified content.

Mark `needs_validation` when scope passes but reproduction, actual/expected contrast, or impact remains inconclusive.

## Review Dimensions

Score each from 0 to 3 and retain the rationale:

| Dimension | 0 | 1 | 2 | 3 |
| --- | --- | --- | --- | --- |
| Evidence | Missing/invalid | Single weak observation | Verified relevant artifacts | Diverse verified claim-linked artifacts |
| Reproduction | None | Hypothesis only | One safe bounded attempt | Repeatable minimal authorized steps |
| Impact | Unsupported | Theoretical | Narrow evidence-backed consequence | Clear demonstrated bounded security harm |
| Confidence | Contradicted | Ambiguous | Consistent | Falsifiable and independently reviewable |
| Scope/policy | Unresolved | Stale/qualified | Current explicit match | Current match plus method/limits documented |
| Duplicate analysis | Missing/stale | Weak fingerprint | Current accessible-source review | Strong fingerprint with alternatives/limits |
| Report clarity | Unusable | Major gaps | Human-reviewable | Concise, complete, evidence-mapped |

Do not average away a zero in evidence, reproduction, scope/policy, or impact. Route it back to the relevant gate.

## Severity

Use the program's stated method first. If it uses CVSS, record version/vector and explain each material choice from demonstrated conditions. If impact is not demonstrated, reduce confidence rather than assuming a worst-case chain. Program-specific exclusions or severity rules take precedence.

## Disposition

- `refuted`: evidence contradicts the hypothesis.
- `blocked`: a hard gate fails.
- `needs_validation`: safe evidence can still resolve a bounded hypothesis.
- `needs_manual_review`: evidence is meaningful but judgment/uncertainty remains.
- `ready_for_draft`: scope/policy current, finding validated, evidence verified/sanitized, impact bounded, severity reasoned, duplicate check current, and reproduction human-reviewable.

`ready_for_draft` means local drafting only. The user must review and submit.

## Safety Ceiling

Never improve a triage outcome by random scanning, brute force, credential attacks, WAF evasion, destructive payloads, sensitive-data extraction, persistence, or automatic exploit escalation. Never promise zero duplicate risk, bounty, validity, or HackerOne acceptance.
