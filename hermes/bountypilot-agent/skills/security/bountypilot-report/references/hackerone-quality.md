# HackerOne Report Quality Gate

Apply these checks to a local draft after BountyPilot scope, evidence, validation, duplicate, and triage gates pass. The references describe platform/reporting concepts; they do not authorize target testing or automatic submission. Accessed 2026-07-18.

## Required Draft Content

- Specific title naming the weakness, affected component/asset, and practical consequence.
- Concise summary of the condition, prerequisite, actual behavior, and affected scope.
- Numbered, minimal, authorized reproduction steps with exact role, asset, endpoint/parameter, and observable result.
- Separate expected and actual behavior.
- Evidence-bounded impact without speculative escalation.
- Program-accepted weakness and reasoned severity; follow the program's chosen scoring method.
- Sanitized supporting evidence with IDs/digests and attachment context.
- Remediation suggestions when supportable.
- Program custom fields and disclosure/attachment requirements.
- Timestamped duplicate-risk note that states checked sources and unavailable private visibility.
- Explicit human-validation status (`pending` in every agent draft) and a human-submission requirement.

HackerOne's quality guidance emphasizes a clear title, detailed reproduction, impact, expected/actual behavior, supporting material, and concise structure: [Quality Reports](https://docs.hackerone.com/en/articles/8475116-quality-reports).

## Platform Mapping

HackerOne's submission flow asks the researcher to select the asset type, template, weakness, optional severity, proof details, attachments, and program custom fields, then preview before submitting: [Submitting Reports](https://docs.hackerone.com/en/articles/8473994-submitting-reports). The agent stops before that platform action; the user must preview and submit.

Severity may be None, Low, Medium, High, or Critical, may use supported CVSS versions, and may follow another program-defined method: [Severity](https://docs.hackerone.com/en/articles/8475343-severity). Never infer a severe rating from a theoretical exploit chain.

Programs can enable, disable, or hide weaknesses, so select only a category accepted by the current program: [Weaknesses](https://docs.hackerone.com/en/articles/8475333-weaknesses).

## Duplicate and Assistant Boundaries

HackerOne describes duplicate analysis across keywords, semantic similarity, technical fingerprints, target, method, root cause, timing, and regression context: [Agentic Duplicate Detection](https://docs.hackerone.com/en/articles/13703106-agentic-duplicate-detection). That organization-side capability does not give this agent visibility into unknown private history, so never claim zero duplicate risk.

HackerOne's Report Assistant checks reproduction, expected/actual behavior, impact, scope, severity, supporting material, and custom fields while leaving changes and final choices to the researcher: [Report Assistant](https://docs.hackerone.com/en/articles/12648472-report-assistant). Treat suggestions as review input, not proof or automatic edits.

## Evidence and Privacy Gate

- Link every material claim to verified sanitized evidence.
- Remove tokens, cookies, credentials, private keys, unnecessary personal data, unrelated records, and internal local paths.
- Attach files rather than exposing sensitive demonstration material on public links.
- Explain limitations, failed/inconclusive attempts, prerequisites, and redactions.
- Never gather stronger proof by brute force, credential attack, WAF evasion, destructive payload, data extraction, persistence, or automatic exploit escalation.

## Language Gate

Reject absolute promises such as "no duplicates," "zero duplicate risk," "guaranteed bounty," "guaranteed valid," or "HackerOne will accept." A passing linter, score, or assistant review improves structure only.

## Human Handoff

Provide the local Markdown draft with human validation still marked `pending`, sanitized attachment list, evidence manifest result, policy/scope revision, duplicate checked-at time, lint result, and unresolved warnings. State plainly: the agent did not validate or submit; the user must verify all details, replace the pending attestation only after independent review, preview, and submit manually.
