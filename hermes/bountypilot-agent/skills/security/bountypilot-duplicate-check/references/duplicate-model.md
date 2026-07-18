# Duplicate-Risk Model

Duplicate analysis estimates accessible evidence; it cannot inspect unknown private reports or guarantee a novel submission.

## Canonical Fingerprint

Compare:

1. exact program and asset family;
2. endpoint/component and normalized route;
3. vulnerable parameter or data flow;
4. weakness/category;
5. prerequisites, role, and state;
6. exploitation/reproduction method;
7. observed effect and demonstrated impact;
8. probable root cause;
9. report/finding status and timing when authorized to view it.

## Candidate Classification

| Class | Interpretation |
| --- | --- |
| Same instance | Exact target element plus same method/root cause; strong duplicate candidate |
| Related instance | Similar issue with material endpoint/component difference; investigate, do not collapse automatically |
| Systemic issue | Shared cause across components; program policy may determine grouping |
| Regression candidate | Prior issue was fixed/resolved and appears to have returned |
| No accessible match | No conclusion about private history; risk is `unknown` or cautiously `low` |

HackerOne describes duplicate comparison using vulnerability type, target, exploitation method, and root cause, while distinguishing regressions and separate endpoints: [Agentic Duplicate Detection](https://docs.hackerone.com/en/articles/13703106-agentic-duplicate-detection).

## Source Tiers

1. Current BountyPilot local findings and drafts.
2. Researcher's own authorized reports/files.
3. Public disclosed reports and public program material.
4. Private reports belonging to others: unavailable; never seek, infer, or claim checked.

Record source ID/URL, access class, checked-at time, query/fingerprint, match reasoning, and visibility limitations.

## Risk Bands

- `high`: one or more strong same-instance candidates.
- `medium`: material overlaps but instance/root-cause differences remain unresolved.
- `low`: accessible sources show weak/no match and the fingerprint is distinctive; private risk remains.
- `unknown`: sources are stale/incomplete, fingerprint is weak, or visibility prevents a reasoned estimate.

Never label risk `zero` or say no duplicate exists.

## Recheck Triggers

Recheck after asset/endpoint/parameter/root-cause changes, validation changes the observed effect, a new public disclosure appears, local history changes, policy changes grouping rules, or immediately before user submission.

Duplicate checking is local/public-passive. It requires no target scan, credential use, extraction, evasion, exploitation, persistence, or automated submission.
