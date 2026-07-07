# Report Score Prompt

Score whether a candidate is ready for a local report draft.

Required checks:
- asset in scope
- vulnerability category clear
- reproduction steps present
- impact statement present
- evidence present
- no secrets leaked
- duplicate risk noted
- safe testing statement present
- remediation present

Return:
- score from 0 to 100
- readiness: blocked, needs_review, or ready_for_draft
- blockers
- warnings
- nextSteps

