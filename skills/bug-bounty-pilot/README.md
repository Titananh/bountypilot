# bug-bounty-pilot

`bug-bounty-pilot` is the packaged BountyPilot skill for authorized bug bounty work. It describes the safe workflow contract used by the CLI command group:

```bash
bounty skill validate bug-bounty-pilot
bounty skill bundle bug-bounty-pilot --output bug-bounty-pilot.skill.zip
bounty skill verify-bundle bug-bounty-pilot.skill.zip
bounty skill run bug-bounty-pilot https://target.example --program example --mode passive --dry-run
```

The skill is local-first and safe-by-default. It can plan recon, collect observations, queue review-required actions, create evidence manifests, score report readiness, and draft local reports. It never auto-submits reports and never bypasses scope, policy, rate limit, or approval gates. The bundle command writes a portable ZIP with `MANIFEST.bountypilot.json` and SHA-256 hashes for each skill file; `verify-bundle` checks the manifest and hashes before use.

## Modes

- `passive`: program context, scope validation, passive recon planning, local parsing only.
- `safe`: light HTTP checks, read-only evidence, JS extraction, non-destructive candidates.
- `deep-safe`: broader crawl and parameter discovery, with scanners and fuzzers staying review-required.
- `lab-offensive`: owned local/private labs only, requiring `rules.lab_mode=true` and a local authorization file.

## Required Files

- `SKILL.md`
- `policy.yml`
- `workflow.yml`
- `tool-registry.yml`
- `playbooks.yml`
- `vm-profile.yml`
- `prompts/*.md`
- `templates/*`
- `examples/*.md`
