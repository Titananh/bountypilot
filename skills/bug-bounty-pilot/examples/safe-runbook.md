# Safe Runbook

```bash
bounty init
bounty import skills/bug-bounty-pilot/templates/program.yml
bounty skill validate bug-bounty-pilot
bounty skill run bug-bounty-pilot <in-scope-target-url> --program example-program --mode passive --dry-run
bounty hunt recon <in-scope-target-url> --profile passive --dry-run
bounty evidence manifest --job <job-id>
bounty reports score <candidate-id> --json
```

All live activity must be in scope and approved by the imported program rules.
