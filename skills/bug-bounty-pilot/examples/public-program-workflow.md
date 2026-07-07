# Public Program Workflow

```bash
bounty import program.yml
bounty scope test https://target.example
bounty skill run bug-bounty-pilot https://target.example --mode passive --dry-run
bounty hunt recon https://target.example --profile passive --dry-run
bounty hunt playbook headers https://target.example --dry-run
```

Do not run scanners or fuzzers unless the program permits them and the action is approved.

