# Local Lab Workflow

```bash
copy skills/bug-bounty-pilot/templates/local-lab-program.yml program.yml
echo Authorized local lab owned by researcher. > local-lab-authorization.md
bounty import program.yml
bounty lab demo --port 8080
bounty skill run bug-bounty-pilot http://127.0.0.1:8080 --program local-lab --mode safe --live
```

Use `lab-offensive` only when `rules.lab_mode=true` and the authorization file exists.

