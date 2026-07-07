# Complete Safe BountyPilot Workflow

This walkthrough keeps the default path local-first: dry-run, inspect, approve, then optionally resume or run live safe checks. External components remain planning-only until you explicitly opt them in.

## 1. Create a Workspace

```bash
npm run build
node dist/cli/index.js init
node dist/cli/index.js release check
node dist/cli/index.js programs validate examples/program.yml
```

## 2. Import a Program

Use the public-style example:

```bash
node dist/cli/index.js import examples/program.yml
node dist/cli/index.js programs list
node dist/cli/index.js programs show example-program
```

Or use the local lab example when practicing. It references `examples/local-lab-authorization.md`, which is copied into the program workspace during import:

```bash
node dist/cli/index.js import examples/local-program.yml
node dist/cli/index.js lab demo --port 8080
node dist/cli/index.js lab e2e http://127.0.0.1:8080
node dist/cli/index.js lab e2e http://127.0.0.1:8080 --live --with safe-checks,js-analyzer
```

## 3. Confirm Scope Before Planning

```bash
node dist/cli/index.js scope list
node dist/cli/index.js scope test https://api.example.com
node dist/cli/index.js scope test https://staging.example.com
```

Expected behavior:

- In-scope targets exit with code `0`.
- Out-of-scope targets exit with code `2`.
- Out-of-scope rules override wildcard in-scope rules.

## 4. Plan Without Network Execution

```bash
node dist/cli/index.js run api.example.com --dry-run --with safe-checks,js-analyzer,playwright,planner
```

Dry-run behavior:

- Writes a local research note.
- Writes a workflow summary under `.bounty/programs/<program>/evidence/<job-id>/workflow-summary.json`.
- Queues planned actions.
- Does not build live JavaScript or crawl `plannerCandidates`; those are added by live `js-analyzer`/crawl phases or by `agent plan --from-job`.
- Leaves approval-requiring actions pending. Low-risk policy-allowed actions can appear as approved, but reviewers can still block them before execution.
- Does not call `fetch`, Playwright, or external scanners.
- Skips wildcard scope entries instead of enumerating unknown assets.

## 5. Review Human Approval Points

```bash
node dist/cli/index.js jobs list
node dist/cli/index.js jobs show <job-id>
node dist/cli/index.js jobs timeline <job-id>
node dist/cli/index.js jobs watch <job-id> --iterations 3
node dist/cli/index.js review --job <job-id>
node dist/cli/index.js audit list --job <job-id>
node dist/cli/index.js actions review --job <job-id>
node dist/cli/index.js actions list --pending
node dist/cli/index.js dashboard
```

The timeline is the fastest way to see phase progress, skipped work, planner output, approval events, execution events, and resume decisions. `jobs watch` keeps that view refreshed during longer runs, and `actions review` turns the action queue into explicit approve/block/execute follow-up commands.

Approve only actions that are clearly authorized by the program:

```bash
node dist/cli/index.js actions show <action-id>
node dist/cli/index.js actions approve <action-id> --note "authorized by program scope and low-risk safe check"
node dist/cli/index.js actions block <action-id> --note "not clearly authorized or not needed"
```

## 6. Execute Approved Actions

Internal safe adapters can run after explicit approval. Trusted external process and stdio MCP adapters can run only when their integration config explicitly enables execution and the local executable has been approved by absolute path and SHA-256 hash.

```bash
node dist/cli/index.js actions execute <action-id>
node dist/cli/index.js actions run-approved --job <job-id>
node dist/cli/index.js findings show <finding-id>
node dist/cli/index.js findings status <finding-id> validated --note "safe local validation complete"
```

For a live workflow run, keep the component list narrow and use safe mode:

```bash
node dist/cli/index.js run api.example.com --mode safe --with safe-checks,js-analyzer,planner
```

## 7. Resume an Incomplete Workflow

If a workflow failed or paused after writing a checkpoint, inspect and resume it deliberately:

```bash
node dist/cli/index.js jobs show <job-id>
node dist/cli/index.js jobs timeline <job-id>
node dist/cli/index.js jobs resume <job-id> --dry-run
node dist/cli/index.js jobs resume <job-id> --live --with safe-checks,js-analyzer
```

Resume is incremental. When target, mode, and components are unchanged, completed global phases are recorded as skipped in the resumed job. Repeated live phases such as `safe-checks`, `js-analyzer`, and `playwright` are tracked per target: if target A completed and target B failed before the checkpoint, target A is recorded in `resumeSkippedWork[]` and target B continues.

## 8. Optional Live Safe Checks

Run live commands only after authorization, scope, and rate limits are confirmed.

```bash
node dist/cli/index.js check https://api.example.com --safe --mode safe
node dist/cli/index.js js https://api.example.com --mode safe
```

## 9. Export a Local Handoff Snapshot

```bash
node dist/cli/index.js dashboard --json
node dist/cli/index.js export summary
node dist/cli/index.js export bundle --job <job-id>
node dist/cli/index.js export bundle --job <job-id> --include-artifacts --output handoff-bundle
node dist/cli/index.js audit export --job <job-id>
node dist/cli/index.js evidence verify --job <job-id>
node dist/cli/index.js reports review <finding-id> --job <job-id> --write
```

The bundle contains workspace summary metadata plus job-filtered findings, actions, evidence metadata, timelines, and audit logs. Use `reports review` before drafting a report to check local evidence quality, duplicate risk, unreadable artifacts, and safety blockers. Use `--include-artifacts` when another reviewer needs copied evidence files.

## 10. Preflight Optional External Adapters

MCP preflight shows whether config, scope, and policy are ready before any opt-in execution. Without `allow_execute=true` or `execution.enabled=true`, optional external components should only record plans or skipped phases. Even with execution enabled, the executable must be approved locally before spawn.

```bash
node dist/cli/index.js integrations show playwright-mcp
node dist/cli/index.js integrations setup playwright-mcp
node dist/cli/index.js integrations setup playwright-mcp --enable-execution --approve-executable
node dist/cli/index.js integrations preflight playwright-mcp browser.navigate --target https://api.example.com
node dist/cli/index.js mcp plan playwright-mcp browser_navigate --target https://api.example.com --arg url=https://api.example.com/
node dist/cli/index.js mcp call playwright-mcp browser_navigate --target https://api.example.com --arg url=https://api.example.com/
node dist/cli/index.js mcp session playwright-mcp --target https://api.example.com --steps examples/mcp-steps.json
```

For package entrypoint execution, approving `node` only verifies the interpreter. Pin `execution.entrypoint_sha256` and `execution.package_json_sha256` when you want BountyPilot to fail closed if the installed package code or metadata changes.

For an explicitly trusted local crawler adapter:

```bash
node dist/cli/index.js integrations setup crawl4ai --command "/absolute/path/to/crawl4ai"
node dist/cli/index.js integrations setup crawl4ai --command "/absolute/path/to/crawl4ai" --enable-execution --approve-executable
node dist/cli/index.js run api.example.com --dry-run --with crawl4ai
node dist/cli/index.js run api.example.com --mode safe --with crawl4ai
```

Do not use BountyPilot for destructive testing, brute force, credential stuffing, spam, data exfiltration, WAF evasion, malware execution, or mass internet scanning.
