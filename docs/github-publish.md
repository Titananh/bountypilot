# Publish BountyPilot v0.2 To GitHub

Use this checklist when you are ready to make the CLI installable by other users.

Safety reminder: publish only reviewed source code, examples, and generated release artifacts. Do not publish private program data, authorization files, real target evidence, secrets, provider keys, or bounty reports. BountyPilot remains local-first: it does not automatically exploit targets or submit reports. External integrations, MCP servers, and registry tools produce plans or handoffs only; only built-in low-risk actions can run through `ActionExecutor` after all gates pass. No release can guarantee finding a bug, avoiding duplicates, acceptance, or a bounty. The release gate fails if tracked files include `.bounty/`, generated artifacts, `.env` files, provider configs, key/evidence captures, or obvious provider/platform token patterns. Never use `git add .`; stage an explicit reviewed allowlist and inspect the staged diff before committing.

Public release reminder: `gh repo create ... --public`, `git push -u origin HEAD:main`, and release tag pushes make the selected source publicly installable. Review the current commit, default branch target, and generated public-readiness plan before running those commands. Do not move or replace `v0.2.0` after it has been published.

## 1. Pick The Public Repository

Choose a GitHub repository such as:

```text
OWNER/REPO
```

Example:

```text
your-name/bountypilot
```

Generate the exact local plan for that repository:

```bash
bounty release github-bootstrap OWNER/REPO --write
bounty release publish-plan OWNER/REPO --write
bounty skill score bug-bounty-pilot --repo OWNER/REPO --write-public-plan .bounty/release/public-readiness.md --json
```

## 2. Verify Locally

```bash
npm ci
npm run verify:release
bounty skill score bug-bounty-pilot --repo OWNER/REPO --json
bounty skill score bug-bounty-pilot --repo OWNER/REPO --write-public-plan .bounty/release/public-readiness.md --json
bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.2.0 --strict --json
bounty release bundle --output .release --force --json
bounty release verify-bundle .release --json
bounty release github-bootstrap OWNER/REPO --write
bounty release publish-plan OWNER/REPO --write
npm run test:external-tools
npm run test:vm-lab
npm run test:vm-real-tools
npm pack --dry-run
```

The release check also verifies the public repository contract:

- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `github:origin` warning/pass state
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/vm-lab.yml`
- `.github/workflows/real-tools.yml`
- `.github/pull_request_template.md`
- `.github/dependabot.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/ISSUE_TEMPLATE/config.yml`

## 3. Push Source To GitHub

If GitHub CLI is installed and authenticated, verify it first:

```bash
gh --version
gh auth status
```

Then create the public repository, set `origin`, and push in one command:

```bash
gh repo create OWNER/REPO --public --source . --remote origin --push
```

If GitHub CLI is not available, use the manual Git flow below.

If this folder has not been initialized as a Git repository yet:

```bash
git init -b main
git status --short
# Repeat for each file or directory that was individually reviewed:
git add -- path/to/reviewed-file
git diff --cached --name-only
git diff --cached --check
git commit -m "Release BountyPilot CLI"
git remote add origin https://github.com/OWNER/REPO.git
git push -u origin main
```

If a Git repository already exists:

```bash
git status --short
# Repeat for each file or directory that was individually reviewed:
git add -- path/to/reviewed-file
git diff --cached --name-only
git diff --cached --check
git commit -m "Release BountyPilot CLI"
git remote add origin https://github.com/OWNER/REPO.git
git push -u origin main
```

If `bounty release check --json` reports `github:origin` as `warn`, add or fix the `origin` remote before announcing the GitHub install command.

The current review branch is not the future immutable release tag. Push it under its own name for review; do not create or move `v0.2.0` and do not publish the branch as `main` before review:

```bash
git push -u origin codex/hermes-bountypilot-agent
```

Only after the reviewed changes are merged or deliberately promoted to `main` should the `main` install commands below be announced.

After the branch is pushed, verify publish readiness from the CLI:

```bash
bounty release publish-status OWNER/REPO --branch main --tag v0.2.0 --online --json
bounty release publish-status OWNER/REPO --branch main --tag v0.2.0 --online --actions --json
bounty release publish-status OWNER/REPO --branch main --tag v0.2.0 --online --actions --write-public-plan .bounty/release/public-readiness.md --json
bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.2.0 --online --actions --strict --json
bounty release public-gate OWNER/REPO --branch main --tag v0.2.0 --online --actions --install-check --write-public-plan .bounty/release/public-readiness.md --json
```

The skill score JSON separates source-package readiness from public publish readiness:

- `layers.local` should be `100/100` and `ultimate` when the bundled skill, release checks, examples, installers, and package metadata are complete.
- `layers.publish` becomes `100/100` only after the GitHub origin, public branch, release tag, online refs, and required Actions runs are verified.
- `publicReadiness.requirements` is the full publish checklist, and `publicReadiness.missing` is the exact set still blocking public 100/100.
- Each missing requirement includes `commands`, a targeted remediation list for that specific check.
- `publicReadiness.fixPlan` groups those remediation commands into ordered phases such as repository selection, GitHub CLI setup, origin, branch, tag, Actions, and final verification.
- `--write-public-plan .bounty/release/public-readiness.md` writes the same missing requirements, ordered phases, command blocks, and safety notes as a local Markdown handoff checklist.

## 4. Install v0.2

### BountyPilot CLI

After `main` is pushed, users can install from GitHub with:

```bash
npm install -g github:OWNER/REPO
```

Linux/macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.sh | BOUNTYPILOT_SOURCE=github:OWNER/REPO#main bash
```

Windows PowerShell:

```powershell
$env:BOUNTYPILOT_SOURCE="github:OWNER/REPO#main"; irm https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.ps1 | iex
```

Set `BOUNTYPILOT_INSTALL_DRY_RUN=1` when testing either installer to verify Node/npm and print the resolved install command without changing the global npm prefix. The installer requires an explicit `BOUNTYPILOT_SOURCE`, `BOUNTYPILOT_REPO`, or `BOUNTYPILOT_VERSION`; it never defaults to an unpublished npm package.

The installer runs the same post-install verification. You can rerun it manually from a clean temporary workspace:

```bash
bugbounty release install-check --json
```

### Fresh Hermes profile

Installing a Hermes profile does not install the `bounty` executable. For the current candidate branch, install BountyPilot CLI `0.2.0` and the nested distribution from the same reviewed checkout:

```bash
git clone --branch codex/hermes-bountypilot-agent --depth 1 https://github.com/OWNER/REPO.git bountypilot
cd bountypilot
npm ci
npm install -g .
bounty --version
hermes profile install ./hermes/bountypilot-agent --name bugbounty --alias -y
hermes profile use bugbounty
```

Require `bounty --version` to print `0.2.0`. After the immutable `v0.2.0` tag is actually published, the same reviewed flow may clone `--branch v0.2.0` instead. Do not assume or push that tag during candidate-branch installation.

The repository root is not a Hermes profile. Never pass the root or the repository URL to `hermes profile install`.

### Existing Hermes profile

The installed npm package provides a merge installer that preserves the profile's credentials, SOUL, config, memories, unrelated skills, and unrelated bundles:

```bash
bountypilot-hermes --dry-run --profile bugbounty
bountypilot-hermes --apply --profile bugbounty
bountypilot-hermes --verify --profile bugbounty
```

`--dry-run` is read-only. During `--apply`, each managed entry is staged and swapped into place with a same-filesystem `rename`; failures reported by that running process trigger journaled rollback of completed swaps. This is per-entry, in-process rollback, not whole-profile or power-loss atomicity.

## 5. Create A GitHub Release

The release workflow runs when a `v*` tag is pushed. The following is a future release step only, after the candidate is reviewed, `main` is published, and the release gate passes; do not run it merely to make the current branch installable:

```bash
git tag -a v0.2.0 -m "BountyPilot v0.2.0"
bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.2.0 --strict --json
git push origin v0.2.0
```

The workflow verifies the release gate, creates `.release` with the npm tarball, standalone `bug-bounty-pilot.skill.zip`, SBOM, `release-manifest.json`, and `SHA256SUMS.txt`, then runs `bounty release verify-bundle .release` before attesting and attaching the artifacts to the GitHub release. Locally, `bounty release bundle --output .release` creates the same handoff set before you tag.
It also attaches `bountypilot-sbom.cdx.json` as a CycloneDX SBOM for supply-chain review. The standalone skill ZIP includes `MANIFEST.bountypilot.json` with SHA-256 hashes for every skill file; verify it directly with `bounty skill verify-bundle bug-bounty-pilot.skill.zip` or as part of the full release set with `bounty release verify-bundle .release`.

The separate VM Lab Smoke workflow runs `npm run test:vm-lab` on `ubuntu-latest`. It installs the packed CLI into a clean consumer project, starts the loopback-only demo lab, runs `lab e2e --live` against that local lab, and checks beta readiness from the installed binary.

The manual Real Tool VM Smoke workflow runs `npm run test:vm-real-tools` on `ubuntu-latest` with Go installed. It checks discovery plus plan/handoff metadata for installed `httpx` and `katana`; BountyPilot does not dispatch those tools.

## 6. Verify A Fresh Install

```bash
bugbounty --version
bugbounty quickstart https://api.example.com
bugbounty lab demo --port 8080
```
