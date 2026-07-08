# Publish BountyPilot To GitHub

Use this checklist when you are ready to make the CLI installable by other users.

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
```

## 2. Verify Locally

```bash
npm ci
npm run verify:release
bounty skill score bug-bounty-pilot --repo OWNER/REPO --json
bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.1.0 --strict --json
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
git add .
git commit -m "Release BountyPilot CLI"
git remote add origin https://github.com/OWNER/REPO.git
git push -u origin main
```

If a Git repository already exists:

```bash
git add .
git commit -m "Release BountyPilot CLI"
git remote add origin https://github.com/OWNER/REPO.git
git push -u origin main
```

If `bounty release check --json` reports `github:origin` as `warn`, add or fix the `origin` remote before announcing the GitHub install command.

If you are preparing the release from a feature or Codex branch, publish the reviewed source to the public install branch before announcing `npm install -g github:OWNER/REPO`:

```bash
git push -u origin HEAD:main
```

After the branch is pushed, verify publish readiness from the CLI:

```bash
bounty release publish-status OWNER/REPO --branch main --tag v0.1.0 --online --json
bounty release publish-status OWNER/REPO --branch main --tag v0.1.0 --online --actions --json
```

## 4. One-Line Install

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

Set `BOUNTYPILOT_INSTALL_DRY_RUN=1` when testing either installer to verify Node/npm and print the resolved install command without changing the global npm prefix.

The installer runs the same post-install verification. You can rerun it manually from a clean temporary workspace:

```bash
bugbounty release install-check --json
```

## 5. Create A GitHub Release

The release workflow runs when a `v*` tag is pushed:

```bash
git tag v0.1.0
bounty skill score bug-bounty-pilot --repo OWNER/REPO --branch main --tag v0.1.0 --strict --json
git push origin v0.1.0
```

The workflow verifies the release gate, creates `.release` with the npm tarball, standalone `bug-bounty-pilot.skill.zip`, SBOM, `release-manifest.json`, and `SHA256SUMS.txt`, then runs `bounty release verify-bundle .release` before attesting and attaching the artifacts to the GitHub release. Locally, `bounty release bundle --output .release` creates the same handoff set before you tag.
It also attaches `bountypilot-sbom.cdx.json` as a CycloneDX SBOM for supply-chain review. The standalone skill ZIP includes `MANIFEST.bountypilot.json` with SHA-256 hashes for every skill file; verify it directly with `bounty skill verify-bundle bug-bounty-pilot.skill.zip` or as part of the full release set with `bounty release verify-bundle .release`.

The separate VM Lab Smoke workflow runs `npm run test:vm-lab` on `ubuntu-latest`. It installs the packed CLI into a clean consumer project, starts the loopback-only demo lab, runs `lab e2e --live` against that local lab, and checks beta readiness from the installed binary.

The manual Real Tool VM Smoke workflow runs `npm run test:vm-real-tools` on `ubuntu-latest` with Go installed. It installs/uses real `httpx` and `katana`, approves their absolute executable paths, starts the loopback-only demo lab, and runs `hunt recon --live --tools httpx,katana` only against that local target.

## 6. Verify A Fresh Install

```bash
bugbounty --version
bugbounty quickstart https://api.example.com
bugbounty lab demo --port 8080
```
