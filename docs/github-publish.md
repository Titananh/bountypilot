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

## 2. Verify Locally

```bash
npm ci
npm run verify:release
npm pack --dry-run
```

The release check also verifies the public repository contract:

- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.github/workflows/codeql.yml`
- `.github/pull_request_template.md`
- `.github/dependabot.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/ISSUE_TEMPLATE/config.yml`

## 3. Push Source To GitHub

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

## 4. One-Line Install

After `main` is pushed, users can install from GitHub with:

```bash
npm install -g github:OWNER/REPO
```

Linux/macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.sh | BOUNTYPILOT_SOURCE=github:OWNER/REPO bash
```

Windows PowerShell:

```powershell
$env:BOUNTYPILOT_SOURCE="github:OWNER/REPO"; irm https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install.ps1 | iex
```

## 5. Create A GitHub Release

The release workflow runs when a `v*` tag is pushed:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow verifies the release gate, creates an npm tarball, bundles `bug-bounty-pilot.skill.zip`, generates `SHA256SUMS.txt`, attests release provenance, and attaches the artifacts to the GitHub release.
It also generates and attaches `bountypilot-sbom.cdx.json` as a CycloneDX SBOM for supply-chain review. The standalone skill ZIP includes `MANIFEST.bountypilot.json` with SHA-256 hashes for every skill file; verify it with `bounty skill verify-bundle bug-bounty-pilot.skill.zip`.

## 6. Verify A Fresh Install

```bash
bugbounty --version
bugbounty quickstart https://api.example.com
bugbounty lab demo --port 8080
```
