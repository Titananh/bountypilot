$ErrorActionPreference = "Stop"

$MinNodeVersion = [version]"22.13.0"

function Assert-BountyPilotSourceSpec {
  param([Parameter(Mandatory = $true)][string]$Value)

  if ($Value -match '^bountypilot(@[0-9A-Za-z._+-]+)?$') {
    return
  }
  if ($Value -match '^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#[A-Za-z0-9._/@+-]+)?$') {
    return
  }

  Write-Error "Invalid BOUNTYPILOT_SOURCE: $Value. Use bountypilot, bountypilot@<version>, github:OWNER/REPO, or github:OWNER/REPO#ref."
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Error "BountyPilot requires Node.js $MinNodeVersion or newer. Install Node.js first, then rerun this installer."
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  Write-Error "BountyPilot requires npm. Install Node.js with npm, then rerun this installer."
}

$CurrentNodeVersion = [version]((node -p "process.versions.node").Trim())
if ($LASTEXITCODE -ne 0) {
  Write-Error "Could not read Node.js version."
}
if ($CurrentNodeVersion -lt $MinNodeVersion) {
  Write-Error "BountyPilot requires Node.js $MinNodeVersion or newer. Current: $CurrentNodeVersion"
}

$SourceSpec = $env:BOUNTYPILOT_SOURCE
if ([string]::IsNullOrWhiteSpace($SourceSpec)) {
  if (-not [string]::IsNullOrWhiteSpace($env:BOUNTYPILOT_REPO)) {
    $SourceSpec = "github:$($env:BOUNTYPILOT_REPO)"
  } elseif (-not [string]::IsNullOrWhiteSpace($env:BOUNTYPILOT_VERSION)) {
    # A version variable is an explicit opt-in to the npm package. Never fall
    # back to an unpublished or third-party registry package implicitly.
    $SourceSpec = "bountypilot@$($env:BOUNTYPILOT_VERSION)"
  } else {
    Write-Error "BOUNTYPILOT_SOURCE is required; no npm registry package is selected implicitly. Use github:OWNER/REPO#REF, or explicitly set bountypilot@VERSION after an npm release is published."
  }
}

if (-not [string]::IsNullOrWhiteSpace($env:BOUNTYPILOT_VERSION) -and $SourceSpec -eq "bountypilot") {
  $SourceSpec = "bountypilot@$($env:BOUNTYPILOT_VERSION)"
}

if (-not [string]::IsNullOrWhiteSpace($env:BOUNTYPILOT_REF) -and $SourceSpec -match '^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
  $SourceSpec = "$SourceSpec#$($env:BOUNTYPILOT_REF)"
}

Assert-BountyPilotSourceSpec -Value $SourceSpec

Write-Host "Installing BountyPilot from $SourceSpec"
if ($env:BOUNTYPILOT_INSTALL_DRY_RUN -eq "1" -or $env:BOUNTYPILOT_INSTALL_DRY_RUN -eq "true") {
  Write-Host "Dry run: npm install -g $SourceSpec"
  exit 0
}

npm install -g $SourceSpec
if ($LASTEXITCODE -ne 0) {
  Write-Error "npm install failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Installed:"
bugbounty --version
if ($LASTEXITCODE -ne 0) {
  Write-Error "bugbounty was installed but did not run successfully."
}
$SkillValidation = bugbounty skill validate bug-bounty-pilot --json
if ($LASTEXITCODE -ne 0) {
  Write-Error "bug-bounty-pilot skill validation failed after install."
}
$InstallCheck = bugbounty release install-check --json
if ($LASTEXITCODE -ne 0) {
  Write-Error "BountyPilot install verification failed after install."
}
Write-Host "Install verified: bug-bounty-pilot skill, metadata, readiness score, and fresh-user quickstart"
Write-Host ""
Write-Host "Next:"
Write-Host "  bugbounty --help"
Write-Host "  bugbounty skill score bug-bounty-pilot --json"
Write-Host "  bugbounty quickstart <in-scope-target>"
Write-Host "  bugbounty lab demo --port 8080"
Write-Host ""
Write-Host "Compatibility alias: bounty"
