$ErrorActionPreference = "Stop"

$MinNodeVersion = [version]"22.13.0"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Error "BountyPilot requires Node.js $MinNodeVersion or newer. Install Node.js first, then rerun this installer."
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  Write-Error "BountyPilot requires npm. Install Node.js with npm, then rerun this installer."
}

$CurrentNodeVersion = [version]((node -p "process.versions.node").Trim())
if ($CurrentNodeVersion -lt $MinNodeVersion) {
  Write-Error "BountyPilot requires Node.js $MinNodeVersion or newer. Current: $CurrentNodeVersion"
}

$SourceSpec = $env:BOUNTYPILOT_SOURCE
if ([string]::IsNullOrWhiteSpace($SourceSpec)) {
  if (-not [string]::IsNullOrWhiteSpace($env:BOUNTYPILOT_REPO)) {
    $SourceSpec = "github:$($env:BOUNTYPILOT_REPO)"
  } else {
    $SourceSpec = "bountypilot"
  }
}

if (-not [string]::IsNullOrWhiteSpace($env:BOUNTYPILOT_VERSION) -and $SourceSpec -eq "bountypilot") {
  $SourceSpec = "bountypilot@$($env:BOUNTYPILOT_VERSION)"
}

Write-Host "Installing BountyPilot from $SourceSpec"
npm install -g $SourceSpec

Write-Host ""
Write-Host "Installed:"
bugbounty --version
Write-Host ""
Write-Host "Next:"
Write-Host "  bugbounty --help"
Write-Host "  bugbounty quickstart <in-scope-target>"
Write-Host "  bugbounty lab demo --port 8080"
Write-Host ""
Write-Host "Compatibility alias: bounty"
