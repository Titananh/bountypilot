#!/usr/bin/env bash
set -euo pipefail

MIN_NODE_VERSION="22.13.0"

validate_source_spec() {
  local value="$1"
  if [[ "${value}" =~ ^bountypilot(@[0-9A-Za-z._+-]+)?$ ]]; then
    return 0
  fi
  if [[ "${value}" =~ ^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#[A-Za-z0-9._/@+-]+)?$ ]]; then
    return 0
  fi
  echo "Invalid BOUNTYPILOT_SOURCE: ${value}" >&2
  echo "Use bountypilot, bountypilot@<version>, github:OWNER/REPO, or github:OWNER/REPO#ref." >&2
  return 1
}

if ! command -v node >/dev/null 2>&1; then
  echo "BountyPilot requires Node.js ${MIN_NODE_VERSION} or newer."
  echo "Install Node.js first, then rerun this installer."
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "BountyPilot requires npm. Install Node.js with npm, then rerun this installer."
  exit 1
fi

node -e "
const required = '${MIN_NODE_VERSION}'.split('.').map(Number);
const current = process.versions.node.split('.').map(Number);
const ok = current[0] > required[0]
  || (current[0] === required[0] && (current[1] > required[1]
  || (current[1] === required[1] && current[2] >= required[2])));
if (!ok) {
  console.error('BountyPilot requires Node.js ${MIN_NODE_VERSION} or newer. Current: ' + process.versions.node);
  process.exit(1);
}
"

source_spec="${BOUNTYPILOT_SOURCE:-}"
if [[ -z "${source_spec}" ]]; then
  if [[ -n "${BOUNTYPILOT_REPO:-}" ]]; then
    source_spec="github:${BOUNTYPILOT_REPO}"
  elif [[ -n "${BOUNTYPILOT_VERSION:-}" ]]; then
    # A version variable is an explicit opt-in to the npm package. Never fall
    # back to an unpublished or third-party registry package implicitly.
    source_spec="bountypilot@${BOUNTYPILOT_VERSION}"
  else
    echo "BOUNTYPILOT_SOURCE is required; no npm registry package is selected implicitly." >&2
    echo "Use github:OWNER/REPO#REF, or explicitly set bountypilot@VERSION after an npm release is published." >&2
    exit 1
  fi
fi

if [[ -n "${BOUNTYPILOT_VERSION:-}" && "${source_spec}" == "bountypilot" ]]; then
  source_spec="bountypilot@${BOUNTYPILOT_VERSION}"
fi

if [[ -n "${BOUNTYPILOT_REF:-}" && "${source_spec}" =~ ^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  source_spec="${source_spec}#${BOUNTYPILOT_REF}"
fi

validate_source_spec "${source_spec}"

echo "Installing BountyPilot from ${source_spec}"
if [[ "${BOUNTYPILOT_INSTALL_DRY_RUN:-}" == "1" || "${BOUNTYPILOT_INSTALL_DRY_RUN:-}" == "true" ]]; then
  echo "Dry run: npm install -g ${source_spec}"
  exit 0
fi

npm install -g "${source_spec}"

echo
echo "Installed:"
bugbounty --version
bugbounty skill validate bug-bounty-pilot --json >/dev/null
bugbounty release install-check --json >/dev/null
echo "Install verified: bug-bounty-pilot skill, metadata, readiness score, and fresh-user quickstart"
echo
echo "Next:"
echo "  bugbounty --help"
echo "  bugbounty skill score bug-bounty-pilot --json"
echo "  bugbounty quickstart <in-scope-target>"
echo "  bugbounty lab demo --port 8080"
echo
echo "Compatibility alias: bounty"
