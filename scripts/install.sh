#!/usr/bin/env bash
set -euo pipefail

MIN_NODE_VERSION="22.13.0"

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
  else
    source_spec="bountypilot"
  fi
fi

if [[ -n "${BOUNTYPILOT_VERSION:-}" && "${source_spec}" == "bountypilot" ]]; then
  source_spec="bountypilot@${BOUNTYPILOT_VERSION}"
fi

echo "Installing BountyPilot from ${source_spec}"
npm install -g "${source_spec}"

echo
echo "Installed:"
bugbounty --version
echo
echo "Next:"
echo "  bugbounty --help"
echo "  bugbounty quickstart <in-scope-target>"
echo "  bugbounty lab demo --port 8080"
echo
echo "Compatibility alias: bounty"
