#!/usr/bin/env bash
set -euo pipefail

# Compatibility smoke for the retired real-tool integration surface.
#
# This script intentionally performs no target request, installs no Go/npm
# tool, starts no external process, and never dispatches httpx or katana.  The
# historical name and environment variable remain so existing CI invocations
# fail closed into this zero-effect canary instead of silently regaining the
# old execution behavior.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$ROOT/dist/cli/index.js"
WORKDIR="${BOUNTYPILOT_VM_REAL_TOOLS_WORKDIR:-$(mktemp -d)}"
BOUNTYPILOT_VM_REAL_TOOLS_INSTALL="${BOUNTYPILOT_VM_REAL_TOOLS_INSTALL:-0}"
RECON_JSON="$WORKDIR/real-tools-recon.json"
ACTIONS_JSON="$WORKDIR/real-tools-actions.json"
TARGET="http://127.0.0.1:8080/"

if [[ ! -f "$CLI" ]]; then
  echo "dist CLI is missing; run npm run build first." >&2
  exit 1
fi

export NO_COLOR=1
mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [[ "$BOUNTYPILOT_VM_REAL_TOOLS_INSTALL" == "1" || "$BOUNTYPILOT_VM_REAL_TOOLS_INSTALL" == "true" ]]; then
  echo "BOUNTYPILOT_VM_REAL_TOOLS_INSTALL is ignored: external tool installation and dispatch are disabled."
fi

# The two files are inert hash-pin canaries.  They are deliberately not
# executable and are only recorded as handoff metadata by `tools approve-executable`.
HTTPX_PIN="$WORKDIR/httpx-handoff-pin"
KATANA_PIN="$WORKDIR/katana-handoff-pin"
printf '%s\n' 'BountyPilot handoff canary: httpx must never execute.' > "$HTTPX_PIN"
printf '%s\n' 'BountyPilot handoff canary: katana must never execute.' > "$KATANA_PIN"

node "$CLI" init --json >/dev/null
node "$CLI" import "$ROOT/examples/local-program.yml" --json >/dev/null
node "$CLI" tools approve-executable httpx --command "$HTTPX_PIN" --json >/dev/null
node "$CLI" tools approve-executable katana --command "$KATANA_PIN" --json >/dev/null

# Even with the historical `--live` intent removed from this smoke, the
# selected external tools must remain planning-only handoffs.
node "$CLI" hunt recon "$TARGET" --profile web --dry-run --tools httpx,katana --json > "$RECON_JSON"

JOB_ID="$(node -e "const fs=require('fs'); const p=JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); process.stdout.write(p.jobId || '')" "$RECON_JSON")"
if [[ -z "$JOB_ID" ]]; then
  echo "recon handoff did not return a job id" >&2
  exit 1
fi
node "$CLI" actions list --job "$JOB_ID" --json > "$ACTIONS_JSON"

node - "$RECON_JSON" "$ACTIONS_JSON" "$HTTPX_PIN" "$KATANA_PIN" <<'NODE'
const fs = require("node:fs");
const [reconPath, actionsPath, httpxPin, katanaPin] = process.argv.slice(2);
const recon = JSON.parse(fs.readFileSync(reconPath, "utf8"));
const actions = JSON.parse(fs.readFileSync(actionsPath, "utf8"));

if (recon.live !== false || recon.observations?.length !== 0) {
  throw new Error("zero-effect recon smoke unexpectedly performed live work");
}
const names = new Set(["httpx", "katana"]);
if (!Array.isArray(recon.tools) || recon.tools.length !== names.size) {
  throw new Error("expected exactly two external-tool handoff records");
}
for (const tool of recon.tools) {
  if (!names.has(tool.tool) || tool.status !== "pending" || tool.approvalPresent !== true || tool.observations !== 0) {
    throw new Error(`${tool.tool ?? "unknown"} was not retained as a pending handoff`);
  }
}
if (!Array.isArray(actions.actions) || actions.actions.length !== names.size) {
  throw new Error("expected exactly two planning-only action rows");
}
for (const action of actions.actions) {
  if (action.status !== "pending" || action.requiredForCompletion !== false || action.metadata?.planningOnly !== true || action.metadata?.handoffOnly !== true || action.metadata?.execute !== false) {
    throw new Error(`${action.id ?? "unknown"} is not a non-required planning-only handoff`);
  }
}
for (const pin of [httpxPin, katanaPin]) {
  if (!fs.existsSync(pin) || fs.readFileSync(pin, "utf8").includes("executed")) {
    throw new Error("handoff canary was modified or executed");
  }
}
console.log(JSON.stringify({ ok: true, zeroDispatch: true, jobId: recon.jobId, tools: [...names], actions: actions.actions.length }));
NODE
