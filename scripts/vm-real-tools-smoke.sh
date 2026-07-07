#!/usr/bin/env bash
set -euo pipefail

# VM-only smoke for real external tools. It uses loopback demo lab targets only.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$ROOT/dist/cli/index.js"
WORKDIR="${BOUNTYPILOT_VM_REAL_TOOLS_WORKDIR:-$(mktemp -d)}"
INSTALL_TOOLS="${BOUNTYPILOT_VM_REAL_TOOLS_INSTALL:-0}"
DEMO_JSON="$WORKDIR/demo-lab.json"
RECON_JSON="$WORKDIR/real-tools-recon.json"
DEMO_PID=""

cleanup() {
  if [[ -n "$DEMO_PID" ]] && kill -0 "$DEMO_PID" >/dev/null 2>&1; then
    kill "$DEMO_PID" >/dev/null 2>&1 || true
    wait "$DEMO_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ ! -f "$CLI" ]]; then
  echo "dist CLI is missing; run npm run build first." >&2
  exit 1
fi

export NO_COLOR=1
export PATH="$HOME/go/bin:$PATH"
mkdir -p "$WORKDIR" "$HOME/go/bin"
cd "$WORKDIR"

if [[ "$INSTALL_TOOLS" == "1" || "$INSTALL_TOOLS" == "true" ]]; then
  command -v go >/dev/null 2>&1 || {
    echo "go is required when BOUNTYPILOT_VM_REAL_TOOLS_INSTALL=1" >&2
    exit 1
  }
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
fi

HTTPX_BIN="$(command -v httpx || true)"
KATANA_BIN="$(command -v katana || true)"
if [[ -z "$HTTPX_BIN" || -z "$KATANA_BIN" ]]; then
  echo "httpx and katana must be available on PATH. Set BOUNTYPILOT_VM_REAL_TOOLS_INSTALL=1 to install them." >&2
  exit 1
fi

node "$CLI" init --json >/dev/null
node "$CLI" import "$ROOT/examples/local-program.yml" --json >/dev/null

node "$CLI" lab demo --port 0 --json > "$DEMO_JSON" &
DEMO_PID="$!"

TARGET=""
for _ in {1..60}; do
  TARGET="$(node -e "const fs=require('fs'); try { const text=fs.readFileSync(process.argv[1], 'utf8'); const parsed=JSON.parse(text); process.stdout.write(parsed.target || ''); } catch {}" "$DEMO_JSON")"
  if [[ "$TARGET" == http://127.0.0.1:* ]]; then
    break
  fi
  sleep 0.25
done

if [[ "$TARGET" != http://127.0.0.1:* ]]; then
  echo "demo lab did not publish a loopback target" >&2
  cat "$DEMO_JSON" >&2 || true
  exit 1
fi

node "$CLI" lab e2e "$TARGET" --live --with safe-checks,js-analyzer --json >/dev/null
node "$CLI" tools approve-executable httpx --command "$HTTPX_BIN" --json >/dev/null
node "$CLI" tools approve-executable katana --command "$KATANA_BIN" --json >/dev/null
node "$CLI" hunt recon "$TARGET" --profile web --live --tools httpx,katana --json > "$RECON_JSON"

node -e "
const fs = require('fs');
const result = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const tools = new Map(result.tools.map((tool) => [tool.tool, tool]));
for (const name of ['httpx', 'katana']) {
  const tool = tools.get(name);
  if (!tool || tool.status !== 'executed' || tool.approvalPresent !== true) {
    throw new Error(name + ' did not execute through the approved tool runner');
  }
}
if (!Array.isArray(result.observations) || result.observations.length < 1) {
  throw new Error('real-tool recon produced no scoped observations');
}
if (!result.observations.every((observation) => observation.scopeAllowed === true)) {
  throw new Error('real-tool recon returned out-of-scope observations');
}
console.log(JSON.stringify({
  ok: true,
  target: result.target,
  jobId: result.jobId,
  observations: result.observations.length,
  tools: result.tools.map((tool) => ({ tool: tool.tool, status: tool.status, observations: tool.observations })),
}, null, 2));
" "$RECON_JSON"
