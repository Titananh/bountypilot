import type { ExecutionMode } from "../types.js";

export interface HuntProfile {
  id: string;
  title: string;
  mode: ExecutionMode;
  components: string[];
  purpose: string;
  phases: string[];
  bugClasses: string[];
  toolCategories: string[];
  validationGates: string[];
}

export interface ArsenalTool {
  name: string;
  category: string;
  purpose: string;
  install: string;
  runPolicy: "passive" | "safe" | "review-required" | "lab-only";
}

export type VmBootstrapLevel = "safe" | "full";

export const HUNT_PROFILES: HuntProfile[] = [
  {
    id: "recon",
    title: "Authorized recon",
    mode: "safe",
    components: ["d-research-skill", "safe-checks", "js-analyzer", "planner"],
    purpose: "Map the in-scope surface, collect passive/client-side signals, and queue next actions for review.",
    phases: ["scope guard", "public research ledger", "safe HTTP checks", "JavaScript endpoint discovery", "planner queue"],
    bugClasses: ["exposed metadata", "missing security headers", "leaked client-side hints", "interesting endpoints"],
    toolCategories: ["subdomain enumeration", "live host discovery", "URLs and parameters", "JavaScript analysis"],
    validationGates: [
      "Target must match imported in_scope rules.",
      "No external adapter execution without explicit config and approval.",
      "Findings remain notes until evidence and triage pass.",
    ],
  },
  {
    id: "web",
    title: "Web app evidence",
    mode: "deep-safe",
    components: ["d-research-skill", "safe-checks", "js-analyzer", "playwright", "planner", "triage"],
    purpose: "Capture browser evidence and turn high-signal observations into triaged local findings.",
    phases: ["scope guard", "safe checks", "client-side analysis", "browser evidence", "planner loop", "triage"],
    bugClasses: ["XSS candidates", "open redirect candidates", "CORS/header issues", "sensitive file exposure", "auth-flow clues"],
    toolCategories: ["screenshots", "technologies", "content discovery", "parameters", "vulnerability scanners"],
    validationGates: [
      "Browser requests must remain in scope.",
      "Evidence must be readable and linked to the current job.",
      "Duplicate risk and reportability must be checked before report drafting.",
    ],
  },
  {
    id: "validate",
    title: "Validate and report",
    mode: "safe",
    components: ["safe-checks", "js-analyzer", "triage"],
    purpose: "Re-check evidence quality, reduce false positives, and prepare report-ready findings.",
    phases: ["scope guard", "repeat safe checks", "evidence review", "triage gate", "report readiness"],
    bugClasses: ["validated impact", "duplicate risk", "report quality", "reproduction clarity"],
    toolCategories: ["triage", "report writing", "evidence manifest", "duplicate review"],
    validationGates: [
      "Can an attacker do this right now?",
      "Is there clear impact beyond informational output?",
      "Can the behavior be reproduced without unsafe steps?",
      "Is the report inside platform scope and rules?",
    ],
  },
  {
    id: "lab-aggressive",
    title: "Owned lab aggressive practice",
    mode: "lab-offensive",
    components: ["safe-checks", "js-analyzer", "playwright", "planner", "triage"],
    purpose: "Practice the full loop against local/private labs that explicitly opt into lab_mode.",
    phases: ["lab authorization", "scope guard", "live local workflow", "planner loop", "triage"],
    bugClasses: ["training XSS", "training SSRF", "training traversal", "training authz issues"],
    toolCategories: ["local lab", "browser evidence", "payload practice", "report drafting"],
    validationGates: [
      "Program config must set rules.lab_mode=true.",
      "Authorization file must exist in the program workspace.",
      "Targets must be local, private, or explicitly owned lab assets.",
    ],
  },
];

export const ARSENAL_TOOLS: ArsenalTool[] = [
  {
    name: "subfinder",
    category: "subdomain enumeration",
    purpose: "Passive subdomain discovery for authorized program assets.",
    install: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    runPolicy: "passive",
  },
  {
    name: "dnsx",
    category: "subdomain enumeration",
    purpose: "Resolve discovered hosts and filter dead DNS records.",
    install: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    runPolicy: "safe",
  },
  {
    name: "httpx",
    category: "live host discovery",
    purpose: "Identify live HTTP services, titles, technologies, redirects, and status codes.",
    install: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    runPolicy: "safe",
  },
  {
    name: "katana",
    category: "URLs and crawling",
    purpose: "Crawl in-scope web apps for URLs, forms, and JavaScript routes.",
    install: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    runPolicy: "safe",
  },
  {
    name: "gau",
    category: "URLs and history",
    purpose: "Gather historical URLs for parameter and endpoint review.",
    install: "go install github.com/lc/gau/v2/cmd/gau@latest",
    runPolicy: "passive",
  },
  {
    name: "waybackurls",
    category: "URLs and history",
    purpose: "Pull archived URLs for scoped hosts.",
    install: "go install github.com/tomnomnom/waybackurls@latest",
    runPolicy: "passive",
  },
  {
    name: "nuclei",
    category: "vulnerability scanners",
    purpose: "Template-based checks; run only with rate limits and program permission.",
    install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    runPolicy: "review-required",
  },
  {
    name: "nuclei-templates",
    category: "vulnerability scanners",
    purpose: "Community templates for nuclei; review severity and intrusiveness before use.",
    install: "nuclei -update-templates",
    runPolicy: "review-required",
  },
  {
    name: "ffuf",
    category: "content discovery",
    purpose: "Directory, file, and parameter discovery with strict rate limits.",
    install: "go install github.com/ffuf/ffuf/v2@latest",
    runPolicy: "review-required",
  },
  {
    name: "dalfox",
    category: "XSS validation",
    purpose: "XSS parameter validation; keep to owned labs or explicitly permitted scopes.",
    install: "go install github.com/hahwul/dalfox/v2@latest",
    runPolicy: "review-required",
  },
  {
    name: "naabu",
    category: "port scanning",
    purpose: "Fast port discovery; frequently restricted by program rules.",
    install: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    runPolicy: "review-required",
  },
  {
    name: "Burp Suite Community",
    category: "web proxy and traffic interception",
    purpose: "Manual verification, request replay, and report-quality evidence.",
    install: "Install from https://portswigger.net/burp/communitydownload",
    runPolicy: "review-required",
  },
  {
    name: "jq",
    category: "workflow utilities",
    purpose: "Parse JSON outputs and stitch recon artifacts.",
    install: "sudo apt-get install -y jq",
    runPolicy: "passive",
  },
  {
    name: "curl",
    category: "workflow utilities",
    purpose: "Capture single scoped HTTP request/response samples.",
    install: "sudo apt-get install -y curl",
    runPolicy: "safe",
  },
  {
    name: "nmap",
    category: "port scanning",
    purpose: "Manual service discovery for explicitly authorized assets and local labs.",
    install: "sudo apt-get install -y nmap",
    runPolicy: "review-required",
  },
  {
    name: "playwright",
    category: "browser evidence",
    purpose: "Capture screenshots, HAR, DOM snapshots, and crawl evidence.",
    install: "npm install -g playwright && npx playwright install chromium",
    runPolicy: "safe",
  },
  {
    name: "crawl4ai",
    category: "crawler",
    purpose: "Optional scoped crawler integration for local crawl graphs.",
    install: "pipx install crawl4ai",
    runPolicy: "review-required",
  },
  {
    name: "playwright-mcp",
    category: "MCP browser",
    purpose: "Optional MCP browser adapter for scoped evidence capture.",
    install: "npm install -g @playwright/mcp",
    runPolicy: "review-required",
  },
  {
    name: "d-research-skill",
    category: "research",
    purpose: "Planning-only public research context and duplicate hints.",
    install: "Bundled planning prompt; no external install required.",
    runPolicy: "passive",
  },
];

export function getHuntProfile(id: string): HuntProfile | undefined {
  return HUNT_PROFILES.find((profile) => profile.id === id);
}

export function renderVmArsenalMarkdown(): string {
  const lines = [
    "# BountyPilot VM Arsenal Plan",
    "",
    "This plan is install guidance only. Run tools only on assets you own or are explicitly authorized to test.",
    "",
    "## Profiles",
    "",
    ...HUNT_PROFILES.flatMap((profile) => [
      `### ${profile.id}: ${profile.title}`,
      "",
      `- Mode: ${profile.mode}`,
      `- Components: ${profile.components.join(", ")}`,
      `- Purpose: ${profile.purpose}`,
      `- Bug classes: ${profile.bugClasses.join(", ")}`,
      "",
    ]),
    "## Tool Install Plan",
    "",
    ...ARSENAL_TOOLS.flatMap((tool) => [
      `### ${tool.name}`,
      "",
      `- Category: ${tool.category}`,
      `- Purpose: ${tool.purpose}`,
      `- Run policy: ${tool.runPolicy}`,
      `- Install: \`${tool.install}\``,
      "",
    ]),
    "## BountyPilot First Run",
    "",
    "- `bounty init --guided --program-file examples/local-program.yml`",
    "- `bounty providers catalog`",
    "- `echo <api-key> | bounty providers connect openai --api-key-stdin --model gpt-4.1-mini`",
    "- `bounty hunt profiles`",
    "- `bounty hunt plan http://127.0.0.1:8080 --profile web --write`",
    "- `bounty hunt run <in-scope-target> --profile recon --dry-run`",
    "",
  ];
  return lines.join("\n");
}

export function renderVmBootstrapScript(level: VmBootstrapLevel): string {
  const selectedTools = ARSENAL_TOOLS.filter((tool) => level === "full" || tool.runPolicy === "passive" || tool.runPolicy === "safe");
  const skippedTools = ARSENAL_TOOLS.filter((tool) => !selectedTools.includes(tool));
  const lines = [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "",
    "# BountyPilot VM bootstrap script.",
    "# Review this file before running it. Only test assets you own or are explicitly authorized to test.",
    `# Level: ${level}`,
    "",
    "sudo apt-get update",
    "sudo apt-get install -y git curl wget jq nodejs npm golang-go python3 python3-pip",
    "",
    "mkdir -p \"$HOME/go/bin\"",
    "export PATH=\"$PATH:$HOME/go/bin\"",
    "grep -q 'HOME/go/bin' \"$HOME/.profile\" || echo 'export PATH=\"$PATH:$HOME/go/bin\"' >> \"$HOME/.profile\"",
    "",
    "# Browser evidence runtime used by BountyPilot.",
    "npx playwright install chromium",
    "",
    "# Bug bounty tools selected for this bootstrap level.",
    ...selectedTools.flatMap((tool) => installLinesForTool(tool)),
  ];
  if (skippedTools.length > 0) {
    lines.push("", "# Review-required tools skipped by safe bootstrap level:");
    for (const tool of skippedTools) {
      lines.push(`# - ${tool.name}: ${tool.install}`);
    }
  }
  lines.push(
    "",
    "# Suggested first BountyPilot commands:",
    "# bounty providers catalog",
    "# bounty hunt profiles",
    "# bounty arsenal profiles",
    "# bounty hunt run <in-scope-target> --profile recon --dry-run",
    "",
  );
  return lines.join("\n");
}

function installLinesForTool(tool: ArsenalTool): string[] {
  if (tool.install.startsWith("go install ") || tool.install.startsWith("sudo ") || tool.install.startsWith("nuclei ")) {
    return ["", `# ${tool.name} - ${tool.purpose}`, tool.install];
  }
  return ["", `# ${tool.name} - manual install`, `# ${tool.install}`];
}
