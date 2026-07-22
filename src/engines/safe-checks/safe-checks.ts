import { maskSecrets } from "../../utils/secrets.js";
import { BountyPilotError } from "../../utils/errors.js";

export interface SafeCheckResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  findings: SafeCheckFinding[];
}

export interface SafeCheckFinding {
  title: string;
  category: string;
  severityEstimate: "info" | "low" | "medium";
  confidence: "low" | "medium" | "high";
  evidence: string;
  remediation?: string;
}

export interface SafeCheckExecutionContext {
  /** The authority-bound fetcher supplied by ActionExecutor. */
  fetchResponse: (url: string) => Promise<Response>;
  /** Explicit scope predicate; there is intentionally no permissive default. */
  allowUrl: (url: string) => boolean;
}

export async function runSafeChecks(url: string, context: SafeCheckExecutionContext): Promise<SafeCheckResult> {
  if (!context || typeof context.fetchResponse !== "function" || typeof context.allowUrl !== "function") {
    throw new BountyPilotError(
      "Safe checks require an authority-bound fetch context.",
      "SAFE_CHECK_CONTEXT_REQUIRED",
    );
  }
  if (!context.allowUrl(url)) {
    throw new BountyPilotError("Safe-check target is outside the approved scope.", "SCOPE_BLOCKED");
  }
  const response = await context.fetchResponse(url);

  const headers = Object.fromEntries(response.headers.entries());
  await response.body?.cancel().catch(() => undefined);
  const findings: SafeCheckFinding[] = [];

  if (!headers["content-security-policy"]) {
    findings.push({
      title: "Content-Security-Policy header is missing",
      category: "security_headers",
      severityEstimate: "info",
      confidence: "high",
      evidence: "Response did not include a content-security-policy header.",
      remediation: "Define a restrictive Content-Security-Policy appropriate for the application.",
    });
  }

  if (!headers["x-frame-options"] && !headers["content-security-policy"]?.includes("frame-ancestors")) {
    findings.push({
      title: "Clickjacking protection header is missing",
      category: "security_headers",
      severityEstimate: "info",
      confidence: "medium",
      evidence: "Response did not include x-frame-options or CSP frame-ancestors.",
      remediation: "Use CSP frame-ancestors or X-Frame-Options where applicable.",
    });
  }

  if (!headers["strict-transport-security"] && url.startsWith("https://")) {
    findings.push({
      title: "Strict-Transport-Security header is missing",
      category: "security_headers",
      severityEstimate: "info",
      confidence: "medium",
      evidence: "HTTPS response did not include strict-transport-security.",
      remediation: "Enable HSTS after confirming HTTPS is consistently available.",
    });
  }

  const acao = headers["access-control-allow-origin"];
  const acac = headers["access-control-allow-credentials"]?.toLowerCase() === "true";
  if (acao === "*") {
    findings.push({
      title: "CORS wildcard origin observed",
      category: "cors",
      severityEstimate: "low",
      confidence: "medium",
      evidence: "access-control-allow-origin was set to *.",
      remediation: "Restrict CORS origins to trusted applications when credentials or sensitive APIs are involved.",
    });
  }
  if (acao === "https://bountypilot.local" && acac) {
    findings.push({
      title: "CORS reflected arbitrary origin with credentials observed",
      category: "cors",
      severityEstimate: "medium",
      confidence: "high",
      evidence: "Response reflected the test Origin and set access-control-allow-credentials: true.",
      remediation: "Use an allowlist of trusted origins and avoid credentialed CORS for untrusted origins.",
    });
  }

  return {
    url,
    status: response.status,
    headers: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, maskSecrets(value)])),
    findings,
  };
}
