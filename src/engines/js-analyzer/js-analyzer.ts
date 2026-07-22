import { maskSecrets } from "../../utils/secrets.js";
import { BountyPilotError } from "../../utils/errors.js";

export interface JsAnalysisResult {
  pageUrl: string;
  scriptUrls: string[];
  endpointCandidates: string[];
  routeCandidates: string[];
  possibleSecrets: string[];
}

export type FetchText = (url: string) => Promise<string>;

const SCRIPT_SRC_PATTERN = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;
const ENDPOINT_PATTERN = /["'`](\/(?:api|graphql|v\d+|internal|admin|auth|oauth|users|account)[^"'`\s]*)["'`]/gi;
const ROUTE_PATTERN = /["'`](\/[a-zA-Z0-9][a-zA-Z0-9/_\-.:?=&%{}]*)["'`]/gi;
const SECRET_PATTERN = /\b(?:api[_-]?key|token|secret|password)\b\s*[:=]\s*["']?([^"'\s,}]+)/gi;

export async function analyzeJavaScript(
  pageUrl: string,
  options: { allowUrl: (url: string) => boolean; fetchText: FetchText },
): Promise<JsAnalysisResult> {
  if (typeof options?.allowUrl !== "function" || typeof options?.fetchText !== "function") {
    throw new BountyPilotError(
      "JavaScript analysis requires an authority-bound fetch context.",
      "JS_ANALYZER_CONTEXT_REQUIRED",
    );
  }
  if (!options.allowUrl(pageUrl)) {
    throw new BountyPilotError("JavaScript analysis target is outside the approved scope.", "SCOPE_BLOCKED");
  }
  const fetchText = options.fetchText;
  const html = await fetchText(pageUrl);
  const scriptUrls = extractScriptUrls(pageUrl, html);
  const endpointCandidates = new Set<string>();
  const routeCandidates = new Set<string>();
  const possibleSecrets = new Set<string>();

  collectMatches(html, ENDPOINT_PATTERN, endpointCandidates);
  collectMatches(html, ROUTE_PATTERN, routeCandidates);
  collectSecretMatches(html, possibleSecrets);

  for (const scriptUrl of scriptUrls.filter((url) => options.allowUrl(url)).slice(0, 10)) {
    try {
      const body = await fetchText(scriptUrl);
      collectMatches(body, ENDPOINT_PATTERN, endpointCandidates);
      collectMatches(body, ROUTE_PATTERN, routeCandidates);
      collectSecretMatches(body, possibleSecrets);
    } catch (error) {
      // Network/content failures for an individual optional script may be
      // skipped, but a scope or authority failure must stop the action. A
      // broad catch here must never turn policy drift into a successful
      // execution record.
      if (isAuthorityBoundaryError(error)) throw error;
      continue;
    }
  }

  return {
    pageUrl,
    scriptUrls,
    endpointCandidates: [...endpointCandidates].sort(),
    routeCandidates: [...routeCandidates].sort().slice(0, 100),
    possibleSecrets: [...possibleSecrets].sort(),
  };
}

function isAuthorityBoundaryError(error: unknown): boolean {
  if (!(error instanceof BountyPilotError)) return false;
  return new Set([
    "ACTION_AUTHORITY_DRIFT",
    "ACTION_EFFECT_AUTHORITY_UNAVAILABLE",
    "SCOPE_BLOCKED",
    "POLICY_BLOCKED",
    "PLAYWRIGHT_REQUEST_AUTHORITY_FAILED",
  ]).has(error.code);
}

function extractScriptUrls(pageUrl: string, html: string): string[] {
  const urls = new Set<string>();
  for (const match of html.matchAll(SCRIPT_SRC_PATTERN)) {
    try {
      urls.add(new URL(match[1], pageUrl).toString());
    } catch {
      continue;
    }
  }
  return [...urls];
}

function collectMatches(source: string, pattern: RegExp, output: Set<string>): void {
  for (const match of source.matchAll(pattern)) {
    output.add(maskSecrets(match[1]));
  }
}

function collectSecretMatches(source: string, output: Set<string>): void {
  for (const match of source.matchAll(SECRET_PATTERN)) {
    output.add(maskSecrets(match[0]));
  }
}
