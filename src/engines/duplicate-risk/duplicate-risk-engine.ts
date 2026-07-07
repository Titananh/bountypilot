import type { DuplicateRisk, NormalizedFinding } from "../../types.js";

export interface DuplicateRiskResult {
  risk: DuplicateRisk;
  reasons: string[];
  matchingFindingIds: string[];
}

export class DuplicateRiskEngine {
  estimate(candidate: Pick<NormalizedFinding, "url" | "asset" | "category" | "title">, history: NormalizedFinding[]): DuplicateRiskResult {
    const signals = history.flatMap((finding, historyIndex) => scoreDuplicateSignals(candidate, finding, historyIndex));
    if (signals.length === 0) {
      return {
        risk: "unknown",
        reasons: ["No local duplicate signal found. Private platform reports cannot be checked locally."],
        matchingFindingIds: [],
      };
    }

    const strongestScore = Math.max(...signals.map((signal) => signal.score));
    const risk = riskFromScore(strongestScore);
    const threshold = minimumScoreForRisk(risk);
    const relevantSignals = signals
      .filter((signal) => signal.score >= threshold)
      .sort((left, right) => right.score - left.score || left.historyIndex - right.historyIndex || left.findingId.localeCompare(right.findingId));

    return {
      risk,
      reasons: [
        ...unique(relevantSignals.map((signal) => signal.reason)).slice(0, 3),
        "Duplicate risk is based only on local BountyPilot history; private platform reports cannot be checked locally.",
      ],
      matchingFindingIds: unique(relevantSignals.map((signal) => signal.findingId)),
    };
  }
}

interface DuplicateSignal {
  score: number;
  historyIndex: number;
  findingId: string;
  reason: string;
}

function scoreDuplicateSignals(
  candidate: Pick<NormalizedFinding, "url" | "asset" | "category" | "title">,
  finding: NormalizedFinding,
  historyIndex: number,
): DuplicateSignal[] {
  const signals: DuplicateSignal[] = [];
  const candidateUrl = urlProfile(candidate.url);
  const findingUrl = urlProfile(finding.url);
  const candidateAsset = assetProfile(candidate.asset);
  const findingAsset = assetProfile(finding.asset);
  const sameUrl = findingUrl.canonical === candidateUrl.canonical;
  const sameHostPathIgnoringScheme = Boolean(
    findingUrl.host &&
      candidateUrl.host &&
      findingUrl.host === candidateUrl.host &&
      findingUrl.port === candidateUrl.port &&
      findingUrl.pathKey === candidateUrl.pathKey,
  );
  const sameHostPathIgnoringCase = Boolean(
    findingUrl.host &&
      candidateUrl.host &&
      findingUrl.host === candidateUrl.host &&
      findingUrl.port === candidateUrl.port &&
      findingUrl.pathKey.toLowerCase() === candidateUrl.pathKey.toLowerCase(),
  );
  const sameRouteTemplate = Boolean(
    findingUrl.host &&
      candidateUrl.host &&
      findingUrl.host === candidateUrl.host &&
      findingUrl.port === candidateUrl.port &&
      findingUrl.routeTemplate === candidateUrl.routeTemplate &&
      findingUrl.routeTemplate !== "/",
  );
  const sameAsset = findingAsset.exactKey === candidateAsset.exactKey;
  const sameAssetFamily = sameAsset || hostBelongsToFamily(candidateAsset.host, findingAsset.familyKey) || hostBelongsToFamily(findingAsset.host, candidateAsset.familyKey);
  const sameCategory = categoryKey(finding.category) === categoryKey(candidate.category);
  const titleScore = titleSimilarity(finding.title, candidate.title);
  const divergentQueryKeys = hasDivergentQueryKeys(candidateUrl.queryKeys, findingUrl.queryKeys);

  if (sameUrl && sameCategory) {
    signals.push(weightedSignal(finding, {
      score: divergentQueryKeys ? 70 : 95,
      historyIndex,
      findingId: finding.id,
      reason: divergentQueryKeys
        ? "Same path and category exist locally, but query parameter names differ and need comparison."
        : "Same normalized URL and vulnerability category already exist in local history.",
    }));
  } else if (sameUrl && titleScore >= 0.6) {
    signals.push(weightedSignal(finding, {
      score: 85,
      historyIndex,
      findingId: finding.id,
      reason: "Same normalized URL and similar title already exist in local history.",
    }));
  } else if (sameHostPathIgnoringScheme && sameCategory) {
    signals.push(weightedSignal(finding, {
      score: 82,
      historyIndex,
      findingId: finding.id,
      reason: "Same host, path, and category already exist locally with a different URL scheme.",
    }));
  } else if (sameHostPathIgnoringCase && sameCategory) {
    signals.push(weightedSignal(finding, {
      score: 78,
      historyIndex,
      findingId: finding.id,
      reason: "Same host, case-insensitive path, and category already exist locally.",
    }));
  } else if (sameRouteTemplate && sameCategory && titleScore >= 0.6) {
    signals.push(weightedSignal(finding, {
      score: 82,
      historyIndex,
      findingId: finding.id,
      reason: "Same host, route template, category, and similar title already exist locally.",
    }));
  } else if (sameRouteTemplate && sameCategory) {
    signals.push(weightedSignal(finding, {
      score: 62,
      historyIndex,
      findingId: finding.id,
      reason: "Same host, route template, and vulnerability category already exist locally.",
    }));
  } else if (sameAsset && sameCategory && titleScore >= 0.6) {
    signals.push(weightedSignal(finding, {
      score: 70,
      historyIndex,
      findingId: finding.id,
      reason: "Same asset, category, and similar title already exist in local history.",
    }));
  } else if (sameAsset && sameCategory) {
    signals.push(weightedSignal(finding, {
      score: 55,
      historyIndex,
      findingId: finding.id,
      reason: "Same asset and vulnerability category already exist in local history.",
    }));
  } else if (sameAssetFamily && sameCategory && titleScore >= 0.65) {
    signals.push(weightedSignal(finding, {
      score: 58,
      historyIndex,
      findingId: finding.id,
      reason: "Related asset, category, and similar title already exist in local history.",
    }));
  } else if (sameCategory && titleScore >= 0.75) {
    signals.push(weightedSignal(finding, {
      score: 50,
      historyIndex,
      findingId: finding.id,
      reason: "Very similar title and vulnerability category already exist in local history.",
    }));
  } else if (sameAsset && titleScore >= 0.75) {
    signals.push(weightedSignal(finding, {
      score: 35,
      historyIndex,
      findingId: finding.id,
      reason: "Very similar title exists on the same asset in local history.",
    }));
  }

  return signals;
}

function weightedSignal(finding: NormalizedFinding, signal: DuplicateSignal): DuplicateSignal {
  if (finding.status === "submitted" || finding.status === "report_drafted" || finding.status === "validated") {
    return { ...signal, score: clamp(signal.score + 5, 0, 99) };
  }
  if (finding.status === "duplicate" || finding.status === "invalid") {
    return { ...signal, score: clamp(signal.score - 15, 0, 99) };
  }
  if (finding.status === "needs_validation" || finding.status === "needs_manual_review") {
    return { ...signal, score: clamp(signal.score - 5, 0, 99) };
  }
  return signal;
}

function riskFromScore(score: number): Exclude<DuplicateRisk, "unknown"> {
  if (score >= 80) return "high";
  if (score >= 50) return "medium";
  return "low";
}

function minimumScoreForRisk(risk: Exclude<DuplicateRisk, "unknown">): number {
  switch (risk) {
    case "high":
      return 80;
    case "medium":
      return 50;
    case "low":
      return 25;
  }
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

interface UrlProfile {
  canonical: string;
  host?: string;
  port: string;
  pathKey: string;
  routeTemplate: string;
  queryKeys: Set<string>;
}

interface AssetProfile {
  exactKey: string;
  familyKey: string;
  host?: string;
}

function urlProfile(value: string): UrlProfile {
  try {
    const url = new URL(value);
    const pathname = normalizePath(url.pathname);
    const port = url.port ? `:${url.port}` : "";
    return {
      canonical: `${url.protocol}//${url.hostname.toLowerCase()}${port}${pathname}`,
      host: stripWww(url.hostname.toLowerCase()),
      port,
      pathKey: pathname,
      routeTemplate: routeTemplate(pathname),
      queryKeys: queryKeys(url.searchParams),
    };
  } catch {
    const normalized = normalize(value);
    return {
      canonical: normalized,
      port: "",
      pathKey: normalized,
      routeTemplate: routeTemplate(normalized),
      queryKeys: new Set(),
    };
  }
}

function titleSimilarity(left: string, right: string): number {
  const leftTokens = new Set(tokenize(left));
  const rightTokens = new Set(tokenize(right));
  if (leftTokens.size === 0 || rightTokens.size === 0) {
    return 0;
  }

  const intersection = [...leftTokens].filter((token) => rightTokens.has(token)).length;
  const union = new Set([...leftTokens, ...rightTokens]).size;
  return intersection / union;
}

function tokenize(value: string): string[] {
  return normalize(value)
    .split(" ")
    .filter((token) => token.length > 2 && !TITLE_STOP_WORDS.has(token));
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

const TITLE_STOP_WORDS = new Set([
  "and",
  "are",
  "can",
  "detected",
  "enabled",
  "exposed",
  "finding",
  "found",
  "issue",
  "missing",
  "possible",
  "potential",
  "the",
  "vulnerability",
  "with",
]);

function categoryKey(value: string): string {
  const normalized = normalize(value);
  if (/\b(graphql|introspection)\b/.test(normalized)) return "graphql";
  if (/\b(idor|bola|bopla|access control|authorization|authorisation|authz)\b/.test(normalized)) return "access_control";
  if (/\b(cross site scripting|xss)\b/.test(normalized)) return "xss";
  if (/\b(open redirect|redirect)\b/.test(normalized)) return "open_redirect";
  if (/\b(cors|cross origin)\b/.test(normalized)) return "cors";
  if (/\b(secret|token|api key|apikey|credential|jwt|password)\b/.test(normalized)) return "secret_exposure";
  if (/\b(ssrf|sqli|sql injection|rce|command injection|template injection|xxe)\b/.test(normalized)) return "injection";
  if (/\b(source map|sourcemap|debug|swagger|openapi)\b/.test(normalized)) return "exposed_debug";
  if (/\b(security headers|security header|hsts|csp)\b/.test(normalized)) return "security_headers";
  if (/\b(cookie flags|cookie flag|samesite|httponly|secure cookie)\b/.test(normalized)) return "cookie_flags";
  return normalized;
}

function assetProfile(value: string): AssetProfile {
  const withoutWildcard = value.trim().toLowerCase().replace(/^\*\./, "");
  const parsed = parseAssetUrl(withoutWildcard);
  const host = parsed ? stripWww(parsed.hostname.toLowerCase()) : stripWww(withoutWildcard.split("/")[0].replace(/:\d+$/, ""));
  return {
    exactKey: host,
    familyKey: host,
    host,
  };
}

function parseAssetUrl(value: string): URL | undefined {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`);
  } catch {
    return undefined;
  }
}

function normalizePath(pathname: string): string {
  const decoded = safeDecode(pathname);
  return decoded.replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/";
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function routeTemplate(pathname: string): string {
  const normalized = normalizePath(pathname).toLowerCase();
  const segments = normalized.split("/").map((segment) => {
    if (/^\d+$/.test(segment)) return ":id";
    if (/^[a-f0-9]{8,}$/.test(segment)) return ":id";
    if (/^[a-f0-9]{8}-[a-f0-9-]{13,}$/i.test(segment)) return ":id";
    return segment;
  });
  return segments.join("/") || "/";
}

function queryKeys(searchParams: URLSearchParams): Set<string> {
  return new Set([...searchParams.keys()].map((key) => key.toLowerCase()).sort());
}

function hasDivergentQueryKeys(left: Set<string>, right: Set<string>): boolean {
  return left.size > 0 && right.size > 0 && !setsIntersect(left, right);
}

function setsIntersect<T>(left: Set<T>, right: Set<T>): boolean {
  for (const item of left) {
    if (right.has(item)) return true;
  }
  return false;
}

function hostBelongsToFamily(host: string | undefined, family: string | undefined): boolean {
  return Boolean(host && family && (host === family || host.endsWith(`.${family}`)));
}

function stripWww(host: string): string {
  return host.replace(/^www\./, "");
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
