import type { ProgramConfig } from "../config/program-schema.js";
import { BountyPilotError } from "../../utils/errors.js";

export interface ScopeMatch {
  allowed: boolean;
  url: string;
  host: string;
  matchedInScope?: string;
  matchedOutOfScope?: string;
  reason: string;
}

export class ScopeGuard {
  constructor(private readonly config: ProgramConfig) {}

  test(urlLike: string): ScopeMatch {
    const url = parseUrl(urlLike);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return {
        allowed: false,
        url: url.toString(),
        host: url.hostname.toLowerCase(),
        reason: "Only http and https targets are supported",
      };
    }
    const host = url.hostname.toLowerCase();
    const matchedOutOfScope = this.config.out_of_scope.find((pattern) => patternMatchesUrl(pattern, url));
    if (matchedOutOfScope) {
      return {
        allowed: false,
        url: url.toString(),
        host,
        matchedOutOfScope,
        reason: `Blocked by out_of_scope rule ${matchedOutOfScope}`,
      };
    }

    const matchedInScope = this.config.in_scope.find((pattern) => patternMatchesUrl(pattern, url));
    if (!matchedInScope) {
      return {
        allowed: false,
        url: url.toString(),
        host,
        reason: "Target is not explicitly in scope",
      };
    }

    return {
      allowed: true,
      url: url.toString(),
      host,
      matchedInScope,
      reason: `Allowed by in_scope rule ${matchedInScope}`,
    };
  }

  assertAllowed(urlLike: string): ScopeMatch {
    const result = this.test(urlLike);
    if (!result.allowed) {
      throw new BountyPilotError(result.reason, "SCOPE_BLOCKED");
    }
    return result;
  }
}

function parseUrl(urlLike: string): URL {
  try {
    return new URL(urlLike);
  } catch {
    try {
      return new URL(`https://${urlLike}`);
    } catch {
      throw new BountyPilotError(`Invalid URL or host: ${urlLike}`, "INVALID_TARGET");
    }
  }
}

export function patternMatchesHost(pattern: string, host: string): boolean {
  const normalized = parseScopePattern(pattern).hostPattern;
  if (normalized.startsWith("*.")) {
    const suffix = normalized.slice(2);
    return host.endsWith(`.${suffix}`) && host !== suffix;
  }
  return host === normalized;
}

interface ParsedScopePattern {
  hostPattern: string;
  protocol?: string;
  port?: string;
  pathPrefix?: string;
}

function patternMatchesUrl(pattern: string, url: URL): boolean {
  const parsed = parseScopePattern(pattern);
  if (!patternMatchesHost(parsed.hostPattern, url.hostname.toLowerCase())) {
    return false;
  }
  if (parsed.protocol && parsed.protocol !== url.protocol) {
    return false;
  }
  if (parsed.port && parsed.port !== effectivePort(url)) {
    return false;
  }
  if (parsed.pathPrefix && !pathMatchesPrefix(url.pathname, parsed.pathPrefix)) {
    return false;
  }
  return true;
}

function parseScopePattern(pattern: string): ParsedScopePattern {
  const trimmed = pattern.trim().toLowerCase();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      return {
        hostPattern: parsed.hostname,
        protocol: parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.protocol : undefined,
        port: explicitPort(trimmed) ?? undefined,
        pathPrefix: parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : undefined,
      };
    } catch {
      return { hostPattern: trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0] ?? trimmed };
    }
  }
  return { hostPattern: trimmed.replace(/^https?:\/\//, "").split("/")[0] ?? trimmed };
}

function explicitPort(pattern: string): string | undefined {
  const authority = pattern.slice(pattern.indexOf("//") + 2).split(/[/?#]/)[0] ?? "";
  const match = authority.match(/:(\d+)$/);
  return match?.[1];
}

function effectivePort(url: URL): string {
  if (url.port) return url.port;
  if (url.protocol === "http:") return "80";
  if (url.protocol === "https:") return "443";
  return "";
}

function pathMatchesPrefix(pathname: string, prefix: string): boolean {
  const normalizedPrefix = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return pathname === prefix || pathname.startsWith(normalizedPrefix);
}
