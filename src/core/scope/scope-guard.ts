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
    if (url.username || url.password) {
      return {
        allowed: false,
        url: url.toString(),
        host: url.hostname.toLowerCase(),
        reason: "Credentials in target URLs are not allowed",
      };
    }
    if (hasPercentEncodedPathOctet(url.pathname)) {
      return {
        allowed: false,
        url: url.toString(),
        host: url.hostname.toLowerCase(),
        reason: "Percent-encoded path octets are not allowed at the scope boundary",
      };
    }
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
  const trimmed = pattern.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      if (
        (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
        parsed.username ||
        parsed.password ||
        parsed.search ||
        parsed.hash ||
        !parsed.hostname ||
        hasPercentEncodedPathOctet(parsed.pathname)
      ) {
        return { hostPattern: "\u0000invalid-scope-pattern" };
      }
      return {
        hostPattern: parsed.hostname.toLowerCase(),
        protocol: parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.protocol.toLowerCase() : undefined,
        // An explicit URL denotes one origin. If the text omits a port, bind
        // the scheme's canonical default instead of authorizing every service
        // on the host.
        port: explicitPort(trimmed) ?? effectivePort(parsed),
        pathPrefix: parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : undefined,
      };
    } catch {
      return { hostPattern: "\u0000invalid-scope-pattern" };
    }
  }
  if (/[/?#@]/.test(trimmed)) {
    return { hostPattern: "\u0000invalid-scope-pattern" };
  }
  return { hostPattern: (trimmed.split("/")[0] ?? trimmed).toLowerCase() };
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

function hasPercentEncodedPathOctet(pathname: string): boolean {
  return /%[0-9a-f]{2}/i.test(pathname);
}
