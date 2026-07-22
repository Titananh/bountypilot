import { BountyPilotError } from "../../utils/errors.js";
import { fetchPinnedNetworkTarget } from "./network-address-policy.js";

export interface ScopedFetchRequestEvent {
  url: string;
  status: number;
  durationMs: number;
  redirectHop: number;
  redirectedFrom?: string;
}

export interface ScopedFetchBlockedRedirectEvent {
  fromUrl: string;
  location: string;
  targetUrl: string;
  redirectStatus: number;
  redirectHop: number;
}

export interface ScopedFetchTextOptions {
  allowUrl: (url: string) => boolean;
  wait?: (url: string) => Promise<void>;
  /** Called after authority/rate gates and immediately before fetch(). */
  beforeRequest?: (url: string) => void | Promise<void>;
  headers?: Record<string, string>;
  maxRedirects?: number;
  onRequest?: (event: ScopedFetchRequestEvent) => void;
  onBlockedRedirect?: (event: ScopedFetchBlockedRedirectEvent) => void;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Fetch a response through the scope/redirect/rate-limit authority hooks. */
export async function fetchScopedResponse(url: string, options: ScopedFetchTextOptions): Promise<Response> {
  const maxRedirects = options.maxRedirects ?? 5;
  let currentUrl = url;
  let redirectedFrom: string | undefined;
  const seenUrls = new Set<string>();

  for (let redirectHop = 0; redirectHop <= maxRedirects; redirectHop += 1) {
    assertSafeHttpUrl(currentUrl);
    assertAllowedFetchUrl(currentUrl, options.allowUrl);
    await options.wait?.(currentUrl);
    await options.beforeRequest?.(currentUrl);

    const started = Date.now();
    const response = await fetchPinnedNetworkTarget(currentUrl, {
      headers: options.headers,
      redirect: "manual",
    });
    options.onRequest?.({
      url: currentUrl,
      status: response.status,
      durationMs: Date.now() - started,
      redirectHop,
      redirectedFrom,
    });

    const location = response.headers.get("location");
    if (!REDIRECT_STATUSES.has(response.status) || !location) return response;

    const targetUrl = new URL(location, currentUrl).toString();
    assertSafeHttpUrl(targetUrl);
    if (!options.allowUrl(targetUrl)) {
      await response.body?.cancel();
      options.onBlockedRedirect?.({
        fromUrl: currentUrl,
        location,
        targetUrl,
        redirectStatus: response.status,
        redirectHop: redirectHop + 1,
      });
      throw new BountyPilotError(`Redirect target is out of scope: ${targetUrl}`, "SCOPE_BLOCKED");
    }
    if (seenUrls.has(targetUrl)) {
      await response.body?.cancel();
      throw new BountyPilotError(`Redirect loop detected at ${targetUrl}`, "HTTP_REDIRECT_LOOP");
    }
    if (redirectHop === maxRedirects) {
      await response.body?.cancel();
      throw new BountyPilotError(`Redirect limit exceeded for ${url}`, "HTTP_REDIRECT_LIMIT");
    }

    seenUrls.add(currentUrl);
    redirectedFrom = currentUrl;
    currentUrl = targetUrl;
  }

  throw new BountyPilotError(`Redirect limit exceeded for ${url}`, "HTTP_REDIRECT_LIMIT");
}

export async function fetchScopedText(url: string, options: ScopedFetchTextOptions): Promise<string> {
  const response = await fetchScopedResponse(url, options);
  return response.text();
}

function assertAllowedFetchUrl(url: string, allowUrl: (url: string) => boolean): void {
  if (!allowUrl(url)) {
    throw new BountyPilotError(`URL is out of scope: ${url}`, "SCOPE_BLOCKED");
  }
}

function assertSafeHttpUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new BountyPilotError(`Invalid request URL: ${url}`, "INVALID_TARGET");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new BountyPilotError("Only HTTP and HTTPS requests are supported", "SCOPE_BLOCKED");
  }
  if (parsed.username || parsed.password) {
    throw new BountyPilotError("Credentials in request URLs are not allowed", "SCOPE_BLOCKED");
  }
  if (/%[0-9a-f]{2}/i.test(parsed.pathname)) {
    throw new BountyPilotError(
      "Percent-encoded path octets are not allowed at the request boundary",
      "SCOPE_BLOCKED",
    );
  }
}
