import { BountyPilotError } from "../../utils/errors.js";

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
  headers?: Record<string, string>;
  maxRedirects?: number;
  onRequest?: (event: ScopedFetchRequestEvent) => void;
  onBlockedRedirect?: (event: ScopedFetchBlockedRedirectEvent) => void;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export async function fetchScopedText(url: string, options: ScopedFetchTextOptions): Promise<string> {
  const maxRedirects = options.maxRedirects ?? 5;
  let currentUrl = url;
  let redirectedFrom: string | undefined;
  const seenUrls = new Set<string>();

  for (let redirectHop = 0; redirectHop <= maxRedirects; redirectHop += 1) {
    assertAllowedFetchUrl(currentUrl, options.allowUrl);
    await options.wait?.(currentUrl);

    const started = Date.now();
    const response = await fetch(currentUrl, {
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
    if (!REDIRECT_STATUSES.has(response.status) || !location) {
      return response.text();
    }

    const targetUrl = new URL(location, currentUrl).toString();
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

function assertAllowedFetchUrl(url: string, allowUrl: (url: string) => boolean): void {
  if (!allowUrl(url)) {
    throw new BountyPilotError(`URL is out of scope: ${url}`, "SCOPE_BLOCKED");
  }
}
