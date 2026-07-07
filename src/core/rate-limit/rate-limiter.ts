export interface RateLimitState {
  host: string;
  nextAllowedAt: number;
}

export class RateLimiter {
  private readonly intervalMs: number;
  private readonly states = new Map<string, RateLimitState>();

  constructor(rateLimit = "1rps") {
    this.intervalMs = parseRateLimitToIntervalMs(rateLimit);
  }

  async wait(urlOrHost: string): Promise<void> {
    const host = toHost(urlOrHost);
    const now = Date.now();
    const state = this.states.get(host) ?? { host, nextAllowedAt: now };
    const delay = Math.max(0, state.nextAllowedAt - now);
    if (delay > 0) {
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
    this.states.set(host, {
      host,
      nextAllowedAt: Date.now() + this.intervalMs,
    });
  }
}

export function parseRateLimitToIntervalMs(rateLimit: string): number {
  const match = /^(\d+(?:\.\d+)?)rps$/.exec(rateLimit.trim());
  if (!match) {
    return 1000;
  }
  const rps = Number(match[1]);
  if (!Number.isFinite(rps) || rps <= 0) {
    return 1000;
  }
  return Math.ceil(1000 / rps);
}

function toHost(urlOrHost: string): string {
  try {
    return new URL(urlOrHost).hostname.toLowerCase();
  } catch {
    return urlOrHost.toLowerCase();
  }
}
