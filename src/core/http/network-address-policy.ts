import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { BountyPilotError } from "../../utils/errors.js";

export interface ResolvedNetworkTarget {
  hostname: string;
  address: string;
  family: 4 | 6;
  /** True when the URL itself contained an IP literal or localhost. */
  explicitLocal: boolean;
}

const DNS_TIMEOUT_MS = 5_000;
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Resolve a request host once and classify every answer before connecting.
 * Explicit IP literals (and localhost) are accepted because ScopeGuard still
 * requires the literal to be explicitly authorized. Hostnames resolving to a
 * private/reserved address are rejected; callers can use an authorized lab IP
 * literal instead of relying on a mutable DNS name.
 */
export async function resolveNetworkTarget(urlLike: string): Promise<ResolvedNetworkTarget> {
  let parsed: URL;
  try {
    parsed = new URL(urlLike);
  } catch {
    throw new BountyPilotError("Invalid network target", "INVALID_TARGET");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new BountyPilotError("Only HTTP and HTTPS network targets are supported", "NETWORK_TARGET_BLOCKED");
  }
  if (parsed.username || parsed.password) {
    throw new BountyPilotError("Credentials in network target URLs are not allowed", "NETWORK_TARGET_BLOCKED");
  }

  const hostname = parsed.hostname.toLowerCase();
  const literalFamily = net.isIP(hostname);
  if (literalFamily === 4 || literalFamily === 6 || hostname === "localhost" || hostname.endsWith(".localhost")) {
    const address = literalFamily === 4 || literalFamily === 6
      ? hostname
      : literalFamily === 6
        ? "::1"
        : "127.0.0.1";
    return { hostname, address, family: literalFamily === 6 ? 6 : 4, explicitLocal: true };
  }

  let answers: dns.LookupAddress[];
  try {
    answers = await withTimeout(
      dns.promises.lookup(hostname, { all: true, verbatim: true }),
      DNS_TIMEOUT_MS,
      "NETWORK_DNS_TIMEOUT",
    );
  } catch (error) {
    if (error instanceof BountyPilotError) throw error;
    throw new BountyPilotError("DNS resolution failed for network target", "NETWORK_DNS_FAILED");
  }
  if (answers.length === 0) {
    throw new BountyPilotError("DNS returned no network addresses", "NETWORK_DNS_FAILED");
  }
  if (answers.some((answer) => isPrivateOrReservedAddress(answer.address))) {
    throw new BountyPilotError(
      "Hostname resolves to a private or reserved network address; use an explicitly authorized lab IP literal",
      "NETWORK_PRIVATE_ADDRESS_BLOCKED",
    );
  }
  const selected = answers.find((answer) => answer.family === 4 || answer.family === 6);
  if (!selected || !net.isIP(selected.address)) {
    throw new BountyPilotError("DNS returned an invalid network address", "NETWORK_DNS_FAILED");
  }
  return {
    hostname,
    address: selected.address,
    family: selected.family === 6 ? 6 : 4,
    explicitLocal: false,
  };
}

/**
 * A fetch-compatible, pinned-address HTTP client. The DNS answer selected by
 * resolveNetworkTarget is supplied through Node's lookup callback, preventing
 * a second resolver call between policy evaluation and socket connection.
 */
export async function fetchPinnedNetworkTarget(
  urlLike: string,
  init: RequestInit = {},
): Promise<Response> {
  const target = await resolveNetworkTarget(urlLike);
  const parsed = new URL(urlLike);
  const transport = parsed.protocol === "https:" ? https : http;
  const headers = new Headers(init.headers);
  if (!headers.has("host")) headers.set("host", parsed.host);
  const body = typeof init.body === "string" ? init.body : undefined;

  return new Promise<Response>((resolve, reject) => {
    const request = transport.request(
      {
        protocol: parsed.protocol,
        hostname: target.address,
        port: parsed.port || undefined,
        path: `${parsed.pathname}${parsed.search}`,
        method: init.method ?? "GET",
        headers: Object.fromEntries(headers.entries()),
        // `hostname` is the vetted IP literal, so Node cannot perform a
        // second hostname lookup between policy evaluation and connect.
        ...(parsed.protocol === "https:" ? { servername: parsed.hostname } : {}),
        timeout: REQUEST_TIMEOUT_MS,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer | string) => chunks.push(Buffer.from(chunk)));
        response.on("end", () => {
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) {
              for (const item of value) responseHeaders.append(name, item);
            } else if (value !== undefined) {
              responseHeaders.set(name, String(value));
            }
          }
          resolve(
            new Response(Buffer.concat(chunks), {
              status: response.statusCode && response.statusCode >= 100 ? response.statusCode : 500,
              statusText: response.statusMessage,
              headers: responseHeaders,
            }),
          );
        });
      },
    );
    request.once("timeout", () => request.destroy(new Error("Network request timed out")));
    request.once("error", () => reject(new BountyPilotError("Network request failed", "NETWORK_REQUEST_FAILED")));
    if (init.signal) {
      if (init.signal.aborted) {
        request.destroy(new Error("Network request aborted"));
      } else {
        init.signal.addEventListener("abort", () => request.destroy(new Error("Network request aborted")), { once: true });
      }
    }
    if (body !== undefined) request.write(body);
    request.end();
  });
}

export function isPrivateOrReservedAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) return isPrivateIpv6(address);
  return true;
}

function isPrivateIpv4(address: string): boolean {
  const octets = address.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b, c] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isPrivateIpv6(address: string): boolean {
  const normalized = address.toLowerCase().split("%", 1)[0];
  if (normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true;
  if (normalized.startsWith("ff")) return true;
  if (normalized.startsWith("2001:db8:") || normalized.startsWith("2001:10:") || normalized.startsWith("2001:2:")) return true;
  // IPv4-mapped IPv6 addresses must receive the IPv4 classification.
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? isPrivateIpv4(mapped[1]) : false;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, code: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new BountyPilotError("DNS resolution timed out", code)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
