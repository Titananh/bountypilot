const SECRET_PATTERNS: RegExp[] = [
  /("?api[_-]?key"?\s*[:=]\s*"?)[^\s"',}\\]+/gi,
  /("?(?:access|refresh)?[_-]?token"?\s*[:=]\s*"?)[^\s"',}\\]+/gi,
  /("?(?:authorization|proxy-authorization)"?\s*[:=]\s*"?(?:bearer|basic)\s+)[^\s"',}\\]+/gi,
  /("?(?:password|passphrase|secret|client[_-]?secret)"?\s*[:=]\s*"?)[^\s"',}\\]+/gi,
  /("?(?:cookie|set-cookie|session(?:[_-]?(?:id|token))?|csrf|xsrf)"?\s*[:=]\s*"?)[^\r\n"'}]+/gi,
  // JWTs are bearer material even when embedded in a response body or URL.
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
];

const SECRET_KEY_PATTERN =
  /^(?:api[\s_-]?key|x-api-key|token|access[\s_-]?token|refresh[\s_-]?token|authorization|proxy[\s_-]?authorization|bearer|password|passphrase|secret|client[\s_-]?secret|cookie|set[\s_-]?cookie|session(?:[\s_-]?(?:id|token))?|csrf|xsrf|jwt|private[\s_-]?key)$/i;

const SENSITIVE_HEADER_PATTERN =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-access-token|x-refresh-token|www-authenticate)$/i;

export function maskSecrets(value: string): string {
  let masked = SECRET_PATTERNS.reduce((current, pattern, index) => {
    // The final pattern matches the complete JWT rather than a key/value
    // prefix, so it must not use a `$1` replacement token.
    return index === SECRET_PATTERNS.length - 1
      ? current.replace(pattern, "[REDACTED]")
      : current.replace(pattern, "$1[REDACTED]");
  }, value);
  // Also handle plain-text header lines, where there is no JSON key to guide
  // maskSecretsDeep. Redact the whole value through the line boundary.
  masked = masked.replace(
    /(^|[\r\n])\s*(?:cookie|set-cookie|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)\s*:\s*[^\r\n]*/gim,
    "$1[REDACTED-HEADER]",
  );
  return masked;
}

/** Return a copy of HTTP headers safe for local evidence and audit output. */
export function redactHttpHeaders(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name,
      isSensitiveHeaderName(name) ? "[REDACTED]" : maskSecrets(String(value)),
    ]),
  );
}

export function isSensitiveHeaderName(name: string): boolean {
  return SENSITIVE_HEADER_PATTERN.test(name) || /(?:auth|token|secret|session|cookie|csrf|xsrf|credential)/i.test(name);
}

export function maskSecretsDeep<T>(value: T): T {
  return maskSecretValue(value) as T;
}

function maskSecretValue(value: unknown, key?: string): unknown {
  if (isSecretKey(key)) {
    return "[REDACTED]";
  }
  if (typeof value === "string") {
    return maskSecrets(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => maskSecretValue(item));
  }
  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, item]) => [entryKey, maskSecretValue(item, entryKey)]),
    );
  }
  return value;
}

function isSecretKey(key?: string): boolean {
  return key ? SECRET_KEY_PATTERN.test(key) : false;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
