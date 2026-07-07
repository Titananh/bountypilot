const SECRET_PATTERNS: RegExp[] = [
  /("?api[_-]?key"?\s*[:=]\s*"?)[^\s"',}\\]+/gi,
  /("?token"?\s*[:=]\s*"?)[^\s"',}\\]+/gi,
  /("?authorization"?\s*[:=]\s*"?bearer\s+)[^\s"',}\\]+/gi,
  /("?password"?\s*[:=]\s*"?)[^\s"',}\\]+/gi,
  /("?secret"?\s*[:=]\s*"?)[^\s"',}\\]+/gi,
];

const SECRET_KEY_PATTERN =
  /^(?:api[\s_-]?key|x-api-key|token|access[\s_-]?token|refresh[\s_-]?token|authorization|password|secret|client[\s_-]?secret)$/i;

export function maskSecrets(value: string): string {
  return SECRET_PATTERNS.reduce((current, pattern) => current.replace(pattern, "$1[REDACTED]"), value);
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
