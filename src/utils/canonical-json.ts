// P0.2 Packet 0 — Canonical JSON utility.
//
// Produces a deterministic UTF-8 byte representation of plain JSON values.
// The output is used to feed SHA-256 across the program authority hash
// contract (scope, policy, action binding, approval context). Any change
// in separator, encoding, key ordering, or hash algorithm is a breaking
// change to the hash contract; the golden tests in
// `tests/program-authority-snapshot.test.ts` pin the exact format.
//
// Contract:
//   - object keys are sorted recursively using their UTF-16 code unit
//     ordering (matches ECMAScript Array.prototype.sort semantics);
//   - arrays preserve insertion order;
//   - JSON primitives, plain objects, and plain arrays are accepted;
//   - `undefined`, functions, symbols, bigints, non-finite numbers, sparse
//     or unsupported array members, symbol-keyed properties, cyclic
//     graphs, and non-plain objects (Date, Map, Buffer, class instances)
//     are rejected with `BountyPilotError` code
//     `CANONICAL_VALUE_UNSUPPORTED`.
//   - the output is UTF-8 encoded with no whitespace and no BOM.
//   - for plain objects, every own string property must be an enumerable
//     data descriptor; symbol keys, accessors, and non-enumerable own
//     string properties are rejected (this guards against
//     `Object.defineProperty` shenanigans that would let a caller hide
//     data from `Object.keys`/`for..in` while the canonicalizer still
//     emits it).
//   - for arrays, the only allowed own properties are the standard
//     `length` property plus an own enumerable data descriptor at every
//     index in `[0, length)`. Holes supplied by the prototype chain,
//     accessor indices, symbol properties, named own properties, and
//     non-enumerable indices are all rejected fail closed.
//   - getters are never invoked: descriptor reads use
//     `Object.getOwnPropertyDescriptor` directly.
//   - cycle detection walks ancestors only; a value may reappear in a
//     sibling subtree after its parent subtree finishes.
//
// `sha256Canonical` performs SHA-256 over `domain || 0x00 || canonical
// bytes` and returns the lowercase hex digest.

import { createHash } from "node:crypto";
import { types as nodeTypes } from "node:util";
import { BountyPilotError } from "./errors.js";

const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const MAX_CANONICAL_DEPTH = 256;
const MAX_CANONICAL_CONTAINER_ENTRIES = 100_000;

export function canonicalize(value: unknown): Buffer {
  return canonicalizeInternal(value, new WeakSet<object>(), 0);
}

export function sha256Canonical(value: unknown, domain: string): string {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new BountyPilotError(
      "sha256Canonical requires a non-empty domain string",
      "CANONICAL_VALUE_UNSUPPORTED",
    );
  }
  const canonical = canonicalize(value);
  const domainBytes = Buffer.from(domain, "utf8");
  if (domainBytes.length === 0) {
    throw new BountyPilotError(
      "sha256Canonical requires a non-empty domain string",
      "CANONICAL_VALUE_UNSUPPORTED",
    );
  }
  if (domainBytes.subarray(0, 3).equals(BOM)) {
    throw new BountyPilotError(
      "sha256Canonical domain must not include a UTF-8 BOM",
      "CANONICAL_VALUE_UNSUPPORTED",
    );
  }
  const separator = Buffer.from([0]);
  return createHash("sha256").update(Buffer.concat([domainBytes, separator, canonical])).digest("hex");
}

function canonicalizeInternal(value: unknown, seen: WeakSet<object>, depth: number): Buffer {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw unsupported("Canonical JSON nesting exceeds the supported depth");
  }
  if (value === null) return Buffer.from("null", "utf8");
  if (typeof value === "boolean") return Buffer.from(value ? "true" : "false", "utf8");
  if (typeof value === "string") return encodeString(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw unsupported(`Non-finite number is not supported by canonical JSON: ${String(value)}`);
    }
    if (Object.is(value, -0)) {
      return Buffer.from("0", "utf8");
    }
    return Buffer.from(JSON.stringify(value), "utf8");
  }
  if (typeof value === "bigint") {
    throw unsupported("BigInt values are not supported by canonical JSON");
  }
  if (typeof value === "function" || typeof value === "symbol" || typeof value === "undefined") {
    throw unsupported(`Value of type ${typeof value} is not supported by canonical JSON`);
  }
  if (typeof value === "object" && nodeTypes.isProxy(value)) {
    throw unsupported("Proxy values are not supported by canonical JSON");
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) {
      throw unsupported("Cyclic object graphs are not supported by canonical JSON");
    }
    seen.add(value);
    try {
      return canonicalizeArray(value, seen, depth);
    } finally {
      seen.delete(value);
    }
  }
  if (value instanceof Date) {
    throw unsupported("Date values are not supported by canonical JSON");
  }
  if (value instanceof Map || value instanceof Set) {
    throw unsupported("Map and Set values are not supported by canonical JSON");
  }
  if (Buffer.isBuffer(value) || value instanceof ArrayBuffer) {
    throw unsupported("Buffer and ArrayBuffer values are not supported by canonical JSON");
  }
  if (typeof value === "object") {
    if (seen.has(value as object)) {
      throw unsupported("Cyclic object graphs are not supported by canonical JSON");
    }
    if (!isPlainObject(value)) {
      throw unsupported("Non-plain object values are not supported by canonical JSON");
    }
    seen.add(value as object);
    try {
      return canonicalizeObject(value as Record<PropertyKey, unknown>, seen, depth);
    } finally {
      seen.delete(value as object);
    }
  }
  throw unsupported(`Value of type ${typeof value} is not supported by canonical JSON`);
}

function canonicalizeArray(value: unknown[], seen: WeakSet<object>, depth: number): Buffer {
  // Inspect every own property descriptor so we can fail closed on
  // hidden slots without ever invoking a getter or triggering a Proxy
  // `get` trap. The only allowed own properties on a plain array are:
  //   * the standard `length` property, which must be an own data
  //     descriptor whose `value` is a safe nonnegative integer no
  //     greater than 4294967295 (2^32 - 1, the V8 array cap). A
  //     subclass that hides `length` behind the prototype, that
  //     overrides `length` as an accessor, or that smuggles a
  //     non-integer or oversized length value in is rejected fail
  //     closed;
  //   * an enumerable data descriptor for every index in [0, length).
  // Anything else — a named property, a symbol, a non-enumerable index,
  // an accessor on an index, or a missing own index whose value is
  // supplied only by the prototype chain — is rejected.
  // Read `length` from its own descriptor so a Proxy cannot smuggle a
  // value through the `get` trap, and so a subclass that has redefined
  // `length` as an accessor or installed a malformed length value is
  // rejected before any index is examined.
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor === undefined) {
    throw unsupported("Arrays must carry an own length property");
  }
  if (!isDataDescriptor(lengthDescriptor)) {
    throw unsupported("Array length must be a data descriptor");
  }
  const length = lengthDescriptor.value;
  if (
    typeof length !== "number" ||
    !Number.isInteger(length) ||
    length < 0 ||
    length > 4294967295
  ) {
    throw unsupported(
      "Array length must be a safe nonnegative integer no greater than 4294967295",
    );
  }
  if (length > MAX_CANONICAL_CONTAINER_ENTRIES) {
    throw unsupported("Array length exceeds the canonical JSON entry budget");
  }
  const ownSymbols = Object.getOwnPropertySymbols(value);
  if (ownSymbols.length > 0) {
    throw unsupported("Arrays must not carry symbol properties");
  }
  const ownNames = Object.getOwnPropertyNames(value);
  // Reject any own string key that is not the standard `length` or a
  // valid index in [0, length).
  let ownIndexCount = 0;
  for (const name of ownNames) {
    if (name === "length") continue;
    if (!isArrayIndexName(name, length)) {
      throw unsupported("Arrays must not carry extra named own properties");
    }
    ownIndexCount += 1;
  }
  if (ownIndexCount !== length) {
    throw unsupported("Sparse arrays are not supported by canonical JSON");
  }
  // For each allowed index, verify the descriptor is an own enumerable
  // data descriptor (no accessors, no holes supplied by the prototype)
  // and cache the value so the serialization pass below never performs
  // an ordinary property read on the array.
  const indexValues: unknown[] = new Array(length);
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined) {
      throw unsupported("Sparse arrays are not supported by canonical JSON");
    }
    if (!isDataDescriptor(descriptor)) {
      throw unsupported(`Arrays must not carry accessor indices (index ${index})`);
    }
    if (descriptor.enumerable !== true) {
      throw unsupported(`Arrays must not carry non-enumerable own indices (index ${index})`);
    }
    indexValues[index] = descriptor.value;
  }
  if (length === 0) {
    return Buffer.from("[]", "utf8");
  }
  const parts: Buffer[] = [Buffer.from("[", "utf8")];
  for (let index = 0; index < length; index += 1) {
    if (index > 0) parts.push(Buffer.from(",", "utf8"));
    parts.push(canonicalizeInternal(indexValues[index], seen, depth + 1));
  }
  parts.push(Buffer.from("]", "utf8"));
  return Buffer.concat(parts);
}

function canonicalizeObject(
  value: Record<PropertyKey, unknown>,
  seen: WeakSet<object>,
  depth: number,
): Buffer {
  // Walk every own property descriptor so we can reject symbol keys,
  // accessors, and non-enumerable own string keys fail closed. We must
  // never invoke a getter — descriptors are inspected, not the values
  // — and we must never perform an ordinary property read, because a
  // Proxy `get` trap would then fire and the canonicalizer would no
  // longer be a pure function of the data descriptors.
  const ownSymbols = Object.getOwnPropertySymbols(value);
  if (ownSymbols.length > 0) {
    throw unsupported("Symbol-keyed object entries are not supported by canonical JSON");
  }
  const ownNames = Object.getOwnPropertyNames(value);
  if (ownNames.length > MAX_CANONICAL_CONTAINER_ENTRIES) {
    throw unsupported("Object size exceeds the canonical JSON entry budget");
  }
  if (ownNames.length === 0) {
    return Buffer.from("{}", "utf8");
  }
  const entries: Array<{ key: string; value: unknown }> = [];
  for (const name of ownNames) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (descriptor === undefined) {
      // Object.getOwnPropertyNames only returns names that have
      // descriptors, so this branch is defensive; the contract is
      // still that any missing descriptor is rejected.
      throw unsupported("An own object property is missing its descriptor");
    }
    if (!isDataDescriptor(descriptor)) {
      throw unsupported("Object accessor properties are not supported by canonical JSON");
    }
    if (descriptor.enumerable !== true) {
      throw unsupported(
        "Object non-enumerable own properties are not supported by canonical JSON",
      );
    }
    entries.push({ key: name, value: descriptor.value });
  }
  entries.sort((left, right) => defaultCompare(left.key, right.key));
  const parts: Buffer[] = [Buffer.from("{", "utf8")];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (index > 0) parts.push(Buffer.from(",", "utf8"));
    parts.push(encodeString(entry.key));
    parts.push(Buffer.from(":", "utf8"));
    parts.push(canonicalizeInternal(entry.value, seen, depth + 1));
  }
  parts.push(Buffer.from("}", "utf8"));
  return Buffer.concat(parts);
}

function isDataDescriptor(
  descriptor: PropertyDescriptor,
): descriptor is { value: unknown; writable?: boolean; enumerable?: boolean; configurable?: boolean } {
  // A property descriptor is an accessor descriptor iff it carries
  // `get` or `set`; otherwise (per ECMA-262 §6.2.5.4) it is a data
  // descriptor, even when only `writable` is present and `value` is
  // undefined. This is the only shape the canonicalizer ever inspects
  // — once we have decided a descriptor is a data descriptor, the
  // caller reads `descriptor.value` directly without ever performing
  // an ordinary property read on the owning object.
  return (
    "value" in descriptor &&
    !("get" in descriptor) &&
    !("set" in descriptor)
  );
}

function isArrayIndexName(name: string, length: number): boolean {
  // A valid non-negative integer string that maps to an index in
  // [0, length) — anything else (including "01", "1.0", "length", or a
  // number that exceeds `length`) is treated as a named property and
  // must be rejected.
  if (name.length === 0) return false;
  for (let i = 0; i < name.length; i += 1) {
    const code = name.charCodeAt(i);
    if (code < 0x30 || code > 0x39) return false;
  }
  const numeric = Number(name);
  if (!Number.isInteger(numeric) || numeric < 0) return false;
  if (name !== String(numeric)) return false;
  return numeric < length;
}

function encodeString(value: string): Buffer {
  // We use JSON.stringify for the string body because it already produces
  // valid canonical JSON for the JavaScript string type (it handles all
  // required escapes, surrogate pairs, and control characters). Rejecting
  // the result would be a strict-mode violation of the spec.
  const quoted = JSON.stringify(value);
  if (quoted === undefined) {
    throw unsupported("String serialization failed");
  }
  const bytes = Buffer.from(quoted, "utf8");
  if (bytes.subarray(0, 3).equals(BOM)) {
    // JSON.stringify never emits a BOM; this branch is defensive and
    // should never execute. The contract test still verifies the output
    // contains no leading BOM, so we enforce that here as well.
    throw unsupported("String serialization produced a UTF-8 BOM");
  }
  return bytes;
}

function unsupported(reason: string): BountyPilotError {
  return new BountyPilotError(reason, "CANONICAL_VALUE_UNSUPPORTED");
}

function isPlainObject(value: unknown): value is Record<PropertyKey, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function defaultCompare(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}
