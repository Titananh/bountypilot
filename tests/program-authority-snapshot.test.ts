// P0.2 Packet 0 — Canonical JSON and program authority snapshot tests.
//
// These tests pin the public contract implemented by
// `src/utils/canonical-json.ts`,
// `src/core/policy/program-authority-snapshot.ts`, and
// `src/core/actions/action-approval-context.ts` must satisfy. They exercise
// only local fixtures, in-memory data, and temp directories, never the
// network or any protected directory.
//
// Required invariants:
//   1. Canonical JSON: sorted object keys, UTF-8 no whitespace/BOM,
//      arrays preserve order by default, set-like arrays are normalized
//      by the caller, and unsupported values (undefined, function,
//      symbol, bigint, cycles, non-finite numbers) fail closed.
//   2. Authority snapshot hashes:
//      - semantically equivalent Zod-normalized configs produce identical
//        hashes regardless of object key order;
//      - omitted defaults equal explicit defaults;
//      - scope array reordering and duplicates do not change scopeHash;
//      - scope/policy/account/evidence/lab authorization mutation changes
//        the right hash and no other;
//      - moving the same workspace to a different absolute path does not
//        change any hash (workspace path is never bound).
//   3. Lab authorization hardening:
//      - actual byte length is verified after read, not just stat;
//      - symlinks that escape the program workspace are rejected without
//        reading bytes outside the workspace;
//      - realpath-based containment is enforced even for nested segments.

import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  loadLabAuthorization,
  loadProgramFile,
  MAX_LAB_AUTHORIZATION_FILE_BYTES,
  type LabAuthorization,
  type LabAuthorizationFileAccess,
} from "../src/core/config/config-loader.js";
import { ProgramSchema, type ProgramConfig } from "../src/core/config/program-schema.js";
import { BountyPilotError } from "../src/utils/errors.js";
import {
  AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  POLICY_SEMANTICS_VERSION,
  POLICY_SNAPSHOT_SCHEMA_VERSION,
  SCOPE_SEMANTICS_VERSION,
  SCOPE_SNAPSHOT_SCHEMA_VERSION,
  buildPolicySnapshot,
  buildProgramAuthoritySnapshot,
  buildScopeSnapshot,
  computePolicyHash,
  computeScopeHash,
  normalizeScopeArrays,
  type PolicySnapshot,
  type ScopeSnapshot,
} from "../src/core/policy/program-authority-snapshot.js";
import { canonicalize, sha256Canonical } from "../src/utils/canonical-json.js";
import {
  ACTION_BINDING_SCHEMA_VERSION,
  ACTION_SEMANTICS_VERSION,
  buildActionBinding,
  computeActionHash,
  computeContextHash,
  type ActionBinding,
  type ActionBindingInput,
  type SafeIntegrationExecutionPolicy,
} from "../src/core/actions/action-approval-context.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    try {
      rmSync(root, { recursive: true, force: true });
    } catch {
      // best-effort cleanup; do not let teardown fail the test
    }
  }
});

function makeTempRoot(prefix: string): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), prefix));
  roots.push(dir);
  return dir;
}

function parseAndNormalize(yamlSource: string): ProgramConfig {
  return ProgramSchema.parse(parseYaml(yamlSource));
}

function buildConfig(overrides: Partial<ProgramConfig> = {}): ProgramConfig {
  const yaml = `program: snapshot-base
platform: hackerone

in_scope:
  - "api.example.com"
  - "*.example.com"

out_of_scope:
  - "staging.example.com"
  - "*.internal.example.com"

rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "1rps"
  browser_crawling: true
  deep_safe_mode: true
  require_human_approval_for_risky_actions: true

accounts:
  required: false
  use_researcher_owned_test_accounts_only: true

evidence:
  screenshots: true
  har: true
  console_logs: true
  dom_snapshot: true
  video: optional
  browser_trace: true
  desktop_screenshots: optional
  mask_secrets: true

integrations: {}
`;
  const base = parseAndNormalize(yaml);
  return { ...base, ...overrides } as ProgramConfig;
}

function configWithExplicitDefaults(overrides: Partial<ProgramConfig> = {}): ProgramConfig {
  return {
    program: "snapshot-explicit",
    platform: "hackerone",
    in_scope: ["api.example.com"],
    out_of_scope: [],
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "1rps",
      browser_crawling: true,
      deep_safe_mode: true,
      lab_mode: false,
      require_human_approval_for_risky_actions: true,
    },
    accounts: {
      required: false,
      use_researcher_owned_test_accounts_only: true,
    },
    evidence: {
      screenshots: true,
      har: true,
      console_logs: true,
      dom_snapshot: true,
      video: "optional",
      browser_trace: true,
      desktop_screenshots: "optional",
      mask_secrets: true,
    },
    integrations: {},
    ...overrides,
  };
}

function configWithLabAuthorization(
  config: ProgramConfig,
  relativePath: string,
  labMode: boolean,
): ProgramConfig {
  return {
    ...config,
    rules: {
      ...config.rules,
      lab_mode: labMode,
      lab_authorization_file: relativePath,
    },
  };
}

function expectBountyError(run: () => unknown, code: string | RegExp): BountyPilotError {
  let thrown: unknown;
  try {
    run();
  } catch (error) {
    thrown = error;
  }
  expect(thrown, "expected function to throw").toBeInstanceOf(BountyPilotError);
  const actual = (thrown as BountyPilotError).code;
  if (typeof code === "string") {
    expect(actual).toBe(code);
  } else {
    expect(actual).toMatch(code);
  }
  return thrown as BountyPilotError;
}

function labAuthorizationFixture(content = "Authorized local lab owned by researcher.\n"): LabAuthorization {
  return {
    relativePath: "lab-authorization.md",
    byteLength: Buffer.byteLength(content, "utf8"),
    contentSha256: createHash("sha256").update(content, "utf8").digest("hex"),
  };
}

describe("canonical JSON utility", () => {
  it("sorts object keys recursively and emits UTF-8 bytes with no whitespace", () => {
    const value = { b: 2, a: { y: 1, x: [{ d: 4, c: 3 }] } };
    const expected = Buffer.from('{"a":{"x":[{"c":3,"d":4}],"y":1},"b":2}', "utf8");
    expect(canonicalize(value).equals(expected)).toBe(true);
  });

  it("preserves array order by default", () => {
    const bytes = canonicalize({ list: [3, 1, 2] });
    expect(bytes.toString("utf8")).toBe('{"list":[3,1,2]}');
  });

  it("hashes the same content with different key order to the same digest", () => {
    const a = { program: "x", rules: { rate_limit: "1rps", destructive_testing: false } };
    const b = { rules: { destructive_testing: false, rate_limit: "1rps" }, program: "x" };
    expect(sha256Canonical(a, "bountypilot/scope-snapshot/v1")).toBe(
      sha256Canonical(b, "bountypilot/scope-snapshot/v1"),
    );
  });

  it("returns a 64-character lowercase hex digest with domain separation", () => {
    const value = { a: 1 };
    const domainA = sha256Canonical(value, "bountypilot/scope-snapshot/v1");
    const domainB = sha256Canonical(value, "bountypilot/policy-snapshot/v1");
    expect(domainA).toMatch(/^[0-9a-f]{64}$/);
    expect(domainB).toMatch(/^[0-9a-f]{64}$/);
    expect(domainA).not.toBe(domainB);
  });

  it("pin: sha256Canonical is SHA-256 over the exact domain string plus a single NUL byte plus the canonical JSON bytes", () => {
    // The canonical authority hash contract binds the domain string verbatim
    // and uses one NUL byte (0x00) as the separator. This test compares the
    // utility directly against node:crypto so any future drift in the
    // separator, encoding, or hash algorithm is caught immediately.
    const value = { b: 2, a: { y: 1, x: [{ d: 4, c: 3 }] } };
    const domain = "bountypilot/scope-snapshot/v1";
    const expected = createHash("sha256")
      .update(Buffer.concat([Buffer.from(domain, "utf8"), Buffer.from([0]), canonicalize(value)]))
      .digest("hex");
    expect(sha256Canonical(value, domain)).toBe(expected);
  });

  it("pin: computeContextHash matches sha256Canonical with the exact bountypilot/approval-context/v1 domain", () => {
    // The docs bind contextHash = SHA256(domain + canonicalJson({scopeHash,
    // policyHash, actionHash})) with the exact domain literal
    // "bountypilot/approval-context/v1". We exercise this against the
    // utility directly so the helper cannot drift from the spec.
    const scopeHash = "a".repeat(64);
    const policyHash = "b".repeat(64);
    const actionHash = "c".repeat(64);
    const expected = sha256Canonical(
      { scopeHash, policyHash, actionHash },
      "bountypilot/approval-context/v1",
    );
    expect(computeContextHash({ scopeHash, policyHash, actionHash })).toBe(expected);
  });

  it.each([
    ["undefined", { a: undefined as unknown as number }],
    ["top-level undefined", undefined],
    ["undefined in an array", [1, undefined]],
    ["a sparse array", Object.assign(new Array(2), { 0: "present" })],
    ["function", { a: () => 1 }],
    ["symbol", { a: Symbol("x") as unknown as number }],
    ["bigint", { a: 1n as unknown as number }],
    ["NaN", { a: Number.NaN }],
    ["Infinity", { a: Number.POSITIVE_INFINITY }],
    ["negative Infinity", { a: Number.NEGATIVE_INFINITY }],
  ])("rejects %s values fail closed", (_label, value) => {
    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("rejects cyclic object graphs fail closed", () => {
    const cycle: Record<string, unknown> = { name: "root" };
    cycle.self = cycle;
    expectBountyError(() => canonicalize(cycle), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("accepts nested null, boolean, and empty containers", () => {
    const bytes = canonicalize({ a: null, b: false, c: {}, d: [] });
    expect(bytes.toString("utf8")).toBe('{"a":null,"b":false,"c":{},"d":[]}');
  });

  it("encodes non-ASCII strings as exact UTF-8 without a BOM", () => {
    const expected = Buffer.from('{"emoji":"🛡️","text":"xin chào"}', "utf8");
    expect(canonicalize({ text: "xin chào", emoji: "🛡️" })).toEqual(expected);
    expect(expected.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))).toBe(false);
  });

  it("rejects symbol-keyed, cyclic-array, and non-plain object values", () => {
    const symbolKeyed: Record<PropertyKey, unknown> = { visible: true };
    symbolKeyed[Symbol("hidden")] = "collision";
    const cyclicArray: unknown[] = [];
    cyclicArray.push(cyclicArray);
    for (const value of [symbolKeyed, cyclicArray, new Date(0), new Map([["a", 1]]), Buffer.from("x")]) {
      expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
    }
  });
});

describe("canonicalize hardening — fail-closed on hidden own properties", () => {
  // P0.2 Packet 0 hardening: `canonicalize` must not silently lose data
  // when an object carries properties that `Object.keys` / `in` / numeric
  // iteration do not see. Every entry below is a deterministic contract test
  // that pins a fail-closed invariant for the canonicalizer. None of
  // these inputs are produced by the rest of the BountyPilot pipeline,
  // but the canonicalizer is the audit-critical primitive that feeds
  // every authority hash, so its rejection surface is a security
  // property, not an internal detail.
  //
  // The pattern across the suite:
  //   * build the value with only the property the test cares about;
  //   * when the contract requires that a getter is not invoked, install
  //     a `vi.fn()` getter and assert the spy was never called before
  //     and after `canonicalize` rejects;
  //   * when the contract requires that a prototype-supplied slot is
  //     ignored, place the value on a non-Array prototype so the bare
  //     `in` check cannot accidentally walk up the chain.

  it("rejects an object that has only a symbol key, no string keys at all", () => {
    const symbolKeyed: Record<PropertyKey, unknown> = Object.create(null) as Record<PropertyKey, unknown>;
    symbolKeyed[Symbol("only")] = "collision";
    expect(Object.keys(symbolKeyed)).toEqual([]);
    expect(Object.getOwnPropertySymbols(symbolKeyed)).toHaveLength(1);
    expectBountyError(() => canonicalize(symbolKeyed), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("rejects an enumerable accessor on a plain object without invoking its getter", () => {
    const getter = vi.fn(() => "must not be evaluated");
    const value: Record<PropertyKey, unknown> = {};
    Object.defineProperty(value, "k", {
      get: getter,
      enumerable: true,
      configurable: true,
    });
    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
    expect(getter).not.toHaveBeenCalled();
  });

  it("rejects a non-enumerable own string property that Object.keys would hide", () => {
    const value: Record<PropertyKey, unknown> = {};
    Object.defineProperty(value, "hidden", {
      value: "must not be silently dropped",
      enumerable: false,
      writable: true,
      configurable: true,
    });
    expect(Object.keys(value)).toEqual([]);
    expect(Object.getOwnPropertyNames(value)).toEqual(["hidden"]);
    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("rejects an array with an extra named own property beyond its numeric indices", () => {
    const arr = ["only-index-0"];
    Object.defineProperty(arr, "extra", {
      value: "named property on a plain array",
      enumerable: true,
      writable: true,
      configurable: true,
    });
    // Sanity: `Object.keys` reports both the numeric index and the
    // named property because both are enumerable own string keys, so
    // the pre-condition for this contract is observable in plain
    // JavaScript. The canonicalizer, however, must reject the input
    // because arrays must be plain index sequences.
    expect(Object.keys(arr).sort()).toEqual(["0", "extra"]);
    expect(Object.getOwnPropertyNames(arr).sort()).toEqual(["0", "extra", "length"]);
    expectBountyError(() => canonicalize(arr), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("rejects a plain array that carries a symbol property", () => {
    const arr = ["only-index-0"];
    (arr as unknown as Record<PropertyKey, unknown>)[Symbol("hidden")] = "collision";
    expect(Object.getOwnPropertySymbols(arr)).toHaveLength(1);
    expectBountyError(() => canonicalize(arr), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("rejects an accessor-backed array index without invoking its getter", () => {
    const getter = vi.fn(() => "must not be evaluated");
    const arr: unknown[] = [];
    Object.defineProperty(arr, 0, {
      get: getter,
      enumerable: true,
      configurable: true,
    });
    arr.length = 1;
    expectBountyError(() => canonicalize(arr), "CANONICAL_VALUE_UNSUPPORTED");
    expect(getter).not.toHaveBeenCalled();
  });

  it("rejects a sparse array whose hole is supplied only by its prototype", () => {
    // The array has length 2, own index 0 set, and no own index 1. The
    // prototype is a fresh plain object that supplies index 1 with a
    // value. A canonicalizer that uses the `in` operator would happily
    // walk into the prototype and emit `[<own>, <prototype>]`; the
    // contract requires that a slot not provided as an own property of
    // the array is treated as a sparse hole and rejected. The array
    // instance must remain a real `Array` so the canonicalizer takes
    // the array branch (otherwise the non-plain-object guard would
    // reject it for an unrelated reason and the test would be green
    // for the wrong contract).
    const proto: Record<PropertyKey, unknown> = { 1: "from prototype" };
    const arr = ["own-zero"];
    Object.setPrototypeOf(arr, proto);
    arr.length = 2;
    expect(Array.isArray(arr)).toBe(true);
    expect(Object.hasOwn(arr, 0)).toBe(true);
    expect(Object.hasOwn(arr, 1)).toBe(false);
    expect(1 in arr).toBe(true);
    expectBountyError(() => canonicalize(arr), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("rejects a plain-object Proxy without invoking its get trap", () => {
    const getTrap = vi.fn((target: { a: number; b: number }, property: PropertyKey, receiver: unknown) =>
      Reflect.get(target, property, receiver),
    );
    const value = new Proxy(
      { b: 2, a: 1 },
      {
        get: getTrap,
      },
    );

    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
    expect(getTrap).not.toHaveBeenCalled();
  });

  it("rejects an array Proxy without invoking its get trap", () => {
    const target: unknown[] = ["first", { b: 2, a: 1 }];
    const getTrap = vi.fn((array: unknown[], property: PropertyKey, receiver: unknown) =>
      Reflect.get(array, property, receiver),
    );
    const value = new Proxy(target, {
      get: getTrap,
    });

    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
    expect(getTrap).not.toHaveBeenCalled();
  });

  it("rejects a Proxy that hides configurable indices and lies about array length", () => {
    const target = ["hidden-zero", "hidden-one"];
    const ownKeysTrap = vi.fn(() => ["length"]);
    const descriptorTrap = vi.fn((array: string[], property: PropertyKey) => {
      const descriptor = Reflect.getOwnPropertyDescriptor(array, property);
      if (property === "length" && descriptor) {
        return {
          ...descriptor,
          value: 0,
        };
      }
      return descriptor;
    });
    const value = new Proxy(target, {
      ownKeys: ownKeysTrap,
      getOwnPropertyDescriptor: descriptorTrap,
    });

    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
    expect(ownKeysTrap).not.toHaveBeenCalled();
    expect(descriptorTrap).not.toHaveBeenCalled();
  });

  it("rejects a huge sparse array before iterating through absent indices", () => {
    const value = new Array(0xffff_ffff);
    const originalGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    const descriptorSpy = vi
      .spyOn(Object, "getOwnPropertyDescriptor")
      .mockImplementation((object: object, property: PropertyKey) => {
        if (object === value && property !== "length") {
          throw new Error("canonicalize iterated a known-sparse array");
        }
        return originalGetOwnPropertyDescriptor(object, property);
      });

    try {
      expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
      expect(descriptorSpy).toHaveBeenCalledTimes(1);
      expect(descriptorSpy).toHaveBeenCalledWith(value, "length");
    } finally {
      descriptorSpy.mockRestore();
    }
  });

  it("rejects an oversized dense array before enumerating all of its keys", () => {
    const value = new Array(100_001).fill(0);
    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("rejects object graphs deeper than the canonical nesting budget", () => {
    let value: Record<string, unknown> = {};
    for (let depth = 0; depth < 300; depth += 1) {
      value = { child: value };
    }
    expectBountyError(() => canonicalize(value), "CANONICAL_VALUE_UNSUPPORTED");
  });

  it("does not echo attacker-controlled property names in canonicalization errors", () => {
    const secretKey = "authorization=canonical-secret";
    const value: Record<PropertyKey, unknown> = {};
    Object.defineProperty(value, secretKey, {
      value: "hidden",
      enumerable: false,
      configurable: true,
    });

    const error = expectBountyError(
      () => canonicalize(value),
      "CANONICAL_VALUE_UNSUPPORTED",
    );
    expect(error.message).not.toContain(secretKey);
    expect(error.message).not.toContain("canonical-secret");
  });
});

describe("program authority snapshot — exact canonical contract", () => {
  const expectedScope: ScopeSnapshot = {
    schemaVersion: "scope-snapshot/v1",
    semanticsVersion: "scope/v1",
    program: "snapshot-base",
    platform: "hackerone",
    inScope: ["*.example.com", "api.example.com"],
    outOfScope: ["*.internal.example.com", "staging.example.com"],
  };
  const expectedPolicy: PolicySnapshot = {
    schemaVersion: "policy-snapshot/v1",
    semanticsVersion: "policy/v1",
    rules: {
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "1rps",
      browser_crawling: true,
      deep_safe_mode: true,
      lab_mode: false,
      require_human_approval_for_risky_actions: true,
    },
    accounts: {
      required: false,
      use_researcher_owned_test_accounts_only: true,
    },
    evidence: {
      screenshots: true,
      har: true,
      console_logs: true,
      dom_snapshot: true,
      video: "optional",
      browser_trace: true,
      desktop_screenshots: "optional",
      mask_secrets: true,
    },
    blockedCapabilities: [
      "brute_force",
      "credential_stuffing",
      "data_exfiltration",
      "destructive_testing",
      "malware_execution",
      "mass_scanning",
      "password_spraying",
      "payment_abuse",
      "real_user_account_takeover",
      "spam",
      "waf_evasion",
    ],
    labAuthorization: null,
  };

  it("pins exact scope/policy projections, canonical bytes, domains, and golden digests", () => {
    const scope = buildScopeSnapshot(buildConfig());
    const policy = buildPolicySnapshot(buildConfig(), null);
    const authority = buildProgramAuthoritySnapshot({ config: buildConfig(), labAuthorization: null });

    expect(SCOPE_SNAPSHOT_SCHEMA_VERSION).toBe("scope-snapshot/v1");
    expect(SCOPE_SEMANTICS_VERSION).toBe("scope/v1");
    expect(POLICY_SNAPSHOT_SCHEMA_VERSION).toBe("policy-snapshot/v1");
    expect(POLICY_SEMANTICS_VERSION).toBe("policy/v1");
    expect(AUTHORITY_SNAPSHOT_SCHEMA_VERSION).toBe("authority-snapshot/v1");
    expect(scope).toEqual(expectedScope);
    expect(policy).toEqual(expectedPolicy);
    expect(canonicalize(scope).toString("utf8")).toBe(
      '{"inScope":["*.example.com","api.example.com"],"outOfScope":["*.internal.example.com","staging.example.com"],"platform":"hackerone","program":"snapshot-base","schemaVersion":"scope-snapshot/v1","semanticsVersion":"scope/v1"}',
    );
    expect(canonicalize(policy).toString("utf8")).toBe(
      '{"accounts":{"required":false,"use_researcher_owned_test_accounts_only":true},"blockedCapabilities":["brute_force","credential_stuffing","data_exfiltration","destructive_testing","malware_execution","mass_scanning","password_spraying","payment_abuse","real_user_account_takeover","spam","waf_evasion"],"evidence":{"browser_trace":true,"console_logs":true,"desktop_screenshots":"optional","dom_snapshot":true,"har":true,"mask_secrets":true,"screenshots":true,"video":"optional"},"labAuthorization":null,"rules":{"automated_scanning":"limited","browser_crawling":true,"deep_safe_mode":true,"destructive_testing":false,"lab_mode":false,"rate_limit":"1rps","require_human_approval_for_risky_actions":true},"schemaVersion":"policy-snapshot/v1","semanticsVersion":"policy/v1"}',
    );
    expect(computeScopeHash(scope)).toBe("4651011099a99852279ee248e3b9fe9178cec0f0325d4f033ca5252f6fec87a8");
    expect(computePolicyHash(policy)).toBe("6947dfc1f0c62f92d8a4ea6b2fa8c549e6b2e510166cdcfb3d1b727bc2d1fac9");
    expect(authority).toEqual({
      schemaVersion: "authority-snapshot/v1",
      scope,
      policy,
      scopeHash: "4651011099a99852279ee248e3b9fe9178cec0f0325d4f033ca5252f6fec87a8",
      policyHash: "6947dfc1f0c62f92d8a4ea6b2fa8c549e6b2e510166cdcfb3d1b727bc2d1fac9",
    });
  });

  it("hashes reordered YAML and omitted defaults exactly like their explicit semantic equivalents", () => {
    const reordered = parseAndNormalize(`program: snapshot-base
platform: hackerone
rules:
  require_human_approval_for_risky_actions: true
  deep_safe_mode: true
  browser_crawling: true
  rate_limit: "1rps"
  destructive_testing: false
  automated_scanning: limited
accounts:
  use_researcher_owned_test_accounts_only: true
  required: false
evidence:
  mask_secrets: true
  desktop_screenshots: optional
  browser_trace: true
  video: optional
  dom_snapshot: true
  console_logs: true
  har: true
  screenshots: true
integrations: {}
out_of_scope: ["*.internal.example.com", "staging.example.com"]
in_scope: ["api.example.com", "*.example.com"]
`);
    expect(buildProgramAuthoritySnapshot({ config: reordered, labAuthorization: null })).toEqual(
      buildProgramAuthoritySnapshot({ config: buildConfig(), labAuthorization: null }),
    );

    const explicit = configWithExplicitDefaults();
    const omitted = parseAndNormalize(`program: snapshot-explicit
platform: hackerone
in_scope: ["api.example.com"]
out_of_scope: []
rules:
  rate_limit: "1rps"
accounts:
  required: false
evidence:
  screenshots: true
integrations: {}
`);
    expect(buildScopeSnapshot(omitted)).toEqual(buildScopeSnapshot(explicit));
    expect(buildPolicySnapshot(omitted, null)).toEqual(buildPolicySnapshot(explicit, null));
  });

  it("normalizes scope as a lowercased, trimmed, deduplicated set", () => {
    const equivalent = {
      ...buildConfig(),
      in_scope: ["  API.example.com  ", "*.Example.com", "api.example.com"],
      out_of_scope: ["STAGING.example.com", "  *.internal.example.com ", "staging.example.com"],
    };
    const baseline = buildProgramAuthoritySnapshot({ config: buildConfig(), labAuthorization: null });
    const normalized = buildProgramAuthoritySnapshot({ config: equivalent, labAuthorization: null });
    expect(normalized.scope).toEqual(expectedScope);
    expect(normalized.scopeHash).toBe(baseline.scopeHash);
    expect(normalized.policyHash).toBe(baseline.policyHash);
  });

  it("keeps path case in authority semantics while normalizing origin case", () => {
    const base = buildConfig();
    const upperPath = {
      ...base,
      in_scope: ["https://API.example.com/App"],
      out_of_scope: [],
    };
    const lowerPath = {
      ...base,
      in_scope: ["https://api.example.com/app"],
      out_of_scope: [],
    };
    const upper = buildProgramAuthoritySnapshot({ config: upperPath, labAuthorization: null });
    const lower = buildProgramAuthoritySnapshot({ config: lowerPath, labAuthorization: null });
    expect(upper.scopeHash).not.toBe(lower.scopeHash);
    const originCaseOnly = {
      ...base,
      in_scope: ["https://API.example.com/App"],
      out_of_scope: [],
    };
    const sameOriginCase = {
      ...base,
      in_scope: ["https://api.example.com/App"],
      out_of_scope: [],
    };
    expect(
      buildProgramAuthoritySnapshot({ config: originCaseOnly, labAuthorization: null }).scopeHash,
    ).toBe(buildProgramAuthoritySnapshot({ config: sameOriginCase, labAuthorization: null }).scopeHash);
  });

  it("changes only scopeHash for every scope authority mutation", () => {
    const base = buildConfig();
    const baseline = buildProgramAuthoritySnapshot({ config: base, labAuthorization: null });
    const mutations: ReadonlyArray<[string, (config: ProgramConfig) => ProgramConfig]> = [
      ["program", (config) => ({ ...config, program: "other-program" })],
      ["platform", (config) => ({ ...config, platform: "bugcrowd" })],
      ["in_scope", (config) => ({ ...config, in_scope: [...config.in_scope, "other.example.com"] })],
      ["out_of_scope", (config) => ({ ...config, out_of_scope: [...config.out_of_scope, "other.example.com"] })],
    ];
    for (const [label, mutate] of mutations) {
      const changed = buildProgramAuthoritySnapshot({ config: mutate(base), labAuthorization: null });
      expect(changed.scopeHash, label).not.toBe(baseline.scopeHash);
      expect(changed.policyHash, label).toBe(baseline.policyHash);
    }
  });

  it("changes only policyHash for every effective rule, account, and evidence mutation", () => {
    const base = buildConfig();
    const baseline = buildProgramAuthoritySnapshot({ config: base, labAuthorization: null });
    const mutations: ReadonlyArray<[string, (config: ProgramConfig) => ProgramConfig]> = [
      ["automated_scanning", (config) => ({ ...config, rules: { ...config.rules, automated_scanning: "allowed" } })],
      ["destructive_testing", (config) => ({ ...config, rules: { ...config.rules, destructive_testing: true } })],
      ["rate_limit", (config) => ({ ...config, rules: { ...config.rules, rate_limit: "2rps" } })],
      ["browser_crawling", (config) => ({ ...config, rules: { ...config.rules, browser_crawling: false } })],
      ["deep_safe_mode", (config) => ({ ...config, rules: { ...config.rules, deep_safe_mode: false } })],
      ["require_human_approval_for_risky_actions", (config) => ({ ...config, rules: { ...config.rules, require_human_approval_for_risky_actions: false } })],
      ["accounts.required", (config) => ({ ...config, accounts: { ...config.accounts, required: true } })],
      ["accounts.owned", (config) => ({ ...config, accounts: { ...config.accounts, use_researcher_owned_test_accounts_only: false } })],
      ["evidence.screenshots", (config) => ({ ...config, evidence: { ...config.evidence, screenshots: false } })],
      ["evidence.har", (config) => ({ ...config, evidence: { ...config.evidence, har: false } })],
      ["evidence.console_logs", (config) => ({ ...config, evidence: { ...config.evidence, console_logs: false } })],
      ["evidence.dom_snapshot", (config) => ({ ...config, evidence: { ...config.evidence, dom_snapshot: false } })],
      ["evidence.video", (config) => ({ ...config, evidence: { ...config.evidence, video: false } })],
      ["evidence.browser_trace", (config) => ({ ...config, evidence: { ...config.evidence, browser_trace: false } })],
      ["evidence.desktop_screenshots", (config) => ({ ...config, evidence: { ...config.evidence, desktop_screenshots: false } })],
      ["evidence.mask_secrets", (config) => ({ ...config, evidence: { ...config.evidence, mask_secrets: false } })],
    ];
    for (const [label, mutate] of mutations) {
      const changed = buildProgramAuthoritySnapshot({ config: mutate(base), labAuthorization: null });
      expect(changed.policyHash, label).not.toBe(baseline.policyHash);
      expect(changed.scopeHash, label).toBe(baseline.scopeHash);
    }
  });

  it("binds lab mode plus normalized path, byte length, and content digest", () => {
    const lab = labAuthorizationFixture();
    const config = configWithLabAuthorization(buildConfig(), lab.relativePath, false);
    const baseline = buildProgramAuthoritySnapshot({ config, labAuthorization: lab });
    const changes: ReadonlyArray<[string, ProgramConfig, LabAuthorization]> = [
      ["lab_mode", configWithLabAuthorization(buildConfig(), lab.relativePath, true), lab],
      ["relativePath", configWithLabAuthorization(buildConfig(), "notes/lab-authorization.md", false), { ...lab, relativePath: "notes/lab-authorization.md" }],
      ["byteLength", config, { ...lab, byteLength: lab.byteLength + 1 }],
      ["contentSha256", config, { ...lab, contentSha256: "f".repeat(64) }],
    ];
    for (const [label, changedConfig, changedLab] of changes) {
      const changed = buildProgramAuthoritySnapshot({ config: changedConfig, labAuthorization: changedLab });
      expect(changed.policyHash, label).not.toBe(baseline.policyHash);
      expect(changed.scopeHash, label).toBe(baseline.scopeHash);
    }
  });

  it("fails closed when configured lab authority and loaded metadata disagree", () => {
    const lab = labAuthorizationFixture();
    expectBountyError(
      () => buildPolicySnapshot(configWithLabAuthorization(buildConfig(), lab.relativePath, false), null),
      "LAB_AUTHORIZATION_METADATA_MISMATCH",
    );
    expectBountyError(
      () => buildPolicySnapshot(buildConfig(), lab),
      "LAB_AUTHORIZATION_METADATA_MISMATCH",
    );
    expectBountyError(
      () => buildPolicySnapshot(configWithLabAuthorization(buildConfig(), "other.md", false), lab),
      "LAB_AUTHORIZATION_METADATA_MISMATCH",
    );
  });

  it("rejects unsafe hand-built lab authorization paths even when config and metadata agree", () => {
    const unsafePaths = [
      "../authorization.md",
      "/absolute/authorization.md",
      "C:/authorization.md",
      "authorization.md:stream",
      "notes//authorization.md",
      "notes/./authorization.md",
      "notes/authorization\u0000.md",
    ];
    for (const unsafePath of unsafePaths) {
      const lab = { ...labAuthorizationFixture(), relativePath: unsafePath };
      expectBountyError(
        () => buildPolicySnapshot(
          configWithLabAuthorization(buildConfig(), unsafePath, false),
          lab,
        ),
        "LAB_AUTHORIZATION_FILE_PATH_INVALID",
      );
    }
  });

  it("rejects malformed hand-built lab authorization byte length and digest metadata", () => {
    const lab = labAuthorizationFixture();
    const config = configWithLabAuthorization(buildConfig(), lab.relativePath, false);
    for (const invalid of [
      { ...lab, byteLength: -1 },
      { ...lab, byteLength: 1.5 },
      { ...lab, byteLength: MAX_LAB_AUTHORIZATION_FILE_BYTES + 1 },
      { ...lab, contentSha256: "A".repeat(64) },
      { ...lab, contentSha256: "0".repeat(63) },
    ]) {
      expectBountyError(
        () => buildPolicySnapshot(config, invalid),
        "LAB_AUTHORIZATION_METADATA_MISMATCH",
      );
    }
  });

  it("accepts normalized loader metadata for an equivalent ./ configured path", () => {
    const root = makeTempRoot("bountypilot-policy-loader-normalization-");
    const notes = path.join(root, "notes");
    const authPath = path.join(notes, "lab-authorization.md");
    const programFile = writeProgram(root, validProgramYaml("normalized-policy", "./notes/lab-authorization.md"));
    const access: LabAuthorizationFileAccess = {
      realpath: (filePath) => path.resolve(filePath),
      readUpTo: (filePath) => {
        expect(path.resolve(filePath)).toBe(path.resolve(authPath));
        return Buffer.from("authorized\n", "utf8");
      },
    };
    const loaded = loadProgramFile(programFile, access);
    expect(loaded.config.rules.lab_authorization_file).toBe("./notes/lab-authorization.md");
    expect(loaded.labAuthorization?.relativePath).toBe("notes/lab-authorization.md");
    expect(() => buildProgramAuthoritySnapshot({
      config: loaded.config,
      labAuthorization: loaded.labAuthorization,
    })).not.toThrow();
  });

  it("keeps integrations and secret sentinels out of policyHash", () => {
    const baseline = buildProgramAuthoritySnapshot({ config: buildConfig(), labAuthorization: null });
    const config = {
      ...buildConfig(),
      integrations: {
        mcp: {
          enabled: true,
          allow_execute: true,
          token: "DO_NOT_HASH_OR_STORE_THIS_SECRET",
          headers: { Authorization: "Bearer DO_NOT_HASH_OR_STORE_THIS_SECRET" },
        },
      },
    };
    const changed = buildProgramAuthoritySnapshot({ config, labAuthorization: null });
    expect(changed.policyHash).toBe(baseline.policyHash);
    expect(JSON.stringify(changed.policy)).not.toContain("DO_NOT_HASH_OR_STORE_THIS_SECRET");
  });

  it("binds module-owned schema/semantics versions and blocked capability profile", () => {
    expect(computeScopeHash({ ...expectedScope, schemaVersion: "scope-snapshot/v2" } as unknown as ScopeSnapshot)).not.toBe(computeScopeHash(expectedScope));
    expect(computeScopeHash({ ...expectedScope, semanticsVersion: "scope/v2" } as unknown as ScopeSnapshot)).not.toBe(computeScopeHash(expectedScope));
    expect(computePolicyHash({ ...expectedPolicy, schemaVersion: "policy-snapshot/v2" } as unknown as PolicySnapshot)).not.toBe(computePolicyHash(expectedPolicy));
    expect(computePolicyHash({ ...expectedPolicy, semanticsVersion: "policy/v2" } as unknown as PolicySnapshot)).not.toBe(computePolicyHash(expectedPolicy));
    expect(computePolicyHash({ ...expectedPolicy, blockedCapabilities: [...expectedPolicy.blockedCapabilities, "new_blocked_capability"] })).not.toBe(computePolicyHash(expectedPolicy));
  });

  it("does not bind absolute workspace paths when identical workspaces are relocated", () => {
    const rootA = makeTempRoot("bountypilot-relocate-a-");
    const rootB = makeTempRoot("bountypilot-relocate-b-");
    const authRelative = "lab-authorization.md";
    const labContent = Buffer.from("Authorized local lab owned by researcher.\n", "utf8");
    const yaml = validProgramYaml("relocate-target", authRelative);
    writeFileSync(path.join(rootA, authRelative), labContent);
    writeFileSync(path.join(rootB, authRelative), labContent);
    const programFileA = writeProgram(rootA, yaml);
    const programFileB = writeProgram(rootB, yaml);
    const configA = parseAndNormalize(yaml);
    const configB = parseAndNormalize(yaml);
    const labA = loadLabAuthorization(programFileA, configA);
    const labB = loadLabAuthorization(programFileB, configB);
    const snapA = buildProgramAuthoritySnapshot({ config: configA, labAuthorization: labA });
    const snapB = buildProgramAuthoritySnapshot({ config: configB, labAuthorization: labB });
    expect(snapA).toEqual(snapB);
    expect(JSON.stringify(snapA)).not.toContain(rootA);
    expect(JSON.stringify(snapA)).not.toContain(rootB);
  });
});

describe("lab authorization hardening", () => {
  it("returns null when lab_authorization_file is unset", () => {
    const root = makeTempRoot("bountypilot-lab-auth-");
    const programFile = writeProgram(root, validProgramYaml("loader-test", null));

    const loaded = loadLabAuthorization(programFile, parseAndNormalize(validProgramYaml("loader-test", null)));
    expect(loaded).toBeNull();
  });

  it("rejects lab_authorization_file that exceeds the cap based on actual bytes read", () => {
    const root = makeTempRoot("bountypilot-lab-auth-oversize-");
    const authRelative = "lab-authorization.md";
    const authPath = path.join(root, authRelative);
    // write MAX+1 actual bytes; the cap is MAX_LAB_AUTHORIZATION_FILE_BYTES
    const payload = "A".repeat(MAX_LAB_AUTHORIZATION_FILE_BYTES + 1);
    writeFileSync(authPath, payload, "utf8");
    const programFile = writeProgram(root, validProgramYaml("loader-test", authRelative));

    expectBountyError(
      () => loadLabAuthorization(programFile, parseAndNormalize(validProgramYaml("loader-test", authRelative))),
      "LAB_AUTHORIZATION_FILE_TOO_LARGE",
    );
  });

  it("enforces the post-read cap when readUpTo returns the MAX+1 overflow sentinel", () => {
    const root = makeTempRoot("bountypilot-lab-post-read-cap-");
    const authRelative = "lab-authorization.md";
    const programFile = writeProgram(root, validProgramYaml("loader-test", authRelative));
    const config = parseAndNormalize(validProgramYaml("loader-test", authRelative));
    let reads = 0;
    const access: LabAuthorizationFileAccess = {
      realpath: (filePath) => path.resolve(filePath),
      readUpTo: (_filePath, maxBytes) => {
        reads += 1;
        expect(maxBytes).toBe(MAX_LAB_AUTHORIZATION_FILE_BYTES + 1);
        return Buffer.alloc(maxBytes, 0x41);
      },
    };

    expectBountyError(
      () => loadLabAuthorization(programFile, config, access),
      "LAB_AUTHORIZATION_FILE_TOO_LARGE",
    );
    expect(reads).toBe(1);
  });

  it("rejects a realpath escape before invoking the content reader, including a workspace-prefix collision", () => {
    const root = makeTempRoot("bountypilot-lab-read-order-");
    const authRelative = "lab-authorization.md";
    const programFile = writeProgram(root, validProgramYaml("loader-test", authRelative));
    const config = parseAndNormalize(validProgramYaml("loader-test", authRelative));
    const workspaceReal = path.resolve(root);
    const workspaceEntry = path.dirname(programFile);
    const candidateEntry = path.resolve(workspaceEntry, authRelative);
    const outsideReal = `${workspaceReal}-attacker${path.sep}authorization.md`;
    const events: string[] = [];
    const access: LabAuthorizationFileAccess = {
      realpath: (filePath) => {
        const resolved = path.resolve(filePath);
        events.push(`realpath:${resolved}`);
        if (resolved === path.resolve(workspaceEntry)) return workspaceReal;
        if (resolved === candidateEntry) return outsideReal;
        throw new Error(`unexpected realpath argument: ${resolved}`);
      },
      readUpTo: (filePath) => {
        events.push(`read:${path.resolve(filePath)}`);
        return Buffer.from("must not be read", "utf8");
      },
    };

    expectBountyError(
      () => loadLabAuthorization(programFile, config, access),
      "LAB_AUTHORIZATION_FILE_SYMLINK_ESCAPE",
    );
    expect(events).toEqual([
      `realpath:${path.resolve(workspaceEntry)}`,
      `realpath:${candidateEntry}`,
    ]);
  });

  it("reads the verified real path for an in-workspace alias, never the lexical symlink entry", () => {
    const root = makeTempRoot("bountypilot-lab-safe-alias-");
    const authRelative = "lab-authorization.md";
    const programFile = writeProgram(root, validProgramYaml("loader-test", authRelative));
    const config = parseAndNormalize(validProgramYaml("loader-test", authRelative));
    const workspaceEntry = path.dirname(programFile);
    const candidateEntry = path.resolve(workspaceEntry, authRelative);
    const verifiedReal = path.resolve(root, "verified", "authorization.md");
    const events: string[] = [];
    const access: LabAuthorizationFileAccess = {
      realpath: (filePath) => {
        const resolved = path.resolve(filePath);
        events.push(`realpath:${resolved}`);
        if (resolved === path.resolve(workspaceEntry)) return path.resolve(root);
        if (resolved === candidateEntry) return verifiedReal;
        throw new Error(`unexpected realpath argument: ${resolved}`);
      },
      readUpTo: (filePath, maxBytes) => {
        events.push(`read:${path.resolve(filePath)}:${maxBytes}`);
        return Buffer.from("authorized\n", "utf8");
      },
    };
    const loaded = loadLabAuthorization(programFile, config, access);
    expect(loaded?.relativePath).toBe(authRelative);
    expect(events).toEqual([
      `realpath:${path.resolve(workspaceEntry)}`,
      `realpath:${candidateEntry}`,
      `read:${verifiedReal}:${MAX_LAB_AUTHORIZATION_FILE_BYTES + 1}`,
    ]);
  });

  it("rejects drive-relative and ADS-like paths before any filesystem access", () => {
    const root = makeTempRoot("bountypilot-lab-lexical-reject-");
    const programFile = writeProgram(root, validProgramYaml("loader-test", null));
    for (const unsafePath of ["C:relative-note.md", "authorization.md:stream"]) {
      const base = parseAndNormalize(validProgramYaml("loader-test", null));
      const config: ProgramConfig = {
        ...base,
        rules: { ...base.rules, lab_authorization_file: unsafePath },
      };
      let realpaths = 0;
      let reads = 0;
      const access: LabAuthorizationFileAccess = {
        realpath: () => {
          realpaths += 1;
          return root;
        },
        readUpTo: () => {
          reads += 1;
          return Buffer.alloc(0);
        },
      };
      expectBountyError(
        () => loadLabAuthorization(programFile, config, access),
        "LAB_AUTHORIZATION_FILE_PATH_INVALID",
      );
      expect(realpaths, unsafePath).toBe(0);
      expect(reads, unsafePath).toBe(0);
    }
  });

  it("maps unexpected reader failures to a sanitized stable code", () => {
    const root = makeTempRoot("bountypilot-lab-read-failure-");
    const authRelative = "lab-authorization.md";
    const programFile = writeProgram(root, validProgramYaml("loader-test", authRelative));
    const config = parseAndNormalize(validProgramYaml("loader-test", authRelative));
    const secretPath = "C:\\private\\outside\\authorization.md";
    const access: LabAuthorizationFileAccess = {
      realpath: (filePath) => path.resolve(filePath),
      readUpTo: () => {
        throw new Error(`read failed at ${secretPath}`);
      },
    };
    let error: BountyPilotError | undefined;
    try {
      loadLabAuthorization(programFile, config, access);
    } catch (caught) {
      error = caught as BountyPilotError;
    }
    expect(error).toBeInstanceOf(BountyPilotError);
    expect(error?.code).toBe("LAB_AUTHORIZATION_FILE_READ_FAILED");
    expect(error?.message).not.toContain(secretPath);
    expect(error?.message).not.toContain(root);
  });

  it.runIf(canCreateSymlink())("rejects symlinks whose resolved path escapes the program workspace", () => {
    const root = makeTempRoot("bountypilot-lab-symlink-");
    const outsideDir = makeTempRoot("bountypilot-lab-symlink-outside-");
    const realAuth = path.join(outsideDir, "real-authorization.md");
    writeFileSync(realAuth, "owned by attacker\n", "utf8");

    const programFile = writeProgram(root, validProgramYaml("loader-test", "lab-authorization.md"));
    const linkPath = path.join(path.dirname(programFile), "lab-authorization.md");

    symlinkSync(realAuth, linkPath, "file");
    expectBountyError(
      () => loadLabAuthorization(programFile, parseAndNormalize(validProgramYaml("loader-test", "lab-authorization.md"))),
      "LAB_AUTHORIZATION_FILE_SYMLINK_ESCAPE",
    );
  });

  it("returns the actual byte length and SHA-256 over the raw on-disk bytes", () => {
    // The contract is the value the loader returns, not the number of
    // reads it performs. This test pins the integration: a valid lab
    // authorization must be loaded with a relative path (forward-slash
    // normalized), a byte length that matches the actual on-disk bytes
    // (not the stat size), and a SHA-256 that matches node:crypto over
    // the same bytes.
    const root = makeTempRoot("bountypilot-lab-actual-bytes-");
    const authRelative = "lab-authorization.md";
    const authPath = path.join(root, authRelative);
    const content = Buffer.from([0x41, 0x00, 0x0d, 0x0a, 0xff, 0x42]);
    writeFileSync(authPath, content);
    const programFile = writeProgram(root, validProgramYaml("loader-test", authRelative));
    const config = parseAndNormalize(validProgramYaml("loader-test", authRelative));

    const loaded = loadLabAuthorization(programFile, config);
    expect(loaded).not.toBeNull();
    expect(loaded!.byteLength).toBe(content.byteLength);
    expect(loaded!.contentSha256).toBe(createHash("sha256").update(content).digest("hex"));
    expect(loaded!.relativePath).toBe(authRelative);
  });

  it("normalizes leading dot segments and both path separator styles in returned metadata", () => {
    const root = makeTempRoot("bountypilot-lab-normalized-relative-");
    const notes = path.join(root, "notes");
    const authPath = path.join(notes, "lab-authorization.md");
    const programFile = writeProgram(root, validProgramYaml("loader-test", null));
    for (const configuredPath of ["./notes/lab-authorization.md", ".\\notes\\lab-authorization.md"]) {
      const base = parseAndNormalize(validProgramYaml("loader-test", null));
      const config: ProgramConfig = {
        ...base,
        rules: { ...base.rules, lab_authorization_file: configuredPath },
      };
      let reads = 0;
      const access: LabAuthorizationFileAccess = {
        realpath: (filePath) => path.resolve(filePath),
        readUpTo: (filePath) => {
          reads += 1;
          expect(path.resolve(filePath)).toBe(path.resolve(authPath));
          return Buffer.from("authorized\n", "utf8");
        },
      };
      const loaded = loadLabAuthorization(programFile, config, access);
      expect(loaded?.relativePath, configuredPath).toBe("notes/lab-authorization.md");
      expect(reads, configuredPath).toBe(1);
    }
  });

  it.runIf(canCreateSymlink())("allows a nested symlinked lab authorization whose real path stays inside the program workspace", () => {
    // Realpath-based containment must be evaluated against the program
    // workspace, not against the literal entry path. A nested symlink
    // that resolves to a real file inside the same root must load
    // successfully and produce the same byte length and hash as the
    // target itself.
    const root = makeTempRoot("bountypilot-lab-nested-symlink-");
    const realAuth = path.join(root, "real-authorization.md");
    const content = "Authorized local lab owned by researcher.\n";
    writeFileSync(realAuth, content, "utf8");
    const linkPath = path.join(root, "lab-authorization.md");
    symlinkSync(realAuth, linkPath, "file");
    const programFile = writeProgram(root, validProgramYaml("loader-test", "lab-authorization.md"));
    const config = parseAndNormalize(validProgramYaml("loader-test", "lab-authorization.md"));

    const loaded = loadLabAuthorization(programFile, config);
    expect(loaded).not.toBeNull();
    expect(loaded!.byteLength).toBe(Buffer.byteLength(content, "utf8"));
    expect(loaded!.contentSha256).toBe(createHash("sha256").update(content, "utf8").digest("hex"));
  });

  it("produces a policyHash that is sensitive to the lab file content bytes", () => {
    const rootA = makeTempRoot("bountypilot-lab-policy-a-");
    const rootB = makeTempRoot("bountypilot-lab-policy-b-");
    const authA = "lab-authorization.md";
    const authB = "lab-authorization.md";
    writeFileSync(path.join(rootA, authA), "Authorized local lab owned by researcher.\n", "utf8");
    writeFileSync(path.join(rootB, authB), "Authorized LOCAL lab owned by researcher (v2).\n", "utf8");
    const programFileA = writeProgram(rootA, validProgramYaml("loader-test", authA));
    const programFileB = writeProgram(rootB, validProgramYaml("loader-test", authB));
    const configA = parseAndNormalize(validProgramYaml("loader-test", authA));
    const configB = parseAndNormalize(validProgramYaml("loader-test", authB));

    const labA = loadLabAuthorization(programFileA, configA);
    const labB = loadLabAuthorization(programFileB, configB);
    expect(labA).not.toBeNull();
    expect(labB).not.toBeNull();
    expect(labA!.contentSha256).not.toBe(labB!.contentSha256);

    const snapA = buildPolicySnapshot(configA, labA);
    const snapB = buildPolicySnapshot(configB, labB);
    expect(computePolicyHash(snapA)).not.toBe(computePolicyHash(snapB));
  });
});

describe("action binding and approval context — exact canonical contract", () => {
  it("pins the exact structured action projection, canonical bytes, domain, and golden digest", () => {
    const binding = buildActionBinding(baselineActionBindingInput());
    const expected = expectedActionBinding();
    expect(ACTION_BINDING_SCHEMA_VERSION).toBe("action-binding/v1");
    expect(ACTION_SEMANTICS_VERSION).toBe("action/v1");
    expect(binding).toEqual(expected);
    expect(canonicalize(binding).toString("utf8")).toBe(
      '{"action":{"actionType":"http.get","adapter":"safe-checks","id":"act-1","jobId":"job-1","normalizedTarget":"https://api.example.com/health","requiredForCompletion":true,"requiresApproval":false,"riskLevel":"low","target":"https://api.example.com/health"},"capabilityEnforcement":{"actionType":"http.get","allowedModes":["deep-safe","safe"],"blockedByDefault":false,"destructive":false,"id":"http.read","mcpTools":["http.get"],"requiresApprovalByDefault":false,"requiresScope":true,"requiresTarget":true,"riskLevel":"low","scopedPostcondition":"current_or_final_url_in_scope","stateChanging":false},"integrationExecutionPolicy":{"allowExecute":true,"blockedCapabilities":[],"capabilities":["http.get"],"enabled":true,"endpointSha256":null,"entrypoint":null,"entrypointSha256":null,"launcherSha256":"1111111111111111111111111111111111111111111111111111111111111111","name":"safe-checks","package":null,"packageJsonSha256":null,"packageVersion":null,"timeoutMs":30000,"transport":null,"type":"browser"},"job":{"mode":"safe","target":"https://api.example.com/health"},"metadataSha256":"e06a580861565d826fa6580049a1ce8779e67650320b475d519f50f2dd90f304","policyAction":{"actionType":"http.get","capability":"http.read","destructive":false,"labModeEnabled":false,"mode":"safe","requiresApprovalByDefault":false,"riskLevel":"low","stateChanging":false,"target":"https://api.example.com/health"},"policyDecision":"allow","schemaVersion":"action-binding/v1","semanticsVersion":"action/v1"}',
    );
    expect(computeActionHash(binding)).toBe("bc6784d20b9e026f8b60b706e652d7a3c9fac76545ceec605b37badefed0bf89");
  });

  it("pins contextHash and stales it when any authority component changes", () => {
    const authority = buildProgramAuthoritySnapshot({ config: buildConfig(), labAuthorization: null });
    const actionHash = computeActionHash(buildActionBinding(baselineActionBindingInput()));
    const context = {
      scopeHash: authority.scopeHash,
      policyHash: authority.policyHash,
      actionHash,
    };
    expect(computeContextHash(context)).toBe("92b431e322c5c389d121cadfbeee81750c59ab61f9557c54debce30898247f4b");
    for (const field of ["scopeHash", "policyHash", "actionHash"] as const) {
      const current = context[field];
      const changed = current.replace(/^./, current.startsWith("0") ? "1" : "0");
      expect(computeContextHash({ ...context, [field]: changed }), field).not.toBe(computeContextHash(context));
    }
  });

  it("rejects malformed authority hash inputs instead of canonicalizing ambiguous tokens", () => {
    const valid = "a".repeat(64);
    for (const field of ["scopeHash", "policyHash", "actionHash"] as const) {
      for (const invalid of ["a".repeat(63), "A".repeat(64), "g".repeat(64), `${valid}00`]) {
        expectBountyError(
          () => computeContextHash({ scopeHash: valid, policyHash: valid, actionHash: valid, [field]: invalid }),
          "AUTHORITY_HASH_INVALID",
        );
      }
    }
  });

  it("normalizes optional action inputs to explicit nulls and hashes empty metadata", () => {
    const input = baselineActionBindingInput();
    const binding = buildActionBinding({
      ...input,
      action: { ...input.action, target: undefined, metadata: undefined },
      job: { ...input.job, target: undefined },
      normalizedTarget: null,
      policyAction: { mode: "safe", actionType: "http.get" },
      capabilityEnforcement: {
        id: "http.read",
        title: "HTTP read",
        description: "Read an authorized scoped HTTP target.",
        actionType: "http.get",
        riskLevel: "low",
        allowedModes: ["safe"],
        produces: ["observation"],
      },
      integrationExecutionPolicy: null,
    });
    expect(binding.action.normalizedTarget).toBeNull();
    expect(binding.job.target).toBeNull();
    expect(binding.policyAction).toEqual({
      mode: "safe",
      actionType: "http.get",
      target: null,
      riskLevel: null,
      stateChanging: null,
      destructive: null,
      capability: null,
      requiresApprovalByDefault: null,
      labModeEnabled: null,
    });
    expect(binding.capabilityEnforcement).toMatchObject({
      allowedModes: ["safe"],
      requiresTarget: null,
      requiresScope: null,
      stateChanging: null,
      destructive: null,
      requiresApprovalByDefault: null,
      blockedByDefault: null,
      scopedPostcondition: null,
      mcpTools: [],
    });
    expect(binding.metadataSha256).toBe("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
    expect(binding.integrationExecutionPolicy).toBeNull();
  });

  it("requires a concrete job ID for an executable action binding", () => {
    const input = baselineActionBindingInput();
    expectBountyError(
      () => buildActionBinding({ ...input, action: { ...input.action, jobId: undefined } }),
      "ACTION_BINDING_INVALID",
    );
    expectBountyError(
      () => buildActionBinding({ ...input, job: { ...input.job, id: "job-other" } }),
      "ACTION_BINDING_INVALID",
    );
  });

  it("rejects malformed runtime policy decisions, execution modes, and risk levels", () => {
    const input = baselineActionBindingInput();
    const invalidInputs: ReadonlyArray<[string, ActionBindingInput]> = [
      ["policyDecision", { ...input, policyDecision: "allow_and_exfiltrate" as never }],
      ["job.mode", { ...input, job: { ...input.job, mode: "turbo" as never } }],
      [
        "policyAction.mode",
        { ...input, policyAction: { ...input.policyAction, mode: "turbo" as never } },
      ],
      [
        "action.riskLevel",
        { ...input, action: { ...input.action, riskLevel: "catastrophic" as never } },
      ],
      [
        "policyAction.riskLevel",
        {
          ...input,
          policyAction: { ...input.policyAction, riskLevel: "catastrophic" as never },
        },
      ],
      [
        "capabilityEnforcement.riskLevel",
        {
          ...input,
          capabilityEnforcement: {
            ...input.capabilityEnforcement,
            riskLevel: "catastrophic" as never,
          },
        },
      ],
    ];

    for (const [label, invalid] of invalidInputs) {
      expectBountyError(
        () => buildActionBinding(invalid),
        "ACTION_BINDING_INVALID",
      );
      expect(label.length).toBeGreaterThan(0);
    }
  });

  it("changes actionHash for every required action, job, PolicyAction, enforcement, metadata, decision, and integration-policy field", () => {
    const input = baselineActionBindingInput();
    const baselineHash = computeActionHash(buildActionBinding(input));
    const mutations: ReadonlyArray<[string, (value: ActionBindingInput) => ActionBindingInput]> = [
      ["action.id", (value) => ({ ...value, action: { ...value.action, id: "act-2" } })],
      ["action.jobId", (value) => ({
        ...value,
        action: { ...value.action, jobId: "job-2" },
        job: { ...value.job, id: "job-2" },
      })],
      ["action.adapter", (value) => ({ ...value, action: { ...value.action, adapter: "recon-engine" } })],
      ["action.actionType", (value) => ({ ...value, action: { ...value.action, actionType: "http.probe" } })],
      ["action.target", (value) => ({ ...value, action: { ...value.action, target: "https://api.example.com/other" } })],
      ["normalizedTarget", (value) => ({ ...value, normalizedTarget: "https://api.example.com/other" })],
      ["action.riskLevel", (value) => ({ ...value, action: { ...value.action, riskLevel: "high" } })],
      ["action.requiresApproval", (value) => ({ ...value, action: { ...value.action, requiresApproval: true } })],
      ["requiredForCompletion", (value) => ({ ...value, requiredForCompletion: false })],
      ["job.mode", (value) => ({ ...value, job: { ...value.job, mode: "deep-safe" } })],
      ["job.target", (value) => ({ ...value, job: { ...value.job, target: "https://job.example.com/other" } })],
      ["policyAction.mode", (value) => ({ ...value, policyAction: { ...value.policyAction, mode: "deep-safe" } })],
      ["policyAction.actionType", (value) => ({ ...value, policyAction: { ...value.policyAction, actionType: "http.probe" } })],
      ["policyAction.target", (value) => ({ ...value, policyAction: { ...value.policyAction, target: "https://api.example.com/other" } })],
      ["policyAction.riskLevel", (value) => ({ ...value, policyAction: { ...value.policyAction, riskLevel: "medium" } })],
      ["policyAction.stateChanging", (value) => ({ ...value, policyAction: { ...value.policyAction, stateChanging: true } })],
      ["policyAction.destructive", (value) => ({ ...value, policyAction: { ...value.policyAction, destructive: true } })],
      ["policyAction.capability", (value) => ({ ...value, policyAction: { ...value.policyAction, capability: "browser.navigate" } })],
      ["policyAction.requiresApprovalByDefault", (value) => ({ ...value, policyAction: { ...value.policyAction, requiresApprovalByDefault: true } })],
      ["policyAction.labModeEnabled", (value) => ({ ...value, policyAction: { ...value.policyAction, labModeEnabled: true } })],
      ["enforcement.id", (value) => withCapabilityEnforcement(value, { id: "http.other" })],
      ["enforcement.actionType", (value) => withCapabilityEnforcement(value, { actionType: "http.probe" })],
      ["enforcement.riskLevel", (value) => withCapabilityEnforcement(value, { riskLevel: "medium" })],
      ["enforcement.allowedModes", (value) => withCapabilityEnforcement(value, { allowedModes: ["safe"] })],
      ["enforcement.requiresTarget", (value) => withCapabilityEnforcement(value, { requiresTarget: false })],
      ["enforcement.requiresScope", (value) => withCapabilityEnforcement(value, { requiresScope: false })],
      ["enforcement.stateChanging", (value) => withCapabilityEnforcement(value, { stateChanging: true })],
      ["enforcement.destructive", (value) => withCapabilityEnforcement(value, { destructive: true })],
      ["enforcement.requiresApprovalByDefault", (value) => withCapabilityEnforcement(value, { requiresApprovalByDefault: true })],
      ["enforcement.blockedByDefault", (value) => withCapabilityEnforcement(value, { blockedByDefault: true })],
      ["enforcement.scopedPostcondition", (value) => withCapabilityEnforcement(value, { scopedPostcondition: undefined })],
      ["enforcement.mcpTools", (value) => withCapabilityEnforcement(value, { mcpTools: ["http.other"] })],
      ["metadata", (value) => ({ ...value, action: { ...value.action, metadata: { probe: "extended" } } })],
      ["policyDecision", (value) => ({ ...value, policyDecision: "require_approval" })],
      ["integration.name", (value) => withIntegrationPolicy(value, { name: "recon-engine" })],
      ["integration.type", (value) => withIntegrationPolicy(value, { type: "external-tool" })],
      ["integration.enabled", (value) => withIntegrationPolicy(value, { enabled: false })],
      ["integration.allowExecute", (value) => withIntegrationPolicy(value, { allowExecute: false })],
      ["integration.transport", (value) => withIntegrationPolicy(value, { transport: "stdio" })],
      ["integration.launcherSha256", (value) => withIntegrationPolicy(value, { launcherSha256: "2".repeat(64) })],
      ["integration.endpointSha256", (value) => withIntegrationPolicy(value, { endpointSha256: "3".repeat(64) })],
      ["integration.package", (value) => withIntegrationPolicy(value, { package: "@scope/tool" })],
      ["integration.packageVersion", (value) => withIntegrationPolicy(value, { packageVersion: "1.0.0" })],
      ["integration.entrypoint", (value) => withIntegrationPolicy(value, { entrypoint: "dist/cli.js" })],
      ["integration.entrypointSha256", (value) => withIntegrationPolicy(value, { entrypointSha256: "4".repeat(64) })],
      ["integration.packageJsonSha256", (value) => withIntegrationPolicy(value, { packageJsonSha256: "5".repeat(64) })],
      ["integration.timeoutMs", (value) => withIntegrationPolicy(value, { timeoutMs: 45_000 })],
      ["integration.capabilities", (value) => withIntegrationPolicy(value, { capabilities: ["http.probe"] })],
      ["integration.blockedCapabilities", (value) => withIntegrationPolicy(value, { blockedCapabilities: ["destructive_testing"] })],
    ];
    for (const [label, mutate] of mutations) {
      expect(computeActionHash(buildActionBinding(mutate(input))), label).not.toBe(baselineHash);
    }
  });

  it("normalizes set-like arrays and metadata key order before hashing", () => {
    const baseline = buildActionBinding(baselineActionBindingInput());
    const reordered = baselineActionBindingInput();
    reordered.action.metadata = { headers: { Accept: "application/json" }, probe: "basic" };
    reordered.capabilityEnforcement.allowedModes = ["safe", "deep-safe", "safe"];
    reordered.capabilityEnforcement.mcpTools = ["http.get", "http.get"];
    reordered.integrationExecutionPolicy!.capabilities = ["http.get", "http.get"];
    expect(buildActionBinding(reordered)).toEqual(baseline);

    const blockedA = baselineActionBindingInput();
    const blockedB = baselineActionBindingInput();
    blockedA.integrationExecutionPolicy!.blockedCapabilities = ["spam", "destructive_testing", "spam"];
    blockedB.integrationExecutionPolicy!.blockedCapabilities = ["destructive_testing", "spam"];
    expect(buildActionBinding(blockedA)).toEqual(buildActionBinding(blockedB));
  });

  it("whitelists the safe integration projection and never binds raw commands, credentials, headers, options, or absolute paths", () => {
    const baseline = baselineActionBindingInput();
    const secret = "DO_NOT_STORE_THIS_SECRET";
    baseline.integrationExecutionPolicy = {
      ...baseline.integrationExecutionPolicy!,
      command: `tool --token ${secret}`,
      args: ["--token", secret],
      endpoint: `https://user:${secret}@provider.example/api`,
      headers: { Authorization: `Bearer ${secret}` },
      options: { token: secret, cwd: "C:\\private\\workspace" },
    } as unknown as SafeIntegrationExecutionPolicy;
    const binding = buildActionBinding(baseline);
    expect(binding).toEqual(expectedActionBinding());
    expect(JSON.stringify(binding)).not.toContain(secret);
    expect(JSON.stringify(binding)).not.toContain("C:\\private\\workspace");
  });

  it("rejects unsafe integration projection identifiers and malformed digests", () => {
    for (const patch of [
      { entrypoint: "C:\\private\\tool.js" },
      { entrypoint: "../tool.js" },
      { launcherSha256: "A".repeat(64) },
      { endpointSha256: "not-a-sha256" },
    ] satisfies Array<Partial<SafeIntegrationExecutionPolicy>>) {
      expectBountyError(
        () => buildActionBinding(withIntegrationPolicy(baselineActionBindingInput(), patch)),
        "INTEGRATION_EXECUTION_POLICY_INVALID",
      );
    }
  });

  it("normalizes a dot-prefixed, backslash-separated entrypoint to the same projection and actionHash as 'dist/cli.js'", () => {
    // The action binding is the audit-critical projection, so a safe
    // entrypoint written on Windows as `.\dist\cli.js` must hash
    // identically to its forward-slash, non-prefixed canonical form.
    // The hash equality is the part that actually proves no audit
    // boundary was crossed; the projection equality is the part that
    // proves the binding does not store the Windows-style identifier.
    const baseline = buildActionBinding(
      withIntegrationPolicy(baselineActionBindingInput(), { entrypoint: "dist/cli.js" }),
    );
    const windowsStyle = buildActionBinding(
      withIntegrationPolicy(baselineActionBindingInput(), { entrypoint: ".\\dist\\cli.js" }),
    );
    expect(windowsStyle.integrationExecutionPolicy?.entrypoint).toBe("dist/cli.js");
    expect(windowsStyle).toEqual(baseline);
    expect(computeActionHash(windowsStyle)).toBe(computeActionHash(baseline));
  });

  it("rejects unsafe entrypoint shapes fail closed with INTEGRATION_EXECUTION_POLICY_INVALID", () => {
    // The cases are pinned independently because each is a distinct
    // class of unsafe input and the production validator must reject
    // every one of them, not merely the most obvious `..` escape.
    const unsafeEntrypoints: ReadonlyArray<[string, string]> = [
      ["empty internal segment", "dist//cli.js"],
      ["internal dot segment", "dist/./cli.js"],
      ["ADS colon", "authorization.md:stream"],
      ["line feed control character", "dist/cli\n.js"],
      ["tab control character", "dist/cli\t.js"],
      ["carriage return control character", "dist/cli\r.js"],
    ];
    for (const [label, entrypoint] of unsafeEntrypoints) {
      expectBountyError(
        () => buildActionBinding(withIntegrationPolicy(baselineActionBindingInput(), { entrypoint })),
        "INTEGRATION_EXECUTION_POLICY_INVALID",
      );
      // The label is the only human-readable context for which case
      // failed when the production validator regresses; it must remain
      // in the test name to keep the failure diagnostic on the line
      // that broke, not buried in a stack trace.
      expect(label.length).toBeGreaterThan(0);
    }
  });

  it("does not bind mutable queue status or timestamps", () => {
    const baseline = baselineActionBindingInput();
    const changed: ActionBindingInput = {
      ...baseline,
      action: {
        ...baseline.action,
        status: "executed",
        createdAt: "2099-01-01T00:00:00.000Z",
        executedAt: "2099-01-01T00:00:01.000Z",
      },
      job: {
        ...baseline.job,
        status: "completed",
        createdAt: "2099-01-01T00:00:00.000Z",
        updatedAt: "2099-01-01T00:00:01.000Z",
      },
    };
    expect(buildActionBinding(changed)).toEqual(buildActionBinding(baseline));
  });
});

describe("normalizeScopeArrays (set-like normalization helper)", () => {
  it("deduplicates and sorts the arrays", () => {
    const result = normalizeScopeArrays(
      ["b.example.com", "a.example.com", "b.example.com"],
      ["z.example.com", "a.example.com", "z.example.com"],
    );
    expect(result.inScope).toEqual(["a.example.com", "b.example.com"]);
    expect(result.outOfScope).toEqual(["a.example.com", "z.example.com"]);
  });

  it("trims whitespace and lowercases entries consistent with current ScopeGuard semantics", () => {
    // ScopeGuard's pattern matcher already does pattern.trim().toLowerCase()
    // when matching, so the set-like normalization that feeds the scope
    // snapshot hash must apply the same trim/lowercase step. Otherwise the
    // hash and the runtime matcher would disagree on what counts as
    // semantically equal scope.
    const result = normalizeScopeArrays(
      ["  API.example.com  ", "*.Example.com"],
      ["STAGING.example.com", "  *.internal.example.com "],
    );
    expect(result.inScope).toEqual(["*.example.com", "api.example.com"]);
    expect(result.outOfScope).toEqual(["*.internal.example.com", "staging.example.com"]);
  });
});

// --- helpers --------------------------------------------------------------

function baselineActionBindingInput(): ActionBindingInput {
  return {
    action: {
      id: "act-1",
      jobId: "job-1",
      adapter: "safe-checks",
      actionType: "http.get",
      target: "https://api.example.com/health",
      riskLevel: "low",
      requiresApproval: false,
      status: "approved",
      metadata: { probe: "basic", headers: { Accept: "application/json" } },
      createdAt: "2026-01-01T00:00:00.000Z",
    },
    normalizedTarget: "https://api.example.com/health",
    requiredForCompletion: true,
    job: {
      id: "job-1",
      type: "hunt",
      target: "https://api.example.com/health",
      mode: "safe",
      status: "running",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    },
    policyAction: {
      mode: "safe",
      actionType: "http.get",
      target: "https://api.example.com/health",
      riskLevel: "low",
      stateChanging: false,
      destructive: false,
      capability: "http.read",
      requiresApprovalByDefault: false,
      labModeEnabled: false,
    },
    capabilityEnforcement: {
      id: "http.read",
      title: "HTTP read",
      description: "Read an authorized scoped HTTP target.",
      actionType: "http.get",
      riskLevel: "low",
      allowedModes: ["safe", "deep-safe"],
      produces: ["observation"],
      requiresTarget: true,
      requiresScope: true,
      stateChanging: false,
      destructive: false,
      requiresApprovalByDefault: false,
      blockedByDefault: false,
      scopedPostcondition: "current_or_final_url_in_scope",
      mcpTools: ["http.get"],
    },
    policyDecision: "allow",
    integrationExecutionPolicy: {
      name: "safe-checks",
      type: "browser",
      enabled: true,
      allowExecute: true,
      transport: null,
      launcherSha256: "1".repeat(64),
      endpointSha256: null,
      package: null,
      packageVersion: null,
      entrypoint: null,
      entrypointSha256: null,
      packageJsonSha256: null,
      timeoutMs: 30_000,
      capabilities: ["http.get"],
      blockedCapabilities: [],
    },
  };
}

function expectedActionBinding(): ActionBinding {
  return {
    schemaVersion: "action-binding/v1",
    semanticsVersion: "action/v1",
    action: {
      id: "act-1",
      jobId: "job-1",
      adapter: "safe-checks",
      actionType: "http.get",
      target: "https://api.example.com/health",
      normalizedTarget: "https://api.example.com/health",
      riskLevel: "low",
      requiresApproval: false,
      requiredForCompletion: true,
    },
    job: {
      mode: "safe",
      target: "https://api.example.com/health",
    },
    policyAction: {
      mode: "safe",
      actionType: "http.get",
      target: "https://api.example.com/health",
      riskLevel: "low",
      stateChanging: false,
      destructive: false,
      capability: "http.read",
      requiresApprovalByDefault: false,
      labModeEnabled: false,
    },
    capabilityEnforcement: {
      id: "http.read",
      actionType: "http.get",
      riskLevel: "low",
      allowedModes: ["deep-safe", "safe"],
      requiresTarget: true,
      requiresScope: true,
      stateChanging: false,
      destructive: false,
      requiresApprovalByDefault: false,
      blockedByDefault: false,
      scopedPostcondition: "current_or_final_url_in_scope",
      mcpTools: ["http.get"],
    },
    metadataSha256: "e06a580861565d826fa6580049a1ce8779e67650320b475d519f50f2dd90f304",
    policyDecision: "allow",
    integrationExecutionPolicy: {
      name: "safe-checks",
      type: "browser",
      enabled: true,
      allowExecute: true,
      transport: null,
      launcherSha256: "1".repeat(64),
      endpointSha256: null,
      package: null,
      packageVersion: null,
      entrypoint: null,
      entrypointSha256: null,
      packageJsonSha256: null,
      timeoutMs: 30_000,
      capabilities: ["http.get"],
      blockedCapabilities: [],
    },
  };
}

function withCapabilityEnforcement(
  input: ActionBindingInput,
  patch: Partial<NonNullable<ActionBindingInput["capabilityEnforcement"]>>,
): ActionBindingInput {
  return {
    ...input,
    capabilityEnforcement: { ...input.capabilityEnforcement, ...patch },
  };
}

function withIntegrationPolicy(
  input: ActionBindingInput,
  patch: Partial<SafeIntegrationExecutionPolicy>,
): ActionBindingInput {
  return {
    ...input,
    integrationExecutionPolicy: { ...input.integrationExecutionPolicy!, ...patch },
  };
}

function validProgramYaml(name: string, authRelative: string | null): string {
  const auth = authRelative
    ? `\n  lab_authorization_file: ${JSON.stringify(authRelative)}\n`
    : "";
  return `program: ${name}
platform: hackerone

in_scope:
  - "api.example.com"

out_of_scope: []

rules:
  automated_scanning: limited
  destructive_testing: false
  rate_limit: "1rps"
  browser_crawling: true
  deep_safe_mode: true
  require_human_approval_for_risky_actions: true${auth}

accounts:
  required: false
  use_researcher_owned_test_accounts_only: true

evidence:
  screenshots: true
  har: true
  console_logs: true
  dom_snapshot: true
  video: optional
  browser_trace: true
  desktop_screenshots: optional
  mask_secrets: true

integrations: {}
`;
}

function writeProgram(root: string, yaml: string): string {
  const programFile = path.join(root, "program.yml");
  writeFileSync(programFile, yaml, "utf8");
  return programFile;
}

// Probe the platform symlink capability exactly once per test file. Caching
// avoids spawning a throwaway temp directory before every symlink test, which
// would otherwise make the suite noisier on Windows hosts that lack
// SeCreateSymbolicLinkPrivilege (developer mode not enabled).
let symlinkCapability: boolean | undefined;
function canCreateSymlink(): boolean {
  if (symlinkCapability !== undefined) return symlinkCapability;
  const probeDir = mkdtempSync(path.join(os.tmpdir(), "bountypilot-symlink-probe-"));
  const target = path.join(probeDir, "target.txt");
  const link = path.join(probeDir, "link");
  writeFileSync(target, "x", "utf8");
  try {
    if (existsSync(link)) {
      rmSync(link);
    }
    try {
      symlinkSync(target, link, "file");
      rmSync(link);
      symlinkCapability = true;
      return true;
    } catch {
      symlinkCapability = false;
      return false;
    }
  } finally {
    rmSync(probeDir, { recursive: true, force: true });
  }
}
