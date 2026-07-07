import { describe, expect, it } from "vitest";
import { ScopeGuard } from "../src/core/scope/scope-guard.js";
import type { ProgramConfig } from "../src/core/config/program-schema.js";

const config: ProgramConfig = {
  program: "test",
  platform: "hackerone",
  in_scope: ["*.example.com", "api.example.com"],
  out_of_scope: ["staging.example.com", "*.internal.example.com"],
  rules: {
    automated_scanning: "limited",
    destructive_testing: false,
    rate_limit: "1rps",
    browser_crawling: true,
    deep_safe_mode: true,
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
};

describe("ScopeGuard", () => {
  it("allows exact in-scope hosts", () => {
    expect(new ScopeGuard(config).test("https://api.example.com").allowed).toBe(true);
  });

  it("allows wildcard subdomains", () => {
    expect(new ScopeGuard(config).test("https://www.example.com").allowed).toBe(true);
  });

  it("does not let wildcard match apex domain", () => {
    expect(new ScopeGuard(config).test("https://example.com").allowed).toBe(false);
  });

  it("prioritizes out-of-scope rules", () => {
    const result = new ScopeGuard(config).test("https://staging.example.com");
    expect(result.allowed).toBe(false);
    expect(result.matchedOutOfScope).toBe("staging.example.com");
  });

  it("enforces scheme and path constraints from URL scope rules", () => {
    const guard = new ScopeGuard({
      ...config,
      in_scope: ["https://api.example.com/app"],
      out_of_scope: [],
    });

    expect(guard.test("https://api.example.com/app").allowed).toBe(true);
    expect(guard.test("https://api.example.com/app/dashboard").allowed).toBe(true);
    expect(guard.test("http://api.example.com/app").allowed).toBe(false);
    expect(guard.test("https://api.example.com/admin").allowed).toBe(false);
  });

  it("enforces explicit port constraints from URL scope rules", () => {
    const guard = new ScopeGuard({
      ...config,
      in_scope: ["https://api.example.com:8443"],
      out_of_scope: [],
    });

    expect(guard.test("https://api.example.com:8443").allowed).toBe(true);
    expect(guard.test("https://api.example.com").allowed).toBe(false);
  });

  it("applies out-of-scope URL path prefixes before host allow rules", () => {
    const guard = new ScopeGuard({
      ...config,
      in_scope: ["api.example.com"],
      out_of_scope: ["https://api.example.com/admin"],
    });

    expect(guard.test("https://api.example.com/public").allowed).toBe(true);
    const blocked = guard.test("https://api.example.com/admin/settings");
    expect(blocked.allowed).toBe(false);
    expect(blocked.matchedOutOfScope).toBe("https://api.example.com/admin");
  });

  it("blocks non-http targets even when the host is in scope", () => {
    const result = new ScopeGuard(config).test("ftp://api.example.com/resource");

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("http and https");
  });
});
