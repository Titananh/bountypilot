import { describe, expect, it } from "vitest";
import { PolicyGate } from "../src/core/policy/policy-gate.js";

describe("PolicyGate", () => {
  it("blocks destructive actions", () => {
    const result = new PolicyGate().evaluate({
      mode: "deep-safe",
      actionType: "http.delete",
      riskLevel: "high",
      destructive: true,
    });
    expect(result.decision).toBe("block");
  });

  it("blocks destructive testing when it is declared only as a capability", () => {
    const result = new PolicyGate().evaluate({
      mode: "deep-safe",
      actionType: "http.probe",
      riskLevel: "low",
      capability: "destructive_testing",
    });

    expect(result).toMatchObject({
      decision: "block",
      reason: expect.stringContaining("destructive_testing"),
    });
  });

  it("blocks active actions in passive mode", () => {
    const result = new PolicyGate().evaluate({
      mode: "passive",
      actionType: "http.get",
      riskLevel: "low",
    });
    expect(result.decision).toBe("block");
  });

  it("allows low-risk safe checks in safe mode", () => {
    const result = new PolicyGate().evaluate({
      mode: "safe",
      actionType: "http.get",
      riskLevel: "low",
    });
    expect(result.decision).toBe("allow");
  });

  it("blocks automated scanning when program rules disable it", () => {
    const result = new PolicyGate({ automated_scanning: "none" }).evaluate({
      mode: "safe",
      actionType: "http.get",
      riskLevel: "low",
    });

    expect(result).toMatchObject({
      decision: "block",
      reason: expect.stringContaining("Automated scanning"),
    });
  });

  it("blocks browser and crawler actions when browser crawling is disabled", () => {
    const gate = new PolicyGate({ browser_crawling: false });

    expect(
      gate.evaluate({
        mode: "safe",
        actionType: "browser.navigate",
        riskLevel: "low",
      }),
    ).toMatchObject({ decision: "block", reason: expect.stringContaining("Browser crawling") });
    expect(
      gate.evaluate({
        mode: "safe",
        actionType: "crawler.fetch",
        riskLevel: "low",
      }),
    ).toMatchObject({ decision: "block", reason: expect.stringContaining("Browser crawling") });
  });

  it("blocks deep-safe mode when disabled by program rules", () => {
    const result = new PolicyGate({ deep_safe_mode: false }).evaluate({
      mode: "deep-safe",
      actionType: "research.public",
      riskLevel: "low",
    });

    expect(result).toMatchObject({
      decision: "block",
      reason: expect.stringContaining("Deep-safe mode"),
    });
  });

  it("requires approval for risky actions when program rules require it", () => {
    const result = new PolicyGate({ require_human_approval_for_risky_actions: true }).evaluate({
      mode: "deep-safe",
      actionType: "agent.plan",
      riskLevel: "medium",
    });

    expect(result).toMatchObject({
      decision: "require_approval",
      reason: expect.stringContaining("Program rules"),
    });
  });

  it("requires approval for high-risk deep-safe actions", () => {
    const result = new PolicyGate().evaluate({
      mode: "deep-safe",
      actionType: "browser.submit",
      riskLevel: "high",
    });
    expect(result.decision).toBe("require_approval");
  });

  it("blocks lab-offensive mode unless lab mode is enabled by config", () => {
    const result = new PolicyGate().evaluate({
      mode: "lab-offensive",
      actionType: "http.get",
      riskLevel: "low",
    });
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("rules.lab_mode=true");
  });

  it("blocks lab-offensive mode unless an explicit lab authorization file is configured", () => {
    const result = new PolicyGate({ lab_mode: true }).evaluate({
      mode: "lab-offensive",
      actionType: "http.get",
      target: "http://127.0.0.1:8080/",
      riskLevel: "low",
    });

    expect(result.decision).toBe("block");
    expect(result.reason).toContain("lab_authorization_file");
  });

  it("allows lab-offensive mode when lab mode and authorization file are configured", () => {
    const result = new PolicyGate({ lab_mode: true, lab_authorization_file: "lab-authorization.md" }).evaluate({
      mode: "lab-offensive",
      actionType: "http.get",
      target: "http://127.0.0.1:8080/",
      riskLevel: "low",
    });
    expect(result.decision).toBe("allow");
  });

  it("blocks lab-offensive mode for public targets even when lab mode is enabled", () => {
    const result = new PolicyGate({ lab_mode: true, lab_authorization_file: "lab-authorization.md" }).evaluate({
      mode: "lab-offensive",
      actionType: "http.get",
      target: "https://api.example.com/",
      riskLevel: "low",
    });

    expect(result.decision).toBe("block");
    expect(result.reason).toContain("local/private");
  });

  it("allows lab-offensive mode for private lab network targets", () => {
    const result = new PolicyGate({ lab_mode: true, lab_authorization_file: "lab-authorization.md" }).evaluate({
      mode: "lab-offensive",
      actionType: "http.get",
      target: "http://192.168.1.20/",
      riskLevel: "low",
    });

    expect(result.decision).toBe("allow");
  });
});
