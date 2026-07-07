import { describe, expect, it } from "vitest";
import { parseRateLimitToIntervalMs } from "../src/core/rate-limit/rate-limiter.js";

describe("RateLimiter", () => {
  it("parses one request per second", () => {
    expect(parseRateLimitToIntervalMs("1rps")).toBe(1000);
  });

  it("parses two requests per second", () => {
    expect(parseRateLimitToIntervalMs("2rps")).toBe(500);
  });

  it("falls back safely on invalid input", () => {
    expect(parseRateLimitToIntervalMs("fast")).toBe(1000);
  });
});
