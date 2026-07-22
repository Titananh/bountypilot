import { describe, expect, it, vi } from "vitest";
import { RateLimiter, parseRateLimitToIntervalMs } from "../src/core/rate-limit/rate-limiter.js";

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

  it("reserves distinct slots for concurrent callers", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(0);
      const limiter = new RateLimiter("2rps");
      const completed: number[] = [];
      const first = limiter.wait("https://example.test").then(() => completed.push(1));
      const second = limiter.wait("https://example.test").then(() => completed.push(2));
      const third = limiter.wait("https://example.test").then(() => completed.push(3));

      await vi.advanceTimersByTimeAsync(0);
      expect(completed).toEqual([1]);
      await vi.advanceTimersByTimeAsync(499);
      expect(completed).toEqual([1]);
      await vi.advanceTimersByTimeAsync(1);
      expect(completed).toEqual([1, 2]);
      await vi.advanceTimersByTimeAsync(500);
      expect(completed).toEqual([1, 2, 3]);
      await Promise.all([first, second, third]);
    } finally {
      vi.useRealTimers();
    }
  });
});
