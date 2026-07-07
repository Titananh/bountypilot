import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/package-bin-smoke.e2e.ts"],
    testTimeout: 120_000,
  },
});
