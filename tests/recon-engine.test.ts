import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { BountyDatabase } from "../src/stores/db/database.js";
import { describe, expect, it } from "vitest";
import { openBountyDatabase } from "../src/stores/db/database.js";
import { ReconObservationStore } from "../src/stores/recon-observation-store.js";
import { parseToolOutput } from "../src/integrations/tool-manager/tool-adapter-runner.js";
import { ToolManager } from "../src/integrations/tool-manager/tool-manager.js";

describe("bug results engine foundations", () => {
  it("parses common bounty tool outputs into normalized observations", () => {
    const observations = parseToolOutput({
      tool: "httpx",
      actionType: "http.probe",
      target: "https://api.example.com/",
      content: [
        JSON.stringify({ url: "https://api.example.com/v1/users?debug=true", title: "API" }),
        JSON.stringify({ url: "https://api.example.com/static/app.js" }),
      ].join("\n"),
    });

    expect(observations.map((observation) => observation.kind)).toEqual(expect.arrayContaining(["parameter", "js_asset"]));
    expect(observations.every((observation) => observation.sourceAdapter === "httpx")).toBe(true);
  });

  it("parses dedicated tool formats into rich recon observations", () => {
    const cases = [
      {
        tool: "subfinder",
        actionType: "research.public",
        content: "api.example.com\nstatic.example.com\n",
        expectedKinds: ["host"],
      },
      {
        tool: "httpx",
        actionType: "http.probe",
        content: JSON.stringify({ url: "https://api.example.com/admin", status_code: 200, tech: ["nginx", "express"] }),
        expectedKinds: ["endpoint", "technology"],
      },
      {
        tool: "katana",
        actionType: "crawler.fetch",
        content: JSON.stringify({ url: "https://api.example.com/login", tag: "form", action: "/session", method: "POST" }),
        expectedKinds: ["endpoint", "form"],
      },
      {
        tool: "nuclei",
        actionType: "http.scan",
        content: JSON.stringify({ "template-id": "exposed-panel", "matched-at": "https://api.example.com/panel", info: { severity: "medium" } }),
        expectedKinds: ["endpoint", "vulnerability_signal"],
      },
      {
        tool: "ffuf",
        actionType: "http.fuzz",
        content: JSON.stringify({ results: [{ url: "https://api.example.com/backup.zip", status: 200, length: 42 }] }),
        expectedKinds: ["endpoint"],
      },
      {
        tool: "dalfox",
        actionType: "http.validate",
        content: JSON.stringify({ target: "https://api.example.com/search?q=test", param: "q", type: "V", poc: "https://api.example.com/search?q=%3Csvg%3E" }),
        expectedKinds: ["parameter", "finding_candidate"],
      },
      {
        tool: "naabu",
        actionType: "tcp.scan",
        content: JSON.stringify({ host: "api.example.com", port: 443, protocol: "tcp" }),
        expectedKinds: ["host", "port"],
      },
    ];

    for (const item of cases) {
      const observations = parseToolOutput({
        tool: item.tool,
        actionType: item.actionType,
        target: "https://api.example.com/",
        content: item.content,
      });
      expect(observations.map((observation) => observation.kind), item.tool).toEqual(expect.arrayContaining(item.expectedKinds));
    }
  });

  it("keeps host-only line output as hosts instead of target-relative URLs", () => {
    const observations = parseToolOutput({
      tool: "subfinder",
      actionType: "research.public",
      target: "https://api.example.com/",
      content: "assets.example.com\n",
    });

    expect(observations).toHaveLength(1);
    expect(observations[0]?.kind).toBe("host");
    expect(observations[0]?.normalizedValue).toBe("assets.example.com");
  });

  it("deduplicates recon observations by fingerprint", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "bountypilot-recon-"));
    let db: BountyDatabase | undefined;
    try {
      db = openBountyDatabase(path.join(dir, "test.sqlite"));
      const store = new ReconObservationStore(db);

      const first = store.upsert({
        jobId: "job-one",
        kind: "endpoint",
        value: "https://api.example.com/v1/users",
        sourceAdapter: "httpx",
        sourceUrl: "https://api.example.com/",
        scopeAllowed: true,
        confidence: "low",
      });
      const second = store.upsert({
        jobId: "job-two",
        kind: "endpoint",
        value: "https://api.example.com/v1/users",
        sourceAdapter: "httpx",
        sourceUrl: "https://api.example.com/",
        scopeAllowed: true,
        confidence: "medium",
      });

      expect(second.id).toBe(first.id);
      expect(store.list()).toHaveLength(1);
      expect(store.list()[0]?.confidence).toBe("medium");
    } finally {
      db?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("includes bug bounty tools in the trusted registry", () => {
    const names = new ToolManager().list().map((tool) => tool.name);

    expect(names).toEqual(expect.arrayContaining(["subfinder", "httpx", "katana", "nuclei", "ffuf", "dalfox"]));
  });
});
