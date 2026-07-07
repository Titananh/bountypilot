import { describe, expect, it } from "vitest";
import * as ui from "../src/cli/ui.js";

describe("CLI UI", () => {
  it("renders compact command headers and panels", () => {
    const lines = captureOutput(() => {
      ui.header("mcp call");
      ui.panel("job", [ui.kv("id", "job_123")]);
    });
    const output = lines.join("\n");

    expect(lines[0]).toContain("bountypilot");
    expect(lines[0]).toContain("mcp call");
    expect(output).toContain("job");
    expect(output).toContain("id");
    expect(output).not.toContain("+---");
  });

  it("keeps tables within the terminal width", () => {
    const lines = captureOutput(() => {
      withColumns(50, () => {
        ui.table(
          ["id", "target", "status"],
          [["action_1234567890", "https://api.example.com/a/very/long/path/that/would/overflow", "pending"]],
        );
      });
    });

    expect(lines.some((line) => line.includes("..."))).toBe(true);
    expect(lines.every((line) => stripAnsi(line).length <= 50)).toBe(true);
  });

  it("keeps panels within the terminal width", () => {
    const lines = captureOutput(() => {
      withColumns(50, () => {
        ui.panel("workflow checkpoint", [
          ui.kv("target", "https://api.example.com/a/very/long/path/that/would/overflow"),
          ui.kv("status", "planned"),
        ]);
      });
    });

    expect(lines.some((line) => line.includes("..."))).toBe(true);
    expect(lines.every((line) => stripAnsi(line).length <= 50)).toBe(true);
  });

  it("renders command hints as copy-paste terminal lines", () => {
    const lines = captureOutput(() => {
      withColumns(96, () => {
        ui.commandList("next commands", [
          "bounty jobs show job-123",
          "bounty actions run-approved --job job-123 --note token=command-secret",
        ]);
      });
    });
    const output = lines.join("\n");

    expect(lines[0]).toContain("next commands");
    expect(output).toContain("$ bounty jobs show job-123");
    expect(output).toContain("[REDACTED]");
    expect(output).not.toContain("command-secret");
    expect(lines.every((line) => stripAnsi(line).length <= 96)).toBe(true);
  });

  it("redacts secrets at human and JSON output boundaries", () => {
    const lines = captureOutput(() => {
      ui.json({
        token: "json-token-secret",
        nested: { password: "json-password-secret" },
        url: "https://api.example.com/?token=json-query-secret",
      });
      ui.status("ok", "completed with password=status-password-secret");
      ui.table(
        ["token", "url"],
        [["table-token-secret", "https://api.example.com/?token=table-query-secret"]],
      );
      ui.panel("redaction", [
        ui.kv("api key", "panel-api-key-secret"),
        "authorization: bearer panel-authorization-secret",
      ]);
      ui.list("items", ["client_secret=list-client-secret"]);
    });
    const output = lines.join("\n");

    for (const secret of [
      "json-token-secret",
      "json-password-secret",
      "json-query-secret",
      "status-password-secret",
      "table-token-secret",
      "table-query-secret",
      "panel-api-key-secret",
      "panel-authorization-secret",
      "list-client-secret",
    ]) {
      expect(output).not.toContain(secret);
    }
    expect(output).toContain("[REDACTED]");
  });
});

function captureOutput(run: () => void): string[] {
  const originalLog = console.log;
  const lines: string[] = [];
  console.log = (value?: unknown) => {
    lines.push(String(value ?? ""));
  };
  try {
    run();
    return lines;
  } finally {
    console.log = originalLog;
  }
}

function withColumns(columns: number, run: () => void): void {
  const previous = process.env.BOUNTYPILOT_COLUMNS;
  process.env.BOUNTYPILOT_COLUMNS = String(columns);
  try {
    run();
  } finally {
    if (previous === undefined) {
      delete process.env.BOUNTYPILOT_COLUMNS;
    } else {
      process.env.BOUNTYPILOT_COLUMNS = previous;
    }
  }
}

function stripAnsi(value: string): string {
  return value.replace(/\u001B\[[0-9;]*m/g, "");
}
