import { describe, expect, it } from "vitest";
import { buildOpenPathCommand } from "../src/utils/open-path.js";

describe("open path command builder", () => {
  it("uses a direct Windows opener without cmd shell parsing", () => {
    const targetPath = "C:\\tmp\\report & evidence";

    const opener = buildOpenPathCommand(targetPath, "win32");

    expect(opener).toEqual({ command: "explorer.exe", args: [targetPath] });
    expect(opener.command).not.toBe("cmd.exe");
    expect(opener.args).not.toContain("/c");
  });

  it("uses platform-native openers on macOS and Linux", () => {
    expect(buildOpenPathCommand("/tmp/report", "darwin")).toEqual({
      command: "open",
      args: ["/tmp/report"],
    });
    expect(buildOpenPathCommand("/tmp/report", "linux")).toEqual({
      command: "xdg-open",
      args: ["/tmp/report"],
    });
  });

  it("rejects empty targets", () => {
    expect(() => buildOpenPathCommand("  ", "linux")).toThrow("Path to open cannot be empty.");
  });
});
