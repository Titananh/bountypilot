import { spawn, spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bountyCli = path.join(repoRoot, "dist", "cli", "index.js");
const workspaces: string[] = [];

afterEach(() => {
  for (const workspace of workspaces.splice(0)) {
    rmSync(workspace, { recursive: true, force: true });
  }
});

describe("CLI chat", () => {
  it("opens an OpenCode-style connect shell from the root bugbounty command when no provider is configured", () => {
    const workspace = createWorkspace();

    const rootChat = runCli([], workspace);

    expectCommand(rootChat).toExit(0);
    expect(rootChat.stderr).toBe("");
    expect(rootChat.stdout).toContain("/connect");
    expect(rootChat.stdout).toContain("OpenAI");
    expect(rootChat.stdout).toContain("Connect  connect provider  BountyPilot Zen");
    expect(rootChat.stdout).toContain("esc interrupt");
    expect(rootChat.stdout).toContain("ctrl+t variants");
    expect(rootChat.stdout).toContain("tab agents");
    expect(rootChat.stdout).not.toContain("bugbounty / connect");
    expect(rootChat.stdout).not.toContain("provider missing");
    expect(rootChat.stdout).not.toContain("workspace ");
    expect(rootChat.stdout).not.toContain("essential commands");
    expect(rootChat.stdout).not.toContain("BountyPilot scoped bug bounty workflow");
    expect(rootChat.stdout).not.toContain("paste API key");
    expect(rootChat.stdout).not.toContain("Choose a provider");
    expect(rootChat.stdout).not.toContain("Ready.");
  });

  it("sends one-shot chat messages through a configured OpenAI-compatible provider", async () => {
    const workspace = createWorkspace();
    let requestBody: any;
    let authorization: string | undefined;
    const server = createServer(async (request, response) => {
      if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
        response.writeHead(404).end();
        return;
      }
      authorization = request.headers.authorization;
      requestBody = JSON.parse(await readRequestText(request));
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          choices: [{ message: { role: "assistant", content: "Use scoped recon, collect evidence, then review actions." } }],
          usage: { total_tokens: 42 },
        }),
      );
    });

    try {
      const baseURL = await listen(server);
      const connect = runCli(
        [
          "providers",
          "connect",
          "mock",
          "--openai-compatible",
          "--base-url",
          `${baseURL}/v1`,
          "--api-key",
          "sk-chat-test",
          "--model",
          "mock-model",
          "--json",
        ],
        workspace,
      );
      expectCommand(connect).toExit(0);

      const chat = await runCliAsync(["chat", "What should I do next?", "--provider", "mock", "--json"], workspace);
      expectCommand(chat).toExit(0);
      const parsed = JSON.parse(chat.stdout);
      expect(parsed).toMatchObject({
        ok: true,
        provider: "mock",
        model: "mock-model",
        message: "Use scoped recon, collect evidence, then review actions.",
      });
      expect(authorization).toBe("Bearer sk-chat-test");
      expect(requestBody.model).toBe("mock-model");
      expect(requestBody.messages).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ role: "system" }),
          expect.objectContaining({ role: "user", content: "What should I do next?" }),
        ]),
      );
    } finally {
      await closeServer(server);
    }
  });

  it("routes the root bugbounty command through the TUI runner when a provider is configured", async () => {
    const workspace = createWorkspace();
    const connect = runCli(
      [
        "providers",
        "connect",
        "mock",
        "--openai-compatible",
        "--base-url",
        "http://127.0.0.1:9/v1",
        "--api-key",
        "sk-chat-test",
        "--model",
        "mock-model",
        "--json",
      ],
      workspace,
    );
    expectCommand(connect).toExit(0);

    const session = await runCliAsync([], workspace);

    expectCommand(session).toExit(0);
    expect(session.stderr).toBe("");
    expect(session.stdout).toContain("BountyPilot Zen");
    expect(session.stdout).toContain("Build  Mock Model  BountyPilot Zen");
    expect(session.stdout).toContain("esc interrupt");
    expect(session.stdout).toContain("tab agents");
    expect(session.stdout).toContain("Mock Model");
    expect(session.stdout).toContain("non-interactive snapshot");
    expect(session.stdout).not.toContain("bugbounty / chat");
    expect(session.stdout).not.toContain("workspace ");
    expect(session.stdout).not.toContain("essential commands");
    expect(session.stdout).not.toContain("BountyPilot scoped bug bounty workflow");
    expect(session.stdout).not.toContain("Ready.");
  });

  it("prints a non-interactive TUI snapshot for smoke tests", () => {
    const workspace = createWorkspace();

    const snapshot = runCli(["tui", "--no-interactive"], workspace);

    expectCommand(snapshot).toExit(0);
    expect(snapshot.stderr).toBe("");
    expect(snapshot.stdout).toContain("/connect");
    expect(snapshot.stdout).toContain("\u2502 _");
    expect(snapshot.stdout).toContain("esc interrupt");
    expect(snapshot.stdout).not.toContain("bugbounty / connect");
    expect(snapshot.stdout).not.toContain("workspace ");
    expect(snapshot.stdout).not.toContain("BountyPilot scoped bug bounty workflow");
    expect(snapshot.stdout).not.toContain("paste API key");
    expect(snapshot.stdout).not.toContain("Choose a provider");
    expect(snapshot.stdout).not.toContain("Ready.");
    expect(snapshot.stdout).toContain("non-interactive snapshot");
  });

  it("prints an OpenCode-style transcript demo snapshot for visual regression", () => {
    const workspace = createWorkspace();

    const snapshot = runCli(["tui", "--demo-snapshot"], workspace);

    expectCommand(snapshot).toExit(0);
    expect(snapshot.stderr).toBe("");
    expect(snapshot.stdout).toContain("\u2502 # Scoped recon to report-ready bounty workflow");
    expect(snapshot.stdout).toContain("Find exposed endpoints for the scoped target");
    expect(snapshot.stdout).toContain("* Recon \"host\" observations");
    expect(snapshot.stdout).toContain("-> Read .bounty/programs/demo.yml");
    expect(snapshot.stdout).toContain("~ Waiting for approval...");
    expect(snapshot.stdout).toContain("\u25c9 Build \u00b7 Claude Opus 4.5");
    expect(snapshot.stdout).toContain("\u2502 _");
    expect(snapshot.stdout).toContain("\u2502 Build  Claude Opus 4.5  BountyPilot Zen");
    expect(snapshot.stdout).toContain("esc interrupt");
    expect(snapshot.stdout).toContain("ctrl+t variants");
    expect(snapshot.stdout).toContain("tab agents");
    expect(snapshot.stdout).toContain("ctrl+p commands");
    expect(snapshot.stdout).not.toContain("workspace ");
    expect(snapshot.stdout).not.toContain("Ready.");
    expect(snapshot.stdout).not.toContain("non-interactive snapshot");
  });

  it("uses the same OpenCode-style demo transcript when demo-session is rendered non-interactively", () => {
    const workspace = createWorkspace();

    const snapshot = runCli(["tui", "--demo-session", "--no-interactive"], workspace);

    expectCommand(snapshot).toExit(0);
    expect(snapshot.stderr).toBe("");
    expect(snapshot.stdout).toContain("\u2502 # Scoped recon to report-ready bounty workflow");
    expect(snapshot.stdout).toContain("\u2502 Build  Claude Opus 4.5  BountyPilot Zen");
    expect(snapshot.stdout).toContain("ctrl+p commands");
    expect(snapshot.stdout).not.toContain("non-interactive snapshot");
  });
});

function createWorkspace(): string {
  const workspace = mkdtempSync(path.join(os.tmpdir(), "bountypilot-chat-"));
  workspaces.push(workspace);
  return workspace;
}

function runCli(args: string[], cwd: string): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [bountyCli, ...args], {
    cwd,
    encoding: "utf8",
    env: testEnv(),
    timeout: 30_000,
  });
}

function runCliAsync(args: string[], cwd: string, stdin?: string): Promise<SpawnSyncReturns<string>> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bountyCli, ...args], {
      cwd,
      env: testEnv(),
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`CLI timed out. stdout=${stdout} stderr=${stderr}`));
    }, 30_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    if (stdin !== undefined) {
      child.stdin.end(stdin);
    }
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("exit", (status, signal) => {
      clearTimeout(timeout);
      resolve({
        pid: child.pid ?? 0,
        output: [stdout, stderr],
        stdout,
        stderr,
        status,
        signal,
      } as SpawnSyncReturns<string>);
    });
  });
}

function listen(server: Server): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Mock provider did not expose a TCP address."));
        return;
      }
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function readRequestText(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function testEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NO_COLOR: "1",
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1",
  };
}

function outputOf(result: SpawnSyncReturns<string>): string {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function expectCommand(result: SpawnSyncReturns<string>): { toExit(status: number): void } {
  return {
    toExit(status: number) {
      expect(result.error, outputOf(result)).toBeUndefined();
      expect(result.status, outputOf(result)).toBe(status);
    },
  };
}
