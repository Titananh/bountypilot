import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { BountyPilotError } from "../utils/errors.js";

export interface DemoLabServerInfo {
  host: string;
  port: number;
  target: string;
  routes: string[];
  nextCommands: string[];
}

export interface DemoLabServerHandle {
  server: Server;
  info: DemoLabServerInfo;
  close: () => Promise<void>;
}

const DEMO_ROUTES = [
  "/",
  "/.env",
  "/assets/app.js",
  "/search",
  "/api/profile",
  "/api/account",
  "/api/cors-demo",
  "/api/fetch",
  "/redirect",
  "/graphql",
  "/admin/settings",
  "/healthz",
];

export async function startDemoLabServer(input: { host: string; port: number }): Promise<DemoLabServerHandle> {
  assertLoopbackHost(input.host);
  assertPort(input.port);

  const server = createServer(handleDemoRequest);
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(input.port, input.host);
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new BountyPilotError("Demo lab server did not report a TCP address.", "LAB_DEMO_ADDRESS_UNAVAILABLE");
  }

  const hostForUrl = input.host === "::1" ? "[::1]" : input.host;
  const target = `http://${hostForUrl}:${address.port}/`;
  const info: DemoLabServerInfo = {
    host: input.host,
    port: address.port,
    target,
    routes: DEMO_ROUTES,
    nextCommands: [
      "bounty import examples/local-program.yml",
      `bounty lab e2e ${target}`,
      `bounty lab e2e ${target} --live --with safe-checks,js-analyzer`,
      `bounty hunt playbook cors ${new URL("/api/cors-demo", target).toString()} --live`,
      `bounty hunt playbook ssrf ${ssrfDemoUrl(target)} --live`,
      `bounty hunt playbook open-redirect ${new URL("/redirect?next=https://example.org", target).toString()} --live`,
      `bounty hunt playbook exposure ${new URL("/.env", target).toString()} --live`,
      `bounty hunt playbook xss ${new URL("/search?q=%3Cbountypilot-xss%3E", target).toString()} --live`,
      `bounty hunt playbook graphql ${new URL("/graphql", target).toString()} --live`,
      `bounty hunt playbook idor ${new URL("/api/account?id=1001", target).toString()} --live`,
      `bounty hunt playbook js-secrets ${target} --live`,
    ],
  };

  return {
    server,
    info,
    close: () => closeServer(server),
  };
}

function ssrfDemoUrl(target: string): string {
  const url = new URL("/api/fetch", target);
  url.searchParams.set("url", new URL("/healthz", target).toString());
  return url.toString();
}

function handleDemoRequest(request: IncomingMessage, response: ServerResponse): void {
  const method = request.method ?? "GET";
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  if (method !== "GET" && method !== "HEAD" && !(method === "POST" && url.pathname === "/graphql")) {
    writeResponse(response, 405, "text/plain; charset=utf-8", "Method not allowed\n", { allow: "GET, HEAD, POST /graphql" }, method);
    return;
  }

  if (url.pathname === "/") {
    writeResponse(response, 200, "text/html; charset=utf-8", demoHtml(), {}, method);
    return;
  }
  if (url.pathname === "/assets/app.js") {
    writeResponse(response, 200, "application/javascript; charset=utf-8", demoJavaScript(), {}, method);
    return;
  }
  if (url.pathname === "/.env") {
    writeResponse(response, 200, "text/plain; charset=utf-8", demoEnvFile(), {}, method);
    return;
  }
  if (url.pathname === "/search") {
    writeResponse(response, 200, "text/html; charset=utf-8", demoSearchHtml(url.searchParams.get("q") ?? ""), {}, method);
    return;
  }
  if (url.pathname === "/api/profile") {
    writeJson(response, method, {
      ok: true,
      account: "researcher-owned-demo-account",
      role: "viewer",
      routes: ["/api/profile", "/api/account?id=1001", "/api/cors-demo", "/api/fetch?url=/healthz", "/graphql", "/admin/settings"],
    });
    return;
  }
  if (url.pathname === "/api/account") {
    writeJson(response, method, demoAccount(url.searchParams.get("id")));
    return;
  }
  if (url.pathname === "/api/cors-demo") {
    writeJson(response, method, {
      ok: true,
      labOnly: true,
      message: "Credentialed CORS demo endpoint for local BountyPilot evidence practice.",
    }, 200, corsDemoHeaders(request));
    return;
  }
  if (url.pathname === "/api/fetch") {
    writeJson(response, method, demoServerFetch(url.searchParams.get("url")));
    return;
  }
  if (url.pathname === "/redirect") {
    const next = url.searchParams.get("next") ?? "/";
    writeResponse(response, 302, "text/plain; charset=utf-8", "Redirecting\n", { location: next }, method);
    return;
  }
  if (url.pathname === "/graphql") {
    if (method === "POST") {
      writeJson(response, method, demoGraphqlIntrospection());
      return;
    }
    writeJson(response, method, {
      data: {
        viewer: {
          id: "demo-viewer",
          labOnly: true,
        },
      },
    });
    return;
  }
  if (url.pathname === "/admin/settings") {
    writeJson(response, method, { ok: false, error: "demo admin route requires manual authorization context" }, 403);
    return;
  }
  if (url.pathname === "/healthz") {
    writeJson(response, method, { ok: true, service: "bountypilot-demo-lab" });
    return;
  }

  writeResponse(response, 404, "text/plain; charset=utf-8", "Not found\n", {}, method);
}

function demoHtml(): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>BountyPilot Local Demo Lab</title>
    <script src="/assets/app.js"></script>
  </head>
  <body>
    <main>
      <h1>BountyPilot Local Demo Lab</h1>
      <p>This loopback-only lab intentionally omits common security headers for safe local evidence practice.</p>
      <nav>
        <a href="/api/profile">Profile API</a>
        <a href="/api/cors-demo">CORS demo API</a>
        <a href="/api/fetch?url=/healthz">Server fetch demo API</a>
        <a href="/api/account?id=1001">Account demo API</a>
        <a href="/redirect?next=https://example.org">Redirect demo</a>
        <a href="/.env">Exposure demo</a>
        <a href="/search?q=%3Cbountypilot-xss%3E">Reflected search demo</a>
        <a href="/graphql">GraphQL endpoint</a>
        <a href="/admin/settings">Admin settings</a>
      </nav>
    </main>
  </body>
</html>
`;
}

function demoJavaScript(): string {
  return `const demoRoutes = ["/api/profile", "/api/account?id=1001", "/api/cors-demo", "/api/fetch?url=/healthz", "/graphql", "/admin/settings", "/account/123"];
const token = "synthetic-local-lab-token";
const api_key = "bp_demo_public_js_key_for_local_detection_only";
window.bountypilotDemoLab = { demoRoutes, token, api_key };
fetch("/api/profile").catch(() => undefined);
`;
}

function demoAccount(id: string | null): unknown {
  const accounts: Record<string, unknown> = {
    "1001": {
      id: "1001",
      ownerUserId: "demo-user-a",
      plan: "starter",
      labOnly: true,
    },
    "1002": {
      id: "1002",
      ownerUserId: "demo-user-b",
      plan: "enterprise",
      labOnly: true,
    },
  };
  return accounts[id ?? ""] ?? { error: "account not found", id, labOnly: true };
}

function demoServerFetch(target: string | null): unknown {
  const requested = target && target.length > 0 ? target : "/healthz";
  return {
    ok: true,
    labOnly: true,
    serverFetch: true,
    fetchedUrl: requested,
    upstreamStatus: requested.includes("healthz") ? 200 : 202,
    note: "Synthetic local lab signal; this endpoint does not fetch external networks.",
  };
}

function demoEnvFile(): string {
  return `# Synthetic local-only exposure demo for BountyPilot.
NODE_ENV=production
API_KEY=bp_demo_env_key_for_local_detection_only
DATABASE_URL=postgres://demo:[REDACTED-BY-LAB]@127.0.0.1:5432/demo
`;
}

function demoSearchHtml(query: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Search demo</title>
  </head>
  <body>
    <main>
      <h1>Search demo</h1>
      <p>Result for: ${query}</p>
    </main>
  </body>
</html>
`;
}

function demoGraphqlIntrospection(): unknown {
  return {
    data: {
      __schema: {
        queryType: { name: "Query" },
        mutationType: { name: "Mutation" },
        subscriptionType: null,
        types: [
          { kind: "OBJECT", name: "Query" },
          { kind: "OBJECT", name: "Mutation" },
          { kind: "OBJECT", name: "Viewer" },
          { kind: "SCALAR", name: "String" },
          { kind: "SCALAR", name: "Boolean" },
        ],
      },
    },
  };
}

function corsDemoHeaders(request: IncomingMessage): Record<string, string> {
  const origin = typeof request.headers.origin === "string" ? request.headers.origin : "https://bountypilot.local";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "vary": "Origin",
  };
}

function writeJson(response: ServerResponse, method: string, value: unknown, status = 200, headers: Record<string, string> = {}): void {
  writeResponse(response, status, "application/json; charset=utf-8", `${JSON.stringify(value, null, 2)}\n`, headers, method);
}

function writeResponse(
  response: ServerResponse,
  status: number,
  contentType: string,
  body: string,
  headers: Record<string, string>,
  method: string,
): void {
  response.writeHead(status, {
    "content-type": contentType,
    "cache-control": "no-store",
    ...headers,
  });
  if (method === "HEAD") {
    response.end();
    return;
  }
  response.end(body);
}

function assertLoopbackHost(host: string): void {
  const normalized = host.trim().toLowerCase();
  if (normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1") {
    return;
  }
  throw new BountyPilotError(
    `Demo lab host must be loopback-only (127.0.0.1, localhost, or ::1), got ${host}.`,
    "LAB_DEMO_HOST_NOT_LOOPBACK",
  );
}

function assertPort(port: number): void {
  if (Number.isInteger(port) && port >= 0 && port <= 65535) {
    return;
  }
  throw new BountyPilotError(`Invalid demo lab port: ${port}. Use an integer from 0 to 65535.`, "LAB_DEMO_PORT_INVALID");
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}
