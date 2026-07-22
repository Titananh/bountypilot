import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  fetchPinnedNetworkTarget,
  isPrivateOrReservedAddress,
  resolveNetworkTarget,
} from "../src/core/http/network-address-policy.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          if (!server.listening) return resolve();
          server.close(() => resolve());
        }),
    ),
  );
});

describe("network address policy", () => {
  it("classifies private, loopback, metadata, and reserved ranges", () => {
    for (const address of [
      "0.0.0.0",
      "10.0.0.1",
      "100.64.0.1",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "192.168.1.1",
      "198.18.0.1",
      "203.0.113.10",
      "::1",
      "fc00::1",
      "fe80::1",
      "2001:db8::1",
    ]) {
      expect(isPrivateOrReservedAddress(address), address).toBe(true);
    }
    expect(isPrivateOrReservedAddress("8.8.8.8")).toBe(false);
    expect(isPrivateOrReservedAddress("2001:4860:4860::8888")).toBe(false);
  });

  it("accepts an explicitly supplied loopback literal but rejects unsafe URL forms", async () => {
    await expect(resolveNetworkTarget("http://127.0.0.1:8080/")).resolves.toMatchObject({
      address: "127.0.0.1",
      family: 4,
      explicitLocal: true,
    });
    await expect(resolveNetworkTarget("http://user:pass@127.0.0.1/")).rejects.toMatchObject({
      code: "NETWORK_TARGET_BLOCKED",
    });
  });

  it("connects to the vetted IP literal while preserving the original Host header", async () => {
    const seen: { host?: string } = {};
    const server = createServer((request, response) => {
      seen.host = request.headers.host;
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("pinned-ok");
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("server address unavailable");

    const response = await fetchPinnedNetworkTarget(`http://127.0.0.1:${address.port}/health`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("pinned-ok");
    expect(seen.host).toBe(`127.0.0.1:${address.port}`);
  });
});
