import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import { probeTcpPort, waitForTcpPort } from "../src/services/tcp-probe.js";

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Expected TCP server address");
  }
  return address.port;
}

test("probeTcpPort reports a reachable localhost service", async () => {
  const server = net.createServer((socket) => socket.end());
  const port = await listen(server);
  try {
    const result = await probeTcpPort("127.0.0.1", port, 1_000);
    assert.equal(result.reachable, true);
    assert.equal(result.error, null);
  } finally {
    server.close();
  }
});

test("waitForTcpPort detects a service that starts later", async () => {
  const reserve = net.createServer();
  const port = await listen(reserve);
  await new Promise<void>((resolve) => reserve.close(() => resolve()));

  const delayed = net.createServer((socket) => socket.end());
  const timer = setTimeout(() => delayed.listen(port, "127.0.0.1"), 100);
  try {
    const result = await waitForTcpPort("127.0.0.1", port, 2_000, 25);
    assert.equal(result.reachable, true);
  } finally {
    clearTimeout(timer);
    if (delayed.listening) {
      await new Promise<void>((resolve) => delayed.close(() => resolve()));
    }
  }
});
