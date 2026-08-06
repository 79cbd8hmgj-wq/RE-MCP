import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import { encodeRspPacket } from "../src/services/gdb-rsp.js";
import { GdbSession } from "../src/services/gdb-session.js";

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected TCP address");
  return address.port;
}

async function close(server: net.Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

test("persistent session connects and exchanges serialized commands", async () => {
  const received: string[] = [];
  const replies = ["OK", "0102"];
  const server = net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("ascii");
      for (;;) {
        const start = buffer.indexOf("$");
        const marker = start >= 0 ? buffer.indexOf("#", start + 1) : -1;
        if (start < 0 || marker < 0 || buffer.length < marker + 3) return;
        const packet = buffer.slice(start, marker + 3);
        buffer = buffer.slice(marker + 3);
        received.push(packet);
        const reply = replies.shift();
        if (reply === undefined) throw new Error("Unexpected command");
        socket.write(`+${encodeRspPacket(reply)}`, "ascii");
      }
    });
  });
  const port = await listen(server);
  const session = new GdbSession({
    host: "127.0.0.1",
    port,
    maxReplyBytes: 1024,
    connectTimeoutMs: 1000,
  });
  try {
    await session.connect();
    assert.equal(session.state(), "stopped");
    const [first, second] = await Promise.all([
      session.sendStoppedCommand("qSupported", 1000),
      session.sendStoppedCommand("g", 1000),
    ]);
    assert.deepEqual([first, second], ["OK", "0102"]);
    assert.deepEqual(received, [encodeRspPacket("qSupported"), encodeRspPacket("g")]);
  } finally {
    await session.close();
    await close(server);
  }
  assert.equal(session.state(), "unavailable");
});

test("session rejects non-local hosts and invalid options", () => {
  assert.throws(
    () => new GdbSession({ host: "localhost" as "127.0.0.1", port: 1, maxReplyBytes: 64, connectTimeoutMs: 1 }),
    /restricted to 127\.0\.0\.1/,
  );
});

test("session enforces reply size and checksum", async () => {
  const oversized = net.createServer((socket) => {
    socket.once("data", () => socket.write("x".repeat(128), "ascii"));
  });
  const port = await listen(oversized);
  const session = new GdbSession({ host: "127.0.0.1", port, maxReplyBytes: 64, connectTimeoutMs: 1000 });
  try {
    await session.connect();
    await assert.rejects(session.sendStoppedCommand("g", 1000), /exceeded configured limit/);
  } finally {
    await session.close();
    await close(oversized);
  }
});

test("reset invalidates the active session", async () => {
  const server = net.createServer(() => undefined);
  const port = await listen(server);
  const session = new GdbSession({ host: "127.0.0.1", port, maxReplyBytes: 1024, connectTimeoutMs: 1000 });
  try {
    await session.connect();
    session.reset("emulator changed");
    assert.equal(session.state(), "unavailable");
  } finally {
    await close(server);
  }
});
