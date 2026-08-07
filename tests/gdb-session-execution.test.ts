import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import { encodeRspPacket, parseRspPacket } from "../src/services/gdb-rsp.js";
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

function createSession(port: number): GdbSession {
  return new GdbSession({
    host: "127.0.0.1",
    port,
    maxReplyBytes: 4096,
    connectTimeoutMs: 1000,
  });
}

function breakpointServer(
  replies: readonly string[],
  received: string[],
): net.Server {
  const remaining = [...replies];
  return net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("ascii");
      for (;;) {
        const parsed = parseRspPacket(buffer);
        if (parsed === null) return;
        buffer = buffer.slice(parsed.consumed);
        received.push(parsed.payload);
        const reply = remaining.shift();
        if (reply === undefined) throw new Error("Unexpected GDB command");
        socket.write(`+${encodeRspPacket(reply)}`, "ascii");
      }
    });
  });
}

test("inserts and removes ARM and Thumb software breakpoints", async () => {
  const received: string[] = [];
  const server = breakpointServer(["OK", "OK", "OK", "OK"], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    await session.insertSoftwareBreakpoint(0x02000000, 4, 1000);
    await session.insertSoftwareBreakpoint(0x02000002, 2, 1000);
    await session.removeSoftwareBreakpoint(0x02000000, 4, 1000);
    await session.removeSoftwareBreakpoint(0x02000002, 2, 1000);

    assert.deepEqual(received, [
      "Z0,2000000,4",
      "Z0,2000002,2",
      "z0,2000000,4",
      "z0,2000002,2",
    ]);
  } finally {
    await session.close();
    await close(server);
  }
});

test("rejects GDB breakpoint errors and unsupported acknowledgements", async () => {
  const received: string[] = [];
  const server = breakpointServer(["E01", ""], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    await assert.rejects(
      session.insertSoftwareBreakpoint(0x02000000, 4, 1000),
      /GDB software breakpoint insert failed: E01/,
    );
    await assert.rejects(
      session.removeSoftwareBreakpoint(0x02000000, 4, 1000),
      /Unsupported GDB software breakpoint remove reply/,
    );
  } finally {
    await session.close();
    await close(server);
  }
});