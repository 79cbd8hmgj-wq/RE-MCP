import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import {
  encodeRspPacket,
  sendRspCommand,
  validateMemoryRead,
} from "../src/services/gdb-rsp.js";

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Expected TCP address");
  }
  return address.port;
}

test("encodeRspPacket adds the standard checksum", () => {
  assert.equal(encodeRspPacket("g"), "$g#67");
  assert.equal(encodeRspPacket("m2000000,10"), "$m2000000,10#5b");
});

test("sendRspCommand validates and returns a reply packet", async () => {
  const server = net.createServer((socket) => {
    socket.once("data", (data) => {
      assert.equal(data.toString("ascii"), "$g#67");
      socket.write("+$01020304#8a", "ascii");
    });
  });
  const port = await listen(server);
  try {
    const reply = await sendRspCommand("127.0.0.1", port, "g", 1_000, 1024);
    assert.equal(reply.payload, "01020304");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("sendRspCommand rejects invalid reply checksums", async () => {
  const server = net.createServer((socket) => {
    socket.once("data", () => socket.write("+$00#00", "ascii"));
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      sendRspCommand("127.0.0.1", port, "g", 1_000, 1024),
      /checksum mismatch/,
    );
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("memory reads are bounded to unsigned ARM9 addresses", () => {
  assert.doesNotThrow(() => validateMemoryRead(0x02000000, 4096));
  assert.throws(() => validateMemoryRead(-1, 1), /unsigned 32-bit/);
  assert.throws(() => validateMemoryRead(0x1_0000_0000, 1), /unsigned 32-bit/);
  assert.throws(() => validateMemoryRead(0x02000000, 0), /1 through 4096/);
  assert.throws(() => validateMemoryRead(0x02000000, 4097), /1 through 4096/);
});
